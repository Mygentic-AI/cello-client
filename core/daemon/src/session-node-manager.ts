/**
 * CELLO Daemon — SessionNodeManager
 *
 * Manages the lifecycle of all ephemeral session nodes:
 *   1. Per-session nodes: fresh transport key + Peer ID, connectionGater allows
 *      only the designated counterparty. Created during cello_initiate_session
 *      (outbound) or cello_await_session (inbound, via standing receiver handoff).
 *   2. Standing receiver node: pre-created, open gater, kept alive at all times.
 *      Handed to the first inbound session; immediately replaced.
 *   3. 32-node cap: enforced before any new node is created.
 *   4. Session status in SQLite: active → sealed (on close) or interrupted
 *      (on graceful shutdown or SIGKILL-restart detection).
 *
 * Pseudocode (SPARC Phase P):
 *
 * initialize():
 *   1. Open SQLite (node:sqlite), create sessions table if not exists
 *   2. Detect interrupted sessions: SELECT * FROM sessions WHERE status='active'
 *      → batch-update to 'interrupted', log session.interrupted.detected for each
 *      (source: 'daemon_restart') — runs before IPC socket opens so no race
 *   3. Create standing receiver node (fresh libp2p, open gater, sentinel agentName)
 *   4. Start standing receiver, set standingReceiverReady=true
 *   5. Log session.node.created for the standing receiver
 *
 * createSessionNode(sessionId, agentName, counterpartyPubkey, counterpartyPeerId, correlationId):
 *   Pseudocode:
 *   1. Check activeNodes.size >= MAX_SESSION_NODES → log cap.reached, return error
 *   2. Create SessionConnectionGater(counterpartyPeerId) — restricted from birth
 *   3. nodeFactory.createNode({gater}) → fresh libp2p node
 *   4. node.start() — bind TCP ephemeral port
 *   5. Insert SQLite row status='active'
 *   6. Log session.node.created
 *   7. Add to activeNodes map
 *   8. Return {ok:true, peerId, addrs}
 *   On libp2p error: extract error.message (never ${error}), log create.failed, return error
 *
 * acceptSession(sessionId, agentName, counterpartyPubkey, initiatorPeerId, correlationId):
 *   Pseudocode:
 *   1. If !standingReceiverReady → return standing_receiver_unavailable
 *   2. Take standing receiver from slot (clear slot atomically)
 *   3. gater.setAllowedPeer(initiatorPeerId) ← BEFORE returning multiaddr (AC-015)
 *   4. Insert SQLite row status='active'
 *   5. Log session.node.created
 *   6. Add to activeNodes map
 *   7. Trigger async replacement of standing receiver (do NOT await)
 *   8. Return {ok:true, peerId, addrs}
 *
 * destroySessionNode(sessionId, reason):
 *   Pseudocode:
 *   1. Find node in activeNodes
 *   2. stop node
 *   3. Update SQLite status to sealed/interrupted/error
 *   4. Remove from activeNodes
 *   5. Log session.node.destroyed
 *
 * gracefulShutdown():
 *   Pseudocode:
 *   1. Get all activeNodes
 *   2. For each: update SQLite 'interrupted', log destroyed(reason:'interrupted')
 *   3. Stop all nodes
 *   4. Stop standing receiver
 *
 * getStatus(): { standingReceiverReady: boolean }
 */

// CELLO-M7-PERSIST-002 (DEC-1): the daemon DB is a SQLCipher database (whole-file AES-256 at rest).
// `DaemonDatabase` is the thin varargs surface the daemon uses; `openEncryptedDatabase` opens with a
// PRAGMA key and `resolveDbKey` manages the single plaintext key file (DEC-2). The whole-DB cipher
// supersedes the old per-column transcript cipher (AC-010).
import {
  type DaemonDatabase,
  openEncryptedDatabase,
  resolveDbKey,
  dbKeyPathFor,
} from "./sqlcipher-db.js";
import { migrateToEncryptedIfNeeded } from "./identity-migration.js";
import { ensureIdentitySchema } from "./db-identity-store.js";
import { randomUUID, createHash } from "node:crypto";
import * as lp from "it-length-prefixed";
import { decode, Encoder } from "cbor-x";
import type { Stream } from "@libp2p/interface";
import type { Logger, SessionRecord } from "./types.js";
import { MAX_SESSION_NODES, STANDING_RECEIVER_AGENT_NAME } from "./types.js";
import { SessionConnectionGater } from "./session-connection-gater.js";
import { SessionTree, type SessionTreeLeafKind } from "./session-tree.js";
import { CELLO_CONTENT_PROTOCOL_ID, NodeAutoNatService, type CelloNode, type IAutoNatService } from "@cello-protocol/transport";
import type { KeyProvider } from "@cello-protocol/crypto";
import { verify } from "@cello-protocol/crypto";
import { encodeSealPayload } from "@cello-protocol/protocol-types";
import { AgentRelayClient, LEAF_KIND_CTRL, type RelayAssignmentCarry } from "./session-relay-client.js";
import { RelayReceiptStore, type RelayReceipt } from "./relay-receipt-store.js";
import { SessionSealLeafStore, type SealCarryLeaf } from "./session-seal-leaf-store.js";

const CBOR_ENC = new Encoder({ tagUint8Array: false });

/**
 * M7 DOD-SPINE-6 / MSG-001-3b: the inputs a session node needs to connect to the relay
 * as the Structure-2 witness (relay endpoint from the FROST-signed assignment + the
 * agent's K_local identity + the 16-byte session id). Optional on node creation: when
 * absent (or connect fails), the session still works over the direct content path — the
 * relay just doesn't witness the leaf yet.
 */
export interface RelayConnectParams {
  relayPeerId: string;
  relayAddrs: string[];
  keyProvider: KeyProvider;
  senderPubkey: Uint8Array;
  sessionIdBytes: Uint8Array;
  /**
   * FED-OPTIONB-SETUP-001 (Option B): the directory-signed relay assignment the client presents to its
   * chosen relay (replaces the directory→relay dial). Absent for direct-mode and on the restart/persisted
   * reconnect path (the relay already recorded the session at first establishment) — the client then just
   * reconnects without re-recording.
   */
  assignment?: RelayAssignmentCarry;
}

// ─── Interfaces ───────────────────────────────────────────────────────────────

/**
 * Adapter interface for session node creation. Allows test injection of a
 * failing factory (AC-007) without touching the real libp2p stack.
 * The adapter pattern is mandatory per outline.md constraints.
 */
export interface ISessionNodeFactory {
  createNode(config: SessionNodeConfig): Promise<CelloNode>;
}

export interface SessionNodeConfig {
  sessionId: string;
  connectionGater?: SessionConnectionGater;
  /**
   * CELLO-M7-TRANSPORT-001: role of the node, forwarded to createNode to tune the
   * libp2p service set (dcutr is included for 'session' dialers, omitted for the
   * 'standing_receiver'). AutoNAT is present for both.
   */
  nodeType?: "session" | "standing_receiver";
  /**
   * M7-SESSION-003 (AC-005): keepalive ping interval for the session node so a
   * counterparty that vanishes without a clean close is detected within a bounded
   * window. Factories should forward this to createNode({ keepAliveIntervalMs }).
   */
  keepAliveIntervalMs?: number;
}

// ─── Active session entry ─────────────────────────────────────────────────────

interface ActiveSessionEntry {
  node: CelloNode;
  agentName: string;
  /** DOD-LOOP-1: the bare session id (hex). The map key is composite (agentName, sessionId), so
   *  iteration/logging reads the real session id from here, not from the map key. */
  sessionId: string;
  counterpartyPubkey: string;
  gater: SessionConnectionGater;
  correlationId: string;
  /**
   * DAEMON-004: the counterparty's SESSION-layer Peer ID — the dial target for
   * the direct content stream (/cello/content/1.0.0). Set when the node is
   * created (outbound: the gater-allowed peer) or accepted (inbound: initiator).
   */
  counterpartySessionPeerId: string;
  /**
   * CELLO-M7-TRANSPORT-001: the AutoNAT service wrapping this session node. Emits
   * transport.autonat.result on each probe cycle; stopped when the node is torn
   * down so its node subscription is released.
   */
  autoNat: NodeAutoNatService;
  /**
   * M7 DOD-SPINE-6 / MSG-001-3b: the agent's shared relay witness client (one stream per
   * agent, multiplexing all that agent's sessions — the relay keys delivery by agent
   * pubkey). The leaf submit path uses it on cello_send. Absent when the relay is
   * unreachable — the direct content path still delivers.
   */
  relayClient?: AgentRelayClient;
  /** The 16-byte session id, for relay leaf submission (the relay frame carries it). */
  relaySessionIdBytes?: Uint8Array;
  /** The `#relayClients` map key (agentName + relay peer id) — federation-safe teardown. */
  relayClientKey?: string;
  /**
   * MSG-001-3b (2b): the session's relay endpoint (peer id + addrs) from the FROST assignment.
   * Held so the content-park backstop can deposit to the SAME relay this session is witnessed by
   * when direct delivery fails. In-memory only (not persisted — the startup-flush park is the
   * separate schema concern; this live park has the endpoint in hand).
   */
  relayPeerId?: string;
  relayAddrs?: string[];
}

/** DAEMON-004: a piece of content received and verified, awaiting cello_receive. */
interface ReceivedContentEntry {
  contentHex: string;
  senderPubkey: string;
  sequenceNumber: number;
}

// ─── Result types ─────────────────────────────────────────────────────────────

type CreateSessionResult =
  | { ok: true; peerId: string; addrs: string[] }
  | { ok: false; reason: string; guidance: string };

// ─── SessionNodeManager ───────────────────────────────────────────────────────

export class SessionNodeManager {
  readonly #factory: ISessionNodeFactory;
  readonly #logger: Logger;
  readonly #dbPath: string;
  #db: DaemonDatabase | null = null;
  /** RELAYSIG-1: shared immutable store of the relay's signed ordering-record receipts (keyed by agent). */
  #relayReceiptStore: RelayReceiptStore | null = null;
  /** FED-OPTIONB-SEAL-001: the per-session leaf log (both parties) carried at a unilateral seal. */
  #sealLeafStore: SessionSealLeafStore | null = null;
  #activeNodes = new Map<string, ActiveSessionEntry>();
  // M7 DOD-SPINE-6 / MSG-001-3b: ONE relay witness client per AGENT (keyed by agent name).
  // The relay authenticates and keys delivery by the agent's K_local pubkey, so all of an
  // agent's sessions share one authenticated relay stream (each frame carries session_id).
  #relayClients = new Map<string, AgentRelayClient>();
  // DOD-LOOP-1: the standing receiver is PER-AGENT, not per-daemon. A daemon hosting two agents
  // (the loopback case) needs each agent to have its OWN inbound receiver node — otherwise the
  // initiator (consuming its agent's standing receiver) and the responder (consuming its agent's)
  // would contend for a single node and thrash. Keyed by agentName. A creation-in-flight guard set
  // prevents two concurrent ensure() calls from building two nodes for the same agent.
  #standingReceivers = new Map<string, { node: CelloNode; gater: SessionConnectionGater; autoNat: NodeAutoNatService }>();
  #standingReceiverCreating = new Set<string>();
  // M8B F14: agents that SHOULD have a standing receiver — marked by
  // ensureStandingReceiverForAgent (cello_start_agent / the inbound accept path) and
  // unmarked by removeStandingReceiverForAgent (cello_stop_agent). Consulted by the
  // teardown re-arm so a session-node teardown never re-arms an offline agent.
  #agentsWantingReceiver = new Set<string>();
  // M8B F14: standing-receiver create retry schedule (see constructor opts).
  #srRetryDelaysMs: number[];
  // Agents whose removeStandingReceiverForAgent ran while an #ensureStandingReceiver for them was
  // in flight (parked on createNode/start, so the map had no entry to delete yet). The in-flight
  // ensure checks this after start() and tears the fresh node down instead of installing an SR for
  // an agent that has since gone offline (cello_stop_agent race). A fresh ensure clears it.
  #standingReceiverRemoving = new Set<string>();
  // Set once gracefulShutdown begins. The standing-receiver replacement that
  // acceptSession kicks off runs un-awaited (AC-003), so it can be in flight when
  // shutdown starts; #createStandingReceiver checks this flag and stops a freshly
  // built node instead of leaving an orphan bound to a TCP port (review M2).
  #shuttingDown = false;
  // DAEMON-004: lazily-loaded in-memory cache of each session's daemon-owned
  // Merkle tree. The authoritative store is the session_tree_leaves table —
  // the cache is rebuilt from it on first access (so it survives a restart).
  #trees = new Map<string, SessionTree>();
  // DAEMON-004: per-session FIFO buffer of verified received content awaiting
  // cello_receive. Populated by ingestReceivedContent / the content stream handler.
  #receivedContent = new Map<string, ReceivedContentEntry[]>();
  // F1-b: a terminal answer for a sealed session, set at seal teardown BEFORE the
  // received-content buffer is evicted. A blocking cello_receive waiting when the seal
  // fires returns this instead of hanging or 404ing; `unreadCount` tells the caller how
  // many buffered messages were dropped (still durable — read via cello_get_transcript).
  // This map is deliberately NOT cleared by #evictSessionCaches (it must outlive teardown);
  // it holds one tiny entry per sealed session for the daemon's lifetime and is cleared on
  // restart. Idempotent: a sealed session always answers "sealed" to a receive.
  #sessionTerminal = new Map<string, { type: "sealed"; unreadCount: number }>();
  // CELLO-M7-TRANSPORT-001: the directory-node multiaddrs serving as AutoNAT
  // probers (SI-002). Empty () => [] when the directory is in 'reconnecting'
  // state — AutoNAT cannot run and dialability stays the conservative default.
  readonly #autoNatProbers: () => string[];
  // M7-SESSION-003: per-session direct-path counterparty liveness, observed on the
  // session node's onPeerConnect ('alive') / onPeerDisconnect ('gone'). This is
  // the liveness authority for direct sessions — the unilateral-seal gate reads
  // it (relay sessions query the relay instead). NEVER the directory (SI-002).
  #sessionLiveness = new Map<string, "alive" | "gone">();
  // M7-UPGRADE-002: sessions whose content integrity could NOT be verified (a content_hash
  // mismatch = tamper was observed). The auto-acknowledge gate (SI-002) refuses to auto-co-sign
  // for a desynced session — B must never blind-sign a tail it cannot verify. Keyed by sessionId hex.
  #contentDesynced = new Set<string>();
  // DOD-MSG-4 (strict in-order): the RELAY is the ordering authority (Structure 2). For each
  // message the relay witnesses, it delivers B a (content_hash -> canonical sequence) binding via
  // the leaf_deliver stream. B records it here — keyed #k(agent,session) -> (contentHashHex -> seq)
  // — and orders its transcript by THIS, never by a sender-stamped field (sovereign-node: B does
  // not trust the counterparty for ordering). When B has no witness for an arriving hash
  // (relay-degraded), it falls back to arrival-order append.
  #witnessedSeq = new Map<string, Map<string, number>>();
  // DOD-MSG-4: out-of-order direct arrivals. A content frame whose canonical sequence is AHEAD of
  // the next expected leaf is HELD here (keyed #k(agent,session) -> (canonicalSeq -> entry)) instead
  // of being appended out of order. Once the missing in-between sequence(s) land (recovered from the
  // relay mailbox), #releaseHeld drains the held entries in canonical order. content is plaintext in
  // memory only — evicted on teardown, same as #receivedContent.
  #heldContent = new Map<string, Map<number, { content: Uint8Array; contentHashHex: string; correlationId?: string }>>();
  // DOD-MSG-4: the relay's high-water canonical sequence for this session — the largest sequence the
  // relay has witnessed (max over leaf_deliver). Keyed #k(agent,session). EXPOSED for the next
  // sub-increment (catch-up-before-live: on reconnect, hold live arrivals until the tree reaches this
  // so a fresh message can't append ahead of earlier ones still parked) — it is NOT yet consumed by
  // the gate, which today holds purely on the per-message `canonicalSeq > nextExpected` test.
  #highWaterSeq = new Map<string, number>();
  // M7-UPGRADE-002: sessions for which B has already submitted its responder SEAL leaf (via
  // auto-ack OR cello_close_session). Idempotency guard — A's SEAL ctrl leaf may be delivered
  // more than once (and the relay echoes leaves), so auto-ack fires AT MOST ONCE per session.
  // M8B FINDING-1: the value carries the first successful submit's reportedRootHex/sequenceNumber
  // (null while the submit is still in flight), so a RETRY close can escalate to a unilateral
  // seal with the original reported root instead of deadlocking on seal_pending_bilateral.
  #responderSealSubmitted = new Map<string, { reportedRootHex: string; sequenceNumber: number } | null>();
  // M7-SESSION-001 (M-1 PUSH): optional callback fired when a session changes
  // state, so the composition root can dispatch a session_state_changed
  // notification to live MCP clients. Injected via a setter AFTER construction
  // because the NotificationDispatcher is built later than this manager in
  // daemon.ts (it depends on the IPC server). Never required — when unset,
  // state changes are persisted and logged but no push notification is emitted.
  #onSessionStateChanged:
    | ((
        agentName: string,
        sessionId: string,
        state: string,
        counterpartyPubkey: string | null,
      ) => void)
    | null = null;

  // CELLO-M7-MSG-001 (AC-001/AC-002/AC-003): the send is no longer fire-and-forget.
  // After a content_frame is delivered over the direct session channel, the sender
  // arms a TTF timer and waits for an unsigned, transport-authenticated `persisted`
  // delivery ACK on the same /cello/content/1.0.0 protocol. A persisted ACK cancels
  // the timer (content.delivery.acked); TTF expiry hands the content to the park
  // backstop. Keyed sessionId → contentHashHex → entry.
  #awaitingAck = new Map<string, Map<string, { timer: ReturnType<typeof setTimeout>; content: Uint8Array; correlationId?: string; structure1Cbor?: Uint8Array; structure2Cbor?: Uint8Array }>>();
  // TTF (time-to-flush) for an un-acked content entry. Injectable so tests can drive
  // expiry deterministically; production default sits in the Part-4 proposed 10–30s band.
  #contentTtfMs = 20_000;
  // CELLO-M7-MSG-001: side-effect hooks the composition root wires to the durable
  // retry_queue (and, in 3b, the relay park deposit). Injected after construction
  // because RetryQueue is built later in daemon.ts. When unset, the awaiting-ACK timer
  // still fires and the ACK still resolves — only the durable crash-backstop is skipped.
  #onAwaitingPersisted: ((agentName: string, sessionId: string, contentHashHex: string) => void) | null = null;
  #onAwaitingTtf: ((agentName: string, sessionId: string, contentHashHex: string, content: Uint8Array) => void) | null = null;
  /**
   * MSG-001-3b (2b): the live content-park deposit. The manager resolves the recipient + relay
   * endpoint from the session entry and calls this when a send is NOT confirmed delivered
   * (direct-fail or TTF expiry). The daemon's hook seals (sealToRecipient) + deposits via
   * ContentParkClient. Best-effort.
   */
  #contentParkHook:
    | ((args: { sessionId: string; recipientPubkeyHex: string; relayPeerId: string; relayAddrs: readonly string[]; contentHashHex: string; content: Uint8Array; structure1Cbor?: Uint8Array; structure2Cbor?: Uint8Array }) => Promise<void>)
    | null = null;

  constructor(opts: {
    factory: ISessionNodeFactory;
    logger: Logger;
    dbPath: string;
    contentTtfMs?: number;
    /**
     * CELLO-M7-TRANSPORT-001: provider for the AutoNAT directory-node prober set
     * (SI-002). Defaults to () => [] (reconnecting — no probers), which makes
     * dialability the conservative default and fires transport.autonat.unavailable.
     */
    autoNatProbers?: () => string[];
    /**
     * M8B F14: backoff schedule for standing-receiver create retries. Attempt 1 runs
     * immediately; each entry is the delay before the next attempt. Default covers the
     * fixed-port race where a teardown and a re-arm interleave (EADDRINUSE clears once
     * the old node's port is released). Tests inject short delays or [] (no retries).
     */
    standingReceiverRetryDelaysMs?: number[];
  }) {
    this.#factory = opts.factory;
    this.#logger = opts.logger;
    this.#dbPath = opts.dbPath;
    if (typeof opts.contentTtfMs === "number" && opts.contentTtfMs > 0) {
      this.#contentTtfMs = opts.contentTtfMs;
    }
    this.#autoNatProbers = opts.autoNatProbers ?? (() => []);
    this.#srRetryDelaysMs = opts.standingReceiverRetryDelaysMs ?? [1_000, 5_000, 15_000];
  }

  /**
   * CELLO-M7-MSG-001: wire the durable-backstop side effects of the awaiting-ACK
   * lifecycle. `onPersisted` clears the durable retry_queue entry when a persisted ACK
   * arrives; `onTtf` records/parks the un-acked content when the TTF timer fires.
   * Injected by the composition root (daemon.ts) after the RetryQueue exists.
   */
  setAwaitingAckHooks(hooks: {
    onPersisted?: (agentName: string, sessionId: string, contentHashHex: string) => void;
    onTtf?: (agentName: string, sessionId: string, contentHashHex: string, content: Uint8Array) => void;
  }): void {
    this.#onAwaitingPersisted = hooks.onPersisted ?? null;
    this.#onAwaitingTtf = hooks.onTtf ?? null;
  }

  /**
   * MSG-001-3b (2b): inject the live content-park deposit (seal + ContentParkClient.deposit).
   * Injected by the composition root (daemon.ts). When absent, a not-confirmed send still records
   * the durable awaiting entry (crash backstop) but does not deposit live.
   */
  setContentParkHook(
    fn: (args: { sessionId: string; recipientPubkeyHex: string; relayPeerId: string; relayAddrs: readonly string[]; contentHashHex: string; content: Uint8Array; structure1Cbor?: Uint8Array; structure2Cbor?: Uint8Array }) => Promise<void>,
  ): void {
    this.#contentParkHook = fn;
  }

  /**
   * MSG-001-3b (2b): deposit un-confirmed content to the relay store-and-forward backstop — keyed
   * to the recipient, on the SAME relay this session is witnessed by — so an offline recipient
   * recovers it (at the sequence the witness already assigned, R1). Best-effort, never throws.
   */
  #parkContent(agentName: string, sessionId: string, contentHashHex: string, content: Uint8Array, structure1Cbor?: Uint8Array, structure2Cbor?: Uint8Array): void {
    const hook = this.#contentParkHook;
    const entry = this.#activeNodes.get(this.#k(agentName, sessionId));
    if (!hook || !entry || !entry.relayPeerId || !entry.relayAddrs) return;
    void hook({
      sessionId,
      recipientPubkeyHex: entry.counterpartyPubkey,
      relayPeerId: entry.relayPeerId,
      relayAddrs: entry.relayAddrs,
      contentHashHex,
      content,
      // DOD-MSG-4 (2b): carry the relay's signed ordering record so the parked entry is self-ordering
      // on recover too (sealed INTO the ciphertext envelope — INV-3: the relay still sees only ciphertext).
      structure1Cbor,
      structure2Cbor,
    }).catch((err: unknown) => {
      this.#logger.warn("content.park.deposit.failed", {
        sessionId,
        contentHash: contentHashHex,
        error: err instanceof Error ? err.message : String(err),
      });
    });
  }

  // ─── Initialization ──────────────────────────────────────────────────────

  async initialize(): Promise<void> {
    // Step 1: Open the SQLCipher database (DEC-1). The key is the single plaintext key file beside
    // the DB (DEC-2). Fail-closed (SI-002/AC-011): resolveDbKey refuses to mint a fresh key over an
    // existing DB, and openEncryptedDatabase throws db_encryption_key_mismatch on a wrong key — there
    // is no plaintext fallback. Whole-DB encryption supersedes the old per-column cipher (AC-010).
    // PERSIST-002 (AC-006): one-time migration of pre-story flat-file identity / a plaintext DB into
    // the encrypted store, BEFORE the key is resolved and the DB opened. A no-op on a fresh install
    // or an already-encrypted DB. Throws identity_migration_failed on a failed migration (DB-002).
    const migration = migrateToEncryptedIfNeeded(this.#dbPath, this.#logger);
    const dbKey = resolveDbKey(this.#dbPath, dbKeyPathFor(this.#dbPath));
    this.#db = openEncryptedDatabase(this.#dbPath, dbKey, this.#logger);
    this.#logger.info("persist.db.opened", { encrypted: true, migrated: migration.migrated });
    // PERSIST-002: the identity store (agents + manifest_state) lives in the same encrypted DB.
    ensureIdentitySchema(this.#db);
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT NOT NULL,
        agent_name TEXT NOT NULL,
        counterparty_pubkey TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        -- DOD-LOOP-1: composite key so two of the operator's agents can hold both ends of the
        -- SAME session_id on ONE daemon (the loopback case). A bare session_id PK would reject
        -- the second end's row.
        PRIMARY KEY (agent_name, session_id)
      )
    `);

    // M7-SESSION-001: idempotent schema extension — add message_count and interrupted_at
    // columns if they do not exist. ALTER TABLE IF NOT EXISTS COLUMN is not supported by
    // older SQLite; we use a try/catch per column as the idempotent approach.
    for (const ddl of [
      "ALTER TABLE sessions ADD COLUMN message_count INTEGER NOT NULL DEFAULT 0",
      "ALTER TABLE sessions ADD COLUMN interrupted_at TEXT",
      // MSG-001-3b (MSG-2 startup-flush): persist the session's relay endpoint so the
      // crash-backstop flush can deposit un-acked content after a restart, when the
      // in-memory entry is gone. relay_addrs is a JSON array of multiaddr strings.
      "ALTER TABLE sessions ADD COLUMN relay_peer_id TEXT",
      "ALTER TABLE sessions ADD COLUMN relay_addrs TEXT",
      // M7-SESSION-004 (AC-005): persist the seal certificate's legibility object with the
      // sealed record so it survives a daemon restart and is readable on the cert-read surface
      // (cello_get_sealed_receipt). JSON string with hex-encoded pubkeys; NULL until sealed.
      // Inline idempotent migration (NOT Flyway — this is the client-side SQLite, AC-011).
      "ALTER TABLE sessions ADD COLUMN seal_legibility TEXT",
      "ALTER TABLE sessions ADD COLUMN sealed_root_hex TEXT",
      // M7 legibility-TBS-binding (responder verify): the counterparty's FROST primary (group)
      // pubkey, taken from the FROST-signed SessionAssignment's signer_pubkey. The responder uses
      // it to VERIFY the bilateral seal signature locally (the seal is signed by the initiator's
      // primary), not just accept it. NULL when this party initiated (it uses its own primary).
      "ALTER TABLE sessions ADD COLUMN counterparty_primary_pubkey TEXT",
    ]) {
      try {
        this.#db.exec(ddl);
      } catch (err: unknown) {
        // Only swallow the idempotent "duplicate column name" case (the column
        // already exists from a prior init). Any other failure — disk full,
        // SQLITE_LOCKED, corruption — must propagate, otherwise the daemon would
        // run without these columns and later silently read undefined.
        const msg = err instanceof Error ? err.message : String(err);
        if (!msg.includes("duplicate column name")) throw err;
      }
    }

    // M7-SESSION-001 (H-1): side table holding the verified bilateral
    // SEAL-INTERRUPTED commitment artifacts. A side table (CREATE TABLE IF NOT
    // EXISTS) is inherently idempotent — no ALTER TABLE / duplicate-column
    // handling required. We keep BOTH parties' signed leaves and the agreed
    // Merkle root so the achieved commitment is never discarded.
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS seal_interrupted_artifacts (
        agent_name TEXT NOT NULL,
        session_id TEXT NOT NULL,
        role TEXT NOT NULL,
        own_leaf TEXT NOT NULL,
        counterparty_leaf TEXT NOT NULL,
        merkle_root TEXT NOT NULL,
        nonce TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        -- DOD-LOOP-1: composite key (per-agent end of a loopback session).
        PRIMARY KEY (agent_name, session_id)
      )
    `);

    // DAEMON-004 (AC-007 / SI-001): the daemon-owned per-session Merkle tree,
    // persisted as an ordered list of leaf hashes. The (session_id, leaf_index)
    // primary key enforces append-order uniqueness; a fresh daemon reconstructs
    // each tree from these rows so the transcript survives a restart. Querying
    // by session_id ORDER BY leaf_index is the only read pattern.
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS session_tree_leaves (
        agent_name TEXT NOT NULL,
        session_id TEXT NOT NULL,
        leaf_index INTEGER NOT NULL,
        leaf_kind TEXT NOT NULL,
        leaf_hash_hex TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        -- DOD-LOOP-1: composite key so each agent's end has its own append-ordered tree.
        PRIMARY KEY (agent_name, session_id, leaf_index)
      )
    `);

    // DOD-LOG-1 (PERSIST-LOG-001) / PERSIST-002 (AC-010): the durable, ENCRYPTED-at-rest readable
    // transcript. Each row is keyed by the canonical leaf `sequence`, so it JOINS to
    // session_tree_leaves(leaf_index) — a stored message is provably behind a committed hash-chain
    // leaf, not a loose dump. `blob` holds the readable plaintext bytes; encryption at rest is now
    // provided by whole-DB SQLCipher, not a per-column cipher (relay/directory never see it — INV-3).
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS transcript (
        agent_name TEXT NOT NULL,
        session_id TEXT NOT NULL,
        sequence INTEGER NOT NULL,
        direction TEXT NOT NULL,        -- 'sent' | 'received'
        blob BLOB NOT NULL,             -- readable plaintext bytes (whole-DB SQLCipher-encrypted at rest)
        created_at INTEGER NOT NULL,
        PRIMARY KEY (agent_name, session_id, sequence, direction)
      )
    `);

    // Step 2: Detect interrupted sessions (SIGKILL detection — AC-010).
    // Any 'active' row in a freshly-started daemon is a remnant of a prior
    // killed process. Batch-update to 'interrupted' before IPC opens.
    const activeRows = this.#db
      .prepare("SELECT * FROM sessions WHERE status = 'active'")
      .all() as unknown as SessionRecord[];

    if (activeRows.length > 0) {
      const now = Date.now();
      const interruptedAt = new Date(now).toISOString();
      for (const row of activeRows) {
        try {
          this.#db
            .prepare(
              "UPDATE sessions SET status = 'interrupted', updated_at = ?, interrupted_at = COALESCE(interrupted_at, ?) WHERE agent_name = ? AND session_id = ?",
            )
            .run(now, interruptedAt, row.agent_name, row.session_id);
          this.#logger.warn("session.interrupted.detected", {
            sessionId: row.session_id,
            agentName: row.agent_name,
            source: "daemon_restart",
          });
        } catch (err: unknown) {
          this.#logger.error("session.interrupt.db.write.failed", {
            sessionId: row.session_id,
            error: err instanceof Error ? err.message : String(err),
          });
        }
      }
    }

    // DOD-LOOP-1: standing receivers are now PER-AGENT, created when each agent comes online
    // (cello_start_agent → ensureStandingReceiverForAgent). No daemon-global receiver is created at
    // init (no agent is online yet). The initiate/accept paths kick off creation on demand if missing.
  }

  // ─── Public API ──────────────────────────────────────────────────────────

  /**
   * Get the underlying DatabaseSync handle.
   * Used by the composition root (daemon.ts) to pass to RetryQueue and
   * NonceDedupStore — they share the same SQLCipher DB file (DAEMON-003 AC-008).
   */
  /**
   * Get the underlying DaemonDatabase handle (the SQLCipher-backed adapter). Used by the
   * composition root (daemon.ts) to pass to RetryQueue and NonceDedupStore — they share the same
   * encrypted DB file.
   */
  getDb(): DaemonDatabase {
    if (!this.#db) {
      throw new Error("SessionNodeManager not initialized — call initialize() first");
    }
    return this.#db;
  }

  /**
   * RELAYSIG-1: the durably-stored, signature-verified relay ordering-record receipts for an agent
   * (optionally a single session). Empty when no receipts have been recorded yet. Read-only.
   */
  getRelayReceipts(agentPubkeyHex: string, sessionIdHex?: string): RelayReceipt[] {
    if (!this.#relayReceiptStore && this.#db) {
      this.#relayReceiptStore = new RelayReceiptStore(this.#db, this.#logger);
    }
    return this.#relayReceiptStore?.getAll(agentPubkeyHex, sessionIdHex) ?? [];
  }

  /**
   * FED-OPTIONB-SEAL-001: the complete ordered leaf chain (both parties) a UNILATERAL seal carries to the
   * directory for the OFFLINE tree rebuild. Empty when no leaves were logged (e.g. a direct-only session
   * with no relay witness) — the caller then has nothing to carry and the seal stays bilateral/pending.
   */
  getSealCarry(agentPubkeyHex: string, sessionIdHex: string): SealCarryLeaf[] {
    if (!this.#sealLeafStore && this.#db) {
      this.#sealLeafStore = new SessionSealLeafStore(this.#db, this.#logger);
    }
    return this.#sealLeafStore?.getCarry(agentPubkeyHex, sessionIdHex) ?? [];
  }

  /**
   * DOD-LOG-1 / PERSIST-002 (AC-010): append one readable message to the durable transcript, keyed
   * by the canonical leaf `sequence` so it joins to the committed hash chain. The blob is stored as
   * plaintext bytes — the whole DB is SQLCipher-encrypted at rest, so the per-column cipher is gone.
   * Idempotent on replay (INSERT OR IGNORE). Never throws into the caller's content path: a
   * transcript-write failure is logged, not fatal.
   */
  recordTranscriptMessage(
    agentName: string,
    sessionId: string,
    sequence: number,
    direction: "sent" | "received",
    plaintext: Uint8Array,
    correlationId?: string,
  ): void {
    if (!this.#db) return;
    try {
      const blob = Buffer.from(plaintext);
      this.#db
        .prepare(
          `INSERT OR IGNORE INTO transcript (agent_name, session_id, sequence, direction, blob, created_at)
           VALUES (?, ?, ?, ?, ?, ?)`,
        )
        .run(agentName, sessionId, sequence, direction, blob, Date.now());
      this.#logger.info("transcript.message.recorded", { sessionId, agentName, sequence, direction, correlationId });
    } catch (err: unknown) {
      this.#logger.warn("transcript.message.record.failed", {
        sessionId, agentName, sequence, direction,
        reason: err instanceof Error ? err.message : String(err),
        correlationId,
      });
    }
  }

  /**
   * DOD-LOG-1: read a session's durable transcript back (after a restart), decrypted and ordered by
   * canonical sequence then direction. A blob that fails to decrypt (tamper/wrong key) is skipped
   * with a loud log rather than crashing the read.
   */
  readTranscript(
    agentName: string,
    sessionId: string,
  ): { messages: Array<{ sequence: number; direction: "sent" | "received"; text: string; createdAt: number }>; undecryptable: number } {
    if (!this.#db) return { messages: [], undecryptable: 0 };
    const rows = this.#db
      .prepare(
        `SELECT sequence, direction, blob, created_at FROM transcript
         WHERE agent_name = ? AND session_id = ? ORDER BY sequence ASC, direction ASC`,
      )
      .all(agentName, sessionId) as Array<{ sequence: number; direction: string; blob: Uint8Array; created_at: number }>;
    const messages: Array<{ sequence: number; direction: "sent" | "received"; text: string; createdAt: number }> = [];
    // PERSIST-002 (AC-010): the blob is plaintext (whole-DB SQLCipher at rest), so there is no
    // per-row decrypt step that can fail — `undecryptable` stays 0 and is kept only for callers that
    // already read the field.
    for (const r of rows) {
      const blob = r.blob instanceof Uint8Array ? r.blob : new Uint8Array(r.blob);
      messages.push({
        sequence: r.sequence,
        direction: r.direction === "sent" ? "sent" : "received",
        text: new TextDecoder().decode(blob),
        createdAt: r.created_at,
      });
    }
    return { messages, undecryptable: 0 };
  }

  /** DOD-LOOP-1: whether the given agent has a standing receiver ready (any agent if omitted). */
  getStandingReceiverReady(agentName?: string): boolean {
    if (agentName !== undefined) return this.#standingReceivers.has(agentName);
    return this.#standingReceivers.size > 0;
  }

  /** First ready standing receiver (any agent) — for agent-agnostic OUTBOUND use (gater-open). */
  #anyStandingReceiver(): { node: CelloNode; gater: SessionConnectionGater; autoNat: NodeAutoNatService } | null {
    for (const sr of this.#standingReceivers.values()) return sr;
    return null;
  }

  /**
   * The current standing receiver node's session-transport coordinates (peer id +
   * listen multiaddrs), or null if it is not ready. These are the addresses a local
   * SessionNegotiator advertises as this node's counterparty endpoint so the initiator
   * can dial it, and the value an inbound session_assignment carries in its
   * counterparty_session_* fields. Read-only — does NOT consume the standing receiver
   * (unlike acceptSession, which hands it off).
   */
  getStandingReceiverInfo(agentName: string): { peerId: string; addrs: string[] } | null {
    // DOD-LOOP-1: the initiator advertises ITS OWN agent's standing receiver, which it then reuses
    // as the session node — so the advertised endpoint matches the node the counterparty dials.
    const sr = this.#standingReceivers.get(agentName);
    if (!sr) return null;
    return { peerId: sr.node.getPeerId(), addrs: sr.node.listenAddresses() };
  }

  /**
   * The standing receiver's libp2p node — a general-purpose, OPEN-gater node usable for
   * OUTBOUND dials that are not session-scoped (e.g. the content-park deposit/pull to the
   * relay, MSG-001-3b). Session nodes have restrictive gaters; the standing receiver does not.
   * Returns null until the receiver is ready.
   */
  getStandingReceiverNode(agentName?: string): CelloNode | null {
    // With an agentName: that agent's own standing-receiver node (needed when the dial must
    // originate from a SPECIFIC agent — e.g. the startup content-park re-park, where the
    // depositor is the original sender). Without one: any ready standing receiver (outbound
    // content-park deposit/pull to the relay — open gater, not session-scoped).
    if (agentName !== undefined) return this.#standingReceivers.get(agentName)?.node ?? null;
    return this.#anyStandingReceiver()?.node ?? null;
  }

  /**
   * The libp2p Peer ID of an active session's node (N_A for an initiated session), or
   * null if no active node exists for it. This is the initiator's session peer id that an
   * inbound session_assignment must carry to the counterparty (so the counterparty gates
   * its handed-off receiver to it). Read-only.
   */
  getSessionNodePeerId(agentName: string, sessionId: string): string | null {
    return this.#activeNodes.get(this.#k(agentName, sessionId))?.node.getPeerId() ?? null;
  }

  /**
   * CELLO-M7-TRANSPORT-001: the AutoNAT service wrapping the current standing
   * receiver node, or null if the standing receiver is not ready. The composition
   * root uses this as the daemon's runtime IAutoNatService — its getDialability()
   * drives the SessionAssignment advertised address (AC-004/AC-019), and it is the
   * source of the transport.autonat.result / transport.autonat.unavailable events.
   */
  getStandingReceiverAutoNat(): IAutoNatService | null {
    // DOD-LOOP-1: the daemon-level autonat source is any ready standing receiver; null until one
    // exists (the composition root falls back to LocalAutoNatStub). Per-session advertised dialability
    // comes from the initiating agent's own SR via getStandingReceiverInfo, not this daemon-level value.
    return this.#anyStandingReceiver()?.autoNat ?? null;
  }

  /**
   * M7-SESSION-001 (M-1 PUSH): register the session-state-change callback.
   * Called by the composition root (daemon.ts) after the NotificationDispatcher
   * exists. Setter injection avoids a construction-order/circular dependency.
   */
  setOnSessionStateChanged(
    cb: (
      agentName: string,
      sessionId: string,
      state: string,
      counterpartyPubkey: string | null,
    ) => void,
  ): void {
    this.#onSessionStateChanged = cb;
  }

  /**
   * DOD-LOOP-1: the session core is keyed by (agentName, sessionId), NOT sessionId alone. Two of
   * the operator's own agents (the loopback case) can hold the two ends of the SAME session_id on
   * ONE daemon, so a bare session_id is ambiguous between them. This composite string key — the
   * agent name and the hex session id joined by a 0x1f unit separator (which appears in neither) —
   * is the key for every in-memory session-core map (#activeNodes, #trees, #receivedContent,
   * #sessionLiveness, #contentDesynced, #responderSealSubmitted, #awaitingAck). #relayClients is
   * already per-agent (its own key), and the standing receivers are keyed by agent name directly.
   */
  #k(agentName: string, sessionId: string): string {
    return `${agentName}\x1f${sessionId}`;
  }

  /**
   * Create a new outbound session node.
   * Called during cello_initiate_session.
   *
   * @param sessionId      Unique session ID (hex string)
   * @param agentName      Name of the initiating agent
   * @param counterpartyPubkey  Counterparty's K_local public key (hex)
   * @param counterpartyPeerId  Counterparty's session-layer Peer ID (for gater)
   * @param correlationId  Correlation ID minted at session initiation
   */
  async createSessionNode(
    sessionId: string,
    agentName: string,
    counterpartyPubkey: string,
    counterpartyPeerId: string,
    correlationId: string,
    reuseStandingReceiver = false,
    relay?: RelayConnectParams,
  ): Promise<CreateSessionResult> {
    // Cap enforcement (AC-006)
    if (this.#activeNodes.size >= MAX_SESSION_NODES) {
      this.#logger.warn("session.node.cap.reached", {
        agentName,
        currentCount: this.#activeNodes.size,
        maxCount: MAX_SESSION_NODES,
      });
      return {
        ok: false,
        reason: "max_sessions_reached",
        guidance:
          "The daemon has reached its maximum of 32 concurrent session nodes. " +
          "Close an existing session before starting a new one.",
      };
    }

    // The session node N_A: either a FRESH ephemeral node (default), or — for the initiator
    // path (reuseStandingReceiver) — the standing receiver handed off as the session node. The
    // latter makes N_A's peer id equal the SESSION endpoint the initiator ADVERTISED to the
    // directory (its standing receiver), so the counterparty's connection gater (set to that
    // advertised peer id) admits N_A's dial. Mirrors acceptSession, which already hands off the
    // standing receiver on the receiver side. WIRE-001/INV-5: a fully-fresh ephemeral initiator
    // node would require advertising N_A's peer id pre-negotiation (a session-node lifecycle
    // split); the symmetric standing-receiver handoff is the consistent interim model.
    let node: CelloNode;
    let gater: SessionConnectionGater;
    let autoNat: NodeAutoNatService;
    if (reuseStandingReceiver) {
      const sr = this.#standingReceivers.get(agentName);
      if (!sr) {
        // DOD-LOOP-1: this agent has no standing receiver ready — kick off (idempotent) creation
        // so a retry finds it, and report unavailable. Per-agent, so the initiator consuming its
        // OWN agent's receiver never contends with a co-resident responder agent (the loopback case).
        void this.#ensureStandingReceiver(agentName, correlationId);
        return {
          ok: false,
          reason: "standing_receiver_unavailable",
          guidance: "The standing receiver node is initializing (completes within 200ms). Retry the session in a moment.",
        };
      }
      ({ node, gater, autoNat } = sr);
      gater.setAllowedPeer(counterpartyPeerId);
      // Hand this agent's standing receiver off to this session; a replacement is spun up below.
      this.#standingReceivers.delete(agentName);
    } else {
      gater = new SessionConnectionGater({
        sessionId,
        allowedPeerId: counterpartyPeerId,
        logger: this.#logger,
      });
      try {
        node = await this.#factory.createNode({ sessionId, connectionGater: gater, nodeType: "session" });
        await node.start();
      } catch (err: unknown) {
        const errorMessage = err instanceof Error ? err.message : String(err);
        this.#logger.error("session.node.create.failed", {
          sessionId,
          agentName,
          error: errorMessage,
          correlationId,
        });
        return {
          ok: false,
          reason: "session_node_creation_failed",
          guidance:
            "Failed to create session transport node. The daemon logged the cause in " +
            "session.node.create.failed. Check that the system has available ports and sufficient memory.",
        };
      }
      // CELLO-M7-TRANSPORT-001: session nodes also need dialability awareness for the
      // dcutr decision path (AC-002). Wrap the node in a NodeAutoNatService and emit
      // its initial result (nodeType: 'session').
      autoNat = new NodeAutoNatService({
        node,
        logger: this.#logger,
        nodeType: "session",
        probers: this.#autoNatProbers(),
      });
      autoNat.emitInitialResult();
    }

    const peerId = node.getPeerId();
    const addrs = node.listenAddresses();

    // Persist to SQLite
    this.#insertSessionRow(sessionId, agentName, counterpartyPubkey, "active");

    // Log observability event (session.node.created)
    this.#logger.info("session.node.created", {
      sessionId,
      agentName,
      sessionPeerId: peerId,
      correlationId,
    });

    // Add to active map (keyed by (agentName, sessionId) — DOD-LOOP-1)
    this.#activeNodes.set(this.#k(agentName, sessionId), {
      node,
      agentName,
      sessionId,
      counterpartyPubkey,
      gater,
      correlationId,
      counterpartySessionPeerId: counterpartyPeerId,
      autoNat,
    });

    // DAEMON-004: register the content stream handler so inbound content_frames
    // are cross-checked, appended to the daemon-owned tree, and buffered.
    await this.#registerContentHandler(agentName, sessionId, node, counterpartyPubkey);
    // M7-SESSION-003 AC-004: act on the session node's peer events for direct-path
    // liveness. The session connection IS the authority for a direct session.
    this.#wireSessionLiveness(agentName, sessionId, node, counterpartyPubkey, correlationId);

    // M7 DOD-SPINE-6 / MSG-001-3b: connect this session node to the relay as the
    // Structure-2 witness (non-fatal — direct content still works without it).
    if (relay) {
      await this.#connectSessionRelay(sessionId, node, agentName, relay, correlationId);
    }

    // If we consumed this agent's standing receiver, spin up a replacement (async — do NOT await).
    if (reuseStandingReceiver) {
      void this.#ensureStandingReceiver(agentName, correlationId);
    }

    return { ok: true, peerId, addrs };
  }

  /**
   * M7 DOD-SPINE-6 / MSG-001-3b: connect a session node to the relay witness and
   * store the client on the active entry. Best-effort: a connect/auth failure logs
   * and leaves relayClient undefined — the session is NOT destroyed and the direct
   * content path keeps working (the relay-park/recovery path is MSG-001-3b's domain).
   */
  async #connectSessionRelay(
    sessionId: string,
    node: CelloNode,
    agentName: string,
    relay: RelayConnectParams,
    correlationId: string,
  ): Promise<void> {
    try {
      // The session node's gater admits only the counterparty; the relay witness is a
      // third peer. Permit it OUTBOUND so the dial isn't denied — inbound stays
      // counterparty-only (INV-5). The relay peer id comes from the signed assignment.
      this.#activeNodes.get(this.#k(agentName, sessionId))?.gater.setAllowedOutboundPeer(relay.relayPeerId);

      // One relay client per (AGENT, RELAY NODE). The relay keys by agent pubkey, so the
      // collision H1 addresses is per relay; CELLO is federated, so a different session for
      // the same agent may be assigned a DIFFERENT relay — that needs its own client.
      const clientKey = `${agentName}::${relay.relayPeerId}`;
      let client = this.#relayClients.get(clientKey);
      if (!client) {
        // RELAYSIG-1: one shared receipt store (keyed by agent_pubkey, so a single instance serves all
        // agents + relays). Lazy — the encrypted DB is open by the time sessions are active.
        if (!this.#relayReceiptStore && this.#db) {
          this.#relayReceiptStore = new RelayReceiptStore(this.#db, this.#logger);
        }
        // FED-OPTIONB-SEAL-001: one shared seal-leaf log (keyed by agent_pubkey), same lazy lifecycle.
        if (!this.#sealLeafStore && this.#db) {
          this.#sealLeafStore = new SessionSealLeafStore(this.#db, this.#logger);
        }
        client = new AgentRelayClient({
          relayPeerId: relay.relayPeerId,
          relayAddrs: relay.relayAddrs,
          keyProvider: relay.keyProvider,
          senderPubkey: relay.senderPubkey,
          logger: this.#logger,
          receiptStore: this.#relayReceiptStore ?? undefined,
          sealLeafStore: this.#sealLeafStore ?? undefined,
        });
        this.#relayClients.set(clientKey, client);
      }
      const sessionIdHexForRelay = Buffer.from(relay.sessionIdBytes).toString("hex");
      client.registerSession(sessionIdHexForRelay, node, (frame) => {
        // The counterparty's witnessed leaf arrived with its canonical sequence. The
        // plaintext is delivered separately over the direct content stream; this is the
        // ordering/witness signal. Full canonical-sequence reconciliation against the
        // local tree is MSG-001-3b (J-CONTENT).
        this.#logger.info("session.relay.leaf.delivered", {
          sessionId,
          sequenceNumber: frame.sequence_number,
          leafKind: frame.leaf_kind,
          correlationId,
        });
        // DOD-MSG-4 (strict in-order): record the relay-witnessed canonical sequence for the
        // counterparty's MSG leaves. The relay is the ordering authority; structure1_cbor =
        // [1, content_hash(32), sender_pubkey, session_id, last_seen_seq, ts]. The relay sequence
        // is 1-based and global per session; the daemon tree is 0-based — normalize with -1. Only
        // COUNTERPARTY leaves (the ones B will ingest); our own echoed leaf already lands via the
        // send path. The gate (ingestReceivedContent) reads this map to hold out-of-order arrivals.
        if (!frame.authored_by_us && frame.leaf_kind !== LEAF_KIND_CTRL) {
          try {
            const s1 = decode(frame.structure1_cbor) as unknown[];
            const contentHash = s1?.[1];
            if (contentHash instanceof Uint8Array && frame.sequence_number > 0) {
              this.recordWitnessedSequence(
                agentName,
                sessionId,
                Buffer.from(contentHash).toString("hex"),
                frame.sequence_number - 1,
              );
            }
          } catch (err: unknown) {
            this.#logger.warn("session.relay.leaf.witness.decode.failed", {
              sessionId,
              error: err instanceof Error ? err.message : String(err),
              correlationId,
            });
          }
        }
        // M7-UPGRADE-002: auto-acknowledge close. When the COUNTERPARTY's SEAL ctrl leaf (0x02)
        // arrives and B has verified the content, B's OWN node auto-co-signs the responder SEAL
        // leaf — no agent prompt — so the bilateral seal completes promptly instead of degrading
        // to unilateral on a slow/busy/crashed agent. Never auto-ack our OWN echoed ctrl leaf.
        if (frame.leaf_kind === LEAF_KIND_CTRL && !frame.authored_by_us) {
          this.#maybeAutoAcknowledgeSeal(agentName, sessionId, correlationId);
        }
      }, relay.assignment);

      const entry = this.#activeNodes.get(this.#k(agentName, sessionId));
      if (entry) {
        entry.relayClient = client;
        entry.relaySessionIdBytes = relay.sessionIdBytes;
        entry.relayClientKey = clientKey;
        // 2b: remember the relay endpoint so the content-park backstop deposits to the SAME relay.
        entry.relayPeerId = relay.relayPeerId;
        entry.relayAddrs = relay.relayAddrs;
        // MSG-2 startup-flush: also PERSIST it, so a restart's crash-backstop flush (which runs
        // before the in-memory entry exists) can deposit un-acked content to the same relay.
        try {
          this.#db
            ?.prepare("UPDATE sessions SET relay_peer_id = ?, relay_addrs = ?, updated_at = ? WHERE agent_name = ? AND session_id = ?")
            .run(relay.relayPeerId, JSON.stringify(relay.relayAddrs), Date.now(), agentName, sessionId);
        } catch (err: unknown) {
          this.#logger.warn("session.relay.endpoint.persist.failed", {
            sessionId,
            error: err instanceof Error ? err.message : String(err),
          });
        }
      } else {
        // The session was torn down while we were wiring — undo the registration.
        client.unregisterSession(sessionIdHexForRelay);
        if (!client.hasSessions() && this.#relayClients.get(clientKey) === client) {
          client.close();
          this.#relayClients.delete(clientKey);
        }
        return;
      }

      // Proactively connect so the relay has this agent's stream to deliver leaves to
      // (the RECEIVER must be connected before the counterparty submits). Best-effort.
      await client.connect(node);
    } catch (err: unknown) {
      this.#logger.warn("session.relay.connect.error", {
        sessionId,
        error: err instanceof Error ? err.message : String(err),
        correlationId,
      });
    }
  }

  /**
   * M7 DOD-SPINE-6 / MSG-001-3b: detach a session from its (agent, relay) client and
   * close the client when it has no remaining sessions. Idempotent and identity-guarded:
   * the map delete only fires if the map still holds THIS client (a racing teardown of a
   * sibling session must not close a freshly-created replacement client for the same key).
   */
  #detachSessionRelay(entry: ActiveSessionEntry): void {
    const client = entry.relayClient;
    const key = entry.relayClientKey;
    if (!client || !entry.relaySessionIdBytes) return;
    // Idempotent: clear the entry's reference so a second teardown of the same entry no-ops.
    entry.relayClient = undefined;
    const sidHex = Buffer.from(entry.relaySessionIdBytes).toString("hex");
    client.unregisterSession(sidHex);
    if (!client.hasSessions() && key && this.#relayClients.get(key) === client) {
      client.close();
      this.#relayClients.delete(key);
    }
  }

  /**
   * M7-SESSION-003 AC-004: wire a session node's peer-connect / peer-disconnect
   * events to per-session direct-path liveness. onPeerConnect → 'alive'; the
   * session node's gater restricts connections to the designated counterparty, so
   * a connect/disconnect on this node is the counterparty's session-path liveness.
   * onPeerDisconnect → 'gone' (the hook the client did not act on before),
   * emitting session.liveness.changed at WARN. Combined with the transport
   * keepalive (AC-005), a peer that vanished without a clean close still surfaces
   * a disconnect and drives 'gone'.
   */
  #wireSessionLiveness(
    agentName: string,
    sessionId: string,
    node: CelloNode,
    counterpartyPubkey: string,
    correlationId: string,
  ): void {
    const key = this.#k(agentName, sessionId);
    node.onPeerConnect(() => {
      const prior = this.#sessionLiveness.get(key);
      this.#sessionLiveness.set(key, "alive");
      if (prior !== "alive") {
        this.#logger.info("session.liveness.changed", {
          sessionId,
          counterpartyPubkey,
          transportPath: "direct",
          liveness: "alive",
          observedBy: "session_node",
          correlationId,
        });
      }
    });
    node.onPeerDisconnect(() => {
      const prior = this.#sessionLiveness.get(key);
      this.#sessionLiveness.set(key, "gone");
      if (prior !== "gone") {
        this.#logger.warn("session.liveness.changed", {
          sessionId,
          counterpartyPubkey,
          transportPath: "direct",
          liveness: "gone",
          observedBy: "session_node",
          correlationId,
        });
      }
    });
  }

  /**
   * M7-SESSION-003: read the direct-path counterparty liveness for a session.
   * 'unknown' when no session node observation has occurred yet.
   */
  getSessionLiveness(agentName: string, sessionId: string): "alive" | "gone" | "unknown" {
    return this.#sessionLiveness.get(this.#k(agentName, sessionId)) ?? "unknown";
  }

  /**
   * Hand the standing receiver to an inbound session.
   * Called during cello_await_session.
   *
   * CRITICAL (AC-015): gater.setAllowedPeer() is called BEFORE returning
   * the node's multiaddr to the caller. This closes the window where an
   * unexpected peer could connect during the hand-off.
   */
  async acceptSession(
    sessionId: string,
    agentName: string,
    counterpartyPubkey: string,
    initiatorPeerId: string,
    correlationId: string,
    relay?: RelayConnectParams,
  ): Promise<CreateSessionResult> {
    const inboundSr = this.#standingReceivers.get(agentName);
    if (!inboundSr) {
      // DOD-LOOP-1: per-agent — kick off (idempotent) creation so a retry finds it.
      void this.#ensureStandingReceiver(agentName, correlationId);
      return {
        ok: false,
        reason: "standing_receiver_unavailable",
        guidance:
          "The standing receiver node is initializing (completes within 200ms). " +
          "Retry cello_await_session in a moment.",
      };
    }

    // Cap enforcement — inbound sessions count against the same limit (AC-006)
    if (this.#activeNodes.size >= MAX_SESSION_NODES) {
      this.#logger.warn("session.node.cap.reached", {
        agentName,
        currentCount: this.#activeNodes.size,
        maxCount: MAX_SESSION_NODES,
      });
      return {
        ok: false,
        reason: "max_sessions_reached",
        guidance:
          "The daemon has reached its maximum of 32 concurrent session nodes. " +
          "Close an existing session before starting a new one.",
      };
    }

    const { node, gater, autoNat } = inboundSr;

    // AC-015: update gater BEFORE retrieving multiaddr / returning to caller
    gater.setAllowedPeer(initiatorPeerId);

    const peerId = node.getPeerId();
    const addrs = node.listenAddresses();

    // Persist to SQLite
    this.#insertSessionRow(sessionId, agentName, counterpartyPubkey, "active");

    // Log observability event
    this.#logger.info("session.node.created", {
      sessionId,
      agentName,
      sessionPeerId: peerId,
      correlationId,
    });

    // Remove this agent's standing receiver from the slot and add to active map. The handed-off
    // node keeps its AutoNAT service (it continues to surface dialability).
    this.#standingReceivers.delete(agentName);
    this.#activeNodes.set(this.#k(agentName, sessionId), {
      node,
      agentName,
      sessionId,
      counterpartyPubkey,
      gater,
      correlationId,
      counterpartySessionPeerId: initiatorPeerId,
      autoNat,
    });

    // DAEMON-004: register the content stream handler for the inbound session.
    await this.#registerContentHandler(agentName, sessionId, node, counterpartyPubkey);
    // M7-SESSION-003 AC-004: act on the inbound session node's peer events too.
    this.#wireSessionLiveness(agentName, sessionId, node, counterpartyPubkey, correlationId);

    // M7 DOD-SPINE-6 / MSG-001-3b: the receiver also connects to the relay witness so
    // the relay can deliver the initiator's witnessed leaves (leaf_deliver) to it.
    if (relay) {
      await this.#connectSessionRelay(sessionId, node, agentName, relay, correlationId);
    }

    // Immediately spin up a replacement for THIS agent (async — do NOT await, AC-003)
    void this.#ensureStandingReceiver(agentName, correlationId);

    return { ok: true, peerId, addrs };
  }

  /**
   * Destroy a session node after seal or on error teardown.
   * Status written to SQLite.
   */
  async destroySessionNode(
    agentName: string,
    sessionId: string,
    reason: "sealed" | "interrupted" | "error",
  ): Promise<void> {
    // F1-b: record the terminal answer BEFORE the caches are evicted (and before the
    // early-return below), so a blocking cello_receive that was waiting when the seal fired
    // returns "session_sealed" (with how many buffered messages it never read) instead of
    // hanging to timeout or 404ing. Set even if the node was already retired — a late receive
    // on a sealed session should always learn it is sealed. The receiver (the party that races
    // the seal on cello_receive) is torn down through THIS path; the closer goes through
    // retireSessionNode and is not blocking on receive.
    if (reason === "sealed") {
      const tkey = this.#k(agentName, sessionId);
      const unreadCount = this.#receivedContent.get(tkey)?.length ?? 0;
      this.#sessionTerminal.set(tkey, { type: "sealed", unreadCount });
    }
    const entry = this.#activeNodes.get(this.#k(agentName, sessionId));
    if (!entry) return;

    entry.autoNat.stop();
    // M7 DOD-SPINE-6 / MSG-001-3b: close the relay witness stream so we don't leak it.
    this.#detachSessionRelay(entry);
    try {
      await entry.node.stop();
    } catch (err: unknown) {
      this.#logger.error("session.node.stop.failed", {
        sessionId,
        agentName: entry.agentName,
        error: err instanceof Error ? err.message : String(err),
        correlationId: entry.correlationId,
      });
      // Fall through — still remove from active map and update DB
    }

    // Update SQLite — 'sealed' → 'sealed', 'interrupted'/'error' → 'interrupted'.
    // 'error' is not a valid SessionStatus in SQLite; error-torn-down sessions
    // surface as interrupted so AC-010 recovery handles them at next login.
    // The session.node.destroyed log preserves the original reason for observability.
    const dbStatus = reason === "sealed" ? "sealed" : "interrupted";
    this.#updateSessionStatus(agentName, sessionId, dbStatus);

    this.#activeNodes.delete(this.#k(agentName, sessionId));
    // Evict the in-memory per-session caches on teardown. The tree is durable in
    // SQLite (getSessionTree reloads it on demand), and the received-content buffer
    // holds plaintext that must not linger after a session ends. Without this, both
    // maps grow unbounded by total sessions seen over a long-lived daemon.
    // (#evictSessionCaches also drops the M7-SESSION-003 liveness flag, so both the
    // destroy and retire teardown paths clear it — no stale verdict survives.)
    this.#evictSessionCaches(agentName, sessionId);

    this.#logger.info("session.node.destroyed", {
      sessionId,
      agentName: entry.agentName,
      reason,
    });

    // M8B F14 (fix 1): the torn-down node has just released its port — on a fixed-port
    // deployment this is the FIRST moment a previously-failed re-arm can succeed. Re-arm
    // the standing receiver for an online agent that has none (async, never awaited).
    this.#rearmAfterTeardown(agentName);
  }

  /**
   * M8B F14: re-arm an online agent's standing receiver after a session-node teardown
   * freed resources (notably the fixed port). No-op when the agent is offline, already
   * has a receiver, or one is being created. The re-arm is a NEW async flow — it mints
   * its own correlationId (via the ensure default) rather than inheriting the torn-down
   * session's.
   */
  #rearmAfterTeardown(agentName: string): void {
    if (this.#shuttingDown) return;
    if (!this.#agentsWantingReceiver.has(agentName)) return;
    if (this.#standingReceivers.has(agentName) || this.#standingReceiverCreating.has(agentName)) return;
    void this.#ensureStandingReceiver(agentName);
  }

  /**
   * round-2 finding #5: retire a session's live libp2p node WITHOUT changing its
   * DB status. Used after the active-session bilateral seal commitment has already
   * advanced the row to 'seal_interrupted_pending': the session is frozen, so we
   * stop the node and unregister its /cello/content handler (no more inbound leaves,
   * no leaked node per active close) but must NOT overwrite the pending/sealed status
   * the way destroySessionNode would. The durable tree stays in SQLite (getSessionTree
   * reloads it); the in-memory plaintext buffer is evicted.
   */
  async retireSessionNode(agentName: string, sessionId: string): Promise<void> {
    const entry = this.#activeNodes.get(this.#k(agentName, sessionId));
    if (!entry) return;
    this.#detachSessionRelay(entry);
    try {
      await entry.node.stop();
    } catch (err: unknown) {
      this.#logger.error("session.node.stop.failed", {
        sessionId,
        agentName: entry.agentName,
        error: err instanceof Error ? err.message : String(err),
        correlationId: entry.correlationId,
      });
      // Fall through — still remove from active map.
    }
    this.#activeNodes.delete(this.#k(agentName, sessionId));
    this.#evictSessionCaches(agentName, sessionId);
    this.#logger.info("session.node.destroyed", {
      sessionId,
      agentName: entry.agentName,
      reason: "sealing",
    });
    // M8B F14 (fix 1): same re-arm point as destroySessionNode — the retired node freed its port.
    this.#rearmAfterTeardown(agentName);
  }

  /** Drop the in-memory tree + received-content caches for a torn-down session (DOD-LOOP-1: per (agent, session)). */
  #evictSessionCaches(agentName: string, sessionId: string): void {
    const key = this.#k(agentName, sessionId);
    // F1-c: dropping a NON-empty received-content buffer means deliverable plaintext the app
    // never read live is being discarded (still durable in the transcript). Make that silent
    // drop diagnosable — it fires on both the destroy (sealed) and retire (sealing) paths.
    const unreadCount = this.#receivedContent.get(key)?.length ?? 0;
    if (unreadCount > 0) {
      this.#logger.info("session.receive.buffer.evicted", { sessionId, agentName, unreadCount });
    }
    this.#trees.delete(key);
    this.#receivedContent.delete(key);
    // CELLO-M7-MSG-001: cancel any armed TTF timers so a torn-down session never
    // fires a park backstop (or keeps a timer) after it is gone.
    this.#clearAwaitingForSession(agentName, sessionId);
    // M7-SESSION-003: drop the direct-path liveness flag (the seal gate already read
    // its verdict) so a destroyed/retired session retains no stale alive/gone state.
    this.#sessionLiveness.delete(key);
    // M7-UPGRADE-002: drop the auto-acknowledge bookkeeping for a torn-down session.
    this.#contentDesynced.delete(key);
    this.#responderSealSubmitted.delete(key);
    // DOD-MSG-4: drop the strict-in-order bookkeeping (witness map, held plaintext, high-water)
    // so a torn-down session retains no stale ordering state or buffered plaintext.
    this.#witnessedSeq.delete(key);
    this.#heldContent.delete(key);
    this.#highWaterSeq.delete(key);
  }

  /**
   * Graceful shutdown: mark all active sessions as interrupted, stop all nodes.
   * Called from the SIGTERM / cello logout path (AC-009).
   * SQLite writes complete before this method returns.
   */
  async gracefulShutdown(): Promise<void> {
    // Signal any in-flight standing-receiver replacement to self-stop (review M2).
    this.#shuttingDown = true;

    // Cancel every armed awaiting-ACK timer so an un-acked send (e.g. a rejected /
    // tampered frame that never produced a `persisted` ACK) does not leave a 20s
    // timer pinning the content + this manager in memory past teardown (review M1).
    for (const bySession of this.#awaitingAck.values()) {
      for (const entry of bySession.values()) clearTimeout(entry.timer);
    }
    this.#awaitingAck.clear();

    // Mark ALL 'active' rows interrupted in SQLite — single batch UPDATE covers
    // both in-memory managed nodes AND any rows that were inserted directly
    // (e.g. by the binary AC-009 SIGTERM test inserting synthetic rows).
    // This is the authoritative persistence step; in-memory map is secondary.
    const now = Date.now();
    if (!this.#db) {
      this.#logger.error("session.interrupt.db.write.failed", {
        sessionId: "__all__",
        error: "db not initialized",
      });
    } else {
      const interruptedAt = new Date(now).toISOString();
      try {
        this.#db.prepare(
          "UPDATE sessions SET status = 'interrupted', updated_at = ?, interrupted_at = COALESCE(interrupted_at, ?) WHERE status = 'active'",
        ).run(now, interruptedAt);
      } catch (err: unknown) {
        this.#logger.error("session.interrupt.db.write.failed", {
          sessionId: "__all__",
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }

    // Stop all session nodes, then emit session.node.destroyed only on success
    // (mirrors destroySessionNode ordering: stop first, log destroyed after)
    const stopPromises: Promise<void>[] = [];
    for (const entry of this.#activeNodes.values()) {
      entry.autoNat.stop();
      // M7 DOD-SPINE-6: detach from the agent relay client (closes it when its last
      // session goes) — consistent with the other teardown paths.
      this.#detachSessionRelay(entry);
      stopPromises.push(
        entry.node.stop().then(() => {
          this.#logger.info("session.node.destroyed", {
            sessionId: entry.sessionId,
            agentName: entry.agentName,
            reason: "interrupted",
          });
        }).catch((err: unknown) => {
          this.#logger.error("session.node.stop.failed", {
            sessionId: entry.sessionId,
            agentName: entry.agentName,
            error: err instanceof Error ? err.message : String(err),
            correlationId: entry.correlationId,
          });
        }),
      );
    }
    await Promise.all(stopPromises);
    this.#activeNodes.clear();
    // Evict in-memory per-session caches (trees reload from SQLite; received-content
    // plaintext must not survive shutdown in memory).
    this.#trees.clear();
    this.#receivedContent.clear();

    // Stop ALL per-agent standing receivers (DOD-LOOP-1).
    for (const [agentName, sr] of this.#standingReceivers) {
      sr.autoNat.stop();
      try {
        await sr.node.stop();
      } catch (err: unknown) {
        this.#logger.error("session.node.stop.failed", {
          sessionId: "standing_receiver_shutdown",
          agentName: `${STANDING_RECEIVER_AGENT_NAME}:${agentName}`,
          error: err instanceof Error ? err.message : String(err),
          correlationId: "n/a",
        });
      }
    }
    this.#standingReceivers.clear();

    // Release the SQLite handle so the DB file is no longer held open after shutdown
    // (review L5). Queries guard on `#db === null` and degrade to empty/null.
    if (this.#db) {
      try { this.#db.close(); } catch { /* already closed */ }
      this.#db = null;
    }
  }

  /**
   * Return all sessions with a given status from SQLite.
   * Used by cello status to surface interrupted sessions.
   */
  getSessionsByStatus(status: "active" | "sealed" | "interrupted"): SessionRecord[] {
    if (!this.#db) return [];
    return this.#db
      .prepare("SELECT * FROM sessions WHERE status = ?")
      .all(status) as unknown as SessionRecord[];
  }

  /**
   * cello_list_sessions: every persisted session for one agent, regardless of
   * status (active, interrupted, sealed, seal_interrupted_pending). Ordered most
   * recently updated first so the live session surfaces at the top. This is the
   * discovery surface that the by-id reads (cello_get_transcript /
   * cello_get_sealed_receipt) depend on — without it an agent has no way to learn
   * its own session ids after a restart or from a fresh MCP connection.
   */
  getSessionsForAgent(agentName: string): SessionRecord[] {
    if (!this.#db) return [];
    return this.#db
      .prepare("SELECT * FROM sessions WHERE agent_name = ? ORDER BY updated_at DESC")
      .all(agentName) as unknown as SessionRecord[];
  }

  /**
   * Every persisted session across ALL agents, most-recently-updated first. Backs the daemon-wide
   * `cello sessions` CLI surface (which has no per-connection current agent, unlike the MCP
   * cello_list_sessions). Classification + filtering + the count limit are applied by the caller.
   */
  getAllSessions(): SessionRecord[] {
    if (!this.#db) return [];
    return this.#db
      .prepare("SELECT * FROM sessions ORDER BY updated_at DESC")
      .all() as unknown as SessionRecord[];
  }

  /**
   * M7-SESSION-004 (AC-005): persist the seal certificate's legibility object with the
   * sealed record. Stored as a JSON string (hex-encoded pubkeys) so it round-trips a
   * daemon restart and is returned intact on the cert-read surface. The caller normalises
   * the raw wire legibility (Uint8Array pubkeys) into a JSON-safe shape before storing.
   * Best-effort: a session row may not yet exist (the seal arrived before the row was
   * persisted); in that case we no-op rather than throw — the cert still flows through the
   * live return path. The legibility content is identical regardless of delivery timing.
   */
  recordSealCertificate(agentName: string, sessionId: string, sealedRootHex: string, legibilityJson: string): void {
    if (!this.#db) return;
    this.#db
      .prepare("UPDATE sessions SET seal_legibility = ?, sealed_root_hex = ?, updated_at = ? WHERE agent_name = ? AND session_id = ?")
      .run(legibilityJson, sealedRootHex, Date.now(), agentName, sessionId);
  }

  /**
   * M7 legibility-TBS-binding (responder verify): record the counterparty's FROST primary (group)
   * pubkey from the FROST-signed SessionAssignment, so the responder can VERIFY the bilateral seal
   * signature locally. Best-effort — a missing row (race) is a no-op; the seal then falls back to
   * accept-without-verify (still sound: the live frame arrives over the authenticated Noise channel).
   */
  recordCounterpartyPrimary(agentName: string, sessionId: string, primaryPubkeyHex: string): void {
    if (!this.#db) return;
    this.#db
      .prepare("UPDATE sessions SET counterparty_primary_pubkey = ?, updated_at = ? WHERE agent_name = ? AND session_id = ?")
      .run(primaryPubkeyHex, Date.now(), agentName, sessionId);
  }

  /**
   * M7-SESSION-004 (AC-005/AC-006): read the persisted seal certificate for a session.
   * Returns the sealed root and the parsed legibility object (JSON-safe, hex pubkeys), or
   * null if the session is unknown or not yet sealed. This is the cert-read surface a
   * reader (operator, agent, arbitrator) — possibly in a DIFFERENT process than the one
   * that built the certificate — uses to determine receipt-not-assent, per-party frontiers,
   * attestation modes, and whether the final message was answered.
   */
  getSealCertificate(agentName: string, sessionId: string): { sealed_root: string; legibility: unknown } | null {
    if (!this.#db) return null;
    const row = this.#db
      .prepare("SELECT sealed_root_hex, seal_legibility FROM sessions WHERE agent_name = ? AND session_id = ?")
      .get(agentName, sessionId) as { sealed_root_hex?: string | null; seal_legibility?: string | null } | undefined;
    if (!row || !row.seal_legibility || !row.sealed_root_hex) return null;
    let legibility: unknown;
    try {
      legibility = JSON.parse(row.seal_legibility);
    } catch {
      return null;
    }
    return { sealed_root: row.sealed_root_hex, legibility };
  }

  /**
   * M7-SESSION-001: Mark a session as interrupted with message count and timestamp.
   * Called when a relay session_interrupted frame arrives or a relay stream closes.
   * Also tears down the in-memory session node if one exists for this sessionId.
   *
   * @param sessionId The hex session ID from the relay frame
   * @param messageCount Number of message leaves at interruption
   * @param source 'relay_frame' | 'stream_close'
   */
  async markInterruptedWithDetails(
    agentName: string,
    sessionId: string,
    messageCount: number,
    source: "relay_frame" | "stream_close",
  ): Promise<void> {
    if (!this.#db) return;

    // H-3 SECURITY: only an 'active' session may transition to 'interrupted'.
    // A late or forged relay frame must NOT revert a 'sealed', 'seal_interrupted_pending',
    // or already-'interrupted' session back to 'interrupted'. This mirrors the
    // stream-close guard in #watchRelayStream below — the two paths must agree.
    const existing = this.getSessionRecord(agentName, sessionId);
    if (!existing || existing.status !== "active") {
      this.#logger.warn("session.interrupt.ignored", {
        sessionId,
        source,
        currentStatus: existing?.status ?? "absent",
        reason: "session_not_active",
      });
      return;
    }

    const now = Date.now();
    const interruptedAt = new Date(now).toISOString();

    // round-2 finding #7: the daemon-owned tree is the authoritative transcript
    // length. The `messageCount` arg comes from registerRelayStream time and defaults
    // to 0, so writing it blindly would clobber the column out of sync with the tree
    // (both seal flows prefer tree.size(), but the column must not lie). When a tree
    // exists for this session, persist its size; otherwise fall back to the arg.
    const treeSize = this.getSessionTree(agentName, sessionId).size();
    const authoritativeCount = treeSize > 0 ? treeSize : messageCount;

    try {
      // The `AND status = 'active'` predicate is the authoritative guard: even if
      // the pre-check above raced (it cannot — DatabaseSync is synchronous), the
      // UPDATE only mutates a row that is still active.
      this.#db
        .prepare(
          "UPDATE sessions SET status = 'interrupted', updated_at = ?, message_count = ?, interrupted_at = ? WHERE agent_name = ? AND session_id = ? AND status = 'active'",
        )
        .run(now, authoritativeCount, interruptedAt, agentName, sessionId);
    } catch (err: unknown) {
      this.#logger.error("session.interrupt.db.write.failed", {
        sessionId,
        error: err instanceof Error ? err.message : String(err),
      });
    }

    // Look up the in-memory entry (keyed by (agent, session)) for teardown.
    const entry = this.#activeNodes.get(this.#k(agentName, sessionId));

    // Tear down the in-memory session node if it exists
    if (entry) {
      entry.autoNat.stop();
      this.#detachSessionRelay(entry);
      try {
        await entry.node.stop();
      } catch (err: unknown) {
        this.#logger.error("session.node.stop.failed", {
          sessionId,
          agentName,
          error: err instanceof Error ? err.message : String(err),
          correlationId: entry.correlationId,
        });
        // Fall through — still remove from active map
      }
      this.#activeNodes.delete(this.#k(agentName, sessionId));
      this.#logger.info("session.node.destroyed", {
        sessionId,
        agentName,
        reason: "interrupted",
      });
      // DELIBERATELY NOT #evictSessionCaches here (unlike destroySessionNode/retireSessionNode):
      // an interrupted session is not terminal. (1) #receivedContent must stay drainable — the
      // record survives, and cello_receive legitimately reads buffered unread messages after a
      // transient relay blip; evicting would silently discard deliverable plaintext. (2) Evict
      // also cancels armed TTF timers (#clearAwaitingForSession) — on a dying session the TTF
      // park backstop is exactly what must fire for un-acked content (MSG-001). The caches are
      // reclaimed when the session later seals (destroy/retire paths) or at daemon restart.
      // M8B F14 (fix 1): the relay-detected interruption is the THIRD teardown path that
      // frees the fixed port — it must re-arm too, or a session ending on a network blip
      // leaves the agent deaf again (review finding on the F14 fix).
      this.#rearmAfterTeardown(agentName);
    }

    this.#logger.warn("session.interrupted.detected", {
      sessionId,
      agentName,
      source,
    });

    // M7-SESSION-001 (M-1 PUSH): notify live MCP clients that this session is now
    // interrupted. Only fires on a real active→interrupted transition (the guard
    // above already returned for any non-active session).
    try {
      this.#onSessionStateChanged?.(
        agentName,
        sessionId,
        "interrupted",
        existing.counterparty_pubkey,
      );
    } catch (err: unknown) {
      this.#logger.debug("session.state.notify.failed", {
        sessionId,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  /**
   * M7-SESSION-001 (H-1): persist a verified bilateral SEAL-INTERRUPTED
   * commitment and transition the session to 'seal_interrupted_pending'.
   *
   * This is NOT a seal. It records that both parties produced and exchanged
   * K_local-signed SEAL-INTERRUPTED leaves over the same {leafCount, merkleRoot}.
   * The FROST threshold notarization is a separate, currently-unwired step (see
   * daemon.ts handleSealInterruptedFlow H-1 note), which is precisely why the
   * status is 'seal_interrupted_pending' and never 'sealed'.
   *
   * The status update is guarded so it only advances a session out of the
   * 'interrupted' state — it will not overwrite a 'sealed' row.
   *
   * @returns true if the session row was advanced to seal_interrupted_pending.
   */
  persistSealInterruptedCommitment(opts: {
    agentName: string;
    sessionId: string;
    role: "initiator" | "responder";
    ownLeaf: unknown;
    counterpartyLeaf: unknown;
    merkleRoot: string;
    nonce: string;
  }): boolean {
    if (!this.#db) return false;
    const now = Date.now();
    try {
      this.#db
        .prepare(
          `INSERT OR REPLACE INTO seal_interrupted_artifacts
           (agent_name, session_id, role, own_leaf, counterparty_leaf, merkle_root, nonce, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          opts.agentName,
          opts.sessionId,
          opts.role,
          JSON.stringify(opts.ownLeaf),
          JSON.stringify(opts.counterpartyLeaf),
          opts.merkleRoot,
          opts.nonce,
          now,
        );
    } catch (err: unknown) {
      this.#logger.error("session.interrupted.db.write.failed", {
        sessionId: opts.sessionId,
        error: err instanceof Error ? err.message : String(err),
      });
      return false;
    }

    // DAEMON-004: the bilateral commitment advances a session out of either
    // 'interrupted' (SESSION-001 interrupted-seal flow) OR 'active' (DAEMON-004
    // active-session seal). The guard still refuses to overwrite a terminal
    // 'sealed' row or an already-pending one.
    const result = this.#db
      .prepare(
        "UPDATE sessions SET status = 'seal_interrupted_pending', updated_at = ? WHERE agent_name = ? AND session_id = ? AND status IN ('active', 'interrupted')",
      )
      .run(now, opts.agentName, opts.sessionId);
    return Number(result.changes) > 0;
  }

  /**
   * M7-SESSION-001 (H-1): read back the persisted bilateral commitment artifacts
   * for a session. Returns null when none exist.
   */
  getSealInterruptedArtifacts(agentName: string, sessionId: string): {
    role: string;
    ownLeaf: unknown;
    counterpartyLeaf: unknown;
    merkleRoot: string;
    nonce: string;
  } | null {
    if (!this.#db) return null;
    const row = this.#db
      .prepare("SELECT * FROM seal_interrupted_artifacts WHERE agent_name = ? AND session_id = ?")
      .get(agentName, sessionId) as
      | {
          role: string;
          own_leaf: string;
          counterparty_leaf: string;
          merkle_root: string;
          nonce: string;
        }
      | undefined;
    if (!row) return null;
    return {
      role: row.role,
      ownLeaf: JSON.parse(row.own_leaf),
      counterpartyLeaf: JSON.parse(row.counterparty_leaf),
      merkleRoot: row.merkle_root,
      nonce: row.nonce,
    };
  }

  /**
   * Return the session record for a specific sessionId, regardless of status.
   * Used by cello_close_session to inspect session state.
   */
  getSessionRecord(agentName: string, sessionId: string): SessionRecord | null {
    if (!this.#db) return null;
    const row = this.#db
      .prepare("SELECT * FROM sessions WHERE agent_name = ? AND session_id = ?")
      .get(agentName, sessionId) as unknown as SessionRecord | undefined;
    return row ?? null;
  }

  /**
   * MSG-2 startup-flush: the persisted relay endpoint for a session, or null if none was
   * recorded. Used by the crash-backstop flush, which runs at startup BEFORE the in-memory
   * session entries exist, so it cannot use `entry.relayPeerId`.
   */
  getPersistedRelayEndpoint(agentName: string, sessionId: string): { relayPeerId: string; relayAddrs: string[] } | null {
    if (!this.#db) return null;
    const row = this.#db
      .prepare("SELECT relay_peer_id, relay_addrs FROM sessions WHERE agent_name = ? AND session_id = ?")
      .get(agentName, sessionId) as { relay_peer_id?: string | null; relay_addrs?: string | null } | undefined;
    if (!row?.relay_peer_id || !row?.relay_addrs) return null;
    try {
      const addrs = JSON.parse(row.relay_addrs) as unknown;
      if (!Array.isArray(addrs) || addrs.length === 0) return null;
      return { relayPeerId: row.relay_peer_id, relayAddrs: addrs as string[] };
    } catch {
      return null;
    }
  }

  /**
   * DOD-MSG-4 (auto-recover): the DISTINCT relay endpoints this agent has sessions on, so the daemon
   * can pull the agent's parked mailbox from each on reconnect (the relay mailbox is keyed by recipient
   * pubkey, so one pull per relay drains all of the agent's parked content there). Distinct by relay
   * peer id.
   */
  getAgentRelayEndpoints(agentName: string): Array<{ relayPeerId: string; relayAddrs: string[] }> {
    if (!this.#db) return [];
    const rows = this.#db
      .prepare("SELECT DISTINCT relay_peer_id, relay_addrs FROM sessions WHERE agent_name = ? AND relay_peer_id IS NOT NULL")
      .all(agentName) as Array<{ relay_peer_id?: string | null; relay_addrs?: string | null }>;
    const byPeer = new Map<string, { relayPeerId: string; relayAddrs: string[] }>();
    for (const row of rows) {
      if (!row.relay_peer_id || !row.relay_addrs) continue;
      try {
        const addrs = JSON.parse(row.relay_addrs) as unknown;
        if (!Array.isArray(addrs) || addrs.length === 0) continue;
        if (!byPeer.has(row.relay_peer_id)) byPeer.set(row.relay_peer_id, { relayPeerId: row.relay_peer_id, relayAddrs: addrs as string[] });
      } catch {
        /* skip malformed */
      }
    }
    return [...byPeer.values()];
  }

  // ─── DAEMON-004: daemon-owned Merkle tree ──────────────────────────────────

  /**
   * Return the daemon-owned Merkle tree for a session, loading it from SQLite
   * on first access (so it survives a restart — AC-007). Never returns null;
   * an unknown session yields an empty tree.
   */
  getSessionTree(agentName: string, sessionId: string): SessionTree {
    const key = this.#k(agentName, sessionId);
    const cached = this.#trees.get(key);
    if (cached) return cached;
    const tree = this.#loadTreeFromDb(agentName, sessionId);
    this.#trees.set(key, tree);
    return tree;
  }

  /** Current daemon-owned tree root for a session, as hex. */
  getSessionTreeRootHex(agentName: string, sessionId: string): string {
    return this.getSessionTree(agentName, sessionId).rootHex();
  }

  /**
   * Append a leaf (by its 32-byte leaf-hash hex) to the daemon-owned tree,
   * persist it, advance the root, and fire session.tree.appended.
   *
   * @returns the new leaf index and the recomputed root hex.
   */
  appendSessionLeaf(
    agentName: string,
    sessionId: string,
    kind: SessionTreeLeafKind,
    leafHashHex: string,
    correlationId?: string,
  ): { leafIndex: number; newRootHex: string } {
    const tree = this.getSessionTree(agentName, sessionId);
    const { leafIndex, newRootHex } = tree.appendLeafHash(kind, leafHashHex);

    if (this.#db) {
      try {
        this.#db
          .prepare(
            `INSERT INTO session_tree_leaves
             (agent_name, session_id, leaf_index, leaf_kind, leaf_hash_hex, created_at)
             VALUES (?, ?, ?, ?, ?, ?)`,
          )
          .run(agentName, sessionId, leafIndex, kind, leafHashHex, Date.now());
        // DAEMON-004 (finding #2): keep sessions.message_count synced to the tree
        // size. message_count is the bilateral leafCount the seal flow signs over
        // (handleSealInterruptedFlow / the responder). If it diverged from the
        // daemon-owned tree, a post-active-messaging seal would attest to a
        // truncated transcript and the bilateral leafCount check would mismatch.
        // The tree (leafIndex + 1 leaves) is authoritative; the column tracks it.
        this.#db
          .prepare("UPDATE sessions SET message_count = ?, updated_at = ? WHERE agent_name = ? AND session_id = ?")
          .run(leafIndex + 1, Date.now(), agentName, sessionId);
      } catch (err: unknown) {
        // A persist failure must be visible, not swallowed: the in-memory tree
        // has advanced but the durable transcript has not, which would diverge
        // on restart. Surface it loudly.
        this.#logger.error("session.tree.persist.failed", {
          sessionId,
          leafIndex,
          error: err instanceof Error ? err.message : String(err),
          correlationId,
        });
      }
    }

    this.#logger.info("session.tree.appended", {
      sessionId,
      leafIndex,
      newRootHex,
      correlationId,
    });
    return { leafIndex, newRootHex };
  }

  /**
   * SEAM 1b (dialer ⇄ session-node reconciliation): dial the counterparty THROUGH
   * this session's OWN node, so the session node N_A holds the connection its content
   * newStream actually rides. TRANSPORT-001's transport selector dialed on a separate
   * (composition-root) node whose connection N_A could not use — the per-session node
   * must be the dialer. Direct mode only here (the default content path, Part 4 D-a);
   * relay-circuit + dcutr strategy via N_A is a later seam. Tries each addr in turn;
   * succeeds on the first connection, returns a named failure if none connect.
   */
  async connectToCounterparty(
    agentName: string,
    sessionId: string,
    addrs: string[],
  ): Promise<{ ok: true } | { ok: false; reason: string; error: string }> {
    const entry = this.#activeNodes.get(this.#k(agentName, sessionId));
    if (!entry) {
      return { ok: false, reason: "session_node_unavailable", error: "no active session node for this session" };
    }
    if (addrs.length === 0) {
      return { ok: false, reason: "no_counterparty_addrs", error: "the assignment carried no counterparty session addrs to dial" };
    }
    let lastError = "";
    for (const addr of addrs) {
      try {
        await entry.node.dial(addr);
        this.#logger.info("session.transport.connected", {
          sessionId,
          addr,
          correlationId: entry.correlationId,
        });
        return { ok: true };
      } catch (err: unknown) {
        // error.message extracted — never [object Object]; try the next addr.
        lastError = err instanceof Error ? err.message : String(err);
      }
    }
    this.#logger.warn("session.transport.connect.failed", {
      sessionId,
      reason: "counterparty_dial_failed",
      error: lastError,
      correlationId: entry.correlationId,
    });
    return { ok: false, reason: "counterparty_dial_failed", error: lastError };
  }

  /**
   * DAEMON-004: send content over the session node's direct P2P content stream.
   * On a dead/missing stream this returns a NAMED, diagnosable failure — never a
   * silent success and never a desync (closing the old silent fire-and-forget
   * content catch in the retired in-process client send path).
   *
   * SCOPE / findings #3 + #4 — what this send path does and does NOT do today:
   *   - #4: it delivers the content over the direct /cello/content/1.0.0 P2P
   *     stream only. It does NOT also submit a K_local-SIGNED content_hash leaf to
   *     the RELAY on /cello/relay/1.0.0 (EARS behavior #1). That relay hash-submit
   *     is MSG-001's scope; AC-001's "relay log shows a hash_submit" evidence is
   *     produced once MSG-001 lands.
   *   - #3: because there is no relay yet, the sequence number cello_send returns
   *     is the LOCAL leaf index, not a relay-assigned canonical global sequence.
   *     Each daemon appends leaves in its own LOCAL observation order, so two
   *     daemons' roots agree only under perfectly ping-ponged traffic. Canonical
   *     cross-process ordering (and thus AC-002 root agreement under concurrent
   *     bidirectional traffic) requires the relay-assigned sequence from MSG-001.
   */
  async sendContent(
    agentName: string,
    sessionId: string,
    content: Uint8Array,
    contentHash: Uint8Array,
    correlationId?: string,
  ): Promise<{ ok: true } | { ok: false; reason: string; error: string }> {
    const entry = this.#activeNodes.get(this.#k(agentName, sessionId));
    if (!entry) {
      return { ok: false, reason: "session_node_unavailable", error: "no active session node for this session" };
    }
    // R1 (MSG-001-3b): witness the message-leaf HASH to the relay FIRST, INDEPENDENT of
    // direct delivery. The relay is the ordering authority (Structure 2): it assigns the
    // canonical sequence from the hash whether or not the counterparty is reachable for direct
    // content. So an OFFLINE recipient still gets a sequence, and the parked content is later
    // recovered AT that sequence (DOD-MSG-4 recovery-not-desync). The relay only ever sees the
    // hash (INV-3). Best-effort: a relay miss degrades to local-only sequencing. Previously this
    // ran AFTER a successful direct send, so an offline recipient's content got NO sequence — the
    // gap R1 closes.
    // DOD-MSG-4 (self-ordering content frame): the relay's committed ordering record for this leaf,
    // captured from the hash submit so it can be stamped into the content frame (and the parked
    // entry). Undefined if the relay is unreachable / an old relay — the receiver then falls back to
    // the leaf_deliver witness stream / arrival order.
    let orderingS1: Uint8Array | undefined;
    let orderingS2: Uint8Array | undefined;
    if (entry.relayClient && entry.relaySessionIdBytes) {
      try {
        const witnessed = await entry.relayClient.submitMessageHash(entry.node, entry.relaySessionIdBytes, contentHash);
        if (witnessed.ok) {
          orderingS1 = witnessed.structure1_cbor;
          orderingS2 = witnessed.structure2_cbor;
          this.#logger.info("session.relay.hash.submitted", {
            sessionId,
            sequenceNumber: witnessed.sequence_number,
            correlationId,
          });
        } else {
          this.#logger.warn("session.relay.hash.submit.failed", {
            sessionId,
            reason: witnessed.reason,
            correlationId,
          });
        }
      } catch (relayErr: unknown) {
        this.#logger.warn("session.relay.hash.submit.failed", {
          sessionId,
          reason: relayErr instanceof Error ? relayErr.message : String(relayErr),
          correlationId,
        });
      }
    }

    // Attempt direct peer↔peer content delivery. On success the receiver's `persisted` ACK
    // resolves the awaiting timer; on failure (counterparty offline) the hash is already
    // witnessed above, so the caller / TTF path parks the SEALED content to the relay
    // store-and-forward backstop and the recipient recovers it at the witnessed sequence (2b).
    try {
      const stream = await entry.node.newStream(entry.counterpartySessionPeerId, CELLO_CONTENT_PROTOCOL_ID);
      // AC-001/AC-003: arm the TTF tracking BEFORE the frame goes on the wire. The
      // receiver's `persisted` ACK can come back fast (in-process / low-latency
      // transports), so registering the awaiting entry after send would let the ACK
      // race ahead of it and be dropped — the timer would then spuriously fire. The
      // content is delivered to the wire but NOT yet confirmed persisted; the ACK
      // resolves it (content.delivery.acked) and TTF expiry hands it to the park
      // backstop. The correlationId rides in the frame so the receiver's
      // session.content.received shares ONE flow id with the sender.
      this.#trackAwaitingAck(agentName, sessionId, content, contentHash, correlationId, orderingS1, orderingS2);
      const frame = CBOR_ENC.encode({
        type: "content_frame",
        session_id: sessionId,
        content_hash: contentHash,
        content_bytes: content,
        correlation_id: correlationId,
        // DOD-MSG-4 (self-ordering): the relay's signed ordering record, so the receiver verifies +
        // orders from the frame ALONE (no dependence on the separate leaf_deliver witness timing).
        // structure1_cbor = sender-signed bytes (verify); structure2_cbor = relay's committed seq +
        // prev_root (order). Omitted if the relay was unreachable — receiver falls back to the witness.
        structure1_cbor: orderingS1,
        structure2_cbor: orderingS2,
      }) as Uint8Array;
      stream.send(lp.encode.single(frame));
      try { await stream.close(); } catch { /* best-effort close */ }
      return { ok: true };
    } catch (err: unknown) {
      // The send failed after (possibly) arming the awaiting tracking — drop it so a
      // never-delivered frame does not later fire a spurious TTF park.
      this.#untrackAwaitingAck(agentName, sessionId, contentHash);
      // 2b: direct delivery failed (counterparty offline). The hash is already witnessed (R1, the
      // sequence is assigned), so deposit the content to the relay store-and-forward backstop now;
      // the recipient pulls + recovers it on next online (DOD-MSG-3/4).
      this.#parkContent(agentName, sessionId, Buffer.from(contentHash).toString("hex"), content, orderingS1, orderingS2);
      // error.message extracted — never [object Object]. libp2p/cross-package errors are not
      // always `instanceof Error` in this realm, so fall back to a message property / JSON.
      const errMsg =
        err instanceof Error
          ? err.message
          : err && typeof err === "object" && typeof (err as { message?: unknown }).message === "string"
            ? (err as { message: string }).message
            : (() => {
                try {
                  return JSON.stringify(err);
                } catch {
                  return String(err);
                }
              })();
      return { ok: false, reason: "session_stream_unavailable", error: errMsg };
    }
  }

  /**
   * M7 DOD-SPINE-7: submit THIS party's SEAL ctrl leaf (0x02) to the relay witness.
   * Structure: content_hash = SHA-256(0x02 || encodeSealPayload({session_id, final_root,
   * close_timestamp, "PENDING"})), where final_root is the daemon's OWN tree root. Two
   * distinct-sender SEAL leaves in the relay's log trigger the relay's #maybeProcessSeal
   * → directory processSeal (rebuild + verify the signed chain) → FROST notarization →
   * session_sealed. Requires an active relay client; the caller falls back to the
   * directory-mediated path when this returns relay_unavailable.
   */
  async submitSealLeaf(
    agentName: string,
    sessionId: string,
    correlationId?: string,
  ): Promise<
    | { ok: true; sequenceNumber: number; reportedRootHex: string }
    | { ok: false; reason: string; reportedRootHex?: string; sequenceNumber?: number }
  > {
    const sealKey = this.#k(agentName, sessionId);
    const entry = this.#activeNodes.get(sealKey);
    if (!entry) return { ok: false, reason: "session_node_unavailable" };
    if (!entry.relayClient || !entry.relaySessionIdBytes) return { ok: false, reason: "relay_unavailable" };

    // M7-UPGRADE-002 idempotency: this party submits its responder SEAL leaf AT MOST ONCE per
    // session. BOTH cello_close_session and the auto-acknowledge path call here; the first to reach
    // this point wins, the second short-circuits. The check+set is SYNCHRONOUS (before any await) so
    // two near-simultaneous triggers (e.g. B's own close racing A's delivered SEAL ctrl leaf) cannot
    // both submit. Cleared below on a relay submit failure so a genuine retry can proceed.
    if (this.#responderSealSubmitted.has(sealKey)) {
      // M8B FINDING-1: carry the FIRST submit's reported root/sequence so a retry close can
      // still escalate to a unilateral seal. A null value means that submit is still in
      // flight — return the bare reason and let the caller fall back to the pending path.
      const prior = this.#responderSealSubmitted.get(sealKey);
      return prior
        ? {
            ok: false,
            reason: "responder_seal_already_submitted",
            reportedRootHex: prior.reportedRootHex,
            sequenceNumber: prior.sequenceNumber,
          }
        : { ok: false, reason: "responder_seal_already_submitted" };
    }
    this.#responderSealSubmitted.set(sealKey, null);

    // A throw anywhere before the mark is finalized would strand the null in-flight marker
    // and lock every future close out of escalation (a FINDING-1-shaped deadlock via a
    // different trigger) — clear the mark on any unexpected exception.
    try {
      const finalRootHex = this.getSessionTreeRootHex(agentName, sessionId);
      const sealPayload = encodeSealPayload({
        session_id: entry.relaySessionIdBytes,
        final_root: new Uint8Array(Buffer.from(finalRootHex, "hex")),
        close_timestamp: Date.now(),
        attestation: "PENDING",
      });
      // content_hash = SHA-256(0x02 || seal_payload) — the ctrl leaf kind byte is 0x02.
      const contentHash = new Uint8Array(
        createHash("sha256").update(new Uint8Array([LEAF_KIND_CTRL])).update(sealPayload).digest(),
      );
      const result = await entry.relayClient.submitLeaf(entry.node, entry.relaySessionIdBytes, contentHash, LEAF_KIND_CTRL);
      if (!result.ok) {
        // Clear the idempotency mark so a genuine retry (agent close / reconnect) can proceed (DB-001).
        this.#responderSealSubmitted.delete(sealKey);
        this.#logger.warn("session.seal.leaf.submit.failed", { sessionId, reason: result.reason, correlationId });
        return { ok: false, reason: result.reason };
      }
      // SESSION-002: the reported_root for a unilateral seal is the content-hash root the
      // local tree WOULD have with this SEAL ctrl leaf appended — the same root the directory
      // rebuilds from the relay's content-hash chain (the relay records the identical
      // content_hash for this ctrl leaf). Computed without mutating the durable tree /
      // message_count, so the bilateral + interrupted seal paths are unaffected.
      const contentHashHex = Buffer.from(contentHash).toString("hex");
      const reportedRootHex = this.getSessionTree(agentName, sessionId).rootWithAppendedHex(contentHashHex);
      // M8B FINDING-1: durably associate the submit's escalation values with the idempotency
      // mark, so any LATER close call can retrieve them via the already-submitted result.
      this.#responderSealSubmitted.set(sealKey, { reportedRootHex, sequenceNumber: result.sequence_number });
      this.#logger.info("session.seal.leaf.submitted", {
        sessionId,
        sequenceNumber: result.sequence_number,
        correlationId,
      });
      // M7-UPGRADE-002: #responderSealSubmitted was set synchronously at the top of this method —
      // the guard now blocks any second submit (auto-ack OR a redelivered counterparty SEAL ctrl leaf).
      return { ok: true, sequenceNumber: result.sequence_number, reportedRootHex };
    } catch (err: unknown) {
      this.#responderSealSubmitted.delete(sealKey);
      throw err;
    }
  }

  /**
   * CELLO-M7-UPGRADE-001 (DOD-UP-1): readiness of a session for B to RATIFY a unilateral seal
   * (the returning absent party). This is the SAME verifiability bar as the UP-2 auto-ack gate:
   *
   *  - `known`: the session exists locally with its content (B has a transcript to ratify). After a
   *    restart B reloads it from SQLite, and autoRecoverForAgent re-pulls any parked content first.
   *  - `tampered`: the content cross-check flagged a content_hash mismatch (#contentDesynced) — B
   *    must NEVER ratify content it could not integrity-verify (the KERNEL refusal, AC-003).
   *
   * The directory separately verifies B's ack signature is genuine; B separately verifies the
   * unilateral cert signature (R1 is authentic). NOTE: a full "B's frontier covers R1's tail"
   * completeness check (the `desynced` reason) requires the deferred MSG-001-3b canonical-sequence
   * reconciliation — same documented limitation as the UP-2 gate above.
   */
  getSealUpgradeReadiness(agentName: string, sessionId: string): { known: boolean; tampered: boolean } {
    const record = this.getSessionRecord(agentName, sessionId);
    return {
      known: !!record,
      tampered: this.#contentDesynced.has(this.#k(agentName, sessionId)),
    };
  }

  /**
   * M7-UPGRADE-002: auto-acknowledge close (POSTMORTEM Workstream E / C-5). When B's daemon
   * ingests the COUNTERPARTY's SEAL control leaf and B has verified the content, B's OWN node
   * auto-co-signs + submits its responder SEAL leaf WITHOUT waiting for B's agent to call
   * cello_close_session — so a bilateral seal completes promptly instead of degrading to
   * unilateral on a slow/busy/crashed agent.
   *
   * SI-001 (non-negotiable): B's signature is ALWAYS produced by B's own node — submitSealLeaf
   * signs the responder SEAL leaf with B's K_local. We remove the agent PROMPT, never the SIGNER;
   * nothing here lets the directory or the peer synthesize B's acknowledgement.
   *
   * SI-002 (verifiability gate): auto-ack ONLY content B has verified. A session whose content
   * cross-check failed (content_hash_mismatch = tamper, recorded in #contentDesynced) is NEVER
   * auto-signed — it surfaces to the agent as a genuine decision point. DISAGREEMENT with the
   * content is NOT a gate failure (C-6): the gate is "can I verify integrity?", never "do I agree?"
   * — a verified-but-disliked tail is auto-sealed and the transcript speaks for B.
   *
   * Idempotent + non-throwing: marks #responderSealSubmitted BEFORE the async submit so a
   * redelivered ctrl leaf cannot double-submit; clears the mark on submit failure so a later
   * agent close / reconnect can still complete the seal (DB-001 — never a silent half-seal).
   */
  #maybeAutoAcknowledgeSeal(agentName: string, sessionId: string, correlationId: string): void {
    const ackKey = this.#k(agentName, sessionId);
    // Idempotency: at most one responder seal per session (auto-ack or agent close).
    if (this.#responderSealSubmitted.has(ackKey)) return;
    const record = this.getSessionRecord(agentName, sessionId);
    // Only an ACTIVE session auto-acks. A committed/sealing/sealed/interrupted session is out of
    // scope (already sealing, or needs the interrupted/upgrade path), not an auto-ack candidate.
    if (!record || record.status !== "active") return;
    // SI-002 verifiability gate: never auto-sign a session whose content we could not verify.
    // Today the ONLY tracked unverifiable cause is a content_hash mismatch = TAMPER (#contentDesynced
    // is set only there). Genuine tamper is a SECURITY event — log it at ERROR with the distinct
    // reason `content_tamper` so the AC-008 tamper alarm can fire (it keys on that reason). The other
    // two specced reasons — `desynced` (B's tree is behind the canonical sealed tail) and
    // `content_unverifiable` (parked content unrecoverable) — require the MSG-001-3b canonical-
    // sequence reconciliation that is deferred; they are reserved for that follow-on.
    if (this.#contentDesynced.has(ackKey)) {
      this.#logger.error("session.seal.autoack.skipped", {
        sessionId,
        reason: "content_tamper",
        correlationId,
      });
      // AC-002: the verifiability gate refused — surface counterparty_closing to B's agent as a
      // GENUINE decision point (the seal will not auto-complete; B must decide). Uses the existing
      // session-state push to the live MCP clients; best-effort (never throws out of this gate).
      try {
        this.#onSessionStateChanged?.(record.agent_name, sessionId, "counterparty_closing", record.counterparty_pubkey);
      } catch (err: unknown) {
        this.#logger.debug("session.state.notify.failed", {
          sessionId,
          reason: err instanceof Error ? err.message : String(err),
        });
      }
      return;
    }
    const entry = this.#activeNodes.get(ackKey);
    const responderPubkey = entry?.relayClient?.senderPubkeyHex ?? "unknown";
    // submitSealLeaf owns the #responderSealSubmitted idempotency mark (set synchronously at its
    // top), so the auto-ack does not pre-mark — it just reacts to the result.
    void this.submitSealLeaf(agentName, sessionId, correlationId)
      .then((result) => {
        if (result.ok) {
          // SI-001: the responder SEAL leaf was signed by B's OWN node (K_local) in submitSealLeaf.
          this.#logger.info("session.seal.autoacknowledged", {
            sessionId,
            responderPubkey,
            correlationId,
          });
        } else if (result.reason === "responder_seal_already_submitted") {
          // B's agent close already submitted the responder seal (it won the race) — nothing to do.
          return;
        } else {
          // Submission failed (e.g. relay path down) — the agent close / reconnect can still
          // complete the seal; never a silent half-seal (DB-001).
          this.#logger.warn("session.seal.autoack.skipped", {
            sessionId,
            reason: result.reason,
            correlationId,
          });
        }
      })
      .catch((err: unknown) => {
        this.#logger.warn("session.seal.autoack.skipped", {
          sessionId,
          reason: err instanceof Error ? err.message : String(err),
          correlationId,
        });
      });
  }

  /**
   * DAEMON-004: cross-check received content against its hash, append the
   * verified leaf to the daemon-owned tree, and buffer it for cello_receive.
   * A hash MISMATCH is genuine tamper — rejected without append or buffer.
   *
   * SCOPE / finding #5 — what this cross-check does and does NOT prove today:
   * `contentHash` here is carried in the SAME content_frame as `content`, so this
   * comparison only catches wire corruption of a single frame — it does NOT prove
   * the content matches what the sender independently committed. Full tamper-
   * evidence (EARS behavior #2) requires cross-checking against the K_local-signed
   * content_hash leaf the sender submits to the RELAY on a separate channel; that
   * relay hash-submit path is MSG-001's scope and does not exist yet. Until MSG-001
   * lands, a malicious sender that sends matching (content, hash) in one frame is
   * not detected here — only the relay-relayed signed leaf closes that gap.
   *
   * @returns the appended leaf index (as sequenceNumber) on success.
   */
  ingestReceivedContent(
    agentName: string,
    sessionId: string,
    content: Uint8Array,
    contentHash: Uint8Array,
    correlationId?: string,
  ): { ok: true; leafIndex: number; sequenceNumber: number; held?: boolean; appendedCount?: number } | { ok: false; reason: string } {
    // The transcript is frozen ONLY once it is COMMITTED + signed — 'sealed' or
    // 'seal_interrupted_pending' (the bilateral seal commitment) — because a later FROST
    // notarization attests that exact root; a late leaf would diverge from it.
    //
    // MSG-001-3b recovery: a merely 'interrupted' session is NOT yet committed. The
    // counterparty's last message(s) may have been parked while this party was offline, so its
    // local transcript is INCOMPLETE (not frozen-final). Recovering that parked content COMPLETES
    // the local view to match the counterparty BEFORE the bilateral seal — it is not a resumption
    // (no new activity, no re-accept) and its root was never committed. So allow 'active' AND
    // 'interrupted'; reject only the two committed states. (No DB row = test-only path, allowed.)
    const record = this.getSessionRecord(agentName, sessionId);
    if (record && (record.status === "sealed" || record.status === "seal_interrupted_pending")) {
      this.#logger.warn("session.content.cross_check.failed", {
        sessionId,
        reason: "session_committed",
        currentStatus: record.status,
        correlationId,
      });
      return { ok: false, reason: "session_committed" };
    }

    const computed = createHash("sha256").update(new Uint8Array([0x00])).update(content).digest();
    const contentHashHex = Buffer.from(contentHash).toString("hex");
    if (Buffer.from(computed).toString("hex") !== contentHashHex) {
      this.#logger.warn("session.content.cross_check.failed", {
        sessionId,
        reason: "content_hash_mismatch",
        correlationId,
      });
      // M7-UPGRADE-002 (SI-002): a tamper makes this session's content unverifiable — the
      // auto-acknowledge gate must never auto-co-sign it. The session stays alive (DOD-MSG-7),
      // but the responder seal now requires the agent's explicit decision, not an auto-ack.
      this.#contentDesynced.add(this.#k(agentName, sessionId));
      return { ok: false, reason: "content_hash_mismatch" };
    }

    const entry = this.#activeNodes.get(this.#k(agentName, sessionId));
    const senderPubkey = entry?.counterpartyPubkey
      ?? this.getSessionRecord(agentName, sessionId)?.counterparty_pubkey
      ?? "unknown";

    // DOD-MSG-5: a content_hash satisfies AT MOST ONE Merkle leaf, exactly once. If this hash is
    // already a leaf in the tree — it arrived BOTH directly and via the relay-park backstop, or it
    // is a replay — do NOT append a second leaf and do NOT double-count it. The recipient already
    // holds this message at its assigned sequence. (In the normal single-delivery case this find is
    // -1, so the live/recover append paths are unchanged.)
    const existingIdx = this.getSessionTree(agentName, sessionId).indexOfHash(contentHashHex);
    if (existingIdx >= 0) {
      this.#logger.info("session.content.deduplicated", {
        sessionId,
        contentHashHex,
        sequenceNumber: existingIdx,
        correlationId,
      });
      // appendedCount 0 — a dedup appends NO new leaf, so a recover that re-pulls an already-ingested
      // entry (e.g. after auto-recover already drained it) must not count it as a fresh recovery.
      return { ok: true, leafIndex: existingIdx, sequenceNumber: existingIdx, appendedCount: 0 };
    }

    // DOD-MSG-4 (strict in-order gate): the RELAY is the ordering authority. If B holds the
    // canonical sequence for this hash (witnessed via leaf_deliver) and it is AHEAD of the next
    // expected leaf, HOLD the content rather than append it out of order. The missing in-between
    // sequence(s) are recovered from the relay mailbox; #releaseHeld then drains the held entries
    // in canonical order. This keeps the daemon-owned leaf index === the canonical sequence by
    // construction, so two parties' roots match even when direct delivery and park-recovery
    // interleave. With NO witness for this hash (relay-degraded) B falls back to arrival-order
    // append — the pre-MSG-4 behavior (no ordering signal available).
    const key = this.#k(agentName, sessionId);
    const canonicalSeq = this.#witnessedSeq.get(key)?.get(contentHashHex);
    const nextExpected = this.getSessionTree(agentName, sessionId).size();
    if (canonicalSeq !== undefined && canonicalSeq > nextExpected) {
      let held = this.#heldContent.get(key);
      if (!held) { held = new Map(); this.#heldContent.set(key, held); }
      held.set(canonicalSeq, { content, contentHashHex, correlationId });
      this.#logger.info("session.content.held", {
        sessionId,
        canonicalSeq,
        nextExpected,
        gap: canonicalSeq - nextExpected,
        correlationId,
      });
      // Held content is NOT yet a durable leaf, so it is deliberately NOT acknowledged `persisted`
      // (the caller checks `held`). The sender's TTF→park backstop and the recover/dedup path
      // guarantee eventual delivery; B never claims persisted for content it only holds in memory.
      return { ok: true, leafIndex: canonicalSeq, sequenceNumber: canonicalSeq, held: true };
    }
    if (canonicalSeq !== undefined && canonicalSeq < nextExpected) {
      // Contradiction (review finding #2): the witness says this hash belongs BEHIND the current
      // tree, yet the dedup scan above found no existing leaf for it — so it is neither a duplicate
      // nor in canonical order. This is only reachable via the accepted content-before-witness /
      // relay-degraded interleaving (the next sub-increment's pending-witness buffer closes it). Log
      // it loudly (the leaf-index===sequence invariant is at risk) and append rather than DROP the
      // message — losing content is worse than a transient mis-order the seal cross-check will catch.
      this.#logger.warn("session.content.sequence_behind_tree", {
        sessionId,
        canonicalSeq,
        nextExpected,
        correlationId,
      });
    }

    const { leafIndex } = this.#appendVerifiedContent(agentName, sessionId, content, contentHashHex, senderPubkey, correlationId);
    // A just-appended leaf may unblock held out-of-order arrivals whose turn is now next.
    // appendedCount = this leaf + any held leaves released by it, so a caller (recover) can tally the
    // leaves ACTUALLY written, not just the directly-ingested one (review #3).
    const released = this.#releaseHeld(agentName, sessionId, senderPubkey);
    return { ok: true, leafIndex, sequenceNumber: leafIndex, appendedCount: 1 + released };
  }

  /**
   * DOD-MSG-4: record the relay-witnessed canonical sequence for a content hash. The relay is the
   * ordering authority (Structure 2): it assigns each message a sequence from its hash and delivers
   * B the (content_hash -> sequence) binding via leaf_deliver. The strict-in-order gate orders the
   * transcript by THIS — never a sender-stamped field. Also advances the per-session high-water mark
   * (the largest witnessed sequence) reserved for the future catch-up-before-live increment. Idempotent.
   */
  recordWitnessedSequence(agentName: string, sessionId: string, contentHashHex: string, sequenceNumber: number): void {
    if (sequenceNumber < 0) return;
    const key = this.#k(agentName, sessionId);
    let map = this.#witnessedSeq.get(key);
    if (!map) { map = new Map(); this.#witnessedSeq.set(key, map); }
    map.set(contentHashHex, sequenceNumber);
    const hw = this.#highWaterSeq.get(key) ?? -1;
    if (sequenceNumber > hw) this.#highWaterSeq.set(key, sequenceNumber);
  }

  /**
   * DOD-MSG-4: the relay's high-water canonical sequence for this session (largest witnessed leaf),
   * or -1 if none. Exposed for the next sub-increment (catch-up-before-live — on reconnect B holds
   * live arrivals until its tree reaches this, because it has more to recover than it has appended);
   * NOT yet consumed by the gate. Also `recordWitnessedSequence` maintains it.
   */
  getHighWaterSeq(agentName: string, sessionId: string): number {
    return this.#highWaterSeq.get(this.#k(agentName, sessionId)) ?? -1;
  }

  /** DOD-MSG-4 / DAEMON-004: append a verified message leaf and buffer it for cello_receive. */
  #appendVerifiedContent(
    agentName: string,
    sessionId: string,
    content: Uint8Array,
    contentHashHex: string,
    senderPubkey: string,
    correlationId?: string,
  ): { leafIndex: number } {
    const { leafIndex } = this.appendSessionLeaf(agentName, sessionId, "msg", contentHashHex, correlationId);
    // DOD-LOG-1: persist the readable RECEIVED plaintext to the durable transcript, keyed by the
    // canonical leaf sequence so it joins the committed hash chain (survives restart; INV-3 — the
    // relay/directory never see this plaintext, only the hash).
    this.recordTranscriptMessage(agentName, sessionId, leafIndex, "received", content, correlationId);
    const recvKey = this.#k(agentName, sessionId);
    // Review finding #6: the witness for this hash has done its ordering job once the leaf is
    // appended — drop it so #witnessedSeq stays proportional to held/pending content, not the whole
    // transcript. A later replay of the same hash is still caught by the dedup leaf-scan, which is
    // independent of the witness map.
    this.#witnessedSeq.get(recvKey)?.delete(contentHashHex);
    let buf = this.#receivedContent.get(recvKey);
    if (!buf) { buf = []; this.#receivedContent.set(recvKey, buf); }
    buf.push({ contentHex: Buffer.from(content).toString("hex"), senderPubkey, sequenceNumber: leafIndex });
    this.#logger.info("session.content.received", {
      sessionId,
      senderPubkey,
      contentHashHex,
      sequenceNumber: leafIndex,
      correlationId,
    });
    return { leafIndex };
  }

  /**
   * DOD-MSG-4: drain held out-of-order content in canonical order. After a leaf is appended, any
   * held entry whose canonical sequence equals the new next-expected index is now in order — append
   * it, then check again (a single fill can release a run of consecutive held messages).
   */
  #releaseHeld(agentName: string, sessionId: string, senderPubkey: string): number {
    const key = this.#k(agentName, sessionId);
    const held = this.#heldContent.get(key);
    if (!held) return 0;
    let released = 0;
    for (;;) {
      const nextExpected = this.getSessionTree(agentName, sessionId).size();
      const entry = held.get(nextExpected);
      if (!entry) break;
      held.delete(nextExpected);
      this.#appendVerifiedContent(agentName, sessionId, entry.content, entry.contentHashHex, senderPubkey, entry.correlationId);
      released++;
      this.#logger.info("session.content.released", {
        sessionId,
        sequenceNumber: nextExpected,
        correlationId: entry.correlationId,
      });
      if (held.size === 0) { this.#heldContent.delete(key); break; }
    }
    return released;
  }

  /** DAEMON-004: pop the oldest verified received content for cello_receive. */
  takeReceivedContent(agentName: string, sessionId: string): ReceivedContentEntry | null {
    const buf = this.#receivedContent.get(this.#k(agentName, sessionId));
    if (!buf || buf.length === 0) return null;
    return buf.shift() ?? null;
  }

  /**
   * F1-b: the terminal answer for a session that sealed while a blocking receive was (or could be)
   * waiting. Idempotent — a sealed session always answers "sealed" to a receive. Null while active.
   */
  peekTerminalMarker(agentName: string, sessionId: string): { type: "sealed"; unreadCount: number } | null {
    return this.#sessionTerminal.get(this.#k(agentName, sessionId)) ?? null;
  }

  /**
   * F1-b: the durable sealed root hex for a session (written by recordSealCertificate on the
   * bilateral path), or null if not recorded. Lets cello_receive echo the sealed root in its
   * terminal answer without threading it through destroySessionNode.
   */
  getSealedRootHex(agentName: string, sessionId: string): string | null {
    if (!this.#db) return null;
    const row = this.#db
      .prepare("SELECT sealed_root_hex FROM sessions WHERE agent_name = ? AND session_id = ?")
      .get(agentName, sessionId) as { sealed_root_hex?: string | null } | undefined;
    return row?.sealed_root_hex ?? null;
  }

  // ─── CELLO-M7-MSG-001: delivery ACK / TTF tracking (send side) ──────────────

  /**
   * Arm awaiting-ACK tracking for a just-sent content frame (AC-001/AC-003). Records
   * the content + a TTF timer keyed by content hash; a `persisted` ACK on the inbound
   * content stream resolves it, TTF expiry hands it to the park backstop. The timer is
   * `unref`'d so an in-flight wait never keeps the daemon process (or a test runner)
   * alive on its own.
   */
  #trackAwaitingAck(agentName: string, sessionId: string, content: Uint8Array, contentHash: Uint8Array, correlationId?: string, structure1Cbor?: Uint8Array, structure2Cbor?: Uint8Array): void {
    const hashHex = Buffer.from(contentHash).toString("hex");
    const ackKey = this.#k(agentName, sessionId);
    let bySession = this.#awaitingAck.get(ackKey);
    if (!bySession) { bySession = new Map(); this.#awaitingAck.set(ackKey, bySession); }
    // Replace any prior timer for the same (session, hash) so we never leak a timer.
    const prior = bySession.get(hashHex);
    if (prior) clearTimeout(prior.timer);
    const timer = setTimeout(() => {
      this.#handleTtfExpiry(agentName, sessionId, hashHex);
    }, this.#contentTtfMs);
    if (typeof (timer as { unref?: () => void }).unref === "function") (timer as { unref: () => void }).unref();
    // DOD-MSG-4 (2b, review #1): retain the relay's ordering record so a TTF-triggered park carries
    // it too (not only the direct-dial-fail park) — so a TTF-parked entry is self-ordering on recover.
    bySession.set(hashHex, { timer, content, correlationId, structure1Cbor, structure2Cbor });
  }

  /**
   * Resolve an awaiting-ACK entry on a `persisted` delivery ACK (AC-001/AC-002): cancel
   * the TTF timer, emit content.delivery.acked, and clear the durable backstop entry.
   * A `received`-level ACK is NOT handled here — the protocol acts on `persisted` only,
   * so a received ACK leaves the timer armed.
   */
  #resolveAwaitingAck(agentName: string, sessionId: string, contentHash: Uint8Array): void {
    const hashHex = Buffer.from(contentHash).toString("hex");
    const ackKey = this.#k(agentName, sessionId);
    const bySession = this.#awaitingAck.get(ackKey);
    const entry = bySession?.get(hashHex);
    if (!entry || !bySession) return; // unknown / already resolved — idempotent
    clearTimeout(entry.timer);
    bySession.delete(hashHex);
    if (bySession.size === 0) this.#awaitingAck.delete(ackKey);
    this.#logger.info("content.delivery.acked", {
      sessionId,
      contentHash: hashHex,
      level: "persisted",
      correlationId: entry.correlationId,
    });
    // Clear the durable crash-backstop entry so the startup flush does not re-park
    // already-delivered content.
    try {
      this.#onAwaitingPersisted?.(agentName, sessionId, hashHex);
    } catch (err: unknown) {
      this.#logger.error("content.delivery.ack.backstop.failed", {
        sessionId, contentHash: hashHex, error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  /**
   * TTF timer fired with no `persisted` ACK (AC-003/AC-019): hand the un-acked content
   * to the park backstop (the durable retry_queue today; the relay store-and-forward
   * deposit in 3b). The session is never killed and the operator is never interrupted —
   * parking is best-effort durability.
   */
  #handleTtfExpiry(agentName: string, sessionId: string, hashHex: string): void {
    const ackKey = this.#k(agentName, sessionId);
    const bySession = this.#awaitingAck.get(ackKey);
    const entry = bySession?.get(hashHex);
    if (!entry || !bySession) return;
    bySession.delete(hashHex);
    if (bySession.size === 0) this.#awaitingAck.delete(ackKey);
    this.#logger.debug("content.delivery.ttf_expired", { sessionId, contentHash: hashHex });
    try {
      this.#onAwaitingTtf?.(agentName, sessionId, hashHex, entry.content);
    } catch (err: unknown) {
      this.#logger.error("content.park.backstop.failed", {
        sessionId, contentHash: hashHex, error: err instanceof Error ? err.message : String(err),
      });
    }
    // 2b: delivered to the wire but never confirmed `persisted` — deposit it to the relay
    // store-and-forward so the recipient recovers it (at the witnessed sequence). The durable
    // awaiting entry above remains the crash backstop. Carry the retained ordering record (review #1)
    // so a TTF-parked entry self-orders on recover, exactly like the direct-dial-fail park.
    this.#parkContent(agentName, sessionId, hashHex, entry.content, entry.structure1Cbor, entry.structure2Cbor);
  }

  /**
   * Send an unsigned `persisted` delivery ACK back to the sender over the same
   * /cello/content/1.0.0 protocol (AC-001). Best-effort: authentication is the Noise
   * session channel, so the ACK carries no signature; a failed ACK send is logged and
   * the sender recovers via its TTF/recovery path rather than a thrown error here.
   */
  async #sendDeliveryAck(agentName: string, sessionId: string, contentHash: Uint8Array, correlationId?: string): Promise<void> {
    const entry = this.#activeNodes.get(this.#k(agentName, sessionId));
    if (!entry) return;
    try {
      const stream = await entry.node.newStream(entry.counterpartySessionPeerId, CELLO_CONTENT_PROTOCOL_ID);
      const frame = CBOR_ENC.encode({
        type: "content_delivery_ack",
        session_id: sessionId,
        content_hash: contentHash,
        level: "persisted",
        correlation_id: correlationId,
      }) as Uint8Array;
      stream.send(lp.encode.single(frame));
      try { await stream.close(); } catch { /* best-effort close */ }
    } catch (err: unknown) {
      this.#logger.warn("content.delivery.ack.send.failed", {
        sessionId,
        contentHash: Buffer.from(contentHash).toString("hex"),
        error: err instanceof Error ? err.message : String(err),
        correlationId,
      });
    }
  }

  /** Cancel and drop a single awaiting-ACK entry (e.g. the send failed after arming). */
  #untrackAwaitingAck(agentName: string, sessionId: string, contentHash: Uint8Array): void {
    const hashHex = Buffer.from(contentHash).toString("hex");
    const ackKey = this.#k(agentName, sessionId);
    const bySession = this.#awaitingAck.get(ackKey);
    const entry = bySession?.get(hashHex);
    if (!entry || !bySession) return;
    clearTimeout(entry.timer);
    bySession.delete(hashHex);
    if (bySession.size === 0) this.#awaitingAck.delete(ackKey);
  }

  /** Cancel and drop all awaiting-ACK timers for a session (teardown). */
  #clearAwaitingForSession(agentName: string, sessionId: string): void {
    const ackKey = this.#k(agentName, sessionId);
    const bySession = this.#awaitingAck.get(ackKey);
    if (!bySession) return;
    for (const entry of bySession.values()) clearTimeout(entry.timer);
    this.#awaitingAck.delete(ackKey);
  }

  #loadTreeFromDb(agentName: string, sessionId: string): SessionTree {
    if (!this.#db) return SessionTree.empty();
    const rows = this.#db
      .prepare(
        "SELECT leaf_kind, leaf_hash_hex FROM session_tree_leaves WHERE agent_name = ? AND session_id = ? ORDER BY leaf_index ASC",
      )
      .all(agentName, sessionId) as Array<{ leaf_kind: string; leaf_hash_hex: string }>;
    return SessionTree.fromLeaves(
      rows.map((r) => ({ kind: r.leaf_kind === "ctrl" ? "ctrl" : "msg", hashHex: r.leaf_hash_hex })),
    );
  }

  /**
   * DAEMON-004: register the /cello/content/1.0.0 handler on a session node so
   * inbound content_frames are decoded, cross-checked, and ingested.
   */
  // Awaited by createSessionNode / acceptSession so the /cello/content/1.0.0 handler
  // is provably registered before the caller returns (and thus before any peer sends
  // content). libp2p registers the protocol synchronously today, but awaiting removes
  // the fragile dependency on that internal timing (review L4).
  async #registerContentHandler(agentName: string, sessionId: string, node: CelloNode, _counterpartyPubkey: string): Promise<void> {
    try {
      await node.handle(CELLO_CONTENT_PROTOCOL_ID, (stream) => {
        void this.#handleContentStream(agentName, sessionId, stream);
      });
    } catch (err: unknown) {
      this.#logger.error("session.content.handler.register.failed", {
        sessionId,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  /**
   * DOD-MSG-4 (self-ordering content frame): verify the relay's signed ordering record carried IN the
   * content frame and record the canonical sequence for the strict-in-order gate — so ordering does
   * not depend on the separate leaf_deliver witness arriving first. Best-effort: any failure (malformed,
   * hash mismatch, bad signature, wrong signer) is logged and ignored — the content still ingests and
   * orders via the witness stream / arrival, so a bad record cannot block delivery.
   *
   * structure1_cbor = [1, content_hash(32), sender_pubkey(32), session_id(16), last_seen_seq, ts] —
   *   the EXACT bytes the sender signed (needed to verify; Structure2 omits session_id/last_seen/ts).
   * structure2_cbor = [seq, sender_pubkey, content_hash, sender_signature, scan_result, prev_root].
   */
  /**
   * DOD-MSG-4 (2b): encode the pre-seal park envelope `[1, content, structure1_cbor|null,
   * structure2_cbor|null]`. The daemon seals THIS (not the bare content) so a parked entry carries
   * its own signed ordering record — recover then orders it the same way the direct frame does. The
   * relay still only ever holds the sealed ciphertext (INV-3 preserved).
   */
  encodeParkEnvelope(content: Uint8Array, structure1Cbor?: Uint8Array, structure2Cbor?: Uint8Array): Uint8Array {
    return CBOR_ENC.encode([1, content, structure1Cbor ?? null, structure2Cbor ?? null]) as Uint8Array;
  }

  /**
   * DOD-MSG-4 (2b): decode a park envelope produced by encodeParkEnvelope. Falls back to treating the
   * whole plaintext as raw content (no ordering record) for entries sealed the old way (e.g. test
   * fixtures that seal bare content) — so recover stays backward-compatible.
   */
  decodeParkEnvelope(plaintext: Uint8Array): { content: Uint8Array; structure1Cbor?: Uint8Array; structure2Cbor?: Uint8Array } {
    try {
      const arr = decode(plaintext) as unknown[];
      // Discriminator (review #2): a 4-element array tagged with version 1 + a byte-string content.
      // The content-hash cross-check in ingestReceivedContent is the real safety net, but narrowing
      // to length 4 makes a bare-content false-positive astronomically less likely still.
      if (Array.isArray(arr) && arr.length === 4 && arr[0] === 1 && arr[1] instanceof Uint8Array) {
        return {
          content: arr[1],
          structure1Cbor: arr[2] instanceof Uint8Array ? arr[2] : undefined,
          structure2Cbor: arr[3] instanceof Uint8Array ? arr[3] : undefined,
        };
      }
    } catch {
      /* not an envelope — fall through to raw */
    }
    return { content: plaintext };
  }

  /**
   * DOD-MSG-4 (2b): public entry for the recover path to verify + record a parked entry's ordering
   * record (the recover handler lives in daemon.ts, which has no access to the private method).
   */
  recordOrderingRecord(
    agentName: string,
    sessionId: string,
    structure1Cbor: Uint8Array,
    structure2Cbor: Uint8Array,
    contentHash: Uint8Array,
    correlationId?: string,
  ): void {
    this.#recordFrameOrdering(agentName, sessionId, structure1Cbor, structure2Cbor, contentHash, correlationId, "park");
  }

  #recordFrameOrdering(
    agentName: string,
    sessionId: string,
    structure1Cbor: Uint8Array,
    structure2Cbor: Uint8Array,
    contentHash: Uint8Array,
    correlationId?: string,
    source: string = "content_frame",
  ): void {
    try {
      const s1 = decode(structure1Cbor) as unknown[];
      const s2 = decode(structure2Cbor) as unknown[];
      const s1Hash = s1?.[1];
      const s1Pubkey = s1?.[2];
      const seq = typeof s2?.[0] === "number" ? s2[0] : -1;
      const s2Sig = s2?.[3];
      if (!(s1Hash instanceof Uint8Array) || !(s1Pubkey instanceof Uint8Array) || !(s2Sig instanceof Uint8Array) || seq < 1) {
        this.#logger.warn("session.content.ordering.malformed", { sessionId, correlationId });
        return;
      }
      // The framed ordering record must bind to THIS content (its hash) — else it orders the wrong bytes.
      const contentHashHex = Buffer.from(contentHash).toString("hex");
      if (Buffer.from(s1Hash).toString("hex") !== contentHashHex) {
        this.#logger.warn("session.content.ordering.hash_mismatch", { sessionId, correlationId });
        return;
      }
      // Verify the SENDER's Ed25519 signature over the exact signed bytes (structure1_cbor) — the same
      // check the relay performs. Proves the counterparty committed to this (content_hash @ sequence).
      if (!verify(s1Pubkey, structure1Cbor, s2Sig)) {
        this.#logger.warn("session.content.ordering.bad_signature", { sessionId, correlationId });
        return;
      }
      // Sovereign-node cross-check: the signer MUST be THIS session's counterparty, not an unrelated
      // key. FAIL CLOSED (review L) — if the counterparty pubkey is unknown we cannot prove the signer,
      // so we do NOT trust the framed ordering record (fall back to the witness stream / arrival). The
      // "B does not trust the counterparty for ordering" invariant is non-negotiable; never fail open.
      const counterparty = this.getSessionRecord(agentName, sessionId)?.counterparty_pubkey;
      if (!counterparty || Buffer.from(s1Pubkey).toString("hex") !== counterparty) {
        this.#logger.warn("session.content.ordering.wrong_signer", {
          sessionId,
          reason: counterparty ? "signer_not_counterparty" : "counterparty_unknown",
          correlationId,
        });
        return;
      }
      // Verified — record the relay-assigned canonical sequence (1-based → 0-based leaf index) for the gate.
      this.recordWitnessedSequence(agentName, sessionId, contentHashHex, seq - 1);
      this.#logger.info("session.content.ordering.recorded", {
        sessionId,
        canonicalSeq: seq - 1,
        source,
        correlationId,
      });
    } catch (err: unknown) {
      this.#logger.warn("session.content.ordering.decode_failed", {
        sessionId,
        error: err instanceof Error ? err.message : String(err),
        correlationId,
      });
    }
  }

  async #handleContentStream(agentName: string, sessionId: string, stream: Stream): Promise<void> {
    const iter = (lp.decode(stream) as AsyncIterable<unknown>)[Symbol.asyncIterator]() as AsyncIterator<Uint8Array>;
    try {
      const result = await iter.next();
      if (result.done || result.value === undefined) return;
      const bytes = result.value instanceof Uint8Array ? result.value
        : Buffer.isBuffer(result.value) ? new Uint8Array(result.value as Buffer)
        : (result.value as { slice(): Uint8Array }).slice();
      const frame = decode(bytes) as Record<string, unknown>;
      const correlationId = typeof frame["correlation_id"] === "string" ? frame["correlation_id"] : undefined;

      // CELLO-M7-MSG-001 (AC-001/AC-002): a `persisted` delivery ACK arriving on the
      // same /cello/content/1.0.0 protocol resolves the sender's awaiting-ACK timer.
      // The protocol acts on `persisted` ONLY — any other level leaves the timer armed.
      if (frame["type"] === "content_delivery_ack") {
        const ackHash = frame["content_hash"];
        const level = frame["level"];
        if (ackHash instanceof Uint8Array && level === "persisted") {
          this.#resolveAwaitingAck(agentName, sessionId, ackHash);
        }
        return;
      }

      if (frame["type"] !== "content_frame") return;
      const contentBytes = frame["content_bytes"];
      const contentHash = frame["content_hash"];
      if (!(contentBytes instanceof Uint8Array) || !(contentHash instanceof Uint8Array)) return;
      // DOD-MSG-4 (self-ordering content frame): if the frame carries the relay's signed ordering
      // record, verify the sender signature and record the canonical sequence FROM THE FRAME, BEFORE
      // ingest — so the strict-in-order gate has the position without waiting on the separate
      // leaf_deliver witness (removes the content-before-witness race). A bad/absent record is
      // non-fatal: the content still ingests, ordered by the witness stream / arrival as before.
      const s1Cbor = frame["structure1_cbor"];
      const s2Cbor = frame["structure2_cbor"];
      if (s1Cbor instanceof Uint8Array && s2Cbor instanceof Uint8Array) {
        this.#recordFrameOrdering(agentName, sessionId, s1Cbor, s2Cbor, contentHash, correlationId);
      }
      // AC-001: carry the sender's correlationId from the frame into the receive
      // path so both sides log the same flow id (never re-minted on receipt).
      const ingest = this.ingestReceivedContent(agentName, sessionId, contentBytes, contentHash, correlationId);
      // AC-001: after the content is durably ingested AND its hash cross-check
      // succeeds, emit an unsigned `persisted` delivery ACK back to the sender. A
      // rejected ingest (tamper / not-active) produces NO ACK, so the sender's TTF
      // path can park / recover.
      // DOD-MSG-4: a HELD (out-of-order) frame is NOT yet a durable leaf, so it is NOT
      // acknowledged `persisted` — the sender's TTF→park backstop then guarantees the
      // missing-earlier message is fetchable, and dedup absorbs the redundant copy.
      if (ingest.ok && !ingest.held) {
        void this.#sendDeliveryAck(agentName, sessionId, contentHash, correlationId);
      }
    } catch (err: unknown) {
      this.#logger.warn("session.content.stream.read.failed", {
        sessionId,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  /**
   * M7-SESSION-001 AC-004/AC-005: Register a relay stream for an active session.
   * Starts a background reader that watches for session_interrupted frames and
   * stream close events. Both detection paths call markInterruptedWithDetails().
   *
   * The reader runs for the lifetime of the relay stream. If the stream closes
   * without delivering a session_interrupted frame (AC-005 / 'stream_close' path),
   * the session is still marked interrupted.
   *
   * @param sessionId The hex session ID
   * @param stream The relay stream to monitor
   * @param messageCount Number of message leaves at the time of registration
   *   (used as the count at interruption — best effort since exact count at frame
   *   receipt may differ, but this is the value available at stream setup time)
   */
  registerRelayStream(agentName: string, sessionId: string, stream: Stream, messageCount: number = 0): void {
    void this.#watchRelayStream(agentName, sessionId, stream, messageCount);
  }

  /**
   * Background relay stream watcher.
   * Pseudocode:
   *   1. Create LP-framed iterator over the stream
   *   2. For each frame:
   *      a. If type === 'session_interrupted':
   *         - Record receivedInterruptFrame = true
   *         - Call markInterruptedWithDetails(sessionId, messageCount, 'relay_frame')
   *         - Break (no more frames expected)
   *   3. On stream close (loop ends normally or with error):
   *      a. If !receivedInterruptFrame:
   *         - Call markInterruptedWithDetails(sessionId, messageCount, 'stream_close')
   */
  async #watchRelayStream(agentName: string, sessionId: string, stream: Stream, messageCount: number): Promise<void> {
    let receivedInterruptFrame = false;
    // CELLO-M7-TRANSPORT-001: cast the stream input to lp.decode. Adding the
    // @libp2p/autonat service (interface@3.2.2 / uint8arraylist v2) to the
    // transport package surfaced a benign mixed-version split between the Stream
    // type (now v2) and it-length-prefixed's expected Uint8ArrayList (v3). The two
    // are structurally identical at runtime — this is a build-time-only artifact.
    const lpSource = stream as unknown as AsyncIterable<Uint8Array>;
    const source = (lp.decode(lpSource) as AsyncIterable<unknown>)[Symbol.asyncIterator]() as AsyncIterator<Uint8Array>;
    try {
      while (true) {
        let result: IteratorResult<Uint8Array>;
        try {
          result = await source.next();
        } catch {
          // Stream error (e.g. stream aborted) — treat as stream close
          break;
        }
        if (result.done || result.value === undefined) break;

        let frame: Record<string, unknown>;
        try {
          const bytes = result.value instanceof Uint8Array ? result.value
            : Buffer.isBuffer(result.value) ? new Uint8Array(result.value as Buffer)
            : (result.value as { slice(): Uint8Array }).slice();
          frame = decode(bytes) as Record<string, unknown>;
        } catch {
          continue;
        }

        if (frame["type"] === "session_interrupted") {
          // H-3 SECURITY: this stream is registered (bound) to a specific
          // sessionId. A malicious or buggy relay could put a DIFFERENT session_id
          // in the frame body to target a session this stream is not authorized
          // for (cross-session targeting). Never trust the frame's id: if the frame
          // names a different session, reject it and keep watching the bound one.
          const frameSessionId = typeof frame["session_id"] === "string"
            ? frame["session_id"]
            : (frame["session_id"] instanceof Uint8Array
              ? Buffer.from(frame["session_id"]).toString("hex")
              : null);
          if (frameSessionId !== null && frameSessionId !== sessionId) {
            this.#logger.warn("session.interrupt.frame.session_mismatch", {
              boundSessionId: sessionId,
              frameSessionId,
              reason: "cross_session_frame_rejected",
            });
            continue; // ignore the hostile/mismatched frame; keep reading
          }
          receivedInterruptFrame = true;
          // Always mark the BOUND sessionId — never the id carried in the frame.
          await this.markInterruptedWithDetails(agentName, sessionId, messageCount, "relay_frame");
          break; // No more relay frames expected after session_interrupted
        }
      }
    } catch {
      // Stream read loop ended — fall through to stream_close check
    }

    // AC-005: stream closed without a session_interrupted frame
    if (!receivedInterruptFrame) {
      // Only mark interrupted if this session is still active in SQLite
      const record = this.getSessionRecord(agentName, sessionId);
      if (record && record.status === "active") {
        await this.markInterruptedWithDetails(agentName, sessionId, messageCount, "stream_close");
      }
    }
  }

  // ─── Private helpers ──────────────────────────────────────────────────────

  /**
   * DOD-LOOP-1: ensure the given agent has a standing receiver node (idempotent). Created when an
   * agent comes online (cello_start_agent) and replaced after it is handed off to a session. The
   * `#standingReceiverCreating` guard prevents two concurrent ensure() calls (e.g. the
   * cello_start_agent hook racing a consume-site retry) from building two nodes for one agent.
   *
   * M8B F14: a create failure no longer strands the agent deaf. Each ensure runs a BOUNDED
   * retry loop (`standingReceiverRetryDelaysMs`, default 1s/5s/15s) — covering the fixed-port
   * race where the consumed receiver still holds the port until its session node is torn down —
   * and when every attempt fails, fires the alarm-worthy `session.standing_receiver.dead`
   * (error level), distinct from the per-attempt `session.node.create.failed`. Re-arm is also
   * kicked from destroySessionNode/retireSessionNode (the moment the port frees) and from the
   * inbound accept path (ensure on demand), so one failure can never leave the agent deaf forever.
   */
  async #ensureStandingReceiver(agentName: string, correlationId: string = randomUUID()): Promise<void> {
    if (this.#standingReceivers.has(agentName) || this.#standingReceiverCreating.has(agentName)) return;
    if (this.#shuttingDown) return;
    // A fresh ensure request supersedes any pending removal (agent toggled offline→online).
    this.#standingReceiverRemoving.delete(agentName);
    this.#standingReceiverCreating.add(agentName);
    try {
      let lastError = "";
      for (let attempt = 0; attempt <= this.#srRetryDelaysMs.length; attempt++) {
        if (attempt > 0) {
          await new Promise((r) => setTimeout(r, this.#srRetryDelaysMs[attempt - 1]));
        }
        if (this.#shuttingDown) return;
        // L1 tombstone: the agent went offline while we were creating / backing off.
        if (this.#standingReceiverRemoving.has(agentName)) {
          this.#standingReceiverRemoving.delete(agentName);
          return;
        }
        const result = await this.#tryCreateStandingReceiver(agentName, correlationId);
        if (result.outcome !== "failed") return; // installed, or cleanly aborted (shutdown/offline)
        lastError = result.error;
      }
      // M8B F14 (fix 4): an agent that WANTS a receiver has none after every attempt — the
      // deaf-agent state. Fail LOUD so it is alarm-visible instead of a quiet degradation.
      this.#logger.error("session.standing_receiver.dead", {
        agentName,
        reason: lastError,
        attempts: this.#srRetryDelaysMs.length + 1,
        correlationId,
      });
    } finally {
      this.#standingReceiverCreating.delete(agentName);
    }
  }

  /** One standing-receiver create attempt (extracted for the M8B F14 retry loop). */
  async #tryCreateStandingReceiver(
    agentName: string,
    correlationId: string,
  ): Promise<{ outcome: "installed" | "aborted" } | { outcome: "failed"; error: string }> {
    const sessionId = `standing_receiver_${randomUUID()}`;
    const gater = new SessionConnectionGater({
      sessionId,
      allowedPeerId: null, // open — counterparty unknown at creation time
      logger: this.#logger,
    });

    let node: CelloNode;
    try {
      node = await this.#factory.createNode({ sessionId, connectionGater: gater, nodeType: "standing_receiver" });
      await node.start();
    } catch (err: unknown) {
      const error = err instanceof Error ? err.message : String(err);
      this.#logger.error("session.node.create.failed", {
        sessionId,
        agentName: `${STANDING_RECEIVER_AGENT_NAME}:${agentName}`,
        error,
        correlationId,
      });
      return { outcome: "failed", error };
    }

    // M2: gracefulShutdown may have begun while this node was starting (ensure runs un-awaited).
    // Don't install an orphan bound to a TCP port — stop it and bail.
    if (this.#shuttingDown) {
      try { await node.stop(); } catch { /* best-effort */ }
      return { outcome: "aborted" };
    }

    // L1: the agent may have gone offline (cello_stop_agent → removeStandingReceiverForAgent)
    // while this ensure was parked on start(). Removal found no map entry to delete, so the
    // tombstone is how we learn of it — tear the fresh node down rather than install an SR for
    // an offline agent.
    if (this.#standingReceiverRemoving.has(agentName)) {
      this.#standingReceiverRemoving.delete(agentName);
      try { await node.stop(); } catch { /* best-effort */ }
      return { outcome: "aborted" };
    }

    // CELLO-M7-TRANSPORT-001: wrap in a NodeAutoNatService so its dialability drives session-
    // address advertisement and the transport.autonat.* events fire.
    const autoNat = new NodeAutoNatService({
      node,
      logger: this.#logger,
      nodeType: "standing_receiver",
      probers: this.#autoNatProbers(),
    });
    autoNat.emitInitialResult();

    this.#standingReceivers.set(agentName, { node, gater, autoNat });
    this.#logger.info("session.node.created", {
      sessionId,
      agentName: `${STANDING_RECEIVER_AGENT_NAME}:${agentName}`,
      sessionPeerId: node.getPeerId(),
      correlationId,
    });
    return { outcome: "installed" };
  }

  /**
   * DOD-LOOP-1: public hook for the composition root to create an agent's standing receiver when
   * the agent comes online (cello_start_agent), and to tear it down when it goes offline.
   * M8B F14: also called from the inbound accept path (ensure on demand). Marks the agent as
   * WANTING a receiver, which arms the teardown re-arm in destroySessionNode/retireSessionNode.
   */
  async ensureStandingReceiverForAgent(agentName: string): Promise<void> {
    this.#agentsWantingReceiver.add(agentName);
    await this.#ensureStandingReceiver(agentName);
  }

  async removeStandingReceiverForAgent(agentName: string): Promise<void> {
    // M8B F14: the agent no longer wants a receiver — disarm the teardown re-arm.
    this.#agentsWantingReceiver.delete(agentName);
    const sr = this.#standingReceivers.get(agentName);
    if (!sr) {
      // L1: an #ensureStandingReceiver for this agent may be in flight (parked on start(), so no
      // map entry yet). Leave a tombstone — that ensure tears its fresh node down on completion
      // instead of installing an SR for an agent that is now offline. Also drop any stale creating
      // marker so a later start can re-ensure.
      if (this.#standingReceiverCreating.has(agentName)) this.#standingReceiverRemoving.add(agentName);
      return;
    }
    this.#standingReceivers.delete(agentName);
    // Best-effort teardown, but NOT silent: a standing receiver that failed to stop keeps a libp2p
    // node live on the network. For a removal/retire (a revocation-class action) that must be visible,
    // so the caller and the operator can see the leak rather than trust a false "torn down". autoNat is
    // inside the try too — its stop() throwing must not skip node.stop() or escape unlogged.
    try {
      sr.autoNat.stop();
      await sr.node.stop();
    } catch (err) {
      this.#logger.warn("session.standing_receiver.teardown.failed", {
        agentName,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  #insertSessionRow(
    sessionId: string,
    agentName: string,
    counterpartyPubkey: string,
    status: "active" | "sealed" | "interrupted",
  ): boolean {
    if (!this.#db) return false;
    const now = Date.now();
    try {
      this.#db
        .prepare(
          `INSERT INTO sessions
           (session_id, agent_name, counterparty_pubkey, status, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?)`,
        )
        .run(sessionId, agentName, counterpartyPubkey, status, now, now);
      return true;
    } catch (err: unknown) {
      this.#logger.error("session.interrupt.db.write.failed", {
        sessionId,
        error: err instanceof Error ? err.message : String(err),
      });
      return false;
    }
  }

  #updateSessionStatus(
    agentName: string,
    sessionId: string,
    status: "active" | "sealed" | "interrupted",
  ): void {
    if (!this.#db) return;
    const now = Date.now();
    try {
      this.#db
        .prepare(
          "UPDATE sessions SET status = ?, updated_at = ? WHERE agent_name = ? AND session_id = ?",
        )
        .run(status, now, agentName, sessionId);
    } catch (err: unknown) {
      this.#logger.error("session.interrupt.db.write.failed", {
        sessionId,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }
}
