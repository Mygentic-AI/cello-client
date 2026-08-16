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
 *   4. Session status in the DB: active → sealed (on close) or interrupted
 *      (on graceful shutdown or SIGKILL-restart detection).
 *
 * Interrupted-session detection runs BEFORE the IPC socket opens, so a client cannot observe a
 * stale 'active' row from a previous process.
 */

// The daemon DB is SQLCipher (whole-file AES-256 at rest), never `node:sqlite`. `DaemonDatabase` is
// the thin varargs surface; `openEncryptedDatabase` opens with a PRAGMA key and `resolveDbKey`
// manages the single plaintext key file.
import { wireContentHash } from "./wire-content-hash.js";
import {
  type DaemonDatabase,
  openEncryptedDatabase,
  resolveDbKey,
  dbKeyPathFor,
} from "./sqlcipher-db.js";
import { migrateToEncryptedIfNeeded } from "./identity-migration.js";
import { ensureIdentitySchema } from "./db-identity-store.js";
import { migrateSessionTablesToAgentId } from "./agent-id-migration.js";
import { TIER, normalizeTier, isKnownTierValue, tierBoundsFor, DEFAULT_TIER_BOUNDS, migrateContactsAddTierMetadata } from "./contacts-tier-migration.js";
import { migrateCborBlobsToCanonical } from "./cbor-blob-migration.js";
import { ensureTrustSignalSchema } from "./trust-signal-store.js";
import { boundSettingKey, settableTierName, isValidSettingKey, awayTierSettingKey, AWAY_DEFAULT_KEY } from "./agent-settings-keys.js";
import { randomUUID, createHash } from "node:crypto";
import * as lp from "it-length-prefixed";
import { decode } from "cbor-x";
import { encodeCbor } from "@cello-protocol/protocol-types";
import type { Stream } from "@libp2p/interface";
import type { Logger, SessionRecord } from "./types.js";
import { MAX_SESSION_NODES, STANDING_RECEIVER_AGENT_NAME } from "./types.js";
import { SessionConnectionGater } from "./session-connection-gater.js";
import { SessionTree, sessionTreeLeafKindFromDb, type WritableSessionTreeLeafKind } from "./session-tree.js";
import { CELLO_CONTENT_PROTOCOL_ID, NodeAutoNatService, type CelloNode, type IAutoNatService } from "@cello-protocol/transport";
import type { KeyProvider } from "@cello-protocol/crypto";
import { verify } from "@cello-protocol/crypto";
import { encodeSealPayload, MONIKER_RE, validateMoniker } from "@cello-protocol/protocol-types";
import { decodeParkEnvelope, authenticateParkedEntry, pubkeyMatchesHex, type ParkEnvelope, type ParkAuthFailure } from "./park-envelope.js";
import { isValidMultiaddr } from "@cello-protocol/transport";
import { AgentRelayClient, LEAF_KIND_CTRL, LEAF_KIND_MSG, isTerminalRelayRefusal, extractErrorMessage, type RelayAssignmentCarry } from "./session-relay-client.js";
import { terminalRelayRefusal } from "./session-terminal-refusal.js";
import { RelayReceiptStore, type RelayReceipt } from "./relay-receipt-store.js";


import { SessionSealLeafStore, type SealCarryLeaf } from "./session-seal-leaf-store.js";
import {
  GATEWAY_UNAVAILABLE,
  GOVERNANCE_TIMEOUT,
  type SecurityGatewayClient,
} from "@cello-protocol/gateway";


/** SEC-1 / review M4: cap on the refused-parked-entry memo (remote-fed → must be bounded). */
/**
 * How long the auto-acknowledge path holds its broker visiting connection AFTER submitting the seal
 * leaf. The directory pushes `seal_verified` back ~60ms later (measured on GCP), so releasing on
 * submit closed the stream before the frame it was opened for. Generous against 60ms, and bounded so
 * a stalled seal cannot leak the connection.
 */
const AUTOACK_BROKER_GRACE_MS = 30_000;

const MAX_REFUSED_PARKED_ENTRIES = 512;

// Persistence bounds are TIER-GRADUATED via DEFAULT_TIER_BOUNDS (contacts-tier-migration). The two
// consts below DERIVE from the grid's UNKNOWN row rather than restating it — the grid is the single
// source (DOD-TIER-2 AC4), so these can never drift from it.
/** Anti-drip-feed: cumulative RECEIVED bytes per session at the UNKNOWN tier (= the grid's UNKNOWN
 *  byte cap). Higher tiers get more (DEFAULT_TIER_BOUNDS); no tier is unbounded (INV-TIER-BOUND). */
export const ABUSE_MAX_SESSION_RECEIVED_BYTES = DEFAULT_TIER_BOUNDS[TIER.UNKNOWN].maxBytesPerSession; // 25 MB
/** Anti-drip-feed via many sessions: active sessions an UNKNOWN counterparty may hold open at once
 *  (= the grid's UNKNOWN per-sender cap). */
export const ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER = DEFAULT_TIER_BOUNDS[TIER.UNKNOWN].maxSessionsPerSender; // 3
/** Anti-swarm: total active sessions from ALL UNKNOWN-tier counterparties combined, per agent. A
 *  scalar across the whole unknown pool — not per-tier — so it stays a standalone const. */
export const ABUSE_MAX_UNKNOWN_SESSIONS_GLOBAL = 50;

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

/**
 * DOD-PARK-DRAIN-1: why the parked-mailbox drain is being asked to run.
 *
 * `standing_receiver_ready` — a receiver was just installed, first time or rebuilt. The rebuild is
 * the case that matters: content parks precisely because the relay link died, and the watchdog
 * rebuild is that same event seen from the client side.
 * `periodic_backstop` — nothing happened; this is the slow sweep that keeps a missed trigger from
 * stranding content until someone restarts the daemon. Drains are deduped and delete-on-confirm,
 * so an extra one costs a pull.
 */
export type ParkedDrainReason = "standing_receiver_ready" | "periodic_backstop";

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
  /**
   * DOD-NAT-REACHABILITY-1: circuit-relay listen addresses
   * (`<relay-multiaddr>/p2p/<relay-peer-id>/p2p-circuit`) the node should take
   * reservations on. Each entry makes libp2p reserve a slot with that relay and
   * advertise the relayed address via getMultiaddrs() — which is what makes a
   * NAT'd standing receiver dialable at all. A dead relay in this list degrades
   * (no reservation, WARN) — it never fails node creation.
   */
  circuitRelayListenAddrs?: string[];
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

/**
 * DOD-COATTEND-1: how much of the arrival buffer is kept. Delivery reads the durable transcript
 * now, so this buffer is only a recency hint (`peekLatestReceivedContentHex` for M8C-AWAY-1's
 * [[WRAP]] check). Small, and stated: an unstated cap is a silent truncation, and no cap at all is
 * the leak the old destructive read was accidentally preventing.
 */
const RECEIVED_BUFFER_CAP = 32;

/**
 * M12-P12 (review F6): the outcome of one park-deposit attempt. A bare boolean conflated
 * "this session has no relay to park to" with "the relay refused the deposit" — only the latter is
 * worth queuing for a later retry, and queuing the former grows the durable queue with rows that
 * can never drain.
 */
/**
 * M12-P13 (review MEDIUM-5): the outcome AND the cause. `standing_receiver_unavailable` is an
 * exit-point label; `cause` is the four-way answer from `standingReceiverAbsenceReason()` that says
 * WHICH state the receiver was in — the distinction M12-P12 added precisely because the label had
 * misnamed this incident. It used to be logged here and then discarded at the mapping site, so the
 * caller (and the operator reading `reason`) was sent to the transport when the blocker was the
 * standing receiver.
 */
// M12-P18: how many refused session ids to retain per agent (drain-sweep matching, not security).
type ParkAttempt = { outcome: "parked" | "refused" | "unconfigured"; cause?: string };

export class SessionNodeManager {
  readonly #factory: ISessionNodeFactory;
  readonly #logger: Logger;
  readonly #dbPath: string;
  #db: DaemonDatabase | null = null;
  /**
   * DOD-COATTEND-1 (review F2): sessions whose RECEIVED transcript row failed to write, and are
   * therefore holding content that can never be delivered. Read by `cello_receive` so the timeout
   * answer names the local failure instead of telling the operator to keep waiting on a
   * counterparty who already sent. Keyed (agent, session) → the leaf sequences that were lost.
   */
  readonly #undeliverableSeqs = new Map<string, Set<number>>();
  /** RELAYSIG-1: shared immutable store of the relay's signed ordering-record receipts (keyed by agent). */
  #relayReceiptStore: RelayReceiptStore | null = null;
  /** FED-OPTIONB-SEAL-001: the per-session leaf log (both parties) carried at a unilateral seal. */
  #sealLeafStore: SessionSealLeafStore | null = null;
  // M9-CORE-001: the inbound screening seam. Every byte that reaches the agent passes
  // through #appendVerifiedContent's buffer write; screenInbound gates it there, on every
  // arrival path (direct, held-release, recovered-park). Defaults to always-allow when no
  // gateway is configured (SI-001: still a verdict, not an ungated pass).
  readonly #securityGateway: SecurityGatewayClient;
  #activeNodes = new Map<string, ActiveSessionEntry>();
  // M7 DOD-SPINE-6 / MSG-001-3b: ONE relay witness client per AGENT (keyed by agent name).
  // The relay authenticates and keys delivery by the agent's K_local pubkey, so all of an
  // agent's sessions share one authenticated relay stream (each frame carries session_id).
  #relayClients = new Map<string, AgentRelayClient>();

  /**
   * M12-P15: build a relay client for a session that has NO in-memory node.
   *
   * Injected by the composition root because it needs the agent's K_local and pubkey, which this
   * manager deliberately does not hold. Only consulted on the detached seal path — an ACTIVE session
   * always uses its own registered client.
   */
  #detachedRelayClientBuilder: ((agentName: string, relayPeerId: string, relayAddrs: string[], stores: { receiptStore?: RelayReceiptStore; sealLeafStore?: SessionSealLeafStore }) => AgentRelayClient | undefined) | null = null;
  setDetachedRelayClientBuilder(fn: (agentName: string, relayPeerId: string, relayAddrs: string[], stores: { receiptStore?: RelayReceiptStore; sealLeafStore?: SessionSealLeafStore }) => AgentRelayClient | undefined): void {
    this.#detachedRelayClientBuilder = fn;
  }

  /**
   * M12-P15: what a seal leaf actually needs, resolved from a LIVE node when there is one and from
   * durable state when there is not.
   *
   * `submitSealLeaf` used to hard-require an `#activeNodes` entry. But it is reachable — by design —
   * for an `interrupted` session, and EVERY producer of that status deletes the entry. So the guard
   * refused 100% of the calls the seal-interrupted path could ever make, which is what made M12-P15's
   * first fix inert. `submitLeaf(node, sessionId, contentHash, leafKind)` takes everything
   * explicitly; nothing about it needs a per-session node.
   *
   * The fallback is the same shape `startupParkFn` already uses for content: the persisted relay
   * endpoint (`relay_peer_id`/`relay_addrs`, columns that exist for exactly this reason) plus the
   * owning agent's standing receiver. Every failure is named for its own cause rather than collapsed
   * into "no node", because that collapse is what sent this investigation at the session lifecycle
   * instead of at the endpoint.
   */
  #resolveSealTransport(agentName: string, sessionId: string):
    | { node: CelloNode; relayClient: AgentRelayClient; relaySessionIdBytes: Uint8Array }
    | { error: string } {
    const entry = this.#activeNodes.get(this.#k(agentName, sessionId));
    if (entry) {
      // The live path is unchanged and takes precedence — a session with its own registered client
      // must never seal through a rebuilt one.
      if (!entry.relayClient || !entry.relaySessionIdBytes) return { error: "relay_unavailable" };
      return { node: entry.node, relayClient: entry.relayClient, relaySessionIdBytes: entry.relaySessionIdBytes };
    }
    const ep = this.getPersistedRelayEndpoint(agentName, sessionId);
    if (!ep) return { error: "no_persisted_relay_endpoint" };
    const node = this.getStandingReceiverNode(agentName);
    if (!node) return { error: "standing_receiver_unavailable" };
    // Reuse the agent's existing client for this relay when the process still has one; otherwise ask
    // the composition root to build one. Without the builder this path would work only within the
    // lifetime that created the session — and the case that matters most is precisely a daemon that
    // RESTARTED, which is what marked the session interrupted in the first place.
    const clientKey = `${agentName}::${ep.relayPeerId}`;
    let client = this.#relayClients.get(clientKey);
    if (!client) {
      // Review HIGH-1: the stores are NOT optional here. Without them `#captureReceipt` silently
      // `return false`s — the submit still reports ok while the relay's signed receipt and our OWN
      // 0x02 ctrl leaf are never persisted. That drops the unilateral-escalation carry chain AND
      // defeats this very unit's ceremony discriminator, which reads `session_seal_leaves`: a seal
      // sent through here would later read as "ceremony unknown" and the peer would decline to
      // sign. The fix would have broken the fix.
      if (!this.#relayReceiptStore && this.#db) this.#relayReceiptStore = new RelayReceiptStore(this.#db, this.#logger);
      if (!this.#sealLeafStore && this.#db) this.#sealLeafStore = new SessionSealLeafStore(this.#db, this.#logger);
      client = this.#detachedRelayClientBuilder?.(agentName, ep.relayPeerId, [...ep.relayAddrs], {
        receiptStore: this.#relayReceiptStore ?? undefined,
        sealLeafStore: this.#sealLeafStore ?? undefined,
      });
      if (!client) return { error: "relay_client_unavailable" };
      // Review MEDIUM-4: cache it, so a retry loop does not leak one authenticated relay stream per
      // attempt. Safe ONLY because the client above now carries the stores — a store-less client
      // cached under this key would be picked up by the live `#connectSessionRelay` path and poison
      // it for the rest of the process.
      this.#relayClients.set(clientKey, client);
    }
    // Review HIGH-2: register the session (no assignment — there is nothing to re-present) so the
    // relay's `session_not_found` is interpreted honestly. Unregistered, `recordedBefore` is false,
    // the retry loop runs pointlessly, and the `recordedBefore && session_not_found ->
    // relay_session_gone` branch — which exists to tell "the relay never had it" apart from "the
    // relay swept or sealed it" — can never fire, so the operator is handed a first-message-race
    // label for a swept session.
    client.registerSession(sessionId, node);
    return { node, relayClient: client, relaySessionIdBytes: new Uint8Array(Buffer.from(sessionId, "hex")) };
  }
  // DOD-LOOP-1: the standing receiver is PER-AGENT, not per-daemon. A daemon hosting two agents
  // (the loopback case) needs each agent to have its OWN inbound receiver node — otherwise the
  // initiator (consuming its agent's standing receiver) and the responder (consuming its agent's)
  // would contend for a single node and thrash. Keyed by agentName. A creation-in-flight guard set
  // prevents two concurrent ensure() calls from building two nodes for the same agent.
  // `hasReservation`: this receiver came up holding a /p2p-circuit address. The
  // watchdog uses it to tell "lost its reservation" (must recover) apart from
  // "never had one" (already degraded, and already loud) — see #reservationWatchdogTick.
  #standingReceivers = new Map<string, { node: CelloNode; gater: SessionConnectionGater; autoNat: NodeAutoNatService; hasReservation: boolean; relayPeerId?: string }>();
  #standingReceiverCreating = new Set<string>();
  // M8B F14: agents that SHOULD have a standing receiver — marked by
  // ensureStandingReceiverForAgent (cello_start_agent / the inbound accept path) and
  // unmarked by removeStandingReceiverForAgent (cello_set_agent_offline). Consulted by the
  // teardown re-arm so a session-node teardown never re-arms an offline agent.
  #agentsWantingReceiver = new Set<string>();
  // M8B F14: standing-receiver create retry schedule (see constructor opts).
  #srRetryDelaysMs: number[];
  /** DOD-NAT-REACHABILITY-1: reservation deadline — see #startReceiverNode. */
  #srReservationTimeoutMs: number;
  /** DOD-NAT-REACHABILITY-1: watchdog for a SILENTLY lost reservation. */
  #srWatchdogIntervalMs: number;
  #reservationWatchdog: ReturnType<typeof setInterval> | null = null;
  /** DOD-PARK-DRAIN-1: how often the backstop drain rides the watchdog grid — see #parkedDrainBackstopTick. */
  #parkedDrainBackstopMs: number;
  #parkedDrainLastBackstopAt = 0;
  /** DOD-PARK-DRAIN-1: the composition root's parked-mailbox drain — see setParkedDrainHook. */
  #parkedDrainHook: ((agentName: string, reason: ParkedDrainReason) => void) | null = null;
  #parkedDrainHookAbsenceLogged = false;
  // Agents whose removeStandingReceiverForAgent ran while an #ensureStandingReceiver for them was
  // in flight (parked on createNode/start, so the map had no entry to delete yet). The in-flight
  // ensure checks this after start() and tears the fresh node down instead of installing an SR for
  // an agent that has since gone offline (cello_set_agent_offline race). A fresh ensure clears it.
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
  #heldContent = new Map<string, Map<number, { content: Uint8Array; originalContent?: Uint8Array; contentHashHex: string; correlationId?: string; screenedOut?: boolean }>>();
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
  /**
   * Fix #1 EXTENSION (cross-node seal-liveness), injected by daemon.ts because the broker-dial
   * machinery (consortium roster + visiting connections) lives above this class.
   *
   * The AUTO-ACKNOWLEDGE path below submits a seal leaf, and the directory answers it within ~60ms
   * by pushing `seal_verified` to the INITIATOR. On a cross-node session the initiator released its
   * visiting connection to the broker after setup, so that push finds no stream, the directory
   * ENQUEUES the frame instead, and the seal blocks forever waiting for a co-signature it never
   * asked for. close-session-handler already guards its own path this way; the auto-ack path did
   * not, and it is the path that fires FIRST whenever the counterparty closes first.
   *
   * Unset (single-node / M6 back-compat) is fine: the initiator is reachable on its home stream.
   */
  #ensureSealBroker:
    | ((agentName: string, sessionId: string) => Promise<{ stop: (reason: string) => Promise<void> } | null>)
    | undefined;

  #onSessionStateChanged:
    | ((
        agentName: string,
        sessionId: string,
        state: string,
        counterpartyPubkey: string | null,
      ) => void)
    | null = null;

  // M8C-MSGWAKE-1 (channel stage 2): fired when a verified inbound message is buffered for
  // cello_receive, so the daemon can push a content-free `cello_message` doorbell. Wired in
  // daemon.ts (depends on the notification dispatcher). Content-free by signature — carries only
  // agent / session / senderPubkey, NEVER the plaintext (INV-CONTENTFREE).
  #onContentArrived:
    | ((agentName: string, sessionId: string, senderPubkey: string) => void)
    | null = null;

  /**
   * M14 / DOD-DOC-INBOUND-2: the document-layer interception, injected by the composition root.
   *
   * Returns whether the document layer CONSUMED the frame. Absent (the default) means every frame
   * is conversation, exactly as before — the document layer cannot change message handling by being
   * unwired, which is the property that lets it be wired incrementally.
   *
   * It is handed the decrypted CONTENT, unlike `#onContentArrived`, which is content-free by
   * signature. That is unavoidable: deciding whether bytes are a document frame requires the bytes.
   * The router it calls never logs them.
   */
  #onDocumentFrame:
    | ((
        agentName: string,
        sessionId: string,
        content: Uint8Array,
        senderPubkey: string,
        correlationId?: string,
      ) => { consumed: boolean; kind?: string; ok?: boolean; reason?: string })
    | null = null;

  // A send is NOT fire-and-forget. After a content_frame is delivered over the direct session
  // channel, the sender arms a TTF timer and waits for an unsigned, transport-authenticated
  // `persisted` delivery ACK on the same /cello/content/1.0.0 protocol. A persisted ACK cancels the
  // timer (content.delivery.acked); TTF expiry hands the content to the park backstop.
  // Keyed sessionId → contentHashHex → entry.
  #awaitingAck = new Map<string, Map<string, { timer: ReturnType<typeof setTimeout>; content: Uint8Array; correlationId?: string; structure1Cbor?: Uint8Array; structure2Cbor?: Uint8Array }>>();
  // TTF (time-to-flush) for an un-acked content entry. Injectable so tests can drive
  // expiry deterministically; production default sits in the Part-4 proposed 10–30s band.
  #contentTtfMs = 20_000;
  // CELLO-M7-MSG-001: side-effect hooks the composition root wires to the durable
  // retry_queue (and, in 3b, the relay park deposit). Injected after construction
  // because RetryQueue is built later in daemon.ts. When unset, the awaiting-ACK timer
  // still fires and the ACK still resolves — only the durable crash-backstop is skipped.
  // DOD-RETRYQ-STRAND-1: fired on the transition INTO a status from which no resend can ever
  // succeed, so durable state keyed to that session gets a disposition instead of stranding.
  // Injected after construction because RetryQueue is built later in daemon.ts.
  #onSessionTerminal: ((sessionId: string, terminalStatus: "sealed" | "abandoned") => void) | null = null;
  #onAwaitingPersisted: ((agentName: string, sessionId: string, contentHashHex: string) => void) | null = null;
  #onAwaitingTtf: ((agentName: string, sessionId: string, contentHashHex: string, content: Uint8Array, structure1Cbor?: Uint8Array, structure2Cbor?: Uint8Array) => void) | null = null;
  // M12-P12 verification: force the next N park deposits to be REFUSED, so the failure this unit
  // fixes can be produced on demand instead of waited for. The real failure is a race — the deposit
  // is refused only in the seconds-long window while the sender's standing receiver rebuilds — and
  // no CLI lever reaches that window: set-agent-offline leaves an open session's node serving, and
  // the CLI refuses a send from an offline agent. Without this the fix ships unwatched.
  // INERT unless the daemon is started with CELLO_FAULT_INJECTION=1; the IPC handler that sets it
  // refuses outright otherwise, so a normal daemon cannot be talked into dropping messages.
  #parkFaultRemaining = 0;
  #parkFaultCause = "standing_receiver_creating";
  // The incident needs BOTH halves: the direct dial has to fail (or the park path is never entered
  // — measured, the counterparty's session node accepts the frame and reports delivered:true even
  // with its agent away), and the park deposit that follows has to be refused. One without the
  // other reproduces nothing.
  #sendFaultRemaining = 0;

  /** Arm the park-deposit fault. Returns the count now armed. */
  injectParkFault(count: number, cause?: string): number {
    this.#parkFaultRemaining = Math.max(0, count);
    if (cause) this.#parkFaultCause = cause;
    return this.#parkFaultRemaining;
  }

  /** Arm the direct-send fault — makes the next N sends take the dial-failure path. */
  injectSendFault(count: number): number {
    this.#sendFaultRemaining = Math.max(0, count);
    return this.#sendFaultRemaining;
  }

  getSendFaultRemaining(): number {
    return this.#sendFaultRemaining;
  }

  /** Remaining armed park faults — so a test can assert the fault was actually consumed. */
  getParkFaultRemaining(): number {
    return this.#parkFaultRemaining;
  }

  // M12-P12: the durable enqueue for a park deposit that FAILED. Distinct from onTtf because the
  // cause is distinct — nothing timed out here, the deposit was refused — and an event named for
  // the wrong cause is how this path stayed invisible.
  // M12-P13 (review HIGH-1): returns whether the content is ACTUALLY queued. `false` means the
  // queue dropped it (today: the content-derived dedupe key collided), and the caller must then not
  // claim durability — nor commit the leaf that claim now authorises.
  #onParkFailed: ((agentName: string, sessionId: string, contentHashHex: string, content: Uint8Array, structure1Cbor?: Uint8Array, structure2Cbor?: Uint8Array) => boolean) | null = null;
  /**
   * MSG-001-3b (2b): the live content-park deposit. The manager resolves the recipient + relay
   * endpoint from the session entry and calls this when a send is NOT confirmed delivered
   * (direct-fail or TTF expiry). The daemon's hook seals (sealToRecipient) + deposits via
   * ContentParkClient. Best-effort.
   */
  /**
   * SEC-1 / review M4: parked entries already refused by the authentication gate, keyed
   * `${agent}:${session}:${contentHash}` → the refusal reason. Bounded (see
   * #rememberRefusedParkedEntry) because its keys come from a REMOTE mailbox.
   */
  readonly #refusedParkedEntries = new Map<string, ParkAuthFailure>();

  #contentParkHook:
    | ((args: { agentName: string; sessionId: string; recipientPubkeyHex: string; relayPeerId: string; relayAddrs: readonly string[]; contentHashHex: string; content: Uint8Array; structure1Cbor?: Uint8Array; structure2Cbor?: Uint8Array }) => Promise<{ ok: true } | { ok: false; reason: string; cause?: string }>)
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
    /**
     * DOD-NAT-REACHABILITY-1: how long a standing receiver may wait for its
     * circuit-relay reservations before coming up WITHOUT them. libp2p's circuit
     * listener has no timeout of its own — an unreachable relay would park start()
     * forever and leave the agent with no receiver at all. See #startReceiverNode.
     */
    standingReceiverReservationTimeoutMs?: number;
    /**
     * DOD-NAT-REACHABILITY-1: how often to check that a standing receiver still HOLDS
     * the reservation it came up with. A dead relay makes the /p2p-circuit address
     * vanish silently — the agent looks healthy and is unreachable to every NAT'd peer.
     */
    standingReceiverWatchdogIntervalMs?: number;
    /**
     * DOD-PARK-DRAIN-1: how often the parked-mailbox BACKSTOP drain runs for an agent with a
     * healthy standing receiver. Rides the reservation watchdog's grid, so the effective period is
     * this value rounded up to a watchdog interval. Default 5 minutes: the trigger-driven drains do
     * the real work, and this only exists so a future missed trigger degrades to "late", never to
     * "stranded until a human restarts the daemon".
     */
    parkedDrainBackstopMs?: number;
    /**
     * M9-CORE-001: the inbound security-screening seam. When absent, a
     * REQUIRED — there is no always-allow default (INV-9). A caller that does not screen must
     * say so by passing PassthroughGatewayClient from `@cello-protocol/gateway/testing`.
     */
    securityGateway: SecurityGatewayClient;
  }) {
    this.#factory = opts.factory;
    this.#logger = opts.logger;
    this.#dbPath = opts.dbPath;
    if (typeof opts.contentTtfMs === "number" && opts.contentTtfMs > 0) {
      this.#contentTtfMs = opts.contentTtfMs;
    }
    this.#autoNatProbers = opts.autoNatProbers ?? (() => []);
    this.#srRetryDelaysMs = opts.standingReceiverRetryDelaysMs ?? [1_000, 5_000, 15_000];
    this.#srReservationTimeoutMs = opts.standingReceiverReservationTimeoutMs ?? 15_000;
    this.#srWatchdogIntervalMs = opts.standingReceiverWatchdogIntervalMs ?? 30_000;
    this.#parkedDrainBackstopMs = opts.parkedDrainBackstopMs ?? 300_000;
    // REQUIRED, no fallback (INV-9, audit finding). This line used to read
    // `opts.securityGateway ?? new PassthroughGatewayClient()` — the identical shape as the defect
    // that reopened this milestone, one layer down and still shipping in the binary. `daemon.ts`
    // was hardened to throw while this constructor was not, so the inbound screen had a silent
    // always-allow path that nothing in the product reached TODAY and any future refactor could.
    // "Currently unreachable" is a property of today's call sites, not of the code.
    if (!opts.securityGateway) {
      throw new Error(
        "SessionNodeManager: securityGateway is required (INV-9). The inbound screen has no " +
          "always-allow fallback, because that fallback is how the entire security layer shipped " +
          "inert. Pass a real client, or new PassthroughGatewayClient() from a test that " +
          "deliberately does not screen.",
      );
    }
    this.#securityGateway = opts.securityGateway;
  }

  /**
   * CELLO-M7-MSG-001: wire the durable-backstop side effects of the awaiting-ACK
   * lifecycle. `onPersisted` clears the durable retry_queue entry when a persisted ACK
   * arrives; `onTtf` records/parks the un-acked content when the TTF timer fires.
   * Injected by the composition root (daemon.ts) after the RetryQueue exists.
   */
  setAwaitingAckHooks(hooks: {
    onPersisted?: (agentName: string, sessionId: string, contentHashHex: string) => void;
    onTtf?: (agentName: string, sessionId: string, contentHashHex: string, content: Uint8Array, structure1Cbor?: Uint8Array, structure2Cbor?: Uint8Array) => void;
    onParkFailed?: (agentName: string, sessionId: string, contentHashHex: string, content: Uint8Array, structure1Cbor?: Uint8Array, structure2Cbor?: Uint8Array) => boolean;
  }): void {
    this.#onAwaitingPersisted = hooks.onPersisted ?? null;
    this.#onAwaitingTtf = hooks.onTtf ?? null;
    this.#onParkFailed = hooks.onParkFailed ?? null;
  }

  /**
   * DOD-RETRYQ-STRAND-1: wire the disposition of durable state a session can no longer drain.
   * Fires once per transition INTO a status from which no resend can succeed. Injected by the
   * composition root (daemon.ts) after the RetryQueue exists.
   */
  setSessionTerminalHook(hook: (sessionId: string, terminalStatus: "sealed" | "abandoned") => void): void {
    this.#onSessionTerminal = hook;
  }

  /**
   * MSG-001-3b (2b): inject the live content-park deposit (seal + ContentParkClient.deposit).
   * Injected by the composition root (daemon.ts). When absent, a not-confirmed send still records
   * the durable awaiting entry (crash backstop) but does not deposit live.
   * DOD-LEAVEMSG-1 (cello-unit-reviewer HIGH fix): the hook returns a TYPED result — `{ok:true}` or
   * `{ok:false, reason}` — mirroring RetryQueue's ParkFn contract. It must NEVER resolve `{ok:true}`
   * merely because it didn't throw: the production hook's own failure branches (standing receiver
   * unavailable, relay explicitly rejects the deposit) log-and-return without throwing, and a
   * throw-only contract would silently report those as success — the exact "system lies about its
   * own health" bug the reviewer caught (a park that never happened reported to the operator as
   * "dispatched to relay," with the durable retry_queue backstop skipped because sendContent's own
   * caller only enqueues on an honest {ok:false}).
   */
  setContentParkHook(
    fn: (args: { agentName: string; sessionId: string; recipientPubkeyHex: string; relayPeerId: string; relayAddrs: readonly string[]; contentHashHex: string; content: Uint8Array; structure1Cbor?: Uint8Array; structure2Cbor?: Uint8Array }) => Promise<{ ok: true } | { ok: false; reason: string; cause?: string }>,
  ): void {
    this.#contentParkHook = fn;
  }

  /**
   * DOD-PARK-DRAIN-1: inject the parked-mailbox drain (daemon.ts → contentPark.autoRecoverForAgent).
   *
   * The manager owns the two events that mean "content may be waiting for this agent on a relay":
   * a standing receiver was (re)built, and the slow backstop sweep. It does not own the drain
   * itself — that needs the agent's key provider and the inbound ingest funnel. So it calls out.
   *
   * Injected by the composition root, not passed to the constructor: the manager is built long
   * before the content park exists (content-park.ts documents why that ordering is load-bearing).
   */
  setParkedDrainHook(fn: (agentName: string, reason: ParkedDrainReason) => void): void {
    this.#parkedDrainHook = fn;
  }

  /**
   * DOD-PARK-DRAIN-1 (review F6): why there is no standing-receiver node to dial from — named
   * precisely, because `standing_receiver_unavailable` is the exit-point label that stood in for
   * four different causes and misnamed this very incident 102 times.
   *
   * Only meaningful once `getStandingReceiverNode()` has returned null, which means NO agent on
   * this daemon has a ready receiver — the dial node is not agent-scoped.
   */
  standingReceiverAbsenceReason(
    agentName: string,
  ): "daemon_shutting_down" | "standing_receiver_creating" | "agent_offline" | "no_standing_receiver" {
    if (this.#shuttingDown) return "daemon_shutting_down";
    if (this.#standingReceiverCreating.has(agentName)) return "standing_receiver_creating";
    if (!this.#agentsWantingReceiver.has(agentName)) return "agent_offline";
    return "no_standing_receiver";
  }

  /** Ask for a drain. Never throws — a broken drain must never cost the caller its receiver. */
  #fireParkedDrain(agentName: string, reason: ParkedDrainReason): void {
    const hook = this.#parkedDrainHook;
    if (this.#shuttingDown) return;
    if (!hook) {
      // DOD-PARK-DRAIN-1 (review F4): an unwired hook silently reverts this entire unit, and the
      // defect it fixes was itself a trigger that silently was not there. Say so — once, because
      // the fire points are on a timer grid. Not an error: a SessionNodeManager built by a test
      // that does not exercise the drain is legitimate.
      if (!this.#parkedDrainHookAbsenceLogged) {
        this.#parkedDrainHookAbsenceLogged = true;
        this.#logger.warn("content.recover.drain.hook.absent", { agentName, reason });
      }
      return;
    }
    // The success-side trail. Without it, a live run cannot say WHICH trigger delivered the
    // content — which is exactly the claim the outstanding acceptance clause has to evidence.
    this.#logger.info("content.recover.drain.triggered", { agentName, reason });
    try {
      hook(agentName, reason);
    } catch (err: unknown) {
      this.#logger.warn("content.recover.drain.hook.failed", {
        agentName,
        reason,
        error: extractErrorMessage(err),
      });
    }
  }

  /**
   * MSG-001-3b (2b): deposit un-confirmed content to the relay store-and-forward backstop — keyed
   * to the recipient, on the SAME relay this session is witnessed by — so an offline recipient
   * recovers it (at the sequence the witness already assigned, R1). Best-effort, never throws.
   * DOD-LEAVEMSG-1: returns whether the deposit actually succeeded (false if no hook/relay is
   * configured, or the hook rejects) so a caller with a live response to shape (sendContent) can
   * distinguish "genuinely parked" from "nothing recoverable" instead of guessing. Callers that
   * fire this from an async backstop with no live caller (the TTF-expiry path) may ignore the
   * result — the deposit itself and its logging are unchanged either way.
   */
  async #parkContent(agentName: string, sessionId: string, contentHashHex: string, content: Uint8Array, structure1Cbor?: Uint8Array, structure2Cbor?: Uint8Array): Promise<ParkAttempt> {
    // Fault injection FIRST, so it reproduces the real shape: the refusal happens at the same point
    // the live hook refuses (before any deposit), with the same event and the same `cause`.
    if (this.#parkFaultRemaining > 0) {
      this.#parkFaultRemaining -= 1;
      this.#logger.warn("content.park.deposit.failed", {
        sessionId,
        contentHash: contentHashHex,
        reason: "standing_receiver_unavailable",
        cause: this.#parkFaultCause,
        injected: true,
      });
      return { outcome: "refused", cause: this.#parkFaultCause };
    }
    const hook = this.#contentParkHook;
    const entry = this.#activeNodes.get(this.#k(agentName, sessionId));
    // M12-P12 (review F6): "no park target configured" is NOT a refused deposit. Content in a
    // session with no relay was never recoverable through the park, so queuing it for re-park would
    // be a lie that grows the DB forever — every boot and every agent start would retry a row whose
    // only possible outcome is no_persisted_relay_endpoint. Reported as unconfigured, not refused.
    if (!hook || !entry || !entry.relayPeerId || !entry.relayAddrs) return { outcome: "unconfigured" };
    try {
      const result = await hook({
        // SEC-1: the hook must sign as the SENDING agent — it needs to know who that is.
        agentName,
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
      });
      // DOD-LEAVEMSG-1 (reviewer HIGH fix): check the TYPED result, not just "didn't throw" — the
      // production hook's own failure branches (standing receiver unavailable, relay explicitly
      // rejects) resolve normally after logging, they never throw. A throw-only check would report
      // those as success.
      if (!result.ok) {
        this.#logger.warn("content.park.deposit.failed", {
          sessionId,
          contentHash: contentHashHex,
          reason: result.reason,
          cause: result.cause,
        });
        return { outcome: "refused", cause: result.cause ?? result.reason };
      }
      return { outcome: "parked" };
    } catch (err: unknown) {
      this.#logger.warn("content.park.deposit.failed", {
        sessionId,
        contentHash: contentHashHex,
        error: err instanceof Error ? err.message : String(err),
      });
      return { outcome: "refused", cause: err instanceof Error ? err.message : String(err) };
    }
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
        agent_id TEXT NOT NULL,
        counterparty_pubkey TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        -- DOD-LOOP-1: composite key so two of the operator's agents can hold both ends of the
        -- SAME session_id on ONE daemon (the loopback case). A bare session_id PK would reject
        -- the second end's row.
        -- DOD-AGENT-ID-JOINKEY-1: keyed on the STABLE agent_id, never the mutable, reuse-freed
        -- agent_name. The display name lives on the agents table and is joined in for reads.
        PRIMARY KEY (agent_id, session_id)
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
      // DOD-SESSION-NAME-1: the operator's own human-readable label for this session. LOCAL AND
      // COSMETIC — it is never sent to the relay or directory, never in a wire frame, never in the
      // transcript, never in the seal or a Merkle leaf, and the counterparty never sees it. It
      // cannot influence protocol behaviour.
      // NULL MEANS SOMETHING: a session closed through an agent usually carries a name, so an
      // unnamed closed session is a hint it did not close cleanly. Never auto-generate a default —
      // a fabricated name destroys that signal.
      "ALTER TABLE sessions ADD COLUMN session_name TEXT",
      // DOD-SEALED-INBOX-1: local-only housekeeping flag — epoch-ms timestamp set by cello_dismiss.
      // Never propagated, never part of the seal ceremony or hash chain. A dismissed terminal
      // session is excluded from cello_inbox's ended_unread section. Distinct from the read
      // watermark: this records "operator acknowledged via dismiss", not "operator received via
      // cello_receive". NULL = not yet dismissed.
      "ALTER TABLE sessions ADD COLUMN read_at INTEGER",
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

    // M12-P18: sessions this agent REFUSED (abuse cap etc.). DURABLE and separate from the in-memory
    // refusedSessionRequests inbox list, for one reason: content parked for a refused session arrives
    // AFTER the refusal and often after a restart, and at drain time `counterparty_unknown` cannot
    // tell "content for a session I declined" from "content I might still want". This table is that
    // missing memory. Deleting parked content matched here judges NOTHING about the content — it acts
    // on OUR OWN refusal, so it does not violate the SEC-1 rule that a forgery must not evict itself.
    // Bounded by pruning on write (keep the most recent N per agent); a refused session id is never
    // reused (directory-assigned, unique), so forgetting an old one only means its stale parked
    // content is not proactively swept — the relay TTL backstop still applies.
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS refused_sessions (
        agent_id   TEXT NOT NULL,
        session_id TEXT NOT NULL,
        reason     TEXT NOT NULL,
        refused_at INTEGER NOT NULL,
        PRIMARY KEY (agent_id, session_id)
      )
    `);

    // M12-P17: the POST-SEAL ANNEX — verified content that arrived for a session which had already
    // ended. It cannot join the sealed chain (that would change `sealed_root` and invalidate the
    // notarization), and it must not be thrown away: it is a real message, provably sent to this
    // operator, that no one would otherwise ever read.
    //
    // A SEPARATE TABLE is the point, not an implementation detail. Inertness has to be structural:
    // nothing here is joined by `getUnreadSummary`, `getEndedUnread`, any inbox count or any wake
    // path, so this content CANNOT ring a doorbell or reach agent context no matter what a future
    // caller does. If it lived in `transcript` behind a flag, the next reader would key on the row
    // and not the flag — which is exactly how an agent came to obey an instruction out of a sealed
    // conversation.
    //
    // Keyed on (agent_id, content_hash): `session_id` is recorded for display but is NOT part of the
    // key, because the sibling case this design must also serve — content we cannot attribute to a
    // session at all — has no session to key on.
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS sealed_session_annex (
        agent_id      TEXT NOT NULL,
        content_hash  TEXT NOT NULL,
        session_id    TEXT NOT NULL,
        sender_pubkey TEXT,
        content       BLOB NOT NULL,
        arrived_at    INTEGER NOT NULL,
        PRIMARY KEY (agent_id, content_hash)
      )
    `);

    // M7-SESSION-001 (H-1): side table holding the verified bilateral
    // SEAL-INTERRUPTED commitment artifacts. A side table (CREATE TABLE IF NOT
    // EXISTS) is inherently idempotent — no ALTER TABLE / duplicate-column
    // handling required. We keep BOTH parties' signed leaves and the agreed
    // Merkle root so the achieved commitment is never discarded.
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS seal_interrupted_artifacts (
        agent_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        role TEXT NOT NULL,
        own_leaf TEXT NOT NULL,
        counterparty_leaf TEXT NOT NULL,
        merkle_root TEXT NOT NULL,
        nonce TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        -- DOD-LOOP-1: composite key (per-agent end of a loopback session).
        PRIMARY KEY (agent_id, session_id)
      )
    `);

    // DAEMON-004 (AC-007 / SI-001): the daemon-owned per-session Merkle tree,
    // persisted as an ordered list of leaf hashes. The (session_id, leaf_index)
    // primary key enforces append-order uniqueness; a fresh daemon reconstructs
    // each tree from these rows so the transcript survives a restart. Querying
    // by session_id ORDER BY leaf_index is the only read pattern.
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS session_tree_leaves (
        agent_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        leaf_index INTEGER NOT NULL,
        leaf_kind TEXT NOT NULL,
        leaf_hash_hex TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        -- DOD-LOOP-1: composite key so each agent's end has its own append-ordered tree.
        PRIMARY KEY (agent_id, session_id, leaf_index)
      )
    `);

    // DOD-LOG-1 (PERSIST-LOG-001) / PERSIST-002 (AC-010): the durable, ENCRYPTED-at-rest readable
    // transcript. Each row is keyed by the canonical leaf `sequence`, so it JOINS to
    // session_tree_leaves(leaf_index) — a stored message is provably behind a committed hash-chain
    // leaf, not a loose dump. `blob` holds the readable plaintext bytes; encryption at rest is now
    // provided by whole-DB SQLCipher, not a per-column cipher (relay/directory never see it — INV-3).
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS transcript (
        agent_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        sequence INTEGER NOT NULL,
        direction TEXT NOT NULL,        -- 'sent' | 'received'
        blob BLOB NOT NULL,             -- readable plaintext bytes (whole-DB SQLCipher-encrypted at rest)
        created_at INTEGER NOT NULL,
        PRIMARY KEY (agent_id, session_id, sequence, direction)
      )
    `);

    // M8C-INBOX-1 (N2): per-agent, per-session read watermark. `last_delivered_seq` is the highest
    // RECEIVED transcript sequence the operator has been shown via cello_receive (delivery marks
    // read — no ack verb). Unread = received transcript rows with sequence > last_delivered_seq.
    // Persisted so a missed doorbell (fire-and-forget push) is reconcilable via cello_check_notifications
    // across daemon restarts, not just within one process (INV-PUSHPULL). Additive table.
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS message_watermarks (
        agent_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        last_delivered_seq INTEGER NOT NULL,
        PRIMARY KEY (agent_id, session_id)
      )
    `);

    // M8C-CONTACT-1: binary per-agent contact whitelist. This is an ACCESS-CONTROL LIST, not a
    // setting — it belongs alongside message_watermarks/sessions as its own real subsystem, not
    // behind the parked M9-CFG-001 config store. Identity PINS to the pubkey at add time (never
    // re-resolved); known stays known until explicitly removed (no TTL/expiry on membership).
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS contacts (
        agent_id TEXT NOT NULL,
        pubkey TEXT NOT NULL,
        added_at INTEGER NOT NULL,
        PRIMARY KEY (agent_id, pubkey)
      )
    `);
    // MONIKER-3 AC1: the receiver's own pet name for a pubkey — the top tier of whoLabel.
    // SQLite has no ADD COLUMN IF NOT EXISTS, so the ALTER is PRAGMA-guarded to stay
    // idempotent; existing rows → NULL, no data loss.
    // M10B / DOD-END-SURFACE-1 — per-counterparty presentation choice.
    //
    // `default_present` on the signal answers "show this by default"; this answers "show THIS signal
    // to THIS person", which is the finer question an operator actually has: an endorsement that is
    // right for a prospective client is not necessarily right for a competitor. Absent row = no
    // opinion → the signal's own default applies, so this table only ever holds explicit choices.
    //
    // Keys on `agent_id`, never `agent_name` — the name is a mutable display label that is reusable
    // after retirement, so keying on it would silently hand a NEW agent the retired one's
    // disclosure choices. Same key as `contacts`, which this is an extension of.
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS contact_signal_prefs (
        agent_id TEXT NOT NULL,
        contact_pubkey TEXT NOT NULL,
        signal_hash TEXT NOT NULL,
        present INTEGER NOT NULL,
        set_at INTEGER NOT NULL,
        PRIMARY KEY (agent_id, contact_pubkey, signal_hash)
      )
    `);
    const contactCols = this.#db.prepare("PRAGMA table_info(contacts)").all() as Array<{ name: string }>;
    if (!contactCols.some((c) => c.name === "moniker")) {
      this.#db.exec("ALTER TABLE contacts ADD COLUMN moniker TEXT");
    }

    // DOD-AGENT-ID-JOINKEY-1: finish REMOVE-001. Re-key the seven child tables from the mutable,
    // reuse-freed `agent_name` to the stable `agent_id`, in ONE transaction. Runs AFTER every
    // CREATE/ALTER above, so an existing table has its full historical column set before it is
    // rebuilt, and BEFORE any read below touches it. A no-op once the tables carry `agent_id`.
    //
    // `retry_queue` (the seventh) is created later, by RetryQueue's constructor. On an existing
    // database it already exists here and is re-keyed in the same transaction; on a fresh one it is
    // absent, is skipped, and RetryQueue then creates it directly in the re-keyed shape.
    migrateSessionTablesToAgentId(this.#db, this.#logger);

    // DOD-TIER-1 (address-book Step 1): give `contacts` its tier metadata (tier / provenance /
    // last_offered_moniker / away_message). Pure ADD COLUMN, no rebuild — so it runs AFTER the
    // agent-id re-key above (it never needs to appear in that migration's pinned DDL) and BEFORE any
    // read below. Idempotent, no column DEFAULT, grandfathers existing contacts to WHITELISTED once.
    migrateContactsAddTierMetadata(this.#db, this.#logger);

    // §1.1: normalize frost_commitments / frost_verifying_shares to ONE CBOR encoding. Registration
    // wrote them with the shared encoder; the refresh path wrote them with cbor-x's bare `encode`,
    // so an agent's share blobs changed format the first time it ran `cello_refresh_shares` and both
    // formats are on disk. Both producers now use encodeCbor; this rewrites what is already stored.
    // Idempotent (a canonical blob re-encodes to itself and is skipped) and per-row fail-safe (an
    // undecodable share is LEFT ALONE, never dropped — losing key material is worse than an old
    // encoding cbor-x still reads).
    migrateCborBlobsToCanonical(this.#db, this.#logger);

    // M8C-TGDOOR-1: daemon-wide Telegram settings (bot token + allowlisted operator chat). A
    // NEW dedicated table — NOT folded into the parked M9-CFG-001 config store, because a bot
    // token has no sensible default (a required credential, unlike AWAY/TTL/CONTACT's real
    // defaults) and can't legitimately wait for M9. Singleton row (id=1) — "token = daemon
    // setting" (DoD), not per-agent.
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS telegram_settings (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        bot_token TEXT NOT NULL,
        allowlisted_chat_id TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      )
    `);

    // DOD-RENAME-1 (Option C): pending rename notices — one per (agent, contact). A notice is queued
    // when a peer the operator has PERSONALLY NAMED offers a self-declared name that differs from the
    // last one seen; it surfaces through cello_check_notifications (NOT a real-time push) and clears
    // when the operator adopts a name (cello_contact_set_moniker) or removes the contact. Keyed on
    // agent_id (the stable key); the offered name is charset-validated at the wire boundary but still
    // operator-untrusted, so surfaces render it as a quoted CLAIM.
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS contact_rename_notices (
        agent_id TEXT NOT NULL,
        pubkey TEXT NOT NULL,
        offered_name TEXT NOT NULL,
        noticed_at INTEGER NOT NULL,
        PRIMARY KEY (agent_id, pubkey)
      )
    `);

    // DOD-SETTINGS-1: a daemon-side per-agent settings store for REACHABILITY POLICY (the tier bounds
    // overrides and the per-tier/agent away messages). A generic key-value table on the stable
    // agent_id, in the same SQLCipher DB. Deliberately NOT M9-CFG-001's gateway config store: this is
    // daemon reachability policy, not gateway SCREENING config, and the M9 store is unwired + plaintext.
    // reconcile with DOD-CONFIG-1 later; this is daemon reachability policy, not gateway config.
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS agent_settings (
        agent_id TEXT NOT NULL,
        key TEXT NOT NULL,
        value TEXT NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (agent_id, key)
      )
    `);

    // M10 / DOD-STORE-CLIENT-1: the two trust-signal tables (wallet + received). Created HERE and
    // deliberately last: `contact_trust_signals` carries a composite FK to `contacts(agent_id,
    // pubkey)`, so its parent must exist and must already have been through the agent-id re-key
    // above. SQLite resolves an FK's parent at DML time, not DDL time — so getting this order wrong
    // would not fail here, it would fail on the first insert, which is a far worse place to find out.
    ensureTrustSignalSchema(this.#db, this.#logger);

    // Step 2: Detect interrupted sessions (SIGKILL detection — AC-010).
    // Any 'active' row in a freshly-started daemon is a remnant of a prior
    // killed process. Batch-update to 'interrupted' before IPC opens.
    // DOD-AGENT-ID-JOINKEY-1: this sweep spans EVERY agent, so it cannot resolve one name up front.
    // It scopes its UPDATE by the row's own agent_id and LEFT JOINs `agents` only to LOG a human
    // name. LEFT, not INNER: an inner join would silently skip a session whose agent row is missing,
    // leaving it 'active' forever — a stuck row hidden by the query that was meant to find it. An
    // orphan is instead marked interrupted like any other AND reported loudly.
    const activeRows = this.#db
      .prepare(
        `SELECT s.session_id, s.agent_id, a.agent_name
         FROM sessions s LEFT JOIN agents a ON a.agent_id = s.agent_id
         WHERE s.status = 'active'`,
      )
      .all() as unknown as Array<{ session_id: string; agent_id: string; agent_name: string | null }>;

    if (activeRows.length > 0) {
      const now = Date.now();
      const interruptedAt = new Date(now).toISOString();
      for (const row of activeRows) {
        try {
          this.#db
            .prepare(
              "UPDATE sessions SET status = 'interrupted', updated_at = ?, interrupted_at = COALESCE(interrupted_at, ?) WHERE agent_id = ? AND session_id = ?",
            )
            .run(now, interruptedAt, row.agent_id, row.session_id);
          if (row.agent_name === null) {
            this.#logger.error("session.agent.orphaned", {
              sessionId: row.session_id,
              agentId: row.agent_id,
              impact: "session row references an agent_id with no agents row",
            });
          }
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
   * plaintext bytes: the whole DB is SQLCipher-encrypted at rest, so there is no per-column cipher.
   * Idempotent on replay (INSERT OR IGNORE). Never throws into the caller's content path — but it
   * REPORTS: returns false when the row did not land, so a caller for whom the row is a delivery
   * precondition can fail instead of proceeding (review F2). Before Tier 1 the return value would
   * have been pointless, because `cello_receive` served content from the in-memory buffer and the
   * lost row only cost the unread count. Delivery reads the transcript now, so a swallowed received
   * row is TOTAL content loss and the caller has to know.
   */
  recordTranscriptMessage(
    agentName: string,
    sessionId: string,
    sequence: number,
    direction: "sent" | "received",
    plaintext: Uint8Array,
    correlationId?: string,
  ): boolean {
    if (!this.#db) return false;
    try {
      const agentId = this.#requireAgentId(agentName);
      const blob = Buffer.from(plaintext);
      this.#db
        .prepare(
          `INSERT OR IGNORE INTO transcript (agent_id, session_id, sequence, direction, blob, created_at)
           VALUES (?, ?, ?, ?, ?, ?)`,
        )
        .run(agentId, sessionId, sequence, direction, blob, Date.now());
      this.#logger.info("transcript.message.recorded", { sessionId, agentName, sequence, direction, correlationId });
      return true;
    } catch (err: unknown) {
      // M8C-INBOX-1 (reviewer F2): a RECEIVED-row write failure is not cosmetic — since INBOX-1 the
      // transcript is the AUTHORITY for unread (getUnreadSummary).
      //
      // UPDATED for DOD-COATTEND-1 (review F2). This comment used to end "...while cello_receive
      // still delivers it live from the in-memory buffer (masking the loss)", and that mitigation
      // was the whole reason a swallowed write was survivable. Tier 1 DELETED it: delivery reads
      // the transcript now, so a lost received row is not an undercount, it is the message never
      // reaching ANY session while the doorbell rings and the leaf sits in the hash chain. The
      // sentence is corrected rather than kept, because as written it reassured a reader about a
      // safety net that no longer exists. Sent-row failures stay a warning (they only affect the
      // durable readable transcript, not delivery).
      const level = direction === "received" ? "error" : "warn";
      this.#logger[level]("transcript.message.record.failed", {
        sessionId, agentName, sequence, direction,
        reason: err instanceof Error ? err.message : String(err),
        correlationId,
        ...(direction === "received" ? { impact: "content_undeliverable_message_lost" } : {}),
      });
      return false;
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
         WHERE agent_id = ? AND session_id = ? ORDER BY sequence ASC, direction ASC`,
      )
      .all(this.#requireAgentId(agentName), sessionId) as Array<{ sequence: number; direction: string; blob: Uint8Array; created_at: number }>;
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

  /**
   * DOD-COATTEND-1 (review F5) — the single next RECEIVED message after `afterSeq`, or null.
   *
   * The delivery path asks this question inside a 20 ms poll, so it is asked ~47 times a second per
   * blocked connection — ~1,400 times over a default 30 s receive. Answering it with
   * `readTranscript()` meant, every single time: SELECT every row of the session with no predicate
   * and no limit, `TextDecoder().decode()` every blob in it, build the array, then `.find()` one
   * row and discard the rest. On a 200-message session with three co-attending connections blocking
   * — which is the M8D use case, not a worst case — that is tens of thousands of blob decodes per
   * second on the daemon's single synchronous SQLCipher handle, contending with the write path.
   *
   * The predicate belongs in SQL. This is O(1) on the existing (agent_id, session_id, sequence)
   * key and decodes exactly the one blob it returns.
   */
  findNextReceivedAfter(
    agentName: string,
    sessionId: string,
    afterSeq: number,
  ): { sequence: number; text: string } | null {
    if (!this.#db) return null;
    const row = this.#db
      .prepare(
        `SELECT sequence, blob FROM transcript
         WHERE agent_id = ? AND session_id = ? AND direction = 'received' AND sequence > ?
         ORDER BY sequence ASC LIMIT 1`,
      )
      .get(this.#requireAgentId(agentName), sessionId, afterSeq) as { sequence: number; blob: Uint8Array } | undefined;
    if (!row) return null;
    const blob = row.blob instanceof Uint8Array ? row.blob : new Uint8Array(row.blob);
    return { sequence: row.sequence, text: new TextDecoder().decode(blob) };
  }

  // ─── M8C-INBOX-1 (N2/N3): read-watermark accessors ───────────────────────────

  /** The highest RECEIVED transcript sequence delivered to the operator for (agent, session).
   *  -1 when nothing has been delivered yet (so a seq-0 message reads as unread). */
  getLastDeliveredSeq(agentName: string, sessionId: string): number {
    if (!this.#db) return -1;
    const row = this.#db
      .prepare("SELECT last_delivered_seq FROM message_watermarks WHERE agent_id = ? AND session_id = ?")
      .get(this.#requireAgentId(agentName), sessionId) as { last_delivered_seq: number } | undefined;
    return row ? row.last_delivered_seq : -1;
  }

  /** Advance the read watermark (delivery marks read). MONOTONIC — never lowers, so a replayed or
   *  out-of-order cello_receive cannot un-read already-read messages. */
  advanceLastDeliveredSeq(agentName: string, sessionId: string, seq: number): void {
    if (!this.#db) return;
    this.#db
      .prepare(
        `INSERT INTO message_watermarks (agent_id, session_id, last_delivered_seq)
         VALUES (?, ?, ?)
         ON CONFLICT(agent_id, session_id)
         DO UPDATE SET last_delivered_seq = MAX(last_delivered_seq, excluded.last_delivered_seq)`,
      )
      .run(this.#requireAgentId(agentName), sessionId, seq);
    this.#logger.info("message.watermark.advanced", { agentName, sessionId, sequence: seq });
  }

  /**
   * The ONE definition of "unread" in this daemon: a RECEIVED transcript row whose sequence is
   * beyond the agent's persisted read watermark. A constant, not a copy-pasted string, so the
   * INBOX unread count and the DOD-CURSOR-DURABLE-1 read-before-write gate can never drift into
   * disagreeing about what "unread" means — the gate deciding one thing while the inbox shows
   * another is precisely the bug this shape prevents. Interpolated SQL only (no user input).
   */
  static readonly #UNREAD_RECEIVED_WHERE = `
           t.direction = 'received'
           AND t.sequence > COALESCE(w.last_delivered_seq, -1)`;

  static readonly #REFUSED_SESSIONS_CAP = 200;
  static readonly #TERMINAL_STATUSES = `('sealed','abandoned','seal_interrupted_pending','interrupted')`;

  /** INBOX-1 (N2): per-session unread summary for an agent — sessions that have RECEIVED transcript
   *  messages beyond the read watermark, excluding terminal sessions (sealed, abandoned,
   *  seal_interrupted_pending) which belong in getEndedUnread instead.
   *  Sessions with no sessions row are treated as non-terminal (LEFT JOIN).
   *  Content-free (counts + ids + last seq, never message text); a COUNT/MAX query, no decrypt. */
  getUnreadSummary(agentName: string): Array<{ session_id: string; unread_count: number; last_seq: number }> {
    if (!this.#db) return [];
    const rows = this.#db
      .prepare(
        `SELECT t.session_id AS session_id,
                COUNT(*)      AS unread_count,
                MAX(t.sequence) AS last_seq
         FROM transcript t
         LEFT JOIN message_watermarks w
           ON w.agent_id = t.agent_id AND w.session_id = t.session_id
         LEFT JOIN sessions s
           ON s.agent_id = t.agent_id AND s.session_id = t.session_id
         WHERE t.agent_id = ?
           AND ${SessionNodeManager.#UNREAD_RECEIVED_WHERE}
           AND (s.status IS NULL OR s.status NOT IN ${SessionNodeManager.#TERMINAL_STATUSES})
         GROUP BY t.session_id
         HAVING unread_count > 0
         ORDER BY t.session_id ASC`,
      )
      .all(this.#requireAgentId(agentName)) as Array<{ session_id: string; unread_count: number; last_seq: number }>;
    return rows;
  }

  /** DOD-SEALED-INBOX-1: terminal sessions with unread received messages that have not been
   *  dismissed. These are answering-machine style messages left in an ENDED session — the operator
   *  can read them via cello_transcript but cannot advance the watermark via cello_receive.
   *  Only returned when read_at IS NULL (not yet dismissed).
   *
   *  DOD-SEALED-INBOX-2: named `getEndedUnread`, not `getSealedUnread`, and it SELECTS `s.status`.
   *  All four #TERMINAL_STATUSES belong here — that part was always right — but only `sealed` is
   *  NOTARIZED. The old name and the caller's hardcoded `session_state: "sealed"` asserted a
   *  cryptographic receipt for `abandoned`, `interrupted` and `seal_interrupted_pending` sessions,
   *  which have none. Callers must render the row's own status; there is nothing to infer from
   *  membership in this list beyond "it ended". */
  getEndedUnread(agentName: string): Array<{ session_id: string; unread_count: number; last_seq: number; status: string }> {
    if (!this.#db) return [];
    const rows = this.#db
      .prepare(
        // M12-P17 (review F2): return the ACTUAL status. `#TERMINAL_STATUSES` spans four states and
        // they are NOT equivalent — an `interrupted` session is not committed, still accepts
        // appends, and may have a counterparty waiting to seal. Stamping "sealed" over all four
        // told an agent that live work was dead history: symptom B inverted.
        `SELECT t.session_id AS session_id,
                COUNT(*)      AS unread_count,
                MAX(t.sequence) AS last_seq,
                s.status      AS status
         FROM transcript t
         LEFT JOIN message_watermarks w
           ON w.agent_id = t.agent_id AND w.session_id = t.session_id
         JOIN sessions s
           ON s.agent_id = t.agent_id AND s.session_id = t.session_id
         WHERE t.agent_id = ?
           AND ${SessionNodeManager.#UNREAD_RECEIVED_WHERE}
           AND s.status IN ${SessionNodeManager.#TERMINAL_STATUSES}
           AND s.read_at IS NULL
         GROUP BY t.session_id
         HAVING unread_count > 0
         ORDER BY t.session_id ASC`,
      )
      .all(this.#requireAgentId(agentName)) as Array<{ session_id: string; unread_count: number; last_seq: number; status: string }>;
    return rows;
  }

  /** DOD-SEALED-INBOX-1: mark a terminal session as dismissed — sets read_at to now.
   *  Only valid for terminal sessions; active/interrupted sessions return session_not_terminal. */
  dismissSession(agentName: string, sessionId: string): { ok: true } | { ok: false; reason: string } {
    if (!this.#db) return { ok: false, reason: "db_not_open" };
    const agentId = this.#requireAgentId(agentName);
    const row = this.#db
      .prepare("SELECT status FROM sessions WHERE agent_id = ? AND session_id = ?")
      .get(agentId, sessionId) as { status: string } | undefined;
    if (!row) return { ok: false, reason: "session_not_found" };
    const terminal = ["sealed", "abandoned", "seal_interrupted_pending", "interrupted"];
    if (!terminal.includes(row.status)) return { ok: false, reason: "session_not_terminal" };
    this.#db
      .prepare("UPDATE sessions SET read_at = ? WHERE agent_id = ? AND session_id = ?")
      .run(Date.now(), agentId, sessionId);
    return { ok: true };
  }

  /**
   * DOD-CURSOR-DURABLE-1: how many RECEIVED messages in THIS session the agent has not read —
   * the durable half of the read-before-write gate. Same predicate as getUnreadSummary (shared
   * constant above), scoped to one session.
   *
   * This is DURABLE and PER-AGENT, where the send gate's other authority (the connection cursor) is
   * in-memory and per-connection. It is what lets a stateless client — the `cello` CLI, one process
   * per command — prove it has read the counterparty, which a dead socket's cursor never can.
   *
   * FAILS CLOSED: an uninitialized DB returns a positive count (treated as "unread"), never 0. A 0
   * here unblocks a send; guessing 0 from a broken DB would silently defeat the gate.
   */
  getUnreadReceivedCount(agentName: string, sessionId: string): number {
    if (!this.#db) return 1; // fail closed — never unblock a send because the DB is unavailable
    const row = this.#db
      .prepare(
        `SELECT COUNT(*) AS unread_count
         FROM transcript t
         LEFT JOIN message_watermarks w
           ON w.agent_id = t.agent_id AND w.session_id = t.session_id
         WHERE t.agent_id = ?
           AND t.session_id = ?
           AND ${SessionNodeManager.#UNREAD_RECEIVED_WHERE}`,
      )
      .get(this.#requireAgentId(agentName), sessionId) as { unread_count: number } | undefined;
    // Absent row → "I cannot count", which is NOT "you are caught up". Answer the same way the
    // #db guard above does. Unreachable today (SELECT COUNT(*) with no GROUP BY always yields a
    // row), but a fail-OPEN default inside a fail-CLOSED gate is a defect that only needs the query
    // to change once. The two branches must never disagree about what "unknown" means.
    return row ? row.unread_count : 1;
  }

  /** M8C-CONTACT-1: is this pubkey a known contact of this agent? */
  isContact(agentName: string, pubkey: string): boolean {
    if (!this.#db) return false;
    const row = this.#db.prepare("SELECT 1 FROM contacts WHERE agent_id = ? AND pubkey = ?").get(this.#requireAgentId(agentName), pubkey);
    return row !== undefined;
  }

  /** DOD-TIER-1: the reachability tier for a counterparty of this agent. The RESULT is total — an
   *  absent contact row (undefined), a NULL `tier`, or a corrupt out-of-range value all resolve to
   *  UNKNOWN via `normalizeTier`, so the return is always in 0..4 and guards the JS `null >= 0`/`0 ||
   *  1`/`grid[99]` traps. It is a SECURITY read (Step 2 gates inbound bounds on it), so it FAILS
   *  CLOSED, never open: an uninitialized DB throws (same contract as addContact) rather than
   *  silently returning UNKNOWN and admitting a BLOCKED sender; an unresolvable/retired agent name
   *  throws via #requireAgentId. Both are invariant violations a caller must surface, not swallow. */
  getTier(agentName: string, pubkey: string): number {
    // Fail CLOSED: a read that decides whether to admit a sender must not degrade to "unclassified"
    // when it cannot reach the ACL — that would admit a blocked contact. Throw as addContact does.
    if (!this.#db) throw new Error(`getTier('${agentName}'): database not initialized`);
    const row = this.#db
      .prepare("SELECT tier FROM contacts WHERE agent_id = ? AND pubkey = ?")
      .get(this.#requireAgentId(agentName), pubkey) as { tier: number | null } | undefined;
    if (row && row.tier !== null && !isKnownTierValue(row.tier)) {
      // A stored tier outside 0..4 is corruption — surface it. normalizeTier still maps it to the
      // tighter UNKNOWN so the caller is safe, but a silent map would hide a broken row.
      this.#logger.warn("contact.tier.corrupt", { agentName, pubkey, storedTier: row.tier });
    }
    return normalizeTier(row?.tier);
  }

  /** DOD-TIER-4: the DISPLAY/relationship check — is this counterparty a genuine contact (KNOWN or
   *  above)? Replaces the old binary `isContact` for behaviour that keyed on "we have a relationship"
   *  (e.g. the away-response wording). An UNKNOWN-tier contact (a mere row) is NOT known. */
  isKnown(agentName: string, pubkey: string): boolean {
    return this.getTier(agentName, pubkey) >= TIER.KNOWN;
  }

  /** DOD-TIER-4: the POLICY gate — may an inbound session from this counterparty be auto-accepted
   *  when the operator is unattended (WHITELISTED or VIP)? The behavioural consumer is the offline
   *  relay mailbox (LEAVEMSG-1), out of scope for this unit; defined here as the seam. Being merely
   *  KNOWN is NOT enough to auto-accept — whitelisting is the deliberate `cello_contact_set_tier` act. */
  isAutoAccept(agentName: string, pubkey: string): boolean {
    return this.getTier(agentName, pubkey) >= TIER.WHITELISTED;
  }

  /** DOD-TIER-BOUNDS-SETTINGS: the effective bound for (agent, tier, field) — a per-agent SETTINGS
   *  override if one is set and valid, else the hardcoded grid default (DEFAULT_TIER_BOUNDS). With no
   *  settings this is byte-identical to Step 2 (the daemon runs on defaults alone). A stored value
   *  that is somehow non-positive/non-finite (should be impossible — validated at SET time) falls back
   *  to the grid default rather than removing the bound (INV-TIER-BOUND, defensive). BLOCKED is never
   *  settable — it always returns the fixed grid value (0). */
  resolveTierBound(agentName: string, tier: number, field: "max_sessions" | "max_bytes"): number {
    const gridDefault = field === "max_sessions"
      ? tierBoundsFor(tier).maxSessionsPerSender
      : tierBoundsFor(tier).maxBytesPerSession;
    const name = settableTierName(tier);
    if (name === null) return gridDefault; // BLOCKED or out-of-range — fixed, not overridable
    const raw = this.getSetting(agentName, boundSettingKey(name, field));
    if (raw === null) return gridDefault; // unset → default
    const parsed = Number(raw);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      // Should be impossible (validated at SET time) → a config-integrity failure. Surface it: this
      // reverts a possibly-TIGHTENED bound to the looser default, so a silent revert would hide a real
      // problem. Still fail SAFE (grid default, never unbounded — INV-TIER-BOUND).
      this.#logger.warn("settings.bound.corrupt", { agentName, tier, field, raw });
      return gridDefault;
    }
    return parsed;
  }

  /** M8C-CONTACT-1: pin a contact at add time — idempotent (re-adding an existing contact is a
   *  no-op, never refreshes added_at; identity does not get re-resolved). MONIKER-3 AC2: an
   *  optional pet name; a NEW non-null moniker on re-add updates it, absence leaves it untouched.
   *  THROWS on an invalid moniker — callers validate first; this is the can-never-be-stored
   *  backstop (same contract as DbIdentityStore.setMoniker).
   *
   *  DOD-TIER-1/4: a NEW row is stamped `tier` (never NULL) and an optional `provenance`
   *  ('accepted' | 'initiated' | null). The `tier` defaults to the least-privilege UNKNOWN floor —
   *  a caller GRANTS trust by passing a higher tier explicitly. Every production creation path is a
   *  deliberate operator action and passes KNOWN (initiate, engage/reply, explicit cello_contact_add
   *  — DEC-AB-1). INSERT OR IGNORE means an EXISTING contact is untouched — tier and provenance pin
   *  at first add, exactly as `added_at`/`moniker` already do; re-adding never downgrades a contact
   *  the operator has since promoted. Raising the tier later is `cello_contact_set_tier`'s job. */
  addContact(agentName: string, pubkey: string, moniker?: string | null, provenance?: string | null, tier: number = TIER.UNKNOWN): void {
    if (!pubkey) return;
    // Review F1: a missing DB handle must FAIL the write loudly — returning silently here let
    // the handler log contact.added and report ok:true for a row that never landed.
    if (!this.#db) throw new Error(`addContact('${agentName}'): database not initialized`);
    if (moniker !== undefined && moniker !== null && validateMoniker(moniker) === null) {
      throw new Error(`invalid contact moniker for agent '${agentName}': must match ${MONIKER_RE.source}`);
    }
    // DOD-TIER-4 (review F3): the stored tier must be a known 0..4 constant — a can-never-be-stored
    // backstop mirroring the moniker validation above. All callers pass a TIER constant; this catches
    // a future caller (or a bad refactor) that would otherwise persist a corrupt tier the read side
    // must then defensively normalize.
    if (!isKnownTierValue(tier)) {
      throw new Error(`invalid contact tier for agent '${agentName}': ${tier} (must be 0..4)`);
    }
    const agentId = this.#requireAgentId(agentName);
    this.#db
      .prepare("INSERT OR IGNORE INTO contacts (agent_id, pubkey, added_at, tier, provenance) VALUES (?, ?, ?, ?, ?)")
      .run(agentId, pubkey, Date.now(), tier, provenance ?? null);
    if (moniker !== undefined && moniker !== null) {
      this.#db
        .prepare("UPDATE contacts SET moniker = ? WHERE agent_id = ? AND pubkey = ?")
        .run(moniker, agentId, pubkey);
    }
  }

  /** MONIKER-3 AC3: rename (string) or clear (null) an EXISTING contact's pet name. Returns false
   *  when no such contact — fail-loud at the caller, never a silent no-op success. Same
   *  validate-throw backstop as addContact. */
  setContactMoniker(agentName: string, pubkey: string, moniker: string | null): boolean {
    // Review F2: false means exactly "no such contact" — a null DB handle throws instead, so the
    // operator is never sent chasing a nonexistent missing-contact problem.
    if (!this.#db) throw new Error(`setContactMoniker('${agentName}'): database not initialized`);
    if (moniker !== null && validateMoniker(moniker) === null) {
      throw new Error(`invalid contact moniker for agent '${agentName}': must match ${MONIKER_RE.source}`);
    }
    const res = this.#db
      .prepare("UPDATE contacts SET moniker = ? WHERE agent_id = ? AND pubkey = ?")
      .run(moniker, this.#requireAgentId(agentName), pubkey);
    // DOD-RENAME-1: setting the local pet name IS the operator acting on a rename — resolve any
    // pending notice for this contact (whether they adopted the offered name or chose their own).
    if (res.changes > 0) this.clearRenameNotice(agentName, pubkey);
    return res.changes > 0;
  }

  /**
   * M10B / DOD-END-SURFACE-1 — decide whether ONE signal is presented to ONE counterparty.
   *
   * `present: null` CLEARS the choice, which is not the same as `false`: cleared means "no opinion,
   * use the signal's own default", while false means "specifically not this person". Collapsing
   * them would make an operator unable to undo an omission without knowing what the default was.
   *
   * Deliberately does NOT require an existing contact row, unlike the tier/moniker/away setters. A
   * decision about what to disclose is meaningful before a relationship is established — indeed
   * that is when it matters most — and refusing here would force the operator to add someone as a
   * contact in order to withhold something from them.
   */
  setContactSignalPref(agentName: string, pubkey: string, signalHash: string, present: boolean | null): void {
    if (!this.#db) throw new Error(`setContactSignalPref('${agentName}'): database not initialized`);
    const agentId = this.#requireAgentId(agentName);
    if (present === null) {
      this.#db
        .prepare("DELETE FROM contact_signal_prefs WHERE agent_id = ? AND contact_pubkey = ? AND signal_hash = ?")
        .run(agentId, pubkey, signalHash);
      this.#logger.info("signal.presentation.pref.cleared", { agentName, pubkey: pubkey.slice(0, 16), signalHash: signalHash.slice(0, 16) });
      return;
    }
    this.#db
      .prepare(
        `INSERT INTO contact_signal_prefs (agent_id, contact_pubkey, signal_hash, present, set_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(agent_id, contact_pubkey, signal_hash) DO UPDATE SET present = excluded.present, set_at = excluded.set_at`,
      )
      .run(agentId, pubkey, signalHash, present ? 1 : 0, Date.now());
    this.#logger.info("signal.presentation.pref.set", {
      agentName, pubkey: pubkey.slice(0, 16), signalHash: signalHash.slice(0, 16), present,
    });
  }

  /**
   * The explicit per-counterparty choices for this contact: signal hash → present.
   *
   * A signal ABSENT from this map has no choice recorded and falls back to its own
   * `default_present`. Returns an EMPTY map on an uninitialised DB rather than throwing, because
   * this is a preference read on the presentation path and losing preferences must not break a
   * session — but note the direction that failure takes: with no preferences, `default_present`
   * decides, and consent still gates everything upstream in SQL. It can therefore only fall back to
   * the operator's standing default, never to disclosing something consent has not cleared.
   */
  getContactSignalPrefs(agentName: string, pubkey: string): Map<string, boolean> {
    if (!this.#db) return new Map();
    const rows = this.#db
      .prepare("SELECT signal_hash, present FROM contact_signal_prefs WHERE agent_id = ? AND contact_pubkey = ?")
      .all(this.#requireAgentId(agentName), pubkey) as Array<{ signal_hash: string; present: number }>;
    return new Map(rows.map((r) => [r.signal_hash, r.present !== 0]));
  }

  /** DOD-AWAY-TIER-1: set (or clear, with null) a contact's per-contact away message. Returns false
   *  when no such contact — fail-loud at the caller (same contract as setContactMoniker/setContactTier). */
  setContactAwayMessage(agentName: string, pubkey: string, message: string | null): boolean {
    if (!this.#db) throw new Error(`setContactAwayMessage('${agentName}'): database not initialized`);
    const res = this.#db
      .prepare("UPDATE contacts SET away_message = ? WHERE agent_id = ? AND pubkey = ?")
      .run(message, this.#requireAgentId(agentName), pubkey);
    return res.changes > 0;
  }

  /** DOD-AWAY-TIER-1: resolve the most-specific CUSTOM away text for a counterparty, most-specific
   *  first: per-contact `away_message` → per-tier away setting → agent default away setting. Returns
   *  null when none is configured, so the CALLER applies the system default (code) — making the full
   *  four-level resolution TOTAL. A pure read; the resolved text is screened on the outbound path by
   *  the caller like any content (SI — it does not bypass the gateway). */
  resolveAwayMessage(agentName: string, pubkey: string): string | null {
    if (!this.#db) return null;
    const agentId = this.#requireAgentId(agentName);
    const row = this.#db
      .prepare("SELECT away_message FROM contacts WHERE agent_id = ? AND pubkey = ?")
      .get(agentId, pubkey) as { away_message: string | null } | undefined;
    if (row?.away_message != null) {
      this.#logger.debug("contact.away.resolved", { agentName, pubkey, level: "contact" }); // obs AC
      return row.away_message; // 1. per-contact
    }
    const tierName = settableTierName(this.getTier(agentName, pubkey));
    if (tierName !== null) {
      const tierAway = this.getSetting(agentName, awayTierSettingKey(tierName));
      if (tierAway !== null) {
        this.#logger.debug("contact.away.resolved", { agentName, pubkey, level: "tier" });
        return tierAway; // 2. per-tier
      }
    }
    const agentDefault = this.getSetting(agentName, AWAY_DEFAULT_KEY);
    // 3. agent default, else null → caller applies the system default (code). Level logged HERE.
    this.#logger.debug("contact.away.resolved", { agentName, pubkey, level: agentDefault !== null ? "agent_default" : "system" });
    return agentDefault;
  }

  /** DOD-CONTACT-VIEW-1: set an EXISTING contact's reachability tier. Returns false when no such
   *  contact — fail-loud at the caller, never a silent no-op success (same contract as
   *  setContactMoniker). The caller validates the tier is a known constant BEFORE calling; this
   *  stores whatever it is handed (the handler is the validation boundary). */
  setContactTier(agentName: string, pubkey: string, tier: number): boolean {
    if (!this.#db) throw new Error(`setContactTier('${agentName}'): database not initialized`);
    const res = this.#db
      .prepare("UPDATE contacts SET tier = ? WHERE agent_id = ? AND pubkey = ?")
      .run(tier, this.#requireAgentId(agentName), pubkey);
    return res.changes > 0;
  }

  /** DOD-RENAME-1 (Option C): record a self-declared name a peer offered, at the moment the offer is
   *  SEEN. The stored local pet name (contacts.moniker) is SACROSANCT — this only ever touches
   *  last_offered_moniker and the notice queue, never the moniker (AC2). A rename NOTICE is queued
   *  only when the peer is a contact the operator has PERSONALLY NAMED (moniker non-null), a name was
   *  seen BEFORE (last_offered_moniker non-null), and the new offer DIFFERS (AC3). The first-ever
   *  offer just records the baseline (no notice); a repeat of the same name is idempotent (AC4).
   *  Called only when a moniker WAS offered (caller-guarded), so silence never clears the baseline
   *  (AC5). Limitation: last_offered_moniker updates only on the RECEIVING side of an offer, so rename
   *  detection works only for peers who INITIATE to you — a property, not a bug. */
  recordOfferedMoniker(agentName: string, pubkey: string, offered: string): void {
    // Fail CLOSED like getTier/setContactTier: a silent skip here would drop a rename baseline update
    // (and any notice) while the daemon reports healthy — the inbound path always has an open DB.
    if (!this.#db) throw new Error(`recordOfferedMoniker('${agentName}'): database not initialized`);
    const agentId = this.#requireAgentId(agentName);
    const row = this.#db
      .prepare("SELECT last_offered_moniker, moniker FROM contacts WHERE agent_id = ? AND pubkey = ?")
      .get(agentId, pubkey) as { last_offered_moniker: string | null; moniker: string | null } | undefined;
    if (!row) return; // not a contact — no row to hold a baseline or a notice
    if (offered === row.last_offered_moniker) return; // idempotent — same name already seen (AC4)
    // A genuine change from a previously-seen name, for a contact the operator has named → notice.
    if (row.last_offered_moniker !== null && row.moniker !== null) {
      this.#db
        .prepare("INSERT OR REPLACE INTO contact_rename_notices (agent_id, pubkey, offered_name, noticed_at) VALUES (?, ?, ?, ?)")
        .run(agentId, pubkey, offered, Date.now());
      // Observability: log the FACT, never the attacker-chosen name (same rule as moniker.rejected).
      this.#logger.info("contact.rename.noticed", { agentName, pubkey });
    }
    this.#db
      .prepare("UPDATE contacts SET last_offered_moniker = ? WHERE agent_id = ? AND pubkey = ?")
      .run(offered, agentId, pubkey);
  }

  /** DOD-RENAME-1: pending rename notices for an agent, oldest first (surfaced in
   *  cello_check_notifications — an INBOX pull, never a real-time push). */
  getRenameNotices(agentName: string): Array<{ pubkey: string; offered_name: string; noticed_at: number; moniker: string | null }> {
    if (!this.#db) return [];
    // JOIN the local pet name so the notice can NAME the contact (AC3) — a notice only ever fires for
    // a personally-named contact, so moniker is expected non-null (LEFT JOIN is defensive).
    return this.#db
      .prepare(
        `SELECT n.pubkey, n.offered_name, n.noticed_at, c.moniker
         FROM contact_rename_notices n
         LEFT JOIN contacts c ON c.agent_id = n.agent_id AND c.pubkey = n.pubkey
         WHERE n.agent_id = ? ORDER BY n.noticed_at ASC`,
      )
      .all(this.#requireAgentId(agentName)) as Array<{ pubkey: string; offered_name: string; noticed_at: number; moniker: string | null }>;
  }

  /** DOD-RENAME-1: clear a pending rename notice — the operator acted (adopted a name or removed the
   *  contact). Idempotent (no notice → no-op). Fail-closed on a missing DB, like the writes above. */
  clearRenameNotice(agentName: string, pubkey: string): void {
    if (!this.#db) throw new Error(`clearRenameNotice('${agentName}'): database not initialized`);
    this.#db
      .prepare("DELETE FROM contact_rename_notices WHERE agent_id = ? AND pubkey = ?")
      .run(this.#requireAgentId(agentName), pubkey);
  }

  /** M8C-CONTACT-1: known stays known until explicitly removed. */
  removeContact(agentName: string, pubkey: string): boolean {
    if (!this.#db) return false;
    const res = this.#db.prepare("DELETE FROM contacts WHERE agent_id = ? AND pubkey = ?").run(this.#requireAgentId(agentName), pubkey);
    // DOD-RENAME-1: a removed contact has no pending rename to resolve.
    if (res.changes > 0) this.clearRenameNotice(agentName, pubkey);
    return res.changes > 0;
  }

  /** MONIKER-4: the operator's pet name for a pubkey (whoLabel's top tier), or null. Read-only
   *  and tolerant of a not-yet-open DB (a missing label degrades the doorbell, never blocks it). */
  getContactMoniker(agentName: string, pubkey: string): string | null {
    if (!this.#db) {
      // Review F2: the last fully-silent branch in the resolution chain — the label degrades to
      // fingerprint, which is correct, but say so rather than returning null wordlessly.
      this.#logger.debug("moniker.local.db_unavailable", { agentName, pubkey });
      return null;
    }
    const row = this.#db
      .prepare("SELECT moniker FROM contacts WHERE agent_id = ? AND pubkey = ?")
      .get(this.#requireAgentId(agentName), pubkey) as { moniker: string | null } | undefined;
    return row?.moniker ?? null;
  }

  /** M8C-CONTACT-1 + DOD-CONTACT-VIEW-1: list an agent's contacts, oldest-added first, each with its
   *  pet name (MONIKER-3), tier + provenance (the address-book metadata), and a READ-side LEFT JOIN
   *  against `sessions` for how many SEALED sessions were shared and when they last spoke (MAX
   *  updated_at). No new stored data — a pure read. A contact with no sessions shows 0 / null (never),
   *  not an error. The JOIN is scoped by agent_id so one agent's sessions never bleed into another's. */
  listContacts(agentName: string): Array<{
    pubkey: string; added_at: number; moniker: string | null;
    tier: number | null; provenance: string | null; sealed_count: number; last_spoke: number | null;
  }> {
    if (!this.#db) return [];
    return this.#db
      .prepare(
        `SELECT c.pubkey, c.added_at, c.moniker, c.tier, c.provenance,
                COUNT(CASE WHEN s.status = 'sealed' THEN 1 END) AS sealed_count,
                MAX(s.updated_at) AS last_spoke
         FROM contacts c
         LEFT JOIN sessions s ON s.agent_id = c.agent_id AND s.counterparty_pubkey = c.pubkey
         WHERE c.agent_id = ?
         GROUP BY c.pubkey, c.added_at, c.moniker, c.tier, c.provenance
         ORDER BY c.added_at ASC`,
      )
      .all(this.#requireAgentId(agentName)) as Array<{
        pubkey: string; added_at: number; moniker: string | null;
        tier: number | null; provenance: string | null; sealed_count: number; last_spoke: number | null;
      }>;
  }

  /** M8C-ABUSE-1: cumulative RECEIVED byte total for a session (anti-drip-feed accounting). */
  #getReceivedBytesTotal(agentName: string, sessionId: string): number {
    if (!this.#db) return 0;
    const row = this.#db
      .prepare("SELECT COALESCE(SUM(LENGTH(blob)), 0) AS total FROM transcript WHERE agent_id = ? AND session_id = ? AND direction = 'received'")
      .get(this.#requireAgentId(agentName), sessionId) as { total: number };
    return row.total;
  }

  /** M8C-ABUSE-1 (reviewer HIGH fix, D18): bytes currently sitting in the out-of-order hold
   *  buffer for this session — NOT yet committed leaves, but real bytes in memory that would
   *  otherwise let multiple held chunks each individually pass the size gate while cumulatively
   *  exceeding it once #releaseHeld drains them. */
  #getHeldBytesTotal(agentName: string, sessionId: string): number {
    const held = this.#heldContent.get(this.#k(agentName, sessionId));
    if (!held) return 0;
    let total = 0;
    for (const entry of held.values()) total += entry.content.length;
    return total;
  }

  /** M8C-ABUSE-1: non-terminal sessions this agent currently holds with the given counterparty.
   *  Reviewer HIGH fix (aeffb82f, D18): counting `status = 'active'` ONLY let a counterparty
   *  evade the bound for free by disconnecting (a trivial, attacker-controlled action that flips
   *  a session to 'interrupted' — markInterruptedWithDetails) and opening a fresh session,
   *  repeated indefinitely. 'interrupted' sessions still accept content (ingestReceivedContent
   *  explicitly allows both statuses) and are NOT terminal (sealed/seal_interrupted_pending are),
   *  so they must still count against the bound. */
  countActiveSessionsForCounterparty(agentName: string, counterpartyPubkey: string): number {
    if (!this.#db) return 0;
    const row = this.#db
      .prepare("SELECT COUNT(*) AS n FROM sessions WHERE agent_id = ? AND counterparty_pubkey = ? AND status IN ('active', 'interrupted')")
      .get(this.#requireAgentId(agentName), counterpartyPubkey) as { n: number };
    return row.n;
  }

  /** M8C-ABUSE-1 (anti-swarm) + DOD-TIER-2: non-terminal sessions this agent holds with UNKNOWN-tier
   *  counterparties — the global cap counts across the whole stranger pool. A sender is exempt from
   *  THIS pool iff it is a KNOWN+ contact (tier >= KNOWN); a bare stranger (no row → UNKNOWN) or an
   *  explicitly UNKNOWN-tier contact both count. Keying on `tier >= KNOWN` (bounded to <= VIP so a
   *  corrupt high value cannot grant pool-exemption) replaces the old row-existence proxy, which
   *  would have let a merely-recorded UNKNOWN contact escape the anti-swarm cap. Same
   *  'interrupted'-status fix as countActiveSessionsForCounterparty above. */
  countActiveSessionsFromUnknownSenders(agentName: string): number {
    if (!this.#db) return 0;
    const row = this.#db
      .prepare(
        `SELECT COUNT(*) AS n FROM sessions s
         WHERE s.agent_id = ? AND s.status IN ('active', 'interrupted')
           AND NOT EXISTS (
             SELECT 1 FROM contacts c
             WHERE c.agent_id = s.agent_id AND c.pubkey = s.counterparty_pubkey
               AND c.tier >= ${TIER.KNOWN} AND c.tier <= ${TIER.VIP}
           )`,
      )
      .get(this.#requireAgentId(agentName)) as { n: number };
    return row.n;
  }

  /** M8C-ABUSE-1 + DOD-TIER-2/3: is a NEW inbound session from this counterparty within the
   *  acceptance bounds? The per-sender cap is now the sender's TIER cap (DEFAULT_TIER_BOUNDS), not a
   *  flat "3 for strangers, unbounded for contacts". This is where DOD-TIER-3 falls out for free: a
   *  BLOCKED sender's cap is 0, so `perSender (>= 0) >= 0` refuses it through the SAME reason and the
   *  SAME path an over-cap UNKNOWN takes — no separate blocked branch, no distinguishing oracle. The
   *  global anti-swarm cap then applies ONLY to UNKNOWN-tier senders (KNOWN+ are trusted, not part of
   *  the stranger pool; BLOCKED never reaches it). Checked BEFORE accepting a fresh inbound session
   *  (counts reflect sessions already active, not yet counting this one). */
  checkUnknownSenderAcceptanceBound(agentName: string, counterpartyPubkey: string): { ok: true } | { ok: false; reason: string } {
    const tier = this.getTier(agentName, counterpartyPubkey);
    const perSenderCap = this.resolveTierBound(agentName, tier, "max_sessions");
    const perSender = this.countActiveSessionsForCounterparty(agentName, counterpartyPubkey);
    if (perSender >= perSenderCap) {
      return { ok: false, reason: "abuse_bound_sessions_per_sender" };
    }
    // The global stranger cap is only for the UNKNOWN pool. A KNOWN+ sender is past it by trust;
    // a BLOCKED sender was already refused above (cap 0).
    if (tier === TIER.UNKNOWN) {
      const globalUnknown = this.countActiveSessionsFromUnknownSenders(agentName);
      if (globalUnknown >= ABUSE_MAX_UNKNOWN_SESSIONS_GLOBAL) {
        return { ok: false, reason: "abuse_bound_unknown_sessions_global" };
      }
    }
    return { ok: true };
  }

  /** M8C-TGDOOR-1: the daemon-wide Telegram bot settings, or null if never configured. */
  getTelegramSettings(): { botToken: string; allowlistedChatId: string } | null {
    if (!this.#db) return null;
    const row = this.#db
      .prepare("SELECT bot_token, allowlisted_chat_id FROM telegram_settings WHERE id = 1")
      .get() as { bot_token: string; allowlisted_chat_id: string } | undefined;
    return row ? { botToken: row.bot_token, allowlistedChatId: row.allowlisted_chat_id } : null;
  }

  /** M8C-TGDOOR-1: persist (or replace) the singleton Telegram settings row. */
  setTelegramSettings(botToken: string, allowlistedChatId: string): void {
    if (!this.#db) return;
    this.#db
      .prepare(
        `INSERT INTO telegram_settings (id, bot_token, allowlisted_chat_id, updated_at) VALUES (1, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET bot_token = excluded.bot_token, allowlisted_chat_id = excluded.allowlisted_chat_id, updated_at = excluded.updated_at`,
      )
      .run(botToken, allowlistedChatId, Date.now());
  }

  /** DOD-SETTINGS-1: read a per-agent setting, or null if unset. The get-with-default is the CALLER's
   *  job (an unset key falls back to the hardcoded grid/system default — the daemon runs correctly on
   *  defaults alone, AC3). Returns null on a missing DB (settings are always optional). */
  getSetting(agentName: string, key: string): string | null {
    if (!this.#db) return null;
    const row = this.#db
      .prepare("SELECT value FROM agent_settings WHERE agent_id = ? AND key = ?")
      .get(this.#requireAgentId(agentName), key) as { value: string } | undefined;
    return row?.value ?? null;
  }

  /**
   * DOD-SETTINGS-1: DELETE a per-agent setting so the built-in default applies again.
   *
   * Deleting is NOT storing "". `getSetting` returns null for both, but the away-text resolver walks
   * per-contact → per-tier → agent-default → system default, and an empty string is a VALUE that
   * wins that walk and blanks the reply. Unsetting is the only way back to the default, and until
   * this existed there was no way back at all: `cello_settings_set` accepted a string, refused an
   * empty one, and told the caller to "pass null to clear" — a null it coerced to undefined and
   * rejected as missing_params. Following that guidance from the CLI set the literal text "null",
   * so an operator trying to remove their away message ended up broadcasting the word "null" to
   * every caller.
   *
   * Returns whether a row was actually removed, so the handler can report what it did rather than
   * claiming a clear it never performed.
   */
  deleteSetting(agentName: string, key: string): boolean {
    if (!this.#db) throw new Error(`deleteSetting('${agentName}'): database not initialized`);
    // Same dual-layer key check as setSetting — an unknown key here means a caller hand-typed one,
    // and silently reporting "cleared" for a key that never existed would be the same class of lie.
    if (!isValidSettingKey(key)) throw new Error(`invalid_key: '${key}' is not a known setting`);
    const res = this.#db
      .prepare("DELETE FROM agent_settings WHERE agent_id = ? AND key = ?")
      .run(this.#requireAgentId(agentName), key);
    return res.changes > 0;
  }

  /** DOD-SETTINGS-1: write a per-agent setting (upsert). Key VALIDATION is the handler's boundary
   *  (isValidSettingKey); value validation for typed settings (finite bounds, etc.) belongs to the
   *  specific consumer. Throws on a missing DB — a write that silently no-ops would be a lie. */
  setSetting(agentName: string, key: string, value: string): void {
    if (!this.#db) throw new Error(`setSetting('${agentName}'): database not initialized`);
    // Store-level backstop (review F2): the handler validates the key, but the dual-layer convention
    // (cf. MONIKER-1) means an unknown key can NEVER be stored — an internal caller that hand-typed a
    // key instead of using the builders would otherwise persist a setting that never takes effect.
    if (!isValidSettingKey(key)) throw new Error(`invalid_key: '${key}' is not a known setting`);
    this.#db
      .prepare(
        `INSERT INTO agent_settings (agent_id, key, value, updated_at) VALUES (?, ?, ?, ?)
         ON CONFLICT(agent_id, key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
      )
      .run(this.#requireAgentId(agentName), key, value, Date.now());
  }

  /** DOD-SETTINGS-1: all explicitly-set settings for an agent (the ones that OVERRIDE a default),
   *  key-sorted. Unset keys are absent — the operator sees only what they changed. */
  getAllSettings(agentName: string): Array<{ key: string; value: string }> {
    if (!this.#db) return [];
    return this.#db
      .prepare("SELECT key, value FROM agent_settings WHERE agent_id = ? ORDER BY key ASC")
      .all(this.#requireAgentId(agentName)) as Array<{ key: string; value: string }>;
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
  /** Fix #1 EXTENSION: inject the broker-connection opener. Setter injection, same construction-order reason. */
  setEnsureSealBroker(
    cb: (agentName: string, sessionId: string) => Promise<{ stop: (reason: string) => Promise<void> } | null>,
  ): void {
    this.#ensureSealBroker = cb;
  }

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
   * M8C-MSGWAKE-1: inject the content-arrival callback (daemon.ts → NotificationDispatcher.
   * dispatchCelloMessage). Setter injection, same construction-order reason as above.
   */
  setOnContentArrived(
    cb: (agentName: string, sessionId: string, senderPubkey: string) => void,
  ): void {
    this.#onContentArrived = cb;
  }

  /** M14 / DOD-DOC-INBOUND-2: inject the document-frame interception. See the field's note. */
  setOnDocumentFrame(
    cb: (
      agentName: string,
      sessionId: string,
      content: Uint8Array,
      senderPubkey: string,
      correlationId?: string,
    ) => { consumed: boolean; kind?: string; ok?: boolean; reason?: string },
  ): void {
    this.#onDocumentFrame = cb;
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
   * DOD-AGENT-ID-JOINKEY-1: resolve an agent's NAME to its STABLE agent_id. This is the ONE place a
   * name becomes a key, and it is the boundary between the two worlds:
   *
   *   - ABOVE it, addressing by name is correct. The operator says `cello_use_agent { name }`, and
   *     the in-memory maps (#k, standing receivers, keyProviders) key by name safely, because
   *     name-addressing only ever resolves ACTIVE agents and the `agents_active_name` partial unique
   *     index makes active names unique.
   *   - BELOW it, only `agent_id` may touch SQL. `agent_name` is a mutable display attribute that a
   *     retire frees for reuse; a table joined on it hands a new keypair the dead identity's rows.
   *
   * It resolves ONLY non-retired agents — a retired identity is gone from the runtime (`list` omits
   * it, `start` returns agent_not_found), so no live surface may act as one.
   *
   * It THROWS on an unresolvable name rather than returning null. A null would flow into a
   * `WHERE agent_id IS NULL` that quietly matches nothing: reads would return empty and writes would
   * vanish, and the daemon would look healthy while losing an agent's data. Every caller has already
   * resolved the agent before it gets here, so an unresolvable name is a bug in the caller, not a
   * condition to absorb.
   */
  #requireAgentId(agentName: string): string {
    if (!this.#db) throw new Error("agent_id_unresolved: database is not open");
    const row = this.#db
      .prepare("SELECT agent_id FROM agents WHERE agent_name = ? AND state != 'retired'")
      .get(agentName) as { agent_id: string } | undefined;
    if (!row) {
      this.#logger.error("session.agent_id.unresolved", { agentName });
      throw new Error(
        `agent_id_unresolved: no active agent named '${agentName}'. The session tables are keyed by the ` +
          `stable agent_id (DOD-AGENT-ID-JOINKEY-1); scoping a query by an unresolvable name would ` +
          `silently match nothing.`,
      );
    }
    return row.agent_id;
  }

  /**
   * DOD-AGENT-ID-JOINKEY-1: the public form of the name→stable-id resolver, for components that own
   * agent-scoped tables of their own (RetryQueue) and must be handed the STABLE key, never a name.
   * The daemon resolves ONCE, at its own boundary, exactly as this class does internally. Throws on
   * an unresolvable name — see #requireAgentId for why null is not an option.
   */
  resolveAgentId(agentName: string): string {
    return this.#requireAgentId(agentName);
  }

  /**
   * Reverse lookup: the display name of a stable agent_id, or null if no such agent.
   *
   * Deliberately INCLUDES retired agents. Its caller (the startup awaiting-content re-park) holds an
   * agent_id read off a durable row and needs a name to find that agent's standing receiver. A
   * retired agent resolves to its name and then has no standing receiver, so the park fails cleanly
   * and loudly — which is correct. Filtering retired agents out here would instead make the row
   * unattributable and the failure mute.
   */
  agentNameForId(agentId: string): string | null {
    if (!this.#db) return null;
    const row = this.#db
      .prepare("SELECT agent_name FROM agents WHERE agent_id = ?")
      .get(agentId) as { agent_name: string } | undefined;
    return row?.agent_name ?? null;
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

    // Persist to SQLite. D4 review F1: #insertSessionRow swallows the write failure (returns
    // false) — ignoring it let a session go fully live with NO sessions row, which after D4a means
    // every inbound message is refused session_orphaned while the session looks healthy to both
    // operators. A rowless session is a dead session by definition — fail ONCE, here, at creation.
    if (!this.#insertSessionRow(sessionId, agentName, counterpartyPubkey, "active")) {
      try {
        await node.stop();
      } catch (err: unknown) {
        this.#logger.warn("session.node.stop.failed", {
          sessionId,
          agentName,
          error: err instanceof Error ? err.message : String(err),
          correlationId,
        });
      }
      // The handed-off standing receiver was consumed above — rebuild it (idempotent).
      if (reuseStandingReceiver) void this.#ensureStandingReceiver(agentName, correlationId);
      return {
        ok: false,
        reason: "session_persist_failed",
        guidance:
          "The daemon could not persist the session row (see session.row.write.failed in the log). " +
          "The session was not created — a session without a durable row cannot receive content. " +
          "Check the daemon's database (disk space, permissions) and retry.",
      };
    }

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
    this.#wireSessionLiveness(agentName, sessionId, node, counterpartyPubkey, correlationId, counterpartyPeerId);

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
            ?.prepare("UPDATE sessions SET relay_peer_id = ?, relay_addrs = ?, updated_at = ? WHERE agent_id = ? AND session_id = ?")
            .run(relay.relayPeerId, JSON.stringify(relay.relayAddrs), Date.now(), this.#requireAgentId(agentName), sessionId);
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
   * events to per-session direct-path liveness. onPeerConnect → 'alive',
   * onPeerDisconnect → 'gone', emitting session.liveness.changed at WARN. Combined
   * with the transport keepalive (AC-005), a peer that vanished without a clean
   * close still surfaces a disconnect and drives 'gone'.
   *
   * THE EVENT MUST BE FILTERED BY PEER (DOD-RELAY-KEEPALIVE-1 review, F2). The
   * original wiring acted on EVERY peer event this node saw, justified by "the
   * session node's gater restricts connections to the designated counterparty".
   * That stopped being true: the session node also dials the RELAY as its
   * Structure-2 witness (#connectSessionRelay), and the gater allows those peers
   * outbound. So a relay link dropping declared the counterparty dead — at WARN,
   * feeding the unilateral-seal gate — while the counterparty was sitting there
   * perfectly alive. During the 2026-08-04 incident, when the relay link churned
   * every 60-90 seconds, that fired continuously.
   *
   * `counterpartySessionPeerId` is the authority when known. When it is not (the
   * peer id can be absent on a session whose assignment has not landed yet),
   * every peer is honoured EXCEPT ones known to be relays for this session —
   * degrading to the old over-eager behaviour minus its one known false positive,
   * rather than to silence, because a liveness detector that never fires is worse
   * than one that fires too often.
   */
  #wireSessionLiveness(
    agentName: string,
    sessionId: string,
    node: CelloNode,
    counterpartyPubkey: string,
    correlationId: string,
    counterpartySessionPeerId?: string,
  ): void {
    const key = this.#k(agentName, sessionId);
    const isCounterparty = (peerId: string): boolean => {
      if (counterpartySessionPeerId) return peerId === counterpartySessionPeerId;
      const entry = this.#activeNodes.get(key);
      return entry?.relayPeerId !== peerId;
    };
    node.onPeerConnect((peerId: string) => {
      if (!isCounterparty(peerId)) return;
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
    node.onPeerDisconnect((peerId: string) => {
      if (!isCounterparty(peerId)) {
        // Not silence: a relay link dropping is a real event, it is simply not a
        // statement about the counterparty. It has its own signal
        // (session.standing_receiver.reservation.lost / session.relay.reader.ended).
        this.#logger.debug("session.liveness.unrelated_peer_disconnect", {
          sessionId,
          peerId,
          correlationId,
        });
        return;
      }
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

  /** Test seam (same spirit as getDb()): seed per-session direct-path liveness, which is otherwise
   *  only set by the live node's onPeerConnect/onPeerDisconnect (#wireSessionLiveness). Lets a
   *  DB-seeded test exercise the CC-5 reaper's "alive counterparty must survive" gate without standing
   *  up a real libp2p peer connection. */
  markSessionLivenessForTest(agentName: string, sessionId: string, state: "alive" | "gone"): void {
    this.#sessionLiveness.set(this.#k(agentName, sessionId), state);
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

    // Persist to SQLite. D4 review F1 (same as createSessionNode): a swallowed row-write failure
    // must fail the accept ONCE here — after D4a a rowless session refuses every ingest. The
    // standing receiver (this node) is consumed and rebuilt rather than left with its gater
    // pointed at this initiator.
    if (!this.#insertSessionRow(sessionId, agentName, counterpartyPubkey, "active")) {
      this.#standingReceivers.delete(agentName);
      try {
        await node.stop();
      } catch (err: unknown) {
        this.#logger.warn("session.node.stop.failed", {
          sessionId,
          agentName,
          error: err instanceof Error ? err.message : String(err),
          correlationId,
        });
      }
      void this.#ensureStandingReceiver(agentName, correlationId);
      return {
        ok: false,
        reason: "session_persist_failed",
        guidance:
          "The daemon could not persist the session row (see session.row.write.failed in the log). " +
          "The inbound session was not accepted — a session without a durable row cannot receive content. " +
          "Check the daemon's database (disk space, permissions).",
      };
    }

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
    this.#wireSessionLiveness(agentName, sessionId, node, counterpartyPubkey, correlationId, initiatorPeerId);

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
      // DOD-COATTEND-1: counted from the DURABLE read watermark, not the buffer's length.
      // Delivery no longer drains that buffer (it reads the transcript against a per-connection
      // bookmark), so its length is now "everything that ever arrived", not "what nobody read" —
      // reporting it would tell the operator every message of a healthy conversation went unread.
      const unreadCount = this.getUnreadReceivedCount(agentName, sessionId);
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
    // DOD-COATTEND-1: same correction as the terminal marker above — the buffer is no longer
    // drained by delivery, so its length no longer means "unread". The watermark does.
    const unreadCount = this.getUnreadReceivedCount(agentName, sessionId);
    if (unreadCount > 0) {
      this.#logger.info("session.receive.buffer.evicted", { sessionId, agentName, unreadCount });
    }
    // READ BEFORE THE EVICTION. The held-content loss report below wants the tree size, and asking
    // for it AFTER this line is not a read — `getSessionTree` misses the cache, reloads the whole
    // leaf table from disk, and puts the tree straight back into `#trees`, so the diagnostic
    // resurrects the state its own teardown exists to drop. Worse, that reload goes through
    // `#requireAgentId`, which THROWS for a retired agent — and it would throw here, before the
    // held content and high-water map below are cleared, on the abnormal path only.
    const treeSizeBeforeEviction = this.#trees.get(key)?.size() ?? null;
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
    // HELD CONTENT IS LOST HERE, AND IT MUST SAY SO.
    //
    // These are frames we RECEIVED and VERIFIED and could not yet append, because the relay's
    // canonical sequence put them ahead of our tree. Deleting the map drops them — the sender
    // believes they were delivered, we never applied them, and until now nothing anywhere recorded
    // that it happened.
    //
    // Found live: a document ack arrived, logged `session.content.held` for a one-slot gap, and was
    // destroyed with the session three seconds later. The sender then re-sent that envelope 90
    // times against a ceiling of 5, and every surface reported the delivery as merely pending.
    //
    // This is a LOSS REPORT, not a fix — the content is unrecoverable by the time we are here. The
    // fix is upstream, in not tearing a session down while an answer is still owed on it.
    const strandedHolds = this.#heldContent.get(key);
    if (strandedHolds && strandedHolds.size > 0) {
      this.#logger.error("session.content.held.discarded", {
        agentName,
        sessionId,
        count: strandedHolds.size,
        canonicalSeqs: [...strandedHolds.keys()].sort((a, b) => a - b),
        // NULL when the tree was not cached at teardown. Honest, and cheap — reloading the leaf
        // table to fill in a diagnostic field is not worth a disk read on every teardown, let
        // alone the cache resurrection it caused.
        treeSize: treeSizeBeforeEviction,
      });
    }
    this.#heldContent.delete(key);
    this.#highWaterSeq.delete(key);
  }

  /**
   * Graceful shutdown: mark all active sessions as interrupted, stop all nodes.
   * Called from the SIGTERM / cello logout path (AC-009).
   * SQLite writes complete before this method returns.
   */
  async gracefulShutdown(): Promise<void> {
    // DOD-NAT-REACHABILITY-1: stop the reservation watchdog before anything is torn
    // down — a tick landing mid-shutdown would try to rebuild a receiver we are in
    // the middle of stopping.
    if (this.#reservationWatchdog !== null) {
      clearInterval(this.#reservationWatchdog);
      this.#reservationWatchdog = null;
    }
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
    // Spans EVERY agent (cello_status is daemon-wide), so no single name can be resolved up front —
    // the display name is joined in from `agents`, its one source of truth. `agent_name` is no
    // longer a `sessions` column, so without this join buildActiveSessions/buildInterruptedSessions
    // read `row.agent_name` as undefined.
    //
    // DOD-AGENT-ID-JOINKEY-1 (reviewer Finding 1): INNER JOIN with `state != 'retired'`, NOT a bare
    // LEFT JOIN. This is the LIVE-status + reaper surface, and a retired agent is gone from the
    // runtime — its leftover session rows (kept for accountability, never re-statused) are not
    // resumable and must not appear here. If they did, the half-open reaper would resolve their
    // RETIRED name via #requireAgentId, which throws, taking down cello_status for the whole daemon.
    // Excluding them also guarantees a non-null agent_name on every returned row. The full historical
    // archive (getAllSessions) keeps its LEFT JOIN and still shows retired/orphaned rows.
    return this.#db
      .prepare(
        `SELECT s.*, a.agent_name AS agent_name
         FROM sessions s JOIN agents a ON a.agent_id = s.agent_id
         WHERE s.status = ? AND a.state != 'retired'`,
      )
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
    // Scoped by the STABLE id. `agent_name` is not a column of `sessions` any more, so it is stamped
    // back on for display — and it is exactly the name we just resolved the id FROM, so no join is
    // needed and no stale copy can exist.
    const rows = this.#db
      .prepare("SELECT * FROM sessions WHERE agent_id = ? ORDER BY updated_at DESC")
      .all(this.#requireAgentId(agentName)) as unknown as SessionRecord[];
    return rows.map((r) => ({ ...r, agent_name: agentName }));
  }

  /**
   * Every persisted session across ALL agents, most-recently-updated first. Backs the daemon-wide
   * `cello sessions` CLI surface (which has no per-connection current agent, unlike the MCP
   * cello_list_sessions). Classification + filtering + the count limit are applied by the caller.
   */
  getAllSessions(): SessionRecord[] {
    if (!this.#db) return [];
    // Spans EVERY agent, so no single name can be resolved up front: the display name is joined in
    // from `agents`, its one source of truth. LEFT JOIN, not INNER — a session whose agent row is
    // missing must still be listed (an invisible session is worse than an unnamed one).
    return this.#db
      .prepare(
        `SELECT s.*, a.agent_name AS agent_name
         FROM sessions s LEFT JOIN agents a ON a.agent_id = s.agent_id
         ORDER BY s.updated_at DESC`,
      )
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
      .prepare("UPDATE sessions SET seal_legibility = ?, sealed_root_hex = ?, updated_at = ? WHERE agent_id = ? AND session_id = ?")
      .run(legibilityJson, sealedRootHex, Date.now(), this.#requireAgentId(agentName), sessionId);
  }

  /**
   * M8B FINDING-6 (cascade-2): persist a seal certificate for a session that may have NO local
   * `sessions` row. recordSealCertificate above is an `UPDATE ... WHERE` — a SILENT no-op when the
   * row is absent (the exact trap the cascade-2 reviewer flagged). The ABSENT party (B), learning of
   * a seal on reconnect via seal_unilateral_notification, may never have persisted a row for this
   * session. This ensures a minimal stub row first (INSERT OR IGNORE — a no-op if a row already
   * exists, e.g. an 'interrupted' row after a restart) so B's receipt is actually durable + retrievable
   * via cello_get_sealed_receipt. The counterparty pubkey is required by the schema (NOT NULL); B
   * derives it from the notification's present_pubkey.
   */
  recordSealCertificateEnsuringRow(
    agentName: string,
    sessionId: string,
    counterpartyPubkeyHex: string,
    sealedRootHex: string,
    legibilityJson: string,
  ): void {
    if (!this.#db) return;
    const now = Date.now();
    this.#db
      .prepare(
        `INSERT OR IGNORE INTO sessions
           (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .run(sessionId, this.#requireAgentId(agentName), counterpartyPubkeyHex, "sealed", now, now);
    this.recordSealCertificate(agentName, sessionId, sealedRootHex, legibilityJson);
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
      .prepare("UPDATE sessions SET counterparty_primary_pubkey = ?, updated_at = ? WHERE agent_id = ? AND session_id = ?")
      .run(primaryPubkeyHex, Date.now(), this.#requireAgentId(agentName), sessionId);
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
      .prepare("SELECT sealed_root_hex, seal_legibility FROM sessions WHERE agent_id = ? AND session_id = ?")
      .get(this.#requireAgentId(agentName), sessionId) as { sealed_root_hex?: string | null; seal_legibility?: string | null } | undefined;
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
          "UPDATE sessions SET status = 'interrupted', updated_at = ?, message_count = ?, interrupted_at = ? WHERE agent_id = ? AND session_id = ? AND status = 'active'",
        )
        .run(now, authoritativeCount, interruptedAt, this.#requireAgentId(agentName), sessionId);
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
           (agent_id, session_id, role, own_leaf, counterparty_leaf, merkle_root, nonce, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          this.#requireAgentId(opts.agentName),
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
        "UPDATE sessions SET status = 'seal_interrupted_pending', updated_at = ? WHERE agent_id = ? AND session_id = ? AND status IN ('active', 'interrupted')",
      )
      .run(now, this.#requireAgentId(opts.agentName), opts.sessionId);
    return Number(result.changes) > 0;
  }

  /**
   * M7-SESSION-001 (H-1): read back the persisted bilateral commitment artifacts
   * for a session. Returns null when none exist.
   */
  /**
   * M12-P17: durably record verified content that arrived for an ALREADY-ENDED session.
   *
   * Returns true only when the row is committed — the caller confirm-deletes the relay copy on the
   * strength of this answer, and the ORDER is load-bearing: annex first, delete second. A crash
   * between them must lose nothing, so a failure here MUST report false and leave the relay copy
   * alone. Getting that backwards converts a noisy re-pull loop into permanent silent loss, which is
   * the outcome this whole unit exists to prevent.
   */
  recordSealedAnnex(agentName: string, sessionId: string, contentHashHex: string, content: Uint8Array, senderPubkeyHex: string | null): boolean {
    if (!this.#db) return false;
    try {
      this.#db
        .prepare(
          `INSERT OR IGNORE INTO sealed_session_annex (agent_id, content_hash, session_id, sender_pubkey, content, arrived_at)
           VALUES (?, ?, ?, ?, ?, ?)`,
        )
        .run(this.#requireAgentId(agentName), contentHashHex, sessionId, senderPubkeyHex, Buffer.from(content), Date.now());
      return true;
    } catch (err: unknown) {
      // FAILS LOUD and reports false: the relay copy is the only other one in existence.
      this.#logger.error("content.annex.write.failed", {
        agentName, sessionId, contentHash: contentHashHex,
        impact: "content NOT annexed — the relay copy must be kept, or the message is lost",
        error: err instanceof Error ? err.message : String(err),
      });
      return false;
    }
  }

  /**
   * M12-P18: record that this agent refused a session, so parked content that later arrives for it
   * (and fails `counterparty_unknown`, because no session row exists) can be swept instead of
   * re-pulled forever. Keeps the most recent REFUSED_SESSIONS_CAP per agent.
   */
  recordRefusedSession(agentName: string, sessionId: string, reason: string): void {
    if (!this.#db) return;
    const agentId = this.#requireAgentId(agentName);
    try {
      this.#db.prepare(
        `INSERT OR REPLACE INTO refused_sessions (agent_id, session_id, reason, refused_at) VALUES (?, ?, ?, ?)`,
      ).run(agentId, sessionId, reason, Date.now());
      // Prune to the cap — oldest first.
      this.#db.prepare(
        `DELETE FROM refused_sessions WHERE agent_id = ? AND session_id NOT IN (
           SELECT session_id FROM refused_sessions WHERE agent_id = ? ORDER BY refused_at DESC LIMIT ${SessionNodeManager.#REFUSED_SESSIONS_CAP}
         )`,
      ).run(agentId, agentId);
    } catch (err: unknown) {
      this.#logger.warn("session.refused.record.failed", {
        agentName, sessionId, error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  /** M12-P18: did this agent refuse this session? Consulted at drain to sweep orphaned parked content. */
  wasSessionRefused(agentName: string, sessionId: string): boolean {
    if (!this.#db) return false;
    const row = this.#db
      .prepare("SELECT 1 AS present FROM refused_sessions WHERE agent_id = ? AND session_id = ?")
      .get(this.#requireAgentId(agentName), sessionId) as { present: number } | undefined;
    return row !== undefined;
  }

  /** M12-P17: read the annex. Operator-initiated ONLY — never wired to a wake path or inbox count. */
  readSealedAnnex(agentName: string, sessionId?: string): Array<{ session_id: string; content_hash: string; sender_pubkey: string | null; text: string; arrived_at: number }> {
    if (!this.#db) return [];
    const rows = (sessionId === undefined
      ? this.#db.prepare("SELECT session_id, content_hash, sender_pubkey, content, arrived_at FROM sealed_session_annex WHERE agent_id = ? ORDER BY arrived_at ASC").all(this.#requireAgentId(agentName))
      : this.#db.prepare("SELECT session_id, content_hash, sender_pubkey, content, arrived_at FROM sealed_session_annex WHERE agent_id = ? AND session_id = ? ORDER BY arrived_at ASC").all(this.#requireAgentId(agentName), sessionId)
    ) as Array<{ session_id: string; content_hash: string; sender_pubkey: string | null; content: Buffer; arrived_at: number }>;
    return rows.map((r) => ({
      session_id: r.session_id, content_hash: r.content_hash, sender_pubkey: r.sender_pubkey,
      text: new TextDecoder().decode(new Uint8Array(r.content)), arrived_at: r.arrived_at,
    }));
  }

  getSealInterruptedArtifacts(agentName: string, sessionId: string): {
    role: string;
    ownLeaf: unknown;
    counterpartyLeaf: unknown;
    merkleRoot: string;
    nonce: string;
  } | null {
    if (!this.#db) return null;
    const row = this.#db
      .prepare("SELECT * FROM seal_interrupted_artifacts WHERE agent_id = ? AND session_id = ?")
      .get(this.#requireAgentId(agentName), sessionId) as
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
      .prepare("SELECT * FROM sessions WHERE agent_id = ? AND session_id = ?")
      .get(this.#requireAgentId(agentName), sessionId) as unknown as SessionRecord | undefined;
    // `agent_name` is display-only and no longer stored on the row; stamp back the name whose
    // agent_id scoped this lookup (~50 daemon call sites read `record.agent_name`).
    return row ? { ...row, agent_name: agentName } : null;
  }

  /**
   * DOD-SESSION-NAME-1: set (string) or clear (null) THIS agent's name for a session.
   *
   * Returns false when the (agent_id, session_id) row does not exist — i.e. the session is not this
   * agent's — so the caller refuses with session_not_found rather than reporting a silent success on
   * a write that landed nowhere. Same contract as setContactMoniker.
   *
   * Ownership is the ONLY scope: the composite key IS the ownership check, and status is deliberately
   * not consulted. A sealed session can be named — naming one long after the fact is the point — and
   * a name is a local column, so writing it cannot touch the seal, a Merkle leaf, or the wire.
   *
   * The caller validates (validateSessionName) before calling; this stores what it is given.
   */
  setSessionName(agentName: string, sessionId: string, sessionName: string | null): boolean {
    if (!this.#db) throw new Error(`setSessionName('${agentName}'): database not initialized`);
    const res = this.#db
      .prepare("UPDATE sessions SET session_name = ? WHERE agent_id = ? AND session_id = ?")
      .run(sessionName, this.#requireAgentId(agentName), sessionId);
    return res.changes > 0;
  }

  /**
   * MSG-2 startup-flush: the persisted relay endpoint for a session, or null if none was
   * recorded. Used by the crash-backstop flush, which runs at startup BEFORE the in-memory
   * session entries exist, so it cannot use `entry.relayPeerId`.
   */
  getPersistedRelayEndpoint(agentName: string, sessionId: string): { relayPeerId: string; relayAddrs: string[] } | null {
    if (!this.#db) return null;
    const row = this.#db
      .prepare("SELECT relay_peer_id, relay_addrs FROM sessions WHERE agent_id = ? AND session_id = ?")
      .get(this.#requireAgentId(agentName), sessionId) as { relay_peer_id?: string | null; relay_addrs?: string | null } | undefined;
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
      .prepare("SELECT DISTINCT relay_peer_id, relay_addrs FROM sessions WHERE agent_id = ? AND relay_peer_id IS NOT NULL")
      .all(this.#requireAgentId(agentName)) as Array<{ relay_peer_id?: string | null; relay_addrs?: string | null }>;
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
    kind: WritableSessionTreeLeafKind,
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
             (agent_id, session_id, leaf_index, leaf_kind, leaf_hash_hex, created_at)
             VALUES (?, ?, ?, ?, ?, ?)`,
          )
          .run(this.#requireAgentId(agentName), sessionId, leafIndex, kind, leafHashHex, Date.now());
        // DAEMON-004 (finding #2): keep sessions.message_count synced to the tree
        // size. message_count is the bilateral leafCount the seal flow signs over
        // (handleSealInterruptedFlow / the responder). If it diverged from the
        // daemon-owned tree, a post-active-messaging seal would attest to a
        // truncated transcript and the bilateral leafCount check would mismatch.
        // The tree (leafIndex + 1 leaves) is authoritative; the column tracks it.
        this.#db
          .prepare("UPDATE sessions SET message_count = ?, updated_at = ? WHERE agent_id = ? AND session_id = ?")
          .run(leafIndex + 1, Date.now(), this.#requireAgentId(agentName), sessionId);
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
    // DOD-NAT-REACHABILITY-1: a /p2p-circuit counterparty address is dialed
    // THROUGH its relay, so the gater must admit that relay peer OUTBOUND. The
    // relay id is embedded in the address, which arrived inside the FROST-signed
    // assignment — the same authorization rail as the assigned witness relay.
    for (const addr of addrs) {
      const viaRelay = addr.match(/\/p2p\/([^/]+)\/p2p-circuit/);
      if (viaRelay) entry.gater.setAllowedOutboundPeer(viaRelay[1]!);
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
        // extractErrorMessage handles the transport's structured plain-object
        // throws (dial() never throws Error instances) — the old
        // `instanceof Error` idiom logged "[object Object]" on every dial
        // failure; try the next addr.
        lastError = extractErrorMessage(err);
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
   * Send content over the session node's direct P2P content stream.
   * On a dead/missing stream this returns a NAMED, diagnosable failure — never a silent success
   * (which desyncs the two sides). Do not swallow a send error here.
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
    /**
     * The DOMAIN this content belongs to, as the relay and the directory will see it. Defaults to
     * MESSAGE so `cello_send` is unchanged; the document path passes 0x04/0x05. Not cosmetic — the
     * directory computes `final_message` and `answered` from the witnessed kind, and both of its
     * document exclusions were dead while every document leaf arrived here as a message.
     */
    leafKind: number = LEAF_KIND_MSG,
  ): Promise<{ ok: true; delivered: true } | { ok: true; delivered: false; parked: true } | { ok: false; reason: string; error: string; durable: boolean; cause?: string; guidance?: string }> {
    const entry = this.#activeNodes.get(this.#k(agentName, sessionId));
    if (!entry) {
      // M12-P13: no node, so nothing was witnessed and nothing was queued — the caller must NOT
      // commit a leaf for this. `durable` is a required field precisely so a new failure branch
      // cannot be added without answering the question every caller now asks.
      return { ok: false, reason: "session_node_unavailable", error: "no active session node for this session", durable: false };
    }
    // R1 (MSG-001-3b): witness the message-leaf HASH to the relay FIRST, INDEPENDENT of
    // direct delivery. The relay is the ordering authority (Structure 2): it assigns the
    // canonical sequence from the hash whether or not the counterparty is reachable for direct
    // content. So an OFFLINE recipient still gets a sequence, and the parked content is later
    // recovered AT that sequence (DOD-MSG-4 recovery-not-desync). The relay only ever sees the
    // hash (INV-3). Best-effort: a relay miss degrades to local-only sequencing.
    //
    // This MUST run BEFORE the direct send, not after it: an offline recipient never completes a
    // direct send, and sequencing after it would leave their content with no sequence at all.
    //
    // DOD-MSG-4 (self-ordering content frame): the relay's committed ordering record for this leaf,
    // captured from the hash submit so it can be stamped into the content frame (and the parked
    // entry). Undefined if the relay is unreachable / an old relay — the receiver then falls back to
    // the leaf_deliver witness stream / arrival order.
    let orderingS1: Uint8Array | undefined;
    let orderingS2: Uint8Array | undefined;
    // DOD-MP-SESSION-RETIRE-1 — the relay's answer SURVIVES to the caller even when the direct send
    // then succeeds. `relay_session_gone` is deliberately not terminal (it also fires for perfectly
    // live sessions whenever the relay restarts, because the relay stores sessions in memory), so
    // this path warns and carries on — and the send returns `ok: true, delivered: true` for a leaf
    // that was never witnessed. The content arrives; the RECORD stops growing, silently.
    //
    // Reporting it does not change success or failure for any existing caller. It lets the document
    // worker, which has no human in the loop, notice that a session's record is dead and route
    // around it. Without this the suspicion counter could never see the one reason it exists for,
    // and the successful direct send actively CLEARED it.
    let relayRefusal: string | undefined;
    if (entry.relayClient && entry.relaySessionIdBytes) {
      try {
        const witnessed = await entry.relayClient.submitMessageHash(entry.node, entry.relaySessionIdBytes, contentHash, leafKind);
        if (witnessed.ok) {
          orderingS1 = witnessed.structure1_cbor;
          orderingS2 = witnessed.structure2_cbor;
          this.#logger.info("session.relay.hash.submitted", {
            sessionId,
            sequenceNumber: witnessed.sequence_number,
            correlationId,
          });
        } else if (isTerminalRelayRefusal(witnessed.reason)) {
          // TERMINAL — REFUSE THE SEND, AND RETIRE THE SESSION. The relay has ended this session, so
          // this leaf can never enter the record and neither can any leaf after it. Continuing would
          // deliver content the conversation cannot prove it exchanged, and report `delivered: true`
          // while doing it.
          //
          // That is not hypothetical. Measured 2026-08-09: a session whose relay had sealed it after
          // both away-responders fired ran for 68 more minutes and 8 more messages, every send
          // reporting success, against a chain that had stopped growing at six leaves.
          //
          // Refused rather than parked: parking is for content the peer has not received YET. There
          // is no yet.
          //
          // DOD-MP-SESSION-RETIRE-1 — extracted to a function so the behaviour is REACHABLE BY A
          // TEST. Inline, it needed a live `#activeNodes` entry holding a real relay client, which
          // no unit test can construct — so nothing could assert what this daemon DOES about a
          // terminal refusal, and for a long time the answer was "logs it and carries on". The seam
          // that must be substituted is the relay's ANSWER; the thing under test is the response to
          // it. Splitting them makes the second testable without faking the first.
          return terminalRelayRefusal(
            {
              logger: this.#logger,
              // FULL TEARDOWN, not a status write. Every other terminal path goes through these,
              // and the difference is not bookkeeping: `destroySessionNode` also records the
              // terminal answer for a BLOCKED `cello_receive` (which otherwise hangs to timeout),
              // detaches the relay stream, stops the libp2p node, evicts the plaintext caches, and
              // re-arms the standing receiver — which on a fixed-port deployment is the moment the
              // port is freed. A DB-only flip leaves the corpse in `#activeNodes` holding the very
              // port the replacement session may need, which would defeat this fix's own purpose.
              //
              // THE TWO TERMINAL REASONS ARE NOT THE SAME FACT and must not share a status:
              //   session_sealed    — the seal really completed; a FROST certificate exists at the
              //                       directory and `cello_sealed_receipt` pulls it on a local miss.
              //   session_not_found — the relay never held it or lost it. There may be no
              //                       certificate anywhere, so writing "sealed" would be a
              //                       FABRICATED NOTARIZATION CLAIM: `cello_close_session` would
              //                       answer "already sealed, view its notarization" while the
              //                       receipt read answers "not sealed yet" — the two-answers-
              //                       pointing-at-each-other deadlock `seal-certificate-pull.ts`
              //                       exists to kill. `abandoned` is the state invented for
              //                       locally-terminal-with-nothing-to-notarize.
              // ONLY `session_sealed` RETIRES ANYTHING. The other terminal reason,
              // `session_not_found`, is documented THREE FUNCTIONS AWAY as **transient**
              // (DOD-FIRSTMSG-WITNESS-1): the relay does not hold the session YET, and in all 23
              // logged first-message failures the assignment landed 5ms–2.1s after the rejected
              // submit. Retiring on it would destroy a live session seconds old — trading a stuck
              // document for a killed conversation, which is a strictly worse bug than the one this
              // unit fixes. It still refuses the send; it just does not reach for the shovel.
              retireSession: (id) => {
                if (witnessed.reason !== "session_sealed") return;
                // STATUS FIRST AND SYNCHRONOUS, teardown second — the order `abandonSession` uses,
                // and for a sharper reason here: `destroySessionNode` returns early at its
                // `if (!entry) return` when the node is not in `#activeNodes`, and the status write
                // lives AFTER that guard. There is an entry on this path today (we are mid-send on
                // its relay client), but resting the whole fix on that is resting it on a
                // coincidence — a concurrent teardown would leave the row `active` and the loop
                // would resume. The flip is the load-bearing half; the teardown is what makes the
                // memory agree with it.
                this.#updateSessionStatus(agentName, id, "sealed");
                void this.destroySessionNode(agentName, id, "sealed");
              },
            },
            { sessionId, reason: witnessed.reason, correlationId },
          );
        } else {
          this.#logger.warn("session.relay.hash.submit.failed", {
            sessionId,
            reason: witnessed.reason,
            correlationId,
          });
          relayRefusal = witnessed.reason;
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
      const frame = encodeCbor({
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
      // Injected dial failure — thrown from inside the try so it lands in exactly the catch the
      // real connection_lost lands in, and the whole downstream path (untrack → park → durable
      // enqueue) runs unmodified.
      if (this.#sendFaultRemaining > 0) {
        this.#sendFaultRemaining -= 1;
        this.#logger.warn("content.send.fault.injected", { sessionId, contentHash: Buffer.from(contentHash).toString("hex") });
        throw new Error("connection_lost: injected direct-send fault");
      }
      stream.send(lp.encode.single(frame));
      // NOT SWALLOWED. This was `try { await stream.close(); } catch { }` followed by
      // `delivered: true` — which reports a frame as delivered when the flush failed.
      //
      // `close()` waits for the write buffer to drain, so a reset mid-flush throws HERE, and that
      // is precisely the case where the bytes never left. Discarding it made `delivered: true` mean
      // "we called send and close did not visibly complain", while every caller reads it as "the
      // peer has it" — and the sender then never retries, because nothing told it to.
      //
      // Letting it reach the catch below is the honest outcome: that path parks the content against
      // the relay backstop and reports `delivered: false` if it can, or `ok: false` if it cannot.
      // A close that failed for a benign reason costs a redundant park, which the receiver dedups
      // on the content hash. A false delivered costs the message.
      await stream.close();
      return { ok: true, delivered: true, ...(relayRefusal === undefined ? {} : { relayRefusal }) };
    } catch (err: unknown) {
      // The send failed after (possibly) arming the awaiting tracking — drop it so a
      // never-delivered frame does not later fire a spurious TTF park.
      this.#untrackAwaitingAck(agentName, sessionId, contentHash);
      // 2b: direct delivery failed (counterparty offline). The hash is already witnessed (R1, the
      // sequence is assigned), so deposit the content to the relay store-and-forward backstop now;
      // the recipient pulls + recovers it on next online (DOD-MSG-3/4).
      // DOD-LEAVEMSG-1: the deposit is now AWAITED (was fire-and-forget) so a genuine park success
      // can be reported as "dispatched to relay" instead of a raw stream failure — the operator/
      // agent sees the truth (the message IS in flight, just not direct), not a false negative.
      const hashHex = Buffer.from(contentHash).toString("hex");
      const attempt = await this.#parkContent(agentName, sessionId, hashHex, content, orderingS1, orderingS2);
      if (attempt.outcome === "parked") {
        return { ok: true, delivered: false, parked: true, ...(relayRefusal === undefined ? {} : { relayRefusal }) };
      }
      // M12-P12: the deposit was refused, and #untrackAwaitingAck above already dropped the
      // in-memory entry — so without this, NOTHING holds the content and the TTF timer that would
      // have enqueued it is cancelled. The recipient has already witnessed this sequence, so it
      // holds every later message in the session behind the gap, forever, and tells no one.
      // Enqueue durably instead; the drain hook re-parks it the moment the standing receiver is
      // rebuilt. Only on a REFUSAL — a successful deposit must not be re-parked, and an
      // unconfigured session has no park target to retry against (F6).
      let durable = false;
      if (attempt.outcome === "refused") {
        try {
          // M12-P13 (review HIGH-1): `durable` is now OBSERVED from the enqueue, not asserted around
          // it. Two ways this used to lie, both of which now commit a chain leaf and so cannot be
          // allowed to: the queue's content-derived dedupe key collides and it silently drops the
          // copy, and the `?.` no-ops entirely when the composition root never wired the hook. An
          // absent hook is not a queue.
          if (this.#onParkFailed === null) {
            this.#logger.error("content.park.durable_enqueue.unwired", {
              sessionId, contentHash: hashHex, agentName,
              impact: "no durable queue is wired — the content is NOT retained and will NOT be retried",
            });
          } else {
            durable = this.#onParkFailed(agentName, sessionId, hashHex, content, orderingS1, orderingS2);
          }
          if (!durable) {
            if (this.#onParkFailed !== null) {
              this.#logger.error("content.park.durable_enqueue.dropped", {
                sessionId, contentHash: hashHex, agentName,
                impact: "the durable queue refused this copy (identical content already queued) — it is NOT separately retained",
              });
            }
          } else {
            // F5: the successful enqueue must be visible. Without this the live run that has to
            // PROVE this fix has nothing to point at, and this log is the sender-side counterpart to
            // `session.content.held` on the receiver — the two together make the trace readable.
            // M12-P13: `witnessed` rides along because the caller is about to commit a hash-chain
            // leaf on the strength of this. Without a relay ordering record the recipient recovers
            // in arrival order instead — the accepted degradation, but it must not be invisible.
            this.#logger.info("content.park.deferred", {
              sessionId, contentHash: hashHex, agentName,
              selfOrdering: Boolean(orderingS1 && orderingS2),
              witnessed: Boolean(orderingS1 && orderingS2),
            });
          }
        } catch (hookErr: unknown) {
          // F3: enqueueAwaitingContent throws ON PURPOSE when the persist fails, because that is
          // data loss. Swallowing it into the same response the durable case returns would tell the
          // operator "it will retry" about a message that is simply gone. Named for its own cause,
          // and the response says so below.
          this.#logger.error("content.park.durable_enqueue.failed", {
            sessionId, contentHash: hashHex, agentName,
            impact: "content is NOT durable and will NOT be retried — the message is lost",
            error: hookErr instanceof Error ? hookErr.message : String(hookErr),
          });
        }
      }
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
      // F3: the two failures are NOT interchangeable to the caller. `reason` is a contract string
      // and stays put; `guidance` carries the difference, because "we are retrying this" and "this
      // message is gone, send it again" demand opposite actions from the operator.
      return {
        ok: false,
        reason: "session_stream_unavailable",
        error: errMsg,
        // M12-P13: the machine-readable half of the distinction below. M12-P12 shipped it in the
        // guidance SENTENCE only, so the callers that have to ACT on it — commit the leaf for a
        // queued message, never for a lost one — would have had to substring-match English. None
        // did, and the sequence the relay had already witnessed was left as a permanent hole.
        durable,
        // M12-P13 (review MEDIUM-5): the specific standing-receiver state, carried rather than
        // discarded. `reason` names where this surfaced; `cause` names what actually blocked it —
        // the exact distinction M12-P12 added `standingReceiverAbsenceReason()` for, which then
        // died inside #parkContent. An operator keying on `reason` alone is sent to the transport
        // when the blocker is the receiver.
        ...(attempt.cause !== undefined ? { cause: attempt.cause } : {}),
        guidance: durable
          ? "Direct delivery failed and the relay refused the hand-off, so the message is queued and will be re-sent automatically when the relay link is back. Do not re-send it: an identical re-send is not separately queued."
          : "Direct delivery failed and the message could NOT be queued for retry — it is lost. Send it again.",
      };
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
    // M12-P15: resolved, not required. See #resolveSealTransport — an interrupted session has no
    // in-memory node BY CONSTRUCTION, and refusing here is what made the first fix inert.
    const transport = this.#resolveSealTransport(agentName, sessionId);
    if ("error" in transport) return { ok: false, reason: transport.error };
    const entry = transport;

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
    // Establish the broker visiting connection BEFORE submitting, not after. The directory acts on
    // the leaf in ~60ms and pushes `seal_verified` straight back; if the stream is not up by then it
    // defers the frame and the seal stalls. Proven on GCP: leaf submitted 18:41:56.555, directory
    // deferred at 18:41:56.615 (initiator_stream_absent), the explicit-close path opened the
    // connection at 18:42:01.529 — five seconds too late.
    void (async () => {
      let sealBrokerConn: { stop: (reason: string) => Promise<void> } | null = null;
      try {
        sealBrokerConn = (await this.#ensureSealBroker?.(agentName, sessionId)) ?? null;
      } catch (err: unknown) {
        // Best-effort: a same-node session needs no visiting connection, and a failure here must not
        // suppress the seal leaf — losing the leaf is strictly worse than racing the push.
        this.#logger.warn("session.seal.autoack.broker.failed", {
          sessionId,
          correlationId,
          reason: err instanceof Error ? err.message : String(err),
        });
      }
      const submitted = await this.submitSealLeaf(agentName, sessionId, correlationId);
      // RELEASE AFTER A GRACE WINDOW, not when the submit resolves.
      //
      // `submitSealLeaf` settles at the relay ack plus a local root computation — milliseconds — while
      // the frame this connection exists to catch arrives ~60ms LATER (the timeline in the comment
      // above is the measurement). Releasing on submit therefore closed the stream before the push it
      // was opened for, which is the stall it was written to prevent.
      //
      // It is worse than a lost race. The directory drains its DURABLE notification queue on ANY
      // stream that authenticates — visiting included — and DELETES each row once sent. So a visiting
      // stream that authenticates and dies milliseconds later invites the directory to send-and-delete
      // queued seal frames into a closing stream: the receipt is gone from the queue and never
      // arrived. That is permanent loss, not a retry.
      //
      // The close path holds its connection around the entire bilateral wait; this path has no waiter
      // to hang off, so it uses a bounded grace instead — generous against a ~60ms push, and bounded
      // so a stalled seal cannot leak the connection. Unref'd: it must never hold the process open.
      if (sealBrokerConn) {
        const conn = sealBrokerConn;
        const t = setTimeout(() => { void conn.stop("autoack-seal-grace-elapsed").catch(() => {}); }, AUTOACK_BROKER_GRACE_MS);
        t.unref?.();
      }
      return submitted;
    })()
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
  async ingestReceivedContent(
    agentName: string,
    sessionId: string,
    content: Uint8Array,
    contentHash: Uint8Array,
    correlationId?: string,
    /**
     * DOD-FRONTIER-STRAND-1 AC1: the relay-assigned canonical position for THIS message, taken from
     * the verified ordering record by the caller. Passed EXPLICITLY rather than recovered from
     * `#witnessedSeq`, because that map is keyed by content hash — so two byte-identical messages
     * collapse in it before dedup is ever consulted, which is the whole defect. Absent when the
     * session has no relay witness (relay-degraded): see the announced fallback below.
     */
    canonicalSeqIn?: number,
  ): Promise<{ ok: true; leafIndex: number; sequenceNumber: number; held?: boolean; appendedCount?: number; screenedOut?: boolean } | { ok: false; reason: string }> {
    // The transcript is frozen ONLY once it is COMMITTED + signed — 'sealed' or
    // 'seal_interrupted_pending' (the bilateral seal commitment) — because a later FROST
    // notarization attests that exact root; a late leaf would diverge from it.
    //
    // MSG-001-3b recovery: a merely 'interrupted' session is NOT yet committed. The
    // counterparty's last message(s) may have been parked while this party was offline, so its
    // local transcript is INCOMPLETE (not frozen-final). Recovering that parked content COMPLETES
    // the local view to match the counterparty BEFORE the bilateral seal — it is not a resumption
    // (no new activity, no re-accept) and its root was never committed. So allow 'active' AND
    // 'interrupted'; reject only the two committed states.
    const record = this.getSessionRecord(agentName, sessionId);
    // DOD-UNREAD-1 D4a: NEVER record content you cannot attribute. With no sessions row there is
    // no counterparty — the transcript has no counterparty column, so a row written here is
    // unattributable forever, counted unread by getUnreadSummary, and unreadable by cello_receive
    // (the phantom-session residue). The old "(No DB row = test-only path, allowed.)" fallback
    // papered that in with senderPubkey="unknown". Refuse loudly instead; the content stays
    // un-acked, so a live sender redelivers once the session actually exists. After D3
    // (DOD-INBOUND-GUARD-1) this path is unreachable from the wire — a fail-loud assertion.
    if (!record) {
      this.#logger.warn("session.content.orphaned", { agentName, sessionId, correlationId });
      return { ok: false, reason: "session_orphaned" };
    }
    // DOD-TERMINAL-WAKE-1 (review F1): `abandoned` belongs here too. It is terminal and, unlike
    // `interrupted`, can NEVER complete — there is nothing left to append to and no seal to join.
    // Without it, late content for a force-abandoned session was accepted: a leaf was written, the
    // `cello_message` doorbell rang, the away-response and Telegram doorbell fired, and
    // `cello_receive` handed it over as live work. That is the same "agent obeys a directive out of
    // a conversation that has ended" harm as the sealed case, reached with no restart at all.
    //
    // `currentStatus` carries the real status onward: the content-park disposition and the operator
    // must be able to tell an abandoned session from a sealed one, and `session_committed` alone is
    // the exit point, not the cause.
    if (
      record.status === "sealed" ||
      record.status === "seal_interrupted_pending" ||
      record.status === "abandoned"
    ) {
      this.#logger.warn("session.content.cross_check.failed", {
        sessionId,
        reason: "session_committed",
        currentStatus: record.status,
        correlationId,
      });
      return { ok: false, reason: "session_committed" };
    }

    const computed = wireContentHash(content);
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
    const senderPubkey = entry?.counterpartyPubkey ?? record.counterparty_pubkey;
    if (!senderPubkey) {
      // DOD-UNREAD-1 D4a (AC4, supersedes the MSGWAKE-1 F1 paper-in): the schema requires
      // counterparty_pubkey NOT NULL, so this is unreachable unless a row was hand-crafted empty.
      // Either way, "unknown" is never written to a transcript row — refuse instead.
      this.#logger.warn("session.content.sender_unresolved", { sessionId, agentName, correlationId });
      return { ok: false, reason: "sender_unresolved" };
    }

    // DOD-MSG-5: a content_hash satisfies AT MOST ONE Merkle leaf, exactly once. If this hash is
    // already a leaf in the tree — it arrived BOTH directly and via the relay-park backstop, or it
    // is a replay — do NOT append a second leaf and do NOT double-count it. The recipient already
    // holds this message at its assigned sequence. (In the normal single-delivery case this find is
    // -1, so the live/recover append paths are unchanged.)
    // ─── DOD-FRONTIER-STRAND-1 AC1: the discriminator is the POSITION, not the content ───
    //
    // The old rule ("a content_hash satisfies AT MOST ONE Merkle leaf") is false whenever two
    // genuinely distinct messages match byte-for-byte — and two instances of the same model,
    // answering the same message with similar context, collide far more readily than humans do.
    // That is what stranded session dbb93dfc... for a week: an away responder fired twice with
    // identical text, the sender appended both, the receiver dropped the second as a "redelivery",
    // and the two frontiers disagreed forever. No receipt was ever possible.
    //
    // The relay already assigns every submission a unique position: a REDELIVERY carries the same
    // position, a genuinely new identical message carries a NEW one. So a duplicate is the same
    // hash AT THE SAME POSITION -- never the same hash anywhere.
    const tree = this.getSessionTree(agentName, sessionId);
    let existingIdx: number;
    if (canonicalSeqIn !== undefined && canonicalSeqIn >= 0 && tree.hashAt(canonicalSeqIn) === contentHashHex) {
      // The relay position holds exactly this content: a redelivery.
      existingIdx = canonicalSeqIn;
    } else if (canonicalSeqIn !== undefined && canonicalSeqIn >= 0 && canonicalSeqIn >= tree.size()) {
      // The position is at or beyond the frontier, so it cannot be a leaf we already hold. A
      // genuinely new message — including one byte-identical to an earlier leaf, which is the whole
      // point of AC1.
      existingIdx = -1;
    } else if (canonicalSeqIn !== undefined && canonicalSeqIn >= 0) {
      // ─── POSITION DRIFT (review F2, a regression this fix introduced and this branch repairs) ───
      //
      // `canonicalSeqIn < tree.size()` yet that slot holds different content, so **leaf index is no
      // longer the relay position** and the position cannot be used as an index into the tree. That
      // is §7a's drift: a first message whose relay submit failed is appended locally and never
      // counted by the relay, leaving the local record permanently one ahead.
      //
      // Using the position as an index here made a TRUE REDELIVERY append a second leaf — measured:
      // tree size 3 where the pre-fix code correctly gave 2. That is the "too permissive" direction,
      // and it inflates this side's tree against the counterparty's: the strand, from the other end.
      //
      // So under drift, fall back to the content-hash rule. It is weaker — it still cannot tell two
      // identical messages apart — but it is CORRECT about redelivery, which is the failure actually
      // reachable here, and it is exactly the pre-existing behavior, so this is not a regression in
      // either direction. Loudly announced, because the ambiguity is real and the drift is the thing
      // that should be fixed (DOD-FIRSTMSG-WITNESS-1 closes the producer).
      existingIdx = tree.indexOfHash(contentHashHex);
      // Announce only when the fallback actually DECIDED something (it found a duplicate). When it
      // finds nothing the message simply appends, `session.content.sequence_behind_tree` already
      // reports the drift itself, and a second warn on every message of a drifted session would
      // bury the case that matters. A signal that fires on the normal case is not a signal.
      if (existingIdx >= 0) this.#logger.warn("session.content.dedup.position_drifted", {
        sessionId,
        agentName,
        contentHashHex,
        canonicalSeq: canonicalSeqIn,
        treeSize: tree.size(),
        dedupedAt: existingIdx,
        reason: "leaf_index_is_not_relay_position_fell_back_to_content_hash",
        correlationId,
      });
    } else {
      // RELAY-DEGRADED: no witness, so no discriminator exists and the content-hash rule is all
      // there is. Keeping it preserves today's protection against real redelivery and today's blind
      // spot for identical messages -- the strand can still form on this path. Section 5a permits
      // proceeding rather than refusing (losing content is worse than mis-ordering it), but only
      // ANNOUNCED: a silent fallback is exactly how this went a week unnoticed. Fires only when the
      // hash actually matches, so it marks a real decision rather than every unwitnessed message.
      existingIdx = tree.indexOfHash(contentHashHex);
      // Gated exactly as its sibling `session.content.unwitnessed` is (see :3933): a session with NO
      // RELAY ATTACHED has no witness BY DESIGN, so warning there would fire on every message of a
      // normal no-relay session and bury the case that means something. A signal that fires on the
      // normal case is not a signal. The reason distinguishes the two shapes rather than asserting
      // the relay is absent — the position can also be missing because this particular frame carried
      // no ordering record while the relay is perfectly healthy.
      if (existingIdx >= 0 && this.#activeNodes.get(this.#k(agentName, sessionId))?.relayClient) {
        this.#logger.warn("session.content.dedup.unwitnessed", {
          sessionId,
          agentName,
          contentHashHex,
          sequenceNumber: existingIdx,
          reason: "no_ordering_record_deduped_on_content_hash",
          correlationId,
        });
      }
    }
    if (existingIdx >= 0) {
      this.#logger.info("session.content.deduplicated", {
        sessionId,
        contentHashHex,
        sequenceNumber: existingIdx,
        witnessed: canonicalSeqIn !== undefined,
        correlationId,
      });
      // appendedCount 0 — a dedup appends NO new leaf, so a recover that re-pulls an already-ingested
      // entry (e.g. after auto-recover already drained it) must not count it as a fresh recovery.
      return { ok: true, leafIndex: existingIdx, sequenceNumber: existingIdx, appendedCount: 0 };
    }

    // M8C-ABUSE-1 (reviewer HIGH fix, D18): per-session total-size cap (anti-drip-feed) —
    // "whitelisted senders bounded only by disk" (DoD), so a known contact is exempt entirely.
    // MUST run BEFORE the hold-branch below — the original placement (after it) let a
    // non-contact sender drip-feed unbounded bytes by making every message arrive "out of order"
    // relative to the relay witness (held content skipped the cap entirely, then #releaseHeld
    // appended it later with no re-check). Accounts for bytes already committed AND bytes
    // currently sitting in the hold buffer (multiple held chunks could otherwise each individually
    // pass the check while cumulatively exceeding it once released). Runs BEFORE the M9 screening
    // seam below (cheap + synchronous — fail fast on volume before spending gateway compute on
    // content headed for rejection anyway); both gates are independent and either rejects on its
    // own criteria, so ordering between them does not change correctness.
    {
      // DOD-TIER-2 AC2: the per-session byte cap is the sender's TIER cap (DEFAULT_TIER_BOUNDS),
      // applied to EVERY sender — no tier is unbounded (INV-TIER-BOUND), so a contact is no longer
      // "exempt entirely". A stranger (no row → UNKNOWN) keeps the 25 MB cap; KNOWN+ get more.
      const senderTier = this.getTier(agentName, senderPubkey);
      const cap = this.resolveTierBound(agentName, senderTier, "max_bytes");
      const priorTotal = this.#getReceivedBytesTotal(agentName, sessionId);
      const heldTotal = this.#getHeldBytesTotal(agentName, sessionId);
      if (priorTotal + heldTotal + content.length > cap) {
        this.#logger.warn("session.content.abuse_bound.session_size_exceeded", {
          sessionId,
          agentName,
          senderPubkey,
          priorTotal,
          heldTotal,
          incoming: content.length,
          cap,
          tier: senderTier,
          correlationId,
        });
        return { ok: false, reason: "session_size_limit_exceeded" };
      }
    }

    // M9-CORE-001: the inbound screening seam (INV-5). Screen here — after the content is proven
    // authentic (hash cross-check) and confirmed not a duplicate, before it is either held for
    // ordering or appended to the agent-facing buffer. This is the SINGLE inbound funnel: direct
    // arrivals, recovered/parked content (daemon recover → here), and held-then-released content
    // (held below, screened now, released already-screened) all pass this point. A non-allow
    // verdict means the content is NOT delivered to the agent: it is not held, not buffered, and
    // no leaf is appended — the message stays un-acked so the sender's TTF/park/retry redelivers
    // it once the gateway is reachable again (DB-001 fail-closed: hold, never expose ungated).
    const inboundVerdict = await this.#securityGateway.screenInbound(content, {
      direction: "inbound",
      agentName,
      sessionId,
      correlationId,
    });
    // M9 terminal-vs-transient split. A TERMINAL block (inboundVerdict.terminal) is a detector
    // rejecting the CONTENT itself — a confident non-allowlisted language (IN-003), a high-score
    // injection (IN-002), or an oversized payload (IN-001). The identical bytes would be rejected
    // identically on redelivery, so holding them un-acked would loop the sender forever. Instead a
    // terminal block is `screenedOut`: it records a leaf binding the ORIGINAL content hash and is
    // acknowledged (the sender stops), but is NEVER buffered for the agent (cello_receive never sees
    // it). The leaf is REQUIRED, not cosmetic: the sender appended this leaf at its CANONICAL position
    // on send, so a terminal block must take the SAME strict-in-order path as a delivered message —
    // record the leaf at its canonical index, not in arrival order — or the two parties' hash chains
    // diverge by POSITION and the bilateral seal cross-check mismatches (code-review HIGH-1). The only
    // difference from a normal message is that it leafs WITHOUT buffering. A TRANSIENT block (a
    // fail-closed gateway_unavailable / governance_timeout) records nothing and is not acked.
    const terminalBlock = inboundVerdict.disposition === "block" && inboundVerdict.terminal === true;
    if (inboundVerdict.disposition !== "allow" && inboundVerdict.disposition !== "redact" && !terminalBlock) {
      // TRANSIENT block / warn HOLD (do not deliver, do not leaf, do not ack). The message stays
      // un-acked so the sender's TTF/park/retry redelivers and re-screens it once the gateway recovers.
      // (If we committed a leaf, dedup would later swallow the redelivery and the agent would never
      // receive it.)
      if (inboundVerdict.reason === GOVERNANCE_TIMEOUT) {
        this.#logger.error("security.gateway.timeout", {
          sessionId,
          reason: inboundVerdict.reason,
          correlationId,
        });
      } else if (inboundVerdict.reason === GATEWAY_UNAVAILABLE) {
        this.#logger.error("security.gateway.unavailable", {
          direction: "inbound",
          reason: inboundVerdict.reason,
          correlationId,
        });
      } else {
        this.#logger.warn("security.gateway.inbound.blocked", {
          sessionId,
          disposition: inboundVerdict.disposition,
          reason: inboundVerdict.reason,
          correlationId,
        });
      }
      return { ok: false, reason: inboundVerdict.reason ?? "inbound_screen_blocked" };
    }
    if (terminalBlock) {
      this.#logger.warn("security.gateway.inbound.terminal_block", {
        sessionId,
        disposition: inboundVerdict.disposition,
        reason: inboundVerdict.reason,
        correlationId,
      });
    }

    // M9-IN-001: a `redact` verdict (inbound sanitization) DELIVERS the sanitized text to the agent,
    // while the Merkle leaf still binds the ORIGINAL content hash below — the transcript records what
    // the peer actually sent; the agent sees the sanitized form. `allow` leaves the content unchanged.
    // A terminal block carries the original bytes here only so its leaf binds the right hash; it is
    // never delivered (the screenedOut flag below routes it to a leaf-without-buffer).
    const deliverContent = inboundVerdict.disposition === "redact" && inboundVerdict.content !== undefined
      ? inboundVerdict.content
      : content;

    // screenInbound above is the ONLY suspension point in this method, and it splits the dedup check
    // (indexOfHash, above) from the leaf append (below). Across that await, two concurrent ingests of
    // the SAME content hash — e.g. a direct retry and a park-recovery racing on reconnect — can BOTH
    // pass the first dedup check before either appends, producing two leaves for one hash
    // (DOD-MSG-5 break → leafIndex≠canonicalSeq → root divergence). So re-check dedup on resume.
    // Everything from here to the append is synchronous (atomic under Node's single thread): the
    // first to resume appends, and the second sees its leaf and dedups.
    //
    // Adding any further await between here and the append reopens the window.
    // DOD-FRONTIER-STRAND-1 AC1: this re-check must use the SAME discriminator as the first one.
    // Left keyed on the content hash it silently re-created the whole defect one branch later --
    // the pre-screen check would correctly let a second identical-but-distinct message through, and
    // then this one would drop it anyway. The race it exists to close is unaffected: two concurrent
    // ingests of a true redelivery share a position, so the second still sees the first's leaf.
    const treeAfterScreen = this.getSessionTree(agentName, sessionId);
    const dedupAfterScreen = canonicalSeqIn !== undefined && canonicalSeqIn >= 0
      ? (treeAfterScreen.hashAt(canonicalSeqIn) === contentHashHex ? canonicalSeqIn : -1)
      : treeAfterScreen.indexOfHash(contentHashHex);
    if (dedupAfterScreen >= 0) {
      this.#logger.info("session.content.deduplicated", {
        sessionId,
        contentHashHex,
        sequenceNumber: dedupAfterScreen,
        witnessed: canonicalSeqIn !== undefined,
        phase: "post_screen",
        correlationId,
      });
      return { ok: true, leafIndex: dedupAfterScreen, sequenceNumber: dedupAfterScreen, appendedCount: 0, ...(terminalBlock ? { screenedOut: true } : {}) };
    }

    // M8C-ABUSE-1 (cello-unit-reviewer HIGH fix, post-M9INT-1 merge): re-check the size cap here,
    // in the SAME synchronous window as the dedup re-check above. The original check (before the
    // screenInbound await) used totals that can go stale: two concurrent ingests for the same
    // non-contact session — e.g. a live direct arrival racing a recoverParkedFromRelay pull —
    // could each independently pass the pre-await check using the SAME stale totals, then both
    // append/hold, jointly exceeding the cap. Symmetric to the dedup fix: everything from here to
    // the append/hold branch is synchronous, so whichever call resumes first appends/holds before
    // the second's re-check runs, and the second's freshly-recomputed totals correctly include the
    // first's contribution.
    {
      // DOD-TIER-2 AC2 (re-check): the SAME tier cap as the primary gate above, recomputed in this
      // synchronous window (the totals can go stale across the screenInbound await). Applied to EVERY
      // sender — a contact is no longer exempt (INV-TIER-BOUND). Must mirror the primary gate exactly
      // so a sender can never pass one and fail the other.
      const senderTier = this.getTier(agentName, senderPubkey);
      const cap = this.resolveTierBound(agentName, senderTier, "max_bytes");
      const priorTotal = this.#getReceivedBytesTotal(agentName, sessionId);
      const heldTotal = this.#getHeldBytesTotal(agentName, sessionId);
      if (priorTotal + heldTotal + content.length > cap) {
        this.#logger.warn("session.content.abuse_bound.session_size_exceeded", {
          sessionId,
          agentName,
          senderPubkey,
          priorTotal,
          heldTotal,
          incoming: content.length,
          cap,
          tier: senderTier,
          correlationId,
          recheck: true,
        });
        return { ok: false, reason: "session_size_limit_exceeded" };
      }
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
    // Prefer the position the CALLER verified for this specific message over the hash-keyed map.
    // The map cannot distinguish two identical messages (AC1) -- it holds one entry per hash, so the
    // second firing overwrites the first's position. The explicit value is per-message and correct;
    // the map remains the fallback for paths that have no ordering record.
    const canonicalSeq = canonicalSeqIn !== undefined && canonicalSeqIn >= 0
      ? canonicalSeqIn
      : this.#witnessedSeq.get(key)?.get(contentHashHex);
    const nextExpected = this.getSessionTree(agentName, sessionId).size();
    if (canonicalSeq !== undefined && canonicalSeq > nextExpected) {
      let held = this.#heldContent.get(key);
      if (!held) { held = new Map(); this.#heldContent.set(key, held); }
      // A terminal block out of canonical order is held WITHOUT delivery (screenedOut): #releaseHeld
      // leafs it at its canonical index when the gap fills, but never buffers it for the agent. This
      // keeps leafIndex === canonicalSeq for screened-out content too (code-review HIGH-1).
      // THE PEER'S RAW BYTES RIDE ALONG. Classification (document frame vs conversation) reads
      // byte 0, and `deliverContent` is the SCREENED copy — for a CBOR frame that is no longer a
      // map header, so a held document frame was released into the CONVERSATION path: transcript,
      // doorbell, and `cello_receive` handing an agent raw CBOR as though a person typed it.
      // The in-order path has always passed these bytes; only the held path dropped them.
      held.set(canonicalSeq, { content: deliverContent, originalContent: content, contentHashHex, correlationId, ...(terminalBlock ? { screenedOut: true } : {}) });
      this.#logger.info("session.content.held", {
        sessionId,
        canonicalSeq,
        nextExpected,
        gap: canonicalSeq - nextExpected,
        screenedOut: terminalBlock,
        correlationId,
      });
      // Held content is NOT yet a durable leaf, so it is deliberately NOT acknowledged `persisted`
      // (the caller checks `held`). The sender's TTF→park backstop and the recover/dedup path
      // guarantee eventual delivery; B never claims persisted for content it only holds in memory.
      return { ok: true, leafIndex: canonicalSeq, sequenceNumber: canonicalSeq, held: true, ...(terminalBlock ? { screenedOut: true } : {}) };
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

    // In-order append. A terminal block leafs the ORIGINAL content hash WITHOUT buffering it for the
    // agent (screenedOut); a delivered message buffers + leafs via #appendVerifiedContent.
    const leafIndex = terminalBlock
      ? this.appendSessionLeaf(agentName, sessionId, "msg", contentHashHex, correlationId).leafIndex
      : this.#appendVerifiedContent(agentName, sessionId, deliverContent, contentHashHex, senderPubkey, correlationId, content).leafIndex;

    // DOD-COATTEND-1 (review F2): the plaintext failed to reach the transcript, and since Tier 1 the
    // transcript IS the delivery path — so this message can never be handed to any session. Report
    // the ingest as failed. Reporting `ok: true` here is what let a local SQLCipher failure surface,
    // 30 seconds later and one subsystem away, as "no content arrived — keep waiting": the operator
    // is sent to debug a counterparty who did nothing wrong.
    //
    // The leaf STAYS. It is genuinely committed to the hash chain, and unwinding a committed leaf to
    // tidy up a reporting problem would corrupt the frontier the counterparty already co-signs
    // against. The hole is now crossable by delivery (F1), so it costs a gap, not a stall.
    if (!terminalBlock && this.getUndeliverableSeqs(agentName, sessionId).includes(leafIndex)) {
      return { ok: false, reason: "transcript_write_failed" };
    }

    // NO relay witness for this hash. We appended it anyway — refusing would make the relay a hard
    // precondition for reading mail, so a relay outage would render the inbox unreadable, and the
    // direct path and park backstop exist precisely to survive that. But this append is a WEAKER
    // guarantee and must not masquerade as the stronger one: with a witness, the received content is
    // checked against a hash the sender committed to a third party; without one, the only available
    // hash rode in the same frame as the content, so the check is the sender's claim against the
    // sender's own claim. Say so. A sender who simply never submits to the relay is otherwise
    // indistinguishable from one the relay merely has not witnessed YET.
    // The relay witness is an INDEPENDENT attestation: a (content_hash → sequence) binding derived
    // from the sender's own signed leaf. Holding one, we check received content against a hash the
    // sender committed to a THIRD PARTY. Holding none, the only hash available rode in the same frame
    // as the content — the sender's claim checked against the sender's claim.
    //
    // Unwitnessed content is still ingested. Refusing it would make the relay a precondition for
    // READING mail, so a relay outage would render the inbox unreadable — the redundancy the direct
    // path and the park backstop exist to provide.
    //
    // Warn ONLY when a witness was EXPECTED. A session with no relay attached has no witness BY
    // DESIGN, and warning on every message there would bury the one case that means something —
    // a relay IS attached, so the sender's leaf should have been submitted and witnessed, and it
    // was not. A signal that fires on the normal case is not a signal.
    if (canonicalSeq === undefined && this.#activeNodes.get(key)?.relayClient) {
      this.#logger.warn("session.content.unwitnessed", {
        agentName,
        sessionId,
        leafIndex,
        contentHash: contentHashHex,
        correlationId,
        guidance: "a relay is attached to this session but no witness bound this content hash — it was ingested with no independent commitment from the sender",
      });
    }
    // A just-appended leaf may unblock held out-of-order arrivals whose turn is now next.
    // appendedCount = this leaf + any held leaves released by it, so a caller (recover) can tally the
    // leaves ACTUALLY written, not just the directly-ingested one (review #3).
    const released = this.#releaseHeld(agentName, sessionId, senderPubkey);
    return { ok: true, leafIndex, sequenceNumber: leafIndex, appendedCount: 1 + released, ...(terminalBlock ? { screenedOut: true } : {}) };
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
   * or -1 if none. The relay is the ordering authority, so this is the outside view of how far the
   * session has actually progressed — which is why it is the right input to a catch-up-before-live
   * gate. Consumed by `sealReadiness` (M12-P14) for REPORTING only: the missing-leaf decision is made
   * from `#witnessedSeq`, because this counts the relay's sequence space (which includes ctrl leaves)
   * and the tree does not. Maintained by `recordWitnessedSequence`.
   */
  /**
   * DOD-COATTEND-1 (review F2): leaf sequences whose plaintext failed to reach the transcript and
   * are therefore undeliverable. Empty is the overwhelmingly normal case.
   */
  getUndeliverableSeqs(agentName: string, sessionId: string): readonly number[] {
    return [...(this.#undeliverableSeqs.get(this.#k(agentName, sessionId)) ?? [])];
  }

  getHighWaterSeq(agentName: string, sessionId: string): number {
    return this.#highWaterSeq.get(this.#k(agentName, sessionId)) ?? -1;
  }

  /**
   * M12-P14: is this side's chain COMPLETE enough to be sealed?
   *
   * A seal is a bilateral signature over the same conversation, so a side that is missing a leaf
   * cannot produce a signable one — the counterparty compares frontiers and refuses with
   * `leaf_count_mismatch`. That refusal is correct and it is also terminal: there is no backfill
   * request in the protocol, so the only exit is a force-abandon, which yields NO notarized receipt.
   * Measured 2026-08-05 on two sessions that died exactly this way (initiator 2 leaves, responder 3).
   *
   * The cheap prevention is to notice BEFORE asking. Two local signals already exist and, until now,
   * nothing read either of them at close time:
   *  - `#highWaterSeq` — the largest canonical sequence the RELAY has witnessed for this session.
   *    The relay is the ordering authority, so a high-water above our own frontier is proof that a
   *    leaf exists which we have not appended. (Its own doc comment called it "reserved … NOT yet
   *    consumed by the gate" — this is that consumer.)
   *  - `#heldContent` — content we HAVE received and verified but cannot append because it sits
   *    behind a gap. Holding content and sealing anyway would seal a chain we know is short.
   *
   * Deliberately NOT a network call: it must work when the counterparty is unreachable, which is
   * the whole situation a seal-interrupted exists for.
   *
   * KNOWN LIMIT, stated rather than hidden: both maps are in-memory and cleared on teardown, so
   * after a daemon restart this returns ready for a session whose gap predates the restart — which
   * is the shape of the 2026-08-05 incident itself. Closing that needs the mailbox drained (or the
   * high-water persisted) before the check; tracked with M12-P14, not claimed here.
   */
  sealReadiness(agentName: string, sessionId: string): {
    ready: boolean; treeSize: number; highWaterSeq: number; heldCount: number; missingLeaves: number;
  } {
    const key = this.#k(agentName, sessionId);
    const treeSize = this.getSessionTree(agentName, sessionId).size();
    const highWaterSeq = this.#highWaterSeq.get(key) ?? -1;
    const heldCount = this.#heldContent.get(key)?.size ?? 0;
    // Review HIGH-2: NOT `(highWaterSeq + 1) - treeSize`. That subtraction silently assumes the
    // relay's sequence space and this tree's index space count the same things, and they do not:
    // `relay-node.ts` increments seq_counter for EVERY accepted leaf including CTRL (0x02), while
    // `appendSessionLeaf` is only ever called with "msg" — `submitSealLeaf` deliberately computes
    // its root without mutating the durable tree. So one seal ctrl leaf offsets the two spaces
    // permanently, and any msg witnessed afterwards would read as a missing leaf FOREVER. That is a
    // false positive, and a false positive here is worse than the bug it guards: it makes a healthy
    // session unsealable, leaving force-abandon (no receipt) as the only exit. `seal-upgrade.ts`
    // already documents the same `leaf_count - 1` offset.
    //
    // `#witnessedSeq` answers the question directly instead of inferring it. It gains an entry when
    // the relay witnesses a COUNTERPARTY msg leaf (ctrl leaves are excluded at the call site) and
    // loses it the moment that leaf is appended. So its remaining size IS the count of leaves the
    // ordering authority has committed and this tree has not — no arithmetic, no space mismatch,
    // and it cannot go negative.
    const missingLeaves = this.#witnessedSeq.get(key)?.size ?? 0;
    return { ready: missingLeaves === 0 && heldCount === 0, treeSize, highWaterSeq, heldCount, missingLeaves };
  }

  /** DOD-MSG-4 / DAEMON-004: append a verified message leaf and buffer it for cello_receive. */
  #appendVerifiedContent(
    agentName: string,
    sessionId: string,
    content: Uint8Array,
    contentHashHex: string,
    senderPubkey: string,
    correlationId?: string,
    /**
     * The bytes as the PEER SENT THEM, before inbound sanitization — for the document classifier
     * only. Defaults to `content` for callers that never screened (the held-release path).
     *
     * A `redact` verdict rewrites `content` for the agent's benefit, and that is right for
     * conversation: the operator sees the sanitized form while the leaf still binds the original.
     * It is WRONG for a document frame, and not marginally. Rewriting bytes inside a signed CBOR
     * envelope does not sanitize it — it destroys it. The frame stops decoding, stops being
     * recognised as document traffic at all, and falls through to the conversation path, where it
     * is recorded as something a person said and handed to the agent by `cello_receive`.
     *
     * Measured live: roughly half of proposals vanished this way. Intermittent because a proposal
     * carries a random 16-byte nonce, so whether its bytes trip a sanitizer rule varies per run —
     * which is why it read as flakiness rather than as a rule firing.
     *
     * Documents are NOT unscreened as a result. They are screened by `DocumentGate`, which is built
     * for them and REFUSES rather than mutates (§16.7) — because mutating one party's replica of a
     * CRDT is not a false positive, it is permanent divergence that both sides converge on and
     * neither can see.
     */
    originalContent?: Uint8Array,
  ): { leafIndex: number } {
    // M14 / DOD-DOC-INBOUND-2 — DOCUMENT FRAMES DIVERGE HERE, and the three-way split is the whole
    // contract:
    //
    //   LEAF   yes, and as `doc` (0x04) rather than `msg` (0x00). The seal covers document traffic
    //          — that is what makes the exchange provable — but it is not conversation, and the
    //          leaf kind is what a verifier renders it by.
    //   TRANSCRIPT no. Recording CRDT bytes as a received message puts them in the operator's
    //          conversation history, where `cello_receive` hands them to an agent as something a
    //          person said.
    //   DOORBELL no (§11.3). A collaborator typing produces a stream of updates; a doorbell each
    //          time would interrupt the operator's agent continuously for something with no
    //          deadline.
    //
    // The hook is injected and absent by default, so a daemon without the document layer behaves
    // exactly as before — this cannot change the conversation path by being unwired.
    const routed = this.#onDocumentFrame?.(
      agentName,
      sessionId,
      // THE PEER'S BYTES, not the sanitized ones. See `originalContent` above.
      originalContent ?? content,
      senderPubkey,
      correlationId,
    );
    if (routed?.consumed === true) {
      const { leafIndex } = this.appendSessionLeaf(agentName, sessionId, "doc", contentHashHex, correlationId);
      // DROP THE WITNESS, exactly as the conversation branch does once its leaf is appended. The
      // witness has done its ordering job either way — the leaf IS committed here.
      //
      // This branch returns early and so never reached that cleanup, and every inbound document
      // frame left a permanent entry behind. Harmless until `sealReadiness` started deriving
      // `missingLeaves` from the size of that map (M12-P14): from then on a session that carried
      // ANY document traffic could never seal, because the ordering authority was recorded as
      // having committed leaves this tree had — but had not been credited with. The refusal is
      // `session_incomplete`, whose only escape is a force-abandon with no notarized receipt.
      //
      // Two correct changes, each fine alone, that break where they meet. Caught by running the
      // live enforcers straight after merging main rather than trusting a green unit suite.
      this.#witnessedSeq.get(this.#k(agentName, sessionId))?.delete(contentHashHex);
      this.#logger.info("session.document.received", {
        sessionId,
        senderPubkey,
        contentHashHex,
        sequenceNumber: leafIndex,
        kind: routed.kind,
        ok: routed.ok,
        reason: routed.reason,
        correlationId,
      });
      return { leafIndex };
    }

    const { leafIndex } = this.appendSessionLeaf(agentName, sessionId, "msg", contentHashHex, correlationId);
    // DOD-LOG-1: persist the readable RECEIVED plaintext to the durable transcript, keyed by the
    // canonical leaf sequence so it joins the committed hash chain (survives restart; INV-3 — the
    // relay/directory never see this plaintext, only the hash).
    const durable = this.recordTranscriptMessage(agentName, sessionId, leafIndex, "received", content, correlationId);
    const recvKey = this.#k(agentName, sessionId);
    if (!durable) {
      // The leaf is committed and the plaintext is not. Delivery reads the transcript, so this
      // message is now unreachable by every session — record it so the receive path can SAY that
      // rather than time out wearing the quiet-counterparty answer (review F2).
      let lost = this.#undeliverableSeqs.get(recvKey);
      if (!lost) { lost = new Set(); this.#undeliverableSeqs.set(recvKey, lost); }
      lost.add(leafIndex);
    }
    // Review finding #6: the witness for this hash has done its ordering job once the leaf is
    // appended — drop it so #witnessedSeq stays proportional to held/pending content, not the whole
    // transcript. A later replay of the same hash is still caught by the dedup leaf-scan, which is
    // independent of the witness map.
    this.#witnessedSeq.get(recvKey)?.delete(contentHashHex);
    let buf = this.#receivedContent.get(recvKey);
    if (!buf) { buf = []; this.#receivedContent.set(recvKey, buf); }
    buf.push({ contentHex: Buffer.from(content).toString("hex"), senderPubkey, sequenceNumber: leafIndex });
    // DOD-COATTEND-1: BOUNDED, because delivery no longer drains this. Its remaining job is
    // `peekLatestReceivedContentHex` (M8C-AWAY-1 reads the TAIL to spot a [[WRAP]]), so only the
    // recent tail is load-bearing — but an unbounded array holding every message of every live
    // session, in memory, for the life of the daemon, is a leak the old destructive read hid.
    if (buf.length > RECEIVED_BUFFER_CAP) buf.splice(0, buf.length - RECEIVED_BUFFER_CAP);
    this.#logger.info("session.content.received", {
      sessionId,
      senderPubkey,
      contentHashHex,
      sequenceNumber: leafIndex,
      correlationId,
    });
    // M8C-MSGWAKE-1: content is now buffered and drainable — fire the doorbell AFTER the push so a
    // woken cello_receive finds the message. Content-free (agent/session/senderPubkey only). Never
    // let a listener error escape the content path.
    try {
      this.#onContentArrived?.(agentName, sessionId, senderPubkey);
    } catch (err: unknown) {
      this.#logger.warn("notification.cello_message.dispatch.failed", {
        sessionId, agentName, reason: err instanceof Error ? err.message : String(err),
      });
    }
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
      // A screened-out (terminal-blocked) held entry leafs at its canonical index but is NEVER
      // buffered for the agent; a normal held entry buffers + leafs (code-review HIGH-1).
      if (entry.screenedOut) {
        this.appendSessionLeaf(agentName, sessionId, "msg", entry.contentHashHex, entry.correlationId);
      } else {
        this.#appendVerifiedContent(agentName, sessionId, entry.content, entry.contentHashHex, senderPubkey, entry.correlationId, entry.originalContent);
      }
      released++;
      this.#logger.info("session.content.released", {
        sessionId,
        sequenceNumber: nextExpected,
        screenedOut: entry.screenedOut === true,
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

  /** DOD-AWAY-WRAP-1: peek at the hex of the most-recently buffered (last) received message without
   *  consuming it. Used by sendAwayResponse to detect [[WRAP]]-signalled messages and skip the away
   *  reply. Returning the last entry (not the first) is intentional — #appendVerifiedContent always
   *  pushes to the tail, so the tail is the message that just triggered onContentArrived. */
  peekLatestReceivedContentHex(agentName: string, sessionId: string): string | null {
    const buf = this.#receivedContent.get(this.#k(agentName, sessionId));
    if (!buf || buf.length === 0) return null;
    return buf[buf.length - 1]?.contentHex ?? null;
  }

  /**
   * TEST-ONLY (M8C-INBOX-1 reviewer F1): buffer a received message + persist its transcript row,
   * exactly as the real inbound path (#appendVerifiedContent) does, WITHOUT standing up a session
   * tree — so a test can drive a live cello_receive that advances the read watermark (the N3
   * "delivery marks read" coupling). Only reachable via the CELLO_ENV=test IPC hook.
   */
  /** CELLO_ENV=test only: patch a relay client and session-id bytes onto an existing active node entry
   *  so submitSealLeaf succeeds without a real relay handshake (used by the oneshot relay-path test). */
  patchRelayClientForTest(agentName: string, sessionId: string, relayClient: AgentRelayClient, relaySessionIdBytes: Uint8Array): void {
    const entry = this.#activeNodes.get(this.#k(agentName, sessionId));
    if (!entry) throw new Error(`patchRelayClientForTest: no active node for (${agentName}, ${sessionId})`);
    entry.relayClient = relayClient;
    entry.relaySessionIdBytes = relaySessionIdBytes;
  }

  pushReceivedContentForTest(agentName: string, sessionId: string, seq: number, content: string, senderPubkey: string): void {
    this.recordTranscriptMessage(agentName, sessionId, seq, "received", new TextEncoder().encode(content), "test");
    const key = this.#k(agentName, sessionId);
    let buf = this.#receivedContent.get(key);
    if (!buf) { buf = []; this.#receivedContent.set(key, buf); }
    buf.push({ contentHex: Buffer.from(content, "utf8").toString("hex"), senderPubkey, sequenceNumber: seq });
  }

  /**
   * F1-b: the terminal answer for a session that sealed while a blocking receive was (or could be)
   * waiting. Idempotent — a sealed session always answers "sealed" to a receive. Null while active.
   *
   * DOD-TERMINAL-WAKE-1: the in-memory marker is written only by `destroySessionNode`, so it does
   * NOT survive a restart — while the `sealed` row on disk does. Reading the absent marker as "not
   * terminal" is what let a sealed session's unread message come back as live work hours later, and
   * an agent obey a `[[STANDBY]]` directive out of a conversation that had already ended. Absent is
   * not fine: fall through to the durable record, which is the authority the marker only caches.
   */
  peekTerminalMarker(agentName: string, sessionId: string): { type: "sealed"; unreadCount: number } | null {
    const cached = this.#sessionTerminal.get(this.#k(agentName, sessionId));
    if (cached) return cached;
    // Only 'sealed' answers here. 'abandoned' forfeited its receipt and 'interrupted' /
    // 'seal_interrupted_pending' can still complete, so none of them may claim a seal — the
    // DOD-SEALED-INBOX-2 lesson, which is what makes this a status read and not a "is it over" read.
    const record = this.getSessionRecord(agentName, sessionId);
    if (record?.status !== "sealed") return null;
    return { type: "sealed", unreadCount: this.getUnreadReceivedCount(agentName, sessionId) };
  }

  /**
   * F1-b: the durable sealed root hex for a session (written by recordSealCertificate on the
   * bilateral path), or null if not recorded. Lets cello_receive echo the sealed root in its
   * terminal answer without threading it through destroySessionNode.
   */
  getSealedRootHex(agentName: string, sessionId: string): string | null {
    if (!this.#db) return null;
    const row = this.#db
      .prepare("SELECT sealed_root_hex FROM sessions WHERE agent_id = ? AND session_id = ?")
      .get(this.#requireAgentId(agentName), sessionId) as { sealed_root_hex?: string | null } | undefined;
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
      // M12-P12 (review pass 2): the ordering record travels on THIS path too. It is in hand — the
      // very next statement hands it to #parkContent — and a TTF row written without it re-parks in
      // arrival order, which is the divergent-leaf-index failure the durable columns exist to stop.
      this.#onAwaitingTtf?.(agentName, sessionId, hashHex, entry.content, entry.structure1Cbor, entry.structure2Cbor);
    } catch (err: unknown) {
      this.#logger.error("content.park.backstop.failed", {
        sessionId, contentHash: hashHex, error: err instanceof Error ? err.message : String(err),
      });
    }
    // 2b: delivered to the wire but never confirmed `persisted` — deposit it to the relay
    // store-and-forward so the recipient recovers it (at the witnessed sequence). The durable
    // awaiting entry above remains the crash backstop. Carry the retained ordering record (review #1)
    // so a TTF-parked entry self-orders on recover, exactly like the direct-dial-fail park.
    // Fire-and-forget: unlike sendContent's live caller, nothing here is awaiting an IPC response
    // to shape (the TTF timer fires long after cello_send already returned) — the deposit's own
    // success/failure logging inside #parkContent is the only observability this path needs.
    void this.#parkContent(agentName, sessionId, hashHex, entry.content, entry.structure1Cbor, entry.structure2Cbor);
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
      const frame = encodeCbor({
        type: "content_delivery_ack",
        session_id: sessionId,
        content_hash: contentHash,
        level: "persisted",
        correlation_id: correlationId,
      }) as Uint8Array;
      stream.send(lp.encode.single(frame));
      // The receiver-side counterpart to the sender's content.delivery.acked: B has acknowledged
      // this content `persisted`, so the sender stops retrying/parking. Emitted for BOTH a normally
      // delivered message AND a terminal-screen block (the block is a definitive receipt — the leaf
      // is recorded, so the sender must stop) — and deliberately NOT for a transient hold.
      this.#logger.info("content.delivery.ack.sent", {
        sessionId,
        contentHash: Buffer.from(contentHash).toString("hex"),
        correlationId,
      });
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
        "SELECT leaf_kind, leaf_hash_hex FROM session_tree_leaves WHERE agent_id = ? AND session_id = ? ORDER BY leaf_index ASC",
      )
      .all(this.#requireAgentId(agentName), sessionId) as Array<{ leaf_kind: string; leaf_hash_hex: string }>;
    return SessionTree.fromLeaves(
      rows.map((r, leafIndex) => {
        const kind = sessionTreeLeafKindFromDb(r.leaf_kind);
        if (kind === "unknown") {
          // A leaf kind written by a newer build. The tree stays intact and sealable (the
          // stored hash carries its own domain), but an operator must be able to see that
          // this daemon is behind the one that wrote the row.
          this.#logger.error("session.tree.leaf_kind.unrecognized", {
            agentName,
            sessionId,
            leafIndex,
            value: r.leaf_kind,
          });
        }
        return { kind, hashHex: r.leaf_hash_hex };
      }),
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
   * DOD-MSG-4 (2b) / SEC-1: decode a park envelope. Legacy/unsigned shapes still DECODE so that
   * `recoverParkedEntry` can refuse them BY NAME (`unsigned_envelope`) — decoding is not accepting.
   * Encoding lives in park-envelope.ts and REQUIRES a sender signature (see SEC-1); it is not
   * exposed here, so no caller can seal an unsigned envelope through this class.
   */
  decodeParkEnvelope(plaintext: Uint8Array): ParkEnvelope {
    return decodeParkEnvelope(plaintext);
  }

  /**
   * SEC-1 — THE ONLY WAY PARKED CONTENT ENTERS THE TRANSCRIPT.
   *
   * Authentication and ingest are FUSED here on purpose, and must stay fused. A caller cannot ingest
   * parked content without passing the signature gate, because this is the only entry point. Exposing
   * a separate `decode → ingest` path — with the signature check as its own optional step — is a
   * downgrade attack: an attacker omits the thing that triggers the check, and the check never runs.
   * A gate the caller can skip by leaving a field out is not a gate.
   *
   * FAILS CLOSED. No signature / bad signature / signer is not this session's counterparty / no
   * session at all → REFUSED, nothing is appended, nothing is written, and the caller MUST NOT
   * confirm-delete the entry from the relay (a forgery must not be able to evict itself, and a
   * genuine bug must not silently eat mail).
   */
  async recoverParkedEntry(
    agentName: string,
    sessionId: string,
    recipientPubkey: Uint8Array,
    unsealed: Uint8Array,
    contentHash: Uint8Array,
    correlationId?: string,
  ): Promise<
    | { ok: true; leafIndex: number; sequenceNumber: number; held?: boolean; appendedCount?: number; screenedOut?: boolean }
    | { ok: false; reason: string }
  > {
    const contentHashHex = Buffer.from(contentHash).toString("hex");

    // Review M4: a refused entry is deliberately NOT confirm-deleted (a forgery must not be able to
    // evict itself), which means an adversary could otherwise make us unseal + Ed25519-verify the
    // same forged entries on EVERY reconnect, forever — turning the mailbox into an amplification
    // vector against our own recover path. Remember what we already refused and skip the crypto on
    // re-pull. Still never confirmed, so nothing is destroyed. In-memory and BOUNDED: the cost of
    // forgetting across a restart is one more verify, which is exactly the pre-existing behavior.
    const refusalKey = `${this.#k(agentName, sessionId)}:${contentHashHex}`;
    const remembered = this.#refusedParkedEntries.get(refusalKey);
    if (remembered) {
      this.#logger.warn("content.recover.unauthenticated", {
        agentName,
        sessionId,
        contentHash: contentHashHex,
        reason: remembered,
        repeat: true,
        correlationId,
      });
      return { ok: false, reason: remembered };
    }

    const env = decodeParkEnvelope(unsealed);
    const verdict = authenticateParkedEntry({
      env,
      sessionIdHex: sessionId,
      recipientPubkey,
      contentHash,
      counterpartyPubkeyHex: this.getSessionRecord(agentName, sessionId)?.counterparty_pubkey,
    });

    if (!verdict.ok) {
      // SEC-1: loud, and specific about WHICH gate refused — a silent drop here would look
      // identical to "no mail", which is how an injection attempt would go unnoticed.
      this.#rememberRefusedParkedEntry(refusalKey, verdict.reason);
      this.#logger.warn("content.recover.unauthenticated", {
        agentName,
        sessionId,
        contentHash: contentHashHex,
        reason: verdict.reason,
        envelopeVersion: env.version,
        correlationId,
      });
      return { ok: false, reason: verdict.reason };
    }

    // Authenticated. The ordering record (when present) is still verified independently by
    // #recordFrameOrdering — it answers a different question (WHERE this message sits in the
    // canonical sequence, per the relay) and is still best-effort: a bad record must not block a
    // message whose AUTHORSHIP we have now proven.
    // DOD-FRONTIER-STRAND-1 AC1: keep the VERIFIED position and hand it to ingest, so dedup can
    // tell a redelivery (same position) from a genuinely new identical message (new position).
    let recoveredSeq: number | null = null;
    if (env.structure1Cbor && env.structure2Cbor) {
      recoveredSeq = this.recordOrderingRecord(agentName, sessionId, env.structure1Cbor, env.structure2Cbor, contentHash, correlationId);
    }

    this.#logger.info("content.recover.verified", {
      agentName,
      sessionId,
      contentHash: contentHashHex,
      correlationId,
    });

    return await this.ingestReceivedContent(agentName, sessionId, env.content, contentHash, correlationId, recoveredSeq ?? undefined);
  }

  /**
   * Review M4: bounded memo of parked entries we have already refused, so a mailbox stuffed with
   * forgeries cannot force an unbounded unseal+verify on every reconnect. FIFO-capped — the cap
   * matters more than the retention: forgetting an entry only costs one extra verification, whereas
   * an unbounded map would be a memory leak fed by a remote party (the exact class the DOD-MSG-4
   * review already caught once in the offered-moniker map).
   */
  #rememberRefusedParkedEntry(key: string, reason: ParkAuthFailure): void {
    if (this.#refusedParkedEntries.size >= MAX_REFUSED_PARKED_ENTRIES) {
      const oldest = this.#refusedParkedEntries.keys().next();
      if (!oldest.done) this.#refusedParkedEntries.delete(oldest.value);
    }
    this.#refusedParkedEntries.set(key, reason);
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
    // DOD-FRONTIER-STRAND-1 AC1: returns the verified canonical position (null when the record is
    // absent, malformed, or not signed by this session's counterparty) so the park-recovery caller
    // can key dedup on the position rather than on the content hash.
  ): number | null {
    return this.#recordFrameOrdering(agentName, sessionId, structure1Cbor, structure2Cbor, contentHash, correlationId, "park");
  }

  #recordFrameOrdering(
    agentName: string,
    sessionId: string,
    structure1Cbor: Uint8Array,
    structure2Cbor: Uint8Array,
    contentHash: Uint8Array,
    correlationId?: string,
    source: string = "content_frame",
    // DOD-FRONTIER-STRAND-1 AC1: RETURNS the verified canonical position so the caller hands it
    // straight to ingest. It was void, and the position was only stashed in the hash-keyed
    // #witnessedSeq map — which cannot hold two positions for one hash, so two identical
    // messages collapsed there before dedup ran. Returning it is what makes per-message dedup
    // possible at all.
  ): number | null {
    try {
      const s1 = decode(structure1Cbor) as unknown[];
      const s2 = decode(structure2Cbor) as unknown[];
      const s1Hash = s1?.[1];
      const s1Pubkey = s1?.[2];
      const seq = typeof s2?.[0] === "number" ? s2[0] : -1;
      const s2Sig = s2?.[3];
      if (!(s1Hash instanceof Uint8Array) || !(s1Pubkey instanceof Uint8Array) || !(s2Sig instanceof Uint8Array) || seq < 1) {
        this.#logger.warn("session.content.ordering.malformed", { sessionId, correlationId });
        return null;
      }
      // The framed ordering record must bind to THIS content (its hash) — else it orders the wrong bytes.
      const contentHashHex = Buffer.from(contentHash).toString("hex");
      if (Buffer.from(s1Hash).toString("hex") !== contentHashHex) {
        this.#logger.warn("session.content.ordering.hash_mismatch", { sessionId, correlationId });
        return null;
      }
      // Verify the SENDER's Ed25519 signature over the exact signed bytes (structure1_cbor) — the same
      // check the relay performs. Proves the counterparty committed to this (content_hash @ sequence).
      if (!verify(s1Pubkey, structure1Cbor, s2Sig)) {
        this.#logger.warn("session.content.ordering.bad_signature", { sessionId, correlationId });
        return null;
      }
      // Sovereign-node cross-check: the signer MUST be THIS session's counterparty, not an unrelated
      // key. FAIL CLOSED (review L) — if the counterparty pubkey is unknown we cannot prove the signer,
      // so we do NOT trust the framed ordering record (fall back to the witness stream / arrival). The
      // "B does not trust the counterparty for ordering" invariant is non-negotiable; never fail open.
      // Review M1: compare BYTES, not hex strings — `counterparty_pubkey` is stored verbatim from the
      // IPC param and is never case-normalized, so a string compare would fail for a mixed-case
      // pubkey and silently strip the canonical ordering from every message in that session.
      const counterparty = this.getSessionRecord(agentName, sessionId)?.counterparty_pubkey;
      if (!pubkeyMatchesHex(s1Pubkey, counterparty)) {
        this.#logger.warn("session.content.ordering.wrong_signer", {
          sessionId,
          reason: counterparty ? "signer_not_counterparty" : "counterparty_unknown",
          correlationId,
        });
        return null;
      }
      // Verified — record the relay-assigned canonical sequence (1-based → 0-based leaf index) for the gate.
      this.recordWitnessedSequence(agentName, sessionId, contentHashHex, seq - 1);
      this.#logger.info("session.content.ordering.recorded", {
        sessionId,
        canonicalSeq: seq - 1,
        source,
        correlationId,
      });
      return seq - 1;
    } catch (err: unknown) {
      this.#logger.warn("session.content.ordering.decode_failed", {
        sessionId,
        error: err instanceof Error ? err.message : String(err),
        correlationId,
      });
    }
    // No verified position — the caller falls back to the announced hash-dedup path.
    return null;
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

      if (frame["type"] !== "content_frame") {
        // LOGGED, not silently dropped. This handler is bound to one session, and a frame it does
        // not understand arriving on that stream is either a peer speaking a newer protocol or a
        // bug on our side — both worth a line, and neither distinguishable from "nothing arrived"
        // when the return is silent.
        this.#logger.warn("session.content.frame_unknown_type", {
          sessionId,
          type: typeof frame["type"] === "string" ? String(frame["type"]) : "(absent)",
        });
        return;
      }
      // THE FRAME NAMES ITS SESSION, and until now nothing checked it.
      //
      // The stream binding decides where content lands, so the field was decorative — which is the
      // problem. A peer holding TWO sessions with us could put content addressed to one on the
      // other's stream and it was ingested, leafed, transcribed and SEALED under the wrong record.
      // The sealed transcript is the artifact this protocol exists to produce; a message in it that
      // its own author addressed elsewhere is exactly the thing it must not contain.
      //
      // Refused rather than re-routed: routing it to the session it names would honour a claim made
      // by the party whose frame arrived in the wrong place, and the stream — which is authenticated
      // — is the better authority. Refusing leaves the sender to redeliver on the right one.
      const framedSessionId = frame["session_id"];
      if (typeof framedSessionId === "string" && framedSessionId !== sessionId) {
        this.#logger.warn("session.content.session_mismatch", {
          sessionId,
          claimedSessionId: framedSessionId,
        });
        return;
      }
      const contentBytes = frame["content_bytes"];
      const contentHash = frame["content_hash"];
      if (!(contentBytes instanceof Uint8Array) || !(contentHash instanceof Uint8Array)) {
        // Same reasoning as the unknown type above: a malformed frame that vanishes without a trace
        // is indistinguishable, from the operator's side, from a counterparty who never sent
        // anything.
        this.#logger.warn("session.content.frame_malformed", {
          sessionId,
          hasContent: contentBytes instanceof Uint8Array,
          hasHash: contentHash instanceof Uint8Array,
        });
        return;
      }
      // DOD-MSG-4 (self-ordering content frame): if the frame carries the relay's signed ordering
      // record, verify the sender signature and record the canonical sequence FROM THE FRAME, BEFORE
      // ingest — so the strict-in-order gate has the position without waiting on the separate
      // leaf_deliver witness (removes the content-before-witness race). A bad/absent record is
      // non-fatal: the content still ingests, ordered by the witness stream / arrival as before.
      const s1Cbor = frame["structure1_cbor"];
      const s2Cbor = frame["structure2_cbor"];
      let framedSeq: number | null = null;
      if (s1Cbor instanceof Uint8Array && s2Cbor instanceof Uint8Array) {
        framedSeq = this.#recordFrameOrdering(agentName, sessionId, s1Cbor, s2Cbor, contentHash, correlationId);
      }
      // AC-001: carry the sender's correlationId from the frame into the receive
      // path so both sides log the same flow id (never re-minted on receipt).
      const ingest = await this.ingestReceivedContent(agentName, sessionId, contentBytes, contentHash, correlationId, framedSeq ?? undefined);
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

  /**
   * DOD-NAT-REACHABILITY-1 (Phase 2): relay endpoints the DIRECTORY handed this
   * agent at signaling-auth time — the freshest, health-filtered view of the
   * relay pool, and the only source a FRESH agent (no session history) has.
   */
  readonly #directoryRelayEndpoints = new Map<string, Array<{ relayPeerId: string; relayAddrs: string[] }>>();

  /**
   * DOD-NAT-REACHABILITY-1 (Phase 2): accept the directory's relay-pool endpoints
   * for an agent (arrives with signaling_auth_ok, i.e. on every connect AND every
   * reconnect). If the agent's standing receiver is up but holds NO reservation —
   * the agent-online ensure raced ahead of auth_ok, or every relay was down at
   * create time — rebuild it now so the agent becomes dialable without waiting
   * for a session handoff that (being unreachable) would never come.
   */
  setDirectoryRelayEndpoints(agentName: string, endpoints: Array<{ relayPeerId: string; relayAddrs: string[] }>): void {
    this.#directoryRelayEndpoints.set(agentName, endpoints);
    if (endpoints.length === 0 || this.#shuttingDown) return;
    const sr = this.#standingReceivers.get(agentName);
    if (!sr) return; // not ensured yet — the coming ensure reads the map
    if (sr.node.listenAddresses().some((a) => a.includes("/p2p-circuit"))) return; // already reserved
    this.#logger.info("session.standing_receiver.reservation.rebuild", {
      agentName,
      relayPeerIds: endpoints.map((e) => e.relayPeerId),
    });
    void this.#rebuildStandingReceiver(agentName);
  }

  /**
   * Replace an agent's reservation-less standing receiver with one that reserves.
   *
   * Deliberately NOT removeStandingReceiverForAgent()+ensureStandingReceiverForAgent():
   * the public remove CLEARS #agentsWantingReceiver, so a cello_set_agent_offline landing in
   * the window while node.stop() is awaited would find no map entry and no creating
   * marker, leave no tombstone, and the re-ensure would then RESURRECT a receiver for
   * an agent that asked to go dark — accepting inbound sessions for an offline agent.
   * Here the want-flag is left intact and re-checked after the stop: a concurrent stop
   * clears it, and the rebuild correctly no-ops.
   */
  async #rebuildStandingReceiver(agentName: string): Promise<void> {
    try {
      const sr = this.#standingReceivers.get(agentName);
      if (sr) {
        this.#standingReceivers.delete(agentName);
        try {
          sr.autoNat.stop();
          await sr.node.stop();
        } catch (err: unknown) {
          this.#logger.warn("session.standing_receiver.teardown.failed", {
            agentName,
            error: extractErrorMessage(err),
          });
        }
      }
      // The agent may have gone offline while we were stopping the old node. Its
      // want-flag is the authority — never resurrect a receiver it disowned.
      if (!this.#agentsWantingReceiver.has(agentName) || this.#shuttingDown) return;
      await this.#ensureStandingReceiver(agentName);
    } catch (err: unknown) {
      this.#logger.warn("session.standing_receiver.reservation.rebuild.failed", {
        agentName,
        error: extractErrorMessage(err),
      });
    }
  }

  /**
   * DOD-NAT-REACHABILITY-1: circuit-relay listen addresses for an agent's known
   * relays, so its standing receiver takes reservations and becomes dialable
   * behind NAT. Sources, merged and deduped by relay peer id: the directory's
   * auth-time relay pool (freshest — first), then the persisted relay endpoints
   * of past sessions (getAgentRelayEndpoints — covers a directory that predates
   * the auth_ok extension).
   */
  #reservationCircuitAddrs(agentName: string): { addrs: string[]; relayPeerIds: string[] } {
    let persisted: Array<{ relayPeerId: string; relayAddrs: string[] }>;
    try {
      persisted = this.getAgentRelayEndpoints(agentName);
    } catch (err: unknown) {
      // No DB / unknown agent — persisted source unavailable. The directory
      // source may still serve; reachability degrades only if both are empty.
      // Logged (not swallowed): a genuine DB failure must be distinguishable
      // from "fresh agent, no history" in the reachability trail.
      this.#logger.debug("session.standing_receiver.persisted_relays.unavailable", {
        agentName,
        error: extractErrorMessage(err),
      });
      persisted = [];
    }
    const merged = new Map<string, { relayPeerId: string; relayAddrs: string[] }>();
    for (const ep of [...(this.#directoryRelayEndpoints.get(agentName) ?? []), ...persisted]) {
      if (!merged.has(ep.relayPeerId)) merged.set(ep.relayPeerId, ep);
    }
    const addrs: string[] = [];
    const relayPeerIds: string[] = [];
    for (const ep of merged.values()) {
      const base = ep.relayAddrs[0];
      if (!base) continue;
      const candidate = base.includes("/p2p/")
        ? `${base}/p2p-circuit`
        : `${base}/p2p/${ep.relayPeerId}/p2p-circuit`;
      // These addresses are built from DIRECTORY-supplied endpoints — data from off
      // this machine. A malformed one throws inside libp2p node construction, which
      // would take the standing receiver down entirely and leave the agent deaf to
      // ALL inbound (worse than the defect this fixes). A bad endpoint must cost one
      // relay, never the receiver.
      if (!isValidMultiaddr(candidate)) {
        this.#logger.warn("session.standing_receiver.relay_endpoint.invalid", {
          agentName,
          relayPeerId: ep.relayPeerId,
          addr: candidate,
        });
        continue;
      }
      addrs.push(candidate);
      relayPeerIds.push(ep.relayPeerId);
    }
    return { addrs, relayPeerIds };
  }

  /**
   * DOD-NAT-REACHABILITY-1: notice when a standing receiver has SILENTLY LOST its
   * reservation, and get it another one.
   *
   * libp2p refreshes a circuit reservation before it expires. If the relay has died,
   * that refresh fails and the /p2p-circuit address simply DISAPPEARS from the node's
   * addresses. Nothing throws. The receiver is still up, still directly dialable, and
   * still looks perfectly healthy — but no NAT'd peer can reach the agent any more.
   * That is precisely the silent-loss-of-inbound failure this whole story exists to
   * kill, so it cannot be left to chance: we watch for it and re-pick a relay.
   *
   * Only receivers that HAD a reservation are watched. One that never got one is
   * already degraded and already loud (reservation.none / reservation.timeout);
   * rebuilding it on a timer would just thrash against relays we know are refusing.
   */
  #reservationWatchdogTick(): void {
    if (this.#shuttingDown) return;
    for (const [agentName, sr] of this.#standingReceivers) {
      if (!sr.hasReservation || sr.relayPeerId === undefined) continue; // never had one — not a LOSS
      if (!this.#agentsWantingReceiver.has(agentName)) continue;        // agent went offline

      // Watch the CONNECTION to the relay, not the circuit address.
      //
      // Killing the relay does NOT make the /p2p-circuit address disappear: libp2p
      // keeps the listen address until the reservation's own refresh, up to two hours
      // away. Watching the address would therefore miss a dead relay for hours — the
      // agent would advertise a circuit address that routes through a relay that no
      // longer exists, which is exactly the silent unreachability we are hunting. The
      // live connection to the relay is the honest signal: no connection, no relay,
      // no reservation.
      const stillConnected = sr.node.getConnections().some((c) => c.peerId === sr.relayPeerId);
      const stillAdvertising = sr.node.listenAddresses().some((a) => a.includes("/p2p-circuit"));
      if (stillConnected && stillAdvertising) continue;

      // DOD-RELAY-KEEPALIVE-1 (review F4): carry the CAUSE, not just the exit point.
      // `relay_connection_gone` says where this was noticed — a poll of getConnections() — by which
      // time the abort reason that actually killed the link is long discarded. The relay client for
      // this (agent, relay) pair kept the error that ended its reader; that is the nearest thing to
      // an upstream cause available here, and its absence is how 2,061 of these went untraced.
      const upstreamReason = this.#relayClients.get(`${agentName}::${sr.relayPeerId}`)?.getLastReaderError();
      this.#logger.warn("session.standing_receiver.reservation.lost", {
        agentName,
        relayPeerId: sr.relayPeerId,
        reason: stillConnected ? "circuit_address_vanished" : "relay_connection_gone",
        ...(upstreamReason ? { upstreamReason } : {}),
      });
      void this.#rebuildStandingReceiver(agentName);
    }
  }

  /**
   * DOD-PARK-DRAIN-1: the backstop sweep — every agent holding a standing receiver gets a drain
   * every #parkedDrainBackstopMs, whether or not anything happened.
   *
   * The trigger-driven drains (agent start, receiver rebuild, signaling reconnect) are what
   * actually deliver. This exists because the incident was a MISSING trigger, and a missing
   * trigger is invisible: the daemon looked healthy, the content was intact on the relay, and the
   * only thing that ever moved it was a human restarting the daemon. With the sweep, the worst a
   * future gap in trigger coverage can cost is one interval of latency. Safe by construction —
   * ingest is deduped and the relay is delete-on-confirm, so a redundant drain pulls nothing.
   */
  #parkedDrainBackstopTick(now: number): void {
    if (this.#parkedDrainHook === null) return;
    if (now - this.#parkedDrainLastBackstopAt < this.#parkedDrainBackstopMs) return;
    this.#parkedDrainLastBackstopAt = now;
    for (const agentName of this.#standingReceivers.keys()) {
      if (!this.#agentsWantingReceiver.has(agentName)) continue; // agent went offline
      this.#fireParkedDrain(agentName, "periodic_backstop");
    }
  }

  /** Start the reservation watchdog (idempotent). Stopped by gracefulShutdown. */
  #startReservationWatchdog(): void {
    if (this.#reservationWatchdog !== null) return;
    // Arm the backstop clock from the START of watching, not from the epoch — otherwise the first
    // tick always fires a sweep on top of the install drain that just ran.
    this.#parkedDrainLastBackstopAt = Date.now();
    this.#reservationWatchdog = setInterval(() => {
      try {
        this.#reservationWatchdogTick();
        this.#parkedDrainBackstopTick(Date.now());
      } catch (err: unknown) {
        this.#logger.warn("session.standing_receiver.watchdog.failed", { error: extractErrorMessage(err) });
      }
    }, this.#srWatchdogIntervalMs);
    // Never hold the process open on account of the watchdog.
    this.#reservationWatchdog.unref?.();
  }

  /**
   * Start the standing receiver's libp2p node, holding a circuit-relay reservation
   * if one can be had — and WITHOUT one if it cannot.
   *
   * THE INVARIANT, learned live: **standing-receiver creation must NEVER be gated on
   * a relay.** libp2p's circuit listener awaits a live connection to its relay before
   * start() resolves, and it does not time out. A relay that does not answer parks
   * start() forever: no created event, no failure, no retry, no alarm — the agent
   * simply has no receiver and is deaf to ALL inbound, including the direct path that
   * worked before reservations existed. Strictly worse than the NAT defect this whole
   * line exists to fix. So every attempt is raced against a deadline, and failure
   * ALWAYS falls through to a plain TCP receiver.
   *
   * ONE relay, tried on the REAL node — not a probe.
   *
   * A relay reservation is a scarce resource: the relay holds it for its full TTL
   * even after the client disconnects, and it has a finite number of slots. An
   * earlier design probed each relay on a throwaway node and then reserved AGAIN on
   * the receiver — burning TWO slots per agent to get one, and leaving the throwaway's
   * slot pinned for hours. That is how a fleet exhausts a relay. Here the receiver
   * itself makes the attempt: if the relay grants the reservation, we KEEP that node.
   * One slot per agent, which is the true cost.
   *
   * Candidates are tried in order (directory pool first). The first that actually
   * grants a reservation wins; the rest are never touched.
   */
  async #startReceiverNode(
    agentName: string,
    sessionId: string,
    gater: SessionConnectionGater,
    candidateCircuitAddrs: string[],
    correlationId: string,
  ): Promise<CelloNode> {
    for (const circuitAddr of candidateCircuitAddrs) {
      const candidate = await this.#factory.createNode({
        sessionId,
        connectionGater: gater,
        nodeType: "standing_receiver",
        circuitRelayListenAddrs: [circuitAddr],
      });
      let timer: ReturnType<typeof setTimeout> | undefined;
      const timedOut = Symbol("reservation_timeout");
      let outcome: "started" | typeof timedOut | "failed" = "failed";
      let error = "";
      try {
        outcome = await Promise.race([
          candidate.start().then(() => "started" as const),
          new Promise<typeof timedOut>((resolve) => {
            timer = setTimeout(() => resolve(timedOut), this.#srReservationTimeoutMs);
          }),
        ]);
      } catch (err: unknown) {
        error = extractErrorMessage(err);
      } finally {
        if (timer !== undefined) clearTimeout(timer);
      }

      // The only proof that counts: the relay actually GRANTED the reservation.
      // start() resolving is not enough — a relay that is out of reservation slots
      // completes the handshake and simply grants nothing, leaving a node that looks
      // started and is reachable by nobody.
      if (outcome === "started" && candidate.listenAddresses().some((a) => a.includes("/p2p-circuit"))) {
        return candidate;
      }

      this.#logger.warn("session.standing_receiver.relay.rejected", {
        agentName,
        circuitAddr,
        reason:
          outcome === "started"
            ? "relay_granted_no_reservation"
            : outcome === "failed"
              ? "relay_unreachable"
              : "reservation_did_not_complete_in_time",
        ...(error !== "" ? { error } : {}),
        correlationId,
      });
      // Abandon it. start() may still be parked on a dial, so stop() is best-effort
      // and must never block the fallback.
      void Promise.resolve()
        .then(() => candidate.stop())
        .catch(() => { /* best-effort: the node never finished starting */ });
    }

    const plain = await this.#factory.createNode({
      sessionId,
      connectionGater: gater,
      nodeType: "standing_receiver",
    });
    await plain.start();
    return plain;
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

    // DOD-NAT-REACHABILITY-1: reserve with the agent's known relays. The relay
    // peers are allowed OUTBOUND on the gater up front, so reservation refreshes
    // keep working after the receiver is claimed and setAllowedPeer() narrows
    // the inbound gate to the session counterparty.
    const reservations = this.#reservationCircuitAddrs(agentName);
    for (const relayPeerId of reservations.relayPeerIds) {
      gater.setAllowedOutboundPeer(relayPeerId);
    }

    let node: CelloNode;
    try {
      node = await this.#startReceiverNode(agentName, sessionId, gater, reservations.addrs, correlationId);
    } catch (err: unknown) {
      // extractErrorMessage, NOT String(err): the transport throws structured
      // plain objects ({ reason, message }), and String() destroys both into
      // "[object Object]" — the loud failure must carry its cause.
      const error = extractErrorMessage(err);
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

    // L1: the agent may have gone offline (cello_set_agent_offline → removeStandingReceiverForAgent)
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

    const circuitAddrs = node.listenAddresses().filter((a) => a.includes("/p2p-circuit")).length;
    // The relay we actually reserved with — the watchdog watches our connection to it.
    const reservedRelayPeerId =
      circuitAddrs > 0 ? reservations.addrs[0]?.match(/\/p2p\/([^/]+)\/p2p-circuit/)?.[1] : undefined;
    this.#standingReceivers.set(agentName, {
      node,
      gater,
      autoNat,
      hasReservation: circuitAddrs > 0,
      ...(reservedRelayPeerId !== undefined ? { relayPeerId: reservedRelayPeerId } : {}),
    });
    this.#logger.info("session.node.created", {
      sessionId,
      agentName: `${STANDING_RECEIVER_AGENT_NAME}:${agentName}`,
      sessionPeerId: node.getPeerId(),
      correlationId,
    });

    // DOD-NAT-REACHABILITY-1 observability: how reachable did this receiver come
    // up? circuitAddrs === 0 with reservations requested means every relay
    // refused/was unreachable — the agent is deaf to NAT'd initiators (public
    // ones can still connect directly). That must be LOUD, not a quiet shrug.
    this.#logger.info("session.standing_receiver.reachability", {
      agentName,
      circuitAddrs,
      reservationsRequested: reservations.addrs.length,
      correlationId,
    });
    if (reservations.addrs.length > 0 && circuitAddrs === 0) {
      this.#logger.warn("session.standing_receiver.reservation.none", {
        agentName,
        reservationsRequested: reservations.addrs.length,
        relayPeerIds: reservations.relayPeerIds,
        correlationId,
      });
    }

    // DOD-PARK-DRAIN-1: this agent has a receiver again — drain whatever parked while it did not.
    // Fired from the ONE place every path converges on (first ensure, the watchdog rebuild after a
    // lost reservation, and the auth_ok rebuild), because the defect this closes was a trigger
    // hooked to the wrong connection: content parks when the RELAY link dies, and the drain was
    // waiting on DIRECTORY SIGNALING to reconnect — which it never had to, having never dropped.
    this.#fireParkedDrain(agentName, "standing_receiver_ready");
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
    this.#startReservationWatchdog();
    await this.#ensureStandingReceiver(agentName);
  }

  async removeStandingReceiverForAgent(agentName: string): Promise<void> {
    // M8B F14: the agent no longer wants a receiver — disarm the teardown re-arm.
    this.#agentsWantingReceiver.delete(agentName);
    // The directory hands these out at signaling-auth time, so a re-started agent
    // gets a fresh set on its next connect — holding the old ones would keep a
    // retired agent's relay list alive for the daemon's lifetime.
    this.#directoryRelayEndpoints.delete(agentName);
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
           (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?)`,
        )
        .run(sessionId, this.#requireAgentId(agentName), counterpartyPubkey, status, now, now);
      return true;
    } catch (err: unknown) {
      // D4 review F2: this helper serves the CREATE/ACCEPT paths (and interrupt-restore) — the old
      // event name `session.interrupt.db.write.failed` steered diagnosis to the interrupt path only.
      this.#logger.error("session.row.write.failed", {
        sessionId,
        agentName,
        status,
        error: err instanceof Error ? err.message : String(err),
      });
      return false;
    }
  }

  /** CC-5/F21: count of RECEIVED messages on a session — the "did the counterparty ever speak"
   *  signal the dead-half-open reaper uses (message_count also counts our own auto-"Dispatched." ack,
   *  so it is NOT a reliable half-open discriminator). Mirrors #getReceivedBytesTotal. */
  countReceivedMessages(agentName: string, sessionId: string): number {
    if (!this.#db) return 0;
    const row = this.#db
      .prepare("SELECT COUNT(*) AS n FROM transcript WHERE agent_id = ? AND session_id = ? AND direction = 'received'")
      .get(this.#requireAgentId(agentName), sessionId) as { n: number };
    return row.n;
  }

  /** CC-5/F21: unilaterally mark a session locally-terminal ("abandoned") — retire its live node and
   *  set the DB status, with NO bilateral seal (a dead half-open handshake has nothing to notarize).
   *  Used by cello_close_session { force } and the dead-half-open reaper. Idempotent: a missing/already-
   *  abandoned session is a no-op. Resolves true iff the status flip was actually written (CC-10
   *  reviewer LOW: callers must not report a reap as successful when the write failed). */
  async abandonSession(agentName: string, sessionId: string): Promise<boolean> {
    // Status flip FIRST and synchronous (before the async node teardown yields), so a non-awaited
    // reaper call from a read path takes effect for the SAME read (the DB is updated before the await).
    const flipped = this.#updateSessionStatus(agentName, sessionId, "abandoned");
    await this.retireSessionNode(agentName, sessionId);
    return flipped;
  }

  /** @returns true iff the UPDATE was executed without error (a failed write is logged, never thrown). */
  #updateSessionStatus(
    agentName: string,
    sessionId: string,
    status: "active" | "sealed" | "interrupted" | "abandoned",
  ): boolean {
    if (!this.#db) return false;
    const now = Date.now();
    try {
      const res = this.#db
        .prepare(
          "UPDATE sessions SET status = ?, updated_at = ? WHERE agent_id = ? AND session_id = ?",
        )
        .run(status, now, this.#requireAgentId(agentName), sessionId) as unknown as { changes?: number | bigint };
      // "Did not throw" is NOT "landed". An UPDATE whose WHERE matches no row — a wrong agent_id, a
      // session_id with no row — succeeds silently and changes nothing. Reporting that as a written
      // status flip is what let a disposition hook delete a live session's content, so the row count
      // is the answer to both questions.
      const landed = Number(res?.changes ?? 0) > 0;
      if (!landed) {
        this.#logger.error("session.status.write.missed", {
          sessionId,
          status,
          agentName,
          impact: "no session row matched — the status was NOT changed and no disposition was run",
        });
        return false;
      }
      // DOD-RETRYQ-STRAND-1: only AFTER the status write actually landed. Disposing of durable
      // state on the strength of a write that did not land would discard content while the session
      // is still, on disk, drainable. 'interrupted' and 'seal_interrupted_pending' are deliberately
      // NOT terminal — both can still complete, and reaping them would destroy live content.
      if (status === "sealed" || status === "abandoned") {
        try {
          this.#onSessionTerminal?.(sessionId, status);
        } catch (hookErr: unknown) {
          // The status flip is the caller's contract and has already succeeded; a failing
          // disposition must not turn it into a reported failure. Named so the strand it leaves
          // behind is attributable rather than mysterious.
          this.#logger.error("session.terminal.disposition.failed", {
            sessionId,
            status,
            error: hookErr instanceof Error ? hookErr.message : String(hookErr),
            impact: "durable state keyed to this session was not disposed of and may strand",
          });
        }
      }
      return true;
    } catch (err: unknown) {
      // CC-5 (reviewer F-2): status-agnostic event + the actual target status in context — this method
      // now writes "abandoned" too, so labeling every failure "interrupt" was misleading.
      this.#logger.error("session.status.write.failed", {
        sessionId,
        status,
        error: err instanceof Error ? err.message : String(err),
      });
      return false;
    }
  }
}
