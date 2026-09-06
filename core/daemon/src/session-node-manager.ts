/**
 * CELLO Daemon — SessionNodeManager
 *
 * Manages the lifecycle of all ephemeral session nodes:
 *   1. Per-session nodes: fresh transport key + Peer ID, connectionGater allows
 *      only the designated counterparty. Created during cello_initiate_session
 *      (outbound) or cello_await_session (inbound, via standing receiver handoff).
 *   2. Standing receiver node: pre-created, kept alive at all times, handed to the first inbound
 *      session and immediately replaced. Its gater is NOT open — `DOD-M15-ASSIGN-1` made it admit
 *      nobody inbound until a session offer names the dialer (see `standing-receivers.ts`). This
 *      line said "open gater" for as long as that was true and for a while after it was not.
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
// `wireContentHash` is gone from this file on purpose: its ONE use was the receive-path cross-check,
// which now goes through `contentHashFor` so the comparison runs under the algorithm the sender
// named. A direct call here would be a hash computed without asking what the frame said (part B1).
import { contentHashFor, type ContentHashAlg } from "./wire-content-hash.js";
import { CAPACITY_REASONS, type CapacityReason } from "./refusal-reasons.js";
import { ownSaltFrame, type SaltAgreementFrame } from "./session-salt-agreement.js";
import { CONTENT_ENCRYPTION_REASONS, CONTENT_ENCRYPTION_GUIDANCE } from "./content-encryption-status.js";
import {
  type DaemonDatabase,
  openEncryptedDatabase,
  resolveDbKey,
  dbKeyPathFor,
} from "./sqlcipher-db.js";
import { migrateToEncryptedIfNeeded } from "./identity-migration.js";
import { ensureIdentitySchema } from "./db-identity-store.js";
import { TIER } from "./contacts-tier-migration.js";
import { normalizeContactPubkey } from "./contact-pubkey-case.js";
import { type RefusalKind } from "./refusal-reasons.js";
import { settableTierName, awayTierSettingKey, AWAY_DEFAULT_KEY } from "./agent-settings-keys.js";
import { randomUUID, createHash, randomBytes } from "node:crypto";
import * as lp from "it-length-prefixed";
import { decode } from "cbor-x";
import { encodeCbor, decodeStructure1 } from "@cello-protocol/protocol-types";
import type { SessionAbandonedNotice } from "@cello-protocol/protocol-types";
import type { Stream } from "@libp2p/interface";
import type { Logger, SessionRecord, SealReadinessView } from "./types.js";
import { MAX_SESSION_NODES, STANDING_RECEIVER_AGENT_NAME } from "./types.js";
import { SessionConnectionGater } from "./session-connection-gater.js";
import { SessionTree, type WritableSessionTreeLeafKind } from "./session-tree.js";
import { CELLO_CONTENT_PROTOCOL_ID, NodeAutoNatService, type CelloNode, type IAutoNatService } from "@cello-protocol/transport";
import type { KeyProvider } from "@cello-protocol/crypto";
import { buildMerkleTree, merkleRoot, type SessionEphemeral } from "@cello-protocol/crypto";
import { encodeSealPayload } from "@cello-protocol/protocol-types";
// `PARK_ENVELOPE_REASONS` is deliberately NOT imported here. The reason codes are compared inside
// `park-envelope.ts` itself (`parkRefusalGuidance`) and asserted in its own test; this file only ever
// receives the already-classified `ParkAuthFailure`, so importing the code table here would invite a
// second, drifting copy of the classification logic.
import { decodeParkEnvelope, type ParkEnvelope } from "./park-envelope.js";
import { isValidMultiaddr } from "@cello-protocol/transport";
// `LEAF_KIND_MSG` is no longer imported here: `sendContent`'s `leafKind` stopped defaulting to it
// (B2b-1 review F4), so this file no longer names a default — every caller states its own kind.
import { AgentRelayClient, LEAF_KIND_CTRL, type RelayAuthRefusal, type RelayWitnessAlert } from "./session-relay-client.js";
import { extractErrorMessage } from "./error-message.js";
import { AuthorshipVerifier } from "./authorship-verification.js";
import { InboundRefusals } from "./inbound-refusals.js";
import { SessionRecords } from "./session-records.js";
import { ParkRecovery } from "./park-recovery.js";
import { SessionSalts } from "./session-salts.js";
import { ensureSessionSchema } from "./session-schema.js";
import { SessionQueries } from "./session-queries.js";
import { RefusalNotices } from "./refusal-notices.js";
import { SessionEphemerals } from "./session-ephemerals.js";
import { SessionLiveness } from "./session-liveness.js";
import { WitnessAlerts } from "./witness-alerts.js";
import { HeldContent, type HeldEntry } from "./held-content.js";
import { SessionLeafRecords } from "./session-leaf-records.js";
import { SessionContentSender } from "./session-content-send.js";
import { SessionContentIngest } from "./session-content-ingest.js";
import type { SessionContentPipelineContext } from "./session-content-context.js";
import { StandingReceivers } from "./standing-receivers.js";
import { RelayReceiptStore, type RelayReceipt } from "./relay-receipt-store.js";
import { SessionSealLeafStore, type SealCarryLeaf } from "./session-seal-leaf-store.js";
import { SessionOwnChainStore } from "./session-own-chain-store.js";
import type { SealUpgradeReadiness } from "./seal-upgrade.js";
import type { SealFrontierLeaf } from "./seal-frontier-verify.js";
import { type QuarantineFrameMeta } from "./quarantine-framing.js";
import { type SecurityGatewayClient } from "@cello-protocol/gateway";

/**
 * One row in an agent's witness-alert list — DOD-M15-CORROBORATE-1 review F1. Deduped on
 * `(witness relay, session)`, so a repeated observation raises `occurrences` rather than taking
 * another slot in a bounded list.
 */
import { ABUSE_MAX_UNKNOWN_SESSIONS_GLOBAL, AUTOACK_BROKER_GRACE_MS, type AbandonNoticeResult, type ActiveSessionEntry, type AwaitingAckEntry, CONTENT_MAX_INBOUND_STREAMS, type CreateSessionResult, type ISessionNodeFactory, LEAF_FETCH_GRACE_MS, type ParkedDrainReason, type QuarantinedRecord, RELAY_QUARANTINE_MS, type ReceivedContentEntry, type RefusalNotice, type RelayConnectParams, SHUTDOWN_STEP_DEADLINE_MS, SR_RESERVATION_MAX_RETRIES, type SessionImpairment, type SessionRevivalIdentity, type TranscriptEntry, type WitnessAlertNotice, carryContentHashInputs, heldRelayIdsOf, relayPeerIdOf } from "./session-node-types.js";

// Re-exported so this module's public surface is unchanged by the split: every existing
// importer of session-node-manager.js keeps working, and no test moves an import path.
export {
  ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER,
  ABUSE_MAX_SESSION_RECEIVED_BYTES,
  ABUSE_MAX_UNKNOWN_SESSIONS_GLOBAL,
  type AbandonNoticeResult,
  type AckHashReason,
  CAP_INTERRUPTED_TTL_MS,
  type ISessionNodeFactory,
  LEAF_FETCH_GRACE_MS,
  MAX_TERMINAL_REFUSALS_PER_SESSION,
  type ParkedDrainReason,
  type QuarantinedRecord,
  RELAY_QUARANTINE_MS,
  REVIVAL_BOUND_SWEEP_MS,
  REVIVAL_WINDOW_MS,
  REVIVE_RESERVATION_CANDIDATES,
  REVIVE_RESERVATION_TIMEOUT_MS,
  type RefusalNotice,
  type RelayConnectParams,
  SR_RESERVATION_MAX_RETRIES,
  type SentAuthorship,
  type SessionImpairment,
  type SessionNodeConfig,
  TERMINAL_REFUSAL_READ_RETRY_MS,
  TERMINAL_REFUSAL_REASONS,
  type TranscriptEntry,
  type WitnessAlertNotice,
} from "./session-node-types.js";

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
  /** `DOD-M15-SELFCHAIN-1` — this agent's own last message per session, so the next one links to it. */
  #ownChainStore: SessionOwnChainStore | null = null;
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
  /**
   * DOD-M15-RELAYSLOTS-1: `onlineToken` is REQUIRED on the dependency bag, not optional. Every
   * relay client needs the directory's token or the relay refuses it a reservation slot, and the
   * failure is invisible from the client side — the agent comes up, reports itself online, and is
   * reachable by nobody. Making it required means a call site that forgets to pass it is a type
   * error rather than an agent that quietly stops being dialable.
   */
  #detachedRelayClientBuilder: ((agentName: string, relayPeerId: string, relayAddrs: string[], stores: { receiptStore?: RelayReceiptStore; sealLeafStore?: SessionSealLeafStore; ownChainStore?: SessionOwnChainStore; onlineToken: () => Uint8Array | undefined }) => AgentRelayClient | undefined) | null = null;
  setDetachedRelayClientBuilder(fn: (agentName: string, relayPeerId: string, relayAddrs: string[], stores: { receiptStore?: RelayReceiptStore; sealLeafStore?: SessionSealLeafStore; ownChainStore?: SessionOwnChainStore; onlineToken: () => Uint8Array | undefined }) => AgentRelayClient | undefined): void {
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
    | { node: CelloNode; relayClient: AgentRelayClient; relaySessionIdBytes: Uint8Array; releaseOnDone?: true }
    | { error: string } {
    const entry = this.#activeNodes.get(this.#k(agentName, sessionId));
    if (entry) {
      // The live path is unchanged and takes precedence — a session with its own registered client
      // must never seal through a rebuilt one.
      if (!entry.relayClient || !entry.relaySessionIdBytes) return { error: "relay_unavailable" };
      return { node: entry.node, relayClient: entry.relayClient, relaySessionIdBytes: entry.relaySessionIdBytes };
    }
    const ep = this.#queries.getPersistedRelayEndpoint(agentName, sessionId);
    if (!ep) return { error: "no_persisted_relay_endpoint" };
    const node = this.#receivers.getStandingReceiverNode(agentName);
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
        ownChainStore: this.#ownChainStore ?? undefined,
        // DOD-M15-RELAYSLOTS-1: read at each auth, never snapshotted — the token expires hourly.
        onlineToken: () => this.getDirectoryOnlineToken(agentName),
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
    /**
     * DOD-M15-RELAYLEAK-1 — **RE-REGISTERING A SESSION THAT IS ALREADY REGISTERED BLINDS IT.**
     *
     * `registerSession` REPLACES the entry's `onLeafDeliver` with `onLeafDeliver ?? (() => {})`, and
     * unlike `assignment` / `recorded` it does NOT carry the existing handler forward. **This path
     * passes no handler.** So a detached seal on a session that still holds a live registration
     * would swap that session's inbound leaf delivery for a no-op: the counterparty's leaves keep
     * arriving at the relay client and are dropped on the floor, while the operator sees a healthy
     * session that has simply gone quiet.
     *
     * A call that finds the session already registered is therefore a PASSENGER: it uses the client
     * and touches nothing. It also does not release — ownership is never inferred, only claimed.
     *
     * ⚠️ **This is NOT justified by a concurrency race, and an earlier version of this comment said
     * it was.** Review checked: `#resolveSealTransport` and everything above the first `await` are
     * synchronous, and a second caller plants/hits `#responderSealSubmitted` and returns
     * `responder_seal_already_submitted` before ever reaching `submitLeaf`. Two callers cannot be in
     * the client at once through the only caller, so "the second one closes the client the first is
     * awaiting" **cannot happen**. The wrong reason mattered: it invites a future reader to delete
     * this guard as defensive clutter once they notice the race is impossible — taking the
     * handler-clobbering protection with it.
     */
    const claimedRegistration = !client.hasSession(sessionId);
    if (claimedRegistration) {
      // 033-ACKEMIT: the seal transport submits a ctrl leaf like any other, so it needs the same
      // acknowledgement seed. It carries no assignment of its own, so the genesis is supplied here
      // from the session's own active entry rather than derived inside the client.
      client.registerSession(sessionId, node, undefined, undefined, this.#leafRecords.sessionGenesisPrevRoot(agentName, sessionId));
    } else {
      /**
       * Review MEDIUM-1 — **A PATH THAT DECLINES TO FIX A LEAK MUST SAY SO.**
       *
       * Reaching here means the session is registered on this client while `#activeNodes` holds no
       * entry for it — and the ways that happens are all orphans: a previous `releaseDetached()`
       * that threw (loud once, then silent forever after), or a revival that registered and then
       * failed to hang the client on an entry. Declining to unregister is right — we cannot prove
       * no live session owns it — but without this line the orphan is invisible, which is the exact
       * shape this whole line exists to remove.
       */
      this.#logger.info("session.seal.transport.registration_shared", {
        agentName,
        sessionId,
        impact:
          "this seal is using a relay registration it did not create, so it will not release it. If " +
          "no live session owns that registration the client is held until process exit.",
      });
    }
    /**
     * DOD-M15-RELAYLEAK-1 — **`releaseOnDone` IS THE RELEASE SIGNAL, and its absence was the leak.**
     *
     * This branch (no `#activeNodes` entry) CACHES a relay client and registers a session on it, and
     * nothing ever unregistered. `#detachSessionRelay` closes a client only when
     * `!client.hasSessions()`, so a registration that is never removed keeps that predicate false
     * **forever** — the client, its authenticated stream and its reader survive for the process
     * lifetime. The LIVE branch above registers nothing here, so only this one needs releasing, and
     * marking it is what lets the caller tell them apart without guessing.
     */
    return {
      node,
      relayClient: client,
      relaySessionIdBytes: new Uint8Array(Buffer.from(sessionId, "hex")),
      // Not `true` unconditionally: a passenger call must not release a registration it did not
      // claim — see the note above `claimedRegistration`.
      ...(claimedRegistration ? { releaseOnDone: true as const } : {}),
    };
  }

  /**
   * DOD-M15-RELAYAUTH-1: authenticate a fresh standing receiver to its reservation relay over the
   * CELLO relay protocol — proof of K_local key possession, not a session. Reuses the SAME
   * `#relayClients` cache `#connectSessionRelay`/`#resolveSealTransport` read from, keyed
   * identically (`${agentName}::${relayPeerId}`), so a session created moments later on this same
   * relay finds an already-authenticated client instead of dialing and authenticating twice.
   *
   * The manager holds no K_local (M12-P15's own rationale for `#detachedRelayClientBuilder`) —
   * without a builder wired (a narrow startup race, or a test harness that never wires one), this
   * is a no-op and the relay's own grace-window revoke is the backstop, not a defect in this path.
   */
  async #authenticateStandingReceiver(
    agentName: string,
    node: CelloNode,
    relayPeerId: string,
    heldCircuitAddr: string,
    correlationId: string,
  ): Promise<void> {
    const clientKey = `${agentName}::${relayPeerId}`;
    let client = this.#relayClients.get(clientKey);
    if (!client) {
      if (!this.#relayReceiptStore && this.#db) this.#relayReceiptStore = new RelayReceiptStore(this.#db, this.#logger);
      if (!this.#sealLeafStore && this.#db) this.#sealLeafStore = new SessionSealLeafStore(this.#db, this.#logger);
      /**
       * ⚠️ SPLIT, NOT AN ANCHORED STRIP. The held address is
       * `/ip4/…/tcp/…/p2p/<relay>/p2p-circuit/p2p/<self>` — the `/p2p-circuit` marker is in the
       * MIDDLE, not at the end, so a `/\/p2p-circuit$/` replace matches nothing and silently
       * hands the relay client a circuit address as its DIAL address. Measured, not assumed:
       * that first version failed this file's own test because the client could not dial.
       */
      const baseRelayAddr = heldCircuitAddr.split("/p2p-circuit")[0] ?? heldCircuitAddr;
      client = this.#detachedRelayClientBuilder?.(agentName, relayPeerId, [baseRelayAddr], {
        receiptStore: this.#relayReceiptStore ?? undefined,
        sealLeafStore: this.#sealLeafStore ?? undefined,
        ownChainStore: this.#ownChainStore ?? undefined,
        // DOD-M15-RELAYSLOTS-1: read at each auth, never snapshotted — the token expires hourly.
        onlineToken: () => this.getDirectoryOnlineToken(agentName),
      });
      if (!client) {
        /**
         * Review M5: this was a `debug` line, and it is not a debug-level event.
         *
         * If no builder is wired we return without proving key possession, the relay revokes this
         * receiver's reservation about fifteen seconds later, and the agent stops being reachable
         * from behind NAT — while reporting itself perfectly healthy. Calling that "a narrow startup
         * race" in a comment concedes it happens in production, and a system that is unreachable
         * must not be quieter about it than a system that is merely slow.
         */
        this.#logger.warn("session.standing_receiver.relay_auth.no_builder", {
          agentName,
          relayPeerId,
          correlationId,
          impact:
            "this receiver cannot prove key possession, so the relay will revoke its reservation and " +
            "the agent becomes unreachable from behind NAT — nobody can start a session with it — " +
            "even though it still reports itself online.",
        });
        return;
      }
      this.#relayClients.set(clientKey, client);
    }
    /**
     * ⚠️ `proveReservation`, NOT `connect`. Review HIGH-1: `connect()` short-circuits on the
     * client's cached stream, which belongs to whichever node connected FIRST — so every
     * REPLACEMENT standing receiver (the one built behind each new session) sent nothing, the relay
     * never saw its transport identity, and its reservation was revoked ~15s later. The agent then
     * churned reserve→revoke→rebuild for the life of the conversation, holding no usable circuit
     * address, so while you were talking to one person nobody else could reach you.
     *
     * `proveReservation` always opens its own stream from THIS node, and marks it so the relay
     * proves possession without rebinding the agent's delivery target away from the live session.
     */
    const proven = await client.proveReservation(node);
    /**
     * DOD-M15-RELAYSLOTS-1: keep the relay's refusal where the OPERATOR can reach it.
     *
     * The log line below is a good log line and it is not an answer to "why is my agent
     * unreachable?" — nobody opens the file. The relay now refuses for reasons a person can act on
     * (no token yet, too many sessions still open, this relay is misconfigured), each with its own
     * next step, and every one of them is useless if it stops at a log.
     */
    if (!proven) {
      const refusal = client.getLastAuthRefusal();
      /**
       * Review L2: the `else` is not symmetry for its own sake. `proveReservation` also fails for
       * transport reasons, which leave `getLastAuthRefusal()` null — and without this branch the
       * PREVIOUS refusal stayed in the map, so `cello_status` went on showing a cause and an
       * affordance for something that was no longer what was wrong.
       */
      if (refusal) this.#srRelayRefusal.set(agentName, { ...this.#withDirectoryCause(agentName, refusal), relayPeerId });
      else this.#srRelayRefusal.delete(agentName);
      /**
       * DOD-M15-RELAYSLOTS-1 clause 9 — **ACT on the classification, do not merely record it.**
       * A relay-side fault means a different relay will work now, so quarantine this one and
       * rebuild the receiver against the rest of the pool. Everything else stays put: a token
       * problem reproduces on every relay, and walking the fleet would turn one client fault into
       * what looks like a fleet-wide outage.
       */
      if (refusal?.tryAnotherRelay && !this.#shuttingDown) {
        this.#quarantineRelay(agentName, relayPeerId, refusal.reason);
        void this.#receivers.rebuildStandingReceiver(agentName);
      }
    } else {
      this.#srRelayRefusal.delete(agentName);
    }
    this.#logger.info("session.standing_receiver.relay_auth.result", {
      agentName,
      relayPeerId,
      // The node that actually proved itself — without this, HIGH-1 was invisible in the logs: the
      // line said `connected: true` for a receiver that had sent nothing.
      nodePeerId: node.getPeerId(),
      proven,
      ...(proven ? {} : {
        refusalReason: client.getLastAuthRefusal()?.reason ?? "no_relay_verdict",
        tryAnotherRelay: client.getLastAuthRefusal()?.tryAnotherRelay ?? false,
      }),
      correlationId,
    });
  }

  /**
   * Review F7: relays that sent a witness alert this build could not read or verify, per agent.
   * Peer id → cause + count. NO session and NO party: it reports that our witness layer is not
   * working, never anything about a participant.
   */
  readonly #witnessUnreadable = new Map<string, Map<string, { why: string; count: number }>>();

  /**
   * DOD-M15-RELAYSLOTS-1: the last relay refusal per agent, with the advice that goes with it.
   * Written where the refusal is actually known; read by whatever tells the operator.
   */
  readonly #srRelayRefusal = new Map<string, RelayAuthRefusal & { relayPeerId: string }>();

  /**
   * Why this agent's standing receiver could not hold a reservation, in words the person running it
   * can act on — or null when the last attempt succeeded or none has been made.
   *
   * This is the surface DoD clause 7 is about: the assertion that matters is what the CLIENT can
   * show someone, not what the relay wrote in its own log.
   */
  getStandingReceiverRefusal(agentName: string): (RelayAuthRefusal & { relayPeerId: string }) | null {
    return this.#srRelayRefusal.get(agentName) ?? null;
  }

  /**
   * DOD-M15-RELAYSLOTS-1 review M1 — **replace the relay's guess with the directory's fact.**
   *
   * The relay can only say "no token was presented"; the DIRECTORY knows why there was none, and
   * the two most useful answers point somewhere the relay's own advice does not. Left alone,
   * `online_token_required` tells the operator to check that their agent is reaching a directory —
   * which, in the `not_registered_here` case, it plainly is.
   */
  #withDirectoryCause(agentName: string, refusal: RelayAuthRefusal): RelayAuthRefusal {
    if (refusal.reason !== "online_token_required") return refusal;
    const absent = this.#directoryOnlineTokenAbsent.get(agentName);
    if (absent === "not_registered_here") {
      return {
        ...refusal,
        advice: "The directory this agent is connected to holds no profile for its key, so it " +
          "issued no token and no relay will grant a reservation. The directory connection itself " +
          "is fine — either this agent registered against a different sovereign node and its " +
          "profile has not replicated here yet, or it is not registered at all.",
      };
    }
    if (absent === "issue_failed") {
      return {
        ...refusal,
        advice: "The directory could not issue this agent a token — its own lookup or signing " +
          "failed. That is a fault on the directory, not on this agent or on any relay; it usually " +
          "clears on the next connection.",
      };
    }
    return refusal;
  }

  // DOD-LOOP-1: the standing receiver is PER-AGENT, not per-daemon. A daemon hosting two agents
  // (the loopback case) needs each agent to have its OWN inbound receiver node — otherwise the
  // initiator (consuming its agent's standing receiver) and the responder (consuming its agent's)
  // would contend for a single node and thrash. Keyed by agentName. A creation-in-flight guard set
  // prevents two concurrent ensure() calls from building two nodes for the same agent.
  // `relayPeerIds`: the relays this receiver holds an announced circuit through. The watchdog reads
  // it as a COUNT — zero tells "never had one" (already degraded, and already loud) apart from a
  // loss, and a drop that leaves it non-empty is a lost relay the agent can absorb without being
  // rebuilt. See #reservationWatchdogTick.
  /**
   * DOD-M12B-SESSION-SEED-1 — session id → the transport seed its node identity derives from.
   *
   * **DELIBERATELY NOT ON `ActiveSessionEntry`.** That entry is deleted the instant a session is
   * interrupted (`markInterruptedWithDetails` and `destroySessionNode` both do it), which is exactly
   * the moment the seed becomes necessary — storing it there would destroy it precisely when the
   * session needs to come back. It has to outlive the NODE without outliving the SESSION.
   *
   * Andre's 2026-08-18 tenet is the lifetime rule: *"it should be possible to revive that session on
   * those peer IDs. But after that, those peer IDs and that peer connection needs to be shut down."*
   * So this map is cleared in the same step that writes a terminal status (`#updateSessionStatus`),
   * not on a later sweep — and the bytes are zeroed before the reference is dropped, because a seed
   * that stays readable in the heap is exactly the "left open" the tenet forbids.
   *
   * It holds the counterparty's session peer id alongside the seed, and not for convenience: that
   * value lives ONLY on `ActiveSessionEntry` and is destroyed with it on interruption, so without a
   * copy here we could rebuild our own identity and still not know who to let back in. Both halves
   * of the revival have the same lifetime, so they are destroyed in one step.
   *
   * In memory only, never persisted. A daemon restart genuinely destroys these identities, which is
   * why restart is `RESTART-SEAL-1`'s case (resolve with a receipt) and not a revival case.
   */
  #sessionSeeds = new Map<string, SessionRevivalIdentity>();

  /** DOD-M12B-SESSION-SEED-1: see setRetryDrainHook — fired when a session is revived. */
  #retryDrainHook: ((agentName: string, sessionId: string) => void) | null = null;

  /**
   * 036-GODFILE Part 1 — WHO SENT THIS, AND DID THEY SEE WHAT THEY CLAIM.
   *
   * It owns the two maps it maintains (`#receivedFromCounterparty`, `#lastFromCounterparty`), which
   * nothing else in the daemon reads. Everything else it needs is listed explicitly in the context
   * object rather than handed over as `this` — the manager's private state stays private, and a
   * reader can see the whole of what authorship verification is allowed to touch in one place.
   *
   * ⚠️ BUILT IN THE CONSTRUCTOR, not as a field initializer. Field initializers run in declaration
   * order, and this one closes over `#logger`, so declaring it above `#logger` made it read an
   * uninitialized field — caught by tsc, and silent at runtime if it had been assigned later.
   */
  readonly #authorship: AuthorshipVerifier;

  /**
   * 036-GODFILE Parts 3+4 — everything that happens to an inbound message we will NOT deliver.
   *
   * It owns the five remote-fed maps it bounds. The manager used to clear them by hand in cache
   * eviction, which is why they are gone from here: a caller that had to know five field names
   * in order to forget a session knew too much, and a sixth would have been missed in silence.
   */
  readonly #refusals: InboundRefusals;

  /**
   * 036-GODFILE — contacts and tiers, agent settings, the transcript, and session divergence.
   *
   * Everything the daemon REMEMBERS about a conversation, as opposed to what it does with a
   * message in flight. Its context is five items, which is why it was a seam.
   */
  readonly #records: SessionRecords;

  /**
   * 036-GODFILE Part 6 — the relay store-and-forward mailbox: depositing content the counterparty
   * could not take live, recovering it when they return, and the backstop sweep that drains it
   * even when a trigger is missing.
   */
  readonly #park: ParkRecovery;

  /**
   * 037-SESSIONCORE Unit 1 — the per-session content salt, and the eleven maps it maintains.
   *
   * Those eleven were the largest single block of the twenty-four per-session containers that
   * `#evictSessionCaches` cleared by hand. They leave with the code that fills them.
   */
  readonly #salts: SessionSalts;

  /**
   * 037-SESSIONCORE — the methods that are SQL and nothing else.
   *
   * Grouped by SHAPE rather than subject: "holds no state, calls nothing but the agent-id lookup,
   * and actually touches the database" is a property a reader can check on any one of them
   * without knowing which subsystem it serves.
   *
   * ⚠️ THE `touches the database` CLAUSE IS LOAD-BEARING. A first pass grouped on "holds no state"
   * alone and swept in `#evictPeersOutsideGate`, which operates on libp2p connections and is not
   * SQL at all. A source-scanning parity test caught the mis-grouping; the filter now requires the
   * method to name `#db`.
   */
  readonly #queries: SessionQueries;

  /**
   * 037-SESSIONCORE — the refusals an operator can actually see.
   *
   * A refusal whose only consumer is the log is not a control: from the receiving operator's
   * chair the conversation just goes quiet, and they conclude the other person stopped replying.
   */
  readonly #notices: RefusalNotices;

  /**
   * 037-SESSIONCORE — the throwaway per-session keypair and the content key its halves agree.
   *
   * It owns the four maps that hold the secrets, which is the right place for them: the teardown
   * that ZEROES them lives beside the code that mints them, rather than being one line in a
   * cache-eviction method that has to remember every map in the class.
   */
  readonly #ephemerals: SessionEphemerals;

  /**
   * 037-SESSIONCORE — connection liveness, and the impairment that explains a degraded session.
   */
  readonly #liveness: SessionLiveness;

  /**
   * 037-SESSIONCORE — what a relay reported seeing, when it does not reconcile with our record.
   */
  readonly #witness: WitnessAlerts;

  /**
   * 037-SESSIONCORE — content we have verified but cannot show yet, because it arrived ahead of
   * a gap. The MAP stays shared: ingest, placeOwnLeaf and sealReadiness all read it, and two
   * sources of truth for "what are we holding" would be worse than one shared one.
   */
  readonly #held: HeldContent;

  /**
   * 037-SESSIONCORE — the two durable facts about a session's leaves: where the chain starts
   * (the genesis prev-root) and which leaves the directory attested.
   */
  readonly #leafRecords: SessionLeafRecords;

  /**
   * The hot path, in two halves — the message going out, and the message coming in. Together they
   * are the single largest piece that left this class.
   *
   * They are separate because they share almost nothing: outbound reaches nothing inbound at all,
   * and inbound reaches exactly one thing outbound (settling the acknowledgement for a message we
   * sent, which arrives on the stream the receiver is already reading). The seven methods further
   * down that delegate to them stay on this class because 451 call sites across the daemon and its
   * tests name them here; the rest of their surface is reached as `#contentIn.…` / `#contentOut.…`.
   */
  readonly #contentOut: SessionContentSender;
  readonly #contentIn: SessionContentIngest;

  // CELLO-M7-TRANSPORT-001: the directory-node multiaddrs serving as AutoNAT probers (SI-002).
  // Empty () => [] when the directory is in 'reconnecting' state — AutoNAT cannot run and
  // dialability stays the conservative default.
  readonly #autoNatProbers: () => string[];

  /**
   * 037-SESSIONCORE — the always-listening node, one per agent.
   *
   * Its maps are passed BY REFERENCE rather than moved: the reservation watchdog and the relay
   * paths still read them and stayed behind, and two sources of truth for "which agents have a
   * receiver" would be worse than one shared one.
   */
  readonly #receivers: StandingReceivers;

  /** ─── DELEGATORS — the standing-receiver API other files call ───────────────────────── */
  standingReceiverAbsenceReason(agentName: string): "daemon_shutting_down" | "standing_receiver_creating" | "agent_offline" | "no_standing_receiver" { return this.#receivers.standingReceiverAbsenceReason(agentName); }
  getStandingReceiverInfo(agentName: string): { peerId: string; addrs: string[] } | null { return this.#receivers.getStandingReceiverInfo(agentName); }
  getStandingReceiverReady(agentName?: string): boolean { return this.#receivers.getStandingReceiverReady(agentName); }
  getStandingReceiverNode(agentName?: string): CelloNode | null { return this.#receivers.getStandingReceiverNode(agentName); }
  getStandingReceiverReachability(agentName: string): "reserved" | "retrying" | "unreachable" | "absent" { return this.#receivers.getStandingReceiverReachability(agentName); }
  getStandingReceiverAutoNat(): IAutoNatService | null { return this.#receivers.getStandingReceiverAutoNat(); }
  getStandingReceiverAllowedPeer(agentName: string): string | null { return this.#receivers.getStandingReceiverAllowedPeer(agentName); }
  admitOfferedDialer(agentName: string, initiatorSessionPeerId: string, sessionIdHex: string): "narrowed" | "no_receiver" | "no_peer_named" { return this.#receivers.admitOfferedDialer(agentName, initiatorSessionPeerId, sessionIdHex); }
  getOfferedDialer(agentName: string, sessionIdHex: string): string | null { return this.#receivers.getOfferedDialer(agentName, sessionIdHex); }
  clearOfferedDialer(agentName: string, sessionIdHex: string): void { return this.#receivers.clearOfferedDialer(agentName, sessionIdHex); }
  revokeOfferedDialer(agentName: string, sessionIdHex: string, offeredPeerId: string | null): void { return this.#receivers.revokeOfferedDialer(agentName, sessionIdHex, offeredPeerId); }

  /** ─── DELEGATORS — the leaf-record API other files call ─────────────────────────────── */
recordSessionGenesis(agentName: string, sessionId: string, participantA: Uint8Array, participantB: Uint8Array, sessionTimestamp: number): void { return this.#leafRecords.recordSessionGenesis(agentName, sessionId, participantA, participantB, sessionTimestamp); }
  setSessionGenesisForTest(agentName: string, sessionId: string, genesis: Uint8Array): void { return this.#leafRecords.setSessionGenesisForTest(agentName, sessionId, genesis); }
  recordCertifiedLeafSet(agentName: string, sessionId: string, signedLeaves: readonly SealFrontierLeaf[], sealedRootHex: string, correlationId?: string): boolean { return this.#leafRecords.recordCertifiedLeafSet(agentName, sessionId, signedLeaves, sealedRootHex, correlationId); }
  noteCertifiedLeafSetUnavailable(agentName: string, sessionId: string, state: "not_carried_absent_party" | "not_carried_present_party", detail: string): void { return this.#leafRecords.noteCertifiedLeafSetUnavailable(agentName, sessionId, state, detail); }
  getCertifiedLeafSet(agentName: string, sessionId: string): string[] | null { return this.#leafRecords.getCertifiedLeafSet(agentName, sessionId); }
  getCertifiedLeafSetState(agentName: string, sessionId: string): { state: string; detail: string | null } | null { return this.#leafRecords.getCertifiedLeafSetState(agentName, sessionId); }

  /** ─── DELEGATORS — the held-content seams other files call ──────────────────────────── */
holdOwnLeafForTest(agentName: string, sessionId: string, canonicalSeq: number, contentHashHex: string): void { return this.#held.holdOwnLeafForTest(agentName, sessionId, canonicalSeq, contentHashHex); }

  /** ─── DELEGATORS — the witness-alert API other files call ────────────────────────────── */
  recordRelayWitnessAlert(agentName: string, alert: RelayWitnessAlert): void { return this.#witness.recordRelayWitnessAlert(agentName, alert); }
  getWitnessAlerts(agentName: string): ReadonlyArray<WitnessAlertNotice> { return this.#witness.getWitnessAlerts(agentName); }
  witnessAlertsTruncated(agentName: string): boolean { return this.#witness.witnessAlertsTruncated(agentName); }

  /** ─── DELEGATORS — the liveness API other files call, unchanged by the split ───────────── */
  getSessionLiveness(agentName: string, sessionId: string): "alive" | "impaired" | "gone" | "unknown" { return this.#liveness.getSessionLiveness(agentName, sessionId); }
  getSessionImpairment(agentName: string, sessionId: string): SessionImpairment | null { return this.#liveness.getSessionImpairment(agentName, sessionId); }
  markSessionLivenessForTest(agentName: string, sessionId: string, state: "alive" | "impaired" | "gone"): void { return this.#liveness.markSessionLivenessForTest(agentName, sessionId, state); }

  /** ─── DELEGATORS — the test seams other files call, unchanged by the split ─────────────── */
  mintSessionEphemeralForTest(agentName: string, sessionId: string): void { return this.#ephemerals.mintSessionEphemeralForTest(agentName, sessionId); }
  sessionEphemeralPublicForTest(agentName: string, sessionId: string): Uint8Array | null { return this.#ephemerals.sessionEphemeralPublicForTest(agentName, sessionId); }
  setSessionEphemeralForTest(agentName: string, sessionId: string, ephemeral: SessionEphemeral): void { return this.#ephemerals.setSessionEphemeralForTest(agentName, sessionId, ephemeral); }
  setSessionContentKeyForTest(agentName: string, sessionId: string, key: Uint8Array): void { return this.#ephemerals.setSessionContentKeyForTest(agentName, sessionId, key); }
  forgetSessionContentKeyForTest(agentName: string, sessionId: string): void { return this.#ephemerals.forgetSessionContentKeyForTest(agentName, sessionId); }
  async signOwnEphemeralForTest(agentName: string, sessionId: string): Promise<{ ephemeralPublic: Uint8Array; signature: Uint8Array } | null> { return this.#ephemerals.signOwnEphemeralForTest(agentName, sessionId); }
  async handleEphemeralFrameForTest(agentName: string, sessionId: string, frame: { ephemeralPublic?: Uint8Array; signature?: Uint8Array }, correlationId = "test"): Promise<void> { return this.#ephemerals.handleEphemeralFrameForTest(agentName, sessionId, frame, correlationId); }

  /** ─── DELEGATORS — the refusal-notice API other files call, unchanged by the split ────────── */
  noteContentRefusal(agentName: string, sessionId: string, reason: string, detail: { kind: RefusalKind; impact: string; guidance: string }): void { return this.#notices.noteContentRefusal(agentName, sessionId, reason, detail); }
  takeContentRefusals(agentName: string, sessionId: string, consumerId: string): Array<Omit<RefusalNotice, "sessionId">> { return this.#notices.takeContentRefusals(agentName, sessionId, consumerId); }
  dismissContentRefusals(agentName: string, sessionId: string): number { return this.#notices.dismissContentRefusals(agentName, sessionId); }
  takeAgentContentRefusals(agentName: string, consumerId: string): { notices: RefusalNotice[]; truncated: boolean } { return this.#notices.takeAgentContentRefusals(agentName, consumerId); }

  /**
   * ─── DELEGATORS — the query API other files call, unchanged by the split ────────────────────
   */
  listExpiredUnrevivableSessions(nowMs: number, windowMs: number): Array<{ agentName: string; sessionId: string; cause: string | null }> { return this.#queries.listExpiredUnrevivableSessions(nowMs, windowMs); }
  listRestartOrphanedSessions(): Array<{ agentName: string; sessionId: string; messageCount: number; status: "interrupted" | "seal_interrupted_pending" }> { return this.#queries.listRestartOrphanedSessions(); }
  readQuarantined(agentName: string, sessionId: string, sequence?: number): QuarantinedRecord[] { return this.#queries.readQuarantined(agentName, sessionId, sequence); }
  getPinnedCounterpartyPrimary(agentName: string, counterpartyPubkeyHex: string): string | null { return this.#queries.getPinnedCounterpartyPrimary(agentName, counterpartyPubkeyHex); }
  recordSealedAnnex(agentName: string, sessionId: string, contentHashHex: string, content: Uint8Array, senderPubkeyHex: string | null): boolean { return this.#queries.recordSealedAnnex(agentName, sessionId, contentHashHex, content, senderPubkeyHex); }
  findNextReceivedAfter(agentName: string, sessionId: string, afterSeq: number): { sequence: number; text: string } | null { return this.#queries.findNextReceivedAfter(agentName, sessionId, afterSeq); }
  getSealInterruptedArtifacts(agentName: string, sessionId: string): { role: string; ownLeaf: unknown; counterpartyLeaf: unknown; merkleRoot: string; nonce: string; } | null { return this.#queries.getSealInterruptedArtifacts(agentName, sessionId); }
  getSessionsByStatus(status: "active" | "sealed" | "interrupted"): SessionRecord[] { return this.#queries.getSessionsByStatus(status); }
  recordRefusedSession(agentName: string, sessionId: string, reason: string): void { return this.#queries.recordRefusedSession(agentName, sessionId, reason); }
  getAgentRelayEndpoints(agentName: string): Array<{ relayPeerId: string; relayAddrs: string[] }> { return this.#queries.getAgentRelayEndpoints(agentName); }
  countActiveSessionsFromUnknownSenders(agentName: string): number { return this.#queries.countActiveSessionsFromUnknownSenders(agentName); }
  getSealCertificate(agentName: string, sessionId: string): { sealed_root: string; legibility: unknown } | null { return this.#queries.getSealCertificate(agentName, sessionId); }
  setSessionName(agentName: string, sessionId: string, sessionName: string | null): boolean { return this.#queries.setSessionName(agentName, sessionId, sessionName); }
  getPersistedRelayEndpoint(agentName: string, sessionId: string): { relayPeerId: string; relayAddrs: string[] } | null { return this.#queries.getPersistedRelayEndpoint(agentName, sessionId); }
  markRestartSealGaveUp(agentName: string, sessionId: string, reason: string): void { return this.#queries.markRestartSealGaveUp(agentName, sessionId, reason); }
  dismissSession(agentName: string, sessionId: string): { ok: true } | { ok: false; reason: string } { return this.#queries.dismissSession(agentName, sessionId); }
  agentNameForId(agentId: string): string | null { return this.#queries.agentNameForId(agentId); }
  getRenameNotices(agentName: string): Array<{ pubkey: string; offered_name: string; noticed_at: number; moniker: string | null }> { return this.#queries.getRenameNotices(agentName); }

  sessionsConsumingCap(agentName: string, counterpartyPubkey: string, limit = 10): string[] { return this.#queries.sessionsConsumingCap(agentName, counterpartyPubkey, limit); }
  advanceLastDeliveredSeq(agentName: string, sessionId: string, seq: number): void { return this.#queries.advanceLastDeliveredSeq(agentName, sessionId, seq); }
  countActiveSessionsForCounterparty(agentName: string, counterpartyPubkey: string): number { return this.#queries.countActiveSessionsForCounterparty(agentName, counterpartyPubkey); }

  getSessionRecord(agentName: string, sessionId: string): SessionRecord | null { return this.#queries.getSessionRecord(agentName, sessionId); }
  hasDatabase(): boolean { return this.#queries.hasDatabase(); }
  readSealedAnnex(agentName: string, sessionId?: string): Array<{ session_id: string; content_hash: string; sender_pubkey: string | null; text: string; arrived_at: number }> { return this.#queries.readSealedAnnex(agentName, sessionId); }
  counterpartyAbandonedAt(agentName: string, sessionId: string): number | null { return this.#queries.counterpartyAbandonedAt(agentName, sessionId); }
  getSealedRootHex(agentName: string, sessionId: string): string | null { return this.#queries.getSealedRootHex(agentName, sessionId); }
  getLastDeliveredSeq(agentName: string, sessionId: string): number { return this.#queries.getLastDeliveredSeq(agentName, sessionId); }
  markSessionsInterruptedByLocalShutdownForTest(): void { return this.#queries.markSessionsInterruptedByLocalShutdownForTest(); }
  wasSessionRefused(agentName: string, sessionId: string): boolean { return this.#queries.wasSessionRefused(agentName, sessionId); }
  countReceivedMessages(agentName: string, sessionId: string): number { return this.#queries.countReceivedMessages(agentName, sessionId); }
  markInterruptedByCounterpartyForTest(agentName: string, sessionId: string): void { return this.#queries.markInterruptedByCounterpartyForTest(agentName, sessionId); }
  recordSealCertificate(agentName: string, sessionId: string, sealedRootHex: string, legibilityJson: string): void { return this.#queries.recordSealCertificate(agentName, sessionId, sealedRootHex, legibilityJson); }
  recordCounterpartyPrimary(agentName: string, sessionId: string, primaryPubkeyHex: string): void { return this.#queries.recordCounterpartyPrimary(agentName, sessionId, primaryPubkeyHex); }

  /**
   * ─── DELEGATORS — the salt API other files call, unchanged by the split ─────────────────────
   *
   * `daemon.ts` and `session-content-handlers.ts` still say `manager.contentHashForSession(...)`.
   * Keeping the surface identical is what lets the suite stand as evidence that this was a
   * restructure and not a rewrite.
   */
  setSaltContributionForTest(agentName: string, sessionId: string, contribution: Uint8Array): void { return this.#salts.setSaltContributionForTest(agentName, sessionId, contribution); }
  forgetSaltContributionForTest(agentName: string, sessionId: string): void { return this.#salts.forgetSaltContributionForTest(agentName, sessionId); }
  async contentHashForSession(agentName: string, sessionId: string, content: Uint8Array): Promise<{ hash: Uint8Array; alg: ContentHashAlg }> { return this.#salts.contentHashForSession(agentName, sessionId, content); }
  abandonUnsaltedHash(agentName: string, sessionId: string): void { return this.#salts.abandonUnsaltedHash(agentName, sessionId); }
  isContentSaltActive(agentName: string, sessionId: string): boolean { return this.#salts.isContentSaltActive(agentName, sessionId); }  // Seams for the teardown-must-settle regression (037-SESSIONCORE): arm a pending salt
  // agreement, then observe the outcome a dropped promise would leave unreachable.
  markSaltPendingForTest(agentName: string, sessionId: string): void { return this.#salts.markSaltPending(agentName, sessionId); }
  saltForHashingForTest(agentName: string, sessionId: string): Promise<{ salt: Uint8Array | null; reason?: string }> { return this.#salts.saltForHashing(agentName, sessionId); }

  /**
   * ─── DELEGATORS — the mailbox API other files call, unchanged by the split ───────────────────
   *
   * `content-park.ts` and `daemon.ts` still say `manager.recoverParkedEntry(...)` and
   * `manager.setContentParkHook(...)`. Keeping the surface identical is what lets the full suite
   * stand as evidence that this was a move: a caller that had to change would mean the contract
   * moved with it.
   */
  injectParkFault(count: number, cause?: string): number { return this.#park.injectParkFault(count, cause); }
  getParkFaultRemaining(): number { return this.#park.getParkFaultRemaining(); }
  setContentParkHook(fn: (args: { agentName: string; sessionId: string; recipientPubkeyHex: string; relayPeerId: string; relayAddrs: readonly string[]; contentHashHex: string; content: Uint8Array; structure1Cbor?: Uint8Array; structure2Cbor?: Uint8Array; structure1Signature?: Uint8Array; leafKind?: number; contentHashAlg: string | undefined }) => Promise<{ ok: true } | { ok: false; reason: string; cause?: string; retryAfterMs?: number }>): void { return this.#park.setContentParkHook(fn); }
  setParkedDrainHook(fn: (agentName: string, reason: ParkedDrainReason) => void): void { return this.#park.setParkedDrainHook(fn); }
  recoverOwnSealCtrlLeafForTest(agentName: string, sessionId: string): { reportedRootHex: string; sequenceNumber: number } | "none" | "unknown" { return this.#park.recoverOwnSealCtrlLeafForTest(agentName, sessionId); }
  async recoverParkedEntry(agentName: string, sessionId: string, recipientPubkey: Uint8Array, unsealed: Uint8Array, contentHash: Uint8Array, correlationId?: string): Promise< | { ok: true; leafIndex: number; sequenceNumber: number; held?: boolean; appendedCount?: number; screenedOut?: boolean } | { ok: false; reason: string } > { return this.#park.recoverParkedEntry(agentName, sessionId, recipientPubkey, unsealed, contentHash, correlationId); }

  /**
   * ─── DELEGATORS — the class API is unchanged by the split, deliberately ──────────────────────
   *
   * Every method below moved into `session-records.ts` with its implementation and its comments.
   * These one-liners exist so that no CALLER had to change: `contact-handlers.ts`, the IPC surface
   * and the tests all still say `manager.getTier(...)`. That is what lets the full suite stand as
   * the evidence that this was a move and not a rewrite — a test that had to change would have
   * meant behaviour moved (Rule B).
   *
   * They are the price of the split and they are the cheap half: one line each, no logic, and the
   * prose that explains each rule lives beside the code that enforces it.
   */
  isContact(agentName: string, pubkey: string): boolean { return this.#records.isContact(agentName, pubkey); }
  getTier(agentName: string, pubkey: string): number { return this.#records.getTier(agentName, pubkey); }
  resolveTierBound(agentName: string, tier: number, field: "max_sessions" | "max_bytes"): number { return this.#records.resolveTierBound(agentName, tier, field); }
  addContact(agentName: string, pubkey: string, moniker?: string | null, provenance?: string | null, tier: number = TIER.UNKNOWN): void { return this.#records.addContact(agentName, pubkey, moniker, provenance, tier); }
  setContactMoniker(agentName: string, pubkey: string, moniker: string | null): boolean { return this.#records.setContactMoniker(agentName, pubkey, moniker); }
  setContactSignalPref(agentName: string, pubkey: string, signalHash: string, present: boolean | null): void { return this.#records.setContactSignalPref(agentName, pubkey, signalHash, present); }
  getContactSignalPrefs(agentName: string, pubkey: string): Map<string, boolean> { return this.#records.getContactSignalPrefs(agentName, pubkey); }
  setContactAwayMessage(agentName: string, pubkey: string, message: string | null): boolean { return this.#records.setContactAwayMessage(agentName, pubkey, message); }
  setContactTier(agentName: string, pubkey: string, tier: number): boolean { return this.#records.setContactTier(agentName, pubkey, tier); }
  recordOfferedMoniker(agentName: string, pubkey: string, offered: string): void { return this.#records.recordOfferedMoniker(agentName, pubkey, offered); }
  removeContact(agentName: string, pubkey: string): boolean { return this.#records.removeContact(agentName, pubkey); }
  getContactMoniker(agentName: string, pubkey: string): string | null { return this.#records.getContactMoniker(agentName, pubkey); }
  listContacts(agentName: string): Array<{ pubkey: string; added_at: number; moniker: string | null; tier: number | null; provenance: string | null; sealed_count: number; last_spoke: number | null; }> { return this.#records.listContacts(agentName); }
  clearRenameNotice(agentName: string, pubkey: string): void { return this.#records.clearRenameNotice(agentName, pubkey); }
  clearPinnedCounterpartyPrimary(agentName: string, counterpartyPubkeyHex: string): number { return this.#records.clearPinnedCounterpartyPrimary(agentName, counterpartyPubkeyHex); }
  getTelegramSettings(): { botToken: string; allowlistedChatId: string } | null { return this.#records.getTelegramSettings(); }
  setTelegramSettings(botToken: string, allowlistedChatId: string): void { return this.#records.setTelegramSettings(botToken, allowlistedChatId); }
  getSetting(agentName: string, key: string): string | null { return this.#records.getSetting(agentName, key); }
  deleteSetting(agentName: string, key: string): boolean { return this.#records.deleteSetting(agentName, key); }
  setSetting(agentName: string, key: string, value: string): void { return this.#records.setSetting(agentName, key, value); }
  getAllSettings(agentName: string): Array<{ key: string; value: string }> { return this.#records.getAllSettings(agentName); }
  recordRelayWitnessUnreadable(agentName: string, relayPeerId: string, why: string): void { return this.#records.recordRelayWitnessUnreadable(agentName, relayPeerId, why); }
  getWitnessUnreadable(agentName: string): ReadonlyArray<{ relayPeerId: string; why: string; count: number }> { return this.#records.getWitnessUnreadable(agentName); }
  recordTranscriptMessage(agentName: string, sessionId: string, sequence: number, direction: "sent" | "received" | "quarantined", plaintext: Uint8Array, correlationId?: string, authorship?: { senderPubkey: Uint8Array; senderSig: Uint8Array }, quarantineReason?: string, senderPubkeyHexOverride?: string | null): boolean { return this.#records.recordTranscriptMessage(agentName, sessionId, sequence, direction, plaintext, correlationId, authorship, quarantineReason, senderPubkeyHexOverride); }
  readTranscript(agentName: string, sessionId: string): { messages: TranscriptEntry[]; undecryptable: number } { return this.#records.readTranscript(agentName, sessionId); }
  getUnreadSummary(agentName: string): Array<{ session_id: string; unread_count: number; last_seq: number }> { return this.#records.getUnreadSummary(agentName); }
  getEndedUnread(agentName: string): Array<{ session_id: string; unread_count: number; last_seq: number; status: string }> { return this.#records.getEndedUnread(agentName); }
  getUnreadReceivedCount(agentName: string, sessionId: string): number { return this.#records.getUnreadReceivedCount(agentName, sessionId); }
  markSessionDiverged(agentName: string, sessionId: string): void { return this.#records.markSessionDiverged(agentName, sessionId); }
  isSessionDiverged(agentName: string, sessionId: string): boolean { return this.#records.isSessionDiverged(agentName, sessionId); }

  /** DOD-M12B-LEAF-TRIGGERS-FETCH-1: content hashes this session has actually resolved — ingested,
   *  held, or authored by us. A witnessed leaf whose hash is in here needs no fetch. */
  #resolvedContent = new Map<string, Set<string>>();

  /** In-flight grace timers, keyed session+hash, so a redelivered leaf does not schedule a second
   *  fetch for the same content — a slow relay must not be turned into a storm against itself. */
  #leafFetchTimers = new Map<string, ReturnType<typeof setTimeout>>();

  /** Test seam: collapse the grace window so a test does not have to wait two real seconds. The
   *  window itself is covered by its own case. */
  #leafFetchGraceMs = LEAF_FETCH_GRACE_MS;

  #standingReceivers = new Map<string, { node: CelloNode; gater: SessionConnectionGater; autoNat: NodeAutoNatService; /** DOD-M12B-SESSION-SEED-1: this receiver's transport seed; follows the node into the session at handoff. */ seed: Uint8Array; /** 032-RELAYSPREAD: every relay this receiver holds a live circuit reservation with. Empty means unreachable behind NAT. Replaces `hasReservation` plus one `relayPeerId`, which together could not describe a receiver holding two. */ relayPeerIds: string[] }>();
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
  #srReservationRetryMs: number;
  /**
   * DOD-M12B-RESERVATION-RETRY-1: per-agent re-attempt state for a receiver the relay refused a
   * reservation to. `attempts` counts RETRIES, not the creation attempt.
   */
  /** The reason the last reservation attempt was refused, per agent — captured at the rejection so
   *  the retry and give-up can name a CAUSE instead of only their own exit point. */
  readonly #srLastRejectionReason = new Map<string, string>();
  /** 032-RELAYSPREAD: when this agent's receiver was last re-spread, so it never rides the 30s grid. */
  readonly #srLastRespreadAt = new Map<string, number>();
  readonly #srReservationRetry = new Map<string, { attempts: number; nextAt: number; correlationId: string; lastReason?: string }>();
  #reservationWatchdog: ReturnType<typeof setInterval> | null = null;

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

  // M7-SESSION-003: per-session direct-path counterparty liveness, observed on the
  // session node's onPeerConnect ('alive') / onPeerDisconnect ('gone'). This is
  // the liveness authority for direct sessions (relay sessions query the relay
  // instead). NEVER the directory (SI-002). Read by exactly three consumers: the
  // half-open reaper, both status surfaces, and cello_receive. No seal path reads
  // it — the coupling to sealing runs through the receive guidance, which turns
  // 'gone' into "call cello_close_session".
  // DOD-M12B-ACK-1 adds 'impaired': connection up, our writes on it failing. It sits BELOW
  // 'alive' and never above 'gone' — see #markSessionImpaired.

  // DOD-M12B-ACK-1: WHY a session is impaired and what became of the content. Separate from the
  // state above because the state is what surfaces print and this is what they must explain.

  // DOD-M12B-STRAND-1: sessions whose durable holds have been read back. One read per session per
  // process; the Map is the working copy from then on.

  // DOD-M12B-SEAL-STUCK-1: sessions whose post-restore release has been attempted. Separate from
  // #heldRestored so a READ-ONLY probe can hydrate without performing (or consuming) the release.

  // DOD-M12B-SEAL-STUCK-1: sessions whose ordering state THIS PROCESS has observed — a relay
  // witness recorded for it. `#witnessedSeq` is memory-only, so for a session that predates this
  // daemon "no gap recorded" means "not recorded", not "no gap", and that difference decides
  // whether we may tell an operator the session is safe to close.
  #orderingObserved = new Set<string>();
  // DOD-M12B-INDEX-1: sessions whose tree and whose relay counter have provably parted. A diverged
  // session can never produce a root the counterparty agrees with, so it must never be reported as
  // safe to close — the close would be signed, refused as `leaf_count_mismatch`, and the receipt
  // lost for good.

  // DOD-M15-FRAME-1 (review F1): sessions frozen because a frame failed to verify against the
  // expected counterparty. Consulted by `reviveSessionNode` — a teardown writes `interrupted`,
  // which is the REVIVABLE status, so without this the next `cello_receive` silently rebuilt the
  // session and re-admitted the same peer. NOT cleared by `#evictSessionCaches`: the freeze is a
  // fact about the session, not about the node that was torn down to enforce it.
  //
  // DOD-M15-SEALWIRE-1 (part A): a MAP, not a Set, and the value is load-bearing. It was a Set when
  // the identity freeze was the only freeze, so `reviveSessionNode` could hardcode its refusal —
  // *"a message failed to verify against the expected counterparty's key"*. A salt disagreement now
  // freezes through the same path, and that sentence would accuse a counterparty who did nothing:
  // the ordinary cause is two builds that do not match. The refusal carries the freezing site's own
  // words instead.
  #frozenSessions = new Map<string, { reason: string; guidance: string }>();

  /**
   * Resolve an agent's long-term identity signer.
   *
   * Injected after construction, like `setParkedDrainHook`, because the daemon builds its agent key
   * providers after this manager exists. Absent resolver, or an agent it does not know, means this
   * side cannot sign its ephemeral — reported as `NO_LOCAL_IDENTITY` rather than quietly skipping
   * the exchange, because "we could not" and "they would not" send the operator to opposite
   * machines.
   */
  #keyProviderResolver: ((agentName: string) => KeyProvider | undefined) | null = null;
  /** Test-only observer of decoded inbound content frames — see `observeInboundContentFramesForTest`. */
  #inboundFrameObserver: ((frame: Record<string, unknown>) => void) | null = null;

  // DOD-M12B-ACK-1: pending linger-resets for inbound content streams the peer has not closed.
  // Held so shutdown can drop them rather than leave timers pointing at a torn-down node.
  #lingeringStreams = new Set<ReturnType<typeof setTimeout>>();
  // M7-UPGRADE-002: sessions whose content integrity could NOT be verified (a content_hash
  // mismatch = tamper was observed). The auto-acknowledge gate (SI-002) refuses to auto-co-sign
  // for a desynced session — B must never blind-sign a tail it cannot verify. Keyed by sessionId hex.
  //
  // DOD-M15-SEALWIRE-1 part B1 (review F1): a MAP, not a Set, and the value is the whole fix.
  //
  // It was a Set because a content_hash mismatch was the only way in, so "present" could mean
  // "tampered". B1 added two more ways for a frame to fail verification — an algorithm we cannot
  // read, and a salted frame we hold no salt for — and BOTH ARE ORDINARY. An honest peer on a newer
  // build produces the first. So the gate must still fire (never sign content you could not verify)
  // while the LABEL must not accuse anyone: `unverifiable` is not `tampered`.
  //
  // One structure with two labels rather than two sets, deliberately: a second set is a second thing
  // for every gate to remember to consult, and the one that gets forgotten is the one that matters.
  #contentDesynced = new Map<string, "tampered" | "unverifiable">();

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
  /**
   * DOD-M15-SEALWIRE-1 bullet 5 — `authorship` rides the held entry.
   *
   * A SENT message that lands ahead of our tree tail is held here and its transcript row is written
   * later, on release. The hold happens AFTER the submit, so it was signed exactly like an unheld
   * one — without carrying the proof through, a message that happened to queue behind a gap became
   * permanently less provable than the identical message that did not, for a reason with nothing to
   * do with authorship.
   */
  /**
   * 033-ACKEMIT review F1 — what this side has ACTUALLY RECEIVED, per session: the canonical
   * position and the content hash at it.
   *
   * ⚠️ **IT MIRRORS THE RELAY CLIENT'S `#lastSeen` RATHER THAN REPLACING IT, and the duplication is
   * deliberate.** The submit path needs the value on the client, because that is where the claim is
   * built; the unwitnessed content path needs it here, because a session with no relay client has no
   * client to read it from. Both are written from ONE place — `#noteAcknowledgeable` below — so they
   * cannot come to disagree, and the client is preferred on read because it also sees leaves the
   * relay delivered that never came through this path.
   */
  #lastAck = new Map<string, { seq: number; hash: Uint8Array }>();
  #heldContent = new Map<string, Map<number, HeldEntry>>();
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
  /**
   * ⚠️ THE RETURN TYPE USED TO DECLARE `ok?: boolean; reason?: string`, AND THE PRODUCER CANNOT
   * SUPPLY EITHER. Narrowed so reading them is a compile error rather than a silent `undefined`.
   *
   * The implementation is `DocumentFrameRouter.routeSync`, whose own return type
   * (`FrameClassification`) is exactly `{consumed:false} | {consumed:true; kind}` — it has no such
   * fields at all. The wider shape here was a promise only this declaration made, and it was
   * assignable precisely because the extra members were optional.
   *
   * It is not an oversight in the router: `routeSync` dispatches with `void this.#enqueue(...)`, so
   * when it returns, the frame has been classified and queued and **no verdict exists yet**. A
   * synchronous caller cannot be told an asynchronous outcome.
   *
   * **The cost of the lie was a wrong lead.** `j-stale-session`'s investigation read those fields'
   * absence from every log line as "the router returned neither" and filed it as the next thread to
   * pull. There was no thread: a JSON logger omits `undefined`, so a field that can never be set is
   * indistinguishable from one that was set to nothing. The verdict lives on
   * `document.frame.refused`, joined by `correlationId`.
   */
  #onDocumentFrame:
    | ((
        agentName: string,
        sessionId: string,
        content: Uint8Array,
        senderPubkey: string,
        correlationId?: string,
      ) => { consumed: boolean; kind?: string })
    | null = null;
  /**
   * DOD-DOC-SCREEN-CLASSIFY-1: the classify-only half of the hook above — is this a document
   * frame, deciding nothing else. Injected together with it so the two cannot disagree about what
   * a document frame is. Null means every frame takes the full inbound screen, exactly as before
   * the document layer existed.
   */
  #isDocumentFrame: ((content: Uint8Array) => boolean) | null = null;

  // A send is NOT fire-and-forget. After a content_frame is delivered over the direct session
  // channel, the sender arms a TTF timer and waits for an unsigned, transport-authenticated
  // `persisted` delivery ACK on the same /cello/content/1.0.0 protocol. A persisted ACK cancels the
  // timer (content.delivery.acked); TTF expiry hands the content to the park backstop.
  // Keyed sessionId → contentHashHex → entry.
  #awaitingAck = new Map<string, Map<string, AwaitingAckEntry>>();
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
  #onAwaitingTtf: ((agentName: string, sessionId: string, contentHashHex: string, content: Uint8Array, structure1Cbor?: Uint8Array, structure2Cbor?: Uint8Array, contentHashAlg?: string, structure1Signature?: Uint8Array, leafKind?: number) => void) | null = null;
  // M12-P12 verification: force the next N park deposits to be REFUSED, so the failure this unit
  // fixes can be produced on demand instead of waited for. The real failure is a race — the deposit
  // is refused only in the seconds-long window while the sender's standing receiver rebuilds — and
  // no CLI lever reaches that window: set-agent-offline leaves an open session's node serving, and
  // the CLI refuses a send from an offline agent. Without this the fix ships unwatched.
  // INERT unless the daemon is started with CELLO_FAULT_INJECTION=1; the IPC handler that sets it
  // refuses outright otherwise, so a normal daemon cannot be talked into dropping messages.

  // The incident needs BOTH halves: the direct dial has to fail (or the park path is never entered
  // — measured, the counterparty's session node accepts the frame and reports delivered:true even
  // with its agent away), and the park deposit that follows has to be refused. One without the
  // other reproduces nothing.
  #sendFaultRemaining = 0;
  // DOD-M12B-ACK-1 — the same seam for the delivery-ACK write. See injectAckFault.
  #ackFaultRemaining = 0;
  // DOD-M12B-REDIAL-1 — makes the next N `newStream` calls report the connection as gone, BEFORE
  // the node is touched. The sibling of injectSendFault for the one condition that used to end a
  // conversation permanently; a real connection drop is not reproducible in-process.
  #connectionLossRemaining = 0;
  // DOD-M12B-REDIAL-1: the counterparty addresses this session dialled, kept so it can dial them
  // again. They arrived in the FROST-signed assignment and were used once and dropped, which is
  // why nothing could ever re-dial.
  #counterpartyAddrs = new Map<string, string[]>();
  // DOD-M12B-REDIAL-1: when this session may next attempt a re-dial. Continuous re-dialling is what
  // produced the 2026-08-17 notification storm, so a burst of sends against a peer that is gone
  // costs one attempt, not one per message.
  #redialNotBefore = new Map<string, number>();

  /** Arm the direct-send fault — makes the next N sends take the dial-failure path. */
  injectSendFault(count: number): number {
    this.#sendFaultRemaining = Math.max(0, count);
    return this.#sendFaultRemaining;
  }

  /** DOD-M12B-ACK-1: arm the delivery-ACK write fault — the sibling of injectSendFault for the
   *  path that fails on a LISTENING agent. Without it the ACK failure branch (which impairs the
   *  session and, until this milestone, could never clear it again) is unreachable from a test:
   *  a listener sends no content, so the direct-send fault never fires for it. */
  injectAckFault(count: number): number {
    this.#ackFaultRemaining = Math.max(0, count);
    return this.#ackFaultRemaining;
  }

  /** DOD-M12B-REDIAL-1: arm the connection-loss fault — the next N direct sends find no open
   *  connection, exactly as they do after any blip. See #connectionLossRemaining. */
  injectConnectionLoss(count: number): number {
    this.#connectionLossRemaining = Math.max(0, count);
    return this.#connectionLossRemaining;
  }

  // M12-P12: the durable enqueue for a park deposit that FAILED. Distinct from onTtf because the
  // cause is distinct — nothing timed out here, the deposit was refused — and an event named for
  // the wrong cause is how this path stayed invisible.
  // M12-P13 (review HIGH-1): returns whether the content is ACTUALLY queued. `false` means the
  // queue dropped it (today: the content-derived dedupe key collided), and the caller must then not
  // claim durability — nor commit the leaf that claim now authorises.
  #onParkFailed: ((agentName: string, sessionId: string, contentHashHex: string, content: Uint8Array, structure1Cbor?: Uint8Array, structure2Cbor?: Uint8Array, contentHashAlg?: string, structure1Signature?: Uint8Array, leafKind?: number) => boolean) | null = null;

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
     * DOD-M12B-RESERVATION-RETRY-1: base delay before re-attempting a circuit reservation the relay
     * refused. Doubles per attempt. Default 5 minutes — deliberately NOT the watchdog's grid, because
     * a reservation is a scarce resource the relay holds for its full TTL and churning attempts is
     * how a fleet exhausts one.
     */
    standingReceiverReservationRetryMs?: number;
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

    // ⚠️ CHECKED AND ASSIGNED FIRST, ahead of every collaborator, because the content pipeline
    // built below is handed this client by value and a constructor cannot hand out a field it has
    // not set yet. Moving it up also means a caller that forgot to screen is told so before the
    // manager builds anything, rather than after.
    if (!opts.securityGateway) {
      throw new Error(
        "SessionNodeManager: securityGateway is required (INV-9). The inbound screen has no " +
          "always-allow fallback, because that fallback is how the entire security layer shipped " +
          "inert. Pass a real client, or new PassthroughGatewayClient() from a test that " +
          "deliberately does not screen.",
      );
    }
    this.#securityGateway = opts.securityGateway;

    // ⚠️ BUILT FIRST, AND THE ORDER IS LOAD-BEARING: `#authorship` and `#refusals` close over
    // `this.#records`. Nothing invokes them during construction today (every context member is a
    // lazy arrow), but tsc caught this exact class once on `#logger`, and the next line added to
    // this constructor is the one that would pay for it.
    this.#records = new SessionRecords({
      logger: this.#logger,
      db: () => this.#db,
      sessionKey: (a, sid) => this.#k(a, sid),
      requireAgentId: (a) => this.#requireAgentId(a),
      witnessUnreadable: this.#witnessUnreadable,
    });
    this.#authorship = new AuthorshipVerifier({
      logger: this.#logger,
      sessionKey: (a, sid) => this.#k(a, sid),
      getSessionRecord: (a, sid) => this.#queries.getSessionRecord(a, sid),
      getSessionTree: (a, sid) => this.getSessionTree(a, sid),
      isSessionDiverged: (a, sid) => this.#records.isSessionDiverged(a, sid),
      sessionGenesisPrevRoot: (a, sid) => this.#leafRecords.sessionGenesisPrevRoot(a, sid),
      relaySessionIdBytes: (a, sid) => this.#activeNodes.get(this.#k(a, sid))?.relaySessionIdBytes,
      heldContentFor: (a, sid) => this.#heldContent.get(this.#k(a, sid)),
    });

    this.#refusals = new InboundRefusals({
      logger: this.#logger,
      // A function, not a value: the database is opened after construction, so a snapshot taken
      // here would be null for the life of the process.
      db: () => this.#db,
      sessionKey: (a, sid) => this.#k(a, sid),
      requireAgentId: (a) => this.#requireAgentId(a),
      cancelLeafFetch: (key, hashHex) => this.#contentIn.cancelLeafFetch(key, hashHex),
      noteContentRefusal: (a, sid, reason, detail) => this.#notices.noteContentRefusal(a, sid, reason, detail),
      recordTranscriptMessage: (...args) => this.#records.recordTranscriptMessage(...args),
      recordWitnessedSequence: (a, sid, h, n) => this.recordWitnessedSequence(a, sid, h, n),
      getTier: (a, pk) => this.#records.getTier(a, pk),
      resolveTierBound: (a, t, f) => this.#records.resolveTierBound(a, t, f),
      mailboxRouteAvailable: (a) => this.#mailboxRouteAvailable(a),
      receivedBytesTotal: (a, sid) => this.#queries.getReceivedBytesTotal(a, sid),
      verifyAuthorshipClaim: (a, sid, s1, sig, h) => this.#authorship.verifyAuthorshipClaim(a, sid, s1, sig, h),
    });

    this.#park = new ParkRecovery({
      logger: this.#logger,
      refusals: this.#refusals,
      shuttingDown: () => this.#shuttingDown,
      sessionKey: (a, sid) => this.#k(a, sid),
      requireAgentId: (a) => this.#requireAgentId(a),
      ownPubkeyHex: (a) => this.#queries.ownPubkeyHex(a),
      activeEntry: (key) => this.#activeNodes.get(key),
      agentsWithLiveReceiver: () => this.#standingReceivers.keys(),
      agentWantsReceiver: (a) => this.#agentsWantingReceiver.has(a),
      getSessionRecord: (a, sid) => this.#queries.getSessionRecord(a, sid),
      getSealCarry: (pk, sid) => this.getSealCarry(pk, sid),
      getSessionTree: (a, sid) => this.getSessionTree(a, sid),
      recordOrderingRecord: (a, sid, s1, s2, h, cid) => this.recordOrderingRecord(a, sid, s1, s2, h, cid),
      ingestReceivedContent: (a, sid, c, h, cid, seq, alg) => this.ingestReceivedContent(a, sid, c, h, cid, seq, alg),
      witnessReceivedLeaf: (a, sid, h, s1, sig, kind, cid) => this.#contentIn.witnessReceivedLeaf(a, sid, h, s1, sig, kind, cid),
      noteAcknowledgeable: (a, sid, seq, h) => this.#contentIn.noteAcknowledgeable(a, sid, seq, h),
    }, opts.parkedDrainBackstopMs ?? 300_000);

    this.#salts = new SessionSalts({
      logger: this.#logger,
      db: () => this.#db,
      sessionKey: (a, sid) => this.#k(a, sid),
      requireAgentId: (a) => this.#requireAgentId(a),
      activeEntry: (key) => this.#activeNodes.get(key),
      getSessionTree: (a, sid) => this.getSessionTree(a, sid),
      getSessionRecord: (a, sid) => this.#queries.getSessionRecord(a, sid),
      heldContentFor: (key) => this.#heldContent.get(key),
      ensureHeldRestored: (a, sid, opts) => this.#held.ensureHeldRestored(a, sid, opts),
      awaitingAck: this.#awaitingAck,
      contentEncryptionState: (a, sid) => this.#ephemerals.contentEncryptionState(a, sid),
      freezeSession: (a, sid, reason, narrative, cid) => this.#freezeSession(a, sid, reason, narrative, cid),
      sendSaltFrame: (a, sid, cid, override) => this.#sendSaltFrame(a, sid, cid, override),
    });

    this.#queries = new SessionQueries({
      logger: this.#logger,
      db: () => this.#db,
      requireAgentId: (a) => this.#requireAgentId(a),
      sessionKey: (a, sid) => this.#k(a, sid),
      unkey: (key, agentName) => this.#unk(key, agentName),
    });

    this.#notices = new RefusalNotices({
      logger: this.#logger,
      queries: this.#queries,
      db: () => this.#db,
      requireAgentId: (a) => this.#requireAgentId(a),
      sessionKey: (a, sid) => this.#k(a, sid),
      unkey: (key, agentName) => this.#unk(key, agentName),
    });

    this.#ephemerals = new SessionEphemerals({
      logger: this.#logger,
      sessionKey: (a, sid) => this.#k(a, sid),
      activeEntry: (key) => this.#activeNodes.get(key),
      keyProvider: (a) => this.#keyProviderResolver?.(a),
      freezeSessionForKeyRefusal: (a, sid, reason, cid) => this.#freezeSessionForKeyRefusal(a, sid, reason, cid),
    });

    this.#liveness = new SessionLiveness({
      logger: this.#logger,
      queries: this.#queries,
      notices: this.#notices,
      ephemerals: this.#ephemerals,
      counterpartyAddrs: this.#counterpartyAddrs,
      sessionKey: (a, sid) => this.#k(a, sid),
      activeEntry: (key) => this.#activeNodes.get(key),
      sendSaltFrame: (a, sid, cid, override) => this.#sendSaltFrame(a, sid, cid, override),
    });

    this.#witness = new WitnessAlerts({ logger: this.#logger });

    this.#held = new HeldContent({
      logger: this.#logger,
      queries: this.#queries,
      records: this.#records,
      db: () => this.#db,
      sessionKey: (a, sid) => this.#k(a, sid),
      requireAgentId: (a) => this.#requireAgentId(a),
      heldContent: this.#heldContent,
      witnessedSeq: this.#witnessedSeq,
      getSessionTree: (a, sid) => this.getSessionTree(a, sid),
      appendSessionLeaf: (a, sid, kind, h, cid) => this.appendSessionLeaf(a, sid, kind, h, cid),
      appendVerifiedContent: (a, sid, c, h, pk, cid, orig, auth) => this.#contentIn.appendVerifiedContent(a, sid, c, h, pk, cid, orig, auth),
    });

    this.#leafRecords = new SessionLeafRecords({
      logger: this.#logger,
      queries: this.#queries,
      db: () => this.#db,
      sessionKey: (a, sid) => this.#k(a, sid),
      requireAgentId: (a) => this.#requireAgentId(a),
      activeEntry: (key) => this.#activeNodes.get(key),
    });

    /**
     * ⚠️ **CONSTRUCTED LAST OF THE COLLABORATORS, and the reason is the same one written above
     * `#records`:** every collaborator below is handed to it BY VALUE, so each has to already
     * exist. `#receivers` is built after this and is not reachable from the content path.
     *
     * `mgr` exists because the getters below need the MANAGER's fields, and a getter written in an
     * object literal binds `this` to the literal. The alternative — capturing the values — is the
     * defect that once left `keyProvider` frozen at `null`, so signing stopped and sessions fell
     * back to unencrypted content with the whole suite green. Anything the manager can REPLACE
     * after this line is reached through a getter; anything it cannot is passed straight through.
     */
    // The rule is right about the pattern it was written for — `var self = this` standing in for a
    // closure. This is the one case the language forces: a `get` in an object literal binds `this`
    // to the LITERAL, so a getter cannot reach the manager's fields without a name for it. The
    // alternative is passing the values, which is the defect this whole block exists to avoid.
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const mgr = this;
    const contentCtx: SessionContentPipelineContext = {
      logger: this.#logger,
      securityGateway: this.#securityGateway,

      records: this.#records,
      authorship: this.#authorship,
      refusals: this.#refusals,
      park: this.#park,
      salts: this.#salts,
      queries: this.#queries,
      notices: this.#notices,
      ephemerals: this.#ephemerals,
      liveness: this.#liveness,
      held: this.#held,
      leafRecords: this.#leafRecords,

      // One Map object each, shared — never a copy. See the context's own note.
      activeNodes: this.#activeNodes,
      awaitingAck: this.#awaitingAck,
      heldContent: this.#heldContent,
      witnessedSeq: this.#witnessedSeq,
      leafFetchTimers: this.#leafFetchTimers,
      lastAck: this.#lastAck,
      receivedContent: this.#receivedContent,
      resolvedContent: this.#resolvedContent,
      undeliverableSeqs: this.#undeliverableSeqs,
      highWaterSeq: this.#highWaterSeq,
      counterpartyAddrs: this.#counterpartyAddrs,
      lingeringStreams: this.#lingeringStreams,
      redialNotBefore: this.#redialNotBefore,
      orderingObserved: this.#orderingObserved,

      // Settable after this point — `#contentTtfMs` is overridden from `opts` three lines below.
      get shuttingDown() { return mgr.#shuttingDown; },
      get contentTtfMs() { return mgr.#contentTtfMs; },
      get leafFetchGraceMs() { return mgr.#leafFetchGraceMs; },
      get ownChainStore() { return mgr.#ownChainStore; },

      // Wired by the composition root long after construction; `null` until then, and `null` is an
      // answer the pipeline reports rather than papers over.
      get onParkFailed() { return mgr.#onParkFailed; },
      get onContentArrived() { return mgr.#onContentArrived; },
      get onDocumentFrame() { return mgr.#onDocumentFrame; },
      get isDocumentFrame() { return mgr.#isDocumentFrame; },
      get onAwaitingPersisted() { return mgr.#onAwaitingPersisted; },
      get inboundFrameObserver() { return mgr.#inboundFrameObserver; },

      // Read AND decremented by the pipeline, so these are the one place a pair is needed.
      get sendFaultRemaining() { return mgr.#sendFaultRemaining; },
      set sendFaultRemaining(v: number) { mgr.#sendFaultRemaining = v; },
      get ackFaultRemaining() { return mgr.#ackFaultRemaining; },
      set ackFaultRemaining(v: number) { mgr.#ackFaultRemaining = v; },
      get connectionLossRemaining() { return mgr.#connectionLossRemaining; },
      set connectionLossRemaining(v: number) { mgr.#connectionLossRemaining = v; },

      sessionKey: (a, sid) => this.#k(a, sid),
      keyProvider: (a) => this.#keyProviderResolver?.(a),
      getSessionTree: (a, sid) => this.getSessionTree(a, sid),
      appendSessionLeaf: (a, sid, kind, h, cid) => this.appendSessionLeaf(a, sid, kind, h, cid),
      mailboxRouteAvailable: (a) => this.#mailboxRouteAvailable(a),
      streamCensus: (node, peerId) => this.#streamCensus(node, peerId),
      freezeOnIdentityFailure: (a, sid, reason, cid) => this.#freezeOnIdentityFailure(a, sid, reason, cid),
      handleTtfExpiry: (a, sid, hashHex) => this.#handleTtfExpiry(a, sid, hashHex),
      markContentUnverifiable: (a, sid, why) => this.#markContentUnverifiable(a, sid, why),
      maybeAutoAcknowledgeSeal: (a, sid, cid) => this.#maybeAutoAcknowledgeSeal(a, sid, cid),
      ownChainOf: (a, sid, entry, ownPubkey) => this.#ownChainOf(a, sid, entry, ownPubkey),
      updateSessionStatus: (a, sid, status, by) => this.#updateSessionStatus(a, sid, status, by),
      abandonSession: (a, sid) => this.abandonSession(a, sid),
      connectToCounterparty: (a, sid, addrs) => this.connectToCounterparty(a, sid, addrs),
      destroySessionNode: (a, sid, reason) => this.destroySessionNode(a, sid, reason),
      retireOnCounterpartyAbandon: (a, sid, cid) => this.retireOnCounterpartyAbandon(a, sid, cid),
    };
    // The sender first: the receiver holds it, and nothing holds the receiver.
    this.#contentOut = new SessionContentSender(contentCtx);
    this.#contentIn = new SessionContentIngest(contentCtx, this.#contentOut);

    this.#dbPath = opts.dbPath;
    if (typeof opts.contentTtfMs === "number" && opts.contentTtfMs > 0) {
      this.#contentTtfMs = opts.contentTtfMs;
    }
    this.#autoNatProbers = opts.autoNatProbers ?? (() => []);
    this.#srRetryDelaysMs = opts.standingReceiverRetryDelaysMs ?? [1_000, 5_000, 15_000];
    this.#srReservationTimeoutMs = opts.standingReceiverReservationTimeoutMs ?? 15_000;
    // ⚠️ BUILT AFTER the retry/timeout settings it captures. Those come from `opts` with defaults
    // applied HERE, and a collaborator constructed above them would capture `undefined` — the
    // same class tsc caught on `#logger`. Duplicating the defaults at the call site would be
    // worse: two places deciding one number is how they stop agreeing.
    this.#receivers = new StandingReceivers({
      logger: this.#logger,
      records: this.#records,
      park: this.#park,
      factory: this.#factory,
      db: () => this.#db,
      shuttingDown: () => this.#shuttingDown,
      sessionKey: (a, sid) => this.#k(a, sid),
      standingReceivers: this.#standingReceivers,
      standingReceiverCreating: this.#standingReceiverCreating,
      agentsWantingReceiver: this.#agentsWantingReceiver,
      srReservationRetry: this.#srReservationRetry,
      srLastRejectionReason: this.#srLastRejectionReason,
      srLastRespreadAt: this.#srLastRespreadAt,
      directoryRelayEndpoints: this.#directoryRelayEndpoints,
      standingReceiverRemoving: this.#standingReceiverRemoving,
      srRetryDelaysMs: this.#srRetryDelaysMs,
      srReservationTimeoutMs: this.#srReservationTimeoutMs,
      autoNatProbers: () => this.#autoNatProbers(),
      proveToRelay: (a, circuitAddr, node, cid, surface) => this.#proveToRelay(a, circuitAddr, node, cid, surface),
      reservationCircuitAddrs: (a) => this.#reservationCircuitAddrs(a),
      authenticateStandingReceiver: (a, node, relayPeerId, heldCircuitAddr, cid) => this.#authenticateStandingReceiver(a, node, relayPeerId, heldCircuitAddr, cid),
    });
    this.#srWatchdogIntervalMs = opts.standingReceiverWatchdogIntervalMs ?? 30_000;
    this.#srReservationRetryMs = opts.standingReceiverReservationRetryMs ?? 5 * 60_000;
    // REQUIRED, no fallback (INV-9, audit finding). This line used to read
    // `opts.securityGateway ?? new PassthroughGatewayClient()` — the identical shape as the defect
    // that reopened this milestone, one layer down and still shipping in the binary. `daemon.ts`
    // was hardened to throw while this constructor was not, so the inbound screen had a silent
    // always-allow path that nothing in the product reached TODAY and any future refactor could.
    // "Currently unreachable" is a property of today's call sites, not of the code.
  }

  /**
   * CELLO-M7-MSG-001: wire the durable-backstop side effects of the awaiting-ACK
   * lifecycle. `onPersisted` clears the durable retry_queue entry when a persisted ACK
   * arrives; `onTtf` records/parks the un-acked content when the TTF timer fires.
   * Injected by the composition root (daemon.ts) after the RetryQueue exists.
   */
  setAwaitingAckHooks(hooks: {
    onPersisted?: (agentName: string, sessionId: string, contentHashHex: string) => void;
    onTtf?: (agentName: string, sessionId: string, contentHashHex: string, content: Uint8Array, structure1Cbor?: Uint8Array, structure2Cbor?: Uint8Array, contentHashAlg?: string, structure1Signature?: Uint8Array, leafKind?: number) => void;
    onParkFailed?: (agentName: string, sessionId: string, contentHashHex: string, content: Uint8Array, structure1Cbor?: Uint8Array, structure2Cbor?: Uint8Array, contentHashAlg?: string, structure1Signature?: Uint8Array, leafKind?: number) => boolean;
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
    /**
     * ⚠️ THE OWN-CHAIN STORE IS BUILT HERE, NOT LAZILY INSIDE THE RELAY-CLIENT BUILDERS —
     * `DOD-M15-SELFCHAIN-1`, review F2.
     *
     * It was constructed only when a relay client was attached, so a session that never attached one
     * left it null: nothing was ever recorded, and every message that side sent carried the same
     * self link. That is the exact defect this unit exists to close, on the path its own comments
     * call the one that matters most — a conversation that ran while the relay was down is precisely
     * the one whose order gets disputed later.
     *
     * The chain belongs to the AGENT and the SESSION. The relay is how the conversation travels; it
     * is not what makes the conversation provable.
     */
    this.#ownChainStore = new SessionOwnChainStore(this.#db, this.#logger);
    ensureSessionSchema(this.#db, this.#logger, () => this.#records.loadDivergedFromDb());

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
              // DOD-CAP-SELF-HEAL-1: OURS. This is the boot sweep finding sessions a previous
              // process left `active`; the counterparty did nothing, so they are not charged for it.
              "UPDATE sessions SET status = 'interrupted', updated_at = ?, interrupted_at = COALESCE(interrupted_at, ?), interrupted_by = 'local' WHERE agent_id = ? AND session_id = ?",
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
  /**
   * REBUILD THE CERTIFIED ROOT FROM THIS DAEMON'S OWN LEAVES — `DOD-M15-SEALWIRE-1` bullet 2.
   *
   * The receipt used to prove only that the directory signed SOMETHING: the client took the sealed
   * root off the wire, confirmed the directory's signature over those bytes, stored it, and threw
   * away the root it had computed a step earlier. At co-signing time that means **your key signs a
   * root you never checked.**
   *
   * Bullet 1 moved the certified root into the content-hash domain, which is the domain this daemon
   * can actually rebuild — each carry leaf's `content_hash` is the leaf hash (RFC 6962 §2.1 "hash"
   * leaves are used as-is), and the carry is ordered by the relay's canonical `sequence_number`,
   * which is the order the directory rebuilds in.
   *
   * ─── Why this returns "cannot judge" instead of always answering ───────────────────────────
   *
   * A root comparison that is WRONG makes every session unsealable, and force-abandon — no receipt —
   * becomes the only exit. That failure is worse than the one being guarded, and this file already
   * carries two comments saying so about other gates.
   *
   * The carry is this daemon's view, and it is not guaranteed complete at the instant a certificate
   * arrives: the counterparty's SEAL ctrl leaf is what TRIGGERS the seal, so it may not have been
   * witnessed here yet. So completeness is checked FIRST, against the certificate's own leaf count.
   * A short carry means this daemon cannot judge — which is a different answer from "the roots
   * disagree", and conflating them would turn a local timing gap into an accusation.
   */
  verifyCertifiedRoot(
    agentPubkeyHex: string,
    sessionIdHex: string,
    certifiedRoot: Uint8Array,
    certifiedLeafCount: number,
  ): { verdict: "match" } | { verdict: "mismatch"; ownRootHex: string | null; detail: string } | { verdict: "cannot_judge"; reason: string } {
    const carry = this.getSealCarry(agentPubkeyHex, sessionIdHex);
    if (carry.length === 0) return { verdict: "cannot_judge", reason: "no_carry" };

    /**
     * COMPLETENESS IS ESTABLISHED FROM THE CARRY'S OWN EVIDENCE, NEVER FROM THE CERTIFICATE.
     *
     * Review F3, and the first cut had this exactly backwards. It gated on
     * `carry.length !== certifiedLeafCount`, where `certifiedLeafCount` is a field the DIRECTORY
     * chooses and signs — so the party being checked controlled whether it was checked. A directory
     * certifying a root over a different conversation had only to state a `leaf_count` that did not
     * match, and the client answered "cannot judge" and accepted. The signature still verified,
     * because the count is signed inside the same TBS.
     *
     * That is the hole §2b names in as many words: *"an attacker who wants to evade a mismatch check
     * simply never supplies a checkable proof. Treating 'we could not tell' as harmless is the
     * hole."* I defended against a false POSITIVE and left the false NEGATIVE one field away.
     *
     * The carry can answer the question by itself. A complete bilateral leaf set is:
     *   - sequences contiguous from 1 — no gap where a leaf this daemon never saw would sit; and
     *   - exactly two SEAL ctrl leaves, from two DISTINCT senders — which is what a bilateral seal
     *     is, and is the condition that says the counterparty's closing leaf has landed here.
     * Both predicates already exist in `seal-escalation.ts`; this reuses their shape rather than
     * inventing a second opinion about the same question.
     *
     * When the carry IS self-evidently complete, a `leaf_count` that disagrees is no longer "I
     * cannot tell" — it is the certificate describing a different leaf set, which is a MISMATCH.
     */
    const sequences = carry.map((l) => l.sequenceNumber).sort((a, b) => a - b);
    const contiguousFromOne = sequences.every((n, i) => n === i + 1);
    const ctrlSenders = new Set(
      carry.filter((l) => l.leafKind === LEAF_KIND_CTRL).map((l) => l.senderPubkeyHex),
    );
    const selfEvidentlyComplete = contiguousFromOne && ctrlSenders.size === 2;

    /**
     * 🚨 THE CERTIFICATE MAY COVER EXACTLY WHAT THIS SIDE HOLDS — ASK THAT FIRST.
     *
     * `DOD-M15-UNILATERAL-1`. The completeness predicate below describes a BILATERAL leaf set: two
     * SEAL ctrl leaves, from two distinct senders. **A solo seal can never satisfy it**, because the
     * counterparty is gone and never posts one — that is the entire premise. So on the solo path
     * this returned `cannot_judge` every time, `session-ceremony.ts` refuses to co-sign on anything
     * that is not `match`, and **the sealing party refused to co-sign its own unilateral seal.** The
     * FROST ceremony never reached threshold, the directory never completed, and the close came back
     * `seal_unilateral_timeout` — the label that names our own wait. Measured against the real
     * binaries: `j-unilateral` failed on exactly this, with the directory having already verified the
     * chain and recorded the counterparty ABSENT.
     *
     * Completeness was only ever needed to tell TWO KINDS OF DISAGREEMENT apart — "the roots differ
     * because my carry is behind" (cannot judge) from "the roots differ because the directory
     * certified something else" (mismatch). It answers nothing when the roots AGREE: a certificate
     * whose root and leaf count are exactly what this daemon holds is, by construction, over this
     * daemon's own leaves. Nothing is taken on trust — both values are recomputed here from the
     * carry, and an adversary who could satisfy them would have to have produced this leaf set.
     *
     * Deliberately BOTH values. A count that disagreed while the root matched would be a certificate
     * contradicting itself, and this is not the place to wave that through.
     */
    const carryInputs = carryContentHashInputs(carry);
    if (
      carryInputs !== null &&
      carry.length === certifiedLeafCount &&
      Buffer.compare(Buffer.from(merkleRoot(buildMerkleTree(carryInputs))), Buffer.from(certifiedRoot)) === 0
    ) {
      return { verdict: "match" };
    }

    if (!selfEvidentlyComplete) {
      return {
        verdict: "cannot_judge",
        reason: contiguousFromOne
          ? `carry_incomplete: ${ctrlSenders.size} of 2 SEAL ctrl leaves witnessed here`
          : `carry_noncontiguous: hold ${carry.length} leaves with a gap in the relay sequence`,
      };
    }
    if (carry.length !== certifiedLeafCount) {
      // The carry proves itself complete and the certificate claims a different size, so the
      // certificate is over a different leaf set. Accusing is correct here.
      return {
        verdict: "mismatch",
        ownRootHex: null, // no root computed — the sets differ in SIZE, which is decisive on its own
        detail: `leaf_count_disagrees: this daemon holds a provably complete ${carry.length}-leaf set, the certificate claims ${certifiedLeafCount}`,
      };
    }
    if (carryInputs === null) {
      // A leaf this daemon cannot decode is a leaf it cannot judge. Never an accusation.
      return { verdict: "cannot_judge", reason: "structure1_content_hash_unreadable" };
    }
    const ownRoot = merkleRoot(buildMerkleTree(carryInputs));
    const ownRootHex = Buffer.from(ownRoot).toString("hex");
    return Buffer.compare(Buffer.from(ownRoot), Buffer.from(certifiedRoot)) === 0
      ? { verdict: "match" }
      : { verdict: "mismatch", ownRootHex, detail: "root_disagrees: same leaf count, different leaves or different order" };
  }

  /**
   * WHERE THE MUTUALLY-SIGNED PREFIX ENDS, DERIVED FROM THIS DAEMON'S OWN LEAVES —
   * `DOD-M15-UNILATERAL-1`, review F2.
   *
   * ⚠️ **THE FIRST VERSION COMPUTED THIS FROM THE CERTIFICATE'S OWN PARTICIPANT LIST, AND CALLED
   * THAT "recomputed, cannot be steered".** It could be steered. On the SOLO path the certificate's
   * TBS binds no legibility at all, and the client verifies only the *live* party's frontier — so
   * the absent party's `content_frontier_seq` and every `last_authored_seq` arrived unchecked. One
   * directory node could publish the absent party's frontier as 3 and the receipt would say
   * "mutually signed through 3" over a transcript that party never signed for. That is the precise
   * conflation this field exists to prevent, reintroduced by the field itself.
   *
   * The carry answers it without trusting anybody. This daemon holds the counterparty's own leaves,
   * each carrying, inside the bytes THEY signed, both the sequence they authored and the
   * `last_seen_seq` they acknowledged. So a party's commitment reaches
   * `max(highest sequence they authored, highest sequence they acknowledged)`, and the transcript is
   * mutually signed only as far as the LEAST-committed party reaches.
   *
   * Fewer than two distinct authors ⇒ `0`: nobody countersigned anything, which is the honest floor
   * for a conversation where the other side only ever received. `null` when the carry is empty or
   * unreadable — the caller must then publish NO boundary rather than fall back to a number
   * somebody else supplied.
   */
  countersignedThroughSeqFromCarry(agentPubkeyHex: string, sessionIdHex: string): number | null {
    const carry = this.getSealCarry(agentPubkeyHex, sessionIdHex);
    if (carry.length === 0) return null;
    const reach = new Map<string, number>();
    for (const leaf of carry) {
      // Structure 1 = [version, content_hash, sender_pubkey, session_id, last_seen_seq, timestamp],
      // plus last_seen_hash at 6 on a v2 claim. `last_seen_seq` is index 4 in both — 020-ACKHASH
      // APPENDS, so this read did not move. The hash is not consulted here: this derives a
      // POSITIONAL boundary, which is the job last_seen_seq keeps doing alongside the new field.
      const s1 = decodeStructure1(leaf.structure1Cbor);
      // Unreadable, or a layout this build cannot name: publish no boundary rather than a
      // half-derived one somebody else could have shaped.
      if (!s1.ok) return null;
      const signedLastSeen = Number.isFinite(Number(s1.fields.lastSeenSeq))
        ? Number(s1.fields.lastSeenSeq)
        : 0;
      const prior = reach.get(leaf.senderPubkeyHex) ?? 0;
      reach.set(leaf.senderPubkeyHex, Math.max(prior, leaf.sequenceNumber, signedLastSeen));
    }
    if (reach.size < 2) return 0;
    return Math.min(...reach.values());
  }

  getSealCarry(agentPubkeyHex: string, sessionIdHex: string): SealCarryLeaf[] {
    if (!this.#sealLeafStore && this.#db) {
      this.#sealLeafStore = new SessionSealLeafStore(this.#db, this.#logger);
    }
    return this.#sealLeafStore?.getCarry(agentPubkeyHex, sessionIdHex) ?? [];
  }

  // ─── M8C-INBOX-1 (N2/N3): read-watermark accessors ───────────────────────────

  /** DOD-TIER-4: the DISPLAY/relationship check — is this counterparty a genuine contact (KNOWN or
   *  above)? Replaces the old binary `isContact` for behaviour that keyed on "we have a relationship"
   *  (e.g. the away-response wording). An UNKNOWN-tier contact (a mere row) is NOT known. */
  isKnown(agentName: string, pubkey: string): boolean {
    return this.#records.getTier(agentName, pubkey) >= TIER.KNOWN;
  }

  /** DOD-TIER-4: the POLICY gate — may an inbound session from this counterparty be auto-accepted
   *  when the operator is unattended (WHITELISTED or VIP)? The behavioural consumer is the offline
   *  relay mailbox (LEAVEMSG-1), out of scope for this unit; defined here as the seam. Being merely
   *  KNOWN is NOT enough to auto-accept — whitelisting is the deliberate `cello_contact_set_tier` act. */
  isAutoAccept(agentName: string, pubkey: string): boolean {
    return this.#records.getTier(agentName, pubkey) >= TIER.WHITELISTED;
  }

  /** DOD-AWAY-TIER-1: resolve the most-specific CUSTOM away text for a counterparty, most-specific
   *  first: per-contact `away_message` → per-tier away setting → agent default away setting. Returns
   *  null when none is configured, so the CALLER applies the system default (code) — making the full
   *  four-level resolution TOTAL. A pure read; the resolved text is screened on the outbound path by
   *  the caller like any content (SI — it does not bypass the gateway). */
  resolveAwayMessage(agentName: string, pubkey: string): string | null {
    // A public key is bytes; its hex case is not part of its identity. Normalized HERE so the
    // query below cannot see two spellings of one contact — see `contact-pubkey-case.ts`.
    pubkey = normalizeContactPubkey(pubkey);
    if (!this.#db) return null;
    const agentId = this.#requireAgentId(agentName);
    const row = this.#db
      .prepare("SELECT away_message FROM contacts WHERE agent_id = ? AND pubkey = ?")
      .get(agentId, pubkey) as { away_message: string | null } | undefined;
    if (row?.away_message != null) {
      this.#logger.debug("contact.away.resolved", { agentName, pubkey, level: "contact" }); // obs AC
      return row.away_message; // 1. per-contact
    }
    const tierName = settableTierName(this.#records.getTier(agentName, pubkey));
    if (tierName !== null) {
      const tierAway = this.#records.getSetting(agentName, awayTierSettingKey(tierName));
      if (tierAway !== null) {
        this.#logger.debug("contact.away.resolved", { agentName, pubkey, level: "tier" });
        return tierAway; // 2. per-tier
      }
    }
    const agentDefault = this.#records.getSetting(agentName, AWAY_DEFAULT_KEY);
    // 3. agent default, else null → caller applies the system default (code). Level logged HERE.
    this.#logger.debug("contact.away.resolved", { agentName, pubkey, level: agentDefault !== null ? "agent_default" : "system" });
    return agentDefault;
  }

  /**
   * DOD-M15-REFUSEDEVIDENCE-1 — retain a message refused OUTSIDE `ingestReceivedContent`.
   *
   * Review F6. The park drain terminally-blocks a message that arrived for an already-committed
   * session, then confirm-deletes the relay copy — the one other route in the tree that discarded
   * refused content, and the highest-suspicion combination in the product: hostile bytes aimed at a
   * conversation somebody has already sealed. Shipped guidance now tells every operator that
   * refused messages are kept, so this is made true rather than the promise narrowed.
   *
   * A thin delegate, not a second implementation: the bound, the dedup, the sequence allocation and
   * the logging are the ones every other refusal uses.
   */
  quarantineRefusedInbound(
    agentName: string,
    sessionId: string,
    reason: string,
    content: Uint8Array,
    contentHashHex: string,
    senderPubkeyHex: string | null,
    correlationId?: string,
  ): number | null {
    return this.#refusals.quarantineRefusedContent(agentName, sessionId, reason, content, contentHashHex, {
      senderPubkeyHex, correlationId,
    });
  }

  /** The metadata half of a framed quarantine read — everything known ABOUT the message, none of it
   *  taken from the message. Split out so the framing module never touches the database. */
  quarantineFrameMeta(agentName: string, sessionId: string, rec: QuarantinedRecord): QuarantineFrameMeta {
    return {
      reason: rec.reason,
      senderPubkeyHex: rec.senderPubkeyHex,
      senderLabel: rec.senderPubkeyHex === null ? null : this.#records.getContactMoniker(agentName, rec.senderPubkeyHex),
      // `attribution` is the column that exists to answer exactly this, so it is read rather than
      // inferred from `sender_sig` being non-null — a stored signature that was never checked
      // against the sender's key would otherwise be reported as VERIFIED.
      signature: rec.attribution === "verified_signature" ? "VERIFIED" : "NOT SIGNED",
      sessionId,
      position: rec.sequence,
      arrivedAtMs: rec.createdAt,
      /**
       * The hash OF THE RETAINED BYTES, recomputed here — not the hash the sender committed to.
       *
       * On the highest-value case in the whole unit those two differ ON PURPOSE:
       * `content_hash_mismatch` means the sender's committed hash does not describe these bytes.
       * Printing their claim over our bytes would label the payload with a hash it does not have,
       * which is the one thing a reader would use this line to check.
       */
      contentHashHex: Buffer.from(contentHashFor(rec.content, { alg: "sha256", salt: null })).toString("hex"),
    };
  }

  /** M8C-ABUSE-1 + DOD-TIER-2/3: is a NEW inbound session from this counterparty within the
   *  acceptance bounds? The per-sender cap is now the sender's TIER cap (DEFAULT_TIER_BOUNDS), not a
   *  flat "3 for strangers, unbounded for contacts". This is where DOD-TIER-3 falls out for free: a
   *  BLOCKED sender's cap is 0, so `perSender (>= 0) >= 0` refuses it through the SAME reason and the
   *  SAME path an over-cap UNKNOWN takes — no separate blocked branch, no distinguishing oracle. The
   *  global anti-swarm cap then applies ONLY to UNKNOWN-tier senders (KNOWN+ are trusted, not part of
   *  the stranger pool; BLOCKED never reaches it). Checked BEFORE accepting a fresh inbound session
   *  (counts reflect sessions already active, not yet counting this one). */
  checkUnknownSenderAcceptanceBound(
    agentName: string,
    counterpartyPubkey: string,
  ): { ok: true } | { ok: false; reason: CapacityReason } {
    const tier = this.#records.getTier(agentName, counterpartyPubkey);
    const perSenderCap = this.#records.resolveTierBound(agentName, tier, "max_sessions");
    const perSender = this.#queries.countActiveSessionsForCounterparty(agentName, counterpartyPubkey);
    if (perSender >= perSenderCap) {
      // BYTE-IDENTICAL to every other refusal, deliberately — DOD-TIER-3. A BLOCKED sender and an
      // over-cap UNKNOWN must be indistinguishable, or the refusal tells someone they are blocked.
      // The operator's alarm needs numbers, so it asks for them SEPARATELY via capDiagnostics;
      // hanging them off this object would put a distinguishing oracle in the return value.
      return { ok: false, reason: CAPACITY_REASONS.ABUSE_BOUND_SESSIONS_PER_SENDER };
    }
    // The global stranger cap is only for the UNKNOWN pool. A KNOWN+ sender is past it by trust;
    // a BLOCKED sender was already refused above (cap 0).
    if (tier === TIER.UNKNOWN) {
      const globalUnknown = this.#queries.countActiveSessionsFromUnknownSenders(agentName);
      if (globalUnknown >= ABUSE_MAX_UNKNOWN_SESSIONS_GLOBAL) {
        return { ok: false, reason: CAPACITY_REASONS.ABUSE_BOUND_UNKNOWN_SESSIONS_GLOBAL };
      }
    }
    return { ok: true };
  }

  /**
   * The current standing receiver node's session-transport coordinates (peer id +
   * listen multiaddrs), or null if it is not ready. These are the addresses a local
   * SessionNegotiator advertises as this node's counterparty endpoint so the initiator
   * can dial it, and the value an inbound session_assignment carries in its
   * counterparty_session_* fields. Read-only — does NOT consume the standing receiver
   * (unlike acceptSession, which hands it off).
   */
  /**
   * 032-RELAYSPREAD — would this receiver ADMIT an inbound dial from this relay?
   *
   * The gater's inbound carve-out is the security-sensitive half of the spread: only relays whose
   * own reservation is confirmed held earn it, so a directory that merely NAMES a relay cannot dial
   * in behind the gate. Nothing could observe that from outside the manager, and the review found
   * the consequence: substituting the CANDIDATE list for the held list at the `setReservedRelayPeers`
   * call kept every test in the unit green while shipping exactly that hole. A guard whose wiring
   * cannot be observed is a guard nothing can test.
   *
   * Reads the live gater rather than a copy, so it cannot drift from what the gate actually does.
   */
  isRelayCarvedOutInbound(agentName: string, relayPeerId: string): boolean {
    return this.#standingReceivers.get(agentName)?.gater.holdsInboundCarveOut(relayPeerId) ?? false;
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
    classifyOnly?: (content: Uint8Array) => boolean,
  ): void {
    this.#onDocumentFrame = cb;
    this.#isDocumentFrame = classifyOnly ?? null;
  }

  /**
   * DOD-LOOP-1: the session core is keyed by (agentName, sessionId), NOT sessionId alone. Two of
   * the operator's own agents (the loopback case) can hold the two ends of the SAME session_id on
   * ONE daemon, so a bare session_id is ambiguous between them. This composite string key — the
   * agent name and the hex session id joined by a 0x1f unit separator (which appears in neither) —
   * is the key for every in-memory session-core map (#activeNodes, #trees, #receivedContent,
   * #contentDesynced, #responderSealSubmitted, #awaitingAck) and for the per-session maps the
   * collaborators own, which build the same key the same way. #relayClients is already per-agent
   * (its own key), and the standing receivers are keyed by agent name directly.
   */
  #k(agentName: string, sessionId: string): string {
    return `${agentName}\x1f${sessionId}`;
  }

  /**
   * The inverse of `#k`, for the ONE reader that has a key and needs the session id back: the
   * unpersisted-refusal fallback, which is keyed like every other per-session map but is drained
   * per AGENT rather than per session.
   *
   * Returns null when the key belongs to a different agent. Split on the FIRST separator only —
   * `agentName` cannot contain 0x1f, so anything after the first one is the session id, and a
   * greedy split would silently mis-attribute a key rather than reject it.
   */
  #unk(key: string, agentName: string): string | null {
    const sep = key.indexOf("\x1f");
    if (sep < 0) return null;
    return key.slice(0, sep) === agentName ? key.slice(sep + 1) : null;
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

    /**
     * ⚠️ THE "NO ASSIGNMENT" REFUSAL IS NOT HERE, AND THE PLACE IT MOVED TO IS THE POINT.
     *
     * `DOD-M15-SELFCHAIN-1`, ruled 2026-09-06: a session offered with no directory assignment is
     * suspicious and must be refused and surfaced. It was briefly enforced HERE, and that was the
     * wrong door: `createSessionNode` also runs on this agent's OWN outbound path, where the
     * counterparty has no say in whether an assignment exists. A refusal there fires on our own
     * initiations and says nothing about anyone's conduct.
     *
     * A counterparty can only attempt it INBOUND, so that is where it is refused and recorded —
     * see `inbound-sessions.ts`. What remains true here is the correctness backstop: a session with
     * no anchor cannot sign a chained message, so the SEND path refuses (`session_unchainable`)
     * rather than emitting a message whose place could never be proven.
     */

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
    // DOD-M12B-SESSION-SEED-1: whichever branch below runs, the session ends up owning a seed.
    // Promotion inherits the receiver's; a freshly-built node mints its own.
    let seed: Uint8Array;
    if (reuseStandingReceiver) {
      const sr = this.#standingReceivers.get(agentName);
      if (!sr) {
        // DOD-LOOP-1: this agent has no standing receiver ready — kick off (idempotent) creation
        // so a retry finds it, and report unavailable. Per-agent, so the initiator consuming its
        // OWN agent's receiver never contends with a co-resident responder agent (the loopback case).
        void this.#receivers.ensureStandingReceiver(agentName, correlationId);
        return {
          ok: false,
          reason: "standing_receiver_unavailable",
          guidance: "The standing receiver node is initializing (completes within 200ms). Retry the session in a moment.",
        };
      }
      ({ node, gater, autoNat, seed } = sr);
      gater.setAllowedPeer(counterpartyPeerId);
      await this.#evictPeersOutsideGate(node, gater, sessionId, counterpartyPeerId, "outbound_promotion");
      // Hand this agent's standing receiver off to this session; a replacement is spun up below.
      this.#standingReceivers.delete(agentName);
    } else {
      gater = new SessionConnectionGater({
        sessionId,
        allowedPeerId: counterpartyPeerId,
        logger: this.#logger,
      });
      try {
        seed = randomBytes(32);
        node = await this.#receivers.createAgentNode(agentName, { sessionId, connectionGater: gater, nodeType: "session", transportPrivateKey: seed });
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
      if (reuseStandingReceiver) void this.#receivers.ensureStandingReceiver(agentName, correlationId);
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
    //
    // `counterpartySessionPeerId` IS LOGGED because it is recorded here ONCE and never refreshed,
    // while a standing receiver is rebuilt with a fresh libp2p keypair on a lost relay reservation
    // and every lost reservation. If the peer rebuilds between advertising its endpoint and this
    // handoff, we record an identity that no longer exists — and since `newStream` never dials, it
    // only ever looks for an ALREADY-OPEN connection filed under exactly this string, so every send
    // in this direction parks forever while the reverse direction works fine.
    //
    // Both sides of a local session log this event, so recording the id we will dial makes that
    // mismatch a direct comparison in the log instead of an unfalsifiable hypothesis.
    this.#logger.info("session.node.created", {
      sessionId,
      agentName,
      sessionPeerId: peerId,
      counterpartySessionPeerId: counterpartyPeerId,
      correlationId,
    });

    // Add to active map (keyed by (agentName, sessionId) — DOD-LOOP-1)
    // 006-CRYPTO: the session's throwaway keypair is minted here, with the node, so "a session is
    // active" and "a session has a key" are the same moment. All THREE activation paths mint.
    this.#ephemerals.mintSessionEphemeral(agentName, sessionId);
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
    this.#rememberSessionSeed(agentName, sessionId, seed, counterpartyPeerId, counterpartyPubkey);

    // DAEMON-004: register the content stream handler so inbound content_frames
    // are cross-checked, appended to the daemon-owned tree, and buffered.
    await this.#contentIn.registerContentHandler(agentName, sessionId, node, counterpartyPubkey);
    // M7-SESSION-003 AC-004: act on the session node's peer events for direct-path
    // liveness. The session connection IS the authority for a direct session.
    this.#liveness.wireSessionLiveness(agentName, sessionId, node, counterpartyPubkey, correlationId, counterpartyPeerId);

    // M7 DOD-SPINE-6 / MSG-001-3b: connect this session node to the relay as the
    // Structure-2 witness (non-fatal — direct content still works without it).
    if (relay) {
      await this.#connectSessionRelay(sessionId, node, agentName, relay, correlationId);
    }

    // If we consumed this agent's standing receiver, spin up a replacement (async — do NOT await).
    if (reuseStandingReceiver) {
      void this.#receivers.ensureStandingReceiver(agentName, correlationId);
    }

    return { ok: true, peerId, addrs };
  }

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
          // DOD-M15-RELAYSLOTS-1: read at each auth, never snapshotted — the token expires hourly.
          onlineToken: () => this.getDirectoryOnlineToken(agentName),
          // DOD-M15-CORROBORATE-1: a relay's witness alert reaches the operator's inbox from here.
          // The DETACHED clients get the same callback from the builder in daemon.ts.
          onWitnessAlert: (alert) => { this.#witness.recordRelayWitnessAlert(agentName, alert); },
          onWitnessUnreadable: (relayPeerId, why) => { this.#records.recordRelayWitnessUnreadable(agentName, relayPeerId, why); },
        });
        this.#relayClients.set(clientKey, client);
      }
      const sessionIdHexForRelay = Buffer.from(relay.sessionIdBytes).toString("hex");
      /**
       * ⚠️ THE GENESIS IS WRITTEN BEFORE THE REGISTRATION, NOT AFTER — review F10.
       *
       * `#leafRecords.sessionGenesisPrevRoot` reads the entry's assignment first and the column second,
       * and BOTH were still unset at this line: the entry's assignment is set below and the column
       * is written below that. So the argument was always `undefined` here on a first attach, and
       * the seed only survived because `registerSession` falls back to deriving one from the
       * assignment it is handed. That is a dead argument standing next to a live fallback, which
       * reads as deliberate and is the shape a later edit removes the wrong half of.
       */
      const entry = this.#activeNodes.get(this.#k(agentName, sessionId));
      if (entry) entry.relayAssignment = relay.assignment;
      if (relay.assignment) this.#leafRecords.persistGenesisPrevRoot(agentName, sessionId, relay.assignment);
      client.registerSession(sessionIdHexForRelay, node, this.#contentIn.relayLeafHandler(agentName, sessionId, correlationId), relay.assignment, this.#leafRecords.sessionGenesisPrevRoot(agentName, sessionId));

      if (entry) {
        entry.relayClient = client;
        entry.relaySessionIdBytes = relay.sessionIdBytes;
        entry.relayClientKey = clientKey;
        // 2b: remember the relay endpoint so the content-park backstop deposits to the SAME relay.
        entry.relayPeerId = relay.relayPeerId;
        entry.relayAddrs = relay.relayAddrs;
        // Review H1: the dial path needs the credential in hand, not just the endpoint.
        // (Set above, before `registerSession`, so the genesis lookup it does has something to
        // find — see the note there.)
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

      // DOD-M15-RELAYAUTH-1 review HIGH-2 — see below. Best-effort and non-blocking: a session must
      // never fail to come up because a SECOND relay could not be told about it.
      //
      // Review M1: `.catch()` is not decoration. This is an unawaited promise, so a throw it does not
      // handle is an unhandled rejection — and this file already carries a comment elsewhere about an
      // absent `await` that became a remote process kill. The method's own try/catch does not cover
      // its prologue, so the catch here is the only thing standing between a torn-down node and the
      // daemon dying.
      void this.#presentAssignmentToReservationRelay(agentName, node, relay, sessionIdHexForRelay, correlationId, entry)
        .catch((err: unknown) => {
          this.#logger.warn("session.relay.assignment.reservation_relay_failed", {
            agentName,
            sessionId: sessionIdHexForRelay.slice(0, 16),
            error: extractErrorMessage(err),
            impact: "inbound relayed dials to this node may be refused by its reservation relay; the session still works over the direct path and the park backstop",
            correlationId,
          });
        });
    } catch (err: unknown) {
      this.#logger.warn("session.relay.connect.error", {
        sessionId,
        error: err instanceof Error ? err.message : String(err),
        correlationId,
      });
    }
  }

  /**
   * DOD-M15-RELAYAUTH-1 review HIGH-2 — **THE RELAY THAT GATES THE DIAL IS NOT ALWAYS THE RELAY
   * THAT HOLDS THE ASSIGNMENT, AND THE GATE DENIES WHEN THEY DIFFER.**
   *
   * Two relays are in play for one session, chosen by unrelated rules:
   *   - the WITNESS relay, `assignment.relay_endpoint`, picked by the directory. Both parties
   *     present `client_record_assignment` to it and to nowhere else.
   *   - the RESERVATION relay, whichever one this node's circuit address is held on — the first
   *     candidate that granted when it was a standing receiver.
   *
   * The counterparty dials our CIRCUIT address, so it is the RESERVATION relay whose gater is asked
   * `denyOutboundRelayedConnection(them, us)`. With no assignment recorded there it finds no binding
   * and refuses a completely legitimate dial. Two relays run in production and the client's own
   * logs show the fall-through to the second candidate is frequent, so this is the ordinary case,
   * not a corner: the session still opens, but every message falls to the store-and-forward park
   * path, and the only trace is a denial on a relay nobody is tailing.
   *
   * So the node that will be DIALLED presents the same assignment to the relay that will be asked
   * to allow it. Safe by construction: the assignment is self-authenticating (a per-node directory
   * signature the relay verifies against its consortium set), so presenting it more widely grants
   * nothing that forging it would not already require. No directory change, no new frame.
   */
  async #presentAssignmentToReservationRelay(
    agentName: string,
    node: CelloNode,
    relay: RelayConnectParams,
    sessionIdHex: string,
    correlationId: string,
    entry?: ActiveSessionEntry,
  ): Promise<void> {
    // Review M1: the prologue below lives INSIDE the try. `listenAddresses()` on a node torn down
    // while we were wiring is exactly the case handled 30 lines above at the caller, and out here it
    // would have escaped both this method's catch and (before the caller's `.catch`) the process.
    let reservationRelayPeerId: string | undefined;
    try {
      if (!relay.assignment) return; // direct/legacy/persisted-reconnect: nothing to present anywhere
      const heldCircuitAddr = node.listenAddresses().find((a) => a.includes("/p2p-circuit"));
      if (!heldCircuitAddr) return; // no reservation held → nobody will gate a dial to us
      reservationRelayPeerId = /\/p2p\/([^/]+)\/p2p-circuit/.exec(heldCircuitAddr)?.[1];
      if (!reservationRelayPeerId || reservationRelayPeerId === relay.relayPeerId) return; // same relay — already recorded
      const clientKey = `${agentName}::${reservationRelayPeerId}`;
      let client = this.#relayClients.get(clientKey);
      if (!client) {
        if (!this.#relayReceiptStore && this.#db) this.#relayReceiptStore = new RelayReceiptStore(this.#db, this.#logger);
        if (!this.#sealLeafStore && this.#db) this.#sealLeafStore = new SessionSealLeafStore(this.#db, this.#logger);
        // Split on the marker, not an anchored strip: the held address is
        // `…/p2p/<relay>/p2p-circuit/p2p/<self>`, so the marker is in the MIDDLE.
        const baseRelayAddr = heldCircuitAddr.split("/p2p-circuit")[0] ?? heldCircuitAddr;
        client = this.#detachedRelayClientBuilder?.(agentName, reservationRelayPeerId, [baseRelayAddr], {
          receiptStore: this.#relayReceiptStore ?? undefined,
          sealLeafStore: this.#sealLeafStore ?? undefined,
          // DOD-M15-RELAYSLOTS-1: read at each auth, never snapshotted — the token expires hourly.
          onlineToken: () => this.getDirectoryOnlineToken(agentName),
        });
        if (!client) return;
        this.#relayClients.set(clientKey, client);
        // Review M4: record the key so teardown releases this client too — `relayClientKey` names
        // only the witness relay, so before this the client and its session registration leaked.
        if (entry) entry.extraRelayClientKeys = [...(entry.extraRelayClientKeys ?? []), clientKey];
      }
      // registerSession presents the assignment eagerly (see its own comment). No leaf handler: this
      // relay is not witnessing the session, it only needs the binding that authorizes the dial.
      // 033-ACKEMIT: no genesis is passed and none is needed. This client is not witnessing the
      // session — it never submits — and `registerSession` derives a seed from the assignment
      // anyway. Reaching into the session record for one here would also be reaching with the RELAY
      // session id, which is not the key that record is stored under.
      client.registerSession(sessionIdHex, node, undefined, relay.assignment);
      this.#logger.info("session.relay.assignment.presented_to_reservation_relay", {
        agentName,
        sessionId: sessionIdHex.slice(0, 16),
        witnessRelayPeerId: relay.relayPeerId,
        reservationRelayPeerId,
        impact: "the relay that will be asked to allow inbound circuit dials to this node now holds the assignment authorizing them",
        correlationId,
      });
    } catch (err: unknown) {
      this.#logger.warn("session.relay.assignment.reservation_relay_failed", {
        agentName,
        sessionId: sessionIdHex.slice(0, 16),
        reservationRelayPeerId,
        error: extractErrorMessage(err),
        impact: "inbound relayed dials to this node may be refused by its reservation relay; the session still works over the direct path and the park backstop",
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
    if (!entry.relaySessionIdBytes) return;
    const sidHex = Buffer.from(entry.relaySessionIdBytes).toString("hex");

    /**
     * Review M4: release the EXTRA relay clients first — the ones opened to relays that gate circuit
     * dials. `relayClientKey` above names only the witness relay, so these were registered and never
     * unregistered: an authenticated relay stream and a `#sessions` entry leaked per session, and
     * relay-side the dial-through binding they hold is then cleared only by the idle timer, which is
     * now 24h. Runs before the early return below so it happens even for a session that never got a
     * witness client.
     */
    for (const extraKey of entry.extraRelayClientKeys ?? []) {
      const extra = this.#relayClients.get(extraKey);
      if (!extra) continue;
      extra.unregisterSession(sidHex);
      if (!extra.hasSessions()) {
        extra.close();
        this.#relayClients.delete(extraKey);
      }
    }
    entry.extraRelayClientKeys = undefined;

    if (!client) return;
    // Idempotent: clear the entry's reference so a second teardown of the same entry no-ops.
    entry.relayClient = undefined;
    client.unregisterSession(sidHex);
    if (!client.hasSessions() && key && this.#relayClients.get(key) === client) {
      client.close();
      this.#relayClients.delete(key);
    }
  }

  /**
   * DOD-M12B-ACK-1 — live `/cello/content/1.0.0` stream counts on a session's direct path, or null
   * when the session has no active node.
   *
   * Answerable at runtime on purpose, in the same spirit as getConnectionMonitorPolicy: the count
   * is what decides whether the next send survives, and until this existed it could only be
   * recovered by measuring a log after the fact. It is also what lets the regression assert that a
   * slot was RELEASED, rather than that some particular number of messages happened to fit.
   */
  countSessionContentStreams(agentName: string, sessionId: string): { inbound: number; outbound: number } | null {
    const entry = this.#activeNodes.get(this.#k(agentName, sessionId));
    if (!entry || typeof entry.node.countProtocolStreams !== "function") return null;
    return entry.node.countProtocolStreams(entry.counterpartySessionPeerId, CELLO_CONTENT_PROTOCOL_ID);
  }

  /**
   * DOD-M12B-ACK-1 — the live content-stream counts for a peer, as log context.
   *
   * A diagnostic must not be able to break the failure path it describes, so a node that predates
   * `countProtocolStreams` (test fakes do) yields no fields rather than throwing.
   */
  #streamCensus(node: CelloNode, peerId: string): Record<string, number> {
    if (typeof node.countProtocolStreams !== "function") return {};
    try {
      const { inbound, outbound } = node.countProtocolStreams(peerId, CELLO_CONTENT_PROTOCOL_ID);
      return { contentStreamsInbound: inbound, contentStreamsOutbound: outbound, contentStreamsInboundCap: CONTENT_MAX_INBOUND_STREAMS };
    } catch {
      return {};
    }
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
    // DOD-M15-OFFER-SIGNED-1 review N5: the offer record has done its job the moment this session is
    // claimed. Keying it by session (the F1 fix) removed the accidental bound that agent-keying gave
    // it — each new offer used to overwrite the last — so without a clear on the SUCCESS path the
    // map gained one permanent entry per offer ever received, on directory-supplied keys. Cleared
    // here rather than only on refusal, which is what the doc comment always claimed.
    this.#receivers.clearOfferedDialer(agentName, sessionId);
    const inboundSr = this.#standingReceivers.get(agentName);
    if (!inboundSr) {
      // DOD-LOOP-1: per-agent — kick off (idempotent) creation so a retry finds it.
      void this.#receivers.ensureStandingReceiver(agentName, correlationId);
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

    const { node, gater, autoNat, seed } = inboundSr;

    // AC-015: update gater BEFORE retrieving multiaddr / returning to caller
    gater.setAllowedPeer(initiatorPeerId);
    await this.#evictPeersOutsideGate(node, gater, sessionId, initiatorPeerId, "inbound_promotion");

    const peerId = node.getPeerId();
    const addrs = node.listenAddresses();

    // Persist to SQLite. D4 review F1 (same as createSessionNode): a swallowed row-write failure
    // must fail the accept ONCE here — after D4a a rowless session refuses every ingest. The
    // standing receiver (this node) is consumed and rebuilt rather than left with its gater
    // pointed at this initiator.
    if (!this.#insertSessionRow(sessionId, agentName, counterpartyPubkey, "active")) {
      this.#standingReceivers.delete(agentName);
      // DOD-M12B-SESSION-SEED-1 (review F8): this abort happens BEFORE `#rememberSessionSeed`, so
      // the identity is not being handed to a session — it is being discarded, and is zeroed like
      // any other discard. (The two PROMOTION sites deliberately do not zero: there the same bytes
      // become the session's.)
      inboundSr.seed.fill(0);
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
      void this.#receivers.ensureStandingReceiver(agentName, correlationId);
      return {
        ok: false,
        reason: "session_persist_failed",
        guidance:
          "The daemon could not persist the session row (see session.row.write.failed in the log). " +
          "The inbound session was not accepted — a session without a durable row cannot receive content. " +
          "Check the daemon's database (disk space, permissions).",
      };
    }

    // Log observability event. `counterpartySessionPeerId` for the same reason as the initiator
    // side: this is the identity every later send will look for an open connection under, it is
    // never refreshed, and the peer's standing receiver may already have been rebuilt under a new
    // one. The RESPONDER is the side that can go stale — only the initiator dials, so this is the
    // half that inherits an id it never verified.
    this.#logger.info("session.node.created", {
      sessionId,
      agentName,
      sessionPeerId: peerId,
      counterpartySessionPeerId: initiatorPeerId,
      correlationId,
    });

    // Remove this agent's standing receiver from the slot and add to active map. The handed-off
    // node keeps its AutoNAT service (it continues to surface dialability).
    this.#standingReceivers.delete(agentName);
    // 006-CRYPTO: the hand-off path. A session promoted out of the standing receiver is as new as
    // one opened outbound, so it mints here too.
    this.#ephemerals.mintSessionEphemeral(agentName, sessionId);
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
    this.#rememberSessionSeed(agentName, sessionId, seed, initiatorPeerId, counterpartyPubkey);

    // DAEMON-004: register the content stream handler for the inbound session.
    await this.#contentIn.registerContentHandler(agentName, sessionId, node, counterpartyPubkey);
    // M7-SESSION-003 AC-004: act on the inbound session node's peer events too.
    /**
     * DOD-M12B-RESPONDER-ADDR-1 — LEARN THE INITIATOR'S ADDRESS, because we will need it and this is
     * the only moment we have it.
     *
     * MEASURED LIVE 2026-08-18. After an interruption the responder's re-dial reported
     * `session.transport.redial.unavailable` — *"this side holds no address for the counterparty, so
     * every send parks until they re-establish"* — and every reply it tried to send failed. The
     * initiator can always come back because it kept the addresses it dialled; the responder dialled
     * nothing, so it kept nothing.
     *
     * In plain terms that meant: whoever ANSWERED a conversation could not restart it. Their replies
     * went nowhere until the other side spoke first.
     *
     * The live connection has known the address all along — the responder is holding it right now,
     * because the initiator just dialled in on it. `#counterpartyAddrs` is the same store the
     * initiator fills from its signed relay assignment, and `#evictSessionCaches` hands both to the
     * revival record on the way down, so this needs no separate lifetime.
     */
    const inboundAddrs = node
      .getConnections()
      .filter((c) => c.peerId === initiatorPeerId && typeof c.remoteAddr === "string")
      .map((c) => c.remoteAddr as string);
    if (inboundAddrs.length > 0) {
      this.#counterpartyAddrs.set(this.#k(agentName, sessionId), [...new Set(inboundAddrs)]);
      this.#logger.info("session.counterparty.addr.learned", {
        agentName,
        sessionId,
        addrs: inboundAddrs.length,
        source: "inbound_connection",
        impact: "this side can now re-dial after an interruption instead of parking every reply",
      });
    } else {
      // NOT A WARNING. Review MEDIUM-4: accept runs off a signaling frame and the initiator dials
      // separately, so "no connection yet" is the ordinary in-flight case — warning on it puts a
      // signal on the normal path, which is how the one occurrence that matters gets buried. The
      // race-free capture is in `#wireSessionLiveness`'s onPeerConnect, which fires when the dial
      // actually lands; this read is only a fast path for when it already has.
      this.#logger.debug("session.counterparty.addr.deferred", {
        agentName,
        sessionId,
        initiatorPeerId,
        impact: "no connection observed yet; the address is captured when the counterparty connects",
      });
    }

    this.#liveness.wireSessionLiveness(agentName, sessionId, node, counterpartyPubkey, correlationId, initiatorPeerId);

    // M7 DOD-SPINE-6 / MSG-001-3b: the receiver also connects to the relay witness so
    // the relay can deliver the initiator's witnessed leaves (leaf_deliver) to it.
    if (relay) {
      await this.#connectSessionRelay(sessionId, node, agentName, relay, correlationId);
    }

    // Immediately spin up a replacement for THIS agent (async — do NOT await, AC-003)
    void this.#receivers.ensureStandingReceiver(agentName, correlationId);

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
      const unreadCount = this.#records.getUnreadReceivedCount(agentName, sessionId);
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
    // DOD-CAP-SELF-HEAL-1: OURS. Every caller of this with a non-sealed reason is a local teardown
    // — the operator's kill switch (`cello_set_agent_offline`), an internal error, a node replaced.
    // The counterparty did nothing, so they must not be charged a cap slot for it.
    this.#updateSessionStatus(agentName, sessionId, dbStatus, dbStatus === "interrupted" ? "local" : undefined);

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
    void this.#receivers.ensureStandingReceiver(agentName);
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
    const unreadCount = this.#records.getUnreadReceivedCount(agentName, sessionId);
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
    this.#contentOut.clearAwaitingForSession(agentName, sessionId);
    // M7-SESSION-003: drop the direct-path liveness flag (the seal gate already read
    // its verdict) so a destroyed/retired session retains no stale alive/gone state.
    this.#liveness.evictSession(agentName, sessionId);
    // M7-UPGRADE-002: drop the auto-acknowledge bookkeeping for a torn-down session.
    this.#contentDesynced.delete(key);
    /**
     * DOD-M15-NO-SILENT-REFUSAL-1 review N2: the UNPERSISTED half IS torn down, and only that half.
     * The in-memory fallback (now `RefusalNotices`' own, dropped by its `evictSession`) restores
     * what the deleted Map did, so it belongs in the teardown set exactly as that Map did. Leaving it out meant a daemon that could not
     * write to disk — already in trouble — grew without bound in memory as well. The durable rows
     * stay, for the reason below.
     */
    this.#notices.evictSession(agentName, sessionId);
    // DOD-M15-NO-SILENT-REFUSAL-1: the DURABLE notices are NOT torn down here, and the omission is
    // deliberate — this list is the documented teardown set, so anything absent from it needs a
    // reason. They live in `content_refusal_notices`, keyed on agent_id + session_id, and the
    // question they answer ("why did that person stop replying?") is one an operator asks AFTER a
    // session ends, most sharply for `session_committed` — a refusal that exists only because the
    // session was already sealed. Dropping them at seal would delete exactly the ones a sealed
    // session produces. Growth is one row per (session, reason), i.e. proportional to `sessions`.
    /**
     * DOD-M15-REFUSALTERMINAL-1 review F7 — named because this list is the documented teardown set.
     *
     * `#terminallyRefused` and `#terminalRefusalsLoaded` are a READ CACHE over
     * `terminal_content_refusals` and are dropped here with everything else in-memory; the durable
     * rows stay, for the same reason the notices do — the question they answer outlives the
     * session, and a fresh check reloads them on demand. `#terminalRefusalsReadFailedAt` goes too,
     * so a torn-down session's back-off does not delay the first read after it is revived.
     */
    this.#refusals.evictSession(agentName, sessionId);
    this.#responderSealSubmitted.delete(key);
    // DOD-MSG-4: drop the strict-in-order bookkeeping (witness map, held plaintext, high-water)
    // so a torn-down session retains no stale ordering state or buffered plaintext.
    this.#witnessedSeq.delete(key);
    /**
     * DOD-M15-SEALWIRE-1 bullet 6 (part A) — both salt maps are CACHES and both go.
     *
     * The salt is re-read from `sessions.content_salt` on revival, which is the reason Decision #8
     * persists it. The contribution is worthless once a salt exists, and if none was agreed yet, a
     * revival minting a fresh one is correct: the peer either also holds nothing (both re-derive
     * from the two current halves and reach the same bytes), or it derived against our old half
     * while we were down — in which case the agreement refuses by name, which is the outcome
     * Decision #10 asks for. What must never happen is a NEW contribution mid-session without a
     * teardown, and that is why `#saltContributionFor` mints once rather than per send.
     */
    this.#salts.evictSession(agentName, sessionId);
    // The throwaway secret is destroyed where the `#activeNodes` entry is DROPPED, not here — see
    // `#destroySessionEphemeralFor`. This call is the belt to that braces: both teardown paths that
    // evict have already dropped the entry, so it is a no-op for them, and it is what catches any
    // future path that evicts without going through one of those.
    this.#ephemerals.destroySessionEphemeralFor(agentName, sessionId);
    /**
     * B2b-2's three, and the pending one is SETTLED rather than dropped.
     *
     * A `delete` alone leaves any send waiting on that promise waiting until its own timer fires —
     * five seconds of a torn-down session holding a message that has nowhere to go. `closed` is the
     * truthful outcome: the agreement is over, because the session is.
     *
     * `#hashedWithoutSalt` and `#unsaltedAnnounced` go with the caches, and that is correct rather
     * than merely tidy. A revived session re-derives its frontier from durable state — leaves, held
     * rows, queued rows — so the adoption question is answered from disk, not from a flag that would
     * be a stale in-memory claim about a process that no longer exists. Re-announcing the fallback
     * once per revival is the right frequency too: it is what an operator reading a fresh log needs
     * in order to know why this session has no salt.
     */
    // SALTSPLIT-1 HIGH-2 goes with its mirror. SETTLED, never deleted: a send awaiting the
    // agreement must be TOLD the session is gone, not left waiting on a promise nobody resolves.
    this.#salts.settleSaltPending(agentName, sessionId, "closed");
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
    // DOD-M12B-STRAND-1 — THIS IS NO LONGER AN EPITAPH. Dropping the Map now drops a CACHE: the
    // frames are rows in `held_content`, and #restoreHeldContent brings them back the next time
    // this session gets a node. `session.content.held.discarded` is kept, at WARN rather than
    // ERROR, and only for what it now means — a gap is still open on a session going away, which
    // is worth an alarm even though nothing is lost.
    //
    // It fires ONLY when the durable rows are confirmed present. A hold whose persist failed is a
    // genuine loss and must not be reported with the same event as a survivor, so it gets its own
    // error naming the count that is actually gone. The check is a COUNT against the store rather
    // than a belief about the write that ran earlier.
    const strandedHolds = this.#heldContent.get(key);
    if (strandedHolds && strandedHolds.size > 0) {
      const canonicalSeqs = [...strandedHolds.keys()].sort((a, b) => a - b);
      // NULL means "we could not find out", and it must never render as "destroyed". The bare
      // catch this replaces coerced a failed COUNT to 0, which then claimed every held frame had
      // been lost — asserting a cause it had not established. It is not hypothetical:
      // #requireAgentId THROWS for a retired agent, on this exact path, so retiring an agent with
      // an open hold fabricated a data-loss alarm pointing at the persistence layer while the real
      // fault was name resolution.
      let durable: number | null = null;
      try {
        const row = this.#db?.prepare(
          "SELECT COUNT(*) AS n FROM held_content WHERE agent_id = ? AND session_id = ?",
        ).get(this.#requireAgentId(agentName), sessionId) as { n: number } | undefined;
        durable = row?.n ?? 0;
      } catch (err: unknown) {
        this.#logger.warn("session.content.held.durable_count.failed", {
          agentName, sessionId,
          impact: "cannot say whether the held frames are durable — reported as unknown, NOT as lost",
          error: err instanceof Error ? err.message : String(err),
        });
      }
      const lost = durable === null ? null : strandedHolds.size - durable;
      this.#logger.warn("session.content.held.discarded", {
        agentName,
        sessionId,
        count: strandedHolds.size,
        durable,
        canonicalSeqs,
        // NULL when the tree was not cached at teardown. Honest, and cheap — reloading the leaf
        // table to fill in a diagnostic field is not worth a disk read on every teardown, let
        // alone the cache resurrection it caused.
        treeSize: treeSizeBeforeEviction,
      });
      if (lost !== null && lost > 0) {
        this.#logger.error("session.content.held.lost", {
          agentName,
          sessionId,
          lost,
          held: strandedHolds.size,
          impact: "verified content was NOT written to held_content and is destroyed by this teardown — the sender was never acknowledged and believes it is still pending",
        });
      }
    }
    this.#heldContent.delete(key);
    // DOD-M12B-STRAND-1: the hydration guard goes with the cache it guards. Without this, a session
    // torn down and given a node again inside ONE process would never re-read its durable holds —
    // the frames would sit in the table, unreleasable, which is indistinguishable from the loss
    // this unit exists to stop.
    this.#held.evictSession(agentName, sessionId);
    // DOD-M15-DIVERGE-1: `#diverged` is NOT evicted here, and the omission is the point.
    //
    // It was, and that made the gate that reads it best-effort in exactly the population it targets.
    // This eviction runs on EVERY teardown including `destroySessionNode` with a non-sealed reason,
    // which writes status `interrupted` — one of the two statuses the seal gate is scoped to. So a
    // session that diverged and was then torn down arrived at the gate with the fact already
    // forgotten, and the read site cannot tell "not diverged" from "we forgot": both are
    // `has() === false`, both read ready, and the close proceeds.
    //
    // Divergence is a fact about the DURABLE TREE, not about the live node — the tree keeps the
    // misplaced leaf whether or not a node exists — so it does not belong to a cache keyed on node
    // lifetime. It is cleared where it actually stops being true: `clearDivergedOnTerminal`, below.
    //
    // NOT YET DURABLE ACROSS A RESTART, stated here rather than left to be rediscovered — the same
    // way `frontier-mismatch.ts` states its own trade. A daemon restart still empties this set, and
    // unlike a frontier mismatch (re-detected by the very next close) divergence is only
    // re-detected by the next send that gets an ack behind the frontier. Until it has a column, a
    // restarted daemon can read a diverged session as ready. Tracked as `DOD-M15-DIVERGE-DURABLE-1`.
    // DOD-M12B-SESSION-SEED-1: HAND THEM TO THE REVIVAL RECORD BEFORE DROPPING THEM. This eviction
    // runs on every teardown, including the interruption a revival is meant to undo — so clearing
    // the addresses here is what left a revived session unable to dial anyone. The revival record
    // has exactly the right lifetime for them: it dies when the session reaches a terminal status.
    const survivingAddrs = this.#counterpartyAddrs.get(key);
    if (survivingAddrs && survivingAddrs.length > 0) {
      const identity = this.#sessionSeeds.get(key);
      if (identity) identity.counterpartyAddrs = [...survivingAddrs];
    }
    this.#counterpartyAddrs.delete(key);
    this.#redialNotBefore.delete(key);
    this.#highWaterSeq.delete(key);
  }

  /**
   * Graceful shutdown: mark all active sessions as interrupted, stop all nodes.
   * Called from the SIGTERM / cello logout path (AC-009).
   * SQLite writes complete before this method returns.
   */
  /**
   * DOD-M12B-SHUTDOWN-1 — wait for a teardown step, but never forever.
   *
   * Every step of shutdown used to be an unbounded `await` on libp2p. That is what makes "the
   * daemon acknowledged the request but is still running" possible: nothing on the daemon side
   * emits a word while it hangs, so the operator's own message ("it may be stuck closing sessions
   * or its database") was a guess. Past the deadline the step is ABANDONED and SAID — the resources
   * it was closing are reclaimed by the OS on exit, and an exit is worth more than a tidy one.
   */
  async #boundedTeardown(work: Promise<unknown>, step: string, count: number): Promise<void> {
    if (count === 0) return;
    const started = Date.now();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<"timeout">((resolve) => {
      timer = setTimeout(() => resolve("timeout"), SHUTDOWN_STEP_DEADLINE_MS);
      timer.unref?.();
    });
    const outcome = await Promise.race([work.then(() => "done" as const), deadline]);
    if (timer) clearTimeout(timer);
    if (outcome === "timeout") {
      this.#logger.error("session.shutdown.step.timeout", {
        step, count, waitedMs: Date.now() - started,
        impact: "this teardown step did not finish and was abandoned so the daemon can exit; the OS reclaims what it held",
      });
    } else {
      this.#logger.debug("session.shutdown.step.done", { step, count, tookMs: Date.now() - started });
    }
  }

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

    // DOD-M12B-ACK-1: drop the inbound-content linger resets. The nodes they would reset are being
    // torn down here anyway, so firing after this point is pure noise on the way out.
    for (const timer of this.#lingeringStreams) clearTimeout(timer);
    this.#lingeringStreams.clear();

    /**
     * DOD-M15-RELAYLEAK-1 — **CLOSE THE RELAY CLIENTS. Shutdown never did.**
     *
     * This method stops every session NODE and left `#relayClients` untouched — verified by reading:
     * the whole of `gracefulShutdown` referenced `relayClient` zero times. Each cached client holds
     * an authenticated libp2p stream to a relay and a reader loop, so a `cello logout` left them
     * open until the process itself exited.
     *
     * That is a real cost rather than untidiness: the relay counts a reservation per client and its
     * slots are finite, so a daemon that restarts repeatedly consumes them faster than they are
     * released, which is the "agents cannot get a reservation" failure the relay's own limits note
     * describes from the other side.
     *
     * Best-effort and individually caught: teardown must not be the thing that throws. One client
     * that refuses to close must not prevent the next from being released.
     */
    for (const [key, client] of this.#relayClients) {
      try {
        client.close();
      } catch (err: unknown) {
        this.#logger.warn("session.relay_client.close_failed", {
          relayClientKey: key,
          reason: err instanceof Error ? err.message : String(err),
          impact: "one cached relay client did not close cleanly on shutdown; the rest are still released",
        });
      }
    }
    this.#relayClients.clear();

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
        const res = this.#db.prepare(
          // DOD-CAP-SELF-HEAL-1: OURS. Our own shutdown ended these, not the counterparty.
          "UPDATE sessions SET status = 'interrupted', updated_at = ?, interrupted_at = COALESCE(interrupted_at, ?), interrupted_by = 'local' WHERE status = 'active'",
        ).run(now, interruptedAt);
        /**
         * ⚠️ THE AUTHORITATIVE PERSISTENCE STEP WAS SILENT ON SUCCESS, AND THAT IS WHY ITS OWN TEST
         * CANNOT BE DIAGNOSED.
         *
         * `AC-009 (binary): SIGTERM marks active sessions interrupted` failed twice in a row on CI
         * and blocked a publish. The captured daemon log ends at `daemon.started` with nothing after
         * it — because the ONLY thing this block could ever log was a thrown error. So the evidence
         * is equally consistent with two very different failures:
         *
         *   - the shutdown never ran (signal handler, early exit, teardown ordering), or
         *   - it ran and the UPDATE matched ZERO rows (visibility, or the rows genuinely were not
         *     `active` at that moment).
         *
         * Nothing in the log separates them, so the test's own comment picked one — *"the daemon's
         * connection can begin its shutdown UPDATE against a snapshot that predates this commit"* —
         * added a `wal_checkpoint(TRUNCATE)` for it, and the test failed again. One diagnosis, one
         * fix, one recurrence: the point at which the diagnosis is the thing to doubt.
         *
         * `changes` was on the result object the whole time and nobody read it. It discriminates the
         * two outright, and this is the last line the daemon writes before it dies, so it is the last
         * thing anyone investigating a bad shutdown will see.
         *
         * ⚠️ INFO AND NOT AN ERROR EVEN AT ZERO. Zero is the ordinary case for a daemon with no
         * active sessions — most shutdowns. Making it a warning would fire on nearly every clean exit
         * and train operators to filter the one signal that matters.
         */
        this.#logger.info("session.interrupt.db.write.complete", {
          sessionId: "__all__",
          rowsMarkedInterrupted: Number(res.changes),
          impact: Number(res.changes) === 0
            ? "no session rows were 'active' at shutdown, so none was marked interrupted. Ordinary for a daemon with no live sessions — but if a session WAS expected to be interrupted, the UPDATE ran and matched nothing, which is a visibility or state question and NOT a shutdown that failed to run."
            : "these sessions are recorded as interrupted by OUR OWN shutdown, so they can be resumed or sealed rather than read as abandoned.",
        });
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
    // DOD-M12B-SHUTDOWN-1: BOUNDED. `node.stop()` awaits libp2p's own teardown, which has no
    // deadline of its own — one connection that will not close holds this, and this holds the whole
    // daemon. Measured 2026-08-17: `cello logout` acknowledged, then the process was still alive
    // 30+ seconds later and needed a signal. An abandoned stop costs a socket the OS reclaims when
    // we exit; an unbounded wait costs the exit itself.
    await this.#boundedTeardown(Promise.all(stopPromises), "session_nodes", stopPromises.length);
    this.#activeNodes.clear();
    // Evict in-memory per-session caches (trees reload from SQLite; received-content
    // plaintext must not survive shutdown in memory).
    this.#trees.clear();
    this.#receivedContent.clear();
    // DOD-M12B-SESSION-SEED-1 (review F5): transport identities are key material and belong in the
    // same sentence as the plaintext above. Shutdown marks every active row `interrupted` by direct
    // SQL, so no `#updateSessionStatus` destroy fires for them — without this, every live session's
    // seed survives the shutdown in memory for as long as the process lingers.
    for (const identity of this.#sessionSeeds.values()) identity.seed.fill(0);
    this.#sessionSeeds.clear();
    // 006-CRYPTO: the per-session throwaway secrets belong in the same sentence, for the same
    // reason and with the same measured cause — shutdown marks rows `interrupted` by direct SQL, so
    // no per-session teardown fires for them, and this process is known to linger (a `cello logout`
    // was still alive 30+ seconds later). Without this, every live session's key survives the
    // shutdown in memory for as long as it lingers.
    this.#ephemerals.destroyAll();

    // Stop ALL per-agent standing receivers (DOD-LOOP-1). In PARALLEL and BOUNDED: this was a
    // sequential await per agent with no deadline, so five agents meant five chances for one stuck
    // libp2p teardown to hold the exit — and it sits between the operator being told the daemon is
    // stopping and the process actually going.
    await this.#boundedTeardown(
      Promise.all([...this.#standingReceivers].map(async ([agentName, sr]) => {
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
      })),
      "standing_receivers",
      this.#standingReceivers.size,
    );
    // Same reason: a receiver's seed is the identity it has already advertised in
    // `session_offer_accept` for any session it is mid-handshake on.
    for (const sr of this.#standingReceivers.values()) sr.seed.fill(0);
    this.#standingReceivers.clear();
    this.#srReservationRetry.clear();
    this.#srLastRejectionReason.clear();
    this.#srLastRespreadAt.clear();

    // Release the SQLite handle so the DB file is no longer held open after shutdown
    // (review L5). Queries guard on `#db === null` and degrade to empty/null.
    if (this.#db) {
      try { this.#db.close(); } catch { /* already closed */ }
      this.#db = null;
    }
  }

  /**
   * DOD-M12B-REVIVAL-BOUND-1 — close every session the revival window has expired.
   *
   * `abandonSession` is the right instrument and already exists: it flips the status FIRST and
   * synchronously, annexes held content so the operator does not lose mail that has nowhere to go,
   * and retires the node. It notarizes nothing, which is the point — we are closing a door, not
   * asserting how it came to be open.
   *
   * One session's failure must not strand the rest, so each is caught and logged; the sweep runs at
   * boot beside the restart-seal resolver and a throw there would take the daemon with it.
   *
   * @returns how many sessions actually flipped — not how many were attempted.
   */
  async closeExpiredUnrevivableSessions(nowMs: number, windowMs: number): Promise<number> {
    // Stamp FIRST. A row with no clock cannot be evaluated by the query below, and this is the only
    // thing that gives it one. Running it before every sweep is safe because the write is scoped to
    // rows that have no timestamp yet.
    this.#queries.stampMissingInterruptedAt(nowMs);
    const expired = this.#queries.listExpiredUnrevivableSessions(nowMs, windowMs);
    let closed = 0;
    for (const s of expired) {
      try {
        if (await this.abandonSession(s.agentName, s.sessionId)) {
          closed += 1;
          this.#logger.info("session.revival_bound.closed", {
            agentName: s.agentName,
            sessionId: s.sessionId,
            // The cause we could NOT establish is the reason this ends without a receipt — log it
            // so an operator asking "why no certificate?" gets the answer here.
            interruptedBy: s.cause ?? "unknown",
            windowMs,
            // NAME THE FORFEIT. Until this sweep ran, `cello_close_session` (without `force`) still
            // accepted this session — it takes `status IN ('active','interrupted')` — so the
            // operator could have come back days later and obtained a real seal. `abandoned` is in
            // TERMINAL_SEAL_REFUSALS, so after this they cannot. That is a deliberate trade (SI-001
            // forbids auto-sealing a session nobody chose to end) and it costs something real, so
            // it is stated rather than left implicit in a WHERE clause.
            forfeited: "a seal was still obtainable by hand until now; it is not after this",
          });
        }
      } catch (err) {
        this.#logger.warn("session.revival_bound.close.failed", {
          agentName: s.agentName,
          sessionId: s.sessionId,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }
    // UNCONDITIONAL. A sweep that found nothing and a sweep that never really ran must not produce
    // the same silence — this line is the only proof the control executed at all.
    this.#logger.info("session.revival_bound.sweep", { expired: expired.length, closed, windowMs });
    if (closed !== expired.length) {
      // Not arithmetic for the reader to do: a session the security control failed to close is one
      // that is still interrupted and still accepting content.
      this.#logger.warn("session.revival_bound.sweep.incomplete", {
        expired: expired.length,
        closed,
        failed: expired.length - closed,
        impact: "these sessions are still interrupted and still accept content from any peer that dials them",
      });
    }
    return closed;
  }

  getSessionsForAgent(agentName: string): SessionRecord[] {
    if (!this.#db) return [];
    // Scoped by the STABLE id. `agent_name` is not a column of `sessions` any more, so it is stamped
    // back on for display — and it is exactly the name we just resolved the id FROM, so no join is
    // needed and no stale copy can exist.
    const rows = this.#db
      .prepare("SELECT * FROM sessions WHERE agent_id = ? ORDER BY updated_at DESC")
      .all(this.#requireAgentId(agentName)) as unknown as SessionRecord[];
    return rows.map((r) => ({ ...this.#salts.saltStatusOf(r, agentName), agent_name: agentName }));
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
      .all()
      // The joined display name is what `#saltSuspended` is keyed on. NULL only where the agent row
      // is missing — an orphaned session, which has no live in-memory state to be suspended in.
      .map((r) => {
        const row = r as SessionRecord & { agent_name?: string | null };
        return this.#salts.saltStatusOf(row, row.agent_name ?? null);
      }) as unknown as SessionRecord[];
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
  /**
   * DOD-M12B-INTERRUPTED-ESCALATE-1 — flip a session to `sealed`, synchronously, without needing a
   * live node.
   *
   * **`destroySessionNode(…, "sealed")` cannot be relied on to do this.** It returns early at
   * `if (!entry) return`, and the status write lives 26 lines BELOW that guard — so it flips the
   * status only for a session that still has an `#activeNodes` entry. An interrupted session has
   * none by construction: every producer of that status deletes the entry. Before this method, a
   * unilateral seal on an interrupted session stored the notarized root and the certificate and
   * left the row saying `interrupted` — the receipt landed and nothing that represents it moved.
   * `cello_sessions` still showed it stuck, `cello_close_session` still refused it by name, and the
   * restart-seal resolver re-selected it on the next boot to run the whole ceremony again against a
   * session that already held a receipt.
   *
   * STATUS FIRST AND SYNCHRONOUS, teardown second — the order `abandonSession` uses and the one
   * `retireSession` documents. The flip is the load-bearing half; the teardown makes memory agree
   * with it. `#updateSessionStatus` also runs the terminal disposition hooks (held content is
   * annexed, not stranded), which the early return skipped entirely.
   */
  markSealed(agentName: string, sessionId: string): boolean {
    // The terminal guard (abandoned/sealed must not be overwritten) lives in #updateSessionStatus,
    // so it holds for destroySessionNode and retireSession too — not only for callers of this
    // wrapper.
    return this.#updateSessionStatus(agentName, sessionId, "sealed");
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
    this.#queries.recordSealCertificate(agentName, sessionId, sealedRootHex, legibilityJson);
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
    /**
     * WHAT ACTUALLY HAPPENED, and it is written to the row — review F3.
     *
     * `key_refused` is its own source rather than a borrowed `stream_close`, because the row's
     * `interrupted_by` is what an operator reads days later: labelling a key-authentication refusal
     * `relay_stream_close` sends them to the relay fleet for a fault in the payload.
     */
    source: "relay_frame" | "stream_close" | "key_refused",
  ): Promise<boolean> {
    if (!this.#db) return false;

    // H-3 SECURITY: only an 'active' session may transition to 'interrupted'.
    // A late or forged relay frame must NOT revert a 'sealed', 'seal_interrupted_pending',
    // or already-'interrupted' session back to 'interrupted'. This mirrors the
    // stream-close guard in #watchRelayStream below — the two paths must agree.
    const existing = this.#queries.getSessionRecord(agentName, sessionId);
    if (!existing || existing.status !== "active") {
      this.#logger.warn("session.interrupt.ignored", {
        sessionId,
        source,
        currentStatus: existing?.status ?? "absent",
        reason: "session_not_active",
      });
      // FALSE, not void — the caller needs to know nothing was torn down (review F11).
      return false;
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
          // DOD-CAP-SELF-HEAL-1: labelled by SOURCE, because the two are not the same event.
          //
          //   relay_frame  — the relay telling us the counterparty went. THEIRS. The D18
          //                  disconnect-evasion move, and it must keep counting.
          //   stream_close — OUR witness stream to the relay ended. That fires on a relay restart,
          //                  a relay fleet roll, or a local network blip. Claiming the counterparty
          //                  did it means three relay deploys permanently refuse a peer who was
          //                  never involved — and relay deploys are routine, so it ratchets faster
          //                  than daemon restarts do.
          //
          // `relay_stream_close` is its own label and STILL COUNTS (the bound excuses only 'local'),
          // because an attacker who can disturb our relay link must not get a free cap reset. It is
          // recorded honestly rather than blamed on the wrong party.
          `UPDATE sessions SET status = 'interrupted', updated_at = ?, message_count = ?, interrupted_at = ?, interrupted_by = '${source === "relay_frame" ? "counterparty" : source === "key_refused" ? "key_refused" : "relay_stream_close"}' WHERE agent_id = ? AND session_id = ? AND status = 'active'`,
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
      /**
       * THE SECRET GOES WITH THE ENTRY — 006-CRYPTO, review pass 2 finding 2.
       *
       * This is the path an interrupted session actually takes, and it is the ORDINARY way a
       * session ends badly: a relay blip, a closed stream, a sleeping laptop. Because it does not
       * evict (see below) the secret used to survive here, and when the session later sealed
       * `destroySessionNode` returned at its `if (!entry) return` without evicting either — so the
       * receipt landed, the session was over, and the key stayed resident until the process exited.
       *
       * The reasons below for KEEPING the other caches do not transfer to key material: buffered
       * plaintext must stay drainable and TTF timers must stay armed, whereas a secret nothing
       * reads must not stay alive. A revived session mints a fresh one and re-keys, which is
       * Decisions Carried #5 and is only true because of this line.
       */
      this.#ephemerals.destroySessionEphemeralFor(agentName, sessionId, entry.correlationId);
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
    return true;
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
    const landed = Number(result.changes) > 0;
    if (landed) {
      // DOD-M12B-SESSION-SEED-1 (review F3): `seal_interrupted_pending` is NOT a state revival
      // exists for, and the first build's comment wrongly grouped it with `interrupted`.
      // `ingestReceivedContent` refuses it outright, and BOTH sweeps that could otherwise close a
      // session — `listRestartOrphanedSessions` and `listExpiredUnrevivableSessions` — filter
      // `status = 'interrupted'`, so a pending-seal session is unrevivable AND unswept. Keeping its
      // identity meant holding it until the process exited. Entry 42's own measurement is that 59%
      // of seals that start never finish, so that is the common path, not a corner.
      this.#destroySessionSeed(opts.agentName, opts.sessionId);
    }
    return landed;
  }

  // ─── DAEMON-004: daemon-owned Merkle tree ──────────────────────────────────

  // ─── The content pipeline's public surface, kept on the manager ────────────────────────────
  //
  // Two of these live in `session-content-send.ts` and five in `session-content-ingest.ts`; the
  // return types below say which. Their documentation is there, next to the code it describes.
  // They stay reachable here because 451 call sites across the daemon and its tests name them on
  // the manager, and moving those is a change to every caller for no gain.
  //
  // ⚠️ The signatures are DERIVED, not copied. `sendContent` alone carries ~60 lines of parameter
  // documentation and a five-branch return type; a hand-copied duplicate of that is a second
  // declaration that drifts from the first, silently, the moment either is edited. Deriving them
  // makes drift impossible — a change to the moved signature is a change to this one.

  ingestReceivedContent(
    ...args: Parameters<SessionContentIngest["ingestReceivedContent"]>
  ): ReturnType<SessionContentIngest["ingestReceivedContent"]> {
    return this.#contentIn.ingestReceivedContent(...args);
  }

  sendContent(
    ...args: Parameters<SessionContentSender["sendContent"]>
  ): ReturnType<SessionContentSender["sendContent"]> {
    return this.#contentOut.sendContent(...args);
  }

  placeOwnLeaf(
    ...args: Parameters<SessionContentSender["placeOwnLeaf"]>
  ): ReturnType<SessionContentSender["placeOwnLeaf"]> {
    return this.#contentOut.placeOwnLeaf(...args);
  }

  takeReceivedContent(
    ...args: Parameters<SessionContentIngest["takeReceivedContent"]>
  ): ReturnType<SessionContentIngest["takeReceivedContent"]> {
    return this.#contentIn.takeReceivedContent(...args);
  }

  recordWitnessedSequence(
    ...args: Parameters<SessionContentIngest["recordWitnessedSequence"]>
  ): ReturnType<SessionContentIngest["recordWitnessedSequence"]> {
    return this.#contentIn.recordWitnessedSequence(...args);
  }

  getUndeliverableSeqs(
    ...args: Parameters<SessionContentIngest["getUndeliverableSeqs"]>
  ): ReturnType<SessionContentIngest["getUndeliverableSeqs"]> {
    return this.#contentIn.getUndeliverableSeqs(...args);
  }

  handleContentFrameForTest(
    ...args: Parameters<SessionContentIngest["handleContentFrameForTest"]>
  ): ReturnType<SessionContentIngest["handleContentFrameForTest"]> {
    return this.#contentIn.handleContentFrameForTest(...args);
  }

  /** Loaded from SQLite on first access so it survives a restart (AC-007). NEVER null: an unknown session yields an EMPTY tree. */
  getSessionTree(agentName: string, sessionId: string): SessionTree {
    const key = this.#k(agentName, sessionId);
    const cached = this.#trees.get(key);
    if (cached) return cached;
    const tree = this.#queries.loadTreeFromDb(agentName, sessionId);
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
    // DOD-M15-RELAYAUTH-1 review H1: the RELAY's gater must also admit this dial, and it only does
    // so once it holds the assignment. Await that here — see the method's own comment for why the
    // counterparty presenting it cannot be relied on.
    await this.#authorizeCircuitDialsToCounterparty(agentName, sessionId, entry, addrs);
    let lastError = "";
    for (const addr of addrs) {
      try {
        await entry.node.dial(addr);
        // DOD-M12B-REDIAL-1: keep them. They arrived in the signed assignment and were used once
        // and dropped, which is the reason nothing could ever dial this counterparty again.
        this.#counterpartyAddrs.set(this.#k(agentName, sessionId), [...addrs]);
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
   * DOD-M15-RELAYAUTH-1 review H1 — **THE GATE WAS DENYING THE LEGITIMATE DIAL, AND USUALLY.**
   *
   * With the gater installed, a relay refuses a circuit dial unless it already holds a
   * directory-signed assignment naming both transport peer ids. Both parties get that assignment
   * from the directory independently, and until this method existed, each only presented it to
   * relays IT had chosen — so whether a dial was allowed came down to which of two independent
   * network races finished first:
   *
   *   1. WE connect to the witness relay, then dial the counterparty's circuit address. ~2 RTT.
   *   2. THEY connect to their witness relay, then — unawaited, on a fresh dial + auth + record —
   *      tell their RESERVATION relay about the session. ~3–4 RTT.
   *
   * Nothing sequenced (1) against (2), and (1) is shorter, so we usually arrived first and were
   * refused. The session still opened and reported `transportMode: "relay"`, so the failure was
   * invisible: every message for the life of that conversation quietly took the store-and-forward
   * park path, and the only trace was a denial logged on a third machine nobody tails.
   *
   * The fix is to stop racing. Whoever is about to dial presents the assignment to the relay that
   * will gate that dial, and WAITS for the relay to confirm it recorded it. The ordering becomes
   * local to one thread of execution, so there is nothing left to lose.
   *
   * Safe by construction: we are a participant the assignment names, so the relay's own participant
   * check passes; and the assignment is self-authenticating (a directory signature the relay
   * verifies against its consortium set), so presenting it more widely grants nothing that forging
   * it would not already require.
   *
   * Best-effort by design — a relay we cannot reach must not stop us from dialling. If the record
   * fails we dial anyway: a dial that might be refused is strictly better than no dial.
   */
  async #authorizeCircuitDialsToCounterparty(
    agentName: string,
    sessionId: string,
    entry: ActiveSessionEntry,
    addrs: string[],
  ): Promise<void> {
    const assignment = entry.relayAssignment;
    if (!assignment || !entry.relaySessionIdBytes) return; // direct/legacy/persisted: no credential to present
    const sessionIdHex = Buffer.from(entry.relaySessionIdBytes).toString("hex");

    // One presentation per distinct relay, not per address: a counterparty commonly advertises
    // several circuit addresses on the SAME relay.
    const seen = new Set<string>();
    for (const addr of addrs) {
      const relayPeerId = /\/p2p\/([^/]+)\/p2p-circuit/.exec(addr)?.[1];
      if (!relayPeerId || seen.has(relayPeerId)) continue;
      seen.add(relayPeerId);
      // The witness relay already has it — registerSession presented it when the session was wired.
      if (relayPeerId === entry.relayPeerId) continue;

      const baseRelayAddr = addr.split("/p2p-circuit")[0] ?? addr;
      try {
        const clientKey = `${agentName}::${relayPeerId}`;
        let client = this.#relayClients.get(clientKey);
        if (!client) {
          if (!this.#relayReceiptStore && this.#db) this.#relayReceiptStore = new RelayReceiptStore(this.#db, this.#logger);
          if (!this.#sealLeafStore && this.#db) this.#sealLeafStore = new SessionSealLeafStore(this.#db, this.#logger);
          client = this.#detachedRelayClientBuilder?.(agentName, relayPeerId, [baseRelayAddr], {
            receiptStore: this.#relayReceiptStore ?? undefined,
            sealLeafStore: this.#sealLeafStore ?? undefined,
            // DOD-M15-RELAYSLOTS-1: read at each auth, never snapshotted — the token expires hourly.
            onlineToken: () => this.getDirectoryOnlineToken(agentName),
          });
          if (!client) {
            this.#logger.warn("session.transport.dial_authorization.no_builder", {
              sessionId,
              relayPeerId,
              impact: "cannot present the assignment to the relay that gates this dial; if the counterparty has not presented it either, the dial will be refused and every message will fall to the park path",
              correlationId: entry.correlationId,
            });
            continue;
          }
          this.#relayClients.set(clientKey, client);
          // Review M4: remember it so teardown releases it — this is a SECOND client for the
          // session, and detach only knows about the witness one.
          entry.extraRelayClientKeys = [...(entry.extraRelayClientKeys ?? []), clientKey];
        }
        // No leaf handler: this relay is not witnessing the session, it only needs the binding.
        client.registerSession(sessionIdHex, entry.node, undefined, assignment, this.#leafRecords.sessionGenesisPrevRoot(agentName, sessionId));
        const recorded = await client.recordAssignmentAndWait(entry.node, sessionIdHex);
        if (recorded) {
          this.#logger.info("session.transport.dial_authorized", {
            sessionId,
            relayPeerId,
            impact: "the relay that gates this circuit dial now holds the assignment authorizing it",
            correlationId: entry.correlationId,
          });
        } else {
          this.#logger.warn("session.transport.dial_authorization.not_recorded", {
            sessionId,
            relayPeerId,
            impact: "the relay did not confirm the assignment; the dial below may be refused and messages would fall to the park path",
            correlationId: entry.correlationId,
          });
        }
      } catch (err: unknown) {
        this.#logger.warn("session.transport.dial_authorization.failed", {
          sessionId,
          relayPeerId,
          error: extractErrorMessage(err),
          impact: "could not tell the relay that gates this dial about the session; the dial is attempted anyway",
          correlationId: entry.correlationId,
        });
      }
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
    /**
     * DOD-M15-RELAYLEAK-1 — release a DETACHED seal transport when this submission is done.
     *
     * Only the detached branch registers a session here, so this can never remove a live one. The
     * client is closed only when it has no sessions left and the cache still holds THIS client —
     * the same two guards `#detachSessionRelay` uses, and for the same reason: a racing teardown
     * must not close a freshly-built replacement for the same key.
     */
    const releaseDetached = (): void => {
      if (transport.releaseOnDone !== true) return;
      try {
        entry.relayClient.unregisterSession(sessionId);
        if (!entry.relayClient.hasSessions()) {
          for (const [key, cached] of this.#relayClients) {
            if (cached === entry.relayClient) {
              cached.close();
              this.#relayClients.delete(key);
              break;
            }
          }
        }
      } catch (err: unknown) {
        this.#logger.warn("session.seal.transport.release_failed", {
          agentName,
          sessionId,
          reason: err instanceof Error ? err.message : String(err),
          impact: "a detached seal relay client could not be released; it is held until process exit",
        });
      }
    };
    /**
     * ⚠️ try/finally, NOT a call at each return. There are three exits today and adding a release
     * to each would be a hand-kept list — the shape this milestone has been bitten by repeatedly,
     * where the FOURTH exit added later quietly leaks. Here the release cannot be bypassed by a new
     * return, and it runs on the throw path too, which is where a leak matters most.
     */
    try {

      // M7-UPGRADE-002 idempotency: this party submits its responder SEAL leaf AT MOST ONCE per
      // session. BOTH cello_close_session and the auto-acknowledge path call here; the first to reach
      // this point wins, the second short-circuits. The check+set is SYNCHRONOUS (before any await) so
      // two near-simultaneous triggers (e.g. B's own close racing A's delivered SEAL ctrl leaf) cannot
      // both submit. Cleared below on a relay submit failure so a genuine retry can proceed.
      // DOD-M12B-INTERRUPTED-ESCALATE-1 — THE MARK MUST SURVIVE A RESTART, or one automatic retry
      // permanently forfeits the receipt.
      //
      // `#responderSealSubmitted` is in memory. A session whose close was in flight when the daemon
      // stopped already has our SEAL ctrl leaf in the relay log — and on the next boot the mark is
      // empty, so the restart-seal resolver's automatic close would submit a SECOND one. The
      // directory requires exactly one ctrl leaf (`ctrlLeaves.length !== 1 → unilateral_seal_leaf_invalid`)
      // and the carry is durable, so every future attempt would carry both and be refused forever.
      //
      // The durable evidence already exists and was simply not consulted: our own ctrl leaf is in
      // `session_seal_leaves`. Recover the escalation values from it instead of submitting again.
      if (!this.#responderSealSubmitted.has(sealKey)) {
        const durable = this.#park.recoverOwnSealCtrlLeaf(agentName, sessionId);
        if (durable === "unknown") {
          // REFUSE, do not submit. A second ctrl leaf makes the session unsealable forever, and the
          // question "is one already there?" just failed to answer. Refusing costs this close; a
          // second leaf costs the receipt permanently.
          return { ok: false, reason: "seal_leaf_recovery_unavailable" };
        }
        if (durable !== "none") {
          this.#logger.info("session.seal.leaf.already_submitted.recovered", {
            sessionId, agentName, sequenceNumber: durable.sequenceNumber,
            impact: "our SEAL ctrl leaf is already in the relay log from a previous run; submitting a second would make this session unsealable forever",
          });
          this.#responderSealSubmitted.set(sealKey, durable);
        }
      }
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
        /**
         * ⚠️ `sealPayload` IS PASSED, AND ITS ABSENCE WAS THE WHOLE DEFECT — `DOD-M15-SEALWIRE-1`
         * bullets 3+4, review pass 1, F1.
         *
         * These exact bytes were computed two lines above, hashed, and then dropped: `submitLeaf` had
         * no parameter for them. So the directory received a SHA-256 pre-image nobody transmitted, and
         * the client's SIGNED `final_root` — the one value in the seal the relay cannot produce — was
         * unrecoverable. Four legs of this line shipped and were reviewed green while the head of the
         * chain did not exist.
         *
         * The payload and the hash MUST come from the same derivation. If they ever diverge the
         * directory reports `seal_payload_unbound`, whose guidance says *"someone between them and here
         * altered or fabricated the payload — the relay is the only party on that path"* — a correct
         * relay accused by name, in an error written to sound like an attack, for a mismatch made here.
         */
        const result = await entry.relayClient.submitLeaf(entry.node, entry.relaySessionIdBytes, contentHash, LEAF_KIND_CTRL, sealPayload);
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
    } finally {
      releaseDetached();
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
  getSealUpgradeReadiness(agentName: string, sessionId: string): SealUpgradeReadiness {
    const record = this.#queries.getSessionRecord(agentName, sessionId);
    return {
      known: !!record,
      /**
       * THE REASON TRAVELS WITH THE VERDICT — review F-A, correcting review F1's fix.
       *
       * F1 made the gate binary and moved the label into the log, and I did that in ONE consumer.
       * This struct feeds a second one (`evaluateSealUpgrade`), which had only a boolean to read and
       * therefore called every cause `content_tamper` — at ERROR, with no guidance. An honest peer on
       * a newer build raised a security alarm on B's reconnect: exactly the harm the F1 fix was
       * written to remove, reached through the consumer it did not check.
       *
       * Returning the LABEL rather than a boolean is what makes that impossible to reintroduce: a
       * caller cannot flatten what it never receives flat.
       */
      unverifiable: this.#contentDesynced.get(this.#k(agentName, sessionId)) ?? null,
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
    const record = this.#queries.getSessionRecord(agentName, sessionId);
    // Only an ACTIVE session auto-acks. A committed/sealing/sealed/interrupted session is out of
    // scope (already sealing, or needs the interrupted/upgrade path), not an auto-ack candidate.
    if (!record || record.status !== "active") return;
    /**
     * SI-002 verifiability gate: never auto-sign a session whose content we could not verify.
     *
     * ⚠️ THIS COMMENT SAID THE OPPOSITE UNTIL `DOD-M15-SEALWIRE-1` part B1 (review F-C). It read
     * *"Today the ONLY tracked unverifiable cause is a content_hash mismatch = TAMPER"*, which was
     * true when a mismatch was the only way to fail the cross-check and is false now: B1 added an
     * unreadable algorithm name and a salted frame with no salt, and **both are ordinary**.
     *
     * Genuine tamper is a SECURITY event — ERROR, reason `content_tamper`, which is what the AC-008
     * alarm keys on. The other two must NOT wear that name, or the alarm fires on an honest peer
     * running a newer build and the operator learns to dismiss it.
     *
     * 🚨 AND `content_unverifiable` IS RESERVED — DO NOT REUSE IT HERE. It is specced for *parked
     * content unrecoverable*, one of the two reasons (with `desynced`, B's tree behind the canonical
     * sealed tail) awaiting the deferred MSG-001-3b canonical-sequence reconciliation. B1's first
     * attempt emitted exactly that string for a different condition, which would have made the two
     * indistinguishable in the log the day the follow-on landed. Hence
     * `content_verification_unavailable`, deliberately distinct.
     */
    const unverifiable = this.#contentDesynced.get(ackKey);
    if (unverifiable) {
      /**
       * DOD-M15-SEALWIRE-1 part B1 (review F1) — THE GATE FIRES FOR BOTH, THE ALARM ONLY FOR ONE.
       *
       * `content_tamper` is what the AC-008 alarm keys on, and it must keep meaning what it says. A
       * frame we could not verify because the peer named an algorithm this build cannot read is an
       * ordinary version difference; raising a tamper alarm for it would train an operator to
       * dismiss the alarm, which costs more than the skew.
       *
       * But the REFUSAL TO AUTO-SIGN is identical in both cases and non-negotiable: SI-002 is "never
       * auto-sign a session whose content we could not verify", and "could not" covers both.
       */
      this.#logger.error("session.seal.autoack.skipped", {
        sessionId,
        reason: unverifiable === "tampered" ? "content_tamper" : "content_verification_unavailable",
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

  #markContentUnverifiable(agentName: string, sessionId: string, why: "tampered" | "unverifiable"): void {
    const key = this.#k(agentName, sessionId);
    if (why === "unverifiable" && this.#contentDesynced.get(key) === "tampered") return;
    this.#contentDesynced.set(key, why);
  }

  /** DOD-M12B-LEAF-TRIGGERS-FETCH-1 test seams. */
  setLeafFetchGraceMsForTest(ms: number): void { this.#leafFetchGraceMs = ms; }
  markContentPresentForTest(agentName: string, sessionId: string, contentHashHex: string): void {
    this.#contentIn.markContentResolved(agentName, sessionId, contentHashHex);
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
    /** DOD-M12B-INDEX-1: of `heldCount`, how many are THIS side's own sends versus the
     *  counterparty's. They block a seal identically and mean completely different things. */
    heldOwn: number; heldReceived: number;
    /**
     * DOD-M15-DIVERGE-1 — this tree and the relay's counter have PROVABLY parted.
     *
     * The other two counters both measure the same direction: positions the relay committed that
     * this tree has not appended. This is the OPPOSITE direction — this tree holds a leaf at a
     * position the relay assigned to something else — and it is the direction an injected or forged
     * leaf appears in. Without it `ready` was asymmetric, and a diverged session read as perfectly
     * sealable right up until the counterparty answered `leaf_count_mismatch`, which is terminal.
     */
    diverged: boolean;
  } {
    const key = this.#k(agentName, sessionId);
    // DOD-M12B-STRAND-1: hydrate first. An under-counted `heldCount` reports a gapped session as
    // READY, and this gate's whole purpose is to stop a short chain being signed — the counterparty
    // answers `leaf_count_mismatch`, which is TERMINAL and costs the receipt permanently. Failing
    // open here is the one outcome worse than refusing a healthy close.
    //
    // Hydrate WITHOUT releasing: this is a read path now — the status surface asks it for every
    // active session — and a read that appends leaves, advances the root and rings the doorbell is
    // a diagnostic command that delivers messages. The release still runs on every path that was
    // going to mutate anyway.
    this.#held.ensureHeldRestored(agentName, sessionId, { release: false });
    const treeSize = this.getSessionTree(agentName, sessionId).size();
    const highWaterSeq = this.#highWaterSeq.get(key) ?? -1;
    const heldCount = this.#heldContent.get(key)?.size ?? 0;
    // Review HIGH-2: NOT `(highWaterSeq + 1) - treeSize`. That subtraction silently assumes the
    // relay's sequence space and this tree's index space count the same things, and they do not:
    // `relay-node.ts` increments seq_counter for EVERY accepted leaf including CTRL (0x02), while
    // NOTHING APPENDS A CTRL LEAF TO THIS TREE — `submitSealLeaf` deliberately computes its root
    // without mutating the durable tree. So one seal ctrl leaf offsets the two spaces permanently,
    // and any msg witnessed afterwards would read as a missing leaf FOREVER. That is a false
    // positive, and a false positive here is worse than the bug it guards: it makes a healthy
    // session unsealable, leaving force-abandon (no receipt) as the only exit. `seal-upgrade.ts`
    //
    // ⚠️ THIS SENTENCE USED TO READ *"`appendSessionLeaf` is only ever called with 'msg'"*, AND THAT
    // WAS FALSE WHEN IT WAS WRITTEN — corrected, not deleted, per review pass 1 F8. Line ~7730
    // appends "doc", and `WritableSessionTreeLeafKind` permits "ctrl" outright, so the type does not
    // enforce it either. Doc leaves are harmless to this subtraction because they are witnessed by
    // the relay too (LEAF_KIND_DOC) and counted in BOTH spaces; the load-bearing property is only
    // ever about CTRL. Stating it as "msg only" made a narrower claim than the code supports and a
    // stronger one than it holds — so a reader checking it would find a counter-example, conclude
    // the reasoning was stale, and be one step from "fixing" the subtraction back.
    // already documents the same `leaf_count - 1` offset.
    //
    // `#witnessedSeq` answers the question directly instead of inferring it. It gains an entry when
    // the relay witnesses a COUNTERPARTY msg leaf (ctrl leaves are excluded at the call site) and
    // loses it the moment that leaf is appended. So its remaining size IS the count of leaves the
    // ordering authority has committed and this tree has not — no arithmetic, no space mismatch,
    // and it cannot go negative.
    const missingLeaves = this.#witnessedSeq.get(key)?.size ?? 0;
    // DOD-M12B-INDEX-1: our OWN held sends are counted separately. They block a seal just as a
    // received hold does, but they are not "a message from the counterparty that has not arrived" —
    // and a refusal that calls them that tells the operator to wait for something already in hand,
    // which is how a close-retry loop ends at force-abandon and no receipt.
    let heldOwn = 0;
    for (const e of this.#heldContent.get(key)?.values() ?? []) if (e.origin === "sent") heldOwn++;
    // DOD-M15-DIVERGE-1: the third term, and the one that closes the asymmetry. `#diverged` is set
    // only where the parting is PROVEN — an ack came back behind our frontier — never where it is
    // merely suspected, because a gate that refuses a healthy session forever is worse than the bug
    // it guards: force-abandon, with no receipt, becomes the only exit.
    const diverged = this.#records.isSessionDiverged(agentName, sessionId);
    return {
      ready: missingLeaves === 0 && heldCount === 0 && !diverged,
      treeSize, highWaterSeq, heldCount, missingLeaves,
      heldOwn, heldReceived: heldCount - heldOwn,
      diverged,
    };
  }

  /**
   * DOD-M12B-SEAL-STUCK-1 — the operator-facing answer to "can this session be closed?".
   *
   * THREE STATES, because there are three answers. `sealReadiness` above returns a boolean plus raw
   * counters, and both of its counters are easy to misread on a surface:
   *
   *  - `missingLeaves` is `#witnessedSeq.size`, which is every position the relay witnessed that
   *    this tree has not appended — and a HELD frame keeps its witness entry. So it INCLUDES the
   *    held ones. Reporting it beside `heldCount` counts the same message twice and labels one copy
   *    "never received" when it is sitting on our own disk. Split here into what each actually is.
   *  - Neither counter survives a restart on its own: `#witnessedSeq` is memory-only. Held content
   *    is durable since DOD-M12B-STRAND-1, but a position the relay witnessed for content that
   *    never arrived leaves no trace. So for a session carrying leaves this process did not watch
   *    arrive, "clean" is unknowable — and saying `ready` there invites a close that gets
   *    `leaf_count_mismatch` back, which is terminal and costs the receipt for good.
   */
  sealReadinessView(agentName: string, sessionId: string): SealReadinessView {
    const key = this.#k(agentName, sessionId);
    const r = this.sealReadiness(agentName, sessionId);
    // DOD-M15-DIVERGE-1: READ THIS BEFORE THE `!ready` BRANCH, and the order is load-bearing.
    // `diverged` is now a term in `ready`, so a diverged session reaches `!ready` — where it would
    // report `blocked` with awaitingArrival and heldBehindGap both ZERO, replacing an accurate,
    // specific answer with one that describes nothing and invites a retry that can never work.
    // Divergence is permanent and has its own state; the gap cases below are the ones that resolve.
    if (r.diverged) {
      // NOT `ready`. The tree is ahead of the relay's counter for good, so a close here signs a root
      // the counterparty answers `leaf_count_mismatch` to — terminal, and the receipt is gone. The
      // raw counters cannot see this: nothing is missing and nothing is held.
      return { state: "unknown", reason: "record_diverged_from_relay" };
    }
    if (!r.ready) {
      const oldestHeldMs = this.#queries.oldestHeldMs(agentName, sessionId);
      return {
        state: "blocked",
        // The witness map counts a held frame until it is appended, so subtract the RECEIVED holds
        // to avoid reporting one message twice. NOT the own-sends: the witness map only ever
        // carries counterparty leaves, so subtracting ours would push this count below the truth.
        awaitingArrival: Math.max(0, r.missingLeaves - r.heldReceived),
        heldBehindGap: r.heldCount,
        oldestHeldMs,
      };
    }
    if (r.treeSize > 0 && !this.#orderingObserved.has(key)) {
      return {
        state: "unknown",
        reason: "witness_state_predates_daemon_start",
      };
    }
    return { state: "ready" };
  }

  /**
   * DOD-M12B-ABANDON-NOTIFY-1 — tell the counterparty we have hung up. Best effort, never blocking.
   *
   * A force-abandon marks the session terminal HERE and did nothing else, so the other side kept
   * its half live, kept retrying delivery into it, and kept trying to re-establish — forever,
   * because nothing would ever answer. That is what produced the 2026-08-17 notification storm:
   * surviving halves calling continuously while the operator saw connection requests from agents
   * nobody was driving.
   *
   * BEST EFFORT, and every caller must treat it that way. A peer that is offline cannot be told, so
   * this is an improvement on silence rather than a guarantee — and it must never delay or fail the
   * abandon, which is the operator's escape hatch out of a session that can never seal.
   */
  async notifyCounterpartyAbandon(agentName: string, sessionId: string, correlationId?: string): Promise<AbandonNoticeResult> {
    const entry = this.#activeNodes.get(this.#k(agentName, sessionId));
    if (!entry) {
      // NAMES ITS CAUSE, and it is not the network. An `interrupted` session has no node — the
      // restart sweep and markInterrupted both tear it down — and `interrupted` is exactly the
      // status force-abandon exists for. Reporting this as "could not be reached" sends the
      // operator to debug a connection when the answer is in our own process. At INFO, not debug,
      // because it is the common case and it changes what the operator is told.
      this.#logger.info("session.abandon.notice.skipped", {
        agentName, sessionId, reason: "no_local_node", correlationId,
        impact: "this side had already torn the session down, so there was nothing to send on — the counterparty was not told",
      });
      return { told: false, reason: "no_local_node" };
    }
    let stream: Stream | undefined;
    try {
      // Through the RE-DIAL path, not a bare newStream. A session worth force-abandoning is very
      // often one whose connection blipped — the peer is online and calling us, which is the whole
      // complaint — so one demand-driven dial is the difference between telling them and not.
      stream = await this.#contentOut.openContentStream(agentName, sessionId, entry, correlationId);
      // Typed against protocol-types so the shape cannot drift from the declaration the receiving
      // side (and any second client implementation) reads.
      const notice: SessionAbandonedNotice = {
        type: "session_abandoned_notice",
        session_id: sessionId,
        ...(correlationId === undefined ? {} : { correlation_id: correlationId }),
      };
      const frame = encodeCbor(notice) as Uint8Array;
      stream.send(lp.encode.single(frame));
      await stream.close();
      this.#logger.info("session.abandon.notice.sent", { agentName, sessionId, correlationId });
      return { told: true, reason: "sent" };
    } catch (err: unknown) {
      if (stream !== undefined) {
        try { stream.abort(err instanceof Error ? err : new Error(String(err))); } catch { /* already gone */ }
      }
      this.#logger.warn("session.abandon.notice.failed", {
        agentName, sessionId, correlationId,
        error: err instanceof Error ? err.message : String(err),
        impact: "the counterparty was not told and may keep calling until it gives up",
      });
      return { told: false, reason: "send_failed" };
    }
  }

  /**
   * DOD-M12B-ABANDON-NOTIFY-1 — the receiving half: our counterparty has abandoned, so retire.
   *
   * RETIRING IS NOT DELETING. The counterparty walking away forfeits the notarized receipt; it must
   * not also cost the operator the record of what was actually said. The transcript and the tree
   * stay exactly as they are.
   *
   * Only an `active` or `interrupted` session moves. A SEALED session has a notarized receipt and
   * must never be turned into an abandoned one by a late or duplicated notice — that would destroy
   * the artifact this protocol exists to produce. An unknown session is refused rather than
   * created: an authenticated stream proves who is speaking, not that a session exists.
   */
  async retireOnCounterpartyAbandon(agentName: string, sessionId: string, correlationId?: string): Promise<boolean> {
    const record = this.#queries.getSessionRecord(agentName, sessionId);
    if (!record) {
      this.#logger.warn("session.abandon.notice.unknown_session", { agentName, sessionId, correlationId });
      return false;
    }
    if (record.status !== "active" && record.status !== "interrupted") {
      this.#logger.debug("session.abandon.notice.ignored", {
        agentName, sessionId, status: record.status, correlationId,
        reason: "session already terminal",
      });
      return false;
    }
    // THE TRANSPORT IS RETIRED. THE SESSION IS NOT.
    //
    // The first build flipped the status to `abandoned`, and that was wrong twice over. It handed
    // the abandoning party a button that DENIES US OUR RECEIPT: the unilateral seal exists for
    // exactly this case — "the counterparty never co-closes" — and produces a notarized certificate
    // after a grace period, but `cello_close_session` refuses an `abandoned` session outright. So
    // one frame from them destroyed a recovery path that already existed, remotely and for free.
    // Today the abandoner can only go silent, and going silent is what the unilateral seal was
    // built to survive.
    //
    // What the DoD actually asks for is that we stop calling them. That is a transport concern:
    // mark it, stop re-dialling, stop retrying delivery — and leave the session sealable.
    const marked = this.#queries.markCounterpartyAbandoned(agentName, sessionId);
    if (!marked) return false;
    // The addresses go, so the demand-driven re-dial has nothing to dial. This is the storm.
    const key = this.#k(agentName, sessionId);
    this.#counterpartyAddrs.delete(key);
    this.#logger.warn("session.counterparty.abandoned", {
      agentName, sessionId, priorStatus: record.status, correlationId,
      impact: "the counterparty ended this session on their side, so nothing more will arrive and replies cannot reach them — this side stops calling. The session is NOT terminal: a unilateral seal is still available, and the transcript is intact",
    });
    // AWAITED, and `retireSessionNode` NOT `destroySessionNode`. The latter writes the status back
    // — `error` maps to `interrupted` — a few hundred milliseconds later, which silently undid the
    // whole unit; the former is the method that tears a node down without touching the status, and
    // it is what the local force-abandon path already uses.
    await this.retireSessionNode(agentName, sessionId);
    return true;
  }

  /**
   * DOD-CAP-SELF-HEAL-1 — the numbers behind a cap refusal, for the OPERATOR'S alarm only.
   *
   * Kept off `checkUnknownSenderAcceptanceBound`'s return on purpose. That refusal is byte-identical
   * across tiers by design (DOD-TIER-3) so a blocked party cannot tell blocking from throttling;
   * attaching the counts to it would put the oracle straight into the value the refusal path
   * carries. This is a separate, purely local read, and nothing it returns crosses the wire.
   */
  capDiagnostics(agentName: string, counterpartyPubkey: string): { tier: number; cap: number; counted: number; mustClear: number; blocked: boolean } {
    const tier = this.#records.getTier(agentName, counterpartyPubkey);
    const cap = this.#records.resolveTierBound(agentName, tier, "max_sessions");
    const counted = this.#queries.countActiveSessionsForCounterparty(agentName, counterpartyPubkey);
    return {
      tier, cap, counted,
      // How many to close to get UNDER the cap — not how many exist. At 5 against a cap of 3 the
      // answer is 3, and "close 5" tells the operator to do more than the job needs.
      mustClear: Math.max(0, counted - cap + 1),
      blocked: tier === TIER.BLOCKED,
    };
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
    /**
     * ⚠️ REGISTER THE SESSION TOO — the seam must leave the state production leaves.
     *
     * A relay client that has never been told about a session holds no starting point for it, and
     * since `DOD-M15-SELFCHAIN-1` every submit on such a session is refused: there is nothing for
     * the chain links to anchor to. Production always registers, because attaching a relay is what
     * registration IS. A seam that attached the client and skipped the registration left fixtures
     * exercising a refusal path, and the failure surfaced as "the seal never happened" in a test
     * about away-mode replies.
     */
    relayClient.registerSession(
      Buffer.from(relaySessionIdBytes).toString("hex"),
      entry.node,
      undefined,
      entry.relayAssignment,
      this.#leafRecords.sessionGenesisPrevRoot(agentName, sessionId),
    );
  }

  pushReceivedContentForTest(agentName: string, sessionId: string, seq: number, content: string, senderPubkey: string): void {
    this.#records.recordTranscriptMessage(agentName, sessionId, seq, "received", new TextEncoder().encode(content), "test");
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
    const record = this.#queries.getSessionRecord(agentName, sessionId);
    if (record?.status !== "sealed") return null;
    return { type: "sealed", unreadCount: this.#records.getUnreadReceivedCount(agentName, sessionId) };
  }

  // ─── CELLO-M7-MSG-001: delivery ACK / TTF tracking (send side) ──────────────

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
      this.#onAwaitingTtf?.(agentName, sessionId, hashHex, entry.content, entry.structure1Cbor, entry.structure2Cbor, entry.contentHashAlg, entry.structure1Signature, entry.leafKind);
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
    // B2b-1 review F2 — the THIRD `#parkContent` caller, and the one that was left unthreaded.
    void this.#park.parkContent(agentName, sessionId, hashHex, entry.content, entry.structure1Cbor, entry.structure2Cbor, entry.contentHashAlg);
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
    // DOD-M15-FRAME-1: the POSITION only, deliberately — this path does not act on `fatal`, and the
    // reason is that its identity proof is somewhere else and is already fail-closed. Parked content
    // arrives inside a sealed envelope carrying the sender's signature over
    // (session_id, recipient_pubkey, content_hash), and recovery already refuses a missing, bad, or
    // wrong-signer envelope. Adding a second, weaker refusal here on the ordering record would gate
    // mail retrieval on a record the relay-degraded path is allowed to omit, which is the
    // false-positive shape this unit is careful to avoid. The live direct path is where the ordering
    // record IS the proof, and that is where `fatal` is consumed.
    return this.#refusals.recordFrameOrdering(agentName, sessionId, structure1Cbor, structure2Cbor, contentHash, correlationId, "park").seq;
  }

  /**
   * DOD-M15-FRAME-1 — NARROWING THE GATE DOES NOT EVICT ANYONE ALREADY INSIDE. This does.
   *
   * libp2p consults the gater only when a connection is ESTABLISHED, so narrowing it never evicts a
   * peer already attached. That is why this sweep exists and why it cannot be replaced by the gate.
   *
   * A peer that attached early can therefore hold its connection open, still be attached when the
   * receiver is promoted, and be sitting there when the content protocol activates. DOD-M15-ASSIGN-1
   * shrank who can get that foothold — an unclaimed standing receiver now admits nobody inbound,
   * where it used to admit everyone — but it did not, and could not, change the constraint above.
   *
   * That is the foothold the whole injection path depends on — placed before the door narrows. The
   * frame-level gate above refuses what they send; this closes the connection they send it on, so
   * the stranger is not merely ineffective but gone, and is not sitting there for the next protocol
   * to activate.
   *
   * BEST-EFFORT BY CONSTRUCTION, and it must stay that way. A failure to hang up one peer must not
   * fail the session setup that is mid-flight — the frame gate is the load-bearing control and it
   * does not depend on this succeeding. Relay peers are exempt: they are on the OUTBOUND allowlist
   * because reservation refreshes ride them, and hanging one up would cost the agent its inbound
   * reachability to remove a peer that cannot speak the content protocol anyway.
   */
  async #evictPeersOutsideGate(
    node: CelloNode,
    gater: SessionConnectionGater,
    sessionId: string,
    allowedPeerId: string,
    trigger: string,
  ): Promise<void> {
    let connections: Array<{ peerId: string }>;
    try {
      connections = node.getConnections();
    } catch (err: unknown) {
      this.#logger.debug("session.gate.evict.unavailable", {
        sessionId, trigger, error: extractErrorMessage(err),
      });
      return;
    }
    const toEvict = connections
      .map((c) => c.peerId)
      .filter((peerId) => peerId !== allowedPeerId && !gater.isAllowedOutboundPeer(peerId));
    /**
     * CONCURRENT AND CAPPED, because the count is ATTACKER-CONTROLLED (review F4).
     *
     * This runs inside `acceptSession`, before the session row is written, and the standing receiver
     * used to accept everyone (closed by DOD-M15-ASSIGN-1) — so opening N connections to an agent's advertised receiver used
     * to make every later session setup on that agent wait for N sequential graceful closes.
     * `hangUp` is libp2p's graceful close and takes no timeout, so the wait was unbounded in both
     * directions. Evicting an injection foothold must not itself become the way to stall an agent.
     *
     * The cap is a LOGGED truncation, never a silent one: what is left behind still cannot inject
     * (the frame gate refuses it and now hangs it up on first contact), and the next promotion
     * sweeps again — but an operator reading this needs to know the sweep did not finish.
     */
    const EVICT_CAP = 32;
    const batch = toEvict.slice(0, EVICT_CAP);
    if (toEvict.length > batch.length) {
      this.#logger.warn("session.gate.evict.capped", {
        sessionId, trigger, attached: toEvict.length, evicting: batch.length,
        impact: "more peers were attached outside the gate than one promotion evicts; the rest keep their connections until a later sweep, and are refused and hung up by the frame gate if they speak",
      });
    }
    await Promise.allSettled(batch.map(async (peerId) => {
      try {
        await node.hangUp(peerId);
        this.#logger.warn("session.gate.evicted", {
          sessionId, trigger, evictedPeerId: peerId, allowedPeerId,
          impact: "a peer attached to this node before the session narrowed its gate was disconnected; libp2p does not re-run the gater against live connections, so it would otherwise have stayed attached when the content protocol activated",
        });
      } catch (err: unknown) {
        // Best-effort: the frame gate still refuses anything this peer sends, and now hangs it up.
        this.#logger.debug("session.gate.evict.failed", {
          sessionId, trigger, peerId, error: extractErrorMessage(err),
        });
      }
    }));
  }

  /**
   * Stop a session whose counterparty's key could not be tied to them.
   *
   * Reuses the identity-freeze machinery rather than inventing a second way for a session to stop:
   * the operator-facing shape, the refusal-to-revive, and the status write are already right there,
   * and a second mechanism is a second thing to keep correct.
   */
  async #freezeSessionForKeyRefusal(
    agentName: string,
    sessionId: string,
    reason: string,
    correlationId?: string,
  ): Promise<void> {
    /**
     * THE REASON IS RECORDED BEFORE THE TEARDOWN, AND SURVIVES IT — review F2.
     *
     * The teardown destroys this session's key material and used to clear the reason with it, so the
     * listing recomputed `NOT_YET_AGREED` and the agent was told *"still agreeing its key, sending is
     * held"* — a reassurance, for the one detection in this unit that means someone may be
     * substituting keys on the connection. Its only real consumer was a log line.
     */
    this.#ephemerals.noteContentEncryptionReason(agentName, sessionId, CONTENT_ENCRYPTION_REASONS.KEY_REFUSED);
    /**
     * ⚠️ `"key_refused"`, NOT `"stream_close"` — review F3, and this is error substitution of the
     * exact kind Invariant 3 names. `stream_close` is written to the row as
     * `interrupted_by = 'relay_stream_close'`, so a key-authentication refusal was durably recorded
     * as a relay problem and an operator debugging it would go and look at the relay fleet.
     */
    const stopped = await this.markInterruptedWithDetails(agentName, sessionId, 0, "key_refused");
    /**
     * OBSERVE THE OUTCOME rather than asserting it — review F11. `markInterruptedWithDetails`
     * returns early when the row is not `active`, so claiming "the session was stopped" here
     * unconditionally would state something that did not happen.
     */
    this.#logger.error("session.key.session_stopped", {
      agentName, sessionId, correlationId, reason,
      stopped,
      impact: stopped
        ? "the session was stopped rather than continued unencrypted; a substituted key would otherwise have been handed exactly the plaintext it was reaching for"
        : "the session was already not active, so nothing was torn down here — the refusal stands and no content was accepted",
      guidance: CONTENT_ENCRYPTION_GUIDANCE[CONTENT_ENCRYPTION_REASONS.KEY_REFUSED],
    });
  }

  /**
   * Test seam: see every decoded inbound content frame, as it arrived.
   *
   * Review F4. The "bytes on the wire are ciphertext" claim needs the ACTUAL frame; asserting on a
   * freshly sealed stand-in tests the crypto primitive and stays green when the send path is
   * reverted to putting plaintext on the wire. There is no other way to reach the decoded frame from
   * outside — the handler consumes it and hands ingest the plaintext.
   *
   * Read-only by construction: the callback receives the frame and cannot influence routing.
   */
  observeInboundContentFramesForTest(cb: (frame: Record<string, unknown>) => void): void {
    this.#inboundFrameObserver = cb;
  }

  /** Injected by the daemon once its per-agent key providers exist. See `#keyProviderResolver`. */
  setKeyProviderResolver(resolver: (agentName: string) => KeyProvider | undefined): void {
    this.#keyProviderResolver = resolver;
  }

  /**
   * Test seam: force this session's own salt half, so the LOCAL-defect path is reachable.
   *
   * `generateSaltContribution` cannot produce a degenerate half, which is the point of it — so the
   * only way to exercise "our own random source is broken" end-to-end is to stand in for the broken
   * source. Named `…ForTest` like every other seam in this file, and it writes the same map
   * production writes rather than a parallel one, so a test cannot pass against state the daemon
   * never reads.
   */
  /**
   * Test seam: run the auto-acknowledge gate, exactly as the counterparty's SEAL ctrl leaf does.
   *
   * `DOD-M15-SEALWIRE-1` part B1, review F-B. The gate has ONE production call site — inside the
   * relay leaf handler, behind `leaf_kind === CTRL && !authored_by_us` — so reaching it from a test
   * needs a live relay client delivering a real ctrl leaf. The consequence was measured: my
   * "tampered never downgrades" test wrapped its decisive assertion in
   * `if (skipped.length > 0)`, which was ALWAYS FALSE, so the whole `content_tamper` vs
   * `content_verification_unavailable` branch had no coverage anywhere in the repo and two mutants
   * on it survived the full gate.
   *
   * It calls the REAL private method rather than reproducing its logic, so a test cannot pass
   * against a decision production does not make.
   */
  runAutoAcknowledgeGateForTest(agentName: string, sessionId: string, correlationId = "test"): void {
    this.#maybeAutoAcknowledgeSeal(agentName, sessionId, correlationId);
  }

  /**
   * Test seam: deliver an inbound salt frame, exactly as the content-stream decoder does.
   *
   * 006-CRYPTO finding 2. WHICH of the four reasons the peer gave decides what the operator is told,
   * and reaching that decision from a test otherwise needs a second live daemon that has closed
   * adoption for a specific reason — which is not something a counterparty can be asked to do on
   * demand. The four labels are the whole point of the finding, so they need to be reachable.
   *
   * It calls the REAL private handler rather than reproducing its routing, so a test cannot pass
   * against a decision production does not make. It takes the DECODED frame, so it deliberately
   * does NOT stand in for the decoder above it — the length and vocabulary checks there have their
   * own tests driving `handleContentFrameForTest`.
   */
  async handleSaltFrameForTest(
    agentName: string,
    sessionId: string,
    frame: SaltAgreementFrame,
    correlationId = "test",
  ): Promise<void> {
    await this.#salts.handleSaltFrame(agentName, sessionId, frame, correlationId);
  }

  /**
  

  /**
    /**
   * TEST SEAM — put a session into the state a real one is in between announcing and being answered.
   *
   * Reaching that state for real needs a live counterparty connection, which the daemon-level
   * fixtures do not have; without a seam the wait could only be tested by not testing it. It calls
   * the same private registration the announce path calls, so it cannot drift from it.
   */
  markSaltAgreementPendingForTest(agentName: string, sessionId: string, boundMs?: number): void {
    this.#salts.markSaltPending(agentName, sessionId, boundMs);
  }

  getSessionContentSalt(agentName: string, sessionId: string): Uint8Array | null {
    return this.#salts.getSessionSalt(agentName, sessionId);
  }

  /**
   * THE SALT, OR WHY THERE ISN'T ONE — `DOD-M15-INCLUSION-1`, fallback-finder finding 2.
   *
   * `getSessionContentSalt` above answers `null` for THREE different situations, and a caller that
   * turns that null into a sentence for an operator gets two of them wrong:
   *
   *   `none`       — no salt was ever agreed. The session really is unsalted.
   *   `unreadable` — a salt row EXISTS and could not be used: the wrong width (corruption on this
   *                  operator's own disk), or the read threw.
   *
   * The distinction is not cosmetic. `unreadable` means the session's leaves WERE hashed under a
   * salt, so telling its operator *"this session's content hashes are UNSALTED … start a session
   * while you are both connected"* is an affirmatively false statement about a security property
   * their session has, and it points them at their counterparty over damage to their own database.
   * That is the same defect `#getSessionSalt`'s own F8 note was written to end, re-committed one
   * surface out.
   *
   * ⚠️ IT DELEGATES — there is no second read here. Calling `#getSessionSalt` first means the salt
   * this reports is the salt the hashing path uses, including its cache and its wrong-width refusal.
   * A parallel query would be free to disagree with it, which is the whole failure this returns a
   * reason to prevent.
   */
  getSessionContentSaltState(
    agentName: string,
    sessionId: string,
  ): { salt: Uint8Array } | { salt: null; reason: "none" | "unreadable" } {
    const salt = this.#salts.getSessionSalt(agentName, sessionId);
    if (salt) return { salt };
    if (!this.#db) return { salt: null, reason: "unreadable" };
    try {
      const row = this.#db
        .prepare("SELECT length(content_salt) AS n FROM sessions WHERE agent_id = ? AND session_id = ?")
        .get(this.#requireAgentId(agentName), sessionId) as { n?: number | null } | undefined;
      // A row with a non-empty blob that `#getSessionSalt` still refused is the corruption case: the
      // bytes are there and they are not a salt. NULL or zero-length is a genuine absence.
      const stored = row?.n ?? 0;
      return { salt: null, reason: stored > 0 ? "unreadable" : "none" };
    } catch {
      // The read that would tell us which case it is has itself failed, so "no salt was agreed" is
      // exactly the thing we cannot assert.
      return { salt: null, reason: "unreadable" };
    }
  }

  /**
   * Announce our state to the counterparty: a contribution if we hold no salt, a fingerprint if we
   * do. Called on every counterparty connect — first connection, reconnect and revival alike — and
   * on receiving a peer contribution.
   *
   * ⚠️ THIS PARAGRAPH USED TO SAY *"nothing hashes with the salt yet, so a frame that never lands
   * costs nothing today"*, and ended by instructing the next unit not to carry it forward unchanged.
   * **This is that unit, and pass 2 caught me leaving it** — I corrected the same claim inside
   * `session.salt.announce.failed`'s `impact` in the previous pass and walked past the method header
   * saying the opposite twenty lines above it.
   *
   * As it stands now: the SEND is still best-effort, but a frame that never lands is no longer free.
   * A first send waiting on this agreement falls back to an unsalted hash, and that is permanent for
   * the session. The catch therefore settles the pending under `announce_failed` rather than leaving
   * the send to time out — so the cost is one dial attempt and an accurate reason, instead of five
   * seconds and a diagnosis blaming the counterparty for a frame we never sent.
   */
  async #sendSaltFrame(agentName: string, sessionId: string, correlationId?: string, override?: SaltAgreementFrame): Promise<void> {
    const entry = this.#activeNodes.get(this.#k(agentName, sessionId));
    if (!entry) return;
    // `override` is the repair and the mismatch notice: a frame the AGREEMENT chose, which is not
    // the one our current state would produce. A side that holds a salt normally announces a
    // fingerprint — the repair has it send its CONTRIBUTION instead, which is the whole mechanism.
    /**
     * `#saltState`, NOT a direct call to the minting accessor — review F15, and this one line was
     * the difference between the safety argument written for the repair and the code that ran.
     *
     * It read `ownContribution: this.#salts.saltContributionFor(...)`, which mints unconditionally. Both
     * arguments are evaluated, so a session that already held a salt got a fresh half minted into
     * `#saltContributions` even though `ownSaltFrame` discards it on that branch — and
     * `#evictSessionCaches` drops the half on every teardown while the salt stays on disk, so ANY
     * revived session hit it, before any inbound frame could be handled.
     *
     * The consequence was not cosmetic. `#ownSaltHalf` never returned null, so `STATE_DIVERGENT`
     * was dead code, and a revived session would REPAIR its counterparty onto a half its salt was
     * never built from — then both sides froze on `salt_fingerprint_mismatch`, whose guidance sends
     * the operator to compare build versions with a counterparty that did nothing wrong.
     */
    const state = this.#salts.saltState(agentName, sessionId);
    const frame = override ?? ownSaltFrame(state);
    if (!frame) {
      // Neither a salt nor a half. `#saltState` does not produce this, so it is a defect rather
      // than a state to paper over — and inventing a contribution here is exactly what F15 was.
      this.#logger.error("session.salt.announce.failed", {
        agentName, sessionId, correlationId, reason: "no_salt_and_no_contribution",
        impact: "this side has neither an agreed salt nor a half to offer, so it announced nothing; no half was invented, because one minted now would not be the half any stored salt was built from",
      });
      return;
    }
    /**
     * ⚠️ REGISTERED BEFORE THE DIAL, NOT AFTER IT — review Finding 2, and this ordering is the whole
     * of constraint 2 for the case that actually happens.
     *
     * This sat after `await newStream(...)`, which negotiates the protocol with the peer and takes
     * tens to hundreds of milliseconds. A `cello_send` landing inside that interval found nothing
     * pending, took the park-only exit, hashed unsalted, and **closed adoption for the life of the
     * session** — a session with a live counterparty and an agreement about to complete. The feature
     * off forever, and the log telling the operator their counterparty was on an old build.
     *
     * That is precisely the failure constraint 2 exists to prevent, arriving by the one route the
     * implementation did not cover: the gap between deciding to announce and the frame leaving.
     *
     * Park-only is untouched — it never reaches this line, because `#sendSaltFrame` returns at the
     * `!entry` guard above when there is no active node. And a failed announce settles the waiter in
     * the catch below rather than leaving a send to sit out the full bound for a frame that never
     * left.
     */
    if (!frame.adoptionClosed) this.#salts.markSaltPending(agentName, sessionId);
    // Held outside the try so the catch can retire a stream that was opened and then failed to
    // write — the same leak, and the same fix, as `#sendDeliveryAck`.
    let saltStream: Stream | undefined;
    try {
      const stream = await entry.node.newStream(entry.counterpartySessionPeerId, CELLO_CONTENT_PROTOCOL_ID);
      saltStream = stream;
      stream.send(lp.encode.single(encodeCbor({
        type: "session_salt_agreement",
        session_id: sessionId,
        ...(frame.contribution ? { contribution: frame.contribution } : {}),
        ...(frame.fingerprint ? { fingerprint: frame.fingerprint } : {}),
        ...(frame.adoptionClosed ? { adoption_closed: frame.adoptionClosed } : {}),
      }) as Uint8Array));
      await stream.close();
      this.#logger.debug("session.salt.announced", {
        agentName, sessionId, correlationId,
        /**
         * THREE STATES, not two. This read `fingerprint ? holds_salt : offering_contribution`, which
         * was exhaustive until the adoption refusal put a third frame on the wire — and a refusal
         * carries no fingerprint, so it logged as `offering_contribution`: the log claiming we asked
         * for a salt at the exact moment we told the peer we were declining one. An operator reading
         * the pair would see an offer that was never answered and go looking for a dropped frame.
         */
        state: frame.adoptionClosed ? "adoption_closed" : frame.fingerprint ? "holds_salt" : "offering_contribution",
      });
    } catch (err: unknown) {
      /**
       * ⚠️ RELEASE THE WAITER — the frame never left, so there is nothing to wait for.
       *
       * Registering before the dial (above) means a failed announce would otherwise leave a first
       * send holding for the full five seconds against a frame that was never sent. Settling here
       * makes the failure cost one dial attempt instead of the whole bound, and B2b-2 turned this
       * from theory into something a user feels: it is the pause before their first message.
       */
      this.#salts.settleSaltPending(agentName, sessionId, "announce_failed");
      this.#logger.warn("session.salt.announce.failed", {
        agentName, sessionId, correlationId, error: extractErrorMessage(err),
        // Review F1: this used to end "so no message is affected", which was FALSE in the situation
        // it fires in — a one-sided announce is exactly what put the two sides out of step, and the
        // peer used to freeze the session over it. It converges now, so the claim is true again;
        // it is stated with its reason rather than as a bare reassurance.
        //
        // ⚠️ B2b-2 CHANGED THE LAST CLAUSE'S TRUTH. "Nothing hashes with the salt yet" was true for
        // part A and is now false: a first send waiting on this agreement falls back to sha256 when
        // it fails, which permanently unsalts the session. Not a message LOST — a protection not
        // taken, and the sentence has to stop promising otherwise.
        impact: "the counterparty was not told our salt state on this attempt. We re-announce on every reconnect, and a side that is out of step re-offers its half rather than refusing, so the agreement converges from here. No message is affected, but a first send waiting on this agreement now falls back to an unsalted hash, which is permanent for this session.",
      });
      if (saltStream !== undefined) {
        try { saltStream.abort(err instanceof Error ? err : new Error(String(err))); } catch { /* already gone */ }
      }
    }
  }

  async #freezeOnIdentityFailure(
    agentName: string,
    sessionId: string,
    reason: string,
    correlationId?: string,
  ): Promise<void> {
    await this.#freezeSession(agentName, sessionId, reason, {
      event: "session.content.identity.frozen",
      observation: "a frame failed to verify against the expected counterparty's key; the session was frozen defensively; cause undetermined",
      reviveReason: "session_frozen_identity_failure",
      reviveGuidance:
        "This session was frozen because a message failed to verify against the expected counterparty's key. " +
        "Cause undetermined — that signal looks the same whether someone was impersonating your counterparty or CELLO's own delivery mishandled a fallback, so it is recorded as an observation and nothing has been concluded about them.",
      // Review F1: this said "no further content will be accepted on this session", which was FALSE
      // as shipped — the next read revived it. It is true now, and it says how it is true, because
      // an operator who reads "frozen" and then watches the session work again learns to distrust
      // the log rather than the session.
      impact: "the content was NOT ingested, NOT displayed and NOT attributed to anyone; the session will not be revived by a read or a send, and only a close or a fresh session moves it now",
    }, correlationId);
  }

  /**
   * Stop a session and refuse to revive it. Shared by the identity freeze and the salt
   * disagreement, because the MECHANISM is identical — mark, then tear down — while the two have
   * nothing else in common and must not describe each other. An identity failure is evidence about
   * the counterparty; a salt disagreement is usually two builds that do not match, and telling an
   * operator their counterparty failed a key check when they did not is worse than saying nothing.
   * Hence the caller supplies both sentences.
   */
  async #freezeSession(
    agentName: string,
    sessionId: string,
    reason: string,
    narrative: { event: string; observation: string; impact: string; reviveReason: string; reviveGuidance: string },
    correlationId?: string,
  ): Promise<void> {
    // Review F1: MARK BEFORE TEARING DOWN. `destroySessionNode` writes `interrupted`, which is the
    // revivable status — if the mark landed after, a read racing the teardown could revive the
    // session out from under the freeze.
    //
    // `reviveReason` is SPELLED OUT by the caller rather than built from `reason`. Deriving it looks
    // tidier and silently changed a shipped contract: the identity freeze's `reason` is the specific
    // ordering failure (`bad_signature`, `signer_not_counterparty`), so a derived code would have
    // turned the stable `session_frozen_identity_failure` into a family of varying strings that no
    // caller matches. Caught by that path's own test.
    this.#frozenSessions.set(this.#k(agentName, sessionId), {
      reason: narrative.reviveReason,
      guidance: narrative.reviveGuidance,
    });
    // The EVENT NAME is the caller's, not this method's. Both freezes share a mechanism and nothing
    // else, and a salt disagreement logged under `…identity.frozen` would tell an operator their
    // counterparty failed a key check when they did not — a worse outcome than saying nothing.
    this.#logger.error(narrative.event, {
      agentName, sessionId, reason, correlationId,
      observation: narrative.observation,
      // Review F1: the identity path's impact line said "no further content will be accepted on this
      // session", which was FALSE as shipped — the next read revived it. It is true now, and it says
      // how it is true, because an operator who reads "frozen" and then watches the session work
      // again learns to distrust the log rather than the session.
      impact: narrative.impact,
    });
    try {
      /**
       * `"error"` maps to DB status `interrupted`, which is the SAME row an ordinary
       * counterparty-gone teardown writes — so a freeze is distinguishable in the log and in
       * behaviour, but not in the session record.
       *
       * ⚠️ THIS COMMENT USED TO SAY THE COLUMNS DID NOT EXIST. They do now: `frozen_at` and
       * `frozen_reason` were added to `sessions` by the salt migration, which carried them for
       * `DOD-M15-FREEZE-STATUS-1` so that two lanes would not both edit this file's migration list.
       * What is still missing is a WRITER — that is `FREEZE-STATUS-1`'s work and it belongs to the
       * other lane, so nothing here fills them in. The gap is unchanged; only the reason for it is.
       */
      await this.destroySessionNode(agentName, sessionId, "error");
    } catch (err: unknown) {
      // The refusal already happened — the content did not ingest. A teardown failure must not
      // turn a successful refusal into a thrown handler, which would close the stream on a path
      // that reads as "nothing arrived".
      this.#logger.warn("session.content.identity.freeze_teardown_failed", {
        agentName, sessionId, error: extractErrorMessage(err), correlationId,
      });
    }
  }

  /**
   * This agent's own last message on a session, from the ONE chain both send paths share.
   *
   * `undefined` means it has not spoken here yet, which is the session genesis and not an absence.
   * The caller supplies that; this does not guess.
   */
  #ownChainOf(
    agentName: string,
    sessionId: string,
    entry: { relayClient?: AgentRelayClient; relaySessionIdBytes?: Uint8Array } | undefined,
    ownPubkey: Uint8Array,
  ): Uint8Array | undefined {
    const relayHex = entry?.relaySessionIdBytes
      ? Buffer.from(entry.relaySessionIdBytes).toString("hex")
      : sessionId;
    return entry?.relayClient?.lastOwnHash(relayHex)
      ?? this.#ownChainStore?.lastOwnHash(Buffer.from(ownPubkey).toString("hex"), sessionId)
      ?? undefined;
  }

  /**
   * An inbound content frame refused before it could be read — the ENCRYPTION gate's three causes.
   *
   * ⚠️ **THESE LOGGED AND FILED NOTHING, AND THAT IS WHY THIS EXISTS.** All three carried a good
   * `impact` and `guidance` at ERROR and none of them called `noteContentRefusal`, so the sentences
   * an operator needed were in a file they have no reason to open. From their chair a message never
   * arrived and the conversation went quiet — the exact defect `DOD-M15-NO-SILENT-REFUSAL-1` was
   * built to end, on the same path, three checks above the one that respected it.
   *
   * Both surfaces, always: the ERROR is the durable forensic record an investigation reads days
   * later, and the notice is the control — the thing that actually reaches the person.
   */
  /**
   * Can a refused message still reach this operator through the relay mailbox? — review F2.
   *
   * Feature-detected, not assumed: `openContentSeal` is documented OPTIONAL on `KeyProvider`, and
   * `content-park.ts` refuses recovery without it. Asking the same resolver `content-park.ts` asks
   * is what keeps the sentence on the operator's screen tied to what their machine can actually do.
   */
  #mailboxRouteAvailable(agentName: string): boolean {
    const kp = this.#keyProviderResolver?.(agentName);
    return kp !== undefined && typeof kp.openContentSeal === "function";
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
      const record = this.#queries.getSessionRecord(agentName, sessionId);
      if (record && record.status === "active") {
        await this.markInterruptedWithDetails(agentName, sessionId, messageCount, "stream_close");
      }
    }
  }

  // ─── Private helpers ──────────────────────────────────────────────────────

  /**
   * DOD-NAT-REACHABILITY-1 (Phase 2): relay endpoints the DIRECTORY handed this
   * agent at signaling-auth time — the freshest, health-filtered view of the
   * relay pool, and the only source a FRESH agent (no session history) has.
   */
  readonly #directoryRelayEndpoints = new Map<string, Array<{ relayPeerId: string; relayAddrs: string[] }>>();

  /**
   * DOD-M15-RELAYSLOTS-1: the directory-issued online token per agent — the credential the relays
   * above now require before they will let this agent hold a circuit reservation slot.
   *
   * Arrives with `signaling_auth_ok`, on the same frame as the relay endpoints and on the same
   * cadence: every connect AND every reconnect. Held here rather than passed to a relay client at
   * construction because it expires within the hour and the client outlives it — the client reads
   * it through `getDirectoryOnlineToken` at each authentication.
   */
  readonly #directoryOnlineTokens = new Map<string, Uint8Array>();

  /**
   * DOD-M15-RELAYSLOTS-1: accept the directory's online token for an agent. Called on every
   * signaling connect and reconnect, which is what keeps it fresh.
   */
  setDirectoryOnlineToken(agentName: string, token: Uint8Array): void {
    this.#directoryOnlineTokens.set(agentName, token);
    this.#directoryOnlineTokenAbsent.delete(agentName);
  }

  /**
   * DOD-M15-RELAYSLOTS-1 review M1: the directory issued no token, and this is which absence it was.
   *
   * Kept so the relay's eventual `online_token_required` refusal can be reported with the cause the
   * DIRECTORY knew and the relay never learns — most importantly `not_registered_here`, where the
   * generic advice ("check that you are reaching a directory") points at a connection that is
   * working and away from the actual problem.
   */
  readonly #directoryOnlineTokenAbsent = new Map<string, "not_registered_here" | "issue_failed" | "unstated">();

  setDirectoryOnlineTokenAbsent(agentName: string, reason: "not_registered_here" | "issue_failed" | undefined): void {
    this.#directoryOnlineTokens.delete(agentName);
    this.#directoryOnlineTokenAbsent.set(agentName, reason ?? "unstated");
  }

  /**
   * The current token, or `undefined` when the directory has not issued one — either no directory
   * connection yet, or this key has no agent profile there. Undefined is a real answer, not a
   * missing one: the relay refuses without a token, which is the intended outcome for a key the
   * directory does not recognise.
   */
  getDirectoryOnlineToken(agentName: string): Uint8Array | undefined {
    return this.#directoryOnlineTokens.get(agentName);
  }

  /**
   * DOD-NAT-REACHABILITY-1 (Phase 2): accept the directory's relay-pool endpoints
   * for an agent (arrives with signaling_auth_ok, i.e. on every connect AND every
   * reconnect). If the agent's standing receiver is up but holds NO reservation —
   * the agent-online ensure raced ahead of auth_ok, or every relay was down at
   * create time — rebuild it now so the agent becomes dialable without waiting
   * for a session handoff that (being unreachable) would never come.
   */
  setDirectoryRelayEndpoints(agentName: string, endpoints: Array<{ relayPeerId: string; relayAddrs: string[] }>): void {
    // DOD-M12B-RESERVATION-RETRY-1: a DIFFERENT relay pool re-arms the retry budget; the same one
    // does not. This fires on every signaling connect AND reconnect, so clearing unconditionally
    // would reset the bound on a short grid and defeat the whole point of having one. But once the
    // budget is spent, `getStandingReceiverReachability` reports `unreachable` for the rest of the
    // online episode — including while this path is actively re-attempting against relays we have
    // never tried. A new relay is new information; a repeat of the same list is not.
    const previous = this.#directoryRelayEndpoints.get(agentName);
    const poolChanged =
      previous === undefined ||
      previous.length !== endpoints.length ||
      endpoints.some((e, i) => e.relayPeerId !== previous[i]?.relayPeerId);
    this.#directoryRelayEndpoints.set(agentName, endpoints);
    if (poolChanged) {
      this.#srReservationRetry.delete(agentName);
      this.#srLastRejectionReason.delete(agentName);
    }
    if (endpoints.length === 0 || this.#shuttingDown) return;
    const sr = this.#standingReceivers.get(agentName);
    if (!sr) return; // not ensured yet — the coming ensure reads the map
    if (sr.node.listenAddresses().some((a) => a.includes("/p2p-circuit"))) return; // already reserved
    this.#logger.info("session.standing_receiver.reservation.rebuild", {
      agentName,
      relayPeerIds: endpoints.map((e) => e.relayPeerId),
    });
    void this.#receivers.rebuildStandingReceiver(agentName);
  }

  /**
   * DOD-NAT-REACHABILITY-1: circuit-relay listen addresses for an agent's known
   * relays, so its standing receiver takes reservations and becomes dialable
   * behind NAT. Sources, merged and deduped by relay peer id: the directory's
   * auth-time relay pool (freshest — first), then the persisted relay endpoints
   * of past sessions (getAgentRelayEndpoints — covers a directory that predates
   * the auth_ok extension).
   */
  /**
   * DOD-M15-RELAYSLOTS-1: relays this agent should skip, and until when — see the failover note in
   * `#reservationCircuitAddrs`. Keyed agent → relay peer id → expiry.
   *
   * Time-boxed rather than permanent because the fault is somebody else's to fix and we will not
   * hear when they have: an operator sets the missing directory key and restarts, and this agent
   * should find that relay again without needing its own restart.
   */
  readonly #relayQuarantine = new Map<string, Map<string, number>>();

  /**
   * Is this agent currently skipping this relay? The observable half of the failover decision — a
   * test that asserts only on the classifier's boolean proves nothing about what the daemon does.
   */
  isRelayQuarantined(agentName: string, relayPeerId: string): boolean {
    return this.#relayQuarantineFor(agentName).has(relayPeerId);
  }

  /** Live quarantine entries for an agent, expired ones swept on read. */
  #relayQuarantineFor(agentName: string): Set<string> {
    const byRelay = this.#relayQuarantine.get(agentName);
    if (!byRelay) return new Set();
    const now = Date.now();
    for (const [relayPeerId, expiresAt] of byRelay) {
      if (now >= expiresAt) byRelay.delete(relayPeerId);
    }
    if (byRelay.size === 0) this.#relayQuarantine.delete(agentName);
    return new Set(byRelay.keys());
  }

  /**
   * Skip this relay for this agent for a while. Called only for refusals the classifier marks
   * `tryAnotherRelay` — a fault of the relay's, not one that would follow us to the next one.
   */
  #quarantineRelay(agentName: string, relayPeerId: string, reason: string): void {
    let byRelay = this.#relayQuarantine.get(agentName);
    if (!byRelay) { byRelay = new Map(); this.#relayQuarantine.set(agentName, byRelay); }
    byRelay.set(relayPeerId, Date.now() + RELAY_QUARANTINE_MS);
    this.#logger.warn("session.standing_receiver.relay_quarantined", {
      agentName,
      relayPeerId,
      reason,
      forMs: RELAY_QUARANTINE_MS,
      impact: "this relay refused this agent for a fault of its own, so the agent will ask a " +
        "different relay for its reservation until the quarantine lapses. Its inbound reachability " +
        "is restored by moving, not by waiting for someone to fix that relay.",
    });
  }

  #reservationCircuitAddrs(agentName: string): { addrs: string[]; relayPeerIds: string[] } {
    let persisted: Array<{ relayPeerId: string; relayAddrs: string[] }>;
    try {
      persisted = this.#queries.getAgentRelayEndpoints(agentName);
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
    /**
     * DOD-M15-RELAYSLOTS-1 — **THE FAILOVER.** Skip relays that refused this agent for a fault of
     * their own (today: a relay holding no directory public key, which can verify nobody and is
     * refusing everyone). We run several relays precisely so one being broken is survivable.
     *
     * ⚠️ NEVER TO THE POINT OF HAVING NO RELAY AT ALL. If the quarantine would empty the candidate
     * list it is ignored wholesale: a relay that refuses is strictly better than no relay, because
     * the refusal at least has a cause the operator can read, while an agent with no candidates is
     * simply unreachable with nothing to show for it. This is the same "refusing too eagerly is the
     * failure mode" rule, applied to the client's own choice of where to ask.
     */
    const quarantined = this.#relayQuarantineFor(agentName);
    const eligible = [...merged.values()].filter((ep) => !quarantined.has(ep.relayPeerId));
    const usable = eligible.length > 0 ? eligible : [...merged.values()];
    if (eligible.length === 0 && quarantined.size > 0 && merged.size > 0) {
      this.#logger.warn("session.standing_receiver.relay_quarantine.ignored", {
        agentName,
        quarantined: [...quarantined],
        impact: "every known relay has refused this agent for a relay-side fault, so the quarantine " +
          "is being ignored and they are all being tried again. A relay that refuses with a cause " +
          "is better than no relay at all — but if this persists, every relay this agent knows " +
          "about is misconfigured, and that is the thing to look at.",
      });
    }
    const addrs: string[] = [];
    const relayPeerIds: string[] = [];
    for (const ep of usable) {
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
  /**
   * DOD-M12B-RESERVATION-RETRY-1 — ask again for a reservation the relay refused.
   *
   * The rebuild is the re-attempt: a circuit listener is fixed at node creation, so the only way to
   * obtain a reservation is to build a new node asking for one.
   */
  #retryReservationIfDue(agentName: string): void {
    const now = Date.now();
    const state = this.#srReservationRetry.get(agentName)
      ?? { attempts: 0, nextAt: now + this.#srReservationRetryMs, correlationId: randomUUID() };
    // The reason the LAST attempt was refused, captured where it is actually known.
    const lastReason = this.#srLastRejectionReason.get(agentName);
    if (lastReason !== undefined) state.lastReason = lastReason;
    if (state.attempts === 0 && !this.#srReservationRetry.has(agentName)) {
      // First sighting — schedule, do not fire. The creation attempt just happened.
      this.#srReservationRetry.set(agentName, state);
      return;
    }
    if (now < state.nextAt) return;

    if (state.attempts >= SR_RESERVATION_MAX_RETRIES) {
      if (state.attempts === SR_RESERVATION_MAX_RETRIES) {
        state.attempts += 1; // mark as reported, so this fires exactly once
        this.#srReservationRetry.set(agentName, state);
        this.#logger.error("session.standing_receiver.reservation.gave_up", {
          agentName,
          attempts: SR_RESERVATION_MAX_RETRIES,
          correlationId: state.correlationId,
          // WHY, not just the consequence. Three different problems reach this one message and they
          // need three different responses: `relay_granted_no_reservation` is relay CAPACITY (and a
          // trustless-cello problem), `relay_unreachable` is the NETWORK, and
          // `reservation_did_not_complete_in_time` is LATENCY — and the only one of the three that
          // can pin a slot it never uses, so its appearance is also the signal that this retry
          // budget needs tightening.
          ...(state.lastReason !== undefined ? { lastRejectionReason: state.lastReason } : {}),
          // "No relay would grant" and "there was no relay to ask" are different facts and lead to
          // different places — the first at relay capacity, the second at this agent's directory
          // connection. Without this they are the same sentence.
          //
          // 032-RELAYSPREAD: this was also called `reservationsRequested` — the same mis-naming as
          // the reachability events, in its worst form, because here the value is a BOOLEAN under a
          // name that reads as a count. It is NOT `relaysOffered`: that field counts the merged
          // candidate list the walk actually asks (directory pool + persisted endpoints, minus
          // quarantine), and this reads the directory pool alone. Two populations must not share
          // one field name, so this one is named for what it measures.
          hadRelayToAsk: (this.#directoryRelayEndpoints.get(agentName)?.length ?? 0) > 0,
          // …and HOW MANY the walk actually asks, so this event stands on its own instead of
          // needing the last reachability line to be read beside it. Same population and same
          // meaning as `relaysOffered` everywhere else: the merged, quarantine-filtered candidate
          // list.
          relaysOffered: this.#reservationCircuitAddrs(agentName).addrs.length,
          impact:
            "no relay would grant this agent a circuit reservation, so anyone behind NAT cannot reach or dial it — inbound sessions will only arrive from peers that can connect directly, and everything else falls back to the relay's store-and-forward",
        });
      }
      return;
    }

    state.attempts += 1;
    // The FINAL attempt gets a fixed settle window rather than another doubled wait: at the top of
    // the ladder that would be 80 minutes of silence after the last thing we did, which is a long
    // time to tell an operator nothing. Every earlier attempt doubles, which is what keeps a fleet
    // off a scarce relay.
    state.nextAt = now + (state.attempts >= SR_RESERVATION_MAX_RETRIES
      ? this.#srReservationRetryMs
      : this.#srReservationRetryMs * 2 ** (state.attempts - 1));
    this.#srReservationRetry.set(agentName, state);
    this.#logger.warn("session.standing_receiver.reservation.retry", {
      agentName,
      attempt: state.attempts,
      maxAttempts: SR_RESERVATION_MAX_RETRIES,
      correlationId: state.correlationId,
      ...(state.lastReason !== undefined ? { lastRejectionReason: state.lastReason } : {}),
      impact: "this agent currently holds no circuit reservation, so a NAT'd peer cannot dial it",
    });
    void this.#receivers.rebuildStandingReceiver(agentName);
  }

  #reservationWatchdogTick(): void {
    if (this.#shuttingDown) return;
    for (const [agentName, sr] of this.#standingReceivers) {
      if (!this.#agentsWantingReceiver.has(agentName)) continue;        // agent went offline

      // DOD-M12B-RESERVATION-RETRY-1 — NEVER HAD ONE IS NOT "NOTHING TO DO".
      //
      // This used to `continue` unconditionally, on the grounds that a receiver with no reservation
      // is "already degraded and already loud". Measured over 17 days: `reservation.none` fired 481
      // times and `relay.rejected` 2,215 — every one of the latter `relay_granted_no_reservation`,
      // a relay out of slots completing the handshake and granting nothing. Nothing ever acted on
      // the noise, and each of those receivers is a plain TCP node with no circuit address: behind
      // NAT, dialable by NOBODY, for its whole life. That is the silent loss of inbound this file
      // says three lines below it exists to kill.
      //
      // A relay out of slots at boot may have one minutes later, so re-attempt — on a BACKOFF and
      // BOUNDED, never on this 30-second grid. A reservation is scarce: the relay holds it for its
      // full TTL even after the client disconnects, and churning attempts across a fleet is how a
      // relay is exhausted (`#startReceiverNode` records that hazard).
      if (sr.relayPeerIds.length === 0) {
        // …unless one has arrived since. Review F4, same class as the recompute below: the
        // slow-start path installs a receiver before every circuit has bound, so "held nothing at
        // install" is not the same fact as "holds nothing now". Adopting it here is what stops the
        // retry ladder rebuilding a receiver that is already reachable.
        const arrived = heldRelayIdsOf(sr.node)
          .filter((id) => sr.node.getConnections().some((c) => c.peerId === id && c.status === "open"));
        if (arrived.length === 0) {
          this.#retryReservationIfDue(agentName);
          continue;
        }
        sr.relayPeerIds = arrived;
        sr.gater.setReservedRelayPeers(arrived);
        this.#logger.info("session.standing_receiver.reservation.gained", {
          agentName,
          relayPeerIds: arrived,
          reservationsHeld: arrived.length,
        });
      }
      // It has at least one — any earlier retry budget, and the reason the last attempt failed, are
      // stale.
      this.#srReservationRetry.delete(agentName);
      this.#srLastRejectionReason.delete(agentName);

      // Watch the CONNECTION to the relay, not the circuit address.
      //
      // Killing the relay does NOT make the /p2p-circuit address disappear: libp2p
      // keeps the listen address until the reservation's own refresh, up to two hours
      // away. Watching the address would therefore miss a dead relay for hours — the
      // agent would advertise a circuit address that routes through a relay that no
      // longer exists, which is exactly the silent unreachability we are hunting. The
      // live connection to the relay is the honest signal: no connection, no relay,
      // no reservation.
      //
      // AND IT MUST BE OPEN. `getConnections()` returns libp2p's registry, which keeps a connection
      // listed while it is closing and after its muxer has died — the state the whole M12 Tier P5
      // investigation turned on. Without the status check a registered corpse reads as "still
      // connected", the rebuild never fires, and the agent silently stops being reachable while
      // this loop reports it healthy. The comment above claimed liveness; only this tests it.
      // 032-RELAYSPREAD — PER RELAY, and the health question is now a COUNT.
      //
      // This used to evaluate one peer id and rebuild the entire standing receiver when it went
      // false. With a pool of one that was the only thing it could do; with a pool of three it is
      // the churn engine — every relay is another watchdog subject, and a full rebuild per loss
      // multiplies the 30-second grid by the size of the pool while throwing away reservations that
      // are perfectly healthy.
      /**
       * RECOMPUTED FROM THE NODE, never filtered down from the stored list. Review F4: filtering
       * `sr.relayPeerIds` makes it SHRINK-ONLY, and a list that can only shrink cannot see a
       * circuit arrive. Three things went wrong with that, and the first one happens routinely:
       *   - the slow-start path installs the receiver before every circuit has bound, so a relay
       *     that binds four seconds later was invisible to this watchdog and absent from the
       *     gater's carve-out set FOREVER — its AutoNAT probe reply refused by our own gate;
       *   - shrinking to zero then rebuilt a receiver that was announcing live circuits, which is
       *     the exact defect this unit is against;
       *   - anything that ever restores a circuit could not be counted.
       * Reading the node's own addresses costs the same and has none of that.
       */
      const open = sr.node.getConnections().filter((c) => c.status === "open").map((c) => c.peerId);
      const stillHeld = heldRelayIdsOf(sr.node).filter((id) => open.includes(id));
      const lost = sr.relayPeerIds.filter((id) => !stillHeld.includes(id));
      const gained = stillHeld.filter((id) => !sr.relayPeerIds.includes(id));
      sr.relayPeerIds = stillHeld;
      if (gained.length > 0) {
        // A circuit this receiver did not have at install. Said out loud because it is the visible
        // half of the slow-start case, and because it is the moment that relay earns its inbound
        // carve-out — a silent widening of the gate is not something to do without a line.
        this.#logger.info("session.standing_receiver.reservation.gained", {
          agentName,
          relayPeerIds: gained,
          reservationsHeld: stillHeld.length,
        });
      }
      if (lost.length === 0) {
        // Nothing lost. The gater still gets the current set, because `gained` may have widened it.
        if (gained.length > 0) sr.gater.setReservedRelayPeers(stillHeld);
        continue;
      }
      // REVOKE FIRST. A relay whose reservation is gone must lose its inbound carve-out in the same
      // breath as the loss is noticed, or the gater's bound quietly becomes "granted one once".
      sr.gater.setReservedRelayPeers(stillHeld);
      for (const relayPeerId of lost) {
        // DOD-RELAY-KEEPALIVE-1 (review F4): carry the CAUSE, not just the exit point.
        // `relay_connection_gone` says where this was noticed — a poll of getConnections() — by
        // which time the abort reason that actually killed the link is long discarded. The relay
        // client for this (agent, relay) pair kept the error that ended its reader; that is the
        // nearest thing to an upstream cause available here, and its absence is how 2,061 of these
        // went untraced.
        const upstreamReason = this.#relayClients.get(`${agentName}::${relayPeerId}`)?.getLastReaderError();
        this.#logger.warn("session.standing_receiver.reservation.lost", {
          agentName,
          relayPeerId,
          reason: open.includes(relayPeerId) ? "circuit_address_vanished" : "relay_connection_gone",
          ...(upstreamReason ? { upstreamReason } : {}),
          reservationsHeld: stillHeld.length,
          // The line an operator reads, and the two cases are not the same event at all.
          impact: stillHeld.length > 0
            ? "this agent still holds " + stillHeld.length + " other circuit reservation(s), so it "
              + "stays dialable from behind NAT and the receiver is NOT rebuilt. Losing one relay "
              + "costs this agent nothing it can feel."
            : "this agent now holds NO circuit reservation, so nobody behind a home router can "
              + "reach it. The receiver is being rebuilt against the rest of the pool.",
        });
      }
      if (stillHeld.length === 0) {
        // ZERO HELD IS STILL THE LOUD, STRUCTURAL CASE — the agent is unreachable behind NAT and
        // only a new node can take a new reservation, because a circuit listener is fixed at node
        // creation.
        void this.#receivers.rebuildStandingReceiver(agentName);
        continue;
      }
      /**
       * STILL REACHABLE, SO THE RECEIVER STANDS, AND NOTHING ELSE HAPPENS HERE. That second half is
       * the part worth reading, because the obvious next line is wrong twice over.
       *
       * **A LOST CONFIGURED CIRCUIT CANNOT BE RETAKEN BY THIS NODE.** Read out of
       * `@libp2p/circuit-relay-v2@4.2.5`, not assumed: for an explicit relay address
       * `transport/listener.js#listen()` is a ONE-SHOT — it reserves once and nothing calls it
       * again; `reservation-store.js#removeReservation()` clears the refresh timeout and deletes
       * the entry; and the listener's `_onAddRelayPeer` returns early for `type === 'configured'`,
       * so even a later reservation would not be announced. A circuit listener is fixed at node
       * creation, and the only thing that takes a new one is a NEW NODE — which is exactly the
       * rebuild this branch exists to refuse.
       *
       * **AND RE-PROVING TO THE LOST RELAY WOULD REBUILD THE RECEIVER ANYWAY.** Review F3: an
       * earlier version called `#authenticateStandingReceiver` here to "remove the relay-side
       * reason for the revocation". That function ends with `if (refusal?.tryAnotherRelay) { …
       * void this.#receivers.rebuildStandingReceiver(agentName); }` — and a dead or misconfigured relay is
       * precisely the one that answers that way. So the common case was: lose relay A while
       * holding B, decline to rebuild, prove to A, A refuses, rebuild the whole receiver and throw
       * B's healthy reservation away. The churn engine, re-entered through the back door.
       *
       * **THE BOUND, STATED PLAINLY BECAUSE IT IS A REAL SHORTFALL AGAINST THE DoD:** a lost
       * circuit is gone until the receiver is next rebuilt for another reason. What the agent buys
       * is that it never STOPS BEING REACHABLE while that is true — the surviving relays carry it,
       * the loss is named in the log with its cause, and the lost relay's inbound carve-out is
       * revoked above. That is availability, not restoration in place.
       *
       * WHICH LEAVES A RATCHET, and `#respreadIfDecayed` below is what stops it: relays are only
       * ever lost between rebuilds, never regained, so an agent nobody talks to walks itself back
       * down to one relay — the exact state this unit exists to get it out of.
       */
    }
    for (const agentName of this.#standingReceivers.keys()) {
      if (this.#agentsWantingReceiver.has(agentName)) this.#respreadIfDecayed(agentName);
    }
  }

  /**
   * 032-RELAYSPREAD — **AN IDLE AGENT MUST NOT RATCHET ITSELF BACK DOWN TO ONE RELAY.**
   *
   * Spreading happens when a receiver is BUILT, and between builds the count only falls: a lost
   * circuit cannot be retaken by a running node (a circuit listener is fixed at node creation), and
   * a relay the directory announces later is skipped while any circuit is held. An agent in
   * conversation re-spreads constantly — the receiver is handed into each session and a fresh one
   * is built behind it — so this is about the agent nobody has talked to for a day. It loses relays
   * one at a time, nothing pulls it back up, and it ends up exactly where this unit found it:
   * reachable through one relay, one relay away from being reachable through none.
   *
   * **THE COST OF FIXING IT IS A NEW PEER ID**, which is why it is fenced three ways rather than
   * simply rebuilding on sight:
   *   - **ONLY WHEN IDLE.** A rebuild replaces the receiver's transport identity, and a counterparty
   *     may be holding the old one from a `session_offer_accept`. With a live session for this agent
   *     we leave it alone — a degraded spread costs redundancy, a changed peer id mid-conversation
   *     costs the conversation.
   *   - **ONLY WHEN THERE IS SOMETHING TO GAIN.** Holding every relay that was offered is not decay.
   *   - **ON ITS OWN SLOW CLOCK**, never the watchdog's 30-second grid. A reservation is scarce —
   *     the relay holds it for its full TTL even after we disconnect — so this reuses the
   *     reservation retry interval rather than inventing a faster one.
   */
  #respreadIfDecayed(agentName: string): void {
    if (this.#shuttingDown) return;
    const sr = this.#standingReceivers.get(agentName);
    if (!sr || sr.relayPeerIds.length === 0) return;                    // zero held is the loud path
    for (const entry of this.#activeNodes.values()) {
      if (entry.agentName === agentName) return;                        // in conversation — hands off
    }
    const offered = this.#reservationCircuitAddrs(agentName).addrs.length;
    if (sr.relayPeerIds.length >= offered) return;                      // nothing to gain
    const now = Date.now();
    const last = this.#srLastRespreadAt.get(agentName) ?? 0;
    if (now - last < this.#srReservationRetryMs) return;
    this.#srLastRespreadAt.set(agentName, now);
    this.#logger.info("session.standing_receiver.respread", {
      agentName,
      reservationsHeld: sr.relayPeerIds.length,
      relaysOffered: offered,
      impact: "this agent is idle and holds fewer relay reservations than it was offered, so its " +
        "receiver is being rebuilt to take the rest. Without this it can only lose relays between " +
        "rebuilds, and an agent nobody talks to drifts back down to a single relay — one relay " +
        "away from being unreachable behind NAT, which is the state this whole mechanism exists " +
        "to keep it out of.",
    });
    void this.#receivers.rebuildStandingReceiver(agentName);
  }

  /** Start the reservation watchdog (idempotent). Stopped by gracefulShutdown. */
  #startReservationWatchdog(): void {
    if (this.#reservationWatchdog !== null) return;
    // Arm the backstop clock from the START of watching, not from the epoch — otherwise the first
    // tick always fires a sweep on top of the install drain that just ran.
    this.#park.armBackstopClock(Date.now());
    this.#reservationWatchdog = setInterval(() => {
      try {
        this.#reservationWatchdogTick();
        this.#park.parkedDrainBackstopTick(Date.now());
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
  /**
   * DOD-M15-RELAYSLOTS-1 — tell the relay this transport identity belongs to a registered agent, so
   * the reservation it just refused is granted on the next attempt.
   *
   * Returns `"proven"` on success, or the shape of the failure so the candidate loop can act on it.
   * It never throws: throwing would turn one unreachable relay into a failure to build a receiver
   * at all.
   *
   * ─── Why this returns a verdict instead of a boolean ──────────────────────────────────────────
   *
   * Review HIGH-1/HIGH-2. Putting the reservation behind a proof MOVED THE FIRST REFUSAL onto this
   * path. `#authenticateStandingReceiver` does everything right with a refusal — records it where
   * `cello_status` can read it, and quarantines a relay whose fault is its own — but it runs only
   * on a receiver that ALREADY HAS a reservation, so under the new gate a total failure never
   * reaches it. This method was logging `proven: false` and returning.
   *
   * What that cost the operator: an expired token, or an agent at its slot cap, refused by every
   * relay in the pool. `cello_status` shows an agent that is online and reachable by nobody, with
   * no cause anywhere the person will look — while the relay had computed the cause, the count, and
   * the next step, and put them on the wire. And `slot_cap_exceeded` is classified
   * `tryAnotherRelay: false` precisely so the client STOPS walking the fleet; without the verdict,
   * the loop walked it anyway, turning one client-side fault into what reads as a fleet outage.
   */
  async #proveToRelay(
    agentName: string,
    circuitAddr: string,
    node: CelloNode,
    correlationId: string,
    /**
     * Whether this proof is the STANDING RECEIVER's, and may therefore write the surface
     * `cello_status` reads as "your standing receiver was refused".
     *
     * A revival proves itself too, and its refusal is real — but it is not evidence about the
     * receiver. A receiver that proved thirty seconds ago and holds a slot, plus a revival refused
     * with `slot_cap_exceeded`, would otherwise have `cello_status` report a front door as refused
     * while it is open. The refusal is still logged and still steers the candidate loop; what it
     * does not do is claim to be about something it did not measure.
     */
    surfaceAsReceiverRefusal: boolean,
  ): Promise<"proven" | "refused_try_another_relay" | "refused_this_agent" | "unavailable"> {
    const relayPeerId = relayPeerIdOf(circuitAddr);
    const baseRelayAddr = circuitAddr.split("/p2p-circuit")[0];
    if (!relayPeerId || !baseRelayAddr) {
      this.#logger.warn("session.standing_receiver.prove.address_unreadable", {
        agentName,
        circuitAddr,
        correlationId,
        impact: "this candidate's circuit address does not name a relay peer, so there is nothing " +
          "to prove to and its reservation will stay refused. Skipped silently before — which made " +
          "a malformed address look identical to a relay that simply said no.",
      });
      return "unavailable";
    }
    /**
     * Declared out here so the `finally` can close it. Scoped inside the `try` before, so a throw
     * from `proveReservation` skipped the close and left the stream and its pending settles behind.
     */
    let client: AgentRelayClient | undefined;
    try {
      client = this.#detachedRelayClientBuilder?.(agentName, relayPeerId, [baseRelayAddr], {
        receiptStore: this.#relayReceiptStore ?? undefined,
        sealLeafStore: this.#sealLeafStore ?? undefined,
        onlineToken: () => this.getDirectoryOnlineToken(agentName),
      });
      if (!client) {
        this.#logger.warn("session.standing_receiver.prove.no_builder", {
          agentName,
          relayPeerId,
          correlationId,
          impact: "no relay client could be built, so this receiver cannot prove itself and the " +
            "relay will refuse its reservation again. The agent is reachable only over a direct " +
            "connection until this is wired.",
        });
        return "unavailable";
      }
      const proven = await client.proveReservation(node);
      if (proven) {
        if (surfaceAsReceiverRefusal) this.#srRelayRefusal.delete(agentName);
        this.#logger.info("session.standing_receiver.prove.result", {
          agentName, relayPeerId, peerId: node.getPeerId(), proven: true, correlationId,
        });
        return "proven";
      }

      /**
       * The same two lines `#authenticateStandingReceiver` runs, for the same reason. The `else`
       * matters as much as the `if`: `proveReservation` also fails for transport reasons, which
       * leave `getLastAuthRefusal()` null, and leaving a PREVIOUS refusal in the map would have
       * `cello_status` explaining a cause that is no longer what is wrong.
       */
      const refusal = client.getLastAuthRefusal();
      if (surfaceAsReceiverRefusal) {
        if (refusal) {
          this.#srRelayRefusal.set(agentName, { ...this.#withDirectoryCause(agentName, refusal), relayPeerId });
        } else {
          this.#srRelayRefusal.delete(agentName);
        }
      }
      this.#logger.warn("session.standing_receiver.prove.result", {
        agentName,
        relayPeerId,
        peerId: node.getPeerId(),
        proven: false,
        refusalReason: refusal?.reason ?? "no_relay_verdict",
        tryAnotherRelay: refusal?.tryAnotherRelay ?? true,
        correlationId,
        impact: refusal?.advice ??
          "the relay would not accept this agent's proof and said nothing about why, which is what " +
          "a transport failure mid-handshake looks like. The candidate loop moves on to the next relay.",
      });
      if (refusal && !refusal.tryAnotherRelay) return "refused_this_agent";
      if (refusal?.tryAnotherRelay && !this.#shuttingDown) {
        this.#quarantineRelay(agentName, relayPeerId, refusal.reason);
      }
      return "refused_try_another_relay";
    } catch (err: unknown) {
      this.#logger.warn("session.standing_receiver.prove.failed", {
        agentName,
        correlationId,
        error: extractErrorMessage(err),
        impact: "this receiver could not prove itself, so its retry will be refused and the " +
          "candidate loop will try the next relay.",
      });
      return "unavailable";
    } finally {
      client?.close();
    }
  }

  /**
   * DOD-LOOP-1: public hook for the composition root to create an agent's standing receiver when
   * the agent comes online (cello_start_agent), and to tear it down when it goes offline.
   * M8B F14: also called from the inbound accept path (ensure on demand). Marks the agent as
   * WANTING a receiver, which arms the teardown re-arm in destroySessionNode/retireSessionNode.
   */
  /**
   * DOD-M12B-SESSION-SEED-1 test seam: the seed the agent's current standing receiver holds.
   *
   * The property under test — "the receiver built behind a promoted one never reuses its seed" — is
   * about an identity that by design never leaves the process, so there is no observable surface for
   * it short of a live two-node dial. Reading it here is the narrowest way to pin it.
   */
  /** DOD-M12B-SESSION-SEED-1: record the identity this session must be able to return at. */
  #rememberSessionSeed(
    agentName: string,
    sessionId: string,
    seed: Uint8Array,
    counterpartyPeerId: string,
    counterpartyPubkey: string,
  ): void {
    const key = this.#k(agentName, sessionId);
    // Defensive: unreachable today because `insertSessionRow` PK-conflicts on a repeat, but an
    // overwrite that dropped a live seed un-zeroed would leave the one copy we are responsible for
    // in the heap with nothing tracking it.
    this.#sessionSeeds.get(key)?.seed.fill(0);
    // `counterpartyAddrs` starts empty: at creation the signed assignment has not necessarily
    // arrived yet. It is filled by `#evictSessionCaches` on the way down, which is the last moment
    // the live addresses exist.
    this.#sessionSeeds.set(key, { seed, counterpartyPeerId, counterpartyPubkey, counterpartyAddrs: [] });
  }

  /**
   * DOD-M12B-SESSION-SEED-1 — destroy a session's transport identity.
   *
   * Called from `#updateSessionStatus` on a terminal status, in the SAME step that writes it, so
   * there is no window in which a session is closed on paper and still revivable in memory.
   *
   * **WHAT THE ZERO-FILL DOES AND DOES NOT DO** — checked against the derivation, not assumed.
   * `createNode` hands the buffer to `generateKeyPairFromSeed`, and `@libp2p/crypto` COPIES it
   * (`uint8arrayConcat([seed, publicKeyRaw])`, then `Uint8Array.from`). Two consequences:
   *   - zeroing after the node has started is SAFE — the running node holds its own copy;
   *   - it does NOT erase the key from the heap. An identical usable copy is the first 32 bytes of
   *     `privateKey.raw` on the node object until that node is dropped.
   * So this removes OUR long-lived copy — the one that would otherwise sit in a map for the life of
   * the process, decoupled from any node — and that is worth doing. It is not a heap scrub, and
   * the DoD already says the bound rather than secrecy is the control.
   */
  #destroySessionSeed(agentName: string, sessionId: string): void {
    const key = this.#k(agentName, sessionId);
    const identity = this.#sessionSeeds.get(key);
    if (identity === undefined) return;
    identity.seed.fill(0);
    this.#sessionSeeds.delete(key);
    this.#logger.debug("session.seed.destroyed", { agentName, sessionId });
  }

  /**
   * DOD-M12B-REVIVE-RELAY-1 — reconnect the session's relay WITNESS, which revival never did.
   *
   * THE FIRST-PRINCIPLES DEFECT, and the one that explains every symptom chased separately before
   * it. Establishment does five things: build the node, register the content handler, wire liveness,
   * **connect the relay**, and dial the counterparty. Revival did the first three. A revived session
   * was therefore not a session — it looked live, reported `active`, and had no live inbound path at
   * all.
   *
   * MEASURED 2026-08-18 with two real agents: a message on a reconnected session took **three
   * minutes**, against seconds on a fresh one, because only the five-minute mailbox backstop ever
   * found it. Doorbells stopped firing for the same reason — the relay stream is what rings them.
   * And `#parkContent` refuses without `entry.relayClient`, so sends could not park either.
   *
   * NO ASSIGNMENT IS PRESENTED, and that is by design rather than omission: `RelayConnectParams`
   * documents the reconnect mode itself — *"absent … on the restart/persisted reconnect path (the
   * relay already recorded the session at first establishment) — the client then just reconnects
   * without re-recording."* A revival is exactly that path.
   *
   * Best-effort and non-fatal: a session that comes back without its witness is still better than
   * one that does not come back, and the failure is named rather than silent.
   */
  async #reconnectRevivedSessionRelay(
    agentName: string,
    sessionId: string,
    node: CelloNode,
    gater: SessionConnectionGater,
    correlationId: string,
    ep: { relayPeerId: string; relayAddrs: string[] } | null,
  ): Promise<void> {
    if (!ep) {
      this.#logger.warn("session.revive.relay.absent", {
        agentName,
        sessionId,
        impact: "no relay is recorded for this session, so it comes back with no live inbound path — "
          + "messages arrive only on the periodic mailbox poll, and a failed send cannot park and is "
          + "reported lost",
      });
      return;
    }
    try {
      // The gater admits only the counterparty inbound; the relay is a third peer and must be
      // permitted OUTBOUND or our own gate refuses the dial (INV-5 keeps inbound counterparty-only).
      gater.setAllowedOutboundPeer(ep.relayPeerId);

      const clientKey = `${agentName}::${ep.relayPeerId}`;
      let client = this.#relayClients.get(clientKey);
      if (!client) {
        if (!this.#relayReceiptStore && this.#db) this.#relayReceiptStore = new RelayReceiptStore(this.#db, this.#logger);
        if (!this.#sealLeafStore && this.#db) this.#sealLeafStore = new SessionSealLeafStore(this.#db, this.#logger);
        client = this.#detachedRelayClientBuilder?.(agentName, ep.relayPeerId, [...ep.relayAddrs], {
          receiptStore: this.#relayReceiptStore ?? undefined,
          sealLeafStore: this.#sealLeafStore ?? undefined,
          // DOD-M15-RELAYSLOTS-1: read at each auth, never snapshotted — the token expires hourly.
          onlineToken: () => this.getDirectoryOnlineToken(agentName),
        });
        if (!client) {
          this.#logger.warn("session.revive.relay.builder_absent", {
            agentName,
            sessionId,
            impact: "no relay client could be built, so this revived session has no live inbound path",
          });
          return;
        }
        this.#relayClients.set(clientKey, client);
      }

      // 033-ACKEMIT: a revived session re-registers with no assignment in hand, so the genesis comes
      // from the entry that was just restored above.
      client.registerSession(sessionId, node, this.#contentIn.relayLeafHandler(agentName, sessionId, correlationId), undefined, this.#leafRecords.sessionGenesisPrevRoot(agentName, sessionId));

      const entry = this.#activeNodes.get(this.#k(agentName, sessionId));
      if (entry) {
        entry.relayClient = client;
        entry.relaySessionIdBytes = Uint8Array.from(Buffer.from(sessionId, "hex"));
        entry.relayClientKey = clientKey;
      }

      /**
       * THE STEP THIS METHOD IS NAMED AFTER, and the first version did not take it (review HIGH-2).
       *
       * `registerSession` files a handler in a Map. It opens nothing — no dial, no auth, no reader
       * loop. `#connectSessionRelay` ends with exactly this line and the reconnect ended without it,
       * so a revived session registered a handler on a client whose stream was `null` and then
       * logged that its live inbound path was back. It was not: the counterparty's leaves queued at
       * the relay, no doorbell fired, and delivery fell back to the five-minute mailbox poll — the
       * three-minutes-versus-seconds symptom the whole unit exists to remove.
       *
       * Worse, the client is usually BRAND NEW here: `markInterruptedWithDetails` closes and drops
       * the client for the last session on a relay, so a single-session agent always lands in the
       * build branch above with a fresh, unconnected client.
       *
       * `#ensureConnected` is idempotent, so this also repairs the cached-but-dead-stream case.
       */
      await client.connect(node);

      this.#logger.info("session.revive.relay.connected", {
        agentName,
        sessionId,
        relayPeerId: ep.relayPeerId,
        impact: "the revived session has its live inbound path back — messages arrive promptly "
          + "instead of waiting for the periodic mailbox poll",
      });
    } catch (err: unknown) {
      this.#logger.warn("session.revive.relay.failed", {
        agentName,
        sessionId,
        error: err instanceof Error ? err.message : String(err),
        impact: "the session is back but without its witness — delivery falls back to the periodic poll",
      });
    }
  }

  /**
   * DOD-M12B-SESSION-SEED-1 — bring an interrupted session back on the peer id it already has.
   *
   * THE DEFECT THIS CLOSES. `markInterruptedWithDetails` and `destroySessionNode` stop the node and
   * delete it from `#activeNodes`, and until now **nothing anywhere recreated one**. A laptop-close
   * session stayed stuck even though both processes were alive and both keypairs were still in
   * memory — the trace on 2026-08-17 found no missing transport capability, just a missing edge.
   *
   * TWO THINGS HAVE TO HAPPEN, and doing only one leaves the session exactly as stuck:
   *   1. the NODE comes back, at the same peer id, or the counterparty can never dial us again;
   *   2. the STATUS comes back to `active`, or every send still refuses with `session_not_active`.
   *
   * **DEMAND-DRIVEN ONLY.** Nothing calls this on a timer. That is the `REDIAL-1` discipline and it
   * is also Andre's tenet — a background rebuilder would hold a dialable endpoint open for a session
   * nobody is using, which is the "open connection a malicious agent can farm for" in as many words.
   *
   * **TERMINAL IS TERMINAL.** A sealed or abandoned session had its seed zeroed in the same step
   * that wrote its status, so there is nothing to come back on. This refuses by name rather than
   * minting a fresh identity — a revival that quietly mints would hand one session a second peer id
   * and break the invariant while appearing to work.
   *
   * Idempotent: a session that already has a live node returns ok without building a second one.
   */
  async reviveSessionNode(
    agentName: string,
    sessionId: string,
  ): Promise<{ ok: true; peerId: string } | { ok: false; reason: string; guidance?: string }> {
    const key = this.#k(agentName, sessionId);
    const live = this.#activeNodes.get(key);
    if (live) return { ok: true, peerId: live.node.getPeerId() };

    // PARITY with `acceptSession` — and the parity guard in msg-022 is what caught its absence.
    // A revived session's offer record has almost always been cleared already (it was cleared when
    // the session was first accepted), so this is usually a no-op. It is here because "usually a
    // no-op" is not a reason for establishment and revival to do different things: every divergence
    // between those two paths in this file has been a defect, and the guard exists because one of
    // them shipped past a green suite for two days.
    this.#receivers.clearOfferedDialer(agentName, sessionId);

    const record = this.#queries.getSessionRecord(agentName, sessionId);
    if (!record) return { ok: false, reason: "session_not_found" };
    /**
     * A REVIVED SESSION GETS ITS SEAL CHANCES BACK — `DOD-M15-SEAL-FAILED-TERMINAL-1` review
     * MEDIUM-6, and without this a receipt can be lost permanently and silently.
     *
     * `restart_seal_gave_up_at` is written when the restart resolver exhausts its attempts, and
     * NOTHING ever cleared it. Its stated purpose is narrow — *"a machine restarting ~6 times a day
     * must not re-run five ceremonies against a hopeless session on every boot"* — and a session
     * being revived is the opposite of hopeless: something is talking to it again.
     *
     * The path it closes: resolver gives up → the column is stamped → the session is REVIVED and
     * carries live traffic → it is closed → the background ceremony dies → the in-memory failure
     * marker is lost at the next restart → `listRestartOrphanedSessions` excludes the row forever on
     * this column → and `listExpiredUnrevivableSessions` explicitly INCLUDES
     * `restart_seal_gave_up_at IS NOT NULL`, so the revival sweep force-abandons it. Receipt gone,
     * with no surface having ever said so.
     *
     * Bounded, because revival is not a boot-loop: it takes a live counterparty or an operator read.
     */
    // One statement, gated in SQL rather than on a field: `SessionRecord` does not carry this column
    // and widening the type to read it once would spread it through every consumer. `changes` tells
    // us whether it actually cleared, so the log stays a signal instead of firing on every revival.
    const clearedGaveUp = this.#db
      ?.prepare(
        "UPDATE sessions SET restart_seal_gave_up_at = NULL, restart_seal_gave_up_reason = NULL " +
        "WHERE agent_id = ? AND session_id = ? AND restart_seal_gave_up_at IS NOT NULL",
      )
      .run(this.resolveAgentId(agentName), sessionId);
    if ((clearedGaveUp?.changes ?? 0) > 0) {
      this.#logger.info("session.restart_seal.gave_up.cleared", {
        agentName, sessionId,
        impact: "this session is eligible for restart-seal recovery again — it is being revived, so it is not hopeless.",
      });
    }
    if (record.status === "sealed" || record.status === "abandoned" || record.status === "seal_interrupted_pending") {
      return {
        ok: false,
        reason: "session_terminal",
        guidance: `Session is '${record.status}'. A session that has ended cannot be revived; start a new one.`,
      };
    }
    /**
     * DOD-M15-FRAME-1 (review F1) — A DEFENSIVE FREEZE MUST NOT UNDO ITSELF ON THE NEXT READ.
     *
     * `#freezeOnIdentityFailure` tears the node down, and a teardown writes status `interrupted`.
     * `interrupted` is not terminal — it is the *revivable* status — so `reviveIfNeededForRead`
     * fired on the operator's very next `cello_receive`, rebuilt a node behind a gater allowing the
     * SAME counterparty peer, flipped the row back to `active`, and logged it as a success.
     *
     * The freeze therefore lasted until the next keystroke, while the log line said *"no further
     * content will be accepted on this session"*. A security decision that silently reverses itself,
     * with a message asserting the opposite, is a worse defect than the one the freeze was added to
     * fix — and it is the class this milestone exists to remove, reintroduced by its own fix.
     *
     * Checked BEFORE the cap and after the terminal statuses, so the answer names the freeze rather
     * than whatever else the session would have been refused for.
     *
     * In memory, and so lost on a daemon restart — the same bound as `DOD-M15-DIVERGE-DURABLE-1`
     * and for the same reason. The durable column is `DOD-M15-FREEZE-STATUS-1`; the reversibility
     * could not wait for it.
     */
    const frozen = this.#frozenSessions.get(key);
    if (frozen) {
      // The REASON and the GUIDANCE both come from the site that froze it. Hardcoding them here was
      // correct while an identity failure was the only way in, and became a false accusation the
      // moment a second one existed — see the note on `#frozenSessions`.
      return {
        ok: false,
        reason: frozen.reason,
        guidance:
          `${frozen.guidance} It is not revived automatically, and reading or sending will not clear it. ` +
          `Your transcript up to the freeze is intact: cello_transcript ${sessionId} reads it. ` +
          `To end the session and keep what it earned, close it — cello_close_session ${sessionId}. To talk to them again, start a fresh session rather than reviving this one.`,
      };
    }

    /**
     * THE CAP APPLIES TO A REVIVAL TOO (review: parity gap). Establishment refuses at
     * `MAX_SESSION_NODES` because each node is a real libp2p instance with listeners, connections
     * and a relay reservation. A revival builds exactly the same thing, so letting it past the cap
     * would let a daemon walk over the limit one reconnect at a time — and the limit exists to stop
     * a machine being taken down by its own session count.
     *
     * Refused by name, so the caller can say something true: this is a local resource limit, not a
     * problem with the session or the counterparty.
     */
    if (this.#activeNodes.size >= MAX_SESSION_NODES) {
      this.#logger.warn("session.revive.cap.reached", {
        agentName,
        sessionId,
        activeCount: this.#activeNodes.size,
        maxCount: MAX_SESSION_NODES,
        impact: "this session stays interrupted until another session ends and frees a node slot",
      });
      return {
        ok: false,
        reason: "session_node_cap_reached",
        guidance:
          `This daemon already holds ${MAX_SESSION_NODES} active session nodes, so this session ` +
          "cannot be brought back yet. Close a session you have finished with and try again.",
      };
    }

    const identity = this.#sessionSeeds.get(key);
    if (identity === undefined) {
      // The honest case: the daemon restarted, so the keypair is genuinely gone. That is
      // RESTART-SEAL-1's territory (resolve with a receipt), not a revival — and saying so is the
      // difference between an operator waiting for a reconnect that cannot happen and one closing
      // the session.
      return {
        ok: false,
        reason: "session_identity_lost",
        guidance:
          "This session's transport identity did not survive a daemon restart, so it cannot be " +
          "revived. It will be sealed automatically, or you can close it now to get its receipt.",
      };
    }

    const gater = new SessionConnectionGater({
      sessionId,
      allowedPeerId: identity.counterpartyPeerId,
      logger: this.#logger,
    });
    // The relay peers must be allowed OUTBOUND before the node starts, or the reservation the line
    // below depends on is refused by our own gater — the same ordering the receiver builder uses.
    const reservations = this.#reservationCircuitAddrs(agentName);
    for (const relayPeerId of reservations.relayPeerIds) gater.setAllowedOutboundPeer(relayPeerId);

    let node: CelloNode;
    const t0 = Date.now();
    this.#logger.info("session.revive.node.building", {
      agentName,
      sessionId,
      circuitAddrs: reservations.addrs.length,
      relayPeerIds: reservations.relayPeerIds.length,
    });
    try {
      node = await this.#receivers.buildRevivedNode(sessionId, gater, identity.seed, reservations.addrs, agentName);
      this.#logger.info("session.revive.node.started", {
        agentName,
        sessionId,
        startMs: Date.now() - t0,
        listenAddrs: node.listenAddresses().length,
        circuitListen: node.listenAddresses().filter((a) => a.includes("/p2p-circuit")).length,
      });
    } catch (err: unknown) {
      this.#logger.error("session.revive.node.failed", {
        agentName,
        sessionId,
        error: err instanceof Error ? err.message : String(err),
        impact: "the session stays interrupted; the next send will attempt this again",
      });
      return { ok: false, reason: "session_node_creation_failed" };
    }

    const autoNat = new NodeAutoNatService({
      node,
      logger: this.#logger,
      nodeType: "session",
      probers: this.#autoNatProbers(),
    });
    autoNat.emitInitialResult();

    // DOD-M12B-SESSION-SEED-1: give the re-dial its addresses back BEFORE the session goes active,
    // so the first send after a revival has somewhere to go. Without this the send fails instantly
    // on a connection that was never made, and — measured live — is lost rather than parked.
    if (identity.counterpartyAddrs.length > 0) {
      this.#counterpartyAddrs.set(key, [...identity.counterpartyAddrs]);
    }
    const correlationId = randomUUID();
    /**
     * DOD-M12B-REVIVE-PARK-1 — RESTORE THE RELAY, or a revived session cannot park and every failed
     * send is declared lost.
     *
     * This is the defect behind five identical live failures on 2026-08-18. `#parkContent` opens
     * with `if (!hook || !entry || !entry.relayPeerId || !entry.relayAddrs) return "unconfigured"`,
     * and a revived entry carried none of it — so the park was skipped and the send fell through to
     * *"could NOT be queued for retry — it is lost. Send it again."* The relay was recorded on the
     * session row the whole time, and store-and-forward would have delivered the message: the
     * counterparty's own sends park through it successfully in the same minute.
     *
     * What it cost the operator: their reply was accepted, discarded, and they were told to retype
     * it — which is how a transcript gets duplicates of a message that was never lost in the first
     * place.
     *
     * Read from the row rather than carried in the revival record on purpose: the row is where the
     * relay assignment is durable, and it is the same source `getPersistedRelayEndpoint` already
     * serves the startup flush from — a path that exists precisely because in-memory entries are
     * gone by then, which is exactly the situation a revival is in.
     */
    // ONE lookup, and ONE event for the absent case (review LOW-8). This used to read the endpoint
    // here and again inside the relay reconnect, and both logged `session.revive.relay.absent` with
    // different `impact` text — one event name standing for two meanings, fired twice for a single
    // condition. `#reconnectRevivedSessionRelay` takes it as a parameter now.
    const persistedRelay = this.#queries.getPersistedRelayEndpoint(agentName, sessionId);
    // 006-CRYPTO: a REVIVED session mints a FRESH keypair and re-keys — Decisions Carried #5. That
    // holds because the interrupt path destroys the old secret when it drops the entry; until it
    // did, this call found the stale key still in the map and quietly kept it. The salt, which IS
    // persisted, is re-read from the row instead — opposite lifetimes, deliberately.
    this.#ephemerals.mintSessionEphemeral(agentName, sessionId);
    /**
     * AND ANNOUNCE IT — review F1, second half. Minting a fresh key achieves nothing on its own: the
     * COUNTERPARTY has to hear about it, and it is the side that did NOT restart, so it is not
     * tearing anything down or reconnecting. `#sendEphemeralFrame` otherwise rides `onPeerConnect`,
     * which does not fire again for a connection that never dropped — the ordinary shape when only
     * one end's witness stream closed, which is what a relay roll produces.
     *
     * Without this the two ends sit on different keys for the life of the session, every message
     * fails GCM, and the receiving operator is told the content may have been MODIFIED IN FLIGHT for
     * what is a local key skew. Deferred a tick so the revived node's handlers are registered before
     * the frame goes out.
     */
    setTimeout(() => { void this.#ephemerals.sendEphemeralFrame(agentName, sessionId, "revive-rekey"); }, 0);
    this.#activeNodes.set(key, {
      node,
      agentName,
      sessionId,
      counterpartyPubkey: identity.counterpartyPubkey,
      gater,
      correlationId,
      counterpartySessionPeerId: identity.counterpartyPeerId,
      autoNat,
      ...(persistedRelay
        ? { relayPeerId: persistedRelay.relayPeerId, relayAddrs: persistedRelay.relayAddrs }
        : {}),
    });
    await this.#contentIn.registerContentHandler(agentName, sessionId, node, identity.counterpartyPubkey);
    /**
     * review HIGH-2 — REWIRE LIVENESS, or this session can never be interrupted again.
     *
     * Both creation paths call this; the first build of the revival did not. Without it the revived
     * session is pinned `active`: a later disconnect fires no transition, no `session_state_changed`
     * reaches the MCP client, and the receive surface renders unknown liveness as healthy-and-quiet.
     * So the SECOND laptop close would leave the operator staring at a session that reports fine and
     * is dead — this milestone's founding defect, one revival later, and with no status change left
     * to trigger the next revival either.
     */
    this.#liveness.wireSessionLiveness(
      agentName,
      sessionId,
      node,
      identity.counterpartyPubkey,
      correlationId,
      identity.counterpartyPeerId,
    );

    // DOD-M12B-REVIVE-RELAY-1: the step revival skipped. Establishment connects the relay witness
    // here; without it the session comes back with no live inbound path at all.
    await this.#reconnectRevivedSessionRelay(agentName, sessionId, node, gater, correlationId, persistedRelay);

    // THE REVERSE EDGE. A transport event took this session out of `active` and nothing has ever
    // put one back. Written after the node is live and its handler registered, so the row never
    // claims `active` for a session that cannot yet receive.
    //
    // review MEDIUM-3: the result is CHECKED. `#updateSessionStatus` returns false when the write
    // matched no row or the DB errored — and reporting revival ok on a row that still says
    // `interrupted` leaves a live, talking session where REVIVAL-BOUND-1's sweep can seal or abandon
    // it. Failing here means tearing the node back down rather than running in that split state.
    if (!this.#updateSessionStatus(agentName, sessionId, "active")) {
      /**
       * DOD-M15-RELAYLEAK-1 (review MEDIUM-4) — **THIS TEARDOWN LEAKED THE EXACT THING THE LINE IS
       * ABOUT, THROUGH A DIFFERENT DOOR.**
       *
       * `#reconnectRevivedSessionRelay` above has already called `registerSession` on the cached
       * relay client and hung it on this entry. Deleting the map key and stopping the node released
       * the daemon's own objects and left that registration standing with **no owner** — and
       * `#detachSessionRelay` closes a client only when `!hasSessions()`, so the orphaned
       * registration held that predicate false for the life of the process. The client, its
       * authenticated stream and its relay-side reservation were unreachable and immortal.
       *
       * The shutdown loop this line added does sweep it at exit, which is precisely why it had to be
       * fixed here too: a leak that is only cleaned up by process death is still a leak for every
       * hour the daemon is up.
       */
      /**
       * ⚠️ Review MEDIUM-2 — **THE ENTRY IS MATCHED BY IDENTITY, NOT BY KEY.** `reviveSessionNode`
       * has no in-flight guard: its `if (live) return` is separated from `#activeNodes.set` by the
       * whole node build, so two revivals for one key can both reach the `set` and the second
       * overwrites the first. Looking up by key alone would then hand THIS failing revival the
       * OTHER one's live entry, and detaching it would unregister a running session's leaf handler
       * — closing the client that session is using if it was the last one on it. Comparing `node`
       * costs one token and makes "the entry I created" provable rather than assumed.
       */
      const revivedEntry = this.#activeNodes.get(key);
      if (revivedEntry?.node === node) this.#detachSessionRelay(revivedEntry);
      this.#activeNodes.delete(key);
      // 006-CRYPTO: the revival FAILED, so the key it just minted belongs to a session that never
      // came back. Dropping the entry without this would strand it for the daemon's lifetime.
      this.#ephemerals.destroySessionEphemeralFor(agentName, sessionId);
      try {
        await node.stop();
      } catch { /* best-effort: the status write already failed and is logged with its cause */ }
      return {
        ok: false,
        reason: "session_status_write_failed",
        guidance:
          "The session node was rebuilt but its status could not be written, so it was torn back " +
          "down rather than left live under an interrupted row. The daemon logged the cause.",
      };
    }

    // The messages that failed while this session was down were queued on a promise of "retried on
    // reconnect". This is that reconnect — fire it before anyone is told the session is back.
    if (this.#retryDrainHook !== null) {
      try {
        this.#retryDrainHook(agentName, sessionId);
      } catch (err: unknown) {
        this.#logger.warn("session.revive.retry_drain.failed", {
          agentName,
          sessionId,
          error: err instanceof Error ? err.message : String(err),
          impact: "messages queued while this session was down are still queued",
        });
      }
    }

    const peerId = node.getPeerId();
    this.#logger.info("session.revived", {
      agentName,
      sessionId,
      peerId,
      // The whole claim of this line, in the log: the id did not change, so the counterparty's
      // stored dial target is still correct and they do not need to be told anything.
      identityPreserved: true,
    });
    return { ok: true, peerId };
  }

  /**
   * DOD-M12B-SESSION-SEED-1 — the DEMAND edge: a send on an interrupted session revives it.
   *
   * One of TWO production callers of `reviveSessionNode` — `reviveIfNeededForRead` is the other —
   * and both are deliberately demand paths rather than timers. The `REDIAL-1` discipline and Andre's tenet say the same thing from two
   * directions: nothing may re-open on its own, because a background rebuilder would hold a dialable
   * endpoint open for a session nobody is using — the *"open connection a malicious agent can farm
   * for"*. The operator sending is the demand; there is no other trigger.
   *
   * A no-op for the normal case. An `active` session with a live node returns immediately without
   * touching it — this sits on the hot path of every send, and replacing a healthy node would be
   * churn that changes the peer id for no reason.
   */
  async reviveIfNeededForSend(
    agentName: string,
    sessionId: string,
  ): Promise<{ ok: true } | { ok: false; reason: string; guidance?: string }> {
    const record = this.#queries.getSessionRecord(agentName, sessionId);
    if (!record) return { ok: false, reason: "session_not_found" };
    // The overwhelmingly common case: nothing to do, and no node was disturbed to find that out.
    if (record.status === "active" && this.#activeNodes.has(this.#k(agentName, sessionId))) return { ok: true };

    const revived = await this.reviveSessionNode(agentName, sessionId);
    if (!revived.ok) {
      this.#logger.info("session.revive.declined", {
        agentName,
        sessionId,
        previousStatus: record.status,
        trigger: "send",
        reason: revived.reason,
      });
      return revived;
    }
    this.#logger.info("session.revived.on_demand", {
      agentName,
      sessionId,
      previousStatus: record.status,
      trigger: "send",
    });
    return { ok: true };
  }

  /**
   * DOD-M12B-SESSION-SEED-1 (case B) — the INBOUND half of the demand edge.
   *
   * `reviveIfNeededForSend` covers the operator waking first. Case B's triggers are symmetric — a
   * wifi hop, a relay restart, a directory node cycling — so half the time the COUNTERPARTY wakes
   * first. They send; we have no node yet, because revival is demand-driven and we have demanded
   * nothing. Their content parks at the relay, which is the backstop working as designed.
   *
   * Then the operator comes back and READS, and until now that told them nothing: the receive
   * handler reads the transcript and never gates on status, so it happily reports what is already
   * stored while messages sit parked, waiting for a node that will not exist until the operator
   * happens to SEND. An operator who only reads was stuck forever with a surface that looked fine.
   *
   * **WHY A READ MAY TRIGGER THIS AND AN INBOUND DIAL MAY NOT.** Andre's tenet is about what a
   * REMOTE party can cause: *"an open connection that a malicious agent can farm for."* Reviving
   * because a peer dialled us would hand that lever straight to the peer — a stranger could keep our
   * endpoints open indefinitely by poking dead sessions. A read is the OPERATOR asking, on their own
   * machine, for their own session: the same class of demand as a send, and the class the tenet
   * allows. That distinction is the whole reason this is a separate entry point rather than a
   * revival triggered from the inbound handler.
   */
  async reviveIfNeededForRead(
    agentName: string,
    sessionId: string,
  ): Promise<{ ok: true } | { ok: false; reason: string; guidance?: string }> {
    const record = this.#queries.getSessionRecord(agentName, sessionId);
    if (!record) return { ok: false, reason: "session_not_found" };
    if (record.status === "active" && this.#activeNodes.has(this.#k(agentName, sessionId))) return { ok: true };
    // Reading the transcript of an ended session is normal and must keep working — the CALLER does
    // not treat this refusal as an error, it just reads what is stored. What must not happen is the
    // read bringing the session back: the receipt is issued and the identity is gone.
    const revived = await this.reviveSessionNode(agentName, sessionId);
    if (!revived.ok) {
      // review MEDIUM-4: the absence of a success line was the only signal that a session could not
      // come back. `session_identity_lost` is the one an operator most needs, and it was generated
      // and destroyed one stack frame later with nothing written down.
      this.#logger.info("session.revive.declined", {
        agentName,
        sessionId,
        previousStatus: record.status,
        trigger: "read",
        reason: revived.reason,
      });
      return revived;
    }

    this.#logger.info("session.revived.on_demand", {
      agentName,
      sessionId,
      previousStatus: record.status,
      trigger: "read",
    });
    // Fetch what is waiting NOW. Review MEDIUM-5 corrected the claim this used to make: the drain
    // runs off the AGENT's standing receiver, not the session node, and the 5-minute backstop would
    // have delivered this content anyway. So this is an accelerator, not a rescue — worth having,
    // and worth describing accurately. (The send path deliberately does not fire one: the same
    // backstop covers it, at a cost of at most one interval.)
    this.#park.fireParkedDrain(agentName, "session_revived");
    return { ok: true };
  }

  /** DOD-M12B-REVIVE-PARK-1 test seam: the relay the live entry will park to. Not otherwise
   *  observable — `#activeNodes` is private and the park's own refusal is silent about which of its
   *  four preconditions was missing. */
  getSessionRelayForTest(agentName: string, sessionId: string): { relayPeerId?: string; relayAddrs?: string[] } | null {
    const entry = this.#activeNodes.get(this.#k(agentName, sessionId));
    if (!entry) return null;
    return {
      ...(entry.relayPeerId !== undefined ? { relayPeerId: entry.relayPeerId } : {}),
      ...(entry.relayAddrs !== undefined ? { relayAddrs: entry.relayAddrs } : {}),
    };
  }

  /** DOD-M12B-SESSION-SEED-1 test seams: the counterparty addresses a re-dial depends on. Not
   *  otherwise observable — they are set from a signed relay assignment that a fixture cannot mint. */
  setCounterpartyAddrsForTest(agentName: string, sessionId: string, addrs: string[]): void {
    this.#counterpartyAddrs.set(this.#k(agentName, sessionId), [...addrs]);
  }

  getCounterpartyAddrsForTest(agentName: string, sessionId: string): string[] {
    return this.#counterpartyAddrs.get(this.#k(agentName, sessionId)) ?? [];
  }

  /** DOD-M12B-SESSION-SEED-1 test seam: drop a seed WITHOUT zeroing or a status change — what a
   *  process restart does to it. The refusal that follows is the one an operator most needs named. */
  forgetSessionSeedForTest(agentName: string, sessionId: string): void {
    this.#sessionSeeds.delete(this.#k(agentName, sessionId));
  }

  /**
   * DOD-M12B-SESSION-SEED-1 — drain the direct-resend queue when a session comes back.
   *
   * `retryQueue.drainSession` had NO production caller. The send path enqueues into it on a failed
   * delivery and tells the operator the message will be "retried on reconnect", and nothing ever
   * reconnected it — the row sat there until the session went terminal and was reaped. Measured
   * live 2026-08-18: two of the operator's messages went in, and the response told them both were
   * lost and to send again, which is how a transcript gets duplicates.
   *
   * A revival IS the reconnect that sentence promised. This is the hook that makes it true.
   */
  setRetryDrainHook(fn: (agentName: string, sessionId: string) => void): void {
    this.#retryDrainHook = fn;
  }

  /** DOD-M12B-SESSION-SEED-1 test seam: does this session still hold a revivable identity? */
  hasSessionSeedForTest(agentName: string, sessionId: string): boolean {
    return this.#sessionSeeds.has(this.#k(agentName, sessionId));
  }

  getStandingReceiverSeedForTest(agentName: string): Uint8Array | undefined {
    return this.#standingReceivers.get(agentName)?.seed;
  }

  async ensureStandingReceiverForAgent(agentName: string): Promise<void> {
    this.#agentsWantingReceiver.add(agentName);
    this.#startReservationWatchdog();
    await this.#receivers.ensureStandingReceiver(agentName);
  }

  async removeStandingReceiverForAgent(agentName: string): Promise<void> {
    // M8B F14: the agent no longer wants a receiver — disarm the teardown re-arm.
    this.#agentsWantingReceiver.delete(agentName);
    // The directory hands these out at signaling-auth time, so a re-started agent
    // gets a fresh set on its next connect — holding the old ones would keep a
    // retired agent's relay list alive for the daemon's lifetime.
    this.#directoryRelayEndpoints.delete(agentName);
    // DOD-M12B-RESERVATION-RETRY-1: and the retry budget with them. A spent budget that survives an
    // offline→online cycle is a LATCH: the new receiver gets no reservation, the watchdog finds
    // `attempts` already past the cap, and returns having done nothing — no retry and not even a
    // second give-up. The agent is undialable and the machinery is inert and mute until a daemon
    // restart. Same reason the line above exists ("holding the old ones would keep a retired agent's
    // relay list alive for the daemon's lifetime").
    this.#srReservationRetry.delete(agentName);
    this.#srLastRejectionReason.delete(agentName);
    const sr = this.#standingReceivers.get(agentName);
    if (!sr) {
      // L1: an #ensureStandingReceiver for this agent may be in flight (parked on start(), so no
      // map entry yet). Leave a tombstone — that ensure tears its fresh node down on completion
      // instead of installing an SR for an agent that is now offline. Also drop any stale creating
      // marker so a later start can re-ensure.
      if (this.#standingReceiverCreating.has(agentName)) this.#standingReceiverRemoving.add(agentName);
      return;
    }
    const removed = this.#standingReceivers.get(agentName);
    this.#standingReceivers.delete(agentName);
    // DOD-M12B-SESSION-SEED-1 (review F8): the operator took this agent offline — its advertised
    // identity is not needed any more, and the tenet's rule is that nothing unneeded stays live.
    removed?.seed.fill(0);
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
      /**
       * ⚠️ THE SESSION'S STARTING POINT GOES IN AT INSERT — `DOD-M15-SELFCHAIN-1`.
       *
       * It is recorded before this row exists (the session open needs it before the node is built),
       * so an UPDATE at that moment has nothing to match. Writing it here is what puts it on disk,
       * and on disk is what lets the chain be resumed after a restart. `null` when nothing recorded
       * one, which is a session whose sends will be refused by name rather than silently unlinked.
       */
      const genesis = this.#leafRecords.genesisFor(agentName, sessionId);
      this.#db
        .prepare(
          `INSERT INTO sessions
           (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at, genesis_prev_root)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(sessionId, this.#requireAgentId(agentName), counterpartyPubkey, status, now, now,
             genesis ? Buffer.from(genesis) : null);
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
  /**
   * DOD-M12B-REAP-HELD-1 — did the counterparty EVER establish? Counted from every place their
   * messages can be, not just the one.
   *
   * OBSERVED LIVE 2026-08-18: the half-open reaper abandoned session `d28db475…` — twenty leaves in
   * the chain and sixteen more frames verified and held, ten of them from the counterparty — while
   * the restart-seal resolver was actively trying to notarize it. The receipt was forfeited.
   *
   * `countReceivedMessages` asks the TRANSCRIPT, and **held content never reaches the transcript**;
   * it sits in `held_content` until it can join the chain. So the very condition that holds content
   * — an interrupted session — is the condition that makes the counterparty's messages invisible,
   * and a fully-established conversation reads identically to an offer nobody ever answered.
   *
   * `origin = 'received'` is load-bearing. Our OWN held frames prove nothing about them, and
   * counting those would make every session we ever spoke into un-reapable — which is exactly the
   * clutter the reaper exists to clear. D18 also depends on the zero case staying zero: reaping only
   * genuinely 0-received ghosts is what stops a stranger whose first handshakes died from being
   * locked out by the acceptance bound forever.
   */
  countEstablishedReceived(agentName: string, sessionId: string): number {
    if (!this.#db) return 0;
    const agentId = this.#requireAgentId(agentName);
    const held = this.#db
      .prepare("SELECT COUNT(*) AS n FROM held_content WHERE agent_id = ? AND session_id = ? AND origin = 'received'")
      .get(agentId, sessionId) as { n: number };
    return this.#queries.countReceivedMessages(agentName, sessionId) + (held?.n ?? 0);
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

  #updateSessionStatus(
    agentName: string,
    sessionId: string,
    status: "active" | "sealed" | "interrupted" | "abandoned",
    // DOD-CAP-SELF-HEAL-1: who caused an interruption, when this call is the one causing it.
    // Omitting it leaves the column NULL, which the acceptance bound reads as the counterparty's —
    // so a LOCAL teardown that forgets to say so is charged to the peer. That is exactly how the
    // operator's own kill switch (`cello_set_agent_offline` → destroySessionNode) was locking out
    // a counterparty who had done nothing.
    interruptedBy?: "local",
  ): boolean {
    if (!this.#db) return false;
    /**
     * DOD-M12B-SESSION-SEED-1 (review F2) — the identity dies on terminal INTENT, not on a
     * successful UPDATE.
     *
     * The first build destroyed the seed only after the write landed. `#requireAgentId` THROWS for
     * a retired agent, so every terminal write for a revoked agent's sessions fell into the catch
     * and kept its transport identity for the life of the process — an identity whose agent has
     * just been revoked in the directory, held with nothing reporting it, and REVIVAL-BOUND-1's
     * sweep excludes retired agents so nothing else closed it either. The same held for a
     * `session.status.write.missed` and for any DB error.
     *
     * Coupling a security teardown to a database write is backwards: the write can fail, and the
     * failure is exactly when we least want a live key lying around. So it runs FIRST and
     * unconditionally, and if the write then fails the session is one we can no longer revive —
     * which is the safe direction, and is reported loudly below rather than inferred from the
     * absence of a debug line.
     */
    if (status === "sealed" || status === "abandoned") {
      this.#destroySessionSeed(agentName, sessionId);
      // DOD-M15-DIVERGE-1: divergence stops being true HERE and only here. It used to be dropped by
      // `#evictSessionCaches` on every node teardown — including the one that writes `interrupted`,
      // which is a status the seal gate still acts on, so the fact was forgotten while it was still
      // load-bearing. A terminal status is the one point at which no future close can be refused,
      // so the flag has nothing left to protect.
      this.#records.clearDivergedMemo(agentName, sessionId);
      // DURABLE too (DOD-M15-DIVERGE-DURABLE-1) — otherwise a sealed session comes back after a
      // restart still carrying a refusal for a close that can no longer happen.
      // (agent_id, session_id) — see markSessionDiverged. Unkeyed, one side sealing cleared the
      // OTHER side's divergence on a loopback session.
      this.#db
        ?.prepare("UPDATE sessions SET diverged_at = NULL WHERE agent_id = ? AND session_id = ?")
        .run(this.#requireAgentId(agentName), sessionId);
    }
    // THE TERMINAL GUARD LIVES HERE, not in one wrapper, because there are three writers of
    // "sealed": markSealed, destroySessionNode, and retireSession on the witnessed-submit path.
    // Guarding only the wrapper asserts the invariant in a test while two other paths still break
    // it.
    //
    //   abandoned → sealed  REFUSED. A force-abandon is the documented way to give up a receipt.
    //     A certificate arriving afterwards must not silently overturn the operator's decision. The
    //     certificate is still stored by recordSealCertificate and stays retrievable.
    //   sealed → sealed     REFUSED. Nothing to write, and re-running the terminal disposition
    //     hooks for a no-op should not be reported as a status that landed.
    if (status === "sealed") {
      const current = this.#queries.getSessionRecord(agentName, sessionId)?.status;
      if (current === "abandoned" || current === "sealed") {
        this.#logger.info("session.seal.status.not_written", {
          agentName, sessionId, currentStatus: current,
          impact: current === "abandoned"
            ? "a certificate arrived for a session the operator force-abandoned; it is stored and retrievable, but the row keeps saying abandoned"
            : "already sealed — nothing to write",
        });
        return false;
      }
      if (current === undefined) {
        // ORDINARY, not an error. recordSealCertificate documents this case: the seal can arrive
        // before the row is persisted. Falling through would emit `session.status.write.missed` at
        // ERROR level for a shape the system expects.
        this.#logger.info("session.seal.status.no_row", {
          agentName, sessionId,
          impact: "no session row yet — the certificate is still recorded and retrievable",
        });
        return false;
      }
    }
    const now = Date.now();
    try {
      const res = this.#db
        .prepare(
          // DOD-M12B-REVIVAL-BOUND-1: this is the FOURTH writer of `status = 'interrupted'`, and
          // until now the only one that wrote no `interrupted_at`. That is where Entry 41's two
          // timestamp-less rows came from, and a row with no timestamp has no revival bound that
          // can be evaluated. `COALESCE` matches the three sibling producers: the FIRST
          // interruption is the clock, so re-entering the status cannot push the deadline out.
          status === "interrupted"
            ? (interruptedBy === undefined
              ? "UPDATE sessions SET status = ?, updated_at = ?, interrupted_at = COALESCE(interrupted_at, ?) WHERE agent_id = ? AND session_id = ?"
              : "UPDATE sessions SET status = ?, updated_at = ?, interrupted_at = COALESCE(interrupted_at, ?), interrupted_by = 'local' WHERE agent_id = ? AND session_id = ?")
            : (interruptedBy === undefined
              ? "UPDATE sessions SET status = ?, updated_at = ? WHERE agent_id = ? AND session_id = ?"
              : "UPDATE sessions SET status = ?, updated_at = ?, interrupted_by = 'local' WHERE agent_id = ? AND session_id = ?"),
        )
        .run(
          ...(status === "interrupted"
            ? [status, now, new Date(now).toISOString(), this.#requireAgentId(agentName), sessionId]
            : [status, now, this.#requireAgentId(agentName), sessionId]),
        ) as unknown as { changes?: number | bigint };
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
          impact: (status === "sealed" || status === "abandoned")
            ? "no session row matched — the status was NOT changed and no disposition was run, AND "
              + "this session's transport identity has already been destroyed, so it can no longer "
              + "be revived even though its row still says it is open"
            : "no session row matched — the status was NOT changed and no disposition was run",
        });
        return false;
      }
      // DOD-RETRYQ-STRAND-1: only AFTER the status write actually landed. Disposing of durable
      // state on the strength of a write that did not land would discard content while the session
      // is still, on disk, drainable. 'interrupted' and 'seal_interrupted_pending' are deliberately
      // NOT terminal — both can still complete, and reaping them would destroy live content.
      if (status === "sealed" || status === "abandoned") {
        // DOD-M12B-STRAND-1: held frames outlive the chain that could have carried them.
        //
        // Once a session is terminal, `ingestReceivedContent` refuses it — and #releaseHeld is only
        // reachable from ingest — so no code path that exists can ever release a held frame again.
        // Left alone the rows sit on disk, unreachable by any surface, while the teardown alarm
        // reports `lost: 0`: a success message for content that has just become permanently
        // unreadable. The annex is the store built for exactly this shape.
        this.#held.annexHeldContentOnTerminal(agentName, sessionId, status);
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
