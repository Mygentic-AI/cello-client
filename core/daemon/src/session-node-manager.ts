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
import { type ContentHashAlg } from "./wire-content-hash.js";
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
import * as lp from "it-length-prefixed";
import { encodeCbor } from "@cello-protocol/protocol-types";
import type { Stream } from "@libp2p/interface";
import type { Logger, SessionRecord } from "./types.js";
import { STANDING_RECEIVER_AGENT_NAME } from "./types.js";
import { SessionConnectionGater } from "./session-connection-gater.js";
import { SessionTree, type WritableSessionTreeLeafKind } from "./session-tree.js";
import { CELLO_CONTENT_PROTOCOL_ID, NodeAutoNatService, type CelloNode, type IAutoNatService } from "@cello-protocol/transport";
import type { KeyProvider } from "@cello-protocol/crypto";
import { type SessionEphemeral } from "@cello-protocol/crypto";
// `PARK_ENVELOPE_REASONS` is deliberately NOT imported here. The reason codes are compared inside
// `park-envelope.ts` itself (`parkRefusalGuidance`) and asserted in its own test; this file only ever
// receives the already-classified `ParkAuthFailure`, so importing the code table here would invite a
// second, drifting copy of the classification logic.
import { decodeParkEnvelope, type ParkEnvelope } from "./park-envelope.js";
// `LEAF_KIND_MSG` is no longer imported here: `sendContent`'s `leafKind` stopped defaulting to it
// (B2b-1 review F4), so this file no longer names a default — every caller states its own kind.
import { AgentRelayClient, type RelayAuthRefusal, type RelayWitnessAlert } from "./session-relay-client.js";
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
import { SessionSeal } from "./session-seal.js";
import { SessionRelay } from "./session-relay.js";
import { SessionLifecycle } from "./session-lifecycle.js";
import type { SessionContentPipelineContext } from "./session-content-context.js";
import { StandingReceivers } from "./standing-receivers.js";
import { RelayReceiptStore } from "./relay-receipt-store.js";
import { SessionSealLeafStore } from "./session-seal-leaf-store.js";
import { SessionOwnChainStore } from "./session-own-chain-store.js";
import type { SealFrontierLeaf } from "./seal-frontier-verify.js";
import { type SecurityGatewayClient } from "@cello-protocol/gateway";

/**
 * One row in an agent's witness-alert list — DOD-M15-CORROBORATE-1 review F1. Deduped on
 * `(witness relay, session)`, so a repeated observation raises `occurrences` rather than taking
 * another slot in a bounded list.
 */
import { ABUSE_MAX_UNKNOWN_SESSIONS_GLOBAL, type ActiveSessionEntry, type AwaitingAckEntry, CONTENT_MAX_INBOUND_STREAMS, type ISessionNodeFactory, LEAF_FETCH_GRACE_MS, type ParkedDrainReason, type QuarantinedRecord, type ReceivedContentEntry, type RefusalNotice, type SessionImpairment, type SessionRevivalIdentity, type TranscriptEntry, type WitnessAlertNotice } from "./session-node-types.js";

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
  // through `session-content-ingest.ts`'s appendVerifiedContent buffer write; screenInbound gates
  // it there, on every
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
  // rebuilt. See `#reservationWatchdogTick` in `session-relay.ts`.
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
   * So this map is cleared in the same step that writes a terminal status (`SessionLifecycle.updateSessionStatus`),
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
   * alone and swept in `#evictPeersOutsideGate` (`session-lifecycle.ts`), which operates on libp2p connections and is not
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

  /**
   * Closing a conversation and proving it closed — readiness, the SEAL leaf, the carry, the
   * certificate, and the auto-acknowledgement gate. Eleven of its methods keep delegators below
   * because 86 call sites outside this class name them on the manager.
   */
  readonly #seal: SessionSeal;

  /**
   * Talking to the blind witness: connecting a session to its relay, proving key possession, holding
   * and renewing the circuit reservation that keeps this agent reachable behind a NAT, quarantining
   * a relay that misbehaves, and detaching cleanly.
   */
  readonly #relay: SessionRelay;

  /**
   * A session's life: opened, accepted, connected, revived on the peer id the counterparty still
   * holds, moved between statuses, and torn down. The last of the four paths to leave this class.
   */
  readonly #life: SessionLifecycle;

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
  /**
   * M7-SESSION-004 (AC-005): persist the seal certificate's legibility object with the
   * sealed record. Stored as a JSON string (hex-encoded pubkeys) so it round-trips a
   * daemon restart and is returned intact on the cert-read surface. The caller normalises
   * the raw wire legibility (Uint8Array pubkeys) into a JSON-safe shape before storing.
   * Best-effort: a session row may not yet exist (the seal arrived before the row was
   * persisted); in that case we no-op rather than throw — the cert still flows through the
   * live return path. The legibility content is identical regardless of delivery timing.
   *
   * ⚠️ THIS BLOCK WAS STRANDED WHEN THE METHOD BECAME A DELEGATOR. It stayed behind and ended up
   * stacked on top of `markSealed`'s own doc block, so that method showed two descriptions and the
   * first one described a different method entirely — and the seal split then carried it into
   * `session-seal.ts`, where `recordSealCertificate` does not appear at all. Returned to the call
   * it describes. The row-writing itself lives in `session-queries.ts`.
   */
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
  // cello_receive. Populated by `session-content-ingest.ts` — ingestReceivedContent and the
  // content stream handler.
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
   * client to read it from. Both are written from ONE place — `noteAcknowledgeable`, in
   * `session-content-ingest.ts` — so they
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

    // REQUIRED, no fallback (INV-9, audit finding). This check used to read
    // `opts.securityGateway ?? new PassthroughGatewayClient()` — the identical shape as the defect
    // that reopened this milestone, one layer down and still shipping in the binary. `daemon.ts`
    // was hardened to throw while this constructor was not, so the inbound screen had a silent
    // always-allow path that nothing in the product reached TODAY and any future refactor could.
    // "Currently unreachable" is a property of today's call sites, not of the code.
    //
    // ⚠️ CHECKED AND ASSIGNED FIRST, ahead of every collaborator: the content pipeline below is
    // handed this client by value, and a constructor cannot hand out a field it has not set. It also
    // means a caller that forgot to screen is told before the manager builds anything.
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
      getSealCarry: (pk, sid) => this.#seal.getSealCarry(pk, sid),
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
      maybeAutoAcknowledgeSeal: (a, sid, cid) => this.#seal.maybeAutoAcknowledgeSeal(a, sid, cid),
      ownChainOf: (a, sid, entry, ownPubkey) => this.#ownChainOf(a, sid, entry, ownPubkey),
      updateSessionStatus: (a, sid, status, by) => this.#life.updateSessionStatus(a, sid, status, by),
      abandonSession: (a, sid) => this.#life.abandonSession(a, sid),
      connectToCounterparty: (a, sid, addrs) => this.#life.connectToCounterparty(a, sid, addrs),
      destroySessionNode: (a, sid, reason) => this.#life.destroySessionNode(a, sid, reason),
      retireOnCounterpartyAbandon: (a, sid, cid) => this.#life.retireOnCounterpartyAbandon(a, sid, cid),
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
      proveToRelay: (a, circuitAddr, node, cid, surface) => this.#relay.proveToRelay(a, circuitAddr, node, cid, surface),
      reservationCircuitAddrs: (a) => this.#relay.reservationCircuitAddrs(a),
      authenticateStandingReceiver: (a, node, relayPeerId, heldCircuitAddr, cid) => this.#relay.authenticateStandingReceiver(a, node, relayPeerId, heldCircuitAddr, cid),
    });

    /**
     * ⚠️ BUILT AFTER `#receivers`, which it holds BY VALUE — the same ordering rule as every
     * collaborator above, and the one tsc caught on `#logger`. The seal path falls back to the
     * agent's standing receiver when an interrupted session has no node of its own, so a seal
     * constructed before the receivers would have captured `undefined` for exactly the case it
     * exists to serve.
     *
     * `mgr` again, and for the same reason as the content context above: the two seal stores are
     * opened LAZILY — on first use, because they need a database that does not exist yet — and both
     * sides must end up holding the SAME instance. Passing them by value would have handed this file
     * a permanent `null` and let it open a second store over the same rows.
     */
    this.#seal = new SessionSeal({
      logger: this.#logger,
      records: this.#records,
      queries: this.#queries,
      park: this.#park,
      held: this.#held,
      leafRecords: this.#leafRecords,
      receivers: this.#receivers,
      db: () => this.#db,

      activeNodes: this.#activeNodes,
      heldContent: this.#heldContent,
      witnessedSeq: this.#witnessedSeq,
      highWaterSeq: this.#highWaterSeq,
      orderingObserved: this.#orderingObserved,
      contentDesynced: this.#contentDesynced,
      responderSealSubmitted: this.#responderSealSubmitted,
      relayClients: this.#relayClients,

      get relayReceiptStore() { return mgr.#relayReceiptStore; },
      set relayReceiptStore(v) { mgr.#relayReceiptStore = v; },
      get sealLeafStore() { return mgr.#sealLeafStore; },
      set sealLeafStore(v) { mgr.#sealLeafStore = v; },
      get ensureSealBroker() { return mgr.#ensureSealBroker; },
      set ensureSealBroker(v) { mgr.#ensureSealBroker = v; },
      get onSessionStateChanged() { return mgr.#onSessionStateChanged; },
      get ownChainStore() { return mgr.#ownChainStore; },
      get detachedRelayClientBuilder() { return mgr.#detachedRelayClientBuilder; },

      sessionKey: (a, sid) => this.#k(a, sid),
      requireAgentId: (a) => this.#requireAgentId(a),
      getSessionTree: (a, sid) => this.getSessionTree(a, sid),
      getSessionTreeRootHex: (a, sid) => this.getSessionTreeRootHex(a, sid),
      getDirectoryOnlineToken: (a) => this.getDirectoryOnlineToken(a),
      destroySessionSeed: (a, sid) => this.#life.destroySessionSeed(a, sid),
      updateSessionStatus: (a, sid, status, by) => this.#life.updateSessionStatus(a, sid, status, by),
    });

    /**
     * ⚠️ ALSO AFTER `#receivers`, and after `#contentIn` — both held by value. The reservation
     * watchdog reads the standing receivers directly, and a witnessed leaf arriving on a relay
     * stream is handed straight to the ingest side. Built before either, this would have captured
     * `undefined` for the two things it exists to connect.
     *
     * The two stores and the watchdog handle are accessors for the same reason as the seal's: they
     * are written after construction, and both sides must see one instance rather than each opening
     * its own over the same rows.
     */
    this.#relay = new SessionRelay({
      logger: this.#logger,
      records: this.#records,
      queries: this.#queries,
      park: this.#park,
      refusals: this.#refusals,
      leafRecords: this.#leafRecords,
      receivers: this.#receivers,
      witness: this.#witness,
      contentIn: this.#contentIn,
      db: () => this.#db,

      activeNodes: this.#activeNodes,
      relayClients: this.#relayClients,
      standingReceivers: this.#standingReceivers,
      agentsWantingReceiver: this.#agentsWantingReceiver,
      directoryRelayEndpoints: this.#directoryRelayEndpoints,
      relayQuarantine: this.#relayQuarantine,
      srReservationRetry: this.#srReservationRetry,
      srLastRejectionReason: this.#srLastRejectionReason,
      srLastRespreadAt: this.#srLastRespreadAt,
      srRelayRefusal: this.#srRelayRefusal,

      get shuttingDown() { return mgr.#shuttingDown; },
      get srReservationRetryMs() { return mgr.#srReservationRetryMs; },
      get srWatchdogIntervalMs() { return mgr.#srWatchdogIntervalMs; },
      get ownChainStore() { return mgr.#ownChainStore; },
      get relayReceiptStore() { return mgr.#relayReceiptStore; },
      set relayReceiptStore(v) { mgr.#relayReceiptStore = v; },
      get sealLeafStore() { return mgr.#sealLeafStore; },
      set sealLeafStore(v) { mgr.#sealLeafStore = v; },
      get reservationWatchdog() { return mgr.#reservationWatchdog; },
      set reservationWatchdog(v) { mgr.#reservationWatchdog = v; },
      get detachedRelayClientBuilder() { return mgr.#detachedRelayClientBuilder; },

      sessionKey: (a, sid) => this.#k(a, sid),
      requireAgentId: (a) => this.#requireAgentId(a),
      getDirectoryOnlineToken: (a) => this.getDirectoryOnlineToken(a),
      withDirectoryCause: (a, refusal) => this.#withDirectoryCause(a, refusal),
      markInterruptedWithDetails: (a, sid, n, source) => this.#life.markInterruptedWithDetails(a, sid, n, source),
    });

    /**
     * ⚠️ LAST, because it holds every other collaborator by value — it is the path that stands a
     * session up and tears it down, so it touches all of them. Anything added above this line is
     * fine; anything added below and handed to it by value is the `undefined` capture this
     * constructor has now been bitten by three times.
     */
    this.#life = new SessionLifecycle({
      logger: this.#logger,
      records: this.#records,
      queries: this.#queries,
      park: this.#park,
      held: this.#held,
      leafRecords: this.#leafRecords,
      receivers: this.#receivers,
      ephemerals: this.#ephemerals,
      liveness: this.#liveness,
      contentIn: this.#contentIn,
      contentOut: this.#contentOut,
      relay: this.#relay,
      db: () => this.#db,

      activeNodes: this.#activeNodes,
      standingReceivers: this.#standingReceivers,
      standingReceiverCreating: this.#standingReceiverCreating,
      agentsWantingReceiver: this.#agentsWantingReceiver,
      counterpartyAddrs: this.#counterpartyAddrs,
      sessionSeeds: this.#sessionSeeds,
      frozenSessions: this.#frozenSessions,
      sessionTerminal: this.#sessionTerminal,

      get shuttingDown() { return mgr.#shuttingDown; },
      get autoNatProbers() { return mgr.#autoNatProbers; },
      get onSessionStateChanged() { return mgr.#onSessionStateChanged; },
      get onSessionTerminal() { return mgr.#onSessionTerminal; },
      get retryDrainHook() { return mgr.#retryDrainHook; },

      sessionKey: (a, sid) => this.#k(a, sid),
      requireAgentId: (a) => this.#requireAgentId(a),
      resolveAgentId: (a) => this.resolveAgentId(a),
      getSessionTree: (a, sid) => this.getSessionTree(a, sid),
      evictSessionCaches: (a, sid) => this.#evictSessionCaches(a, sid),
    });
    this.#srWatchdogIntervalMs = opts.standingReceiverWatchdogIntervalMs ?? 30_000;
    this.#srReservationRetryMs = opts.standingReceiverReservationRetryMs ?? 5 * 60_000;
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
      this.#relay.detachSessionRelay(entry);
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
    await this.#life.boundedTeardown(Promise.all(stopPromises), "session_nodes", stopPromises.length);
    this.#activeNodes.clear();
    // Evict in-memory per-session caches (trees reload from SQLite; received-content
    // plaintext must not survive shutdown in memory).
    this.#trees.clear();
    this.#receivedContent.clear();
    // DOD-M12B-SESSION-SEED-1 (review F5): transport identities are key material and belong in the
    // same sentence as the plaintext above. Shutdown marks every active row `interrupted` by direct
    // SQL, so no `SessionLifecycle.updateSessionStatus` destroy fires for them — without this, every live session's
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
    await this.#life.boundedTeardown(
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
        if (await this.#life.abandonSession(s.agentName, s.sessionId)) {
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


  // ─── The session-lifecycle path's public surface, kept on the manager ──────────────────────
  //
  // These thirteen live in `session-lifecycle.ts`; their documentation is there, next to the code
  // it describes. They stay reachable here because 429 call sites outside this class name them on
  // the manager — `createSessionNode` alone has 177. Signatures are DERIVED, not copied.

  createSessionNode(
    ...args: Parameters<SessionLifecycle["createSessionNode"]>
  ): ReturnType<SessionLifecycle["createSessionNode"]> {
    return this.#life.createSessionNode(...args);
  }

  acceptSession(
    ...args: Parameters<SessionLifecycle["acceptSession"]>
  ): ReturnType<SessionLifecycle["acceptSession"]> {
    return this.#life.acceptSession(...args);
  }

  destroySessionNode(
    ...args: Parameters<SessionLifecycle["destroySessionNode"]>
  ): ReturnType<SessionLifecycle["destroySessionNode"]> {
    return this.#life.destroySessionNode(...args);
  }

  retireSessionNode(
    ...args: Parameters<SessionLifecycle["retireSessionNode"]>
  ): ReturnType<SessionLifecycle["retireSessionNode"]> {
    return this.#life.retireSessionNode(...args);
  }

  markInterruptedWithDetails(
    ...args: Parameters<SessionLifecycle["markInterruptedWithDetails"]>
  ): ReturnType<SessionLifecycle["markInterruptedWithDetails"]> {
    return this.#life.markInterruptedWithDetails(...args);
  }

  connectToCounterparty(
    ...args: Parameters<SessionLifecycle["connectToCounterparty"]>
  ): ReturnType<SessionLifecycle["connectToCounterparty"]> {
    return this.#life.connectToCounterparty(...args);
  }

  notifyCounterpartyAbandon(
    ...args: Parameters<SessionLifecycle["notifyCounterpartyAbandon"]>
  ): ReturnType<SessionLifecycle["notifyCounterpartyAbandon"]> {
    return this.#life.notifyCounterpartyAbandon(...args);
  }

  retireOnCounterpartyAbandon(
    ...args: Parameters<SessionLifecycle["retireOnCounterpartyAbandon"]>
  ): ReturnType<SessionLifecycle["retireOnCounterpartyAbandon"]> {
    return this.#life.retireOnCounterpartyAbandon(...args);
  }

  reviveSessionNode(
    ...args: Parameters<SessionLifecycle["reviveSessionNode"]>
  ): ReturnType<SessionLifecycle["reviveSessionNode"]> {
    return this.#life.reviveSessionNode(...args);
  }

  reviveIfNeededForSend(
    ...args: Parameters<SessionLifecycle["reviveIfNeededForSend"]>
  ): ReturnType<SessionLifecycle["reviveIfNeededForSend"]> {
    return this.#life.reviveIfNeededForSend(...args);
  }

  reviveIfNeededForRead(
    ...args: Parameters<SessionLifecycle["reviveIfNeededForRead"]>
  ): ReturnType<SessionLifecycle["reviveIfNeededForRead"]> {
    return this.#life.reviveIfNeededForRead(...args);
  }

  abandonSession(
    ...args: Parameters<SessionLifecycle["abandonSession"]>
  ): ReturnType<SessionLifecycle["abandonSession"]> {
    return this.#life.abandonSession(...args);
  }

  getSessionNodePeerId(
    ...args: Parameters<SessionLifecycle["getSessionNodePeerId"]>
  ): ReturnType<SessionLifecycle["getSessionNodePeerId"]> {
    return this.#life.getSessionNodePeerId(...args);
  }

  // ─── The relay path's public surface, kept on the manager ──────────────────────────────────
  //
  // These nine live in `session-relay.ts`; their documentation is there, next to the code it
  // describes. They stay reachable here because 43 call sites outside this class name them on the
  // manager. Signatures are DERIVED, not copied, for the same reason as the seal and content
  // delegators: a copy is a second declaration free to drift from the first.

  setDirectoryRelayEndpoints(
    ...args: Parameters<SessionRelay["setDirectoryRelayEndpoints"]>
  ): ReturnType<SessionRelay["setDirectoryRelayEndpoints"]> {
    return this.#relay.setDirectoryRelayEndpoints(...args);
  }

  registerRelayStream(
    ...args: Parameters<SessionRelay["registerRelayStream"]>
  ): ReturnType<SessionRelay["registerRelayStream"]> {
    return this.#relay.registerRelayStream(...args);
  }

  isRelayCarvedOutInbound(
    ...args: Parameters<SessionRelay["isRelayCarvedOutInbound"]>
  ): ReturnType<SessionRelay["isRelayCarvedOutInbound"]> {
    return this.#relay.isRelayCarvedOutInbound(...args);
  }

  isRelayQuarantined(
    ...args: Parameters<SessionRelay["isRelayQuarantined"]>
  ): ReturnType<SessionRelay["isRelayQuarantined"]> {
    return this.#relay.isRelayQuarantined(...args);
  }

  quarantineRefusedInbound(
    ...args: Parameters<SessionRelay["quarantineRefusedInbound"]>
  ): ReturnType<SessionRelay["quarantineRefusedInbound"]> {
    return this.#relay.quarantineRefusedInbound(...args);
  }

  quarantineFrameMeta(
    ...args: Parameters<SessionRelay["quarantineFrameMeta"]>
  ): ReturnType<SessionRelay["quarantineFrameMeta"]> {
    return this.#relay.quarantineFrameMeta(...args);
  }

  getRelayReceipts(
    ...args: Parameters<SessionRelay["getRelayReceipts"]>
  ): ReturnType<SessionRelay["getRelayReceipts"]> {
    return this.#relay.getRelayReceipts(...args);
  }

  patchRelayClientForTest(
    ...args: Parameters<SessionRelay["patchRelayClientForTest"]>
  ): ReturnType<SessionRelay["patchRelayClientForTest"]> {
    return this.#relay.patchRelayClientForTest(...args);
  }

  getSessionRelayForTest(
    ...args: Parameters<SessionRelay["getSessionRelayForTest"]>
  ): ReturnType<SessionRelay["getSessionRelayForTest"]> {
    return this.#relay.getSessionRelayForTest(...args);
  }

  // ─── The seal path's public surface, kept on the manager ───────────────────────────────────
  //
  // These eleven live in `session-seal.ts`; their documentation is there, next to the code it
  // describes. They stay reachable here because 86 call sites outside this class — the close
  // handler, the seal coordinator, the escalation and certificate-pull paths, and `daemon.ts`
  // itself — name them on the manager. Signatures are DERIVED for the same reason as the content
  // delegators below: a copy is a second declaration free to drift from the first.

  submitSealLeaf(
    ...args: Parameters<SessionSeal["submitSealLeaf"]>
  ): ReturnType<SessionSeal["submitSealLeaf"]> {
    return this.#seal.submitSealLeaf(...args);
  }

  sealReadiness(
    ...args: Parameters<SessionSeal["sealReadiness"]>
  ): ReturnType<SessionSeal["sealReadiness"]> {
    return this.#seal.sealReadiness(...args);
  }

  sealReadinessView(
    ...args: Parameters<SessionSeal["sealReadinessView"]>
  ): ReturnType<SessionSeal["sealReadinessView"]> {
    return this.#seal.sealReadinessView(...args);
  }

  verifyCertifiedRoot(
    ...args: Parameters<SessionSeal["verifyCertifiedRoot"]>
  ): ReturnType<SessionSeal["verifyCertifiedRoot"]> {
    return this.#seal.verifyCertifiedRoot(...args);
  }

  getSealCarry(
    ...args: Parameters<SessionSeal["getSealCarry"]>
  ): ReturnType<SessionSeal["getSealCarry"]> {
    return this.#seal.getSealCarry(...args);
  }

  markSealed(
    ...args: Parameters<SessionSeal["markSealed"]>
  ): ReturnType<SessionSeal["markSealed"]> {
    return this.#seal.markSealed(...args);
  }

  recordSealCertificateEnsuringRow(
    ...args: Parameters<SessionSeal["recordSealCertificateEnsuringRow"]>
  ): ReturnType<SessionSeal["recordSealCertificateEnsuringRow"]> {
    return this.#seal.recordSealCertificateEnsuringRow(...args);
  }

  persistSealInterruptedCommitment(
    ...args: Parameters<SessionSeal["persistSealInterruptedCommitment"]>
  ): ReturnType<SessionSeal["persistSealInterruptedCommitment"]> {
    return this.#seal.persistSealInterruptedCommitment(...args);
  }

  getSealUpgradeReadiness(
    ...args: Parameters<SessionSeal["getSealUpgradeReadiness"]>
  ): ReturnType<SessionSeal["getSealUpgradeReadiness"]> {
    return this.#seal.getSealUpgradeReadiness(...args);
  }

  countersignedThroughSeqFromCarry(
    ...args: Parameters<SessionSeal["countersignedThroughSeqFromCarry"]>
  ): ReturnType<SessionSeal["countersignedThroughSeqFromCarry"]> {
    return this.#seal.countersignedThroughSeqFromCarry(...args);
  }

  setEnsureSealBroker(
    ...args: Parameters<SessionSeal["setEnsureSealBroker"]>
  ): ReturnType<SessionSeal["setEnsureSealBroker"]> {
    return this.#seal.setEnsureSealBroker(...args);
  }

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

  // ─── DAEMON-004: daemon-owned Merkle tree ──────────────────────────────────
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
   *  reply. Returning the last entry (not the first) is intentional — the ingest file's
   *  appendVerifiedContent always
   *  pushes to the tail, so the tail is the message that just triggered onContentArrived. */
  peekLatestReceivedContentHex(agentName: string, sessionId: string): string | null {
    const buf = this.#receivedContent.get(this.#k(agentName, sessionId));
    if (!buf || buf.length === 0) return null;
    return buf[buf.length - 1]?.contentHex ?? null;
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
    const stopped = await this.#life.markInterruptedWithDetails(agentName, sessionId, 0, "key_refused");
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
   * It calls the REAL method (public on `SessionSeal` since the split, private before it) rather than reproducing its logic, so a test cannot pass
   * against a decision production does not make.
   */
  runAutoAcknowledgeGateForTest(agentName: string, sessionId: string, correlationId = "test"): void {
    this.#seal.maybeAutoAcknowledgeSeal(agentName, sessionId, correlationId);
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
    // write — the same leak, and the same fix, as `#sendDeliveryAck` in `session-content-ingest.ts`.
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
      await this.#life.destroySessionNode(agentName, sessionId, "error");
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
   * DOD-NAT-REACHABILITY-1: circuit-relay listen addresses for an agent's known
   * relays, so its standing receiver takes reservations and becomes dialable
   * behind NAT. Sources, merged and deduped by relay peer id: the directory's
   * auth-time relay pool (freshest — first), then the persisted relay endpoints
   * of past sessions (getAgentRelayEndpoints — covers a directory that predates
   * the auth_ok extension).
   */
  /**
   * DOD-M15-RELAYSLOTS-1: relays this agent should skip, and until when — see the failover note in
   * `reservationCircuitAddrs` (`session-relay.ts`). Keyed agent → relay peer id → expiry.
   *
   * Time-boxed rather than permanent because the fault is somebody else's to fix and we will not
   * hear when they have: an operator sets the missing directory key and restarts, and this agent
   * should find that relay again without needing its own restart.
   */
  readonly #relayQuarantine = new Map<string, Map<string, number>>();

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
    this.#relay.startReservationWatchdog();
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

}
