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
// `wireContentHash` is gone from this file on purpose: its ONE use was the receive-path cross-check,
// which now goes through `contentHashFor` so the comparison runs under the algorithm the sender
// named. A direct call here would be a hash computed without asking what the frame said (part B1).
import { contentHashFor, resolveContentHashAlg, CONTENT_HASH_ALGS, type ContentHashAlg } from "./wire-content-hash.js";
import { CAPACITY_REASONS, type CapacityReason } from "./refusal-reasons.js";
import {
  onPeerSaltFrame,
  ownSaltFrame,
  SALT_ADOPTION_LABEL_MAX,
  SALT_ADOPTION_LABELS,
  SALT_FREEZE_GUIDANCE,
  type SaltAgreementFrame,
} from "./session-salt-agreement.js";
import { CONTENT_ENCRYPTION_REASONS } from "./content-encryption-status.js";
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
import { publishableEndpoint, relayOnlyState } from "./relay-only.js";
import { randomUUID, createHash, randomBytes } from "node:crypto";
import * as lp from "it-length-prefixed";
import { decode } from "cbor-x";
import { encodeCbor } from "@cello-protocol/protocol-types";
import type { SessionAbandonedNotice } from "@cello-protocol/protocol-types";
import type { Stream } from "@libp2p/interface";
import type { Logger, SessionRecord, SealReadinessView } from "./types.js";
import { MAX_SESSION_NODES, STANDING_RECEIVER_AGENT_NAME } from "./types.js";
import { SessionConnectionGater } from "./session-connection-gater.js";
import { SessionTree, sessionTreeLeafKindFromDb, type WritableSessionTreeLeafKind } from "./session-tree.js";
import { CELLO_CONTENT_PROTOCOL_ID, NodeAutoNatService, type CelloNode, type IAutoNatService } from "@cello-protocol/transport";
import type { KeyProvider } from "@cello-protocol/crypto";
import {
  verify, buildMerkleTree, merkleRoot, generateSaltContribution, SESSION_SALT_BYTES,
  generateSessionEphemeral, destroySessionEphemeral, type SessionEphemeral,
} from "@cello-protocol/crypto";
import type { LeafInput } from "@cello-protocol/crypto";
import { encodeSealPayload, MONIKER_RE, validateMoniker } from "@cello-protocol/protocol-types";
// `PARK_ENVELOPE_REASONS` is deliberately NOT imported here. The reason codes are compared inside
// `park-envelope.ts` itself (`parkRefusalGuidance`) and asserted in its own test; this file only ever
// receives the already-classified `ParkAuthFailure`, so importing the code table here would invite a
// second, drifting copy of the classification logic.
import { decodeParkEnvelope, authenticateParkedEntry, pubkeyMatchesHex, ParkEnvelopeError, parkRefusalGuidance, type ParkEnvelope, type ParkAuthFailure } from "./park-envelope.js";
import { isValidMultiaddr } from "@cello-protocol/transport";
// `LEAF_KIND_MSG` is no longer imported here: `sendContent`'s `leafKind` stopped defaulting to it
// (B2b-1 review F4), so this file no longer names a default — every caller states its own kind.
import { AgentRelayClient, LEAF_KIND_CTRL, isTerminalRelayRefusal, extractErrorMessage, type RelayAssignmentCarry, type RelayAuthRefusal } from "./session-relay-client.js";
import { terminalRelayRefusal } from "./session-terminal-refusal.js";
import { RelayReceiptStore, type RelayReceipt } from "./relay-receipt-store.js";


import { SessionSealLeafStore, type SealCarryLeaf } from "./session-seal-leaf-store.js";
import type { SealUpgradeReadiness } from "./seal-upgrade.js";
import { addColumnIfMissing } from "./column-birth.js";
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
/**
 * Per-session cap on remembered unreadable-algorithm frames (`DOD-M15-SEALWIRE-1` part B1).
 *
 * Fed by a REMOTE party — a peer on a newer build refuses every frame it sends — so it needs a
 * bound for the same reason `MAX_REFUSED_PARKED_ENTRIES` does. Small on purpose: the entries exist
 * only to reconcile a refusal with its park-route redelivery, which happens within seconds, and
 * losing an old one costs a log line rather than correctness.
 */
const MAX_UNREADABLE_ALG_FRAMES = 64;

/**
 * How long the first send waits for an in-flight salt agreement before giving up on it —
 * `DOD-M15-SEALWIRE-1` B2b-2 constraint 2.
 *
 * The agreement is ONE round trip on a stream that is already open, so a healthy exchange finishes
 * in milliseconds; this bound is not sized for the normal case, it is sized for how long an operator
 * should wait before their message goes out unsalted instead of not going out.
 *
 * Five seconds because both errors cost real things. Too short and a merely slow counterparty makes
 * the session permanently unsalted for no reason — the decision is irreversible, so the bound should
 * be generous relative to the round trip. Too long and the first message of every conversation with
 * a peer on an older build visibly hangs, which is the failure a user actually notices and blames
 * the product for. This is only ever paid by a session that HAS an agreement outstanding: a
 * park-only session never starts one and never waits (constraint 5).
 */
const SALT_AGREEMENT_WAIT_MS = 5_000;

/**
 * WHY a session is hashing unsalted — review Finding 1, and this exists because one sentence was
 * carrying five different situations.
 *
 * `#saltForHashing` returns null for five distinct upstream conditions, and the single guidance
 * string asserted one of them: *"expected when your counterparty runs a build that predates the salt
 * agreement… start a new session once they upgrade."* An operator whose counterparty was merely
 * OFFLINE when they sent their first message — the most common case by far, since a parked first
 * message unsalts the session by design — read that and went and told a fully up-to-date
 * counterparty to upgrade.
 *
 * That is the `directory_unreachable` shape this project keeps re-learning: the message names the
 * exit point and points at the wrong machine. A closed set of reasons with its own guidance per
 * reason is the fix, and a closed set is what stops a sixth condition quietly inheriting a fifth's
 * explanation.
 */
const UNSALTED_REASONS = {
  /** No agreement was ever started — the counterparty has not connected. The park-only case. */
  NO_AGREEMENT_STARTED: "no_agreement_started",
  /** We announced and they did not answer inside the bound. */
  AGREEMENT_TIMED_OUT: "agreement_timed_out",
  /**
   * They answered, terminally: they have already hashed content and can never adopt.
   *
   * ⚠️ THIS IS ONE OF FOUR THINGS THE PEER CAN SAY, AND IT USED TO BE ALL OF THEM — 006-CRYPTO
   * finding 2. The wire frame carries WHICH reason, and `SaltAgreementFrame.adoptionClosed` is a
   * label rather than a boolean precisely so a caller cannot say `closed` without saying why. That
   * distinction reached the log and was then dropped one call before the operator, who was told
   * "they had already hashed messages" no matter which of the four it was.
   */
  PEER_CLOSED_ADOPTION: "peer_closed_adoption",
  /**
   * They answered terminally because their side could NOT READ its own frontier — local storage
   * trouble on their machine, not a conversation that started early.
   *
   * Kept apart from `PEER_CLOSED_ADOPTION` because the remedies are opposites: a new session fixes
   * the already-hashing case and does nothing at all for this one.
   */
  PEER_FRONTIER_UNREADABLE: "peer_frontier_unreadable",
  /** They answered terminally because the two sides could not converge — 006-CRYPTO finding 1. */
  PEER_EXCHANGE_STALLED: "peer_exchange_stalled",
  /**
   * They closed adoption naming a reason THIS build does not recognise.
   *
   * Deliberately non-asserting. The peer chooses this string, so the safe rendering states what we
   * know — they declined, and the label is in the log line above — and asserts nothing about why.
   * Guessing here is how an operator ends up asking a counterparty to change something that was
   * never the problem.
   */
  PEER_CLOSED_UNSPECIFIED: "peer_closed_unspecified",
  /** The session was torn down while the first send was still waiting. */
  SESSION_TORN_DOWN: "session_torn_down",
  /** This side already hashed, leafed, held or has in flight — adoption closed here. */
  ADOPTION_CLOSED_LOCALLY: "adoption_closed_locally",
  /** They answered in time and OUR OWN write failed. Nothing about their build is involved. */
  OUR_PERSIST_FAILED: "our_persist_failed",
  /**
   * OUR announce never left this machine — review pass 2, F2. Reusing `AGREEMENT_TIMED_OUT` here
   * told the operator *"your counterparty did not answer"* about a frame we never sent, which is the
   * exact substitution this closed set was created to end, re-entering through the settle site the
   * previous pass asked for.
   */
  ANNOUNCE_FAILED: "our_announce_failed",
  /**
   * They answered, we stored it, and reading it back FAILED — review pass 2, F4. Distinct from
   * `OUR_PERSIST_FAILED` because the two point at different log lines, and the guidance names one.
   */
  OUR_READ_FAILED: "our_read_failed",
} as const;

type UnsaltedReason = (typeof UNSALTED_REASONS)[keyof typeof UNSALTED_REASONS];

/**
 * What the operator should DO about each. TOTAL by construction — a `Record` over the union, so a
 * new reason cannot be added without something for the reader to act on. Same shape, and the same
 * reason, as `refusal-reasons.ts`: that file exists because a free-form `reason: string` let a new
 * code slip past every test in its own guard file.
 */
const UNSALTED_GUIDANCE: Record<UnsaltedReason, string> = {
  [UNSALTED_REASONS.NO_AGREEMENT_STARTED]:
    "Your counterparty was not connected when you sent this, so there was nobody to agree a salt with — most often they are simply offline and this message is going to their relay mailbox. Nothing is wrong with either build. The agreement only runs at session open, so this session stays unsalted even after they come online; a session started while you are both connected will be salted.",
  [UNSALTED_REASONS.AGREEMENT_TIMED_OUT]:
    "Your counterparty was connected but did not answer the salt agreement in time. Almost always they are on a build that predates it, in which case this is expected and permanent for this session — start a new session once they upgrade. If you know they are on the same version, look for session.salt.persist.failed on this side and session.salt.announce.failed on either.",
  [UNSALTED_REASONS.PEER_CLOSED_ADOPTION]:
    "Your counterparty declined the salt because their side of this session had already hashed messages — their conversation started before yours could agree one. Both builds are fine and both sides know. Start a new session if you want the protection.",
  [UNSALTED_REASONS.PEER_FRONTIER_UNREADABLE]:
    "Your counterparty declined the salt because their machine could not read its own record of this conversation — their local storage is not answering. Nothing is wrong with your machine or with either build, and they did not do anything wrong. STARTING A NEW SESSION WILL NOT HELP: the next one will decline the same way until their storage is working. Ask them, out of band, to look for session.salt.adoption.refused on their side; it names the read that failed.",
  [UNSALTED_REASONS.PEER_EXCHANGE_STALLED]:
    "Your counterparty holds a salt for this session and this side never managed to store one, so the two of you could not converge and both agreed to stop rather than trade messages about it forever. Nobody is at fault and no message was lost. Look for session.salt.persist.failed on this side — if it is there, a write to local storage failed and that is the whole cause. Start a new session; it will agree a salt normally.",
  [UNSALTED_REASONS.PEER_CLOSED_UNSPECIFIED]:
    "Your counterparty declined the salt for a reason this build does not recognise — most likely they are on a newer build that names a case this one predates. Both sides agree there is no salt, so nothing is broken and no message was lost. The exact reason they gave is in the session.salt.adoption.closed line just above. Start a new session once you both know why.",
  [UNSALTED_REASONS.SESSION_TORN_DOWN]:
    "This session was closed or reset while the message was still being prepared. This line is about the salt only; look for the close or freeze event just before it for what actually happened to the session.",
  [UNSALTED_REASONS.ADOPTION_CLOSED_LOCALLY]:
    "This session had already hashed or sent messages before a salt could be agreed, so adopting one now would leave half the conversation verifiable by one rule and half by another. That is permanent for this session and both builds are fine. Start a new session if you want the protection.",
  [UNSALTED_REASONS.OUR_PERSIST_FAILED]:
    "Your counterparty answered in time and THIS side failed to store the agreed salt — the fault is local, not theirs. Do not ask them to upgrade. Look for session.salt.persist.failed immediately above this line; it names the write that failed.",
  [UNSALTED_REASONS.ANNOUNCE_FAILED]:
    "THIS side could not send the salt agreement to your counterparty — the frame never left this machine, so they were never asked and their build is not involved. Do not ask them to upgrade. Look for session.salt.announce.failed immediately above this line for the connection error; most often the direct link to them dropped between connecting and sending.",
  [UNSALTED_REASONS.OUR_READ_FAILED]:
    "A salt was agreed for this session and THIS side could not read it back — the fault is local storage, not your counterparty. Do not ask them to upgrade. Look for session.salt.read.failed immediately above this line; a wrong-width or unreadable row is named there.",
};

/**
 * DOD-M12B-ACK-1 — inbound `/cello/content/1.0.0` streams allowed per connection.
 *
 * libp2p's registrar default is 32, and it enforces the cap AFTER protocol negotiation has already
 * answered, so exceeding it resets a stream the sender believes it just opened and the sender's
 * next write fails with a message that names nothing. Content delivery is bursty by design (a
 * document sweep opened 99 events in one second on a live daemon), and a slot stays occupied for
 * the whole of ingest — which awaits SQLCipher and the security gateway. 32 is simply too close to
 * normal traffic to be a safety limit.
 *
 * This is headroom, NOT the fix. The fix is that #handleContentStream now closes what it opens; a
 * raised cap without that would only move the cliff. Kept finite on purpose: an unbounded cap would
 * let a peer pin memory by opening streams it never uses, and the ceiling is what makes a future
 * leak of this shape show up as a bounded failure instead of a heap.
 */
const CONTENT_MAX_INBOUND_STREAMS = 512;

/**
 * DOD-M12B-ACK-1 — how long an inbound content stream may stay open after we have closed our end.
 *
 * Closing our write end retires the stream only once the PEER has closed its end too, so a peer
 * that opens streams and never closes them still fills our inbound slots — a guard that runs only
 * on the party it constrains is not a guard. After this window we reset it ourselves, which the
 * muxer honours unilaterally.
 *
 * It cannot be zero: an immediate reset would land while a well-behaved sender is still inside its
 * own `await stream.close()`, rejecting that close and turning every ordinary send into a park.
 * The frame is already ingested long before this fires, so nothing waits on it.
 */
const CONTENT_STREAM_LINGER_MS = 30_000;

/**
 * DOD-M12B-SHUTDOWN-1 — how long one teardown step may block the daemon's exit.
 *
 * Chosen against the surface that complains: `cello logout` gives up and reports the daemon still
 * running after 5 s, so a step that can burn longer than that guarantees the message the operator
 * saw. Two steps at 2 s each stay inside it.
 */
const SHUTDOWN_STEP_DEADLINE_MS = 2_000;

/**
 * DOD-M12B-REDIAL-1 — the shortest gap between two re-dials of one session.
 *
 * Long enough that a burst of sends against a peer that is genuinely gone costs one dial rather
 * than one per message; short enough that a peer coming back is picked up on the next thing the
 * operator says. It is cleared on a successful dial, so it never delays a live counterparty.
 */
const REDIAL_COOLDOWN_MS = 15_000;

/**
 * DOD-CAP-SELF-HEAL-1 — how long an interrupted session keeps consuming a cap slot.
 *
 * ATTRIBUTION ALONE DID NOT FIX THIS, and the reason is worth keeping. Recording who ended a
 * session only works for sessions ended after the recording started: every row written before the
 * column existed is unlabelled, and an unlabelled row counts. So the operator's actual backlog —
 * five finished conversations that were blocking two of their own agents — was untouched by it.
 * Attribution can never clear history, and history is what fills a cap.
 *
 * Age can. An interrupted session nobody has touched for hours is debris, not a live obligation,
 * and that is true whether our restart or their disconnect produced it.
 *
 * D18 SURVIVES BECAUSE THE ATTACK IS A RATE. The disconnect-evasion peer has to drop and reopen
 * faster than this window to gain anything, so everything it churns is recent and everything it
 * churns still counts. What ages out is the thing that was never an attack: a conversation that
 * finished. An attacker who waits out the window to gain one slot per window is not evading the
 * bound, they are obeying a slower one — and the global anti-swarm cap still applies on top.
 *
 * Two hours: comfortably longer than any churn worth attacking with, comfortably shorter than
 * "yesterday's conversation still blocks me".
 */
/**
 * DOD-M12B-RESERVATION-RETRY-1 — how many times to re-ask for a refused reservation before saying
 * the agent is undialable and stopping. Bounded because a reservation is scarce and a fleet that
 * retries forever is how a relay is exhausted. With the 5-minute base and doubling, five retries
 * span about 2.5 hours.
 */
export const SR_RESERVATION_MAX_RETRIES = 5;

/**
 * DOD-M15-RELAYSLOTS-1 — how long an agent skips a relay that refused it for a relay-side fault.
 *
 * Ten minutes: long enough that the agent is not re-asking a relay that cannot serve it every time
 * its receiver rebuilds, short enough that when someone fixes that relay the agent finds it again
 * without needing its own restart. The fault is on somebody else's machine and nobody tells us when
 * it is fixed, so this has to expire on its own.
 */
export const RELAY_QUARANTINE_MS = 10 * 60 * 1000;

export const CAP_INTERRUPTED_TTL_MS = Number(process.env["CELLO_CAP_INTERRUPTED_TTL_MS"]) || 2 * 60 * 60 * 1000;

/**
 * DOD-CAP-SELF-HEAL-1 — what counts against a per-sender acceptance bound.
 *
 * `active` always. `interrupted` ONLY when the counterparty caused it.
 *
 * D18 is why `interrupted` has to count at all: a peer can flip a session to `interrupted` for free
 * by dropping its stream, then open a fresh one, indefinitely. Those are theirs and still count.
 *
 * What broke was charging them for OURS. A daemon restart flips every live session to
 * `interrupted`, nothing resolves them, and the reaper correctly refuses to take any with received
 * content — so the bound became all-time instead of concurrent. Measured 2026-08-17: two of one
 * operator's own agents could not open a session, because one held five finished conversations with
 * the other against a stranger cap of three.
 *
 * NULL counts as the counterparty's. The column is new, so every pre-existing row is unlabelled,
 * and the safe default for an anti-abuse bound is to count rather than to excuse.
 */
const CAP_COUNTS = (alias = ""): string => {
  const p = alias ? `${alias}.` : "";
  return `(${p}status = 'active'
           OR (${p}status = 'interrupted'
               AND COALESCE(${p}interrupted_by, 'counterparty') != 'local'
               AND ${p}updated_at >= ?))`;
};
const CAP_COUNT_SQL = (where: string): string =>
  `SELECT COUNT(*) AS n FROM sessions WHERE ${where} AND ${CAP_COUNTS()}`;

/** The cutoff an interrupted session must be newer than to still count. */
const capStaleBefore = (): number => Date.now() - CAP_INTERRUPTED_TTL_MS;

/**
 * DOD-M12B-ABANDON-NOTIFY-1 — what happened when we tried to tell the counterparty we hung up.
 *
 * A REASON, not a boolean. The three causes are not interchangeable, and collapsing them made the
 * operator's guidance blame the network for a session this side had already torn down — which is
 * the most common case, since force-abandon is largely used on `interrupted` sessions and those
 * have no node left to send on.
 *
 * `told: true` means the bytes left this node. There is no acknowledgement, so it is not proof the
 * far side acted — a counterparty on an older client does not understand the frame and keeps
 * calling. The guidance says so rather than promising they will stop.
 */
export interface AbandonNoticeResult {
  told: boolean;
  reason: "sent" | "no_local_node" | "send_failed";
}

/**
 * DOD-M12B-ACK-1 — why a session is impaired, and what became of the content that revealed it.
 *
 * `cause` separates "your own message did not reach them" (`direct_send`) from "our acknowledgement
 * to them did not go out" (`delivery_ack`) — on the second the operator sent nothing at all, so a
 * surface that talks about their last send is describing a message they never wrote.
 *
 * `retained` is what makes it safe to advise. A parked or durably-queued message must NOT be
 * resent — a resend takes a second canonical position, which is this milestone's founding defect.
 * A LOST one must be, and `cello_send` has already said so. `unknown` means do not claim either.
 */
export interface SessionImpairment {
  cause: "direct_send" | "delivery_ack";
  retained: "parked" | "durable" | "lost" | "unknown";
}

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
export type ParkedDrainReason =
  | "standing_receiver_ready"
  | "periodic_backstop"
  /**
   * DOD-M12B-SESSION-SEED-1 (case B): a session that was interrupted has just been revived, so the
   * content the counterparty parked while we had no node can finally be fetched. Reviving the node
   * without draining leaves the operator looking at a healthy session with no new mail.
   */
  | "session_revived"
  /**
   * DOD-M12B-LEAF-TRIGGERS-FETCH-1: the relay told us a specific message exists — we hold its hash
   * and its canonical sequence — and its plaintext never arrived on the direct path. Measured live
   * 2026-08-18: the leaf landed in ONE second and the bytes took 102, because nothing connected the
   * two facts.
   */
  | "witnessed_leaf_unresolved";

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
   * DOD-M15-RELAYONLY-1: this agent has asked never to be directly reachable, so the factory must
   * omit dcutr from the node's service set.
   *
   * ⚠️ NOT a duplicate of filtering the published addresses. Those two things stop DIFFERENT
   * disclosures: the filter controls what the DIRECTORY is told, and dcutr talks to the peer
   * directly. Its whole job is to upgrade a relayed connection into a direct one, and the inbound
   * side starts the upgrade — which is exactly a standing receiver. Leaving it on means the agent
   * routes over the relay precisely as asked and then hole-punches to a direct connection anyway,
   * with every test still green because the leak happens inside libp2p after the assertions.
   */
  relayOnly?: boolean;
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
  /**
   * DOD-M12B-SESSION-SEED-1: the 32-byte Ed25519 seed this node's transport identity is derived
   * from, so a node that is torn down can be rebuilt at the SAME peer id.
   *
   * Without it libp2p generates the key internally and the id is unrecoverable — which is why a
   * laptop-close session cannot come back today: a rebuilt node could dial the counterparty, but
   * the counterparty holds an id that no longer exists.
   *
   * PER SESSION, NEVER PER AGENT. Each standing receiver mints its own; at handoff the seed becomes
   * that session's and the replacement receiver mints a fresh one. That preserves the recorded
   * 2026-04-11 rationale for ephemeral ids (a passive observer must not be able to correlate one
   * agent's sessions across days) while making the id stable WITHIN the one session an observer can
   * already correlate by watching the connection.
   */
  transportPrivateKey?: Uint8Array;
  /**
   * DOD-M12B-SESSION-SEED-1 (case B review HIGH-1): bind a ROUTABLE interface, not loopback.
   *
   * Ordinary session nodes dial OUT and need no inbound reachability, so the factory gives them
   * `127.0.0.1`. But a session node that reached its role by PROMOTION inherited the standing
   * receiver's `0.0.0.0` bind and its circuit-relay reservation — which is every session node in
   * production. A REBUILT one does not inherit anything, so without this it comes back on loopback
   * with no relay address: the peer id is preserved and the counterparty still cannot reach us,
   * which is precisely the half of the promise revival exists to keep. Preserving the id only
   * matters because the circuit address `/p2p/<relay>/p2p-circuit/p2p/<sessionPeerId>` embeds it —
   * and that is the address that was not being taken.
   */
  inboundReachable?: boolean;
}

/**
 * DOD-M12B-SESSION-SEED-1 — everything needed to bring one session back, and nothing else.
 *
 * Deliberately minimal: a revival re-establishes the SAME session with the SAME two parties, so it
 * needs our identity and theirs and no more. Anything else added here would be state that has to be
 * destroyed on the same edge, and each addition is another way to leave something open.
 */
interface SessionRevivalIdentity {
  /** The 32-byte Ed25519 seed our session node's peer id derives from. Zeroed on destruction. */
  seed: Uint8Array;
  /** The counterparty's SESSION-layer peer id — the gater's allowed peer, and our dial target. */
  counterpartyPeerId: string;
  /** Their agent pubkey, for the rebuilt content handler's authentication check. */
  counterpartyPubkey: string;
  /**
   * DOD-M12B-SESSION-SEED-1 — the counterparty's transport addresses, so a revived session can DIAL
   * them. Measured live 2026-08-18: without this the rebuild succeeded in 1ms and the very next send
   * failed and was LOST, because `#evictSessionCaches` clears `#counterpartyAddrs` on teardown and
   * the re-dial then has nothing to dial. A revived node with no way to reach the other side is a
   * session that is "active" and cannot speak.
   */
  counterpartyAddrs: string[];
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
  /**
   * DOD-M15-RELAYAUTH-1 review H1: the session's directory-signed assignment, held so the DIAL path
   * can present it to whichever relay is about to be asked to allow the dial. Without it here, the
   * dialer has no credential in hand at the moment it needs one and the gate refuses a legitimate
   * dial. Self-authenticating, so holding it grants nothing that forging it would not already require.
   */
  relayAssignment?: RelayAssignmentCarry;
  /**
   * DOD-M15-RELAYAUTH-1 review M4: `#relayClients` keys for the ADDITIONAL relay clients this
   * session opened beyond its witness relay — the relays that gate circuit dials. `relayClientKey`
   * only ever names the witness one, so without this list these clients and their `#sessions`
   * entries are never released and accumulate for the life of the daemon.
   */
  extraRelayClientKeys?: string[];
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
/**
 * ⚠️ `retryAfterMs` — `DOD-M15-RELAYABUSE-1` review MEDIUM-6. The guidance told operators the
 * throttle clears *"in about a minute"*, which is a hardcoded guess about the RELAY's configurable
 * window: a relay run at ten minutes makes that sentence a wrong promise. The real number was in
 * hand two frames away and died here, which is the value-with-no-reader defect one layer further
 * out from where it was just fixed twice.
 */
type ParkAttempt = { outcome: "parked" | "refused" | "unconfigured"; cause?: string; retryAfterMs?: number };

/**
 * DOD-M12B-REVIVAL-BOUND-1 — how long an interrupted session stays revivable before it is closed.
 *
 * 24 hours. The bound exists because of Andre's 2026-08-18 tenet — *"leave nothing open that is no
 * longer needed"* — and its value is set by the case it must not break: a laptop closed for the
 * night. A window shorter than a night's sleep would abandon exactly the sessions case A/B exist to
 * rescue, which is why this is not zero and not an hour.
 *
 * It is deliberately a plain constant and not a setting. A per-operator knob here is a knob that
 * turns the guarantee off, and the guarantee is the security property, not a preference.
 */
export const REVIVAL_WINDOW_MS = 24 * 60 * 60 * 1000;

/**
 * DOD-M12B-REVIVAL-BOUND-1 — how often the revival bound is applied.
 *
 * Hourly. The window is 24 hours, so the worst-case overshoot is ~4% of the bound, and the pass is
 * one DB walk with no network in it. Boot-only was the first build and it is not a bound at all: a
 * daemon left up for a week never applies it, and a long-lived daemon is the normal case.
 */
export const REVIVAL_BOUND_SWEEP_MS = 60 * 60 * 1000;

/** DOD-M12B-SESSION-SEED-1: per-relay deadline when a revived node asks for a circuit reservation.
 *  Three seconds — a relay that has a slot answers well inside it, and one that does not never
 *  answers at all (measured: 10,002ms and still waiting). */
export const REVIVE_RESERVATION_TIMEOUT_MS = 3_000;

/** How many relays a revival will ask before settling for a plain node. Two: the worst case is then
 *  ~6s to a usable session, against a measured "never" for the unbounded form. */
export const REVIVE_RESERVATION_CANDIDATES = 2;

/**
 * DOD-M12B-LEAF-TRIGGERS-FETCH-1 — how long the DIRECT path gets before we go and fetch content the
 * relay has already told us about.
 *
 * Two seconds. The witness leaf and the plaintext are separate deliveries, and on a healthy session
 * the direct content normally lands within milliseconds of the leaf — so fetching the instant a leaf
 * arrives would put a relay round trip on the hot path of every message in every session, which is a
 * self-inflicted load problem. Waiting forever is what cost 102 seconds. Two seconds is far above
 * the healthy direct latency and far below anything a person would notice.
 */
export const LEAF_FETCH_GRACE_MS = 2_000;

/**
 * DOD-M15-SEALWIRE-1 bullet 5, SENT half — our own authorship proof for a message we sent.
 *
 * Deliberately the SAME shape as the received half's `verifiedAuthorship`, because the transcript
 * column pair is the same and a second shape would invite a second meaning. What differs is the
 * ATTRIBUTION the row records: a sent row is `self_authored` (we PRODUCED this signature), never
 * `verified_signature` (we CHECKED someone else's). Same bytes, different claim.
 */
export interface SentAuthorship {
  senderPubkey: Uint8Array;
  senderSig: Uint8Array;
}

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
  /**
   * DOD-M15-RELAYSLOTS-1: `onlineToken` is REQUIRED on the dependency bag, not optional. Every
   * relay client needs the directory's token or the relay refuses it a reservation slot, and the
   * failure is invisible from the client side — the agent comes up, reports itself online, and is
   * reachable by nobody. Making it required means a call site that forgets to pass it is a type
   * error rather than an agent that quietly stops being dialable.
   */
  #detachedRelayClientBuilder: ((agentName: string, relayPeerId: string, relayAddrs: string[], stores: { receiptStore?: RelayReceiptStore; sealLeafStore?: SessionSealLeafStore; onlineToken: () => Uint8Array | undefined }) => AgentRelayClient | undefined) | null = null;
  setDetachedRelayClientBuilder(fn: (agentName: string, relayPeerId: string, relayAddrs: string[], stores: { receiptStore?: RelayReceiptStore; sealLeafStore?: SessionSealLeafStore; onlineToken: () => Uint8Array | undefined }) => AgentRelayClient | undefined): void {
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
      client.registerSession(sessionId, node);
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
        void this.#rebuildStandingReceiver(agentName);
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
  // `hasReservation`: this receiver came up holding a /p2p-circuit address. The
  // watchdog uses it to tell "lost its reservation" (must recover) apart from
  // "never had one" (already degraded, and already loud) — see #reservationWatchdogTick.
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

  /** DOD-M12B-LEAF-TRIGGERS-FETCH-1: content hashes this session has actually resolved — ingested,
   *  held, or authored by us. A witnessed leaf whose hash is in here needs no fetch. */
  #resolvedContent = new Map<string, Set<string>>();

  /** In-flight grace timers, keyed session+hash, so a redelivered leaf does not schedule a second
   *  fetch for the same content — a slow relay must not be turned into a storm against itself. */
  #leafFetchTimers = new Map<string, ReturnType<typeof setTimeout>>();

  /** Test seam: collapse the grace window so a test does not have to wait two real seconds. The
   *  window itself is covered by its own case. */
  #leafFetchGraceMs = LEAF_FETCH_GRACE_MS;

  #standingReceivers = new Map<string, { node: CelloNode; gater: SessionConnectionGater; autoNat: NodeAutoNatService; hasReservation: boolean; /** DOD-M12B-SESSION-SEED-1: this receiver's transport seed; follows the node into the session at handoff. */ seed: Uint8Array; relayPeerId?: string }>();
  #standingReceiverCreating = new Set<string>();
  /**
   * (agentName, sessionId) → the peer id that session's `session_offer` named as the dialer.
   *
   * KEYED BY SESSION, not by agent (review F1). Keyed by agent alone, two overlapping inbound
   * sessions destroyed each other: offer P narrows to peer P, offer Q overwrites with peer Q, then
   * assignment P arrives and MISMATCHES — refusing a legitimate session while accusing the directory
   * of naming two dialers, which it had not. It then cleared Q's record too, so assignment Q passed
   * unchecked. An attacker could therefore disarm the check by provoking one mismatch.
   *
   * The gap between offer and assignment spans a cross-region threshold ceremony, so overlapping
   * sessions are ordinary, not exotic. `DOD-M15-OFFER-EXPIRY-1` already prescribed this fix shape —
   * "bind the narrowing to the session id it came from" — and the session id was in hand at both
   * ends the whole time.
   *
   * DOD-M15-OFFER-SIGNED-1: read back when the SIGNED assignment arrives, so an unsigned offer
   * cannot name a peer the signed document does not.
   */
  #offeredDialer = new Map<string, string>();
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
  readonly #srReservationRetry = new Map<string, { attempts: number; nextAt: number; correlationId: string; lastReason?: string }>();
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
  // the liveness authority for direct sessions (relay sessions query the relay
  // instead). NEVER the directory (SI-002). Read by exactly three consumers: the
  // half-open reaper, both status surfaces, and cello_receive. No seal path reads
  // it — the coupling to sealing runs through the receive guidance, which turns
  // 'gone' into "call cello_close_session".
  // DOD-M12B-ACK-1 adds 'impaired': connection up, our writes on it failing. It sits BELOW
  // 'alive' and never above 'gone' — see #markSessionImpaired.
  #sessionLiveness = new Map<string, "alive" | "impaired" | "gone">();
  // DOD-M12B-ACK-1: WHY a session is impaired and what became of the content. Separate from the
  // state above because the state is what surfaces print and this is what they must explain.
  #impairmentCause = new Map<string, SessionImpairment>();
  // DOD-M12B-STRAND-1: sessions whose durable holds have been read back. One read per session per
  // process; the Map is the working copy from then on.
  #heldRestored = new Set<string>();
  // DOD-M12B-SEAL-STUCK-1: sessions whose post-restore release has been attempted. Separate from
  // #heldRestored so a READ-ONLY probe can hydrate without performing (or consuming) the release.
  #heldReleased = new Set<string>();
  // DOD-M12B-SEAL-STUCK-1: sessions whose ordering state THIS PROCESS has observed — a relay
  // witness recorded for it. `#witnessedSeq` is memory-only, so for a session that predates this
  // daemon "no gap recorded" means "not recorded", not "no gap", and that difference decides
  // whether we may tell an operator the session is safe to close.
  #orderingObserved = new Set<string>();
  // DOD-M12B-INDEX-1: sessions whose tree and whose relay counter have provably parted. A diverged
  // session can never produce a root the counterparty agrees with, so it must never be reported as
  // safe to close — the close would be signed, refused as `leaf_count_mismatch`, and the receipt
  // lost for good.
  #diverged = new Set<string>();

  /**
   * Rehydrate `#diverged` from `sessions.diverged_at` — `DOD-M15-DIVERGE-DURABLE-1`.
   *
   * The Set stays as the hot read (the seal gate consults it per close), and the column is the
   * truth. Loaded once at boot rather than queried per read so the gate's cost does not change.
   */
  #loadDivergedFromDb(): void {
    if (!this.#db) return;
    const rows = this.#db
      .prepare(
        `SELECT s.session_id AS sid, a.agent_name AS agent
           FROM sessions s JOIN agents a ON a.agent_id = s.agent_id
          WHERE s.diverged_at IS NOT NULL`,
      )
      .all() as Array<{ sid: string; agent: string }>;
    for (const r of rows) this.#diverged.add(this.#k(r.agent, r.sid));
    if (rows.length > 0) {
      this.#logger.info("session.diverged.restored", {
        count: rows.length,
        impact:
          "these sessions provably cannot seal bilaterally and are refused at the seal gate — before " +
          "this was durable, a restart made them read as healthy",
      });
    }
  }

  /**
   * Record that this session's tree and the relay's counter have provably parted.
   *
   * Idempotent, and deliberately does NOT touch `updated_at`: that column drives the inbox's
   * last-spoke ordering, and divergence is not activity.
   */
  markSessionDiverged(agentName: string, sessionId: string): void {
    this.#diverged.add(this.#k(agentName, sessionId));
    if (!this.#db) return;
    /**
     * KEYED ON (agent_id, session_id) — review F3, and the loopback case makes it concrete.
     *
     * This was `WHERE session_id = ?` alone. The table's PK is composite for a documented reason
     * (`DOD-LOOP-1`, on the CREATE TABLE above): **two of one operator's agents can hold both ends
     * of the SAME session_id on ONE daemon**, so `sessions` holds two rows. Unkeyed, marking one
     * side diverged marked BOTH, and the clear below wiped BOTH — so side B sealing its half
     * erased side A's divergence, and after a restart A's seal gate read healthy and signed a close
     * that could only be refused. The line's own defect, produced by the line's own clear.
     *
     * Every other per-session UPDATE in this file keys on both columns; these two were the
     * exceptions.
     */
    this.#db
      .prepare("UPDATE sessions SET diverged_at = ? WHERE agent_id = ? AND session_id = ? AND diverged_at IS NULL")
      .run(Date.now(), this.#requireAgentId(agentName), sessionId);
  }

  /** Whether this session has provably parted from the relay's ordering. */
  isSessionDiverged(agentName: string, sessionId: string): boolean {
    return this.#diverged.has(this.#k(agentName, sessionId));
  }
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
   * DOD-M15-SEALWIRE-1 bullet 6 (part A) — the salt agreement's two pieces of per-session state.
   *
   * `#saltContributions` — OUR random half, MINTED ONCE PER SESSION. This being a map rather than a
   * fresh call at each send is the whole correctness of the exchange: we re-announce on every
   * counterparty connect, and a contribution regenerated per reconnect would have both sides
   * deriving against a moving value with the fingerprints never settling — a session that
   * reconnects and still disagrees, which reads as a network fault rather than a bug here.
   *
   * `#sessionSalts` — a CACHE over `sessions.content_salt`, which is the durable copy. Both are
   * cleared by `#evictSessionCaches`: the contribution is worthless once a salt exists, and the
   * salt is re-read from the row on revival, which is exactly what Decision #8 persists it for.
   */
  #saltContributions = new Map<string, Uint8Array>();
  #sessionSalts = new Map<string, Uint8Array>();
  /**
   * The peer half we last answered with a repair, hex — review F14, and it is what makes the repair
   * TERMINATE. Without it, two daemons that already hold the same salt trade contributions forever
   * once a reconnect leaves a stale copy queued on each side. See `onPeerSaltFrame`'s
   * `alreadyRepairedAgainstPeerHalf`.
   */
  #saltRepairedAgainst = new Map<string, string>();
  /**
   * THE MIRROR OF THE ABOVE — the peer FINGERPRINT we last answered with our half, hex.
   *
   * 006-CRYPTO finding 1. `#saltRepairedAgainst` terminates the salt-HOLDER's direction only. A side
   * holding no salt answered every fingerprint with its contribution, and a latched holder answers
   * every contribution with its fingerprint — so after one failed persist plus a reconnect, two
   * healthy daemons repair at each other for the life of the session, one new stream and one INFO
   * line each per round trip. Keyed on the peer's fingerprint BYTES for the same reason the other
   * map is keyed on its half: a genuinely NEW fingerprint is new information and must still be
   * answered; only an identical re-offer is the loop.
   */
  #saltRepairedAgainstFingerprint = new Map<string, string>();
  /**
   * THE LABEL THE PEER GAVE when it closed adoption — 006-CRYPTO finding 2.
   *
   * The wire carries WHY, `session-salt-agreement.ts` makes it a union so a caller cannot close
   * without saying why, and the agreement's `detail` puts it in the log. It was going no further:
   * `#settleSaltPending(..., "closed")` recorded only that it was closed, so every one of the four
   * reasons arrived at the operator as "they had already hashed messages".
   *
   * Stored raw and rendered through `#peerClosedReason`, which maps anything outside the known set
   * to a non-asserting reason — the peer chooses these bytes.
   */
  #saltPeerClosedLabel = new Map<string, string>();
  /**
   * THIS SESSION'S THROWAWAY KEYPAIR — `DOD-M15-KEYAGREE-1`, the lifecycle half (006-CRYPTO).
   *
   * **A `Map`, never a field on the session row, and that is the whole point.** The secret is held
   * in memory and nowhere else: not in SQLite, not in a backup, not in an export. Forward secrecy is
   * not a property of minting a fresh key — it is a property of the old one being GONE — so anything
   * that made this durable would void it permanently and silently.
   *
   * Minted ONCE per session, at the moment the session becomes active, and destroyed by
   * `#evictSessionCaches` when it tears down. A revived session therefore mints a FRESH one and
   * re-keys, which is Decisions Carried #5 and is correct: the old secret did not survive, so there
   * is nothing to be consistent with.
   *
   * ⚠️ NOTHING SENDS THE PUBLIC HALF YET. The exchange, the signature over it, and encrypting
   * content with the agreed secret are `007-CRYPTO`, and they are one wire format that ships
   * together. Until that lands, this keypair is minted, held and destroyed correctly and no message
   * is encrypted with it — which `#contentEncryptionStatus` states on the session itself rather than
   * leaving a reader to assume.
   */
  #sessionEphemerals = new Map<string, SessionEphemeral>();
  /**
   * ─── B2b-2 state: what the SEND path needs that the row cannot answer ─────────────────────────
   *
   * `#saltPending` — an agreement that has actually gone out and not yet been answered. The first
   * send waits on it (constraint 2). Absent means *nothing is in flight*, which is not the same as
   * "no salt": a park-only session never starts one at all, and must not wait (constraint 5).
   *
   * `#hashedWithoutSalt` — this session has already computed an unsalted content hash. Decision #8
   * closes adoption at the moment content is HASHED, and for a session's first message that is a
   * full network round trip before any leaf, held row or in-flight entry exists. Without this flag
   * the frontier count reads empty for exactly the window in which adopting would split the
   * transcript.
   *
   * `#unsaltedAnnounced` — the fallback has been stated for this session. Decision #15 says once per
   * session; a per-message warning is a filter waiting to be written.
   *
   * All three are per-session and in-memory by design, and are dropped with the rest of a session's
   * caches on eviction — a revived session re-reads its salt from the row, re-derives its frontier
   * from durable state, and starts a fresh agreement if it reconnects.
   */
  #saltPending = new Map<string, {
    settled: Promise<"agreed" | "timeout" | "closed" | "persist_failed" | "announce_failed">;
    resolve: (v: "agreed" | "timeout" | "closed" | "persist_failed" | "announce_failed") => void;
    timer: ReturnType<typeof setTimeout>;
    boundMs: number;
  }>();
  /**
   * HOW THE LAST AGREEMENT ENDED, kept after `#saltPending` is cleared.
   *
   * ⚠️ FOUND BY FALSIFYING MY OWN FIX. `#settleSaltPending` deletes the pending entry, so a send that
   * arrives AFTER an agreement has already failed finds nothing pending and is told
   * `no_agreement_started` — *"your counterparty was not connected"* — when in fact they were
   * connected and our own dial to them failed. The outcome was observable only to a send that
   * happened to already be waiting, which is the minority case.
   *
   * So the verdict outlives the wait. An ABSENT entry still means what it always meant — no
   * agreement was ever started, the park-only case — and that distinction is the whole reason this
   * is a separate map rather than a default.
   */
  #saltLastOutcome = new Map<string, "timeout" | "closed" | "persist_failed" | "announce_failed">();
  #hashedWithoutSalt = new Map<string, number>();

  /**
   * `#hashedWithSalt` — how many content hashes this session has computed UNDER its salt and not yet
   * landed anywhere a count can see (`DOD-M15-SALTSPLIT-1`, review HIGH-2).
   *
   * The mirror of `#hashedWithoutSalt`, and it exists for the same window: a hash is computed, then a
   * relay round trip happens, and only afterwards does the message appear as a leaf, a hold or an
   * awaiting-ack entry. In between, every count reads zero.
   *
   * It is read by `#discardUnspentSalt` alone. "Unspent" must mean *nothing has been hashed under
   * it*, and without this the answer is *nothing has FINISHED being hashed under it* — which is the
   * question nobody asked, answered destructively.
   *
   * Never decremented on success: a salted hash that reaches the wire is spent forever, and unlike
   * the unsalted counter there is no `abandonUnsaltedHash` equivalent to undo. It is cleared only
   * with the rest of the session's caches. **For a discard decision, erring toward "spent" is the
   * safe direction** — a salt kept is recoverable, a salt erased is not.
   */
  #hashedWithSalt = new Map<string, number>();

  /**
   * `#saltSuspended` — the peer has told us it can never hold a salt, so ours must not be USED. The
   * bytes stay on disk (`DOD-M15-SALTSPLIT-1`, the other lane's authorization argument).
   *
   * ⚠️ THIS REPLACED AN IMMEDIATE, IRREVERSIBLE ERASE, AND THE REFRAMING IS THE WHOLE POINT.
   *
   * I defended the erase as a compatibility question — a legacy peer might send the misleading frame,
   * we are pre-launch, do not carry weight for a state nobody is in. All true, and it does not reach
   * the question. **It is an AUTHORIZATION question:** the receiver performed an irreversible
   * destruction of durable key material on a peer's bare assertion with nothing to check it against.
   * Re-derived against an empty database — *would I let one side erase the other's key material on an
   * unauthenticated claim carrying no evidence?* No. My own empty-database rule argued FOR a guard,
   * not against one.
   *
   * And my own trigger was the proof I walked past: `frontier_unreadable` is not a legacy peer, it is
   * a **healthy current peer having one bad second**. Fixing the producer made our side stop emitting
   * it wrongly and left the receiver built to obey it — *one side of that exchange correct by
   * construction, the other still correct by luck.*
   *
   * A salt that cannot be used is inert. The destruction is what turned a transient disagreement into
   * a permanent one, so **nothing irreversible hangs on the claim any more** and proving the claim
   * stops being load-bearing.
   *
   * ⚠️ IN MEMORY ON PURPOSE, AND THE ERASE IS DEFERRED RATHER THAN CANCELLED. A durable mark needs a
   * column, and this milestone has lost data twice in the rebuild DDL. In-memory alone would split
   * the transcript at the next restart — unsalted now, salted after a reboot — so the salt IS erased,
   * at the first unsalted hash, which is the moment erasing becomes both harmless (nothing was hashed
   * under it) and REQUIRED (keeping it would re-salt after a restart). Before that moment a corrected
   * announce carrying a matching fingerprint un-suspends and the session recovers fully salted, which
   * erasure makes impossible even in principle: the far side cannot re-derive without both halves.
   *
   * A restart before either outcome loses the mark, we are salted again, the peer refuses one message,
   * and the announce re-runs and re-suspends. **One refused message, then convergence** — against a
   * dead session.
   */
  #saltSuspended = new Set<string>();
  #unsaltedAnnounced = new Set<string>();
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
  /**
   * Frames refused because they named a content-hash algorithm this build cannot read, keyed by
   * session → the refused frame's content hash → the name it used. Review F2, corrected by F-D.
   *
   * ⚠️ KEYED BY THE FRAME, NOT THE SESSION, and the first version was keyed by the session. That
   * made it fire on the NORMAL case: after one junk-alg frame, every subsequent park recovery on
   * that session logged a WARN forever, for entirely unrelated messages — and the text asserted the
   * two events were "the same message arriving twice by different routes", which nothing had
   * established. A warning that fires on the benign steady state is not a signal.
   *
   * Hash-keyed, the claim becomes a fact and the event fires exactly once per affected message: the
   * entry is removed the moment it is reconciled.
   */
  #unreadableAlgSeen = new Map<string, Map<string, string>>();
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
  #heldContent = new Map<string, Map<number, { content: Uint8Array; originalContent?: Uint8Array; contentHashHex: string; correlationId?: string; screenedOut?: boolean; origin?: "sent"; kind?: WritableSessionTreeLeafKind; authorship?: SentAuthorship; restoredAcrossRestart?: boolean }>>();
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
  #awaitingAck = new Map<string, Map<string, { timer: ReturnType<typeof setTimeout>; content: Uint8Array; correlationId?: string; structure1Cbor?: Uint8Array; structure2Cbor?: Uint8Array; contentHashAlg?: string }>>();
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
  #onAwaitingTtf: ((agentName: string, sessionId: string, contentHashHex: string, content: Uint8Array, structure1Cbor?: Uint8Array, structure2Cbor?: Uint8Array, contentHashAlg?: string) => void) | null = null;
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
  #onParkFailed: ((agentName: string, sessionId: string, contentHashHex: string, content: Uint8Array, structure1Cbor?: Uint8Array, structure2Cbor?: Uint8Array, contentHashAlg?: string) => boolean) | null = null;
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
    | ((args: { agentName: string; sessionId: string; recipientPubkeyHex: string; relayPeerId: string; relayAddrs: readonly string[]; contentHashHex: string; content: Uint8Array; structure1Cbor?: Uint8Array; structure2Cbor?: Uint8Array; contentHashAlg: string | undefined }) => Promise<{ ok: true } | { ok: false; reason: string; cause?: string; retryAfterMs?: number }>)
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
    this.#dbPath = opts.dbPath;
    if (typeof opts.contentTtfMs === "number" && opts.contentTtfMs > 0) {
      this.#contentTtfMs = opts.contentTtfMs;
    }
    this.#autoNatProbers = opts.autoNatProbers ?? (() => []);
    this.#srRetryDelaysMs = opts.standingReceiverRetryDelaysMs ?? [1_000, 5_000, 15_000];
    this.#srReservationTimeoutMs = opts.standingReceiverReservationTimeoutMs ?? 15_000;
    this.#srWatchdogIntervalMs = opts.standingReceiverWatchdogIntervalMs ?? 30_000;
    this.#srReservationRetryMs = opts.standingReceiverReservationRetryMs ?? 5 * 60_000;
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
    onTtf?: (agentName: string, sessionId: string, contentHashHex: string, content: Uint8Array, structure1Cbor?: Uint8Array, structure2Cbor?: Uint8Array, contentHashAlg?: string) => void;
    onParkFailed?: (agentName: string, sessionId: string, contentHashHex: string, content: Uint8Array, structure1Cbor?: Uint8Array, structure2Cbor?: Uint8Array, contentHashAlg?: string) => boolean;
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
    fn: (args: { agentName: string; sessionId: string; recipientPubkeyHex: string; relayPeerId: string; relayAddrs: readonly string[]; contentHashHex: string; content: Uint8Array; structure1Cbor?: Uint8Array; structure2Cbor?: Uint8Array; contentHashAlg: string | undefined }) => Promise<{ ok: true } | { ok: false; reason: string; cause?: string; retryAfterMs?: number }>,
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
  /**
   * `contentHashAlg` is `string | undefined`, NOT optional — B2b-1 review F4's shape, applied to the
   * last place it was missing.
   *
   * Optional, dropping it at a call site was neither a typecheck error nor a test failure, because
   * absent silently means `sha256` and that is the only value in play today. Measured: the
   * direct-dial-fail route's mutant SURVIVED the whole daemon suite. Requiring the argument — even
   * when its value is `undefined` — forces each of the three callers to state what this message was
   * hashed under, so a new fourth caller cannot omit it by accident.
   */
  async #parkContent(agentName: string, sessionId: string, contentHashHex: string, content: Uint8Array, structure1Cbor: Uint8Array | undefined, structure2Cbor: Uint8Array | undefined, contentHashAlg: string | undefined): Promise<ParkAttempt> {
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
        // B2b: the park route must name the same algorithm the direct frame did, or the recipient
        // verifies the same message two different ways depending on which route it took.
        contentHashAlg,
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
        return {
          outcome: "refused",
          cause: result.cause ?? result.reason,
          ...(result.retryAfterMs !== undefined ? { retryAfterMs: result.retryAfterMs } : {}),
        };
      }
      return { outcome: "parked" };
    } catch (err: unknown) {
      /**
       * THE CODE GOES IN `cause`, THE PARAGRAPH GOES IN THE LOG — B2b-2 constraint 6.
       *
       * `cause` is documented as the machine-readable half and is handed to callers that branch on
       * it. Putting `err.message` there meant a producer-side refusal — this build cannot seal that
       * algorithm — was indistinguishable from a relay outage, so it inherited the relay's guidance:
       * *"queued, and will be re-sent when the relay link is back."* The relay was never asked, and
       * every re-park throws in the same place, so that sends the operator to the wrong subsystem
       * and then tells them to wait for a recovery that cannot happen.
       *
       * `instanceof`, not a string test: an untyped failure keeps the old behaviour exactly, so this
       * narrows what the caller can distinguish without changing anything it could not.
       */
      const coded = err instanceof ParkEnvelopeError ? err : null;
      this.#logger.warn("content.park.deposit.failed", {
        sessionId,
        contentHash: contentHashHex,
        ...(coded === null ? {} : { reason: coded.reason, detail: coded.detail }),
        error: err instanceof Error ? err.message : String(err),
      });
      return {
        outcome: "refused",
        cause: coded?.reason ?? (err instanceof Error ? err.message : String(err)),
      };
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
      /**
       * Decisions Carried #8 — THE SESSION SALT, persisted.
       *
       * Agreed once at session open from BOTH sides' random contributions, and unchanged for the
       * life of the session. It is NOT a key: it decrypts nothing, and it is what lets this
       * operator's own transcript stay verifiable — the content hash is recomputed from stored
       * plaintext on the receive path and again for any later check, and salted it is underivable
       * without this value.
       *
       * PERSISTED because the alternative is silent corruption. ⚠️ FUTURE TENSE, deliberately
       * (review F10): NOTHING WRITES OR READS THIS COLUMN YET. `DOD-M15-SEALWIRE-1` will add the
       * contribution exchange and the lookup — "does this session already have a salt? yes → use it,
       * no → agree one" — and without the column that lookup would fail after a restart, mint a
       * fresh salt, and split the transcript at the crash: every leaf before it unverifiable, with
       * nothing saying so. The column lands now because it must exist before the code that needs it.
       *
       * NULL for every session opened before this column existed; those keep the unsalted hash.
       */
      "ALTER TABLE sessions ADD COLUMN content_salt BLOB",
      /**
       * DOD-M15-FREEZE-STATUS-1 — carried here for the OTHER LANE (`CELLO_Support`), agreed in
       * session `e3adcaa7…`. Two lanes must not both edit this file (§2e, one file two branches), so
       * the columns land in one migration and every line of behaviour stays on their side. Nothing
       * in this lane reads or writes them.
       *
       *   `frozen_at`     epoch-ms when `#freezeOnIdentityFailure` fired. NULL = never frozen.
       *   `frozen_reason` the `reason` already passed to that method. NULL iff `frozen_at` is NULL.
       *
       * ⚠️ THE WRITE MUST LAND BEFORE `destroySessionNode`, NOT AFTER — FRAME-1 review F1's
       * ordering, and the reason the in-memory `#frozenSessions.add` already sits before the
       * teardown. `destroySessionNode` writes `interrupted`, which is the REVIVABLE status, so a
       * durable mark landing after it lets a read race the teardown and revive the session out from
       * under the freeze — the disk reproducing the bug the memory mark was moved early to fix.
       *
       * Why it earns a slot rather than waiting: `#frozenSessions` is memory-only today, so a
       * restart UN-FREEZES a session that was frozen because a party signed with a key that was not
       * the counterparty's. The next read revives it and re-admits that peer, while the log still
       * says the session will not be revived.
       */
      "ALTER TABLE sessions ADD COLUMN frozen_at INTEGER",
      "ALTER TABLE sessions ADD COLUMN frozen_reason TEXT",
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
      // DOD-M12B-ABANDON-NOTIFY-1: epoch-ms when the counterparty told us they force-abandoned.
      // Deliberately NOT a status — the session stays sealable, so the operator can still take a
      // unilateral receipt. It stops this side calling them, nothing more.
      "ALTER TABLE sessions ADD COLUMN counterparty_abandoned_at INTEGER",
      // DOD-CAP-SELF-HEAL-1: WHO caused this session to be interrupted — 'counterparty' when their
      // stream dropped, 'local' when OUR daemon stopped or started. Only theirs counts against the
      // acceptance bound. Without this the bound is all-time rather than concurrent: every restart
      // flips every live session to `interrupted`, nothing ever resolves them, and a pair of agents
      // that has talked three times can never talk again. NULL means "not recorded" and is treated
      // as the counterparty's, because the safe default for an anti-abuse bound is to count it.
      "ALTER TABLE sessions ADD COLUMN interrupted_by TEXT",
      // DOD-M12B-RESTART-SEAL-1: when automatic sealing exhausted this session, and why. Durable
      // because the resolver's attempt budget is in memory — without it a machine that restarts
      // several times a day re-runs the whole budget against a hopeless session on every boot.
      "ALTER TABLE sessions ADD COLUMN restart_seal_gave_up_at INTEGER",
      "ALTER TABLE sessions ADD COLUMN restart_seal_gave_up_reason TEXT",
      // DOD-M15-DIVERGE-DURABLE-1: epoch-ms when this session's tree and the relay's counter
      // provably parted, so it can never seal bilaterally. NULL = not diverged.
      //
      // DURABLE, and the reason is that the read site cannot tell "not diverged" from "forgotten":
      // both are false and both read READY. `#diverged` was in memory, so a restart turned a
      // session that provably cannot seal into one the gate was happy to close.
      //
      // NOT the trade `frontier-mismatch.ts` makes on purpose. A frontier mismatch is re-detected
      // by the very next close, so losing it costs a recomputation. Divergence is re-detected only
      // by the next send that gets an ack behind the frontier — which on a finished conversation
      // never comes. Losing it costs a WRONG ANSWER.
      "ALTER TABLE sessions ADD COLUMN diverged_at INTEGER",
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

    // DOD-M12B-STRAND-1 — content we RECEIVED and VERIFIED but cannot append yet.
    //
    // Held content used to live only in `#heldContent`, a Map that died with the session node. The
    // teardown path said so itself: "the content is unrecoverable by the time we are here."
    // Measured on one daemon in one morning: 367 held, 8 released, **24 destroyed**. Each
    // destruction is permanent and one-sided — the sender was never acknowledged, so it believes
    // the message is merely pending, while the only copy the receiver will ever see is gone and
    // every later message in that session is stuck behind a gap nothing can fill.
    //
    // `canonical_seq` is the RELAY's position, not a local counter, and it is part of the key: that
    // is what lets a frame come back after a restart and land at its OWN index rather than the next
    // free slot. Appending it anywhere else would change the root the seal signs over.
    //
    // Keyed on agent_id, never agent_name — agent_name is a mutable display label (see the repo
    // guide). `content_blob` is the SCREENED copy that gets delivered; `original_blob` is the peer's
    // raw bytes, which the release path needs because classification reads byte 0 and the screened
    // copy is no longer a CBOR map header for a document frame.
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS held_content (
        agent_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        canonical_seq INTEGER NOT NULL,
        content_blob BLOB NOT NULL,
        original_blob BLOB,
        content_hash_hex TEXT NOT NULL,
        screened_out INTEGER NOT NULL DEFAULT 0,
        correlation_id TEXT,
        held_at INTEGER NOT NULL,
        -- DOD-M12B-INDEX-1: 'received' (default) or 'sent'. A held frame of OUR OWN must be
        -- released down the sent path — appended and transcribed as sent — never down the received
        -- path, which would put our words in the counterparty's mouth in the sealed record and hand
        -- them back to our own agent through cello_receive as though they had just arrived.
        origin TEXT NOT NULL DEFAULT 'received',
        -- DOD-M12B-INDEX-1: 'msg' or 'doc'. A held document leaf must come back as a document leaf.
        leaf_kind TEXT NOT NULL DEFAULT 'msg',
        PRIMARY KEY (agent_id, session_id, canonical_seq)
      )
    `);

    // DOD-M12B-INDEX-1: `CREATE TABLE IF NOT EXISTS` is a NO-OP against a table that already
    // exists, so a database created between DOD-M12B-STRAND-1 and this change has `held_content`
    // WITHOUT `origin`. On those every insert throws and every restore throws — holds go back to
    // memory-only, silently at the surface, and that now includes our own sent messages, which
    // nobody else holds a copy of. Loud in the log is not the same as visible.
    try {
      this.#db.exec("ALTER TABLE held_content ADD COLUMN origin TEXT NOT NULL DEFAULT 'received'");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (!/duplicate column name/i.test(msg)) throw err;
    }
    // DOD-M12B-INDEX-1: and the LEAF KIND. `#releaseHeld` used to append every held frame as "msg",
    // so a document leaf that had to wait for its position came back as a conversation message —
    // the distinction survived the immediate append and was destroyed by the hold, unrecoverably
    // after a restart.
    try {
      this.#db.exec("ALTER TABLE held_content ADD COLUMN leaf_kind TEXT NOT NULL DEFAULT 'msg'");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (!/duplicate column name/i.test(msg)) throw err;
    }

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
        -- ─── DOD-M15-SEALWIRE-1 bullet 5: the row proves AUTHORSHIP, or says it cannot ──────────
        --
        -- Before this, a row was (message, direction) and attribution came entirely from local
        -- session state: "this arrived on the socket I believed was Bob's". That is fine while the
        -- transcript is only ever read by its owner, and worthless the moment it is shown to anyone
        -- else — which is the whole point of a notarized record.
        --
        -- sender_sig holds one of TWO things, and which one is told by direction:
        --   RECEIVED row -> the Structure-2 signature, stored ONLY after the receiver verified it
        --                   against the pubkey inside the sender's own signed bytes
        --                   (#recordFrameOrdering). Verified, never claimed.
        --   SENT row     -> OUR OWN signature over the Structure-1 bytes we put on the wire, taken
        --                   from the submit result. Produced, not verified — there was no
        --                   counterparty in the act, so it must NEVER be labelled verified_signature.
        --
        -- ⚠️ self_authored COVERS TWO PROVENANCES, and sender_sig IS NOT NULL is the discriminator.
        -- Named here because it is the same shape this column exists to prevent, one level up: a
        -- provable sent row and an unprovable one share a label, so a reader keying on attribution
        -- alone cannot tell them apart. An unprovable sent row is legitimate — an UNWITNESSED send
        -- never put a Structure 1 on the wire, so there is nothing signed to store — but the reader
        -- has to be told where the distinction lives, or it will be rediscovered as a bug.
        --   self_authored + sender_sig NOT NULL -> we wrote it and can prove we did
        --   self_authored + sender_sig NULL     -> we wrote it; the relay never witnessed it
        --
        -- attribution is NOT NULL ON PURPOSE, and it is the load-bearing column. There is a soft
        -- path — session.content.ordering.decode_failed falls back to hash-dedup — that ingests a
        -- message with no verified signature, so rows legitimately without one WILL exist. A
        -- nullable signature column and nothing else would rebuild the defect this bullet exists to
        -- fix: a table that IMPLIES every row carries authorship proof, where some carry none and
        -- nothing distinguishes them. Forcing every writer to name which it is makes silent NULL
        -- impossible rather than merely discouraged.
        sender_pubkey TEXT,             -- from INSIDE the sender's signed bytes; NULL unless verified
        sender_sig BLOB,                -- the VERIFIED Structure-2 signature; NULL unless verified
        attribution TEXT NOT NULL DEFAULT 'local_session_state',  -- verified_signature | self_authored | local_session_state
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
    /**
     * DOD-M15-SEALWIRE-1 bullet 5: authorship columns on an EXISTING transcript.
     *
     * BEFORE `migrateSessionTablesToAgentId` — the rebuild copies the intersection of old and new
     * columns, so a column added after it would be dropped on the upgrade boot and re-added empty.
     * These have their second entry in that migration's pinned DDL; `DOD-M15-MIGRATION-GUARD-1`
     * fails the build if the two ever disagree.
     *
     * `addColumnIfMissing` rather than a bare try/catch: it swallows ONLY `duplicate column name`
     * and rethrows anything else, so broken DDL cannot be mistaken for "already applied".
     */
    // Written as three LITERAL statements rather than a loop over a column array. A loop needs its
    // own parser in the guard (as retry_queue does); literals are read by the guard's generic one,
    // so these are replayed automatically and cannot fall outside it.
    addColumnIfMissing(this.#db, this.#logger, {
      table: "transcript", column: "sender_pubkey",
      sql: "ALTER TABLE transcript ADD COLUMN sender_pubkey TEXT",
    });
    addColumnIfMissing(this.#db, this.#logger, {
      table: "transcript", column: "sender_sig",
      sql: "ALTER TABLE transcript ADD COLUMN sender_sig BLOB",
    });
    addColumnIfMissing(this.#db, this.#logger, {
      table: "transcript", column: "attribution",
      sql: "ALTER TABLE transcript ADD COLUMN attribution TEXT NOT NULL DEFAULT 'local_session_state'",
    });

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

    /**
     * DOD-M15-DIVERGE-DURABLE-1: rehydrate the divergence set from `sessions.diverged_at`.
     *
     * AFTER `migrateSessionTablesToAgentId`, not with the column migrations that create the field.
     * The query joins `sessions.agent_id` to `agents`, and on a database written before REMOVE-001
     * that column does not exist until this migration adds it — placing the load earlier failed
     * with `no such column: s.agent_id` on exactly those legacy databases, which are the ones a
     * restart matters most for.
     */
    this.#loadDivergedFromDb();

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
   * DOD-M15-RELAYONLY-1: is the settings store readable RIGHT NOW?
   *
   * ⚠️ Exists because `getSetting` cannot answer it. That method returns `null` for BOTH "the key is
   * unset" and "there is no database", and a security setting must tell those apart: unset-means-off
   * is correct, db-gone-means-off publishes the operator's real address during the shutdown window.
   * `getDb()` cannot stand in either — it THROWS when there is no database, which on a catch-less
   * ceremony path is worse than the wrong answer.
   */
  hasDatabase(): boolean {
    return this.#db !== null;
  }

  /**
   * DOD-M15-RELAYONLY-1: build a transport node for THIS AGENT, with its privacy posture applied.
   *
   * ⚠️ THE CHOKE POINT FOR NODE CREATION, and it exists for the same reason as the one around
   * `getStandingReceiverInfo`. Five call sites construct nodes; passing `relayOnly` at each would be
   * a hand-kept list, and the SIXTH — added next month by someone who has never read this line —
   * would build a node that hole-punches its way to a direct connection for an operator who asked
   * never to be directly reachable. Here, a new caller inherits the posture instead of being told.
   *
   * `unknown` counts as ON, matching the publish and dial halves: a node that declines to hole-punch
   * is reachable over the relay, while a disclosed address cannot be recalled.
   */
  // ⚠️ NOT `async`. This wrapper sits in the standing-receiver startup path, and making it async
  // added ONE extra microtask hop before the receiver was installed in `#standingReceivers` — which
  // was enough for `createSessionNode` to run first and answer `standing_receiver_unavailable`. Two
  // tests in `msg-021-session-seed` caught it. Returning the factory's promise directly keeps the
  // await count identical to the call it replaced. **This is a real fragility in the install path,
  // not a quirk of the tests:** anything that adds a tick here re-breaks it.
  #createAgentNode(agentName: string, config: SessionNodeConfig): Promise<CelloNode> {
    // ⚠️ THE POSTURE READ MUST NEVER COST US A NODE. This sits in the standing-receiver startup
    // path, whose caller treats a throw as "no receiver" and leaves the agent deaf to all inbound —
    // surfacing to the operator as `standing_receiver_unavailable`, which names the transport for a
    // fault in a settings lookup. `relayOnlyState` already absorbs a throwing GETTER; this absorbs
    // everything else, including a resolution failure for an agent row that is not there yet.
    //
    // The fallback is ON, not off: an agent whose posture we cannot read gets the private-but-
    // reachable node, because a node that declines to hole-punch still works over the relay while a
    // disclosed address cannot be recalled.
    let relayOnly = true;
    try {
      relayOnly = relayOnlyState((key) => this.getSetting(agentName, key), this.#db !== null) !== "off";
    } catch (err) {
      this.#logger.warn("settings.relay_only.unreadable", {
        agentName,
        reason: err instanceof Error ? err.message : String(err),
        impact: "could not read this agent's relay-only posture, so the node is built WITHOUT the hole-punch",
      });
    }
    return this.#factory.createNode({ ...config, relayOnly });
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
    const inputs: LeafInput[] = [];
    for (const leaf of carry) {
      let contentHash: unknown;
      try {
        // Canonical Structure 1 is [version, content_hash, sender_pubkey, session_id, last_seen_seq, timestamp].
        contentHash = (decode(leaf.structure1Cbor) as unknown[])[1];
      } catch {
        return { verdict: "cannot_judge", reason: "structure1_decode_failed" };
      }
      if (!(contentHash instanceof Uint8Array) || contentHash.length !== 32) {
        return { verdict: "cannot_judge", reason: "structure1_content_hash_missing" };
      }
      inputs.push({ kind: "hash", data: contentHash });
    }
    const ownRoot = merkleRoot(buildMerkleTree(inputs));
    const ownRootHex = Buffer.from(ownRoot).toString("hex");
    return Buffer.compare(Buffer.from(ownRoot), Buffer.from(certifiedRoot)) === 0
      ? { verdict: "match" }
      : { verdict: "mismatch", ownRootHex, detail: "root_disagrees: same leaf count, different leaves or different order" };
  }

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
    /**
     * DOD-M15-SEALWIRE-1 bullet 5: the VERIFIED authorship proof, when there is one.
     *
     * Optional because there legitimately is not always one — the ordering decode can fail SOFT and
     * the message is still ingested via hash-dedup. Optional is NOT the same as unremarked: absence
     * is written into the row as `attribution = 'local_session_state'`, so a reader can tell a row
     * whose author was proven from one whose author was assumed. That distinction is the bullet.
     */
    authorship?: { senderPubkey: Uint8Array; senderSig: Uint8Array },
  ): boolean {
    if (!this.#db) return false;
    try {
      const agentId = this.#requireAgentId(agentName);
      const blob = Buffer.from(plaintext);
      this.#db
        .prepare(
          `INSERT OR IGNORE INTO transcript
             (agent_id, session_id, sequence, direction, blob, created_at, sender_pubkey, sender_sig, attribution)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          agentId, sessionId, sequence, direction, blob, Date.now(),
          authorship ? Buffer.from(authorship.senderPubkey).toString("hex") : null,
          authorship ? Buffer.from(authorship.senderSig) : null,
          /**
           * THREE values, not two — caught by CELLO_Coder_1 reviewing the first version, and it was
           * the same defect this column exists to prevent, surviving one layer up in the enum.
           *
           * `local_session_state` covered two OPPOSITE rows: one this agent AUTHORED (provenance
           * fully known, merely not third-party-provable) and one RECEIVED on the soft fallback
           * (provenance unknown — something arrived on a socket and was trusted). A reader shown the
           * transcript later could not separate "he wrote this himself" from "nobody checked".
           * Structurally identical rows with different trustworthiness is exactly what I refused to
           * ship when I rejected a nullable signature column.
           *
           * No plumbing needed: `direction` already carries the answer at write time.
           */
          /**
           * DIRECTION FIRST — DOD-M15-SEALWIRE-1 bullet 5, sent half.
           *
           * This used to read `authorship ? "verified_signature" : …`, which was right while only
           * RECEIVED rows could carry a signature. Now a SENT row carries one too — our own, over
           * the Structure-1 bytes we put on the wire — and labelling that `verified_signature` would
           * be false in the way this column exists to prevent: **we did not verify it, we produced
           * it.** Nobody checked a counterparty's key; there was no counterparty in the act.
           *
           * So the three values keep meaning three different things:
           *   `self_authored`      — this agent wrote it. Now PROVABLE when a signature is stored.
           *   `verified_signature` — someone else wrote it and we checked their key against it.
           *   `local_session_state`— someone else wrote it and nobody checked anything.
           */
          direction === "sent" ? "self_authored" : authorship ? "verified_signature" : "local_session_state",
        );
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
    /**
     * OUTSIDE the `changes > 0` guard — review N2, and inside it the F2 fix did nothing for the
     * case that matters.
     *
     * The pin is written on every ACCEPTED INBOUND session. A contact row is written only on an
     * outbound initiate, an explicit add, a reply, or a trust-signal presentation — and an inbound
     * requester is deliberately NOT auto-added. So a counterparty you never replied to (away-mode
     * auto-ack is exactly this) has a pin and no contact row.
     *
     * Guarded, `cello_contact_remove` for them returned `{ ok: true, removed: false }`, cleared
     * nothing, and the identity refusal stayed permanent — the original lockout, now wearing an
     * `ok: true`, which is harder to notice than the original.
     */
    const pinsCleared = this.clearPinnedCounterpartyPrimary(agentName, pubkey);
    return res.changes > 0 || pinsCleared > 0;
  }

  /**
   * Forget the pinned threshold group key for a counterparty, so the next session re-pins.
   *
   * DOD-M15-OFFER-SIGNED-1 review F2 — WITHOUT THIS THE REFUSAL WAS PERMANENT. The identity-change
   * check refuses a counterparty whose group key differs from the one recorded in an earlier
   * session, and its guidance told the operator to confirm out of band and then remove the contact
   * so the new identity is pinned afresh. `removeContact` deleted a row in `contacts`; the pin lives
   * in `sessions.counterparty_primary_pubkey`, and nothing in the daemon ever cleared it.
   *
   * So an operator who did exactly as instructed — called their counterparty, confirmed the
   * re-registration was genuine, removed the contact, retried — got the identical refusal, with no
   * way out short of editing the database. A security control that cannot be reset by the person it
   * protects is a lockout, and the printed remedy made it worse by reading as though it worked.
   *
   * Nulls the column rather than deleting the session rows: those rows are the transcript record,
   * and a re-pin is not a reason to lose them.
   */
  clearPinnedCounterpartyPrimary(agentName: string, counterpartyPubkeyHex: string): number {
    if (!this.#db) return 0;
    const res = this.#db
      .prepare(
        // NO `updated_at` BUMP — review N6. `CAP_COUNTS` counts an interrupted session only while
        // `updated_at` is inside the staleness window, so touching it here reset the clock on every
        // stale session with that counterparty, re-inflating their per-sender cap — while removing
        // the contact simultaneously dropped them to UNKNOWN tier, which LOWERS it. The operator
        // follows the printed remedy and their counterparty's next session is refused for cap,
        // through a reason string deliberately identical to every other refusal. A second lockout
        // that says nothing. Nothing needs the timestamp: every candidate row ends up NULL.
        "UPDATE sessions SET counterparty_primary_pubkey = NULL WHERE agent_id = ? AND counterparty_pubkey = ?",
      )
      .run(this.#requireAgentId(agentName), counterpartyPubkeyHex);
    return Number(res.changes);
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
    // DOD-M12B-STRAND-1: hydrate first. Reading the Map before the durable holds are back
    // under-counts, and this gate exists to stop several held chunks each passing the size cap
    // individually while cumulatively exceeding it — an under-count is the bypass.
    this.#ensureHeldRestored(agentName, sessionId);
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
      .prepare(CAP_COUNT_SQL("agent_id = ? AND counterparty_pubkey = ?"))
      .get(this.#requireAgentId(agentName), counterpartyPubkey, capStaleBefore()) as { n: number };
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
         WHERE s.agent_id = ?
           AND ${CAP_COUNTS("s")}
           AND NOT EXISTS (
             SELECT 1 FROM contacts c
             WHERE c.agent_id = s.agent_id AND c.pubkey = s.counterparty_pubkey
               AND c.tier >= ${TIER.KNOWN} AND c.tier <= ${TIER.VIP}
           )`,
      )
      .get(this.#requireAgentId(agentName), capStaleBefore()) as { n: number };
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
  checkUnknownSenderAcceptanceBound(
    agentName: string,
    counterpartyPubkey: string,
  ): { ok: true } | { ok: false; reason: CapacityReason } {
    const tier = this.getTier(agentName, counterpartyPubkey);
    const perSenderCap = this.resolveTierBound(agentName, tier, "max_sessions");
    const perSender = this.countActiveSessionsForCounterparty(agentName, counterpartyPubkey);
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
      const globalUnknown = this.countActiveSessionsFromUnknownSenders(agentName);
      if (globalUnknown >= ABUSE_MAX_UNKNOWN_SESSIONS_GLOBAL) {
        return { ok: false, reason: CAPACITY_REASONS.ABUSE_BOUND_UNKNOWN_SESSIONS_GLOBAL };
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

  /**
   * DOD-M12B-RESERVATION-RETRY-1 — whether a NAT'd peer can actually DIAL this agent.
   *
   * `standing_receiver_ready` answers "is there a receiver?", which is true for a plain TCP node
   * that no relay would give a circuit reservation to. Behind NAT that node is reachable by nobody,
   * and the difference was visible only in the log — where it was visible 481 times and nobody
   * acted. `"retrying"` and `"unreachable"` are the states an operator can do something about.
   *
   *   reserved    — holds a circuit reservation; a NAT'd peer can dial it.
   *   retrying    — no reservation yet, still re-asking on a backoff.
   *   unreachable — no circuit reservation and the automatic re-attempts are spent, so only peers
   *                 that can connect DIRECTLY will get in. It is not permanent: a directory
   *                 reconnect carrying a DIFFERENT relay pool re-arms the budget, because a relay we
   *                 have never tried is new information.
   *   absent      — no receiver at all (the agent is not online).
   */
  getStandingReceiverReachability(agentName: string): "reserved" | "retrying" | "unreachable" | "absent" {
    const sr = this.#standingReceivers.get(agentName);
    if (!sr) return "absent";
    if (sr.hasReservation && sr.relayPeerId !== undefined) return "reserved";
    const retry = this.#srReservationRetry.get(agentName);
    return retry !== undefined && retry.attempts > SR_RESERVATION_MAX_RETRIES ? "unreachable" : "retrying";
  }

  /**
   * First ready standing receiver (any agent) — for agent-agnostic OUTBOUND use. Its gater admits
   * nobody INBOUND until a session names them (DOD-M15-ASSIGN-1); outbound stays open, which is the
   * property these callers depend on.
   */
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
    // DOD-M15-RELAYONLY-1: THE CHOKE POINT. Every path that publishes this agent's session
    // addresses draws from here — `initiator_session_addrs` on the way out, and
    // `counterparty_session_addrs` when answering an offer — and this method has no other kind of
    // consumer: its whole purpose is to be advertised, as the docstring above says.
    //
    // The suppression lives HERE rather than at those call sites deliberately. Call-site gating
    // would be a hand-kept list, and a fourth publish path added later would leak the operator's IP
    // while every test stayed green. At the choke point a new caller inherits the protection
    // instead of having to be told about it.
    const endpoint = { peerId: sr.node.getPeerId(), addrs: sr.node.listenAddresses() };
    // ⚠️ TRI-STATE, not a boolean, and the third state is the one that matters. `getSetting` answers
    // `null` both for "unset" and for "there is no database", and reading the second as OFF fails
    // TOWARD DISCLOSURE: the standing receiver outlives the DB during shutdown, so an offer arriving
    // in that window would publish the operator's real addresses with relay-only switched on.
    // `relayOnlyState` also absorbs a THROW — `#requireAgentId` throws for a retired agent, and this
    // method is called from the offer ceremony inside a floating async with no catch, where the
    // throw becomes an unhandled rejection and the offer vanishes with no local log.
    // ⚠️ `!== null`, NOT `!== undefined`. The field is declared `DaemonDatabase | null` and is only
    // ever assigned on open or set to `null` on close — **it is never `undefined` at any point in
    // its lifetime**, so the first version of this line was a compile-time-constant `true` that
    // TypeScript had no reason to complain about, and the whole `"unknown"` branch was unreachable
    // dead code. The fix for the disclosure window silently did nothing, which is worse than not
    // having written it: the DoD said the window was closed and it was wide open.
    const state = relayOnlyState((key) => this.getSetting(agentName, key), this.#db !== null);
    if (state === "unknown") {
      this.#logger.warn("settings.relay_only.unreadable", {
        agentName,
        impact:
          "cannot tell whether relay-only is on, so ONLY this agent's relay-circuit addresses are " +
          "published — never a direct one. Publishing a real address is irreversible and a narrowed " +
          "route is not, so this errs toward reachability loss rather than disclosure",
      });
    }
    // ONE filter, not two. The `unknown` branch used to build its own filtered object inline, which
    // put a second implementation inside the very method whose design rationale is that there is
    // exactly one — and the bypass guard could not see it.
    return publishableEndpoint(endpoint, state !== "off");
  }

  /**
   * DOD-M15-ASSIGN-1 — name the one peer allowed to dial this agent's standing receiver, at the
   * moment the directory's `session_offer` says who is coming.
   *
   * This is what makes the receiver's deny-by-default safe. The offer names
   * `initiator_session_peer_id`, and the responder answers it by advertising its OWN address in
   * `session_offer_accept`. Narrowing here — BEFORE that answer goes out — means the door opens to
   * exactly one peer at the same instant the address that reaches them is published, and never
   * before. The initiator cannot know where to dial until the accept it triggers has been sent.
   *
   * Returns WHICH failure it was, never a bare false (review F6). The caller reports a distinct
   * reason per cause: "no receiver" and "the directory named nobody" are different subsystems, and
   * collapsing them sent the operator to the directory for a local problem. This method never
   * widens the gate to compensate.
   *
   * Narrows INBOUND ONLY. The receiver is still the daemon's general-purpose dialer at this point
   * — no assignment exists yet — so revoking its outbound latitude here would break content
   * parking and restart-seal submission (review F2).
   */
  admitOfferedDialer(
    agentName: string,
    initiatorSessionPeerId: string,
    sessionIdHex: string,
  ): "narrowed" | "no_receiver" | "no_peer_named" {
    const sr = this.#standingReceivers.get(agentName);
    if (!sr) return "no_receiver";
    if (initiatorSessionPeerId === "") return "no_peer_named";
    sr.gater.admitInboundPeer(initiatorSessionPeerId);
    this.#offeredDialer.set(this.#k(agentName, sessionIdHex), initiatorSessionPeerId);
    return "narrowed";
  }

  /**
   * What the UNSIGNED offer claimed, so the SIGNED assignment can be checked against it.
   *
   * DOD-M15-OFFER-SIGNED-1. Decision 2 rules that the listening socket is "gated on the
   * assignment", and the gate is narrowed from `session_offer` — a frame carrying no signature —
   * because that is the only thing that arrives early enough. Timing forced the offer; it does not
   * excuse trusting it.
   *
   * Keeping what the offer said turns the two frames into a CHECK ON EACH OTHER. The assignment is
   * FROST-signed by the initiator's own threshold group, which no single directory can produce, and
   * it names the same peer id. A directory that says one peer in the offer and another in the
   * assignment is naming two different dialers for one session — which a truthful directory never
   * does, and which is exactly the move a compromised one would make to slip a peer past the gate
   * before the signed document arrives.
   */
  getOfferedDialer(agentName: string, sessionIdHex: string): string | null {
    return this.#offeredDialer.get(this.#k(agentName, sessionIdHex)) ?? null;
  }

  /**
   * Which peer this agent's standing receiver is currently admitting INBOUND — `null` for nobody.
   *
   * Read-only, and it answers a question the daemon otherwise cannot: *"whose dial would this
   * receiver accept right now?"* The gate is narrowed and re-closed from several paths (an offer
   * arrives, an assignment is refused, a session is promoted), and until now the only way to know
   * where it had ended up was to reproduce the sequence in your head.
   *
   * Added for `DOD-M15-RESPONDER-VERIFY-1`, where a refusal for one session was closing the gate a
   * DIFFERENT session had narrowed — a defect with no observable symptom short of the second
   * session's initiator being refused with "nothing invited it".
   */
  getStandingReceiverAllowedPeer(agentName: string): string | null {
    return this.#standingReceivers.get(agentName)?.gater.getAllowedPeerId() ?? null;
  }

  /** Forget the offered dialer for ONE session — called on BOTH the claim and the refusal paths. */
  clearOfferedDialer(agentName: string, sessionIdHex: string): void {
    this.#offeredDialer.delete(this.#k(agentName, sessionIdHex));
  }

  /**
   * RE-CLOSE the standing receiver — but ONLY if this session is still the one holding it.
   *
   * DOD-M15-OFFER-SIGNED-1 review F4, then N1. The first version closed the gate unconditionally,
   * and that was worse than the defect it fixed: an agent has ONE standing receiver with ONE allowed
   * peer, so a refusal for session P closed the gate that offer Q had narrowed. Q's initiator —
   * invited, legitimate — was then refused with *"nothing invited it"*, which this daemon had.
   *
   * That is the same cross-session interference F1 was written to remove, moved one method along,
   * and triggerable the same way: one bogus offer/assignment pair collapses a concurrent real
   * session.
   *
   * So the gate is closed only when it still names the peer THIS session opened it to. If a later
   * offer has already re-narrowed it, that offer owns the receiver and its narrowing stands.
   *
   * NO EVICTION SWEEP, deliberately (N4). The sweep evicts by "not the allowed peer", and
   * `getConnections()` returns OUTBOUND connections too — including the content-park and
   * restart-seal dials this node makes as the daemon's general-purpose dialer, whose targets are on
   * no allowlist by construction. Sweeping here hung those up, and the failure surfaced as
   * `relay_unavailable`: a transport label for a local decision, which is the exact substitution
   * that comment was written to prevent. The load-bearing control is `DOD-M15-FRAME-1`'s frame gate,
   * which refuses what an unauthorised peer sends; closing the door is enough here.
   */
  revokeOfferedDialer(agentName: string, sessionIdHex: string, offeredPeerId: string | null): void {
    this.clearOfferedDialer(agentName, sessionIdHex);
    const sr = this.#standingReceivers.get(agentName);
    if (!sr || offeredPeerId === null) return;
    if (sr.gater.getAllowedPeerId() !== offeredPeerId) {
      // A later offer already owns the receiver. Closing it would refuse THAT session's initiator.
      this.#logger.debug("session.gate.revoke.skipped", {
        agentName,
        sessionId: sessionIdHex,
        reason: "a later offer has re-narrowed this receiver; its narrowing stands",
      });
      return;
    }
    sr.gater.closeInbound();
  }

  /**
   * The standing receiver's libp2p node — a general-purpose node usable for OUTBOUND dials that
   * are not session-scoped (e.g. the content-park deposit/pull to the relay, MSG-001-3b). Its
   * gater admits nobody INBOUND until a session names them (DOD-M15-ASSIGN-1), but leaves these
   * outbound errands open. Returns null until the receiver is ready.
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
    // DOD-M12B-SESSION-SEED-1: whichever branch below runs, the session ends up owning a seed.
    // Promotion inherits the receiver's; a freshly-built node mints its own.
    let seed: Uint8Array;
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
        node = await this.#createAgentNode(agentName, { sessionId, connectionGater: gater, nodeType: "session", transportPrivateKey: seed });
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
    this.#mintSessionEphemeral(agentName, sessionId);
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
  /**
   * DOD-M12B-REVIVE-RELAY-1 — the relay witness leaf handler, shared by establishment and revival.
   *
   * Extracted because a REVIVED session must register the same handler. It was inline in
   * `#connectSessionRelay`, so revival — which never called that at all — had no live inbound path:
   * every message fell back to the five-minute mailbox poll, which is why a reconnected session took
   * three minutes to deliver what a fresh one delivers in seconds, and why doorbells stopped firing.
   *
   * A revived session that behaves differently from a fresh one is the defect. This is one of the
   * two halves of making them the same.
   */
  #relayLeafHandler(agentName: string, sessionId: string, correlationId: string) {
    return (frame: {
      sequence_number: number;
      leaf_kind: number;
      authored_by_us: boolean;
      structure1_cbor: Uint8Array;
    }): void => {
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
    };
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
        });
        this.#relayClients.set(clientKey, client);
      }
      const sessionIdHexForRelay = Buffer.from(relay.sessionIdBytes).toString("hex");
      client.registerSession(sessionIdHexForRelay, node, this.#relayLeafHandler(agentName, sessionId, correlationId), relay.assignment);

      const entry = this.#activeNodes.get(this.#k(agentName, sessionId));
      if (entry) {
        entry.relayClient = client;
        entry.relaySessionIdBytes = relay.sessionIdBytes;
        entry.relayClientKey = clientKey;
        // 2b: remember the relay endpoint so the content-park backstop deposits to the SAME relay.
        entry.relayPeerId = relay.relayPeerId;
        entry.relayAddrs = relay.relayAddrs;
        // Review H1: the dial path needs the credential in hand, not just the endpoint.
        entry.relayAssignment = relay.assignment;
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
    /**
     * Named rather than inline so the already-attached sweep below can invoke **this exact function**
     * instead of a second copy of it. A copy is what would drift: the two would have to be kept in
     * step by whoever edits either, and the failure would be silent.
     */
    const onCounterpartyAttached = (peerId: string): void => {
      /**
       * DOD-M12B-RESPONDER-ADDR-1 (review MEDIUM-4) — LEARN THE ADDRESS HERE, where it cannot race.
       *
       * The accept-time read was a race between two independent async chains: the responder accepts
       * off a signaling frame, while the initiator dials only after its own `createSessionNode`. If
       * accept looked before the dial landed it saw nothing, and the responder was back to holding
       * no address — the state that made every reply after an interruption park forever.
       *
       * This fires exactly when the counterparty connects: on both sides, on the first connection,
       * on every reconnect, and on a revived node too. It also REFRESHES, which the accept-time read
       * never did — a counterparty that rebuilds its receiver would otherwise leave us dialling a
       * dead address for the life of the session.
       */
      const observed = node
        .getConnections()
        .filter((c) => c.peerId === peerId && typeof c.remoteAddr === "string")
        .map((c) => c.remoteAddr as string);
      if (observed.length > 0) {
        this.#counterpartyAddrs.set(key, [...new Set(observed)]);
      }
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
      /**
       * DOD-M15-SEALWIRE-1 bullet 6 (part A) — ANNOUNCE OUR SALT STATE, here and nowhere else.
       *
       * This is the only hook that fires on BOTH sides for every way a session's direct path comes
       * up: the initiator's first dial, the responder's inbound connection, every reconnect, and a
       * revived node. `newStream` never dials — it only finds an already-open connection — so a
       * send placed at `createSessionNode` would be an announcement to a peer that is not attached
       * yet, and the responder's half has no dial of its own to hang one on at all.
       *
       * Fire-and-forget: a failed announcement must not turn a peer-connect handler into a rejected
       * promise, and there is nothing to await it. We re-announce on the next connect, and
       * `#handleSaltFrame` answers a peer contribution on a connection that is provably up — so a
       * single lost frame does not strand the agreement.
       */
      void this.#sendSaltFrame(agentName, sessionId, correlationId);
    };
    node.onPeerConnect(onCounterpartyAttached);

    /**
     * ⚠️ THE CONNECT THAT ALREADY HAPPENED — `DOD-M15-SALTANNOUNCE-LATE-1`.
     *
     * `onPeerConnect` above is `addEventListener("peer:connect", …)` (`core/transport/src/node.ts`),
     * and **an event listener cannot fire for a connection that predates it.** On the
     * `reuseStandingReceiver` path this session does not build a node — it TAKES the standing
     * receiver's, which has been listening all along. So the ordinary sequence is:
     *
     *   1. `#tryCreateStandingReceiver` starts the node listening. It never calls this method, so
     *      there is no handler yet.
     *   2. The counterparty connects. `peer:connect` fires into nothing.
     *   3. The session promotes that same node and registers the handler — one step too late.
     *
     * The handler then never runs, and everything hanging off it is silently skipped: **the salt is
     * never announced** (`no_agreement_started`, the sender salts, the receiver holds none, and every
     * message between them is refused) **and the counterparty's address is never learned or
     * refreshed.** Measured live: `j-documents` 7 of 12 red, every failure a document update that
     * never arrived, with no error shown to either operator.
     *
     * ⚠️ THE COMMENT ON THE HANDLER ABOVE NAMES THE OPPOSITE HAZARD, AND IT IS ALSO RIGHT: *"a send
     * placed at `createSessionNode` would be an announcement to a peer that is not attached yet."*
     * Both are real, which is why this is a SWEEP AFTER REGISTERING rather than a move. Too-early
     * stays impossible — the sweep runs at the same point the handler is armed — and too-late stops
     * being invisible, because an already-open connection is now looked at instead of waited for.
     *
     * Idempotent by construction: it invokes the SAME handler the event would have, so a peer that
     * connects normally is unaffected, and a peer seen twice re-announces — which the announce path
     * already tolerates (*"we re-announce on every reconnect"*).
     */
    try {
      // `getConnections()` returns CONNECTIONS, and one peer can hold several — dedupe, or a peer
      // with two open connections would run the attach path twice for no reason.
      const attachedPeers = new Set(node.getConnections().map((c) => c.peerId));
      for (const peerId of attachedPeers) {
        if (!isCounterparty(peerId)) continue;
        this.#logger.info("session.liveness.peer_already_attached", {
          agentName, sessionId, peerId, correlationId,
          impact: "this counterparty connected BEFORE the session's liveness handler was registered — on the standing-receiver promotion path that is the ordinary case, not a rare one. Running the attach path for it now: without this the salt is never announced (every message from the peer is then refused) and the counterparty's address is never learned.",
        });
        onCounterpartyAttached(peerId);
      }
    } catch (err: unknown) {
      // Never let the sweep cost the caller its session: the handler is already armed, so a failure
      // here degrades to exactly the behaviour that shipped before this fix.
      this.#logger.warn("session.liveness.attached_sweep.failed", {
        agentName, sessionId, correlationId, error: extractErrorMessage(err),
        impact: "could not check for an already-attached counterparty. If one is attached, this session may never announce its salt and will refuse that peer's messages — the pre-fix behaviour.",
      });
    }

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
   *
   * DOD-M12B-ACK-1: 'impaired' is DAEMON-LOCAL and deliberately not on the relay's
   * SessionLiveness wire type — the relay answers a different question (does it hold the
   * recipient's standing connection) and its three states are a deployed bilateral contract.
   */
  getSessionLiveness(agentName: string, sessionId: string): "alive" | "impaired" | "gone" | "unknown" {
    return this.#sessionLiveness.get(this.#k(agentName, sessionId)) ?? "unknown";
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
   * DOD-M12B-ACK-1 — the connection is up and delivery on it is not working.
   *
   * Liveness is otherwise driven ONLY by libp2p peer-connect/peer-disconnect, so it answers "is
   * there a connection object?" while every surface that prints it is read as "can I talk to them?".
   * Measured 2026-08-17: one session reported `alive` for 70 minutes after every write had started
   * failing, another never stopped.
   *
   * ONLY 'gone' is protected, and 'gone' is NOT protected because a seal gate reads it — nothing in
   * the code does. It is protected because the receive surface turns 'gone' into "call
   * cello_close_session", and a failed write must never be able to produce that instruction.
   *
   * 'unknown' is DOWNGRADED just like 'alive', which is not obvious and is the point. A session
   * whose recorded `counterpartySessionPeerId` has gone stale never sees a matching peer-connect,
   * so it sits at 'unknown' while every send fails forever — the exact case documented at
   * #wireSessionLiveness — and the receive surface renders 'unknown' as healthy-and-quiet, which is
   * the 70-minute lie relocated one lane over. 'unknown' claims nothing; the surface built on it does.
   */
  #markSessionImpaired(
    agentName: string,
    sessionId: string,
    opts: { cause: "direct_send" | "delivery_ack"; error: string; correlationId?: string },
  ): void {
    const key = this.#k(agentName, sessionId);
    const prior = this.#sessionLiveness.get(key);
    if (prior === "gone") {
      // Declining is a decision, so it is logged. A silent early return here is the shape that let
      // the original defect hide for a day: nothing recorded that writes were failing on a session
      // every surface was still calling healthy.
      this.#logger.debug("session.liveness.impairment.declined", {
        sessionId, liveness: prior, cause: opts.cause, error: opts.error, correlationId: opts.correlationId,
      });
      return;
    }
    // The CAUSE is refreshed even when the state does not move, because the receive surface builds
    // its guidance from it and a stale cause would describe the wrong failure.
    this.#impairmentCause.set(key, { cause: opts.cause, retained: "unknown" });
    if (prior === "impaired") return;
    this.#sessionLiveness.set(key, "impaired");
    this.#logger.warn("session.liveness.changed", {
      sessionId,
      counterpartyPubkey: this.getSessionRecord(agentName, sessionId)?.counterparty_pubkey,
      transportPath: "direct",
      liveness: "impaired",
      observedBy: opts.cause,
      priorLiveness: prior ?? "unknown",
      // `reason` is a contract string and `error` is the message — the convention every other
      // failure log in this file follows. Collapsing them makes grouping by `reason` useless.
      reason: "write_failed",
      error: opts.error,
      correlationId: opts.correlationId,
    });
  }

  /**
   * DOD-M12B-ACK-1 — what became of the content whose send caused the impairment.
   *
   * The receive surface has no memory of the last send, so without this it can only guess — and the
   * guess it would make ("it was parked, do not resend") is FALSE in the two cases that matter
   * most: a refused park whose durable enqueue was dropped, and one that threw. In both the message
   * is gone and `cello_send` has already told the caller to send it again, so a receive that says
   * "do not resend" contradicts it later, while the agent is sitting there waiting.
   */
  #noteImpairmentRetention(agentName: string, sessionId: string, retained: "parked" | "durable" | "lost"): void {
    const key = this.#k(agentName, sessionId);
    const current = this.#impairmentCause.get(key);
    if (!current) return;
    this.#impairmentCause.set(key, { cause: current.cause, retained });
  }

  /** DOD-M12B-ACK-1: why this session is impaired, for the surface that has to explain it. Null
   *  when it is not impaired — a caller must not narrate a failure that is not current. */
  getSessionImpairment(agentName: string, sessionId: string): SessionImpairment | null {
    const key = this.#k(agentName, sessionId);
    if (this.#sessionLiveness.get(key) !== "impaired") return null;
    return this.#impairmentCause.get(key) ?? null;
  }

  /**
   * DOD-M12B-ACK-1 — a delivery landed, so the impairment is over.
   *
   * Without this an `impaired` flag is a one-way door: one bad write would make a session report a
   * broken conversation for the rest of its life, which is the same class of lie in the other
   * direction. Called from BOTH send paths — an agent that mostly listens sends content rarely and
   * ACKs constantly, so clearing only on content would leave exactly those sessions impaired
   * forever. Only clears 'impaired': a successful write says nothing about a connection libp2p has
   * already declared 'gone'.
   */
  #clearSessionImpairment(agentName: string, sessionId: string, observedBy: "direct_send" | "delivery_ack", correlationId?: string): void {
    const key = this.#k(agentName, sessionId);
    if (this.#sessionLiveness.get(key) !== "impaired") return;
    this.#sessionLiveness.set(key, "alive");
    this.#impairmentCause.delete(key);
    this.#logger.info("session.liveness.changed", {
      sessionId,
      counterpartyPubkey: this.getSessionRecord(agentName, sessionId)?.counterparty_pubkey,
      transportPath: "direct",
      liveness: "alive",
      observedBy,
      reason: "write_succeeded",
      correlationId,
    });
  }

  /**
   * DOD-M12B-ABANDON-NOTIFY-1 — drive the REAL inbound content handler with one framed message and
   * a claimed peer identity.
   *
   * The handler is registered on a live libp2p node, so without this the only way to reach its
   * branches is a full two-node transport fixture — which is why the session-abandoned branch and
   * its peer pinning had no coverage at all. This feeds the same function the protocol handler
   * calls, including the authentication check, rather than a copy of its logic.
   */
  async handleContentFrameForTest(agentName: string, sessionId: string, framedBytes: Uint8Array, remotePeerId?: string): Promise<void> {
    const source = {
      async *[Symbol.asyncIterator]() { yield framedBytes; },
      close: async (): Promise<void> => {},
      abort: (): void => {},
      status: "closed",
    } as unknown as Stream;
    await this.#handleContentStream(agentName, sessionId, source, remotePeerId);
  }

  /** DOD-CAP-SELF-HEAL-1 test seam: the shutdown sweep's effect, without a shutdown. Mirrors the
   *  real UPDATE at gracefulShutdown so a test cannot pass against a label production never sets. */
  markSessionsInterruptedByLocalShutdownForTest(): void {
    // SCOPED TO UNLABELLED ROWS. Unscoped, this would relabel rows already marked
    // `counterparty` — one call excusing every interruption every attacker ever caused, on every
    // agent. Production never relabels; nor does this.
    this.#db?.prepare("UPDATE sessions SET interrupted_by = 'local' WHERE status = 'interrupted' AND interrupted_by IS NULL").run();
  }

  /** DOD-CAP-SELF-HEAL-1 test seam: the counterparty's stream closing, without a real peer. */
  markInterruptedByCounterpartyForTest(agentName: string, sessionId: string): void {
    this.#db?.prepare(
      "UPDATE sessions SET interrupted_by = 'counterparty' WHERE agent_id = ? AND session_id = ?",
    ).run(this.#requireAgentId(agentName), sessionId);
  }

  /** Test seam (same spirit as getDb()): seed per-session direct-path liveness, which is otherwise
   *  only set by the live node's onPeerConnect/onPeerDisconnect (#wireSessionLiveness). Lets a
   *  DB-seeded test exercise the CC-5 reaper's "alive counterparty must survive" gate without standing
   *  up a real libp2p peer connection. */
  markSessionLivenessForTest(agentName: string, sessionId: string, state: "alive" | "impaired" | "gone"): void {
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
    // DOD-M15-OFFER-SIGNED-1 review N5: the offer record has done its job the moment this session is
    // claimed. Keying it by session (the F1 fix) removed the accidental bound that agent-keying gave
    // it — each new offer used to overwrite the last — so without a clear on the SUCCESS path the
    // map gained one permanent entry per offer ever received, on directory-supplied keys. Cleared
    // here rather than only on refusal, which is what the doc comment always claimed.
    this.clearOfferedDialer(agentName, sessionId);
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
    this.#mintSessionEphemeral(agentName, sessionId);
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
    await this.#registerContentHandler(agentName, sessionId, node, counterpartyPubkey);
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
    // DOD-M15-REFUSED-INBOUND-SILENT-1: and the unshown refusals. Bounded (a fixed set of reasons
    // per session) so leaving them was a slow leak rather than a bug — but this list IS the
    // documented teardown set, and a map that is not in it drifts out of everyone's mental model.
    this.#contentRefusals.delete(key);
    this.#unreadableAlgSeen.delete(key);
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
    this.#saltContributions.delete(key);
    this.#sessionSalts.delete(key);
    this.#saltRepairedAgainst.delete(key);
    this.#saltRepairedAgainstFingerprint.delete(key);
    this.#saltPeerClosedLabel.delete(key);
    /**
     * DESTROY THE THROWAWAY SECRET — 006-CRYPTO, and this is what forward secrecy actually is.
     *
     * Zeroed, then dropped. Dropping the map entry alone would leave the bytes for the garbage
     * collector to move around at its leisure; `destroySessionEphemeral` overwrites the buffer we
     * hold, which is the one copy we control.
     *
     * ⚠️ THIS RUNS AFTER THE SEAL, and that is a property of WHERE it is called, not of this line.
     * Both teardown paths reach here at the end: the sealing path retires the node once the
     * ceremony is finished, and the destroy path is a session that is already over. Moving this
     * call earlier — into a close handler, or before the seal — would zero the key while the
     * ceremony still needs the session, so the ordering is load-bearing.
     */
    const ephemeral = this.#sessionEphemerals.get(key);
    if (ephemeral) {
      destroySessionEphemeral(ephemeral);
      this.#sessionEphemerals.delete(key);
      this.#logger.debug("session.ephemeral.destroyed", { agentName, sessionId });
    }
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
    this.#settleSaltPending(agentName, sessionId, "closed");
    this.#hashedWithoutSalt.delete(key);
    // DOD-M15-SALTSPLIT-1 HIGH-2: goes with its mirror. The session is being torn down, so there is
    // no discard decision left for it to protect.
    this.#hashedWithSalt.delete(key);
    this.#saltSuspended.delete(key);
    this.#unsaltedAnnounced.delete(key);
    this.#saltLastOutcome.delete(key);
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
    this.#heldRestored.delete(key);
    this.#heldReleased.delete(key);
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
   * DOD-M12B-RESTART-SEAL-1 / DOD-M12B-PENDING-RESOLVE-1 — sessions that need a receipt and have
   * nobody asking for one. TWO populations, one queue, each with its own safety argument.
   *
   * **(2) `seal_interrupted_pending` — a seal commitment nobody notarized.** Measured 2026-08-18 on
   * the live store: 28 sessions, aged 0.3 to 12.8 days, one of them 14 messages long, 26 holding
   * relay-witnessed seal leaves, and **not one with a sealed root**.
   *
   * **HALF OF THEM ARE NOT BILATERAL, and the first version of this comment claimed they were.**
   * Measured split: 14 initiator rows, each carrying the counterparty's signed leaf — and 14
   * responder rows with `counterparty_leaf = NULL`. A responder row is written by
   * `inbound-seal-request.ts` from an UNSIGNED `seal_interrupted_request` frame, before its ack is
   * even sent, so an ordinary send failure produces a one-sided pending row.
   *
   * So the licence is NOT "both parties signed". It is **somebody chose to end this**, on two
   * branches: an initiator row carries the counterparty's signature, and a responder row exists
   * because the counterparty sent a request to seal. And what makes the result VERIFIABLE is
   * neither — it is that the directory rebuilds the tree from relay-witnessed leaves and checks
   * their signatures, never consulting the commitment at all. The commitment is what makes it
   * legitimate to ASK. (`close-session-handler.ts` states this in full; the first draft of this
   * header contradicted it 200 lines away.) `PENDING-EXIT-1` built their exit and it works — but only when an operator runs
   * `cello_close_session` on that session by hand, having somehow deduced they should. Nothing
   * enumerated them, because both sweeps filtered `status = 'interrupted'`. An exit nobody is told
   * about is not an exit.
   *
   * `interrupted_by` is deliberately NOT consulted for that population. It answers "did WE cause
   * this, and may we therefore describe it" — and that is the wrong question once a seal was
   * requested or signed. **SI-001 is not weakened:** it forbids notarizing *"a conversation nobody
   * chose to end"*, and every row here was chosen to be ended by one side or the other. The only
   * thing missing is the request to notarize it.
   *
   * **(1) `interrupted` — sessions our own stop orphaned, and only those.** Here `interrupted_by` is
   * the whole safety argument. `'local'` means the boot sweep, the shutdown
   * sweep, or the operator's own kill switch ended this session — nobody else did, and it cannot be
   * resumed because the transport keypairs died with the process. Those are the ones the resolver
   * may seal on its own.
   *
   * Everything else is excluded and must stay excluded:
   *   'counterparty'        — they hung up. SI-001: the operator may still want to wait.
   *   'relay_stream_close'  — our relay witness link ended; the session itself may be fine.
   *   NULL                  — written before the column existed, so the cause is UNKNOWN. An
   *                           unknown cause is not a licence to notarize; it is the reason not to.
   *
   * Same INNER JOIN discipline as getSessionsByStatus: a retired agent's rows are kept for
   * accountability and are not resumable, so they are not offered for sealing either.
   */
  listRestartOrphanedSessions(): Array<{ agentName: string; sessionId: string; messageCount: number; status: "interrupted" | "seal_interrupted_pending" }> {
    if (!this.#db) return [];
    const rows = this.#db
      .prepare(
        // `message_count > 0` — a never-messaged interrupted session is a dead HANDSHAKE, which
        // `classifySession` deliberately hides in the "failed" bucket so it does not clutter
        // status. Sealing one spends a directory ceremony to obtain a receipt over nothing, and
        // then moves it into the operator's CLOSED list, making the clutter visible. The whole
        // justification for this work is "3,576 messages produced nothing" — zero messages is
        // nothing to produce.
        //
        // `restart_seal_gave_up_at IS NULL` — a session we have already exhausted. Without it a
        // machine restarting ~6 times a day re-runs five ceremonies against a hopeless session on
        // every boot, forever.
        `SELECT s.session_id AS session_id, s.message_count AS message_count, a.agent_name AS agent_name,
                s.status AS status
         FROM sessions s JOIN agents a ON a.agent_id = s.agent_id
         WHERE a.state != 'retired'
           AND (
                 -- (1) OURS, and we can say so. SI-001 holds: an interrupted session with an
                 -- unknown cause has no signatures behind it and must not be notarized.
                 (s.status = 'interrupted' AND s.interrupted_by = 'local')
                 -- (2) A seal commitment with nobody asking for it. review F5: the EXISTS is
                 -- STRUCTURAL, not decoration. The header's licence is "a commitment was made", and
                 -- a status check alone asserts that in prose while the query checks something
                 -- else. Today status implies an artifact row by construction, which is exactly the
                 -- kind of invariant that holds until someone adds a fourth writer.
                 OR (s.status = 'seal_interrupted_pending'
                     AND EXISTS (SELECT 1 FROM seal_interrupted_artifacts sa
                                 WHERE sa.agent_id = s.agent_id AND sa.session_id = s.session_id))
               )
           AND s.message_count > 0
           AND s.restart_seal_gave_up_at IS NULL
         ORDER BY s.updated_at ASC`,
      )
      .all() as unknown as Array<{ session_id: string; message_count: number; agent_name: string; status: string }>;
    return rows.map((r) => ({
      agentName: r.agent_name,
      sessionId: r.session_id,
      messageCount: r.message_count ?? 0,
      // Carried so a give-up can say something TRUE about this session: the two populations need
      // different words, and force-abandon is right for one and destructive for the other.
      status: r.status === "seal_interrupted_pending" ? "seal_interrupted_pending" as const : "interrupted" as const,
    }));
  }

  /**
   * DOD-M12B-REVIVAL-BOUND-1 — interrupted sessions that can no longer be revived, and must close.
   *
   * Andre, 2026-08-18: *"after that, those peer IDs and that peer connection needs to be shut down.
   * It is an open connection that a malicious agent can farm for."* The tenet is **leave nothing
   * open that is no longer needed**, and the threat model is a daemon that has been reprogrammed —
   * so the guarantee has to hold on the side that is not the attacker.
   *
   * WHAT IS OPEN. `ingestReceivedContent` refuses `sealed`, `seal_interrupted_pending` and
   * `abandoned`, but deliberately ACCEPTS `interrupted` — that acceptance is the only reason
   * recovery can work. Nothing else ever leaves `interrupted`, so it means accepts FOREVER.
   *
   * **THIS IS THE BACKSTOP, NOT THE COMPLEMENT.** The seal path gets first refusal on every
   * local-cause session, because a session whose ending we can describe truthfully earns a
   * notarized receipt. But "the seal path owns it" is not the same as "the seal path will finish
   * it", and two populations fall through the gap between those:
   *
   *   - **The resolver gave up.** `markRestartSealGaveUp` writes only `restart_seal_gave_up_at`;
   *     the status stays `interrupted`, and `listRestartOrphanedSessions` then excludes the row by
   *     `restart_seal_gave_up_at IS NULL` so it is never retried. `TERMINAL_SEAL_REFUSALS` has ten
   *     entries and the measured figure is that 59% of seals that start never finish, so this is
   *     the common case, not a corner.
   *   - **Zero-message local sessions.** The resolver requires `message_count > 0` — a dead
   *     handshake is not worth a ceremony. It is still an open write surface.
   *
   * Excluding those left them permanently interrupted and permanently writable, which is the exact
   * condition this line exists to end. And the population is about to become the majority: no row
   * has ever carried `interrupted_by = 'local'` yet, and from the next shutdown onward every
   * shutdown-orphaned session will. So the sweep takes a local-cause session once the seal path
   * has either declined it or exhausted it — never before.
   *
   * **THE CLOCK MUST BE ONE THE COUNTERPARTY CANNOT MOVE.** The obvious fallback for a row with no
   * `interrupted_at` is `updated_at` — and it is exactly wrong. `ingestReceivedContent` accepts
   * content into an `interrupted` session (that acceptance is this whole line's premise), and a
   * successful ingest runs `UPDATE sessions SET message_count = ?, updated_at = <now>`. So
   * `updated_at` is a clock the reprogrammed peer holds: one message every 24 hours and the session
   * never expires, forever. The fallback would have handed the attacker the off switch for the
   * control built to stop them.
   *
   * Instead the missing timestamps are STAMPED ONCE, by `#stampMissingInterruptedAt` immediately
   * before this query runs, and this query reads `interrupted_at` and nothing else. The stamp is
   * written under `WHERE interrupted_at IS NULL`, so it is monotone — set once, never moved, by us
   * and not by a peer. A legacy row therefore gets its full window starting from the first sweep
   * that sees it, which is later than the true interruption but is the only bound that is sound.
   *
   * Same retired-agent INNER JOIN as the sibling query: a retired agent's rows are kept for
   * accountability, are not resumable, and are not writable either.
   *
   * **THE TIME ARITHMETIC IS LOAD-BEARING, AND BOTH OBVIOUS FORMS OF IT ARE WRONG.** These two
   * columns do not hold the same kind of value:
   *
   *   `interrupted_at`  TEXT,    an ISO-8601 string — `new Date(now).toISOString()`.
   *   `updated_at`      INTEGER, epoch milliseconds.
   *
   * There are FOUR writers of `status = 'interrupted'`, not three. The fourth is
   * `destroySessionNode` → `#updateSessionStatus(…, "interrupted", "local")`, which historically
   * wrote `interrupted_by` and **no timestamp at all** — and it is the path that produced the two
   * rows in Entry 41. It now stamps `interrupted_at` like the others, so NULL is a legacy state
   * rather than one production keeps creating.
   *
   * So a bare `interrupted_at <= ?` against a numeric bound is **always false** — the column has
   * TEXT affinity and the bound parameter has none, so SQLite applies TEXT affinity to the
   * parameter and compares them as STRINGS (`'2026-08-18T05:32:04.183Z' <= 1755000000000` → 0).
   * The query silently returns nothing forever and reads as "nothing has expired yet". And
   * `CAST(interrupted_at AS
   * INTEGER)` is worse than useless: SQLite casts by taking the leading digits, so
   * `'2026-08-18T05:32:04Z'` becomes **2026**, which is older than any epoch bound. That form
   * abandons every interrupted session on the next boot, immediately, whatever its age. It was
   * written, and `session-001`/`cello-list-sessions` failed on it in the gate.
   *
   * `strftime('%s', …) * 1000` parses the ISO string properly and returns NULL for anything it
   * cannot parse — so a malformed or differently-formatted value falls through the COALESCE to
   * `updated_at` rather than being read as the year 2026.
   */
  listExpiredUnrevivableSessions(
    nowMs: number,
    windowMs: number,
  ): Array<{ agentName: string; sessionId: string; cause: string | null }> {
    if (!this.#db) {
      // ABSENT IS NOT FINE. An empty array here is indistinguishable from "the store is clean",
      // which is the state this line exists to end — so the one boot where the sweep could not
      // read the store must not look like the boots where it read it and found nothing.
      this.#logger.error("session.revival_bound.enumerate.failed", {
        error: "db not initialized",
        impact: "no interrupted session was checked against the revival window this boot; any that "
          + "have expired are still accepting content",
      });
      return [];
    }
    const rows = this.#db
      .prepare(
        `SELECT s.session_id AS session_id, s.interrupted_by AS cause, a.agent_name AS agent_name
         FROM sessions s JOIN agents a ON a.agent_id = s.agent_id
         WHERE s.status = 'interrupted' AND a.state != 'retired'
           AND (COALESCE(s.interrupted_by, '') != 'local'
                OR s.restart_seal_gave_up_at IS NOT NULL
                OR s.message_count = 0)
           AND CAST(strftime('%s', s.interrupted_at) AS INTEGER) * 1000 <= ?
         ORDER BY CAST(strftime('%s', s.interrupted_at) AS INTEGER) * 1000 ASC`,
      )
      .all(nowMs - windowMs) as unknown as Array<{ session_id: string; cause: string | null; agent_name: string }>;
    return rows.map((r) => ({ agentName: r.agent_name, sessionId: r.session_id, cause: r.cause }));
  }

  /**
   * DOD-M12B-REVIVAL-BOUND-1 — give every timestamp-less interrupted session a clock, once.
   *
   * A row with `interrupted_at IS NULL` has no bound that can be evaluated, and skipping such rows
   * would exempt the oldest sessions in the store from the control permanently — the same "open
   * forever" failure wearing a different NULL. The two rows measured in Entry 41 are exactly this
   * shape, written by a `destroySessionNode` path that set the cause and no timestamp.
   *
   * **`WHERE interrupted_at IS NULL` is the security property, not an optimisation.** It makes the
   * stamp write-once: this can run on every sweep forever and a row's clock still cannot be moved
   * after the first one. That is what disqualifies `updated_at`, which a peer moves with every
   * message it sends into the still-accepting session.
   *
   * The cost is honest and bounded: a legacy row's window starts at the first sweep that sees it
   * rather than at its true interruption, so it survives up to one window longer than it should.
   * A late close is recoverable; a clock the counterparty winds is not.
   *
   * @returns how many rows were stamped.
   */
  #stampMissingInterruptedAt(nowMs: number): number {
    if (!this.#db) return 0;
    try {
      const res = this.#db
        .prepare("UPDATE sessions SET interrupted_at = ? WHERE status = 'interrupted' AND interrupted_at IS NULL")
        .run(new Date(nowMs).toISOString()) as unknown as { changes?: number | bigint };
      const stamped = Number(res?.changes ?? 0);
      if (stamped > 0) {
        this.#logger.info("session.revival_bound.clock.stamped", {
          stamped,
          impact: "these sessions had no interruption timestamp; their revival window starts now",
        });
      }
      return stamped;
    } catch (err: unknown) {
      this.#logger.error("session.revival_bound.clock.stamp.failed", {
        error: err instanceof Error ? err.message : String(err),
        impact: "sessions with no interruption timestamp cannot be evaluated and stay open",
      });
      return 0;
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
    this.#stampMissingInterruptedAt(nowMs);
    const expired = this.listExpiredUnrevivableSessions(nowMs, windowMs);
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


  /**
   * DOD-M12B-RESTART-SEAL-1 — record that automatic sealing has exhausted this session.
   *
   * Durable on purpose. The resolver's attempt budget is in memory, so without this the budget
   * resets on every boot and a session that can never seal costs five directory ceremonies a day
   * for the life of the machine.
   *
   * IT IS NOT A DEAD END FOR THE OPERATOR. The row keeps status `interrupted`, so a manual
   * `cello_close_session` still works on it and — since DOD-M12B-INTERRUPTED-ESCALATE-1 — still
   * escalates to a unilateral seal. This column only withdraws the session from AUTOMATIC retries.
   */
  markRestartSealGaveUp(agentName: string, sessionId: string, reason: string): void {
    if (!this.#db) return;
    this.#db
      .prepare("UPDATE sessions SET restart_seal_gave_up_at = ?, restart_seal_gave_up_reason = ? WHERE agent_id = ? AND session_id = ?")
      .run(Date.now(), reason, this.#requireAgentId(agentName), sessionId);
  }

  /**
   * cello_list_sessions: every persisted session for one agent, regardless of
   * status (active, interrupted, sealed, seal_interrupted_pending). Ordered most
   * recently updated first so the live session surfaces at the top. This is the
   * discovery surface that the by-id reads (cello_get_transcript /
   * cello_get_sealed_receipt) depend on — without it an agent has no way to learn
   * its own session ids after a restart or from a fresh MCP connection.
   */
  /**
   * DOD-M15-REFUSED-INBOUND-SILENT-1, the DECLINED PROTECTION half — a FIELD, not an alert.
   *
   * An unsalted session is exactly as verifiable as every session shipped before salting existed,
   * so there is nothing to interrupt the operator with and no event to fire. What was missing is
   * STATE: nothing let anyone tell *"unsalted because this build predates the feature"* from
   * *"unsalted because adoption was refused"* — and only the second says something about their
   * setup. The session's own status now answers it, which costs nothing per message and cannot
   * become a flood.
   *
   * The raw salt is dropped on the way out rather than passed through. `SELECT *` was handing the
   * BLOB to a listing surface that has no use for it; the boolean is the whole question a reader of
   * this list is asking, and shipping key material to answer a yes/no is not a trade worth making.
   */
  /**
   * ⚠️ THE STORED COLUMN IS NOT THE ANSWER ON ITS OWN — 006-CRYPTO finding 3.
   *
   * A SUSPENDED salt keeps its bytes on disk deliberately (`DOD-M15-SALTSPLIT-1`: a salt kept is
   * recoverable, a salt erased is not), while `#saltForHashing` returns null for it and every
   * message goes out `sha256`. Reading the column alone therefore reported `true` at the exact
   * moment the session had STOPPED salting — and because the field is emitted only when `false`,
   * the agent saw nothing at all, which reads as "not unsalted".
   *
   * That is precisely the case this field was added for. Its own note above says it exists to tell
   * *"unsalted because this build predates the feature"* from *"unsalted because adoption was
   * refused"*, and the refused case was the one it could not report.
   */
  #saltStatusOf(row: SessionRecord, agentName: string | null): SessionRecord {
    const { content_salt, ...rest } = row as SessionRecord & { content_salt?: Uint8Array | null };
    const stored = content_salt != null && content_salt.length > 0;
    const suspended =
      agentName !== null && this.#saltSuspended.has(this.#k(agentName, String(row.session_id)));
    return {
      ...rest,
      content_hashes_salted: stored && !suspended,
      content_encrypted: false,
      content_encryption_reason: CONTENT_ENCRYPTION_REASONS.NO_KEY_EXCHANGE,
    } as SessionRecord;
  }

  getSessionsForAgent(agentName: string): SessionRecord[] {
    if (!this.#db) return [];
    // Scoped by the STABLE id. `agent_name` is not a column of `sessions` any more, so it is stamped
    // back on for display — and it is exactly the name we just resolved the id FROM, so no join is
    // needed and no stale copy can exist.
    const rows = this.#db
      .prepare("SELECT * FROM sessions WHERE agent_id = ? ORDER BY updated_at DESC")
      .all(this.#requireAgentId(agentName)) as unknown as SessionRecord[];
    return rows.map((r) => ({ ...this.#saltStatusOf(r, agentName), agent_name: agentName }));
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
        return this.#saltStatusOf(row, row.agent_name ?? null);
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
  /**
   * The counterparty's threshold group key as this agent has seen it BEFORE — trust on first use.
   *
   * DOD-M15-OFFER-SIGNED-1 / RESPONDER-VERIFY-1. The responder does not verify the assignment's
   * signature (deferred to SESSION-004), so every field in it is whatever the directory said. That
   * makes a same-frame check circular: a compromised directory just says the same thing twice.
   *
   * This is the one anchor the responder holds that a directory CANNOT retroactively change — its
   * own memory of previous sessions with this counterparty. A directory that names a different
   * threshold group key for someone you have already talked to is either substituting an identity
   * or has been compromised since; neither is a session to accept quietly.
   *
   * THE BOUND, stated rather than glossed: this is worth nothing on FIRST contact, which is the
   * definition of trust-on-first-use. It hardens every session after it, which is where a long-lived
   * counterparty relationship actually lives.
   *
   * Keyed on `counterparty_pubkey` — the K_local IDENTITY, which is the stable thing — not on a
   * session id or a display name.
   */
  getPinnedCounterpartyPrimary(agentName: string, counterpartyPubkeyHex: string): string | null {
    if (!this.#db) return null;
    const row = this.#db
      .prepare(
        `SELECT counterparty_primary_pubkey FROM sessions
          WHERE agent_id = ? AND counterparty_pubkey = ? AND counterparty_primary_pubkey IS NOT NULL
          ORDER BY updated_at DESC LIMIT 1`,
      )
      .get(this.#requireAgentId(agentName), counterpartyPubkeyHex) as
      | { counterparty_primary_pubkey: string }
      | undefined;
    return row?.counterparty_primary_pubkey ?? null;
  }

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
          `UPDATE sessions SET status = 'interrupted', updated_at = ?, message_count = ?, interrupted_at = ?, interrupted_by = '${source === "relay_frame" ? "counterparty" : "relay_stream_close"}' WHERE agent_id = ? AND session_id = ? AND status = 'active'`,
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
        client.registerSession(sessionIdHex, entry.node, undefined, assignment);
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
    /**
     * Required alongside the two below — every production caller already passes one, and an optional
     * parameter in front of a required one is what TypeScript refuses. Making it explicit costs
     * nothing and removes the last place a positional argument can silently shift.
     */
    correlationId: string | undefined,
    /**
     * The DOMAIN this content belongs to, as the relay and the directory will see it. Defaults to
     * MESSAGE so `cello_send` is unchanged; the document path passes 0x04/0x05. Not cosmetic — the
     * directory computes `final_message` and `answered` from the witnessed kind, and both of its
     * document exclusions were dead while every document leaf arrived here as a message.
     *
     * ⚠️ ALSO REQUIRED NOW, and for the same reason as `contentHashAlg` below — this parameter is the
     * precedent, not a bystander. It defaulted to MESSAGE, the document adapter in `daemon.ts`
     * silently dropped it, and the wire was wrong for a whole release: *"0.0.145 shipped the fix
     * everywhere except here."* A default that matches the common case makes the omission invisible
     * at every call site and at typecheck. Every caller states its kind now.
     */
    leafKind: number,
    /**
     * `DOD-M15-SEALWIRE-1` part B2b — the algorithm `contentHash` was produced under, taken from
     * `contentHashForSession` by the caller that computed the hash.
     *
     * Passed rather than re-derived HERE, deliberately: re-deriving would ask "how would this
     * session hash something now?", and the answer can differ from how THIS message was actually
     * hashed. A hash and its label must travel together or the peer refuses a message nobody touched.
     *
     * ⚠️ REQUIRED, NOT DEFAULTED — review B2b-1 F4, and the default is what made four mutants
     * unfalsifiable. It was `= CONTENT_HASH_ALGS.SHA256`, which equals the only value in play today,
     * so DROPPING THE ARGUMENT AT ANY OF THE FIVE HOPS produced byte-identical output and the whole
     * 2,800-test daemon suite stayed green. Measured at all four send sites individually.
     *
     * A default that equals the current value makes every threading edit invisible until the value
     * changes — and the day it changes, the dropped argument mislabels the message and every peer
     * refuses it as a tamper. Required makes a dropped argument a TYPECHECK failure instead of a
     * test question nobody can answer.
     */
    contentHashAlg: string,
  ): Promise<
    // DOD-M12B-INDEX-1: `sequenceNumber` is the position the relay assigned this message, carried
    // out so the caller can place its leaf THERE rather than at whatever the tail happens to be.
    // Absent when no ordering authority answered — the documented relay-degraded case.
    // DOD-M15-SEALWIRE-1 bullet 5, SENT half: `authorship` is OUR OWN signature over the Structure-1
    // bytes we put on the wire, carried out so the caller can store it on the sent transcript row.
    //
    // ⚠️ IT IS RETURNED, NOT STASHED, for the same reason `sequenceNumber` is: the value belongs to
    // THIS send, and a side map keyed by session would hand a caller the wrong send's signature the
    // moment two are in flight. It is also paired with the exact `structure1_cbor` it signs —
    // a signature next to the wrong signed bytes is worse than no signature, because it looks
    // checkable and fails.
    //
    // Absent whenever the relay did not witness this leaf: an unwitnessed send has no Structure 1 on
    // the wire, so there is nothing signed to store. The row then records `self_authored` with no
    // proof, which is exactly what happened, rather than implying one.
    | { ok: true; delivered: true; sequenceNumber?: number; authorship?: SentAuthorship }
    | { ok: true; delivered: false; parked: true; sequenceNumber?: number; authorship?: SentAuthorship }
    /**
     * ⚠️ `authorship` RIDES THE FAILURE PATH TOO — review pass 2, and it is the same reasoning that
     * already put `sequenceNumber` here.
     *
     * A DURABLY QUEUED message was witnessed and SIGNED before delivery was attempted; only the
     * direct hand-off failed. Omitting the proof here meant every relay-degraded-but-alive send —
     * the common case — wrote a transcript row indistinguishable from one the relay never saw, while
     * the signature for it sat in scope and was discarded. The position survives a failed delivery
     * for exactly this reason; so does the proof.
     */
    | { ok: false; reason: string; error: string; durable: boolean; cause?: string; guidance?: string; sequenceNumber?: number; authorship?: SentAuthorship }
  > {
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
    /**
     * DOD-M15-SEALWIRE-1 bullet 5, SENT half. Our own Ed25519 signature over `orderingS1`.
     *
     * The submit path already computes this — `keyProvider.sign(structure1)` — and puts it on the
     * wire as `sender_signature`. It was simply never handed back, which is the whole of the defect:
     * a RECEIVED row could prove its author to a third party and a SENT row could not, so half the
     * transcript was provable and half was assertion.
     */
    let sentAuthorship: SentAuthorship | undefined;
    // DOD-M12B-INDEX-1: the relay's answer to "where does this message go", carried to the caller.
    let assignedSeq: number | undefined;
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
          /**
           * PAIRED WITH THE BYTES IT SIGNS, in one place, so the two can never be assigned apart.
           *
           * ⚠️ THE PUBKEY COMES FROM INSIDE `structure1_cbor`, NOT FROM AN AGENT LOOKUP — the same
           * source the RECEIVED half uses. A verifier checks the signature against the key in the
           * signed bytes; storing any other key would produce a row that looks checkable and fails,
           * and a lookup could drift from what was actually signed (a rotated identity, the wrong
           * agent resolved by name). Taking it from the signed bytes makes that class impossible.
           */
          if (witnessed.structure1_cbor && witnessed.sender_signature) {
            /**
             * ⚠️ THE DROP IS SOFT, BUT IT MUST NOT BE SILENT — review pass 1, F2.
             *
             * My comment here claimed the resulting row is "distinguishable from one that carries a
             * signature". True, and it misses the comparison that matters: **it is byte-identical to
             * an UNWITNESSED send** — `self_authored`, both proof columns NULL. So the record cannot
             * tell "the relay never witnessed this" from "we witnessed it, held the proof, and
             * dropped it decoding our own bytes."
             *
             * And the asymmetry with the received half is the argument. `#recordFrameOrdering` is
             * soft because the COUNTERPARTY supplied those bytes — an absence we cannot resolve.
             * Here **we produced them**, in `session-relay-client.ts`, moments earlier. A failure
             * means our own encoder and decoder disagree: an internal invariant break that would
             * strip authorship from every sent row for the life of the process. Soft is still right
             * — throwing would lose a delivered message over a missing attestation — but soft and
             * unannounced is the silent-fallback pattern this milestone exists to find.
             */
            const dropAuthorship = (reason: string, error?: unknown, extra?: Record<string, unknown>): void => {
              this.#logger.warn("session.sent.authorship.unavailable", {
                sessionId,
                agentName,
                reason,
                // WHICH ROW lost its proof — review pass 2, M2. Without the sequence an operator knows
                // a message is unproven and not which one, in a transcript of hundreds.
                ...(witnessed.ok ? { relaySequence: witnessed.sequence_number } : {}),
                ...(extra ?? {}),
                ...(error === undefined ? {} : { error: error instanceof Error ? error.message : String(error) }),
                impact:
                  "this sent message is recorded with attribution 'self_authored' and NO signature, so the row " +
                  "asserts its author rather than proving one. It is indistinguishable in the database from a " +
                  "send the relay never witnessed — this log line is the only thing that tells them apart.",
                guidance:
                  "We produced these bytes ourselves, so a decode or shape failure here means this daemon's own " +
                  "encoder and decoder disagree. Treat it as an internal invariant break, not a peer problem.",
                correlationId,
              });
            };
            try {
              // Structure 1 = [1, content_hash, sender_pubkey, session_id, last_seen_seq, timestamp]
              // — the same decode `#recordFrameOrdering` does for the received half, index 2.
              const s1 = decode(witnessed.structure1_cbor) as unknown[];
              const pk = s1[2];
              // The SIGNATURE is length-checked too (review F2): the guard checked the pubkey's 32
              // bytes and only truthiness on the signature, so a zero-length one would have stored an
              // uncheckable BLOB. Not reachable today — `sign()` returns 64 — and the asymmetry is
              // the kind that stops being unreachable quietly.
              /**
               * ⚠️ VERIFIED BEFORE IT IS STORED, NOT SHAPE-CHECKED — review pass 2, H2, and this is
               * worth more than any test of it.
               *
               * This used to accept the pair on 32 bytes and 64 bytes. A shape check cannot tell a
               * real proof from 96 bytes that resemble one, and **nothing downstream ever checks
               * either**: not at write time, and not at read time, because no production reader of
               * these columns exists yet. So a wrong Structure-1 index, a wrong key, or a pair from
               * two different submits would all have been persisted as a row that **looks checkable
               * to an auditor and fails** — strictly worse than the honest unproven row it replaced.
               *
               * The received half has always done this (`#recordFrameOrdering` verifies before
               * storing and treats a failure as fatal). The sent half did not, and every ingredient
               * was already in scope on this line.
               *
               * What it buys over a test: a wrong index becomes **impossible to persist**. The row
               * gets NULL, the warn below fires, and it happens in production on the machine that
               * caused it — not in a suite someone has to remember to write.
               *
               * NOT fatal, unlike the received half, and the asymmetry is deliberate: there the
               * failure means a COUNTERPARTY sent something that does not verify, which is an
               * identity problem. Here it means our own encoder and decoder disagree — bad, but it
               * must not cost the operator a delivered message.
               */
              if (!(pk instanceof Uint8Array) || pk.length !== 32) {
                dropAuthorship("pubkey_shape", undefined, { pubkeyLen: pk instanceof Uint8Array ? pk.length : -1 });
              } else if (witnessed.sender_signature.length !== 64) {
                dropAuthorship("signature_shape", undefined, { sigLen: witnessed.sender_signature.length });
              } else if (!verify(pk, witnessed.structure1_cbor, witnessed.sender_signature)) {
                dropAuthorship("pair_does_not_verify");
              } else {
                sentAuthorship = { senderPubkey: pk, senderSig: witnessed.sender_signature };
              }
            } catch (err: unknown) {
              dropAuthorship("structure1_decode_failed", err);
            }
          }
          // 1-BASED → 0-BASED. The relay numbers the first leaf of a session 1
          // (`relay-node.ts`: `const seq = state.seq_counter + 1`), and this tree is 0-indexed.
          // Every RECEIVE path in this file normalises with -1 and says so; the send path took the
          // raw number, which puts every comparison against `tree.size()` one position out — so a
          // perfectly healthy first message reads as "ahead of the tail" and is held behind a gap
          // that does not exist. Do not remove this without changing both receive sites too.
          assignedSeq = witnessed.sequence_number - 1;
          this.#logger.info("session.relay.hash.submitted", {
            sessionId,
            // BOTH SPACES, NAMED. The relay's number is 1-based and the leaf index is 0-based, and
            // reading one as the other is the defect this milestone exists to stop — so a log that
            // carries only "sequenceNumber" invites exactly that mistake on the next investigation.
            relaySequence: witnessed.sequence_number,
            leafIndex: assignedSeq,
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
                /**
                 * `session_sealed` retires as SEALED. `seal_refused` retires as ABANDONED —
                 * `DOD-M15-TERMINAL-REASON-1`, and the distinction is the whole reason that unit
                 * exists.
                 *
                 * A refused seal has NO certificate: a directory read it and rejected it. Writing
                 * `sealed` here would be a fabricated notarization claim — `cello_close_session`
                 * answering "already sealed, view its notarization" while the receipt read answers
                 * "not sealed yet", which is the two-answers-pointing-at-each-other deadlock
                 * described above. `abandoned` is the state invented for exactly this:
                 * locally terminal with nothing to notarize.
                 */
                if (witnessed.reason === "seal_refused") {
                  // `abandonSession`, not a hand-rolled flip-then-teardown: it already does the
                  // status write synchronously BEFORE the async teardown yields, which is the
                  // ordering the comment above spends a paragraph on. Reimplementing it here would
                  // be a second copy of that reasoning, free to drift from the first.
                  void this.abandonSession(agentName, id);
                  return;
                }
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
            // The relay's own words about what happened, when it sent any. `reason` is the class and
            // this is the cause — without it a refusal reaches the operator as a bare code, which is
            // the state this field existed to end and never actually did.
            ...(witnessed.detail === undefined ? {} : { detail: witnessed.detail }),
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
    // Held outside the try so the catch can retire a stream that was opened and then failed to
    // write. Without it every failure leaks the OUTBOUND half of the stream the receiver-side
    // `finally` retires — same defect, other end, other cap (64 outbound per protocol per
    // connection). See the note on #handleContentStream's finally.
    let sendStream: Stream | undefined;
    try {
      const stream = await this.#openContentStream(agentName, sessionId, entry, correlationId);
      sendStream = stream;
      // AC-001/AC-003: arm the TTF tracking BEFORE the frame goes on the wire. The
      // receiver's `persisted` ACK can come back fast (in-process / low-latency
      // transports), so registering the awaiting entry after send would let the ACK
      // race ahead of it and be dropped — the timer would then spuriously fire. The
      // content is delivered to the wire but NOT yet confirmed persisted; the ACK
      // resolves it (content.delivery.acked) and TTF expiry hands it to the park
      // backstop. The correlationId rides in the frame so the receiver's
      // session.content.received shares ONE flow id with the sender.
      this.#trackAwaitingAck(agentName, sessionId, content, contentHash, correlationId, orderingS1, orderingS2, contentHashAlg);
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
        // DOD-M15-SEALWIRE-1 part B2b: HOW `content_hash` was produced. An older peer ignores an
        // unknown CBOR key, so emitting it is safe for every build in existence; a newer one reads
        // it and verifies under the named algorithm instead of assuming.
        content_hash_alg: contentHashAlg,
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
      this.#clearSessionImpairment(agentName, sessionId, "direct_send", correlationId);
      return { ok: true, delivered: true, ...(assignedSeq === undefined ? {} : { sequenceNumber: assignedSeq }), ...(sentAuthorship === undefined ? {} : { authorship: sentAuthorship }), ...(relayRefusal === undefined ? {} : { relayRefusal }) };
    } catch (err: unknown) {
      this.#markSessionImpaired(agentName, sessionId, { cause: "direct_send", error: err instanceof Error ? err.message : String(err), correlationId });
      if (sendStream !== undefined) {
        try { sendStream.abort(err instanceof Error ? err : new Error(String(err))); } catch { /* already gone */ }
      }
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
      // NAME THE CAUSE. This catch used to discard `err` outright, so a park reported only its exit
      // point — "dispatched to relay" — and never what went wrong. Measured 2026-08-17: 212 parks on
      // one daemon, not one of them recording a reason, which is what made a one-way session look
      // like a protocol mystery for a night.
      //
      // `counterpartySessionPeerId` is the load-bearing field. It is recorded ONCE at session
      // establishment and never refreshed. (CORRECTED 2026-08-18: this used to say a standing
      // receiver is rebuilt "on every signaling reconnect" — it is not. `ensureStandingReceiverForAgent`
      // no-ops on a healthy receiver; the only rebuild triggers are a LOST RELAY RESERVATION and the
      // one-shot upgrade when relay endpoints first arrive.) If the two ever cross, every send goes
      // one-way forever and nothing says so. With this line that becomes a single grep instead of a
      // night.
      this.#logger.warn("session.content.direct.send.failed", {
        agentName,
        sessionId,
        contentHash: hashHex,
        counterpartySessionPeerId: entry.counterpartySessionPeerId,
        error: err instanceof Error ? err.message : String(err),
        // "Cannot write to a stream that is closed" names where the write died, never why. The
        // why is almost always the per-protocol stream cap, and these two numbers are what turn
        // that from a log-measurement session into a grep.
        ...this.#streamCensus(entry.node, entry.counterpartySessionPeerId),
        correlationId,
      });
      const attempt = await this.#parkContent(agentName, sessionId, hashHex, content, orderingS1, orderingS2, contentHashAlg);
      if (attempt.outcome === "parked") {
        this.#noteImpairmentRetention(agentName, sessionId, "parked");
        return { ok: true, delivered: false, parked: true, ...(assignedSeq === undefined ? {} : { sequenceNumber: assignedSeq }), ...(sentAuthorship === undefined ? {} : { authorship: sentAuthorship }), ...(relayRefusal === undefined ? {} : { relayRefusal }) };
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
            // B2b-1 review F1: the DURABLE writer. Without the 7th argument the column this unit
            // added has no producer at all — every queued row would carry NULL, and the crash
            // backstop would re-park a salted message as sha256 and have it refused forever.
            durable = this.#onParkFailed(agentName, sessionId, hashHex, content, orderingS1, orderingS2, contentHashAlg);
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
      //
      // The same distinction is recorded on the session, because `cello_receive` will be asked
      // about this later and would otherwise have to guess — and its guess ("it was parked, do not
      // resend") is the exact opposite of what the lost case needs.
      this.#noteImpairmentRetention(agentName, sessionId, durable ? "durable" : "lost");
      return {
        ok: false,
        reason: "session_stream_unavailable",
        error: errMsg,
        // Carried on the failure path too: a DURABLY QUEUED message still owns the position the
        // relay witnessed for it before delivery was attempted, and its leaf must go there.
        ...(assignedSeq === undefined ? {} : { sequenceNumber: assignedSeq }),
        // …and so does its PROOF, for the same reason. It was signed before the hand-off failed.
        ...(sentAuthorship === undefined ? {} : { authorship: sentAuthorship }),
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
        /**
         * ⚠️ A FAULT THAT IS NOT THE RELAY MUST NOT SAY IT IS — B2b-2 constraint 6.
         *
         * The `durable` branch below is written for a relay that is down: queued, retried, nothing
         * for you to do. That is right for the case it was written for and WRONG for a producer-side
         * refusal, which reaches the same branch by the same route. There the relay was never asked,
         * and the drain re-parks the same entry into the same throw — so the message is genuinely
         * durable and will genuinely never leave. Telling that operator to wait costs them however
         * long they are willing to wait before they stop believing the message.
         *
         * This is the reason `cause` had to become a code first: the distinction is unbranchable
         * while the field holds an English paragraph.
         */
        guidance: parkRefusalGuidance(attempt.cause, durable, attempt.retryAfterMs),
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
        const durable = this.#recoverOwnSealCtrlLeaf(agentName, sessionId);
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
    const record = this.getSessionRecord(agentName, sessionId);
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
    const record = this.getSessionRecord(agentName, sessionId);
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
  /**
   * Mark this session's content unverifiable — review F1, and every path that fails the cross-check
   * must come through here.
   *
   * It gates `getSealUpgradeReadiness().tampered` and the auto-acknowledge check, i.e. whether this
   * agent's key signs anything covering content it could not check. Three refusal paths reach it and
   * they carry different labels, because what the operator is told must differ; **what the gate does
   * must not.**
   *
   * TAMPERED NEVER DOWNGRADES. A session that has already seen a hash mismatch stays `tampered` even
   * if a later frame merely names an unreadable algorithm — otherwise a sender that had been caught
   * could clear its own alarm by sending one more frame with a junk algorithm name, and the seal
   * would auto-complete.
   */
  /**
   * Remember that THIS frame was refused for naming an unreadable algorithm, so the park path can
   * say so if the same message comes back the other way (review F2/F-D).
   *
   * BOUNDED, and it has to be: a peer that keeps sending unreadable frames would otherwise grow this
   * without limit, and it is fed entirely by a remote party. The cap is per session and it drops the
   * OLDEST entry — losing one only costs a missing reconciliation line, whereas an unbounded map fed
   * by a counterparty is the leak class this codebase has already caught twice.
   */
  #noteUnreadableAlgFrame(agentName: string, sessionId: string, contentHash: Uint8Array, declaredAlg: string): void {
    const key = this.#k(agentName, sessionId);
    let byHash = this.#unreadableAlgSeen.get(key);
    if (!byHash) { byHash = new Map(); this.#unreadableAlgSeen.set(key, byHash); }
    if (byHash.size >= MAX_UNREADABLE_ALG_FRAMES) {
      const oldest = byHash.keys().next();
      if (!oldest.done) byHash.delete(oldest.value);
    }
    byHash.set(Buffer.from(contentHash).toString("hex"), declaredAlg);
  }

  /**
   * ─── DOD-M15-REFUSED-INBOUND-SILENT-1: refusals the RECEIVING operator can actually see ───────
   *
   * Every inbound refusal already logs a `reason`, an `impact` and a `guidance` — and they are
   * good. They had no reader. From the receiving operator's chair a refused message simply never
   * arrives: the conversation goes quiet with a full explanation sitting in a file they have no
   * reason to open, and they conclude the other person stopped replying.
   *
   * `content_hash_alg_unknown` is why this matters more than it sounds. It is a VERSION SKEW, so it
   * affects every message from that counterparty, permanently — not a rare one-off.
   *
   * **DEDUPLICATED PER SESSION PER REASON, and that is the design, not an optimisation.** A skewed
   * peer turns one problem into a flood: the first refusal of a kind is the signal, the ninetieth is
   * noise that trains the operator to ignore the surface. `count` keeps the scale visible without
   * repeating the alert.
   *
   * **NEVER carries the content.** It failed verification; surfacing it is the injection path the
   * cross-check exists to close. The operator learns that a message was refused and why — never
   * what it said.
   *
   * In memory, deliberately: a restart re-signalling a still-broken peer is correct behaviour, not
   * duplication, and durability here would buy nothing the next refusal does not.
   */
  /**
   * (agentName, sessionId) → reason → the notice. `firstAt` was dropped: it was written and read by
   * nothing, and a field nobody consumes is a claim the code does not keep.
   */
  #contentRefusals = new Map<string, Map<string, { reason: string; impact?: string; guidance?: string; count: number; surfacedTo: Map<string, number> }>>();

  /** Record an inbound refusal for the operator. First of its kind per session is the signal. */
  noteContentRefusal(
    agentName: string,
    sessionId: string,
    reason: string,
    detail?: { impact?: string; guidance?: string },
  ): void {
    const key = this.#k(agentName, sessionId);
    let perSession = this.#contentRefusals.get(key);
    if (!perSession) {
      perSession = new Map();
      this.#contentRefusals.set(key, perSession);
    }
    const existing = perSession.get(reason);
    if (existing) {
      existing.count += 1;
      return;
    }
    perSession.set(reason, {
      reason,
      impact: detail?.impact,
      guidance: detail?.guidance,
      count: 1,
      // Per CONSUMER, not one global flag. See `takeContentRefusals`.
      surfacedTo: new Map<string, number>(),
    });
  }

  /**
   * Drain the refusals a GIVEN CONSUMER has not been shown yet, and remember what it was shown.
   *
   * ─── Why this is keyed by connection, and not by a single flag ─────────────────────────────────
   *
   * It used to set one `surfaced: boolean` on the notice. Two MCP windows attending the same agent
   * is the ordinary case, and under that flag whoever read FIRST consumed the notice — the second
   * window was told nothing, permanently. **That is the same defect `takeReceivedContent` had**, and
   * the comment above the delivery loop in `session-content-handlers.ts` spells out why it was
   * removed: *"reading is non-destructive by construction. Nothing one consumer does mutates state
   * another consumer reads."* The whole `taken_by_sibling` apparatus exists because this was paid
   * for once already; re-introducing it on a different surface makes it no less true.
   *
   * ─── Why the count now has a reader ────────────────────────────────────────────────────────────
   *
   * The old docstring claimed *"count still grows underneath, so a later reader can ask how many
   * without being told again."* **There was no later reader.** After the first surfacing the count
   * incremented under a flag the drain skipped unconditionally, so 3 refusals became 903 and nothing
   * anywhere could say so — while the comment asserted the opposite.
   *
   * So a reason RE-ANNOUNCES to a consumer when its count has grown by an order of magnitude since
   * that consumer last saw it (1 → 10 → 100 → …), marked `repeat: true`. That keeps the first
   * refusal the signal and the ninetieth silent, which is the dedup's point, while still making a
   * skew that has swallowed hundreds of messages visible — at a handful of announcements per
   * session, not one per message.
   */
  takeContentRefusals(
    agentName: string,
    sessionId: string,
    /**
     * REQUIRED, deliberately — no default.
     *
     * It had one (`"default"`), and a default is the defect this method was rewritten to remove,
     * lying in wait: any future call site that omits the argument silently shares ONE bucket across
     * every window, the first reader consumes the notice for all the others, and nothing fails to
     * compile and no test goes red. The parameter existing is not the protection; being unable to
     * forget it is.
     */
    consumerId: string,
  ): Array<{ reason: string; impact?: string; guidance?: string; count: number; repeat?: boolean }> {
    const perSession = this.#contentRefusals.get(this.#k(agentName, sessionId));
    if (!perSession) return [];
    const out: Array<{ reason: string; impact?: string; guidance?: string; count: number; repeat?: boolean }> = [];
    for (const notice of perSession.values()) {
      const shownAt = notice.surfacedTo.get(consumerId);
      const firstTime = shownAt === undefined;
      // `shownAt` is at least 1 whenever it is set, so this cannot loop on zero.
      if (!firstTime && notice.count < shownAt * 10) continue;
      notice.surfacedTo.set(consumerId, notice.count);
      out.push({
        reason: notice.reason,
        impact: notice.impact,
        guidance: notice.guidance,
        count: notice.count,
        ...(firstTime ? {} : { repeat: true }),
      });
    }
    return out;
  }

  #markContentUnverifiable(agentName: string, sessionId: string, why: "tampered" | "unverifiable"): void {
    const key = this.#k(agentName, sessionId);
    if (why === "unverifiable" && this.#contentDesynced.get(key) === "tampered") return;
    this.#contentDesynced.set(key, why);
  }

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
    /**
     * DOD-M15-SEALWIRE-1 part B1 — the algorithm the SENDER named on the frame, verbatim.
     *
     * `undefined` means the frame carried no name, which is a peer that predates the field and is
     * the one case we may safely assume `sha256` for. It is threaded through rather than read off
     * the session, because whether a hash is salted is a fact about the FRAME and its sender, never
     * about what this side happens to hold.
     */
    contentHashAlgIn?: string | null,
    /**
     * DOD-M15-SEALWIRE-1 bullet 5: the VERIFIED authorship proof for this message, when the caller
     * has one. The caller is the only place that has it — `#recordFrameOrdering` verifies the
     * signature against the key inside the sender's own signed bytes and matches the signer to this
     * session's counterparty, and that result reaches here or nowhere.
     *
     * Optional, because the soft decode-failure path ingests without it. The row records which it
     * was, so absence is never silent.
     */
    verifiedAuthorship?: { senderPubkey: Uint8Array; senderSig: Uint8Array },
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

    /**
     * DOD-M15-SEALWIRE-1 part B1 — VERIFY UNDER THE ALGORITHM THE SENDER NAMED.
     *
     * Three outcomes and they must stay apart, because two of them are version differences and only
     * the third is evidence of tampering. Collapsing them is how a routine skew becomes a security
     * incident in the operator's log, and how a real tamper gets dismissed as a skew.
     */
    /**
     * ⚠️ `content_hash_alg` IS NOT COVERED BY ANY SIGNATURE — review F1, and it shapes both branches
     * below.
     *
     * The sender's signature is over `structure1_cbor`, which binds `content_hash`. It does NOT bind
     * the frame envelope, so this field is an unauthenticated CLAIM by whoever sent the frame. That
     * is fine for choosing how to verify — a wrong choice simply fails — but it means neither branch
     * may state, as fact, anything it learned only from this field.
     *
     * It also means both branches MUST mark the session unverifiable. Before B1 every frame that
     * failed the cross-check reached `#contentDesynced`, which gates auto-co-signing and unilateral
     * ratification. Returning early here would have let a sender bypass the tamper detector by
     * appending one unsigned string: sign hash H, send different bytes, add an unreadable algorithm
     * name, and the receiver refuses politely, records nothing, and auto-co-signs at seal time.
     */
    const algResolved = resolveContentHashAlg(contentHashAlgIn);
    if (!algResolved.ok) {
      // A NAME WE CANNOT READ. Not a legacy peer — an unreadable one. There is no value to compare
      // against, so `content_hash_mismatch` here would be an exit-point label standing in for
      // "their build is newer than ours" (Invariant 2). Refused by its own name instead.
      this.#markContentUnverifiable(agentName, sessionId, "unverifiable");
      this.#noteUnreadableAlgFrame(agentName, sessionId, contentHash, algResolved.value);
      this.#logger.error("session.content.cross_check.failed", {
        sessionId, correlationId,
        reason: "content_hash_alg_unknown",
        declaredAlg: algResolved.value,
        // States only what is KNOWN. The old wording said "nothing was altered and nobody did
        // anything wrong" and "Do not treat this as a security event" — both inferred from the
        // unsigned field, i.e. from the attacker in the case that matters.
        impact: "this message could not be verified, so it was NOT ingested and NOT shown. The algorithm name is a claim by the sender and is not covered by any signature, so it does not establish what they actually did. This session will not auto-co-sign at close.",
        guidance: "Almost always their CELLO build is newer than this one: ask which version they are running, and upgrade. If they are on the SAME version as you, that explanation does not hold and the frame was malformed or crafted — do not close the session by auto-acknowledgement.",
      });
      // DOD-M15-REFUSED-INBOUND-SILENT-1: the SAME strings the log just carried, to the operator.
      // This reason is a version skew, so it affects every message from that counterparty — without
      // this the conversation goes permanently quiet and they conclude the peer stopped replying.
      this.noteContentRefusal(agentName, sessionId, "content_hash_alg_unknown", {
        impact: "this message could not be verified, so it was NOT ingested and NOT shown. The algorithm name is a claim by the sender and is not covered by any signature, so it does not establish what they actually did. This session will not auto-co-sign at close.",
        guidance: "Almost always their CELLO build is newer than this one: ask which version they are running, and upgrade. If they are on the SAME version as you, that explanation does not hold and the frame was malformed or crafted — do not close the session by auto-acknowledgement.",
      });
      return { ok: false, reason: "content_hash_alg_unknown" };
    }
    let computed: Uint8Array;
    try {
      computed = contentHashFor(content, {
        alg: algResolved.alg,
        // The salt is OURS — the sender's frame never carries one, and could not be trusted if it
        // did. A salted frame we hold no salt for throws below and is refused by name.
        salt: this.#getSessionSalt(agentName, sessionId),
      });
    } catch (err: unknown) {
      // Reached when the peer named the salted algorithm and this side holds no salt for the
      // session — the agreement never completed, or its record is gone. Distinct from a mismatch
      // for the same reason as above: nothing was tampered with, we simply cannot check it.
      this.#markContentUnverifiable(agentName, sessionId, "unverifiable");
      this.#logger.error("session.content.cross_check.failed", {
        sessionId, correlationId,
        reason: "content_hash_salt_unavailable",
        declaredAlg: algResolved.alg,
        detail: extractErrorMessage(err),
        // "Nothing was altered" was the same mistake as the branch above: it is not knowable from
        // here. What IS knowable is that we could not check.
        impact: "this message could not be verified — the sender says it is salted and this side holds no salt for the session — so it was NOT ingested and NOT shown. This session will not auto-co-sign at close.",
        // Review F6: `#getSessionSalt` returns null for THREE conditions and only one of them wants
        // a close. A read failure and a corrupt row both leave us holding no salt, which is exactly
        // what makes the agreement re-offer a contribution and repair itself on the next connect.
        //
        // The adoption refusal is the FOURTH, added with the Decision #8 guard, and it is the only
        // one that does not repair: this side declined the salt permanently for this session, so
        // waiting for a reconnect is exactly the wrong advice. Leaving it out of this list would
        // have sent an operator to look for a read failure that is not there and never will be.
        // DOD-M15-SALTSPLIT-1 review MEDIUM-3: `session.salt.discarded` is the FIFTH cause, and it
        // was added by the discard without appearing in this tree. Without it an operator whose salt
        // was deliberately dropped is sent to look for three events that will not be there and then
        // told a fifth thing that is false — the agreement DID complete here, and was then undone on
        // purpose.
        guidance: "Look for session.salt.discarded first: if it is there, this side dropped its salt because the counterparty said it could never hold one, the agreement did complete and was deliberately undone, and a new session is the repair. Otherwise look for session.salt.adoption.refused: if it is there, this side declined the salt because the session had already hashed messages, that is permanent for this session, and reconnecting will NOT fix it — close the session and start a new one. Otherwise look for session.salt.read.failed or session.salt.persist.failed. If either is present the agreement re-runs on the next reconnect and this repairs itself — wait for that before doing anything. If none of the four is present, the agreement never completed with this counterparty: close the session and start a new one. In every case the transcript up to here is intact.",
      });
      // DOD-M15-REFUSED-INBOUND-SILENT-1 — and this branch needed it MORE than the two that had it.
      //
      // It was refused, logged with a full impact and guidance, not ingested, not shown — and the
      // operator was told nothing. Twenty lines below the branches that were wired, in the same
      // function, with the same shape.
      //
      // One of its four causes is permanent, and the guidance above says so in its own words: an
      // adoption refusal means this side declined the salt for the life of the session and
      // reconnecting will NOT fix it. So the failure this line exists to close — the conversation
      // goes quiet, the explanation sits in a log nobody opens — was still live on the one branch
      // that never repairs itself.
      //
      // The guidance is passed by reference to the log's own text rather than duplicated: a second
      // copy is a second thing to keep true, and the log's version is the one that gets maintained.
      this.noteContentRefusal(agentName, sessionId, "content_hash_salt_unavailable", {
        impact:
          "this message could not be verified — the sender says it is salted and this side holds no salt for the session — so it was NOT ingested and NOT shown. This session will not auto-co-sign at close.",
        guidance:
          "If session.salt.discarded is present, this side dropped its salt on purpose because the counterparty said it could never hold one — a new session is the repair. If this side refused the salt because the session had already hashed messages, that is PERMANENT for this session and reconnecting will not fix it — close the session and start a new one. Otherwise the salt agreement re-runs on the next reconnect and this repairs itself. Check session.salt.discarded and session.salt.adoption.refused in the log to tell which. The transcript up to here is intact either way.",
      });
      return { ok: false, reason: "content_hash_salt_unavailable" };
    }
    const contentHashHex = Buffer.from(contentHash).toString("hex");
    if (Buffer.from(computed).toString("hex") !== contentHashHex) {
      this.#logger.warn("session.content.cross_check.failed", {
        sessionId,
        reason: "content_hash_mismatch",
        // WHICH algorithm the comparison ran under. Without it, a mismatch is unfalsifiable from the
        // log: an operator cannot tell "the bytes were altered" from "we checked it the wrong way".
        declaredAlg: algResolved.alg,
        correlationId,
      });
      // M7-UPGRADE-002 (SI-002): a tamper makes this session's content unverifiable — the
      // auto-acknowledge gate must never auto-co-sign it. The session stays alive (DOD-MSG-7),
      // but the responder seal now requires the agent's explicit decision, not an auto-ack.
      this.#markContentUnverifiable(agentName, sessionId, "tampered");
      // DOD-M15-REFUSED-INBOUND-SILENT-1. Deliberately does NOT include the content or the hashes:
      // it failed verification, and showing it is the injection path this cross-check closes.
      this.noteContentRefusal(agentName, sessionId, "content_hash_mismatch", {
        impact:
          "a message arrived whose bytes do not match the hash the sender committed to, so it was NOT ingested and NOT shown. This session will not auto-co-sign at close.",
        guidance:
          "Either the message was altered in transit or the sender's record is wrong. Ask the counterparty to resend. Do not close this session by auto-acknowledgement — seal it only by an explicit decision.",
      });
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
    // DOD-DOC-SCREEN-CLASSIFY-1: a DOCUMENT frame skips the gateway's content screen HERE, and is
    // screened later on text instead of bytes. Every content step is inert or worse for one at this
    // point — the sanitizer's rewrites are deliberately discarded by the funnel below (rewriting a
    // signed envelope destroys it), and language/injection judge a UTF-8 decode of binary. Size stays
    // bounded twice (MAX_DOCUMENT_FRAME_BYTES at classify, the gate's own cap).
    //
    // WHAT IS TRADED, stated plainly: the screen skipped here is fail-CLOSED (a gateway that is down
    // returns a transient block, and the frame is held un-acked for redelivery). Its replacement —
    // the gate's in-process rules, then the semantic screen at `document-inbound.ts` step 7a-bis —
    // is fail-OPEN on that same condition, because holding document convergence hostage to an
    // optional layer breaks a layer that degrades by design. That degradation is LOGGED BY NAME
    // there (`document.inbound.screen.unavailable`); it is not silent, and it is not free.
    //
    // Logged by name so the skip is visible rather than assumed.
    const isDocFrame = this.#isDocumentFrame?.(content) === true;
    if (isDocFrame) {
      this.#logger.info("session.content.screen.skipped_document_frame", {
        sessionId,
        agentName,
        correlationId,
      });
    }
    const inboundVerdict: Awaited<ReturnType<SecurityGatewayClient["screenInbound"]>> = isDocFrame
      ? { disposition: "allow", content }
      : await this.#securityGateway.screenInbound(content, {
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
      this.#ensureHeldRestored(agentName, sessionId);
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
      // DOD-M12B-STRAND-1: and to disk, before we answer. The in-memory Map is the working copy;
      // this row is the one that survives the teardown that used to destroy it.
      this.#persistHeldContent(agentName, sessionId, canonicalSeq, deliverContent, content, contentHashHex, terminalBlock === true, correlationId);
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
      : this.#appendVerifiedContent(agentName, sessionId, deliverContent, contentHashHex, senderPubkey, correlationId, content, verifiedAuthorship).leafIndex;

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
    // DOD-M12B-SEAL-STUCK-1: this process has now seen this session's ordering state, so an empty
    // witness map for it means "no gap" rather than "never looked".
    this.#orderingObserved.add(key);
    let map = this.#witnessedSeq.get(key);
    if (!map) { map = new Map(); this.#witnessedSeq.set(key, map); }
    map.set(contentHashHex, sequenceNumber);
    const hw = this.#highWaterSeq.get(key) ?? -1;
    if (sequenceNumber > hw) this.#highWaterSeq.set(key, sequenceNumber);

    /**
     * DOD-M12B-LEAF-TRIGGERS-FETCH-1 — A LEAF WE CANNOT READ IS A FETCH ORDER.
     *
     * MEASURED LIVE 2026-08-18: the relay delivered this leaf one second after the counterparty
     * sent. We had the hash and the sequence, the bytes were parked at that same relay, and the
     * plaintext arrived 102 seconds later on a background sweep. Nothing connected the two facts —
     * this method recorded the sequence and stopped.
     *
     * The witness leaf and the plaintext are separate deliveries: the leaf comes over the relay, the
     * bytes over the direct content stream. After an interruption the two session nodes have no
     * direct connection, so the bytes go to the park instead and only a timer ever finds them.
     *
     * The grace window is what keeps this off the hot path. On a healthy session the direct content
     * lands within milliseconds of its leaf, so fetching immediately would mean a relay round trip
     * for every message in every session. We give the direct path its two seconds first.
     */
    this.#scheduleLeafFetchIfUnresolved(agentName, sessionId, contentHashHex);
  }

  /** DOD-M12B-LEAF-TRIGGERS-FETCH-1: this content is here — no fetch is owed for it, and any
   *  pending one is cancelled. Called wherever content actually lands. */
  #markContentResolved(agentName: string, sessionId: string, contentHashHex: string): void {
    const key = this.#k(agentName, sessionId);
    let set = this.#resolvedContent.get(key);
    if (!set) { set = new Set(); this.#resolvedContent.set(key, set); }
    set.add(contentHashHex);
    const timerKey = `${key}::${contentHashHex}`;
    const t = this.#leafFetchTimers.get(timerKey);
    if (t !== undefined) {
      clearTimeout(t);
      this.#leafFetchTimers.delete(timerKey);
    }
  }

  #scheduleLeafFetchIfUnresolved(agentName: string, sessionId: string, contentHashHex: string): void {
    const key = this.#k(agentName, sessionId);
    if (this.#resolvedContent.get(key)?.has(contentHashHex)) return;
    const timerKey = `${key}::${contentHashHex}`;
    // ONE fetch per content hash. The relay redelivers, and a redelivery carries the same sequence —
    // scheduling per redelivery turns a slow relay into a storm against itself.
    if (this.#leafFetchTimers.has(timerKey)) return;
    const timer = setTimeout(() => {
      this.#leafFetchTimers.delete(timerKey);
      if (this.#resolvedContent.get(key)?.has(contentHashHex)) return; // the direct path won
      if (this.#shuttingDown) return;
      this.#logger.info("session.content.leaf_unresolved.fetch", {
        agentName,
        sessionId,
        contentHash: contentHashHex,
        graceMs: this.#leafFetchGraceMs,
        impact: "the relay told us this message exists and its plaintext never arrived directly — "
          + "fetching it now instead of waiting for the periodic sweep",
      });
      this.#fireParkedDrain(agentName, "witnessed_leaf_unresolved");
    }, this.#leafFetchGraceMs);
    timer.unref?.();
    this.#leafFetchTimers.set(timerKey, timer);
  }

  /** DOD-M12B-LEAF-TRIGGERS-FETCH-1 test seams. */
  setLeafFetchGraceMsForTest(ms: number): void { this.#leafFetchGraceMs = ms; }
  markContentPresentForTest(agentName: string, sessionId: string, contentHashHex: string): void {
    this.#markContentResolved(agentName, sessionId, contentHashHex);
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
    this.#ensureHeldRestored(agentName, sessionId, { release: false });
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
    const diverged = this.#diverged.has(key);
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
      const oldestHeldMs = this.#oldestHeldMs(agentName, sessionId);
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

  /** DOD-M12B-INDEX-1 — this agent's own K_local pubkey, for attributing its own held content.
   *  Null when it cannot be resolved: an UNATTRIBUTED annex row is true, a falsely attributed one
   *  is not, and this is the record that outlives the session. */
  /**
   * Test seam for `#recoverOwnSealCtrlLeaf` (documented on the method itself, below). The
   * distinction it draws — "there is none" versus "I could not tell" — is the whole safety
   * property, and it had no coverage at any level.
   */
  recoverOwnSealCtrlLeafForTest(agentName: string, sessionId: string): { reportedRootHex: string; sequenceNumber: number } | "none" | "unknown" {
    return this.#recoverOwnSealCtrlLeaf(agentName, sessionId);
  }

  /**
   * DOD-M12B-INTERRUPTED-ESCALATE-1 — our own SEAL ctrl leaf, if a previous run already posted one.
   *
   * Returns the two values a unilateral escalation runs on, rebuilt from durable state:
   * the ctrl leaf's relay-assigned sequence, and the root the tree WOULD have with that leaf
   * appended. The content hash cannot be recomputed — the seal payload embeds a `close_timestamp`
   * — so it is read out of the signed Structure 1 the store already holds.
   *
   * Null when there is no own ctrl leaf, which is the ordinary first-close case.
   */
  #recoverOwnSealCtrlLeaf(agentName: string, sessionId: string): { reportedRootHex: string; sequenceNumber: number } | "none" | "unknown" {
    const ownPubkey = this.#ownPubkeyHex(agentName);
    // "I CANNOT TELL" IS NOT "THERE IS NONE". Returning the absent answer here would let the caller
    // submit a second SEAL ctrl leaf — the exact permanent loss this method exists to prevent — on
    // the strength of a lookup that failed. Every path that could not determine the answer says so.
    if (!ownPubkey) {
      this.#logger.warn("session.seal.leaf.recover.failed", {
        sessionId, agentName, reason: "own_pubkey_unresolved",
        impact: "cannot tell whether a SEAL ctrl leaf was already posted, so the close refuses rather than risk a second one",
      });
      return "unknown";
    }
    let own: SealCarryLeaf | undefined;
    try {
      own = this.getSealCarry(ownPubkey, sessionId)
        .find((l) => l.leafKind === LEAF_KIND_CTRL && l.senderPubkeyHex === ownPubkey);
    } catch (err: unknown) {
      this.#logger.warn("session.seal.leaf.recover.failed", {
        sessionId, agentName, reason: "carry_read_failed",
        error: err instanceof Error ? err.message : String(err),
        impact: "cannot tell whether a SEAL ctrl leaf was already posted, so the close refuses rather than risk a second one",
      });
      return "unknown";
    }
    if (!own) return "none";
    try {
      // Canonical Structure 1 is [version, content_hash, sender_pubkey, session_id, last_seen_seq, timestamp].
      const fields = decode(own.structure1Cbor) as unknown[];
      const contentHash = fields[1];
      if (!(contentHash instanceof Uint8Array)) {
        this.#logger.warn("session.seal.leaf.recover.failed", {
          sessionId, agentName, reason: "structure1_content_hash_missing",
          impact: "cannot tell whether a SEAL ctrl leaf was already posted, so the close refuses rather than risk a second one",
        });
        return "unknown";
      }
      const contentHashHex = Buffer.from(contentHash).toString("hex");
      return {
        reportedRootHex: this.getSessionTree(agentName, sessionId).rootWithAppendedHex(contentHashHex),
        sequenceNumber: own.sequenceNumber,
      };
    } catch (err: unknown) {
      this.#logger.warn("session.seal.leaf.recover.failed", {
        sessionId, agentName, reason: "structure1_decode_failed",
        error: err instanceof Error ? err.message : String(err),
        impact: "cannot tell whether a SEAL ctrl leaf was already posted, so the close refuses rather than risk a second one",
      });
      return "unknown";
    }
  }

  #ownPubkeyHex(agentName: string): string | null {
    if (!this.#db) return null;
    try {
      // BY agent_id, never by agent_name. The name is a mutable, reuse-freed display label, and
      // scoping on it hands one identity's rows to another keypair (DOD-AGENT-ID-JOINKEY-1).
      const row = this.#db
        .prepare("SELECT k_local_pubkey FROM agents WHERE agent_id = ?")
        .get(this.#requireAgentId(agentName)) as { k_local_pubkey: string } | undefined;
      return row?.k_local_pubkey ?? null;
    } catch (err: unknown) {
      // An unattributed annex row is truthful; an unattributed row nobody knows about is not. This
      // throws for a retired agent, and without a line here EVERY own held message would land in
      // the record that outlives the session with no sender and no explanation.
      this.#logger.warn("session.own_pubkey.unresolved", {
        agentName,
        error: err instanceof Error ? err.message : String(err),
        impact: "this agent's own held content will be annexed without a sender",
      });
      return null;
    }
  }

  /** DOD-M12B-SEAL-STUCK-1 — how long the oldest held frame for this session has been waiting, or
   *  null when nothing is held. This is what separates "stuck since this morning" from "in flight
   *  40 ms ago", and without it a healthy mid-conversation window reads as a stranded session. */
  #oldestHeldMs(agentName: string, sessionId: string): number | null {
    if (!this.#db) return null;
    try {
      const row = this.#db.prepare(
        "SELECT MIN(held_at) AS oldest FROM held_content WHERE agent_id = ? AND session_id = ?",
      ).get(this.#requireAgentId(agentName), sessionId) as { oldest: number | null } | undefined;
      if (!row || row.oldest === null) return null;
      return Date.now() - row.oldest;
    } catch {
      // A diagnostic detail must not be able to break the surface it decorates.
      return null;
    }
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
    /**
     * DOD-M15-SEALWIRE-1 bullet 5: threaded from `ingestReceivedContent`, which is the only place
     * that has it — `#recordFrameOrdering` verified this signature against the pubkey inside the
     * sender's own signed bytes and matched the signer to this session's counterparty. It reaches
     * the transcript row from here or not at all.
     *
     * Undefined on the held-release and soft-fallback paths; the row records that as
     * `local_session_state` rather than leaving it indistinguishable from a proven one.
     */
    verifiedAuthorship?: { senderPubkey: Uint8Array; senderSig: Uint8Array },
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
      /**
       * ⚠️ THIS LINE USED TO LOG `ok: routed.ok` AND `reason: routed.reason`, AND NEITHER CAN EVER
       * BE PRESENT HERE. Removed rather than left, because their absence was read as evidence.
       *
       * The producer is `DocumentFrameRouter.routeSync`, and it has four returns — `unshaped`,
       * `undecodable`, `owner_unresolved`, and the normal path — **none of which sets either
       * field.** It cannot: the normal path is `void this.#enqueue(...)`, fire-and-forget, so at the
       * instant this line is written the frame has been CLASSIFIED and QUEUED and nothing has yet
       * decided whether it will be accepted. The verdict is genuinely not knowable here.
       *
       * **What that cost:** `j-stale-session` reported `framesReceived=3 inbound=0`, and the
       * investigation recorded that `ok` and `reason` were "ABSENT from every line in the run — so
       * the router returned neither, which is itself the next thread to pull: a routing result that
       * reports no outcome cannot say whether it accepted or dropped the frame." That thread leads
       * nowhere. The router did not fail to report an outcome; **it has no outcome to report at this
       * point in the flow**, and a JSON logger omits an `undefined` field, so a structural absence
       * looked exactly like a fault. A field that can never be populated is worse than no field.
       *
       * **Where the verdict actually lands**, named here so the next reader does not have to find it
       * the hard way: a refusal is `document.frame.refused` (warn, carrying `kind` + `reason`,
       * emitted from `#enqueue`'s continuation under the same `correlationId`). Acceptance is
       * silent on this event. So "was this frame ingested?" is answered by joining on
       * `correlationId`, never by reading this line alone.
       */
      this.#logger.info("session.document.received", {
        sessionId,
        senderPubkey,
        contentHashHex,
        sequenceNumber: leafIndex,
        kind: routed.kind,
        // The verdict is asynchronous. Stated positively so absence is not mistaken for silence.
        dispatch: "queued",
        verdictEvent: "document.frame.refused",
        correlationId,
      });
      return { leafIndex };
    }

    const { leafIndex } = this.appendSessionLeaf(agentName, sessionId, "msg", contentHashHex, correlationId);
    // DOD-LOG-1: persist the readable RECEIVED plaintext to the durable transcript, keyed by the
    // canonical leaf sequence so it joins the committed hash chain (survives restart; INV-3 — the
    // relay/directory never see this plaintext, only the hash).
    const durable = this.recordTranscriptMessage(
      agentName, sessionId, leafIndex, "received", content, correlationId,
      // DOD-M15-SEALWIRE-1 bullet 5: present only when the ordering record verified AND the signer
      // matched this session's counterparty. Undefined on the soft fallback, which the row records
      // as `local_session_state` rather than leaving indistinguishable.
      verifiedAuthorship,
    );
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
    // DOD-M12B-LEAF-TRIGGERS-FETCH-1: the bytes are here, so cancel any fetch the witness leaf
    // scheduled. On a healthy session this is the branch that runs — the direct path beats the
    // grace window and the relay is never asked, which is what keeps a fetch off the hot path of
    // every message.
    this.#markContentResolved(agentName, sessionId, contentHashHex);
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
      stream = await this.#openContentStream(agentName, sessionId, entry, correlationId);
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
    const record = this.getSessionRecord(agentName, sessionId);
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
    const marked = this.#markCounterpartyAbandoned(agentName, sessionId);
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

  /** DOD-M12B-ABANDON-NOTIFY-1 — durable "they hung up" marker. Not a status: the session stays
   *  sealable, which is the whole point of not making this terminal. */
  #markCounterpartyAbandoned(agentName: string, sessionId: string): boolean {
    if (!this.#db) return false;
    try {
      const res = this.#db
        .prepare("UPDATE sessions SET counterparty_abandoned_at = ?, updated_at = ? WHERE agent_id = ? AND session_id = ? AND counterparty_abandoned_at IS NULL")
        .run(Date.now(), Date.now(), this.#requireAgentId(agentName), sessionId) as unknown as { changes?: number | bigint };
      // No rows changed means it was already marked — a duplicated notice, which must not
      // re-announce. "Did not throw" is not "landed"; the row count is the answer.
      return Number(res?.changes ?? 0) > 0;
    } catch (err: unknown) {
      this.#logger.error("session.counterparty.abandoned.write.failed", {
        agentName, sessionId,
        error: err instanceof Error ? err.message : String(err),
        impact: "this side will go on trying to reach a counterparty that has hung up",
      });
      return false;
    }
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
    const tier = this.getTier(agentName, counterpartyPubkey);
    const cap = this.resolveTierBound(agentName, tier, "max_sessions");
    const counted = this.countActiveSessionsForCounterparty(agentName, counterpartyPubkey);
    return {
      tier, cap, counted,
      // How many to close to get UNDER the cap — not how many exist. At 5 against a cap of 3 the
      // answer is 3, and "close 5" tells the operator to do more than the job needs.
      mustClear: Math.max(0, counted - cap + 1),
      blocked: tier === TIER.BLOCKED,
    };
  }

  /** DOD-CAP-SELF-HEAL-1: the sessions with this counterparty that are consuming cap slots, oldest
   *  first. The operator is told to close some — this is WHICH, because "close three of them" with
   *  no list is not an instruction they can follow. */
  sessionsConsumingCap(agentName: string, counterpartyPubkey: string, limit = 10): string[] {
    if (!this.#db) return [];
    try {
      const rows = this.#db.prepare(
        `SELECT session_id FROM sessions WHERE agent_id = ? AND counterparty_pubkey = ? AND ${CAP_COUNTS()}
         ORDER BY updated_at ASC LIMIT ?`,
      ).all(this.#requireAgentId(agentName), counterpartyPubkey, capStaleBefore(), limit) as Array<{ session_id: string }>;
      return rows.map((r) => r.session_id);
    } catch {
      return [];
    }
  }

  /** DOD-M12B-ABANDON-NOTIFY-1: has the counterparty told us they hung up? */
  counterpartyAbandonedAt(agentName: string, sessionId: string): number | null {
    if (!this.#db) return null;
    try {
      const row = this.#db
        .prepare("SELECT counterparty_abandoned_at FROM sessions WHERE agent_id = ? AND session_id = ?")
        .get(this.#requireAgentId(agentName), sessionId) as { counterparty_abandoned_at: number | null } | undefined;
      return row?.counterparty_abandoned_at ?? null;
    } catch {
      return null;
    }
  }

  /**
   * DOD-M12B-REDIAL-1 — open a content stream, re-dialling once if the connection has gone.
   *
   * `newStream` never dials. It looks for an already-open connection filed under the recorded peer
   * id and throws `connection_lost` when there is none — and NOTHING re-dialled: not on
   * `session.liveness.changed → gone`, not on signaling reconnect, not on agent offline→online, not
   * in the drain hook. So one blip and that session parked EVERY message for the rest of its life,
   * on both sides, permanently. The relay backstop kept the messages moving, which is exactly why
   * it hid: nothing was lost, the conversation just stopped being a conversation.
   *
   * DEMAND-DRIVEN, never a timer. A background re-dial loop is what produced the 2026-08-17
   * notification storm — surviving halves of abandoned sessions dialling continuously while the
   * operator saw connection requests from agents nobody was driving. This fires only when a send
   * actually needs the connection, and a cooldown bounds a burst against a peer that is genuinely
   * gone: five sends cost one dial, not five.
   */
  async #openContentStream(
    agentName: string,
    sessionId: string,
    entry: { node: CelloNode; counterpartySessionPeerId: string },
    correlationId?: string,
  ): Promise<Stream> {
    const attempt = async (): Promise<Stream> => {
      if (this.#connectionLossRemaining > 0) {
        this.#connectionLossRemaining -= 1;
        throw { reason: "no_connection", message: "injected connection loss" };
      }
      return entry.node.newStream(entry.counterpartySessionPeerId, CELLO_CONTENT_PROTOCOL_ID);
    };
    try {
      return await attempt();
    } catch (err: unknown) {
      const reason = (err as { reason?: string } | null)?.reason;
      // ONLY for a missing connection, and `no_connection` is the reason that means exactly that.
      // NOT `connection_lost`, which is the transport's catch-all default and therefore also covers
      // a stream that failed on a healthy connection — the per-protocol stream cap of
      // DOD-M12B-ACK-1. Dialling there fixes nothing and shows the counterparty a connection
      // request caused by a defect on this side, which is the storm this unit exists to avoid.
      if (reason !== "no_connection") throw err;

      const key = this.#k(agentName, sessionId);
      const addrs = this.#counterpartyAddrs.get(key);
      if (!addrs || addrs.length === 0) {
        // ABSENT IS NOT FINE, and it is not silent. A session we never dialled — the responder's
        // half — has no addresses to dial back with, and that is a real limitation the operator
        // should be able to see rather than infer from a park.
        this.#logger.warn("session.transport.redial.unavailable", {
          sessionId, agentName, correlationId,
          impact: "the direct path is down and this side holds no address for the counterparty, so every send parks until they re-establish",
        });
        throw err;
      }
      const now = Date.now();
      const notBefore = this.#redialNotBefore.get(key) ?? 0;
      if (now < notBefore) {
        this.#logger.debug("session.transport.redial.cooldown", {
          sessionId, agentName, retryInMs: notBefore - now, correlationId,
        });
        throw err;
      }
      this.#redialNotBefore.set(key, now + REDIAL_COOLDOWN_MS);
      this.#logger.info("session.transport.redial.attempted", { sessionId, agentName, addrs: addrs.length, correlationId });
      const reconnected = await this.connectToCounterparty(agentName, sessionId, addrs);
      if (!reconnected.ok) {
        this.#logger.warn("session.transport.redial.failed", {
          sessionId, agentName, reason: reconnected.reason, error: reconnected.error, correlationId,
        });
        throw err;
      }
      this.#logger.info("session.transport.redial.succeeded", { sessionId, agentName, correlationId });
      // Cleared so the NEXT blip is repaired immediately: the cooldown exists to bound a dead peer,
      // not to make a live one wait.
      this.#redialNotBefore.delete(key);
      return attempt();
    }
  }

  /**
   * DOD-M12B-INDEX-1 — commit THIS agent's own leaf at the position the relay assigned it.
   *
   * The receiver has always enforced "leaf index === canonical position": content witnessed ahead
   * of the next expected leaf is held, not appended out of order. The sender never did. It had the
   * position in hand — the relay answers about 4 ms before the append — and called a push-only
   * append that puts the leaf at the tail whatever the tail happens to be. While its own tree has
   * no gap the two agree and nothing shows; the first gap puts its leaf at someone else's index,
   * parts its root from the counterparty's, and the next seal gets `leaf_count_mismatch`, which is
   * terminal.
   *
   * DELIVERY IS NOT DEFERRED BY THIS. The caller has already put the bytes on the wire; only the
   * leaf waits for its slot, exactly as a received message does. Holding our own send is only
   * affordable because holds are durable (DOD-M12B-STRAND-1) — before that it would have risked
   * losing the message outright.
   *
   * `assignedSeq` absent means no ordering authority answered. That is the documented degradation
   * and it appends in arrival order as before: with no position there is no discipline to enforce,
   * and refusing would take messaging down whenever the relay is unreachable.
   */
  placeOwnLeaf(
    agentName: string,
    sessionId: string,
    contentHashHex: string,
    sentBytes: Uint8Array,
    assignedSeq: number | undefined,
    correlationId: string | undefined,
    /**
     * ⚠️ NO DEFAULT, for the same reason `authorship` has none.
     *
     * `kind = "msg"` meant a caller writing a `doc` or a `ctrl` leaf got a `msg` leaf by saying
     * nothing, and the tree recorded a leaf kind the author never chose. TypeScript also forbids a
     * required parameter after a defaulted one, so leaving the default here would have forced
     * `authorship` back to optional — which is the defect above. Every one of the seven call sites
     * already passed a kind or wanted "msg"; making it explicit cost nothing and removes a second
     * silent answer from the same signature.
     */
    kind: WritableSessionTreeLeafKind,
    /**
     * DOD-M15-SEALWIRE-1 bullet 5 — the proof for THIS send, so a held row keeps it.
     *
     * ⚠️ REQUIRED, AND `undefined` IS A VALID ANSWER — the two are not the same thing.
     *
     * This was `authorship?:` for exactly one review cycle, and in that cycle THREE of the seven
     * call sites omitted it: `daemon.ts` 1440, 1671, 1685 — the away-reply path, which is the
     * highest-traffic sent-writer in the daemon and the one with no human watching it. All three
     * had the proof **already in a local variable one line below**, handed to
     * `recordTranscriptMessage` and not to this method. Nothing went red, because an optional
     * parameter's whole behaviour on omission is to look deliberate.
     *
     * An unwitnessed send genuinely has no proof, so absence must stay expressible. Requiring the
     * parameter keeps that while making the caller SAY it: omission is now a type error, and
     * `undefined` is a claim the author made rather than one the signature made for them.
     */
    authorship: SentAuthorship | undefined,
  ): { placed: true; leafIndex: number; diverged?: true } | { placed: false; heldAt: number } {
    // Hydrate before reading the frontier: a durable hold this process has not read back yet would
    // make the tree look further along than it is.
    this.#ensureHeldRestored(agentName, sessionId);
    const nextExpected = this.getSessionTree(agentName, sessionId).size();

    if (assignedSeq === undefined) {
      const { leafIndex } = this.appendSessionLeaf(agentName, sessionId, kind, contentHashHex, correlationId);
      /**
       * ─── DOD-M15-UNWITNESSED-1(b): SAY IT HERE, where the code says the damage happens ────────
       *
       * This branch was entirely silent — no log, no flag — while the `position_behind_frontier`
       * branch twenty lines below logs at ERROR and its own comment says the loss occurred
       * *"at the unwitnessed append, not here."* So the system announced the consequence one send
       * later than it announced nothing about the cause.
       *
       * **This does NOT gate the seal, deliberately.** The DoD bar is explicit: do not gate on
       * suspicion, because a relay that has not witnessed a leaf YET is indistinguishable here from
       * one that never will, and refusing on the first would make a healthy session unsealable —
       * which is worse than the thing it guards. What was missing is not a refusal, it is the
       * ERROR at the moment the code already believes something was lost.
       */
      this.#logger.error("session.tree.own_leaf_unwitnessed", {
        sessionId,
        leafIndex,
        kind,
        correlationId,
        impact:
          "this message was appended to the local record with NO relay witness, so the ordering " +
          "authority has no copy of it. The counterparty's tree cannot gain this leaf from the " +
          "relay, so the two records may no longer agree — and a bilateral seal needs them to.",
        guidance:
          "Usually the relay was briefly unreachable and the next send re-establishes ordering. If " +
          "it repeats, the relay is not carrying this session: check connectivity before closing, " +
          "because sealing on a record the counterparty cannot match produces a receipt only one " +
          "side can verify.",
      });
      return { placed: true, leafIndex };
    }

    if (assignedSeq === nextExpected) {
      const { leafIndex } = this.appendSessionLeaf(agentName, sessionId, kind, contentHashHex, correlationId);
      return { placed: true, leafIndex };
    }

    if (assignedSeq < nextExpected) {
      // THE TREE AND THE RELAY HAVE ALREADY DIVERGED, and refusing here does not undo that.
      //
      // This side is AHEAD of the relay's counter, which happens by design: a message whose relay
      // submit failed still appends unwitnessed (the documented degradation). From then on every
      // ack comes back behind our frontier and the two can never agree again — the seal was already
      // lost at the unwitnessed append, not here.
      //
      // So the choice is between a record that is short by every subsequent message and one that is
      // complete but skewed. Appending at the tail keeps the operator's own words in their own
      // transcript, which is worth more than a tidiness the roots cannot recover anyway; writing
      // over the assigned slot is the one thing never done, because that rewrites a leaf a root has
      // already been computed over. The divergence is reported at ERROR and carried to the caller
      // rather than dressed up as an ordinary success.
      this.#logger.error("session.tree.position_behind_frontier", {
        agentName, sessionId, assignedSeq, nextExpected, contentHash: contentHashHex, correlationId,
        impact: "this side's tree is ahead of the relay's counter, so the two can no longer agree on a root — the message is kept in the local record and this session can no longer be sealed bilaterally",
      });
      this.markSessionDiverged(agentName, sessionId);
      const { leafIndex } = this.appendSessionLeaf(agentName, sessionId, kind, contentHashHex, correlationId);
      return { placed: true, leafIndex, diverged: true };
    }

    // Ahead of the tail: hold it, exactly as the receiver holds theirs, and let #releaseHeld put it
    // in at its own index when the gap fills.
    const key = this.#k(agentName, sessionId);
    let held = this.#heldContent.get(key);
    if (!held) { held = new Map(); this.#heldContent.set(key, held); }
    held.set(assignedSeq, { content: sentBytes, contentHashHex, correlationId, origin: "sent", kind, ...(authorship ? { authorship } : {}) });
    this.#persistHeldContent(agentName, sessionId, assignedSeq, sentBytes, sentBytes, contentHashHex, false, correlationId, "sent", kind);
    this.#logger.info("session.content.held", {
      sessionId, canonicalSeq: assignedSeq, nextExpected, gap: assignedSeq - nextExpected,
      origin: "sent", correlationId,
    });
    return { placed: false, heldAt: assignedSeq };
  }

  /**
   * DOD-M12B-STRAND-1 — write one held frame to the durable store.
   *
   * LOGS LOUD, does not refuse. The caller answers `held: true` either way, and that is correct:
   * held content is never `persisted`-acked, so the sender keeps its copy and retries whether or
   * not this row lands. What a failure costs is the restart case — the frame is memory-only again,
   * exactly as it was before this unit — so it is reported at ERROR here and counted again by the
   * teardown alarm, and never allowed to look like a success.
   */
  #persistHeldContent(
    agentName: string,
    sessionId: string,
    canonicalSeq: number,
    deliverContent: Uint8Array,
    originalContent: Uint8Array,
    contentHashHex: string,
    screenedOut: boolean,
    correlationId?: string,
    origin: "received" | "sent" = "received",
    leafKind: WritableSessionTreeLeafKind = "msg",
  ): void {
    if (!this.#db) return;
    try {
      // A position may legitimately be re-written by a redelivery of the SAME frame. Different
      // content at the same relay position means the relay contradicted itself, and destroying the
      // first copy silently is not an option for verified content.
      const existing = this.#db.prepare(
        "SELECT content_hash_hex FROM held_content WHERE agent_id = ? AND session_id = ? AND canonical_seq = ?",
      ).get(this.#requireAgentId(agentName), sessionId, canonicalSeq) as { content_hash_hex: string } | undefined;
      if (existing && existing.content_hash_hex !== contentHashHex) {
        this.#logger.error("session.content.held.position_conflict", {
          agentName, sessionId, canonicalSeq, correlationId,
          existingContentHash: existing.content_hash_hex, incomingContentHash: contentHashHex,
          impact: "two different frames claim one canonical position — the earlier held copy is being replaced",
        });
      }
      this.#db.prepare(
        `INSERT OR REPLACE INTO held_content
           (agent_id, session_id, canonical_seq, content_blob, original_blob, content_hash_hex, screened_out, correlation_id, held_at, origin, leaf_kind)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run(
        this.#requireAgentId(agentName), sessionId, canonicalSeq,
        Buffer.from(deliverContent), Buffer.from(originalContent), contentHashHex,
        screenedOut ? 1 : 0, correlationId ?? null, Date.now(), origin, leafKind,
      );
    } catch (err: unknown) {
      this.#logger.error("session.content.held.persist.failed", {
        agentName, sessionId, canonicalSeq, contentHash: contentHashHex, correlationId,
        impact: "this frame is held IN MEMORY ONLY and will be destroyed if the daemon restarts",
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  /** DOD-M12B-STRAND-1 — drop one held frame from the durable store, on release or on a refusal
   *  that supersedes it. A row that outlives its release re-appends on the next boot. */
  #deleteHeldContent(agentName: string, sessionId: string, canonicalSeq: number): void {
    if (!this.#db) return;
    try {
      this.#db.prepare(
        "DELETE FROM held_content WHERE agent_id = ? AND session_id = ? AND canonical_seq = ?",
      ).run(this.#requireAgentId(agentName), sessionId, canonicalSeq);
    } catch (err: unknown) {
      this.#logger.error("session.content.held.delete.failed", {
        agentName, sessionId, canonicalSeq,
        impact: "the released frame's durable row survives and will be re-appended on the next boot",
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  /**
   * DOD-M12B-STRAND-1 — restore this session's held frames into memory.
   *
   * Called when a session node is (re)created, which is the moment the session becomes able to
   * append again. Loading at daemon boot instead would be wrong for the same reason the old code
   * was wrong: a frame is only releasable against a tree, and the tree is loaded per session.
   *
   * A frame whose content the tree ALREADY HOLDS at that position is dropped — re-appending it
   * would change the root a seal signs over. That test is `hashAt`, not `canonical_seq < frontier`:
   * the two counters are different spaces and this file documents them drifting, so the index
   * comparison alone would destroy a frame the tree never held. See the drift branch below.
   */
  #ensureHeldRestored(agentName: string, sessionId: string, opts?: { release?: boolean }): void {
    const key = this.#k(agentName, sessionId);
    if (!this.#heldRestored.has(key)) {
      // Set BEFORE restoring, so the #ensureHeldRestored inside #releaseHeld below returns straight
      // away instead of recursing.
      this.#heldRestored.add(key);
      this.#restoreHeldContent(agentName, sessionId);
    }
    // A RESTORED FRAME MAY ALREADY BE IN ORDER, and nothing else would ever notice.
    //
    // #releaseHeld has one caller: the tail of a successful inbound ingest. Every other way the tree
    // grows — an outbound send leaf, a queued or rejected leaf — advances the frontier without
    // draining. While holds died with the session node that cost seconds; now the hold is durable,
    // so the stall is durable too: the counterparty's message sits on disk at exactly the next slot,
    // is never delivered, and `sealReadiness` counts it, so the session cannot close either.
    // Undeliverable AND unsealable, forever, from one restart.
    //
    // TRACKED SEPARATELY FROM THE HYDRATION. A read-only caller (the status surface) hydrates and
    // must NOT release — otherwise `cello status` appends leaves, advances the session root, writes
    // transcript rows and rings the doorbell, which makes a diagnostic command the thing that
    // delivers messages. One shared flag would also let that read CONSUME the release the next real
    // ingest was going to perform, which is the stall above, reintroduced.
    if (opts?.release === false) return;
    if (this.#heldReleased.has(key)) return;
    this.#heldReleased.add(key);
    if (this.#heldContent.get(key)?.size) {
      const counterparty = this.getSessionRecord(agentName, sessionId)?.counterparty_pubkey;
      if (counterparty) this.#releaseHeld(agentName, sessionId, counterparty);
    }
  }

  #restoreHeldContent(agentName: string, sessionId: string): void {
    if (!this.#db) return;
    let rows: Array<{ canonical_seq: number; content_blob: Buffer; original_blob: Buffer | null; content_hash_hex: string; screened_out: number; correlation_id: string | null; origin: string; leaf_kind: string }>;
    try {
      rows = this.#db.prepare(
        `SELECT canonical_seq, content_blob, original_blob, content_hash_hex, screened_out, correlation_id, origin, leaf_kind
           FROM held_content WHERE agent_id = ? AND session_id = ? ORDER BY canonical_seq ASC`,
      ).all(this.#requireAgentId(agentName), sessionId) as never;
    } catch (err: unknown) {
      this.#logger.error("session.content.held.restore.failed", {
        agentName, sessionId,
        impact: "verified content held before the restart is not in memory and cannot be released",
        error: err instanceof Error ? err.message : String(err),
      });
      return;
    }
    if (rows.length === 0) return;
    const key = this.#k(agentName, sessionId);
    let held = this.#heldContent.get(key);
    if (!held) { held = new Map(); this.#heldContent.set(key, held); }
    const tree = this.getSessionTree(agentName, sessionId);
    const frontier = tree.size();
    let restored = 0;
    let superseded = 0;
    let drifted = 0;
    for (const row of rows) {
      // ASK THE TREE WHAT IS AT THAT POSITION — do not infer it from the index.
      //
      // `canonical_seq` is the RELAY's sequence space; `frontier` is this tree's msg-leaf count.
      // The two drift, on purpose and by documented cases: the relay counts CTRL leaves the tree
      // never appends, and a first message whose relay submit failed leaves the tree one ahead.
      // Under drift `canonical_seq < frontier` is TRUE for a frame the tree has never held, and
      // deleting on that comparison destroys verified content while reporting it as tidy-up —
      // the exact failure this unit exists to end, reintroduced on the recovery path.
      const occupant = tree.hashAt(row.canonical_seq);
      if (occupant === row.content_hash_hex) {
        this.#deleteHeldContent(agentName, sessionId, row.canonical_seq);
        superseded++;
        continue;
      }
      if (row.canonical_seq < frontier) {
        // The position is taken by DIFFERENT content. The frame cannot be appended (that would
        // rewrite a committed leaf) and must not be deleted (it is verified content nobody else
        // holds), so it goes to the annex that exists for exactly this — content that arrived for
        // a chain that can no longer carry it — and only then does the row go.
        const annexed = this.recordSealedAnnex(
          agentName, sessionId, row.content_hash_hex, new Uint8Array(row.content_blob),
          // DOD-M12B-INDEX-1: our own held send is attributed to US, never to the counterparty.
          row.origin === "sent"
            ? this.#ownPubkeyHex(agentName)
            : this.getSessionRecord(agentName, sessionId)?.counterparty_pubkey ?? null,
        );
        this.#logger.error("session.content.held.position_drifted", {
          agentName, sessionId, canonicalSeq: row.canonical_seq, frontier,
          contentHash: row.content_hash_hex, occupant, annexed,
          correlationId: row.correlation_id ?? undefined,
          impact: annexed
            ? "the relay's position for this frame is occupied by different content — it cannot join the chain and is readable only from the annex"
            : "the relay's position for this frame is occupied by different content AND the annex write failed — the durable row is kept rather than destroyed",
        });
        if (annexed) this.#deleteHeldContent(agentName, sessionId, row.canonical_seq);
        drifted++;
        continue;
      }
      held.set(row.canonical_seq, {
        content: new Uint8Array(row.content_blob),
        ...(row.original_blob ? { originalContent: new Uint8Array(row.original_blob) } : {}),
        contentHashHex: row.content_hash_hex,
        ...(row.correlation_id ? { correlationId: row.correlation_id } : {}),
        ...(row.screened_out ? { screenedOut: true } : {}),
        ...(row.origin === "sent" ? { origin: "sent" as const } : {}),
        ...(row.leaf_kind === "doc" ? { kind: "doc" as const } : {}),
        /**
         * ⚠️ `restoredAcrossRestart` EXISTS TO NAME A LOSS, NOT TO CHANGE BEHAVIOUR — review pass 2, H1.
         *
         * `held_content` has no authorship columns, so a SENT message held behind a gap and released
         * after a daemon restart comes back with **no signature** — its transcript row records
         * `self_authored` with no proof, indistinguishable from an unwitnessed send. That is the
         * defect bullet 5 exists to end, reappearing on the recovery path, and it was silent.
         *
         * The proof cannot be reconstructed here: it was made over Structure-1 bytes this process no
         * longer holds. **So the honest move is to say so, not to fabricate one** — a proof that
         * cannot be checked, presented as one that can, is worse than the absence.
         *
         * Two BLOB columns would close it properly (this table already carries two `ALTER TABLE …
         * ADD COLUMN` migrations, so the pattern exists). Under a frozen gate a log is additive and
         * tightenable where a schema change is neither, so this announces the loss now and
         * `DOD-M15-HELD-AUTHORSHIP-1` carries the column.
         */
        restoredAcrossRestart: true,
      });
      restored++;
    }
    if (held.size === 0) this.#heldContent.delete(key);
    this.#logger.info("session.content.held.restored", {
      agentName, sessionId, restored, superseded, drifted, frontier,
      canonicalSeqs: [...held.keys()].sort((a, b) => a - b),
      // The flow ids of the frames that came back, so a restored message ties to the
      // `session.content.held` that opened its flow before the restart.
      correlationIds: rows.map((r) => r.correlation_id).filter((c): c is string => c !== null),
    });
  }

  /**
   * DOD-MSG-4: drain held out-of-order content in canonical order. After a leaf is appended, any
   * held entry whose canonical sequence equals the new next-expected index is now in order — append
   * it, then check again (a single fill can release a run of consecutive held messages).
   */
  #releaseHeld(agentName: string, sessionId: string, senderPubkey: string): number {
    const key = this.#k(agentName, sessionId);
    // DOD-M12B-STRAND-1: hydrate before scanning. Restoring eagerly at session-node creation put
    // it behind writes that can fail — one failed `sessions` row upsert and the frames stayed on
    // disk, invisible, which is the same outcome as losing them.
    this.#ensureHeldRestored(agentName, sessionId);
    const held = this.#heldContent.get(key);
    if (!held) return 0;
    let released = 0;
    for (;;) {
      const nextExpected = this.getSessionTree(agentName, sessionId).size();
      const entry = held.get(nextExpected);
      if (!entry) break;
      held.delete(nextExpected);
      // DOD-M12B-STRAND-1: released content leaves the durable store in the same breath. A row
      // that outlives its release would re-append the same content on the next boot — growing the
      // tree and changing a root that has already been signed.
      this.#deleteHeldContent(agentName, sessionId, nextExpected);
      // DOD-M12B-INDEX-1: OUR OWN held message. It leafs at its canonical index and is transcribed
      // as SENT — never routed down the received path, which would attribute our words to the
      // counterparty in the sealed record and hand them back to our own agent as inbound.
      if (entry.origin === "sent") {
        // The KIND the leaf was placed with, not a hardcoded "msg" — a document leaf that had to
        // wait for its position must come back as a document leaf, or the two sides disagree about
        // what the chain contains.
        this.appendSessionLeaf(agentName, sessionId, entry.kind ?? "msg", entry.contentHashHex, entry.correlationId);
        // A DOCUMENT frame takes a leaf and NO transcript row — matching what the immediate-append
        // path does for one. Writing one would put raw CBOR into the operator's transcript as
        // something they said, which is the same attribution failure as releasing it inbound.
        if (entry.kind === "doc") {
          released++;
          this.#logger.info("session.content.released", {
            sessionId, sequenceNumber: nextExpected, leafKind: "doc", correlationId: entry.correlationId,
          });
          if (held.size === 0) { this.#heldContent.delete(key); break; }
          continue;
        }
        // OBSERVED, not assumed — the received path already does this. The leaf commits either way,
        // so a dropped transcript write means the operator's OWN message is missing from their own
        // transcript with the chain saying it is there, and nothing anywhere said so.
        // bullet 5: the proof was captured at submit time and rides the held entry — see #heldContent.
        /**
         * THE RESTART LOSS, ANNOUNCED — review pass 2, H1. Only for an entry that actually crossed a
         * restart: an in-memory held entry carries its proof, and an unwitnessed send legitimately
         * has none, so warning on every absent proof would fire on a designed benign state and bury
         * the one occurrence that means something.
         */
        if (entry.restoredAcrossRestart === true && entry.authorship === undefined) {
          this.#logger.warn("session.content.released.authorship.lost", {
            agentName, sessionId, sequenceNumber: nextExpected, correlationId: entry.correlationId,
            impact:
              "this message was held behind a gap, survived a daemon restart, and is now committed with " +
              "attribution 'self_authored' and NO signature. Its transcript row asserts its author rather " +
              "than proving one, and is indistinguishable from a send the relay never witnessed.",
            guidance:
              "Not recoverable after the fact — the signature covered Structure-1 bytes this process no longer " +
              "holds, and fabricating one would be worse than the absence. Tracked as DOD-M15-HELD-AUTHORSHIP-1: " +
              "held_content needs the two proof columns so a restart carries them.",
          });
        }
        if (!this.recordTranscriptMessage(agentName, sessionId, nextExpected, "sent", entry.content, entry.correlationId, entry.authorship)) {
          this.#logger.error("session.content.released.transcript.failed", {
            agentName, sessionId, sequenceNumber: nextExpected, correlationId: entry.correlationId,
            impact: "this side's own message is committed to the chain but missing from its transcript",
          });
        }
      } else if (entry.screenedOut) {
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
  /**
   * `contentHashAlg` is `string | undefined`, NOT optional — B2b-1 pass-2 F1.
   *
   * The previous fix applied this shape to `#parkContent` and left its SIBLING on the same code path
   * optional, so dropping the argument here compiled clean and no test could see it — the TTF park
   * route reads this map, and a v2 envelope omits the field entirely whenever the value is `sha256`,
   * which is every value in play today. That re-opened the exact finding the fix closed.
   */
  #trackAwaitingAck(agentName: string, sessionId: string, content: Uint8Array, contentHash: Uint8Array, correlationId: string | undefined, structure1Cbor: Uint8Array | undefined, structure2Cbor: Uint8Array | undefined, contentHashAlg: string | undefined): void {
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
    // B2b-1 review F2: the algorithm rides WITH the entry. The TTF-expiry park route reads this map
    // minutes later, in-process, and without it that copy names nothing (= sha256) while the direct
    // frame named something else — the same message, two claims about what it is, no restart needed.
    bySession.set(hashHex, { timer, content, correlationId, structure1Cbor, structure2Cbor, contentHashAlg });
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
      this.#onAwaitingTtf?.(agentName, sessionId, hashHex, entry.content, entry.structure1Cbor, entry.structure2Cbor, entry.contentHashAlg);
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
    void this.#parkContent(agentName, sessionId, hashHex, entry.content, entry.structure1Cbor, entry.structure2Cbor, entry.contentHashAlg);
  }

  /**
   * Send an unsigned `persisted` delivery ACK back to the sender over the same
   * /cello/content/1.0.0 protocol (AC-001). Best-effort: authentication is the Noise
   * session channel, so the ACK carries no signature; a failed ACK send is logged and
   * the sender recovers via its TTF/recovery path rather than a thrown error here.
   */
  async #sendDeliveryAck(agentName: string, sessionId: string, contentHash: Uint8Array, correlationId?: string): Promise<void> {
    const entry = this.#activeNodes.get(this.#k(agentName, sessionId));
    if (!entry) {
      // NOT a silent return. No ACK is exactly this milestone's symptom — the sender's TTF expires
      // and the message parks — so the one case where we knowingly decline to send one has to say
      // so, or it is indistinguishable from the defect.
      this.#logger.debug("content.delivery.ack.skipped", {
        agentName,
        sessionId,
        contentHash: Buffer.from(contentHash).toString("hex"),
        reason: "session_node_gone",
        correlationId,
      });
      return;
    }
    // Held outside the try so the catch can retire a stream that was opened and then failed to
    // write. Without it every failure leaks the OUTBOUND half of the stream the receiver-side
    // `finally` retires — same defect, other end, other cap. See the note on #handleContentStream.
    // Assigned IMMEDIATELY after newStream: anything between the two is a window where a throw
    // leaks the stream because the catch cannot see it.
    let ackStream: Stream | undefined;
    try {
      const stream = await entry.node.newStream(entry.counterpartySessionPeerId, CELLO_CONTENT_PROTOCOL_ID);
      ackStream = stream;
      // Injected ACK-write failure — thrown from inside the try so it lands in exactly the catch a
      // real reset lands in, and the whole downstream path (impair → abort → log) runs unmodified.
      if (this.#ackFaultRemaining > 0) {
        this.#ackFaultRemaining -= 1;
        this.#logger.warn("content.delivery.ack.fault.injected", { sessionId });
        throw new Error("connection_lost: injected delivery-ack fault");
      }
      const frame = encodeCbor({
        type: "content_delivery_ack",
        session_id: sessionId,
        content_hash: contentHash,
        level: "persisted",
        correlation_id: correlationId,
      }) as Uint8Array;
      stream.send(lp.encode.single(frame));
      // NOT SWALLOWED, for the same reason the direct-send path stopped swallowing it: `close()`
      // waits for the write buffer to drain, so a reset mid-flush throws HERE and that is exactly
      // the case where the bytes never left. A swallowed close made two things happen at once —
      // this log claimed the ACK went out while the sender's TTF fired and parked, and the abort in
      // the catch below (the thing that frees the stream slot) became unreachable.
      await stream.close();
      // AFTER the close, because that is when it is true. The receiver-side counterpart to the
      // sender's content.delivery.acked: B has acknowledged this content `persisted`, so the sender
      // stops retrying/parking. Emitted for BOTH a normally delivered message AND a terminal-screen
      // block (the block is a definitive receipt — the leaf is recorded, so the sender must stop) —
      // and deliberately NOT for a transient hold.
      this.#logger.info("content.delivery.ack.sent", {
        sessionId,
        contentHash: Buffer.from(contentHash).toString("hex"),
        correlationId,
      });
      // An agent that mostly LISTENS sends content rarely and ACKs constantly. Clearing only on the
      // content path would leave exactly those sessions reporting a broken conversation forever
      // after one bad ACK — the one-way door, on the other send path.
      this.#clearSessionImpairment(agentName, sessionId, "delivery_ack", correlationId);
    } catch (err: unknown) {
      this.#logger.warn("content.delivery.ack.send.failed", {
        sessionId,
        contentHash: Buffer.from(contentHash).toString("hex"),
        error: err instanceof Error ? err.message : String(err),
        // "Cannot write to a stream that is closed" names where the write died, never why. The
        // why is almost always the per-protocol stream cap, and these two numbers are what turn
        // that from a log-measurement session into a grep.
        ...this.#streamCensus(entry.node, entry.counterpartySessionPeerId),
        correlationId,
      });
      // The ACK travels the same direct path as our own content, so a failure here is the same
      // evidence: writes to this counterparty are not landing.
      this.#markSessionImpaired(agentName, sessionId, { cause: "delivery_ack", error: err instanceof Error ? err.message : String(err), correlationId });
      if (ackStream !== undefined) {
        try { ackStream.abort(err instanceof Error ? err : new Error(String(err))); } catch { /* already gone */ }
      }
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
      await node.handle(CELLO_CONTENT_PROTOCOL_ID, (stream, remotePeerId) => {
        // `.catch` is not decoration: the handler builds its length-prefixed decoder before its own
        // try, and a throw there would otherwise become an unhandled rejection that takes the
        // daemon down for one malformed inbound stream.
        void this.#handleContentStream(agentName, sessionId, stream, remotePeerId).catch((err: unknown) => {
          this.#logger.warn("session.content.stream.handler.failed", {
            sessionId,
            error: err instanceof Error ? err.message : String(err),
          });
        });
      }, { maxInboundStreams: CONTENT_MAX_INBOUND_STREAMS });
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

    /**
     * DOD-M15-SEALWIRE-1 part B1 — RECOVERED-FROM-PARK CONTENT CARRIES NO ALGORITHM NAME, and that
     * is correct today rather than an oversight.
     *
     * The park envelope has no field for one, so this passes `undefined`, which resolves to
     * `sha256`. In part B1 that was exactly right and provably so: no sender salted, so every parked
     * entry in existence had been hashed unsalted.
     *
     * ✅ FIXED IN PART B2a, at BOTH sites: here, and the independent verifier in `content-park.ts`.
     * The envelope carries the algorithm from v3 onward, and a v2 envelope's absent field resolves to
     * `sha256` — which is what a peer predating the field actually used.
     *
     * > **⛔ THE LAST SENTENCE HERE READ "Every envelope this build emits is still v2, because
     * > nothing salts yet." THAT IS FALSE NOW.** B2b-2 turned salting on: a session holding an
     * > agreed salt hashes under `hmac-sha256-salt-v1`, so this build DOES emit v3 envelopes.
     * > Rewritten rather than deleted, per `DOD-M15-CLAIM-COMMENTS-1` — the sentence is why the
     * > staleness survived, and an absence would read as deliberate.
     * >
     * > The consequence is not theoretical: a v2 envelope carrying a SALTED hash recomputes unsalted
     * > at the far end and reports `content_hash_mismatch` — a false tamper claim on honest content,
     * > which also blocks auto-co-sign at seal. Measured on 2026-08-24.
     *
     * ─── AND THE REFUSAL DOES NOT HOLD — review F2 ────────────────────────────────────────────
     *
     * A direct-path refusal sends no delivery ACK, so the sender's TTF backstop parks the message
     * and it arrives here seconds later, where `undefined` means `sha256` and it may well succeed.
     * A frame refused BY NAME on one path is then accepted on the other, with nothing tying the two
     * together in the log — an operator sees an ERROR and, ten seconds on, a healthy delivery.
     *
     * That is not repaired by refusing here as well: today's park entry genuinely IS `sha256`, and
     * refusing it would drop good mail. What is wrong is the SILENCE, so the reconciliation is
     * logged instead — the two events become one story, and B2 removes the ambiguity for real by
     * putting the name in the envelope.
     */
    /**
     * ⚠️ LOGGED AFTER THE INGEST, NOT BEFORE IT — review B2a F1, and the previous version of this
     * block ANNOUNCED A DELIVERY THAT DOES NOT HAPPEN.
     *
     * It fired on a memo hit and said *"the message is being delivered by the other route"*, which
     * was true-by-construction only while the park path passed `undefined` for the algorithm. Part
     * B2a made the park path carry `env.contentHashAlg` — so a peer that names an unreadable
     * algorithm on the direct path AND parks the same content as v3 with the same name is refused
     * AGAIN here, re-arms the memo, is never confirm-deleted, and repeats on every drain. An
     * unbounded stream of warnings asserting a delivery that never occurs, drowning the real
     * reconciliation when the sender eventually re-parks as v2.
     *
     * The claim is only sound once the ingest has actually succeeded, so it is made there.
     */
    const memoKey = this.#k(agentName, sessionId);
    const priorDeclaredAlg = this.#unreadableAlgSeen.get(memoKey)?.get(contentHashHex);
    const result = await this.ingestReceivedContent(
      agentName, sessionId, env.content, contentHash, correlationId, recoveredSeq ?? undefined,
      // The envelope's own claim, verbatim — `undefined` on a v2 envelope, which resolves to
      // `sha256` and is exactly right for a peer that predates the field.
      env.contentHashAlg,
    );
    /**
     * `ok` IS NOT "DELIVERED" — review B2a pass-2 F1, and this is the same class the F1 fix was
     * raised for, one predicate over.
     *
     * `ingestReceivedContent` returns `ok` in three shapes and only one is a delivery:
     *   `{ok, held: true}`       — buffered behind an ordering gap; not appended, not shown YET.
     *   `{ok, screenedOut: true}` — leafed and PERMANENTLY never shown to the agent.
     * Announcing *"the message was delivered by the other route"* for either is a false all-clear on
     * the operator's one line about this message, and the memo is deleted in the same breath, so
     * nothing ever re-raises it.
     *
     * Leaving the memo ARMED on `held` is deliberate: the release path re-enters ingest, which is
     * when delivery actually happens, and the claim becomes true there.
     *
     * ⚠️ THE `screenedOut` CLAUSE IS UNREACHABLE TODAY and is kept anyway — said out loud so nobody
     * reads it as covered. A terminal inbound block needs a detector the shipping security gateway
     * does not wire, so it returns only `allow` and a fail-closed non-terminal `block`. Measured: a
     * mutant dropping just that clause SURVIVES the suite. It stays because the day a detector is
     * wired, this line is the difference between an all-clear and a permanent silent discard — and
     * finding that then costs more than the clause costs now.
     */
    if (priorDeclaredAlg !== undefined && result.ok && result.held !== true && result.screenedOut !== true) {
      // Cleared ONLY on a real reconciliation. Clearing on the lookup (as this did) forgets the
      // refusal even when the recovery fails, so the next genuine reconciliation says nothing.
      const byHash = this.#unreadableAlgSeen.get(memoKey);
      byHash?.delete(contentHashHex);
      if (byHash && byHash.size === 0) this.#unreadableAlgSeen.delete(memoKey);
      this.#logger.warn("content.recover.alg_refusal_reconciled", {
        agentName, sessionId, correlationId,
        contentHash: contentHashHex,
        priorDeclaredAlg,
        recoveredAlg: env.contentHashAlg ?? "(absent → sha256)",
        impact: "THIS EXACT MESSAGE was refused on the direct path because it named an algorithm this build cannot read, and the same content has now been accepted via the relay park under an algorithm this build CAN read. The refusal did not hold: the message was delivered by the other route.",
      });
    }
    return result;
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
    // DOD-M15-FRAME-1: the POSITION only, deliberately — this path does not act on `fatal`, and the
    // reason is that its identity proof is somewhere else and is already fail-closed. Parked content
    // arrives inside a sealed envelope carrying the sender's signature over
    // (session_id, recipient_pubkey, content_hash), and recovery already refuses a missing, bad, or
    // wrong-signer envelope. Adding a second, weaker refusal here on the ordering record would gate
    // mail retrieval on a record the relay-degraded path is allowed to omit, which is the
    // false-positive shape this unit is careful to avoid. The live direct path is where the ordering
    // record IS the proof, and that is where `fatal` is consumed.
    return this.#recordFrameOrdering(agentName, sessionId, structure1Cbor, structure2Cbor, contentHash, correlationId, "park").seq;
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
   * DOD-M15-FRAME-1 — a proven identity failure ends the session, and says so as an OBSERVATION.
   *
   * SESSION-ENDING, NOT PER-MESSAGE. One frame that fails to verify against the expected
   * counterparty is not a bad message to drop while hoping the next is better — it is evidence
   * about the CONNECTION. Dropping the frame and continuing leaves the same peer able to try again
   * with a frame that omits the proof entirely.
   *
   * THE WORDING IS NOT A VERDICT, and that is deliberate rather than squeamish. The identical
   * signal comes from a real impersonation attempt and from our own infrastructure mishandling a
   * fallback — a relay bug, a bad deploy, an uncovered edge in the direct-connection failover. The
   * daemon cannot tell those apart from this signal, so it must not pretend to. This mirrors the
   * account-recovery pattern already in the codebase, which anchors a compromise window to logged
   * events and accepts that some evidence cannot separate misconduct from an innocent cause.
   *
   * IT MUST NEVER FEED A TRUST SIGNAL. An automatic reputation consequence driven by a signal this
   * ambiguous would let a hostile peer — or a bad deploy of ours — manufacture a mark against an
   * innocent counterparty. Recorded here because the absence of that wiring is a decision, not an
   * omission, and the next person to reach for it should find this comment first.
   *
   * The accusatory half stays local for the same reason. Freezing what THIS daemon trusts is always
   * safe unilaterally; asserting on the record that a counterparty misbehaved needs corroboration
   * from a party the accusing client does not control, which is `DOD-M15-CORROBORATE-1` (the relay
   * holds the sender's signed hash independently and never routes it through the receiver).
   */
  /**
   * DOD-M15-SEALWIRE-1 bullet 6 (part A) — THE SALT AGREEMENT, the I/O half.
   *
   * The decisions live in `session-salt-agreement.ts` as a pure function; everything here is the
   * three things that function cannot do: read and write the durable row, put a frame on the wire,
   * and stop a session.
   *
   * ─── Where a contribution may travel, and it is the one rule that cannot be fixed later ───────
   *
   * `/cello/content/1.0.0` ONLY. It rides circuit-relay-v2 carrying its own Noise session, so a
   * relay forwarding it sees ciphertext. It must never be added to `session_offer` /
   * `session_offer_accept` or anything a DIRECTORY brokers — and that is the trap, because the only
   * round trip at session open today runs on the directory's signaling stream, which makes it the
   * obvious place to put one. A session that shipped it there could not be repaired: the relay
   * would already hold the salt and every hash it protects.
   */
  /**
   * MINT THIS SESSION'S THROWAWAY KEYPAIR — once, at the moment the session becomes active.
   *
   * Idempotent on purpose. Three paths make a session active (open, hand-off from the standing
   * receiver, revive) and a reconnect can re-enter them; minting a second keypair mid-session would
   * leave the two sides deriving against a moving value, and the symptom — a session that reconnects
   * and still cannot agree — reads as a network fault rather than as a bug here. `#saltContributionFor`
   * mints once for exactly the same reason.
   *
   * A REVIVED session is not an exception. `#evictSessionCaches` destroyed the previous secret at
   * teardown and it was never persisted, so there is nothing left to be consistent with: a revival
   * mints fresh and re-keys (Decisions Carried #5).
   */
  #mintSessionEphemeral(agentName: string, sessionId: string): void {
    const key = this.#k(agentName, sessionId);
    if (this.#sessionEphemerals.has(key)) return;
    this.#sessionEphemerals.set(key, generateSessionEphemeral());
    this.#logger.debug("session.ephemeral.minted", {
      agentName, sessionId,
      // The PUBLIC half only, and only a prefix of it. The secret must never reach a log line, and
      // an operator correlating two daemons needs an identifier rather than the value.
      publicKeyPrefix: Buffer.from(this.#sessionEphemerals.get(key)!.publicKey.subarray(0, 8)).toString("hex"),
    });
  }

  /**
   * Our throwaway keypair for a session, WITHOUT minting one — the read-only counterpart.
   *
   * `null` means the session is not active here. It never means "mint one now": minting outside
   * `#mintSessionEphemeral` is how a second keypair appears mid-session.
   */
  #sessionEphemeralFor(agentName: string, sessionId: string): SessionEphemeral | null {
    return this.#sessionEphemerals.get(this.#k(agentName, sessionId)) ?? null;
  }

  #saltContributionFor(agentName: string, sessionId: string): Uint8Array {
    const key = this.#k(agentName, sessionId);
    let contribution = this.#saltContributions.get(key);
    if (!contribution) {
      contribution = generateSaltContribution();
      this.#saltContributions.set(key, contribution);
    }
    return contribution;
  }

  /**
   * Our half for a session, **without minting one** — review F1, and the distinction is the whole
   * safety of the repair.
   *
   * A session that already holds a salt must never mint a fresh half. If it did, the repair would
   * offer the peer a half the stored salt was NOT derived from, they would compute a different salt,
   * and both sides would believe they had agreed — silently, which is the one outcome worse than
   * refusing. So `null` from here means exactly "we hold a salt and the half behind it is gone",
   * and that is the only state the agreement is allowed to call unrepairable.
   */
  #ownSaltHalf(agentName: string, sessionId: string): Uint8Array | null {
    return this.#saltContributions.get(this.#k(agentName, sessionId)) ?? null;
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

  setSaltContributionForTest(agentName: string, sessionId: string, contribution: Uint8Array): void {
    this.#saltContributions.set(this.#k(agentName, sessionId), contribution);
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
    await this.#handleSaltFrame(agentName, sessionId, frame, correlationId);
  }

  /**
   * Test seam: drop this session's own half while leaving the stored salt in place — the state every
   * teardown produces, because `#evictSessionCaches` clears the map and the row survives.
   *
   * It clears the SAME map the eviction clears rather than a stand-in, so a test cannot pass against
   * a state the daemon never reaches. Reproducing it through a real teardown/revive would also drag
   * in node rebuild and relay reconnection, none of which this is about.
   */
  forgetSaltContributionForTest(agentName: string, sessionId: string): void {
    this.#saltContributions.delete(this.#k(agentName, sessionId));
  }

  /**
   * The pair the agreement reasons over: our salt, and the half that goes with it.
   *
   * Minting is deliberate and conditional. With NO salt we are certain to need a half — to offer, or
   * to derive with — so minting here is what makes the exchange work at all. WITH a salt we must
   * never mint; see `#ownSaltHalf`.
   */
  #saltState(agentName: string, sessionId: string): { ownSalt: Uint8Array | null; ownContribution: Uint8Array | null } {
    const ownSalt = this.#getSessionSalt(agentName, sessionId);
    return {
      ownSalt,
      ownContribution: ownSalt
        ? this.#ownSaltHalf(agentName, sessionId)
        : this.#saltContributionFor(agentName, sessionId),
    };
  }

  /**
   * THE ONE PLACE THAT DECIDES HOW A SESSION'S OUTBOUND CONTENT IS HASHED —
   * `DOD-M15-SEALWIRE-1` part B2b.
   *
   * Returns the hash AND the algorithm that produced it, together, because the two must not be
   * decided separately. `wire-content-hash.ts` exists for exactly this reason and says so in its own
   * header: the expression was written out at five call sites, the two added last got it wrong, and
   * the failure was invisible — *"the send succeeds, `parked: false`, the sender's log says the frame
   * left, and the receiver discards it at the authenticity check."* It took two real daemons.
   *
   * There are FOUR outbound sites (`session-content-handlers.ts`, two in `daemon.ts`,
   * `document-delivery-transport.ts`). Once salting is switchable, each of them independently
   * deciding whether to salt is that defect again with a worse failure mode — a message hashed one
   * way and LABELLED another is refused by every peer, including a correct one.
   *
   * ⚠️ ASYNC, AND THAT IS THE POINT — B2b-2 constraint 2, not an implementation detail.
   *
   * The agreement is in flight while the operator composes their first message. Hash without waiting
   * and it comes out unsalted, and that first unsalted hash closes adoption for the LIFE of the
   * session (Decision #8, unit 1). Every session would fall back permanently while every log line
   * about it stayed true — the feature present, wired, tested, and never once reached.
   *
   * The wait lives HERE rather than at the four call sites for the same reason `contentHashAlg` is a
   * required parameter rather than a defaulted one: a site that forgets it must fail to compile. A
   * caller that drops the `await` gets a `Promise` where bytes belong, which is a typecheck error;
   * a caller that forgot to call a separate `awaitSaltSettled()` would silently send unsalted.
   */
  async contentHashForSession(
    agentName: string,
    sessionId: string,
    content: Uint8Array,
  ): Promise<{ hash: Uint8Array; alg: ContentHashAlg }> {
    const { salt, reason } = await this.#saltForHashing(agentName, sessionId);
    if (salt !== null) {
      /**
       * ⚠️ THE SALTED HASH MARKS ITSELF SPENT — `DOD-M15-SALTSPLIT-1` review pass 1, HIGH-2.
       *
       * The unsalted branch below has counted itself since review pass 2 F1, for a reason stated
       * there in full: between hashing and `#trackAwaitingAck` there is a relay round trip, and in
       * that window leaves, held content and awaiting-ack ALL read zero. **The salted direction was
       * left with no counterpart**, which was harmless while nothing acted on the answer — and
       * `#discardUnspentSalt` is the first code that acts on it destructively.
       *
       * Without this, a peer's `adoption_closed` frame arriving inside that window finds adoption
       * "open", discards the salt, and the message already on the wire carries
       * `content_hash_alg: hmac-salt-v1` with a hash **nobody — including this daemon — can ever
       * recompute**. The alg is copied verbatim into the parked envelope on TTF expiry, so it
       * survives the round trip that would otherwise have hidden it.
       *
       * A COUNT, not a bit, for the same reason the unsalted side is a count: two connections can be
       * mid-send at once, and one finishing must not clear the claim the other is still relying on.
       */
      const key = this.#k(agentName, sessionId);
      this.#hashedWithSalt.set(key, (this.#hashedWithSalt.get(key) ?? 0) + 1);
      const alg = CONTENT_HASH_ALGS.HMAC_SALT_V1;
      return { hash: contentHashFor(content, { alg, salt }), alg };
    }
    /**
     * ⚠️ MARKED BEFORE THE HASH IS RETURNED, and this closes a window the row cannot see.
     *
     * `#saltAdoptionClosed` counts leaves, held content and in-flight sends. For the FIRST message of
     * a session none of the three exists at this moment — the leaf lands after `sendContent` returns,
     * which is a network round trip later. A peer contribution arriving in that gap would be adopted,
     * and the message already on the wire would become the single unsalted leaf in an otherwise
     * salted transcript: the exact split Decision #8 forbids, reached by the one route every count
     * reads as empty.
     *
     * In memory rather than in a column, and that is sufficient rather than convenient: if this
     * process survives, the flag holds; if it does not, the message it protects either reached a
     * durable form (leaf, held row, queued row — all of which the counts see) or never left, in which
     * case there is nothing to split. The one remaining case — hashed, sent, and no local record —
     * is covered from the other side, because the peer DID leaf it and closes its own adoption, and
     * the wire state added in unit 1 tells us so.
     */
    /**
     * ⚠️ NOT FOR A TORN-DOWN SESSION — review Finding 5. `#evictSessionCaches` settles the wait and
     * clears both of these sets; a `.add()` afterwards re-populates a map whose eviction has already
     * run, and the entries then outlive the session they describe. There is also nothing to protect:
     * a session that no longer exists cannot adopt a salt or split a transcript.
     */
    /**
     * ⚠️ THE DEFERRED ERASE — `DOD-M15-SALTSPLIT-1`. This is the moment a suspended salt becomes both
     * harmless to erase and NECESSARY to erase, and it must run BEFORE the count below.
     *
     * Harmless: this session has hashed nothing under the salt, which is what let it be suspended.
     * Necessary: we are about to hash unsalted, and a salt left on disk reads back fine after a
     * restart — so the next process would hash salted and the transcript would be split down the
     * middle by a reboot rather than by any frame.
     *
     * **Before the `#hashedWithoutSalt` increment on purpose.** `#discardUnspentSalt` refuses to erase
     * once adoption is closed, and that counter is one of the things that closes it — increment first
     * and the erase we just decided is correct gets refused by our own guard, leaving exactly the
     * split this ordering exists to prevent.
     */
    if (reason !== UNSALTED_REASONS.SESSION_TORN_DOWN && this.#saltSuspended.has(this.#k(agentName, sessionId))) {
      /**
       * ⚠️ GOING UNSALTED AND ERASING THE SALT ARE ONE DECISION — pass 2, F2 (HIGH), and this is my
       * regression, not a pre-existing one.
       *
       * The note above claimed the ordering was sufficient because `#hashedWithoutSalt` is what
       * closes adoption. **It is one of FOUR contributors.** Leaves, held rows and awaiting-ack close
       * it too — and the most ordinary event in the protocol closes it: *the peer sends us its next
       * message.* Reproduced through the real inbound path: suspend, peer's message lands as leaf 0,
       * we hash `sha256`, and the erase is REFUSED with `already_hashing` while the bytes stay on
       * disk. One teardown-and-revive later — no process restart required — we hash `hmac` again.
       * That is the split transcript, produced by the fix for the split transcript.
       *
       * Worth naming precisely: **the immediate-erase design this replaced could NOT produce it.**
       * There, a refused discard simply kept the session salted — one rule throughout, and loud.
       * Suspension is what made "unsalted now, salted later" reachable. Same shape as pass 1: the fix
       * worse than the defect on one path.
       *
       * So the two are atomic. If the salt cannot be erased, we do **not** go unsalted — we keep
       * hashing under the held salt, which is one rule for the whole session, and say so at ERROR.
       * The counterparty may refuse those messages, and that is the honest failure: a dead session
       * beats a transcript no single rule can verify. The durable column remains the real answer.
       */
      if (!this.#discardUnspentSalt(agentName, sessionId)) {
        const stillHeld = this.#getSessionSalt(agentName, sessionId);
        if (stillHeld !== null) {
          const key = this.#k(agentName, sessionId);
          this.#logger.error("session.salt.split", {
            agentName, sessionId, reason: "suspended_but_unerasable",
            impact: "this session stays SALTED even though the counterparty says it can never hold a salt, because the salt could not be erased and hashing unsalted now would leave half this transcript under each rule — verifiable by nobody. Expect the counterparty to refuse messages sent from here.",
            guidance: "Start a new session with this counterparty: the salt agreement runs at open, before anything is hashed. This one cannot be repaired — look for session.salt.discard.refused immediately above for why the salt could not be released.",
          });
          this.#hashedWithSalt.set(key, (this.#hashedWithSalt.get(key) ?? 0) + 1);
          const alg = CONTENT_HASH_ALGS.HMAC_SALT_V1;
          return { hash: contentHashFor(content, { alg, salt: stillHeld }), alg };
        }
      }
    }
    if (reason !== UNSALTED_REASONS.SESSION_TORN_DOWN) {
      /**
       * ⚠️ A COUNT, NOT A BIT — review pass 2, F1 (HIGH). It was a `Set`, and that made it ONE FLAG
       * PER SESSION for a fact that is per MESSAGE.
       *
       * The `sibling_send_in_flight` refusal path exists precisely when another connection is
       * mid-send with an unsalted hash it computed itself — and `sendContent` awaits a full relay
       * round trip before `#trackAwaitingAck` records anything. So: connection A hashes and sets the
       * flag; A enters that round trip, visible in no count; connection B hashes, sees A's claim,
       * refuses, and calls `abandonUnsaltedHash` — **deleting the flag A is still relying on.** The
       * frontier then reads entirely empty, a salt frame arriving in that window is adopted, and A's
       * message lands as leaf 0 hashed sha256 in a session that hashes everything after it under
       * HMAC.
       *
       * That is the split transcript this unit exists to prevent, through a window a relay round
       * trip wide. A count makes each in-flight hash hold its own claim.
       */
      const key = this.#k(agentName, sessionId);
      this.#hashedWithoutSalt.set(key, (this.#hashedWithoutSalt.get(key) ?? 0) + 1);
    }
    /**
     * NO `??` DEFAULT — review pass 2, F6. It read `reason ?? ADOPTION_CLOSED_LOCALLY`, which is the
     * shape the closed set was built to eliminate: a seventh return path forgetting its reason would
     * have been silently labelled *"you already hashed"* and inherited guidance about a frontier that
     * never moved. `#saltForHashing` returns a discriminated union now, so a null salt without a
     * reason does not compile.
     */
    this.#announceUnsaltedOnce(agentName, sessionId, reason);
    const alg = CONTENT_HASH_ALGS.SHA256;
    return { hash: contentHashFor(content, { alg, salt: null }), alg };
  }

  /**
   * The salt to hash this session's next message under, waiting for a pending agreement if one is
   * genuinely in flight — B2b-2 constraints 2 and 5.
   *
   * Three exits, and the order matters:
   *
   *   1. We already hold one. No wait, ever.
   *   2. Adoption is closed — this session has hashed or leafed something already, so a salt could
   *      never be adopted now even if one arrived. Waiting would be waiting for a value we would
   *      then have to refuse.
   *   3. Nothing is pending. **This is the park-only case (constraint 5)**: the announcement hangs
   *      off `onPeerConnect`, an offline counterparty never connects, so no agreement was ever
   *      started. Waiting the full bound there pauses every message to an offline peer and falls
   *      back anyway — a stall bought for nothing.
   *
   * Only a session with an agreement actually in flight waits, and only until it settles or the
   * bound expires.
   */
  async #saltForHashing(
    agentName: string,
    sessionId: string,
  ): Promise<{ salt: Uint8Array; reason?: undefined } | { salt: null; reason: UnsaltedReason }> {
    const key = this.#k(agentName, sessionId);
    const held = this.#getSessionSalt(agentName, sessionId);
    if (held !== null) {
      /**
       * SUSPENDED BEATS HELD — `DOD-M15-SALTSPLIT-1`. The peer has said it can never hold a salt, so
       * hashing under ours produces a message it must refuse. We hold one and deliberately do not
       * use it.
       *
       * ⚠️ An earlier note here said `PEER_CLOSED_ADOPTION` "already carries exactly the right
       * guidance, so no new reason is needed and none is invented." That was right about not
       * inventing a reason and wrong about which one applies: the peer can suspend us for any of
       * four reasons, and the one hardcoded here asserted the most flattering of them. It now asks
       * the same mapping every other closed path asks (006-CRYPTO finding 2).
       */
      if (this.#saltSuspended.has(key)) {
        return { salt: null, reason: this.#peerClosedReason(key) };
      }
      return { salt: held };
    }
    if (this.#saltAdoptionClosed(agentName, sessionId).closed) {
      return { salt: null, reason: UNSALTED_REASONS.ADOPTION_CLOSED_LOCALLY };
    }

    const pending = this.#saltPending.get(key);
    if (pending === undefined) {
      // An agreement that already ENDED is not an agreement that never started. Only the second is
      // "your counterparty was not connected", and only an absent entry means it.
      const last = this.#saltLastOutcome.get(key);
      if (last !== undefined) return { salt: null, reason: this.#reasonForOutcome(key, last) };
      return { salt: null, reason: UNSALTED_REASONS.NO_AGREEMENT_STARTED };
    }

    const settled = await pending.settled;
    if (settled === "agreed") {
      const agreed = this.#getSessionSalt(agentName, sessionId);
      /**
       * A settled-`agreed` that reads back NULL is a READ failure, not a persist failure — pass 2,
       * F4. `persist_failed` has its own outcome now, so the only way to arrive here empty is
       * `#getSessionSalt` returning null after the salt was stored: a throwing read, or a
       * wrong-width row, with the cache evicted in the microtask between settle and resume. Rare —
       * and labelling it `our_persist_failed` sent the operator to look for a
       * `session.salt.persist.failed` line that will not be there.
       */
      return agreed !== null
        ? { salt: agreed }
        : { salt: null, reason: UNSALTED_REASONS.OUR_READ_FAILED };
    }
    if (settled === "announce_failed") {
      return { salt: null, reason: UNSALTED_REASONS.ANNOUNCE_FAILED };
    }
    if (settled === "persist_failed") {
      // Named separately from the timeout on purpose: the peer answered in time and OUR write
      // failed, so nothing about their build is involved and sending the operator there wastes them.
      return { salt: null, reason: UNSALTED_REASONS.OUR_PERSIST_FAILED };
    }
    if (settled === "closed") {
      /**
       * Two very different things reach `closed`, and only one of them is about the counterparty.
       *
       * `#handleSaltFrame`'s terminal branch — the peer told us it cannot adopt — is a settled
       * bilateral outcome and the session is fine. `#evictSessionCaches` — this session is being
       * torn down underneath us — is not: there is no session left to be unsalted, and a caller that
       * marks `#hashedWithoutSalt` for it re-populates a map whose eviction has already run
       * (review Finding 5). `#saltPending` is gone by the time we look, so the live node is what
       * distinguishes them.
       */
      return {
        salt: null,
        reason: this.#activeNodes.has(key)
          ? UNSALTED_REASONS.PEER_CLOSED_ADOPTION
          : UNSALTED_REASONS.SESSION_TORN_DOWN,
      };
    }
    if (settled === "timeout") {
      /**
       * A DECISION, NOT A RETRY. Logged once, here, because this is the moment the session became
       * permanently unsalted — and an operator reading a later `session.content.unsalted` needs to
       * be able to find out WHY this session has no salt when their others do.
       */
      this.#logger.warn("session.salt.agreement.timeout", {
        agentName, sessionId, waitedMs: pending.boundMs,
        impact: "the counterparty did not answer the salt agreement in time, so this session is unsalted FOR ITS LIFE — the message is being sent now rather than held any longer. Nothing is lost and nothing is degraded relative to any shipped release.",
        // Review F4: `session.salt.persist.failed` reaches this same timeout by a completely
        // different route — the peer answered promptly and OUR OWN write failed, so we returned
        // before announcing and nothing came back. Omitting it sent that operator to ask their
        // counterparty about a version mismatch that was never involved.
        guidance: "Most often the counterparty is on a build that predates the salt agreement, in which case this is expected and permanent for this session — a newer one will agree normally. If you know they are on the same version, look for session.salt.persist.failed on THIS side first (our own write failing produces this same timeout), then session.salt.announce.failed on either side.",
      });
      return { salt: null, reason: UNSALTED_REASONS.AGREEMENT_TIMED_OUT };
    }
    return { salt: null, reason: UNSALTED_REASONS.AGREEMENT_TIMED_OUT };
  }

  /**
   * Decision #15's fallback announcement — ONCE per session, never per message.
   *
   * A warning that fires on every message of every unsalted session is not a signal, it is a reason
   * to build a filter; and the operator who filters it also filters the one session where it meant
   * something. Stated once, with what the session actually loses.
   */
  #announceUnsaltedOnce(agentName: string, sessionId: string, reason: UnsaltedReason): void {
    const key = this.#k(agentName, sessionId);
    if (this.#unsaltedAnnounced.has(key)) return;
    this.#unsaltedAnnounced.add(key);
    this.#logger.info("session.content.unsalted", {
      agentName, sessionId,
      // The REASON is the field that makes this line diagnosable, and it was the missing one. The
      // impact is the same for all six; what to do about it is not.
      reason,
      impact: "this session hashes its messages the way every build before this feature did. Nothing is degraded relative to any shipped release and no message is affected — it only means a relay holding the hashes could confirm a guess at a short message in THIS conversation, which a salt would have prevented.",
      guidance: UNSALTED_GUIDANCE[reason],
    });
  }

  /**
   * Register that a salt agreement is IN FLIGHT for this session, so the first send waits for it.
   *
   * Called where we announce our own state — not at session creation. That distinction is
   * constraint 5: an agreement exists to be waited for only once a frame has actually gone out.
   */
  #markSaltPending(agentName: string, sessionId: string, boundMs = SALT_AGREEMENT_WAIT_MS): void {
    const key = this.#k(agentName, sessionId);
    if (this.#saltPending.has(key)) return;
    let resolve: (v: "agreed" | "timeout" | "closed" | "persist_failed" | "announce_failed") => void = () => { };
    const settled = new Promise<"agreed" | "timeout" | "closed" | "persist_failed" | "announce_failed">((r) => { resolve = r; });
    const timer = setTimeout(() => this.#settleSaltPending(agentName, sessionId, "timeout"), boundMs);
    // The daemon must be able to exit with this outstanding — a pending agreement is not a reason to
    // hold the process open.
    if (typeof timer.unref === "function") timer.unref();
    this.#saltPending.set(key, { settled, resolve, timer, boundMs });
  }

  /**
   * ONE mapping from a settled outcome to the operator-facing reason, so the send that WAITED and the
   * send that arrived afterwards cannot disagree about what happened.
   */
  #reasonForOutcome(
    key: string,
    outcome: "timeout" | "closed" | "persist_failed" | "announce_failed",
  ): UnsaltedReason {
    if (outcome === "announce_failed") return UNSALTED_REASONS.ANNOUNCE_FAILED;
    if (outcome === "persist_failed") return UNSALTED_REASONS.OUR_PERSIST_FAILED;
    if (outcome === "closed") return this.#peerClosedReason(key);
    return UNSALTED_REASONS.AGREEMENT_TIMED_OUT;
  }

  /**
   * WHICH of the four terminal answers the peer actually gave — 006-CRYPTO finding 2.
   *
   * The default is the NON-ASSERTING reason, not the most common one. An unknown label means a build
   * we do not understand, and rendering that as "they had already hashed messages" states something
   * about a counterparty that may be untrue — which is what sends an operator to raise a
   * non-problem with them. The label is peer-supplied, so nothing outside the known set is repeated
   * back as our own diagnosis.
   *
   * A missing entry maps to the already-hashing case: `PEER_CLOSED_FIRST` and an absent label both
   * mean the peer is answering a closure of OURS, and `#saltForHashing` answers that with
   * `ADOPTION_CLOSED_LOCALLY` one branch earlier — this is only the fallback if it did not.
   */
  #peerClosedReason(key: string): UnsaltedReason {
    const label = this.#saltPeerClosedLabel.get(key);
    if (label === undefined || label === SALT_ADOPTION_LABELS.PEER_CLOSED_FIRST) {
      return UNSALTED_REASONS.PEER_CLOSED_ADOPTION;
    }
    if (label === SALT_ADOPTION_LABELS.ALREADY_HASHING) return UNSALTED_REASONS.PEER_CLOSED_ADOPTION;
    if (label === SALT_ADOPTION_LABELS.FRONTIER_UNREADABLE) return UNSALTED_REASONS.PEER_FRONTIER_UNREADABLE;
    if (label === SALT_ADOPTION_LABELS.EXCHANGE_STALLED) return UNSALTED_REASONS.PEER_EXCHANGE_STALLED;
    return UNSALTED_REASONS.PEER_CLOSED_UNSPECIFIED;
  }

  /** Resolve a pending agreement. Idempotent: the first outcome wins and the timer is cleared. */
  #settleSaltPending(agentName: string, sessionId: string, outcome: "agreed" | "timeout" | "closed" | "persist_failed" | "announce_failed"): void {
    const key = this.#k(agentName, sessionId);
    const pending = this.#saltPending.get(key);
    if (pending === undefined) return;
    this.#saltPending.delete(key);
    // `agreed` is not recorded: the salt itself is the record, and `#getSessionSalt` answers first.
    if (outcome !== "agreed") this.#saltLastOutcome.set(key, outcome);
    clearTimeout(pending.timer);
    pending.resolve(outcome);
  }

  /**
   * THIS SESSION'S UNSALTED HASH NEVER BECAME A MESSAGE — release the permanent closure it caused.
   *
   * ⚠️ REVIEW FINDING 3, and it is the opposite of the direction the flag was written to defend.
   * `#hashedWithoutSalt` closes adoption at hash time, because for a session's first message the
   * leaf is a network round trip away and every frontier count reads zero in between. Correct — but
   * `cello_send` has three paths that compute the hash and then produce NOTHING: a sibling send
   * holding the in-flight claim, the frontier moving under the send, and a non-durable send failure
   * whose bytes go to a queue with no production consumer.
   *
   * In all three the session was permanently unsalted for a message that exists nowhere: no leaf, no
   * wire, no copy at the peer. And B2b-2 made two of them MORE likely on a first message, because
   * the five-second wait widens the very window the frontier re-check is watching.
   *
   * Only safe because it is called on paths that provably sent nothing. It deliberately does NOT
   * clear `#unsaltedAnnounced`: the announcement was true when it fired and re-announcing on the
   * retry would be the per-message flood Decision #15 forbids.
   *
   * ─── THREE OTHER SITES HASH AND MAY SEND NOTHING, AND ARE EXEMPT ON PURPOSE (pass 2, F8) ──────
   *
   * `daemon.ts`'s one-shot rejection and away reply, and `document-delivery-transport.ts`'s frame
   * send, can all fail after hashing. None of them needs to abandon, and the reason is the same in
   * each: every one is a REPLY. The inbound message that triggered it has already been leafed on
   * this side, so `#saltAdoptionClosed` is already closed by the leaf count and would stay closed
   * whatever this flag said. Calling abandon there would be a no-op that looks like a guarantee.
   *
   * Written down rather than left to be re-derived: the next reader's first question is why the
   * list is three and not six.
   */
  abandonUnsaltedHash(agentName: string, sessionId: string): void {
    const key = this.#k(agentName, sessionId);
    const held = this.#hashedWithoutSalt.get(key) ?? 0;
    if (held === 0) return;
    // DECREMENT, never delete — F1. Deleting released a sibling's claim along with this one.
    if (held > 1) { this.#hashedWithoutSalt.set(key, held - 1); return; }
    this.#hashedWithoutSalt.delete(key);
    /**
     * INFO, not DEBUG — review pass 2, F3. `session.content.unsalted` has already told this operator
     * at INFO that the session is unsalted *"permanently… start a new session if you want the
     * protection."* That statement is now false, and a retraction logged below the level of the
     * claim it retracts is not a retraction. The announcement itself is deliberately NOT re-armed —
     * re-announcing on the retry is the per-message flood Decision #15 forbids.
     */
    this.#logger.info("session.content.unsalted.retracted", {
      agentName, sessionId,
      impact: "a hash computed unsalted never became a message — no leaf, nothing on the wire, no copy at the counterparty — so this session CAN still adopt a salt. An earlier session.content.unsalted line said the session was permanently unsalted; that no longer applies.",
    });
  }

  /**
   * TEST SEAM — put a session into the state a real one is in between announcing and being answered.
   *
   * Reaching that state for real needs a live counterparty connection, which the daemon-level
   * fixtures do not have; without a seam the wait could only be tested by not testing it. It calls
   * the same private registration the announce path calls, so it cannot drift from it.
   */
  markSaltAgreementPendingForTest(agentName: string, sessionId: string, boundMs?: number): void {
    this.#markSaltPending(agentName, sessionId, boundMs);
  }

  /**
   * PUBLIC read of a session's agreed salt — `DOD-M15-SEALWIRE-1` part B2a.
   *
   * `content-park.ts` runs a SECOND, independent content-hash verifier (the park signature does not
   * cover the envelope content, so it checks before `ingestReceivedContent` is ever reached), and it
   * hardcoded `sha256`. It needs the salt to verify a v3 envelope, and it is outside this class.
   *
   * Read-only and cache-backed, so exposing it adds no way to CHANGE the salt from outside — the
   * only writer remains `#persistSessionSalt`, behind the one-salt-per-session predicate.
   */
  /**
   * IS THIS SESSION ACTUALLY PROTECTED BY ITS SALT RIGHT NOW — pass 2, F3.
   *
   * Distinct from `getSessionContentSalt`, which is POSSESSION and is what the verifier needs: a
   * message parked before suspension was hashed under this salt and must still be checkable against
   * it, so that accessor must keep answering with the bytes.
   *
   * This one answers the OPERATOR's question, and it is a different question. A suspended session
   * holds a salt it will not use, so every hash it produces is `sha256` — reporting `contentSalted:
   * true` there is not a gap, it is an affirmatively false security claim on the surface whose own
   * comment reads *"a security property must not be inferable from a gap."* Same predicate
   * `#saltForHashing` uses, so the flag cannot drift from the behaviour it describes.
   */
  isContentSaltActive(agentName: string, sessionId: string): boolean {
    if (this.#saltSuspended.has(this.#k(agentName, sessionId))) return false;
    return this.#getSessionSalt(agentName, sessionId) !== null;
  }

  getSessionContentSalt(agentName: string, sessionId: string): Uint8Array | null {
    return this.#getSessionSalt(agentName, sessionId);
  }

  /**
   * This session's agreed salt, or null. Reads the durable row through a cache, because Decision #8
   * persists it for exactly one reason: *"a restart silently splits the transcript"* if the lookup
   * misses and a fresh salt is minted.
   *
   * A read failure returns null WITH a log rather than throwing — except the bare `!this.#db` guard,
   * which is this file's convention at 60+ sites and only reachable during shutdown. Null means "we
   * hold no salt", which drives the agreement to offer a contribution — and against a peer that does
   * hold one that is a named, loud `salt_state_divergent` refusal. So the degraded path ends in a
   * diagnosis, not in a session that quietly hashes under the wrong value.
   *
   * ⚠️ THIS PARAGRAPH SPENT A UNIT STRANDED 180 LINES AWAY, directly above `contentHashForSession`
   * and followed by that method's own block — so a reader hovering the hash decision got prose about
   * salt read failures. Harmless and exactly the kind of drift that makes a comment stop being read.
   */
  #getSessionSalt(agentName: string, sessionId: string): Uint8Array | null {
    const key = this.#k(agentName, sessionId);
    const cached = this.#sessionSalts.get(key);
    if (cached) return cached;
    if (!this.#db) return null;
    try {
      const row = this.#db
        .prepare("SELECT content_salt FROM sessions WHERE agent_id = ? AND session_id = ?")
        .get(this.#requireAgentId(agentName), sessionId) as { content_salt?: Uint8Array | null } | undefined;
      const stored = row?.content_salt;
      if (!stored || stored.length === 0) return null;
      /**
       * A WRONG-WIDTH ROW IS NOT A SALT — review F8.
       *
       * Any non-empty blob used to be accepted, so a truncated row became "our salt", the digests
       * then differed, and the operator was told *"one of you is running an older build — compare
       * versions with them"*: sent to their counterparty over corruption on their own disk. Refusing
       * it here makes this side hold NO salt, which re-offers a contribution and repairs.
       */
      if (stored.length !== SESSION_SALT_BYTES) {
        this.#logger.error("session.salt.read.failed", {
          agentName, sessionId, storedBytes: stored.length, expected: SESSION_SALT_BYTES,
          reason: "wrong_width",
          impact: "the stored salt is the wrong size, so it is not used; this session is treated as holding no salt and will re-agree one with the counterparty rather than comparing a corrupt value and blaming their build",
        });
        return null;
      }
      const salt = new Uint8Array(stored);
      this.#sessionSalts.set(key, salt);
      return salt;
    } catch (err: unknown) {
      this.#logger.error("session.salt.read.failed", {
        agentName, sessionId, error: extractErrorMessage(err),
        impact: "this session is treated as holding no salt, so it will offer a fresh contribution; against a counterparty that still holds theirs the agreement refuses by name rather than hashing under a value only one side has",
      });
      return null;
    }
  }

  /**
   * Is this session past the point where a salt can be adopted? — Decision #8, part B2b-2.
   *
   * ⚠️ THE PREDICATE IS "HAS ANYTHING BEEN HASHED", NOT "IS THERE A LEAF" — review F5. A leaf is
   * APPENDED after `await sendContent(...)` returns, so a message can be hashed, put on the wire, and
   * still be invisible to `tree.size()`. Adopting inside that window makes leaf 0 unsalted and the
   * rest salted — the exact split this exists to prevent, with the guard green.
   *
   * ⚠️ HELD CONTENT COUNTS, AND MUST BE HYDRATED FIRST — review F6. `#ensureHeldRestored` is lazy and
   * is not called at session-node creation, so a revived session whose first inbound frame is the
   * salt frame reads a frontier that excludes durable `held_content` rows — rows already hashed
   * unsalted, which `#releaseHeld` will append moments later. Every other frontier reader in this
   * file hydrates first, for this reason. `release: false`, because a salt frame must never deliver
   * messages as a side effect.
   *
   * ⚠️ "CANNOT TELL" IS CLOSED, NOT OPEN. `#requireAgentId` throws for a retired agent, and inferring
   * "zero leaves" from a failure to count them is how a guard becomes a formality. The cost of
   * refusing is an unsalted session; the cost of permitting is a transcript neither rule can verify.
   */
  #saltAdoptionClosed(agentName: string, sessionId: string): { closed: boolean; label: string; leafCount: number; why: string } {
    try {
      this.#ensureHeldRestored(agentName, sessionId, { release: false });
    } catch { /* hydration is best-effort; the counts below still refuse on their own failure */ }
    try {
      const key = this.#k(agentName, sessionId);
      const leaves = this.getSessionTree(agentName, sessionId).size();
      const held = this.#heldContent.get(key)?.size ?? 0;
      const inFlight = this.#awaitingAck.get(key)?.size ?? 0;
      /**
       * ⚠️ THE HASH ITSELF COUNTS — B2b-2, and none of the three counts above can see it.
       *
       * Decision #8 closes adoption when content is HASHED. For a session's first message the leaf
       * lands after `sendContent` returns, a network round trip later; there is no held row and no
       * in-flight entry yet either. So between the hash and the leaf every count reads zero, and a
       * peer contribution arriving in that window would be adopted — leaving the message already on
       * the wire as the one unsalted leaf in a salted transcript.
       */
      const hashed = this.#hashedWithoutSalt.get(key) ?? 0;
      const total = leaves + held + inFlight + hashed;
      return {
        closed: total > 0,
        // The label crosses the WIRE, so it carries no counts and no error text — only which of the
        // two refusals this is. The counts stay in `why`, which stays local.
        label: SALT_ADOPTION_LABELS.ALREADY_HASHING,
        leafCount: total,
        why: `leaves=${leaves} held=${held} awaiting_ack=${inFlight} hashed=${hashed}`,
      };
    } catch (err: unknown) {
      return {
        closed: true,
        label: SALT_ADOPTION_LABELS.FRONTIER_UNREADABLE,
        leafCount: -1,
        why: `frontier_unreadable: ${extractErrorMessage(err)}`,
      };
    }
  }

  /**
   * Persist the agreed salt, and DO NOT ANNOUNCE ONE WE FAILED TO STORE.
   *
   * The caller sends its fingerprint only if this returns true. A salt held in memory and not on
   * disk would confirm agreement to the counterparty and then be gone at the next restart — turning
   * a loud `salt_state_divergent` refusal, which is the whole point of Decision #10, into the silent
   * split it exists to prevent, one restart later.
   *
   * ⚠️ SECOND ORPHAN OF THE SAME KIND. This paragraph was stranded above `#saltAdoptionClosed` and
   * followed by that method's own block, exactly like the `#getSessionSalt` one re-homed in the
   * previous pass — which walked straight past this one sixty lines below it. Two in one file is not
   * coincidence: inserting a method between a doc block and its subject leaves no error, no lint,
   * and no test, so the drift is invisible until someone reads for it.
   */
  #persistSessionSalt(agentName: string, sessionId: string, salt: Uint8Array): boolean {
    if (!this.#db) {
      // NOT a silent return — review F7. The other two persist failures each emit an event, so a
      // derive that could not store because the handle is closed was the ONE salt path producing no
      // record at all. Only reachable during shutdown, which is exactly when a lone unexplained
      // gap in the log is hardest to account for later.
      this.#logger.error("session.salt.persist.failed", {
        agentName, sessionId, reason: "db_closed",
        impact: "the salt was NOT stored and is not announced; the agreement stays open and re-runs on the next connect",
      });
      return false;
    }
    try {
      /**
       * ORDER MATTERS HERE, and getting it wrong cost three findings — review F3, F4, F7.
       *
       * The adoption guard used to run FIRST, above `!this.#db` and outside this `try`. That:
       *   - short-circuited the `salt_already_stored` discrimination below, so a session that DOES
       *     hold a valid salt was told it "stays unsalted FOR THE LIFE of the session" after a
       *     transient read failure — a refusal asserting something false about the row (F4);
       *   - put `getSessionTree`'s `#requireAgentId` throw outside the `try`, where it surfaced as
       *     *"the stream read failed"* instead of a named salt-persist failure (F7).
       *
       * So the row's own state is established first, and only a session with no salt at all reaches
       * the adoption question.
       */
      const existingRow = this.#db
        .prepare("SELECT length(content_salt) AS n FROM sessions WHERE agent_id = ? AND session_id = ?")
        .get(this.#requireAgentId(agentName), sessionId) as { n: number | null } | undefined;
      if (existingRow?.n === SESSION_SALT_BYTES) {
        this.#logger.error("session.salt.persist.failed", {
          agentName, sessionId, reason: "salt_already_stored",
          impact: "this session already has a salt and it was NOT replaced — Decision #8 is one salt per session. Reaching here means a read failure made this side believe it had none; the stored salt is intact, nothing was announced, and the agreement re-runs against it on the next connect.",
        });
        return false;
      }
      const adoption = this.#saltAdoptionClosed(agentName, sessionId);
      if (adoption.closed) {
        this.#logger.warn("session.salt.adoption.refused", {
          agentName, sessionId, reason: "already_hashing", leafCount: adoption.leafCount, frontier: adoption.why,
          impact: "this session has already hashed content under the unsalted rule, so the salt was NOT adopted — it stays unsalted FOR THE LIFE of the session. Adopting now would hash the rest of the conversation differently and leave a transcript that neither rule can verify end to end.",
          guidance: "Nothing is broken and no message was lost: an unsalted session is exactly as verifiable as every session before this feature existed. It only means a relay holding the hashes could confirm a guess at a short message in THIS conversation. If you want the protection, start a new session — the agreement runs at open, before anything is hashed.",
        });
        return false;
      }
      /**
       * THE ROW COUNT IS THE CHECK, and without it this method reported success for a write that
       * stored nothing.
       *
       * An `UPDATE` that matches no row does not throw — it returns `changes: 0`. So a session whose
       * row is missing (retired agent, a row that failed to write at creation, an id that does not
       * line up) took the success branch, cached the salt in memory, and announced our fingerprint
       * to the counterparty. Agreement confirmed, nothing on disk, and the failure surfaces at the
       * next restart as the divergence this whole design exists to make loud — except one restart
       * late and with both sides believing they had agreed.
       *
       * Found by a mutant that removed the caller's `if (!persisted) return`: the suite stayed green,
       * because nothing could produce a false from here.
       */
      /**
       * ONE SALT PER SESSION, ENFORCED AT THE WRITE — review F18.
       *
       * This `UPDATE` was unconditional, so it could replace an already-stored VALID salt. The path
       * is real: `#getSessionSalt` returns null on a transient read failure, which sends this side
       * down the derive path, which then overwrote the perfectly good salt on disk. The read error
       * was logged; the destruction of the durable value was not — and the read log actively said
       * the wrong thing, promising only that we would "offer a fresh contribution".
       *
       * The predicate has to allow ONE overwrite: a wrong-width blob is refused by `#getSessionSalt`
       * (F8) precisely so a corrupt row can be replaced rather than stranding the session forever.
       * So: write when there is nothing there, or when what is there is not a salt.
       */
      const written = this.#db
        .prepare(
          "UPDATE sessions SET content_salt = ? WHERE agent_id = ? AND session_id = ? " +
          "AND (content_salt IS NULL OR length(content_salt) <> ?)",
        )
        .run(Buffer.from(salt), this.#requireAgentId(agentName), sessionId, SESSION_SALT_BYTES);
      if (Number(written.changes) !== 1) {
        // WHICH of the two it was. "No row" is a broken session record; "a salt is already there" is
        // this guard doing its job, and telling an operator the row is missing when it is not would
        // send them to look at the wrong thing.
        // The `salt_already_stored` case is decided above now, before the adoption question, so
        // reaching here with a valid salt in the row is not possible. Re-read anyway rather than
        // assume: a wrong-width blob also fails the predicate and must not be reported as a missing
        // row, which would send the operator to look at session state for a corrupt value.
        const existing = this.#db
          .prepare("SELECT length(content_salt) AS n FROM sessions WHERE agent_id = ? AND session_id = ?")
          .get(this.#requireAgentId(agentName), sessionId) as { n: number | null } | undefined;
        const alreadyStored = existing?.n === SESSION_SALT_BYTES;
        this.#logger.error("session.salt.persist.failed", {
          agentName, sessionId, changes: Number(written.changes),
          reason: alreadyStored ? "salt_already_stored" : "no_session_row",
          impact: alreadyStored
            ? "this session already has a salt and it was NOT replaced — Decision #8 is one salt per session. Reaching here means a read failure made this side believe it had none; the stored salt is intact, nothing was announced, and the agreement re-runs against it on the next connect."
            : "the salt was NOT stored — no session row matched — so it is not announced either; the agreement stays open rather than being confirmed against a value that exists only in memory",
        });
        return false;
      }
      this.#sessionSalts.set(this.#k(agentName, sessionId), salt);
      return true;
    } catch (err: unknown) {
      this.#logger.error("session.salt.persist.failed", {
        agentName, sessionId, error: extractErrorMessage(err),
        impact: "the salt was NOT stored, so it is not announced to the counterparty either; the agreement stays open rather than being confirmed against a value that would vanish at the next restart",
      });
      return false;
    }
  }

  /**
   * DROP AN UNSPENT SALT — `DOD-M15-SALTSPLIT-1`. The second writer of `content_salt`, and the only
   * one that clears it.
   *
   * Reached when the counterparty tells us it can never adopt a salt for this session. Keeping ours
   * would mean every message we send from here is refused by them with
   * `content_hash_salt_unavailable` — a conversation that dies while looking merely quiet, which is
   * the failure this exists to prevent.
   *
   * ⚠️ THE ADOPTION CHECK IS REPEATED HERE ON PURPOSE, not because the caller is untrusted.
   *
   * The caller has already computed `adoption`, so this looks redundant — and it is, for today's one
   * call site. It stays because the cost of a future caller getting it wrong is a transcript that no
   * single rule can verify: leaves hashed under a salt that has just been erased, with nothing
   * recording that they were. A guard whose failure mode is silent and permanent belongs next to the
   * destructive act, not only at the place that currently decides to perform it. Same reasoning that
   * made `placeOwnLeaf`'s authorship parameter required rather than optional.
   *
   * Returns true only if a salt was actually cleared.
   */
  /**
   * SUSPEND, don't destroy — `DOD-M15-SALTSPLIT-1`, the authorization argument. Returns true if a
   * salt is now suspended (or already was).
   *
   * This is the frame handler's entry point. It runs the same two refusals as the erase below —
   * a spent salt and one mid-flight are not ours to set aside either, because the messages already
   * hashed under them would become unverifiable the moment we stop using it — and where they do not
   * fire it records the suspension instead of doing anything irreversible.
   */
  #suspendSalt(agentName: string, sessionId: string, correlationId?: string): boolean {
    const key = this.#k(agentName, sessionId);
    if (this.#getSessionSalt(agentName, sessionId) === null) return false;
    if (this.#saltSuspended.has(key)) return true;

    const inFlight = this.#hashedWithSalt.get(key) ?? 0;
    const adoption = this.#saltAdoptionClosed(agentName, sessionId);
    if (inFlight > 0 || adoption.closed) {
      /**
       * SPENT, or mid-send. Suspending is not destructive, but it IS a split: content already hashed
       * under this salt stays hashed under it while everything after would be hashed the other way,
       * in one session, with nothing recording where the change happened. That is the one thing
       * Decision #8 forbids outright, so the salt keeps being used and the session stays honestly
       * broken rather than becoming dishonestly half-verifiable.
       */
      this.#logger.info("session.salt.suspend.refused", {
        agentName, sessionId, correlationId,
        reason: inFlight > 0 ? "salted_hash_in_flight" : adoption.label,
        ...(inFlight > 0 ? { inFlight } : { frontier: adoption.why }),
        impact: "the salt stays IN USE, because content in this session is already hashed under it and switching now would split the transcript — half verifiable by one rule, half by another. The counterparty cannot hold this salt, so it will keep refusing messages sent from here. See session.salt.split.",
      });
      return false;
    }

    this.#saltSuspended.add(key);
    this.#logger.info("session.salt.suspended", {
      agentName, sessionId, correlationId,
      impact: "the counterparty can never adopt a salt for this session, so this side has STOPPED USING its own — messages are hashed the way every build before content salting hashed them, and every message continues to be accepted. Nothing was hashed under it, so nothing is split.",
      guidance: "No action. The salt bytes are kept, not erased: if the counterparty was merely unable to read its own state for a moment, its next announcement carrying a matching fingerprint restores this session to salted automatically. The bytes are erased only when this session actually hashes a message unsalted, which is the point after which keeping them would re-salt the session at the next restart.",
    });
    return true;
  }

  /** Un-suspend: the peer answered with a fingerprint matching the salt we kept. */
  #resumeSalt(agentName: string, sessionId: string, correlationId?: string): void {
    const key = this.#k(agentName, sessionId);
    if (!this.#saltSuspended.has(key)) return;

    /**
     * ⚠️ REFUSE THE RESUME IF THIS SESSION HAS ALREADY HASHED UNSALTED — pass 2, F1 (HIGH).
     *
     * `#resumeSalt` deleted the mark unconditionally, and the reviewer produced the counter-example
     * in ONE process with no restart: suspend, the peer keeps talking so a leaf lands, we send `m1`
     * under `sha256`, the peer's frontier recovers and announces `fingerprint(S)`, we resume, and
     * `m2` goes out under `hmac`. Two rules, one session — and `session.salt.resumed` asserted
     * *"No message was hashed while suspended, so the transcript is uniform"* while it was happening.
     * **The code never checked the thing its own log line claimed**, which is this milestone's
     * signature defect committed inside the fix for it.
     *
     * `#unsaltedAnnounced` is exactly that fact and is already maintained, so the check costs a
     * lookup. Once it is set the salt can never be used again, so it is erased here rather than left
     * to be found by a later restart.
     */
    if (this.#unsaltedAnnounced.has(key)) {
      this.#logger.warn("session.salt.resume.refused", {
        agentName, sessionId, correlationId,
        impact: "the counterparty now confirms a salt this side is holding, but this session has ALREADY hashed at least one message unsalted. Resuming would put half the transcript under each rule, which no single rule can verify — so the session stays unsalted for its whole life and the salt is released.",
        guidance: "Nothing to do here, and nothing is lost: the transcript stays uniform and every message is intact. If you want the salt protection with this counterparty, start a new session — the agreement runs at open, before anything is hashed.",
      });
      this.#saltSuspended.delete(key);
      this.#discardUnspentSalt(agentName, sessionId, correlationId);
      return;
    }

    this.#saltSuspended.delete(key);
    /**
     * THE RECOVERY THE ERASE MADE IMPOSSIBLE. Keeping the bytes is what allows this line to exist:
     * the peer's earlier terminal frame was wrong (a frontier it could not read for a moment), it can
     * read again, and the fingerprints match — so the session resumes salted with nothing lost. An
     * erased salt cannot be re-derived from one side.
     */
    this.#logger.info("session.salt.resumed", {
      agentName, sessionId, correlationId,
      impact: "the counterparty now confirms the same salt this side kept, so this session is salted again. It was suspended earlier because the counterparty reported it could never hold one; that has resolved. No message was hashed while suspended, so the transcript is uniform.",
    });
  }

  #discardUnspentSalt(agentName: string, sessionId: string, correlationId?: string): boolean {
    const held = this.#getSessionSalt(agentName, sessionId);
    if (held === null) return false;

    /**
     * ⚠️ IN-FLIGHT FIRST — `DOD-M15-SALTSPLIT-1` review HIGH-2. `#saltAdoptionClosed` cannot see a
     * hash that has been computed under the salt but has not yet become a leaf, a hold or an
     * awaiting-ack entry, and that gap is a full relay round trip wide.
     */
    /**
     * ⚠️ MEASURED UNREACHABLE FROM TODAY'S CALLERS, AND KEPT ANYWAY — pass 2 test-teeth, survivor 2.
     *
     * Deleting this block leaves the whole salt suite GREEN. That is the definition this unit has
     * used all along for *"not a guard, a comment that happens to execute"*, so it is labelled rather
     * than quietly left to look load-bearing. `#suspendSalt` refuses on `inFlight > 0` before a
     * session can ever be marked, and both callers of this method require the mark — so the deferred
     * erase cannot observe a non-zero count.
     *
     * It stays for one reason: **it sits at an irreversible write.** The earlier instance of this
     * question in this same unit was resolved by making the guard the actual decision-maker, and that
     * option does not exist here — `#suspendSalt` genuinely must refuse early, so the duplication is
     * structural rather than a mistake about where responsibility lives. For a destructive act, the
     * safe direction is to keep a check that cannot fire over removing one that turns out it could.
     *
     * What must NOT happen is claiming it as coverage. It is not tested and it is not testable from
     * outside; if a third caller ever reaches this method without the suspension mark, this becomes
     * reachable and needs a test in the same commit.
     */
    const inFlight = this.#hashedWithSalt.get(this.#k(agentName, sessionId)) ?? 0;
    if (inFlight > 0) {
      this.#logger.info("session.salt.discard.refused", {
        agentName, sessionId, correlationId, reason: "salted_hash_in_flight", inFlight,
        impact: "the salt was NOT dropped: a message has already been hashed under it and is mid-send, so erasing it now would put a hash on the wire that nothing — including this daemon — could ever recompute. The session stays salted and the counterparty, which cannot adopt, will refuse what is in flight.",
      });
      return false;
    }

    const adoption = this.#saltAdoptionClosed(agentName, sessionId);
    if (adoption.closed) {
      /**
       * SPENT. Something is already hashed under this salt, so it is not ours to drop.
       *
       * INFO, not ERROR, and the level is a judgement rather than a downgrade: this is the guard
       * doing its job correctly, and the FAILURE it accompanies — the session is split and unusable
       * — is reported by `session.salt.split` at ERROR from the caller that has the operator-facing
       * detail. Two ERRORs for one condition trains people to read neither. This line stays so the
       * refusal itself is correlatable when someone asks why the salt is still on disk.
       */
      this.#logger.info("session.salt.discard.refused", {
        agentName, sessionId, correlationId, reason: adoption.label, frontier: adoption.why,
        impact: "the salt was NOT dropped, because content in this session is already hashed under it and erasing it would leave a transcript no single rule can verify. The session stays split: the counterparty holds no salt and refuses everything sent from here.",
      });
      return false;
    }

    if (!this.#db) {
      this.#logger.error("session.salt.discard.failed", {
        agentName, sessionId, correlationId, reason: "db_closed",
        impact: "the salt is still stored, so after the next restart this side hashes salted while the counterparty refuses every message. Only reachable during shutdown; the agreement re-runs on the next connect, which discards it then.",
      });
      return false;
    }

    try {
      const cleared = this.#db
        .prepare("UPDATE sessions SET content_salt = NULL WHERE agent_id = ? AND session_id = ?")
        .run(this.#requireAgentId(agentName), sessionId);
      if (Number(cleared.changes) !== 1) {
        // The row-count check that `#persistSessionSalt` learned the hard way: an UPDATE matching no
        // row does not throw, and reporting success here would leave the durable salt in place while
        // the cache said otherwise — salted after a restart, unsalted before one.
        this.#logger.error("session.salt.discard.failed", {
          agentName, sessionId, correlationId, changes: Number(cleared.changes), reason: "no_session_row",
          impact: "the stored salt was NOT cleared, so this side hashes unsalted now and salted again after a restart — the transcript splits at the restart rather than here",
        });
        return false;
      }
    } catch (err: unknown) {
      this.#logger.error("session.salt.discard.failed", {
        agentName, sessionId, correlationId, error: extractErrorMessage(err),
        impact: "the stored salt was NOT cleared, so this side hashes unsalted now and salted again after a restart — the transcript splits at the restart rather than here",
      });
      return false;
    }

    /**
     * CACHE AFTER ROW, and both or the session is worse off than before.
     *
     * `#saltForHashing` reads the cache on its first line and never consults the row, so clearing
     * one without the other produces a session that hashes one way in this process and the other way
     * in the next — the split transcript, arriving at a daemon restart instead of at a frame.
     */
    this.#sessionSalts.delete(this.#k(agentName, sessionId));
    /**
     * ⚠️ THE MARK GOES WITH THE BYTES — pass 2, F5. Leaving the key in `#saltSuspended` after a
     * successful erase means a LATER agreed salt is silently never used: `#persistSessionSalt`'s
     * predicate explicitly allows a write when the column is NULL, and `abandonUnsaltedHash` can
     * re-open adoption — so the session would log `session.salt.agreed`, surface as protected, and
     * hash `sha256` for the rest of its life. A stale suppression is indistinguishable from a
     * feature that does not work.
     */
    this.#saltSuspended.delete(this.#k(agentName, sessionId));
    this.#logger.info("session.salt.discarded", {
      agentName, sessionId, correlationId,
      impact: "the counterparty can never adopt a salt for this session, so this side dropped its own before spending it. Both sides now hash unsalted — exactly as verifiable as every session shipped before content salting existed, and every message continues to be accepted. Nothing was hashed under the discarded salt.",
    });
    return true;
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
     * It read `ownContribution: this.#saltContributionFor(...)`, which mints unconditionally. Both
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
    const state = this.#saltState(agentName, sessionId);
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
    if (!frame.adoptionClosed) this.#markSaltPending(agentName, sessionId);
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
      this.#settleSaltPending(agentName, sessionId, "announce_failed");
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

  /** Apply one inbound salt-agreement frame. The verdict is the pure function's; this executes it. */
  async #handleSaltFrame(
    agentName: string,
    sessionId: string,
    frame: SaltAgreementFrame,
    correlationId?: string,
  ): Promise<void> {
    const key = this.#k(agentName, sessionId);
    const peerHalfHex = frame.contribution ? Buffer.from(frame.contribution).toString("hex") : null;
    const peerFingerprintHex = frame.fingerprint ? Buffer.from(frame.fingerprint).toString("hex") : null;
    // WHY the peer closed, kept for the operator-facing reason — 006-CRYPTO finding 2. Recorded here
    // rather than in the `adoption_closed` handler because that action fires for OUR closure too,
    // and only the frame says what the PEER said.
    if (typeof frame.adoptionClosed === "string") {
      this.#saltPeerClosedLabel.set(key, frame.adoptionClosed);
    }
    const adoption = this.#saltAdoptionClosed(agentName, sessionId);
    const action = onPeerSaltFrame({
      ...this.#saltState(agentName, sessionId),
      // Review F2: the frontier is what decides whether THIS side can still adopt, and only the
      // caller can count it. Without this the state machine derives, the persist refuses, and the
      // peer never learns — which is how the two sides end up on opposite verdicts.
      ownAdoption: adoption.closed
        ? { closed: true, label: adoption.label, why: adoption.why }
        : { closed: false },
      // Keyed on the peer's BYTES, not on a repair counter: a genuinely NEW half from the peer must
      // still get our contribution back, and only an identical re-offer is the loop (review F14).
      alreadyRepairedAgainstPeerHalf: peerHalfHex !== null && this.#saltRepairedAgainst.get(key) === peerHalfHex,
      // The mirror, 006-CRYPTO finding 1: without it a saltless side answers a latched holder's
      // fingerprint forever. Same keying rule — an identical re-offer is the loop, a new one is not.
      alreadyRepairedAgainstPeerFingerprint:
        peerFingerprintHex !== null && this.#saltRepairedAgainstFingerprint.get(key) === peerFingerprintHex,
      frame,
    });
    if (action.action === "confirmed") {
      // DOD-M15-SALTSPLIT-1: the peer confirms the salt we KEPT while suspended — resume before logging
      // agreement, so a resumed session is never reported as agreed while still suspended.
      this.#resumeSalt(agentName, sessionId, correlationId);
      this.#logger.info("session.salt.agreed", {
        agentName, sessionId, correlationId, via: "fingerprint_match",
      });
      // B2b-2: release a first send that is waiting on this agreement. Both `confirmed` and
      // `derive_and_announce` end with a salt this side can hash under, so both settle the wait.
      this.#settleSaltPending(agentName, sessionId, "agreed");
      return;
    }
    if (action.action === "derive_and_announce") {
      /**
       * ⚠️ I DEFENDED THE OPPOSITE OF THIS TWICE, AND BOTH DEFENCES WERE WRONG. The code now does
       * what the "surviving mutant" did; recording that rather than quietly switching, because the
       * reasoning is the useful part.
       *
       * A failed persist used to fall through with no settle, so a waiting first send sat out the
       * FULL FIVE SECONDS and was then told, by the timeout path, to go and check its counterparty's
       * build version — for a fault that was this machine's own disk.
       *
       * Defence #1 said releasing the waiter "would hand it a null it would hash unsalted under."
       * True, and not a consequence: that is exactly what the timeout does. Defence #2 said the
       * remaining bound gave a repair a chance to land — and the review showed that essentially
       * cannot fire. This branch returns BEFORE the announce, so nothing goes out and nothing comes
       * back; all five of `#sendSaltFrame`'s callers are triggered by a peer connect or an inbound
       * frame. Only a counterparty reconnect inside those seconds could do it.
       *
       * So the real trade was a rare reconnect-within-five-seconds repair against five seconds of
       * visible latency on the operator's first message AND a diagnosis pointing at the wrong
       * machine. The repair loses. Settle immediately under its own name, so `#saltForHashing` can
       * say *our own write failed* instead of *they did not answer*.
       */
      if (!this.#persistSessionSalt(agentName, sessionId, action.salt)) {
        this.#settleSaltPending(agentName, sessionId, "persist_failed");
        return;
      }
      this.#logger.info("session.salt.agreed", {
        agentName, sessionId, correlationId, via: "derived",
      });
      this.#settleSaltPending(agentName, sessionId, "agreed");
      // `void`, not `await` — review F10. This runs inside the INBOUND content-stream handler, so
      // awaiting an outbound `newStream` here lets a stalled dial hold up the stream we are reading.
      // The connect-side call is `void`-ed for the same reason and this is now consistent with it.
      void this.#sendSaltFrame(agentName, sessionId, correlationId);
      return;
    }
    if (action.action === "adoption_closed") {
      // B2b-2: terminal means there is nothing left to wait for. A send still holding on the bound
      // would otherwise sit out the full five seconds for an answer that has already arrived and
      // said no — the slowest possible way to reach a decision both sides already agree on.
      this.#settleSaltPending(agentName, sessionId, "closed");
      /**
       * Terminal, and NOT a freeze — review F1/F2. Both sides stay unsalted, which is exactly as
       * verifiable as every session shipped before the salt existed; the thing that was broken was
       * them disagreeing about it silently.
       *
       * WHICH SIDE DECLINED decides the level, and it is not decoration.
       *
       * If WE closed, an operator has lost a protection they could otherwise have had, and there is
       * something they can do about it — that is a WARN under `session.salt.adoption.refused`, which
       * keeps meaning what it has always meant.
       *
       * If we are merely LEARNING the peer closed, nothing about this machine is at fault and there
       * is nothing for its operator to do. Logging that at WARN would fire on the innocent side of
       * every such session and train them to ignore the name.
       */
      /**
       * DOD-M15-SALTSPLIT-1 — ONE PLACE DECIDES WHETHER THE SALT GOES, and it is not here.
       *
       * ⚠️ THIS CALL WAS INSIDE THE `else` BELOW, AND THE REVERT TEST CAUGHT IT.
       *
       * Guarding it by `adoption.closed` here meant `#discardUnspentSalt`'s own adoption check could
       * never be reached, so deleting that check left all three tests GREEN — the survivor. A guard
       * nothing can redden is not a guard; it is a comment that happens to execute, which is the
       * shape this milestone keeps finding.
       *
       * Called unconditionally now. The method owns the spent/unspent decision, both outcomes run
       * through it, and deleting its check reddens the spent test immediately. That also removes the
       * duplicated condition: two places deciding the same thing is one place being wrong later.
       */
      /**
       * The return is CONSUMED, not decorative — review LOW-5. `true` means a salt was actually
       * cleared, which settles the question below without a second read; `false` is ambiguous (we
       * held none, or we refused to drop one), so that case still asks.
       */
      const suspended = this.#suspendSalt(agentName, sessionId, correlationId);
      /**
       * "Still holds a salt it is USING" — suspension is what settles it, not possession. A suspended
       * session keeps the bytes on disk deliberately, and reporting that as an unrecoverable split
       * would fire the ERROR below on the one case that recovers by itself.
       */
      const stillHoldsSalt = !suspended && this.#getSessionSalt(agentName, sessionId) !== null;

      const shared = {
        agentName, sessionId, correlationId, detail: action.detail,
        /**
         * ⚠️ *"no message is affected"* IS FALSE WHEN WE ARE STILL HOLDING A SALT — review MEDIUM-4,
         * second instance. The sentence was written for a session where neither side ever adopted
         * one, and it stayed attached to a branch that now also covers the case where this side
         * kept a spent salt and every message it sends is about to be refused. Two log lines from
         * one event contradicting each other is worse than either alone.
         */
        impact: stillHoldsSalt
          ? "the counterparty will not use a content salt, and this side is still holding one it cannot drop — see session.salt.split on the next line for what that costs and what to do about it."
          : "neither side will use a content salt for this session, and both now know it. Messages are hashed the way every build before this feature hashed them — nothing is degraded relative to any shipped release, and no message is affected.",
      };
      if (adoption.closed) {
        /**
         * ⚠️ TWO REFUSALS, TWO DIFFERENT THINGS TO DO — and this used to report both as
         * `already_hashing`.
         *
         * A session that has already sent messages is the feature working: the fix is a new session,
         * and it will work. A frontier this side could not READ is local storage trouble: a new
         * session will refuse in exactly the same way, so sending the operator to open one is
         * sending them somewhere that cannot help. `frontier` carries the counts (or the error) so
         * the two are separable from the log alone.
         */
        const unreadable = adoption.label === SALT_ADOPTION_LABELS.FRONTIER_UNREADABLE;
        this.#logger.warn("session.salt.adoption.refused", {
          ...shared,
          reason: adoption.label,
          leafCount: adoption.leafCount,
          frontier: adoption.why,
          guidance: unreadable
            ? "This side could not read its own message frontier, so it refused the salt rather than risk hashing half the session one way and half the other. Starting a new session will NOT help — it will refuse the same way. Look for session.content.held.restore.failed or other storage errors around this line; the conversation still works and every message is intact, it is just unsalted."
            : "Nothing is broken and no message was lost: an unsalted session is exactly as verifiable as every session before this feature existed. It only means a relay holding the hashes could confirm a guess at a short message in THIS conversation. If you want the protection, start a new session — the agreement runs at open, before anything is hashed.",
        });
      } else {
        /**
         * DOD-M15-SALTSPLIT-1 — CARRY OUT THE CLAIM ABOVE INSTEAD OF ONLY STATING IT.
         *
         * `shared.impact` says *"neither side will use a content salt for this session, and both now
         * know it."* Nothing made that true: a salt already agreed on this side stayed on disk and in
         * the cache, and `#saltForHashing` returns it before it ever looks at adoption. Our adoption
         * is still open here, so nothing has been hashed under it and dropping it is free.
         *
         * Ordering matters — discard BEFORE the log, so the line cannot claim an outcome that the
         * write then failed to produce.
         */
        this.#logger.info("session.salt.adoption.closed", shared);
      }

      /**
       * ⚠️ OUTSIDE THE ADOPTION BRANCH — pass 2, F4. This used to live inside `if (adoption.closed)`,
       * so the one case that needed it most never got it: suspension refused for
       * `salted_hash_in_flight` while adoption is still OPEN leaves us holding a salt the peer can
       * never accept, and it took the `else` path. Measured on that exact scenario:
       * `suspend.refused = 1`, `adoption.closed = 1`, **`split = 0`** — while two other log lines
       * told the operator to *"see session.salt.split on the next line"*, a line that was never
       * written. Guidance pointing at an event that does not fire is worse than no guidance: it
       * spends the reader's trust and their time.
       *
       * The condition was always `stillHoldsSalt`; only its placement disagreed.
       *
       * ─── What this event means, moved here with the code it describes ─────────────────────────
       *
       * We hold a salt AND the peer has told us it can never hold one. Either our frontier closed
       * with the salt already spent, or a salted hash is mid-flight — both mean the salt cannot be
       * released, so the peer will refuse every message we send with `content_hash_salt_unavailable`.
       *
       * `session.salt.adoption.refused` may fire alongside, saying *"nothing is degraded relative to
       * any shipped release, and no message is affected"* — true for the ordinary refusal and FALSE
       * here, at the exact moment every message stops being accepted. Hence its own event at ERROR
       * rather than a tightened sentence on that one: an operator filtering for the refusal is
       * looking at a benign condition, and this is not it.
       */
      if (stillHoldsSalt) {
          /**
           * ⚠️ TWO REASONS REACH `adoption.closed`, AND ONLY ONE IS ABOUT CONTENT — review MEDIUM-4.
           *
           * This fired for both with a single impact asserting *"content here is already hashed
           * under a salt"*. For `frontier_unreadable` that is a claim about content made from a
           * database read that FAILED — we do not know what was hashed; that is the whole condition.
           *
           * The WARN twenty lines above was explicitly corrected for this exact collapse — its
           * comment reads *"TWO REFUSALS, TWO DIFFERENT THINGS TO DO — and this used to report both
           * as `already_hashing`"* — and I reintroduced it one severity level up, with the guidance
           * that WARN was fixed to stop giving. Branching on the label the way it already does.
           */
          const unreadable = adoption.label === SALT_ADOPTION_LABELS.FRONTIER_UNREADABLE;
          this.#logger.error("session.salt.split", {
            agentName, sessionId, correlationId, reason: adoption.label, frontier: adoption.why,
            impact: unreadable
              ? "this side holds a salt, the counterparty can never hold one, and this side could NOT read its own message frontier — so whether anything has been hashed under that salt is unknown. The salt is kept rather than dropped, because dropping one that HAS been spent leaves a transcript no single rule can verify. Until the read succeeds, expect the counterparty to refuse messages sent from here."
              : "this session cannot continue. Content here is already hashed under a salt the counterparty can never hold, so they refuse every message sent from this side — the conversation looks quiet rather than broken, and the session can never be sealed because the two transcripts no longer agree on a leaf.",
            guidance: unreadable
              ? "Do NOT start a new session yet — it would refuse in exactly the same way, because the fault is this side's storage rather than this conversation. Look for session.content.held.restore.failed or other storage errors around this line. Once the frontier reads again, this resolves to either an ordinary salted session or the split case, and the log will say which."
              : "Start a new session with this counterparty: the salt agreement runs at open, before anything is hashed, so a fresh session agrees or declines cleanly on both sides. This one cannot be repaired — the salt cannot be dropped without leaving a transcript no single rule can verify, and it cannot be shared with a peer that has already closed adoption.",
          });
        }
      if (action.announce) {
        void this.#sendSaltFrame(agentName, sessionId, correlationId, action.announce);
      }
      return;
    }
    if (action.action === "repair") {
      /**
       * THE REPAIR — review F1. The two sides are out of step and CAN converge, so re-send our half
       * rather than destroying the session.
       *
       * At INFO because it is a real event an operator may need to correlate with a
       * `session.salt.announce.failed` or `session.salt.persist.failed` on either machine, and
       * because a session that repairs REPEATEDLY is a signal even though each repair is benign.
       */
      this.#logger.info("session.salt.repair", {
        agentName, sessionId, correlationId, detail: action.detail,
        answeredWith: action.frame.contribution ? "contribution" : "fingerprint",
      });
      // Recorded ONLY for a repair that sent our half, because that is the one a second identical
      // offer must not repeat (review F14).
      if (peerHalfHex && action.frame.contribution) this.#saltRepairedAgainst.set(key, peerHalfHex);
      // AND THE MIRROR (006-CRYPTO finding 1): we answered the peer's FINGERPRINT with our half. An
      // earlier note here said recording this "says nothing, that branch is already terminal for the
      // peer" — it is terminal only for a peer that HOLDS a salt, and the loop is the case where we
      // do not. A second identical fingerprint now closes adoption instead of repairing again.
      if (peerFingerprintHex && action.frame.contribution) {
        this.#saltRepairedAgainstFingerprint.set(key, peerFingerprintHex);
      }
      void this.#sendSaltFrame(agentName, sessionId, correlationId, action.frame);
      return;
    }
    // `detail` is the primitive's own sentence wherever the primitive produced it — never a code of
    // ours substituted for it (Invariant 2). `guidance` is what the operator can DO, and it comes
    // from the total map so a reason can never reach a log without one.
    this.#logger.error("session.salt.disagreement", {
      agentName, sessionId, correlationId,
      reason: action.reason,
      detail: action.detail,
      guidance: SALT_FREEZE_GUIDANCE[action.reason],
    });
    /**
     * TELL THE PEER BEFORE TEARING DOWN — review F1's mirror.
     *
     * Only the fingerprint mismatch carries a notice, and only it can: the peer holds everything
     * needed to run the identical comparison and has simply not been given our side of it. Without
     * this the session stops answering and the far operator gets no reason at all, while ours gets a
     * full explanation — Decision #10 asks for BOTH sides to refuse by name.
     *
     * Awaited, unlike the other sends, because `destroySessionNode` on the next line takes the node
     * away and an un-awaited write would race its own transport. A failure is already handled
     * inside — the refusal here has happened either way.
     */
    if (action.notifyPeer) {
      await this.#sendSaltFrame(agentName, sessionId, correlationId, action.notifyPeer);
    }
    await this.#freezeSession(agentName, sessionId, action.reason, {
      event: "session.salt.frozen",
      observation: `the salt agreement could not be completed with this counterparty: ${action.detail}`,
      impact: "the session was stopped rather than left to hash under a value the two sides do not share; no message was lost and the transcript is unaffected — only a NEW session moves this forward",
      reviveReason: `session_frozen_${action.reason}`,
      // The operator-facing sentence comes from the TOTAL guidance map, so a reason can never reach
      // this refusal without one — and it is what stops a salt disagreement being reported to them
      // as their counterparty failing a key check.
      reviveGuidance: SALT_FREEZE_GUIDANCE[action.reason],
    }, correlationId);
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
    //
    // DOD-M15-FRAME-1: `null` no longer says enough. It meant "no position" for six different
    // reasons, two of which are PROOF THAT THE SIGNER IS NOT WHO THIS SESSION IS WITH — and the
    // caller treated all six alike and ingested the content regardless. The check ran, answered
    // correctly, and its answer was thrown away.
    //
    // `fatal` separates the two questions Invariant 2 keeps apart: sequence POSITION may stay soft
    // (a missing ordering record is the documented relay-degraded path and refusing it would make
    // the relay a precondition for reading mail), while IDENTITY may never be. A bad signature, or
    // a signature by a key that is not this session's counterparty, is an identity failure that the
    // sender supplied and that we verified — not an absence we could not resolve.
  ): {
    seq: number | null;
    fatal?: { reason: string };
    /**
     * DOD-M15-SEALWIRE-1 bullet 5. Present ONLY on the verified path — the signature checked
     * against the pubkey inside the sender's own signed bytes, and the signer matched to this
     * session's counterparty. Absent everywhere else, including the SOFT decode-failure fallback,
     * so a caller cannot mistake "we did not check" for "it did not verify".
     */
    senderPubkey?: Uint8Array;
    senderSig?: Uint8Array;
  } {
    try {
      const s1 = decode(structure1Cbor) as unknown[];
      const s2 = decode(structure2Cbor) as unknown[];
      const s1Hash = s1?.[1];
      const s1Pubkey = s1?.[2];
      const seq = typeof s2?.[0] === "number" ? s2[0] : -1;
      const s2Sig = s2?.[3];
      if (!(s1Hash instanceof Uint8Array) || !(s1Pubkey instanceof Uint8Array) || !(s2Sig instanceof Uint8Array) || seq < 1) {
        // SOFT: we could not read the record, so we learned nothing about the signer either way.
        // Position falls back to the witness stream, exactly as an absent record does.
        this.#logger.warn("session.content.ordering.malformed", { sessionId, correlationId });
        return { seq: null };
      }
      // The framed ordering record must bind to THIS content (its hash) — else it orders the wrong bytes.
      const contentHashHex = Buffer.from(contentHash).toString("hex");
      if (Buffer.from(s1Hash).toString("hex") !== contentHashHex) {
        // SOFT: the record does not describe this content. Nothing is proven about the signer's
        // identity — only that this record and these bytes do not belong together.
        this.#logger.warn("session.content.ordering.hash_mismatch", { sessionId, correlationId });
        return { seq: null };
      }
      // Verify the SENDER's Ed25519 signature over the exact signed bytes (structure1_cbor) — the same
      // check the relay performs. Proves the counterparty committed to this (content_hash @ sequence).
      if (!verify(s1Pubkey, structure1Cbor, s2Sig)) {
        // FATAL. The sender supplied a signature and it does not verify against the key inside its
        // own record. That is not an absence we could not resolve — it is a proof that failed.
        this.#logger.warn("session.content.ordering.bad_signature", { sessionId, correlationId });
        return { seq: null, fatal: { reason: "bad_signature" } };
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
        /**
         * FATAL when the counterparty is KNOWN and the signer is someone else. SOFT when we simply
         * do not know who the counterparty is.
         *
         * The fatal half is the session-open MITM detection from the 2026-08-21 T-of-N
         * investigation, which found this check *"fires correctly, and its answer is thrown away."*
         * A rogue quorum of the directories holding shares for agent B can sign a false
         * SessionAssignment naming M's key as B's, and everything downstream is genuinely real —
         * M signs with M's own valid key. Nothing is missing for A to notice. This comparison is
         * where the substitution shows, because `counterparty_pubkey` comes from A's own request
         * and is untouched by anything the directory returns.
         *
         * ⚠️ IT SHOWS ONLY WHEN THE RECORD IS PRESENT (review F3). An earlier version of this
         * comment said this was "the one place the substitution shows", full stop — and that
         * asserted a property the code does not have: M can decline to supply an ordering record
         * and be ingested without ever reaching this line. The caller logs
         * `session.content.ordering.absent` so the weaker case is at least visible, and closing it
         * needs a check that does not depend on the sender's cooperation — the relay's independent
         * copy, `DOD-M15-CORROBORATE-1`.
         *
         * The soft half stays soft deliberately: `counterparty_unknown` means we cannot prove the
         * signer either way, and refusing there would strand sessions whose record we failed to
         * read rather than sessions that are under attack.
         */
        const reason = counterparty ? "signer_not_counterparty" : "counterparty_unknown";
        this.#logger.warn("session.content.ordering.wrong_signer", { sessionId, reason, correlationId });
        return counterparty ? { seq: null, fatal: { reason } } : { seq: null };
      }
      // Verified — record the relay-assigned canonical sequence (1-based → 0-based leaf index) for the gate.
      this.recordWitnessedSequence(agentName, sessionId, contentHashHex, seq - 1);
      this.#logger.info("session.content.ordering.recorded", {
        sessionId,
        canonicalSeq: seq - 1,
        source,
        correlationId,
      });
      /**
       * DOD-M15-SEALWIRE-1 bullet 5: return the VERIFIED proof, not just the position.
       *
       * Three lines above, `verify(s1Pubkey, structure1Cbor, s2Sig)` has already passed and the
       * signer has been matched to this session's counterparty. That is the strongest statement
       * this daemon ever makes about who wrote a message — and until now it was made, used to
       * decide a sequence number, and then discarded. The transcript row that outlives it recorded
       * only a direction.
       *
       * Returned rather than stashed, for the same reason `seq` is: a caller that has to go looking
       * for it in a side map is a caller that will not.
       */
      return { seq: seq - 1, senderPubkey: s1Pubkey, senderSig: s2Sig };
    } catch (err: unknown) {
      this.#logger.warn("session.content.ordering.decode_failed", {
        sessionId,
        error: err instanceof Error ? err.message : String(err),
        correlationId,
      });
    }
    // No verified position — the caller falls back to the announced hash-dedup path. SOFT: a decode
    // throw tells us nothing about the signer, so it is the absent case, not the refuted one.
    return { seq: null };
  }

  async #handleContentStream(agentName: string, sessionId: string, stream: Stream, remotePeerId?: string): Promise<void> {
    // CLOSING THIS STREAM IS WHAT KEEPS THE SESSION ALIVE PAST ITS 33RD MESSAGE.
    //
    // Every content frame and every delivery ACK opens a fresh /cello/content/1.0.0 stream on the
    // one muxed connection the session holds, and libp2p caps INBOUND streams per protocol per
    // connection. It enforces that cap AFTER multistream-select has answered, so an over-cap stream
    // negotiates fine and is reset an instant later, and the SENDER's next `stream.send(...)`
    // throws "Cannot write to a stream that is closed" — an error that names the exit point and not
    // one thing about the cause.
    //
    // A stream leaves the muxer's set only on its `close` event, and closing our write end triggers
    // that only once the peer has closed its end too. So a handler that reads its frame and returns
    // leaves the stream half-open for the life of the connection and the count only ever rises.
    // Measured on a live daemon: 115 failures over 3.5 hours, with EXACTLY 32 successful streams
    // before the first one on both affected sessions (M12B Entry 10).
    //
    // The decoder is built INSIDE the try so a malformed stream cannot throw past the close below.
    let iter: AsyncIterator<Uint8Array> | undefined;
    try {
      iter = (lp.decode(stream) as AsyncIterable<unknown>)[Symbol.asyncIterator]() as AsyncIterator<Uint8Array>;
      const result = await iter.next();
      if (result.done || result.value === undefined) return;
      const bytes = result.value instanceof Uint8Array ? result.value
        : Buffer.isBuffer(result.value) ? new Uint8Array(result.value as Buffer)
        : (result.value as { slice(): Uint8Array }).slice();
      const frame = decode(bytes) as Record<string, unknown>;
      const correlationId = typeof frame["correlation_id"] === "string" ? frame["correlation_id"] : undefined;
      const frameType = typeof frame["type"] === "string" ? frame["type"] : "(absent)";

      /**
       * DOD-M15-FRAME-1 — ONE GATE, BEFORE THE DISPATCH, FOR EVERY FRAME ON THIS PROTOCOL.
       *
       * A stranger could dial an agent's standing receiver (it admitted everyone until DOD-M15-ASSIGN-1), hold
       * the connection open through promotion — libp2p's gater runs only at connection
       * establishment, so narrowing it does not evict anyone already attached — and then speak the
       * content protocol the moment it activated. The frame was ingested, leafed, transcribed, and
       * attributed to the legitimate counterparty, because attribution is read from local session
       * state rather than from anything the frame proved.
       *
       * DELIBERATELY SHARED RATHER THAN COPIED INTO EACH BRANCH. `session_abandoned_notice` already
       * had both checks, correct and complete, twenty lines below — and the other two frame types
       * did not. Copying the pattern a third and fourth time would fix today's three and leave the
       * fifth frame type, added later by someone who did not read this comment, unguarded again.
       * Placing it above the dispatch makes the guard the DEFAULT: a new frame type is protected by
       * construction and has to opt OUT visibly rather than opt in silently.
       *
       * Verified safe for all three current types by enumeration, not assumption — `content_frame`
       * (:5169), `session_abandoned_notice` (:6663) and `content_delivery_ack` (:7439) are the only
       * senders on `CELLO_CONTENT_PROTOCOL_ID`, and all three put `session_id` in the frame.
       *
       * MISSING, MALFORMED AND MISMATCHED TAKE ONE PATH. An attacker evading a mismatch check does
       * not send a wrong value — it sends no value, and a guard that only fires on a present-and-
       * wrong field is a guard that is trivially skipped. That is exactly what the old
       * `content_frame` check did: `typeof x === "string" && x !== sessionId`.
       */
      const expectedPeer = this.#activeNodes.get(this.#k(agentName, sessionId))?.counterpartySessionPeerId;
      if (!remotePeerId || !expectedPeer || remotePeerId !== expectedPeer) {
        // Loud in the LOG — there is no caller to answer on an inbound stream, so this is the whole
        // surface. Neutral wording: this is an observation, not a verdict about intent. The same
        // signal comes from a real impersonation attempt and from our own fallback paths
        // mishandling a reconnect, and nothing here can tell them apart.
        this.#logger.warn("session.content.peer_mismatch", {
          agentName, sessionId, frameType,
          remotePeerId: remotePeerId ?? "(absent)", expected: expectedPeer ?? "(unknown)",
          impact: "a frame arrived on this session's content protocol from a peer that is not its counterparty; it was refused — not ingested, not attributed, not recorded — and the peer was disconnected",
        });
        /**
         * PEER-ENDING, NOT SESSION-ENDING — and the difference is a deliberate deviation from the
         * DoD clause (review F2).
         *
         * The clause says the refusal is session-ending. Applied HERE that would be a worse hole
         * than the one it closes: a pre-positioned stranger could kill any session on the machine
         * with a single frame, trading an injection hole for a denial-of-service hole. The
         * session-ending response belongs where the evidence is about the SESSION's counterparty —
         * `#freezeOnIdentityFailure`, reached when a party that IS the peer we dialled signs with a
         * key that is not theirs.
         *
         * Here the evidence is about the PEER: they are not party to this session at all. So the
         * connection goes and the session is untouched. Without this the stranger stayed attached
         * for the life of the session and the gate re-refused each frame forever — and the eviction
         * sweep's own fallback ("the frame gate still refuses anything this peer sends") only closes
         * the loop if the frame gate does something about the connection.
         *
         * Fire-and-forget: a hang-up that fails must not turn a successful refusal into a thrown
         * handler, and the refusal above has already done the load-bearing work.
         */
        if (remotePeerId) {
          const entry = this.#activeNodes.get(this.#k(agentName, sessionId));
          void entry?.node.hangUp(remotePeerId).catch((err: unknown) => {
            this.#logger.debug("session.content.peer_mismatch.hangup_failed", {
              sessionId, peerId: remotePeerId, error: extractErrorMessage(err),
            });
          });
        }
        return;
      }
      const claimedSessionId = frame["session_id"];
      if (typeof claimedSessionId !== "string" || claimedSessionId !== sessionId) {
        this.#logger.warn("session.content.session_mismatch", {
          agentName, sessionId, frameType,
          claimedSessionId: typeof claimedSessionId === "string" ? claimedSessionId : "(absent)",
          impact: "the frame does not name the session whose stream it arrived on; it was refused rather than routed, because the authenticated stream is the better authority for where content belongs",
        });
        return;
      }

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

      // DOD-M12B-ABANDON-NOTIFY-1: the counterparty force-abandoned. Handled here, on the same
      // authenticated stream the delivery acknowledgement rides, and AFTER the session-id check
      // below cannot be skipped — the frame names its session and the handler is bound to one.
      if (frame["type"] === "session_abandoned_notice") {
        // DOD-M15-FRAME-1: the peer and session checks that used to live here now run above, for
        // EVERY frame type, unchanged in substance — this branch was where they were written first
        // and correctly, and it is the reference the shared gate was lifted from. Its comment is
        // preserved there, including the reason the transport being authenticated is not enough.
        // Left as a bare dispatch on purpose: a second copy of a guard is a second thing to keep in
        // step, and the one that drifts is the one nobody is reading.
        void this.retireOnCounterpartyAbandon(agentName, sessionId, correlationId);
        return;
      }

      /**
       * DOD-M15-SEALWIRE-1 bullet 6 (part A) — the salt agreement.
       *
       * Placed BELOW the shared peer/session gate deliberately, which is the whole reason that gate
       * was lifted above the dispatch: a new frame type is protected by construction rather than
       * having to remember to opt in. A stranger's salt frame is refused before it reaches here, so
       * nothing about this session's salt can be steered by a peer that is not its counterparty.
       *
       * The fields are read defensively into the frame shape rather than cast: an inbound value is
       * whatever a peer chose to encode, and `onPeerSaltFrame` refuses both-fields and neither-field
       * by name — so a non-Uint8Array in either slot must arrive at that function as ABSENT, not as
       * a present-but-wrong value it would then try to use.
       */
      if (frame["type"] === "session_salt_agreement") {
        const contribution = frame["contribution"];
        const fingerprint = frame["fingerprint"];
        const adoptionClosed = frame["adoption_closed"];
        await this.#handleSaltFrame(agentName, sessionId, {
          ...(contribution instanceof Uint8Array ? { contribution } : {}),
          ...(fingerprint instanceof Uint8Array ? { fingerprint } : {}),
          // A non-string stays ABSENT rather than being coerced, exactly like the other two: the
          // decision function refuses a shape it cannot read, and must never be handed a `"42"`.
          //
          // TRUNCATED AT THE BOUNDARY — 006-CRYPTO finding 6. Every label CELLO sends is under
          // twenty characters, and this one is chosen entirely by the peer. Cutting it here means
          // no unbounded peer string is stored, logged or rendered anywhere downstream; the
          // rendering that keeps it out of our own sentences is `renderPeerAdoptionLabel`.
          ...(typeof adoptionClosed === "string" && adoptionClosed.length > 0
            ? { adoptionClosed: adoptionClosed.slice(0, SALT_ADOPTION_LABEL_MAX) }
            : {}),
        }, correlationId);
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
      // DOD-M15-FRAME-1: the session-id check moved to the shared gate above, and its `&&` became
      // `||` on the way. It read `typeof x === "string" && x !== sessionId` — firing only when the
      // field was PRESENT and wrong, so omitting it passed. Its own sibling twenty lines up already
      // refused absence, with a comment saying treating a missing field as agreement is how a guard
      // stops guarding. Same file, same switch, opposite conclusion.
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
      // leaf_deliver witness (removes the content-before-witness race).
      //
      // DOD-M15-FRAME-1 — POSITION MAY BE SOFT; IDENTITY MAY NOT. The old comment here read "A
      // bad/absent record is non-fatal: the content still ingests", and it was accurate: a
      // signature that failed to verify, and a signature by a key that is NOT this session's
      // counterparty, both returned null and the content was ingested and attributed anyway. An
      // ABSENT record stays soft — that is the documented relay-degraded path and refusing it would
      // make the relay a precondition for reading mail. A record that is PRESENT and REFUTED is a
      // different fact, and it is now refused.
      const s1Cbor = frame["structure1_cbor"];
      const s2Cbor = frame["structure2_cbor"];
      let framedSeq: number | null = null;
      /**
       * DOD-M15-SEALWIRE-1 bullet 5. Set ONLY when the ordering record verified — the signature
       * checked against the pubkey inside the sender's own signed bytes AND the signer matched this
       * session's counterparty. It is deliberately NOT set on the two soft paths below (no record
       * supplied; decode failed), because on those the author is attested by local session state
       * and the transcript row must say so rather than imply a proof it does not have.
       */
      let verifiedAuthorship: { senderPubkey: Uint8Array; senderSig: Uint8Array } | undefined;
      if (s1Cbor instanceof Uint8Array && s2Cbor instanceof Uint8Array) {
        const ordering = this.#recordFrameOrdering(agentName, sessionId, s1Cbor, s2Cbor, contentHash, correlationId);
        if (ordering.fatal) {
          await this.#freezeOnIdentityFailure(agentName, sessionId, ordering.fatal.reason, correlationId);
          return;
        }
        framedSeq = ordering.seq;
        if (ordering.senderPubkey !== undefined && ordering.senderSig !== undefined) {
          verifiedAuthorship = { senderPubkey: ordering.senderPubkey, senderSig: ordering.senderSig };
        }
      } else {
        /**
         * Review F3 — THE WEAKER GUARANTEE MUST NOT BE INDISTINGUISHABLE FROM THE STRONGER ONE.
         *
         * A frame with no ordering record is still ingested, and that is correct: it is the
         * documented relay-degraded path, and refusing it would make the relay a precondition for
         * reading mail. But it means the per-message signer check is **opt-in for the sender** — a
         * party that passed the peer gate and wants to avoid the comparison simply omits the proof.
         * Silently, until now: nothing recorded that a message arrived unverified, so the log looked
         * identical to one where every message had been checked.
         *
         * Not fatal, and deliberately not: an absent record proves nothing about the signer, and
         * refusing on an absence would strand every relay-degraded session. What closes the omission
         * case is relay-side corroboration — `DOD-M15-CORROBORATE-1` — where the relay holds the
         * sender's signed hash independently and never routes it through this daemon.
         */
        this.#logger.info("session.content.ordering.absent", {
          agentName, sessionId, correlationId,
          impact: "this frame carried no signed ordering record, so its SIGNER was not verified for this message — it was ingested on the strength of the authenticated transport alone",
        });
      }
      // AC-001: carry the sender's correlationId from the frame into the receive
      // path so both sides log the same flow id (never re-minted on receipt).
      /**
       * DOD-M15-SEALWIRE-1 part B1 — the algorithm the sender named, taken from the FRAME.
       *
       * Read as `unknown` and passed through verbatim, deliberately: `resolveContentHashAlg` is the
       * one place that decides what a value means, and it distinguishes ABSENT (a peer predating
       * the field — verify as `sha256`) from a non-string or an unreadable name (refuse by name).
       * Coercing here would collapse that distinction and turn a version skew into a tamper report.
       */
      const declaredAlg = frame["content_hash_alg"];
      const ingest = await this.ingestReceivedContent(
        agentName, sessionId, contentBytes, contentHash, correlationId, framedSeq ?? undefined,
        declaredAlg === undefined ? undefined : (declaredAlg as string | null),
        verifiedAuthorship,
      );
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
    } finally {
      // `close()` waits only for OUR write buffer, which is empty here, so this cannot stall the
      // handler; it runs on every exit above, and there are several early returns.
      try {
        await stream.close();
      } catch (err: unknown) {
        // NOT SILENT. A close that fails here is the signature of the cap biting from the other
        // side, and it was the absence of exactly this line that turned the original diagnosis
        // into a 6,451-record log measurement.
        this.#logger.warn("session.content.stream.close.failed", {
          sessionId,
          error: err instanceof Error ? err.message : String(err),
        });
        try { stream.abort(err instanceof Error ? err : new Error(String(err))); } catch { /* already gone */ }
        return;
      }
      // OUR CLOSE ALONE DOES NOT FREE THE SLOT — the peer has to close its end too, and a peer
      // owns its own daemon. Without this, someone who opens content streams and never closes them
      // pins every inbound slot we have and puts us straight back into the defect above, with the
      // same unreadable error. `abort` resets unilaterally, so it works regardless of the peer;
      // the delay is what keeps it from landing while a well-behaved sender is still inside its
      // own `close()`. Unref'd so it can never hold the process open at shutdown, and tracked so
      // teardown can drop it.
      if (stream.status === "open" || stream.status === "closing") {
        const linger = setTimeout(() => {
          this.#lingeringStreams.delete(linger);
          if (stream.status !== "open" && stream.status !== "closing") return;
          this.#logger.debug("session.content.stream.linger.reset", { sessionId });
          try { stream.abort(new Error("inbound content stream not closed by peer")); } catch { /* already gone */ }
        }, CONTENT_STREAM_LINGER_MS);
        linger.unref?.();
        this.#lingeringStreams.add(linger);
      }
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
        /**
         * DOD-M12B-SESSION-SEED-1 (review F8): drop it zeroed, like every other seed.
         *
         * (review F7, DECIDED AGAINST — deliberately NOT reusing this seed for the replacement.)
         * Reuse is attractive: this receiver's peer id may already be inside a `session_offer_accept`
         * the counterparty is acting on, and a rebuild in that window is the documented "we record
         * an identity that no longer exists… every send in this direction parks forever" defect. But
         * a preserved identity would have to be handed to the candidate loop in
         * `#startReceiverNode`, whose rejected candidates are stopped WITHOUT awaiting `start()` —
         * so two nodes could be briefly live on one advertised peer id, which is review F1, a HIGH,
         * and the reason each candidate now mints its own. Fixing F7 properly means bounding and
         * awaiting the loser's teardown first, and an unawaited stop is precisely what the current
         * code chose to avoid a stuck libp2p teardown blocking receiver creation. Filed as
         * follow-on work rather than trading a MEDIUM fix for a HIGH regression.
         */
        sr.seed.fill(0);
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
          reservationsRequested: (this.#directoryRelayEndpoints.get(agentName)?.length ?? 0) > 0,
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
    void this.#rebuildStandingReceiver(agentName);
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
      if (!sr.hasReservation || sr.relayPeerId === undefined) {
        this.#retryReservationIfDue(agentName);
        continue;
      }
      // It has one — any earlier retry budget, and the reason the last attempt failed, are stale.
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
      const stillConnected = sr.node.getConnections()
        .some((c) => c.peerId === sr.relayPeerId && c.status === "open");
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
  ): Promise<{ node: CelloNode; seed: Uint8Array }> {
    for (const circuitAddr of candidateCircuitAddrs) {
      // DOD-M12B-SESSION-SEED-1: A SEED PER CANDIDATE, NOT ONE FOR THE LOOP.
      //
      // A rejected candidate is stopped with an unawaited `void …then(() => candidate.stop())`
      // while its `start()` may still be in flight, so two candidate nodes can briefly be live at
      // once. Sharing one seed would give both the SAME peer id — and the loser would then be a
      // second live node under the identity we advertise in `session_offer_accept`, sharing this
      // gater (so it admits dials) with no content handler registered. Inbound arriving there goes
      // nowhere, and it is an open endpoint under our advertised id: the "connection a malicious
      // agent can farm for" the tenet names. Before seeds existed the loser had its own random key
      // and was harmless; introducing a shared seed is what would have made it dangerous.
      //
      // Nothing reads the seed before the winner is installed, so per-candidate costs nothing.
      const candidateSeed = randomBytes(32);
      const candidate = await this.#createAgentNode(agentName, {
        sessionId,
        connectionGater: gater,
        nodeType: "standing_receiver",
        circuitRelayListenAddrs: [circuitAddr],
        transportPrivateKey: candidateSeed,
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
        return { node: candidate, seed: candidateSeed };
      }

      const rejectionReason =
        outcome === "started"
          ? "relay_granted_no_reservation"
          : outcome === "failed"
            ? "relay_unreachable"
            : "reservation_did_not_complete_in_time";
      this.#srLastRejectionReason.set(agentName, rejectionReason);
      this.#logger.warn("session.standing_receiver.relay.rejected", {
        agentName,
        circuitAddr,
        reason: rejectionReason,
        ...(error !== "" ? { error } : {}),
        correlationId,
      });
      // Abandon it. start() may still be parked on a dial, so stop() is best-effort
      // and must never block the fallback.
      void Promise.resolve()
        .then(() => candidate.stop())
        .catch(() => { /* best-effort: the node never finished starting */ });
    }

    const plainSeed = randomBytes(32);
    const plain = await this.#createAgentNode(agentName, {
      sessionId,
      connectionGater: gater,
      nodeType: "standing_receiver",
      transportPrivateKey: plainSeed,
    });
    await plain.start();
    return { node: plain, seed: plainSeed };
  }

  /** One standing-receiver create attempt (extracted for the M8B F14 retry loop). */
  async #tryCreateStandingReceiver(
    agentName: string,
    correlationId: string,
  ): Promise<{ outcome: "installed" | "aborted" } | { outcome: "failed"; error: string }> {
    const sessionId = `standing_receiver_${randomUUID()}`;
    const gater = new SessionConnectionGater({
      sessionId,
      // No named peer: admits NOBODY inbound until a session offer names the dialer, while leaving
      // this node's own outbound errands open (DOD-M15-ASSIGN-1). It does NOT mean "open".
      allowedPeerId: null,
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
    /**
     * DOD-M12B-SESSION-SEED-1 — the transport identity of the receiver that actually survived.
     *
     * Minted per CANDIDATE inside `#startReceiverNode` and returned with the winner, not minted
     * here: a rejected candidate is stopped without awaiting its `start()`, so two candidates can
     * be briefly live, and one shared seed would put both on the same advertised peer id.
     *
     * FRESH EVERY TIME, which is the privacy property rather than an implementation detail. A
     * receiver serves at most one session (it is promoted into the session at handoff and replaced),
     * so no identifier is ever shared between two sessions and the 2026-04-11 rationale —
     * unlinkability of an agent's sessions to a passive observer — survives intact.
     */
    let seed: Uint8Array;
    try {
      ({ node, seed } = await this.#startReceiverNode(agentName, sessionId, gater, reservations.addrs, correlationId));
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
    // FROM THE ADDRESS THE NODE ACTUALLY HOLDS, not from `reservations.addrs[0]`.
    //
    // `#startReceiverNode` tries candidates in order and returns the FIRST that actually grants —
    // so when candidate 0 refuses (the measured `relay_granted_no_reservation` case) and candidate 1
    // grants, reading candidate 0's address records a relay we are not connected to. The watchdog
    // then evaluates `getConnections().some(c => c.peerId === relayPeerId)` against that wrong peer,
    // finds it false on every tick forever, and rebuilds on the 30-second grid — churning the very
    // reservations this unit exists to conserve. Dormant while the pool is size 1; the pool is
    // designed to be larger.
    // PREFER the held address, FALL BACK to the candidate — strictly better than either alone.
    // The held address is authoritative about which relay actually granted, but it is libp2p's
    // string, not ours: if a transport ever reports the circuit address without the relay's peer id
    // in `/p2p/<id>/p2p-circuit` form, reading only it would yield UNDEFINED, and an undefined
    // relayPeerId makes the watchdog treat a perfectly healthy reservation as absent and rebuild it.
    // That would be a regression on the single-relay case that works today. The candidate string is
    // ours and always carries the id, so it is the safe floor.
    const heldCircuitAddr = node.listenAddresses().find((a) => a.includes("/p2p-circuit"));
    const CIRCUIT_RELAY_ID = /\/p2p\/([^/]+)\/p2p-circuit/;
    const reservedRelayPeerId =
      circuitAddrs > 0
        ? (heldCircuitAddr?.match(CIRCUIT_RELAY_ID)?.[1] ?? reservations.addrs[0]?.match(CIRCUIT_RELAY_ID)?.[1])
        : undefined;
    // DOD-M15-ASSIGN-1 review N3: the ONE relay this receiver actually reserved with earns the
    // inbound AutoNAT carve-out — nothing else does. Set only when a reservation genuinely
    // completed, so a directory that merely NAMES a relay cannot dial in behind it.
    gater.setReservedRelayPeer(circuitAddrs > 0 && reservedRelayPeerId !== undefined ? reservedRelayPeerId : null);
    this.#standingReceivers.set(agentName, {
      node,
      gater,
      autoNat,
      seed,
      hasReservation: circuitAddrs > 0,
      ...(reservedRelayPeerId !== undefined ? { relayPeerId: reservedRelayPeerId } : {}),
    });
    this.#logger.info("session.node.created", {
      sessionId,
      agentName: `${STANDING_RECEIVER_AGENT_NAME}:${agentName}`,
      sessionPeerId: node.getPeerId(),
      correlationId,
    });

    // DOD-M15-RELAYAUTH-1: authenticate to the reservation relay NOW, not when a session first
    // needs one. The relay times out a reservation nobody has proven key possession for
    // (relay-connection-gater.ts, trustless-cello) — proving it here, instead of waiting for a
    // real session to exist, is what keeps this reservation alive past that grace window.
    // Best-effort and unawaited: a failure here costs nothing beyond the relay's own grace-window
    // revoke, which the reservation watchdog already treats as an ordinary lost reservation.
    if (reservedRelayPeerId !== undefined && heldCircuitAddr !== undefined) {
      void this.#authenticateStandingReceiver(agentName, node, reservedRelayPeerId, heldCircuitAddr, correlationId)
        .catch((err: unknown) => {
          this.#logger.warn("session.standing_receiver.relay_auth.failed", {
            agentName,
            relayPeerId: reservedRelayPeerId,
            error: extractErrorMessage(err),
            correlationId,
          });
        });
    }

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
   * DOD-M12B-SESSION-SEED-1 — build a revived session node that is REACHABLE, without ever hanging.
   *
   * MEASURED 2026-08-18, live, three ways:
   *   - handed 2 relay addrs at once, no deadline:  `start()` never completes (10,002ms and counting)
   *   - handed none:                                `start()` in 1ms, but NOBODY can dial the node —
   *                                                 the counterparty's re-dial fails
   *                                                 `counterparty_dial_failed` and every message in
   *                                                 both directions has to go the relay park route
   *   - this:                                       one candidate at a time, each raced against its
   *                                                 own deadline, plain node as the floor
   *
   * The middle option is what shipped for one test run and it made the session half-dead: revived,
   * `active`, and unreachable. The first is what shipped before that and it hung. Neither is a
   * choice between "fast" and "reliable" — the per-candidate race is how `#startReceiverNode` has
   * always done it, and it is the shape that works in production every day.
   *
   * A FAILED CANDIDATE IS TORN DOWN AT SETTLEMENT. The first version awaited `stop()` immediately
   * and claimed that made seed reuse safe; it did not — `libp2p.stop()` returns at once unless the
   * node is `'started'`, and during the timeout window it is `'starting'` (review HIGH-3, verified
   * against libp2p 3.3.2). The teardown is now chained onto the candidate's OWN start promise, so it
   * runs whenever that settles, however late.
   *
   * A BRIEF OVERLAP IS THEREFORE POSSIBLE and is stated rather than denied: a candidate that grants
   * at 4s comes up on this session's peer id and is stopped immediately after. What is guaranteed is
   * that it dies, not that it never lives. The receiver path avoids even that by minting a seed per
   * candidate; here the identity is fixed, which is the whole point of a revival, so that option
   * does not exist.
   *
   * The floor is a plain node: a session that is usable over the relay park route beats no session.
   */
  async #buildRevivedNode(
    sessionId: string,
    gater: SessionConnectionGater,
    seed: Uint8Array,
    candidateAddrs: string[],
    agentName: string,
  ): Promise<CelloNode> {
    for (const circuitAddr of candidateAddrs.slice(0, REVIVE_RESERVATION_CANDIDATES)) {
      const candidate = await this.#createAgentNode(agentName, {
        sessionId,
        connectionGater: gater,
        nodeType: "session",
        inboundReachable: true,
        transportPrivateKey: seed,
        circuitRelayListenAddrs: [circuitAddr],
      });
      // KEEP THE START PROMISE. Review HIGH-3: `libp2p.stop()` opens with
      // `if (this.status !== 'started') return`, and during the whole timeout window the status is
      // `'starting'` — so awaiting `stop()` on a timed-out candidate stopped nothing and waited for
      // nothing. The abandoned `start()` stayed in flight, and if the relay answered late the node
      // went live holding THIS SESSION'S peer id, sharing the gater (so it admits the counterparty)
      // with no content handler registered, and with no reference left to stop it. Verified against
      // libp2p 3.3.2 rather than assumed.
      const startP = candidate.start();
      let startError: unknown;
      const started = await Promise.race([
        startP.then(() => true as const),
        new Promise<false>((res) => setTimeout(() => res(false), REVIVE_RESERVATION_TIMEOUT_MS).unref?.()),
      ]).catch((err: unknown) => { startError = err; return false as const; });

      if (started && candidate.listenAddresses().some((a) => a.includes("/p2p-circuit"))) {
        this.#logger.info("session.revive.reservation.granted", { agentName, sessionId });
        return candidate;
      }
      // Started but granted nothing, or never started. Either way this node is not the one.
      //
      // Review MEDIUM-5: name WHICH of the three causes this was, the way `#startReceiverNode` does.
      // "declined" alone stood for a relay that is full, a relay that is unreachable, and a relay
      // that is merely slow — three different problems with three different responses, and the
      // thrown error was discarded entirely.
      const declineReason = started
        ? "relay_granted_no_reservation"
        : startError !== undefined
          ? "relay_unreachable"
          : "reservation_did_not_complete_in_time";
      const isLast = circuitAddr === candidateAddrs.slice(0, REVIVE_RESERVATION_CANDIDATES).at(-1);
      this.#logger.warn("session.revive.reservation.declined", {
        agentName,
        sessionId,
        circuitAddr,
        reason: declineReason,
        ...(startError !== undefined ? { error: extractErrorMessage(startError) } : {}),
        impact: isLast
          ? "no relay granted; the session comes up reachable only via the relay park route"
          : "trying the next relay",
      });
      // Teardown at SETTLEMENT, not now: a `stop()` issued while the node is still starting is a
      // no-op (see above), so the only way to guarantee this node dies is to wait for its own start
      // to finish first. Not awaited, so a hung start cannot hold the revival up — the point is that
      // the teardown eventually happens, not that it happens before the next candidate.
      void startP.then(
        () => candidate.stop().catch(() => { /* best-effort */ }),
        () => { /* never started; nothing bound */ },
      );
    }

    // THE FLOOR. No reservation, so the counterparty cannot dial us directly — but their messages
    // park at the relay and drain, which is how every message in the 2026-08-18 test arrived. A
    // session usable one way beats a session that never comes back.
    const plain = await this.#createAgentNode(agentName, {
      sessionId,
      connectionGater: gater,
      nodeType: "session",
      inboundReachable: true,
      transportPrivateKey: seed,
    });
    await plain.start();
    if (candidateAddrs.length > 0) {
      this.#logger.warn("session.revive.reservation.none", {
        agentName,
        sessionId,
        candidates: candidateAddrs.length,
        impact: "the revived session holds no circuit address — the counterparty cannot dial it, so "
          + "delivery in both directions depends on relay store-and-forward until it is rebuilt",
      });
    }
    return plain;
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

      client.registerSession(sessionId, node, this.#relayLeafHandler(agentName, sessionId, correlationId));

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
    this.clearOfferedDialer(agentName, sessionId);

    const record = this.getSessionRecord(agentName, sessionId);
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
      node = await this.#buildRevivedNode(sessionId, gater, identity.seed, reservations.addrs, agentName);
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
    const persistedRelay = this.getPersistedRelayEndpoint(agentName, sessionId);
    // 006-CRYPTO: a REVIVED session mints a FRESH keypair and re-keys — Decisions Carried #5. The
    // previous secret was destroyed at teardown and was never persisted, so there is nothing to be
    // consistent with; the salt, which IS persisted, is re-read from the row instead.
    this.#mintSessionEphemeral(agentName, sessionId);
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
    await this.#registerContentHandler(agentName, sessionId, node, identity.counterpartyPubkey);
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
    this.#wireSessionLiveness(
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
    const record = this.getSessionRecord(agentName, sessionId);
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
    const record = this.getSessionRecord(agentName, sessionId);
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
    this.#fireParkedDrain(agentName, "session_revived");
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
    await this.#ensureStandingReceiver(agentName);
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
    return this.countReceivedMessages(agentName, sessionId) + (held?.n ?? 0);
  }

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
  /**
   * DOD-M12B-STRAND-1 — move a terminal session's held frames to the annex.
   *
   * A held frame is content this agent RECEIVED and VERIFIED. When its session ends it can never
   * join that chain (appending behind a committed root is not an option, and ingest refuses a
   * terminal session outright), but it is still the operator's mail and no other copy exists —
   * the sender was never acknowledged for it. `sealed_session_annex` is where M12-P17 already puts
   * content that arrives for an ended session; this is the same content arriving slightly earlier.
   *
   * ANNEX FIRST, DELETE SECOND, per row. A crash between them costs a duplicate the annex's
   * INSERT OR IGNORE absorbs; the other order costs the message. A row whose annex write fails is
   * KEPT — the retention sweep will find it again, and a leftover row is cheaper than a lost one.
   */
  #annexHeldContentOnTerminal(agentName: string, sessionId: string, status: "sealed" | "abandoned"): void {
    if (!this.#db) return;
    let rows: Array<{ canonical_seq: number; content_blob: Buffer; content_hash_hex: string; held_at: number; origin: string }>;
    try {
      rows = this.#db.prepare(
        `SELECT canonical_seq, content_blob, content_hash_hex, held_at, origin
           FROM held_content WHERE agent_id = ? AND session_id = ? ORDER BY canonical_seq ASC`,
      ).all(this.#requireAgentId(agentName), sessionId) as never;
    } catch (err: unknown) {
      this.#logger.error("session.content.held.annex.scan.failed", {
        agentName, sessionId, status,
        impact: "held frames for a terminal session were not moved to the annex and remain unreadable",
        error: err instanceof Error ? err.message : String(err),
      });
      return;
    }
    if (rows.length === 0) return;
    const counterparty = this.getSessionRecord(agentName, sessionId)?.counterparty_pubkey ?? null;
    let annexed = 0;
    let kept = 0;
    for (const row of rows) {
      // DOD-M12B-INDEX-1: ATTRIBUTION. A `sent` row is our own message. Stamping the counterparty's
      // pubkey on it would put our words in their mouth in the one record that survives the
      // session — the same failure the release path was changed to avoid, on the drain it did not
      // touch. `#ownPubkeyHex` is null only when the identity cannot be resolved, and a null sender
      // reads as "unattributed", which is true, rather than as a false attribution.
      const sender = row.origin === "sent" ? this.#ownPubkeyHex(agentName) : counterparty;
      if (this.recordSealedAnnex(agentName, sessionId, row.content_hash_hex, new Uint8Array(row.content_blob), sender)) {
        this.#deleteHeldContent(agentName, sessionId, row.canonical_seq);
        // AND OUT OF THE IN-MEMORY MAP. Measured live 2026-08-17 on daemon 0.0.170: this frame is
        // now safe in the annex and its durable row is gone — but teardown still found it in the
        // map, counted `held_content` for the session, got 0, and fired
        // `session.content.held.lost`: "verified content was destroyed". Ten frames were annexed
        // and the same ten were reported destroyed, in the same second. A false alarm on the most
        // serious event in the system is worse than no alarm, because the next investigation goes
        // looking for content that was never lost.
        this.#heldContent.get(this.#k(agentName, sessionId))?.delete(row.canonical_seq);
        annexed++;
      } else {
        kept++;
      }
    }
    this.#logger.warn("session.content.held.annexed", {
      agentName, sessionId, status, annexed, kept,
      // The consumer of `held_at`: how long the oldest frame waited before its session ended.
      oldestHeldMs: Date.now() - Math.min(...rows.map((r) => r.held_at)),
      impact: "these messages arrived and verified but never joined the chain — they are readable from the annex, not the transcript",
    });
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
      this.#diverged.delete(this.#k(agentName, sessionId));
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
      const current = this.getSessionRecord(agentName, sessionId)?.status;
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
        this.#annexHeldContentOnTerminal(agentName, sessionId, status);
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
