/**
 * CELLO Daemon — SessionNodeManager: the shapes and the constants
 *
 * Split out of `session-node-manager.ts` by 036-GODFILE. This module is DECLARATIONS ONLY — the
 * interfaces the manager passes around, the bounds it enforces, the operator-facing reason tables,
 * and four pure helpers. No session state and no behaviour live here, which is what makes it safe
 * to import from anywhere.
 *
 * Everything is moved verbatim, comments included. The prose is the asset: much of it records why a
 * bound has the value it has, or a defect that came back once already.
 */
import { TIER, DEFAULT_TIER_BOUNDS } from "./contacts-tier-migration.js";
import type { RefusalKind } from "./refusal-reasons.js";
import { SessionConnectionGater } from "./session-connection-gater.js";
import { NodeAutoNatService, type CelloNode } from "@cello-protocol/transport";
import type { KeyProvider, LeafInput } from "@cello-protocol/crypto";
import { AgentRelayClient, type RelayAssignmentCarry, type RelayWitnessAlert } from "./session-relay-client.js";
import type { SealCarryLeaf } from "./session-seal-leaf-store.js";
import { decodeStructure1 } from "@cello-protocol/protocol-types";

export interface WitnessAlertNotice {
  /** `${relayId}::${sessionIdHex}` — the dedupe key, not shown to anyone. */
  key: string;
  alert: RelayWitnessAlert;
  occurrences: number;
  /**
   * When this witness first said it. Held SEPARATELY from `alert.observedAt`, because a later
   * repeat can replace `alert` (a provable one supersedes an unprovable one) and that must not
   * silently move the first sighting forward — an operator reading "first observed" wants to know
   * when this started, not when the strongest version of it arrived.
   */
  firstObservedAt: number;
  lastObservedAt: number;
}



/** SEC-1 / review M4: cap on the refused-parked-entry memo (remote-fed → must be bounded). */
/**
 * How long the auto-acknowledge path holds its broker visiting connection AFTER submitting the seal
 * leaf. The directory pushes `seal_verified` back ~60ms later (measured on GCP), so releasing on
 * submit closed the stream before the frame it was opened for. Generous against 60ms, and bounded so
 * a stalled seal cannot leak the connection.
 */
export const AUTOACK_BROKER_GRACE_MS = 30_000;

export const MAX_REFUSED_PARKED_ENTRIES = 512;
/**
 * Per-session cap on remembered unreadable-algorithm frames (`DOD-M15-SEALWIRE-1` part B1).
 *
 * Fed by a REMOTE party — a peer on a newer build refuses every frame it sends — so it needs a
 * bound for the same reason `MAX_REFUSED_PARKED_ENTRIES` does. Small on purpose: the entries exist
 * only to reconcile a refusal with its park-route redelivery, which happens within seconds, and
 * losing an old one costs a log line rather than correctness.
 */
export const MAX_UNREADABLE_ALG_FRAMES = 64;

/**
 * How many consumers' read positions a single refusal notice remembers.
 *
 * A consumer id is an IPC connection id, so every reconnect mints a new one and the read state would
 * otherwise grow without bound in a durable table. Sixteen is far above the real number of windows
 * attending one agent; past that the OLDEST reader is evicted, which costs at worst one repeated
 * announcement to a window that has already gone.
 */
export const MAX_REFUSAL_READERS = 16;

/**
 * How many refusal notices one read returns, newest first.
 *
 * Review F3. The store is never emptied for an agent — a refusal records something that happened —
 * and read state is per IPC connection, so a fresh window after a restart is entitled to every
 * notice ever recorded. Uncapped, the answer to "why did this conversation go quiet?" was at the
 * bottom of an archive. Capped and newest-first, the recent cause leads and the caller is TOLD the
 * list was cut (`refusals_incomplete`), rather than the tail vanishing silently.
 */
export const MAX_REFUSALS_PER_READ = 25;

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
export const SALT_AGREEMENT_WAIT_MS = 5_000;

/**
 * How many times this side re-attempts its session-key announce, and the base delay between them.
 *
 * Bounded on purpose (review F5): the announce rides `onPeerConnect`, so a connection that stays up
 * after one failed attempt would never produce another — encryption off for the life of the session,
 * with guidance pointing at a reconnect that never comes.
 */
export const SESSION_KEY_ANNOUNCE_RETRIES = 4;
export const SESSION_KEY_ANNOUNCE_RETRY_MS = 250;

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
export const UNSALTED_REASONS = {
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

export type UnsaltedReason = (typeof UNSALTED_REASONS)[keyof typeof UNSALTED_REASONS];

/**
 * What the operator should DO about each. TOTAL by construction — a `Record` over the union, so a
 * new reason cannot be added without something for the reader to act on. Same shape, and the same
 * reason, as `refusal-reasons.ts`: that file exists because a free-form `reason: string` let a new
 * code slip past every test in its own guard file.
 */
export const UNSALTED_GUIDANCE: Record<UnsaltedReason, string> = {
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
export const CONTENT_MAX_INBOUND_STREAMS = 512;

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
export const CONTENT_STREAM_LINGER_MS = 30_000;

/**
 * DOD-M12B-SHUTDOWN-1 — how long one teardown step may block the daemon's exit.
 *
 * Chosen against the surface that complains: `cello logout` gives up and reports the daemon still
 * running after 5 s, so a step that can burn longer than that guarantees the message the operator
 * saw. Two steps at 2 s each stay inside it.
 */
export const SHUTDOWN_STEP_DEADLINE_MS = 2_000;

/**
 * DOD-M12B-REDIAL-1 — the shortest gap between two re-dials of one session.
 *
 * Long enough that a burst of sends against a peer that is genuinely gone costs one dial rather
 * than one per message; short enough that a peer coming back is picked up on the next thing the
 * operator says. It is cleared on a successful dial, so it never delays a live counterparty.
 */
export const REDIAL_COOLDOWN_MS = 15_000;

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

/** The relay peer id inside a `/…/p2p/<relay>/p2p-circuit/…` address. */
export const CIRCUIT_RELAY_ID = /\/p2p\/([^/]+)\/p2p-circuit/;

/**
 * 032-RELAYSPREAD — the relays a node ACTUALLY HOLDS a circuit with, read off the addresses it is
 * announcing. One entry per relay, deduped.
 *
 * This is the single definition of "a reservation is held", and it is deliberately the strictest
 * one available: an ANNOUNCED circuit address. `start()` resolving is not enough — a relay out of
 * reservation slots completes the handshake, grants nothing, and leaves a node that looks started
 * and is dialable by nobody. Nor is a candidate address enough: a candidate is a relay we asked.
 */
export function heldRelayIdsOf(node: CelloNode): string[] {
  const ids = new Set<string>();
  for (const addr of node.listenAddresses()) {
    if (!addr.includes("/p2p-circuit")) continue;
    const id = CIRCUIT_RELAY_ID.exec(addr)?.[1];
    if (id !== undefined) ids.add(id);
  }
  return [...ids];
}

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
export const CAP_COUNTS = (alias = ""): string => {
  const p = alias ? `${alias}.` : "";
  return `(${p}status = 'active'
           OR (${p}status = 'interrupted'
               AND COALESCE(${p}interrupted_by, 'counterparty') != 'local'
               AND ${p}updated_at >= ?))`;
};
export const CAP_COUNT_SQL = (where: string): string =>
  `SELECT COUNT(*) AS n FROM sessions WHERE ${where} AND ${CAP_COUNTS()}`;

/** The cutoff an interrupted session must be newer than to still count. */
export const capStaleBefore = (): number => Date.now() - CAP_INTERRUPTED_TTL_MS;

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
  /**
   * `content_key` added by `029c` review F7: a send that failed because this machine had no content
   * encryption key — never agreed, or gone between the preflight and the seal — is a LOCAL key
   * fault, not a transport one. Reported as `direct_send` it sent the operator to inspect a
   * connection that was working.
   */
  cause: "direct_send" | "delivery_ack" | "content_key";
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
export interface SessionRevivalIdentity {
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

export interface ActiveSessionEntry {
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
export interface ReceivedContentEntry {
  contentHex: string;
  senderPubkey: string;
  sequenceNumber: number;
}

// ─── Result types ─────────────────────────────────────────────────────────────

export type CreateSessionResult =
  | { ok: true; peerId: string; addrs: string[] }
  | { ok: false; reason: string; guidance: string };

// ─── SessionNodeManager ───────────────────────────────────────────────────────

/**
 * DOD-COATTEND-1: how much of the arrival buffer is kept. Delivery reads the durable transcript
 * now, so this buffer is only a recency hint (`peekLatestReceivedContentHex` for M8C-AWAY-1's
 * [[WRAP]] check). Small, and stated: an unstated cap is a silent truncation, and no cap at all is
 * the leak the old destructive read was accidentally preventing.
 */
export const RECEIVED_BUFFER_CAP = 32;

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
export type ParkAttempt = { outcome: "parked" | "refused" | "unconfigured"; cause?: string; retryAfterMs?: number };

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
 * DOD-M15-REFUSALTERMINAL-1 — the refusal reasons no retry can ever get past.
 *
 * MEASURED LIVE 2026-09-04: one message aimed at a conversation the counterparty had already
 * closed, refused `session_committed` and re-fetched roughly twice a second for 62 hours across
 * several daemon restarts — 232,056 refusal events on that one session and a 484 MB `daemon.log`.
 *
 * **WHY `session_committed` QUALIFIES.** A committed session carries a signature over its contents.
 * Nothing can be appended to it by anyone — not the counterparty, not us — so there is no future
 * state in which this content is accepted. That is the bar, and it is the whole bar.
 *
 * **⚠️ DO NOT ADD A REASON WITHOUT MEETING IT.** A reason wrongly called terminal silently drops a
 * message that would have arrived on the next try, which is worse than the loop this set exists to
 * end. The tempting ones and why each fails:
 *
 *   - `content_hash_mismatch` — the fetch is BY CONTENT HASH, and a later fetch may retrieve a
 *     correct copy from a different relay. Retrying can succeed.
 *   - `sender_unresolved` — the sender may become resolvable when a profile arrives or a directory
 *     syncs. Retrying can succeed.
 *   - `session_orphaned` — `024-ORPHANTRIAGE` owns that path and decides its disposition.
 *   - `session_size_limit_exceeded` — the cap IS monotonic, but its bound is a setting, and an
 *     operator who raises it must be able to un-stick the conversation.
 *   - a transient screener block — transient is in its name.
 */
/**
 * ⚠️ NOT the same concept as `session-terminal-refusal.ts` (`DOD-MP-SESSION-RETIRE-1`), which is the
 * RELAY terminally refusing one of OUR SENDS. This set is about INBOUND content this side will
 * never accept. Two "terminal refusal" ideas live in this daemon and they point in opposite
 * directions — review F9.
 */
export const TERMINAL_REFUSAL_REASONS: ReadonlySet<string> = new Set(["session_committed"]);

/**
 * DOD-M15-REFUSALTERMINAL-1 review F3 — how long a FAILED read of the terminal-refusal rows is
 * backed off for, per session.
 *
 * A minute: long enough that a database throwing on every witnessed leaf produces one ERROR rather
 * than one per message (the exact log growth this unit exists to end), short enough that a disk
 * which recovers is noticed within a message or two rather than at the next restart.
 */
export const TERMINAL_REFUSAL_READ_RETRY_MS = 60_000;

/**
 * DOD-M15-REFUSALTERMINAL-1 review F7 — how many terminally-refused content hashes are remembered
 * per session.
 *
 * The counterparty chooses how many rows this table gets: one per distinct message aimed at a
 * closed conversation, written even after the byte cap has stopped retaining evidence. 512 matches
 * `MAX_REFUSED_PARKED_ENTRIES`, is far above any honest volume for a conversation that has ENDED,
 * and bounds the table at (sessions × 512) small rows.
 */
export const MAX_TERMINAL_REFUSALS_PER_SESSION = 512;

/**
 * DOD-M15-REFUSALTERMINAL-1 — ONE refusal, TWO counts, and the NAMES are the fix.
 *
 * The inbox reported `times: 58` for a refusal that had fired tens of thousands of times, and the
 * code was not wrong — the sentence describing it was. One number is "since you last dismissed this
 * conversation" and the other is "ever". Neither may be called `times`, because that is the word an
 * operator, and an agent deciding whether to escalate, reads as a lifetime figure.
 */
export interface RefusalNotice {
  sessionId: string;
  reason: string;
  kind: RefusalKind;
  impact: string;
  guidance: string;
  /** Refusals of this reason on this session since the last `cello_dismiss` — which DELETES the
   *  notice row, restarting this counter at 1. Zero dismissals and it equals `timesTotal`. */
  timesSinceDismissed: number;
  /**
   * Every refusal of this reason on this session, from the first one, untouched by dismissal.
   *
   * OMITTED, never guessed, when the notice is served from the in-memory fallback — that path
   * exists precisely because the database write failed, so no durable total was ever written, and
   * reporting the smaller number twice would put the original lie back with two names on it.
   *
   * MUTUALLY EXCLUSIVE with `timesTotalAtLeast`: a figure and a floor are different claims and
   * must not share a name.
   */
  timesTotal?: number;
  /**
   * A LOWER BOUND on the lifetime count, for a row SEEDED at upgrade from a notice that already
   * existed — review F1c.
   *
   * The seed is that notice's `count`, which is refusals since the last dismissal, so the true
   * figure is at least this and may be far more: on the machine this unit was written for, the
   * notice read 58 and the log held 232,056 refusal events. Reporting 58 as `timesTotal` would be
   * the original defect with the new name on it. "At least 58" is true; "58" is not.
   */
  timesTotalAtLeast?: number;
  repeat?: boolean;
}


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

/**
 * `DOD-M15-AUTHORSHIP-ABSENT-1` — the answer to "did the sender prove they wrote this message?",
 * with the three NOT-YES cases kept apart because they are three different facts about the peer.
 *
 * The distinction that matters is between `refuted` and `unusable`, and getting it backwards is the
 * trap this unit was written against:
 *
 *   - `refuted`   — a proof was supplied and it FAILED. That is evidence about the counterparty's
 *                   key, and it freezes the session (`#freezeOnIdentityFailure`).
 *   - `unusable`  — there is nothing here that could be checked against this message. Almost always
 *                   a peer on an older build; possibly someone stripping the field. It refuses THE
 *                   MESSAGE and leaves the session alone, because freezing on it would turn every
 *                   version skew into an incident only a new session can clear.
 *
 * Absent is not a fourth case: a frame with no `sender_signature` never reaches the verifier, and
 * its caller refuses it on the same path an `unusable` verdict takes. Missing, malformed and
 * mismatched arrive at one outcome, which is the rule this whole class of defect comes from.
 */
export type AuthorshipVerdict =
  /** Signature verified against the key inside the signed bytes, and that key IS this session's counterparty. */
  | { verdict: "verified"; senderPubkey: Uint8Array; senderSig: Uint8Array }
  /**
   * 024-ORPHANTRIAGE: the signature VERIFIED and there was no session record to match it against.
   *
   * ⚠️ **DELIBERATELY A SEPARATE VERDICT, NOT A `verified` WITH A FLAG.** `verified` means *verified
   * AND matched to this session's counterparty*; the transcript column it feeds is documented as
   * exactly that ("verified, never claimed") and seal-time attribution rests on it. Returning an
   * unmatched signer under that name would silently widen a proof the rest of the system reads as
   * stronger. This one carries the weaker fact under its own name, and has exactly one consumer:
   * the orphan branch, which needs to tell an operator whether anything at all is known about who
   * sent a message for a conversation that does not exist here.
   */
  | { verdict: "verified_unmatched"; senderPubkey: Uint8Array }
  /** A proof was supplied and it is WRONG. Identity failure — fatal for the session. */
  | { verdict: "refuted"; reason: "bad_signature" | "signer_not_counterparty" }
  /** Nothing checkable arrived. Refuses the message; says nothing about the counterparty's key. */
  | { verdict: "unusable"; reason: string };

/**
 * The `unusable` reason for a proof that is real and describes some OTHER message.
 *
 * ⚠️ NOT `"content_hash_mismatch"` — review §6. That string is already the refusal reason for the
 * RECEIVER's own recompute failing (`ingestReceivedContent`), which is a tamper signal about the
 * BODY. This one says the sender's signed claim is about different content. Two different failures
 * sharing one name is a collision an operator grepping the log walks straight into.
 */
export const AUTHORSHIP_CONTENT_HASH_MISMATCH = "authorship_hash_mismatch";

/**
 * The `unusable` reason for a proof that is real, is by the right signer, describes this content —
 * and was signed for a DIFFERENT conversation. A replay, not a forgery.
 *
 * Every one of those properties has been ESTABLISHED by the time this is returned; see the ordering
 * note in `#verifyAuthorshipClaim`. An earlier version of this sentence was true of the intent and
 * not of the code, because the check ran before the signature was verified.
 */
export const AUTHORSHIP_SESSION_MISMATCH = "session_mismatch";

/**
 * ─── 033-ACKEMIT: the three things that can be wrong with an ACKNOWLEDGEMENT ─────────────────────
 *
 * All three are `unusable` — the message is refused and the session lives. None of them is an
 * identity fault: by the time any is returned the signature has verified, the signer IS this
 * session's counterparty, and the claim is about this content in this conversation. What is wrong is
 * what the claim says the sender had SEEN.
 *
 * They are three names and not one because the operator's next move differs for each, and because an
 * investigator who cannot tell "your counterparty is on an older build" from "your counterparty
 * acknowledged something you never sent" is looking at the wrong half of the problem.
 *
 * ⚠️ **NAME WHAT WAS OBSERVED, NEVER AN INFERRED CONCLUSION** (`DOD-M15-ERRSTRING-1`). Not one of
 * these says "peer is malicious" — a mismatch is equally what a genuine software fault on the other
 * side looks like, and an error that names a party the code did not check is this milestone's
 * founding defect.
 */

/**
 * `DOD-M15-SELFCHAIN-1` — the sender's link to their OWN previous message names content this side
 * did not receive from them as their last one.
 *
 * ⚠️ THIS IS THE ONE THAT MEANS THE ORDER OF THE CONVERSATION IS IN DISPUTE, and it is why it is
 * named apart from the acknowledgement reasons above rather than folded in with them. Those say the
 * sender is wrong about what WE said; this says they are wrong about what THEY said, which is the
 * only thing they cannot be honestly mistaken about for long.
 *
 * ⚠️ AND IT STILL NAMES WHAT WAS OBSERVED, NEVER A CONCLUSION. The same signal is produced by a
 * peer reordering a conversation and by a peer whose own chain record went out of step after a
 * restart, and this side cannot tell them apart.
 */
export const AUTHORSHIP_SELF_CHAIN_MISMATCH = "self_chain_mismatch";

/** The hash names content this side does not hold at the position the claim names. */
export const AUTHORSHIP_ACK_HASH_MISMATCH = "ack_hash_mismatch";

/** The hash names content this side has never held — not in the tree, and not held pending a gap. */
export const AUTHORSHIP_ACK_HASH_UNKNOWN = "ack_hash_unknown_content";


/**
 * The set that routes an `unusable` reason to the acknowledgement wording rather than the generic
 * one. A SET, not a string prefix test: a name-shaped check would silently adopt any future reason
 * someone happens to call `ack_*`, and give it a sentence written for these three.
 */
export type AckHashReason =
  typeof AUTHORSHIP_ACK_HASH_MISMATCH | typeof AUTHORSHIP_ACK_HASH_UNKNOWN;

export const ACK_HASH_REASONS: ReadonlySet<string> = new Set<string>([
  AUTHORSHIP_ACK_HASH_MISMATCH,
  AUTHORSHIP_ACK_HASH_UNKNOWN,
]);

/**
 * ⚠️ **THE REFUSALS THAT SAY THIS ARE THE ONES WHERE THE REFUSAL DOES NOT HOLD — NOT ALL OF THEM.**
 *
 * It said "EVERY INBOUND REFUSAL SAYS THIS", and review F5 measured that: fifteen call sites file a
 * refusal notice in this file and four carry this sentence — the three encryption causes and the
 * authorship one. The rest MUST NOT. A screened-out message is deliberately never delivered by any
 * route, and a transcript write failure lost content that was already accepted; promising either
 * operator a second chance would be a lie in the opposite direction. Rewritten rather than deleted,
 * because "EVERY" read as a rule and the next person to add a refusal would have applied it blindly.
 *
 * Where it DOES apply: refusing an inbound frame sends back no delivery acknowledgement, so a CELLO
 * sender's TTF backstop parks a copy in the relay mailbox — sealed to this agent's LONG-TERM
 * IDENTITY key, not the session key — and recovery opens that one whatever went wrong with the
 * direct copy.
 *
 * ⚠️ AND ONLY WHEN THIS MACHINE CAN OPEN ONE. See `REFUSAL_NO_OTHER_ROUTE`; the choice is made by
 * `#mailboxRouteAvailable`, never by a caller writing the sentence into a literal.
 */
export const REFUSAL_MAY_STILL_ARRIVE =
  "IT MAY STILL REACH YOU BY THE OTHER ROUTE: a refusal sends back no acknowledgement, so a CELLO " +
  "counterparty's agent parks a copy in the relay mailbox and this side opens that one with your " +
  "long-term key instead of this session's. If it arrives, it arrives without whatever this check " +
  "was unable to confirm — and if they are not running CELLO, there is no such copy and it will " +
  "not arrive.";

/**
 * ⚠️ **THE OTHER ROUTE DOES NOT EXIST ON THIS MACHINE, AND SAYING SO IS THE POINT** — review F2.
 *
 * Opening a mailbox copy needs `KeyProvider.openContentSeal`, which is OPTIONAL: a threshold or
 * signing-only provider does not implement it, and an agent loaded without a provider has none at
 * all. `content-park.ts` refuses both — `signing_key_unavailable`, `cannot_unseal`.
 *
 * That is the SAME condition `CONTENT_ENCRYPTION_REASONS.NO_LOCAL_IDENTITY` reports. So on the one
 * refusal that names a missing local identity, the reassurance above was false: both routes are shut
 * by one cause, permanently, for every message on every session of that agent — and the operator was
 * told to wait for a delivery that cannot happen. That is the H1 defect exactly: a refusal
 * announcing a better outcome than it delivers.
 */
export const REFUSAL_NO_OTHER_ROUTE =
  "AND IT WILL NOT REACH YOU BY THE OTHER ROUTE EITHER: the relay mailbox copy is opened with this " +
  "agent's long-term identity key, which is the very thing this machine is missing. One cause shuts " +
  "both routes, and it will keep shutting them until the agent is loaded with its identity key. Do " +
  "not wait for this message to turn up.";

/**
 * Constant-shape byte equality for the two binding checks. Lifted rather than hand-rolled a second
 * time — `seal-frontier-verify` has the same helper for the same comparison, and two copies of
 * "are these the same bytes" is two things to keep true.
 */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * One row of a session's durable transcript as a reader sees it.
 *
 * DOD-M15-REFUSEDEVIDENCE-1: `'quarantined'` is a message that was received and REFUSED. Its `text`
 * is the withholding statement, never the payload — the storage is complete and only the READ is
 * redacted. `withheld` is present exactly on those rows so a caller can style or skip them without
 * string-matching the statement.
 */
export interface TranscriptEntry {
  sequence: number;
  direction: "sent" | "received" | "quarantined";
  text: string;
  createdAt: number;
  refusalReason?: string;
  withheld?: true;
  /** Named to end in `guidance` on purpose: that suffix is what the vocabulary layer rewrites, so a
   *  CLI reader is told `cello quarantined` and an MCP reader `cello_quarantined`. */
  withheld_guidance?: string;
}

/** A retained refused message, read back whole. The payload is handed out FRAMED, never raw. */
export interface QuarantinedRecord {
  sequence: number;
  reason: string;
  content: Uint8Array;
  senderPubkeyHex: string | null;
  senderSig: Uint8Array | null;
  attribution: string;
  createdAt: number;
}

/**
 * The relay's peer id out of a circuit listen address, or `null` if the address does not name one.
 *
 * Returns null rather than throwing or guessing: an unreadable address means we cannot tell which
 * relay this candidate was for, and every caller has a real thing to do with that answer.
 */
export function relayPeerIdOf(circuitAddr: string): string | null {
  return /\/p2p\/([^/]+)\/p2p-circuit/.exec(circuitAddr)?.[1] ?? null;
}

/**
 * The Merkle leaf inputs for a seal carry: each leaf's `content_hash`, read out of the bytes its
 * SENDER SIGNED (`structure1_cbor`), never out of an envelope field somebody else filled in.
 *
 * `null` when any leaf is unreadable — the caller must then answer "I cannot judge", never "we
 * disagree". A decode failure is this daemon's limitation, not evidence against anyone.
 *
 * Canonical Structure 1 is `[version, content_hash, sender_pubkey, session_id, last_seen_seq,
 * timestamp]`, plus `last_seen_hash` at index 6 on a v2 claim (020-ACKHASH). The content hash is at
 * index 1 in both and is used AS the leaf hash (RFC 6962 §2.1 "hash" leaves are taken as-is), which
 * is the domain the certified root lives in.
 */
export function carryContentHashInputs(carry: readonly SealCarryLeaf[]): LeafInput[] | null {
  const inputs: LeafInput[] = [];
  for (const leaf of carry) {
    const s1 = decodeStructure1(leaf.structure1Cbor);
    if (!s1.ok) return null;
    inputs.push({ kind: "hash", data: s1.fields.contentHash });
  }
  return inputs;
}

/**
 * How many of the counterparty's content hashes a session remembers for the self-link check.
 *
 * Bounded because a peer feeds it. 256 covers any realistic gap in our own copy of a conversation —
 * a held message, one the inbound screen refused, one lost in flight — while keeping the memory a
 * single session can cost fixed. Past the cap the check gets STRICTER, never looser.
 */
export const SELF_CHAIN_MEMORY = 256;

