/**
 * Daemon-side relay witness client (PER AGENT).
 *
 * In CELLO the relay is the ordering/witness authority (Structure 2): it never sees
 * plaintext (content is peer↔peer), only the SIGNED content-hash leaves. It assigns
 * the canonical `sequence_number` and forwards each witnessed leaf to the counterparty
 * (`leaf_deliver`). A `cello_send` whose hash the relay never witnessed has no canonical
 * sequence and is not a complete CELLO message — so the session submits the message leaf
 * hash here, in parallel with the direct content delivery.
 *
 * ONE stream per AGENT, not per session. The relay authenticates a stream by the agent's
 * K_local pubkey and keys its delivery/queue maps by that pubkey (relay-node
 * #handleRelayStream / #processHashSubmit), so a second stream for the same pubkey would
 * OVERWRITE the first's delivery stream and steal its queued `leaf_deliver`s. The protocol
 * is designed for one relay connection per agent identity multiplexing all that agent's
 * sessions — every wire frame carries `session_id`. So this client is shared across an
 * agent's sessions: submits are globally FIFO-serialized on the stream (a `hash_submit_ack`
 * carries NO session_id, so at most one submit may be outstanding at a time and acks match
 * the queue head in order), while inbound `leaf_deliver` (which DOES carry `session_id`) is
 * routed to the owning session's handler.
 *
 * The stream is (re)dialed from whatever live session node is current at submit time, so it
 * survives individual session teardown (the relay treats a same-pubkey reconnect as a
 * reconnect, re-auths, and re-drains).
 *
 * The server contract this must match: `packages/relay/src/relay-node.ts`.
 *
 * Crypto: Ed25519 RFC 8032. Relay auth domain: "CELLO-RELAY-AUTH-v1".
 */
import { createHash } from "node:crypto";
import * as lp from "it-length-prefixed";
import { decode } from "cbor-x";
import { encodeCbor, decodeSealPayload, encodeStructure1, decodeStructure1, computeGenesisPrevRoot } from "@cello-protocol/protocol-types";
import type { Stream } from "@libp2p/interface";
import type { CelloNode } from "@cello-protocol/transport";
import { verify, type KeyProvider } from "@cello-protocol/crypto";
import type { Logger } from "./types.js";
import { extractErrorMessage } from "./error-message.js";
import { evaluateRelayAck, type RelayReceiptStore } from "./relay-receipt-store.js";
import type { SessionSealLeafStore } from "./session-seal-leaf-store.js";
import type { SessionOwnChainStore } from "./session-own-chain-store.js";


export const RELAY_PROTOCOL_ID = "/cello/relay/1.0.0";
export const RELAY_AUTH_DOMAIN = "CELLO-RELAY-AUTH-v1";
/** Structure 1 leaf kind: 0x00 = message, 0x02 = control (matches the relay). */
/**
 * DOD-WITNESS-STALL-1 — relay refusals that can NEVER resolve.
 *
 * `sendContent` treats a failed leaf-hash submit as a transient degradation: the content is real,
 * the peer still gets it, and the canonical sequence is recovered later. That is correct for a relay
 * that is briefly unreachable.
 *
 * It is WRONG for these two. They mean the relay has ended the session — there is no later, and
 * nothing sent from here can ever enter the record. Collapsing them into the transient case is what
 * let a conversation run for 68 minutes and 8 messages, every send reporting `delivered: true`,
 * against a chain that had stopped growing.
 *
 * ENUMERATED, never pattern-matched. A substring rule like `reason.includes("sealed")` would absorb
 * a future reason nobody has considered — which is the same collapse in a new coat.
 */
export const TERMINAL_RELAY_REFUSALS: ReadonlySet<string> = new Set([
  "session_sealed",
  "session_not_found",
  /**
   * `DOD-M15-TERMINAL-REASON-1` split `session_sealed` into named causes, and this set is one of
   * THREE places keyed on the old literal — a rename on the relay silently made a terminal refusal
   * non-terminal here, which is the 68-minute defect above reopened by a string change.
   *
   * `seal_refused`: a directory READ the seal and rejected it. Terminal in the strongest sense —
   * there is no later, and no retry can change a merits verdict.
   *
   * `seal_in_progress` is deliberately ABSENT. A seal in flight may still succeed, and after
   * `DOD-M15-TRANSPORT-TERMINAL-1` the session can return to `active` — treating it as terminal
   * would retire a conversation that is about to seal normally.
   */
  "seal_refused",
]);

/** True when the relay has ended this session and no later submit can succeed. */
export function isTerminalRelayRefusal(reason: string | undefined): boolean {
  return reason !== undefined && TERMINAL_RELAY_REFUSALS.has(reason);
}

/**
 * DOD-M15-RELAYSLOTS-1 — why a relay refused to let this agent hold a reservation slot, in the
 * shape the daemon and the operator both need.
 *
 * `reason` is the relay's own code, unmodified. `advice` is what the person reading it should DO,
 * chosen for that specific cause. `tryAnotherRelay` is the machine half of the same question.
 */
export interface RelayAuthRefusal {
  reason: string;
  advice: string;
  tryAnotherRelay: boolean;
  /** Present when the relay said how many slots are held and what its cap is. */
  slotsHeld?: number;
  slotCap?: number;
  /** Present when the relay said when to come back. */
  retryAfterMs?: number;
}

/**
 * DOD-M15-RELAYSLOTS-1 — **WHICH REFUSALS JUSTIFY TRYING A DIFFERENT RELAY.**
 *
 * We run several relays, so "move on to the next one" is always available — which is exactly why it
 * needs a rule. Moving on from a problem that every relay will have turns one client-side fault into
 * what looks like a fleet-wide outage, and the operator then goes looking for a broken relay.
 *
 * ENUMERATED, never pattern-matched, for the same reason `TERMINAL_RELAY_REFUSALS` is: a substring
 * rule would silently absorb a future reason nobody has considered.
 */
const RELAY_SIDE_REFUSALS: ReadonlySet<string> = new Set([
  /**
   * The relay holds no directory public key, so it can verify nothing and is refusing everyone.
   * That is this relay being misconfigured, not us being wrong — another relay is the right move,
   * and it is the whole reason we run more than one.
   */
  "online_token_no_directory_key",
]);

/**
 * Classify a relay's auth refusal: what to tell the operator, and whether another relay would help.
 *
 * Everything not in `RELAY_SIDE_REFUSALS` defaults to "do not try another", and that default is the
 * safe direction. A token problem reproduces identically on every relay in the fleet, so retrying
 * around the fleet spends real time turning a client fault into an apparent outage — and a slot cap
 * IS satisfiable elsewhere, but spreading to another relay papers over sessions that leaked and
 * brings the same wall back on the next one.
 */
export function classifyRelayAuthRefusal(
  reason: string,
  extra: { slotsHeld?: number; slotCap?: number; retryAfterMs?: number } = {},
): RelayAuthRefusal {
  const tryAnotherRelay = RELAY_SIDE_REFUSALS.has(reason);
  let advice: string;
  switch (reason) {
    case "online_token_required":
      advice = "This agent has no online token from a directory yet. It is issued when a directory " +
        "marks the agent online, so this usually clears itself on the next directory connection. If " +
        "it persists, the agent is not reaching any directory — check that first, not the relay.";
      break;
    case "online_token_expired":
      advice = "The online token has expired and is refreshed on the next directory connection. If " +
        "it keeps expiring, this machine's clock or its directory connection is the thing to look at.";
      break;
    case "online_token_signature_invalid":
    case "online_token_malformed":
    case "online_token_lifetime_too_long":
      advice = "This relay would not accept the token this agent was issued. Most often the relay " +
        "and the directory are not in the same consortium — check which directories this relay is " +
        "configured to trust.";
      break;
    case "online_token_pubkey_mismatch":
      advice = "The token names a different key from the one this agent signed with. That is an " +
        "identity mix-up on this machine, not a relay problem.";
      break;
    case "online_token_no_directory_key":
      advice = "This relay holds no directory public key, so it cannot verify anyone and is " +
        "refusing every agent. Its operator needs to configure one; another relay will work now.";
      break;
    case "slot_cap_exceeded":
      advice = extra.slotsHeld !== undefined && extra.slotCap !== undefined
        ? `This agent already holds ${String(extra.slotsHeld)} of a maximum ${String(extra.slotCap)} ` +
          "reservations on this relay, and none is idle enough to reclaim. That is almost always " +
          "sessions that were never closed — close some and this clears. Moving to another relay " +
          "would work now and hit the same wall there."
        : "This agent already holds the most reservations one agent may hold on this relay. That is " +
          "almost always sessions that were never closed — close some and this clears.";
      break;
    case "session_tuple_cap_exceeded":
      advice = extra.slotsHeld !== undefined && extra.slotCap !== undefined
        ? `You already have ${String(extra.slotsHeld)} conversations open with this counterparty, ` +
          `which is the maximum of ${String(extra.slotCap)} this relay allows between one pair of ` +
          "agents. Close some and try again — this is almost always conversations that were never " +
          "closed rather than ones anybody is still using."
        : "You already have the maximum number of concurrent conversations open with this " +
          "counterparty. Close some and try again.";
      break;
    case "rate_limited":
      advice = extra.retryAfterMs !== undefined
        ? `This relay is throttling this agent; it clears on its own in about ${String(Math.ceil(extra.retryAfterMs / 1000))}s.`
        : "This relay is throttling this agent; it clears on its own after the throttle window.";
      break;
    default:
      advice = "This agent could not authenticate to this relay, so it cannot hold a reservation " +
        "here and is reachable only over a direct connection.";
  }
  return {
    reason,
    advice,
    tryAnotherRelay,
    ...(extra.slotsHeld !== undefined ? { slotsHeld: extra.slotsHeld } : {}),
    ...(extra.slotCap !== undefined ? { slotCap: extra.slotCap } : {}),
    ...(extra.retryAfterMs !== undefined ? { retryAfterMs: extra.retryAfterMs } : {}),
  };
}

export const LEAF_KIND_MSG = 0x00;
/** Control leaf (SEAL etc.) — two distinct-sender ctrl leaves trigger directory notarization. */
export const LEAF_KIND_CTRL = 0x02;
/** Document-operation leaf (DOD-DOC-LEAF-1): a CRDT update riding the session tree. */
export const LEAF_KIND_DOC = 0x04;
/** Rejection leaf (DOD-DOC-LEAF-1): references the rejected update envelope's hash. */
export const LEAF_KIND_REJECT = 0x05;

const RELAY_AUTH_TIMEOUT_MS = 5_000;
const HASH_SUBMIT_TIMEOUT_MS = 10_000;

/**
 * The Ed25519-signed payload that proves K_local ownership to the relay:
 * SHA-256("CELLO-RELAY-AUTH-v1" || nonce || pubkey). The relay verifies the
 * signature against exactly this hash (relay-node #handleRelayStream).
 */
export function buildRelayAuthPayload(nonce: Uint8Array, pubkey: Uint8Array): Uint8Array {
  const domain = Buffer.from(RELAY_AUTH_DOMAIN, "utf8");
  const authMsg = Buffer.concat([domain, nonce, pubkey]);
  return new Uint8Array(createHash("sha256").update(authMsg).digest());
}

export interface LeafDeliverFrame {
  sequence_number: number;
  leaf_kind: number;
  structure1_cbor: Uint8Array;
  structure2_cbor: Uint8Array;
  /**
   * True when the relay echoed back OUR OWN submitted leaf (sender_pubkey ===
   * our K_local), false when it is a genuine COUNTERPARTY leaf. The auto-acknowledge gate uses
   * this to never auto-co-sign in response to its own SEAL ctrl leaf (which would loop). An
   * explicit field — the consumer must not have to re-decode structure1_cbor to learn it.
   */
  authored_by_us: boolean;
}

/** Result of a single relay hash submission. */
export type SubmitResult =
  | {
      ok: true;
      sequence_number: number;
      // The signed ordering record for THIS leaf, so the sender can stamp it into the content frame.
      // structure1_cbor is the sender-signed bytes (built locally); structure2_cbor is the relay's
      // committed record (from hash_submit_ack). Both undefined against an OLD relay that does not
      // return structure2_cbor.
      structure1_cbor?: Uint8Array;
      structure2_cbor?: Uint8Array;
      /**
       * DOD-M15-SEALWIRE-1 bullet 5, SENT half — OUR signature over `structure1_cbor`.
       *
       * It is already computed on the submit path (`keyProvider.sign(structure1)`) and put on the
       * wire as `sender_signature`; it simply was not handed back, so the transcript row for a
       * message THIS agent sent stored no proof of authorship at all.
       *
       * Why that matters and is not symmetry for its own sake: a RECEIVED row carries the
       * counterparty's pubkey and signature, so a third party can check it. A SENT row carried
       * `attribution: "self_authored"` and nothing else — fine for its owner, who already knows, and
       * **worth nothing to the auditor the bullet exists for.** Half a transcript was provable.
       *
       * Undefined on the relay-degraded path, where no submit happens and there is nothing to sign.
       */
      sender_signature?: Uint8Array;
    }
  | {
      ok: false;
      reason: string;
      /**
       * The relay's own words about what went wrong — `relay-types.ts`'s stated invariant is
       * *"`reason` is the class, `detail` is what happened."*
       *
       * ⚠️ THAT INVARIANT HAD NEVER BEEN TRUE END TO END. The relay composed a `detail` on every
       * `hash_submit_error`, and this client read `reason` and **dropped it on the floor** — so the
       * only sentence naming a cause never reached an operator. It defeats two things at once:
       * `DOD-M15-SEALWIRE-1`'s refusal detail (which rule, which leaf kind), and
       * `DOD-M15-TERMINAL-REASON-1`'s F6, where `detail` exists specifically to carry the
       * DIRECTORY's refusal cause out from behind a `seal_refused`.
       *
       * Optional, because an older relay sends none.
       */
      detail?: string;
      /**
       * DOD-M15-RELAYABUSE-1: milliseconds until the relay's rate-limit window clears, present only
       * with `reason: "rate_limited"`. The relay computes it; nobody guesses it. `#doSubmit` waits
       * this out and resubmits rather than surfacing a throttle — see the retry loop there.
       */
      retry_after_ms?: number;
    };
type AckResolver = (r: SubmitResult) => void;

export interface AgentRelayClientOpts {
  relayPeerId: string;
  relayAddrs: string[];
  /** The agent's K_local signing key (relay auth + leaf signatures). */
  keyProvider: KeyProvider;
  /** The agent's K_local public key (32 bytes) — relay routes delivery by this. */
  senderPubkey: Uint8Array;
  logger: Logger;
  /**
   * Durable store for the relay's signed ordering-record receipts. When present, each
   * verified `hash_submit_ack` is recorded immutably (the client's evidence of the relay's sequence
   * attestation, carried to the directory at seal time). Optional — when absent, ACKs are not recorded.
   */
  receiptStore?: RelayReceiptStore;
  /**
   * The per-session leaf log a unilateral seal carries to the directory. When
   * present, every leaf this client sees — its OWN submits (with the relay receipt) and the COUNTERPARTY's
   * delivered leaves (no receipt) — is recorded so a later unilateral seal presents the full chain for the
   * directory's OFFLINE tree rebuild. Optional — when absent, no leaf log is kept.
   */
  sealLeafStore?: SessionSealLeafStore;
  /**
   * `DOD-M15-SELFCHAIN-1` — what this agent last said in each session, so the next message links to
   * it. Optional on the type because test harnesses construct a client without one; when it is
   * absent this daemon cannot chain to itself and says so rather than signing an unlinked claim.
   */
  ownChainStore?: SessionOwnChainStore;
  /**
   * DOD-M15-RELAYSLOTS-1: the current directory-issued online token for this agent, or `undefined`
   * when the directory has not issued one (not connected yet, or this key is not a registered
   * agent). A relay refuses an auth without it, and refuses to let the peer hold a reservation slot.
   *
   * ⚠️ A FUNCTION, NOT A VALUE, and that is the whole point. The token is short-lived and reissued
   * on every signaling reconnect — which happens far more often than a relay auth. A client
   * constructed with a snapshot would work for the first hour of an agent's life and then present
   * an expired token forever, losing its slot for a reason nothing on this side reports.
   *
   * Optional so a caller with no directory connection at all (tests of unrelated paths) still
   * compiles; production always supplies it.
   */
  onlineToken?: () => Uint8Array | undefined;
  /**
   * DOD-M15-CORROBORATE-1: the relay saw a leaf on one of this agent's sessions that verified
   * against neither participant's key, and is telling us directly.
   *
   * Optional so a caller with no notice surface still compiles; production always supplies it. A
   * client that decoded the frame and dropped it would leave the unit's whole point — a record the
   * accused party's client cannot suppress — reaching nobody.
   */
  onWitnessAlert?: (alert: RelayWitnessAlert) => void;
  /**
   * DOD-M15-CORROBORATE-1 review F7: this relay sent a witness alert this build could not read or
   * could not verify. Neutral by construction — a relay peer id and a machine-readable cause, never
   * a session or a party.
   */
  onWitnessUnreadable?: (relayPeerId: string, why: string) => void;
}

/**
 * What ONE relay observed. Deliberately not a verdict, and the field names say so: this establishes
 * that this relay saw and refused that submission, and nothing about who sent it. Corroboration
 * would need several relays reporting the same hash sequence, which does not exist yet.
 */
export interface RelayWitnessAlert {
  sessionIdHex: string;
  reason: "leaf_signed_by_neither_participant";
  /** Which witness. Null when the relay runs without a signing identity and could not name itself. */
  relayId: string | null;
  observedAt: number;
  /** True iff the relay says the submitter was our counterparty; false = a third party. */
  submitterIsCounterparty: boolean;
  /**
   * The libp2p peer id of the relay that said it — always known, unlike `relayId`, which is absent
   * for a relay that could not sign. Used to tell two unnamed witnesses apart.
   */
  witnessPeerId: string;
  /**
   * Whether the relay PROVED it said this — review F3.
   *
   * `true` means the signature verified against the key `relayId` names, so the operator holds
   * something they can show a third party. `false` means the relay named no identity at all, so what
   * they hold is our word that a relay told us — which is worth exactly as much as the accusation
   * this is supposed to corroborate, and the inbox says so.
   *
   * There is no third state: a relay that DECLARES a `relayId` and fails to prove it is refused
   * outright, never reported as an unverifiable alert.
   */
  verifiable: boolean;
}

/**
 * Rebuild the bytes a relay signs when it reports a witnessed forgery.
 *
 * ⚠️ **MIRRORED CODEC** — `packages/relay/src/leaf-witness.ts` `buildWitnessAlertTbs` in
 * trustless-cello is the other half and the two MUST stay in sync. Both call `encodeCbor` from
 * `@cello-protocol/protocol-types` rather than configuring an encoder, so the only thing that can
 * drift is the field list, and both list it in one place.
 */
const RELAY_WITNESS_DOMAIN = "CELLO-RELAY-WITNESS-v1";
function buildWitnessAlertTbs(
  sessionId: Uint8Array,
  reason: string,
  observedAt: number,
  submitterIsCounterparty: boolean,
): Uint8Array {
  const body = encodeCbor([RELAY_WITNESS_DOMAIN, sessionId, reason, observedAt, submitterIsCounterparty]);
  return new Uint8Array(createHash("sha256").update(body).digest());
}

/**
 * The directory-signed relay assignment a client presents to its chosen relay (a
 * `client_record_assignment` frame). The relay
 * reconstructs the relay TBS from these fields and verifies `assignmentSignature` (the directory's
 * per-node relayDirSig) against any consortium directory pubkey. Field order/presence MUST match the
 * directory producer (directory-node.ts) and the relay verifier (relay-node.ts recordAssignment).
 */
/**
 * 034-CARRYLEAF — a leaf this agent RECEIVED, carried to the relay on its author's behalf.
 *
 * The author's own signed bytes and their signature over them, verbatim as they arrived on the
 * content frame. **Never re-encoded**: the signature is over the ENCODED BYTES, so a decode-and-
 * re-encode on this path would produce a claim the relay refuses and blame the wrong party for it.
 */
export interface CarriedLeafClaim {
  /** The AUTHOR's `structure1_cbor`, exactly as received. */
  structure1Cbor: Uint8Array;
  /** The AUTHOR's signature over those bytes, exactly as received. */
  senderSignature: Uint8Array;
}

export interface RelayAssignmentCarry {
  participantA: Uint8Array;            // 32-byte initiator pubkey
  participantB: Uint8Array;            // 32-byte counterparty pubkey
  sessionTimestamp: number;            // Unix ms
  initiatorSessionPeerId?: string;     // present for relay-mode sessions (covered by the sig when both present)
  counterpartySessionPeerId?: string;
  assignmentSignature: Uint8Array;     // 64-byte per-node directory sig over the relay TBS (relay_directory_signature)
}

/**
 * The genesis prev_root derivable from a relay assignment — 033-ACKEMIT.
 *
 * The carry holds both participant keys and the session timestamp, which with the session id are
 * exactly `computeGenesisPrevRoot`'s inputs. Returns `undefined` when there is no assignment, and
 * the caller then has no seed: absence is reported at the submit, never papered over.
 *
 * ⚠️ NOT 32 ZERO BYTES, and not any other constant. A value identical across every session is one
 * an attacker can present for any session, which would make the first message's acknowledgement
 * unfalsifiable exactly where it is most exposed.
 */
function genesisFromAssignment(
  sessionIdHex: string,
  assignment: RelayAssignmentCarry | undefined,
): Uint8Array | undefined {
  if (!assignment) return undefined;
  return computeGenesisPrevRoot(
    assignment.participantA,
    assignment.participantB,
    Uint8Array.from(Buffer.from(sessionIdHex, "hex")),
    assignment.sessionTimestamp,
  );
}

function toU8(v: unknown): Uint8Array {
  if (v instanceof Uint8Array) return v;
  if (Buffer.isBuffer(v)) return new Uint8Array(v as Buffer);
  if (v && typeof (v as { subarray?: unknown }).subarray === "function") {
    return (v as { subarray(): Uint8Array }).subarray();
  }
  if (v && typeof (v as { slice?: unknown }).slice === "function") {
    return (v as { slice(): Uint8Array }).slice();
  }
  return new Uint8Array();
}

async function nextWithTimeout(
  iter: AsyncIterator<Uint8Array>,
  ms: number,
): Promise<{ value: Uint8Array | undefined; done: boolean }> {
  let timer!: ReturnType<typeof setTimeout>;
  const timeout = new Promise<{ value: undefined; done: true }>((resolve) => {
    timer = setTimeout(() => resolve({ value: undefined, done: true }), ms);
  });
  try {
    const result = (await Promise.race([iter.next(), timeout])) as IteratorResult<Uint8Array>;
    return { value: result.value, done: !!result.done };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Per-AGENT relay witness client. Shared across all of an agent's sessions; one
 * authenticated stream at a time (the relay keys by agent pubkey). Submits are FIFO and
 * single-in-flight on the stream; `leaf_deliver` is routed by session_id.
 */
export class AgentRelayClient {
  /**
   * DOD-RELAY-KEEPALIVE-1 (review F4): the last error that ended this relay's reader.
   * The reservation watchdog reports `relay_connection_gone` — an exit-point label derived from a
   * poll, with the real abort reason already discarded. This carries the cause across to it.
   */
  #lastReaderError: string | null = null;
  /** The cause of the most recent reader end, or null if it has not ended. */
  getLastReaderError(): string | null {
    return this.#lastReaderError;
  }

  readonly #relayPeerId: string;
  readonly #relayAddrs: string[];
  readonly #keyProvider: KeyProvider;
  readonly #senderPubkey: Uint8Array;
  readonly #logger: Logger;
  readonly #receiptStore: RelayReceiptStore | undefined;
  readonly #sealLeafStore: SessionSealLeafStore | undefined;
  readonly #ownChainStore: SessionOwnChainStore | undefined;
  /** DOD-M15-RELAYSLOTS-1 — read fresh at every auth. See `AgentRelayClientOpts.onlineToken`. */
  readonly #onlineToken: (() => Uint8Array | undefined) | undefined;
  /** DOD-M15-CORROBORATE-1 — where a relay's witness alert goes. See the opt of the same name. */
  readonly #onWitnessAlert: ((alert: RelayWitnessAlert) => void) | undefined;
  /** DOD-M15-CORROBORATE-1 review F7 — where an UNREADABLE witness alert goes. */
  readonly #onWitnessUnreadable: ((relayPeerId: string, why: string) => void) | undefined;
  /**
   * DOD-M15-RELAYSLOTS-1: the last refusal this relay gave us, classified. Kept because a log line
   * reaches neither the operator asking why their agent is unreachable nor the code deciding
   * whether a different relay would do any better.
   */
  #lastAuthRefusal: RelayAuthRefusal | null = null;

  /** The last classified auth refusal from this relay, or null if the last attempt succeeded. */
  getLastAuthRefusal(): RelayAuthRefusal | null {
    return this.#lastAuthRefusal;
  }

  #stream: Stream | null = null;
  #connecting: Promise<boolean> | null = null;
  #closed = false;
  /**
   * PER-SESSION acknowledgement state (session_id hex → the position AND the content at it).
   *
   * `seq` is the highest relay-assigned sequence. The relay's `seq_counter` is per session, and it
   * rejects `last_seen_seq > seq_counter`, so each session's submit MUST carry that session's own
   * high-water mark — NOT an agent-global one (which would make a newer session's first submit look
   * ahead and get rejected).
   *
   * ⚠️ `hash` IS THE SAME FACT AS `seq`, WHICH IS WHY THEY LIVE IN ONE ENTRY — 033-ACKEMIT.
   *
   * `last_seen_seq` is a NUMBER: "I saw position 7" attests to a POSITION and never to CONTENT, so
   * a signed acknowledgement was an unbacked number that only the relay's separate receipt gave any
   * meaning to. `hash` is the content hash of the message AT that position, and the two are written
   * together in `#bumpLastSeen` from ONE decode of ONE leaf. They cannot be assigned apart, so they
   * cannot come to mean different messages — which is the defect this unit exists to remove, not a
   * disagreement to reconcile later.
   *
   * Seeded at `registerSession` with `{ seq: 0, hash: genesisPrevRoot }`: the first message of a
   * session has seen nothing, and that case is a DEFINED 32-byte value — the agreed starting point
   * of this two-party chain — never a missing field and never a fallback to v1.
   */
  readonly #lastSeen = new Map<string, { seq: number; hash: Uint8Array }>();
  /** The one outstanding submit's resolver (global FIFO — ack carries no session_id). */
  #pendingAck: AckResolver | null = null;
  // The sender-signed structure1_cbor of the in-flight submit, paired with its ack so the
  // SubmitResult can carry it (the ack itself only returns the relay's structure2_cbor).
  #pendingStructure1: Uint8Array | null = null;
  /**
   * DOD-M15-SEALWIRE-1 bullet 5 (sent half) — OUR signature over the in-flight `#pendingStructure1`,
   * paired with its ack for the same reason that one is: the ack returns the relay's record, never
   * ours. Cleared wherever `#pendingStructure1` is cleared; the two must never drift apart, because
   * a signature paired with the WRONG signed bytes is worse than no signature at all.
   */
  #pendingSignature: Uint8Array | null = null;
  // The in-flight submit's leaf kind (0x00 msg / 0x02 ctrl), paired with its ack so
  // #captureReceipt can persist it alongside the Structure2/Structure1 carry bytes for the unilateral seal.
  #pendingLeafKind: number | null = null;
  /** The session_id hex of the in-flight submit, so its ack updates the right #lastSeen. */
  #pendingAckSessionHex: string | null = null;
  /**
   * Resolver for the in-flight `client_record_assignment` ack. The ack carries
   * no session_id (like hash_submit_ack), so at most one record is in flight; records are serialized on
   * the same `#submitChain` as submits, guaranteeing no overlap.
   */
  #pendingRecord: ((result: "ok" | "rejected" | "closed") => void) | null = null;
  /** Serializes submits so only one is in flight at a time across all sessions. */
  #submitChain: Promise<unknown> = Promise.resolve();
  /** session_id hex → { the live node to (re)dial from, inbound leaf handler, Option-B assignment to present }. */
  readonly #sessions = new Map<string, {
    node: CelloNode;
    onLeafDeliver: (frame: LeafDeliverFrame) => void;
    /** The directory-signed relay assignment to present (absent for direct/legacy sessions). */
    assignment?: RelayAssignmentCarry;
    /** True once the relay has acked this session's client_record_assignment. */
    recorded: boolean;
    /**
     * The relay cleanly REJECTED this assignment (assignment_invalid — e.g. not signed by any
     * consortium directory). Terminal: stop re-presenting
     * it, so a misconfigured relay can't trigger a reconnect/re-present storm across sibling sessions.
     */
    recordRejected: boolean;
    /**
     * The record TIMED OUT rather than failing fast. A distinct sub-state because it means the
     * relay is unhealthy, not that the session is "not ready yet" — and the retry loop below is
     * for the not-ready-yet case. Retrying a timeout burns HASH_SUBMIT_TIMEOUT_MS per attempt on
     * the agent's SHARED submit chain, so a degraded relay would hold every session's sends.
     */
    recordTimedOut: boolean;
  }>();

  constructor(opts: AgentRelayClientOpts) {
    this.#relayPeerId = opts.relayPeerId;
    this.#relayAddrs = opts.relayAddrs;
    this.#keyProvider = opts.keyProvider;
    this.#senderPubkey = opts.senderPubkey;
    this.#logger = opts.logger;
    this.#receiptStore = opts.receiptStore;
    this.#sealLeafStore = opts.sealLeafStore;
    this.#ownChainStore = opts.ownChainStore;
    this.#onlineToken = opts.onlineToken;
    this.#onWitnessAlert = opts.onWitnessAlert;
    this.#onWitnessUnreadable = opts.onWitnessUnreadable;
  }

  /** The agent's K_local public key as hex — the responder identity for auto-acknowledge. */
  get senderPubkeyHex(): string {
    return Buffer.from(this.#senderPubkey).toString("hex");
  }

  /**
   * Register a session's inbound leaf handler + a live node to (re)dial the relay from
   * (idempotent). Storing the node per session lets a pure-receiver session re-establish
   * the shared stream if the node that originally dialed is torn down.
   */
  registerSession(
    sessionIdHex: string,
    node: CelloNode,
    onLeafDeliver?: (frame: LeafDeliverFrame) => void,
    assignment?: RelayAssignmentCarry,
    /**
     * 033-ACKEMIT — the session's genesis prev_root: what the FIRST message of this session
     * acknowledges, before anything has been received.
     *
     * Supplied by the caller because `session-node-manager` is where the session record lives. When
     * it is absent an ASSIGNMENT can still produce it (both participant keys and the session
     * timestamp are on the carry), and that covers re-registration of a session whose row predates
     * the column. When NEITHER is available the session has no seed, and its first submit claims
     * position 0 with no hash — which asserts nothing about content and is therefore honest, rather
     * than a claim about a position it cannot back.
     */
    genesisPrevRoot?: Uint8Array,
  ): void {
    const existing = this.#sessions.get(sessionIdHex);
    const carriedAssignment = assignment ?? existing?.assignment;
    this.#sessions.set(sessionIdHex, {
      node,
      onLeafDeliver: onLeafDeliver ?? (() => {}),
      // Carry the assignment forward across re-registration; never lose a recorded flag on re-register.
      assignment: carriedAssignment,
      recorded: existing?.recorded ?? false,
      recordRejected: existing?.recordRejected ?? false,
      recordTimedOut: existing?.recordTimedOut ?? false,
    });
    /**
     * SEED THE ACKNOWLEDGEMENT, and only when there is nothing to lose.
     *
     * A session that has already received a leaf holds a REAL `{ seq, hash }`; overwriting it with
     * the genesis on a re-registration would walk the acknowledgement backwards to "I have seen
     * nothing" for a conversation that is well underway — and the relay would then answer the next
     * submit from a position we had already passed.
     */
    if (!this.#lastSeen.has(sessionIdHex)) {
      const seed = genesisPrevRoot ?? genesisFromAssignment(sessionIdHex, carriedAssignment);
      if (seed) this.#lastSeen.set(sessionIdHex, { seq: 0, hash: seed });
    }
    // Eagerly present the assignment so the relay records the session (binds peer IDs, creates the
    // session entry) BEFORE the first hash_submit or the counterparty's leaves arrive — the relay
    // rejects frames for a session it has not recorded. Best-effort + serialized on the submit chain
    // (the ack carries no session_id, so no overlap).
    if (assignment) {
      this.#submitChain = this.#submitChain
        .then(() => this.#doRecord(node, sessionIdHex))
        .then(() => undefined, () => undefined);
    }
  }

  /**
   * DOD-M15-RELAYAUTH-1 review H1 — **present the assignment and WAIT for the relay to say it
   * recorded it.**
   *
   * `registerSession` above presents eagerly and forgets: the record is queued onto the submit chain
   * and nobody can observe when it lands. That is correct for the witness relay, where the only
   * requirement is "before the first submit". It is NOT sufficient for the relay that GATES A DIAL,
   * because there the record is a precondition of an action we are about to take on another thread
   * of the protocol — and losing that race denies a legitimate dial (review H1).
   *
   * Chained on `#submitChain` exactly like `#doSubmit`, so it cannot interleave with a submit on the
   * same stream. Idempotent by construction: `#doRecord` returns `true` immediately once the session
   * is recorded, so calling this straight after `registerSession` waits for the record that call
   * already queued rather than sending a second one.
   *
   * Returns whether the relay recorded it. NEVER throws — a caller must be free to proceed on false
   * (a dial that might be denied still beats no dial at all).
   */
  async recordAssignmentAndWait(node: CelloNode, sessionIdHex: string): Promise<boolean> {
    const run = this.#submitChain.then(() => this.#doRecord(node, sessionIdHex));
    this.#submitChain = run.then(() => undefined, () => undefined);
    return run.catch(() => false);
  }

  /**
   * Present the directory-signed assignment to the relay. Idempotent
   * (no-op once `recorded`, or when the session has no assignment — direct/persisted/legacy sessions).
   * The relay reconstructs the TBS and verifies the per-node directory signature against any consortium
   * key. On success the session is recorded; the send/ack is single-in-flight (mirrors #doSubmit).
   */
  async #doRecord(node: CelloNode, sessionIdHex: string): Promise<boolean> {
    if (this.#closed) return false;
    const sess = this.#sessions.get(sessionIdHex);
    if (!sess || !sess.assignment) return true;
    if (sess.recorded) return true;
    // Terminal rejection: a relay that cleanly rejected this assignment will reject it
    // again — stop re-presenting so a misconfigured/forged case can't storm the shared stream.
    if (sess.recordRejected) return false;
    if (!(await this.#ensureConnected(node))) return false;
    const stream = this.#stream;
    if (!stream) return false;
    const a = sess.assignment;
    const frame = encodeCbor({
      type: "client_record_assignment",
      session_id: new Uint8Array(Buffer.from(sessionIdHex, "hex")),
      participant_a: a.participantA,
      participant_b: a.participantB,
      session_timestamp: a.sessionTimestamp,
      initiator_session_peer_id: a.initiatorSessionPeerId,
      counterparty_session_peer_id: a.counterpartySessionPeerId,
      assignment_signature: a.assignmentSignature,
    }) as Uint8Array;
    let resolveRec!: (result: "ok" | "rejected" | "closed") => void;
    const ackPromise = new Promise<"ok" | "rejected" | "closed">((r) => { resolveRec = r; });
    this.#pendingRecord = resolveRec;
    try {
      stream.send(lp.encode.single(frame));
    } catch (err: unknown) {
      if (this.#pendingRecord === resolveRec) this.#pendingRecord = null;
      this.#logger.warn("session.relay.record.send.failed", { relayPeerId: this.#relayPeerId, error: extractErrorMessage(err) });
      return false;
    }
    let timer!: ReturnType<typeof setTimeout>;
    const timeout = new Promise<"timeout">((r) => { timer = setTimeout(() => r("timeout"), HASH_SUBMIT_TIMEOUT_MS); });
    try {
      const result = await Promise.race([ackPromise, timeout]);
      if (result === "ok") {
        sess.recorded = true;
        sess.recordTimedOut = false;
        this.#logger.info("session.relay.assignment.recorded", { relayPeerId: this.#relayPeerId, sessionShort: sessionIdHex.slice(0, 16) });
        return true;
      }
      if (result === "timeout") {
        // ONLY here reset the stream: a late ack on this superseded stream would settle a LATER submit's
        // resolver (FIFO desync). recorded stays false ⇒ a transient timeout is retried on reconnect.
        this.#resetStream();
        sess.recordTimedOut = true;
        this.#logger.warn("session.relay.assignment.record.timeout", { relayPeerId: this.#relayPeerId, sessionShort: sessionIdHex.slice(0, 16) });
        return false;
      }
      if (result === "rejected") {
        // The relay cleanly rejected (assignment_invalid) — the ack already arrived, the stream is HEALTHY.
        // Do NOT reset (that would tear down sibling sessions' in-flight submits). Mark terminal so we stop
        // re-presenting. The session has no relay witness; sends still complete via the direct path
        // (sovereign-node redundancy) and a hash_submit will fail loud (session_not_found) — diagnosable.
        sess.recordRejected = true;
        this.#logger.warn("session.relay.assignment.record.rejected", { relayPeerId: this.#relayPeerId, sessionShort: sessionIdHex.slice(0, 16) });
        return false;
      }
      // "closed": the stream dropped while the record was in flight (settled by the reader/close path).
      // Transient — no reset needed (already gone); recorded stays false ⇒ retried on reconnect.
      return false;
    } finally {
      clearTimeout(timer);
      if (this.#pendingRecord === resolveRec) this.#pendingRecord = null;
    }
  }

  /** Remove a session; caller closes the client when no sessions remain. */
  unregisterSession(sessionIdHex: string): void {
    this.#sessions.delete(sessionIdHex);
    this.#lastSeen.delete(sessionIdHex);
  }

  hasSessions(): boolean {
    return this.#sessions.size > 0;
  }

  /**
   * Is THIS session already registered on this client?
   *
   * DOD-M15-RELAYLEAK-1 (review MEDIUM-5). The detached seal transport releases its registration
   * when the submit finishes, and "did I register it, or did I find it already there?" is the
   * difference between releasing my own and **pulling a live one out from under a concurrent
   * caller** — which closes the client that caller is mid-`submitLeaf` on. `hasSessions()` cannot
   * answer it: it is a count, and by then the id is in the set either way.
   */
  hasSession(sessionIdHex: string): boolean {
    return this.#sessions.has(sessionIdHex);
  }

  /** Settle the one outstanding submit (if any) exactly once. */
  #settlePending(r: SubmitResult): void {
    const resolve: AckResolver | null = this.#pendingAck;
    this.#pendingAck = null;
    this.#pendingAckSessionHex = null;
    this.#pendingStructure1 = null;
    this.#pendingSignature = null;
    this.#pendingLeafKind = null;
    if (resolve) resolve(r);
  }

  /**
   * Tear down the current stream (drops it so the next submit re-dials). Used on a submit
   * timeout: because `hash_submit_ack` carries no session_id, ack↔submit matching is purely
   * FIFO, so a LATE ack from a timed-out submit would settle the NEXT submit's resolver and
   * shift every subsequent ack by one. Resetting the stream prevents that desync (the relay
   * re-auths + re-drains on the reconnect).
   */
  #resetStream(): void {
    const stream = this.#stream;
    this.#stream = null;
    if (stream) {
      try { void stream.close(); } catch { /* best-effort */ }
    }
  }

  /**
   * Advance this session's acknowledgement to a counterparty leaf: the POSITION and the CONTENT
   * AT IT, written together (033-ACKEMIT).
   *
   * `contentHash` comes from the same `decodeStructure1` of the same leaf that produced `seq`, so
   * the pair describes one message by construction. There is no path that advances one without the
   * other, and that is deliberate: a `last_seen_seq` and a `last_seen_hash` that could drift apart
   * would let this daemon sign an acknowledgement of a message it never saw.
   *
   * Monotonic on `seq` — a re-delivery of an earlier leaf must not walk the acknowledgement
   * backwards, and it must not swap the hash under an unchanged position either.
   */
  #bumpLastSeen(sessionIdHex: string, seq: number, contentHash: Uint8Array): void {
    if (seq < 0) return;
    const prev = this.#lastSeen.get(sessionIdHex);
    if (prev && seq <= prev.seq) return;
    this.#lastSeen.set(sessionIdHex, { seq, hash: contentHash });
  }

  /** True if this Structure-1 leaf was authored by US (sender_pubkey === our K_local). */
  #isOwnLeaf(structure1Cbor: Uint8Array): boolean {
    // Structure 1 = [version, content_hash, sender_pubkey, session_id, last_seen_seq, ts], plus
    // last_seen_hash at index 6 on a v2 claim (020-ACKHASH). sender_pubkey is index 2 in both.
    const s1 = decodeStructure1(structure1Cbor);
    /**
     * ⚠️ `false` IS THE DANGEROUS DIRECTION, NOT THE CONSERVATIVE ONE — review F8, correcting a
     * comment that claimed the opposite.
     *
     * It read "conservative: don't suppress a real counterparty leaf." At the call site, `false`
     * means our OWN echoed leaf gets `#bumpLastSeen` applied — which the comment there says must not
     * happen — and is written into the seal-leaf log as a COUNTERPARTY leaf. Returning `false`
     * wrongly corrupts the log; returning `true` wrongly drops one witness signal.
     *
     * It stays `false` because the input set is bytes the relay already decoded and accepted, so an
     * unreadable leaf here means this daemon and the relay disagree about a frame the relay passed —
     * not a hostile peer. Widening it to every layout failure (it was only a CBOR throw before) does
     * not change that: the relay's own decoder gates every path that reaches here.
     */
    if (!s1.ok) return false;
    return Buffer.from(s1.fields.senderPubkey).equals(Buffer.from(this.#senderPubkey));
  }

  /**
   * Verify a relay `hash_submit_ack`'s signed ordering record and durably store the receipt.
   * The relay signs TBS = SHA-256(content_hash || seq_BE4 || ts_BE8) with its ack-signing key, whose hex is
   * `relay_id`. We verify SELF-CONSISTENCY (the signature binds the sequence ⇒ a FORGED sequence fails) and
   * record the immutable receipt. The authoritative registered-relay check is the directory's at seal
   * (OPTIONB-SEAL). No-op when there is no receipt store, no pending leaf, or the ACK is unsigned.
   */
  #captureReceipt(frame: Record<string, unknown>, structure1Cbor: Uint8Array | undefined, seq: number): boolean {
    if (seq < 0 || !structure1Cbor) return false;
    // Structure 1 = [version, content_hash(32), sender_pubkey(32), session_id(16), last_seen_seq,
    // ts], plus last_seen_hash(32) at index 6 on a v2 claim (020-ACKHASH). content_hash is index 1
    // and session_id index 3 in both.
    const s1 = decodeStructure1(structure1Cbor);
    if (!s1.ok) {
      // Our OWN just-signed bytes — near-impossible to fail; surface it rather than drop silently.
      // The reason is carried because "we cannot read what we just wrote" and "we wrote a layout we
      // cannot name" are different faults with the same symptom.
      this.#logger.warn("relay.receipt.undecodable_leaf", { seq, structure1Reason: s1.reason });
      return false;
    }
    const contentHash = s1.fields.contentHash;
    const sessionId = s1.fields.sessionId;
    const ev = evaluateRelayAck({
      contentHash,
      sessionIdHex: Buffer.from(sessionId).toString("hex"),
      agentPubkeyHex: this.senderPubkeyHex,
      relayId: typeof frame["relay_id"] === "string" ? frame["relay_id"] : undefined,
      relaySignature: frame["relay_signature"] instanceof Uint8Array ? (frame["relay_signature"] as Uint8Array) : undefined,
      timestamp: typeof frame["timestamp"] === "number" ? frame["timestamp"] : undefined,
      sequenceNumber: seq,
    });
    switch (ev.kind) {
      case "unsigned":
        // A relay that SHOULD sign but didn't → no durable witness for this message. Unsigned ACKs are
        // tolerated, but make it diagnosable instead of invisible.
        this.#logger.debug("relay.receipt.unsigned", { seq, hashShort: Buffer.from(contentHash).toString("hex").slice(0, 16) });
        return false;
      case "bad_relay_id":
        this.#logger.warn("relay.receipt.bad_relay_id", { seq });
        return false;
      case "invalid_signature":
        // FORGED / corrupt ACK — the signature does not bind (hash, seq, ts). REJECT the submit so the send
        // does NOT settle ok on an unverified sequence (a forged ordering record must not drive ordering),
        // and store nothing. The send still completes via the direct
        // content path — the relay witness simply degrades to absent for this leaf.
        this.#logger.warn("relay.receipt.signature_invalid", { seq });
        return true;
      case "store": {
        if (!this.#receiptStore) return false;
        try {
          const wrote = this.#receiptStore.store(ev.receipt, Date.now());
          if (wrote) {
            this.#logger.info("relay.receipt.stored", { seq, hashShort: ev.receipt.hashHex.slice(0, 16), relayShort: ev.receipt.relayId.slice(0, 16) });
          }
          // Record this OWN leaf in the seal-leaf log WITH its relay receipt (the
          // relay's signature pins content_hash→seq — the teeth that stop a supplier reordering its own
          // leaves). structure2_cbor rides the ack we just verified; structure1Cbor + the leaf kind are this
          // submit's paired in-flight values. Best-effort + separate from the receipt write.
          const structure2Cbor = frame["structure2_cbor"] instanceof Uint8Array ? (frame["structure2_cbor"] as Uint8Array) : undefined;
          if (this.#sealLeafStore && structure2Cbor && structure1Cbor && this.#pendingLeafKind !== null) {
            /**
             * ⚠️ **THE AUTHOR COMES FROM THE SIGNED BYTES, AND THE RECEIPT ONLY ATTACHES TO OUR OWN
             * LEAF — 034-CARRYLEAF review F3.**
             *
             * This wrote `senderPubkeyHex: this.senderPubkeyHex` unconditionally, which was true for
             * as long as the only thing a client could submit was its own leaf. `witnessReceivedLeaf`
             * ended that: on a counter-submit `structure1Cbor` holds the COUNTERPARTY's bytes, so
             * this row labelled their leaf as ours — and attached a relay receipt to it, which is the
             * one thing that must never happen to a leaf we did not author, because a receipt is what
             * pins OUR leaves to a sequence we could otherwise renumber.
             *
             * It was inert on the wire by luck: `sender_pubkey_hex` is not transmitted and the
             * directory re-derives the author from `structure2_cbor`. It was never inert locally —
             * the store is `INSERT OR IGNORE` on `(agent, session, sequence)`, and the ack arrives
             * BEFORE the `leaf_deliver` echo, so this row won and the correct one was silently
             * dropped.
             *
             * Same rule as everywhere else on this path: the identity comes from inside the bytes
             * the author signed, never from an ambient value that happens to be right today.
             */
            const authored = decodeStructure1(structure1Cbor);
            const authorHex = authored.ok
              ? Buffer.from(authored.fields.senderPubkey).toString("hex")
              : this.senderPubkeyHex;
            const ourOwnLeaf = authorHex === this.senderPubkeyHex;
            this.#sealLeafStore.store(this.senderPubkeyHex, ev.receipt.sessionIdHex, {
              sequenceNumber: seq,
              leafKind: this.#pendingLeafKind,
              senderPubkeyHex: authorHex,
              structure2Cbor,
              structure1Cbor,
              ...(ourOwnLeaf
                ? {
                    relayId: ev.receipt.relayId,
                    relayTimestamp: ev.receipt.timestamp,
                    relaySignatureHex: ev.receipt.signatureHex,
                  }
                : {}),
            }, Date.now());
          }
        } catch (err) {
          // A durable-evidence write failure must be LOUD — the relay will not re-emit this ack, so a
          // swallowed write permanently loses a verified receipt.
          this.#logger.error("relay.receipt.store_failed", { seq, error: err instanceof Error ? err.message : String(err) });
        }
        return false;
      }
    }
  }

  #dispatch(frame: Record<string, unknown>): void {
    const type = frame["type"];
    if (type === "hash_submit_ack") {
      const seq = typeof frame["sequence_number"] === "number" ? frame["sequence_number"] : -1;
      // DO NOT advance #lastSeen here: the ack is for OUR OWN leaf. last_seen_seq must track
      // the highest COUNTERPARTY sequence we've observed — the directory's causal check rejects a leaf
      // whose last_seen_seq exceeds the max sequence of OTHER-sender leaves before it. Advancing on our
      // own ack would inflate it and trip causal_chain_violated on a subsequent submit (e.g. the SEAL
      // leaf after a sent message).
      // Pair the relay's committed structure2_cbor with our in-flight structure1_cbor so
      // the SubmitResult carries the full signed ordering record for the self-ordering content frame.
      // Captured BEFORE #settlePending clears #pendingStructure1.
      const s2 = frame["structure2_cbor"];
      const structure2Cbor = s2 instanceof Uint8Array ? s2 : undefined;
      const structure1Cbor = this.#pendingStructure1 ?? undefined;
      // Captured with structure1Cbor and BEFORE #settlePending clears both — see #pendingSignature.
      const senderSignature = this.#pendingSignature ?? undefined;
      // Verify the relay's signed ordering record and durably store the receipt BEFORE
      // settling (which clears #pendingStructure1, the source of the content hash + session id). A
      // signed-but-INVALID ACK rejects the submit so the send does not settle ok on an unverified sequence.
      const rejectSubmit = this.#captureReceipt(frame, structure1Cbor, seq);
      this.#settlePending(
        rejectSubmit
          ? { ok: false, reason: "relay_ack_signature_invalid" }
          : seq >= 0
            ? { ok: true, sequence_number: seq, structure1_cbor: structure1Cbor, structure2_cbor: structure2Cbor, sender_signature: senderSignature }
            : { ok: false, reason: "relay_ack_malformed" },
      );
    } else if (type === "hash_submit_error") {
      const reason = typeof frame["reason"] === "string" ? frame["reason"] : "relay_rejected";
      // Carry the relay's `detail` through — see `SubmitResult`. Reading the class and discarding
      // what happened is how a refusal arrives as a bare code with no cause attached to it.
      const detail = typeof frame["detail"] === "string" ? frame["detail"] : undefined;
      // DOD-M15-RELAYABUSE-1: the relay knows when its window clears and says so. Carried, not
      // dropped — `#doSubmit` waits it out and resubmits, so a throttle never reaches the operator.
      const rawRetry = frame["retry_after_ms"];
      const retry_after_ms = typeof rawRetry === "number" && Number.isFinite(rawRetry) && rawRetry > 0 ? rawRetry : undefined;
      this.#settlePending({
        ok: false,
        reason,
        ...(detail ? { detail } : {}),
        ...(retry_after_ms !== undefined ? { retry_after_ms } : {}),
      });
    } else if (type === "assignment_ok") {
      // The relay verified + recorded our client-presented assignment.
      const r = this.#pendingRecord; this.#pendingRecord = null; if (r) r("ok");
    } else if (type === "assignment_invalid") {
      // The relay rejected the assignment (e.g. directory_signature_invalid — not signed by any
      // consortium directory). Fail LOUD: the session has no relay witness until this is resolved.
      const reason = typeof frame["reason"] === "string" ? (frame["reason"] as string) : "unknown";
      this.#logger.warn("session.relay.assignment.invalid", { relayPeerId: this.#relayPeerId, reason });
      /**
       * DOD-M15-RELAYSLOTS-1 review M2 — **the tuple cap has to reach the operator too.**
       *
       * Clause 7 says EVERY refusal reaches them with a cause and an affordance, and this one was
       * arriving as `assignment_invalid` in a log. It is also the refusal most likely to hit a real
       * person, for the reason the order itself gives: nobody knows what sessions they have open, so
       * whoever hits it believes they have none. Routed through the same classifier and onto the
       * same surface as every other relay refusal.
       */
      const concurrent = typeof frame["concurrent_sessions"] === "number" ? (frame["concurrent_sessions"] as number) : undefined;
      const cap = typeof frame["session_cap"] === "number" ? (frame["session_cap"] as number) : undefined;
      this.#lastAuthRefusal = classifyRelayAuthRefusal(reason, {
        ...(concurrent !== undefined ? { slotsHeld: concurrent } : {}),
        ...(cap !== undefined ? { slotCap: cap } : {}),
      });
      const r = this.#pendingRecord; this.#pendingRecord = null; if (r) r("rejected");
    } else if (type === "leaf_deliver") {
      const seq = typeof frame["sequence_number"] === "number" ? frame["sequence_number"] : -1;
      const sidHex = Buffer.from(toU8(frame["session_id"])).toString("hex");
      const s1 = toU8(frame["structure1_cbor"]);
      /**
       * ONE DECODE, TWO CONSUMERS — 033-ACKEMIT. The acknowledgement bump and the seal-leaf capture
       * below both need the sender's own signed fields, and they must agree about which leaf they
       * are looking at. Decoding twice would let a future edit change one read and not the other.
       */
      const deliveredS1 = decodeStructure1(s1);
      // Advance last_seen ONLY for a COUNTERPARTY leaf. The relay also echoes our OWN
      // leaf back as a leaf_deliver — that must NOT advance it (same reason as the ack above).
      const authoredByUs = this.#isOwnLeaf(s1);
      /**
       * The POSITION and the CONTENT AT IT, from the counterparty's own signed bytes.
       *
       * ⚠️ THE HASH COMES FROM INSIDE `structure1_cbor`, NEVER FROM AN ENVELOPE FIELD. The frame
       * also carries `structure2_cbor`, which the RELAY built — taking the hash from there would key
       * our acknowledgement on a value the witness supplies, and a tampering relay could then make
       * us sign an acknowledgement of content the counterparty never sent. Index 1 of Structure 1 is
       * inside the bytes the counterparty signed, so it is the one copy neither we nor the relay can
       * move.
       *
       * A leaf whose layout this build cannot name advances NOTHING — position included. The
       * previous code advanced `seq` from the envelope regardless, so an unreadable leaf could move
       * the acknowledgement forward while leaving the hash behind it; refusing to advance keeps the
       * pair describing one real message, and the relay's own decoder already gates what reaches
       * here.
       */
      if (seq >= 0 && !authoredByUs) {
        if (deliveredS1.ok) {
          this.#bumpLastSeen(sidHex, seq, deliveredS1.fields.contentHash);
        } else {
          this.#logger.warn("relay.leaf_deliver.unreadable", {
            seq,
            session: sidHex,
            structure1Reason: deliveredS1.reason,
            impact:
              "this delivered leaf could not be read, so this session's acknowledgement was NOT " +
              "advanced to it. The next message this agent sends will acknowledge the last leaf it " +
              "could read, which is honest — it never claims to have seen something it could not.",
          });
        }
      }
      // Record the COUNTERPARTY's delivered leaf in the seal-leaf log (no relay
      // receipt — the relay does not ack-sign a delivery to the recipient). It is pinned at seal by the
      // absent party's sender_signature (unforgeable) + sequence contiguity against our receipt-pinned own
      // leaves. Our OWN echoed leaf is skipped here (it is recorded WITH its receipt on the ack path).
      /**
       * ─── OUR OWN LEAF, WITNESSED BY SOMEBODY ELSE — 034-CARRYLEAF review F2 ──────────────────
       *
       * ⚠️ **WITHOUT THIS, MAKING THE COUNTERPARTY ABLE TO WITNESS OUR LEAF COST US THE RECEIPT.**
       *
       * When the counterparty counter-submits a leaf WE authored, the relay assigns it a position
       * and delivers it to us — and `authoredByUs` is true, so the capture below skipped it. We
       * never submitted it ourselves, so no ack ever arrived and the ack path never wrote a row
       * either. The result was a permanent hole at that position in our own carry: the unilateral
       * seal refused it as `seal_carry_noncontiguous`, and the bilateral one refused to co-sign a
       * root it could not judge. **An honest sender whose relay hiccuped once lost the receipt for
       * the entire conversation** — for a message sitting in their own transcript.
       *
       * So the leaf is stored, **with NO relay receipt**, because we hold none: nobody acked it to
       * us. That asymmetry is exactly the one the seal design already relies on. A bilateral seal
       * needs a contiguous chain and gets one. A UNILATERAL seal additionally requires every one of
       * our OWN leaves to carry a receipt — so a party who never witnesses their own messages still
       * cannot seal alone on them (`unilateral_own_leaf_unwitnessed`), which is precisely what
       * `DOD-M15-WITHHOLD-SEAL-1` intends.
       *
       * `INSERT OR IGNORE` keeps whichever row lands first, and a real receipt-bearing row for the
       * same position can only come from our own ack — which cannot exist here, or we would have
       * submitted it ourselves.
       */
      if (this.#sealLeafStore && seq >= 0 && authoredByUs && deliveredS1.ok) {
        const s2Own = frame["structure2_cbor"];
        if (s2Own instanceof Uint8Array && s1.length > 0) {
          try {
            const wrote = this.#sealLeafStore.store(this.senderPubkeyHex, sidHex, {
              sequenceNumber: seq,
              leafKind: typeof frame["leaf_kind"] === "number" ? frame["leaf_kind"] : LEAF_KIND_MSG,
              senderPubkeyHex: this.senderPubkeyHex,
              structure2Cbor: s2Own,
              structure1Cbor: s1,
            }, Date.now());
            if (wrote) {
              this.#logger.info("relay.seal_leaf.own.witnessed_by_counterparty", {
                seq,
                session: sidHex,
                impact:
                  "a message THIS agent wrote was witnessed by the counterparty rather than by us — " +
                  "our own submit did not land. The leaf is kept so this conversation can still be " +
                  "sealed together; sealing it alone would still need a receipt we do not hold.",
              });
            }
          } catch (err) {
            this.#logger.error("relay.seal_leaf.own.store_failed", { seq, session: sidHex, error: extractErrorMessage(err) });
          }
        }
      }
      if (this.#sealLeafStore && seq >= 0 && !authoredByUs) {
        const s2 = frame["structure2_cbor"];
        const structure2Cbor = s2 instanceof Uint8Array ? s2 : undefined;
        // Review F1: a raw positional read of index 2 with NO version and NO length check lived here
        // — it accepted a v3 array, a 40-element array, anything with 32 bytes at index 2, and fed
        // the result into the seal-leaf log as the counterparty's identity. It is in the same file as
        // #isOwnLeaf and #captureReceipt and was simply missed by the order's reader list, which is
        // exactly the "next layout change has to find them again" problem the shared decoder exists
        // to end. Behaviour for every relay-accepted leaf is unchanged; the fail-open closes.
        const senderHex = deliveredS1.ok
          ? Buffer.from(deliveredS1.fields.senderPubkey).toString("hex")
          : undefined;
        if (structure2Cbor && s1.length > 0 && senderHex) {
          try {
            this.#sealLeafStore.store(this.senderPubkeyHex, sidHex, {
              sequenceNumber: seq,
              leafKind: typeof frame["leaf_kind"] === "number" ? frame["leaf_kind"] : LEAF_KIND_MSG,
              senderPubkeyHex: senderHex,
              structure2Cbor,
              structure1Cbor: s1,
            }, Date.now());
          } catch (err) {
            this.#logger.error("relay.seal_leaf.counterparty.store_failed", { seq, session: sidHex, error: err instanceof Error ? err.message : String(err) });
          }
        } else {
          this.#logger.warn("relay.seal_leaf.counterparty.capture_skipped", { seq, session: sidHex, hasS2: !!structure2Cbor, hasS1: s1.length > 0, hasSender: !!senderHex });
        }
      }
      const session = this.#sessions.get(sidHex);
      if (session && seq >= 0) {
        session.onLeafDeliver({
          sequence_number: seq,
          leaf_kind: typeof frame["leaf_kind"] === "number" ? frame["leaf_kind"] : LEAF_KIND_MSG,
          structure1_cbor: s1,
          structure2_cbor: toU8(frame["structure2_cbor"]),
          // Tell the consumer whether this is our own echoed leaf (so the
          // auto-acknowledge gate never co-signs in response to its own SEAL ctrl leaf).
          authored_by_us: authoredByUs,
        });
      }
    } else if (type === "session_witness_alert") {
      /**
       * DOD-M15-CORROBORATE-1 — **the relay is telling us what it saw, and this is where it lands.**
       *
       * A relay is not trusted to send a well-formed frame any more than a peer is, so every field
       * is checked before anything is reported. A frame that does not decode is a MISBEHAVING OR
       * SKEWED RELAY, not an alert: reporting it as one would let a broken build manufacture
       * accusations against a counterparty who did nothing. It is logged loudly and goes no further.
       */
      const sid = frame["session_id"];
      const rawRelayId = frame["relay_id"];
      const observedAt = frame["observed_at"];
      const submitterIsCounterparty = frame["submitter_is_counterparty"];
      const sidBytes = sid instanceof Uint8Array || Buffer.isBuffer(sid) ? toU8(sid) : new Uint8Array();
      const wellFormed =
        sidBytes.length === 16
        && frame["reason"] === "leaf_signed_by_neither_participant"
        && typeof observedAt === "number" && Number.isFinite(observedAt)
        && typeof submitterIsCounterparty === "boolean"
        && (rawRelayId === undefined || typeof rawRelayId === "string");
      const unreadable = (why: string): void => {
        this.#logger.error("session.relay.witness.malformed", {
          relayPeerId: this.#relayPeerId,
          why,
          impact: "this relay sent a witness alert this build cannot read, so NOTHING has been " +
            "reported to the operator about it. Treat it as a relay fault or a version skew, not " +
            "as evidence about either participant.",
        });
        /**
         * Review F7 — **and it reaches a surface, not only this file.** If a version skew makes
         * every relay's alert unreadable, the witness layer is silently dead and the operator would
         * have no way to find that out. Deliberately carries NO session and NO party: it says a
         * relay sent something we could not read, and claims nothing about anyone.
         */
        this.#onWitnessUnreadable?.(this.#relayPeerId, why);
      };
      if (!wellFormed) { unreadable("field_shape"); return; }

      const sessionIdHex = Buffer.from(sidBytes).toString("hex");
      /**
       * ⚠️ **IT MUST BE A SESSION THIS CLIENT ACTUALLY HOLDS ON THIS RELAY** — review F2.
       *
       * `wellFormed` checks shape and shape only. Without this, any relay we are authenticated to
       * could push alerts naming arbitrary session ids — including conversations carried by a
       * DIFFERENT relay — and they would land in the operator's inbox as statements of fact about
       * a counterparty. Combined with a bounded notice list that is the cheap mute: flood
       * fabrications until the real one is gone.
       */
      if (!this.#sessions.has(sessionIdHex)) {
        /**
         * ⚠️ **REFUSED AS AN ALERT, BUT NOT BINNED IN SILENCE** — fallback-finder HIGH 1.
         *
         * It cannot be reported as an observation about a conversation: a relay naming a session we
         * do not hold is exactly the fabrication the check above exists to stop, and rendering it
         * would put a claim about a counterparty in front of an operator on a stranger's say-so.
         *
         * But dropping it entirely was worse than it looked, because the relay's own copy is GONE by
         * then: its queue is keyed by PUBKEY and `drainWitnessAlerts` splices, so it hands over
         * everything it held for this agent the moment any client authenticates. The detached seal
         * client registers exactly ONE session and then authenticates — so a restart-then-seal on
         * one conversation destroyed a held alert about a different one, at both ends, and the
         * operator's inbox looked clean.
         *
         * So it goes to the same neutral surface a version skew does: something arrived that this
         * daemon could not place. No session, no party, no claim.
         */
        this.#logger.error("session.relay.witness.unknown_session", {
          relayPeerId: this.#relayPeerId,
          session: sessionIdHex,
          impact: "not rendered as an observation — this relay named a session this client is not " +
            "holding. Reported to the operator as an unplaceable witness report, never as a claim " +
            "about a counterparty.",
        });
        this.#onWitnessUnreadable?.(this.#relayPeerId, "session_not_held_here");
        return;
      }

      /**
       * A DECLARED IDENTITY MUST BE PROVEN — review F3. `relay_id` is the hex of the key that signs
       * every `hash_submit_ack`, so the same check that verifies a receipt verifies this. Missing,
       * malformed and mismatched take ONE path: omitting the proof is the cheapest way to dodge it.
       */
      const rawSig = frame["witness_signature"];
      const sigBytes = rawSig instanceof Uint8Array || Buffer.isBuffer(rawSig) ? toU8(rawSig) : null;
      let verifiable = false;
      if (typeof rawRelayId === "string") {
        if (!/^[0-9a-fA-F]{64}$/.test(rawRelayId)) { unreadable("relay_id_not_a_pubkey"); return; }
        if (!sigBytes || sigBytes.length !== 64) { unreadable("declared_relay_id_without_signature"); return; }
        const tbs = buildWitnessAlertTbs(sidBytes, "leaf_signed_by_neither_participant", observedAt, submitterIsCounterparty);
        if (!verify(new Uint8Array(Buffer.from(rawRelayId, "hex")), tbs, sigBytes)) {
          unreadable("witness_signature_invalid"); return;
        }
        verifiable = true;
      }
      const alert: RelayWitnessAlert = {
        sessionIdHex,
        reason: "leaf_signed_by_neither_participant",
        relayId: typeof rawRelayId === "string" ? rawRelayId : null,
        observedAt,
        submitterIsCounterparty,
        witnessPeerId: this.#relayPeerId,
        verifiable,
      };
      // BOTH halves, per Invariant 2: the log is the durable forensic record, and the callback is
      // the half that actually reaches a person.
      this.#logger.error("session.relay.witness.alert", {
        relayPeerId: this.#relayPeerId,
        session: alert.sessionIdHex,
        relayId: alert.relayId ?? "(unnamed)",
        submitterIsCounterparty: alert.submitterIsCounterparty,
        verifiable: alert.verifiable,
        observation: "one relay refused a leaf on this session because it verified against neither participant key",
        impact: "nothing was added to the conversation record. This is ONE relay's observation and " +
          "establishes only that it saw and refused that submission — not who sent it.",
      });
      if (this.#onWitnessAlert) this.#onWitnessAlert(alert);
    } else if (type === "relay_slot_reclaimed") {
      /**
       * DOD-M15-RELAYSLOTS-1 clause 8 — **the reaped party is told, and this is where it lands.**
       *
       * The relay reclaimed this agent's circuit reservation to free capacity. Without a branch
       * here the frame fell off the end of this chain and was discarded in silence, which is the
       * trap the order records in its own words: a refusal that only reaches the relay's log does
       * not exist. From the agent's side the reservation simply stops working.
       *
       * Recorded as a refusal so it reaches `cello_status` through the same surface as every other
       * relay refusal, with the same shape: a cause, and what to do about it.
       */
      const idleMs = typeof frame["idle_ms"] === "number" ? (frame["idle_ms"] as number) : undefined;
      const detail = typeof frame["detail"] === "string" ? (frame["detail"] as string) : undefined;
      this.#lastAuthRefusal = {
        reason: "slot_reclaimed",
        advice: detail ?? "This relay reclaimed your circuit reservation to free capacity because it " +
          "had carried no traffic for a long time. Your agent stays online and rebuilds its receiver " +
          "automatically; a new session will take a fresh reservation.",
        // Not the relay's fault and not ours — it was under pressure and we were the quietest. The
        // client rebuilds against the same pool, so there is nothing to fail over from.
        tryAnotherRelay: false,
      };
      this.#logger.warn("session.relay.slot_reclaimed", {
        relayPeerId: this.#relayPeerId,
        ...(idleMs !== undefined ? { idleHours: Math.round(idleMs / 3_600_000) } : {}),
        impact: "this relay reclaimed our circuit reservation to free capacity. Until a receiver is " +
          "rebuilt, this agent is reachable only over a direct connection.",
      });
    }
    // session_interrupted / content_park_notify are out of scope here — session interruption
    // is handled by the session node manager's dedicated relay-stream watcher.
  }

  /**
   * Proactively establish the authenticated stream from `node`. The RECEIVER must connect
   * before the counterparty submits, so the relay has its stream to deliver `leaf_deliver`
   * to (otherwise the relay queues until the recipient connects). Best-effort.
   */
  async connect(node: CelloNode): Promise<boolean> {
    return this.#ensureConnected(node);
  }

  /**
   * DOD-M15-RELAYAUTH-1 review HIGH-1 — prove key possession FROM THIS NODE, on its own stream.
   *
   * ⚠️ **`connect()` CANNOT be used for this, and using it was the defect.** `#ensureConnected`
   * returns `true` the moment `#stream` is non-null, and `#stream` belongs to whichever node
   * connected FIRST. An agent legitimately runs several nodes against one relay — the node promoted
   * into a live session, plus the replacement standing receiver built behind it — and they share
   * one `AgentRelayClient` because the cache is keyed `${agent}::${relay}`. So calling `connect()`
   * from the replacement receiver short-circuited on the session node's stream, sent nothing, and
   * the relay never saw that receiver's transport identity: it revoked the reservation ~15s later,
   * the watchdog rebuilt, and the agent churned on a ~45s loop holding no usable circuit address
   * for as long as the conversation lasted. Any future "reuse the existing connection" optimisation
   * here reintroduces exactly that.
   *
   * So this always opens its own short-lived stream from `node`, and marks it
   * `purpose: "reservation"` so the relay proves possession WITHOUT rebinding the agent's delivery
   * stream (which would steal the live session's inbound leaves — see the relay-side dispatch).
   */
  async proveReservation(node: CelloNode): Promise<boolean> {
    if (this.#closed) return false;
    for (const addr of this.#relayAddrs) {
      try { await node.dial(addr); break; } catch { /* try the next address */ }
    }
    let stream: Stream;
    try {
      stream = await node.newStream(this.#relayPeerId, RELAY_PROTOCOL_ID);
    } catch (err: unknown) {
      this.#logger.warn("session.relay.reservation_proof.failed", {
        relayPeerId: this.#relayPeerId, reason: "stream", error: extractErrorMessage(err),
      });
      return false;
    }
    try {
      const iter = (lp.decode(stream as unknown as AsyncIterable<Uint8Array>) as AsyncIterable<unknown>)[
        Symbol.asyncIterator
      ]() as AsyncIterator<Uint8Array>;
      const ok = await this.#authenticate(stream, iter, "reservation");
      this.#logger.info("session.relay.reservation_proof.result", {
        relayPeerId: this.#relayPeerId,
        nodePeerId: node.getPeerId(),
        ok,
        // DOD-M15-RELAYSLOTS-1: name the cause here too. `ok: false` alone sent people looking at
        // the transport for what is usually a token or a cap.
        ...(ok ? {} : { refusalReason: this.#lastAuthRefusal?.reason ?? "no_relay_verdict" }),
      });
      return ok;
    } finally {
      await stream.close().catch(() => {});
    }
  }

  /** Ensure an authenticated stream exists, (re)dialing from `node` if needed. */
  async #ensureConnected(node: CelloNode): Promise<boolean> {
    if (this.#closed) return false;
    if (this.#stream) return true;
    if (this.#connecting) return this.#connecting;
    this.#connecting = this.#connect(node).finally(() => { this.#connecting = null; });
    return this.#connecting;
  }

  async #connect(node: CelloNode): Promise<boolean> {
    // Best-effort dial: newStream auto-dials a known peer, but the relay's addrs may not
    // be in the peerstore yet, so dial each addr first. One success is enough.
    let dialed = false;
    let lastDialError = "";
    for (const addr of this.#relayAddrs) {
      try {
        await node.dial(addr);
        dialed = true;
        break;
      } catch (err: unknown) {
        lastDialError = extractErrorMessage(err);
      }
    }
    if (!dialed && this.#relayAddrs.length > 0) {
      this.#logger.warn("session.relay.dial.failed", {
        relayPeerId: this.#relayPeerId,
        relayAddrs: this.#relayAddrs,
        error: lastDialError,
      });
      return false;
    }

    let stream: Stream;
    try {
      stream = await node.newStream(this.#relayPeerId, RELAY_PROTOCOL_ID);
    } catch (err: unknown) {
      this.#logger.warn("session.relay.stream.failed", { relayPeerId: this.#relayPeerId, error: extractErrorMessage(err) });
      return false;
    }

    // ONE shared lp.decode iterator for the whole stream lifetime — splitting it signals
    // EOF to the relay's single-iterator reader and breaks subsequent reads.
    const iter = (lp.decode(stream as unknown as AsyncIterable<Uint8Array>) as AsyncIterable<unknown>)[
      Symbol.asyncIterator
    ]() as AsyncIterator<Uint8Array>;

    if (!(await this.#authenticate(stream, iter))) return false;

    this.#stream = stream;
    this.#logger.info("session.relay.connected", { relayPeerId: this.#relayPeerId });
    this.#startReader(stream, iter);
    return true;
  }

  async #authenticate(stream: Stream, iter: AsyncIterator<Uint8Array>, purpose?: "reservation"): Promise<boolean> {
    const challengeRes = await nextWithTimeout(iter, RELAY_AUTH_TIMEOUT_MS);
    if (challengeRes.done || challengeRes.value === undefined) {
      this.#logger.warn("session.relay.auth.failed", { relayPeerId: this.#relayPeerId, reason: "no_challenge" });
      return false;
    }
    let challenge: Record<string, unknown>;
    try {
      challenge = decode(toU8(challengeRes.value)) as Record<string, unknown>;
    } catch {
      this.#logger.warn("session.relay.auth.failed", { relayPeerId: this.#relayPeerId, reason: "challenge_decode" });
      return false;
    }
    if (challenge["type"] !== "relay_auth_challenge") {
      this.#logger.warn("session.relay.auth.failed", { relayPeerId: this.#relayPeerId, reason: "not_challenge" });
      return false;
    }
    const nonce = toU8(challenge["nonce"]);
    if (nonce.length !== 32) {
      this.#logger.warn("session.relay.auth.failed", { relayPeerId: this.#relayPeerId, reason: "bad_nonce" });
      return false;
    }
    const authSig = await this.#keyProvider.sign(buildRelayAuthPayload(nonce, this.#senderPubkey));
    /**
     * DOD-M15-RELAYSLOTS-1: read the token NOW, not at construction — it is reissued on every
     * signaling reconnect and the one this client was built with is usually already gone.
     *
     * When there is none we send the auth anyway. Declining to try would replace a named refusal
     * from the relay (`online_token_required`, which says what is wrong and what to do) with
     * silence on both sides — and silence is what an operator reads as "the product is broken".
     */
    const onlineToken = this.#onlineToken?.();
    if (!onlineToken) {
      this.#logger.warn("session.relay.auth.no_online_token", {
        relayPeerId: this.#relayPeerId,
        impact: "authenticating without the directory's online token. The relay will refuse this and " +
          "will not let this node keep a circuit reservation, so the agent is reachable by nobody " +
          "over this relay. The usual cause is that no directory connection has been established " +
          "yet; the next signaling connect issues a token and the receiver re-authenticates.",
      });
    }
    try {
      stream.send(lp.encode.single(encodeCbor({
        type: "relay_auth_response",
        pubkey: this.#senderPubkey,
        signature: authSig,
        // DOD-M15-RELAYAUTH-1: absent for the ordinary session auth (which also registers this
        // stream as the agent's delivery target). `"reservation"` proves possession from THIS
        // node's transport identity and nothing more — see proveReservation().
        ...(purpose ? { purpose } : {}),
        // DOD-M15-RELAYSLOTS-1: opaque bytes from the directory, forwarded verbatim. The client
        // never parses them — a format it does not read is a format it cannot get wrong.
        ...(onlineToken ? { online_token: onlineToken } : {}),
      }) as Uint8Array));
    } catch (err: unknown) {
      this.#logger.warn("session.relay.auth.failed", { relayPeerId: this.#relayPeerId, reason: "response_send", error: extractErrorMessage(err) });
      return false;
    }
    const ackRes = await nextWithTimeout(iter, RELAY_AUTH_TIMEOUT_MS);
    if (ackRes.done || ackRes.value === undefined) {
      this.#logger.warn("session.relay.auth.failed", { relayPeerId: this.#relayPeerId, reason: "no_auth_ok" });
      return false;
    }
    let ackFrame: Record<string, unknown>;
    try {
      ackFrame = decode(toU8(ackRes.value)) as Record<string, unknown>;
    } catch {
      this.#logger.warn("session.relay.auth.failed", { relayPeerId: this.#relayPeerId, reason: "auth_ok_decode" });
      return false;
    }
    if (ackFrame["type"] !== "relay_auth_ok") {
      /**
       * DOD-M15-RELAYABUSE-1 review F2 — **THE RELAY SAYS WHY, AND WE USED TO THROW IT AWAY.**
       *
       * `relay_auth_failed` carries a `reason` — `rate_limited`, `signature_invalid`, `nonce_expired`,
       * `nonce_reused`, `nonce_unknown` — and, when throttled, a `retry_after_ms`. This branch
       * collapsed all of them into the single word `auth_rejected`, so a throttled agent looked
       * exactly like a bad signature, which looked exactly like a dead relay. That is precisely the
       * distinction the order that added those refusals set out to create, undone at the last hop.
       *
       * The difference matters to whoever is looking: `rate_limited` clears by itself and says when;
       * `signature_invalid` never clears and means a key or clock problem; a nonce failure means the
       * handshake raced and an immediate retry is the right move. One label for all three sends
       * someone to look for a broken relay in all three cases.
       */
      const relayReason = typeof ackFrame["reason"] === "string" ? (ackFrame["reason"] as string) : undefined;
      const retryAfterMs = typeof ackFrame["retry_after_ms"] === "number" ? (ackFrame["retry_after_ms"] as number) : undefined;
      /**
       * DOD-M15-RELAYSLOTS-1: keep the refusal, do not merely log it.
       *
       * Everything below writes an excellent warn line into a file nobody opens. The operator who
       * runs `cello_use_agent` and finds their agent unreachable never sees it, and the daemon
       * deciding whether another relay would help cannot read it either. So the classified refusal
       * — reason, what to do about it, and whether to fail over — is stored where both can reach it.
       */
      const slotsHeld = typeof ackFrame["slots_held"] === "number" ? (ackFrame["slots_held"] as number) : undefined;
      const slotCap = typeof ackFrame["slot_cap"] === "number" ? (ackFrame["slot_cap"] as number) : undefined;
      this.#lastAuthRefusal = classifyRelayAuthRefusal(
        ackFrame["type"] === "relay_auth_failed" ? (relayReason ?? "auth_rejected") : "unexpected_frame",
        {
          ...(slotsHeld !== undefined ? { slotsHeld } : {}),
          ...(slotCap !== undefined ? { slotCap } : {}),
          ...(retryAfterMs !== undefined ? { retryAfterMs } : {}),
        },
      );
      this.#logger.warn("session.relay.auth.failed", {
        relayPeerId: this.#relayPeerId,
        reason: ackFrame["type"] === "relay_auth_failed" ? (relayReason ?? "auth_rejected") : "unexpected_frame",
        ...(retryAfterMs !== undefined ? { retryAfterMs } : {}),
        impact: relayReason === "rate_limited"
          ? "this relay is throttling us; it clears on its own after the stated window, and until it does this agent cannot reserve or witness here"
          : "this agent could not authenticate to this relay, so it cannot witness leaves or hold a reservation here",
      });
      return false;
    }
    // DOD-M15-RELAYSLOTS-1: a success clears the stored refusal, so a stale one is never reported
    // as the current state of a relay that has since started admitting us.
    this.#lastAuthRefusal = null;
    return true;
  }

  #startReader(stream: Stream, iter: AsyncIterator<Uint8Array>): void {
    void (async () => {
      try {
        while (!this.#closed && this.#stream === stream) {
          const res = await iter.next();
          if (res.done || res.value === undefined) break;
          // The await above can suspend across a #resetStream() (timeout) that supersedes this
          // stream. Re-check identity before dispatching so a late frame from a stale stream
          // (e.g. a buffered ack for a timed-out submit) can't bump/settle the wrong session.
          if (this.#stream !== stream) break;
          let frame: Record<string, unknown>;
          try {
            frame = decode(toU8(res.value)) as Record<string, unknown>;
          } catch {
            continue;
          }
          this.#dispatch(frame);
        }
      } catch (err: unknown) {
        // WARN, not debug (DOD-RELAY-KEEPALIVE-1 review F4). This is the ONLY place the cause of a
        // dead relay link survives: the watchdog that notices later reports `relay_connection_gone`,
        // which names where it noticed, not why. At debug, 2,061 of these went untraced through a
        // launch — the reader ending is not routine, it means in-flight submits just failed.
        this.#logger.warn("session.relay.reader.ended", { relayPeerId: this.#relayPeerId, error: extractErrorMessage(err) });
        this.#lastReaderError = extractErrorMessage(err);
      } finally {
        // Stream gone — clear it so the next submit re-dials, and fail any in-flight submit.
        if (this.#stream === stream) this.#stream = null;
        this.#settlePending({ ok: false, reason: "relay_stream_closed" });
        // Settle an in-flight record too, so #doRecord doesn't
        // wait the full timeout on a dropped stream. "closed" is transient (not a directory rejection) ⇒
        // recorded stays false and it is retried after reconnect.
        { const r = this.#pendingRecord; this.#pendingRecord = null; if (r) r("closed"); }
        // A pure-receiver session issues no submit, so it would never trigger a re-dial
        // after the node that owned the stream is torn down. If sessions remain, proactively
        // re-establish from any still-live registered session node so queued leaf_delivers
        // are drained (the relay queues by pubkey and re-delivers on reconnect).
        if (!this.#closed && this.#sessions.size > 0) {
          void this.#reconnectFromAnySession();
        }
      }
    })();
  }

  /** Re-establish the shared stream from any registered session's node (first that dials). */
  async #reconnectFromAnySession(): Promise<void> {
    if (this.#closed || this.#stream) return;
    for (const { node } of this.#sessions.values()) {
      if (await this.#ensureConnected(node)) return;
    }
  }

  /**
   * Submit a session's CONTENT-leaf hash to the relay. Connects/re-connects from `node` if needed.
   * Globally FIFO across the agent's sessions (the ack has no session_id).
   *
   * `leafKind` defaults to MESSAGE, which is what `cello_send` wants. It is a PARAMETER because
   * the document path needs 0x04/0x05: the seal certificate is computed by the directory from the
   * leaves the RELAY witnessed, and `seal-legibility.ts` excludes doc/reject leaves from
   * `final_message` and from `answered` — guards that could never fire while this method hardcoded
   * MSG for every caller. See `document-leaf-kind-on-the-wire.test.ts` for what that cost.
   */
  async submitMessageHash(
    node: CelloNode,
    sessionId: Uint8Array,
    contentHash: Uint8Array,
    /**
     * REQUIRED — `DOD-M15-SEALWIRE-1` B2b-1 pass-2 F3. This default was the last one on the path,
     * and it is the reason a test passing `undefined` for `leafKind` looked correct: the value was
     * silently rebuilt as MESSAGE one hop below the parameter the fix had just made required. Its
     * one production caller always passes explicitly, so the default was dead and misleading.
     */
    leafKind: number,
  ): Promise<SubmitResult> {
    /**
     * `null`, and it is now IMPOSSIBLE to omit — see `submitLeaf`'s note on why the parameter is
     * required. A message leaf's content belongs to the operator and never reaches the relay.
     */
    return this.submitLeaf(node, sessionId, contentHash, leafKind, null);
  }

  /**
   * ─── WITNESS A LEAF THIS AGENT RECEIVED BUT DID NOT AUTHOR — 034-CARRYLEAF ────────────────────
   *
   * **This is what closes `DOD-M15-WITHHOLD-SEAL-1`.** Until it existed, `submitMessageHash` had
   * one production caller on the SEND path, so nothing ever witnessed a message that was RECEIVED.
   * A counterparty who delivered a message directly and never submitted its hash left the relay's
   * account of the conversation one message short — permanently — and a unilateral seal then agreed
   * with the witness. Every leaf validly signed, nothing false, the last thing said simply absent.
   *
   * **The teeth are the author's own signature.** It arrived on the content frame beside the bytes
   * it signs, this daemon verified it before ingesting anything, and it cannot be forged here. The
   * relay verifies it again against the session's assignment before sequencing — so what this hands
   * over is a claim the author made and cannot disown.
   *
   * ⚠️ **THE BYTES ARE PASSED THROUGH, NEVER REBUILT.** A signature is over the encoded bytes, and
   * the one measured cost of forgetting that on this exact structure was a daemon-local encoder
   * emitting a timestamp as float64 where the published one promotes to uint64 — same value,
   * different signed bytes, refused by everyone.
   */
  async witnessReceivedLeaf(
    node: CelloNode,
    sessionId: Uint8Array,
    contentHash: Uint8Array,
    leafKind: number,
    carried: CarriedLeafClaim,
  ): Promise<SubmitResult> {
    return this.submitLeaf(node, sessionId, contentHash, leafKind, null, carried);
  }

  /**
   * Submit a leaf hash of a given kind (0x00 message / 0x02 control) to the relay. The SEAL
   * ctrl leaf rides this path: two distinct-sender ctrl leaves in the relay's
   * log trigger the directory's FROST notarization (relay `#maybeProcessSeal`).
   *
   * ─── `contentBytes` — `DOD-M15-SEALWIRE-1` bullets 3+4, THE SENDER LEG ───────────────────────
   *
   * The SEAL leaf's own payload, carried alongside its hash. Without it the directory holds a
   * SHA-256 pre-image and nothing else, so the client's SIGNED `final_root` — the one value in the
   * whole seal that the relay cannot produce — is unrecoverable, and every root check the directory
   * can make compares the relay against itself.
   *
   * ⚠️ THIS PARAMETER PUTS LEAF CONTENT ON THE RELAY, AND THE RELAY IS THE PARTY THIS PROTOCOL
   * EXISTS TO KEEP CONTENT AWAY FROM (INV-3: a forwarding relay sees ciphertext).
   *
   * It is safe for a SEAL ctrl leaf and for nothing else. The payload is `[session_id, final_root,
   * close_timestamp, "PENDING"]` and the relay already knows all four — it assigned the session,
   * built the tree the root comes from, and stamped the leaf. Nothing is disclosed. That reasoning
   * stops dead at the next leaf kind: a `msg` leaf's content is the operator's plaintext and a `doc`
   * leaf's is their document.
   *
   * So both directions are REFUSED rather than tidied, and refused HERE rather than at the relay:
   *
   *   - content on a non-ctrl leaf → the relay would refuse the whole frame, but only after the
   *     operator's words had already crossed the wire to the party that must not have them, and the
   *     refusal would destroy their send rather than protect it.
   *   - a ctrl leaf with NO payload → this was the actual defect. `submitSealLeaf` computed the
   *     payload, hashed it, and had nowhere to put it, so it was dropped. The seal still succeeded,
   *     the relay still acked, and three hops later the directory reported `not_carried` and blamed
   *     the relay's build version — for a value the client never sent. Four reviewed legs shipped
   *     over that silence. A dropped argument now fails on the machine that dropped it.
   *
   * ⚠️ REQUIRED, AND `| null` RATHER THAN `?` — THE TYPE IS THE GUARD.
   *
   * I first wrote this optional and covered it with tests. Then I ran the revert test that mattered:
   * drop the argument at the one call site that must pass it, exactly reproducing the original
   * defect. **All five new tests stayed green.** An optional parameter makes the defect a silent,
   * type-legal omission — which is precisely how it shipped through four reviews the first time.
   *
   * Required means the omission is a COMPILE ERROR, caught by the gate on the machine that made it,
   * before any test runs. Every caller must now say what this leaf carries, and `submitMessageHash`
   * says `null` in one visible place instead of by saying nothing at all.
   */
  async submitLeaf(
    node: CelloNode,
    sessionId: Uint8Array,
    contentHash: Uint8Array,
    leafKind: number,
    contentBytes: Uint8Array | null,
    /**
     * 034-CARRYLEAF — a leaf THIS AGENT DID NOT AUTHOR, carried on its author's behalf.
     *
     * Absent for every ordinary send, where this client builds and signs its own claim. Present
     * only when witnessing something received whose author never submitted it — see
     * `witnessReceivedLeaf`.
     */
    carried?: CarriedLeafClaim,
  ): Promise<SubmitResult> {
    if (contentBytes !== null && leafKind !== LEAF_KIND_CTRL) {
      // Logged at ERROR and returned: a caller reaching this line is trying to hand the relay
      // operator content, and the log must carry it even if the caller swallows the result.
      this.#logger.error("session.relay.submit.content_not_permitted", {
        relayPeerId: this.#relayPeerId,
        leafKind,
        impact: "the submit was NOT sent. Only a SEAL ctrl leaf may carry its content to the relay; every other leaf kind's content belongs to the operator.",
        guidance: "Pass contentBytes only with LEAF_KIND_CTRL. If a new leaf kind genuinely needs to disclose its content to the relay, that is a protocol decision, not a call-site one.",
      });
      return { ok: false, reason: "content_not_permitted_for_leaf_kind" };
    }
    if (contentBytes === null && leafKind === LEAF_KIND_CTRL) {
      this.#logger.error("session.relay.submit.seal_payload_missing", {
        relayPeerId: this.#relayPeerId,
        impact: "the seal leaf was NOT sent. Sending it without its payload produces a certificate the directory cannot check against any participant's signed transcript — silently, and reported downstream as the RELAY being on an old build.",
        guidance: "A ctrl leaf on this path is a SEAL leaf; pass the encodeSealPayload bytes whose SHA-256(0x02 ‖ payload) is the contentHash argument.",
      });
      return { ok: false, reason: "seal_payload_not_carried" };
    }
    if (contentBytes !== null) {
      /**
       * ⚠️ THE BYTES MUST BE A SEAL PAYLOAD FOR THIS SESSION, AND THEY MUST HASH TO THE HASH BEING
       * SIGNED — review pass 2, MEDIUM-1 and HIGH-1. The kind check alone was not the property this
       * parameter's whole justification rests on.
       *
       * The justification is: *"the payload is [session_id, final_root, close_timestamp, "PENDING"]
       * and the relay already knows all four, so nothing is disclosed."* The code enforced
       * `leafKind === CTRL` and nothing else — so a caller passing a ctrl leaf with four kilobytes
       * of the operator's text would have transmitted it, and been refused only at the relay, AFTER
       * it crossed the wire to the party that must not have it. That is the precise harm the local
       * guard exists to prevent, and the relay learned this same lesson at its own review (H1 in
       * `relay-frames.ts`) one file over. I wrote the weaker version anyway.
       *
       * THE HASH BINDING IS THE MORE IMPORTANT HALF, and it closes a mutant that survived pass 1's
       * type hardening. Making the parameter required catches an OMITTED argument; it cannot catch a
       * SUBSTITUTED one. A caller that re-derives the payload instead of passing the one it hashed
       * — a second `encodeSealPayload` call, a fresh `Date.now()` — compiles, and the mismatch
       * surfaces at the directory as `seal_payload_unbound`, whose guidance reads *"someone between
       * them and here altered or fabricated the payload — the relay is the only party on that path.
       * Treat this as relay tampering, not a version mismatch."*
       *
       * **A client-side derivation slip would be published as a named accusation against a healthy
       * relay operator.** Checking it here makes it a local refusal on the machine that caused it.
       */
      const rederived = new Uint8Array(
        createHash("sha256").update(new Uint8Array([LEAF_KIND_CTRL])).update(contentBytes).digest(),
      );
      if (!Buffer.from(rederived).equals(Buffer.from(contentHash))) {
        this.#logger.error("session.relay.submit.seal_payload_unbound", {
          relayPeerId: this.#relayPeerId,
          impact: "the seal leaf was NOT sent. The payload does not hash to the content_hash this leaf signs, so the directory would have reported it as RELAY TAMPERING — a named accusation against a node that did nothing wrong.",
          guidance: "Pass the SAME bytes that produced contentHash. Re-deriving the payload at the call site produces a different close_timestamp and breaks the binding.",
        });
        return { ok: false, reason: "seal_payload_unbound" };
      }
      const decoded = decodeSealPayload(contentBytes);
      if (!decoded || !Buffer.from(decoded.session_id).equals(Buffer.from(sessionId))) {
        this.#logger.error("session.relay.submit.seal_payload_invalid", {
          relayPeerId: this.#relayPeerId,
          impact: "the submit was NOT sent. Only a SEAL payload for THIS session may be disclosed to the relay — arbitrary bytes on a ctrl leaf are still the operator's content, and a payload for another session is a replay.",
          guidance: decoded
            ? "The payload names a different session than the one being submitted."
            : "The bytes are not a decodable SEAL payload. Build them with encodeSealPayload.",
        });
        return { ok: false, reason: "seal_payload_invalid" };
      }
    }
    // Chain on the prior submit so only one is outstanding at a time (FIFO). The ack
    // carries no session_id, so concurrent submits on one stream would be ambiguous.
    const run = this.#submitChain.then(() => this.#doSubmit(node, sessionId, contentHash, leafKind, contentBytes, carried));
    // Keep the chain alive regardless of this submit's outcome.
    this.#submitChain = run.then(() => undefined, () => undefined);
    return run;
  }

  /**
   * DOD-FIRSTMSG-WITNESS-1: `session_not_found` is TRANSIENT, not terminal.
   *
   * The relay answers it when it does not hold the session YET — the assignment record is still
   * landing, or the counterparty recorded it and our own record raced ahead of the submit. Proven
   * from the live log: in all 23 first-message failures the `assignment.recorded` event lands
   * 5 ms – 2.1 s AFTER the rejected submit. The relay is reachable and answering; it is simply
   * not ready.
   *
   * Before this, the rejection was returned to `sendContent`, which logged
   * `session.relay.hash.submit.failed` and appended the leaf UNWITNESSED anyway. Nothing retried,
   * so the relay's counter never counted that message and the local record stayed exactly one
   * ahead for the life of the session. Because the bilateral certificate is rebuilt EXCLUSIVELY
   * from relay-witnessed leaves, the sealed receipt omitted the conversation's opening message —
   * and was issued regardless.
   *
   * Retrying re-presents the assignment first (idempotent — the relay answers `assignment_ok` on
   * `session_already_exists`), which is also what supplies the wait: re-recording is a full
   * round trip, so the retry cannot busy-spin against a relay that is still catching up.
   *
   * This does NOT collapse the two states the fix must tell apart:
   *   - `session_not_found` — a reachable relay that does not hold the session yet → retry here.
   *   - `relay_unavailable` / stream failures — a genuine outage → returned untouched, so
   *     `sendContent` still degrades to an unwitnessed append and the inbox stays readable.
   * Any other rejection (`session_sealed`, `not_a_participant`, signature failures) is terminal
   * and returned as-is — retrying those would be pointless traffic masking a real state.
   */
  static readonly #SESSION_NOT_FOUND_ATTEMPTS = 3;
  /**
   * DOD-M15-RELAYABUSE-1 review F1: how many times a throttled submit waits out the relay's stated
   * window before the refusal is surfaced. Three, because the window is a fixed sliding minute —
   * two waits clear any ordinary burst, and a third failure means something other than this
   * sender's own volume is going on, which the operator should hear about.
   */
  static readonly #RATE_LIMITED_ATTEMPTS = 3;
  /** Used only when the relay names no window (an older relay, or a malformed value). */
  static readonly #RATE_LIMITED_FALLBACK_MS = 5_000;
  /**
   * Ceiling on a single wait, so a relay reporting an implausible window cannot park a send
   * indefinitely — a hostile or misconfigured relay must not be able to stall a sender by
   * answering `retry_after_ms: 3600000`. Past this the send fails and says so.
   */
  static readonly #RATE_LIMITED_MAX_WAIT_MS = 65_000;

  async #doSubmit(node: CelloNode, sessionId: Uint8Array, contentHash: Uint8Array, leafKind: number, contentBytes: Uint8Array | null, carried?: CarriedLeafClaim): Promise<SubmitResult> {
    const sessionIdHex = Buffer.from(sessionId).toString("hex");
    // Snapshotted BEFORE the first attempt, and it is the whole safety of this loop.
    //
    // The first-message race is BY DEFINITION a session we have not recorded yet. A session we DID
    // record and that the relay now reports missing is a DIFFERENT state: the relay destroys a
    // session on seal (relay-node.ts `confirmSeal`) and on idle sweep, and its store keeps NO
    // tombstone — `recordSession` re-creates any absent key fresh (`seq_counter: 0`, empty
    // leaf_log, status "active"). So `getSession` answers `session_not_found`, NOT `session_sealed`.
    // Re-presenting our still-valid directory-signed assignment there would silently RESURRECT a
    // sealed session on the relay: a ghost with an empty log, an idle timer and a delivery path,
    // created by a client submit retry. Two ctrl leaves on it would drive a second notarization
    // over a 1-leaf log for an already-certified session.
    //
    // The 2 post-seal failures in this defect's own evidence table are exactly that shape — they
    // reported `session_not_found`, indistinguishable at the wire from the race — which is why
    // this must be discriminated on OUR state, not on the relay's reason string.
    const recordedBefore = this.#sessions.get(sessionIdHex)?.recorded === true;

    let result = await this.#doSubmitOnce(node, sessionId, contentHash, leafKind, contentBytes, carried);
    for (
      let attempt = 1;
      attempt < AgentRelayClient.#SESSION_NOT_FOUND_ATTEMPTS
        && !recordedBefore
        && !result.ok
        && (result.reason === "session_not_found" || result.reason === "session_not_recorded")
        && !this.#closed;
      attempt++
    ) {
      // Force the assignment to be re-presented: we never recorded this session, so the relay
      // genuinely does not hold it yet. A session with no assignment to present (direct/legacy)
      // re-submits without a record — still bounded, and it surfaces the same named failure
      // rather than hanging.
      const sess = this.#sessions.get(sessionIdHex);
      if (sess) sess.recorded = false;
      this.#logger.info("session.relay.submit.retry", {
        relayPeerId: this.#relayPeerId,
        sessionShort: sessionIdHex.slice(0, 16),
        attempt,
        reason: result.reason,
      });
      result = await this.#doSubmitOnce(node, sessionId, contentHash, leafKind, contentBytes, carried);
    }

    /**
     * DOD-M15-RELAYABUSE-1 review F1 — **A THROTTLE IS BACK-PRESSURE, NOT AN ERROR.** (Andre,
     * 2026-08-31: retry on the relay's own timing; surface only if the retry also fails.)
     *
     * Without this the relay's `rate_limited` fell into the caller's catch-all: one log line, and
     * `cello_send` returned `{ok:true, delivered:true}` for a message the relay had refused to
     * witness — on the parked path telling the operator it was *"sealed, witnessed and on its way"*.
     * The leaf went out unwitnessed with no sequence number, and the seal later covered a transcript
     * missing it.
     *
     * This is the ONE refusal that is safely retryable and self-clearing, and the relay tells us
     * exactly when. So we wait it out here, where the wait is invisible, rather than handing the
     * agent an error for a condition that resolves in under a minute. Bounded: if the window is
     * absent or implausible we fall back to a fixed wait, and after
     * `#RATE_LIMITED_ATTEMPTS` the refusal is returned and the caller surfaces it — Option 2 as
     * the fallback, not the first move.
     */
    for (
      let attempt = 1;
      attempt < AgentRelayClient.#RATE_LIMITED_ATTEMPTS
        && !result.ok
        && result.reason === "rate_limited"
        && !this.#closed;
      attempt++
    ) {
      const waitMs = Math.min(
        result.retry_after_ms !== undefined ? result.retry_after_ms : AgentRelayClient.#RATE_LIMITED_FALLBACK_MS,
        AgentRelayClient.#RATE_LIMITED_MAX_WAIT_MS,
      );
      this.#logger.info("session.relay.submit.throttled", {
        relayPeerId: this.#relayPeerId,
        sessionShort: sessionIdHex.slice(0, 16),
        attempt,
        waitMs,
        retryAfterMsFromRelay: result.retry_after_ms,
        impact: "the relay is throttling this sender; waiting out its stated window and resubmitting — the message is NOT lost and the operator is not told, because this clears on its own",
      });
      await new Promise((r) => setTimeout(r, waitMs));
      if (this.#closed) break;
      result = await this.#doSubmitOnce(node, sessionId, contentHash, leafKind, contentBytes, carried);
    }
    if (!result.ok && result.reason === "rate_limited") {
      // Option 2, the fallback: it did not clear within our budget, so the caller must hear it
      // rather than be told the message was witnessed.
      this.#logger.warn("session.relay.submit.throttle_persisted", {
        relayPeerId: this.#relayPeerId,
        sessionShort: sessionIdHex.slice(0, 16),
        attempts: AgentRelayClient.#RATE_LIMITED_ATTEMPTS,
        impact: "this message was NOT witnessed by the relay — it has no sequence number and will not appear in the notarized record",
      });
    }

    // The relay lost a session we had successfully recorded — sealed, idle-swept, or restarted.
    // Report THAT, rather than letting the caller read a bare `session_not_found` that reads like
    // the first-message race. Never re-present here: recreating it is the resurrection above.
    if (recordedBefore && !result.ok && result.reason === "session_not_found") {
      this.#logger.warn("session.relay.session.gone", {
        relayPeerId: this.#relayPeerId,
        sessionShort: sessionIdHex.slice(0, 16),
        guidance: "the relay no longer holds a session it had recorded (sealed, idle-swept, or restarted) — not re-presented, because that would recreate it with an empty leaf log",
      });
      return { ok: false, reason: "relay_session_gone" };
    }
    return result;
  }

  async #doSubmitOnce(node: CelloNode, sessionId: Uint8Array, contentHash: Uint8Array, leafKind: number, contentBytes: Uint8Array | null, carried?: CarriedLeafClaim): Promise<SubmitResult> {
    if (this.#closed) return { ok: false, reason: "relay_client_closed" };
    if (!(await this.#ensureConnected(node))) return { ok: false, reason: "relay_unavailable" };

    const sessionIdHex = Buffer.from(sessionId).toString("hex");
    // The relay records the session from the CLIENT-presented assignment. It MUST be recorded BEFORE
    // the first hash_submit — the relay rejects a submit for an unknown session. Idempotent + no-op when
    // there is no assignment to present (direct/persisted sessions). Runs inline on the submit chain (no re-chaining
    // — #doSubmit is already a chain link), and may reset the stream on failure, so capture #stream after.
    const recorded = await this.#doRecord(node, sessionIdHex);
    const sess = this.#sessions.get(sessionIdHex);
    if (!recorded && sess?.assignment) {
      // DOD-FIRSTMSG-WITNESS-1 AC3: do NOT send a hash_submit for a session we know the relay does
      // not hold. Previously this return value was discarded and the doomed frame went out anyway —
      // the line this defect's producer→consumer trace names as THE gap. Two sub-states, kept apart:
      //   - recordRejected  → TERMINAL (the relay refused the assignment as unverifiable). Retrying
      //                       cannot help and would storm the shared stream.
      //   - anything else   → the record is in flight or transiently failed. Retryable.
      // A session with NO assignment to present (direct/legacy) is not covered here: #doRecord
      // returns true for it, so it still submits exactly as before.
      if (sess.recordRejected) return { ok: false, reason: "relay_assignment_rejected" };
      // A TIMEOUT IS NOT "NOT READY YET". The retry below exists for a relay that has not finished
      // registering the session — it answers in milliseconds. A record that timed out means the relay
      // is not answering at all, and retrying spends HASH_SUBMIT_TIMEOUT_MS again per attempt on the
      // chain SHARED by every session this agent holds on this relay. Classifying it as unreachable
      // proceeds unwitnessed immediately, which is what AC2 asks for on an outage — the send is not
      // lost, and one sick relay cannot hold an operator's other conversations for half a minute.
      if (sess.recordTimedOut) return { ok: false, reason: "relay_unavailable" };
      return { ok: false, reason: "session_not_recorded" };
    }
    const stream = this.#stream;
    if (!stream) return { ok: false, reason: "relay_unavailable" };

    /**
     * ─── WHAT THIS SEND ACKNOWLEDGES — 033-ACKEMIT ───────────────────────────────────────────────
     *
     * This session's OWN high-water mark (NOT an agent-global one) — the relay's seq_counter is per
     * session and rejects `last_seen_seq > seq_counter` — AND the content hash at that position,
     * read from the one entry that holds both.
     */
    const lastSeen = this.#lastSeen.get(sessionIdHex);
    /**
     * ⚠️ **THIS COMMENT USED TO SAY "REFUSED, NOT DOWNGRADED", AND THE CODE UNDER IT DID REFUSE.**
     * It is rewritten rather than deleted because a comment asserting a refusal that no longer
     * happens is how the next reader comes to believe a guard exists where there is a fallback.
     *
     * There is no seed only when this session was registered with neither a genesis nor an
     * assignment to derive one from, AND nothing has been received on it. The claim that goes out
     * then is `last_seen_seq: 0` with no hash — "I have seen nothing of yours" — which is true and
     * asserts nothing about content, so it is not the unbacked number this unit exists to stop
     * signing. A claim that NAMES a position with no hash is the defect, and the receiving daemon
     * refuses exactly that.
     */
    /**
     * ⚠️ NOT FOR A CARRIED LEAF — 034-CARRYLEAF review F8. This branch describes THIS agent having
     * nothing to acknowledge, and on a counter-submit the acknowledgement inside the bytes is the
     * AUTHOR's, already made. Logging "this submit acknowledges nothing" about it would be false,
     * and this daemon's own seed is irrelevant to a claim it did not write.
     */
    if (!lastSeen && !carried) {
      /**
       * ⚠️ **v1, AND ONLY BECAUSE THERE IS NOTHING TO ACKNOWLEDGE.** Same rule as the content
       * claim's, and the receiving half is `#verifyAcknowledgedContent` — a v1 claim is refused the
       * moment it names position 1 or beyond, and accepted when it names none.
       *
       * Reaching here means the session was registered with no genesis and no assignment to derive
       * one from, and no counterparty leaf has been delivered. `last_seen_seq: 0` with no hash says
       * "I have seen nothing of yours", which is true, and asserts nothing about content — so it is
       * not the unbacked number this unit exists to stop signing.
       *
       * It does not refuse the submit, and an earlier version did. Sessions brokered without a
       * relay assignment are real, and refusing there left them unable to be witnessed at all.
       */
      this.#logger.info("session.relay.submit.unacknowledged", {
        relayPeerId: this.#relayPeerId,
        session: sessionIdHex,
        impact:
          "this submit acknowledges nothing: the session has no recorded starting point and no " +
          "counterparty leaf has arrived on it. The leaf is witnessed as normal; the claim simply " +
          "makes no assertion about what this agent has received.",
      });
    }
    // The published encoder from protocol-types — the ONE definition of the field order, pinned by
    // `structure1-canonical.json` (v1) and `structure1-v2-canonical.json` (v2). A second local copy
    // lived here until 020-ACKHASH; it drifted, and the drift was invisible because both copies
    // "worked": it encoded a timestamp above 2^32-1 as a CBOR float64 while the published encoder
    // (and every other TBS builder in this package) promotes it to a uint64. Same value, different
    // signed bytes, and only the vector said which was canonical.
    //
    // `lastSeenHash` is passed on EVERY send, so every claim this daemon signs is v2 and binds to
    // content. Nothing here ever passes `undefined` — see the refusal above.
    /**
     * ⚠️ **A CARRIED LEAF IS SENT VERBATIM AND SIGNED BY NOBODY HERE — 034-CARRYLEAF.**
     *
     * When this agent is witnessing something it RECEIVED, the claim already exists: its author
     * built it, signed it, and put it on the content frame. Re-encoding it would change the signed
     * bytes and the relay would refuse a leaf that is perfectly valid. Signing it ourselves would be
     * worse — it would turn their statement into ours, which is the one thing that must never happen
     * to a record whose whole value is that each party's words are their own.
     *
     * So this branch takes the bytes as they arrived, and this agent's own acknowledgement state is
     * deliberately NOT consulted: `last_seen_seq` and `last_seen_hash` inside those bytes are the
     * AUTHOR's account of what THEY had seen, and they are not ours to restate.
     */
    /**
     * ─── THE SELF LINK — `DOD-M15-SELFCHAIN-1` ───────────────────────────────────────────────────
     *
     * `lastSeenHash` above chains this sender to their COUNTERPARTY. It does not chain them to
     * themselves, so two messages sent back to back carry identical acknowledgements and nothing in
     * the signed bytes tells them apart. `prevOwnHash` is the other half: the content hash of this
     * agent's own previous message in this session.
     *
     * ⚠️ THE FIRST MESSAGE CARRIES THE SESSION GENESIS, NOT AN ABSENCE. "I have not spoken here" is
     * a real state with a defined value, derived per session — the same rule and the same constant
     * `lastSeenHash` uses, for the same reason: a shared constant would be presentable for any
     * conversation.
     *
     * ⚠️ AND WITHOUT A SEED THERE IS NO LINK TO MAKE, so the claim stays v2 rather than carrying a
     * link this daemon cannot support. That is the same honest degradation as the `lastSeen` branch
     * above: a session registered with neither a genesis nor an assignment has no agreed starting
     * point, and inventing one would sign a chain anchored to nothing.
     */
    const selfSeed = lastSeen?.hash;
    const prevOwn = this.#ownChainStore && selfSeed
      ? (this.#ownChainStore.lastOwnHash(this.senderPubkeyHex, sessionIdHex) ?? selfSeed)
      : undefined;
    if (!carried && !prevOwn) {
      this.#logger.warn("session.relay.submit.unchained", {
        relayPeerId: this.#relayPeerId,
        session: sessionIdHex,
        impact:
          "this message does not link to this agent's previous message in the conversation, so the " +
          "order of its own messages cannot be proven later. The message is witnessed as normal. " +
          "This happens when the session has no recorded starting point on this machine.",
      });
    }
    const structure1 = carried ? carried.structure1Cbor : encodeStructure1({
      contentHash,
      senderPubkey: this.#senderPubkey,
      sessionId,
      lastSeenSeq: lastSeen?.seq ?? 0,
      timestamp: Date.now(),
      ...(lastSeen ? { lastSeenHash: lastSeen.hash } : {}),
      ...(prevOwn ? { prevOwnHash: prevOwn } : {}),
    });
    const signature = carried ? carried.senderSignature : await this.#keyProvider.sign(structure1);
    const frame = encodeCbor({
      type: "hash_submit",
      session_id: sessionId,
      leaf_kind: leafKind,
      structure1_cbor: structure1,
      sender_signature: signature,
      /**
       * `DOD-M15-SEALWIRE-1` bullets 3+4 — the SEAL payload, and ONLY on a ctrl leaf.
       *
       * ⚠️ MY REASON FOR THE SPREAD WAS MEASURABLY WRONG, AND THE TRUE RISK IS THE OPPOSITE ONE —
       * review pass 2, MEDIUM-3, corrected rather than deleted.
       *
       * It said an explicit `content_bytes: undefined` *"encodes as a present CBOR key, and the
       * relay's guard refuses a present-but-unusable value by voiding the whole frame — that would
       * turn every ordinary message into a refused submit."* Measured through the production encoder:
       * the key IS emitted (0xf7), but it decodes back to `undefined`, so the relay's guard never
       * fires and the frame is **accepted with no payload**.
       *
       * So the mutation does not produce a loud federation-wide refusal. It produces a silent
       * `not_carried` at the directory — exactly the silent downgrade this whole unit exists to kill,
       * and a far worse outcome than the one I warned about. Writing the scarier consequence would
       * have sent the next reader hunting an availability bug instead of a mute one.
       *
       * The spread is still correct, and the ANCHOR test is what pins it: `"content_bytes" in frame`
       * is TRUE for the `undefined` mutant precisely because the key is present, so that assertion —
       * not the relay — is what catches this.
       *
       * `submitLeaf` has already established that this is set if and only if `leafKind` is ctrl, and
       * that the bytes are a SEAL payload for this session hashing to the signed `content_hash` —
       * every direction refused there, at ERROR, before anything reaches the wire.
       */
      ...(contentBytes !== null ? { content_bytes: contentBytes } : {}),
    }) as Uint8Array;

    // Set the resolver synchronously (no await between the in-flight check and the set):
    // the submit chain guarantees no other submit runs concurrently, so #pendingAck is null.
    let resolveAck!: AckResolver;
    const ackPromise = new Promise<SubmitResult>((r) => { resolveAck = r; });
    this.#pendingAck = resolveAck;
    this.#pendingAckSessionHex = sessionIdHex;
    // Remember this submit's sender-signed structure1_cbor so its ack can return the full
    // ordering record (the ack itself carries only the relay's structure2_cbor).
    this.#pendingStructure1 = structure1;
    this.#pendingSignature = signature;
    this.#pendingLeafKind = leafKind;
    try {
      stream.send(lp.encode.single(frame));
    } catch (err: unknown) {
      if (this.#pendingAck === resolveAck) { this.#pendingAck = null; this.#pendingAckSessionHex = null; this.#pendingStructure1 = null; this.#pendingSignature = null; this.#pendingLeafKind = null; }
      this.#logger.warn("session.relay.submit.send.failed", { relayPeerId: this.#relayPeerId, error: extractErrorMessage(err) });
      return { ok: false, reason: "relay_submit_send_failed" };
    }
    let timer!: ReturnType<typeof setTimeout>;
    const timeout = new Promise<SubmitResult>((r) => {
      timer = setTimeout(() => r({ ok: false, reason: "relay_submit_timeout" }), HASH_SUBMIT_TIMEOUT_MS);
    });
    try {
      const result = await Promise.race([ackPromise, timeout]);
      // On timeout, reset the stream so a late ack can't settle a LATER submit (FIFO desync).
      if (!result.ok && result.reason === "relay_submit_timeout") this.#resetStream();
      /**
       * ─── ADVANCE THE SELF CHAIN, AND ONLY ON SUCCESS — `DOD-M15-SELFCHAIN-1` ──────────────────
       *
       * Recorded AFTER the relay acknowledged, never before. Advancing first and then failing to
       * send would leave the chain pointing at a message that never existed, and every later message
       * would be refused by the counterparty with a reason that names tampering — an outage
       * reported as an attack.
       *
       * A retry therefore re-reads the same predecessor, which is exactly right: a retransmission is
       * the same message, not the next one.
       *
       * NOT for a carried leaf. Those bytes are the AUTHOR's and this agent did not write them, so
       * they are no part of this agent's own chain.
       */
      if (result.ok && !carried && this.#ownChainStore) {
        try {
          this.#ownChainStore.record(this.senderPubkeyHex, sessionIdHex, contentHash, Date.now());
        } catch (err: unknown) {
          this.#logger.error("session.selfchain.record.failed", {
            session: sessionIdHex,
            error: err instanceof Error ? err.message : String(err),
            impact:
              "this message was witnessed, but this agent could not record it as the link for its " +
              "next message — so the next one will chain to the wrong predecessor and the " +
              "counterparty will refuse it. Restart the session to re-anchor the chain.",
          });
        }
      }
      return result;
    } finally {
      clearTimeout(timer);
      if (this.#pendingAck === resolveAck) { this.#pendingAck = null; this.#pendingAckSessionHex = null; this.#pendingStructure1 = null; this.#pendingSignature = null; this.#pendingLeafKind = null; }
    }
  }

  /** The highest relay-assigned sequence observed for a given session (ack or deliver). */
  /**
   * Advance this session's acknowledgement from a message that ARRIVED — 033-ACKEMIT review F1.
   *
   * ⚠️ **`#bumpLastSeen` used to have exactly one caller, inside the `leaf_deliver` handler, so the
   * acknowledgement tracked what the RELAY DELIVERED rather than what was RECEIVED.** On a direct
   * session that is a real difference: the content arrives peer-to-peer and the relay's copy of the
   * leaf follows separately, so until it did, this daemon signed an acknowledgement one message
   * behind what it had actually read — and on a session where delivery never came back at all, the
   * acknowledgement never moved.
   *
   * The order's own words are "the content hash of the last message this sender ACTUALLY RECEIVED".
   * This is the caller that makes that true: the receive path calls it as soon as a message has been
   * verified and ingested at a known canonical position.
   *
   * **THE POSITION IS STILL REQUIRED, and that is a real limit rather than an oversight.** The pair
   * is (position, content-at-position), and the relay refuses a `last_seen_seq` that runs ahead of
   * its counter — so a message that arrived with NO ordering record cannot be acknowledged by
   * position at all, whatever we hold of it. That case is the withheld-submit attack itself, and it
   * is closed by carrying the sender's signed leaf into the seal, not from here.
   */
  noteReceivedLeaf(sessionIdHex: string, relaySeq: number, contentHash: Uint8Array): void {
    this.#bumpLastSeen(sessionIdHex, relaySeq, contentHash);
  }

  /**
   * The POSITION and the CONTENT AT IT together — 033-ACKEMIT.
   *
   * ⚠️ **IT REPLACED `lastSeenSeq()`, WHICH IS DELETED RATHER THAN LEFT WIRED.** That accessor
   * returned the position alone, and `session-node-manager`'s unwitnessed content claim was its
   * only caller. Leaving it in place after this one took over would leave a second way to read half
   * of a pair that must be read whole: a `last_seen_seq` paired with a `last_seen_hash` for a
   * different message is worse than no acknowledgement at all, because it looks checkable and
   * fails.
   *
   * `undefined` means this session has no acknowledgement to make, which the caller must handle
   * rather than fill in.
   */
  lastSeenAck(sessionIdHex: string): { seq: number; hash: Uint8Array } | undefined {
    return this.#lastSeen.get(sessionIdHex);
  }

  close(): void {
    this.#closed = true;
    this.#settlePending({ ok: false, reason: "relay_client_closed" });
    // Settle any in-flight record so #doRecord resolves promptly.
    { const r = this.#pendingRecord; this.#pendingRecord = null; if (r) r("closed"); }
    const stream = this.#stream;
    this.#stream = null;
    if (stream) {
      try { void stream.close(); } catch { /* best-effort */ }
    }
  }
}
