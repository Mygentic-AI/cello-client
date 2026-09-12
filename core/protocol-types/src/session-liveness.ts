/**
 * CELLO-M7-SESSION-003 — session-path liveness wire types + codec
 *
 * The relay is the session-path liveness authority for relay-mode sessions. The
 * client queries it over the relay protocol stream with a session_liveness_query
 * frame and receives a session_liveness_response.
 *
 * WIRE CONVENTION (cross-ref SESSION-001 L-1): on-wire keys are snake_case,
 * matching every other relay frame. session_id is the 16-byte binary session id
 * and counterparty_pubkey is the 32-byte Ed25519 pubkey — identical to the keys
 * the relay uses for its delivery queue. The relay (trustless-cello) re-encodes
 * the SAME shape independently in relay-frames.ts (it cannot import this
 * unpublished package); the two MUST agree byte-for-byte. These tests pin the
 * shape.
 *
 * liveness is exactly 'alive' | 'gone' | 'unknown':
 *   - 'alive'   : the relay currently holds the recipient's standing connection
 *   - 'gone'    : the relay positively observed the recipient's disconnect with
 *                 no subsequent reconnect
 *   - 'unknown' : the relay has no tracked entry for the recipient. The relay
 *                 NEVER fabricates 'gone' from a missing entry (no observation is
 *                 'unknown', not 'gone').
 */

import { decode as cborDecode } from "cbor-x";
import { encodeCbor } from "./cbor.js";


export type SessionLiveness = "alive" | "gone" | "unknown";

/**
 * DOD-M15-AWAYSCOPE-1 — what the far daemon says about ITSELF, as distinct from what the relay
 * observed about its connection.
 *
 *   - 'attended'   : online, and a live client has claimed the agent — a person is watching.
 *   - 'unattended' : online, nobody watching. The message is queued and WILL be read on return.
 *   - 'offline'    : deliberately not accepting. Not a fault, and not a wait.
 *
 * THREE VALUES, NOT TWO, and the middle one is the whole point. Collapsing 'unattended' into
 * 'offline' tells the counterparty to give up on a conversation that is merely waiting; collapsing
 * it into 'attended' tells them a person is reading when nobody is. The failure this order exists
 * to fix came from a daemon ANSWERING in place of its absent operator, and the fix is only complete
 * if the counterparty can learn the same fact without a message being sent.
 */
export type SessionAttendance = "attended" | "unattended" | "offline";

export interface SessionLivenessQuery {
  type: "session_liveness_query";
  /** 16-byte binary session id */
  session_id: Uint8Array;
  /** 32-byte Ed25519 pubkey of the counterparty whose liveness is queried */
  counterparty_pubkey: Uint8Array;
}

export interface SessionLivenessResponse {
  type: "session_liveness_response";
  session_id: Uint8Array;
  counterparty_pubkey: Uint8Array;
  liveness: SessionLiveness;
  /** Unix ms timestamp of the relay's most recent observation for this recipient */
  observed_at: number;
  /**
   * The counterparty daemon's own assertion about itself, relayed verbatim.
   *
   * ABSENT unless `liveness` is 'alive', and that is a rule about reality rather than a convention:
   * a daemon the relay cannot reach cannot be asserting anything, so a frame pairing an attendance
   * with 'gone' or 'unknown' is self-contradictory and the decoder refuses it whole. See the decoder
   * for why refusing beats trimming.
   */
  attendance?: SessionAttendance;
  /**
   * When the far daemon made that assertion.
   *
   * ⚠️ NOT `observed_at`, AND THE TWO ARE ROUTINELY HOURS APART. `observed_at` is when the relay
   * last saw that agent's CONNECTION change; this is when the agent last said something about
   * itself. The relay sees you connect at 09:00 and you step away at 11:30 — labelling the
   * attendance "as of 09:00" reports a state as of a time before it was true, and it never moves
   * when you step away again, so a counterparty watching the number sees a frozen clock.
   *
   * Rides with `attendance` and is absent whenever it is, for the same reason: a daemon that is not
   * asserting anything has no assertion to have timestamped.
   */
  attendance_observed_at?: number;
}

/**
 * DOD-M15-AWAYSCOPE-1 — how the relay learns attendance, since it cannot observe it.
 *
 * The relay knows whether it holds a connection. It cannot know whether a human is watching the
 * daemon at the other end of it. So the daemon asserts that itself, out of band, and the relay
 * repeats the assertion to the counterparty on the liveness response.
 *
 * ⚠️ THIS FRAME NAMES NO SPEAKER, DELIBERATELY. The sender is the authenticated relay connection,
 * never a key inside the frame — the relay matches that authenticated key against the participants
 * of the directory-signed assignment it already holds for the named session. `leaf-witness.ts`
 * states the reason in full: a claim is proof only when checked against something the claimant does
 * not supply. A `pubkey` field here would be a field the attacker fills in.
 *
 * ⚠️ AND IT CARRIES NO SEQUENCE NUMBER. `observed_at` orders it, last-write-wins, and the price is
 * that a notice may arrive twice, late, or out of order. That price is correct. A sequence number
 * would make this ordered traffic, ordered traffic wants a witness, and a witnessed position is how
 * machine chatter got into the leaf set and destroyed a receipt in the first place.
 */
export interface SessionAttendanceNotice {
  type: "session_attendance_notice";
  /** 16-byte binary session id this assertion is scoped to. */
  session_id: Uint8Array;
  attendance: SessionAttendance;
  /** Unix ms at which the asserting daemon observed its own state. Bounded by the relay, not here. */
  observed_at: number;
}

function toUint8Array(v: unknown): Uint8Array | null {
  if (v instanceof Uint8Array) return v;
  if (Buffer.isBuffer(v)) return new Uint8Array(v);
  return null;
}

function isLiveness(v: unknown): v is SessionLiveness {
  return v === "alive" || v === "gone" || v === "unknown";
}

function isAttendance(v: unknown): v is SessionAttendance {
  return v === "attended" || v === "unattended" || v === "offline";
}

export function encodeSessionLivenessQuery(frame: SessionLivenessQuery): Uint8Array {
  return encodeCbor({
    type: "session_liveness_query",
    session_id: frame.session_id,
    counterparty_pubkey: frame.counterparty_pubkey,
  }) as Uint8Array;
}

export function decodeSessionLivenessQuery(bytes: Uint8Array): SessionLivenessQuery | null {
  let obj: unknown;
  try {
    obj = cborDecode(bytes);
  } catch {
    return null;
  }
  if (typeof obj !== "object" || obj === null) return null;
  const o = obj as Record<string, unknown>;
  if (o["type"] !== "session_liveness_query") return null;
  const session_id = toUint8Array(o["session_id"]);
  const counterparty_pubkey = toUint8Array(o["counterparty_pubkey"]);
  if (!session_id || session_id.length !== 16) return null;
  if (!counterparty_pubkey || counterparty_pubkey.length !== 32) return null;
  return { type: "session_liveness_query", session_id, counterparty_pubkey };
}

export function encodeSessionLivenessResponse(frame: SessionLivenessResponse): Uint8Array {
  return encodeCbor({
    type: "session_liveness_response",
    session_id: frame.session_id,
    counterparty_pubkey: frame.counterparty_pubkey,
    liveness: frame.liveness,
    observed_at: frame.observed_at,
    // The KEY is omitted when there is nothing to say, never written as an explicit undefined: an
    // older relay omits it entirely, and a build that can be told apart from an older one by the
    // shape of its silence is a build whose silence means two different things.
    ...(frame.attendance !== undefined ? { attendance: frame.attendance } : {}),
    ...(frame.attendance_observed_at !== undefined ? { attendance_observed_at: frame.attendance_observed_at } : {}),
  }) as Uint8Array;
}

export function decodeSessionLivenessResponse(bytes: Uint8Array): SessionLivenessResponse | null {
  let obj: unknown;
  try {
    obj = cborDecode(bytes);
  } catch {
    return null;
  }
  if (typeof obj !== "object" || obj === null) return null;
  const o = obj as Record<string, unknown>;
  if (o["type"] !== "session_liveness_response") return null;
  const session_id = toUint8Array(o["session_id"]);
  const counterparty_pubkey = toUint8Array(o["counterparty_pubkey"]);
  const liveness = o["liveness"];
  const observed_at = o["observed_at"];
  if (!session_id || session_id.length !== 16) return null;
  if (!counterparty_pubkey || counterparty_pubkey.length !== 32) return null;
  if (!isLiveness(liveness)) return null;
  if (typeof observed_at !== "number") return null;
  /**
   * DOD-M15-AWAYSCOPE-1 — MALFORMED FAILS EXACTLY LIKE MISSING. No tolerance branch.
   *
   * Two shapes are refused, and the second is the one that matters. An unrecognised VALUE is
   * refused because a value this build cannot interpret is not evidence, and passing the raw string
   * through would put unvalidated peer input on an operator's status line. An attendance paired
   * with a liveness other than 'alive' is refused because it is self-contradictory — the relay
   * never builds that frame, so seeing one means someone else did.
   *
   * Refusing the FRAME rather than dropping the field is the deliberate half. Trimming would leave
   * a caller holding a liveness answer that looks ordinary, while the thing that made it suspicious
   * has been quietly discarded — and it is exactly the shape a modified peer would send to pin a
   * stale attendance onto a counterparty's view.
   */
  const attendance = o["attendance"];
  const attendance_observed_at = o["attendance_observed_at"];
  if (attendance !== undefined) {
    if (!isAttendance(attendance)) return null;
    if (liveness !== "alive") return null;
    // The timestamp is REQUIRED alongside an attendance and refused without it. An attendance with
    // no age is not actionable — "nobody is watching" is a different instruction at thirty seconds
    // old and at two days — and accepting a bare one would make a build that cannot supply the age
    // indistinguishable from one whose clock failed to.
    if (typeof attendance_observed_at !== "number") return null;
    return { type: "session_liveness_response", session_id, counterparty_pubkey, liveness, observed_at, attendance, attendance_observed_at };
  }
  // And the reverse: a timestamp with nothing to date is a field that can only mislead.
  if (attendance_observed_at !== undefined) return null;
  return { type: "session_liveness_response", session_id, counterparty_pubkey, liveness, observed_at };
}

export function encodeSessionAttendanceNotice(frame: SessionAttendanceNotice): Uint8Array {
  return encodeCbor({
    type: "session_attendance_notice",
    session_id: frame.session_id,
    attendance: frame.attendance,
    observed_at: frame.observed_at,
  }) as Uint8Array;
}

export function decodeSessionAttendanceNotice(bytes: Uint8Array): SessionAttendanceNotice | null {
  let obj: unknown;
  try {
    obj = cborDecode(bytes);
  } catch {
    return null;
  }
  if (typeof obj !== "object" || obj === null) return null;
  const o = obj as Record<string, unknown>;
  if (o["type"] !== "session_attendance_notice") return null;
  const session_id = toUint8Array(o["session_id"]);
  const attendance = o["attendance"];
  const observed_at = o["observed_at"];
  if (!session_id || session_id.length !== 16) return null;
  if (!isAttendance(attendance)) return null;
  if (typeof observed_at !== "number") return null;
  // `observed_at` is NOT bounded here. A codec that clamped or rejected on clock skew would be
  // making a trust decision with no clock of its own to compare against on the encode side; the
  // relay is the party with the authority and the reference clock, and it refuses out-of-range
  // values rather than clamping them. See `#processSessionAttendanceNotice`.
  return { type: "session_attendance_notice", session_id, attendance, observed_at };
}
