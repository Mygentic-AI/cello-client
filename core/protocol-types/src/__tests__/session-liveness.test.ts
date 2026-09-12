/**
 * CELLO-M7-SESSION-003 — session-liveness wire codec tests
 *
 * AC understanding:
 *   - AC-002: the relay liveness frame carries session_id, counterparty_pubkey,
 *     liveness ('alive'|'gone'|'unknown'), observed_at. The client encodes the
 *     query and decodes the response; the relay (trustless-cello) re-implements
 *     the same wire shape in relay-frames.ts. The two MUST agree byte-for-byte,
 *     so the codec here pins the canonical wire shape: snake_case keys, binary
 *     session_id (16 bytes) and counterparty_pubkey (32 bytes), CBOR-encoded.
 *   - The codec is the producer (query) / consumer (response) on the client side.
 *
 * No external state — pure CBOR round-trip; no CELLO_E2E_LIVE guard needed.
 */
import { describe, it, expect } from "vitest";
import {
  encodeSessionLivenessQuery,
  decodeSessionLivenessQuery,
  encodeSessionLivenessResponse,
  decodeSessionLivenessResponse,
  encodeSessionAttendanceNotice,
  decodeSessionAttendanceNotice,
} from "../session-liveness.js";
import { encodeCbor } from "../cbor.js";

/** Hand-build a frame the encoders would never produce, to test what the DECODER refuses. */
function encodeCborForTest(o: Record<string, unknown>): Uint8Array {
  return encodeCbor(o) as Uint8Array;
}

const SID = new Uint8Array(16).fill(7);
const PUB = new Uint8Array(32).fill(9);

describe("session_liveness_query codec", () => {
  it("round-trips a query frame", () => {
    const bytes = encodeSessionLivenessQuery({
      type: "session_liveness_query",
      session_id: SID,
      counterparty_pubkey: PUB,
    });
    const decoded = decodeSessionLivenessQuery(bytes);
    expect(decoded).not.toBeNull();
    expect(decoded!.type).toBe("session_liveness_query");
    expect(Buffer.from(decoded!.session_id)).toEqual(Buffer.from(SID));
    expect(Buffer.from(decoded!.counterparty_pubkey)).toEqual(Buffer.from(PUB));
  });

  it("rejects a wrong-length session_id", () => {
    const bytes = encodeSessionLivenessQuery({
      type: "session_liveness_query",
      session_id: new Uint8Array(8),
      counterparty_pubkey: PUB,
    });
    expect(decodeSessionLivenessQuery(bytes)).toBeNull();
  });

  it("returns null on a frame of the wrong type", () => {
    const bytes = encodeSessionLivenessResponse({
      type: "session_liveness_response",
      session_id: SID,
      counterparty_pubkey: PUB,
      liveness: "alive",
      observed_at: 1,
    });
    expect(decodeSessionLivenessQuery(bytes)).toBeNull();
  });
});

describe("session_liveness_response codec", () => {
  for (const liveness of ["alive", "gone", "unknown"] as const) {
    it(`round-trips a response with liveness '${liveness}'`, () => {
      const bytes = encodeSessionLivenessResponse({
        type: "session_liveness_response",
        session_id: SID,
        counterparty_pubkey: PUB,
        liveness,
        observed_at: 1234,
      });
      const decoded = decodeSessionLivenessResponse(bytes);
      expect(decoded).not.toBeNull();
      expect(decoded!.liveness).toBe(liveness);
      expect(decoded!.observed_at).toBe(1234);
      expect(Buffer.from(decoded!.session_id)).toEqual(Buffer.from(SID));
      expect(Buffer.from(decoded!.counterparty_pubkey)).toEqual(Buffer.from(PUB));
    });
  }

  it("rejects an out-of-range liveness value (never fabricates)", () => {
    // Hand-craft a frame with an illegal liveness string.
    const bytes = encodeSessionLivenessResponse({
      type: "session_liveness_response",
      session_id: SID,
      counterparty_pubkey: PUB,
      // @ts-expect-error deliberately illegal value to prove the decoder validates
      liveness: "busy",
      observed_at: 1,
    });
    expect(decodeSessionLivenessResponse(bytes)).toBeNull();
  });
});

/**
 * DOD-M15-AWAYSCOPE-1 unit 2 — ATTENDANCE, which is a different fact from liveness.
 *
 * Two connections define how disconnected a party is, and only one of them was ever on this frame:
 *   - `liveness` is the RELAY's observation. A daemon that is gone cannot speak, so this is
 *     necessarily inferred by a third party. Unchanged.
 *   - `attendance` is the DAEMON's own assertion about itself, relayed back verbatim. Three values,
 *     not two: `unattended` means online with nobody watching and the message WILL be read later;
 *     `offline` means deliberately not accepting. Collapsing those tells the counterparty the
 *     opposite of the truth about whether to wait.
 *
 * It is absent when `liveness` is not `alive`, because a daemon that cannot be reached cannot be
 * asserting anything — and a frame that claims otherwise is refused whole rather than trimmed.
 * `trustless-cello`'s `relay-frames.ts` re-encodes this shape independently and the two must agree
 * byte-for-byte; `dod-m15-awayscope-1-wire.test.ts` there pins the same vectors from the other side.
 */
describe("DOD-M15-AWAYSCOPE-1: attendance on the liveness response", () => {
  const base = { type: "session_liveness_response" as const, session_id: SID, counterparty_pubkey: PUB, observed_at: 1_700_000_000_000 };

  it("★★ round-trips all three attendance values under liveness 'alive', each with its own age", () => {
    for (const attendance of ["attended", "unattended", "offline"] as const) {
      const decoded = decodeSessionLivenessResponse(
        encodeSessionLivenessResponse({ ...base, liveness: "alive", attendance, attendance_observed_at: 1_700_000_009_999 }),
      );
      expect(decoded, `attendance ${attendance} did not survive the round trip`).not.toBeNull();
      expect(decoded!.attendance).toBe(attendance);
      // NOT `observed_at`. That one is when the RELAY last saw the connection change; this is when
      // the agent last said something about itself, and they are routinely hours apart.
      expect(decoded!.attendance_observed_at).toBe(1_700_000_009_999);
      expect(decoded!.observed_at).toBe(base.observed_at);
    }
  });

  it("★★ an attendance with NO age is refused, and an age with no attendance is too", () => {
    /**
     * Both directions, because each is a different lie. An attendance with no age is not actionable
     * — "nobody is watching" is a different instruction at thirty seconds old and at two days — and
     * accepting a bare one makes a build that cannot supply the age indistinguishable from one
     * whose clock failed to. An age with nothing to date can only mislead the reader about which
     * fact it belongs to, and this frame already carries a second timestamp it could be read as.
     */
    expect(decodeSessionLivenessResponse(
      encodeCborForTest({ ...base, liveness: "alive", attendance: "unattended" }),
    ), "an attendance with no age").toBeNull();
    expect(decodeSessionLivenessResponse(
      encodeCborForTest({ ...base, liveness: "alive", attendance_observed_at: 1 }),
    ), "an age with no attendance").toBeNull();
  });

  it("★★ an OMITTED attendance decodes as absent, not as a default", () => {
    // An older relay sends no attendance at all. `undefined` is the only honest reading — defaulting
    // it to `attended` would report a person present, and to `unattended` would report an absence
    // nobody observed. The KEY must be gone from the encoding too, not present-and-undefined.
    const bytes = encodeSessionLivenessResponse({ ...base, liveness: "alive" });
    const decoded = decodeSessionLivenessResponse(bytes);
    expect(decoded).not.toBeNull();
    expect(decoded!.attendance).toBeUndefined();
    expect("attendance" in (decoded as object)).toBe(false);
  });

  it("★★ attendance alongside a non-alive liveness is REFUSED, not trimmed", () => {
    // A daemon the relay cannot reach cannot be asserting anything about itself, so the two fields
    // contradict each other. Dropping the bad field and keeping the frame is the tolerance branch
    // the order forbids: it would let a modified peer pin a stale attendance by pairing it with a
    // liveness the relay would never have sent.
    for (const liveness of ["gone", "unknown"] as const) {
      const bytes = encodeSessionLivenessResponse({ ...base, liveness, attendance: "attended", attendance_observed_at: 1 });
      expect(decodeSessionLivenessResponse(bytes), `${liveness} + attendance must not decode`).toBeNull();
    }
  });

  it("★★ an unrecognised attendance value fails exactly like a malformed frame", () => {
    // No best-effort accept: an attendance this build does not understand is not evidence of
    // anything, and passing it through as a string would put an unvalidated value on a status line.
    const bytes = encodeCborForTest({ ...base, liveness: "alive", attendance: "busy", attendance_observed_at: 1 });
    expect(decodeSessionLivenessResponse(bytes)).toBeNull();
  });

  it("★ the query frame is untouched — attendance is answered, never asked for", () => {
    // The asker names a session and a counterparty and nothing else. A query that could request
    // attendance separately would be a second enumeration surface on a frame that already had one.
    const bytes = encodeSessionLivenessQuery({ type: "session_liveness_query", session_id: SID, counterparty_pubkey: PUB });
    const decoded = decodeSessionLivenessQuery(bytes);
    expect(Object.keys(decoded as object).sort()).toEqual(["counterparty_pubkey", "session_id", "type"]);
  });
});

/**
 * DOD-M15-AWAYSCOPE-1 unit 2 — the NOTICE, which is how the relay learns attendance at all.
 *
 * The relay cannot observe whether a human is watching a daemon; only the daemon knows. So the
 * daemon asserts it, and the relay relays that assertion. This is the frame that carries it.
 *
 * ⚠️ IT NAMES NO SPEAKER. The sender's identity is the authenticated relay connection, never a
 * pubkey inside the frame — `leaf-witness.ts` states the reason this codebase keeps re-learning: a
 * claim is proof only when checked against something the claimant does not supply. The relay matches
 * the authenticated key against the participants of the directory-signed assignment it already
 * recorded for this session. A `pubkey` field here would be a field an attacker fills in.
 *
 * `observed_at` is what makes last-write-wins safe off the chain. It gets NO sequence number: a
 * sequence would make this ordered traffic, and ordered traffic is what ends up in the leaf set.
 */
describe("DOD-M15-AWAYSCOPE-1: the attendance notice frame", () => {
  it("★★ round-trips, and carries no identity of its own", () => {
    const bytes = encodeSessionAttendanceNotice({
      type: "session_attendance_notice", session_id: SID, attendance: "unattended", observed_at: 1_700_000_000_000,
    });
    const decoded = decodeSessionAttendanceNotice(bytes);
    expect(decoded).not.toBeNull();
    expect(decoded!.attendance).toBe("unattended");
    expect(decoded!.observed_at).toBe(1_700_000_000_000);
    // The whole frame, key by key. A `pubkey` or `sequence_number` appearing here later is the
    // regression this asserts against, and neither would fail any other assertion in this file.
    expect(Object.keys(decoded as object).sort()).toEqual(["attendance", "observed_at", "session_id", "type"]);
  });

  it("★★ every malformed shape fails the same way — null, with no partial frame", () => {
    const good = { type: "session_attendance_notice", session_id: SID, attendance: "attended", observed_at: 1 };
    const bad: Array<[string, Record<string, unknown>]> = [
      ["a short session id", { ...good, session_id: new Uint8Array(15) }],
      ["a long session id", { ...good, session_id: new Uint8Array(17) }],
      ["a missing session id", { type: good.type, attendance: good.attendance, observed_at: good.observed_at }],
      ["an unknown attendance value", { ...good, attendance: "busy" }],
      ["a missing attendance", { type: good.type, session_id: SID, observed_at: 1 }],
      ["a non-numeric observed_at", { ...good, observed_at: "now" }],
      ["a missing observed_at", { type: good.type, session_id: SID, attendance: "attended" }],
      ["the wrong type", { ...good, type: "session_liveness_query" }],
    ];
    for (const [why, frame] of bad) {
      expect(decodeSessionAttendanceNotice(encodeCborForTest(frame)), why).toBeNull();
    }
    expect(decodeSessionAttendanceNotice(new Uint8Array([0xff, 0xff])), "non-CBOR bytes").toBeNull();
  });
});
