/**
 * 020-ACKHASH — Structure 1 v2 (`last_seen_hash`), READING HALF ONLY.
 *
 * The unit under test ships tolerance, not emission: `encodeStructure1` can build a v2 array when
 * asked, `decodeStructure1` accepts one, and no production caller passes `lastSeenHash`.
 *
 * The load-bearing tests here are the REFUSALS and the v1/7 regression. A tolerance test that only
 * exercises the happy path is vacuous — it stays green if the version branch is deleted and the
 * length check widened to `>= 6`, which is precisely the mutation that would break the deployed
 * relay's submission-id tolerance.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { encode as cborEncode } from "cbor-x";
import {
  encodeStructure1,
  decodeStructure1,
  STRUCTURE1_VERSION,
  STRUCTURE1_VERSION_V2,
  STRUCTURE1_VERSION_V3,
  LAST_SEEN_HASH_BYTES,
  PREV_OWN_HASH_BYTES,
  STRUCTURE1_DECODE_REASONS,
} from "../structure1.js";
import { computeGenesisPrevRoot } from "../session.js";

const __dirname = fileURLToPath(new URL(".", import.meta.url));

const fromHex = (h: string): Uint8Array => new Uint8Array(Buffer.from(h, "hex"));
const toHex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

const CONTENT_HASH = new Uint8Array(32).fill(0xcc);
const SENDER_PUBKEY = new Uint8Array(32).fill(0xdd);
const COUNTERPARTY_PUBKEY = new Uint8Array(32).fill(0xbb);
const SESSION_ID = new Uint8Array(16).fill(0xee);
const LAST_SEEN_HASH = new Uint8Array(32).fill(0xa7);
const PREV_OWN_HASH = new Uint8Array(32).fill(0xb4);
const TIMESTAMP = 1_700_000_000_000;

const V1_FIELDS = {
  contentHash: CONTENT_HASH,
  senderPubkey: SENDER_PUBKEY,
  sessionId: SESSION_ID,
  lastSeenSeq: 3,
  timestamp: TIMESTAMP,
};

/**
 * Build a Structure 1 array directly, bypassing the encoder, so a shape the encoder REFUSES to
 * build can still be handed to the decoder. Without this every refusal test would be limited to
 * shapes our own encoder can produce — which is the set that is already correct.
 */
function rawArray(...fields: unknown[]): Uint8Array {
  return new Uint8Array(cborEncode(fields));
}

// ─── encode: v1 is unchanged, v2 is opt-in ────────────────────────────────────

describe("020-ACKHASH: encodeStructure1 emits v1 unless asked for v2", () => {
  it("no lastSeenHash ⇒ six fields, version 1, byte-identical to the pinned v1 vector", () => {
    const fixture = JSON.parse(
      readFileSync(join(__dirname, "../../test/vectors/structure1-canonical.json"), "utf8"),
    ) as { inputs: Record<string, never>; expected_cbor_hex: string };

    const bytes = encodeStructure1({
      contentHash: fromHex("cc".repeat(32)),
      senderPubkey: fromHex("dd".repeat(32)),
      sessionId: fromHex("ee".repeat(16)),
      lastSeenSeq: 3,
      timestamp: 1_700_000_000_000,
    });
    expect(toHex(bytes)).toBe(fixture.expected_cbor_hex);
  });

  it("an explicit `undefined` lastSeenHash is the SAME as omitting it — no seven-field array with a hole", () => {
    // `absent` and `present-but-undefined` are the same call in JS and must be the same bytes. If
    // the encoder branched on `"lastSeenHash" in fields` instead of on the value, this would emit a
    // 7-array whose index 6 is CBOR `undefined` — a v2 claim with no hash in it, which is the
    // fail-open this layout exists to prevent.
    const omitted = encodeStructure1(V1_FIELDS);
    const explicit = encodeStructure1({ ...V1_FIELDS, lastSeenHash: undefined });
    expect(toHex(explicit)).toBe(toHex(omitted));
    expect(decodeStructure1(omitted)).toEqual(decodeStructure1(explicit));
  });

  it("with a lastSeenHash ⇒ seven fields, version 2, matching the pinned v2 vector", () => {
    const fixture = JSON.parse(
      readFileSync(join(__dirname, "../../test/vectors/structure1-v2-canonical.json"), "utf8"),
    ) as { inputs: { last_seen_hash_hex: string }; expected_cbor_hex: string };

    const bytes = encodeStructure1({
      contentHash: fromHex("cc".repeat(32)),
      senderPubkey: fromHex("dd".repeat(32)),
      sessionId: fromHex("ee".repeat(16)),
      lastSeenSeq: 3,
      timestamp: 1_700_000_000_000,
      lastSeenHash: fromHex(fixture.inputs.last_seen_hash_hex),
    });
    expect(toHex(bytes)).toBe(fixture.expected_cbor_hex);
  });

  it("v2 APPENDS — every field a v1 reader already reads keeps its index and its value", () => {
    // This is the whole reason the field went to index 6 rather than into the middle. Asserted on
    // the decoded values, not on a byte prefix: the version tag at index 0 differs by design, so a
    // prefix comparison would be asserting the wrong thing.
    const v1 = decodeStructure1(encodeStructure1(V1_FIELDS));
    const v2 = decodeStructure1(encodeStructure1({ ...V1_FIELDS, lastSeenHash: LAST_SEEN_HASH }));
    expect(v1.ok && v2.ok).toBe(true);
    if (!v1.ok || !v2.ok) return;
    expect(toHex(v2.fields.contentHash)).toBe(toHex(v1.fields.contentHash));
    expect(toHex(v2.fields.senderPubkey)).toBe(toHex(v1.fields.senderPubkey));
    expect(toHex(v2.fields.sessionId)).toBe(toHex(v1.fields.sessionId));
    expect(v2.fields.lastSeenSeq).toBe(v1.fields.lastSeenSeq);
    expect(Number(v2.fields.timestamp)).toBe(Number(v1.fields.timestamp));
    // ADD, never replace: last_seen_seq keeps doing ordering and dedup work alongside the hash.
    expect(v2.fields.lastSeenSeq).toBe(3);
  });

  it("refuses to build a v2 array around a lastSeenHash that is not 32 bytes", () => {
    // The encoder is the last place a malformed v2 can be stopped before it is signed. A wrong-width
    // hash reaching the wire would be refused by every peer, and the sender would see a valid
    // signature over bytes nobody accepts.
    expect(() => encodeStructure1({ ...V1_FIELDS, lastSeenHash: new Uint8Array(31) })).toThrow();
    expect(() => encodeStructure1({ ...V1_FIELDS, lastSeenHash: new Uint8Array(33) })).toThrow();
    expect(() => encodeStructure1({ ...V1_FIELDS, lastSeenHash: new Uint8Array(0) })).toThrow();
  });
});

// ─── last_seen_hash is a VALUE, never an absence ──────────────────────────────

describe("020-ACKHASH: the first message of a session has a defined last_seen_hash", () => {
  it("computeGenesisPrevRoot's output is a well-formed lastSeenHash and round-trips", () => {
    // "I have seen nothing" is the agreed starting point of this two-party chain, NOT a missing
    // field and NOT a shorter array. Pinned to computeGenesisPrevRoot so no second genesis constant
    // gets invented later, and so nobody reaches for 32 zero bytes — a value identical across every
    // session is one an attacker can present for any session.
    // Called with its REAL arguments — two participant pubkeys, not a content hash standing in for
    // one. A round-trip passes either way, which is exactly why the wrong call was easy to write.
    const genesis = computeGenesisPrevRoot(SENDER_PUBKEY, COUNTERPARTY_PUBKEY, SESSION_ID, TIMESTAMP);
    expect(genesis.length).toBe(LAST_SEEN_HASH_BYTES);

    const res = decodeStructure1(encodeStructure1({ ...V1_FIELDS, lastSeenHash: genesis }));
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.fields.lastSeenHash).not.toBeNull();
    expect(toHex(res.fields.lastSeenHash!)).toBe(toHex(genesis));
  });

  it("a genesis root differs per session, so it cannot be replayed into another one", () => {
    const a = computeGenesisPrevRoot(SENDER_PUBKEY, COUNTERPARTY_PUBKEY, SESSION_ID, TIMESTAMP);
    const b = computeGenesisPrevRoot(
      SENDER_PUBKEY,
      COUNTERPARTY_PUBKEY,
      new Uint8Array(16).fill(0x11),
      TIMESTAMP,
    );
    expect(toHex(a)).not.toBe(toHex(b));
  });
});

// ─── decode: the version decides, never the length ────────────────────────────

describe("020-ACKHASH: decodeStructure1 branches on the VERSION", () => {
  it("v1 six-array ⇒ accepted, lastSeenHash null", () => {
    const res = decodeStructure1(encodeStructure1(V1_FIELDS));
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.fields.version).toBe(STRUCTURE1_VERSION);
    expect(res.fields.lastSeenHash).toBeNull();
    expect(toHex(res.fields.contentHash)).toBe(toHex(CONTENT_HASH));
    expect(toHex(res.fields.senderPubkey)).toBe(toHex(SENDER_PUBKEY));
    expect(toHex(res.fields.sessionId)).toBe(toHex(SESSION_ID));
    expect(res.fields.lastSeenSeq).toBe(3);
    expect(Number(res.fields.timestamp)).toBe(TIMESTAMP);
  });

  it("THE REGRESSION: a v1 SEVEN-array (submission id) still decodes, lastSeenHash null", () => {
    // DOD-M15-SUBMIT-ID-1 widened the deployed relay to accept seven fields for a submission id at
    // index 6. `length === 7` alone therefore cannot mean "ack-hash": if this decoder refused a v1
    // seven-array, or read its submission id AS a last_seen_hash, it would break the shape already
    // tolerated on the deployed fleet.
    const submissionId = new Uint8Array(16).fill(0x5b);
    const res = decodeStructure1(
      rawArray(STRUCTURE1_VERSION, CONTENT_HASH, SENDER_PUBKEY, SESSION_ID, 3, TIMESTAMP, submissionId),
    );
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.fields.version).toBe(STRUCTURE1_VERSION);
    expect(res.fields.lastSeenHash).toBeNull();
    expect(res.fields.lastSeenSeq).toBe(3);
  });

  it("a v1 seven-array whose index 6 is a plausible 32-byte value is STILL not an ack-hash", () => {
    // The sharpest form of the collision: 32 bytes at index 6 under version 1. A length check, or a
    // width check on index 6, would read this as v2. Only the version tag separates them.
    const res = decodeStructure1(
      rawArray(STRUCTURE1_VERSION, CONTENT_HASH, SENDER_PUBKEY, SESSION_ID, 3, TIMESTAMP, LAST_SEEN_HASH),
    );
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.fields.lastSeenHash).toBeNull();
  });

  it("v2 seven-array ⇒ accepted, lastSeenHash carries the 32 bytes", () => {
    const res = decodeStructure1(encodeStructure1({ ...V1_FIELDS, lastSeenHash: LAST_SEEN_HASH }));
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.fields.version).toBe(STRUCTURE1_VERSION_V2);
    expect(toHex(res.fields.lastSeenHash!)).toBe(toHex(LAST_SEEN_HASH));
  });

  it("accepts a bigint timestamp (canonical uint64) and a plain number alike", () => {
    // Legacy leaves on the wire carry a CBOR float64 timestamp; the canonical encoder emits uint64,
    // which decodes to a bigint. Both are valid Structure 1 and neither is re-encoded on any
    // verification path — the signature is over the bytes as received.
    const asNumber = decodeStructure1(rawArray(1, CONTENT_HASH, SENDER_PUBKEY, SESSION_ID, 3, TIMESTAMP));
    const asBigint = decodeStructure1(rawArray(1, CONTENT_HASH, SENDER_PUBKEY, SESSION_ID, 3, BigInt(TIMESTAMP)));
    expect(asNumber.ok && asBigint.ok).toBe(true);
    if (!asNumber.ok || !asBigint.ok) return;
    expect(Number(asNumber.fields.timestamp)).toBe(TIMESTAMP);
    expect(Number(asBigint.fields.timestamp)).toBe(TIMESTAMP);
  });
});

// ─── refusals: an unnamed shape is refused BY NAME ────────────────────────────

describe("020-ACKHASH: decodeStructure1 refuses an unnamed shape by name", () => {
  it("version 2 with SIX fields ⇒ unknown layout, not 'v1 with a missing hash'", () => {
    // The fail-open this whole layout exists to prevent: a v2 claim that simply omits the field, and
    // a reader that shrugs and treats the absence as fine. Refused, and refused as an unknown
    // LAYOUT rather than degraded to v1.
    const res = decodeStructure1(rawArray(STRUCTURE1_VERSION_V2, CONTENT_HASH, SENDER_PUBKEY, SESSION_ID, 3, TIMESTAMP));
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.reason).toBe(STRUCTURE1_DECODE_REASONS.UNKNOWN_LAYOUT);
  });

  it("an unknown version ⇒ unknown layout, whatever the length", () => {
    for (const version of [0, 3, 255]) {
      for (const extra of [[], [LAST_SEEN_HASH]]) {
        const res = decodeStructure1(
          rawArray(version, CONTENT_HASH, SENDER_PUBKEY, SESSION_ID, 3, TIMESTAMP, ...extra),
        );
        expect(res.ok).toBe(false);
        if (res.ok) return;
        expect(res.reason).toBe(STRUCTURE1_DECODE_REASONS.UNKNOWN_LAYOUT);
      }
    }
  });

  it("an unknown LENGTH ⇒ unknown layout — a longer array is not 'v2 plus extras'", () => {
    // `>= 6` would admit this. An arbitrarily long array is a frame this build does not understand,
    // and accepting it means verifying a signature over bytes whose meaning is not agreed.
    for (const version of [STRUCTURE1_VERSION, STRUCTURE1_VERSION_V2]) {
      const res = decodeStructure1(
        rawArray(version, CONTENT_HASH, SENDER_PUBKEY, SESSION_ID, 3, TIMESTAMP, LAST_SEEN_HASH, 0x99),
      );
      expect(res.ok).toBe(false);
      if (res.ok) return;
      expect(res.reason).toBe(STRUCTURE1_DECODE_REASONS.UNKNOWN_LAYOUT);
    }
    const short = decodeStructure1(rawArray(STRUCTURE1_VERSION, CONTENT_HASH, SENDER_PUBKEY, SESSION_ID, 3));
    expect(short.ok).toBe(false);
    if (short.ok) return;
    expect(short.reason).toBe(STRUCTURE1_DECODE_REASONS.UNKNOWN_LAYOUT);
  });

  it("a v2 whose last_seen_hash is the wrong width or the wrong type ⇒ named refusal, never null", () => {
    // Present-but-malformed is REFUSED, not quietly dropped to null. Dropping it would turn a
    // corrupt acknowledgement into an unacknowledged one — a downgrade the sender chooses.
    const cases: unknown[] = [new Uint8Array(31), new Uint8Array(33), new Uint8Array(0), 7, "beef", null];
    for (const bad of cases) {
      const res = decodeStructure1(
        rawArray(STRUCTURE1_VERSION_V2, CONTENT_HASH, SENDER_PUBKEY, SESSION_ID, 3, TIMESTAMP, bad),
      );
      expect(res.ok).toBe(false);
      if (res.ok) return;
      expect(res.reason).toBe(STRUCTURE1_DECODE_REASONS.LAST_SEEN_HASH_MALFORMED);
    }
  });

  it("a session_id of a NON-WIRE width still decodes — the 16-byte rule lives at the wire edge", () => {
    // The relay and the directory each refuse a session_id that is not 16 bytes, and they keep
    // doing so. This decoder is also handed leaves the daemon just produced, and no client-side
    // reader ever checked this width — enforcing it here would newly reject sessions that work.
    // Consumers compare the value against an expected session id, so width is never load-bearing
    // on its own.
    const res = decodeStructure1(rawArray(1, CONTENT_HASH, SENDER_PUBKEY, new Uint8Array(32).fill(0x11), 3, TIMESTAMP));
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.fields.sessionId.length).toBe(32);
  });

  it("a malformed field at an unchanged index ⇒ field malformed", () => {
    const bad: Array<[string, unknown[]]> = [
      ["content_hash wrong width", [1, new Uint8Array(31), SENDER_PUBKEY, SESSION_ID, 3, TIMESTAMP]],
      ["sender_pubkey wrong width", [1, CONTENT_HASH, new Uint8Array(31), SESSION_ID, 3, TIMESTAMP]],
      ["session_id not bytes", [1, CONTENT_HASH, SENDER_PUBKEY, "not-bytes", 3, TIMESTAMP]],
      ["last_seen_seq not a number", [1, CONTENT_HASH, SENDER_PUBKEY, SESSION_ID, "3", TIMESTAMP]],
      ["timestamp not numeric", [1, CONTENT_HASH, SENDER_PUBKEY, SESSION_ID, 3, "now"]],
    ];
    for (const [label, fields] of bad) {
      const res = decodeStructure1(rawArray(...fields));
      expect(res.ok, label).toBe(false);
      if (res.ok) return;
      expect(res.reason, label).toBe(STRUCTURE1_DECODE_REASONS.FIELD_MALFORMED);
    }
  });

  it("not CBOR, and CBOR that is not an array, each get their own reason", () => {
    const notCbor = decodeStructure1(new Uint8Array([0xff, 0xff, 0xff, 0xff]));
    expect(notCbor.ok).toBe(false);
    if (notCbor.ok) return;
    expect(notCbor.reason).toBe(STRUCTURE1_DECODE_REASONS.NOT_CBOR);

    const notArray = decodeStructure1(new Uint8Array(cborEncode({ version: 1 })));
    expect(notArray.ok).toBe(false);
    if (notArray.ok) return;
    expect(notArray.reason).toBe(STRUCTURE1_DECODE_REASONS.NOT_ARRAY);
  });
});

// ─── 035-SELFCHAIN: v3 — the sender's link to their OWN previous message ──────

describe("035-SELFCHAIN: prev_own_hash is what makes a conversation a chain", () => {
  const V2_FIELDS = { ...V1_FIELDS, lastSeenHash: LAST_SEEN_HASH };
  const V3_FIELDS = { ...V2_FIELDS, prevOwnHash: PREV_OWN_HASH };

  it("with a prevOwnHash ⇒ eight fields, version 3, matching the pinned v3 vector", () => {
    const fixture = JSON.parse(
      readFileSync(join(__dirname, "../../test/vectors/structure1-v3-canonical.json"), "utf8"),
    ) as { inputs: { last_seen_hash_hex: string; prev_own_hash_hex: string }; expected_cbor_hex: string };

    const bytes = encodeStructure1({
      contentHash: fromHex("cc".repeat(32)),
      senderPubkey: fromHex("dd".repeat(32)),
      sessionId: fromHex("ee".repeat(16)),
      lastSeenSeq: 3,
      timestamp: 1_700_000_000_000,
      lastSeenHash: fromHex(fixture.inputs.last_seen_hash_hex),
      prevOwnHash: fromHex(fixture.inputs.prev_own_hash_hex),
    });
    expect(toHex(bytes)).toBe(fixture.expected_cbor_hex);
  });

  it("v3 APPENDS — the v2 bytes are a prefix once the version header is accounted for", () => {
    /**
     * The whole reason the field went to index 7. Asserted on the BYTES here rather than only on
     * decoded values, because "append" is a claim about the encoding: strip each array's 2-byte
     * header and v2's remainder must be a prefix of v3's.
     */
    const v2 = toHex(encodeStructure1(V2_FIELDS));
    const v3 = toHex(encodeStructure1(V3_FIELDS));
    expect(v2.startsWith("8702")).toBe(true);
    expect(v3.startsWith("8803")).toBe(true);
    expect(v3.slice(4).startsWith(v2.slice(4))).toBe(true);
    // …and the only thing after that prefix is the 32-byte hash, in a CBOR byte-string header.
    expect(v3.slice(4 + v2.slice(4).length)).toBe("5820" + "b4".repeat(32));
  });

  it("every field a v1 or v2 reader already reads keeps its index and its value", () => {
    const v1 = decodeStructure1(encodeStructure1(V1_FIELDS));
    const v2 = decodeStructure1(encodeStructure1(V2_FIELDS));
    const v3 = decodeStructure1(encodeStructure1(V3_FIELDS));
    expect(v1.ok && v2.ok && v3.ok).toBe(true);
    if (!v1.ok || !v2.ok || !v3.ok) return;
    expect(toHex(v3.fields.contentHash)).toBe(toHex(v1.fields.contentHash));
    expect(toHex(v3.fields.senderPubkey)).toBe(toHex(v1.fields.senderPubkey));
    expect(toHex(v3.fields.sessionId)).toBe(toHex(v1.fields.sessionId));
    expect(v3.fields.lastSeenSeq).toBe(v1.fields.lastSeenSeq);
    expect(v3.fields.timestamp).toBe(v1.fields.timestamp);
    expect(toHex(v3.fields.lastSeenHash!)).toBe(toHex(v2.fields.lastSeenHash!));
  });

  it("an explicit `undefined` prevOwnHash is the SAME as omitting it — no eight-field array with a hole", () => {
    // Same trap the v2 test pins: branching on `"prevOwnHash" in fields` would emit an 8-array whose
    // index 7 is CBOR `undefined` — a v3 claim carrying no self link, which is the fail-open this
    // layout exists to close.
    const omitted = encodeStructure1(V2_FIELDS);
    const explicit = encodeStructure1({ ...V2_FIELDS, prevOwnHash: undefined });
    expect(toHex(explicit)).toBe(toHex(omitted));
    expect(decodeStructure1(omitted)).toEqual(decodeStructure1(explicit));
  });

  it("prevOwnHash without lastSeenHash still emits v2 — the self link never travels alone", () => {
    /**
     * ⚠️ NAMED BECAUSE IT LOOKS LIKE A BUG AND IS NOT. There is no layout carrying a self link and
     * no acknowledgement: v3 is defined as v2 plus one field. A caller in that state has nothing to
     * acknowledge, which means it is the first message of the session — and its self link would be
     * the session genesis, which asserts nothing either. The honest encoding is the one that makes
     * no claim it cannot support.
     */
    const bytes = encodeStructure1({ ...V1_FIELDS, prevOwnHash: PREV_OWN_HASH });
    expect(toHex(bytes)).toBe(toHex(encodeStructure1(V1_FIELDS)));
  });

  it("a WRONG-WIDTH prevOwnHash throws at encode — never silently downgraded to v2", () => {
    /**
     * A silent downgrade is the worse failure and it is why this throws. An unacceptable ack hash
     * shows up immediately — the counterparty refuses the message. A missing SELF link is invisible
     * in any single message: everything verifies, and the only symptom appears later, as a
     * conversation whose order cannot be proven. Catch it before the bytes are signed.
     */
    expect(() => encodeStructure1({ ...V2_FIELDS, prevOwnHash: new Uint8Array(31) }))
      .toThrow(/prev_own_hash must be 32 bytes/);
    expect(() => encodeStructure1({ ...V2_FIELDS, prevOwnHash: new Uint8Array(0) }))
      .toThrow(/prev_own_hash must be 32 bytes/);
  });

  it("the session GENESIS is a legal prevOwnHash — a first message is a value, not an absence", () => {
    const genesis = computeGenesisPrevRoot(SENDER_PUBKEY, COUNTERPARTY_PUBKEY, SESSION_ID, TIMESTAMP);
    expect(genesis.length).toBe(PREV_OWN_HASH_BYTES);
    const decoded = decodeStructure1(encodeStructure1({ ...V2_FIELDS, prevOwnHash: genesis }));
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect(toHex(decoded.fields.prevOwnHash!)).toBe(toHex(genesis));
    // And it is SESSION-SPECIFIC, which is the reason it is not 32 zero bytes: a constant shared by
    // every session is one an attacker can present for any of them.
    const other = computeGenesisPrevRoot(SENDER_PUBKEY, COUNTERPARTY_PUBKEY, new Uint8Array(16).fill(0x11), TIMESTAMP);
    expect(toHex(other)).not.toBe(toHex(genesis));
  });

  // ─── refusals: the load-bearing half ───

  it("a v3 that OMITS prev_own_hash is refused — seven fields cannot claim to be a v3", () => {
    const raw = rawArray(STRUCTURE1_VERSION_V3, CONTENT_HASH, SENDER_PUBKEY, SESSION_ID, 3, TIMESTAMP, LAST_SEEN_HASH);
    const r = decodeStructure1(raw);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toBe(STRUCTURE1_DECODE_REASONS.UNKNOWN_LAYOUT);
  });

  it("a v3 whose prev_own_hash is the wrong width is refused BY NAME, never dropped to null", () => {
    for (const bad of [new Uint8Array(31), new Uint8Array(33), new Uint8Array(0)]) {
      const raw = rawArray(STRUCTURE1_VERSION_V3, CONTENT_HASH, SENDER_PUBKEY, SESSION_ID, 3, TIMESTAMP, LAST_SEEN_HASH, bad);
      const r = decodeStructure1(raw);
      expect(r.ok).toBe(false);
      if (r.ok) continue;
      expect(r.reason).toBe(STRUCTURE1_DECODE_REASONS.PREV_OWN_HASH_MALFORMED);
    }
  });

  it("a v3 whose prev_own_hash is not bytes at all is refused BY NAME", () => {
    const raw = rawArray(STRUCTURE1_VERSION_V3, CONTENT_HASH, SENDER_PUBKEY, SESSION_ID, 3, TIMESTAMP, LAST_SEEN_HASH, 7);
    const r = decodeStructure1(raw);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toBe(STRUCTURE1_DECODE_REASONS.PREV_OWN_HASH_MALFORMED);
  });

  it("an EIGHT-field array that is not version 3 is refused — the version decides, never the length", () => {
    for (const v of [STRUCTURE1_VERSION, STRUCTURE1_VERSION_V2, 4]) {
      const raw = rawArray(v, CONTENT_HASH, SENDER_PUBKEY, SESSION_ID, 3, TIMESTAMP, LAST_SEEN_HASH, PREV_OWN_HASH);
      const r = decodeStructure1(raw);
      expect(r.ok).toBe(false);
      if (r.ok) continue;
      expect(r.reason).toBe(STRUCTURE1_DECODE_REASONS.UNKNOWN_LAYOUT);
    }
  });

  it("a v3 whose LAST_SEEN_HASH is malformed is refused for THAT reason, not the self link's", () => {
    // Two 32-byte fields sit side by side, and a reader that checked them in one place would name
    // the wrong one. Each names itself.
    const raw = rawArray(STRUCTURE1_VERSION_V3, CONTENT_HASH, SENDER_PUBKEY, SESSION_ID, 3, TIMESTAMP, new Uint8Array(31), PREV_OWN_HASH);
    const r = decodeStructure1(raw);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toBe(STRUCTURE1_DECODE_REASONS.LAST_SEEN_HASH_MALFORMED);
  });

  it("v1 and v2 still decode with prevOwnHash null — null means the layout has none, never a missing one", () => {
    const v1 = decodeStructure1(encodeStructure1(V1_FIELDS));
    const v2 = decodeStructure1(encodeStructure1(V2_FIELDS));
    expect(v1.ok && v2.ok).toBe(true);
    if (!v1.ok || !v2.ok) return;
    expect(v1.fields.prevOwnHash).toBeNull();
    expect(v2.fields.prevOwnHash).toBeNull();
  });

  it("a v1 SEVEN-array is still the submission-id layout — the new field did not widen it", () => {
    // The regression 020-ACKHASH pinned, re-pinned one layout later: the relay's submission-id
    // tolerance must survive every future append.
    const raw = rawArray(STRUCTURE1_VERSION, CONTENT_HASH, SENDER_PUBKEY, SESSION_ID, 3, TIMESTAMP, new Uint8Array(16).fill(0x5b));
    const r = decodeStructure1(raw);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.fields.lastSeenHash).toBeNull();
    expect(r.fields.prevOwnHash).toBeNull();
  });
});
