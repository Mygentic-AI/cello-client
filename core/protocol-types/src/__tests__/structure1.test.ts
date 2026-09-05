/**
 * `DOD-M15-SELFCHAIN-1` — Structure 1 is ONE layout with BOTH chain links, and every other shape is
 * refused.
 *
 * ─── What these tests are actually protecting ──────────────────────────────────────────────────
 *
 * A conversation is a cryptographic chain. Two links make it one, and both are inside the signed
 * bytes: `last_seen_hash` (the last message I received from you) and `prev_own_hash` (my own
 * previous message). Only the first used to exist, and that is not a chain — when one party sends
 * twice in a row, both of their messages acknowledge the same message from the other side, so their
 * acknowledgements are identical and nothing says which came first.
 *
 * The relay-assigned position cannot stand in for it: the relay assigns position AFTER the sender
 * signs, so a sender can never sign their own position.
 *
 * ─── The load-bearing half is the REFUSALS ─────────────────────────────────────────────────────
 *
 * A happy-path test for a required field is nearly vacuous — it stays green if the requirement is
 * deleted and the field made optional again. What cannot stay green is a refusal test, so most of
 * this file is shapes that must NOT decode.
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
  STRUCTURE1_FIELD_COUNT,
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

const FIELDS = {
  contentHash: CONTENT_HASH,
  senderPubkey: SENDER_PUBKEY,
  sessionId: SESSION_ID,
  lastSeenSeq: 3,
  timestamp: TIMESTAMP,
  lastSeenHash: LAST_SEEN_HASH,
  prevOwnHash: PREV_OWN_HASH,
};

/**
 * Build a Structure 1 array directly, bypassing the encoder, so a shape the encoder REFUSES to
 * build can still be handed to the decoder. Without this every refusal test would be limited to
 * shapes our own encoder can produce — which is the set that is already correct.
 */
function rawArray(...fields: unknown[]): Uint8Array {
  return new Uint8Array(cborEncode(fields));
}

// ─── the one layout ──────────────────────────────────────────────────────────

describe("Structure 1 is one layout, and it is pinned", () => {
  it("matches the canonical vector byte for byte", () => {
    const fixture = JSON.parse(
      readFileSync(join(__dirname, "../../test/vectors/structure1-canonical.json"), "utf8"),
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

  it("round-trips every field", () => {
    const r = decodeStructure1(encodeStructure1(FIELDS));
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.fields.version).toBe(STRUCTURE1_VERSION);
    expect(toHex(r.fields.contentHash)).toBe(toHex(CONTENT_HASH));
    expect(toHex(r.fields.senderPubkey)).toBe(toHex(SENDER_PUBKEY));
    expect(toHex(r.fields.sessionId)).toBe(toHex(SESSION_ID));
    expect(r.fields.lastSeenSeq).toBe(3);
    // Promoted to a CBOR uint64 on the way out, so it reads back as a bigint — see the
    // promotion test below for why a float64 here would be a different signed byte string.
    expect(Number(r.fields.timestamp)).toBe(TIMESTAMP);
    expect(typeof r.fields.timestamp).toBe("bigint");
    expect(toHex(r.fields.lastSeenHash)).toBe(toHex(LAST_SEEN_HASH));
    expect(toHex(r.fields.prevOwnHash)).toBe(toHex(PREV_OWN_HASH));
  });

  it("the two links are DIFFERENT fields at different indices — one cannot stand in for the other", () => {
    /**
     * Two 32-byte hashes side by side is exactly the shape where a reader transposes them and every
     * test still passes. The vector pins the bytes; this pins that the decoder does not swap them.
     */
    const bytes = encodeStructure1(FIELDS);
    const r = decodeStructure1(bytes);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(toHex(r.fields.lastSeenHash)).not.toBe(toHex(r.fields.prevOwnHash));
    expect(toHex(r.fields.lastSeenHash)).toBe("a7".repeat(32));
    expect(toHex(r.fields.prevOwnHash)).toBe("b4".repeat(32));
  });

  it("the SESSION GENESIS is a legal value for either link — a first message is a value, not an absence", () => {
    const genesis = computeGenesisPrevRoot(SENDER_PUBKEY, COUNTERPARTY_PUBKEY, SESSION_ID, TIMESTAMP);
    expect(genesis.length).toBe(PREV_OWN_HASH_BYTES);
    expect(genesis.length).toBe(LAST_SEEN_HASH_BYTES);
    const r = decodeStructure1(encodeStructure1({ ...FIELDS, lastSeenHash: genesis, prevOwnHash: genesis }));
    expect(r.ok).toBe(true);

    // SESSION-SPECIFIC, which is the reason it is not 32 zero bytes: a constant shared by every
    // session is one an attacker can present for any of them.
    const other = computeGenesisPrevRoot(SENDER_PUBKEY, COUNTERPARTY_PUBKEY, new Uint8Array(16).fill(0x11), TIMESTAMP);
    expect(toHex(other)).not.toBe(toHex(genesis));
  });

  it("promotes a timestamp above 2^32-1 to a CBOR uint64, not a float64", () => {
    // Two implementations that disagree about which they emit produce different signed bytes for
    // the same value, and only the vector says which is canonical.
    const big = 0x1_0000_0000 + 1;
    const r = decodeStructure1(encodeStructure1({ ...FIELDS, timestamp: big }));
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(typeof r.fields.timestamp).toBe("bigint");
    expect(Number(r.fields.timestamp)).toBe(big);
  });

  it("accepts a bigint timestamp and a plain number alike on the way back in", () => {
    const asNumber = decodeStructure1(rawArray(STRUCTURE1_VERSION, CONTENT_HASH, SENDER_PUBKEY, SESSION_ID, 3, TIMESTAMP, LAST_SEEN_HASH, PREV_OWN_HASH));
    const asBigint = decodeStructure1(rawArray(STRUCTURE1_VERSION, CONTENT_HASH, SENDER_PUBKEY, SESSION_ID, 3, BigInt(TIMESTAMP), LAST_SEEN_HASH, PREV_OWN_HASH));
    expect(asNumber.ok && asBigint.ok).toBe(true);
  });
});

// ─── refusals: the load-bearing half ─────────────────────────────────────────

describe("Structure 1 refuses everything that is not the one layout", () => {
  it("BOTH links are required at encode — neither can be dropped to a shorter array", () => {
    /**
     * Typed as required, so a caller cannot omit one without a compile error — which is the real
     * guard. These assert the RUNTIME half: a wrong-width hash throws rather than emitting a
     * shorter array, at the last point before the bytes are signed.
     *
     * Throwing matters more for the self link than for the acknowledgement. A bad acknowledgement
     * surfaces immediately, because the counterparty refuses the message. A missing self link is
     * invisible in any single message — everything verifies — and only shows up later, as a
     * conversation whose order cannot be proven.
     */
    expect(() => encodeStructure1({ ...FIELDS, lastSeenHash: new Uint8Array(31) }))
      .toThrow(/last_seen_hash must be 32 bytes/);
    expect(() => encodeStructure1({ ...FIELDS, prevOwnHash: new Uint8Array(31) }))
      .toThrow(/prev_own_hash must be 32 bytes/);
    expect(() => encodeStructure1({ ...FIELDS, prevOwnHash: new Uint8Array(0) }))
      .toThrow(/prev_own_hash must be 32 bytes/);
  });

  it("a SIX-field array is refused — the layout that carried no acknowledgement is gone", () => {
    const raw = rawArray(1, CONTENT_HASH, SENDER_PUBKEY, SESSION_ID, 3, TIMESTAMP);
    const r = decodeStructure1(raw);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toBe(STRUCTURE1_DECODE_REASONS.UNKNOWN_LAYOUT);
  });

  it("a SEVEN-field array is refused under EVERY domain tag — both old seven-field layouts are gone", () => {
    /**
     * There were two, and they were distinguishable only by the tag: index 6 was a sender-minted
     * submission id under one and an acknowledgement hash under the other. Nothing ever emitted the
     * submission id — it was relay tolerance waiting for a client that never shipped — so both are
     * deleted rather than carried. This pins that neither comes back by accident.
     */
    for (const tag of [1, 2, 3]) {
      const raw = rawArray(tag, CONTENT_HASH, SENDER_PUBKEY, SESSION_ID, 3, TIMESTAMP, LAST_SEEN_HASH);
      const r = decodeStructure1(raw);
      expect(r.ok, `tag ${tag} must not decode`).toBe(false);
      if (r.ok) continue;
      expect(r.reason).toBe(STRUCTURE1_DECODE_REASONS.UNKNOWN_LAYOUT);
    }
  });

  it("an EIGHT-field array under the WRONG domain tag is refused — arity alone is never enough", () => {
    for (const tag of [0, 1, 2, 4, "3", null]) {
      const raw = rawArray(tag, CONTENT_HASH, SENDER_PUBKEY, SESSION_ID, 3, TIMESTAMP, LAST_SEEN_HASH, PREV_OWN_HASH);
      const r = decodeStructure1(raw);
      expect(r.ok, `tag ${String(tag)} must not decode`).toBe(false);
      if (r.ok) continue;
      expect(r.reason).toBe(STRUCTURE1_DECODE_REASONS.UNKNOWN_LAYOUT);
    }
  });

  it("a NINE-field array is refused — a trailing field is not a compatible extension", () => {
    const raw = rawArray(STRUCTURE1_VERSION, CONTENT_HASH, SENDER_PUBKEY, SESSION_ID, 3, TIMESTAMP, LAST_SEEN_HASH, PREV_OWN_HASH, 1);
    const r = decodeStructure1(raw);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toBe(STRUCTURE1_DECODE_REASONS.UNKNOWN_LAYOUT);
  });

  it("each link names ITSELF when it is the wrong width — not the other one", () => {
    /**
     * The exemplar check: two 32-byte fields side by side, and a reader that validated them in one
     * place would send an investigation to the wrong field. Each reason must be reachable.
     */
    for (const bad of [new Uint8Array(31), new Uint8Array(33), new Uint8Array(0)]) {
      const ackBad = decodeStructure1(rawArray(STRUCTURE1_VERSION, CONTENT_HASH, SENDER_PUBKEY, SESSION_ID, 3, TIMESTAMP, bad, PREV_OWN_HASH));
      expect(ackBad.ok).toBe(false);
      if (!ackBad.ok) expect(ackBad.reason).toBe(STRUCTURE1_DECODE_REASONS.LAST_SEEN_HASH_MALFORMED);

      const selfBad = decodeStructure1(rawArray(STRUCTURE1_VERSION, CONTENT_HASH, SENDER_PUBKEY, SESSION_ID, 3, TIMESTAMP, LAST_SEEN_HASH, bad));
      expect(selfBad.ok).toBe(false);
      if (!selfBad.ok) expect(selfBad.reason).toBe(STRUCTURE1_DECODE_REASONS.PREV_OWN_HASH_MALFORMED);
    }
  });

  it("a link that is not bytes at all is refused BY NAME, never coerced", () => {
    const ackBad = decodeStructure1(rawArray(STRUCTURE1_VERSION, CONTENT_HASH, SENDER_PUBKEY, SESSION_ID, 3, TIMESTAMP, 7, PREV_OWN_HASH));
    expect(ackBad.ok).toBe(false);
    if (!ackBad.ok) expect(ackBad.reason).toBe(STRUCTURE1_DECODE_REASONS.LAST_SEEN_HASH_MALFORMED);

    const selfBad = decodeStructure1(rawArray(STRUCTURE1_VERSION, CONTENT_HASH, SENDER_PUBKEY, SESSION_ID, 3, TIMESTAMP, LAST_SEEN_HASH, "b4"));
    expect(selfBad.ok).toBe(false);
    if (!selfBad.ok) expect(selfBad.reason).toBe(STRUCTURE1_DECODE_REASONS.PREV_OWN_HASH_MALFORMED);
  });

  it("a malformed field at indices 1–5 is refused, and does not read as a bad link", () => {
    const cases: Array<[string, Uint8Array[]]> = [
      ["content hash", [new Uint8Array(31), SENDER_PUBKEY, SESSION_ID]],
      ["sender pubkey", [CONTENT_HASH, new Uint8Array(31), SESSION_ID]],
    ];
    for (const [what, [ch, spk, sid]] of cases) {
      const r = decodeStructure1(rawArray(STRUCTURE1_VERSION, ch, spk, sid, 3, TIMESTAMP, LAST_SEEN_HASH, PREV_OWN_HASH));
      expect(r.ok, what).toBe(false);
      if (r.ok) continue;
      expect(r.reason).toBe(STRUCTURE1_DECODE_REASONS.FIELD_MALFORMED);
    }
  });

  it("non-CBOR and non-array inputs are named apart from a layout refusal", () => {
    const notCbor = decodeStructure1(new Uint8Array([0xff, 0xff, 0xff, 0xff]));
    expect(notCbor.ok).toBe(false);
    if (!notCbor.ok) expect(notCbor.reason).toBe(STRUCTURE1_DECODE_REASONS.NOT_CBOR);

    const notArray = decodeStructure1(new Uint8Array(cborEncode({ version: 3 })));
    expect(notArray.ok).toBe(false);
    if (!notArray.ok) expect(notArray.reason).toBe(STRUCTURE1_DECODE_REASONS.NOT_ARRAY);
  });

  it("the field count constant and the encoder agree — a drift here silently widens the decoder", () => {
    // Read the CBOR header byte directly rather than restating the decoder's own constant back to
    // itself: 0x88 is a definite-length array of eight. If the encoder ever emits a different
    // arity, this fails even though the decoder and the constant still agree with each other.
    const bytes = encodeStructure1(FIELDS);
    expect(bytes[0]).toBe(0x80 + STRUCTURE1_FIELD_COUNT);
    expect(STRUCTURE1_FIELD_COUNT).toBe(8);
  });
});
