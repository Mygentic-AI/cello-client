/**
 * M16 / 002-ARTIFACT — the signed broadcast artifact wire format.
 *
 * Tests are written RED-first. Expected reasons come from the work order, never from the encoder
 * under test; expected hashes are recomputed inline from the crypto primitive.
 */

import { setupV3Tests, describe, it, expect } from "@claude-flow/testing";
import { generateKeypair, msgLeafHash, verify } from "@cello-protocol/crypto";
import { encodeCbor } from "../cbor.js";
import {
  BROADCAST_ARTIFACT_DOMAIN,
  MAX_BROADCAST_BODY_BYTES,
  MAX_BROADCAST_TITLE_CHARS,
  broadcastArtifactLeafHash,
  decodeBroadcastArtifact,
  encodeBroadcastArtifact,
  signBroadcastArtifact,
  validateBroadcastTitle,
  verifyBroadcastArtifact,
} from "../broadcast-artifact.js";
import type { BroadcastArtifact } from "../broadcast-artifact.js";

setupV3Tests();

type Fields = Omit<BroadcastArtifact, "signature" | "channel_pubkey">;

function makeFields(overrides: Partial<Fields> = {}): Fields {
  return {
    seq: 3,
    epoch_index: 1,
    title: "Deploy finished",
    body_ciphertext: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
    supersedes: null,
    prev_epoch_root: null,
    ext: null,
    ...overrides,
  };
}

/** Epoch-first shape with supersedes set: no two adjacent optional slots hold equal values. */
const DISTINCT_SLOTS: Partial<Fields> = {
  seq: 3,
  epoch_index: 1,
  supersedes: 2,
  prev_epoch_root: new Uint8Array(32).fill(0xab),
};

/** The ten wire slots of a valid encoded artifact, for building malformed variants by hand. */
function slotsOf(a: BroadcastArtifact): unknown[] {
  return [
    BROADCAST_ARTIFACT_DOMAIN,
    a.channel_pubkey,
    a.seq,
    a.epoch_index,
    a.title,
    a.body_ciphertext,
    a.supersedes,
    a.prev_epoch_root,
    a.ext,
    a.signature,
  ];
}

function withSlot(a: BroadcastArtifact, index: number, value: unknown): Uint8Array {
  const slots = slotsOf(a);
  slots[index] = value;
  return encodeCbor(slots);
}

/**
 * The same signed artifact with `seq` written as float64 3.0 instead of the integer 3. Values are
 * identical and the signature still verifies, but the bytes are a second wire form of one artifact.
 * Offset 64 = array header (1) + domain text (2 + 27) + pubkey bytes (2 + 32).
 */
function floatSeq(a: BroadcastArtifact): Uint8Array {
  const canonical = encodeBroadcastArtifact(a);
  if (a.seq !== 3 || canonical[64] !== 0x03) throw new Error("fixture drift: seq is not at offset 64");
  const float3 = [0xfb, 0x40, 0x08, 0, 0, 0, 0, 0, 0];
  return new Uint8Array([...canonical.slice(0, 64), ...float3, ...canonical.slice(65)]);
}

async function signed(overrides: Partial<Fields> = {}): Promise<BroadcastArtifact> {
  return signBroadcastArtifact(generateKeypair(), makeFields(overrides));
}

describe("002-ARTIFACT — broadcast artifact", () => {
  it("1. sign → encode → decode → verify round-trips", async () => {
    const kp = generateKeypair();
    // Every nullable slot NON-null and distinct, so the inline preimage below pins their order:
    // with all three null, swapping two of them leaves the bytes identical.
    const fields = makeFields(DISTINCT_SLOTS);
    const a = await signBroadcastArtifact(kp, fields);
    const d = decodeBroadcastArtifact(encodeBroadcastArtifact(a));
    expect(d.ok).toBe(true);
    if (!d.ok) return;
    expect(d.artifact.channel_pubkey).toEqual(await kp.getPublicKey());
    expect(d.artifact.seq).toBe(fields.seq);
    expect(d.artifact.epoch_index).toBe(fields.epoch_index);
    expect(d.artifact.title).toBe(fields.title);
    expect(d.artifact.body_ciphertext).toEqual(fields.body_ciphertext);
    expect(d.artifact.supersedes).toBe(2);
    expect(d.artifact.prev_epoch_root).toEqual(new Uint8Array(32).fill(0xab));
    expect(d.artifact.ext).toBeNull();
    expect(d.artifact.signature).toEqual(a.signature);
    expect(verifyBroadcastArtifact(d.artifact)).toBe(true);
    // Pin the TBS to the spec's slot order, rebuilt inline. Sign and verify share one TBS builder,
    // so a reordered builder still round-trips; only an independent preimage catches it.
    const specTbs = encodeCbor([
      BROADCAST_ARTIFACT_DOMAIN,
      a.channel_pubkey,
      fields.seq,
      fields.epoch_index,
      fields.title,
      fields.body_ciphertext,
      fields.supersedes,
      fields.prev_epoch_root,
      fields.ext,
    ]);
    expect(verify(a.channel_pubkey, specTbs, a.signature)).toBe(true);
  });

  it("2. encoding is deterministic", async () => {
    const a = await signed();
    expect(encodeBroadcastArtifact(a)).toEqual(encodeBroadcastArtifact(a));
  });

  it("3. every field is signed", async () => {
    const a = await signed();
    const d = decodeBroadcastArtifact(encodeBroadcastArtifact(a));
    expect(d.ok).toBe(true);
    if (!d.ok) return;
    expect(verifyBroadcastArtifact(d.artifact)).toBe(true);
    const flip = (b: Uint8Array): Uint8Array => {
      const c = new Uint8Array(b);
      c[0] ^= 0x01;
      return c;
    };
    const cases: Array<[string, (x: BroadcastArtifact) => BroadcastArtifact]> = [
      ["seq", (x) => ({ ...x, seq: x.seq + 1 })],
      ["epoch_index", (x) => ({ ...x, epoch_index: x.epoch_index + 1 })],
      ["title", (x) => ({ ...x, title: x.title + "x" })],
      ["body_ciphertext", (x) => ({ ...x, body_ciphertext: flip(x.body_ciphertext) })],
      ["supersedes", (x) => ({ ...x, supersedes: 1 })],
      ["prev_epoch_root", (x) => ({ ...x, epoch_index: 1, prev_epoch_root: new Uint8Array(32) })],
      ["channel_pubkey", (x) => ({ ...x, channel_pubkey: flip(x.channel_pubkey) })],
    ];
    for (const [name, mutate] of cases) {
      expect({ field: name, verified: verifyBroadcastArtifact(mutate(d.artifact)) }).toEqual({
        field: name,
        verified: false,
      });
    }
  });

  it("4. title validation", async () => {
    expect(validateBroadcastTitle("").ok).toBe(false);
    expect(validateBroadcastTitle("🚨".repeat(200)).ok).toBe(true);
    expect(validateBroadcastTitle("🚨".repeat(201)).ok).toBe(false);
    expect(validateBroadcastTitle("a\u0000b").ok).toBe(false);
    expect(validateBroadcastTitle("a\nb").ok).toBe(false);
    expect(validateBroadcastTitle("a\u007Fb").ok).toBe(false);
    expect(validateBroadcastTitle("a".repeat(MAX_BROADCAST_TITLE_CHARS)).ok).toBe(true);
    // An unpaired surrogate is rewritten to U+FFFD by UTF-8 encoding, so a title carrying one signs
    // fine and then fails verification for every subscriber. Refuse it before signing.
    expect(validateBroadcastTitle("t\uD800x").ok).toBe(false);
    expect(validateBroadcastTitle("t\uDC00x").ok).toBe(false);
    await expect(signBroadcastArtifact(generateKeypair(), makeFields({ title: "t\uD800x" }))).rejects.toThrow(RangeError);
    const refused = validateBroadcastTitle(42);
    expect(refused.ok).toBe(false);
    if (!refused.ok) expect(refused.reason).toBe("bad_title");
  });

  it("5. decode rejects each malformation with its named reason", async () => {
    const a = await signed();
    const cases: Array<[string, Uint8Array]> = [
      ["not_cbor", new Uint8Array([0xfe, 0x3c, 0x9a, 0x17, 0x44])],
      ["wrong_shape", encodeCbor(slotsOf(a).slice(0, 9))],
      ["wrong_domain", withSlot(a, 0, "cello-trust-signal-v1")],
      ["bad_channel_pubkey", withSlot(a, 1, new Uint8Array(31))],
      ["bad_seq", withSlot(a, 2, 0)],
      ["bad_seq", withSlot(a, 2, 1.5)],
      ["bad_epoch_index", withSlot(a, 3, -1)],
      ["bad_title", withSlot(a, 4, "bad\u0001title")],
      ["body_too_large", withSlot(a, 5, new Uint8Array(MAX_BROADCAST_BODY_BYTES + 1))],
      ["bad_supersedes", withSlot(a, 6, a.seq)],
      ["bad_supersedes", withSlot(a, 6, 0)],
      ["bad_prev_epoch_root", withSlot(a, 7, new Uint8Array(16))],
      [
        "bad_prev_epoch_root",
        (() => {
          const s = slotsOf(a);
          s[3] = 0;
          s[7] = new Uint8Array(32);
          return encodeCbor(s);
        })(),
      ],
      ["ext_not_null", withSlot(a, 8, 7)],
      ["bad_signature_shape", withSlot(a, 9, new Uint8Array(63))],
      ["wrong_shape", floatSeq(a)],
    ];
    for (const [reason, bytes] of cases) {
      const d = decodeBroadcastArtifact(bytes);
      expect({ expected: reason, got: d.ok ? "ok" : d.reason }).toEqual({ expected: reason, got: reason });
    }
  });

  it("6. adversarial CBOR does not throw", () => {
    const inputs = [
      new Uint8Array(0),
      encodeCbor({ a: 1 }),
      encodeCbor(7),
      new Uint8Array(1024).fill(0xff),
    ];
    for (const bytes of inputs) {
      let result: ReturnType<typeof decodeBroadcastArtifact> | undefined;
      expect(() => {
        result = decodeBroadcastArtifact(bytes);
      }).not.toThrow();
      expect(result?.ok).toBe(false);
    }
  });

  it("7. signBroadcastArtifact enforces the same rules", async () => {
    const kp = generateKeypair();
    await expect(signBroadcastArtifact(kp, makeFields({ seq: 0 }))).rejects.toThrow(RangeError);
    await expect(signBroadcastArtifact(kp, makeFields({ title: "é".repeat(201) }))).rejects.toThrow(RangeError);
  });

  it("8. wrong key fails verify", async () => {
    const a = await signed();
    const other = await generateKeypair().getPublicKey();
    expect(verifyBroadcastArtifact({ ...a, channel_pubkey: other })).toBe(false);
  });

  it("9. leaf hash commits to the signature", async () => {
    const fields = makeFields(DISTINCT_SLOTS);
    const a = await signBroadcastArtifact(generateKeypair(), fields);
    const b = await signBroadcastArtifact(generateKeypair(), fields);
    expect(broadcastArtifactLeafHash(a)).not.toEqual(broadcastArtifactLeafHash(b));
    const inline = msgLeafHash(encodeCbor(slotsOf(a)));
    expect(broadcastArtifactLeafHash(a)).toEqual(inline);
    expect(broadcastArtifactLeafHash(a)).toEqual(msgLeafHash(encodeBroadcastArtifact(a)));
  });

  it("10. supersedes survives the wire", async () => {
    const a = await signed({ seq: 3, supersedes: 2 });
    const d = decodeBroadcastArtifact(encodeBroadcastArtifact(a));
    expect(d.ok).toBe(true);
    if (!d.ok) return;
    expect(d.artifact.supersedes).toBe(2);
    expect(verifyBroadcastArtifact(d.artifact)).toBe(true);
  });
});
