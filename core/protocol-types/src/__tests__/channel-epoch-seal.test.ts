/**
 * M16 / 003-SEALTYPE — the channel-epoch-seal receipt.
 *
 * Tests are written RED-first. Expected reasons and slot order come from the work order, never
 * from the encoder under test.
 */

import { setupV3Tests, describe, it, expect } from "@claude-flow/testing";
import { generateKeypair, verify } from "@cello-protocol/crypto";
import { encodeCbor } from "../cbor.js";
import {
  CHANNEL_EPOCH_SEAL_ATTESTS,
  CHANNEL_EPOCH_SEAL_DOMAIN,
  buildChannelEpochSealTbs,
  checkEpochChainLink,
  decodeChannelEpochSeal,
  encodeChannelEpochSeal,
  signChannelEpochSeal,
  verifyChannelEpochSealSignature,
} from "../channel-epoch-seal.js";
import type { ChannelEpochSeal } from "../channel-epoch-seal.js";

setupV3Tests();

type Fields = Omit<ChannelEpochSeal, "publisher_signature" | "notarization" | "cosig_ext" | "channel_pubkey">;

const SEALED_AT = 1_789_000_000_000;

function bytes(seed: number, length = 32): Uint8Array {
  return Uint8Array.from({ length }, (_, i) => (seed * 31 + i * 17) & 0xff);
}

/** A valid epoch-1 seal. Every integer field holds a distinct value, so a slot swap shows. */
function makeSealFields(overrides: Partial<Fields> = {}): Fields {
  return {
    epoch_index: 1,
    epoch_root: bytes(7),
    first_seq: 6,
    leaf_count: 4,
    prev_epoch_root: bytes(3),
    sealed_at: SEALED_AT,
    ...overrides,
  };
}

/** The eleven wire slots of an encoded seal, for building malformed variants by hand. */
function slotsOf(s: ChannelEpochSeal): unknown[] {
  return [
    CHANNEL_EPOCH_SEAL_DOMAIN,
    s.channel_pubkey,
    s.epoch_index,
    s.epoch_root,
    s.first_seq,
    s.leaf_count,
    s.prev_epoch_root,
    s.sealed_at,
    s.publisher_signature,
    s.notarization,
    s.cosig_ext,
  ];
}

function withSlot(s: ChannelEpochSeal, index: number, value: unknown): Uint8Array {
  const slots = slotsOf(s);
  slots[index] = value;
  return encodeCbor(slots);
}

function flip(b: Uint8Array): Uint8Array {
  const copy = Uint8Array.from(b);
  copy[0] ^= 0x01;
  return copy;
}

/**
 * The same signed seal with `leaf_count` written as float64 4.0 instead of the integer 4. The
 * values are identical and the signature still verifies, but the bytes are a second wire form.
 * Offset 100 = array header (1) + domain text (2 + 27) + pubkey (2 + 32) + epoch_index (1)
 * + epoch_root (2 + 32) + first_seq (1).
 */
function floatLeafCount(s: ChannelEpochSeal): Uint8Array {
  const canonical = encodeChannelEpochSeal(s);
  if (s.leaf_count !== 4 || canonical[100] !== 0x04) {
    throw new Error("fixture drift: leaf_count is not at offset 100");
  }
  const float4 = [0xfb, 0x40, 0x10, 0, 0, 0, 0, 0, 0];
  return new Uint8Array([...canonical.slice(0, 100), ...float4, ...canonical.slice(101)]);
}

describe("M16 003-SEALTYPE: channel-epoch-seal receipt", () => {
  it("sign → encode → decode → verify round-trips", async () => {
    const kp = generateKeypair();
    const fields = makeSealFields();
    const seal = await signChannelEpochSeal(kp, fields);
    const decoded = decodeChannelEpochSeal(encodeChannelEpochSeal(seal));
    if (!decoded.ok) throw new Error(`decode failed: ${decoded.reason} ${decoded.detail}`);
    const d = decoded.seal;
    expect(d.channel_pubkey).toEqual(await kp.getPublicKey());
    expect(d.epoch_index).toBe(1);
    expect(d.epoch_root).toEqual(fields.epoch_root);
    expect(d.first_seq).toBe(6);
    expect(d.leaf_count).toBe(4);
    expect(d.prev_epoch_root).toEqual(fields.prev_epoch_root);
    expect(d.sealed_at).toBe(SEALED_AT);
    expect(d.publisher_signature).toEqual(seal.publisher_signature);
    expect(d.notarization).toBeNull();
    expect(d.cosig_ext).toBeNull();
    expect(verifyChannelEpochSealSignature(d)).toBe(true);
  });

  it("every TBS field is signed", async () => {
    const seal = await signChannelEpochSeal(generateKeypair(), makeSealFields());
    expect(verifyChannelEpochSealSignature(seal)).toBe(true);
    const variants: [string, ChannelEpochSeal][] = [
      ["epoch_index", { ...seal, epoch_index: 2 }],
      ["epoch_root", { ...seal, epoch_root: flip(seal.epoch_root) }],
      ["first_seq", { ...seal, first_seq: 7 }],
      ["leaf_count", { ...seal, leaf_count: 5 }],
      ["prev_epoch_root", { ...seal, prev_epoch_root: flip(seal.prev_epoch_root as Uint8Array) }],
      ["sealed_at", { ...seal, sealed_at: SEALED_AT + 1 }],
      ["channel_pubkey", { ...seal, channel_pubkey: flip(seal.channel_pubkey) }],
    ];
    for (const [name, variant] of variants) {
      expect(verifyChannelEpochSealSignature(variant), name).toBe(false);
    }
  });

  it("notarization is OUTSIDE the publisher's signature", async () => {
    const seal = await signChannelEpochSeal(generateKeypair(), makeSealFields());
    expect(verifyChannelEpochSealSignature(seal)).toBe(true);
    const notarized: ChannelEpochSeal = { ...seal, notarization: bytes(9, 96) };
    expect(verifyChannelEpochSealSignature(notarized)).toBe(true);
  });

  it("decode rejects each malformation with its named reason", async () => {
    const seal = await signChannelEpochSeal(generateKeypair(), makeSealFields());
    const cases: [string, Uint8Array][] = [
      ["not_cbor", Uint8Array.from([0xff, 0xfe, 0x00, 0x13, 0x37])],
      ["wrong_shape", encodeCbor(slotsOf(seal).slice(0, 10))],
      ["wrong_domain", withSlot(seal, 0, "cello-channel-epoch-seal-v2")],
      ["bad_channel_pubkey", withSlot(seal, 1, new Uint8Array(31))],
      ["bad_epoch_index", withSlot(seal, 2, -1)],
      ["bad_epoch_root", withSlot(seal, 3, new Uint8Array(16))],
      ["bad_first_seq", withSlot(seal, 4, 0)],
      ["bad_leaf_count", withSlot(seal, 5, 0)],
      ["bad_prev_epoch_root", encodeCbor(Object.assign(slotsOf(seal), { 2: 0 }))],
      ["bad_prev_epoch_root", withSlot(seal, 6, null)],
      ["bad_sealed_at", withSlot(seal, 7, -5)],
      ["bad_publisher_signature", withSlot(seal, 8, new Uint8Array(63))],
      ["bad_notarization", withSlot(seal, 9, new Uint8Array(5000))],
      ["bad_notarization", withSlot(seal, 9, new Uint8Array(0))],
      ["cosig_ext_not_null", withSlot(seal, 10, "later")],
      ["wrong_shape", floatLeafCount(seal)],
    ];
    for (const [reason, input] of cases) {
      const result = decodeChannelEpochSeal(input);
      expect(result.ok, reason).toBe(false);
      if (!result.ok) expect(result.reason, reason).toBe(reason);
    }
    // The float case is a second byte form of a VALID seal: it must be the encoding refused.
    const floatResult = decodeChannelEpochSeal(floatLeafCount(seal));
    if (!floatResult.ok) expect(floatResult.detail).toBe("non-canonical encoding");
  });

  it("epoch 0 shape", async () => {
    const seal = await signChannelEpochSeal(
      generateKeypair(),
      makeSealFields({ epoch_index: 0, prev_epoch_root: null, first_seq: 1 }),
    );
    const decoded = decodeChannelEpochSeal(encodeChannelEpochSeal(seal));
    if (!decoded.ok) throw new Error(`decode failed: ${decoded.reason} ${decoded.detail}`);
    expect(decoded.seal.epoch_index).toBe(0);
    expect(decoded.seal.prev_epoch_root).toBeNull();
    expect(decoded.seal.first_seq).toBe(1);
    expect(verifyChannelEpochSealSignature(decoded.seal)).toBe(true);
  });

  describe("chain links", () => {
    async function pair() {
      const kp = generateKeypair();
      const rootA = bytes(11);
      const a = await signChannelEpochSeal(kp, makeSealFields({
        epoch_index: 0, epoch_root: rootA, first_seq: 1, leaf_count: 5, prev_epoch_root: null,
      }));
      const bFields = makeSealFields({
        epoch_index: 1, epoch_root: bytes(12), first_seq: 6, leaf_count: 3, prev_epoch_root: rootA,
      });
      const b = await signChannelEpochSeal(kp, bFields);
      return { kp, a, b, bFields };
    }

    it("chain link accepts the true successor", async () => {
      const { a, b } = await pair();
      expect(checkEpochChainLink(a, b)).toEqual({ ok: true });
    });

    it("chain link rejects each break with its named reason", async () => {
      const { kp, a, bFields } = await pair();
      const cases: [string, ChannelEpochSeal][] = [
        ["channel_mismatch", await signChannelEpochSeal(generateKeypair(), bFields)],
        ["epoch_index_not_next", await signChannelEpochSeal(kp, { ...bFields, epoch_index: 2 })],
        ["prev_root_mismatch", await signChannelEpochSeal(kp, {
          ...bFields, prev_epoch_root: flip(a.epoch_root),
        })],
        ["seq_not_contiguous", await signChannelEpochSeal(kp, { ...bFields, first_seq: 7 })],
      ];
      for (const [reason, next] of cases) {
        const result = checkEpochChainLink(a, next);
        expect(result.ok, reason).toBe(false);
        if (!result.ok) expect(result.reason, reason).toBe(reason);
      }
    });

    it("a gap hidden between epochs is caught", async () => {
      const { kp, a, bFields } = await pair();
      // A covers seqs 1..5. B claims to start at 8, silently dropping 6 and 7.
      const gapped = await signChannelEpochSeal(kp, { ...bFields, first_seq: 8 });
      const result = checkEpochChainLink(a, gapped);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.reason).toBe("seq_not_contiguous");
    });
  });

  it("signChannelEpochSeal enforces field rules", async () => {
    const kp = generateKeypair();
    await expect(signChannelEpochSeal(kp, makeSealFields({ leaf_count: 0 }))).rejects.toThrow(RangeError);
    await expect(
      signChannelEpochSeal(kp, makeSealFields({ epoch_index: 1, prev_epoch_root: null })),
    ).rejects.toThrow(RangeError);
  });

  it("the honesty statement is exported and immutable in shape", () => {
    expect(CHANNEL_EPOCH_SEAL_ATTESTS.counterparty_approved).toBe(false);
    expect(CHANNEL_EPOCH_SEAL_ATTESTS.disclaimer).toContain("No counterparty");
  });

  it("the TBS slot order is pinned against the spec", async () => {
    const kp = generateKeypair();
    const fields = makeSealFields();
    const seal = await signChannelEpochSeal(kp, fields);
    const pubkey = await kp.getPublicKey();
    // Written out from the work order's slot list — NOT built by the code under test.
    const inlineTbs = encodeCbor([
      CHANNEL_EPOCH_SEAL_DOMAIN,
      pubkey,
      1,
      fields.epoch_root,
      6,
      4,
      fields.prev_epoch_root,
      SEALED_AT,
    ]);
    expect(buildChannelEpochSealTbs({ ...fields, channel_pubkey: pubkey })).toEqual(inlineTbs);
    expect(verify(pubkey, inlineTbs, seal.publisher_signature)).toBe(true);
  });
});
