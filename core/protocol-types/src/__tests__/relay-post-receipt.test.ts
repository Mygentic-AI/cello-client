/**
 * M16 / 016-CLIENTREWORK — the relay's signed receipt for a post.
 *
 * `published_at` is the publisher's own clock and proves nothing on its own. The receipt is what
 * makes time meaningful: the relay signs the post's HASH together with its own receive time, so the
 * publisher holds proof of what it sent and when that relay took it.
 *
 * The receipt binds its post BY HASH, never by sequence number alone — a receipt that matched on
 * (channel, seq) would attest to any post the publisher later chose to put at that number.
 */

import { setupV3Tests, describe, it, expect } from "@claude-flow/testing";
import { generateKeypair, hash, verify } from "@cello-protocol/crypto";
import { encodeCbor } from "../cbor.js";
import { encodeBroadcastArtifact, signBroadcastArtifact } from "../broadcast-artifact.js";
import type { BroadcastArtifact } from "../broadcast-artifact.js";
import {
  RELAY_POST_RECEIPT_DOMAIN,
  buildRelayPostReceiptTbs,
  decodeRelayPostReceipt,
  encodeRelayPostReceipt,
  signRelayPostReceipt,
  verifyRelayPostReceipt,
} from "../relay-post-receipt.js";
import type { RelayPostReceipt } from "../relay-post-receipt.js";

setupV3Tests();

const RECEIVED_AT = 1_758_000_000_123;

async function post(seq = 3): Promise<BroadcastArtifact> {
  return signBroadcastArtifact(generateKeypair(), generateKeypair(), {
    seq,
    published_at: 1_758_000_000_000,
    title: "Deploy finished",
    body: new Uint8Array([9, 8, 7, 6]),
    supersedes: null,
    ext: null,
  });
}

function slotsOf(r: RelayPostReceipt): unknown[] {
  return [
    RELAY_POST_RECEIPT_DOMAIN,
    r.relay_pubkey,
    r.channel_pubkey,
    r.seq,
    r.post_hash,
    r.received_at,
    r.signature,
  ];
}

function withSlot(r: RelayPostReceipt, index: number, value: unknown): Uint8Array {
  const slots = slotsOf(r);
  slots[index] = value;
  return encodeCbor(slots);
}

describe("016-CLIENTREWORK — the relay post receipt", () => {
  it("9. a receipt signed by a relay verifies against its post, over the spec's preimage", async () => {
    const p = await post();
    const relay = generateKeypair();
    const r = await signRelayPostReceipt(relay, p, RECEIVED_AT);

    expect(r.relay_pubkey).toEqual(await relay.getPublicKey());
    expect(r.channel_pubkey).toEqual(p.channel_pubkey);
    expect(r.seq).toBe(p.seq);
    expect(r.received_at).toBe(RECEIVED_AT);
    expect(r.post_hash).toEqual(hash(encodeBroadcastArtifact(p)));
    expect(verifyRelayPostReceipt(r, p)).toBe(true);

    // Rebuilt inline, so a reordered TBS builder does not pass by signing and verifying itself.
    const specTbs = encodeCbor([
      RELAY_POST_RECEIPT_DOMAIN,
      r.relay_pubkey,
      r.channel_pubkey,
      r.seq,
      r.post_hash,
      r.received_at,
    ]);
    expect(buildRelayPostReceiptTbs(r)).toEqual(specTbs);
    expect(verify(r.relay_pubkey, specTbs, r.signature)).toBe(true);

    const d = decodeRelayPostReceipt(encodeRelayPostReceipt(r));
    expect(d.ok).toBe(true);
    if (!d.ok) return;
    expect(verifyRelayPostReceipt(d.receipt, p)).toBe(true);
  });

  it("10. the same receipt against a DIFFERENT post is false, even at the same seq", async () => {
    const p = await post(3);
    const relay = generateKeypair();
    const r = await signRelayPostReceipt(relay, p, RECEIVED_AT);

    // A different post at the same sequence number: only the hash tells them apart.
    const other = await post(3);
    expect(other.seq).toBe(p.seq);
    expect(verifyRelayPostReceipt(r, other)).toBe(false);

    // And a post at a different number.
    expect(verifyRelayPostReceipt(r, await post(4))).toBe(false);
  });

  it("11. a tampered received_at, hash or relay key fails verification", async () => {
    const p = await post();
    const relay = generateKeypair();
    const r = await signRelayPostReceipt(relay, p, RECEIVED_AT);
    const flip = (b: Uint8Array): Uint8Array => {
      const c = new Uint8Array(b);
      c[0] ^= 0x01;
      return c;
    };
    const cases: Array<[string, RelayPostReceipt]> = [
      ["received_at", { ...r, received_at: r.received_at + 1 }],
      ["post_hash", { ...r, post_hash: flip(r.post_hash) }],
      ["relay_pubkey", { ...r, relay_pubkey: flip(r.relay_pubkey) }],
      ["seq", { ...r, seq: r.seq + 1 }],
      ["channel_pubkey", { ...r, channel_pubkey: flip(r.channel_pubkey) }],
      ["signature", { ...r, signature: flip(r.signature) }],
    ];
    for (const [field, tampered] of cases) {
      expect({ field, verified: verifyRelayPostReceipt(tampered, p) }).toEqual({ field, verified: false });
    }
  });

  it("12. decode names the offending field and never throws", async () => {
    const p = await post();
    const r = await signRelayPostReceipt(generateKeypair(), p, RECEIVED_AT);
    const cases: Array<[string, Uint8Array]> = [
      ["not_cbor", new Uint8Array([0xfe, 0x3c, 0x9a, 0x17, 0x44])],
      ["wrong_shape", encodeCbor(slotsOf(r).slice(0, 6))],
      ["wrong_domain", withSlot(r, 0, "cello-broadcast-artifact-v1")],
      ["bad_relay_pubkey", withSlot(r, 1, new Uint8Array(31))],
      ["bad_channel_pubkey", withSlot(r, 2, new Uint8Array(31))],
      ["bad_seq", withSlot(r, 3, 0)],
      ["bad_seq", withSlot(r, 3, 1.5)],
      ["bad_post_hash", withSlot(r, 4, new Uint8Array(31))],
      ["bad_received_at", withSlot(r, 5, 0)],
      ["bad_received_at", withSlot(r, 5, 1.5)],
      ["bad_signature_shape", withSlot(r, 6, new Uint8Array(63))],
    ];
    for (const [reason, bytes] of cases) {
      const d = decodeRelayPostReceipt(bytes);
      expect({ expected: reason, got: d.ok ? "ok" : d.reason }).toEqual({ expected: reason, got: reason });
    }
    for (const bytes of [new Uint8Array(0), encodeCbor({ a: 1 }), encodeCbor(7), new Uint8Array(512).fill(0xff)]) {
      let result: ReturnType<typeof decodeRelayPostReceipt> | undefined;
      expect(() => {
        result = decodeRelayPostReceipt(bytes);
      }).not.toThrow();
      expect(result?.ok).toBe(false);
    }
  });
});
