/**
 * M16 / 016-CLIENTREWORK — the doubly-signed broadcast post.
 *
 * The epoch fields are gone; the post now carries the publishing agent's key and the publisher's
 * own timestamp, and it is signed TWICE — once by the channel key (the right to publish) and once
 * by the agent key (what ties the post to a human operator). One valid signature is not a valid
 * post.
 *
 * Tests are written RED-first. Expected reasons come from the work order, never from the encoder
 * under test; expected preimages are rebuilt inline from the CBOR encoder.
 */

import { setupV3Tests, describe, it, expect } from "@claude-flow/testing";
import { generateKeypair, verify } from "@cello-protocol/crypto";
import type { KeyProvider } from "@cello-protocol/crypto";
import { encodeCbor } from "../cbor.js";
import {
  BROADCAST_ARTIFACT_DOMAIN,
  MAX_BROADCAST_BODY_BYTES,
  MAX_BROADCAST_TITLE_CHARS,
  decodeBroadcastArtifact,
  encodeBroadcastArtifact,
  signBroadcastArtifact,
  validateBroadcastTitle,
  verifyBroadcastArtifact,
} from "../broadcast-artifact.js";
import type { BroadcastArtifact } from "../broadcast-artifact.js";

setupV3Tests();

type Fields = Omit<BroadcastArtifact, "channel_signature" | "agent_signature" | "channel_pubkey" | "agent_pubkey">;

const PUBLISHED_AT = 1_758_000_000_000;

function makeFields(overrides: Partial<Fields> = {}): Fields {
  return {
    seq: 3,
    published_at: PUBLISHED_AT,
    title: "Deploy finished",
    body: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
    supersedes: null,
    ext: null,
    ...overrides,
  };
}

/** The eleven wire slots of a valid encoded post, for building malformed variants by hand. */
function slotsOf(a: BroadcastArtifact): unknown[] {
  return [
    BROADCAST_ARTIFACT_DOMAIN,
    a.channel_pubkey,
    a.agent_pubkey,
    a.seq,
    a.published_at,
    a.title,
    a.body,
    a.supersedes,
    a.ext,
    a.channel_signature,
    a.agent_signature,
  ];
}

function withSlot(a: BroadcastArtifact, index: number, value: unknown): Uint8Array {
  const slots = slotsOf(a);
  slots[index] = value;
  return encodeCbor(slots);
}

/**
 * The same signed post with `seq` written as float64 3.0 instead of the integer 3. Values are
 * identical and both signatures still verify, but the bytes are a second wire form of one post —
 * and anything that hashes the RECEIVED bytes (the relay receipt) would then disagree.
 * Offset 98 = array header (1) + domain text (2 + 27) + channel pubkey (2 + 32) + agent pubkey (2 + 32).
 */
function floatSeq(a: BroadcastArtifact): Uint8Array {
  const canonical = encodeBroadcastArtifact(a);
  if (a.seq !== 3 || canonical[98] !== 0x03) throw new Error("fixture drift: seq is not at offset 98");
  const float3 = [0xfb, 0x40, 0x08, 0, 0, 0, 0, 0, 0];
  return new Uint8Array([...canonical.slice(0, 98), ...float3, ...canonical.slice(99)]);
}

async function signed(
  overrides: Partial<Fields> = {},
  keys: { channel?: KeyProvider; agent?: KeyProvider } = {},
): Promise<BroadcastArtifact> {
  return signBroadcastArtifact(
    keys.channel ?? generateKeypair(),
    keys.agent ?? generateKeypair(),
    makeFields(overrides),
  );
}

describe("016-CLIENTREWORK — the doubly-signed post", () => {
  it("4. sign → encode → decode → verify round-trips, and the TBS is the spec's slot order", async () => {
    const channel = generateKeypair();
    const agent = generateKeypair();
    // `supersedes` non-null so no two adjacent optional slots hold equal values: with both null,
    // swapping them leaves the bytes identical and the inline preimage would not pin the order.
    const fields = makeFields({ seq: 3, supersedes: 2 });
    const a = await signBroadcastArtifact(channel, agent, fields);
    const d = decodeBroadcastArtifact(encodeBroadcastArtifact(a));
    expect(d.ok).toBe(true);
    if (!d.ok) return;
    expect(d.artifact.channel_pubkey).toEqual(await channel.getPublicKey());
    expect(d.artifact.agent_pubkey).toEqual(await agent.getPublicKey());
    expect(d.artifact.seq).toBe(fields.seq);
    expect(d.artifact.published_at).toBe(fields.published_at);
    expect(d.artifact.title).toBe(fields.title);
    expect(d.artifact.body).toEqual(fields.body);
    expect(d.artifact.supersedes).toBe(2);
    expect(d.artifact.ext).toBeNull();
    expect(verifyBroadcastArtifact(d.artifact)).toEqual({ ok: true });

    // Sign and verify share one TBS builder, so a reordered builder still round-trips; only an
    // independent preimage catches it. BOTH signatures are over this one preimage.
    const specTbs = encodeCbor([
      BROADCAST_ARTIFACT_DOMAIN,
      a.channel_pubkey,
      a.agent_pubkey,
      fields.seq,
      fields.published_at,
      fields.title,
      fields.body,
      fields.supersedes,
      fields.ext,
    ]);
    expect(verify(a.channel_pubkey, specTbs, a.channel_signature)).toBe(true);
    expect(verify(a.agent_pubkey, specTbs, a.agent_signature)).toBe(true);
    expect(encodeBroadcastArtifact(a)).toEqual(encodeBroadcastArtifact(a));
  });

  it("5. flipping any field breaks BOTH signatures", async () => {
    const a = await signed({ seq: 3, supersedes: 2 });
    expect(verifyBroadcastArtifact(a)).toEqual({ ok: true });
    const flip = (b: Uint8Array): Uint8Array => {
      const c = new Uint8Array(b);
      c[0] ^= 0x01;
      return c;
    };
    const cases: Array<[string, (x: BroadcastArtifact) => BroadcastArtifact]> = [
      ["seq", (x) => ({ ...x, seq: x.seq + 1 })],
      ["published_at", (x) => ({ ...x, published_at: x.published_at + 1 })],
      ["title", (x) => ({ ...x, title: x.title + "x" })],
      ["body", (x) => ({ ...x, body: flip(x.body) })],
      ["supersedes", (x) => ({ ...x, supersedes: 1 })],
      ["channel_pubkey", (x) => ({ ...x, channel_pubkey: flip(x.channel_pubkey) })],
      ["agent_pubkey", (x) => ({ ...x, agent_pubkey: flip(x.agent_pubkey) })],
    ];
    for (const [field, mutate] of cases) {
      const mutated = mutate(a);
      // Name the failing side: a mutation that only broke one signature would still be refused,
      // and this test would pass while the other signature covered nothing.
      const channelOnly = verify(
        mutated.channel_pubkey,
        encodeCbor(slotsOf(mutated).slice(0, 9)),
        mutated.channel_signature,
      );
      const agentOnly = verify(
        mutated.agent_pubkey,
        encodeCbor(slotsOf(mutated).slice(0, 9)),
        mutated.agent_signature,
      );
      expect({ field, channelOnly, agentOnly, verified: verifyBroadcastArtifact(mutated).ok }).toEqual({
        field,
        channelOnly: false,
        agentOnly: false,
        verified: false,
      });
    }
  });

  it("5b. one good signature and one forged one is refused, naming which side failed", async () => {
    const channel = generateKeypair();
    const agent = generateKeypair();
    const impostor = generateKeypair();
    const fields = makeFields();

    // Valid channel signature, agent signature made by a key that is not `agent_pubkey`.
    const good = await signBroadcastArtifact(channel, agent, fields);
    const forgedAgent = await signBroadcastArtifact(channel, impostor, fields);
    const agentBad: BroadcastArtifact = { ...good, agent_signature: forgedAgent.agent_signature };
    expect(verifyBroadcastArtifact(agentBad)).toEqual({ ok: false, reason: "agent_signature_invalid" });

    // And the reverse.
    const forgedChannel = await signBroadcastArtifact(impostor, agent, fields);
    const channelBad: BroadcastArtifact = { ...good, channel_signature: forgedChannel.channel_signature };
    expect(verifyBroadcastArtifact(channelBad)).toEqual({ ok: false, reason: "channel_signature_invalid" });

    // A post signed entirely by one key pair does not verify against the other's pubkey either.
    const other = await generateKeypair().getPublicKey();
    expect(verifyBroadcastArtifact({ ...good, channel_pubkey: other }).ok).toBe(false);
    expect(verifyBroadcastArtifact({ ...good, agent_pubkey: other }).ok).toBe(false);
  });

  it("6. the old ten-slot epoch shape fails wrong_shape", async () => {
    const a = await signed();
    const epochShape = encodeCbor([
      BROADCAST_ARTIFACT_DOMAIN,
      a.channel_pubkey,
      a.seq,
      1, // epoch_index
      a.title,
      a.body,
      a.supersedes,
      null, // prev_epoch_root
      a.ext,
      a.channel_signature,
    ]);
    const d = decodeBroadcastArtifact(epochShape);
    expect(d.ok ? "ok" : d.reason).toBe("wrong_shape");
  });

  it("7. published_at must be a safe integer >= 1", async () => {
    const a = await signed();
    for (const bad of [0, -1, 1.5, "now", null]) {
      const d = decodeBroadcastArtifact(withSlot(a, 4, bad));
      expect({ bad, got: d.ok ? "ok" : d.reason }).toEqual({ bad, got: "bad_published_at" });
    }
    await expect(
      signBroadcastArtifact(generateKeypair(), generateKeypair(), makeFields({ published_at: 0 })),
    ).rejects.toThrow(RangeError);
  });

  it("8. title, body and supersedes limits are unchanged, and decode names each field", async () => {
    expect(validateBroadcastTitle("").ok).toBe(false);
    expect(validateBroadcastTitle("🚨".repeat(200)).ok).toBe(true);
    expect(validateBroadcastTitle("🚨".repeat(201)).ok).toBe(false);
    expect(validateBroadcastTitle("a b").ok).toBe(false);
    expect(validateBroadcastTitle("a\nb").ok).toBe(false);
    expect(validateBroadcastTitle("a".repeat(MAX_BROADCAST_TITLE_CHARS)).ok).toBe(true);
    // An unpaired surrogate is rewritten to U+FFFD by UTF-8 encoding, so a title carrying one signs
    // fine and then fails verification for every subscriber. Refuse it before signing.
    expect(validateBroadcastTitle("t\uD800x").ok).toBe(false);

    const a = await signed({ seq: 3, supersedes: 2 });
    const cases: Array<[string, Uint8Array]> = [
      ["not_cbor", new Uint8Array([0xfe, 0x3c, 0x9a, 0x17, 0x44])],
      ["wrong_shape", encodeCbor(slotsOf(a).slice(0, 10))],
      ["wrong_domain", withSlot(a, 0, "cello-trust-signal-v1")],
      ["bad_channel_pubkey", withSlot(a, 1, new Uint8Array(31))],
      ["bad_agent_pubkey", withSlot(a, 2, new Uint8Array(31))],
      ["bad_seq", withSlot(a, 3, 0)],
      ["bad_seq", withSlot(a, 3, 1.5)],
      ["bad_title", withSlot(a, 5, "badtitle")],
      ["body_too_large", withSlot(a, 6, new Uint8Array(MAX_BROADCAST_BODY_BYTES + 1))],
      ["bad_supersedes", withSlot(a, 7, a.seq)],
      ["bad_supersedes", withSlot(a, 7, 0)],
      ["ext_not_null", withSlot(a, 8, 7)],
      ["bad_signature_shape", withSlot(a, 9, new Uint8Array(63))],
      ["bad_signature_shape", withSlot(a, 10, new Uint8Array(63))],
      ["wrong_shape", floatSeq(a)],
    ];
    for (const [reason, bytes] of cases) {
      const d = decodeBroadcastArtifact(bytes);
      expect({ expected: reason, got: d.ok ? "ok" : d.reason }).toEqual({ expected: reason, got: reason });
    }

    // Adversarial CBOR is refused, never thrown.
    for (const bytes of [new Uint8Array(0), encodeCbor({ a: 1 }), encodeCbor(7), new Uint8Array(1024).fill(0xff)]) {
      let result: ReturnType<typeof decodeBroadcastArtifact> | undefined;
      expect(() => {
        result = decodeBroadcastArtifact(bytes);
      }).not.toThrow();
      expect(result?.ok).toBe(false);
    }

    await expect(
      signBroadcastArtifact(generateKeypair(), generateKeypair(), makeFields({ title: "é".repeat(201) })),
    ).rejects.toThrow(RangeError);
  });
});
