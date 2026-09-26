/**
 * M16 / 043-POSTERS Part A — the posting pass and the poster's post.
 *
 * The admin hands another agent a POSTING PASS signed by the CHANNEL key. The poster signs its post
 * with its own agent key only (zero-length channel signature) and carries the pass in `ext`. A post
 * is valid when it is an admin post exactly as before, or a poster post whose pass verifies against
 * the channel, names this agent, and had not expired when the post was written.
 *
 * Tests are RED-first. The admin post's bytes are pinned against hex captured BEFORE this change.
 */

import { setupV3Tests, describe, it, expect } from "@claude-flow/testing";
import { InMemoryKeyProvider, generateKeypair } from "@cello-protocol/crypto";
import { encodeCbor } from "../cbor.js";
import {
  BROADCAST_ARTIFACT_DOMAIN,
  decodeBroadcastArtifact,
  encodeBroadcastArtifact,
  posterPassOf,
  signBroadcastArtifact,
  signPosterPost,
  verifyBroadcastArtifact,
} from "../broadcast-artifact.js";
import type { BroadcastArtifact } from "../broadcast-artifact.js";
import {
  CHANNEL_POSTER_PASS_DOMAIN,
  decodeChannelPosterPass,
  encodeChannelPosterPass,
  signChannelPosterPass,
  verifyPosterPass,
} from "../channel-poster-pass.js";
import { decodeChannelInfo, encodeChannelInfo, signChannelInfo, channelPostingOf } from "../channel-info.js";

setupV3Tests();

const T0 = 1_758_000_000_000;
const DAY = 86_400_000;

/** Captured from `encodeBroadcastArtifact` at the commit BEFORE 043 (seeds 7/9, seq 3, supersedes 2). */
const ADMIN_POST_PIN =
  "8b781b63656c6c6f2d62726f6164636173742d61727469666163742d76315820ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c5820fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f61803fb4279950f72c000006f4465706c6f792066696e697368656448010203040506070802f65840a0246736c44e00f462a6910942f142c5f453bf14c0df8c79ec4a4a0a49290166afda1f47ee6cc75cc176b12e3e3e71a8d50b70a1908e0fe6122264b1c06905045840aa507cade9acbaf61da2ee6b62a3a64dac20794fb83ad756e869bbdd5d1445b71a9864e39250390a5aaa10799b841bf64d1a6db7b0357279ff4923274d2e6a01";

function hex(b: Uint8Array): string {
  return Buffer.from(b).toString("hex");
}

async function passFor(
  channel: InMemoryKeyProvider,
  poster: InMemoryKeyProvider,
  window: { issued_at?: number; expires_at?: number } = {},
): Promise<Uint8Array> {
  const pass = await signChannelPosterPass(channel, {
    poster_pubkey: await poster.getPublicKey(),
    issued_at: window.issued_at ?? T0,
    expires_at: window.expires_at ?? T0 + 7 * DAY,
  });
  return encodeChannelPosterPass(pass);
}

async function posterPost(
  channel: InMemoryKeyProvider,
  poster: InMemoryKeyProvider,
  passBytes: Uint8Array,
  published_at = T0 + DAY,
): Promise<BroadcastArtifact> {
  return signPosterPost(
    poster,
    {
      channel_pubkey: await channel.getPublicKey(),
      seq: 1,
      published_at,
      title: "From a poster",
      body: new Uint8Array([9, 9, 9]),
      supersedes: null,
    },
    passBytes,
  );
}

describe("043-POSTERS Part A — the posting pass", () => {
  it("A1. sign → encode → decode → verify round-trips, and the TBS is the spec's slot order", async () => {
    const channel = generateKeypair();
    const poster = generateKeypair();
    const bytes = await passFor(channel, poster);
    const d = decodeChannelPosterPass(bytes);
    expect(d.ok).toBe(true);
    if (!d.ok) return;
    expect(d.pass.channel_pubkey).toEqual(await channel.getPublicKey());
    expect(d.pass.poster_pubkey).toEqual(await poster.getPublicKey());
    expect(d.pass.issued_at).toBe(T0);
    expect(d.pass.expires_at).toBe(T0 + 7 * DAY);
    expect(verifyPosterPass(d.pass, await channel.getPublicKey())).toEqual({ ok: true });
    // Independent preimage: the spec's five slots, signed by the channel key.
    const specTbs = encodeCbor([
      CHANNEL_POSTER_PASS_DOMAIN,
      await channel.getPublicKey(),
      await poster.getPublicKey(),
      T0,
      T0 + 7 * DAY,
    ]);
    expect(hex(bytes)).toBe(hex(encodeCbor([
      CHANNEL_POSTER_PASS_DOMAIN, await channel.getPublicKey(), await poster.getPublicKey(), T0, T0 + 7 * DAY,
      await channel.sign(specTbs),
    ])));
  });

  it("A2. a pass verified against another channel, or signed by the poster's own key, is refused", async () => {
    const channel = generateKeypair();
    const poster = generateKeypair();
    const d = decodeChannelPosterPass(await passFor(channel, poster));
    if (!d.ok) throw new Error("fixture");
    expect(verifyPosterPass(d.pass, await generateKeypair().getPublicKey())).toEqual({ ok: false, reason: "wrong_channel" });
    // A self-issued pass: the poster signs a pass naming the channel.
    const forged = await signChannelPosterPass(poster, {
      poster_pubkey: await poster.getPublicKey(), issued_at: T0, expires_at: T0 + DAY,
    });
    const f = decodeChannelPosterPass(encodeCbor([
      CHANNEL_POSTER_PASS_DOMAIN, await channel.getPublicKey(), forged.poster_pubkey, T0, T0 + DAY, forged.signature,
    ]));
    if (!f.ok) throw new Error("fixture");
    expect(verifyPosterPass(f.pass, await channel.getPublicKey())).toEqual({ ok: false, reason: "signature_invalid" });
  });

  it("A3. decode names each malformed field and never throws", async () => {
    const c = new Uint8Array(32).fill(1);
    const p = new Uint8Array(32).fill(2);
    const s = new Uint8Array(64);
    const cases: Array<[string, Uint8Array]> = [
      ["not_cbor", new Uint8Array([0xfe, 0x3c])],
      ["wrong_shape", encodeCbor([CHANNEL_POSTER_PASS_DOMAIN, c, p, T0, T0 + 1])],
      ["wrong_domain", encodeCbor(["cello-channel-info-v1", c, p, T0, T0 + 1, s])],
      ["bad_channel_pubkey", encodeCbor([CHANNEL_POSTER_PASS_DOMAIN, new Uint8Array(31), p, T0, T0 + 1, s])],
      ["bad_poster_pubkey", encodeCbor([CHANNEL_POSTER_PASS_DOMAIN, c, new Uint8Array(31), T0, T0 + 1, s])],
      ["bad_issued_at", encodeCbor([CHANNEL_POSTER_PASS_DOMAIN, c, p, 0, T0 + 1, s])],
      ["bad_expires_at", encodeCbor([CHANNEL_POSTER_PASS_DOMAIN, c, p, T0, T0, s])],
      ["bad_signature_shape", encodeCbor([CHANNEL_POSTER_PASS_DOMAIN, c, p, T0, T0 + 1, new Uint8Array(63)])],
    ];
    for (const [reason, bytes] of cases) {
      const d = decodeChannelPosterPass(bytes);
      expect({ expected: reason, got: d.ok ? "ok" : d.reason }).toEqual({ expected: reason, got: reason });
    }
  });
});

describe("043-POSTERS Part A — the poster's post", () => {
  it("A4. an admin post's bytes are exactly the pre-043 bytes, and it still verifies", async () => {
    const a = await signBroadcastArtifact(
      new InMemoryKeyProvider(new Uint8Array(32).fill(7)),
      new InMemoryKeyProvider(new Uint8Array(32).fill(9)),
      { seq: 3, published_at: T0, title: "Deploy finished", body: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]), supersedes: 2, ext: null },
    );
    expect(hex(encodeBroadcastArtifact(a))).toBe(ADMIN_POST_PIN);
    expect(verifyBroadcastArtifact(a)).toEqual({ ok: true });
    expect(posterPassOf(a)).toBeNull();
  });

  it("A5. a valid poster post round-trips, verifies, has a zero-length channel signature, and exposes its pass", async () => {
    const channel = generateKeypair();
    const poster = generateKeypair();
    const a = await posterPost(channel, poster, await passFor(channel, poster));
    expect(a.channel_signature.length).toBe(0);
    const d = decodeBroadcastArtifact(encodeBroadcastArtifact(a));
    expect(d.ok).toBe(true);
    if (!d.ok) return;
    expect(d.artifact.agent_pubkey).toEqual(await poster.getPublicKey());
    expect(verifyBroadcastArtifact(d.artifact)).toEqual({ ok: true });
    const pass = posterPassOf(d.artifact);
    expect(pass?.poster_pubkey).toEqual(await poster.getPublicKey());
    expect(pass?.expires_at).toBe(T0 + 7 * DAY);
  });

  it("A6. pass_invalid: a pass from another channel, or garbage pass bytes", async () => {
    const channel = generateKeypair();
    const poster = generateKeypair();
    const other = generateKeypair();
    const a = await posterPost(channel, poster, await passFor(other, poster));
    expect(verifyBroadcastArtifact(a)).toEqual({ ok: false, reason: "pass_invalid" });
    const g = await posterPost(channel, poster, new Uint8Array([1, 2, 3]));
    expect(verifyBroadcastArtifact(g)).toEqual({ ok: false, reason: "pass_invalid" });
  });

  it("A7. pass_not_for_this_agent: agent B posts with agent A's pass", async () => {
    const channel = generateKeypair();
    const a = generateKeypair();
    const b = generateKeypair();
    const post = await posterPost(channel, b, await passFor(channel, a));
    expect(verifyBroadcastArtifact(post)).toEqual({ ok: false, reason: "pass_not_for_this_agent" });
  });

  it("A8. pass_expired: published after expires_at; at expires_at exactly is still valid", async () => {
    const channel = generateKeypair();
    const poster = generateKeypair();
    const pass = await passFor(channel, poster, { expires_at: T0 + DAY });
    expect(verifyBroadcastArtifact(await posterPost(channel, poster, pass, T0 + DAY + 1))).toEqual({ ok: false, reason: "pass_expired" });
    expect(verifyBroadcastArtifact(await posterPost(channel, poster, pass, T0 + DAY))).toEqual({ ok: true });
  });

  it("A9. agent_signature is still required on a poster post", async () => {
    const channel = generateKeypair();
    const poster = generateKeypair();
    const a = await posterPost(channel, poster, await passFor(channel, poster));
    const forged = { ...a, agent_signature: await generateKeypair().sign(new Uint8Array([1])) };
    expect(verifyBroadcastArtifact(forged)).toEqual({ ok: false, reason: "agent_signature_invalid" });
  });

  it("A10. decode pairs the signature with ext: a pass with a 64-byte channel signature, or no pass with a zero-length one, is bad_signature_shape; a non-map ext is bad_ext", async () => {
    const channel = generateKeypair();
    const poster = generateKeypair();
    const p = await posterPost(channel, poster, await passFor(channel, poster));
    const slots = (x: BroadcastArtifact, i: number, v: unknown): Uint8Array => {
      const s: unknown[] = [BROADCAST_ARTIFACT_DOMAIN, x.channel_pubkey, x.agent_pubkey, x.seq, x.published_at,
        x.title, x.body, x.supersedes, x.ext === null ? null : new Map([[1, x.ext.poster_pass]]),
        x.channel_signature, x.agent_signature];
      s[i] = v;
      return encodeCbor(s);
    };
    const pick = (b: Uint8Array): string => { const d = decodeBroadcastArtifact(b); return d.ok ? "ok" : d.reason; };
    expect(pick(slots(p, 9, new Uint8Array(64)))).toBe("bad_signature_shape");
    expect(pick(slots(p, 8, null))).toBe("bad_signature_shape");
    expect(pick(slots(p, 8, 7))).toBe("bad_ext");
    expect(pick(slots(p, 8, new Map([[2, p.ext?.poster_pass]])))).toBe("bad_ext");
    expect(pick(slots(p, 8, new Map<number, unknown>([[1, p.ext?.poster_pass], [2, 1]])))).toBe("bad_ext");
    // A plain CBOR map whose key is the TEXT "1" is a second wire form and is refused.
    expect(pick(slots(p, 8, { 1: p.ext?.poster_pass }))).not.toBe("ok");
  });
});

describe("043-POSTERS Part A — the channel info record's posting setting", () => {
  const base = {
    access: "invite_only" as const,
    relays: ["/dns4/relay.example/tcp/443"],
    guidance: "g",
    retention_seconds: 3600,
    updated_at: T0,
  };

  it("A11. a missing ext means posting admin with no revocations", async () => {
    const channel = generateKeypair();
    const info = await signChannelInfo(channel, { ...base, admin_pubkey: new Uint8Array(32).fill(3), ext: null });
    const d = decodeChannelInfo(encodeChannelInfo(info));
    if (!d.ok) throw new Error(d.reason);
    expect(channelPostingOf(d.info)).toEqual({ posting: "admin", revoked: [] });
  });

  it("A12. ext {1: posting, 2: revocations} round-trips and is signed", async () => {
    const channel = generateKeypair();
    const revokedKey = new Uint8Array(32).fill(5);
    const info = await signChannelInfo(channel, {
      ...base, admin_pubkey: new Uint8Array(32).fill(3),
      ext: { posting: "listed", revoked: [{ poster_pubkey: revokedKey, revoked_at: T0 + 5 }] },
    });
    const d = decodeChannelInfo(encodeChannelInfo(info));
    if (!d.ok) throw new Error(d.reason);
    expect(channelPostingOf(d.info)).toEqual({ posting: "listed", revoked: [{ poster_pubkey: revokedKey, revoked_at: T0 + 5 }] });
    for (const posting of ["admin", "members"] as const) {
      const i2 = await signChannelInfo(channel, { ...base, admin_pubkey: new Uint8Array(32).fill(3), ext: { posting, revoked: [] } });
      const d2 = decodeChannelInfo(encodeChannelInfo(i2));
      expect(d2.ok && channelPostingOf(d2.info).posting).toBe(posting);
    }
  });

  it("A13. an unknown posting value or malformed revocation is bad_ext, and signing refuses it", async () => {
    const channel = generateKeypair();
    await expect(signChannelInfo(channel, {
      ...base, admin_pubkey: new Uint8Array(32).fill(3),
      // @ts-expect-error — an unknown posting value
      ext: { posting: "everyone", revoked: [] },
    })).rejects.toThrow(/bad_ext/);
    const good = await signChannelInfo(channel, { ...base, admin_pubkey: new Uint8Array(32).fill(3), ext: null });
    const withExt = (ext: unknown): Uint8Array => encodeCbor([
      "cello-channel-info-v1", good.channel_pubkey, good.access, good.admin_pubkey, good.relays, good.guidance,
      good.retention_seconds, good.updated_at, ext, good.signature,
    ]);
    for (const ext of [7, new Map<number, unknown>([[1, "everyone"], [2, []]]), new Map<number, unknown>([[1, "listed"], [2, [[new Uint8Array(31), 1]]]]),
      new Map<number, unknown>([[1, "listed"], [2, [[new Uint8Array(32), 0]]]]), new Map<number, unknown>([[1, "listed"]])]) {
      const d = decodeChannelInfo(withExt(ext));
      expect(d.ok ? "ok" : d.reason).toBe("bad_ext");
    }
  });
});
