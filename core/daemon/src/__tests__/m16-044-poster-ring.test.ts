/**
 * M16 044-POSTERBELL Part C — the poster rings the members itself.
 *
 * After a poster publish that at least one relay accepted, the poster's daemon sends ONE wake on its
 * own directory stream: the channel, the stored members minus itself, its pass, and one relay
 * receipt from this publish. A publish no relay accepted rings nobody (there is no receipt to prove
 * it), and a ring that is refused or fails never touches the publish — the members' backstop poll
 * catches them.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeypair, generateGroupKey } from "@cello-protocol/crypto";
import type { InMemoryKeyProvider } from "@cello-protocol/crypto";
import { encodeChannelPosterPass, signChannelPosterPass } from "@cello-protocol/protocol-types";
import { createPosterWakeSender, type WakeSignaling } from "../channel-wake-sender.js";
import { ChannelLogStore } from "../channel-log-store.js";
import { ChannelSubscriptionStore } from "../channel-subscription-store.js";
import { ChannelPosterPublisher } from "../channel-poster-publisher.js";
import { openTestDb } from "./helpers/encrypted-db.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";
import type { Logger } from "../types.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };
const NOW = 1_800_000_000_000;
const DAY = 86_400_000;
const RELAY_A = "/dns4/relay-a.example/tcp/443/tls/ws/p2p/12D3KooWJXHpnWQhGk3jXBJYdXMmeLxEhRqzwZCYd1bxSUh4pg83";
const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

const OWN = "0f".repeat(32);
const M1 = "a1".repeat(32);
const M2 = "b2".repeat(32);

/** A signaling stub that records every frame it was handed. */
function signalingRecorder(over: { ok?: boolean; reason?: string; throws?: boolean } = {}) {
  const frames: Array<Record<string, unknown>> = [];
  const signaling: WakeSignaling = {
    sendRaw: (frame) => {
      frames.push(frame as Record<string, unknown>);
      if (over.throws) return Promise.reject(new Error("stream dead"));
      return Promise.resolve({ ok: over.ok ?? true, ...(over.reason ? { reason: over.reason } : {}) });
    },
  };
  return { frames, signaling };
}

describe("044-POSTERBELL Part C — createPosterWakeSender", () => {
  it("1. rings ONE wake with the channel, the members minus self, the pass and the receipt", async () => {
    const rec = signalingRecorder();
    const passCbor = new Uint8Array([1, 2, 3]);
    const receipt = new Uint8Array([9, 9, 9]);
    const ring = createPosterWakeSender({
      logger: silent,
      posterPassFor: () => ({ pass_cbor: passCbor, members: [OWN, M1, M2] }),
      ownPubkeyHex: () => OWN,
      signalingFor: () => rec.signaling,
      resolveAgentId: (name) => `id-${name}`,
    });
    await ring("bob", "cc".repeat(32), receipt);
    // Give the un-awaited sendRaw a tick to run.
    await new Promise((r) => setTimeout(r, 0));

    expect(rec.frames).toHaveLength(1);
    const f = rec.frames[0]!;
    expect(f["type"]).toBe("channel_wake_request");
    expect(hex(f["channel_pubkey"] as Uint8Array)).toBe("cc".repeat(32));
    expect((f["agent_pubkeys"] as Uint8Array[]).map(hex).sort()).toEqual([M1, M2].sort());
    expect(hex(f["poster_pass"] as Uint8Array)).toBe(hex(passCbor));
    expect(hex(f["relay_receipt"] as Uint8Array)).toBe(hex(receipt));
  });

  it("2. with no members but itself, it rings nobody", async () => {
    const rec = signalingRecorder();
    const ring = createPosterWakeSender({
      logger: silent,
      posterPassFor: () => ({ pass_cbor: new Uint8Array([1]), members: [OWN] }),
      ownPubkeyHex: () => OWN,
      signalingFor: () => rec.signaling,
      resolveAgentId: (name) => `id-${name}`,
    });
    await ring("bob", "cc".repeat(32), new Uint8Array([9]));
    await new Promise((r) => setTimeout(r, 0));
    expect(rec.frames).toEqual([]);
  });

  it("3. no held pass, or no directory stream, rings nobody and does not throw", async () => {
    const rec = signalingRecorder();
    const noPass = createPosterWakeSender({
      logger: silent, posterPassFor: () => null, ownPubkeyHex: () => OWN,
      signalingFor: () => rec.signaling, resolveAgentId: (n) => `id-${n}`,
    });
    await noPass("bob", "cc".repeat(32), new Uint8Array([9]));
    const noStream = createPosterWakeSender({
      logger: silent, posterPassFor: () => ({ pass_cbor: new Uint8Array([1]), members: [M1] }),
      ownPubkeyHex: () => OWN, signalingFor: () => null, resolveAgentId: (n) => `id-${n}`,
    });
    await noStream("bob", "cc".repeat(32), new Uint8Array([9]));
    await new Promise((r) => setTimeout(r, 0));
    expect(rec.frames).toEqual([]);
  });

  it("4. a refused or failed ring never throws", async () => {
    for (const over of [{ ok: false, reason: "rate_limited" }, { throws: true }]) {
      const rec = signalingRecorder(over);
      const ring = createPosterWakeSender({
        logger: silent, posterPassFor: () => ({ pass_cbor: new Uint8Array([1]), members: [M1] }),
        ownPubkeyHex: () => OWN, signalingFor: () => rec.signaling, resolveAgentId: (n) => `id-${n}`,
      });
      await expect(ring("bob", "cc".repeat(32), new Uint8Array([9]))).resolves.toBeUndefined();
      await new Promise((r) => setTimeout(r, 0));
    }
  });
});

// A poster publish where NO relay accepts must hand up no receipt, so the daemon rings nobody.
describe("044-POSTERBELL Part C — no relay accepted → no receipt to ring with", () => {
  let dir: string;
  let db: DaemonDatabase;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "cello-m16-044c-"));
    db = openTestDb(join(dir, "sessions.db"));
  });
  afterEach(() => { db.close(); rmSync(dir, { recursive: true, force: true }); });

  it("a poster publish every relay refused is ok:false with no poster_receipt_cbor", async () => {
    const channel = generateKeypair();
    const channelHex = hex(await channel.getPublicKey());
    const bob = generateKeypair();
    const log = new ChannelLogStore(db, silent);
    const subs = new ChannelSubscriptionStore(db, silent);
    const passes = new (await import("../channel-poster-pass-store.js")).ChannelPosterPassStore(db, silent);
    subs.upsert({ agent_id: `id-bob`, channel_pubkey: channelHex, admin_pubkey: "ad".repeat(32), access: "public", relays: [RELAY_A] });
    const pass = await signChannelPosterPass(channel, { poster_pubkey: await bob.getPublicKey(), issued_at: NOW - DAY, expires_at: NOW + DAY });
    passes.put(`id-bob`, channelHex, { pass_cbor: encodeChannelPosterPass(pass), issued_at: NOW - DAY, expires_at: NOW + DAY, members: [] });

    const pub = new ChannelPosterPublisher({
      logger: silent, log, passes, subscriptions: subs,
      resolveAgentId: (name) => `id-${name}`,
      getAgentKey: (name) => (name === "bob" ? bob : null),
      screenOutbound: () => Promise.resolve({ disposition: "allow" }),
      now: () => NOW,
      // Every relay refuses.
      deposit: () => Promise.resolve({ ok: false, reason: "not_a_channel" }),
    });
    const r = await pub.publish("bob", channelHex, "t", "b");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("no_relay_accepted");
    expect((r as { poster_receipt_cbor?: Uint8Array }).poster_receipt_cbor).toBeUndefined();
  });

  // 044-POSTERBELL Part E2: a removed poster's post is refused by the relays with pass_revoked — the
  // publisher surfaces THAT reason (not no_relay_accepted) and drops the post from the lane so it is
  // never resendable.
  it("every relay refusing pass_revoked surfaces pass_revoked and drops the lane", async () => {
    const channel = generateKeypair();
    const channelHex = hex(await channel.getPublicKey());
    const bob = generateKeypair();
    const bobHex = hex(await bob.getPublicKey());
    const log = new ChannelLogStore(db, silent);
    const subs = new ChannelSubscriptionStore(db, silent);
    const passes = new (await import("../channel-poster-pass-store.js")).ChannelPosterPassStore(db, silent);
    subs.upsert({ agent_id: `id-bob`, channel_pubkey: channelHex, admin_pubkey: "ad".repeat(32), access: "public", relays: [RELAY_A] });
    const pass = await signChannelPosterPass(channel, { poster_pubkey: await bob.getPublicKey(), issued_at: NOW - DAY, expires_at: NOW + DAY });
    passes.put(`id-bob`, channelHex, { pass_cbor: encodeChannelPosterPass(pass), issued_at: NOW - DAY, expires_at: NOW + DAY, members: [] });

    const pub = new ChannelPosterPublisher({
      logger: silent, log, passes, subscriptions: subs,
      resolveAgentId: (name) => `id-${name}`,
      getAgentKey: (name) => (name === "bob" ? bob : null),
      screenOutbound: () => Promise.resolve({ disposition: "allow" }),
      now: () => NOW,
      deposit: () => Promise.resolve({ ok: false, reason: "pass_revoked" }),
    });
    const r = await pub.publish("bob", channelHex, "t", "b");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("pass_revoked");
    // The lane was dropped: nothing left to resend.
    const lane = `${channelHex}/${bobHex}`;
    log.ensureChannel(lane);
    expect(log.head(lane).last_seq).toBeNull();
  });
});
