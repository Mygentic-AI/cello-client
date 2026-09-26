/**
 * M16 043-POSTERS Part C — posting as a poster, and receiving a pass.
 *
 * An agent that does not hold the channel key posts under a pass the admin sent it: an unexpired
 * pass is required (no_posting_pass), a non-public channel encrypts under the member's newest group
 * key (channel_group_key_unavailable — never plaintext), the post is numbered in the agent's own
 * LANE of the log, signed with signPosterPost, and deposited to the subscription row's relays.
 * A pass arrives over a sealed session and is stored only when it comes from the stored admin.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeypair, generateGroupKey, decryptBody } from "@cello-protocol/crypto";
import type { InMemoryKeyProvider, GroupKey } from "@cello-protocol/crypto";
import {
  decodeBroadcastArtifact, encodeChannelPosterPass, encodeChannelPosterPassFrame, posterPassOf,
  signChannelPosterPass, signRelayPostReceipt, encodeRelayPostReceipt, verifyBroadcastArtifact,
} from "@cello-protocol/protocol-types";
import { ChannelLogStore } from "../channel-log-store.js";
import { ChannelSubscriptionStore } from "../channel-subscription-store.js";
import { ChannelMembershipStore } from "../channel-membership-store.js";
import { ChannelPosterPassStore } from "../channel-poster-pass-store.js";
import { ChannelPosterPublisher } from "../channel-poster-publisher.js";
import { createChannelJoinExchange } from "../channel-join-exchange.js";
import { openTestDb } from "./helpers/encrypted-db.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";
import type { Logger } from "../types.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };
const RELAY_A = "/dns4/relay-a.example/tcp/443/tls/ws/p2p/12D3KooWJXHpnWQhGk3jXBJYdXMmeLxEhRqzwZCYd1bxSUh4pg83";
const RELAY_B = "/dns4/relay-b.example/tcp/443/tls/ws/p2p/12D3KooWPjceQrSwdWXPyLLeABRXmuqt69Rg3sBYbU1Nft9HyQ6X";
const NOW = 1_800_000_000_000;
const DAY = 86_400_000;
const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

let dir: string;
let db: DaemonDatabase;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "cello-m16-043c-"));
  db = openTestDb(join(dir, "sessions.db"));
});
afterEach(() => {
  db.close();
  rmSync(dir, { recursive: true, force: true });
});

interface H {
  pub: ChannelPosterPublisher; log: ChannelLogStore; subs: ChannelSubscriptionStore; passes: ChannelPosterPassStore;
  channel: InMemoryKeyProvider; admin: InMemoryKeyProvider; channelHex: string;
  deposits: Array<{ relay: string; post_cbor: Uint8Array; fetch_key?: unknown }>;
  relayHeld: Map<string, Set<string>>;
  agents: Map<string, InMemoryKeyProvider>;
  gk: GroupKey;
}

async function harness(): Promise<H> {
  const channel = generateKeypair();
  const admin = generateKeypair();
  const channelHex = hex(await channel.getPublicKey());
  const log = new ChannelLogStore(db, silent);
  const subs = new ChannelSubscriptionStore(db, silent);
  const passes = new ChannelPosterPassStore(db, silent);
  const agents = new Map<string, InMemoryKeyProvider>();
  const relayKey = generateKeypair();
  const deposits: H["deposits"] = [];
  const relayHeld = new Map<string, Set<string>>();
  const pub = new ChannelPosterPublisher({
    logger: silent, log, passes, subscriptions: subs,
    resolveAgentId: (name) => `id-${name}`,
    getAgentKey: (name) => agents.get(name) ?? null,
    screenOutbound: () => Promise.resolve({ disposition: "allow" }),
    now: () => NOW,
    resendPaceMs: 0,
    deposit: async (relay, req) => {
      deposits.push({ relay, post_cbor: req.post_cbor, ...(req.fetch_key ? { fetch_key: req.fetch_key } : {}) });
      const d = decodeBroadcastArtifact(req.post_cbor);
      if (!d.ok) return { ok: false, reason: "bad_post" };
      const held = relayHeld.get(relay) ?? new Set<string>();
      held.add(`${hex(d.artifact.agent_pubkey)}:${String(d.artifact.seq)}`);
      relayHeld.set(relay, held);
      return { ok: true, receipt_cbor: encodeRelayPostReceipt(await signRelayPostReceipt(relayKey, d.artifact, NOW)) };
    },
  });
  return { pub, log, subs, passes, channel, admin, channelHex, deposits, relayHeld, agents, gk: generateGroupKey(1) };
}

async function member(h: H, name: string, opts: { pass?: "valid" | "expired" | "none"; key?: boolean; access?: "invite_only" | "public" } = {}): Promise<InMemoryKeyProvider> {
  const kp = generateKeypair();
  h.agents.set(name, kp);
  h.subs.upsert({
    agent_id: `id-${name}`, channel_pubkey: h.channelHex, admin_pubkey: hex(await h.admin.getPublicKey()),
    access: opts.access ?? "invite_only", relays: [RELAY_A, RELAY_B], joined_at: NOW - DAY,
  });
  if (opts.key !== false) h.subs.addKey(`id-${name}`, h.channelHex, h.gk, NOW - DAY);
  const which = opts.pass ?? "valid";
  if (which !== "none") {
    const expires = which === "valid" ? NOW + 6 * DAY : NOW - 1;
    const pass = await signChannelPosterPass(h.channel, { poster_pubkey: await kp.getPublicKey(), issued_at: NOW - DAY, expires_at: expires });
    h.passes.put(`id-${name}`, h.channelHex, { pass_cbor: encodeChannelPosterPass(pass), issued_at: pass.issued_at, expires_at: pass.expires_at, members: [] });
  }
  return kp;
}

describe("043-POSTERS Part C — posting as a poster", () => {
  it("C1. no pass held → no_posting_pass, and nothing is logged or deposited", async () => {
    const h = await harness();
    await member(h, "bob", { pass: "none" });
    const r = await h.pub.publish("bob", h.channelHex, "t", "b");
    expect(r).toMatchObject({ ok: false, reason: "no_posting_pass" });
    expect(h.deposits.length).toBe(0);
  });

  it("C2. an expired pass → no_posting_pass", async () => {
    const h = await harness();
    await member(h, "bob", { pass: "expired" });
    expect(await h.pub.publish("bob", h.channelHex, "t", "b")).toMatchObject({ ok: false, reason: "no_posting_pass" });
    expect(h.deposits.length).toBe(0);
  });

  it("C3. a non-public channel with no group key → channel_group_key_unavailable, never plaintext", async () => {
    const h = await harness();
    await member(h, "bob", { key: false });
    expect(await h.pub.publish("bob", h.channelHex, "t", "secret body")).toMatchObject({ ok: false, reason: "channel_group_key_unavailable" });
    expect(h.deposits.length).toBe(0);
  });

  it("C4. two posters each post seq 1 in their own lane, encrypted, signed as poster posts, to both relays", async () => {
    const h = await harness();
    const bob = await member(h, "bob");
    const carol = await member(h, "carol");
    const rb = await h.pub.publish("bob", h.channelHex, "from bob", "hello from bob");
    const rc = await h.pub.publish("carol", h.channelHex, "from carol", "hello from carol");
    expect(rb).toMatchObject({ ok: true, seq: 1 });
    expect(rc).toMatchObject({ ok: true, seq: 1 });
    // 044-POSTERBELL: a successful poster publish hands up one verified relay receipt so the daemon
    // can ring the members.
    if (rb.ok) expect(rb.poster_receipt_cbor).toBeInstanceOf(Uint8Array);
    expect(h.deposits.map((d) => d.relay).sort()).toEqual([RELAY_A, RELAY_A, RELAY_B, RELAY_B]);
    for (const d of h.deposits) {
      expect(d.fetch_key).toBeUndefined();
      const a = decodeBroadcastArtifact(d.post_cbor);
      if (!a.ok) throw new Error(a.reason);
      expect(verifyBroadcastArtifact(a.artifact)).toEqual({ ok: true });
      expect(a.artifact.channel_signature.length).toBe(0);
      expect(hex(posterPassOf(a.artifact)!.poster_pubkey)).toBe(hex(a.artifact.agent_pubkey));
      const opened = decryptBody([h.gk], a.artifact.channel_pubkey, a.artifact.seq, a.artifact.body);
      expect(opened.ok).toBe(true);
    }
    const bobLane = `${h.channelHex}/${hex(await bob.getPublicKey())}`;
    const carolLane = `${h.channelHex}/${hex(await carol.getPublicKey())}`;
    expect(h.log.head(bobLane).last_seq).toBe(1);
    expect(h.log.head(carolLane).last_seq).toBe(1);
    // A second post from bob is seq 2 in bob's lane only.
    expect(await h.pub.publish("bob", h.channelHex, "again", "x")).toMatchObject({ ok: true, seq: 2 });
    expect(h.log.head(carolLane).last_seq).toBe(1);
  });

  it("C5. a public channel posts in clear (no group key needed)", async () => {
    const h = await harness();
    await member(h, "bob", { key: false, access: "public" });
    const r = await h.pub.publish("bob", h.channelHex, "t", "plain");
    expect(r).toMatchObject({ ok: true, seq: 1 });
    const a = decodeBroadcastArtifact(h.deposits[0]!.post_cbor);
    expect(a.ok && Buffer.from(a.artifact.body).toString()).toBe("plain");
  });

  it("C6. resend re-deposits the lane's posts a relay no longer holds", async () => {
    const h = await harness();
    const bob = await member(h, "bob");
    await h.pub.publish("bob", h.channelHex, "one", "1");
    await h.pub.publish("bob", h.channelHex, "two", "2");
    h.deposits.length = 0;
    const r = await h.pub.resendMissing("bob", h.channelHex, RELAY_B);
    // 044-POSTERBELL: a poster resend also carries one verified receipt up, so it can ring the members.
    expect(r.deposited).toBe(2);
    expect(r.poster_receipt_cbor).toBeInstanceOf(Uint8Array);
    expect(h.deposits.every((d) => d.relay === RELAY_B)).toBe(true);
    expect(h.deposits.map((d) => { const a = decodeBroadcastArtifact(d.post_cbor); return a.ok ? hex(a.artifact.agent_pubkey) : ""; }))
      .toEqual([hex(await bob.getPublicKey()), hex(await bob.getPublicKey())]);
    expect(await h.pub.resendMissing("carol", h.channelHex, RELAY_B)).toMatchObject({ deposited: 0, refused: "no_posting_pass" });
  });
});

describe("043-POSTERS Part C — receiving a pass", () => {
  async function exchangeHarness(): Promise<{
    ex: ReturnType<typeof createChannelJoinExchange>; h: H; bob: InMemoryKeyProvider;
  }> {
    const h = await harness();
    const bob = await member(h, "bob", { pass: "none" });
    const ex = createChannelJoinExchange({
      logger: silent, members: new ChannelMembershipStore(db, silent), subscriptions: h.subs,
      sendInSession: () => Promise.resolve(), localChannelAdmin: () => null,
      profileAdminPubkey: () => Promise.resolve({ ok: false, reason: "unused" }),
      keyProviderFor: (id) => (id === "id-bob" ? bob : null), raiseNotice: () => {},
      posterPasses: h.passes, now: () => NOW,
    });
    return { ex, h, bob };
  }

  async function frameFor(h: H, poster: InMemoryKeyProvider, issued = NOW, signer = h.channel): Promise<Uint8Array> {
    const pass = await signChannelPosterPass(signer, { poster_pubkey: await poster.getPublicKey(), issued_at: issued, expires_at: issued + 7 * DAY });
    const bytes = encodeChannelPosterPass(signer === h.channel ? pass : { ...pass, channel_pubkey: await h.channel.getPublicKey() });
    return encodeChannelPosterPassFrame(bytes, []);
  }

  it("C7. a pass from the stored admin is stored; latest wins", async () => {
    const { ex, h, bob } = await exchangeHarness();
    const adminHex = hex(await h.admin.getPublicKey());
    expect((await ex.onSubscriberFrame("id-bob", "s1", adminHex, await frameFor(h, bob, NOW))).ok).toBe(true);
    expect(h.passes.get("id-bob", h.channelHex)?.issued_at).toBe(NOW);
    await ex.onSubscriberFrame("id-bob", "s1", adminHex, await frameFor(h, bob, NOW + 5));
    expect(h.passes.get("id-bob", h.channelHex)?.issued_at).toBe(NOW + 5);
    // An OLDER pass arriving late does not displace the newer one.
    await ex.onSubscriberFrame("id-bob", "s1", adminHex, await frameFor(h, bob, NOW + 1));
    expect(h.passes.get("id-bob", h.channelHex)?.issued_at).toBe(NOW + 5);
  });

  it("C8. a pass from anyone but the stored admin, for another agent, or not signed by the channel, is refused", async () => {
    const { ex, h, bob } = await exchangeHarness();
    const stranger = generateKeypair();
    const r1 = await ex.onSubscriberFrame("id-bob", "s1", hex(await stranger.getPublicKey()), await frameFor(h, bob));
    expect(r1).toMatchObject({ ok: false, reason: "not_admin_of_channel" });
    const adminHex = hex(await h.admin.getPublicKey());
    const r2 = await ex.onSubscriberFrame("id-bob", "s1", adminHex, await frameFor(h, stranger));
    expect(r2).toMatchObject({ ok: false, reason: "pass_invalid" });
    const r3 = await ex.onSubscriberFrame("id-bob", "s1", adminHex, await frameFor(h, bob, NOW, h.admin));
    expect(r3).toMatchObject({ ok: false, reason: "pass_invalid" });
    expect(h.passes.get("id-bob", h.channelHex)).toBeNull();
  });
});
