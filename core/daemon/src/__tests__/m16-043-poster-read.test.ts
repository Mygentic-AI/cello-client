/**
 * M16 043-POSTERS Parts C+D — two posters and the admin on one channel; a member reads them all.
 *
 * The posters publish through the real ChannelPosterPublisher (Part C) into an in-memory relay that
 * keeps one queue per LANE, exactly as the relay does (Part B). The member's collector fetches the
 * admin lane as before, asks `channel_lanes`, fetches each poster lane from its own position, and
 * `read` returns every lane's unread posts merged in relay-receipt time order, each attributed.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeypair, generateGroupKey, encryptBody, decryptBody } from "@cello-protocol/crypto";
import type { InMemoryKeyProvider, GroupKey } from "@cello-protocol/crypto";
import {
  decodeBroadcastArtifact, encodeBroadcastArtifact, encodeChannelPosterPass, encodeRelayPostReceipt,
  signBroadcastArtifact, signChannelPosterPass, signPosterPost, signRelayPostReceipt,
} from "@cello-protocol/protocol-types";
import { ChannelLogStore } from "../channel-log-store.js";
import { ChannelSubscriptionStore } from "../channel-subscription-store.js";
import { ChannelInboxStore } from "../channel-inbox-store.js";
import { ChannelPosterPassStore } from "../channel-poster-pass-store.js";
import { ChannelLanePositionStore } from "../channel-lane-position-store.js";
import { ChannelPosterPublisher } from "../channel-poster-publisher.js";
import { ChannelCollector } from "../channel-collector.js";
import { createChannelSubscribe, type ChannelSubscribeDeps } from "../channel-subscribe.js";
import { openTestDb } from "./helpers/encrypted-db.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";
import type { Logger } from "../types.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };
const RELAY = "/dns4/relay-a.example/tcp/443/tls/ws/p2p/12D3KooWJXHpnWQhGk3jXBJYdXMmeLxEhRqzwZCYd1bxSUh4pg83";
const NOW = 1_800_000_000_000;
const DAY = 86_400_000;
const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

let dir: string;
let db: DaemonDatabase;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "cello-m16-043d-"));
  db = openTestDb(join(dir, "sessions.db"));
});
afterEach(() => {
  db.close();
  rmSync(dir, { recursive: true, force: true });
});

/** A relay that queues per lane: the channel hex for the admin, `<channel>/<poster>` for a poster. */
class LaneRelay {
  readonly lanes = new Map<string, Map<number, { post_cbor: Uint8Array; receipt_cbor: Uint8Array }>>();
  readonly key = generateKeypair();
  clock = NOW;
  /** Posts the relay "lost" — held back from every fetch. */
  readonly hidden = new Set<string>();

  async deposit(postCbor: Uint8Array): Promise<{ ok: true; receipt_cbor: Uint8Array } | { ok: false; reason: string }> {
    const d = decodeBroadcastArtifact(postCbor);
    if (!d.ok) return { ok: false, reason: "bad_post" };
    const a = d.artifact;
    const lane = a.ext === null ? hex(a.channel_pubkey) : `${hex(a.channel_pubkey)}/${hex(a.agent_pubkey)}`;
    this.clock += 1000;
    const receipt_cbor = encodeRelayPostReceipt(await signRelayPostReceipt(this.key, a, this.clock));
    const q = this.lanes.get(lane) ?? new Map();
    q.set(a.seq, { post_cbor: postCbor, receipt_cbor });
    this.lanes.set(lane, q);
    return { ok: true, receipt_cbor };
  }

  fetch(req: { channel_pubkey: Uint8Array; since_seq: number; lane_poster?: Uint8Array }) {
    const lane = req.lane_poster ? `${hex(req.channel_pubkey)}/${hex(req.lane_poster)}` : hex(req.channel_pubkey);
    const q = this.lanes.get(lane) ?? new Map();
    const seqs = [...q.keys()].sort((x, y) => x - y);
    const posts = seqs.filter((s) => s >= req.since_seq && !this.hidden.has(`${lane}#${String(s)}`))
      .map((s) => ({ seq: s, ...q.get(s)! }));
    return Promise.resolve({
      ok: true as const, posts,
      first_held_seq: seqs[0] ?? null, last_seq: seqs[seqs.length - 1] ?? null,
    });
  }

  lanesOf(channelPubkey: Uint8Array) {
    const prefix = `${hex(channelPubkey)}/`;
    const out: Array<{ poster_pubkey: Uint8Array; last_seq: number }> = [];
    for (const [k, q] of this.lanes) {
      if (!k.startsWith(prefix) || q.size === 0) continue;
      out.push({ poster_pubkey: new Uint8Array(Buffer.from(k.slice(prefix.length), "hex")), last_seq: Math.max(...q.keys()) });
    }
    return Promise.resolve({ ok: true as const, lanes: out });
  }
}

interface World {
  relay: LaneRelay; channel: InMemoryKeyProvider; admin: InMemoryKeyProvider; channelHex: string; gk: GroupKey;
  subs: ChannelSubscriptionStore; inbox: ChannelInboxStore; lanes: ChannelLanePositionStore;
  collector: ChannelCollector; read: ReturnType<typeof createChannelSubscribe>["read"];
  poster: ChannelPosterPublisher; agents: Map<string, InMemoryKeyProvider>; passes: ChannelPosterPassStore;
  adminSeq: number;
  revoked: { poster_pubkey: Uint8Array; revoked_at: number }[];
}

async function world(): Promise<World> {
  const relay = new LaneRelay();
  const channel = generateKeypair();
  const admin = generateKeypair();
  const channelHex = hex(await channel.getPublicKey());
  const gk = generateGroupKey(1);
  const subs = new ChannelSubscriptionStore(db, silent);
  const inbox = new ChannelInboxStore(db, silent);
  const lanes = new ChannelLanePositionStore(db, silent);
  const passes = new ChannelPosterPassStore(db, silent);
  const agents = new Map<string, InMemoryKeyProvider>();
  const revoked: World["revoked"] = [];
  const names = new Map<string, string>();
  const collector = new ChannelCollector({
    logger: silent, subscriptions: subs, inbox, lanePositions: lanes,
    fetch: (_r, req) => relay.fetch(req),
    lanes: (_r, req) => relay.lanesOf(req.channel_pubkey),
    fetchAuth: () => Promise.resolve(undefined),
    localAgentKeys: () => [], requestRepair: () => Promise.resolve(),
    revocations: () => Promise.resolve(revoked),
  });
  const { read } = createChannelSubscribe({
    logger: silent, subscriptions: subs, inbox, lanePositions: lanes,
    decrypt: (_a: string, ch: string, seq: number, body: Uint8Array) => {
      const r = decryptBody([gk], new Uint8Array(Buffer.from(ch, "hex")), seq, body);
      return Promise.resolve(r.ok ? r.plaintext : null);
    },
    posterName: (_agentId: string, pubkeyHex: string) => names.get(pubkeyHex) ?? null,
  } as unknown as ChannelSubscribeDeps);
  const poster = new ChannelPosterPublisher({
    logger: silent, log: new ChannelLogStore(db, silent), passes, subscriptions: subs,
    resolveAgentId: (n) => `id-${n}`, getAgentKey: (n) => agents.get(n) ?? null,
    screenOutbound: () => Promise.resolve({ disposition: "allow" }), now: () => NOW,
    deposit: (_r, req) => relay.deposit(req.post_cbor),
  });
  names.set(hex(await admin.getPublicKey()), "TheAdmin");
  // The reading member.
  subs.upsert({ agent_id: "id-reader", channel_pubkey: channelHex, admin_pubkey: hex(await admin.getPublicKey()), access: "invite_only", relays: [RELAY] });
  subs.addKey("id-reader", channelHex, gk, NOW);
  const w: World = { relay, channel, admin, channelHex, gk, subs, inbox, lanes, collector, read, poster, agents, passes, adminSeq: 0, revoked };
  (w as World & { names: Map<string, string> }).names = names;
  return w;
}

async function addPoster(w: World, name: string, moniker?: string): Promise<InMemoryKeyProvider> {
  const kp = generateKeypair();
  w.agents.set(name, kp);
  w.subs.upsert({ agent_id: `id-${name}`, channel_pubkey: w.channelHex, admin_pubkey: hex(await w.admin.getPublicKey()), access: "invite_only", relays: [RELAY] });
  w.subs.addKey(`id-${name}`, w.channelHex, w.gk, NOW);
  const pass = await signChannelPosterPass(w.channel, { poster_pubkey: await kp.getPublicKey(), issued_at: NOW - DAY, expires_at: NOW + 6 * DAY });
  w.passes.put(`id-${name}`, w.channelHex, { pass_cbor: encodeChannelPosterPass(pass), issued_at: pass.issued_at, expires_at: pass.expires_at });
  if (moniker) (w as World & { names: Map<string, string> }).names.set(hex(await kp.getPublicKey()), moniker);
  return kp;
}

async function adminPost(w: World, title: string): Promise<void> {
  w.adminSeq += 1;
  const cpk = await w.channel.getPublicKey();
  const a = await signBroadcastArtifact(w.channel, w.admin, {
    seq: w.adminSeq, published_at: NOW, title,
    body: encryptBody(w.gk, cpk, w.adminSeq, new TextEncoder().encode(`${title} body`)), supersedes: null, ext: null,
  });
  await w.relay.deposit(encodeBroadcastArtifact(a));
}

describe("043-POSTERS Parts C+D — a member reads every lane", () => {
  it("D1. admin + two posters: all posts read, merged in receipt order, attributed by moniker or short key", async () => {
    const w = await world();
    await addPoster(w, "bob", "Bob");
    const carol = await addPoster(w, "carol");
    await adminPost(w, "a1");
    expect(await w.poster.publish("bob", w.channelHex, "b1", "bob body 1")).toMatchObject({ ok: true, seq: 1 });
    expect(await w.poster.publish("carol", w.channelHex, "c1", "carol body 1")).toMatchObject({ ok: true, seq: 1 });
    await adminPost(w, "a2");
    expect(await w.poster.publish("bob", w.channelHex, "b2", "bob body 2")).toMatchObject({ ok: true, seq: 2 });

    await w.collector.collectOnce("id-reader", w.channelHex);
    const r = await w.read("id-reader", w.channelHex);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.posts.map((p) => p.title)).toEqual(["a1", "b1", "c1", "a2", "b2"]);
    expect(r.posts.map((p) => p.body)).toEqual(["a1 body", "bob body 1", "carol body 1", "a2 body", "bob body 2"]);
    const carolShort = hex(await carol.getPublicKey()).slice(0, 8);
    expect(r.posts.map((p) => p.poster)).toEqual(["TheAdmin", "Bob", carolShort, "TheAdmin", "Bob"]);
    // Everything read: a second read is empty, and the lane positions moved.
    const again = await w.read("id-reader", w.channelHex);
    expect(again.ok && again.posts.length).toBe(0);
    expect(w.lanes.unread("id-reader", w.channelHex)).toBe(0);
  });

  it("D2. a gap in one lane does not stall the others", async () => {
    const w = await world();
    const bob = await addPoster(w, "bob");
    await addPoster(w, "carol");
    for (const t of ["b1", "b2", "b3"]) await w.poster.publish("bob", w.channelHex, t, t);
    for (const t of ["c1", "c2"]) await w.poster.publish("carol", w.channelHex, t, t);
    await adminPost(w, "a1");
    w.relay.hidden.add(`${w.channelHex}/${hex(await bob.getPublicKey())}#2`);

    await w.collector.collectOnce("id-reader", w.channelHex);
    expect(w.lanes.unread("id-reader", w.channelHex)).toBe(3); // b1, c1, c2 — b3 waits behind the gap
    const r = await w.read("id-reader", w.channelHex);
    expect(r.ok && r.posts.map((p) => p.title)).toEqual(["b1", "c1", "c2", "a1"]);
  });

  it("D3. a poster-lane post without a valid pass for THIS channel, or by an agent other than the lane's, is dropped", async () => {
    const w = await world();
    const mallory = generateKeypair();
    const otherChannel = generateKeypair();
    const cpk = await w.channel.getPublicKey();
    const foreign = await signChannelPosterPass(otherChannel, { poster_pubkey: await mallory.getPublicKey(), issued_at: NOW - DAY, expires_at: NOW + DAY });
    const bad = await signPosterPost(mallory, {
      channel_pubkey: cpk, seq: 1, published_at: NOW, title: "forged",
      body: encryptBody(w.gk, cpk, 1, new TextEncoder().encode("x")), supersedes: null,
    }, encodeChannelPosterPass(foreign));
    await w.relay.deposit(encodeBroadcastArtifact(bad));
    await w.collector.collectOnce("id-reader", w.channelHex);
    const r = await w.read("id-reader", w.channelHex);
    expect(r.ok && r.posts.length).toBe(0);
    expect(w.inbox.heldSeqs("id-reader", `${w.channelHex}/${hex(await mallory.getPublicKey())}`)).toEqual([]);
  });

  it("D5. the member drops a REVOKED poster's post even when the relay still serves it; a revocation older than the pass does not", async () => {
    const w = await world();
    const bob = await addPoster(w, "bob");
    expect(await w.poster.publish("bob", w.channelHex, "b1", "bob body 1")).toMatchObject({ ok: true, seq: 1 });
    w.revoked.push({ poster_pubkey: await bob.getPublicKey(), revoked_at: NOW });
    await w.collector.collectOnce("id-reader", w.channelHex);
    let r = await w.read("id-reader", w.channelHex);
    expect(r.ok && r.posts.length).toBe(0);

    w.revoked.splice(0, 1, { poster_pubkey: await bob.getPublicKey(), revoked_at: NOW - 2 * DAY });
    await w.collector.collectOnce("id-reader", w.channelHex);
    r = await w.read("id-reader", w.channelHex);
    expect(r.ok && r.posts.length).toBe(1);
  });

  it("D4. unread is the sum of the admin lane and every poster lane", async () => {
    const w = await world();
    await addPoster(w, "bob");
    await adminPost(w, "a1");
    await w.poster.publish("bob", w.channelHex, "b1", "x");
    await w.poster.publish("bob", w.channelHex, "b2", "y");
    await w.collector.collectOnce("id-reader", w.channelHex);
    const sub = w.subs.get("id-reader", w.channelHex)!;
    expect(sub.delivered_through - sub.processed_through + w.lanes.unread("id-reader", w.channelHex)).toBe(3);
  });
});
