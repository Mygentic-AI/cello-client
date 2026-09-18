/**
 * M16 018-PUBCOLLECT — the subscriber half.
 *
 * A channel's two relays are NOT coordinated: each holds its own queue, they disagree by design, and
 * the subscriber takes the union. Everything is verified here, against the keys inside the bytes —
 * a relay's word that a post is good is worth nothing.
 *
 * Real DB, real keys, fake relay seam. Tests are written RED-first.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeypair } from "@cello-protocol/crypto";
import type { InMemoryKeyProvider } from "@cello-protocol/crypto";
import {
  encodeBroadcastArtifact,
  encodeRelayPostReceipt,
  signBroadcastArtifact,
  signRelayPostReceipt,
  type BroadcastArtifact,
} from "@cello-protocol/protocol-types";
import { ChannelCollector, type RelayFetchSeam } from "../channel-collector.js";
import { ChannelSubscriptionStore } from "../channel-subscription-store.js";
import { ChannelInboxStore } from "../channel-inbox-store.js";
import { openTestDb } from "./helpers/encrypted-db.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";
import type { Logger } from "../types.js";

const RELAY_A = "/dns4/relay-a.example/tcp/443/tls/ws";
const RELAY_B = "/dns4/relay-b.example/tcp/443/tls/ws";
const AGENT = "agent-1";

function recorder(): { logger: Logger; events: Array<{ name: string; ctx?: unknown }> } {
  const events: Array<{ name: string; ctx?: unknown }> = [];
  const logger: Logger = {
    debug: (n, c) => events.push({ name: n, ctx: c }),
    info: (n, c) => events.push({ name: n, ctx: c }),
    warn: (n, c) => events.push({ name: n, ctx: c }),
    error: (n, c) => events.push({ name: n, ctx: c }),
  };
  return { logger, events };
}

let dir: string;
let db: DaemonDatabase;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "cello-m16-018c-"));
  db = openTestDb(join(dir, "sessions.db"));
});
afterEach(() => {
  db.close();
  rmSync(dir, { recursive: true, force: true });
});

interface Relay {
  /** seq → encoded post, as that relay holds it. */
  posts: Map<number, Uint8Array>;
  receipts: Map<number, Uint8Array>;
  firstHeld: number | null;
  down: boolean;
  /** Fetches this relay was asked for, to prove who was asked and in what order. */
  asked: number;
}

interface Harness {
  collector: ChannelCollector;
  subs: ChannelSubscriptionStore;
  inbox: ChannelInboxStore;
  channelKp: InMemoryKeyProvider;
  adminKp: InMemoryKeyProvider;
  channelHex: string;
  relays: Map<string, Relay>;
  events: Array<{ name: string; ctx?: unknown }>;
  repairs: Array<{ from: number; to: number }>;
  post: (seq: number, opts?: { body?: Uint8Array; agentKp?: InMemoryKeyProvider }) => Promise<BroadcastArtifact>;
  place: (relay: string, post: BroadcastArtifact) => Promise<void>;
}

async function harness(): Promise<Harness> {
  const channelKp = generateKeypair();
  const adminKp = generateKeypair();
  const relayKp = generateKeypair();
  const channelHex = Buffer.from(await channelKp.getPublicKey()).toString("hex");
  const { logger, events } = recorder();
  const relays = new Map<string, Relay>([
    [RELAY_A, { posts: new Map(), receipts: new Map(), firstHeld: null, down: false, asked: 0 }],
    [RELAY_B, { posts: new Map(), receipts: new Map(), firstHeld: null, down: false, asked: 0 }],
  ]);
  const repairs: Array<{ from: number; to: number }> = [];

  const subs = new ChannelSubscriptionStore(db, logger);
  subs.upsert({
    agent_id: AGENT,
    channel_pubkey: channelHex,
    admin_pubkey: Buffer.from(await adminKp.getPublicKey()).toString("hex"),
    access: "public",
    relays: [RELAY_A, RELAY_B],
  });
  const inbox = new ChannelInboxStore(db, logger);

  const fetch: RelayFetchSeam = (relayAddr, req) => {
    const relay = relays.get(relayAddr)!;
    if (relay.down) return Promise.reject(new Error(`relay ${relayAddr} unreachable`));
    relay.asked += 1;
    const held = [...relay.posts.keys()].sort((a, b) => a - b).filter((s) => s >= req.since_seq);
    return Promise.resolve({
      ok: true as const,
      posts: held.map((s) => ({ seq: s, post_cbor: relay.posts.get(s)!, receipt_cbor: relay.receipts.get(s)! })),
      first_held_seq: relay.firstHeld,
      last_seq: relay.posts.size === 0 ? null : Math.max(...relay.posts.keys()),
    });
  };

  const collector = new ChannelCollector({
    db, logger, subscriptions: subs, inbox, fetch,
    now: () => 1_800_000_000_000,
    localAgentKeys: () => [],
    fetchAuth: () => Promise.resolve(undefined),
    requestRepair: (_agent, _ch, from, to) => {
      repairs.push({ from, to });
      return Promise.resolve();
    },
  });

  async function post(seq: number, opts: { body?: Uint8Array; agentKp?: InMemoryKeyProvider } = {}): Promise<BroadcastArtifact> {
    return signBroadcastArtifact(channelKp, opts.agentKp ?? adminKp, {
      seq, published_at: 1_800_000_000_000, title: `post ${seq}`,
      body: opts.body ?? new Uint8Array([seq]), supersedes: null, ext: null,
    });
  }

  async function place(relayAddr: string, p: BroadcastArtifact): Promise<void> {
    const relay = relays.get(relayAddr)!;
    const encoded = encodeBroadcastArtifact(p);
    relay.posts.set(p.seq, encoded);
    relay.receipts.set(p.seq, encodeRelayPostReceipt(await signRelayPostReceipt(relayKp, p, 1_800_000_000_001)));
    relay.firstHeld = Math.min(...relay.posts.keys());
  }

  return { collector, subs, inbox, channelKp, adminKp, channelHex, relays, events, repairs, post, place };
}

describe("M16 018-PUBCOLLECT: collecting", () => {
  it("11. posts from BOTH relays merge and store once", async () => {
    const h = await harness();
    const p1 = await h.post(1);
    await h.place(RELAY_A, p1);
    await h.place(RELAY_B, p1); // both relays hold it — the ordinary case

    await h.collector.collectOnce(AGENT, h.channelHex);
    expect(h.inbox.range(AGENT, h.channelHex, 1, 10).map((p) => p.seq)).toEqual([1]);
    expect(h.subs.get(AGENT, h.channelHex)?.delivered_through).toBe(1);
  });

  it("12. relay A holding 1-5 and relay B holding 3-8 yields 1-8, delivered_through 8", async () => {
    const h = await harness();
    for (let s = 1; s <= 5; s++) await h.place(RELAY_A, await h.post(s));
    for (let s = 3; s <= 8; s++) await h.place(RELAY_B, await h.post(s));

    await h.collector.collectOnce(AGENT, h.channelHex);
    expect(h.inbox.range(AGENT, h.channelHex, 1, 20).map((p) => p.seq)).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(h.subs.get(AGENT, h.channelHex)?.delivered_through).toBe(8);
  });

  it("13. holding 1, 2, 4 leaves the position at 2 and reports 3 missing", async () => {
    const h = await harness();
    for (const s of [1, 2, 4]) await h.place(RELAY_A, await h.post(s));

    await h.collector.collectOnce(AGENT, h.channelHex);
    // ⚠️ THE CONTIGUOUS RUN ONLY. Advancing to 4 would mean post 3 is never delivered when it
    // arrives, because the position already passed it.
    expect(h.subs.get(AGENT, h.channelHex)?.delivered_through).toBe(2);
    const gaps = h.collector.gapsFor(AGENT, h.channelHex);
    expect(gaps.missing).toEqual([3]);
    expect(h.events.some((e) => e.name === "channel.gap.detected")).toBe(true);
  });

  it("14. nothing BELOW first_held_seq is reported as a gap", async () => {
    const h = await harness();
    // The relay pruned 1-4; it holds 5 and 6 and says so.
    for (const s of [5, 6]) await h.place(RELAY_A, await h.post(s));
    for (const s of [5, 6]) await h.place(RELAY_B, await h.post(s));

    await h.collector.collectOnce(AGENT, h.channelHex);
    const gaps = h.collector.gapsFor(AGENT, h.channelHex);
    // ⚠️ Without this, every subscriber demands posts that no longer exist, for ever.
    expect(gaps.missing).toEqual([]);
    expect(gaps.first_held_seq).toBe(5);
    expect(h.subs.get(AGENT, h.channelHex)?.delivered_through).toBe(6);
  });

  it("15. an INVALID post is dropped, named, and advances nothing", async () => {
    const h = await harness();
    await h.place(RELAY_A, await h.post(1));

    // Post 2 is signed by an agent that is not this channel's admin — valid signatures, wrong
    // author. The subscriber checks against the admin IT knows, not against the relay's word.
    const impostor = generateKeypair();
    await h.place(RELAY_A, await h.post(2, { agentKp: impostor }));
    await h.place(RELAY_A, await h.post(3));

    await h.collector.collectOnce(AGENT, h.channelHex);
    expect(h.inbox.range(AGENT, h.channelHex, 1, 10).map((p) => p.seq)).toEqual([1]);
    expect(h.subs.get(AGENT, h.channelHex)?.delivered_through).toBe(1);
    const invalid = h.events.find((e) => e.name === "channel.post.invalid");
    expect(invalid, "the drop must say WHICH check failed").toBeDefined();
    expect(JSON.stringify(invalid?.ctx)).toContain("admin");
  });

  it("16. a FORK is kept, reported, and the position stops there", async () => {
    const h = await harness();
    await h.place(RELAY_A, await h.post(1));
    // Two different posts at number 2: each relay witnessed one. Both are genuinely signed.
    await h.place(RELAY_A, await h.post(2, { body: new Uint8Array([0xaa]) }));
    await h.place(RELAY_B, await h.post(2, { body: new Uint8Array([0xbb]) }));
    await h.place(RELAY_A, await h.post(3));

    await h.collector.collectOnce(AGENT, h.channelHex);
    const fork = h.events.find((e) => e.name === "channel.fork.detected");
    expect(fork, "a fork is never silently dropped").toBeDefined();
    expect(JSON.stringify(fork?.ctx), "both hashes, so the publisher can be confronted with them")
      .toMatch(/hash/i);
    // ⚠️ NO AUTOMATIC RESOLUTION. Picking one would make the relay that happened to answer first
    // the arbiter of what a channel said.
    expect(h.subs.get(AGENT, h.channelHex)?.delivered_through).toBe(1);
    expect(h.inbox.forksFor(AGENT, h.channelHex, 2)).toHaveLength(2);
  });

  it("17. one relay down still delivers from the other", async () => {
    const h = await harness();
    for (let s = 1; s <= 3; s++) await h.place(RELAY_B, await h.post(s));
    h.relays.get(RELAY_A)!.down = true;

    await h.collector.collectOnce(AGENT, h.channelHex);
    expect(h.subs.get(AGENT, h.channelHex)?.delivered_through).toBe(3);
    expect(h.events.some((e) => e.name === "channel.fetch.failed")).toBe(true);
  });

  it("18. repair asks the OTHER relay first, then the publisher, rate-limited per channel", async () => {
    const h = await harness();
    for (const s of [1, 2, 4]) await h.place(RELAY_A, await h.post(s));
    // Relay B holds the missing one, so the repair should never reach the publisher.
    await h.place(RELAY_B, await h.post(3));

    await h.collector.collectOnce(AGENT, h.channelHex);
    await h.collector.repairGaps(AGENT, h.channelHex);
    expect(h.repairs, "the other relay had it; the publisher is not bothered").toEqual([]);
    expect(h.subs.get(AGENT, h.channelHex)?.delivered_through).toBe(4);

    // Now a gap neither relay holds: the publisher is asked, ONCE.
    const h2 = await harness();
    for (const s of [1, 3]) await h2.place(RELAY_A, await h2.post(s));
    await h2.collector.collectOnce(AGENT, h2.channelHex);
    await h2.collector.repairGaps(AGENT, h2.channelHex);
    await h2.collector.repairGaps(AGENT, h2.channelHex);
    expect(h2.repairs, "a gap that survives both is reported once, not every tick").toHaveLength(1);
    expect(h2.repairs[0]).toEqual({ from: 2, to: 2 });
  });

  it("19. a public channel fetches with NO auth; a non-public one signs with the fetch key", async () => {
    const h = await harness();
    await h.place(RELAY_A, await h.post(1));
    let sawAuth: boolean | undefined;
    const collector = new ChannelCollector({
      db, logger: recorder().logger, subscriptions: h.subs, inbox: h.inbox,
      now: () => 1_800_000_000_000, localAgentKeys: () => [],
      fetch: (relayAddr, req) => {
        sawAuth = req.auth !== undefined;
        return Promise.resolve({ ok: true as const, posts: [], first_held_seq: null, last_seq: null });
      },
      fetchAuth: (access) => Promise.resolve(access === "public" ? undefined : { signature: new Uint8Array(64), time_ms: 1 }),
      requestRepair: () => Promise.resolve(),
    });

    await collector.collectOnce(AGENT, h.channelHex); // subscription is public
    expect(sawAuth, "a public channel needs no credentials at all").toBe(false);

    h.subs.upsert({
      agent_id: AGENT, channel_pubkey: h.channelHex,
      admin_pubkey: Buffer.from(await h.adminKp.getPublicKey()).toString("hex"),
      access: "open", relays: [RELAY_A, RELAY_B],
    });
    await collector.collectOnce(AGENT, h.channelHex);
    expect(sawAuth, "a non-public channel is gated on the fetch key").toBe(true);
  });

  it("20. processed_through NEVER moves, across everything above", async () => {
    const h = await harness();
    for (let s = 1; s <= 3; s++) await h.place(RELAY_A, await h.post(s));
    await h.collector.collectOnce(AGENT, h.channelHex);
    await h.collector.repairGaps(AGENT, h.channelHex);

    const sub = h.subs.get(AGENT, h.channelHex);
    expect(sub?.delivered_through).toBe(3);
    // ⚠️ TWO POSITIONS, NEVER ONE. If a fetch moved the read position, everything the daemon
    // collected while the agent was away would be silently marked as read.
    expect(sub?.processed_through, "only the agent's own read moves this").toBe(0);
  });
});
