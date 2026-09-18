/**
 * M16 018-PUBCOLLECT — the collection SCHEDULE.
 *
 * The collector was written, tested and left unwired: there is no inbound event for a channel post,
 * so a collector nobody calls is a subscriber who receives nothing while every component reports
 * healthy. These tests pin the schedule itself rather than the fetching, which
 * `channel-collector.test.ts` already covers.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openTestDb } from "./helpers/encrypted-db.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";
import type { Logger } from "../types.js";
import { ChannelSubscriptionStore } from "../channel-subscription-store.js";
import {
  createChannelCollectTicker,
  jitterForChannel,
  COLLECT_TICK_INTERVAL_MS,
  COLLECT_JITTER_MS,
} from "../channel-collect-tick.js";
import type { ChannelCollector } from "../channel-collector.js";

const CHANNEL_A = "aa".repeat(32);
const CHANNEL_B = "bb".repeat(32);
const AGENT = "agent-1";
const SECOND = "agent-2";

function recorder(): { logger: Logger; events: Array<{ event: string; ctx?: unknown }> } {
  const events: Array<{ event: string; ctx?: unknown }> = [];
  const logger: Logger = {
    debug: (n, c) => events.push({ event: n, ctx: c }),
    info: (n, c) => events.push({ event: n, ctx: c }),
    warn: (n, c) => events.push({ event: n, ctx: c }),
    error: (n, c) => events.push({ event: n, ctx: c }),
  };
  return { logger, events };
}

let dir: string;
let db: DaemonDatabase;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "cello-m16-018t-"));
  db = openTestDb(join(dir, "sessions.db"));
});
afterEach(() => {
  db.close();
  rmSync(dir, { recursive: true, force: true });
});

interface Fake {
  collected: Array<{ agentId: string; channelHex: string }>;
  repaired: Array<{ agentId: string; channelHex: string }>;
  failOn: Set<string>;
  collector: ChannelCollector;
}

function fakeCollector(): Fake {
  const collected: Array<{ agentId: string; channelHex: string }> = [];
  const repaired: Array<{ agentId: string; channelHex: string }> = [];
  const failOn = new Set<string>();
  const collector = {
    collectOnce: (agentId: string, channelHex: string) => {
      collected.push({ agentId, channelHex });
      if (failOn.has(channelHex)) return Promise.reject(new Error("both relays unreachable"));
      return Promise.resolve();
    },
    repairGaps: (agentId: string, channelHex: string) => {
      repaired.push({ agentId, channelHex });
      return Promise.resolve();
    },
  } as unknown as ChannelCollector;
  return { collected, repaired, failOn, collector };
}

function subscribe(subs: ChannelSubscriptionStore, agentId: string, channelHex: string): void {
  subs.upsert({
    agent_id: agentId,
    channel_pubkey: channelHex,
    admin_pubkey: "cc".repeat(32),
    access: "public",
    relays: ["/relay/a", "/relay/b"],
  });
}

describe("M16 018-PUBCOLLECT: the collection schedule", () => {
  it("21. a newly seen subscription collects IMMEDIATELY, not one interval later", async () => {
    const { logger } = recorder();
    const subs = new ChannelSubscriptionStore(db, logger);
    subscribe(subs, AGENT, CHANNEL_A);
    const fake = fakeCollector();
    const ticker = createChannelCollectTicker({
      logger, collector: fake.collector, subscriptions: subs, isAgentOnline: () => true,
    });

    await ticker.collectAllDue(1_000);
    // ⚠️ A new subscriber waiting out a full interval before its first post looks broken and is.
    expect(fake.collected).toEqual([{ agentId: AGENT, channelHex: CHANNEL_A }]);
    expect(fake.repaired).toHaveLength(1);
  });

  it("22. a second pass before the interval elapses does NOT re-fetch", async () => {
    const { logger } = recorder();
    const subs = new ChannelSubscriptionStore(db, logger);
    subscribe(subs, AGENT, CHANNEL_A);
    const fake = fakeCollector();
    const ticker = createChannelCollectTicker({
      logger, collector: fake.collector, subscriptions: subs, isAgentOnline: () => true,
    });

    await ticker.collectAllDue(1_000);
    await ticker.collectAllDue(1_000 + 1_000);
    expect(fake.collected, "still just the first pass").toHaveLength(1);

    // Past the interval AND the widest the jitter can push it — now it is certainly due.
    await ticker.collectAllDue(1_000 + COLLECT_TICK_INTERVAL_MS + COLLECT_JITTER_MS + 1);
    expect(fake.collected).toHaveLength(2);
  });

  it("23. an OFFLINE agent is skipped, and its channels do not stop another agent's", async () => {
    const { logger } = recorder();
    const subs = new ChannelSubscriptionStore(db, logger);
    subscribe(subs, AGENT, CHANNEL_A);
    subscribe(subs, SECOND, CHANNEL_B);
    const fake = fakeCollector();
    const ticker = createChannelCollectTicker({
      logger, collector: fake.collector, subscriptions: subs,
      // ⚠️ PER AGENT. Collecting for an agent the operator switched off is the kill switch failing
      // to switch something off — and one agent being off must not stop the other's channels.
      isAgentOnline: (agentId) => agentId === SECOND,
    });

    await ticker.collectAllDue(1_000);
    expect(fake.collected).toEqual([{ agentId: SECOND, channelHex: CHANNEL_B }]);
  });

  it("24. a channel whose relays fail is BACKED OFF, and any success resets it", async () => {
    const { logger, events } = recorder();
    const subs = new ChannelSubscriptionStore(db, logger);
    subscribe(subs, AGENT, CHANNEL_A);
    const fake = fakeCollector();
    fake.failOn.add(CHANNEL_A);
    const ticker = createChannelCollectTicker({
      logger, collector: fake.collector, subscriptions: subs, isAgentOnline: () => true,
      intervalMs: 1_000, jitterMs: 0, maxBackoffMs: 8_000,
    });

    // Fail at t=0 → next attempt is 2 intervals out, not 1.
    await ticker.collectAllDue(0);
    expect(fake.collected).toHaveLength(1);
    await ticker.collectAllDue(1_500);
    expect(fake.collected, "still inside the backoff").toHaveLength(1);
    await ticker.collectAllDue(2_100);
    expect(fake.collected).toHaveLength(2);

    // ⚠️ THE FAILURE IS LOGGED. A background collection that fails in silence is a subscriber who
    // stops receiving with nothing anywhere saying why.
    expect(events.some((e) => e.event === "channel.collect.tick_failed")).toBe(true);

    // It doubles, up to the ceiling.
    await ticker.collectAllDue(6_200);
    const afterThird = fake.collected.length;
    // Now it succeeds: the very next interval is the plain one again, not the backed-off one.
    fake.failOn.delete(CHANNEL_A);
    await ticker.collectAllDue(6_200 + 8_001);
    expect(fake.collected.length).toBe(afterThird + 1);
    await ticker.collectAllDue(6_200 + 8_001 + 1_001);
    expect(fake.collected.length, "backoff reset by the success").toBe(afterThird + 2);
  });

  it("25. the jitter is STABLE per subscriber and inside the window", () => {
    const first = jitterForChannel(CHANNEL_A, AGENT, COLLECT_JITTER_MS);
    // ⚠️ Same channel, same subscriber, same offset — every time. A fresh random each tick spreads
    // load just as well but makes a slow channel impossible to tell from a jittery one.
    expect(jitterForChannel(CHANNEL_A, AGENT, COLLECT_JITTER_MS)).toBe(first);
    expect(first).toBeGreaterThanOrEqual(0);
    expect(first).toBeLessThan(COLLECT_JITTER_MS);

    // Different subscribers to the SAME channel are spread, which is the point: every subscriber to
    // a popular channel would otherwise hit its two relays at the same moment, every interval.
    expect(jitterForChannel(CHANNEL_A, SECOND, COLLECT_JITTER_MS)).not.toBe(first);
  });

  it("26. the interval is well inside the shortest retention a channel could set", () => {
    /**
     * ⚠️ If collection is rarer than retention, a post can be delivered, held for its whole life and
     * swept without the subscriber ever seeing it — and without recording a gap either, because by
     * the time anyone looks the number is below the relay's floor. The default retention is 7 days.
     */
    const defaultRetentionMs = 7 * 24 * 60 * 60 * 1000;
    expect(COLLECT_TICK_INTERVAL_MS).toBeLessThan(defaultRetentionMs / 100);
  });
});
