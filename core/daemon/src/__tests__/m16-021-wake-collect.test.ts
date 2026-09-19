/**
 * M16 021-WAKE, client half — the doorbell drives a fetch, and the timer becomes a backstop.
 *
 * Before this, a post reached nobody until each subscriber's five-minute timer fired. The timer now
 * has a different job: push is best-effort, and the poll is what makes delivery certain when a wake
 * never arrives — the publisher crashed, the frame was lost in stream churn, or the forward did not
 * reach this subscriber's node. Each of those leaves a post on a relay with nobody told.
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
  createChannelCollectTicker, jitterForChannel,
  COLLECT_TICK_INTERVAL_MS, COLLECT_JITTER_MS,
} from "../channel-collect-tick.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };
const AGENT = "agent-1";
const CHANNEL = "aa".repeat(32);
const CHANNEL_B = "bb".repeat(32);
const ADMIN = "cc".repeat(32);
const RELAY_A = "/dns4/relay-a.example/tcp/443/tls/ws";

let dir: string;
let db: DaemonDatabase;
let subs: ChannelSubscriptionStore;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "cello-m16-021-"));
  db = openTestDb(join(dir, "sessions.db"));
  subs = new ChannelSubscriptionStore(db, silent);
  for (const ch of [CHANNEL, CHANNEL_B]) {
    subs.upsert({ agent_id: AGENT, channel_pubkey: ch, admin_pubkey: ADMIN, access: "invite_only", relays: [RELAY_A] });
  }
});
afterEach(() => {
  db.close();
  rmSync(dir, { recursive: true, force: true });
});

function ticker(over: Partial<Parameters<typeof createChannelCollectTicker>[0]> = {}) {
  const collected: string[] = [];
  const t = createChannelCollectTicker({
    logger: silent,
    collector: {
      collectOnce: (_a: string, channelHex: string) => { collected.push(channelHex); return Promise.resolve({ ok: true as const }); },
      repairGaps: () => Promise.resolve(),
    } as never,
    subscriptions: subs,
    isAgentOnline: () => true,
    ...over,
  });
  return { t, collected };
}

describe("M16 021 — the doorbell, and the timer as a backstop", () => {
  it("14. the backstop interval is an HOUR, not five minutes", () => {
    /**
     * ⚠️ The number is the point of the order. At five minutes the timer WAS the delivery
     * mechanism; with a doorbell it is a repair pass for wakes that never arrived, and a repair pass
     * that runs twelve times an hour is eleven wasted rounds of every subscriber asking every relay.
     */
    expect(COLLECT_TICK_INTERVAL_MS).toBe(60 * 60_000);
  });

  it("16. jitter is a PROPORTION of the interval, so it still spreads at the slower cadence", () => {
    /**
     * ⚠️ **A FIXED JITTER SIZED FOR FIVE MINUTES IS A NARROW BAND INSIDE AN HOUR.** Keep 60 seconds
     * of spread on an hourly tick and the fleet clumps into the same minute every hour — the
     * thundering herd the jitter exists to prevent, just less often and therefore harder to notice.
     */
    expect(COLLECT_JITTER_MS).toBeGreaterThanOrEqual(COLLECT_TICK_INTERVAL_MS / 4);

    // Still deterministic per (channel, agent): the same pair must not wander between ticks, or a
    // channel's position in the window would drift every hour.
    const a = jitterForChannel(CHANNEL, AGENT, COLLECT_JITTER_MS);
    expect(jitterForChannel(CHANNEL, AGENT, COLLECT_JITTER_MS)).toBe(a);
    expect(jitterForChannel(CHANNEL_B, AGENT, COLLECT_JITTER_MS)).not.toBe(a);
    expect(a).toBeLessThan(COLLECT_JITTER_MS);
  });

  it("11. a wake collects EVERY channel this agent follows, immediately", async () => {
    /**
     * ⚠️ The doorbell carries no channel, by design — naming one would put channel→member on a
     * second wire. So the daemon fetches all of them; that is what makes the empty frame sufficient.
     */
    const { t, collected } = ticker();
    await t.collectNow(AGENT);
    expect(collected.sort()).toEqual([CHANNEL, CHANNEL_B].sort());
  });

  it("11b. a wake does NOT wait for the timer, and does not disturb it either", async () => {
    // A wake that reset the schedule would let a chatty channel starve the backstop for a quiet one.
    const { t, collected } = ticker();
    await t.collectNow(AGENT);
    expect(collected).toHaveLength(2);

    collected.length = 0;
    await t.collectAllDue(0);
    expect(collected, "the first-sight pass still runs on its own terms").toHaveLength(2);
  });

  it("12. a wake for an agent with no subscriptions does nothing and does not throw", async () => {
    const { t, collected } = ticker();
    await expect(t.collectNow("agent-nobody")).resolves.toBeUndefined();
    expect(collected).toEqual([]);
  });

  it("12b. a wake for an OFFLINE agent collects nothing", async () => {
    /**
     * ⚠️ The kill switch has to hold here too. Collecting for an agent the operator switched off is
     * the switch failing to switch something off, and a doorbell must not be a way around it.
     */
    const { t, collected } = ticker({ isAgentOnline: () => false });
    await t.collectNow(AGENT);
    expect(collected).toEqual([]);
  });

  it("13. a wake never advances a read position by itself", async () => {
    /**
     * ⚠️ It causes a FETCH; the fetch decides what was read. A doorbell that moved the position
     * would skip the very post it was announcing.
     */
    const before = subs.get(AGENT, CHANNEL);
    const { t } = ticker();
    await t.collectNow(AGENT);
    const after = subs.get(AGENT, CHANNEL);
    expect(after?.delivered_through).toBe(before?.delivered_through);
    expect(after?.processed_through).toBe(before?.processed_through);
  });

  it("15. a collect failure on one channel does not stop the others", async () => {
    const collected: string[] = [];
    const t = createChannelCollectTicker({
      logger: silent,
      collector: {
        collectOnce: (_a: string, ch: string) => {
          if (ch === CHANNEL) return Promise.reject(new Error("relay down"));
          collected.push(ch);
          return Promise.resolve({ ok: true as const });
        },
        repairGaps: () => Promise.resolve(),
      } as never,
      subscriptions: subs,
      isAgentOnline: () => true,
    });
    await t.collectNow(AGENT);
    expect(collected, "the healthy channel still collected").toEqual([CHANNEL_B]);
  });
});
