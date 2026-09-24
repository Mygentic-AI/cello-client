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
  COLLECT_TICK_INTERVAL_MS, COLLECT_JITTER_MS, COLLECT_MAX_BACKOFF_MS, COLLECT_RETRY_SPREAD_MS,
} from "../channel-collect-tick.js";
import { createIsAgentOnlineById } from "../agent-online.js";

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

  it("15. start() collects IMMEDIATELY, it does not wait out the first interval", async () => {
    /**
     * ⚠️ **WITHOUT THIS THE ORDER MADE ITS OWN WORST CASE TWELVE TIMES WORSE.** A daemon that has
     * just started — your laptop opened after a night shut — used to wait five minutes for its
     * first collection. At an hourly interval it waited an hour. The wake only reaches agents that
     * are ALREADY online, so start and reconnect are the only events covering the ones that were
     * not, which is the precise case the backstop exists for.
     */
    const { t, collected } = ticker();
    t.start();
    await new Promise((r) => setTimeout(r, 30));
    t.stop();
    expect(collected.sort()).toEqual([CHANNEL, CHANNEL_B].sort());
  });

  it("17. the backoff ceiling EXCEEDS the interval, or a broken channel is retried sooner than a healthy one", () => {
    /**
     * ⚠️ **THE CEILING WAS 30 MINUTES AGAINST AN HOURLY POLL, so the backoff did not back off.**
     * First failure computed min(30min, 60min×2) = 30 minutes, and every one after stayed there: a
     * FAILING channel became due at +30 while a healthy one went to +60. The constant was sized for
     * a five-minute interval and not re-derived when the interval moved — which is why it is now
     * written as a multiple of the interval rather than as a number that has to be remembered.
     */
    expect(COLLECT_MAX_BACKOFF_MS).toBeGreaterThan(COLLECT_TICK_INTERVAL_MS);
    // And the retry path carries its own randomness: the stable per-channel jitter spreads channels
    // across subscribers but cannot stagger the WAVE of daemons returning after a relay outage,
    // because every failing channel lands on the same ceiling.
    expect(COLLECT_RETRY_SPREAD_MS).toBeGreaterThan(0);
  });

  it("11c. a wake through the PRODUCTION isAgentOnline (id → name → online set) collects", async () => {
    /**
     * ⚠️ 029-COLLECTID. The subscription is keyed by the STABLE agent_id (AGENT); the online sets are
     * keyed by NAME. The id and the name are deliberately DIFFERENT here — the collector passes the
     * id, the set holds the name, and only the id→name map makes the two meet. A stubbed
     * `() => true` hid the defect for four orders; this wires the real `createIsAgentOnlineById` so a
     * wake for an online subscriber actually reaches `collectOnce`.
     */
    const ONLINE_NAME = "alice";
    const isAgentOnline = createIsAgentOnlineById({
      onlineAgents: new Set([ONLINE_NAME]),
      explicitlyOfflineAgents: new Set<string>(),
      agentNameForId: (id) => (id === AGENT ? ONLINE_NAME : null),
    });
    const { t, collected } = ticker({ isAgentOnline });
    await t.collectNow(AGENT);
    expect(collected.sort(), "the id resolved to an online name, so both channels collected").toEqual(
      [CHANNEL, CHANNEL_B].sort(),
    );
  });

  it("15b. a collect failure on one channel does not stop the others", async () => {
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
