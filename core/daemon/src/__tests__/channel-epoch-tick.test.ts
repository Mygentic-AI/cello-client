/**
 * M16 008-EPOCH — the scheduler tick that enforces the epoch cap.
 *
 * The sealer's own tests prove the rule; these prove the tick applies it with the channel's STORED
 * policy, that no stored value or environment setting can switch the cap off, and that the designed
 * compare-and-set refusal reads as a retry rather than an alarm. Real SQLCipher DB, real identity
 * rows, real signatures, controllable clock.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeypair } from "@cello-protocol/crypto";
import type { InMemoryKeyProvider } from "@cello-protocol/crypto";
import { signBroadcastArtifact } from "@cello-protocol/protocol-types";
import { ChannelLogStore } from "../channel-log-store.js";
import { EPOCH_MAX_AGE_MS } from "../channel-epoch-sealer.js";
import { CHANNEL_EPOCH_TICK_MS, channelEpochTickIntervalMs, startChannelEpochTick } from "../channel-epoch-tick.js";
import { DbIdentityStore, DbRegistrationPersistence } from "../db-identity-store.js";
import type { SessionNodeManager } from "../session-node-manager.js";
import { openTestDb } from "./helpers/encrypted-db.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";
import type { Logger } from "../types.js";

const HOUR = 60 * 60 * 1000;

let dir: string;
let db: DaemonDatabase;
let log: ChannelLogStore;
let events: Array<{ level: string; event: string; ctx: Record<string, unknown> }>;
let clock: number;
let kp: InMemoryKeyProvider;
let hex: string;
let timers: NodeJS.Timeout[];

const logger: Logger = {
  debug(event, ctx) { events.push({ level: "debug", event, ctx: ctx ?? {} }); },
  info(event, ctx) { events.push({ level: "info", event, ctx: ctx ?? {} }); },
  warn(event, ctx) { events.push({ level: "warn", event, ctx: ctx ?? {} }); },
  error(event, ctx) { events.push({ level: "error", event, ctx: ctx ?? {} }); },
};

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "cello-epoch-tick-"));
  db = openTestDb(join(dir, "sessions.db"));
  events = [];
  timers = [];
  clock = 1_789_000_000_000;
  log = new ChannelLogStore(db, logger);
  kp = generateKeypair();
  hex = Buffer.from(await kp.getPublicKey()).toString("hex");
  new DbIdentityStore(db, logger).createAgent("news", new Uint8Array(32).fill(1), hex);
  await new DbRegistrationPersistence({ db, agentName: "news", logger }).persistRegistrationState({
    agentId: "agent-news", primaryPubkey: "aa".repeat(32), mlDsaPubkey: "bb".repeat(32), registeredAt: 1,
    keyBinding: "cd".repeat(64), channel: true, adminPubkey: "ef".repeat(32),
  });
  log.ensureChannel(hex);
});
afterEach(() => {
  for (const t of timers) clearInterval(t);
  db.close();
  rmSync(dir, { recursive: true, force: true });
});

async function publish(): Promise<void> {
  const pos = log.nextPosition(hex);
  const a = await signBroadcastArtifact(kp, {
    seq: pos.seq, epoch_index: pos.epoch_index, title: `post ${pos.seq}`, body_ciphertext: new Uint8Array([pos.seq]),
    supersedes: null, prev_epoch_root: pos.first_in_epoch ? pos.prev_epoch_root : null, ext: null,
  });
  log.append(hex, a, clock);
}

function tickWith(keyProvider: InMemoryKeyProvider = kp): () => Promise<void> {
  const sessionNodeManager = { getDb: () => db, getChannelLogStore: () => log } as unknown as SessionNodeManager;
  const { timer, tick } = startChannelEpochTick({
    logger, sessionNodeManager, agents: [{ name: "news", pubkey: hex }],
    getKeyProvider: (n) => (n === "news" ? keyProvider : undefined), now: () => clock,
  });
  timers.push(timer);
  return tick;
}

const sealed = () => events.filter((e) => e.event === "channel.epoch.sealed");

describe("M16 008-EPOCH: the cap tick", () => {
  it("honours a shorter stored policy", async () => {
    db.prepare("UPDATE channel_epoch_state SET max_age_ms = ? WHERE channel_pubkey = ?").run(HOUR, hex);
    await publish();
    const tick = tickWith();
    clock += HOUR - 1;
    await tick();
    expect(sealed()).toHaveLength(0);
    clock += 1;
    await tick();
    expect(sealed()).toHaveLength(1);
    expect(sealed()[0]!.ctx["trigger"]).toBe("cap_age");
  });

  it("an invalid stored policy still enforces the protocol maxima, and says so at error", async () => {
    db.prepare("UPDATE channel_epoch_state SET max_age_ms = ? WHERE channel_pubkey = ?").run(2 * EPOCH_MAX_AGE_MS, hex);
    await publish();
    const tick = tickWith();
    clock += HOUR;
    await tick();
    expect(sealed()).toHaveLength(0);
    expect(events.some((e) => e.level === "error" && e.event === "channel.epoch.seal_failed" && e.ctx["reason"] === "policy_invalid")).toBe(true);
    clock += EPOCH_MAX_AGE_MS - HOUR;
    await tick();
    expect(sealed(), "a stored 48h cap must not stretch the 24h window").toHaveLength(1);
    expect(sealed()[0]!.ctx["trigger"]).toBe("cap_age");
  });

  it("a publish landing mid-seal is a retry, logged once at info, and the next tick seals", async () => {
    await publish();
    let racing = true;
    const racer = {
      getPublicKey: () => kp.getPublicKey(),
      sign: async (m: Uint8Array) => { if (racing) { racing = false; await publish(); } return kp.sign(m); },
    } as unknown as InMemoryKeyProvider;
    const tick = tickWith(racer);
    clock += EPOCH_MAX_AGE_MS;
    await tick();
    expect(sealed()).toHaveLength(0);
    expect(events.filter((e) => e.event === "channel.epoch.seal_retry" && e.level === "info")).toHaveLength(1);
    expect(events.filter((e) => e.level === "error" || e.level === "warn"), "a designed refusal is not an alarm").toEqual([]);
    await tick();
    expect(sealed()).toHaveLength(1);
    expect(sealed()[0]!.ctx["leaf_count"]).toBe(2);
  });

  it("the interval override can shorten the tick, never lengthen it", () => {
    expect(channelEpochTickIntervalMs(undefined)).toBe(CHANNEL_EPOCH_TICK_MS);
    expect(channelEpochTickIntervalMs("500")).toBe(500);
    expect(channelEpochTickIntervalMs("100")).toBe(CHANNEL_EPOCH_TICK_MS);
    expect(channelEpochTickIntervalMs(String(EPOCH_MAX_AGE_MS))).toBe(CHANNEL_EPOCH_TICK_MS);
    expect(channelEpochTickIntervalMs(String(2 ** 31))).toBe(CHANNEL_EPOCH_TICK_MS);
    expect(channelEpochTickIntervalMs("soon")).toBe(CHANNEL_EPOCH_TICK_MS);
  });
});
