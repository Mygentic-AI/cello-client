/**
 * M16 011-SEALREQ — a requested seal, the publisher-side half: the trigger and its limiter.
 *
 * A seal costs a directory threshold signature, so "anyone can make the publisher burn one" is a
 * grinding lever. The settled rule, and what these tests pin:
 *
 *   - A request is honored at most once per channel per hour, for EVERY requester — the publisher's
 *     own request shares the window with a subscriber's. `>= 1h` since the last honored request
 *     honors; `< 1h` is rate-limited.
 *   - A rate-limited request is not an empty refusal: it reports the latest seal's index and root
 *     and how long until the window reopens, and it seals nothing.
 *   - An empty epoch does not consume the window — nothing was sealed, so a no-op request cannot
 *     deny a real one.
 *   - Windows are per channel.
 *   - The IPC verb `cello_channel_seal` refuses a non-channel agent with `not_a_channel` and returns
 *     the gate's outcome with bytes hex-encoded.
 *
 * Real SQLCipher DB, real keys and signatures, 008's sealer constructed directly, controllable clock.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeypair } from "@cello-protocol/crypto";
import type { InMemoryKeyProvider } from "@cello-protocol/crypto";
import { signBroadcastArtifact } from "@cello-protocol/protocol-types";
import { ChannelLogStore } from "../channel-log-store.js";
import { ChannelEpochSealStore } from "../channel-epoch-seal-store.js";
import { ChannelEpochSealer } from "../channel-epoch-sealer.js";
import { ChannelSealRequestGate, registerChannelSealHandler } from "../channel-seal-request.js";
import { DbIdentityStore, DbRegistrationPersistence } from "../db-identity-store.js";
import type { IpcHandler } from "../ipc-server.js";
import { openTestDb } from "./helpers/encrypted-db.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";
import type { Logger } from "../types.js";

const HOUR = 60 * 60 * 1000;
const MIN = 60 * 1000;

let dir: string;
let db: DaemonDatabase;
let log: ChannelLogStore;
let sealStore: ChannelEpochSealStore;
let events: Array<{ level: string; event: string; ctx: Record<string, unknown> }>;
let clock: number;
let keys: Map<string, InMemoryKeyProvider>;

const logger: Logger = {
  debug(event, ctx) { events.push({ level: "debug", event, ctx: ctx ?? {} }); },
  info(event, ctx) { events.push({ level: "info", event, ctx: ctx ?? {} }); },
  warn(event, ctx) { events.push({ level: "warn", event, ctx: ctx ?? {} }); },
  error(event, ctx) { events.push({ level: "error", event, ctx: ctx ?? {} }); },
};

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "cello-seal-request-"));
  db = openTestDb(join(dir, "sessions.db"));
  events = [];
  clock = 1_789_000_000_000;
  keys = new Map();
  log = new ChannelLogStore(db, logger);
  sealStore = new ChannelEpochSealStore(db, logger);
});
afterEach(() => {
  db.close();
  rmSync(dir, { recursive: true, force: true });
});

/** A fresh channel key with an ensured log; returns its pubkey hex. */
async function newChannel(): Promise<string> {
  const kp = generateKeypair();
  const hex = Buffer.from(await kp.getPublicKey()).toString("hex");
  keys.set(hex, kp);
  log.ensureChannel(hex);
  return hex;
}

async function publish(hex: string, n: number): Promise<void> {
  const kp = keys.get(hex)!;
  for (let i = 0; i < n; i++) {
    const pos = log.nextPosition(hex);
    const a = await signBroadcastArtifact(kp, {
      seq: pos.seq, epoch_index: pos.epoch_index, title: `p${pos.seq}`, body_ciphertext: new Uint8Array([1]),
      supersedes: null, prev_epoch_root: pos.first_in_epoch ? pos.prev_epoch_root : null, ext: null,
    });
    log.append(hex, a, clock);
  }
}

function gate(): ChannelSealRequestGate {
  const sealer = new ChannelEpochSealer({
    log, sealStore, logger, now: () => clock, getKeyProvider: (h) => keys.get(h) ?? null,
  });
  return new ChannelSealRequestGate({ sealer, sealStore, logger, now: () => clock });
}

const hx = (b: Uint8Array) => Buffer.from(b).toString("hex");

describe("M16 011-SEALREQ: ChannelSealRequestGate", () => {
  it("first request with leaves is honored", async () => {
    const ch = await newChannel();
    await publish(ch, 2);
    const r = await gate().requestSeal(ch, "publisher", "r1");
    expect(r).toMatchObject({ honored: true, epoch_index: 0, leaf_count: 2 });
    const honored = events.find((e) => e.event === "channel.seal_request.honored");
    expect(honored?.ctx).toMatchObject({ correlationId: "r1", channel_pubkey: ch, requester: "publisher", epoch_index: 0 });
    expect(sealStore.latest(ch)?.epoch_index).toBe(0);
  });

  it("second request inside the window is rate-limited and reports the latest seal", async () => {
    const ch = await newChannel();
    const g = gate();
    await publish(ch, 2);
    const first = await g.requestSeal(ch, "publisher", "r2a");
    if (!first.honored) throw new Error(`expected honored, got ${JSON.stringify(first)}`);
    await publish(ch, 1);
    clock += 30 * MIN;
    const r = await g.requestSeal(ch, "publisher", "r2b");
    if (r.honored || r.reason !== "rate_limited") throw new Error(`expected rate_limited, got ${JSON.stringify(r)}`);
    expect(r.latest_epoch_index).toBe(0);
    expect(hx(r.latest_epoch_root!)).toBe(hx(first.epoch_root));
    expect(r.retry_after_ms).toBe(1_800_000);
    expect(log.openEpochRoot(ch).leaf_count, "the new leaf must stay unsealed").toBe(1);
    expect(sealStore.latest(ch)?.epoch_index).toBe(0);
    const limited = events.find((e) => e.event === "channel.seal_request.rate_limited");
    expect(limited?.ctx).toMatchObject({ correlationId: "r2b", channel_pubkey: ch, requester: "publisher", retry_after_ms: 1_800_000 });
  });

  it("request at exactly one hour is honored", async () => {
    const ch = await newChannel();
    const g = gate();
    await publish(ch, 2);
    const firstAt = clock;
    expect((await g.requestSeal(ch, "publisher", "r3a")).honored).toBe(true);
    await publish(ch, 1);
    clock = firstAt + 3_600_000;
    const r = await g.requestSeal(ch, "publisher", "r3b");
    expect(r).toMatchObject({ honored: true, epoch_index: 1, leaf_count: 1 });
  });

  it("empty epoch does not consume the window", async () => {
    const ch = await newChannel();
    const g = gate();
    const empty = await g.requestSeal(ch, "publisher", "r4a");
    expect(empty).toEqual({ honored: false, reason: "epoch_empty", latest_epoch_index: null, latest_epoch_root: null });
    await publish(ch, 1);
    const r = await g.requestSeal(ch, "publisher", "r4b");
    expect(r).toMatchObject({ honored: true, epoch_index: 0, leaf_count: 1 });

    // With a seal present, the empty reply reports it — never hard-coded nulls.
    clock += HOUR;
    const afterSeal = await g.requestSeal(ch, "publisher", "r4c");
    if (!r.honored) throw new Error("expected honored");
    expect(afterSeal).toEqual({ honored: false, reason: "epoch_empty", latest_epoch_index: 0, latest_epoch_root: r.epoch_root });
  });

  it("publisher and subscriber share one window", async () => {
    const ch = await newChannel();
    const g = gate();
    await publish(ch, 1);
    expect((await g.requestSeal(ch, "publisher", "r5a")).honored).toBe(true);
    await publish(ch, 1);
    clock += MIN;
    const r = await g.requestSeal(ch, "ab".repeat(32), "r5b");
    expect(r).toMatchObject({ honored: false, reason: "rate_limited", latest_epoch_index: 0, retry_after_ms: HOUR - MIN });
    expect(events.find((e) => e.event === "channel.seal_request.rate_limited")?.ctx["requester"]).toBe("ab".repeat(32));
  });

  it("two requests at once: one is honored, the other is rate-limited, one seal is recorded", async () => {
    const ch = await newChannel();
    const g = gate();
    await publish(ch, 2);
    const [a, b] = await Promise.all([g.requestSeal(ch, "publisher", "rc1"), g.requestSeal(ch, "ab".repeat(32), "rc2")]);
    expect([a, b].filter((r) => r.honored)).toHaveLength(1);
    expect([a, b].filter((r) => !r.honored && r.reason === "rate_limited")).toHaveLength(1);
    expect(sealStore.latest(ch)?.epoch_index).toBe(0);
    expect(events.filter((e) => e.event === "channel.epoch.sealed")).toHaveLength(1);
  });

  it("two channels have independent windows", async () => {
    const a = await newChannel();
    const b = await newChannel();
    const g = gate();
    await publish(a, 1);
    await publish(b, 1);
    expect((await g.requestSeal(a, "publisher", "r6a")).honored).toBe(true);
    const r = await g.requestSeal(b, "publisher", "r6b");
    expect(r).toMatchObject({ honored: true, epoch_index: 0, leaf_count: 1 });
  });
});

describe("M16 011-SEALREQ: the cello_channel_seal IPC verb", () => {
  function handler(): IpcHandler {
    const handlers = new Map<string, IpcHandler>();
    const byName = new Map<string, InMemoryKeyProvider>();
    for (const a of new DbIdentityStore(db, logger).listAgents()) {
      const kp = keys.get(a.kLocalPubkey);
      if (kp) byName.set(a.agentName, kp);
    }
    registerChannelSealHandler({
      handlers, logger, now: () => clock,
      sessionNodeManager: { getDb: () => db, getChannelLogStore: () => log },
      getKeyProvider: (n) => byName.get(n),
    });
    const h = handlers.get("cello_channel_seal");
    if (!h) throw new Error("cello_channel_seal was not registered");
    return h;
  }

  it("IPC cello_channel_seal on a non-channel agent errors not_a_channel", async () => {
    const hex = await newChannel();
    new DbIdentityStore(db, logger).createAgent("plain", new Uint8Array(32).fill(2), hex);
    await publish(hex, 1);
    const r = (await handler()({ agent: "plain" }, "conn-1")) as { ok?: boolean; reason?: string; guidance?: string };
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("not_a_channel");
    expect(typeof r.guidance).toBe("string");
    expect(sealStore.latest(hex), "a non-channel must not be sealed").toBeNull();
    const unknown = (await handler()({ agent: "plian" }, "conn-1")) as { ok?: boolean; reason?: string };
    expect(unknown).toMatchObject({ ok: false, reason: "agent_not_found" });
  });

  it("IPC cello_channel_seal on a channel returns the honored outcome", async () => {
    const hex = await newChannel();
    new DbIdentityStore(db, logger).createAgent("news", new Uint8Array(32).fill(1), hex);
    await new DbRegistrationPersistence({ db, agentName: "news", logger }).persistRegistrationState({
      agentId: "agent-news", primaryPubkey: "aa".repeat(32), mlDsaPubkey: "bb".repeat(32), registeredAt: 1,
      keyBinding: "cd".repeat(64), channel: true, adminPubkey: "ef".repeat(32),
    });
    await publish(hex, 2);
    const h = handler();
    const r = (await h({ agent: "news" }, "conn-1")) as Record<string, unknown>;
    const latest = sealStore.latest(hex);
    expect(latest).not.toBeNull();
    expect(r).toEqual({ honored: true, epoch_index: 0, epoch_root: hx(latest!.epoch_root), leaf_count: 2 });
    expect(events.find((e) => e.event === "channel.seal_request.honored")?.ctx["requester"]).toBe("publisher");

    clock += HOUR;
    const empty = (await h({ agent: "news" }, "conn-1")) as Record<string, unknown>;
    expect(empty).toEqual({ honored: false, reason: "epoch_empty", latest_epoch_index: 0, latest_epoch_root: hx(latest!.epoch_root) });
  });
});
