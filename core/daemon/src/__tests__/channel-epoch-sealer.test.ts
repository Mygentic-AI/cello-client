/**
 * M16 008-EPOCH — sealing a channel's epoch, and the cap that bounds how long a channel can lie.
 *
 * Until an epoch is sealed and notarized, a channel could show two subscribers two different
 * message #47s. So an epoch is force-sealed 24h after its first leaf or at 1,000 leaves, whichever
 * comes first; an empty epoch never seals; a channel may only shorten the cap. Real SQLCipher DB,
 * real signatures, and a controllable clock — the scheduler itself is proven by the enforcer.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeypair } from "@cello-protocol/crypto";
import type { InMemoryKeyProvider } from "@cello-protocol/crypto";
import {
  checkEpochChainLink,
  decodeChannelEpochSeal,
  signBroadcastArtifact,
  verifyChannelEpochSealSignature,
  type ChannelEpochSeal,
} from "@cello-protocol/protocol-types";
import { ChannelLogStore } from "../channel-log-store.js";
import { ChannelEpochSealStore } from "../channel-epoch-seal-store.js";
import {
  ChannelEpochSealer,
  EPOCH_MAX_AGE_MS,
  EPOCH_MAX_LEAVES,
  type SealOutcome,
} from "../channel-epoch-sealer.js";
import { openTestDb } from "./helpers/encrypted-db.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";
import type { Logger } from "../types.js";

let dir: string;
let db: DaemonDatabase;
let log: ChannelLogStore;
let sealStore: ChannelEpochSealStore;
let events: Array<{ level: string; event: string; ctx: Record<string, unknown> }>;
let clock: number;
let kp: InMemoryKeyProvider;
let hex: string;

const logger: Logger = {
  debug(event, ctx) { events.push({ level: "debug", event, ctx: ctx ?? {} }); },
  info(event, ctx) { events.push({ level: "info", event, ctx: ctx ?? {} }); },
  warn(event, ctx) { events.push({ level: "warn", event, ctx: ctx ?? {} }); },
  error(event, ctx) { events.push({ level: "error", event, ctx: ctx ?? {} }); },
};

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "cello-epoch-sealer-"));
  db = openTestDb(join(dir, "sessions.db"));
  events = [];
  clock = 1_789_000_000_000;
  log = new ChannelLogStore(db, logger);
  sealStore = new ChannelEpochSealStore(db, logger);
  kp = generateKeypair();
  hex = Buffer.from(await kp.getPublicKey()).toString("hex");
  log.ensureChannel(hex);
});
afterEach(() => {
  db.close();
  rmSync(dir, { recursive: true, force: true });
});

function sealer(overrides: { getKeyProvider?: (h: string) => InMemoryKeyProvider | null } = {}): ChannelEpochSealer {
  return new ChannelEpochSealer({
    log,
    sealStore,
    getKeyProvider: overrides.getKeyProvider ?? ((h) => (h === hex ? kp : null)),
    logger,
    now: () => clock,
  });
}

/** Publish `n` artifacts at the current clock. */
async function publish(n: number): Promise<void> {
  for (let i = 0; i < n; i++) {
    const pos = log.nextPosition(hex);
    const a = await signBroadcastArtifact(kp, {
      seq: pos.seq, epoch_index: pos.epoch_index, title: `p${pos.seq}`, body_ciphertext: new Uint8Array([1]),
      supersedes: null, prev_epoch_root: pos.first_in_epoch ? pos.prev_epoch_root : null, ext: null,
    });
    log.append(hex, a, clock);
  }
}

function decoded(outcome: SealOutcome): ChannelEpochSeal {
  const d = decodeChannelEpochSeal(outcome.seal_cbor);
  if (!d.ok) throw new Error(`seal did not decode: ${d.reason}`);
  return d.seal;
}

const DEFAULT_POLICY = { maxAgeMs: EPOCH_MAX_AGE_MS, maxLeaves: EPOCH_MAX_LEAVES };
const hx = (b: Uint8Array) => Buffer.from(b).toString("hex");

describe("M16 008-EPOCH: ChannelEpochSealer", () => {
  it("sealNow on an empty epoch refuses with epoch_empty", async () => {
    const r = await sealer().sealNow(hex, "c1");
    expect(r).toEqual({ sealed: false, reason: "epoch_empty" });
    expect(sealStore.latest(hex)).toBeNull();
    expect(log.nextPosition(hex).epoch_index).toBe(0);
    expect(events.some((e) => e.event === "channel.epoch.seal_skipped_empty" && e.level === "info")).toBe(true);
  });

  it("sealNow with 3 leaves produces a verifying seal and closes the epoch", async () => {
    await publish(3);
    const before = log.openEpochRoot(hex);
    const r = await sealer().sealNow(hex, "c2");
    if (!r.sealed) throw new Error(`expected a seal, got ${JSON.stringify(r)}`);
    const seal = decoded(r);
    expect(verifyChannelEpochSealSignature(seal)).toBe(true);
    expect(hx(seal.epoch_root)).toBe(hx(before.root));
    expect(seal.leaf_count).toBe(3);
    expect(seal.first_seq).toBe(1);
    expect(seal.notarization).toBeNull();
    const pos = log.nextPosition(hex);
    expect(pos.epoch_index).toBe(1);
    expect(hx(pos.prev_epoch_root!)).toBe(hx(before.root));
    const sealed = events.find((e) => e.event === "channel.epoch.sealed");
    expect(sealed?.ctx).toMatchObject({ correlationId: "c2", channel_pubkey: hex, epoch_index: 0, leaf_count: 3, first_seq: 1, trigger: "explicit" });
  });

  it("two consecutive seals chain", async () => {
    const s = sealer();
    await publish(3);
    const r0 = await s.sealNow(hex, "c3a");
    await publish(2);
    const r1 = await s.sealNow(hex, "c3b");
    if (!r0.sealed || !r1.sealed) throw new Error("expected two seals");
    const seal0 = decoded(r0);
    const seal1 = decoded(r1);
    expect(checkEpochChainLink(seal0, seal1)).toEqual({ ok: true });
    expect(seal1.first_seq).toBe(4);
  });

  it("age cap: 24h minus one minute is not due; 24h is due", async () => {
    const openedAt = clock;
    await publish(1);
    const s = sealer();
    clock = openedAt + 86_340_000;
    expect(await s.sealIfDue(hex, DEFAULT_POLICY, "c4a")).toEqual({ sealed: false, reason: "not_due" });
    clock = openedAt + 86_400_000;
    const r = await s.sealIfDue(hex, DEFAULT_POLICY, "c4b");
    expect(r.sealed).toBe(true);
    expect(events.find((e) => e.event === "channel.epoch.sealed")?.ctx["trigger"]).toBe("cap_age");
  });

  it("leaf cap: 999 leaves not due, 1000 due", async () => {
    const s = sealer();
    await publish(999);
    expect(await s.sealIfDue(hex, DEFAULT_POLICY, "c5a")).toEqual({ sealed: false, reason: "not_due" });
    await publish(1);
    const r = await s.sealIfDue(hex, DEFAULT_POLICY, "c5b");
    expect(r.sealed).toBe(true);
    expect(events.find((e) => e.event === "channel.epoch.sealed")?.ctx["trigger"]).toBe("cap_leaves");
  }, 60_000);

  it("a shorter declared policy is honored; a longer one is refused", () => {
    expect(ChannelEpochSealer.validatePolicy({ maxAgeMs: 3_600_000 })).toEqual({ maxAgeMs: 3_600_000, maxLeaves: EPOCH_MAX_LEAVES });
    expect(() => ChannelEpochSealer.validatePolicy({ maxAgeMs: 172_800_000 })).toThrow(RangeError);
    expect(() => ChannelEpochSealer.validatePolicy({ maxLeaves: 5000 })).toThrow(RangeError);
  });

  it("empty open epoch is never force-sealed by age", async () => {
    clock += 10 * EPOCH_MAX_AGE_MS;
    const r = await sealer().sealIfDue(hex, DEFAULT_POLICY, "c7");
    expect(r.sealed).toBe(false);
    expect(sealStore.latest(hex)).toBeNull();
    expect(log.nextPosition(hex).epoch_index).toBe(0);
  });

  it("seal record and epoch close are atomic", async () => {
    await publish(2);
    const before = log.nextPosition(hex);
    const original = sealStore.record.bind(sealStore);
    sealStore.record = () => { throw new Error("simulated record failure"); };
    await expect(sealer().sealNow(hex, "c8")).rejects.toThrow(/simulated record failure/);
    sealStore.record = original;
    expect(log.nextPosition(hex)).toEqual(before);
    expect(sealStore.latest(hex)).toBeNull();
  });

  it("a close refused after the record rolls the record back", async () => {
    // The other direction of the same atomicity: a publish lands while the seal is being signed, so
    // the log refuses the close (epoch_changed). The seal row must not survive without its close.
    await publish(1);
    const s = new ChannelEpochSealer({
      log, sealStore, logger, now: () => clock,
      getKeyProvider: () => ({
        getPublicKey: () => kp.getPublicKey(),
        sign: async (m: Uint8Array) => { await publish(1); return kp.sign(m); },
      } as unknown as InMemoryKeyProvider),
    });
    await expect(s.sealNow(hex, "c8b")).rejects.toThrow(/epoch_changed/);
    expect(sealStore.latest(hex)).toBeNull();
    expect(log.nextPosition(hex).epoch_index).toBe(0);
    expect(events.some((e) => e.event === "channel.epoch.seal_failed" && e.ctx["reason"] === "epoch_changed")).toBe(true);
  });

  it("markNotarized is the only mutation", async () => {
    await publish(1);
    const r = await sealer().sealNow(hex, "c9");
    if (!r.sealed) throw new Error("expected a seal");
    const notarizedCbor = new Uint8Array([9, 9, 9]);
    sealStore.markNotarized(hex, 0, notarizedCbor);
    const got = sealStore.get(hex, 0)!;
    expect(hx(got.seal_cbor)).toBe(hx(notarizedCbor));
    expect(got.notarized).toBe(true);
    let code: string | undefined;
    try { sealStore.record(hex, decoded(r)); } catch (err) { code = (err as { code?: string }).code; }
    expect(code).toBe("seal_position_taken");
  });

  it("a channel with no key is refused with key_unavailable", async () => {
    await publish(1);
    const r = await sealer({ getKeyProvider: () => null }).sealNow(hex, "c10");
    expect(r).toEqual({ sealed: false, reason: "key_unavailable" });
    expect(events.some((e) => e.event === "channel.epoch.seal_failed" && e.level === "error" && e.ctx["reason"] === "key_unavailable")).toBe(true);
  });
});
