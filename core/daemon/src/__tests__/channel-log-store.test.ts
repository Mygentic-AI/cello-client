/**
 * M16 007-PUBLOG — the publisher-side channel log.
 *
 * A channel keeps ONE append-only log of every artifact it published. It is the durable copy
 * subscribers repair from, so its rows are immutable and every position check throws its own code.
 * Real SQLCipher DB, real signatures; expected roots are recomputed inline from the crypto
 * primitives, never read back from the store.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildMerkleTree, generateKeypair, merkleRoot } from "@cello-protocol/crypto";
import type { InMemoryKeyProvider } from "@cello-protocol/crypto";
import {
  broadcastArtifactLeafHash,
  signBroadcastArtifact,
  verifyBroadcastArtifact,
  type BroadcastArtifact,
} from "@cello-protocol/protocol-types";
import { ChannelLogStore, ChannelLogError } from "../channel-log-store.js";
import { openTestDb } from "./helpers/encrypted-db.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";
import type { Logger } from "../types.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };

let dir: string;
let db: DaemonDatabase;
let store: ChannelLogStore;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "cello-channel-log-"));
  db = openTestDb(join(dir, "sessions.db"));
  store = new ChannelLogStore(db, silent);
});
afterEach(() => {
  db.close();
  rmSync(dir, { recursive: true, force: true });
});

async function channel(): Promise<{ kp: InMemoryKeyProvider; hex: string }> {
  const kp = generateKeypair();
  const hex = Buffer.from(await kp.getPublicKey()).toString("hex");
  store.ensureChannel(hex);
  return { kp, hex };
}

/** Sign at exactly what nextPosition reports, with optional overrides, WITHOUT appending. */
async function signAt(
  kp: InMemoryKeyProvider,
  hex: string,
  overrides: Partial<Omit<BroadcastArtifact, "signature" | "channel_pubkey">> = {},
): Promise<BroadcastArtifact> {
  const pos = store.nextPosition(hex);
  return signBroadcastArtifact(kp, {
    seq: pos.seq,
    epoch_index: pos.epoch_index,
    title: `post ${pos.seq}`,
    body_ciphertext: new Uint8Array([pos.seq, 1, 2, 3]),
    supersedes: null,
    prev_epoch_root: pos.first_in_epoch ? pos.prev_epoch_root : null,
    ext: null,
    ...overrides,
  });
}

async function publish(kp: InMemoryKeyProvider, hex: string) {
  const a = await signAt(kp, hex);
  return { artifact: a, result: store.append(hex, a, 1_789_000_000_000 + a.seq) };
}

function rootOver(artifacts: BroadcastArtifact[]): Uint8Array {
  return merkleRoot(buildMerkleTree(artifacts.map((a) => ({ kind: "hash" as const, data: broadcastArtifactLeafHash(a) }))));
}

function expectCode(fn: () => unknown, code: string): void {
  let thrown: unknown;
  try { fn(); } catch (err) { thrown = err; }
  expect(thrown, `expected ChannelLogError ${code}`).toBeInstanceOf(ChannelLogError);
  expect((thrown as ChannelLogError).code).toBe(code);
}

const hex32 = (b: Uint8Array) => Buffer.from(b).toString("hex");

describe("M16 007-PUBLOG: ChannelLogStore", () => {
  it("ensureChannel is idempotent", async () => {
    const { hex } = await channel();
    store.ensureChannel(hex);
    const rows = db.prepare("SELECT COUNT(*) AS n FROM channel_epoch_state WHERE channel_pubkey = ?").get(hex) as { n: number };
    expect(Number(rows.n)).toBe(1);
    expect(store.nextPosition(hex).seq).toBe(1);
  });

  it("first append lands at seq 1 epoch 0 with a real root", async () => {
    const { kp, hex } = await channel();
    const { artifact, result } = await publish(kp, hex);
    expect(result.seq).toBe(1);
    expect(result.epoch_index).toBe(0);
    expect(result.leaf_count).toBe(1);
    expect(hex32(result.epoch_root)).toBe(hex32(rootOver([artifact])));
  });

  it("three appends: root equals independent recomputation over all three leaf hashes", async () => {
    const { kp, hex } = await channel();
    const a1 = (await publish(kp, hex)).artifact;
    const a2 = (await publish(kp, hex)).artifact;
    const { artifact: a3, result } = await publish(kp, hex);
    expect(result.leaf_count).toBe(3);
    expect(hex32(result.epoch_root)).toBe(hex32(rootOver([a1, a2, a3])));
    expect(hex32(store.openEpochRoot(hex).root)).toBe(hex32(rootOver([a1, a2, a3])));
  });

  it("seq_not_next", async () => {
    const { kp, hex } = await channel();
    await publish(kp, hex);
    const wrong = await signAt(kp, hex, { seq: 5 });
    expectCode(() => store.append(hex, wrong, 1), "seq_not_next");
    expect(store.nextPosition(hex).seq).toBe(2);
    expect(store.readRange(hex, 2, 10)).toEqual([]);
  });

  it("epoch_mismatch", async () => {
    const { kp, hex } = await channel();
    const wrong = await signAt(kp, hex, { epoch_index: 1, prev_epoch_root: new Uint8Array(32).fill(9) });
    expectCode(() => store.append(hex, wrong, 1), "epoch_mismatch");
  });

  it("prev_root_mismatch, both directions", async () => {
    const { kp, hex } = await channel();
    // Built by hand: signBroadcastArtifact refuses to sign an epoch-0 artifact carrying a root, so
    // this shape can only reach the store from a caller that skipped the signer. Check (4) runs first.
    const carrying: BroadcastArtifact = { ...(await signAt(kp, hex)), prev_epoch_root: new Uint8Array(32).fill(7) };
    expectCode(() => store.append(hex, carrying, 1), "prev_root_mismatch");

    const root0 = (await publish(kp, hex)).result.epoch_root;
    store.closeEpoch(hex, root0);
    const missing = await signAt(kp, hex, { prev_epoch_root: null });
    expectCode(() => store.append(hex, missing, 2), "prev_root_mismatch");
    const wrongRoot = Uint8Array.from(root0);
    wrongRoot[0] ^= 1;
    const wrong = await signAt(kp, hex, { prev_epoch_root: wrongRoot });
    expectCode(() => store.append(hex, wrong, 2), "prev_root_mismatch");
    const right = await signAt(kp, hex, { prev_epoch_root: root0 });
    expect(store.append(hex, right, 2).epoch_index).toBe(1);
  });

  it("position_taken", async () => {
    const { kp, hex } = await channel();
    const { artifact } = await publish(kp, hex);
    // Rewind next_seq by hand so the only guard left is the row itself.
    db.prepare("UPDATE channel_epoch_state SET next_seq = 1 WHERE channel_pubkey = ?").run(hex);
    expectCode(() => store.append(hex, artifact, 2), "position_taken");
    const n = db.prepare("SELECT COUNT(*) AS n FROM channel_log WHERE channel_pubkey = ?").get(hex) as { n: number };
    expect(Number(n.n)).toBe(1);
    expect(hex32(store.readRange(hex, 1, 1)[0]!.signature)).toBe(hex32(artifact.signature));
  });

  it("artifact_invalid", async () => {
    const { kp, hex } = await channel();
    const signed = await signAt(kp, hex);
    const handBuilt: BroadcastArtifact = { ...signed, title: "badtitle" };
    expectCode(() => store.append(hex, handBuilt, 1), "artifact_invalid");
    const n = db.prepare("SELECT COUNT(*) AS n FROM channel_log").get() as { n: number };
    expect(Number(n.n)).toBe(0);
  });

  it("closeEpoch advances state", async () => {
    const { kp, hex } = await channel();
    await publish(kp, hex);
    await publish(kp, hex);
    const { result } = await publish(kp, hex);
    store.closeEpoch(hex, result.epoch_root);
    const pos = store.nextPosition(hex);
    expect(pos.epoch_index).toBe(1);
    expect(pos.first_in_epoch).toBe(true);
    expect(hex32(pos.prev_epoch_root!)).toBe(hex32(result.epoch_root));
    expect(store.openEpochLeafHashes(hex)).toEqual([]);
    expect(store.openEpochRoot(hex).leaf_count).toBe(0);
    expect(store.readRange(hex, 1, 3).map((a) => a.seq)).toEqual([1, 2, 3]);
  });

  it("readRange returns decoded artifacts in seq order and verifies", async () => {
    const { kp, hex } = await channel();
    for (let i = 0; i < 4; i++) await publish(kp, hex);
    const got = store.readRange(hex, 1, 4);
    expect(got.map((a) => a.seq)).toEqual([1, 2, 3, 4]);
    for (const a of got) expect(verifyBroadcastArtifact(a)).toBe(true);
  });

  it("two channels do not interfere", async () => {
    const A = await channel();
    const B = await channel();
    await publish(A.kp, A.hex);
    await publish(A.kp, A.hex);
    expect(store.nextPosition(A.hex).seq).toBe(3);
    expect(store.nextPosition(B.hex).seq).toBe(1);
  });

  it("an unknown channel is refused", async () => {
    const kp = generateKeypair();
    const hex = Buffer.from(await kp.getPublicKey()).toString("hex");
    store.ensureChannel(hex);
    const a = await signAt(kp, hex);
    const other = "ab".repeat(32);
    expectCode(() => store.append(other, a, 1), "channel_unknown");
    expectCode(() => store.readRange(other, 1, 10), "channel_unknown");
  });

  it("first-in-epoch bookkeeping: first_seq, opened_at, and only the first leaf carries a root", async () => {
    // Review: never updating first_seq/opened_at, or dropping the "later leaves carry no root"
    // branch, left every other test green.
    const { kp, hex } = await channel();
    const root0 = (await publish(kp, hex)).result.epoch_root;
    store.closeEpoch(hex, root0);
    const first = await signAt(kp, hex, { prev_epoch_root: root0 });
    store.append(hex, first, 5_000);
    const second = await signAt(kp, hex, { prev_epoch_root: null });
    const r2 = store.append(hex, second, 6_000);
    expect(r2.leaf_index).toBe(1);
    const open = store.openEpochRoot(hex);
    expect(open.first_seq).toBe(2);
    expect(open.opened_at).toBe(5_000);
    // Built by hand: a later leaf carrying a root cannot be signed, but the store must refuse it.
    const third: BroadcastArtifact = { ...(await signAt(kp, hex, { prev_epoch_root: null })), prev_epoch_root: root0 };
    expectCode(() => store.append(hex, third, 7_000), "prev_root_mismatch");
  });

  it("the log row and the state change in one transaction", async () => {
    // Review: removing BEGIN/COMMIT left every other test green. A state update that fails after
    // the row is written must leave no row behind.
    const { kp, hex } = await channel();
    db.exec(`CREATE TRIGGER fail_state_update BEFORE UPDATE ON channel_epoch_state BEGIN SELECT RAISE(ABORT, 'simulated state write failure'); END;`);
    const a = await signAt(kp, hex);
    expect(() => store.append(hex, a, 1)).toThrow(/simulated state write failure/);
    const n = db.prepare("SELECT COUNT(*) AS n FROM channel_log").get() as { n: number };
    expect(Number(n.n)).toBe(0);
    db.exec("DROP TRIGGER fail_state_update");
    expect(store.append(hex, a, 1).seq, "the store is usable afterwards").toBe(1);
  });

  it("append stores title and published_at, and logs channel.artifact.appended", async () => {
    const events: Array<{ event: string; ctx: Record<string, unknown> }> = [];
    const recording: Logger = { debug() {}, warn() {}, error() {}, info(event, ctx) { events.push({ event, ctx: ctx ?? {} }); } };
    const s = new ChannelLogStore(db, recording);
    const kp = generateKeypair();
    const hex = Buffer.from(await kp.getPublicKey()).toString("hex");
    s.ensureChannel(hex);
    const pos = s.nextPosition(hex);
    const a = await signBroadcastArtifact(kp, {
      seq: pos.seq, epoch_index: pos.epoch_index, title: "hello channel", body_ciphertext: new Uint8Array([1]),
      supersedes: null, prev_epoch_root: null, ext: null,
    });
    s.append(hex, a, 42_000, "corr-1");
    const row = db.prepare("SELECT title, published_at FROM channel_log WHERE channel_pubkey = ? AND seq = 1").get(hex) as { title: string; published_at: number };
    expect(row.title).toBe("hello channel");
    expect(Number(row.published_at)).toBe(42_000);
    const ev = events.find((e) => e.event === "channel.artifact.appended");
    expect(ev?.ctx).toMatchObject({ correlationId: "corr-1", channel_pubkey: hex, seq: 1, epoch_index: 0, leaf_count: 1 });
  });

  it("closeEpoch refuses a stale, repeated, empty, or malformed close", async () => {
    // Review HIGH: a close whose root no longer matches the open epoch orphaned a published artifact
    // in an epoch no seal covers; a repeated close skipped an epoch; an empty one sealed nothing.
    const { kp, hex } = await channel();
    const rootAtSigning = (await publish(kp, hex)).result.epoch_root;
    await publish(kp, hex); // a publish lands while the seal over one leaf is being signed
    expectCode(() => store.closeEpoch(hex, rootAtSigning), "epoch_changed");
    expect(store.nextPosition(hex).epoch_index, "a refused close leaves the epoch open").toBe(0);

    expectCode(() => store.closeEpoch(hex, new Uint8Array(31)), "sealed_root_invalid");

    const current = store.openEpochRoot(hex).root;
    store.closeEpoch(hex, current);
    expectCode(() => store.closeEpoch(hex, current), "epoch_changed");
    expect(store.nextPosition(hex).epoch_index, "a repeated close does not skip an epoch").toBe(1);
  });

  it("a full open epoch refuses the next append until it is sealed (epoch_full)", async () => {
    // 008 review: the leaf cap was only checked by the once-a-minute tick, so a burst of 5,000
    // publishes inside one minute sealed as ONE epoch. The cap has to hold at the append.
    const { kp, hex } = await channel();
    db.prepare("UPDATE channel_epoch_state SET max_leaves = 2 WHERE channel_pubkey = ?").run(hex);
    await publish(kp, hex);
    await publish(kp, hex);
    const third = await signAt(kp, hex);
    expectCode(() => store.append(hex, third, 1), "epoch_full");
    expect(store.openEpochRoot(hex).leaf_count, "nothing was filed").toBe(2);
    store.closeEpoch(hex, store.openEpochRoot(hex).root);
    await publish(kp, hex); // the next epoch accepts again

    // A stored cap above the protocol maximum does not lift the maximum.
    const other = await channel();
    db.prepare("UPDATE channel_epoch_state SET max_leaves = 5000 WHERE channel_pubkey = ?").run(other.hex);
    db.prepare("UPDATE channel_epoch_state SET next_seq = 1001, open_epoch_first_seq = 1 WHERE channel_pubkey = ?").run(other.hex);
    const over = await signAt(other.kp, other.hex);
    expectCode(() => store.append(other.hex, over, 1), "epoch_full");
  });

  it("readRange refuses a stored row that no longer matches its leaf hash", async () => {
    const { kp, hex } = await channel();
    await publish(kp, hex);
    db.prepare("UPDATE channel_log SET leaf_hash = ? WHERE channel_pubkey = ? AND seq = 1").run(Buffer.alloc(32, 1), hex);
    expectCode(() => store.readRange(hex, 1, 1), "log_row_corrupt");
  });
});
