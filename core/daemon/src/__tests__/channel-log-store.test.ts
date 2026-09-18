/**
 * M16 016-CLIENTREWORK — the publisher-side channel log, reworked for the post-epoch design.
 *
 * A channel keeps ONE append-only log of every post it published. It is the durable copy a relay is
 * refilled from, so its rows are immutable: only `pruneThrough` deletes, only from the oldest end.
 * Beside each post sit the relays' signed receipts — the publisher's proof of what it sent and when
 * each relay took it — and a receipt is VERIFIED before it is stored, because an unverified receipt
 * is worthless as proof.
 *
 * Real SQLCipher DB, real signatures. Expected values are recomputed inline from the primitives,
 * never read back from the store.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeypair } from "@cello-protocol/crypto";
import type { InMemoryKeyProvider } from "@cello-protocol/crypto";
import {
  encodeBroadcastArtifact,
  signBroadcastArtifact,
  signRelayPostReceipt,
  verifyBroadcastArtifact,
  verifyRelayPostReceipt,
  type BroadcastArtifact,
  type RelayPostReceipt,
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

interface Channel {
  kp: InMemoryKeyProvider;
  agent: InMemoryKeyProvider;
  hex: string;
}

async function channel(): Promise<Channel> {
  const kp = generateKeypair();
  const agent = generateKeypair();
  const hex = Buffer.from(await kp.getPublicKey()).toString("hex");
  store.ensureChannel(hex);
  return { kp, agent, hex };
}

/** Sign at exactly what nextPosition reports, with optional overrides, WITHOUT appending. */
async function signAt(
  ch: Channel,
  overrides: Partial<Omit<BroadcastArtifact, "channel_signature" | "agent_signature" | "channel_pubkey" | "agent_pubkey">> = {},
): Promise<BroadcastArtifact> {
  const pos = store.nextPosition(ch.hex);
  return signBroadcastArtifact(ch.kp, ch.agent, {
    seq: pos.seq,
    published_at: 1_789_000_000_000 + pos.seq,
    title: `post ${pos.seq}`,
    body: new Uint8Array([pos.seq, 1, 2, 3]),
    supersedes: null,
    ext: null,
    ...overrides,
  });
}

async function publish(ch: Channel): Promise<BroadcastArtifact> {
  const post = await signAt(ch);
  store.append(ch.hex, post);
  return post;
}

async function receipt(post: BroadcastArtifact, relay = generateKeypair(), at = 1_789_000_500_000): Promise<RelayPostReceipt> {
  return signRelayPostReceipt(relay, post, at);
}

function expectCode(fn: () => unknown, code: string): void {
  let thrown: unknown;
  try { fn(); } catch (err) { thrown = err; }
  expect(thrown, `expected ChannelLogError ${code}`).toBeInstanceOf(ChannelLogError);
  expect((thrown as ChannelLogError).code).toBe(code);
}

const rowCount = (table: string, hex: string): number =>
  Number((db.prepare(`SELECT COUNT(*) AS n FROM ${table} WHERE channel_pubkey = ?`).get(hex) as { n: number | bigint }).n);

describe("M16 016-CLIENTREWORK: ChannelLogStore", () => {
  it("13. the first append lands at seq 1 and reads back byte-identical", async () => {
    const ch = await channel();
    expect(store.nextPosition(ch.hex)).toEqual({ seq: 1 });
    const post = await publish(ch);
    expect(post.seq).toBe(1);

    const read = store.readRange(ch.hex, 1, 10);
    expect(read).toHaveLength(1);
    expect(encodeBroadcastArtifact(read[0])).toEqual(encodeBroadcastArtifact(post));
    expect(verifyBroadcastArtifact(read[0])).toEqual({ ok: true });
    expect(store.head(ch.hex)).toEqual({ first_seq: 1, last_seq: 1, pruned_through: 0 });
    expect(store.nextPosition(ch.hex)).toEqual({ seq: 2 });
  });

  it("14. seq_not_next and position_taken refuse and write nothing", async () => {
    const ch = await channel();
    await publish(ch);

    const skipped = await signAt(ch, { seq: 5 });
    expectCode(() => store.append(ch.hex, skipped), "seq_not_next");

    // A post re-signed at a position already taken: the store never overwrites a published row.
    const taken = await signAt(ch, { seq: 1, title: "rewritten" });
    expectCode(() => store.append(ch.hex, taken), "seq_not_next");

    expect(rowCount("channel_log", ch.hex)).toBe(1);
    expect(store.readRange(ch.hex, 1, 10)[0].title).toBe("post 1");

    // And the direct collision: the position is next by state, but the row is already there.
    db.prepare("UPDATE channel_state SET next_seq = 1 WHERE channel_pubkey = ?").run(ch.hex);
    expectCode(() => store.append(ch.hex, taken), "position_taken");
    expect(rowCount("channel_log", ch.hex)).toBe(1);

    // An unknown channel is named, never auto-created.
    expectCode(() => store.append("ff".repeat(32), taken), "channel_unknown");
  });

  it("15. a receipt for another post is refused receipt_invalid and written nowhere", async () => {
    const ch = await channel();
    const first = await publish(ch);
    const second = await publish(ch);

    // Signed over `second`, filed against `first`: only the hash tells them apart.
    const wrong = await receipt(second);
    expectCode(() => store.recordReceipt(ch.hex, { ...wrong, seq: first.seq }), "receipt_invalid");
    expect(rowCount("channel_log_receipts", ch.hex)).toBe(0);

    // A receipt whose own signature does not verify is refused too.
    const good = await receipt(first);
    const forged: RelayPostReceipt = { ...good, received_at: good.received_at + 1 };
    expect(verifyRelayPostReceipt(forged, first)).toBe(false);
    expectCode(() => store.recordReceipt(ch.hex, forged), "receipt_invalid");
    expect(rowCount("channel_log_receipts", ch.hex)).toBe(0);

    // A receipt for a post this log does not hold names the missing post, not the signature.
    const absent = await signBroadcastArtifact(ch.kp, ch.agent, {
      seq: 99, published_at: 1, title: "not in the log", body: new Uint8Array([1]), supersedes: null, ext: null,
    });
    const forAbsent = await receipt(absent);
    expectCode(() => store.recordReceipt(ch.hex, forAbsent), "receipt_invalid");
    expect(rowCount("channel_log_receipts", ch.hex)).toBe(0);
  });

  it("16. two relays' receipts for one post are both kept, and a repeat is a no-op", async () => {
    const ch = await channel();
    const post = await publish(ch);
    const relayA = generateKeypair();
    const relayB = generateKeypair();
    const a = await receipt(post, relayA, 1_789_000_500_000);
    const b = await receipt(post, relayB, 1_789_000_600_000);

    store.recordReceipt(ch.hex, a);
    store.recordReceipt(ch.hex, b);
    store.recordReceipt(ch.hex, a); // idempotent: same relay, same post, identical bytes

    // A DIFFERENT receipt from the SAME relay — a re-ack after a reconnect, with a later time. The
    // row is keyed on (channel, seq, relay), so it cannot be stored; what must not happen is the
    // store reporting it as stored, which would put a received_at in the log that disagrees with
    // the bytes actually kept.
    const later = await receipt(post, relayA, 1_789_000_900_000);
    store.recordReceipt(ch.hex, later);
    const afterRepeat = store.receiptsFor(ch.hex, post.seq)
      .find((r) => Buffer.from(r.relay_pubkey).equals(Buffer.from(a.relay_pubkey)));
    expect(afterRepeat?.received_at).toBe(1_789_000_500_000);

    const stored = store.receiptsFor(ch.hex, post.seq);
    expect(stored).toHaveLength(2);
    for (const r of stored) expect(verifyRelayPostReceipt(r, post)).toBe(true);
    expect(stored.map((r) => r.received_at).sort()).toEqual([1_789_000_500_000, 1_789_000_600_000]);
    expect(
      stored.map((r) => Buffer.from(r.relay_pubkey).toString("hex")).sort(),
    ).toEqual([
      Buffer.from(await relayA.getPublicKey()).toString("hex"),
      Buffer.from(await relayB.getPublicKey()).toString("hex"),
    ].sort());
  });

  it("17. readRange refuses a tampered row with log_row_corrupt", async () => {
    const ch = await channel();
    await publish(ch);
    const post2 = await publish(ch);

    // Rewrite the stored bytes behind the store's back: a row that no longer decodes, or no longer
    // carries valid signatures, is corruption — never something to skip past or hand to a relay.
    const broken = new Uint8Array(encodeBroadcastArtifact(post2));
    broken[broken.length - 1] ^= 0x01; // breaks the agent signature, not the CBOR shape
    db.prepare("UPDATE channel_log SET post_cbor = ? WHERE channel_pubkey = ? AND seq = ?")
      .run(Buffer.from(broken), ch.hex, post2.seq);
    expectCode(() => store.readRange(ch.hex, 1, 10), "log_row_corrupt");

    db.prepare("UPDATE channel_log SET post_cbor = ? WHERE channel_pubkey = ? AND seq = ?")
      .run(Buffer.from(new Uint8Array([0xfe, 0x01])), ch.hex, post2.seq);
    expectCode(() => store.readRange(ch.hex, 1, 10), "log_row_corrupt");
  });

  it("18. pruneThrough deletes posts AND their receipts, and head reports the new first_seq", async () => {
    const ch = await channel();
    const posts: BroadcastArtifact[] = [];
    for (let i = 0; i < 5; i++) posts.push(await publish(ch));
    for (const p of posts) store.recordReceipt(ch.hex, await receipt(p));
    expect(rowCount("channel_log_receipts", ch.hex)).toBe(5);

    expect(store.pruneThrough(ch.hex, 3)).toEqual({ pruned: 3 });
    expect(store.head(ch.hex)).toEqual({ first_seq: 4, last_seq: 5, pruned_through: 3 });
    expect(store.readRange(ch.hex, 1, 10).map((p) => p.seq)).toEqual([4, 5]);
    // The receipts of pruned posts go with them — they are proof about bytes that no longer exist.
    expect(rowCount("channel_log_receipts", ch.hex)).toBe(2);
    expect(store.receiptsFor(ch.hex, 1)).toEqual([]);
    expect(store.receiptsFor(ch.hex, 4)).toHaveLength(1);
  });

  it("19. a prune below pruned_through is refused, and a repeat is a no-op", async () => {
    const ch = await channel();
    for (let i = 0; i < 4; i++) await publish(ch);
    store.pruneThrough(ch.hex, 2);

    expectCode(() => store.pruneThrough(ch.hex, 1), "prune_regression");
    expect(store.head(ch.hex)).toEqual({ first_seq: 3, last_seq: 4, pruned_through: 2 });

    expect(store.pruneThrough(ch.hex, 2)).toEqual({ pruned: 0 });
    expect(store.head(ch.hex)).toEqual({ first_seq: 3, last_seq: 4, pruned_through: 2 });
    expect(store.readRange(ch.hex, 1, 10).map((p) => p.seq)).toEqual([3, 4]);
  });

  it("20. appending continues from the same numbers after a prune", async () => {
    const ch = await channel();
    for (let i = 0; i < 3; i++) await publish(ch);
    store.pruneThrough(ch.hex, 3);

    // Everything is pruned, so the log is empty — but the numbering never restarts, or a later
    // post would collide with one a subscriber already holds.
    expect(store.head(ch.hex)).toEqual({ first_seq: null, last_seq: null, pruned_through: 3 });
    expect(store.nextPosition(ch.hex)).toEqual({ seq: 4 });
    const fourth = await publish(ch);
    expect(fourth.seq).toBe(4);
    expect(store.head(ch.hex)).toEqual({ first_seq: 4, last_seq: 4, pruned_through: 3 });
  });

  it("21. two channels do not interfere", async () => {
    const one = await channel();
    const two = await channel();
    await publish(one);
    await publish(one);
    const post = await publish(two);
    store.recordReceipt(two.hex, await receipt(post));

    expect(store.head(one.hex)).toEqual({ first_seq: 1, last_seq: 2, pruned_through: 0 });
    expect(store.head(two.hex)).toEqual({ first_seq: 1, last_seq: 1, pruned_through: 0 });
    store.pruneThrough(one.hex, 2);
    expect(store.head(two.hex)).toEqual({ first_seq: 1, last_seq: 1, pruned_through: 0 });
    expect(store.receiptsFor(two.hex, 1)).toHaveLength(1);
    expect(rowCount("channel_log", two.hex)).toBe(1);

    // A post signed by ONE channel, filed under the OTHER. Every other check passes — the number is
    // next, it encodes, it decodes, and both signatures verify against the keys the post NAMES — so
    // only an explicit binding check refuses it. Without it, `two`'s relay is later refilled with
    // `one`'s posts and every subscriber of `two` rejects them for a key mismatch.
    const strayPos = store.nextPosition(two.hex);
    const stray = await signBroadcastArtifact(one.kp, one.agent, {
      seq: strayPos.seq, published_at: 1_789_000_000_001, title: "signed by the other channel",
      body: new Uint8Array([7]), supersedes: null, ext: null,
    });
    expect(verifyBroadcastArtifact(stray)).toEqual({ ok: true });
    expectCode(() => store.append(two.hex, stray), "post_invalid");
    expect(rowCount("channel_log", two.hex)).toBe(1);
    expect(store.nextPosition(two.hex)).toEqual(strayPos);

    // And the same for a receipt that names another channel.
    const strayReceipt = await receipt(post);
    expectCode(
      () => store.recordReceipt(one.hex, strayReceipt),
      "receipt_invalid",
    );

    // A receipt for a PRUNED post is not an invalid receipt — the log simply no longer holds the
    // bytes, and an operator told "receipt_invalid" would go and debug the relay's signing key.
    const pruned = await receipt((await store.readRange(two.hex, 1, 1))[0]);
    store.pruneThrough(two.hex, 1);
    expectCode(() => store.recordReceipt(two.hex, pruned), "post_pruned");

    // An unknown channel is named rather than answered with an empty log.
    expectCode(() => store.head("ab".repeat(32)), "channel_unknown");
    expectCode(() => store.readRange("ab".repeat(32), 1, 5), "channel_unknown");
  });
});
