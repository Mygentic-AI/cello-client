/**
 * The redesigned seal answer — every leaf the seal covers, in the relay's numbering, readable.
 *
 * The old answer listed only this side's own sends, numbered them from the local tree (0-based)
 * while other fields used the relay's sequence (1-based), and carried no text. These tests pin the
 * three things the redesign exists for: BOTH sides' messages, ONE numbering, and the closes labelled
 * with their author.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash, randomBytes } from "node:crypto";
import { encodeStructure1 } from "@cello-protocol/protocol-types";
import { openEncryptedDatabase, type DaemonDatabase } from "../sqlcipher-db.js";
import { ensureSessionSchema } from "../session-schema.js";
import { RelayReceiptStore } from "../relay-receipt-store.js";
import { SessionSealLeafStore } from "../session-seal-leaf-store.js";
import { SessionTree } from "../session-tree.js";
import { readSealedConversation } from "../sealed-conversation.js";
import { storeDeliveryAck, storeGivenDeliveryAck } from "../session-delivery-acks.js";
import type { Logger } from "../types.js";

const logger: Logger = { debug() {}, info() {}, warn() {}, error() {} };
const AGENT_ID = "agent-a";
const A = "aa".repeat(32);
const B = "bb".repeat(32);
const SID = "cd".repeat(16);

function h(label: string): string {
  return createHash("sha256").update(label).digest("hex");
}

let dir: string;
let db: DaemonDatabase;
let receipts: RelayReceiptStore;
let sealLeaves: SessionSealLeafStore;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "sealed-conv-"));
  db = openEncryptedDatabase(join(dir, "s.db"), randomBytes(32));
  ensureSessionSchema(db, logger, () => {});
  receipts = new RelayReceiptStore(db, logger);
  sealLeaves = new SessionSealLeafStore(db, logger);
});
afterEach(async () => {
  db.close();
  await rm(dir, { recursive: true, force: true });
});

function s1(hashHex: string, senderHex: string): Uint8Array {
  return encodeStructure1({
    contentHash: Buffer.from(hashHex, "hex"),
    senderPubkey: Buffer.from(senderHex, "hex"),
    sessionId: Buffer.from(SID, "hex"),
    lastSeenSeq: 0,
    timestamp: 1_789_000_000_000,
    lastSeenHash: new Uint8Array(32),
    prevOwnHash: new Uint8Array(32),
  });
}

/**
 * Written the way production writes them: the receipt row exactly as `evaluateRelayAck` builds it
 * (no Structure 1, no leaf kind), and the signed leaf through `SessionSealLeafStore`. An earlier
 * version put the author on the receipt row, which production never does, so it passed while every
 * author in the real answer was null.
 */
function receipt(seq: number, hashHex: string, sender: string, kind: 0 | 2): void {
  receipts.store({
    hashHex, agentPubkeyHex: A, sessionIdHex: SID, relayId: "ee".repeat(32), relayPubkeyHex: "ee".repeat(32),
    sequenceNumber: seq, timestamp: 1_789_000_000_000 + seq * 1000, signatureHex: `relaysig${seq}`, runningRootHex: "00".repeat(32),
  }, 0);
  sealLeaves.store(A, SID, {
    sequenceNumber: seq, leafKind: kind, senderPubkeyHex: sender,
    structure2Cbor: new Uint8Array([1]), structure1Cbor: s1(hashHex, sender),
  }, 0);
}

function message(index: number, direction: "sent" | "received", hashHex: string, text: string): void {
  db.prepare(
    `INSERT INTO session_tree_leaves (agent_id, session_id, leaf_index, leaf_kind, leaf_hash_hex, created_at)
     VALUES (?, ?, ?, 'msg', ?, 0)`,
  ).run(AGENT_ID, SID, index, hashHex);
  db.prepare(
    `INSERT INTO transcript (agent_id, session_id, sequence, direction, blob, created_at) VALUES (?, ?, ?, ?, ?, 0)`,
  ).run(AGENT_ID, SID, index, direction, Buffer.from(text));
}

function read(sealedRoot: string) {
  const texts = new Map<number, string>();
  for (const r of db.prepare(`SELECT sequence, blob FROM transcript WHERE session_id = ?`).all(SID) as Array<{ sequence: number; blob: Uint8Array }>) {
    texts.set(r.sequence, Buffer.from(r.blob).toString("utf8"));
  }
  return readSealedConversation(db, logger, {
    agentId: AGENT_ID,
    agentPubkey: A,
    sessionId: SID,
    sealedRoot,
    texts,
    nameFor: (pk) => (pk === A ? "Alice" : pk === B ? "Bob" : "unknown"),
  });
}

function rootOf(hashes: string[]): string {
  const t = SessionTree.empty();
  for (const x of hashes) t.appendLeafHash("msg", x);
  return t.rootHex();
}

describe("readSealedConversation", () => {
  it("lists BOTH sides' messages and both closes, in the relay's numbering, with text and authors", () => {
    const m1 = h("hello"), m2 = h("hi back"), c1 = h("close-b"), c2 = h("close-a");
    message(0, "sent", m1, "hello");
    message(1, "received", m2, "hi back");
    receipt(1, m1, A, 0);
    receipt(2, m2, B, 0);
    receipt(3, c1, B, 2);
    receipt(4, c2, A, 2);
    storeDeliveryAck(db, logger, { agentId: AGENT_ID, agentName: "Alice", sessionId: SID, contentHashHex: m1, signerPubkeyHex: B, signature: Buffer.from("bobsig") });
    storeGivenDeliveryAck(db, logger, { agentId: AGENT_ID, agentName: "Alice", sessionId: SID, contentHashHex: m2, signerPubkeyHex: A, signature: Buffer.from("alicesig") });

    const out = read(rootOf([m1, m2, c1, c2]));

    expect(out.leaves.map((l) => [l.seq, l.kind, l.from])).toEqual([
      [1, "message", "Alice"],
      [2, "message", "Bob"],
      [3, "close", "Bob"],
      [4, "close", "Alice"],
    ]);
    expect(out.leaves[0]).toMatchObject({ text: "hello", content_hash: m1, relay_ack: "relaysig1", delivery_ack: Buffer.from("bobsig").toString("hex") });
    expect(out.leaves[1]).toMatchObject({ text: "hi back", from_pubkey: B, delivery_ack: Buffer.from("alicesig").toString("hex") });
    expect(out.leaves[2]).toMatchObject({ from_pubkey: B });
    expect(out.leaves[2]).not.toHaveProperty("text");
    expect(out.leaves[2]).not.toHaveProperty("delivery_ack");
    expect(out.leaves[0].at).toBe(new Date(1_789_000_001_000).toISOString());
    expect(out.closed_by).toEqual(["Bob", "Alice"]);
    expect(out.root_matches_my_transcript).toBe(true);
  });

  it("attributes identical bytes from both sides by position, not by hash", () => {
    const ok = h("ok"), c1 = h("c1"), c2 = h("c2");
    message(0, "sent", ok, "ok");
    message(1, "received", ok, "ok");
    receipt(1, ok, A, 0);
    receipt(2, ok, B, 0);
    receipt(3, c1, A, 2);
    receipt(4, c2, B, 2);
    const out = read(rootOf([ok, ok, c1, c2]));
    expect(out.leaves.map((l) => [l.seq, l.kind, l.from])).toEqual([
      [1, "message", "Alice"], [2, "message", "Bob"], [3, "close", "Alice"], [4, "close", "Bob"],
    ]);
    expect(out.root_matches_my_transcript).toBe(true);
  });

  it("reports a root mismatch when the certificate does not cover this record", () => {
    const m1 = h("x"), c1 = h("c1");
    message(0, "sent", m1, "x");
    receipt(1, m1, A, 0);
    receipt(2, c1, A, 2);
    const out = read(h("some other root"));
    expect(out.root_matches_my_transcript).toBe(false);
    expect(out.root_mismatch_reason).toBe("root_differs");
  });

  it("keeps a message the relay never numbered, unnumbered and last, and says the root does not match", () => {
    const m1 = h("one"), m2 = h("lost"), c1 = h("c1");
    message(0, "sent", m1, "one");
    message(1, "sent", m2, "lost");
    receipt(1, m1, A, 0);
    receipt(2, c1, A, 2);
    const out = read(rootOf([m1, c1]));
    expect(out.root_mismatch_reason).toBe("unnumbered_messages");
    expect(out.leaves.map((l) => [l.seq, l.kind, l.text])).toEqual([
      [1, "message", "one"], [2, "close", undefined], [null, "message", "lost"],
    ]);
    expect(out.root_matches_my_transcript).toBe(false);
  });
});
