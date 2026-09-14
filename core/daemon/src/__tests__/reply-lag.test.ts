/**
 * Warn when the other side keeps replying without having seen this side's latest message.
 *
 * Each of their messages signs the last position they had seen. If two of their replies in a row
 * were signed before our newest message, they are answering an older one — and until now nothing
 * said so during the conversation.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";
import { encodeStructure1 } from "@cello-protocol/protocol-types";
import { openEncryptedDatabase, type DaemonDatabase } from "../sqlcipher-db.js";
import { SessionSealLeafStore } from "../session-seal-leaf-store.js";
import { replyLag } from "../reply-lag.js";
import type { Logger } from "../types.js";

const logger: Logger = { debug() {}, info() {}, warn() {}, error() {} };
const ME = "aa".repeat(32);
const THEM = "bb".repeat(32);
const SID = "cd".repeat(16);

let dir: string;
let db: DaemonDatabase;
let store: SessionSealLeafStore;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "reply-lag-"));
  db = openEncryptedDatabase(join(dir, "s.db"), randomBytes(32));
  store = new SessionSealLeafStore(db, logger);
});
afterEach(async () => { db.close(); await rm(dir, { recursive: true, force: true }); });

function leaf(seq: number, sender: string, lastSeen: number, kind = 0): void {
  store.store(ME, SID, {
    sequenceNumber: seq, leafKind: kind, senderPubkeyHex: sender, structure2Cbor: new Uint8Array([1]),
    structure1Cbor: encodeStructure1({
      contentHash: randomBytes(32), senderPubkey: Buffer.from(sender, "hex"), sessionId: Buffer.from(SID, "hex"),
      lastSeenSeq: lastSeen, timestamp: 1, lastSeenHash: new Uint8Array(32), prevOwnHash: new Uint8Array(32),
    }),
  }, 0);
}

describe("replyLag", () => {
  it("two replies in a row signed before our newest message → lag, naming the positions", () => {
    leaf(1, ME, 0);
    leaf(2, THEM, 1);
    leaf(3, ME, 2);      // our newest
    leaf(4, THEM, 2);    // did not see 3
    leaf(5, THEM, 2);    // still did not see 3
    expect(replyLag(db, ME, SID)).toEqual({ replies: 2, their_last_seen_seq: 2, your_unseen_seq: 3 });
  });

  it("one crossed reply is ordinary back-and-forth, not a lag", () => {
    leaf(1, ME, 0);
    leaf(2, ME, 0);
    leaf(3, THEM, 1);
    expect(replyLag(db, ME, SID)).toBeUndefined();
  });

  it("a reply that saw our newest message clears it", () => {
    leaf(1, ME, 0);
    leaf(2, THEM, 0);
    leaf(3, THEM, 0);
    leaf(4, THEM, 1);
    expect(replyLag(db, ME, SID)).toBeUndefined();
  });

  it("closes are not replies", () => {
    leaf(1, ME, 0);
    leaf(2, THEM, 0, 2);
    leaf(3, THEM, 0, 2);
    expect(replyLag(db, ME, SID)).toBeUndefined();
  });
});
