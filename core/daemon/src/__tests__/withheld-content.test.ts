import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";
import { encodeStructure1 } from "@cello-protocol/protocol-types";
import { openEncryptedDatabase, type DaemonDatabase } from "../sqlcipher-db.js";
import { ensureSessionSchema } from "../session-schema.js";
import { SessionSealLeafStore } from "../session-seal-leaf-store.js";
import { withheldPositions } from "../withheld-content.js";
import type { Logger } from "../types.js";

const logger: Logger = { debug() {}, info() {}, warn() {}, error() {} };
const ME = "aa".repeat(32);
const THEM = "bb".repeat(32);
const SID = "cd".repeat(16);
let dir: string;
let db: DaemonDatabase;
let store: SessionSealLeafStore;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "withheld-"));
  db = openEncryptedDatabase(join(dir, "s.db"), randomBytes(32));
  ensureSessionSchema(db, logger, () => {});
  store = new SessionSealLeafStore(db, logger);
});
afterEach(async () => { db.close(); await rm(dir, { recursive: true, force: true }); });

function announced(seq: number, sender: string, hash: Buffer, kind = 0): void {
  store.store(ME, SID, {
    sequenceNumber: seq, leafKind: kind, senderPubkeyHex: sender, structure2Cbor: new Uint8Array([1]),
    structure1Cbor: encodeStructure1({
      contentHash: hash, senderPubkey: Buffer.from(sender, "hex"), sessionId: Buffer.from(SID, "hex"),
      lastSeenSeq: 0, timestamp: 1, lastSeenHash: new Uint8Array(32), prevOwnHash: new Uint8Array(32),
    }),
  }, 0);
}
function placed(index: number, hash: Buffer): void {
  db.prepare("INSERT INTO session_tree_leaves (agent_id, session_id, leaf_index, leaf_kind, leaf_hash_hex, created_at) VALUES ('ag', ?, ?, 'msg', ?, 0)")
    .run(SID, index, hash.toString("hex"));
}

describe("withheldPositions — a message the other side filed but never delivered", () => {
  it("names the position whose content this side does not hold", () => {
    const got = randomBytes(32), withheld = randomBytes(32), mine = randomBytes(32);
    announced(1, THEM, got); placed(0, got);
    announced(2, ME, mine); placed(1, mine);
    announced(3, THEM, withheld); // announced, never placed
    expect(withheldPositions(db, { agentId: "ag", agentPubkeyHex: ME, sessionId: SID, relaySessionHex: SID, upToSeq: 3 })).toEqual([3]);
  });

  it("ignores positions past what the close claims, and the other side's closes", () => {
    const later = randomBytes(32);
    announced(4, THEM, later);
    announced(5, THEM, randomBytes(32), 2);
    expect(withheldPositions(db, { agentId: "ag", agentPubkeyHex: ME, sessionId: SID, relaySessionHex: SID, upToSeq: 3 })).toEqual([]);
    expect(withheldPositions(db, { agentId: "ag", agentPubkeyHex: ME, sessionId: SID, relaySessionHex: SID, upToSeq: 9 })).toEqual([4]);
  });
});
