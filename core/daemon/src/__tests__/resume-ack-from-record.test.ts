/**
 * A session resumed after an interruption must remember what it had seen from the other side.
 *
 * Live, 2026-09-14: Ctrl-C and a restart mid-conversation left a seven-message session that could
 * never seal. The relay client kept "the last message I saw from you" only in memory, so after the
 * restart it started again from nothing. Every close then claimed to have seen nothing; the relay
 * refused each one as stale, because the other side's messages were already filed after that point;
 * and the retry waited for a new message that never came. Both agents gave up after five attempts.
 *
 * The daemon already keeps every leaf the other side authored, with its position, in the seal leaf
 * store. Registering a session must seed the acknowledgement from there.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash, randomBytes } from "node:crypto";
import { generateKeypair } from "@cello-protocol/crypto";
import { encodeStructure1 } from "@cello-protocol/protocol-types";
import { AgentRelayClient } from "../session-relay-client.js";
import { SessionSealLeafStore } from "../session-seal-leaf-store.js";
import { openEncryptedDatabase, type DaemonDatabase } from "../sqlcipher-db.js";
import { ensureSessionSchema } from "../session-schema.js";
import { recordLastAck } from "../resume-last-seen.js";
import { makeFakeRelay, noopLogger, fakeRelayAnchor } from "./relay-client-fake.js";

const GENESIS = new Uint8Array(32).fill(0x9c);
const SID = new Uint8Array(16).fill(0xf7);
const SID_HEX = Buffer.from(SID).toString("hex");
const THEM = "bb".repeat(32);

let dir: string;
let db: DaemonDatabase;
let store: SessionSealLeafStore;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "resume-ack-"));
  db = openEncryptedDatabase(join(dir, "s.db"), randomBytes(32));
  ensureSessionSchema(db, noopLogger, () => {});
  db.exec("CREATE TABLE IF NOT EXISTS agents (agent_id TEXT PRIMARY KEY, agent_name TEXT, k_local_pubkey TEXT NOT NULL)");
  store = new SessionSealLeafStore(db, noopLogger);
});
afterEach(async () => {
  db.close();
  await rm(dir, { recursive: true, force: true });
});

const hash = (label: string): Uint8Array => new Uint8Array(createHash("sha256").update(label).digest());

function leaf(ownerHex: string, seq: number, senderHex: string, contentHash: Uint8Array, kind = 0): void {
  store.store(ownerHex, SID_HEX, {
    sequenceNumber: seq,
    leafKind: kind,
    senderPubkeyHex: senderHex,
    structure2Cbor: new Uint8Array([1]),
    structure1Cbor: encodeStructure1({
      contentHash,
      senderPubkey: Buffer.from(senderHex, "hex"),
      sessionId: SID,
      lastSeenSeq: 0,
      timestamp: 1_789_000_000_000,
      lastSeenHash: new Uint8Array(32),
      prevOwnHash: new Uint8Array(32),
    }),
  }, 0);
}

async function resumedClient(): Promise<{ client: AgentRelayClient; meHex: string }> {
  const kp = generateKeypair();
  const pub = await kp.getPublicKey();
  const meHex = Buffer.from(pub).toString("hex");
  const client = new AgentRelayClient({
    relayPeerId: "12D3KooWRelay",
    relayAddrs: ["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWRelay"],
    keyProvider: kp,
    senderPubkey: pub,
    logger: noopLogger,
    sealLeafStore: store,
  });
  return { client, meHex };
}

describe("resuming a session seeds the acknowledgement from the stored record", () => {
  it("picks up the last leaf the OTHER side authored — its position and its real content hash", async () => {
    const { client, meHex } = await resumedClient();
    const theirLast = hash("their third message");
    leaf(meHex, 1, THEM, hash("their first"));
    leaf(meHex, 2, meHex, hash("my reply"));
    leaf(meHex, 3, THEM, hash("their second"));
    leaf(meHex, 4, meHex, hash("my second"));
    leaf(meHex, 5, THEM, theirLast);
    leaf(meHex, 6, meHex, hash("my last word"));

    client.registerSession(SID_HEX, makeFakeRelay().node, undefined, await fakeRelayAnchor(), GENESIS);

    const ack = client.lastSeenAck(SID_HEX);
    expect(ack?.seq).toBe(5);
    expect(Buffer.from(ack!.hash).equals(Buffer.from(theirLast))).toBe(true);
  });

  it("counts a message that arrived on the DIRECT path, which never writes the seal leaf store", async () => {
    const { client, meHex } = await resumedClient();
    db.prepare("INSERT INTO agents (agent_id, agent_name, k_local_pubkey) VALUES ('ag1', 'me', ?)").run(meHex);
    leaf(meHex, 1, THEM, hash("their first, via the relay"));
    leaf(meHex, 2, meHex, hash("my reply"));
    // Their second message was placed from the direct stream at relay position 3. The live path
    // acknowledged it, and that acknowledgement — position and hash — is what was recorded.
    const direct = hash("their second, direct");
    recordLastAck(db, { agentId: "ag1", sessionId: SID_HEX, seq: 3, hash: direct });

    client.registerSession(SID_HEX, makeFakeRelay().node, undefined, await fakeRelayAnchor(), GENESIS);

    const ack = client.lastSeenAck(SID_HEX);
    expect(ack?.seq).toBe(3);
    expect(Buffer.from(ack!.hash).equals(Buffer.from(direct))).toBe(true);
  });

  it("never guesses a position from the local record, which can drift one ahead of the relay", async () => {
    const { client, meHex } = await resumedClient();
    db.prepare("INSERT INTO agents (agent_id, agent_name, k_local_pubkey) VALUES ('ag1', 'me', ?)").run(meHex);
    // A first submit that failed left the local tree one AHEAD of the relay: a received row sits at
    // local index 3, but the relay filed that message at position 3 (not 4), and the live path
    // acknowledged position 3.
    const theirs = hash("theirs");
    leaf(meHex, 3, THEM, theirs);
    db.prepare("INSERT INTO session_tree_leaves (agent_id, session_id, leaf_index, leaf_kind, leaf_hash_hex, created_at) VALUES ('ag1', ?, 3, 'msg', ?, 0)")
      .run(SID_HEX, Buffer.from(theirs).toString("hex"));
    db.prepare("INSERT INTO transcript (agent_id, session_id, sequence, direction, blob, created_at) VALUES ('ag1', ?, 3, 'received', ?, 0)")
      .run(SID_HEX, Buffer.from("theirs"));
    recordLastAck(db, { agentId: "ag1", sessionId: SID_HEX, seq: 3, hash: theirs });

    client.registerSession(SID_HEX, makeFakeRelay().node, undefined, await fakeRelayAnchor(), GENESIS);

    expect(client.lastSeenAck(SID_HEX)?.seq, "resume must not claim position 4 from the local index").toBe(3);
  });

  it("the recorded acknowledgement only moves forward", () => {
    recordLastAck(db, { agentId: "ag1", sessionId: SID_HEX, seq: 5, hash: hash("five") });
    recordLastAck(db, { agentId: "ag1", sessionId: SID_HEX, seq: 4, hash: hash("four, redelivered late") });
    const row = db.prepare("SELECT relay_seq FROM session_last_ack WHERE agent_id = 'ag1' AND session_id = ?").get(SID_HEX) as { relay_seq: number };
    expect(row.relay_seq).toBe(5);
  });

  it("a session with nothing from the other side still starts at the genesis", async () => {
    const { client, meHex } = await resumedClient();
    leaf(meHex, 1, meHex, hash("I spoke first and they never answered"));
    client.registerSession(SID_HEX, makeFakeRelay().node, undefined, await fakeRelayAnchor(), GENESIS);
    expect(client.lastSeenAck(SID_HEX)).toEqual({ seq: 0, hash: GENESIS });
  });

  it("reads only THIS agent's record — another local agent's copy of the same session is ignored", async () => {
    const { client, meHex } = await resumedClient();
    leaf(meHex, 1, THEM, hash("to me"));
    leaf(THEM, 2, meHex, hash("the other agent's own copy, one position further"));
    client.registerSession(SID_HEX, makeFakeRelay().node, undefined, await fakeRelayAnchor(), GENESIS);
    expect(client.lastSeenAck(SID_HEX)?.seq).toBe(1);
  });
});
