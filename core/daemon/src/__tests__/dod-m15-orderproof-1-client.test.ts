/**
 * DOD-M15-ORDERPROOF-1, client half — the participant KEEPS the relay's ordering proof, and only
 * keeps one it can actually check.
 *
 * ─── What this file measures, and why each part is here ────────────────────────────────────────
 *
 *  1. **The recipient stores it.** Before this order the attestation rode the submit acknowledgement
 *     and nothing else, so the party who RECEIVED a message held no proof of where it sat in the
 *     conversation. One party's copy being the only copy is the dependency this design removes.
 *  2. **It is checked against the relay the DIRECTORY named**, from the FROST-signed assignment —
 *     never `relay_id` in the frame being checked. A signature verified against a key its own signer
 *     supplied proves the frame is internally consistent and nothing about who ordered anything.
 *  3. **A refusal on the DELIVERY path is loud and the message still arrives.** This is the one
 *     place the two halves differ, deliberately: on the send path a refusal means OUR message has no
 *     witness and the send must not settle, but dropping an inbound message would let a relay
 *     silence a conversation by withholding its own signature — a better weapon than the one the
 *     check takes away.
 *  4. **It survives a restart**, in SQLCipher, and a session that predates this order still reads.
 *
 * SQLCipher throughout — `node:sqlite` is forbidden in this project and stores plaintext.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";
import { generateKeypair } from "@cello-protocol/crypto";
import { encodeStructure1 } from "@cello-protocol/protocol-types";
import { AgentRelayClient, LEAF_KIND_MSG } from "../session-relay-client.js";
import { escalateToUnilateralSeal } from "../seal-escalation.js";
import type { SessionNodeManager } from "../session-node-manager.js";
import { RelayReceiptStore } from "../relay-receipt-store.js";
import { SessionSealLeafStore } from "../session-seal-leaf-store.js";
import { openTestDb } from "./helpers/encrypted-db.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";
import {
  makeFakeRelay, tick, noopLogger, fakeRelayAnchor, fakeRelayAttestation, pushAck,
} from "./relay-client-fake.js";
import { startTwoConnectionFixture } from "./helpers/two-connection-fixture.js";

const GENESIS = new Uint8Array(32).fill(0x9c);
const SID = new Uint8Array(16).fill(0xf7);
const SID_HEX = Buffer.from(SID).toString("hex");

interface LogLine { event: string; ctx: Record<string, unknown> }
function recordingLogger(sink: LogLine[]) {
  const at = () => (event: string, ctx?: Record<string, unknown>) => sink.push({ event, ctx: ctx ?? {} });
  return { debug: at(), info: at(), warn: at(), error: at() } as never;
}

describe("DOD-M15-ORDERPROOF-1 (client): the recipient keeps the proof, and only a checkable one", () => {
  let dir = "";
  let db: DaemonDatabase | undefined;
  beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), "cello-orderproof-")); });
  afterEach(async () => { db = undefined; await rm(dir, { recursive: true, force: true }); });

  const dbPath = () => join(dir, "sessions.db");

  /** A connected client with a real SQLCipher receipt store and the session's anchor recorded. */
  async function connected(logs: LogLine[] = []) {
    db = openTestDb(dbPath());
    const receiptStore = new RelayReceiptStore(db, noopLogger);
    const kp = generateKeypair();
    const pub = await kp.getPublicKey();
    const client = new AgentRelayClient({
      relayPeerId: "12D3KooWRelay",
      relayAddrs: ["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWRelay"],
      keyProvider: kp,
      senderPubkey: pub,
      logger: logs.length >= 0 ? recordingLogger(logs) : noopLogger,
      receiptStore,
    });
    const relay = makeFakeRelay();
    client.registerSession(SID_HEX, relay.node, undefined, await fakeRelayAnchor(), GENESIS);

    // Authenticate the stream by driving one real submit, so the reader loop is live.
    const warmHash = new Uint8Array(32).fill(0x01);
    const warm = client.submitMessageHash(relay.node, SID, warmHash, LEAF_KIND_MSG);
    await tick();
    relay.push({ type: "relay_auth_challenge", nonce: new Uint8Array(32).fill(7) });
    await tick();
    relay.push({ type: "relay_auth_ok" });
    await tick();
    await pushAck(relay, SID, 1);
    expect((await warm).ok, "precondition: the client must be authenticated and reading").toBe(true);

    return { client, relay, receiptStore, pub, pubHex: Buffer.from(pub).toString("hex") };
  }

  /** A leaf authored by the COUNTERPARTY, as the relay delivers it. */
  async function counterpartyLeaf(seq: number, over: Record<string, unknown> = {}) {
    const theirKp = generateKeypair();
    const theirPub = await theirKp.getPublicKey();
    const contentHash = new Uint8Array(randomBytes(32));
    const structure1_cbor = encodeStructure1({
      contentHash,
      senderPubkey: theirPub,
      sessionId: SID,
      lastSeenSeq: 0,
      timestamp: 1_750_000_000_000,
      lastSeenHash: GENESIS,
      prevOwnHash: GENESIS,
    });
    return {
      contentHash,
      frame: {
        type: "leaf_deliver",
        session_id: SID,
        sequence_number: seq,
        leaf_kind: LEAF_KIND_MSG,
        structure1_cbor,
        structure2_cbor: new Uint8Array([0xaa, 0xbb]),
        ...(await fakeRelayAttestation(SID, contentHash, seq)),
        ...over,
      },
    };
  }

  it("★★★ a DELIVERED leaf's attestation is stored — the recipient holds the proof too", async () => {
    const fx = await connected();
    const { contentHash, frame } = await counterpartyLeaf(2);
    fx.relay.push(frame);
    await tick();

    const stored = fx.receiptStore.get(fx.pubHex, SID_HEX, 2);
    expect(stored, "the recipient must hold a receipt for the counterparty's message").toBeDefined();
    expect(stored!.hashHex).toBe(Buffer.from(contentHash).toString("hex"));
    expect(stored!.runningRootHex).toBe(Buffer.from(frame.running_root as Uint8Array).toString("hex"));
    expect(stored!.sequenceNumber).toBe(2);
  });

  it("★★★ an attestation from a relay the DIRECTORY DID NOT NAME is refused and NOT stored", async () => {
    /**
     * The signature here is perfectly valid — over the right statement, by a real key. It is
     * refused because that key is not the one the directory put in the session assignment. That is
     * the whole difference between a check and a decoration.
     */
    const logs: LogLine[] = [];
    const fx = await connected(logs);
    const impostor = generateKeypair();
    const built = await counterpartyLeaf(2);
    // The attestation is signed over the frame's OWN hash, so the only thing wrong with it is who
    // signed it. A mismatched hash would refuse for a different reason and prove nothing here.
    fx.relay.push({
      ...built.frame,
      ...(await fakeRelayAttestation(SID, built.contentHash, 2, { signWith: impostor })),
    });
    await tick();

    expect(
      fx.receiptStore.get(fx.pubHex, SID_HEX, 2),
      "nothing is stored unverified to sort out later",
    ).toBeUndefined();
    const refusal = logs.find((l) => l.event === "relay.attestation.delivered.refused");
    expect(refusal, "the refusal must be audible, not silent").toBeDefined();
    expect(refusal!.ctx["cause"]).toBe("relay_not_assigned");
  });

  it("★★★ MALFORMED and MISSING are the same outcome on the delivery path", async () => {
    const logs: LogLine[] = [];
    const fx = await connected(logs);

    // MALFORMED: a 64-byte value that is not a signature over anything.
    const malformed = await counterpartyLeaf(2);
    fx.relay.push({ ...malformed.frame, relay_signature: new Uint8Array(randomBytes(64)) });
    await tick();

    // MISSING: no attestation fields at all, which is what a relay on an old build sends.
    const missing = await counterpartyLeaf(3);
    const bare = { ...missing.frame };
    delete (bare as Record<string, unknown>)["relay_id"];
    delete (bare as Record<string, unknown>)["relay_signature"];
    delete (bare as Record<string, unknown>)["timestamp"];
    delete (bare as Record<string, unknown>)["running_root"];
    fx.relay.push(bare);
    await tick();

    // Same observable outcome: no receipt at either position.
    expect(fx.receiptStore.get(fx.pubHex, SID_HEX, 2)).toBeUndefined();
    expect(fx.receiptStore.get(fx.pubHex, SID_HEX, 3)).toBeUndefined();
    // And both were reported, with their own causes so an operator is not left guessing.
    const causes = logs
      .filter((l) => l.event === "relay.attestation.delivered.refused")
      .map((l) => l.ctx["cause"]);
    expect(causes).toEqual(["signature_invalid", "attestation_absent"]);
  });

  it("★★ a refused attestation does NOT cost the counterparty their message", async () => {
    /**
     * The asymmetry, pinned. If an inbound message were dropped along with its unverifiable proof,
     * a relay could silence a conversation by withholding its own signature — which hands the party
     * this check constrains a better weapon than the one it takes away.
     */
    const delivered: unknown[] = [];
    const fx = await connected();
    fx.client.registerSession(SID_HEX, fx.relay.node, (f) => delivered.push(f), await fakeRelayAnchor(), GENESIS);

    const { frame } = await counterpartyLeaf(2);
    fx.relay.push({ ...frame, relay_signature: new Uint8Array(randomBytes(64)) });
    await tick();

    expect(delivered.length, "the message still reaches the session").toBe(1);
    expect(fx.receiptStore.get(fx.pubHex, SID_HEX, 2), "but no proof was invented for it").toBeUndefined();
  });

  it("★★★ attestations survive a client restart, in SQLCipher", async () => {
    const fx = await connected();
    const { contentHash, frame } = await counterpartyLeaf(2);
    fx.relay.push(frame);
    await tick();
    fx.client.close();
    db = undefined;

    // A NEW process: a fresh store over the same encrypted file, opened the way the daemon does.
    const reopened = openTestDb(dbPath());
    const store = new RelayReceiptStore(reopened, noopLogger);
    const after = store.get(fx.pubHex, SID_HEX, 2);
    expect(after, "the proof must outlive the process that received it").toBeDefined();
    expect(after!.hashHex).toBe(Buffer.from(contentHash).toString("hex"));
    expect(after!.runningRootHex).toBe(Buffer.from(frame.running_root as Uint8Array).toString("hex"));
  });

  it("★★★ a REFUSED attestation on the SEND path rejects the submit — it does not settle ok", async () => {
    /**
     * The wiring, not the predicate. `evaluateRelayAck` refusing is tested next door; this drives a
     * real submit through the real client and reads what the SEND returns. Without it, making
     * `#captureReceipt` swallow a refusal would leave every other test in this file green while a
     * message reported itself witnessed by a relay that witnessed nothing.
     */
    const logs: LogLine[] = [];
    const fx = await connected(logs);
    const contentHash = new Uint8Array(32).fill(0x5a);
    const submit = fx.client.submitMessageHash(fx.relay.node, SID, contentHash, LEAF_KIND_MSG);
    await tick();
    // A well-formed frame whose signature is not over anything — the relay's own copy corrupted, or
    // a frame a stranger wrote onto the stream.
    const attestation = await fakeRelayAttestation(SID, contentHash, 2);
    fx.relay.push({
      type: "hash_submit_ack",
      sequence_number: 2,
      ...attestation,
      relay_signature: new Uint8Array(randomBytes(64)),
    });

    const res = await submit;
    expect(res.ok, "a send must not settle ok on a position nothing witnessed").toBe(false);
    expect(res.ok === false && res.reason).toBe("relay_ack_unverified");
    expect(fx.receiptStore.get(fx.pubHex, SID_HEX, 2), "and nothing was stored").toBeUndefined();
    const refusal = logs.find((l) => l.event === "relay.attestation.refused");
    expect(refusal?.ctx["cause"]).toBe("signature_invalid");
  });

  it("★★★ a seal carry recorded BEFORE this order is refused HERE, by name, not by the directory", async () => {
    /**
     * A leaf stored before this order has a relay id, a timestamp and a signature and NO running
     * root, because the statement the relay signed then did not bind one. Shipped as-is, the
     * directory's decoder treats the partial receipt as a malformed FRAME and voids the whole
     * submission — which reaches the operator as `not_authenticated` on an authenticated stream and
     * then as a timeout naming our own wait. That is the error-fidelity defect this milestone is
     * about, so the carry is judged locally where the cause is known.
     */
    db = openTestDb(dbPath());
    const store = new SessionSealLeafStore(db, noopLogger);
    const kp = generateKeypair();
    const pubHex = Buffer.from(await kp.getPublicKey()).toString("hex");
    // Exactly the pre-069 shape: witnessed, and no root.
    store.store(pubHex, SID_HEX, {
      sequenceNumber: 1,
      leafKind: LEAF_KIND_MSG,
      senderPubkeyHex: pubHex,
      structure2Cbor: new Uint8Array([0xa1]),
      structure1Cbor: new Uint8Array([0xb1]),
      relayId: "dd".repeat(32),
      relayTimestamp: 10,
      relaySignatureHex: "ee".repeat(64),
    }, 1);

    const sent: unknown[] = [];
    const res = await escalateToUnilateralSeal(
      {
        logger: noopLogger,
        sessionNodeManager: { getSealCarry: (a: string, s: string) => store.getCarry(a, s) } as unknown as SessionNodeManager,
        sendOver: async (_a: string, f: Record<string, unknown>) => { sent.push(f); return { ok: true }; },
        pendingUnilateralWaiters: new Map(),
        sealKey: (a: string, s: string) => `${a}:${s}`,
        getKeyProvider: () => kp,
        timeoutMs: 500,
      },
      "alice",
      SID_HEX,
      { reportedRootHex: "11".repeat(32), sequenceNumber: 1 },
      "corr",
      { refuseOnUnusableCarry: true },
    );

    expect(res.ok, "a carry the directory cannot check must not be sent").toBe(false);
    expect(res.ok === false && res.reason).toBe("seal_carry_pre_orderproof");
    expect(
      sent.length,
      "and NOTHING went to the directory — a frame it will void is a 30-second wait ending in a " +
      "reason that names our own timer",
    ).toBe(0);
    expect(
      res.ok === false && res.guidance,
      "the guidance names an action the operator can actually take",
    ).toMatch(/close it WITH your counterparty/i);
  });

  it("★★ a session recorded BEFORE this order still opens and reads — the migration is additive", async () => {
    /**
     * The shape a pre-069 database is in: `relay_ack_receipts` with no `running_root_hex` column at
     * all. Opening the store must ADD the column and leave every existing row intact and readable —
     * a migration that dropped or rewrote them would destroy the only ordering evidence those
     * sessions have.
     */
    const legacy = openTestDb(dbPath());
    legacy.exec(`
      CREATE TABLE relay_ack_receipts (
        agent_pubkey TEXT NOT NULL, session_id TEXT NOT NULL, sequence_number INTEGER NOT NULL,
        hash_hex TEXT NOT NULL, relay_id TEXT NOT NULL, relay_pubkey_hex TEXT NOT NULL,
        relay_timestamp INTEGER NOT NULL, signature_hex TEXT NOT NULL, stored_at INTEGER NOT NULL,
        PRIMARY KEY (agent_pubkey, session_id, sequence_number)
      );
    `);
    legacy.prepare(
      `INSERT INTO relay_ack_receipts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run("aa".repeat(32), SID_HEX, 1, "11".repeat(32), "dd".repeat(32), "dd".repeat(32), 10, "ee".repeat(64), 1);

    // Opening the store runs the migration.
    const store = new RelayReceiptStore(legacy, noopLogger);
    const old = store.get("aa".repeat(32), SID_HEX, 1);
    expect(old, "the pre-069 row is still there").toBeDefined();
    expect(old!.hashHex).toBe("11".repeat(32));
    expect(old!.signatureHex).toBe("ee".repeat(64));
    expect(old!.runningRootHex, "and simply has no root recorded, rather than a fabricated one").toBeUndefined();

    // And a new row alongside it carries one.
    store.store({
      hashHex: "22".repeat(32), agentPubkeyHex: "aa".repeat(32), sessionIdHex: SID_HEX,
      relayId: "dd".repeat(32), relayPubkeyHex: "dd".repeat(32), sequenceNumber: 2,
      timestamp: 20, signatureHex: "ff".repeat(64), runningRootHex: "ab".repeat(32),
    }, 2);
    expect(store.get("aa".repeat(32), SID_HEX, 2)?.runningRootHex).toBe("ab".repeat(32));
  });
});

describe("DOD-M15-ORDERPROOF-1: the anchor OUTLIVES the process that learned it", () => {
  /**
   * ★★★ THE TEST THAT WAS MISSING, AND THE DEFECT IT CATCHES.
   *
   * The anchor — which relay's ordering signature this session trusts — arrives on the
   * directory-signed assignment, which exists only while the session is being opened. Every read
   * after that is from memory, and memory dies with the daemon. So the anchor has to be on the
   * session ROW, and the first implementation wrote it with an UPDATE that ran BEFORE the row was
   * inserted: it matched nothing, threw nothing, and logged nothing.
   *
   * What that costs the operator: the conversation works perfectly, the daemon restarts — an
   * upgrade, a reboot, a crash — and from that moment every message on that conversation is
   * refused, and it can never be sealed alone either, because the seal's own leaf is refused with
   * it. The daemon's refusal names the relay, so the operator goes and looks at a relay that is
   * fine.
   *
   * It is asserted on the ROW and through a fixture that has been torn down, not on the live
   * object: reading the in-memory copy is what made the defect invisible in the first place.
   */
  it("★★★ the relay key the directory named is on the session ROW, not only in memory", async () => {
    const fx = await startTwoConnectionFixture({ dirPrefix: "cello-orderproof-anchor-" });
    try {
      const sid = "5d".repeat(16);
      await fx.createSession(sid, "alice", "bobpubkeyhex", "bob-peer-id", { relay: true });

      const expected = (await fakeRelayAnchor()).relayPubkeyHex;
      expect(
        fx.snm.sessionRelayAnchor("alice", sid),
        "PRECONDITION: the live session knows its anchor — if this fails the test below proves nothing",
      ).toBe(expected);

      /**
       * Read through the PRODUCTION row getter, not a test-only one. `SELECT *`, so the column is
       * there at runtime; `SessionRecord` does not declare it because nothing in production reads
       * the anchor off the record, and a declaration added only to satisfy a test would be the
       * first step towards it becoming something production depends on.
       */
      const row = fx.snm.getSessionRecord("alice", sid) as unknown as { relay_anchor_hex?: string } | null;
      expect(
        row?.relay_anchor_hex,
        "the anchor must be ON DISK. NULL here means it lives only in this process, and the first " +
          "restart takes the session's ability to send or to seal alone with it",
      ).toBe(expected);
    } finally {
      await fx.cleanup();
    }
  }, 60_000);
});
