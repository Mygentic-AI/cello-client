/**
 * CELLO-M7-MSG-001 / DOD-MSG-4 — strict in-order content delivery (the receiver gate).
 *
 * DECIDED (Andre, 2026-06-22, discussion log 2026-06-22_1745_strict-in-order-content-recovery):
 * the receiver processes content strictly in canonical sequence. It accepts ONLY the next
 * expected sequence; an out-of-order arrival (a message whose canonical sequence is AHEAD of
 * the next expected leaf) is HELD, not appended. The missing in-between message(s) are fetched
 * from the relay mailbox first; then the held message(s) are released in order. This keeps the
 * daemon-owned leaf index === the relay's canonical sequence BY CONSTRUCTION, so two parties'
 * Merkle roots match even when direct delivery and relay-park recovery interleave.
 *
 * The canonical sequence is the RELAY's (the ordering authority, Structure 2): B learns each
 * message's (content_hash -> sequence) from the relay's leaf_deliver witness — NEVER from a
 * sender-stamped field (sovereign-node: B does not trust the counterparty for ordering). Here
 * we inject the witness directly via recordWitnessedSequence (in production the onLeafDeliver
 * callback feeds it). No relay process — this proves the in-process gate state machine.
 *
 * Crypto refs: RFC 6962 §2.1 (Merkle), FIPS 180-4 (SHA-256).
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { SessionNodeManager } from "../session-node-manager.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { Logger } from "../types.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { Stream } from "@libp2p/interface";
import { generateKeypair } from "@cello-protocol/crypto";
import { buildStructure2, encodeStructure2 } from "@cello-protocol/protocol-types";
import { encodeStructure1 } from "@cello-protocol/protocol-types";
import { encodeParkEnvelope } from "../park-envelope.js";
import { seedAgents } from "./helpers/seed-agents.js";

interface LogEvent { level: string; event: string; context: Record<string, unknown> }

function makeLogger(): { logger: Logger; events: LogEvent[] } {
  const events: LogEvent[] = [];
  const logger: Logger = {
    debug(event, context) { events.push({ level: "debug", event, context }); },
    info(event, context) { events.push({ level: "info", event, context }); },
    warn(event, context) { events.push({ level: "warn", event, context }); },
    error(event, context) { events.push({ level: "error", event, context }); },
  };
  return { logger, events };
}

function msgLeafHash(content: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(new Uint8Array([0x00])).update(content).digest());
}

/** Minimal fake node — content arrives via direct ingest, no stream needed for the gate logic. */
class FakeNode implements Partial<CelloNode> {
  readonly #peerId = `fake-${Math.random().toString(36).slice(2)}`;
  async start(): Promise<void> {}
  async stop(): Promise<void> {}
  getPeerId(): string { return this.#peerId; }
  listenAddresses(): string[] { return ["/ip4/127.0.0.1/tcp/0"]; }
  async dial(_addr: string): Promise<{ peerId: string }> { return { peerId: "remote" }; }
  async handle(_p: string, _h: unknown): Promise<void> {}
  getProtocols(): string[] { return []; }
  getConnections(): Array<{ peerId: string; encryption: string | undefined }> { return []; }
  onPeerConnect(_h: (p: string) => void): void {}
  onPeerDisconnect(_h: (p: string) => void): void {}
  getDialability(): { dialable: boolean; publicAddr: string | null } { return { dialable: false, publicAddr: null }; }
  onDialabilityChange(_l: (d: { dialable: boolean; publicAddr: string | null }) => void): () => void { return () => {}; }
  async newStream(_peer: string, _proto: string): Promise<Stream> { throw new Error("unused"); }
}

class ControlledFactory implements ISessionNodeFactory {
  constructor(private node: CelloNode) {}
  async createNode(_c: SessionNodeConfig): Promise<CelloNode> { return this.node; }
}

async function makeManager(logger: Logger, dbPath: string): Promise<SessionNodeManager> {
  const mgr = new SessionNodeManager({ securityGateway: new PassthroughGatewayClient(), factory: new ControlledFactory(new FakeNode() as unknown as CelloNode), logger, dbPath });
  await mgr.initialize();
  return mgr;
}

const AGENT = "alice";

describe("DOD-MSG-4: strict in-order content gate", () => {
  let tempDir: string;
  let logger: Logger;
  let events: LogEvent[];
  const sid = "e".repeat(64);

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-msg4-"));
    const l = makeLogger();
    logger = l.logger;
    events = l.events;
  });
  afterEach(async () => { await rm(tempDir, { recursive: true, force: true }); });

  function leafHashes(mgr: SessionNodeManager): string[] {
    return mgr.getSessionTree(AGENT, sid).leaves().map((l) => l.hashHex);
  }

  it("a content witnessed AHEAD of the next expected leaf is HELD, not appended out of order", async () => {
    const mgr = await makeManager(logger, join(tempDir, "s.db"));
    await seedAgents(mgr.getDb(), [AGENT]);
    await mgr.createSessionNode(sid, AGENT, "bobpubkey", "bob-peer-id", "corr-1");

    const c0 = new TextEncoder().encode("m0");
    const c1 = new TextEncoder().encode("m1");
    const c2 = new TextEncoder().encode("m2");
    const h0 = msgLeafHash(c0), h1 = msgLeafHash(c1), h2 = msgLeafHash(c2);
    const hx = (h: Uint8Array) => Buffer.from(h).toString("hex");

    // The relay (ordering authority) has witnessed canonical sequences 0,1,2 for these hashes.
    mgr.recordWitnessedSequence(AGENT, sid, hx(h0), 0);
    mgr.recordWitnessedSequence(AGENT, sid, hx(h1), 1);
    mgr.recordWitnessedSequence(AGENT, sid, hx(h2), 2);

    // c2 (canonical seq 2) arrives FIRST. nextExpected is 0 → it must be HELD, NOT appended.
    const r2 = await mgr.ingestReceivedContent(AGENT, sid, c2, h2, "corr-1");
    expect(r2.ok).toBe(true);
    expect(mgr.getSessionTree(AGENT, sid).size(), "out-of-order content is held, tree stays empty").toBe(0);
    expect(events.some((e) => e.event === "session.content.held")).toBe(true);

    // c0 (seq 0) arrives → appended as leaf 0. c2 still held (gap at seq 1).
    await mgr.ingestReceivedContent(AGENT, sid, c0, h0, "corr-1");
    expect(mgr.getSessionTree(AGENT, sid).size(), "only seq 0 lands; seq 2 still held behind the gap").toBe(1);

    // c1 (seq 1) arrives → appended leaf 1, and now c2 is released → leaf 2. Order preserved.
    await mgr.ingestReceivedContent(AGENT, sid, c1, h1, "corr-1");
    expect(mgr.getSessionTree(AGENT, sid).size()).toBe(3);
    expect(leafHashes(mgr), "leaf order is the canonical sequence, not arrival order").toEqual([hx(h0), hx(h1), hx(h2)]);

    // And cello_receive drains them in canonical order m0, m1, m2.
    const drain = [0, 1, 2].map(() => mgr.takeReceivedContent(AGENT, sid));
    expect(drain.map((d) => d && Buffer.from(d.contentHex, "hex").toString())).toEqual(["m0", "m1", "m2"]);
  });

  /**
   * REGRESSION, found live 2026-08-16 from `cello relay-receipts` on Andre's daemon.
   *
   * The file header above claims the leaf-index === canonical-sequence invariant is kept "BY
   * CONSTRUCTION". It is not. It rests on a second assumption, stated in session-node-manager.ts:
   *
   *   "The relay already assigns every submission a unique position: a REDELIVERY carries the same
   *    position, a genuinely new identical message carries a NEW one."
   *
   * Production falsifies it. One content hash held 49 DIFFERENT relay positions in session
   * f54e0d07 (49 receipts, ONE distinct message, max sequence 98); another was submitted 69 times.
   * Every unacknowledged send is retried, and each retry is witnessed at a NEW canonical sequence
   * while the receiver deduplicates by content hash and appends nothing.
   *
   * So the receiver's tree stands still while the canonical counter advances — and because the gate
   * is `canonicalSeq > tree.size()`, every genuinely new message afterwards is held behind a gap
   * that no message will ever fill. Held content is never acknowledged, so it is retried, which
   * burns another sequence and widens the gap that caused it. The repair mechanism is the thing
   * that makes it unrepairable.
   *
   * Measured consequence on 2026-08-16: `session.content.held.discarded` (verified content
   * destroyed at teardown, memory-only) fired 20 times on one daemon in one day.
   */
  // `it.fails` DELIBERATELY: this asserts the defect still EXISTS, so the gate stays green while the
  // fix is an open design decision (see below). The moment the defect is fixed this test starts
  // FAILING — that is the signal to change `it.fails` back to `it`. Do not delete it to make that
  // stop.
  //
  // WHY NO FIX IS SHIPPED WITH THIS TEST. Every route restores `leafIndex === canonicalSeq` by
  // changing what the Merkle tree contains, and the tree root is what the seal signs over — so the
  // wrong choice silently invalidates receipts, which is the product. The three routes, and they
  // are not equivalent:
  //   1. SOURCE (relay/sender contract): a resubmission must carry the position it was FIRST
  //      assigned instead of taking a new one. Fixes the cause; needs a relay-side change and is
  //      the only option that keeps both parties' roots identical by construction.
  //   2. RECEIVER accounting: track canonical positions consumed by a deduplicated redelivery so
  //      the gate can advance past a position nothing will ever fill. Client-only, but it concedes
  //      that leaf index and canonical sequence have permanently diverged.
  //   3. BOUND THE HOLD: release held content in canonical order rather than discarding it at
  //      teardown, per this file's own stated policy that "losing content is worse than a transient
  //      mis-order the seal cross-check will catch". Stops the destruction; changes roots.
  // This is a §9-class decision in the sense of the reconcile-don't-deliver design note
  // (docs/planning/discussion_logs/2026-08-14_1155_...): settle it before writing code, because
  // under "ask what they have and send the difference" this whole failure class cannot occur.
  it.fails("REGRESSION: a redelivery witnessed at a NEW canonical sequence must not strand every later message", async () => {
    const mgr = await makeManager(logger, join(tempDir, "resubmit.db"));
    await seedAgents(mgr.getDb(), [AGENT]);
    await mgr.createSessionNode(sid, AGENT, "bobpubkey", "bob-peer-id", "corr-1");

    const c0 = new TextEncoder().encode("m0");
    const c1 = new TextEncoder().encode("m1");
    const h0 = msgLeafHash(c0), h1 = msgLeafHash(c1);
    const hx = (h: Uint8Array) => Buffer.from(h).toString("hex");

    // Seq 0: m0 arrives and appends normally.
    mgr.recordWitnessedSequence(AGENT, sid, hx(h0), 0);
    await mgr.ingestReceivedContent(AGENT, sid, c0, h0, "corr-1");
    expect(mgr.getSessionTree(AGENT, sid).size()).toBe(1);

    // The sender never saw an ack, so it RESUBMITS m0 byte-identical. The relay witnesses the
    // resubmission at canonical sequence 1 — a NEW position for content already held.
    mgr.recordWitnessedSequence(AGENT, sid, hx(h0), 1);
    await mgr.ingestReceivedContent(AGENT, sid, c0, h0, "corr-1");
    expect(mgr.getSessionTree(AGENT, sid).size(), "the redelivery is deduplicated — no second leaf").toBe(1);

    // Canonical sequence 1 is now consumed by a redelivery that appended nothing, so the tree can
    // never reach size 2. m1, a genuinely new message, is witnessed at 2.
    mgr.recordWitnessedSequence(AGENT, sid, hx(h1), 2);
    await mgr.ingestReceivedContent(AGENT, sid, c1, h1, "corr-1");

    // THE DEFECT: m1 is verified, held, and unreachable forever — no message will ever fill seq 1.
    expect(
      mgr.getSessionTree(AGENT, sid).size(),
      "m1 must be delivered: the only gap is a position a redelivery consumed, and nothing will ever fill it",
    ).toBe(2);
    expect(
      mgr.takeReceivedContent(AGENT, sid) !== null,
      "m1 must be readable by the agent, not stranded in the in-memory hold buffer",
    ).toBe(true);
  });

  it("the in-order happy path is unchanged — sequential arrivals append immediately", async () => {
    const mgr = await makeManager(logger, join(tempDir, "happy.db"));
    await seedAgents(mgr.getDb(), [AGENT]);
    await mgr.createSessionNode(sid, AGENT, "bobpubkey", "bob-peer-id", "corr-1");
    const msgs = ["a", "b", "c"].map((s) => new TextEncoder().encode(s));
    const hashes = msgs.map(msgLeafHash);
    hashes.forEach((h, i) => mgr.recordWitnessedSequence(AGENT, sid, Buffer.from(h).toString("hex"), i));
    for (let i = 0; i < msgs.length; i++) {
      const r = await mgr.ingestReceivedContent(AGENT, sid, msgs[i], hashes[i], "corr-1");
      expect(r.ok).toBe(true);
      expect(mgr.getSessionTree(AGENT, sid).size()).toBe(i + 1);
    }
    expect(leafHashes(mgr)).toEqual(hashes.map((h) => Buffer.from(h).toString("hex")));
  });

  it("without a witness (relay-degraded) content still appends in arrival order — no regression", async () => {
    const mgr = await makeManager(logger, join(tempDir, "nowitness.db"));
    await seedAgents(mgr.getDb(), [AGENT]);
    await mgr.createSessionNode(sid, AGENT, "bobpubkey", "bob-peer-id", "corr-1");
    // No recordWitnessedSequence calls: B has no canonical sequence to gate on, so it falls
    // back to the pre-MSG-4 behavior (append on arrival). This preserves delivery when the
    // relay witness is unavailable.
    const c = new TextEncoder().encode("ungated");
    const r = await mgr.ingestReceivedContent(AGENT, sid, c, msgLeafHash(c), "corr-1");
    expect(r.ok).toBe(true);
    expect(mgr.getSessionTree(AGENT, sid).size()).toBe(1);
  });

  it("2b/SEC-1: the SIGNED park envelope round-trips content + ordering record; legacy shapes decode as v1 (so they can be REFUSED by name)", async () => {
    const mgr = await makeManager(logger, join(tempDir, "env.db"));
    const content = new TextEncoder().encode("payload");
    const s1 = new Uint8Array([0x01, 0x02, 0x03]);
    const s2 = new Uint8Array([0x04, 0x05, 0x06]);
    const senderPubkey = new Uint8Array(32).fill(0xaa);
    const parkSig = new Uint8Array(64).fill(0xbb);

    // With the ordering record (the live-park path).
    const dec = mgr.decodeParkEnvelope(encodeParkEnvelope({ content, structure1Cbor: s1, structure2Cbor: s2, senderPubkey, parkSig }));
    expect(dec.version).toBe(2);
    expect(Buffer.from(dec.content).toString()).toBe("payload");
    expect(dec.structure1Cbor && Buffer.from(dec.structure1Cbor).toString("hex")).toBe(Buffer.from(s1).toString("hex"));
    expect(dec.structure2Cbor && Buffer.from(dec.structure2Cbor).toString("hex")).toBe(Buffer.from(s2).toString("hex"));
    expect(dec.senderPubkey && Buffer.from(dec.senderPubkey).toString("hex")).toBe(Buffer.from(senderPubkey).toString("hex"));
    expect(dec.parkSig && Buffer.from(dec.parkSig).toString("hex")).toBe(Buffer.from(parkSig).toString("hex"));

    // Without a record (the startup-flush crash-backstop path) — still SIGNED (SEC-1).
    const dec2 = mgr.decodeParkEnvelope(encodeParkEnvelope({ content, senderPubkey, parkSig }));
    expect(dec2.version).toBe(2);
    expect(Buffer.from(dec2.content).toString()).toBe("payload");
    expect(dec2.structure1Cbor).toBeUndefined();
    expect(dec2.structure2Cbor).toBeUndefined();
    expect(dec2.senderPubkey).toBeDefined();

    // SEC-1: a legacy bare-content seal still DECODES (as v1, unsigned) — decoding is not accepting.
    // recoverParkedEntry refuses it as `unsigned_envelope`; see sec-1-park-authentication.test.ts.
    const bare = new TextEncoder().encode("legacy bare content, not an envelope at all");
    const decBare = mgr.decodeParkEnvelope(bare);
    expect(decBare.version).toBe(1);
    expect(Buffer.from(decBare.content).toString("hex")).toBe(Buffer.from(bare).toString("hex"));
    expect(decBare.senderPubkey).toBeUndefined();
  });
});

// ─── DOD-MSG-4 SECURITY: the ordering-record verification has teeth (test-attacker BLOCKING) ──────
// The receiver MUST verify the relay-signed Structure2 carried in the frame/park envelope: the
// SENDER signature over structure1_cbor, the signer == the session counterparty (sovereign-node — B
// does not trust the counterparty for ordering), and the record binds to THIS content's hash. Without
// these, a malicious counterparty/MITM stamps an arbitrary canonical sequence: a forged-ahead seq
// parks the message in #heldContent forever (never acked persisted) = silent denial-of-delivery; a
// rearranged seq diverges B's leaf order from A's, breaking leaf-index===canonical-sequence. These
// tests fail if the verify / counterparty / hash-bind checks are stripped.
describe("DOD-MSG-4: ordering-record verification is adversarially exercised", () => {
  let tempDir: string;
  let logger: Logger;
  let events: LogEvent[];
  const sid = "f".repeat(64);
  const enc = (s: string) => new TextEncoder().encode(s);
  const fired = (event: string) => events.some((e) => e.event === event);

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-msg4-sec-"));
    const l = makeLogger();
    logger = l.logger;
    events = l.events;
  });
  afterEach(async () => { await rm(tempDir, { recursive: true, force: true }); });

  /** A self-consistent signed ordering record by `kp` for `content` at relay sequence `seq`. */
  async function buildRecord(
    kp: ReturnType<typeof generateKeypair>,
    content: Uint8Array,
    seq: number,
    opts: { corruptSig?: boolean } = {},
  ): Promise<{ structure1Cbor: Uint8Array; structure2Cbor: Uint8Array; contentHash: Uint8Array }> {
    const pubkey = await kp.getPublicKey();
    const contentHash = msgLeafHash(content); // 32-byte msg leaf hash, as the sender submits
    const structure1Cbor = encodeStructure1({
      contentHash,
      senderPubkey: pubkey,
      sessionId: new Uint8Array(16),
      lastSeenSeq: 0,
      timestamp: 1_700_000_000_000,
    });
    let sig = await kp.sign(structure1Cbor); // 64-byte Ed25519 over the exact structure1 bytes
    if (opts.corruptSig) { sig = new Uint8Array(sig); sig[0] ^= 0xff; }
    const built = buildStructure2(seq, pubkey, contentHash, sig, new Uint8Array(32));
    if (!built.ok) throw new Error("buildStructure2 failed: " + JSON.stringify(built.error));
    return { structure1Cbor, structure2Cbor: encodeStructure2(built.structure2), contentHash };
  }

  async function managerWithCounterparty(kp: ReturnType<typeof generateKeypair>, dbName: string): Promise<SessionNodeManager> {
    const mgr = await makeManager(logger, join(tempDir, dbName));
    await seedAgents(mgr.getDb(), ["alice"]);
    const cpHex = Buffer.from(await kp.getPublicKey()).toString("hex");
    await mgr.createSessionNode(sid, "alice", cpHex, "peer-id", "corr");
    return mgr;
  }

  it("HAPPY: a validly-signed counterparty record IS recorded → ingest appends at the canonical sequence", async () => {
    const kp = generateKeypair();
    const mgr = await managerWithCounterparty(kp, "happy.db");
    const c = enc("m0");
    const rec = await buildRecord(kp, c, 1); // relay seq 1 → 0-based idx 0
    mgr.recordOrderingRecord("alice", sid, rec.structure1Cbor, rec.structure2Cbor, rec.contentHash);
    expect(fired("session.content.ordering.recorded"), "valid record is accepted").toBe(true);
    expect((await mgr.ingestReceivedContent("alice", sid, c, rec.contentHash)).ok).toBe(true);
    expect(mgr.getSessionTree("alice", sid).size()).toBe(1);
  });

  it("BAD SIGNATURE is REJECTED — no ordering recorded, bad_signature warn, content still delivered (fail-closed, no loss)", async () => {
    const kp = generateKeypair();
    const mgr = await managerWithCounterparty(kp, "badsig.db");
    const c = enc("m0");
    const rec = await buildRecord(kp, c, 5, { corruptSig: true }); // forged-ahead seq 5
    mgr.recordOrderingRecord("alice", sid, rec.structure1Cbor, rec.structure2Cbor, rec.contentHash);
    expect(fired("session.content.ordering.recorded"), "a bad signature must NOT record ordering").toBe(false);
    expect(fired("session.content.ordering.bad_signature")).toBe(true);
    // The forged seq-5 was NOT recorded, so the honest arrival is NOT held forever behind a fake gap —
    // it appends in arrival order. (If verification were stripped, seq-5 would record and HOLD this.)
    const r = await mgr.ingestReceivedContent("alice", sid, c, rec.contentHash);
    expect(r.ok && r.held !== true, "fail-closed on the record, but the message still delivers").toBe(true);
    expect(mgr.getSessionTree("alice", sid).size()).toBe(1);
  });

  it("WRONG SIGNER (valid sig by a NON-counterparty key) is REJECTED — wrong_signer, no ordering recorded", async () => {
    const counterparty = generateKeypair();
    const attacker = generateKeypair(); // a different, perfectly valid key
    const mgr = await managerWithCounterparty(counterparty, "wrongsigner.db");
    const c = enc("m0");
    const rec = await buildRecord(attacker, c, 9); // self-consistent, but signed by the attacker
    mgr.recordOrderingRecord("alice", sid, rec.structure1Cbor, rec.structure2Cbor, rec.contentHash);
    expect(fired("session.content.ordering.recorded"), "a non-counterparty signer must NOT record ordering").toBe(false);
    expect(fired("session.content.ordering.wrong_signer")).toBe(true);
    expect((await mgr.ingestReceivedContent("alice", sid, c, rec.contentHash)).ok).toBe(true);
    expect(mgr.getSessionTree("alice", sid).size()).toBe(1);
  });

  it("HASH MISMATCH (record bound to a DIFFERENT content hash) is REJECTED — hash_mismatch, no ordering recorded", async () => {
    const kp = generateKeypair();
    const mgr = await managerWithCounterparty(kp, "hashmismatch.db");
    const c = enc("m0");
    const rec = await buildRecord(kp, c, 3); // structure1 binds hash(m0)
    const otherHash = msgLeafHash(enc("a different message")); // present the record for the wrong content
    mgr.recordOrderingRecord("alice", sid, rec.structure1Cbor, rec.structure2Cbor, otherHash);
    expect(fired("session.content.ordering.recorded"), "a hash-mismatched record must NOT record ordering").toBe(false);
    expect(fired("session.content.ordering.hash_mismatch")).toBe(true);
  });
});
