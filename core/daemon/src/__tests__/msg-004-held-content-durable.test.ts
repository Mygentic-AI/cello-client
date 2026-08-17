/**
 * DOD-M12B-STRAND-1 — held content is never destroyed.
 *
 * `#heldContent` is memory-only. Content that has been RECEIVED, VERIFIED and cross-checked, and
 * is merely waiting for an earlier canonical position to arrive, dies with the session node. The
 * teardown path says so itself: *"This is a LOSS REPORT, not a fix — the content is unrecoverable
 * by the time we are here."*
 *
 * Measured on one daemon in one morning (M12B Entry 6 / launch-triage item 24): **367 held, 8
 * released, 24 DESTROYED**, and `session.content.held.discarded` fired **20 times on 2026-08-16**.
 * Each destruction is a permanent hole: the sender was never acknowledged, so it believes the
 * message is merely pending, while the receiver has thrown away the only copy it will ever see and
 * every later message in that session is now held behind a gap nothing can fill.
 *
 * This is what turns a hiccup into a dead conversation. With durable holds the gap is RECOVERABLE:
 * the missing frame may still be parked at the relay, and the hold is still there to release
 * against when it lands.
 *
 * Revert test: drop the `held_content` writes and this fails — the content is gone after restart
 * and the tree stalls at 2 leaves with the third hole unfillable.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { msgLeafHash } from "@cello-protocol/crypto";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { SessionNodeManager } from "../session-node-manager.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { Logger } from "../types.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { Stream } from "@libp2p/interface";
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
  async createNode(_c: SessionNodeConfig): Promise<CelloNode> { return new FakeNode() as unknown as CelloNode; }
}

async function makeManager(logger: Logger, dbPath: string): Promise<SessionNodeManager> {
  const mgr = new SessionNodeManager({ securityGateway: new PassthroughGatewayClient(), factory: new ControlledFactory(), logger, dbPath });
  await mgr.initialize();
  return mgr;
}

const AGENT = "alice";

describe("DOD-M12B-STRAND-1: verified content that cannot yet be delivered is durable", () => {
  let tempDir: string;
  const sid = "f".repeat(64);

  beforeEach(async () => { tempDir = await mkdtemp(join(tmpdir(), "cello-msg004-")); });
  afterEach(async () => { await rm(tempDir, { recursive: true, force: true }); });

  const hx = (h: Uint8Array) => Buffer.from(h).toString("hex");

  it("held content survives session teardown AND a daemon restart, then releases into its canonical slot", async () => {
    const dbPath = join(tempDir, "s.db");
    const c0 = new TextEncoder().encode("m0");
    const c1 = new TextEncoder().encode("m1");
    const c2 = new TextEncoder().encode("m2");
    const h0 = msgLeafHash(c0), h1 = msgLeafHash(c1), h2 = msgLeafHash(c2);

    const first = makeLogger();
    {
      const mgr = await makeManager(first.logger, dbPath);
      await seedAgents(mgr.getDb(), [AGENT]);
      await mgr.createSessionNode(sid, AGENT, "bobpubkey", "bob-peer-id", "corr-1");

      // The relay witnessed seq 2 for m2. It arrives first, so it is held behind the gap at 0..1.
      mgr.recordWitnessedSequence(AGENT, sid, hx(h2), 2);
      const r2 = await mgr.ingestReceivedContent(AGENT, sid, c2, h2, "corr-1");
      expect(r2.ok).toBe(true);
      expect(first.events.some((e) => e.event === "session.content.held")).toBe(true);
      expect(mgr.getSessionTree(AGENT, sid).size()).toBe(0);

      // The session node is DESTROYED while the gap is still open — the exact shape that destroyed
      // 24 verified messages on one morning. Driven explicitly rather than via gracefulShutdown,
      // which clears its caches directly and never touches the hold map, so the teardown report
      // this asserts on could not fire either way.
      await mgr.destroySessionNode(AGENT, sid, "error");
      const discarded = first.events.filter((e) => e.event === "session.content.held.discarded");
      expect(discarded.length, "the teardown must still report that a gap was open").toBe(1);
      // It reports SURVIVAL, not loss. `durable` is a COUNT against the store, not a belief.
      expect(discarded[0]!.context["durable"]).toBe(1);
      expect(
        first.events.filter((e) => e.event === "session.content.held.lost"),
        "the content was persisted, so nothing may report it destroyed",
      ).toEqual([]);
      await mgr.gracefulShutdown();
    }

    // A NEW daemon process on the same database — the held frame must still be there.
    const second = makeLogger();
    const mgr2 = await makeManager(second.logger, dbPath);
    await mgr2.createSessionNode(sid, AGENT, "bobpubkey", "bob-peer-id", "corr-2");

    // The gap fills from the relay mailbox, exactly as it would in production.
    mgr2.recordWitnessedSequence(AGENT, sid, hx(h0), 0);
    await mgr2.ingestReceivedContent(AGENT, sid, c0, h0, "corr-2");
    expect(mgr2.getSessionTree(AGENT, sid).size(), "seq 2 is still held behind the gap at seq 1").toBe(1);

    mgr2.recordWitnessedSequence(AGENT, sid, hx(h1), 1);
    await mgr2.ingestReceivedContent(AGENT, sid, c1, h1, "corr-2");

    // The survivor lands at its OWN canonical position — leaf index 2, not "next free slot".
    // A restart that re-appended it anywhere else would change the root the seal signs over.
    expect(mgr2.getSessionTree(AGENT, sid).size()).toBe(3);
    expect(mgr2.getSessionTree(AGENT, sid).leaves().map((l) => l.hashHex)).toEqual([hx(h0), hx(h1), hx(h2)]);
    expect(second.events.some((e) => e.event === "session.content.released")).toBe(true);

    // And the agent can actually read it — durable must mean deliverable, not merely stored.
    const drained = [0, 1, 2].map(() => mgr2.takeReceivedContent(AGENT, sid));
    expect(drained.map((d) => d && Buffer.from(d.contentHex, "hex").toString())).toEqual(["m0", "m1", "m2"]);

    // The restore is OBSERVABLE. A silent one would leave the live run that has to prove this fix
    // with nothing to point at, and it is the counterpart to `session.content.held` on the way in.
    const restored = second.events.find((e) => e.event === "session.content.held.restored");
    expect(restored, "the restore must announce itself").toBeDefined();
    expect(restored!.context["restored"]).toBe(1);
    expect(restored!.context["superseded"]).toBe(0);

    await mgr2.gracefulShutdown();
  }, 60_000);

  it("after a restart the seal gate still sees the gap — a durable hold must not read as an empty one", async () => {
    const dbPath = join(tempDir, "s4.db");
    const c1 = new TextEncoder().encode("q1");
    const h1 = msgLeafHash(c1);

    const first = makeLogger();
    {
      const mgr = await makeManager(first.logger, dbPath);
      await seedAgents(mgr.getDb(), [AGENT]);
      await mgr.createSessionNode(sid, AGENT, "bobpubkey", "bob-peer-id", "corr-1");
      mgr.recordWitnessedSequence(AGENT, sid, hx(h1), 1);
      await mgr.ingestReceivedContent(AGENT, sid, c1, h1, "corr-1");
      expect(mgr.sealReadiness(AGENT, sid).ready, "a session with a gap is not sealable").toBe(false);
      await mgr.gracefulShutdown();
    }

    // THE DANGEROUS DIRECTION. Holds are restored lazily, so a reader that consults the in-memory
    // map before hydration counts zero — and `sealReadiness` reporting READY on a gapped session is
    // the one outcome worse than refusing a healthy close: the counterparty answers
    // leaf_count_mismatch, which is terminal, and the receipt is gone for good.
    const second = makeLogger();
    const mgr2 = await makeManager(second.logger, dbPath);
    await mgr2.createSessionNode(sid, AGENT, "bobpubkey", "bob-peer-id", "corr-2");
    const readiness = mgr2.sealReadiness(AGENT, sid);
    expect(readiness.heldCount, "the durable hold must be counted before the gate judges").toBe(1);
    expect(readiness.ready, "a restart must not make a gapped session look sealable").toBe(false);
    await mgr2.gracefulShutdown();
  }, 60_000);

  it("a hold whose content the tree ALREADY HOLDS at that position is dropped, never re-appended", async () => {
    const dbPath = join(tempDir, "s3.db");
    const c0 = new TextEncoder().encode("p0");
    const c1 = new TextEncoder().encode("p1");
    const h0 = msgLeafHash(c0), h1 = msgLeafHash(c1);

    const first = makeLogger();
    {
      const mgr = await makeManager(first.logger, dbPath);
      await seedAgents(mgr.getDb(), [AGENT]);
      await mgr.createSessionNode(sid, AGENT, "bobpubkey", "bob-peer-id", "corr-1");
      // Hold p1 at seq 1, then fill seq 0 so p1 is released and lands at index 1 — after which the
      // tree genuinely holds that content at that position.
      mgr.recordWitnessedSequence(AGENT, sid, hx(h1), 1);
      await mgr.ingestReceivedContent(AGENT, sid, c1, h1, "corr-1");
      mgr.recordWitnessedSequence(AGENT, sid, hx(h0), 0);
      await mgr.ingestReceivedContent(AGENT, sid, c0, h0, "corr-1");
      expect(mgr.getSessionTree(AGENT, sid).size()).toBe(2);
      // Put the row back by hand: a real daemon reaches this state by crashing between the append
      // and the delete, and that window is exactly what the restore must be safe against.
      mgr.getDb().prepare(
        `INSERT OR REPLACE INTO held_content (agent_id, session_id, canonical_seq, content_blob, original_blob, content_hash_hex, screened_out, correlation_id, held_at)
         VALUES ((SELECT agent_id FROM sessions WHERE session_id = ?), ?, 1, ?, ?, ?, 0, 'corr-1', ?)`,
      ).run(sid, sid, Buffer.from(c1), Buffer.from(c1), hx(h1), Date.now());
      await mgr.gracefulShutdown();
    }

    const second = makeLogger();
    const mgr2 = await makeManager(second.logger, dbPath);
    await mgr2.createSessionNode(sid, AGENT, "bobpubkey", "bob-peer-id", "corr-2");
    const next = new TextEncoder().encode("p2");
    await mgr2.ingestReceivedContent(AGENT, sid, next, msgLeafHash(next), "corr-2");
    expect(mgr2.getSessionTree(AGENT, sid).size(), "the duplicate must not re-append").toBe(3);
    const restored = second.events.find((e) => e.event === "session.content.held.restored");
    expect(restored).toBeDefined();
    expect(restored!.context["superseded"], "the tree holds this exact content here — the row is redundant").toBe(1);
    expect(restored!.context["drifted"]).toBe(0);
    await mgr2.gracefulShutdown();
  }, 60_000);

  it("a hold whose position is occupied by DIFFERENT content is annexed, never silently deleted", async () => {
    const dbPath = join(tempDir, "s5.db");
    const held = new TextEncoder().encode("mine, and nobody else has a copy");
    const heldHash = msgLeafHash(held);

    const first = makeLogger();
    {
      const mgr = await makeManager(first.logger, dbPath);
      await seedAgents(mgr.getDb(), [AGENT]);
      await mgr.createSessionNode(sid, AGENT, "bobpubkey", "bob-peer-id", "corr-1");
      mgr.recordWitnessedSequence(AGENT, sid, hx(heldHash), 1);
      await mgr.ingestReceivedContent(AGENT, sid, held, heldHash, "corr-1");
      // The tree grows past position 1 with OTHER content. The relay's sequence space and this
      // tree's leaf-index space drift — the relay counts ctrl leaves the tree never appends — so
      // "canonical_seq < frontier" is true here for a frame the tree has never held. Judging on the
      // index alone would destroy it and file the destruction as tidy-up.
      mgr.appendSessionLeaf(AGENT, sid, "msg", "aa".repeat(32), "seed");
      mgr.appendSessionLeaf(AGENT, sid, "msg", "bb".repeat(32), "seed");
      await mgr.gracefulShutdown();
    }

    const second = makeLogger();
    const mgr2 = await makeManager(second.logger, dbPath);
    await mgr2.createSessionNode(sid, AGENT, "bobpubkey", "bob-peer-id", "corr-2");
    const next = new TextEncoder().encode("p9");
    await mgr2.ingestReceivedContent(AGENT, sid, next, msgLeafHash(next), "corr-2");

    const drift = second.events.find((e) => e.event === "session.content.held.position_drifted");
    expect(drift, "a frame that cannot join the chain must be named, not counted as tidy-up").toBeDefined();
    expect(drift!.level, "losing the ability to deliver verified content is an error, not a note").toBe("error");
    expect(drift!.context["annexed"]).toBe(true);

    // THE CONTENT STILL EXISTS. That is the whole invariant: it cannot join this chain, but it is
    // not destroyed to resolve an ordering problem.
    const annex = mgr2.getDb()
      .prepare("SELECT content FROM sealed_session_annex WHERE session_id = ? AND content_hash = ?")
      .get(sid, hx(heldHash)) as { content: Buffer } | undefined;
    expect(annex, "the frame must be readable from the annex").toBeDefined();
    expect(Buffer.from(annex!.content).toString()).toBe("mine, and nobody else has a copy");
    await mgr2.gracefulShutdown();
  }, 60_000);

  it("a document frame survives the round trip as the peer's RAW bytes, not the screened copy", async () => {
    const dbPath = join(tempDir, "s6.db");
    // Classification reads byte 0, and the screened copy is no longer a CBOR map header for a
    // document frame — so a restore that dropped `original_blob` would release a document frame
    // into the conversation path: transcript, doorbell, and an agent handed raw CBOR.
    const raw = new Uint8Array([0xa2, 0x01, 0x02, 0x03, 0x04, 0x05]);
    const rawHash = msgLeafHash(raw);
    const c0 = new TextEncoder().encode("first");
    const h0 = msgLeafHash(c0);

    const first = makeLogger();
    {
      const mgr = await makeManager(first.logger, dbPath);
      await seedAgents(mgr.getDb(), [AGENT]);
      await mgr.createSessionNode(sid, AGENT, "bobpubkey", "bob-peer-id", "corr-1");
      mgr.recordWitnessedSequence(AGENT, sid, hx(rawHash), 1);
      await mgr.ingestReceivedContent(AGENT, sid, raw, rawHash, "corr-1");
      await mgr.gracefulShutdown();
    }

    const second = makeLogger();
    const mgr2 = await makeManager(second.logger, dbPath);
    await mgr2.createSessionNode(sid, AGENT, "bobpubkey", "bob-peer-id", "corr-2");
    mgr2.recordWitnessedSequence(AGENT, sid, hx(h0), 0);
    await mgr2.ingestReceivedContent(AGENT, sid, c0, h0, "corr-2");
    expect(mgr2.getSessionTree(AGENT, sid).size()).toBe(2);
    // The leaf binds the hash of the RAW bytes — if the restore had lost them, the released leaf
    // would bind the screened copy's hash instead and the two parties' roots would part.
    expect(mgr2.getSessionTree(AGENT, sid).leaves().map((l) => l.hashHex)).toEqual([hx(h0), hx(rawHash)]);
    await mgr2.gracefulShutdown();
  }, 60_000);

  it("released content is removed from the durable store — it must not resurrect on the next restart", async () => {
    const dbPath = join(tempDir, "s2.db");
    const c0 = new TextEncoder().encode("n0");
    const c1 = new TextEncoder().encode("n1");
    const h0 = msgLeafHash(c0), h1 = msgLeafHash(c1);

    const first = makeLogger();
    {
      const mgr = await makeManager(first.logger, dbPath);
      await seedAgents(mgr.getDb(), [AGENT]);
      await mgr.createSessionNode(sid, AGENT, "bobpubkey", "bob-peer-id", "corr-1");
      mgr.recordWitnessedSequence(AGENT, sid, hx(h1), 1);
      await mgr.ingestReceivedContent(AGENT, sid, c1, h1, "corr-1");
      mgr.recordWitnessedSequence(AGENT, sid, hx(h0), 0);
      await mgr.ingestReceivedContent(AGENT, sid, c0, h0, "corr-1");
      expect(mgr.getSessionTree(AGENT, sid).size(), "both landed, nothing is held").toBe(2);
      // ASSERT ON THE STORE, IN THIS PROCESS. Asserting only that the restarted tree looks right
      // proves nothing about the row: the second manager never reads a row that is behind its
      // frontier, so deleting the DELETE and leaving the row behind would look identical.
      const remaining = mgr.getDb()
        .prepare("SELECT COUNT(*) AS n FROM held_content WHERE session_id = ?")
        .get(sid) as { n: number };
      expect(remaining.n, "a released frame's durable row must be gone the moment it is released").toBe(0);
      await mgr.gracefulShutdown();
    }

    // A durable hold that is never deleted would re-append its content on every boot, growing the
    // tree and changing the root under a seal that already signed the old one.
    const second = makeLogger();
    const mgr2 = await makeManager(second.logger, dbPath);
    await mgr2.createSessionNode(sid, AGENT, "bobpubkey", "bob-peer-id", "corr-2");
    expect(mgr2.getSessionTree(AGENT, sid).size(), "the tree must be unchanged by a restart").toBe(2);
    expect(mgr2.getSessionTree(AGENT, sid).leaves().map((l) => l.hashHex)).toEqual([hx(h0), hx(h1)]);
    await mgr2.gracefulShutdown();
  }, 60_000);
});
