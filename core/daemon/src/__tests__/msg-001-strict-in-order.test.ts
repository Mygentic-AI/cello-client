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
import { SessionNodeManager } from "../session-node-manager.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { Logger } from "../types.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { Stream } from "@libp2p/interface";

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
  const mgr = new SessionNodeManager({ factory: new ControlledFactory(new FakeNode() as unknown as CelloNode), logger, dbPath });
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
    const r2 = mgr.ingestReceivedContent(AGENT, sid, c2, h2, "corr-1");
    expect(r2.ok).toBe(true);
    expect(mgr.getSessionTree(AGENT, sid).size(), "out-of-order content is held, tree stays empty").toBe(0);
    expect(events.some((e) => e.event === "session.content.held")).toBe(true);

    // c0 (seq 0) arrives → appended as leaf 0. c2 still held (gap at seq 1).
    mgr.ingestReceivedContent(AGENT, sid, c0, h0, "corr-1");
    expect(mgr.getSessionTree(AGENT, sid).size(), "only seq 0 lands; seq 2 still held behind the gap").toBe(1);

    // c1 (seq 1) arrives → appended leaf 1, and now c2 is released → leaf 2. Order preserved.
    mgr.ingestReceivedContent(AGENT, sid, c1, h1, "corr-1");
    expect(mgr.getSessionTree(AGENT, sid).size()).toBe(3);
    expect(leafHashes(mgr), "leaf order is the canonical sequence, not arrival order").toEqual([hx(h0), hx(h1), hx(h2)]);

    // And cello_receive drains them in canonical order m0, m1, m2.
    const drain = [0, 1, 2].map(() => mgr.takeReceivedContent(AGENT, sid));
    expect(drain.map((d) => d && Buffer.from(d.contentHex, "hex").toString())).toEqual(["m0", "m1", "m2"]);
  });

  it("the in-order happy path is unchanged — sequential arrivals append immediately", async () => {
    const mgr = await makeManager(logger, join(tempDir, "happy.db"));
    await mgr.createSessionNode(sid, AGENT, "bobpubkey", "bob-peer-id", "corr-1");
    const msgs = ["a", "b", "c"].map((s) => new TextEncoder().encode(s));
    const hashes = msgs.map(msgLeafHash);
    hashes.forEach((h, i) => mgr.recordWitnessedSequence(AGENT, sid, Buffer.from(h).toString("hex"), i));
    msgs.forEach((c, i) => {
      const r = mgr.ingestReceivedContent(AGENT, sid, c, hashes[i], "corr-1");
      expect(r.ok).toBe(true);
      expect(mgr.getSessionTree(AGENT, sid).size()).toBe(i + 1);
    });
    expect(leafHashes(mgr)).toEqual(hashes.map((h) => Buffer.from(h).toString("hex")));
  });

  it("without a witness (relay-degraded) content still appends in arrival order — no regression", async () => {
    const mgr = await makeManager(logger, join(tempDir, "nowitness.db"));
    await mgr.createSessionNode(sid, AGENT, "bobpubkey", "bob-peer-id", "corr-1");
    // No recordWitnessedSequence calls: B has no canonical sequence to gate on, so it falls
    // back to the pre-MSG-4 behavior (append on arrival). This preserves delivery when the
    // relay witness is unavailable.
    const c = new TextEncoder().encode("ungated");
    const r = mgr.ingestReceivedContent(AGENT, sid, c, msgLeafHash(c), "corr-1");
    expect(r.ok).toBe(true);
    expect(mgr.getSessionTree(AGENT, sid).size()).toBe(1);
  });

  it("2b: park envelope round-trips content + ordering record; bare content falls back (backward compat)", async () => {
    const mgr = await makeManager(logger, join(tempDir, "env.db"));
    const content = new TextEncoder().encode("payload");
    const s1 = new Uint8Array([0x01, 0x02, 0x03]);
    const s2 = new Uint8Array([0x04, 0x05, 0x06]);

    // With the ordering record (the live-park path).
    const dec = mgr.decodeParkEnvelope(mgr.encodeParkEnvelope(content, s1, s2));
    expect(Buffer.from(dec.content).toString()).toBe("payload");
    expect(dec.structure1Cbor && Buffer.from(dec.structure1Cbor).toString("hex")).toBe(Buffer.from(s1).toString("hex"));
    expect(dec.structure2Cbor && Buffer.from(dec.structure2Cbor).toString("hex")).toBe(Buffer.from(s2).toString("hex"));

    // Without a record (the startup-flush crash-backstop path).
    const dec2 = mgr.decodeParkEnvelope(mgr.encodeParkEnvelope(content));
    expect(Buffer.from(dec2.content).toString()).toBe("payload");
    expect(dec2.structure1Cbor).toBeUndefined();
    expect(dec2.structure2Cbor).toBeUndefined();

    // Backward compat: a bare-content seal (old/test-fixture path, not an envelope) → content only.
    const bare = new TextEncoder().encode("legacy bare content, not an envelope at all");
    const decBare = mgr.decodeParkEnvelope(bare);
    expect(Buffer.from(decBare.content).toString("hex")).toBe(Buffer.from(bare).toString("hex"));
    expect(decBare.structure2Cbor).toBeUndefined();
  });
});
