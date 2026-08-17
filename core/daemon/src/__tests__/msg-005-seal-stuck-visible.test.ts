/**
 * DOD-M12B-SEAL-STUCK-1 — a session that can never seal must not be invisible.
 *
 * The seal gate refuses correctly: a chain with a gap cannot be co-signed, and signing a short one
 * gets `leaf_count_mismatch` back, which is terminal and costs the notarized receipt for good. That
 * refusal is right and this unit does not touch it.
 *
 * What is missing is that you cannot SEE the condition. A stuck session sits in `cello status` as
 * an ordinary active session; the only way to learn it will never close is to attempt a close on
 * each one and read the refusal. Measured 2026-08-17: **25 sessions opened by the document worker,
 * 25 seals blocked, 0 closed** — and each one holds a slot against the per-sender cap, so a spine
 * defect turns straight into "this agent stops accepting sessions" with nothing on any surface
 * saying why.
 *
 * Revert test: drop `seal_blocked` from `buildActiveSessions` and the first case fails — a stuck
 * session becomes indistinguishable from a healthy one again.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { FileKeyProvider, msgLeafHash } from "@cello-protocol/crypto";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { startDaemon } from "../daemon.js";
import type { Logger, DaemonConfig } from "../types.js";
import type { ISessionNodeFactory, SessionNodeConfig } from "../session-node-manager.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { Stream } from "@libp2p/interface";

interface LogEvent { level: string; event: string; context: Record<string, unknown> }

function makeLogger(): { logger: Logger; events: LogEvent[] } {
  const events: LogEvent[] = [];
  const logger: Logger = {
    debug(event, context) { events.push({ level: "debug", event, context: context ?? {} }); },
    info(event, context) { events.push({ level: "info", event, context: context ?? {} }); },
    warn(event, context) { events.push({ level: "warn", event, context: context ?? {} }); },
    error(event, context) { events.push({ level: "error", event, context: context ?? {} }); },
  };
  return { logger, events };
}

/** Minimal fake node — content arrives via direct ingest; no stream is needed for the gate logic. */
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

class FixedFactory implements ISessionNodeFactory {
  async createNode(_c: SessionNodeConfig): Promise<CelloNode> { return new FakeNode() as unknown as CelloNode; }
}

describe("DOD-M12B-SEAL-STUCK-1: a session that cannot seal is visible without probing it", () => {
  let tempDir: string;
  let handle: Awaited<ReturnType<typeof startDaemon>> | null;

  beforeEach(async () => { tempDir = await mkdtemp(join(tmpdir(), "cello-msg005-")); handle = null; });
  afterEach(async () => {
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* stopped */ } }
    await rm(tempDir, { recursive: true, force: true });
  });

  async function makeAgentDir(name: string): Promise<string> {
    const dir = join(tempDir, "agents", name);
    await mkdir(dir, { recursive: true });
    const kp = await FileKeyProvider.load(join(dir, "key"));
    return Buffer.from(await kp.getPublicKey()).toString("hex");
  }

  async function start(logger: Logger): Promise<Awaited<ReturnType<typeof startDaemon>>> {
    const config: DaemonConfig = {
      securityGateway: new PassthroughGatewayClient(),
      celloDir: tempDir, socketPath: join(tempDir, "daemon.sock"), lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16, version: "0.0.1-test", logger, sessionNodeFactory: new FixedFactory(),
    };
    const h = await startDaemon(config);
    handle = h;
    return h;
  }

  const STUCK = "7a".repeat(32);
  const HEALTHY = "7b".repeat(32);

  it("status marks the stuck session and leaves the healthy one alone", async () => {
    await makeAgentDir("alice");
    const { logger } = makeLogger();
    const h = await start(logger);
    const snm = h.getSessionNodeManager();

    await snm.createSessionNode(STUCK, "alice", "bobpubkeyhex", "peer-1", "corr");
    await snm.createSessionNode(HEALTHY, "alice", "bobpubkeyhex", "peer-2", "corr");

    // The stuck one: the relay witnessed position 1 and this side never received position 0, so
    // the arriving frame is held behind a gap that nothing on this daemon can fill.
    const c = new TextEncoder().encode("held behind a gap");
    const hash = msgLeafHash(c);
    snm.recordWitnessedSequence("alice", STUCK, Buffer.from(hash).toString("hex"), 1);
    await snm.ingestReceivedContent("alice", STUCK, c, hash, "corr");
    expect(snm.sealReadiness("alice", STUCK).ready, "the fixture must actually be stuck").toBe(false);

    // The healthy one: an ordinary in-order message.
    const c2 = new TextEncoder().encode("ordinary");
    await snm.ingestReceivedContent("alice", HEALTHY, c2, msgLeafHash(c2), "corr");
    expect(snm.sealReadiness("alice", HEALTHY).ready).toBe(true);

    const status = h.getStatus();
    const rows = status.active_sessions;
    const stuck = rows.find((r) => r.sessionId === STUCK);
    const healthy = rows.find((r) => r.sessionId === HEALTHY);
    expect(stuck, "the stuck session must be listed at all").toBeDefined();
    expect(healthy).toBeDefined();

    // THE POINT: the two are distinguishable from the status surface alone, with the numbers that
    // say WHY — not a bare flag the operator then has to go and interpret.
    expect(stuck!.sealBlocked, "a session that can never close must say so on the surface that lists it").not.toBeNull();
    expect(stuck!.sealBlocked!.heldMessages).toBe(1);
    expect(healthy!.sealBlocked, "a healthy session must not be flagged — a warning on everything is a warning on nothing").toBeNull();
  }, 60_000);

  // A GUARD test, not a change test: it passes before this unit because DOD-M12B-STRAND-1 already
  // made holds durable. It is here so that the property force-abandon now depends on — "the escape
  // hatch costs the receipt, not the messages" — cannot be removed without something going red.
  it("held content survives a force-abandon (guard on the durable-hold rows, which the escape hatch now relies on)", async () => {
    await makeAgentDir("alice");
    const { logger } = makeLogger();
    const h = await start(logger);
    const snm = h.getSessionNodeManager();

    await snm.createSessionNode(STUCK, "alice", "bobpubkeyhex", "peer-1", "corr");
    const c = new TextEncoder().encode("received, verified, never delivered");
    const hash = msgLeafHash(c);
    snm.recordWitnessedSequence("alice", STUCK, Buffer.from(hash).toString("hex"), 1);
    await snm.ingestReceivedContent("alice", STUCK, c, hash, "corr");

    // Force-abandon is the operator's way out of a session that can never seal. Before durable
    // holds it also destroyed whatever was waiting behind the gap, which made the only exit a
    // data-losing one. It must not any more.
    await snm.abandonSession("alice", STUCK);

    // The content moved, it did not vanish. Once a session is terminal nothing can ever release a
    // held frame into its chain again — ingest refuses a terminal session, and the release path is
    // only reachable from ingest — so leaving the row in `held_content` would be durable storage
    // nothing can read. The annex is where content that outlived its chain is readable from.
    const stillHeld = snm.getDb()
      .prepare("SELECT COUNT(*) AS n FROM held_content WHERE session_id = ?")
      .get(STUCK) as { n: number };
    expect(stillHeld.n, "an unreachable held row is not preservation — it must be moved, not kept").toBe(0);

    const annexed = snm.getDb()
      .prepare("SELECT content FROM sealed_session_annex WHERE session_id = ?")
      .get(STUCK) as { content: Buffer } | undefined;
    expect(annexed, "abandoning a session must not destroy content it already received and verified").toBeDefined();
    expect(Buffer.from(annexed!.content).toString()).toBe("received, verified, never delivered");
  }, 60_000);
});
