/**
 * CELLO-M7-MSG-001 — content size cap (send side), re-homed onto the daemon.
 *
 * AC-013 (send cap): content offered to cello_send that exceeds the 1 MB message
 *   content cap is rejected with { ok:false, reason:'content_too_large', guidance },
 *   NO content frame is transmitted, NO hash/tree leaf is produced, the session is
 *   NOT desynced, and content.rejected.too_large fires with sessionId, contentSize,
 *   and cap.
 * AC-021: the cello_send failure response carries a `guidance` field naming the
 *   correct next action (split under the cap / use the large-object path).
 * AC-018 (the daemon's half): the cap is the single named constant MAX_CONTENT_BYTES
 *   and is strictly below the it-length-prefixed transport default so the app cap
 *   always fires first.
 *
 * The receive-side cap (AC-014) is enforced in the transport content decode path
 * (component_under_test: transport) and is covered there.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { MAX_CONTENT_BYTES, IT_LENGTH_PREFIX_DEFAULT_MAX } from "@cello-protocol/protocol-types";
import { FileKeyProvider } from "@cello-protocol/crypto";
import { PassthroughGatewayClient } from "@cello-protocol/gateway";
import { startDaemon } from "../daemon.js";
import { connectToDaemon } from "../ipc-client.js";
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

/** Fake session node that captures every content frame it is asked to send. */
class FakeNode implements Partial<CelloNode> {
  sent: Uint8Array[] = [];
  readonly #peerId = `fake-${Math.random().toString(36).slice(2)}`;
  async start(): Promise<void> {}
  async stop(): Promise<void> {}
  getPeerId(): string { return this.#peerId; }
  listenAddresses(): string[] { return ["/ip4/127.0.0.1/tcp/0"]; }
  async dial(_a: string): Promise<{ peerId: string }> { return { peerId: "remote" }; }
  async handle(_p: string, _h: unknown): Promise<void> {}
  getProtocols(): string[] { return []; }
  getConnections(): Array<{ peerId: string; encryption: string | undefined }> { return []; }
  onPeerConnect(_h: (p: string) => void): void {}
  onPeerDisconnect(_h: (p: string) => void): void {}
  getDialability(): { dialable: boolean; publicAddr: string | null } { return { dialable: false, publicAddr: null }; }
  onDialabilityChange(_l: (d: { dialable: boolean; publicAddr: string | null }) => void): () => void { return () => {}; }
  async newStream(_peer: string, _proto: string): Promise<Stream> {
    const sink = this.sent;
    return { send(d: Uint8Array) { sink.push(d); }, async close() {}, abort() {}, status: "open" } as unknown as Stream;
  }
}

class FixedFactory implements ISessionNodeFactory {
  constructor(private node: CelloNode) {}
  async createNode(_c: SessionNodeConfig): Promise<CelloNode> { return this.node; }
}

describe("MSG-001: content size cap (send side, daemon)", () => {
  let tempDir: string;
  let handle: Awaited<ReturnType<typeof startDaemon>> | null;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-msg001-cap-"));
    handle = null;
  });
  afterEach(async () => {
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* ignore */ } }
    await rm(tempDir, { recursive: true, force: true });
  });

  async function makeAgentDir(name: string): Promise<void> {
    const dir = join(tempDir, "agents", name);
    await mkdir(dir, { recursive: true });
    await FileKeyProvider.load(join(dir, "key"));
  }

  async function start(logger: Logger, node: CelloNode): Promise<Awaited<ReturnType<typeof startDaemon>>> {
    const config: DaemonConfig = {
    securityGateway: new PassthroughGatewayClient(),
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger,
      sessionNodeFactory: new FixedFactory(node),
    };
    const h = await startDaemon(config);
    handle = h;
    return h;
  }

  const SID = "cd".repeat(32);

  it("AC-018: MAX_CONTENT_BYTES is 1 MiB and strictly below the it-length-prefix transport default", () => {
    expect(MAX_CONTENT_BYTES).toBe(1_048_576);
    expect(MAX_CONTENT_BYTES).toBeLessThan(IT_LENGTH_PREFIX_DEFAULT_MAX);
  });

  it("AC-013/AC-021: cello_send rejects > 1 MB content with content_too_large + guidance; no frame sent, no leaf, session stays active", async () => {
    const { logger, events } = makeLogger();
    await makeAgentDir("alice");
    const node = new FakeNode();
    const h = await start(logger, node);
    const snm = h.getSessionNodeManager();
    await snm.createSessionNode(SID, "alice", "bobpubkeyhex", "bob-peer-id", "corr");
    const rootBefore = snm.getSessionTreeRootHex("alice", SID);

    const client = await connectToDaemon(join(tempDir, "daemon.sock"));
    try {
      await client.send("ipc.connect", { clientType: "test" });
      await client.send("cello_start_agent", { name: "alice" });
      await client.send("cello_use_agent", { name: "alice" });

      const oversize = "x".repeat(MAX_CONTENT_BYTES + 1);
      const res = await client.send("cello_send", { session_id: SID, content: oversize }) as Record<string, unknown>;

      expect(res.ok).toBe(false);
      expect(res.reason).toBe("content_too_large");
      expect(typeof res.guidance).toBe("string");
      expect((res.guidance as string).length).toBeGreaterThan(0);
    } finally { client.close(); }

    // No content frame was transmitted, and no tree leaf was appended (no desync).
    expect(node.sent.length).toBe(0);
    expect(snm.getSessionTreeRootHex("alice", SID)).toBe(rootBefore);
    expect(snm.getSessionRecord("alice", SID)?.status).toBe("active");
    expect(events.find((e) => e.event === "session.content.sent")).toBeUndefined();

    const rejected = events.find((e) => e.event === "content.rejected.too_large");
    expect(rejected).toBeDefined();
    expect(rejected?.context.sessionId).toBe(SID);
    expect(rejected?.context.contentSize).toBe(MAX_CONTENT_BYTES + 1);
    expect(rejected?.context.cap).toBe(MAX_CONTENT_BYTES);
  });
});
