/**
 * `DOD-M15-START-AGENT-UNAWAITED-1` — `cello_start_agent` says whether the agent can actually hear.
 *
 * ── THE DEFECT ────────────────────────────────────────────────────────────────────────────────
 *
 * `daemon.ts` fires `void sessionNodeManager.ensureStandingReceiverForAgent(name)` and returns
 * `{ ok: true }` on the next line. The fire-and-forget is DELIBERATE and stays — initiate and accept
 * both ensure on demand, and awaiting it would turn a transient network failure into a failed start.
 *
 * **What was wrong is the CLAIM.** A bare `{ ok: true }` reads as "your agent is running and
 * reachable", and a session landing before the receiver exists is refused
 * `standing_receiver_unavailable` — a precondition on OUR side, surfacing to the operator as though
 * the counterparty or the directory were at fault. `.claude/CLAUDE.md` names that error as the
 * documented first suspect for a daemon whose start never landed, precisely because it is so often
 * read as the far end being broken.
 *
 * ── WHY THIS TEST IS THE ONE THAT MATTERS ─────────────────────────────────────────────────────
 *
 * The whole justification for adding the field rests on ONE claim: **`ready` is genuinely
 * reachable.** A readiness flag computed one line after firing an async ensure would otherwise be
 * `starting` on every call in existence — a field that can never take its other value, which is the
 * same defect as a log line reporting a verdict its producer cannot have (fixed the same day in
 * `session.document.received`). It escapes that only because
 * `ensureStandingReceiverForAgent` is IDEMPOTENT.
 *
 * So the load-bearing assertion here is not "starting is reported". It is that **both states occur
 * on the same daemon, for the same agent, minutes apart in the same test.** If a future change makes
 * `ready` unreachable, the field becomes decoration and this goes red.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { FileKeyProvider } from "@cello-protocol/crypto";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
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
    debug(event, context) { events.push({ level: "debug", event, context }); },
    info(event, context) { events.push({ level: "info", event, context }); },
    warn(event, context) { events.push({ level: "warn", event, context }); },
    error(event, context) { events.push({ level: "error", event, context }); },
  };
  return { logger, events };
}

class FakeNode implements Partial<CelloNode> {
  stopped = false;
  readonly #peerId = `fake-${Math.random().toString(36).slice(2)}`;
  async start(): Promise<void> {}
  async stop(): Promise<void> { this.stopped = true; }
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
    return { send(_d: Uint8Array) {}, async close() {}, abort() {}, status: "open" } as unknown as Stream;
  }
}

class FixedFactory implements ISessionNodeFactory {
  constructor(private node: CelloNode) {}
  async createNode(_c: SessionNodeConfig): Promise<CelloNode> { return this.node; }
}

describe("DOD-M15-START-AGENT-UNAWAITED-1: cello_start_agent reports standing-receiver readiness", () => {
  let tempDir: string;
  let handle: Awaited<ReturnType<typeof startDaemon>> | null;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-startagent-"));
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

  async function start(logger: Logger, node: CelloNode) {
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

  it("★★ BOTH states are reachable — the field is not decoration", async () => {
    const { logger, events } = makeLogger();
    await makeAgentDir("alice");
    const h = await start(logger, new FakeNode());
    const snm = h.getSessionNodeManager();

    const client = await connectToDaemon(join(tempDir, "daemon.sock"));
    try {
      await client.send("ipc.connect", { clientType: "test" });

      // ── (1) THE FIRST START, answered while the ensure is still in flight. ──
      const first = await client.send("cello_start_agent", { name: "alice" }) as Record<string, unknown>;
      expect(first.ok, `start must still succeed: ${JSON.stringify(first)}`).toBe(true);
      expect(
        first.standing_receiver,
        `the first start is answered one line after firing an ASYNC ensure, so the receiver cannot ` +
        `exist yet and the response must say so rather than claiming the agent is reachable. Got: ` +
        `${JSON.stringify(first)}`,
      ).toBe("starting");

      // The affordance, not just the state. An operator who hits the refusal in the next second
      // must be able to tell "this daemon is not ready" from "the counterparty is unreachable" —
      // the whole reason this line exists is that those two are reported identically today.
      expect(typeof first.guidance).toBe("string");
      expect(
        first.guidance as string,
        "the guidance must name the refusal the operator will actually see, or it does not connect " +
        "the answer to the symptom",
      ).toContain("standing_receiver_unavailable");
      expect(
        first.standing_receiver_cause,
        "the cause comes from the same four-way answer the refusal path uses, so the response and " +
        "the eventual error do not describe one state in two vocabularies",
      ).toBeTruthy();

      // ── (2) LET THE ENSURE SETTLE, then start again. ──
      // Polling the PRODUCER rather than sleeping a guessed interval: the question is literally
      // "does this agent have a receiver yet", which is the same thing the handler asks.
      const deadline = Date.now() + 10_000;
      while (snm.getStandingReceiverInfo("alice") === null && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 25));
      }
      expect(
        snm.getStandingReceiverInfo("alice"),
        "the standing receiver never came up, so this test cannot prove the `ready` branch is " +
        "reachable — which is the only thing that makes the field worth having",
      ).not.toBeNull();

      const second = await client.send("cello_start_agent", { name: "alice" }) as Record<string, unknown>;
      expect(second.ok).toBe(true);
      expect(
        second.standing_receiver,
        `★ THE LOAD-BEARING ASSERTION. With the receiver up, the response must say 'ready'. If this ` +
        `ever reports 'starting', the field can never take its other value and is decoration — the ` +
        `exact defect this unit was written against. Got: ${JSON.stringify(second)}`,
      ).toBe("ready");
      // A ready answer carries no guidance: there is nothing to warn about, and a warning that
      // fires on the healthy case is one operators learn to skip.
      expect(second.guidance, "a ready start has nothing to advise").toBeUndefined();

      // ── (3) THE LOG AGREES WITH THE RESPONSE (Invariant 2: loud in the log AND the response). ──
      const online = events.filter((e) => e.event === "agent.online");
      expect(online.length, "agent.online fires on the transition, once").toBeGreaterThanOrEqual(1);
      expect(
        online[0]!.context.standingReceiver,
        "the log must carry the same readiness the response did, or the two accounts of one moment " +
        "disagree and the log is the one nobody can cross-check",
      ).toBe("starting");
    } finally { client.close(); }
  }, 30_000);

  it("an ALREADY-ONLINE agent reports real readiness, not a bare ok", async () => {
    const { logger } = makeLogger();
    await makeAgentDir("alice");
    const h = await start(logger, new FakeNode());
    const snm = h.getSessionNodeManager();

    const client = await connectToDaemon(join(tempDir, "daemon.sock"));
    try {
      await client.send("ipc.connect", { clientType: "test" });
      await client.send("cello_start_agent", { name: "alice" });

      const deadline = Date.now() + 10_000;
      while (snm.getStandingReceiverInfo("alice") === null && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 25));
      }

      /**
       * The idempotent branch returns early, before the ensure is re-fired. It used to answer a bare
       * `{ ok: true }`, which is the most reassuring answer in the run handed out on exactly the call
       * an operator makes when the first one seemed not to work. It must report what is true NOW.
       */
      const again = await client.send("cello_start_agent", { name: "alice" }) as Record<string, unknown>;
      expect(again.ok).toBe(true);
      expect(
        again.standing_receiver,
        `"already online" says this daemon marked the agent online earlier; it says nothing about ` +
        `whether the receiver ever came up. Got: ${JSON.stringify(again)}`,
      ).toBe("ready");
    } finally { client.close(); }
  }, 30_000);
});
