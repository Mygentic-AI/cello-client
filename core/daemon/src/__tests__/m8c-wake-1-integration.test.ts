/**
 * CELLO-M8C-WAKE-1 — channel stage 1 integration (real daemon + real shim over stdio)
 *
 * The faithful enforcer for the daemon→shim→MCP-client hop that SPIKE-1 de-risked. Spawns the
 * REAL shim binary (core/adapter-claude-code/src/bin/cello-mcp.ts, via tsx from source so it does
 * not depend on a prior build) as a stdio subprocess, speaks raw MCP JSON-RPC to it, triggers a
 * real daemon notification dispatch, and asserts the shim emits a `notifications/claude/channel`
 * event on its stdout.
 *
 * Clause coverage (M8C-BUILD-JOURNAL Entry 5):
 * - C1: the shim's `initialize` response advertises the `claude/channel` capability.
 * - C3/C4: session_state_changed (and agent_state/current_changed) surface as
 *   `notifications/claude/channel` with the content-free daemon `data` blob as params.
 * - C7: a `sealed`-state session_state_changed forwards gracefully (state-agnostic bridge).
 * - INV-CONTENTFREE: forwarded params carry no message content.
 *
 * The in-context hop (the event appearing inside a live `claude --channels` chat) is Anthropic's
 * channel feature and is proven at LIVE-1, not here.
 */

import { describe, it, expect, beforeAll, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn, execSync, type ChildProcess } from "node:child_process";
import { PassthroughGatewayClient } from "@cello-protocol/gateway";
import { startDaemon, type DaemonHandle } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import { FileKeyProvider } from "@cello-protocol/crypto";
import type { Logger, DaemonConfig } from "../types.js";

// Workspace-root-relative paths (this file is core/daemon/src/__tests__/). Spawn the BUILT shim
// with plain `node` (fast, deterministic) rather than tsx-from-source — tsx cold-compiles the shim
// + its imports on every spawn, which on a loaded CI runner raced past the 30s test timeout and
// hung the initialize handshake. CI builds before test; locally we build-if-missing in beforeAll.
const ROOT = join(import.meta.dirname, "..", "..", "..", "..");
const SHIM_BUILT = join(ROOT, "core", "adapter-claude-code", "dist", "bin", "cello-mcp.js");

describe("M8C-WAKE-1: real daemon → real shim → notifications/claude/channel", () => {
  let tempDir: string;
  let handle: DaemonHandle | null;
  let shim: ChildProcess | null;
  let trigger: IpcClient | null;
  let logger: Logger;

  beforeAll(() => {
    // Ensure the spawned dist shim reflects CURRENT source: incremental `tsc --build` is a fast
    // no-op when up-to-date and rebuilds if the shim source changed (the local `pnpm test` gate runs
    // BEFORE the build step, so the dist could otherwise be stale; CI builds first, so it's a no-op).
    execSync("pnpm --filter @cello-protocol/connect exec tsc --build", { cwd: ROOT, stdio: "ignore" });
    if (!existsSync(SHIM_BUILT)) throw new Error(`shim build did not produce ${SHIM_BUILT}`);
  }, 180_000);

  beforeEach(async () => {
    process.env["CELLO_ENV"] = "test";
    tempDir = await mkdtemp(join(tmpdir(), "cello-wake1-int-"));
    handle = null;
    shim = null;
    trigger = null;
    logger = {
      debug() {}, info() {}, warn() {}, error() {},
    };
  });

  afterEach(async () => {
    try { trigger?.close(); } catch { /* already closed */ }
    try { shim?.kill(); } catch { /* already dead */ }
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* already stopped */ } }
    await rm(tempDir, { recursive: true, force: true });
    delete process.env["CELLO_ENV"];
  });

  it("forwards session_state_changed (created + sealed) as content-free claude/channel events", async () => {
    // ─── real daemon ───
    const config: DaemonConfig = {
    securityGateway: new PassthroughGatewayClient(),
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.57",
      logger,
    };
    const aliceDir = join(tempDir, "agents", "alice");
    await mkdir(aliceDir, { recursive: true });
    await FileKeyProvider.load(join(aliceDir, "key"));
    handle = await startDaemon(config);

    // ─── real shim binary over stdio (built dist, plain node) ───
    shim = spawn(process.execPath, [SHIM_BUILT], {
      env: { ...process.env, CELLO_DIR: tempDir },
      stdio: ["pipe", "pipe", "pipe"],
    });

    const channelEvents: Array<Record<string, unknown>> = [];
    const stderrEvents: Array<Record<string, unknown>> = [];
    let initializeResult: Record<string, unknown> | null = null;
    let stdoutBuf = "";
    let stderrRaw = ""; // full stderr, so a startup failure surfaces instead of a silent hang
    const pending = new Map<number, (msg: Record<string, unknown>) => void>();

    // C6 observability: the shim writes domain.noun.verb events (JSON) to its stderr tee.
    let stderrBuf = "";
    shim.stderr!.on("data", (chunk: Buffer) => {
      stderrRaw += chunk.toString("utf-8");
      stderrBuf += chunk.toString("utf-8");
      let nl: number;
      while ((nl = stderrBuf.indexOf("\n")) !== -1) {
        const line = stderrBuf.slice(0, nl);
        stderrBuf = stderrBuf.slice(nl + 1);
        if (!line.trim()) continue;
        try {
          const ev = JSON.parse(line) as Record<string, unknown>;
          if (typeof ev["event"] === "string") stderrEvents.push(ev);
        } catch { /* non-JSON diagnostic line */ }
      }
    });

    shim.stdout!.on("data", (chunk: Buffer) => {
      stdoutBuf += chunk.toString("utf-8");
      let nl: number;
      while ((nl = stdoutBuf.indexOf("\n")) !== -1) {
        const line = stdoutBuf.slice(0, nl);
        stdoutBuf = stdoutBuf.slice(nl + 1);
        if (!line.trim()) continue;
        let msg: Record<string, unknown>;
        try { msg = JSON.parse(line) as Record<string, unknown>; } catch { continue; }
        if (msg["method"] === "notifications/claude/channel") {
          channelEvents.push(msg);
        } else if (typeof msg["id"] === "number" && pending.has(msg["id"] as number)) {
          pending.get(msg["id"] as number)!(msg);
          pending.delete(msg["id"] as number);
        }
      }
    });

    const send = (obj: Record<string, unknown>) => shim!.stdin!.write(JSON.stringify(obj) + "\n");
    // Per-request timeout: if the shim never answers (e.g. it crashed on startup), fail FAST with
    // its captured stderr rather than hanging to the whole-test timeout with no diagnostics.
    const request = (obj: Record<string, unknown>) =>
      new Promise<Record<string, unknown>>((resolve, reject) => {
        const id = obj["id"] as number;
        const timer = setTimeout(() => {
          pending.delete(id);
          reject(new Error(`shim did not answer request id=${id} within 15s. shim stderr:\n${stderrRaw || "(empty)"}`));
        }, 15_000);
        pending.set(id, (msg) => { clearTimeout(timer); resolve(msg); });
        send(obj);
      });
    const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

    // ─── raw MCP handshake ───
    initializeResult = await request({
      jsonrpc: "2.0", id: 1, method: "initialize",
      params: {
        protocolVersion: "2024-11-05",
        capabilities: { experimental: { "claude/channel": {} } },
        clientInfo: { name: "wake1-int", version: "0.0.0" },
      },
    });
    send({ jsonrpc: "2.0", method: "notifications/initialized" });
    await sleep(150);

    // C1: capability advertised
    const caps = (initializeResult["result"] as Record<string, unknown>)["capabilities"] as Record<string, unknown>;
    const experimental = caps["experimental"] as Record<string, unknown> | undefined;
    expect(experimental?.["claude/channel"]).toBeDefined();

    // bring alice online + current on the shim's connection
    await request({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "cello_start_agent", arguments: { name: "alice" } } });
    await request({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "cello_use_agent", arguments: { name: "alice" } } });
    await sleep(150);

    // ─── trigger real dispatches from a SECOND ipc client ───
    trigger = await connectToDaemon(config.socketPath);
    await trigger.send("ipc.connect", { clientType: "cli" });
    await trigger.send("__test_emit_session_event", {
      type: "created", sessionId: "wake1-sess", agentName: "alice", counterpartyPubkey: "deadbeef", sessionPeerId: "peer-1", correlationId: "corr-1",
    });
    await trigger.send("__test_emit_session_event", {
      type: "destroyed", state: "sealed", sessionId: "wake1-sess", agentName: "alice", counterpartyPubkey: "deadbeef", reason: "sealed", correlationId: "corr-2",
    });
    await sleep(500);

    // C3 (no per-type allowlist): THREE distinct daemon notification types must surface through
    // the same generic bridge — session_state_changed (created + sealed) AND the two agent-level
    // types already triggered above (cello_start_agent → agent_state_changed; cello_use_agent →
    // agent_current_changed). A bridge that special-cased only session_state_changed would pass
    // the session assertions but fail these — that is the T1 bypass this guards against.
    // `type` now rides in params.meta (Claude Code channel contract), not at the params top level.
    const typeOf = (e: Record<string, unknown>) =>
      ((e["params"] as { meta?: Record<string, unknown> })?.meta)?.["type"];
    expect(channelEvents.some((e) => typeOf(e) === "agent_state_changed")).toBe(true);
    expect(channelEvents.some((e) => typeOf(e) === "agent_current_changed")).toBe(true);

    // C3/C4: the session_state_changed frames surfaced as claude/channel events
    const sessionEvents = channelEvents.filter((e) => typeOf(e) === "session_state_changed");
    expect(sessionEvents.length).toBeGreaterThanOrEqual(2);

    const params = sessionEvents.map((e) => e["params"] as { content?: unknown; meta?: Record<string, unknown> });
    // Routing now rides in `meta` (Claude Code channel contract), not at the params top level.
    const created = params.find((p) => p.meta?.["state"] === "created");
    const sealed = params.find((p) => p.meta?.["state"] === "sealed"); // C7: sealed forwards too
    expect(created).toBeDefined();
    expect(sealed).toBeDefined();
    expect(created!.meta?.["agent"]).toBe("alice");
    expect(created!.meta?.["sessionId"]).toBe("wake1-sess");

    // Claude Code channel contract: every event MUST carry a `content` string (the <channel> tag
    // body) or Claude Code silently drops it — the root cause of the DOD-LIVE-1 doorbell failure
    // (BUILD-JOURNAL Entry 43). content here is a synthesized, content-free announcement.
    for (const p of params) {
      expect(typeof p.content).toBe("string");
      expect((p.content as string).length).toBeGreaterThan(0);
    }
    // INV-CONTENTFREE: no MESSAGE content anywhere — not in the announcement body, not in meta.
    for (const p of params) {
      expect(p.meta).not.toHaveProperty("message");
      expect(p.meta).not.toHaveProperty("text");
      expect(p.meta).not.toHaveProperty("content");
    }

    // C6: the forward emits a domain.noun.verb observability event
    const forwarded = stderrEvents.filter((e) => e["event"] === "notification.channel.forwarded");
    expect(forwarded.length).toBeGreaterThanOrEqual(2);
    expect(forwarded.some((e) => e["type"] === "session_state_changed" && e["agent"] === "alice")).toBe(true);
  }, 60000);
});
