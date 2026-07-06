/**
 * CELLO-M8C-LOGINSTART-1 CORE — cello login auto-starts all registered agents
 *
 * Tests the extracted autoStartAllAgents helper (what `cello login` calls) against a real
 * in-process daemon, so the login-command orchestration is proven without spawning the binary.
 *
 * Clause coverage (M8C-BUILD-JOURNAL Entry 18):
 * - L1: every loaded agent is brought online.
 * - L2: login always completes; failures are collected, not thrown; zero-agents is clean.
 * - L3: idempotent — a second pass is a no-op (already-online agents don't fail).
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { startDaemon, connectToDaemon, acquireLock, type DaemonHandle, type DaemonConfig, type Logger, type IpcClient } from "@cello-protocol/daemon";
import { autoStartAllAgents, formatLoginSummary, login } from "../commands.js";

describe("M8C-LOGINSTART-1 CORE: autoStartAllAgents", () => {
  let tempDir: string;
  let logger: Logger;
  let handle: DaemonHandle | null;
  let client: IpcClient | null;

  beforeEach(async () => {
    process.env["CELLO_ENV"] = "test";
    tempDir = await mkdtemp(join(tmpdir(), "cello-loginstart-"));
    logger = { debug() {}, info() {}, warn() {}, error() {} };
    handle = null;
    client = null;
  });

  afterEach(async () => {
    try { client?.close(); } catch { /* closed */ }
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* stopped */ } }
    await rm(tempDir, { recursive: true, force: true });
    delete process.env["CELLO_ENV"];
  });

  function makeConfig(): DaemonConfig {
    return {
      celloDir: tempDir, socketPath: join(tempDir, "daemon.sock"), lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16, version: "0.0.1-test", logger,
    };
  }

  it("L1/L2/L3: brings every loaded agent online (and is idempotent on a second pass)", async () => {
    const config = makeConfig();
    handle = await startDaemon(config);
    client = await connectToDaemon(config.socketPath);
    await client.send("ipc.connect", { clientType: "cli" });
    await client.send("cello_create_agent", { name: "alice" });
    await client.send("cello_create_agent", { name: "bob" });

    const res = await autoStartAllAgents(client);
    expect(res.started.slice().sort()).toEqual(["alice", "bob"]);
    expect(res.failed).toEqual([]);

    const status = (await client.send("cello_status")) as { agents: Array<{ name: string; state: string }> };
    expect(status.agents.filter((a) => a.state === "online").map((a) => a.name).sort()).toEqual(["alice", "bob"]);

    // L3: idempotent — a second login pass starts the (already-online) agents again with no failures.
    const again = await autoStartAllAgents(client);
    expect(again.failed).toEqual([]);
    expect(again.started.slice().sort()).toEqual(["alice", "bob"]);
  });

  // A minimal IpcClient stub so we can FORCE per-agent start outcomes (a {ok:false} and a throw) —
  // the failure-enumeration path the DoD exists for, which a real daemon rarely produces.
  function stubClient(starts: Record<string, { ok: boolean; reason?: string } | Error>): IpcClient {
    return {
      async send(method: string, params?: { name?: string }) {
        if (method === "cello_list_agents") return { agents: Object.keys(starts).map((name) => ({ name })) };
        if (method === "cello_start_agent") {
          const r = starts[params!.name!];
          if (r instanceof Error) throw r;
          return r;
        }
        return {};
      },
      onNotification() { /* unused */ },
      close() { /* unused */ },
    } as unknown as IpcClient;
  }

  // F1 (reviewer, blocking): the failure-enumeration path — collected, not thrown; one bad agent
  // does not abort the loop; each failure carries {name, reason} (from {ok:false}.reason AND a throw).
  it("L2 failure path: collects per-agent failures by {name, reason} without aborting the loop", async () => {
    const client = stubClient({
      alice: { ok: true },
      bob: { ok: false, reason: "boom" },
      carol: new Error("Connection closed"),
    });
    const { started, failed } = await autoStartAllAgents(client);
    expect(started).toEqual(["alice"]); // the good agent still started despite two failures
    expect(failed).toEqual([
      { name: "bob", reason: "boom" },
      { name: "carol", reason: "Connection closed" },
    ]);
  });

  it("L2 enumeration: formatLoginSummary names each failed agent + reason", () => {
    const s = formatLoginSummary({ started: ["alice"], failed: [{ name: "bob", reason: "boom" }] });
    expect(s).toContain("Started 1 agent(s): alice.");
    expect(s).toContain("bob (boom)"); // the enumeration the operator sees
    expect(formatLoginSummary({ started: [], failed: [] })).toContain("No registered agents");
  });

  // F2 (reviewer): the login() boundary — exit 0 with the summary appended, against a REAL in-process
  // daemon (acquireLock points connectOrStart at it, so it CONNECTS instead of spawning the binary).
  it("F2: login() returns exit 0 and appends the auto-start summary", async () => {
    const config = makeConfig();
    handle = await startDaemon(config);
    await acquireLock(config.lockFilePath, { pid: process.pid, socketPath: config.socketPath, version: "0.0.1-test" });
    const seed = await connectToDaemon(config.socketPath);
    await seed.send("ipc.connect", { clientType: "cli" });
    await seed.send("cello_create_agent", { name: "alice" });
    seed.close();

    const res = await login(config.celloDir, "/nonexistent-daemon-bin", logger);
    expect(res.exitCode).toBe(0);
    expect(res.output.startsWith("Daemon already running.")).toBe(true);
    expect(res.output).toContain("Started 1 agent(s): alice.");
  });

  it("L2: zero registered agents → completes cleanly (empty summary, no throw)", async () => {
    const config = makeConfig();
    handle = await startDaemon(config);
    client = await connectToDaemon(config.socketPath);
    await client.send("ipc.connect", { clientType: "cli" });

    const res = await autoStartAllAgents(client);
    expect(res.started).toEqual([]);
    expect(res.failed).toEqual([]);
  });
});
