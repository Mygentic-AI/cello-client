/**
 * CELLO-M8C — DOD-AGENT-PARAM-1, the producer half.
 *
 * The story's AC-B3 claimed the CLI never sends the agent selector over IPC ("it carries the agent
 * selection via its use-agent replay, not as an IPC param"). That is true of the 18 commands that go
 * through withDaemon — and FALSE of these two, which take the agent as a REQUIRED POSITIONAL and send
 * it themselves:
 *
 *   cello refresh <name>          → cello_refresh_shares      { name }
 *   cello relay-receipts <name>   → cello_get_relay_receipts  { name }
 *
 * Renaming the daemon's selector without them would not fail loudly. The daemon would read no
 * selector, fall through to the connection's current agent / the sole online agent, and rotate FROST
 * shares for whoever happened to be up — `cello refresh alice` acting on bob, exit 0. A silent
 * misroute on key material.
 *
 * Two agents are loaded and NEITHER is online, so there is no fallback to mask a dropped selector:
 * if the producer sends the dead spelling, the daemon answers no_current_agent and both assertions
 * below fail.
 *
 * REVERT TEST, stated plainly: this file is GREEN before the change too, because today's producer
 * and consumer agree on the dead word. What it pins is the AGREEMENT — revert either half alone
 * (rename the daemon and leave the CLI, or the reverse) and it goes red. That is the failure the
 * story would otherwise have shipped, so that is what it guards.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { startDaemon, connectToDaemon, type DaemonHandle } from "@cello-protocol/daemon";
import type { Logger, DaemonConfig } from "@cello-protocol/daemon";
import { refreshShares, relayReceipts } from "../commands.js";

describe("DOD-AGENT-PARAM-1: the CLI sends the selector the daemon actually reads", () => {
  let tempDir: string;
  let logger: Logger;
  let handle: DaemonHandle | null;

  beforeEach(async () => {
    process.env["CELLO_ENV"] = "test";
    tempDir = await mkdtemp(join(tmpdir(), "cello-agentparam-cli-"));
    logger = { debug() {}, info() {}, warn() {}, error() {} };
    handle = null;
  });

  afterEach(async () => {
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* stopped */ } }
    await rm(tempDir, { recursive: true, force: true });
    delete process.env["CELLO_ENV"];
  });

  async function startWithTwoAgents(): Promise<void> {
    const config: DaemonConfig = {
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger,
    };
    handle = await startDaemon(config);
    const client = await connectToDaemon(config.socketPath);
    try {
      await client.send("ipc.connect", { clientType: "cli" });
      // Created, therefore loaded — but not started, so neither is online.
      await client.send("cello_create_agent", { name: "alice" });
      await client.send("cello_create_agent", { name: "bob" });
    } finally {
      client.close();
    }
  }

  it("`cello relay-receipts alice` reaches ALICE — not the daemon's fallback guess", async () => {
    await startWithTwoAgents();
    const result = await relayReceipts(tempDir, "alice");
    const payload = JSON.parse(result.output) as { ok: boolean; reason?: string; receipts?: unknown[] };
    expect(payload.reason).not.toBe("no_current_agent");
    expect(payload.ok).toBe(true);
    expect(payload.receipts).toEqual([]);
    expect(result.exitCode).toBe(0);
  });

  it("`cello refresh <name>` names the agent it was given — a typo is a typo, not a misroute", async () => {
    await startWithTwoAgents();
    // A name nobody holds: the daemon must refuse THAT name. If the selector were dropped, the
    // refusal would be no_current_agent instead — and with one agent online it would not refuse at
    // all, it would refresh the wrong agent's shares.
    const result = await refreshShares(tempDir, "ghost");
    const payload = JSON.parse(result.output) as { ok: boolean; reason?: string; guidance?: string };
    expect(payload.reason).toBe("agent_not_found");
    expect(payload.guidance).toContain("ghost");
    expect(result.exitCode).toBe(1);
  });
});
