/**
 * The attestation and endorsement verbs open their OWN daemon connection. The daemon's current agent
 * is per-connection, so without replaying the `cello use-agent` selection every one of them answered
 * no_current_agent on a machine with more than one agent — `cello use-agent X && cello attestations
 * index` never worked. They now resolve the agent by the same rule as every parity command.
 *
 * Neither agent is online, so the replay's verdict is visible: a replayed selection refuses as
 * selected_agent_offline, and no selection refuses as no_agent_selected. Revert the replay and both
 * read no_current_agent (the daemon's own refusal) — red.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { startDaemon, connectToDaemon, type DaemonHandle } from "@cello-protocol/daemon";
import { PassthroughGatewayClient } from "@cello-protocol/daemon/testing";
import type { Logger, DaemonConfig } from "@cello-protocol/daemon";
import { attestations, endorsements } from "../commands.js";

describe("attestation verbs replay the `use-agent` selection", () => {
  let tempDir: string;
  let handle: DaemonHandle | null;
  const logger: Logger = { debug() {}, info() {}, warn() {}, error() {} };

  beforeEach(async () => {
    process.env["CELLO_ENV"] = "test";
    tempDir = await mkdtemp(join(tmpdir(), "cello-att-replay-"));
    handle = null;
    const config: DaemonConfig = {
      securityGateway: new PassthroughGatewayClient(),
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
      await client.send("cello_create_agent", { name: "alice" });
      await client.send("cello_create_agent", { name: "bob" });
    } finally {
      client.close();
    }
  });

  afterEach(async () => {
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* stopped */ } }
    await rm(tempDir, { recursive: true, force: true });
    delete process.env["CELLO_ENV"];
  });

  it("a persisted selection is replayed — the refusal names THAT agent, not the daemon's no_current_agent", async () => {
    await writeFile(join(tempDir, "current-agent"), "alice\n", "utf8");
    for (const res of [await attestations(tempDir, "index", []), await attestations(tempDir, "rights", [])]) {
      expect(res.exitCode).toBe(1);
      expect(res.output).toContain("selected_agent_offline");
      expect(res.output).toContain("alice");
      expect(res.output).not.toContain("no_current_agent");
    }
  });

  it("no selection with two agents refuses as no_agent_selected — the same rule as every parity command", async () => {
    const res = await attestations(tempDir, "index", []);
    expect(res.exitCode).toBe(1);
    expect(res.output).toContain("no_agent_selected");
  });

  it("the endorsement outcome sweep replays it too", async () => {
    await writeFile(join(tempDir, "current-agent"), "alice\n", "utf8");
    const res = await endorsements(tempDir, "issued", []);
    expect(res.output).toContain("selected_agent_offline");
  });
});
