/**
 * CELLO-M7-DAEMON-001 — Agent loader tests
 *
 * ACs tested:
 * - Loads agent identities from ~/.cello/agents/<name>/key into Registered state
 * - Legacy backwards compat: ~/.cello/key → agent 'default'
 * - Subdirectories without a key file are silently skipped
 * - Malformed key files trigger agent.load.failed
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { loadAgents } from "../agent-loader.js";
import type { Logger } from "../types.js";
import { FileKeyProvider } from "@cello-protocol/crypto";

describe("agent-loader", () => {
  let tempDir: string;
  let logEvents: Array<{ level: string; event: string; context: Record<string, unknown> }>;
  let logger: Logger;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-agent-test-"));
    logEvents = [];
    logger = {
      info(event, context) { logEvents.push({ level: "info", event, context }); },
      warn(event, context) { logEvents.push({ level: "warn", event, context }); },
      error(event, context) { logEvents.push({ level: "error", event, context }); },
    };
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("returns empty array when no agents/ dir and no legacy key", async () => {
    const result = await loadAgents(tempDir, logger);
    expect(result).toEqual([]);
  });

  it("loads legacy ~/.cello/key as agent 'default' when agents/ does not exist", async () => {
    // Create a valid key file using FileKeyProvider (which auto-generates)
    const keyPath = join(tempDir, "key");
    const keyProvider = await FileKeyProvider.load(keyPath);
    const pubkey = await keyProvider.getPublicKey();

    const result = await loadAgents(tempDir, logger);
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe("default");
    expect(result[0].pubkey).toBe(Buffer.from(pubkey).toString("hex"));
  });

  it("loads agents from agents/<name>/key subdirectories", async () => {
    const agentsDir = join(tempDir, "agents");
    await mkdir(join(agentsDir, "alice"), { recursive: true });
    await mkdir(join(agentsDir, "bob"), { recursive: true });

    // Create valid keys
    const aliceKey = await FileKeyProvider.load(join(agentsDir, "alice", "key"));
    await FileKeyProvider.load(join(agentsDir, "bob", "key"));

    const result = await loadAgents(tempDir, logger);
    expect(result).toHaveLength(2);

    const names = result.map((a) => a.name).sort();
    expect(names).toEqual(["alice", "bob"]);

    const alice = result.find((a) => a.name === "alice")!;
    const alicePubkey = await aliceKey.getPublicKey();
    expect(alice.pubkey).toBe(Buffer.from(alicePubkey).toString("hex"));
  });

  it("silently skips directories without a key file", async () => {
    const agentsDir = join(tempDir, "agents");
    await mkdir(join(agentsDir, "no-key-agent"), { recursive: true });
    await mkdir(join(agentsDir, "valid-agent"), { recursive: true });
    await FileKeyProvider.load(join(agentsDir, "valid-agent", "key"));

    const result = await loadAgents(tempDir, logger);
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe("valid-agent");
    // No error logged for the skipped directory
    expect(logEvents.filter((e) => e.event === "agent.load.failed")).toHaveLength(0);
  });

  it("logs agent.load.failed for malformed key files", async () => {
    const agentsDir = join(tempDir, "agents");
    await mkdir(join(agentsDir, "bad-agent"), { recursive: true });
    // Write garbage data as the key file
    await writeFile(join(agentsDir, "bad-agent", "key"), "not a valid key");

    const result = await loadAgents(tempDir, logger);
    expect(result).toHaveLength(0);

    const errorEvents = logEvents.filter((e) => e.event === "agent.load.failed");
    expect(errorEvents).toHaveLength(1);
    expect(errorEvents[0].context.agentName).toBe("bad-agent");
    expect(typeof errorEvents[0].context.error).toBe("string");
  });

  it("prefers agents/ directory over legacy key when both exist", async () => {
    // Create both legacy key and agents directory
    await FileKeyProvider.load(join(tempDir, "key"));
    const agentsDir = join(tempDir, "agents");
    await mkdir(join(agentsDir, "my-agent"), { recursive: true });
    await FileKeyProvider.load(join(agentsDir, "my-agent", "key"));

    const result = await loadAgents(tempDir, logger);
    // Should load from agents/, not the legacy key
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe("my-agent");
  });

  it("skips non-directory entries in agents/", async () => {
    const agentsDir = join(tempDir, "agents");
    await mkdir(agentsDir, { recursive: true });
    // Create a regular file (not a directory) in agents/
    await writeFile(join(agentsDir, "not-a-dir"), "some content");
    await mkdir(join(agentsDir, "real-agent"), { recursive: true });
    await FileKeyProvider.load(join(agentsDir, "real-agent", "key"));

    const result = await loadAgents(tempDir, logger);
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe("real-agent");
  });
});
