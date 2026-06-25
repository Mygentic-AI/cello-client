/**
 * CELLO-M7-DAEMON-001 / PERSIST-002 (AC-007) — Agent loader tests.
 *
 * The loader now enumerates agents from the encrypted `agents` table — ONE path. The legacy
 * `~/.cello/key` "default" fallback and the per-agent `agents/<name>/key` file read are gone (a
 * pre-story key file is imported into the table by identity-migration.ts before the loader runs).
 *
 * ACs tested:
 * - Loads agent identities (K_local seed → sign-only InMemoryKeyProvider) from the `agents` table.
 * - Empty table → empty result.
 * - A row with a corrupt seed triggers agent.load.failed and is reported (never silently dropped).
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { loadAgents } from "../agent-loader.js";
import { DbIdentityStore, ensureIdentitySchema } from "../db-identity-store.js";
import { generateKLocalSeed, InMemoryKeyProvider } from "@cello-protocol/crypto";
import { openTestDb } from "./helpers/encrypted-db.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";
import type { Logger } from "../types.js";

describe("agent-loader (PERSIST-002 — DB-backed)", () => {
  let tempDir: string;
  let dbPath: string;
  let db: DaemonDatabase;
  let logEvents: Array<{ level: string; event: string; context: Record<string, unknown> }>;
  let logger: Logger;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-agent-test-"));
    dbPath = join(tempDir, "sessions.db");
    db = openTestDb(dbPath);
    logEvents = [];
    logger = {
      debug(event, context) { logEvents.push({ level: "debug", event, context: context ?? {} }); },
      info(event, context) { logEvents.push({ level: "info", event, context: context ?? {} }); },
      warn(event, context) { logEvents.push({ level: "warn", event, context: context ?? {} }); },
      error(event, context) { logEvents.push({ level: "error", event, context: context ?? {} }); },
    };
  });

  afterEach(async () => {
    db.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  it("returns an empty result when the agents table is empty", async () => {
    const result = await loadAgents(db, logger);
    expect(result.loaded).toEqual([]);
    expect(result.failed).toEqual([]);
  });

  it("loads agents from the agents table with the correct pubkey", async () => {
    const store = new DbIdentityStore(db, logger);
    const aliceSeed = generateKLocalSeed();
    const alicePub = Buffer.from(await new InMemoryKeyProvider(aliceSeed).getPublicKey()).toString("hex");
    store.createAgent("alice", aliceSeed, alicePub);
    const bobSeed = generateKLocalSeed();
    const bobPub = Buffer.from(await new InMemoryKeyProvider(bobSeed).getPublicKey()).toString("hex");
    store.createAgent("bob", bobSeed, bobPub);

    const result = await loadAgents(db, logger);
    expect(result.failed).toEqual([]);
    expect(result.loaded.map((a) => a.name).sort()).toEqual(["alice", "bob"]);
    const alice = result.loaded.find((a) => a.name === "alice")!;
    expect(alice.pubkey).toBe(alicePub);
    // The loaded provider signs (sign-only K_local reconstructed from the DB seed).
    const sig = await alice.keyProvider.sign(new TextEncoder().encode("x"));
    expect(sig.length).toBe(64);
  });

  it("reports a corrupt-seed row as failed (never silently dropped)", async () => {
    // Insert a row with a too-short seed directly (bypassing createAgent's generation).
    ensureIdentitySchema(db);
    const now = Date.now();
    db.prepare(
      `INSERT INTO agents (agent_name, k_local_seed, k_local_pubkey, state, created_at, updated_at)
       VALUES (?, ?, ?, 'created', ?, ?)`,
    ).run("broken", Buffer.alloc(8), "nopub", now, now);

    const result = await loadAgents(db, logger);
    expect(result.loaded).toEqual([]);
    expect(result.failed.map((f) => f.name)).toEqual(["broken"]);
    expect(logEvents.some((e) => e.event === "agent.load.failed" && e.context.agentName === "broken")).toBe(true);
  });
});
