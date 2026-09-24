/**
 * CELLO-M7-DAEMON-001 / PERSIST-002 (AC-007) — Agent loader tests.
 *
 * The loader enumerates agents from the encrypted `agents` table — ONE path, no key files.
 *
 * ACs tested:
 * - Loads agent identities (K_local seed → sign-only InMemoryKeyProvider) from the `agents` table.
 * - Empty table → empty result.
 * - A row with a corrupt seed triggers agent.load.failed and is reported (never silently dropped).
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

/**
 * M9D 002-PQKEYS test 11: the loader must NEVER mint a replacement post-quantum key. The two seed
 * generators are wrapped in spies that PASS THROUGH to the real functions (not stubs), so a loader
 * that fell back to generating a seed would both work and be caught.
 */
vi.mock("@cello-protocol/crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@cello-protocol/crypto")>();
  return {
    ...actual,
    mlDsaGenerateSeed: vi.fn(actual.mlDsaGenerateSeed),
    mlKemGenerateSeed: vi.fn(actual.mlKemGenerateSeed),
  };
});
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { loadAgents } from "../agent-loader.js";
import { DbIdentityStore, ensureIdentitySchema } from "../db-identity-store.js";
import { generateKLocalSeed, InMemoryKeyProvider, mlDsaGenerateSeed, mlKemGenerateSeed, mlKemKeypairFromSeed, mlDsaProviderFromSeed } from "@cello-protocol/crypto";
import { DbRegistrationPersistence } from "../db-identity-store.js";
import { PQ_LOAD_REMEDY } from "../agent-loader.js";
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

  // ─── M9D 002-PQKEYS test 11: a registered agent's post-quantum seeds ─────────────────────────

  /** A REGISTERED row for `name`, with the PQ seeds as given (null = absent). */
  async function registeredRow(name: string, mlDsaSeed: Uint8Array | null, mlKemSeed: Uint8Array | null): Promise<void> {
    const store = new DbIdentityStore(db, logger);
    const seed = generateKLocalSeed();
    store.createAgent(name, seed, Buffer.from(await new InMemoryKeyProvider(seed).getPublicKey()).toString("hex"));
    const p = new DbRegistrationPersistence({ db, agentName: name, logger });
    await p.persistRegistrationState({
      agentId: `id-${name}`, primaryPubkey: "aa".repeat(32), mlDsaPubkey: "bb", mlKemPubkey: "cc",
      registeredAt: 1, keyBinding: "dd".repeat(64), keyBindingPq: "ee".repeat(2420),
    });
    db.prepare("UPDATE agents SET ml_dsa_secret = ?, ml_kem_seed = ? WHERE agent_name = ?")
      .run(mlDsaSeed ? Buffer.from(mlDsaSeed) : null, mlKemSeed ? Buffer.from(mlKemSeed) : null, name);
  }

  const DSA = () => new Uint8Array(32).fill(7);
  const KEM = () => new Uint8Array(64).fill(9);

  it.each([
    ["ml_kem_seed missing", DSA(), null, "ml_kem_seed_missing"],
    ["ml_dsa_seed missing", null, KEM(), "ml_dsa_seed_missing"],
    ["a 2,560-byte (old expanded) ml_dsa_secret", new Uint8Array(2560), KEM(), "ml_dsa_seed_invalid"],
    ["a 63-byte ml_kem_seed", DSA(), new Uint8Array(63), "ml_kem_seed_invalid"],
  ] as const)("a REGISTERED row with %s lands in failed with its reason, and no key is generated", async (_label, dsa, kem, reason) => {
    vi.mocked(mlDsaGenerateSeed).mockClear();
    vi.mocked(mlKemGenerateSeed).mockClear();
    await registeredRow("alice", dsa, kem);

    const result = await loadAgents(db, logger);

    // FIRST: no replacement key was minted — the property decision 8 exists for.
    expect(mlDsaGenerateSeed, "the loader must never mint an ML-DSA seed").not.toHaveBeenCalled();
    expect(mlKemGenerateSeed, "the loader must never mint an ML-KEM seed").not.toHaveBeenCalled();
    expect(result.loaded.map((a) => a.name)).not.toContain("alice");
    expect(result.failed).toEqual([{ name: "alice", error: reason, remedy: PQ_LOAD_REMEDY }]);
    const logged = logEvents.find((e) => e.event === "agent.load.failed");
    expect(logged?.context).toMatchObject({ agentName: "alice", error: reason, remedy: PQ_LOAD_REMEDY });
  });

  it("a REGISTERED row with both seeds loads with the ML-DSA provider for exactly that seed", async () => {
    await registeredRow("alice", DSA(), KEM());
    const result = await loadAgents(db, logger);
    expect(result.failed).toEqual([]);
    const alice = result.loaded.find((a) => a.name === "alice")!;
    expect(Buffer.from(await alice.mlDsaProvider!.getPublicKey()))
      .toEqual(Buffer.from(await (await mlDsaProviderFromSeed(DSA())).getPublicKey()));
    expect(Buffer.from((await mlKemKeypairFromSeed(alice.mlKemSeed!)).publicKey))
      .toEqual(Buffer.from((await mlKemKeypairFromSeed(KEM())).publicKey));
  });

  it("an UNREGISTERED row loads without a PQ identity — registration mints it", async () => {
    const store = new DbIdentityStore(db, logger);
    const seed = generateKLocalSeed();
    store.createAgent("fresh", seed, Buffer.from(await new InMemoryKeyProvider(seed).getPublicKey()).toString("hex"));
    const result = await loadAgents(db, logger);
    expect(result.failed).toEqual([]);
    expect(result.loaded[0]).toMatchObject({ name: "fresh", mlDsaProvider: null, mlKemSeed: null });
  });
});
