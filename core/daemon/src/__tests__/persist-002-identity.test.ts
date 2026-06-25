/**
 * CELLO-M7-PERSIST-002 — Unit 2: the `agents` table + DB-backed identity persistence.
 *
 * Specification (SPARC Phase S):
 *   AC-002  A registered agent's K_local seed, FROST share, ML-DSA keypair, registration state, and
 *           agent↔user link exist ONLY as columns of an `agents` row — never as flat files. (This
 *           file proves the DB side: every item round-trips through the row. File-absence is asserted
 *           by the wiring + write-allow-list units.)
 *   AC-003/AC-005/SI-003  The FROST share reloads from the encrypted row byte-for-byte after a fresh
 *           open of the same DB — the durable-commit guarantee a register-success implies.
 *   SI-001  Secrets (K_local seed, ML-DSA secret, FROST signing share) live as BLOBs in the encrypted
 *           DB; the round-trip preserves the exact bytes.
 *   AC-012  A persist against a non-existent agent fails loud (identity_persist_failed), never a
 *           silent no-op.
 *
 * The store is exercised against a REAL SQLCipher DB (via the keyed test helper) so the BLOB columns
 * are proven under whole-DB encryption, and a reopen proves durability across handles.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";
import type { Logger } from "../types.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";
import { DbIdentityStore, DbRegistrationPersistence, ensureIdentitySchema } from "../db-identity-store.js";
import { InMemoryKeyProvider } from "@cello-protocol/crypto";
import { openTestDb } from "./helpers/encrypted-db.js";

function makeLogger(): { logger: Logger; events: Array<{ level: string; event: string; ctx: Record<string, unknown> }> } {
  const events: Array<{ level: string; event: string; ctx: Record<string, unknown> }> = [];
  const logger: Logger = {
    debug(event, ctx) { events.push({ level: "debug", event, ctx: ctx ?? {} }); },
    info(event, ctx) { events.push({ level: "info", event, ctx: ctx ?? {} }); },
    warn(event, ctx) { events.push({ level: "warn", event, ctx: ctx ?? {} }); },
    error(event, ctx) { events.push({ level: "error", event, ctx: ctx ?? {} }); },
  };
  return { logger, events };
}

let tempDir = "";
let dbPath = "";
beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "persist002-id-"));
  dbPath = join(tempDir, "sessions.db");
});
afterEach(async () => {
  await rm(tempDir, { recursive: true, force: true });
});

/** Open a fresh keyed DB handle for the test path (real SQLCipher). */
function open(): DaemonDatabase {
  return openTestDb(dbPath);
}

const SEED = (n: number): Uint8Array => new Uint8Array(randomBytes(32).map((_b, i) => (i + n) & 0xff));

describe("PERSIST-002 Unit 2 — DbIdentityStore (AC-002/AC-004)", () => {
  it("createAgent inserts a 'created' row with the K_local seed; listAgents and hasAgent reflect it", async () => {
    const db = open();
    const { logger, events } = makeLogger();
    const store = new DbIdentityStore(db, logger);

    const seed = SEED(1);
    const realPub = Buffer.from(await new InMemoryKeyProvider(seed).getPublicKey()).toString("hex");
    expect(store.hasAgent("alice")).toBe(false);
    store.createAgent("alice", seed, realPub);
    expect(store.hasAgent("alice")).toBe(true);

    const agents = store.listAgents();
    expect(agents).toHaveLength(1);
    expect(agents[0]!.agentName).toBe("alice");
    expect(agents[0]!.state).toBe("created");
    expect(agents[0]!.kLocalPubkey).toBe(realPub);
    // SI-001: the seed round-trips byte-for-byte from the encrypted BLOB column, and re-derives the pubkey.
    expect(Buffer.from(agents[0]!.kLocalSeed).equals(Buffer.from(seed))).toBe(true);
    expect(Buffer.from(await new InMemoryKeyProvider(agents[0]!.kLocalSeed).getPublicKey()).toString("hex")).toBe(realPub);

    // persist.identity.created fires with the agent name + PUBLIC key only — never the seed.
    const created = events.find((e) => e.event === "persist.identity.created");
    expect(created).toBeDefined();
    expect(created!.ctx).toMatchObject({ agentName: "alice", agentPubkey: realPub });
    expect(JSON.stringify(created!.ctx)).not.toContain(Buffer.from(seed).toString("hex"));
  });

  it("createAgent refuses to overwrite an existing identity", () => {
    const store = new DbIdentityStore(open(), makeLogger().logger);
    store.createAgent("alice", SEED(1), "pub1");
    expect(() => store.createAgent("alice", SEED(2), "pub2")).toThrow(/already exists/);
    // The original seed/pubkey are untouched.
    expect(store.listAgents()[0]!.kLocalPubkey).toBe("pub1");
  });

  it("the seed durably reloads from a SECOND handle on the same encrypted DB", () => {
    const seed = SEED(9);
    new DbIdentityStore(open(), makeLogger().logger).createAgent("alice", seed, "pub");
    // Fresh handle — proves the row is committed to the encrypted file, not just in a cache.
    const reopened = new DbIdentityStore(open(), makeLogger().logger).listAgents();
    expect(reopened).toHaveLength(1);
    expect(Buffer.from(reopened[0]!.kLocalSeed).equals(Buffer.from(seed))).toBe(true);
  });
});

describe("PERSIST-002 Unit 2 — DbRegistrationPersistence (AC-002/AC-003/AC-005, SI-001/SI-003, AC-012)", () => {
  function seededStore(db: DaemonDatabase, logger: Logger): DbRegistrationPersistence {
    new DbIdentityStore(db, logger).createAgent("alice", SEED(3), "alicepub");
    return new DbRegistrationPersistence({ db, agentName: "alice", logger });
  }

  it("loads return null on a freshly-created (unregistered) agent", async () => {
    const db = open();
    const p = seededStore(db, makeLogger().logger);
    expect(await p.loadMlDsaKeypair()).toBeNull();
    expect(await p.loadActiveFrostKeyShare()).toBeNull();
    expect(await p.loadRegistrationState()).toBeNull();
    expect(await p.loadAgentUserLink()).toBeNull();
  });

  it("persists + reloads the full identity bundle byte-for-byte, and flips state to 'registered'", async () => {
    const db = open();
    const { logger } = makeLogger();
    const p = seededStore(db, logger);

    const mlSecret = SEED(11);
    const signingShare = SEED(22);
    const commitments = SEED(33);
    const verifying = SEED(44);

    await p.persistMlDsaKeypair({ mlDsaPubkey: "mldsapub", secretKeyBlob: mlSecret });
    await p.persistFrostKeyShare({
      epochId: "epoch-1",
      primaryPubkey: "primarypub",
      identifier: "id-1",
      signingShare,
      threshold: 2,
      participants: 3,
      commitmentsCbor: commitments,
      verifyingSharesCbor: verifying,
      dkgMethod: "network_dkg",
    });
    await p.persistRegistrationState({
      agentId: "agent-1",
      primaryPubkey: "primarypub",
      mlDsaPubkey: "mldsapub",
      registeredAt: 1234,
    });
    await p.persistAgentUserLink({ agentId: "agent-1", preAuthToken: "tok-abc", linkedAt: 5678 });

    // Reopen the DB on a fresh handle to prove durable commit (AC-005/SI-003 — the share survives a
    // process boundary, not just an in-memory cache).
    const p2 = new DbRegistrationPersistence({ db: open(), agentName: "alice", logger });

    const ml = await p2.loadMlDsaKeypair();
    expect(ml).not.toBeNull();
    expect(Buffer.from(ml!.secretKeyBlob).equals(Buffer.from(mlSecret))).toBe(true);
    expect(ml!.mlDsaPubkey).toBe("mldsapub");
    expect(ml!.algorithm).toBe("ML-DSA-44");

    const share = await p2.loadActiveFrostKeyShare();
    expect(share).not.toBeNull();
    expect(Buffer.from(share!.signingShare).equals(Buffer.from(signingShare))).toBe(true);
    expect(Buffer.from(share!.commitmentsCbor).equals(Buffer.from(commitments))).toBe(true);
    expect(Buffer.from(share!.verifyingSharesCbor).equals(Buffer.from(verifying))).toBe(true);
    expect(share!.epochId).toBe("epoch-1");
    expect(share!.identifier).toBe("id-1");
    expect(share!.threshold).toBe(2);
    expect(share!.participants).toBe(3);
    expect(share!.dkgMethod).toBe("network_dkg");

    const reg = await p2.loadRegistrationState();
    expect(reg).toMatchObject({ agentId: "agent-1", primaryPubkey: "primarypub", mlDsaPubkey: "mldsapub", registeredAt: 1234, status: "active" });

    const link = await p2.loadAgentUserLink();
    expect(link).toMatchObject({ agentId: "agent-1", preAuthToken: "tok-abc", linkedAt: 5678 });

    // state flipped to 'registered' by the registration-state persist.
    expect(new DbIdentityStore(open(), logger).listAgents()[0]!.state).toBe("registered");
  });

  it("AC-012/SI-003: a persist against a non-existent agent throws identity_persist_failed (never a silent no-op)", async () => {
    const db = open();
    ensureIdentitySchema(db); // table exists but no 'ghost' row
    const p = new DbRegistrationPersistence({ db, agentName: "ghost", logger: makeLogger().logger });
    await expect(
      p.persistFrostKeyShare({
        epochId: "e",
        primaryPubkey: "pp",
        identifier: "i",
        signingShare: SEED(1),
        threshold: 1,
        participants: 1,
        commitmentsCbor: SEED(2),
        verifyingSharesCbor: SEED(3),
        dkgMethod: "trusted_dealer",
      }),
    ).rejects.toThrow(/identity_persist_failed/);
    // Teeth: the share was NOT written somewhere else — no row exists for the ghost.
    expect(new DbIdentityStore(db, makeLogger().logger).hasAgent("ghost")).toBe(false);
  });

  it("SI-001: no secret (seed/share/ml-dsa secret) appears in any emitted log event", async () => {
    const db = open();
    const { logger, events } = makeLogger();
    const p = seededStore(db, logger);
    const signingShare = SEED(77);
    const mlSecret = SEED(88);
    await p.persistMlDsaKeypair({ mlDsaPubkey: "mp", secretKeyBlob: mlSecret });
    await p.persistFrostKeyShare({
      epochId: "e", primaryPubkey: "pp", identifier: "i", signingShare,
      threshold: 1, participants: 1, commitmentsCbor: SEED(5), verifyingSharesCbor: SEED(6), dkgMethod: "trusted_dealer",
    });
    const blob = JSON.stringify(events);
    expect(blob).not.toContain(Buffer.from(signingShare).toString("hex"));
    expect(blob).not.toContain(Buffer.from(mlSecret).toString("hex"));
  });
});
