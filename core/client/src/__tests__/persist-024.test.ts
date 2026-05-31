/**
 * CELLO-PERSIST-024 — V2 structured schema + startup state loading
 *
 * Specification (Phase S):
 *
 * AC-000: V2 migration creates 18 structured tables, drops client_store, is idempotent.
 * AC-001: FROST key share persisted and loaded on restart (fresh createClient from key+DB only).
 * AC-002: ML-DSA keypair persisted and loaded on restart.
 * AC-003: Registration state persisted and loaded on restart.
 * AC-004: Connections persisted and loaded on restart.
 * AC-005: Connection policy persisted and loaded on restart.
 * AC-006: Sessions + leaves persisted and loaded on restart (leaf order preserved).
 * AC-007: Sealed session loaded with frost_signature, seal_type, close_timestamp.
 * AC-008: Pending hashes + relay ACK receipts persisted/loaded (SI-004 append-only).
 * AC-011: First-install path (no DB file) — both V1 and V2 applied, no client_store.
 * AC-013: client.startup.state.loaded emitted once with correct fields.
 * SI-001: signing_share MUST NOT appear in any log.
 * SI-002: secret_key_blob MUST NOT appear in any log.
 * SI-003: db_key not stored in any table or log.
 * SI-004: relay_ack_receipts INSERT OR IGNORE — first ACK wins.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { rmSync, mkdirSync, existsSync } from "node:fs";
import { deriveDbKey } from "../db-key-derivation.js";

// ─── Dynamic import for SQLCipher ────────────────────────────────────────────

let sqlCipherAvailable = false;
let SQLCipherClientStore: typeof import("../sqlcipher-client-store.js").SQLCipherClientStore;
let ClientStatePersistence: typeof import("../client-state-persistence.js").ClientStatePersistence;

try {
  const storeMod = await import("../sqlcipher-client-store.js");
  SQLCipherClientStore = storeMod.SQLCipherClientStore;
  const persistMod = await import("../client-state-persistence.js");
  ClientStatePersistence = persistMod.ClientStatePersistence;
  sqlCipherAvailable = true;
} catch {
  sqlCipherAvailable = false;
}

const describeWithSQLCipher = sqlCipherAvailable ? describe : describe.skip;

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeSpyLogger() {
  const events: Array<{ level: string; event: string; context: Record<string, unknown> }> = [];
  const logger = {
    debug: (event: string, context: Record<string, unknown> = {}) => events.push({ level: "debug", event, context }),
    info: (event: string, context: Record<string, unknown> = {}) => events.push({ level: "info", event, context }),
    warn: (event: string, context: Record<string, unknown> = {}) => events.push({ level: "warn", event, context }),
    error: (event: string, context: Record<string, unknown> = {}) => events.push({ level: "error", event, context }),
    events,
  };
  return logger;
}

function makeTmpDbPath(): string {
  const dir = join(tmpdir(), `cello-persist-024-${randomBytes(8).toString("hex")}`);
  mkdirSync(dir, { recursive: true });
  return join(dir, "test.db");
}

function cleanupPath(dbPath: string): void {
  const dir = join(dbPath, "..");
  try { rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
}

async function openStore(dbPath: string, agentId: string, logger: ReturnType<typeof makeSpyLogger>) {
  const dbKey = deriveDbKey(randomBytes(32), agentId);
  const store = new SQLCipherClientStore(dbKey, { dbPath, agentId, logger });
  await store.open();
  return { store, dbKey };
}


// ─── AC-000: V2 migration ────────────────────────────────────────────────────

describeWithSQLCipher("PERSIST-024 AC-000 — V2 migration creates 18 tables and drops client_store", () => {
  let dbPath: string;
  let logger: ReturnType<typeof makeSpyLogger>;

  beforeEach(() => {
    dbPath = makeTmpDbPath();
    logger = makeSpyLogger();
  });
  afterEach(() => cleanupPath(dbPath));

  it("V2 migration applies, creates all tables, drops client_store", async () => {
    const { store } = await openStore(dbPath, "agent-ac000", logger);

    // Verify the 18 structured tables exist
    const tables = await store.allRows<{ name: string }>(
      `SELECT name FROM sqlite_master WHERE type='table' ORDER BY name`,
    );
    const tableNames = tables.map((t) => t.name);

    expect(tableNames).toContain("agents");
    expect(tableNames).toContain("registration_state");
    expect(tableNames).toContain("frost_key_shares");
    expect(tableNames).toContain("ml_dsa_keypairs");
    expect(tableNames).toContain("connection_policy");
    expect(tableNames).toContain("connection_policy_requirements");
    expect(tableNames).toContain("connections");
    expect(tableNames).toContain("endorsements");
    expect(tableNames).toContain("attestations");
    expect(tableNames).toContain("peers");
    expect(tableNames).toContain("sessions");
    expect(tableNames).toContain("session_tree_leaves");
    expect(tableNames).toContain("pending_hashes");
    expect(tableNames).toContain("relay_ack_receipts");
    expect(tableNames).toContain("backup_metadata");
    expect(tableNames).toContain("known_relays");
    expect(tableNames).toContain("pending_connection_requests");
    expect(tableNames).toContain("decided_connection_requests");

    // client_store MUST be dropped
    expect(tableNames).not.toContain("client_store");

    // schema_migrations should have V2 entry
    const migrations = await store.allRows<{ version: string }>(
      `SELECT version FROM schema_migrations`,
    );
    const versions = migrations.map((m) => m.version);
    expect(versions).toContain("V2__client_schema_structured");

    await store.close();
  });

  it("V2 migration does not run again on re-open; client.db.v2.migration.skipped logged", async () => {
    const identityKey = randomBytes(32);
    const dbKey = deriveDbKey(identityKey, "agent-ac000-idempotent");

    // First open — applies V2
    const store1 = new SQLCipherClientStore(dbKey, { dbPath, agentId: "agent-ac000-idempotent", logger });
    await store1.open();
    await store1.close();

    const appliedEvents = logger.events.filter((e) => e.event === "client.db.v2.migration.applied");
    expect(appliedEvents.length).toBe(1);

    // Second open — V2 should be skipped
    const store2 = new SQLCipherClientStore(dbKey, { dbPath, agentId: "agent-ac000-idempotent", logger });
    await store2.open();
    await store2.close();

    const skippedEvents = logger.events.filter((e) => e.event === "client.db.v2.migration.skipped");
    expect(skippedEvents.length).toBe(1);
    expect(skippedEvents[0].context).toHaveProperty("agentPubkey");
    expect(skippedEvents[0].context).toHaveProperty("currentVersion");
  });
});

// ─── AC-001: FROST key share persistence ─────────────────────────────────────

describeWithSQLCipher("PERSIST-024 AC-001 — FROST key share persisted and loaded on restart", () => {
  let dbPath: string;
  let logger: ReturnType<typeof makeSpyLogger>;

  beforeEach(() => {
    dbPath = makeTmpDbPath();
    logger = makeSpyLogger();
  });
  afterEach(() => cleanupPath(dbPath));

  it("FROST share is written to frost_key_shares and loaded on fresh open", async () => {
    const agentPubkey = randomBytes(32).toString("hex");
    const dbKey = deriveDbKey(randomBytes(32), agentPubkey);

    // Open, upsert agent, persist FROST share
    const store = new SQLCipherClientStore(dbKey, { dbPath, agentId: agentPubkey, logger });
    await store.open();

    const persistence = new ClientStatePersistence({
      store, agentPubkey, keyFilePath: "/tmp/test-key", logger,
    });
    await persistence.upsertAgent();

    const signingShare = randomBytes(32);
    const commitmentsCbor = randomBytes(128);
    const verifyingSharesCbor = randomBytes(96);
    const primaryPubkey = randomBytes(32).toString("hex");
    const epochId = `${agentPubkey}:epoch:1`;

    await persistence.persistFrostKeyShare({
      epochId,
      primaryPubkey,
      identifier: "test-id",
      signingShare,
      threshold: 2,
      participants: 3,
      commitmentsCbor,
      verifyingSharesCbor,
      dkgMethod: "network_dkg",
    });
    await store.close();

    // "Restart" — fresh open, load state
    const store2 = new SQLCipherClientStore(dbKey, { dbPath, agentId: agentPubkey, logger });
    await store2.open();
    const persistence2 = new ClientStatePersistence({
      store: store2, agentPubkey, keyFilePath: "/tmp/test-key", logger,
    });

    const loaded = await persistence2.loadActiveFrostKeyShare();
    expect(loaded).toBeDefined();
    expect(loaded!.epoch_id).toBe(epochId);
    expect(loaded!.primary_pubkey).toBe(primaryPubkey);
    expect(loaded!.threshold).toBe(2);
    expect(loaded!.participants).toBe(3);
    expect(loaded!.dkg_method).toBe("network_dkg");
    expect(loaded!.is_active).toBe(1);
    expect(Buffer.from(loaded!.signing_share as Buffer)).toEqual(Buffer.from(signingShare));
    expect(Buffer.from(loaded!.commitments_cbor as Buffer)).toEqual(Buffer.from(commitmentsCbor));
    expect(Buffer.from(loaded!.verifying_shares_cbor as Buffer)).toEqual(Buffer.from(verifyingSharesCbor));

    await store2.close();
  });

  it("client.frost.share.persisted event logged without signing_share (SI-001)", async () => {
    const agentPubkey = randomBytes(32).toString("hex");
    const dbKey = deriveDbKey(randomBytes(32), agentPubkey);
    const store = new SQLCipherClientStore(dbKey, { dbPath, agentId: agentPubkey, logger });
    await store.open();

    const persistence = new ClientStatePersistence({
      store, agentPubkey, keyFilePath: "/tmp/test-key", logger,
    });
    await persistence.upsertAgent();

    const signingShare = randomBytes(32);
    const signingShareHex = Buffer.from(signingShare).toString("hex");

    await persistence.persistFrostKeyShare({
      epochId: "test:epoch:1",
      primaryPubkey: "abc123",
      identifier: "id",
      signingShare,
      threshold: 2,
      participants: 3,
      commitmentsCbor: randomBytes(64),
      verifyingSharesCbor: randomBytes(64),
      dkgMethod: "network_dkg",
    });

    // SI-001: signing_share MUST NOT appear in any log
    const persistedEvents = logger.events.filter((e) => e.event === "client.frost.share.persisted");
    expect(persistedEvents.length).toBe(1);
    const serialized = JSON.stringify(persistedEvents[0]).toLowerCase();
    expect(serialized).not.toContain(signingShareHex.toLowerCase());
    expect(serialized).not.toContain("signingshare");
    expect(serialized).not.toContain("signing_share");

    await store.close();
  });
});

// ─── AC-002: ML-DSA keypair persistence ──────────────────────────────────────

describeWithSQLCipher("PERSIST-024 AC-002 — ML-DSA keypair persisted and loaded on restart", () => {
  let dbPath: string;
  let logger: ReturnType<typeof makeSpyLogger>;

  beforeEach(() => {
    dbPath = makeTmpDbPath();
    logger = makeSpyLogger();
  });
  afterEach(() => cleanupPath(dbPath));

  it("ML-DSA keypair is written and loaded on fresh open", async () => {
    const agentPubkey = randomBytes(32).toString("hex");
    const dbKey = deriveDbKey(randomBytes(32), agentPubkey);
    const store = new SQLCipherClientStore(dbKey, { dbPath, agentId: agentPubkey, logger });
    await store.open();

    const persistence = new ClientStatePersistence({
      store, agentPubkey, keyFilePath: "/tmp/test-key", logger,
    });
    await persistence.upsertAgent();

    const secretKeyBlob = randomBytes(2560); // ML-DSA-44 secret key is 2560 bytes
    const mlDsaPubkey = randomBytes(1312).toString("hex"); // 2624 hex chars

    await persistence.persistMlDsaKeypair({ mlDsaPubkey, secretKeyBlob });
    await store.close();

    // Restart
    const store2 = new SQLCipherClientStore(dbKey, { dbPath, agentId: agentPubkey, logger });
    await store2.open();
    const persistence2 = new ClientStatePersistence({
      store: store2, agentPubkey, keyFilePath: "/tmp/test-key", logger,
    });

    const loaded = await persistence2.loadMlDsaKeypair();
    expect(loaded).toBeDefined();
    expect(loaded!.ml_dsa_pubkey).toBe(mlDsaPubkey);
    expect(Buffer.from(loaded!.secret_key_blob as Buffer)).toEqual(Buffer.from(secretKeyBlob));

    await store2.close();
  });

  it("client.mldsa.keypair.persisted logged without secret_key_blob (SI-002)", async () => {
    const agentPubkey = randomBytes(32).toString("hex");
    const dbKey = deriveDbKey(randomBytes(32), agentPubkey);
    const store = new SQLCipherClientStore(dbKey, { dbPath, agentId: agentPubkey, logger });
    await store.open();

    const persistence = new ClientStatePersistence({
      store, agentPubkey, keyFilePath: "/tmp/test-key", logger,
    });
    await persistence.upsertAgent();

    const secretKeyBlob = randomBytes(2560);
    const secretKeyBlobHex = Buffer.from(secretKeyBlob).toString("hex");

    await persistence.persistMlDsaKeypair({
      mlDsaPubkey: "test-pub",
      secretKeyBlob,
    });

    const persistedEvents = logger.events.filter((e) => e.event === "client.mldsa.keypair.persisted");
    expect(persistedEvents.length).toBe(1);
    const serialized = JSON.stringify(persistedEvents[0]).toLowerCase();
    // SI-002: secret key blob must not appear
    expect(serialized).not.toContain(secretKeyBlobHex.slice(0, 64).toLowerCase());
    expect(serialized).not.toContain("secret_key_blob");
    expect(serialized).not.toContain("secretkeyblob");

    await store.close();
  });
});

// ─── AC-003: Registration state persistence ──────────────────────────────────

describeWithSQLCipher("PERSIST-024 AC-003 — Registration state persisted and loaded on restart", () => {
  let dbPath: string;
  let logger: ReturnType<typeof makeSpyLogger>;

  beforeEach(() => {
    dbPath = makeTmpDbPath();
    logger = makeSpyLogger();
  });
  afterEach(() => cleanupPath(dbPath));

  it("registration state is written and loaded correctly", async () => {
    const agentPubkey = randomBytes(32).toString("hex");
    const dbKey = deriveDbKey(randomBytes(32), agentPubkey);
    const store = new SQLCipherClientStore(dbKey, { dbPath, agentId: agentPubkey, logger });
    await store.open();

    const persistence = new ClientStatePersistence({
      store, agentPubkey, keyFilePath: "/tmp/test-key", logger,
    });
    await persistence.upsertAgent();

    const agentId = randomBytes(16).toString("hex");
    const primaryPubkey = randomBytes(32).toString("hex");
    const mlDsaPubkey = randomBytes(1312).toString("hex");
    const registeredAt = Date.now();

    await persistence.persistRegistrationState({
      agentId, primaryPubkey, mlDsaPubkey, registeredAt,
    });
    await store.close();

    // Restart
    const store2 = new SQLCipherClientStore(dbKey, { dbPath, agentId: agentPubkey, logger });
    await store2.open();
    const persistence2 = new ClientStatePersistence({
      store: store2, agentPubkey, keyFilePath: "/tmp/test-key", logger,
    });

    const loaded = await persistence2.loadRegistrationState();
    expect(loaded).toBeDefined();
    expect(loaded!.agent_id).toBe(agentId);
    expect(loaded!.primary_pubkey).toBe(primaryPubkey);
    expect(loaded!.ml_dsa_pubkey).toBe(mlDsaPubkey);
    expect(loaded!.registered_at).toBe(registeredAt);
    expect(loaded!.status).toBe("active");

    await store2.close();
  });
});

// ─── AC-004: Connection persistence ──────────────────────────────────────────

describeWithSQLCipher("PERSIST-024 AC-004 — Connections persisted and loaded on restart", () => {
  let dbPath: string;
  let logger: ReturnType<typeof makeSpyLogger>;

  beforeEach(() => {
    dbPath = makeTmpDbPath();
    logger = makeSpyLogger();
  });
  afterEach(() => cleanupPath(dbPath));

  it("connection records are written and loaded correctly", async () => {
    const agentPubkey = randomBytes(32).toString("hex");
    const dbKey = deriveDbKey(randomBytes(32), agentPubkey);
    const store = new SQLCipherClientStore(dbKey, { dbPath, agentId: agentPubkey, logger });
    await store.open();

    const persistence = new ClientStatePersistence({
      store, agentPubkey, keyFilePath: "/tmp/test-key", logger,
    });
    await persistence.upsertAgent();

    const connId = randomBytes(16).toString("hex");
    const counterpartyPubkey = randomBytes(32).toString("hex");
    const establishedAt = Date.now();

    await persistence.persistConnection({
      connectionId: connId,
      counterpartyPubkey,
      establishedAt,
    });
    await store.close();

    // Restart
    const store2 = new SQLCipherClientStore(dbKey, { dbPath, agentId: agentPubkey, logger });
    await store2.open();
    const persistence2 = new ClientStatePersistence({
      store: store2, agentPubkey, keyFilePath: "/tmp/test-key", logger,
    });

    const loaded = await persistence2.loadConnections();
    expect(loaded.length).toBe(1);
    expect(loaded[0].connection_id).toBe(connId);
    expect(loaded[0].counterparty_pubkey).toBe(counterpartyPubkey);
    expect(loaded[0].established_at).toBe(establishedAt);

    await store2.close();
  });
});

// ─── AC-005: Connection policy persistence ───────────────────────────────────

describeWithSQLCipher("PERSIST-024 AC-005 — Connection policy persisted and loaded on restart", () => {
  let dbPath: string;
  let logger: ReturnType<typeof makeSpyLogger>;

  beforeEach(() => {
    dbPath = makeTmpDbPath();
    logger = makeSpyLogger();
  });
  afterEach(() => cleanupPath(dbPath));

  it("policy with requirements is written and loaded in position order", async () => {
    const agentPubkey = randomBytes(32).toString("hex");
    const dbKey = deriveDbKey(randomBytes(32), agentPubkey);
    const store = new SQLCipherClientStore(dbKey, { dbPath, agentId: agentPubkey, logger });
    await store.open();

    const persistence = new ClientStatePersistence({
      store, agentPubkey, keyFilePath: "/tmp/test-key", logger,
    });
    await persistence.upsertAgent();

    const policy = {
      mode: "guarded" as const,
      review_mode: "inference" as const,
      requirements: [
        { signal_type: "endorsement" as const, condition: { type: "min_count" as const, count: 2 } },
        { signal_type: "registration_age" as const, condition: { type: "min_age_days" as const, days: 7 } },
      ],
    };

    await persistence.persistConnectionPolicy(policy);
    await store.close();

    // Restart
    const store2 = new SQLCipherClientStore(dbKey, { dbPath, agentId: agentPubkey, logger });
    await store2.open();
    const persistence2 = new ClientStatePersistence({
      store: store2, agentPubkey, keyFilePath: "/tmp/test-key", logger,
    });

    const loaded = await persistence2.loadConnectionPolicy();
    expect(loaded).toBeDefined();
    expect(loaded!.mode).toBe("guarded");
    expect(loaded!.review_mode).toBe("inference");
    expect(loaded!.requirements.length).toBe(2);
    expect(loaded!.requirements[0].signal_type).toBe("endorsement");
    expect(loaded!.requirements[0].condition).toEqual({ type: "min_count", count: 2 });
    expect(loaded!.requirements[1].signal_type).toBe("registration_age");
    expect(loaded!.requirements[1].condition).toEqual({ type: "min_age_days", days: 7 });

    await store2.close();
  });
});

// ─── AC-006: Session + leaves persistence ────────────────────────────────────

describeWithSQLCipher("PERSIST-024 AC-006 — Sessions and leaves persisted in correct order", () => {
  let dbPath: string;
  let logger: ReturnType<typeof makeSpyLogger>;

  beforeEach(() => {
    dbPath = makeTmpDbPath();
    logger = makeSpyLogger();
  });
  afterEach(() => cleanupPath(dbPath));

  it("session with 12 leaves is persisted and loaded in leaf_index order", async () => {
    const agentPubkey = randomBytes(32).toString("hex");
    const dbKey = deriveDbKey(randomBytes(32), agentPubkey);
    const store = new SQLCipherClientStore(dbKey, { dbPath, agentId: agentPubkey, logger });
    await store.open();

    const persistence = new ClientStatePersistence({
      store, agentPubkey, keyFilePath: "/tmp/test-key", logger,
    });
    await persistence.upsertAgent();

    const sessionIdHex = randomBytes(32).toString("hex");
    const counterpartyPubkey = randomBytes(32);
    const directoryPubkey = randomBytes(32);
    const genesisPrevRoot = randomBytes(32);

    // Create session record
    const session: import("../types.js").SessionRecord = {
      session_id: Buffer.from(sessionIdHex, "hex"),
      counterparty_pubkey: counterpartyPubkey,
      counterparty_peer_id: "peer-123",
      counterparty_multiaddrs: ["/ip4/127.0.0.1/tcp/4001"],
      relay_endpoint: { peer_id: "relay-1", multiaddrs: ["/ip4/127.0.0.1/tcp/5001"] },
      directory_endpoint: { peer_id: "dir-1", multiaddrs: ["/ip4/127.0.0.1/tcp/6001"] },
      directory_pubkey: directoryPubkey,
      genesis_prev_root: genesisPrevRoot,
      last_seen_seq: 10,
      last_sent_seq: 5,
      next_expected_seq: 11,
      status: "active",
      desynchronized: false,
      local_tree_leaves: [],
    };

    await persistence.persistSession(sessionIdHex, session);

    // Insert 12 leaves
    const leaves: Uint8Array[] = [];
    for (let i = 0; i < 12; i++) {
      const s2Cbor = randomBytes(64 + i); // variable size to detect ordering issues
      leaves.push(s2Cbor);
      await persistence.persistSessionTreeLeaf({
        sessionIdHex,
        leafIndex: i,
        leafKind: i % 3 === 0 ? "ctrl" : "msg",
        s2Cbor,
        sequenceNumber: i + 1,
      });
    }
    await store.close();

    // Restart
    const store2 = new SQLCipherClientStore(dbKey, { dbPath, agentId: agentPubkey, logger });
    await store2.open();
    const persistence2 = new ClientStatePersistence({
      store: store2, agentPubkey, keyFilePath: "/tmp/test-key", logger,
    });

    const loadedLeaves = await persistence2.loadSessionTreeLeaves(sessionIdHex);
    expect(loadedLeaves.length).toBe(12);

    // Verify ALL 12 leaves are present and in correct order
    for (let i = 0; i < 12; i++) {
      expect(loadedLeaves[i].leaf_index).toBe(i);
      expect(Buffer.from(loadedLeaves[i].s2_cbor as Buffer)).toEqual(Buffer.from(leaves[i]));
      expect(loadedLeaves[i].sequence_number).toBe(i + 1);
    }

    // Verify session sequence numbers restored
    const sessions = await persistence2.loadSessions();
    expect(sessions.length).toBe(1);
    expect(sessions[0].last_seen_seq).toBe(10);
    expect(sessions[0].last_sent_seq).toBe(5);
    expect(sessions[0].next_expected_seq).toBe(11);

    await store2.close();
  });
});

// ─── AC-007: Sealed session persistence ──────────────────────────────────────

describeWithSQLCipher("PERSIST-024 AC-007 — Sealed session loaded with seal fields", () => {
  let dbPath: string;
  let logger: ReturnType<typeof makeSpyLogger>;

  beforeEach(() => {
    dbPath = makeTmpDbPath();
    logger = makeSpyLogger();
  });
  afterEach(() => cleanupPath(dbPath));

  it("sealed session has frost_signature, seal_type, close_timestamp after reload", async () => {
    const agentPubkey = randomBytes(32).toString("hex");
    const dbKey = deriveDbKey(randomBytes(32), agentPubkey);
    const store = new SQLCipherClientStore(dbKey, { dbPath, agentId: agentPubkey, logger });
    await store.open();

    const persistence = new ClientStatePersistence({
      store, agentPubkey, keyFilePath: "/tmp/test-key", logger,
    });
    await persistence.upsertAgent();

    const sessionIdHex = randomBytes(32).toString("hex");
    const sealedRoot = randomBytes(32);
    const frostSignature = randomBytes(64);
    const signerPubkey = randomBytes(32);
    const closeTimestamp = Date.now();

    const session: import("../types.js").SessionRecord = {
      session_id: Buffer.from(sessionIdHex, "hex"),
      counterparty_pubkey: randomBytes(32),
      counterparty_peer_id: "peer-1",
      counterparty_multiaddrs: [],
      relay_endpoint: { peer_id: "r1", multiaddrs: [] },
      directory_endpoint: { peer_id: "d1", multiaddrs: [] },
      directory_pubkey: randomBytes(32),
      genesis_prev_root: randomBytes(32),
      last_seen_seq: 0,
      last_sent_seq: 0,
      next_expected_seq: 1,
      status: "sealed",
      desynchronized: false,
      local_tree_leaves: [],
      sealed_root: sealedRoot,
      seal_type: "frost",
      close_timestamp: closeTimestamp,
      frost_signature: frostSignature,
      signer_pubkey: signerPubkey,
    };

    await persistence.persistSession(sessionIdHex, session);
    await store.close();

    // Restart
    const store2 = new SQLCipherClientStore(dbKey, { dbPath, agentId: agentPubkey, logger });
    await store2.open();
    const persistence2 = new ClientStatePersistence({
      store: store2, agentPubkey, keyFilePath: "/tmp/test-key", logger,
    });

    const sessions = await persistence2.loadSessions();
    expect(sessions.length).toBe(1);
    const s = sessions[0];
    expect(s.status).toBe("sealed");
    expect(s.seal_type).toBe("frost");
    expect(s.close_timestamp).toBe(closeTimestamp);
    expect(Buffer.from(s.sealed_root as Buffer)).toEqual(Buffer.from(sealedRoot));
    expect(Buffer.from(s.frost_signature as Buffer)).toEqual(Buffer.from(frostSignature));
    expect(Buffer.from(s.signer_pubkey as Buffer)).toEqual(Buffer.from(signerPubkey));

    await store2.close();
  });
});

// ─── SI-004: relay_ack_receipts append-only ──────────────────────────────────

describeWithSQLCipher("PERSIST-024 SI-004 — relay_ack_receipts INSERT OR IGNORE (first ACK wins)", () => {
  let dbPath: string;
  let logger: ReturnType<typeof makeSpyLogger>;

  beforeEach(() => {
    dbPath = makeTmpDbPath();
    logger = makeSpyLogger();
  });
  afterEach(() => cleanupPath(dbPath));

  it("second ACK for same hash is silently dropped; first ACK values preserved", async () => {
    const agentPubkey = randomBytes(32).toString("hex");
    const dbKey = deriveDbKey(randomBytes(32), agentPubkey);
    const store = new SQLCipherClientStore(dbKey, { dbPath, agentId: agentPubkey, logger });
    await store.open();

    const persistence = new ClientStatePersistence({
      store, agentPubkey, keyFilePath: "/tmp/test-key", logger,
    });
    await persistence.upsertAgent();

    const hashHex = randomBytes(32).toString("hex");
    const sessionId = randomBytes(16).toString("hex");

    // First ACK
    const firstResult = await persistence.persistRelayAckReceipt({
      hashHex,
      sessionId,
      relayId: "relay-1",
      relayPubkeyHex: randomBytes(32).toString("hex"),
      sequenceNumber: 42,
      relayTimestamp: 1000000,
      signatureHex: randomBytes(64).toString("hex"),
    });
    expect(firstResult.isDuplicate).toBe(false);

    // Second ACK (different values for same hash)
    const secondResult = await persistence.persistRelayAckReceipt({
      hashHex,
      sessionId,
      relayId: "relay-2",
      relayPubkeyHex: randomBytes(32).toString("hex"),
      sequenceNumber: 99,
      relayTimestamp: 2000000,
      signatureHex: randomBytes(64).toString("hex"),
    });
    expect(secondResult.isDuplicate).toBe(true);

    // Verify only one row exists with first ACK values
    const rows = await store.allRows<{ hash_hex: string; sequence_number: number; relay_id: string }>(
      `SELECT hash_hex, sequence_number, relay_id FROM relay_ack_receipts WHERE hash_hex = ? AND agent_pubkey = ?`,
      [hashHex, agentPubkey],
    );
    expect(rows.length).toBe(1);
    expect(rows[0].sequence_number).toBe(42);
    expect(rows[0].relay_id).toBe("relay-1");

    // Verify client.relay.ack.duplicate was logged
    const dupEvents = logger.events.filter((e) => e.event === "client.relay.ack.duplicate");
    expect(dupEvents.length).toBe(1);

    await store.close();
  });
});

// ─── AC-011: First-install path ──────────────────────────────────────────────

describeWithSQLCipher("PERSIST-024 AC-011 — First-install path (no DB file)", () => {
  it("new database has V1 and V2 applied, no client_store table", async () => {
    const dbPath = makeTmpDbPath();
    const logger = makeSpyLogger();
    cleanupPath(dbPath); // ensure no file exists
    mkdirSync(join(dbPath, ".."), { recursive: true });
    expect(existsSync(dbPath)).toBe(false);

    const dbKey = deriveDbKey(randomBytes(32), "agent-fresh");
    const store = new SQLCipherClientStore(dbKey, { dbPath, agentId: "agent-fresh", logger });
    await store.open();

    // Verify both V1 and V2 migrations applied
    const migrations = await store.allRows<{ version: string }>(
      `SELECT version FROM schema_migrations ORDER BY version`,
    );
    const versions = migrations.map((m) => m.version);
    expect(versions).toContain("V1__client_schema");
    expect(versions).toContain("V2__client_schema_structured");

    // No client_store table
    const tables = await store.allRows<{ name: string }>(
      `SELECT name FROM sqlite_master WHERE type='table' AND name='client_store'`,
    );
    expect(tables.length).toBe(0);

    // client.db.v2.migration.applied was logged
    const v2Events = logger.events.filter((e) => e.event === "client.db.v2.migration.applied");
    expect(v2Events.length).toBe(1);

    await store.close();
    cleanupPath(dbPath);
  });
});

// ─── AC-013: client.startup.state.loaded event ───────────────────────────────

describeWithSQLCipher("PERSIST-024 AC-013 — client.startup.state.loaded emitted with all fields", () => {
  let dbPath: string;
  let logger: ReturnType<typeof makeSpyLogger>;

  beforeEach(() => {
    dbPath = makeTmpDbPath();
    logger = makeSpyLogger();
  });
  afterEach(() => cleanupPath(dbPath));

  it("loadStartupState emits event with correct counts and booleans", async () => {
    const agentPubkey = randomBytes(32).toString("hex");
    const dbKey = deriveDbKey(randomBytes(32), agentPubkey);
    const store = new SQLCipherClientStore(dbKey, { dbPath, agentId: agentPubkey, logger });
    await store.open();

    const persistence = new ClientStatePersistence({
      store, agentPubkey, keyFilePath: "/tmp/test-key", logger,
    });
    await persistence.upsertAgent();

    // Populate some state
    await persistence.persistFrostKeyShare({
      epochId: "e1", primaryPubkey: "pk1", identifier: "id1",
      signingShare: randomBytes(32), threshold: 2, participants: 3,
      commitmentsCbor: randomBytes(64), verifyingSharesCbor: randomBytes(64),
      dkgMethod: "network_dkg",
    });
    await persistence.persistMlDsaKeypair({
      mlDsaPubkey: "mldsa-pub", secretKeyBlob: randomBytes(2560),
    });
    await persistence.persistRegistrationState({
      agentId: "aid1", primaryPubkey: "pk1", mlDsaPubkey: "mldsa-pub", registeredAt: Date.now(),
    });
    await persistence.persistConnection({
      connectionId: "c1", counterpartyPubkey: "cp1", establishedAt: Date.now(),
    });
    await persistence.persistConnectionPolicy({
      mode: "guarded", review_mode: "inference",
      requirements: [{ signal_type: "endorsement", condition: { type: "min_count", count: 1 } }],
    });

    // Call loadStartupState
    const state = await persistence.loadStartupState();

    expect(state.hasFrostShare).toBe(true);
    expect(state.hasMlDsaKeypair).toBe(true);
    expect(state.hasRegistration).toBe(true);
    expect(state.hasPolicy).toBe(true);
    expect(state.connectionCount).toBe(1);
    expect(state.sessionCount).toBe(0);
    expect(state.leafCount).toBe(0);
    expect(state.pendingHashCount).toBe(0);

    // Verify the event was logged
    const loadedEvents = logger.events.filter((e) => e.event === "client.startup.state.loaded");
    expect(loadedEvents.length).toBe(1);
    const ctx = loadedEvents[0].context;
    expect(ctx.agentPubkey).toBe(agentPubkey);
    expect(ctx.hasFrostShare).toBe(true);
    expect(ctx.hasMlDsaKeypair).toBe(true);
    expect(ctx.hasRegistration).toBe(true);
    expect(ctx.hasPolicy).toBe(true);
    expect(ctx.connectionCount).toBe(1);
    expect(ctx.sessionCount).toBe(0);
    expect(ctx.leafCount).toBe(0);
    expect(ctx.pendingHashCount).toBe(0);

    await store.close();
  });
});

// ─── SI-003: db_key not in DB or logs ────────────────────────────────────────

describeWithSQLCipher("PERSIST-024 SI-003 — db_key never stored or logged", () => {
  it("db_key hex never appears in any log event from the persistence layer", async () => {
    const dbPath = makeTmpDbPath();
    const logger = makeSpyLogger();
    const identityKey = randomBytes(32);
    const agentPubkey = randomBytes(32).toString("hex");
    const dbKey = deriveDbKey(identityKey, agentPubkey);
    const dbKeyHex = Buffer.from(dbKey).toString("hex").toLowerCase();

    const store = new SQLCipherClientStore(dbKey, { dbPath, agentId: agentPubkey, logger });
    await store.open();

    const persistence = new ClientStatePersistence({
      store, agentPubkey, keyFilePath: "/tmp/test-key", logger,
    });
    await persistence.upsertAgent();
    await persistence.persistFrostKeyShare({
      epochId: "e1", primaryPubkey: "pk1", identifier: "id1",
      signingShare: randomBytes(32), threshold: 2, participants: 3,
      commitmentsCbor: randomBytes(64), verifyingSharesCbor: randomBytes(64),
      dkgMethod: "network_dkg",
    });
    await persistence.loadStartupState();
    await store.close();

    // No log event should contain the db_key hex
    for (const ev of logger.events) {
      const serialized = JSON.stringify(ev).toLowerCase();
      expect(serialized).not.toContain(dbKeyHex);
    }

    cleanupPath(dbPath);
  });
});

// ─── AC-009: Endorsements and attestations ───────────────────────────────────

describeWithSQLCipher("PERSIST-024 AC-009 — Endorsements and attestations loaded with expiry filter", () => {
  let dbPath: string;
  let logger: ReturnType<typeof makeSpyLogger>;

  beforeEach(() => {
    dbPath = makeTmpDbPath();
    logger = makeSpyLogger();
  });
  afterEach(() => cleanupPath(dbPath));

  it("loadStartupState includes unexpired endorsements and attestations, excludes expired ones", async () => {
    const agentPubkey = randomBytes(32).toString("hex");
    const dbKey = deriveDbKey(randomBytes(32), agentPubkey);
    const store = new SQLCipherClientStore(dbKey, { dbPath, agentId: agentPubkey, logger });
    await store.open();

    const persistence = new ClientStatePersistence({
      store, agentPubkey, keyFilePath: "/tmp/test-key", logger,
    });
    await persistence.upsertAgent();

    const now = Date.now();
    const futureExpiry = now + 86400_000; // 1 day from now
    const pastExpiry = now - 1_000;       // 1 second ago (expired)

    const endorserPubkey1 = randomBytes(32).toString("hex");
    const endorserPubkey2 = randomBytes(32).toString("hex");
    const attesterPubkey1 = randomBytes(32).toString("hex");
    const attesterPubkey2 = randomBytes(32).toString("hex");

    // Insert unexpired endorsement
    await store.run(
      `INSERT INTO endorsements
       (agent_pubkey, endorser_pubkey, endorser_ml_dsa_pubkey, target_pubkey, endorsement_type, created_at, expires_at, endorser_ml_dsa_sig)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [agentPubkey, endorserPubkey1, Buffer.from(randomBytes(32)), agentPubkey, "trust", now, futureExpiry, Buffer.from(randomBytes(64))],
    );
    // Insert expired endorsement
    await store.run(
      `INSERT INTO endorsements
       (agent_pubkey, endorser_pubkey, endorser_ml_dsa_pubkey, target_pubkey, endorsement_type, created_at, expires_at, endorser_ml_dsa_sig)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [agentPubkey, endorserPubkey2, Buffer.from(randomBytes(32)), agentPubkey, "trust", now - 10000, pastExpiry, Buffer.from(randomBytes(64))],
    );
    // Insert unexpired attestation
    await store.run(
      `INSERT INTO attestations
       (agent_pubkey, attester_pubkey, attestation_type, attester_ml_dsa_pubkey, attestation_data, created_at, expires_at, attester_ml_dsa_sig)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [agentPubkey, attesterPubkey1, "registration_age", Buffer.from(randomBytes(32)), Buffer.from("{}"), now, futureExpiry, Buffer.from(randomBytes(64))],
    );
    // Insert expired attestation
    await store.run(
      `INSERT INTO attestations
       (agent_pubkey, attester_pubkey, attestation_type, attester_ml_dsa_pubkey, attestation_data, created_at, expires_at, attester_ml_dsa_sig)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [agentPubkey, attesterPubkey2, "endorsement_count", Buffer.from(randomBytes(32)), Buffer.from("{}"), now - 10000, pastExpiry, Buffer.from(randomBytes(64))],
    );

    const state = await persistence.loadStartupState();

    // Only unexpired items are returned
    expect(state.endorsements.length).toBe(1);
    expect(state.endorsements[0]["endorser_pubkey"]).toBe(endorserPubkey1);

    expect(state.attestations.length).toBe(1);
    expect(state.attestations[0]["attester_pubkey"]).toBe(attesterPubkey1);

    await store.close();
  });
});

// ─── AC-010: Pending connection requests survive restart ─────────────────────

describeWithSQLCipher("PERSIST-024 AC-010 — pending connection requests survive restart", () => {
  let dbPath: string;
  let logger: ReturnType<typeof makeSpyLogger>;

  beforeEach(() => {
    dbPath = makeTmpDbPath();
    logger = makeSpyLogger();
  });
  afterEach(() => cleanupPath(dbPath));

  it("pending request is persisted, loads after restart, moves to decided on decision", async () => {
    const agentPubkey = randomBytes(32).toString("hex");
    const dbKey = deriveDbKey(randomBytes(32), agentPubkey);
    const store = new SQLCipherClientStore(dbKey, { dbPath, agentId: agentPubkey, logger });
    await store.open();

    const persistence = new ClientStatePersistence({
      store, agentPubkey, keyFilePath: "/tmp/test-key", logger,
    });
    await persistence.upsertAgent();

    const requestId = randomBytes(16).toString("hex");
    const fromPubkey = randomBytes(32).toString("hex");
    const packageCbor = randomBytes(128);

    // Persist a pending connection request
    await persistence.persistPendingConnectionRequest({
      requestId,
      fromPubkey,
      packageCbor,
      round: 1,
    });

    // Simulate restart
    await store.close();
    const store2 = new SQLCipherClientStore(dbKey, { dbPath, agentId: agentPubkey, logger });
    await store2.open();
    const persistence2 = new ClientStatePersistence({
      store: store2, agentPubkey, keyFilePath: "/tmp/test-key", logger,
    });

    // Verify the pending request survives restart
    const pending = await persistence2.loadPendingConnectionRequests();
    expect(pending.length).toBe(1);
    expect(pending[0].request_id).toBe(requestId);
    expect(pending[0].from_pubkey).toBe(fromPubkey);
    expect(Buffer.from(pending[0].package_cbor as Buffer)).toEqual(Buffer.from(packageCbor));
    expect(pending[0].round).toBe(1);

    // Decide the request (accept)
    await persistence2.decidePendingConnectionRequest(requestId, "accepted");

    // Verify it moves to decided_connection_requests
    const decided = await persistence2.loadDecidedConnectionRequests();
    expect(decided.length).toBe(1);
    expect(decided[0].request_id).toBe(requestId);
    expect(decided[0].decision).toBe("accepted");

    // Verify it is gone from pending_connection_requests
    const pendingAfter = await persistence2.loadPendingConnectionRequests();
    expect(pendingAfter.length).toBe(0);

    await store2.close();
  });
});

// ─── AC-008: Pending hashes ──────────────────────────────────────────────────

describeWithSQLCipher("PERSIST-024 AC-008 — Pending hashes persisted and loaded", () => {
  let dbPath: string;
  let logger: ReturnType<typeof makeSpyLogger>;

  beforeEach(() => {
    dbPath = makeTmpDbPath();
    logger = makeSpyLogger();
  });
  afterEach(() => cleanupPath(dbPath));

  it("pending hashes survive restart in FIFO order", async () => {
    const agentPubkey = randomBytes(32).toString("hex");
    const dbKey = deriveDbKey(randomBytes(32), agentPubkey);
    const store = new SQLCipherClientStore(dbKey, { dbPath, agentId: agentPubkey, logger });
    await store.open();

    const persistence = new ClientStatePersistence({
      store, agentPubkey, keyFilePath: "/tmp/test-key", logger,
    });
    await persistence.upsertAgent();

    const sessionId = "session-abc";
    const hash1 = randomBytes(32).toString("hex");
    const hash2 = randomBytes(32).toString("hex");

    await persistence.persistPendingHash({ sessionId, hashHex: hash1, enqueuedAt: 1000 });
    await persistence.persistPendingHash({ sessionId, hashHex: hash2, enqueuedAt: 2000 });
    await store.close();

    // Restart
    const store2 = new SQLCipherClientStore(dbKey, { dbPath, agentId: agentPubkey, logger });
    await store2.open();
    const persistence2 = new ClientStatePersistence({
      store: store2, agentPubkey, keyFilePath: "/tmp/test-key", logger,
    });

    const loaded = await persistence2.loadPendingHashes();
    expect(loaded.length).toBe(2);
    expect(loaded[0].hash_hex).toBe(hash1);
    expect(loaded[1].hash_hex).toBe(hash2);
    expect(loaded[0].enqueued_at).toBe(1000);
    expect(loaded[1].enqueued_at).toBe(2000);

    await store2.close();
  });
});
