/**
 * DOD-AGENT-ID-JOINKEY-1 — AC2: the transactional re-key of the seven child tables.
 *
 * SQLite cannot alter a PRIMARY KEY, so each table is REBUILT (create, copy, drop, rename). All
 * seven rebuilds share ONE `BEGIN…COMMIT`, so a failure leaves the original database untouched —
 * there is no half-migrated state, and therefore no recovery path to get wrong.
 *
 * The tests below assert the three properties that make the migration trustworthy:
 *
 *   1. It preserves every row and attributes each to the RIGHT identity (including a retired agent's
 *      rows, which backfill to the retired agent's own id and then sit inert — no purge, no bleed).
 *   2. It REFUSES rather than guesses. An ambiguous name (a retired name reused) or an orphaned row
 *      aborts the whole transaction with the original schema and data intact. Guessing here would
 *      bind one identity's transcript to another's keypair — the exact defect, made permanent and
 *      blessed by a migration.
 *   3. A MIGRATED database ends up structurally identical to a FRESH one. The migration pins its own
 *      target DDL (deliberately — a migration must not follow a moving schema), and this test is what
 *      stops the pinned copy from drifting away from what `session-node-manager` / `retry-queue`
 *      create on a new machine.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { DatabaseSync } from "node:sqlite";
import { migrateSessionTablesToAgentId } from "../agent-id-migration.js";
import { migrateContactsAddTierMetadata } from "../contacts-tier-migration.js";
import { ensureIdentitySchema } from "../db-identity-store.js";
import { PassthroughGatewayClient } from "@cello-protocol/gateway";
import { SessionNodeManager } from "../session-node-manager.js";
import { RetryQueue } from "../retry-queue.js";
import type { ISessionNodeFactory } from "../session-node-manager.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { DaemonDatabase } from "../sqlcipher-db.js";
import type { Logger } from "../types.js";

function makeLogger(): { logger: Logger; events: Array<{ level: string; event: string; context: Record<string, unknown> }> } {
  const events: Array<{ level: string; event: string; context: Record<string, unknown> }> = [];
  const logger: Logger = {
    debug(event, context) { events.push({ level: "debug", event, context: context ?? {} }); },
    info(event, context) { events.push({ level: "info", event, context: context ?? {} }); },
    warn(event, context) { events.push({ level: "warn", event, context: context ?? {} }); },
    error(event, context) { events.push({ level: "error", event, context: context ?? {} }); },
  };
  return { logger, events };
}

class StubNodeFactory implements ISessionNodeFactory {
  async create(): Promise<CelloNode> {
    return {
      peerId: "stub-peer",
      addrs: ["/ip4/127.0.0.1/tcp/1"],
      stop: async () => {},
      dial: async () => { throw new Error("not dialable"); },
      handle: () => {},
    } as unknown as CelloNode;
  }
}

/**
 * The PRE-migration schema, exactly as REMOVE-001 left it: seven children keyed on the mutable
 * `agent_name`. Written out literally so the test builds a genuine legacy database rather than
 * asking the code under test what "legacy" means.
 */
const LEGACY_DDL = `
  CREATE TABLE sessions (
    session_id TEXT NOT NULL, agent_name TEXT NOT NULL, counterparty_pubkey TEXT NOT NULL,
    status TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
    message_count INTEGER NOT NULL DEFAULT 0, interrupted_at TEXT, relay_peer_id TEXT,
    relay_addrs TEXT, seal_legibility TEXT, sealed_root_hex TEXT, counterparty_primary_pubkey TEXT,
    PRIMARY KEY (agent_name, session_id));
  CREATE TABLE seal_interrupted_artifacts (
    agent_name TEXT NOT NULL, session_id TEXT NOT NULL, role TEXT NOT NULL, own_leaf TEXT NOT NULL,
    counterparty_leaf TEXT NOT NULL, merkle_root TEXT NOT NULL, nonce TEXT NOT NULL,
    created_at INTEGER NOT NULL, PRIMARY KEY (agent_name, session_id));
  CREATE TABLE session_tree_leaves (
    agent_name TEXT NOT NULL, session_id TEXT NOT NULL, leaf_index INTEGER NOT NULL,
    leaf_kind TEXT NOT NULL, leaf_hash_hex TEXT NOT NULL, created_at INTEGER NOT NULL,
    PRIMARY KEY (agent_name, session_id, leaf_index));
  CREATE TABLE transcript (
    agent_name TEXT NOT NULL, session_id TEXT NOT NULL, sequence INTEGER NOT NULL,
    direction TEXT NOT NULL, blob BLOB NOT NULL, created_at INTEGER NOT NULL,
    PRIMARY KEY (agent_name, session_id, sequence, direction));
  CREATE TABLE message_watermarks (
    agent_name TEXT NOT NULL, session_id TEXT NOT NULL, last_delivered_seq INTEGER NOT NULL,
    PRIMARY KEY (agent_name, session_id));
  CREATE TABLE contacts (
    agent_name TEXT NOT NULL, pubkey TEXT NOT NULL, added_at INTEGER NOT NULL, moniker TEXT,
    PRIMARY KEY (agent_name, pubkey));
  CREATE TABLE retry_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL, nonce_hex TEXT NOT NULL,
    content_blob BLOB NOT NULL, queued_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 1,
    position INTEGER NOT NULL, awaiting_ack INTEGER NOT NULL DEFAULT 0, content_hash_hex TEXT,
    agent_name TEXT, UNIQUE(session_id, nonce_hex));
`;

const SEVEN = [
  "sessions", "seal_interrupted_artifacts", "session_tree_leaves",
  "transcript", "message_watermarks", "contacts", "retry_queue",
] as const;

/** An in-memory legacy database with an `agents` parent and the seven pre-migration children. */
function legacyDb(): DatabaseSync {
  const db = new DatabaseSync(":memory:");
  ensureIdentitySchema(db as unknown as DaemonDatabase);
  db.exec(LEGACY_DDL);
  return db;
}

function addAgent(db: DatabaseSync, id: string, name: string, state = "created"): void {
  db.prepare(
    `INSERT INTO agents (agent_id, agent_name, k_local_seed, k_local_pubkey, state, created_at, updated_at)
     VALUES (?, ?, x'00', ?, ?, 1, 1)`,
  ).run(id, name, `pub-${id}`, state);
}

const cols = (db: DatabaseSync | DaemonDatabase, t: string): string[] =>
  (db.prepare(`PRAGMA table_info(${t})`).all() as unknown as Array<{ name: string }>).map((c) => c.name).sort();

const pkOf = (db: DatabaseSync | DaemonDatabase, t: string): string[] =>
  (db.prepare(`PRAGMA table_info(${t})`).all() as unknown as Array<{ name: string; pk: number }>)
    .filter((c) => c.pk > 0).sort((a, b) => a.pk - b.pk).map((c) => c.name);

describe("DOD-AGENT-ID-JOINKEY-1 AC2 — the migration preserves and re-attributes every row", () => {
  it("backfills agent_id across all seven tables and copies every row", () => {
    const db = legacyDb();
    addAgent(db, "id-alice", "alice");
    addAgent(db, "id-bob", "bob");

    db.exec(`
      INSERT INTO sessions (session_id, agent_name, counterparty_pubkey, status, created_at, updated_at) VALUES ('s1','alice','cp',  'active',1,1);
      INSERT INTO sessions (session_id, agent_name, counterparty_pubkey, status, created_at, updated_at) VALUES ('s2','bob',  'cp2', 'sealed',1,1);
      INSERT INTO transcript (agent_name, session_id, sequence, direction, blob, created_at) VALUES ('alice','s1',0,'received',x'41',1);
      INSERT INTO contacts (agent_name, pubkey, added_at) VALUES ('alice','peer-1',1);
      INSERT INTO contacts (agent_name, pubkey, added_at) VALUES ('bob','peer-1',1);
      INSERT INTO message_watermarks (agent_name, session_id, last_delivered_seq) VALUES ('alice','s1',3);
      INSERT INTO session_tree_leaves (agent_name, session_id, leaf_index, leaf_kind, leaf_hash_hex, created_at) VALUES ('alice','s1',0,'msg','ab',1);
      INSERT INTO seal_interrupted_artifacts (agent_name, session_id, role, own_leaf, counterparty_leaf, merkle_root, nonce, created_at) VALUES ('bob','s2','responder','{}','{}','root','n',1);
      INSERT INTO retry_queue (session_id, agent_name, nonce_hex, content_blob, queued_at, position, awaiting_ack, content_hash_hex) VALUES ('s1','alice','aa',x'01',1,1,1,'aa');
      INSERT INTO retry_queue (session_id, nonce_hex, content_blob, queued_at, position) VALUES ('s9','bb',x'02',1,1);
    `);

    const { logger, events } = makeLogger();
    const res = migrateSessionTablesToAgentId(db as unknown as DaemonDatabase, logger);
    expect(res.migrated).toBe(true);

    // Every row survived, attributed to the right stable id.
    expect((db.prepare("SELECT agent_id FROM sessions WHERE session_id='s1'").get() as { agent_id: string }).agent_id).toBe("id-alice");
    expect((db.prepare("SELECT agent_id FROM sessions WHERE session_id='s2'").get() as { agent_id: string }).agent_id).toBe("id-bob");
    expect((db.prepare("SELECT agent_id FROM transcript").get() as { agent_id: string }).agent_id).toBe("id-alice");
    expect((db.prepare("SELECT COUNT(*) AS n FROM contacts").get() as { n: number }).n).toBe(2);
    expect((db.prepare("SELECT agent_id FROM seal_interrupted_artifacts").get() as { agent_id: string }).agent_id).toBe("id-bob");
    expect((db.prepare("SELECT last_delivered_seq FROM message_watermarks WHERE agent_id='id-alice'").get() as { last_delivered_seq: number }).last_delivered_seq).toBe(3);
    expect((db.prepare("SELECT COUNT(*) AS n FROM session_tree_leaves WHERE agent_id='id-alice'").get() as { n: number }).n).toBe(1);

    // retry_queue: the awaiting row resolves; the agent-LESS direct-retry row stays NULL, because
    // "not agent-scoped" is TRUE of it and must survive the migration.
    expect((db.prepare("SELECT agent_id FROM retry_queue WHERE nonce_hex='aa'").get() as { agent_id: string }).agent_id).toBe("id-alice");
    expect((db.prepare("SELECT agent_id FROM retry_queue WHERE nonce_hex='bb'").get() as { agent_id: string | null }).agent_id).toBeNull();

    // agent_name is gone from every child — it is a display attribute of `agents`, nowhere else.
    for (const t of SEVEN) expect(cols(db, t), `${t} must not carry agent_name`).not.toContain("agent_name");

    // SI: the observability AC — per-table row counts, at info.
    const ev = events.find((e) => e.event === "daemon.migration.agent_id_backfill");
    expect(ev, "the migration must log daemon.migration.agent_id_backfill").toBeDefined();
    expect(ev!.level).toBe("info");
    expect((ev!.context.rowCounts as Record<string, number>).sessions).toBe(2);
    expect((ev!.context.rowCounts as Record<string, number>).retry_queue).toBe(2);
  });

  it("a RETIRED agent's rows backfill to the retired id and never to the live reuser of its name", () => {
    const db = legacyDb();
    addAgent(db, "id-old", "ada", "retired");
    // The live 'ada' is a DIFFERENT identity that reused the freed name. Both rows exist, but only
    // the retired one has history — so the name is still unambiguous and the migration proceeds.
    db.exec("INSERT INTO contacts (agent_name, pubkey, added_at) VALUES ('ada','ghost-peer',1)");
    db.exec("INSERT INTO transcript (agent_name, session_id, sequence, direction, blob, created_at) VALUES ('ada','s1',0,'received',x'41',1)");

    migrateSessionTablesToAgentId(db as unknown as DaemonDatabase, makeLogger().logger);

    // The dead identity keeps its history — nothing is purged — and it now hangs off ITS id.
    expect((db.prepare("SELECT agent_id FROM contacts").get() as { agent_id: string }).agent_id).toBe("id-old");
    expect((db.prepare("SELECT agent_id FROM transcript").get() as { agent_id: string }).agent_id).toBe("id-old");
    // A new 'ada' (a fresh agent_id) simply never matches those rows. The hazard closes without a DELETE.
    addAgent(db, "id-new", "ada");
    expect((db.prepare("SELECT COUNT(*) AS n FROM contacts WHERE agent_id='id-new'").get() as { n: number }).n).toBe(0);
  });

  it("is idempotent — a second run is a no-op", () => {
    const db = legacyDb();
    addAgent(db, "id-alice", "alice");
    db.exec("INSERT INTO contacts (agent_name, pubkey, added_at) VALUES ('alice','p',1)");
    expect(migrateSessionTablesToAgentId(db as unknown as DaemonDatabase, makeLogger().logger).migrated).toBe(true);
    expect(migrateSessionTablesToAgentId(db as unknown as DaemonDatabase, makeLogger().logger).migrated).toBe(false);
    expect((db.prepare("SELECT COUNT(*) AS n FROM contacts").get() as { n: number }).n).toBe(1);
  });
});

describe("DOD-AGENT-ID-JOINKEY-1 AC2 — the migration REFUSES rather than guesses", () => {
  it("aborts on an AMBIGUOUS name (a retired name reused) and leaves the database untouched", () => {
    const db = legacyDb();
    // The exact retire-reuse state: two agent_ids, one name. Which identity owns 'ada's transcript?
    // It is genuinely undecidable, and a wrong answer binds one keypair's history to another.
    addAgent(db, "id-old", "ada", "retired");
    addAgent(db, "id-new", "ada");
    db.exec("INSERT INTO transcript (agent_name, session_id, sequence, direction, blob, created_at) VALUES ('ada','s1',0,'received',x'41',1)");

    const { logger, events } = makeLogger();
    expect(() => migrateSessionTablesToAgentId(db as unknown as DaemonDatabase, logger))
      .toThrow(/agent_id_backfill_ambiguous/);

    // ROLLED BACK: the legacy schema and the row are exactly as they were.
    expect(cols(db, "transcript")).toContain("agent_name");
    expect(cols(db, "transcript")).not.toContain("agent_id");
    expect((db.prepare("SELECT COUNT(*) AS n FROM transcript").get() as { n: number }).n).toBe(1);
    // It names the offender rather than failing mutely.
    expect(events.some((e) => e.event === "daemon.migration.agent_id_backfill.failed")).toBe(true);
  });

  it("aborts on an ORPHANED row whose agent_name matches no agent, and rolls the whole thing back", () => {
    const db = legacyDb();
    addAgent(db, "id-alice", "alice");
    db.exec("INSERT INTO contacts (agent_name, pubkey, added_at) VALUES ('alice','p',1)");
    // 'nobody' has no agents row. Its rows cannot be attributed to any identity.
    db.exec("INSERT INTO transcript (agent_name, session_id, sequence, direction, blob, created_at) VALUES ('nobody','s1',0,'received',x'41',1)");

    expect(() => migrateSessionTablesToAgentId(db as unknown as DaemonDatabase, makeLogger().logger))
      .toThrow(/agent_id_backfill_row_count_mismatch/);

    // ATOMICITY: `contacts` was rebuilt BEFORE `transcript` failed. It must be back to legacy shape.
    expect(cols(db, "contacts"), "an earlier table's rebuild must roll back with the failing one").toContain("agent_name");
    expect(cols(db, "contacts")).not.toContain("agent_id");
    expect((db.prepare("SELECT COUNT(*) AS n FROM contacts").get() as { n: number }).n).toBe(1);
    expect((db.prepare("SELECT COUNT(*) AS n FROM transcript").get() as { n: number }).n).toBe(1);
  });

  it("a non-null retry_queue.agent_name that resolves to nobody is fatal (NULL is fine, a lie is not)", () => {
    const db = legacyDb();
    db.exec("INSERT INTO retry_queue (session_id, agent_name, nonce_hex, content_blob, queued_at, position) VALUES ('s1','nobody','aa',x'01',1,1)");
    expect(() => migrateSessionTablesToAgentId(db as unknown as DaemonDatabase, makeLogger().logger))
      .toThrow(/agent_id_backfill_/);
    expect(cols(db, "retry_queue")).toContain("agent_name");
  });
});

describe("DOD-AGENT-ID-JOINKEY-1 AC2 — a MIGRATED database matches a FRESH one", () => {
  let tempDir = "";
  beforeEach(async () => { tempDir = await mkdtemp(join(tmpdir(), "joinkey-mig-")); });
  afterEach(async () => { await rm(tempDir, { recursive: true, force: true }); });

  /**
   * The migration pins its target DDL literally (a migration must not follow a moving schema). This
   * is the test that keeps the pinned copy honest: build a FRESH database the normal way, build an
   * OLD one and migrate it, and require the two to be structurally identical. If someone adds a
   * column to `session-node-manager` and forgets `agent-id-migration`, this goes red.
   */
  it("column sets and primary keys are identical for all seven tables", async () => {
    const freshMgr = new SessionNodeManager({ securityGateway: new PassthroughGatewayClient(), factory: new StubNodeFactory(), logger: makeLogger().logger, dbPath: join(tempDir, "fresh.db") });
    await freshMgr.initialize();
    const fresh = freshMgr.getDb();
    new RetryQueue(fresh, makeLogger().logger); // creates retry_queue in the re-keyed shape

    const migratedMgr = new SessionNodeManager({ securityGateway: new PassthroughGatewayClient(), factory: new StubNodeFactory(), logger: makeLogger().logger, dbPath: join(tempDir, "old.db") });
    await migratedMgr.initialize();
    const migrated = migratedMgr.getDb();
    // Tear the six back down to their legacy shape, plus a legacy retry_queue, then re-run init's
    // migration by calling it directly on this handle.
    for (const t of SEVEN) migrated.exec(`DROP TABLE IF EXISTS ${t}`);
    migrated.exec(LEGACY_DDL);
    migrated.prepare(
      `INSERT INTO agents (agent_id, agent_name, k_local_seed, k_local_pubkey, state, created_at, updated_at)
       VALUES ('id-a','alice',x'00','pub-a','created',1,1)`,
    ).run();
    migrated.exec("INSERT INTO contacts (agent_name, pubkey, added_at) VALUES ('alice','p',1)");
    // Replay the manager's FULL init migration sequence, in order: the join-key re-key, then the
    // DOD-TIER-1 contacts ADD COLUMN. `initialize()` runs both, so a faithful legacy replay must too —
    // otherwise `migrated` lacks the tier metadata that a fresh init now creates. This keeps the
    // fresh==migrated invariant honest against BOTH migrations, not just the re-key.
    migrateSessionTablesToAgentId(migrated, makeLogger().logger);
    migrateContactsAddTierMetadata(migrated, makeLogger().logger);
    // Replay the inline sessions ALTER migrations that initialize() applies incrementally.
    // Each is idempotent (duplicate column → swallowed), so adding a new column here keeps
    // fresh==migrated honest without touching the locked LEGACY_DDL.
    for (const ddl of [
      "ALTER TABLE sessions ADD COLUMN message_count INTEGER NOT NULL DEFAULT 0",
      "ALTER TABLE sessions ADD COLUMN interrupted_at TEXT",
      "ALTER TABLE sessions ADD COLUMN relay_peer_id TEXT",
      "ALTER TABLE sessions ADD COLUMN relay_addrs TEXT",
      "ALTER TABLE sessions ADD COLUMN seal_legibility TEXT",
      "ALTER TABLE sessions ADD COLUMN sealed_root_hex TEXT",
      "ALTER TABLE sessions ADD COLUMN counterparty_primary_pubkey TEXT",
      "ALTER TABLE sessions ADD COLUMN session_name TEXT",
      "ALTER TABLE sessions ADD COLUMN read_at INTEGER",
    ]) {
      try { migrated.exec(ddl); } catch { /* duplicate column — already applied */ }
    }
    new RetryQueue(migrated, makeLogger().logger);

    for (const t of SEVEN) {
      expect(cols(migrated, t), `${t}: migrated columns must equal fresh columns`).toEqual(cols(fresh, t));
      expect(pkOf(migrated, t), `${t}: migrated PRIMARY KEY must equal fresh PRIMARY KEY`).toEqual(pkOf(fresh, t));
    }

    // And the row survived the round trip, attributed correctly.
    expect((migrated.prepare("SELECT agent_id FROM contacts").get() as { agent_id: string }).agent_id).toBe("id-a");

    fresh.close();
    migrated.close();
  });

  it("the re-keyed retry_queue carries the agent-scoped unique index, and it is the CORRECT tuple", async () => {
    const mgr = new SessionNodeManager({ securityGateway: new PassthroughGatewayClient(), factory: new StubNodeFactory(), logger: makeLogger().logger, dbPath: join(tempDir, "rq.db") });
    await mgr.initialize();
    const db = mgr.getDb();
    new RetryQueue(db, makeLogger().logger);

    const idx = db.prepare("SELECT name, sql FROM sqlite_master WHERE type='index' AND tbl_name='retry_queue'")
      .all() as unknown as Array<{ name: string; sql: string | null }>;
    const unique = idx.find((i) => i.name === "retry_queue_agent_session_nonce");
    expect(unique, "retry_queue must have the agent-scoped unique index").toBeDefined();
    expect(unique!.sql).toMatch(/COALESCE\(agent_id, ''\)/);
    expect(unique!.sql).toMatch(/session_id/);
    expect(unique!.sql).toMatch(/nonce_hex/);

    // Two agents, one session, identical content → both rows land (the collision DOD-LOOP-1 lost).
    db.exec("INSERT INTO retry_queue (session_id, agent_id, nonce_hex, content_blob, queued_at, position, awaiting_ack) VALUES ('s','a','n',x'01',1,1,1)");
    db.exec("INSERT INTO retry_queue (session_id, agent_id, nonce_hex, content_blob, queued_at, position, awaiting_ack) VALUES ('s','b','n',x'01',1,1,1)");
    expect((db.prepare("SELECT COUNT(*) AS n FROM retry_queue").get() as { n: number }).n).toBe(2);

    // But an agent-LESS direct-retry row keeps its old (session_id, nonce_hex) dedup: NULLs are
    // DISTINCT in a bare UNIQUE, so the index folds them through COALESCE into one bucket.
    db.exec("INSERT INTO retry_queue (session_id, nonce_hex, content_blob, queued_at, position) VALUES ('d','x',x'01',1,1)");
    expect(() =>
      db.exec("INSERT INTO retry_queue (session_id, nonce_hex, content_blob, queued_at, position) VALUES ('d','x',x'01',1,2)"),
    ).toThrow();

    db.close();
  });
});
