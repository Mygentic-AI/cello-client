/**
 * DOD-TIER-1 (Step 1) — the contacts ADD COLUMN migration, against a REAL on-disk SQLCipher DB.
 *
 * This is the flip side of the join-key migration's discipline. That one REBUILT tables and pinned
 * its own DDL; this one only ADD COLUMNs (tier / provenance / last_offered_moniker / away_message)
 * onto the already-agent_id-keyed `contacts` table — no rebuild, no PK change. It runs AFTER
 * `migrateSessionTablesToAgentId`, so it never has to appear in that migration's pinned DDL.
 *
 * The properties that make it trustworthy, each asserted below:
 *
 *   1. NO column DEFAULT. A `DEFAULT` would give every EXISTING row a value the instant the column
 *      is added, so the grandfather backfill (`UPDATE … WHERE tier IS NULL`) would then match
 *      NOTHING and silently demote every auto-accepting contact to UNKNOWN. The column must be added
 *      with no default → existing rows read NULL → the explicit backfill promotes them to WHITELISTED.
 *   2. Grandfather. An existing contact (they were auto-accepting under the binary whitelist) migrates
 *      to WHITELISTED, preserving today's behaviour (design §1). A row born on this key survives.
 *   3. Idempotent, and grandfather is ONE-TIME. Re-running the migration is a no-op; a NULL-tier row
 *      inserted AFTER the column already exists is NOT re-grandfathered (the promotion is tied to the
 *      column's birth, not to any later NULL — a later NULL is normalized to UNKNOWN at read time,
 *      the tighter default, never silently promoted).
 *   4. Fresh == migrated. A database that reached this schema by migration is structurally identical
 *      to one created fresh — the same guarantee the join-key test enforces, so a new machine and an
 *      upgraded one agree.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { openTestDb } from "./helpers/encrypted-db.js";
import { seedAgents } from "./helpers/seed-agents.js";
import {
  TIER,
  migrateContactsAddTierMetadata,
} from "../contacts-tier-migration.js";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { SessionNodeManager, type ISessionNodeFactory, type SessionNodeConfig } from "../session-node-manager.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { Logger } from "../types.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };

class StubNodeFactory implements ISessionNodeFactory {
  async createNode(_c: SessionNodeConfig): Promise<CelloNode> {
    return {
      getPeerId: () => "stub",
      listenAddresses: () => ["/ip4/127.0.0.1/tcp/0"],
      async start() {}, async stop() {},
      async dial() { return { peerId: "remote" }; },
      async handle() {}, getProtocols: () => [],
      getConnections: () => [], onPeerConnect() {}, onPeerDisconnect() {},
      getDialability: () => ({ dialable: false, publicAddr: null }),
      onDialabilityChange: () => () => {},
      async newStream() { return { send() {}, async close() {}, abort() {}, status: "open" }; },
    } as unknown as CelloNode;
  }
}

/** The pre-tier `contacts` shape — exactly what daemon@0.0.45 (173d34f) ships: agent_id-keyed,
 *  carrying `moniker`, with NO tier metadata. "Legacy" for THIS unit is current production. */
function createPreTierContacts(db: DaemonDatabase): void {
  db.exec(`
    CREATE TABLE contacts (
      agent_id TEXT NOT NULL,
      pubkey TEXT NOT NULL,
      added_at INTEGER NOT NULL,
      moniker TEXT,
      PRIMARY KEY (agent_id, pubkey)
    )
  `);
}

function contactColumns(db: DaemonDatabase): Array<{ name: string; type: string; dflt_value: unknown }> {
  return db.prepare("PRAGMA table_info(contacts)").all() as unknown as Array<{
    name: string; type: string; dflt_value: unknown;
  }>;
}

describe("DOD-TIER-1 — contacts tier metadata migration (real SQLCipher)", () => {
  let tempDir: string;
  beforeEach(async () => { tempDir = await mkdtemp(join(tmpdir(), "dod-tier-1-")); });
  afterEach(async () => { await rm(tempDir, { recursive: true, force: true }); });

  it("adds the four columns with NO default (a default would defeat the grandfather backfill)", () => {
    const dbPath = join(tempDir, "cols.db");
    const db = openTestDb(dbPath);
    createPreTierContacts(db);
    migrateContactsAddTierMetadata(db, silent);

    const cols = contactColumns(db);
    const byName = new Map(cols.map((c) => [c.name, c]));
    for (const name of ["tier", "provenance", "last_offered_moniker", "away_message"]) {
      expect(byName.has(name), `column ${name} must exist`).toBe(true);
      expect(byName.get(name)!.dflt_value, `column ${name} must have NO default`).toBeNull();
    }
    db.close();
  });

  it("grandfathers an existing contact to WHITELISTED (preserves auto-accept — design §1)", () => {
    const dbPath = join(tempDir, "grand.db");
    const db = openTestDb(dbPath);
    createPreTierContacts(db);
    db.prepare("INSERT INTO contacts (agent_id, pubkey, added_at) VALUES (?, ?, ?)")
      .run("agentX", "oldfriendpubkey", 111);

    migrateContactsAddTierMetadata(db, silent);

    const row = db.prepare("SELECT tier FROM contacts WHERE agent_id = ? AND pubkey = ?")
      .get("agentX", "oldfriendpubkey") as { tier: number };
    expect(row.tier).toBe(TIER.WHITELISTED);
    db.close();
  });

  it("is idempotent and grandfathers ONE-TIME (a NULL inserted after the column exists is not re-promoted)", () => {
    const dbPath = join(tempDir, "idem.db");
    const db = openTestDb(dbPath);
    createPreTierContacts(db);
    db.prepare("INSERT INTO contacts (agent_id, pubkey, added_at) VALUES (?, ?, ?)")
      .run("agentX", "grandfathered", 111);

    migrateContactsAddTierMetadata(db, silent); // first run: adds columns, grandfathers the row → WHITELISTED

    // A raw NULL-tier row inserted AFTER the column already exists — simulates a row the grandfather
    // must NOT touch (only column-birth promotes; a later NULL is a read-time UNKNOWN, never promoted).
    db.prepare("INSERT INTO contacts (agent_id, pubkey, added_at, tier) VALUES (?, ?, ?, NULL)")
      .run("agentX", "postmigrate", 222);

    migrateContactsAddTierMetadata(db, silent); // second run: no-op, MUST NOT re-grandfather

    const grand = db.prepare("SELECT tier FROM contacts WHERE pubkey = 'grandfathered'").get() as { tier: number };
    const post = db.prepare("SELECT tier FROM contacts WHERE pubkey = 'postmigrate'").get() as { tier: number | null };
    expect(grand.tier).toBe(TIER.WHITELISTED);
    expect(post.tier, "a NULL inserted after column-birth must stay NULL (normalized to UNKNOWN at read)").toBeNull();
    // Columns added exactly once — no duplicate-column error on the second run means idempotent.
    const tierCols = contactColumns(db).filter((c) => c.name === "tier");
    expect(tierCols.length).toBe(1);
    db.close();
  });

  it("is ATOMIC: if the grandfather backfill fails, the ADD COLUMNs roll back too (no half-migrated state)", () => {
    // F1 (review): the ALTERs and the backfill must commit together. If they didn't, a crash after
    // the `tier` ALTER but before the backfill would leave the column present with the grandfather
    // never run — and the one-time gate would skip it FOREVER, silently demoting every legacy contact.
    // Proof: inject a failure into the backfill and assert the whole thing rolled back — the `tier`
    // column must NOT exist afterward, so a clean re-run does the entire add+grandfather.
    const dbPath = join(tempDir, "atomic.db");
    const real = openTestDb(dbPath);
    createPreTierContacts(real);
    real.prepare("INSERT INTO contacts (agent_id, pubkey, added_at) VALUES (?, ?, ?)").run("agentX", "legacy", 111);

    // A minimal wrapper (migrate only uses exec + prepare) that fails the grandfather UPDATE. An
    // explicit delegation, not a Proxy — the real DB has private fields, so its methods must run with
    // the real object as `this`, which `real.exec(sql)` / `real.prepare(sql)` preserve.
    const failingBackfill = {
      exec: (sql: string) => real.exec(sql),
      prepare: (sql: string) =>
        /UPDATE\s+contacts\s+SET\s+tier/i.test(sql)
          ? { run: () => { throw new Error("injected backfill failure"); } }
          : real.prepare(sql),
    } as unknown as DaemonDatabase;

    expect(() => migrateContactsAddTierMetadata(failingBackfill, silent)).toThrow(/injected backfill failure/);

    // Rolled back: the tier column must be gone, and the legacy row untouched (still one row, no tier).
    const cols = contactColumns(real).map((c) => c.name);
    expect(cols).not.toContain("tier");
    expect(cols).not.toContain("provenance");

    // And a clean re-run (no injection) now does the WHOLE thing: columns added AND row grandfathered.
    migrateContactsAddTierMetadata(real, silent);
    const row = real.prepare("SELECT tier FROM contacts WHERE pubkey = 'legacy'").get() as { tier: number };
    expect(row.tier).toBe(TIER.WHITELISTED);
    real.close();
  });

  it("fresh == migrated: a migrated contacts schema is structurally identical to a fresh one", async () => {
    // MIGRATED: pre-seed a legacy contacts (+ a row + the agent) then let the manager initialize().
    const oldPath = join(tempDir, "old.db");
    const seed = openTestDb(oldPath);
    createPreTierContacts(seed);
    const ids = await seedAgents(seed, ["ada"]);
    seed.prepare("INSERT INTO contacts (agent_id, pubkey, added_at) VALUES (?, ?, ?)")
      .run(ids.get("ada"), "somebodypubkey", 111);
    seed.close();
    const migratedMgr = new SessionNodeManager({ securityGateway: new PassthroughGatewayClient(), factory: new StubNodeFactory(), logger: silent, dbPath: oldPath });
    await migratedMgr.initialize();

    // FRESH: a brand-new manager, no pre-existing contacts.
    const freshPath = join(tempDir, "fresh.db");
    const freshMgr = new SessionNodeManager({ securityGateway: new PassthroughGatewayClient(), factory: new StubNodeFactory(), logger: silent, dbPath: freshPath });
    await freshMgr.initialize();

    const norm = (db: DaemonDatabase) =>
      contactColumns(db).map((c) => `${c.name}:${c.type}:${c.dflt_value ?? "∅"}`).sort();
    const migratedCols = norm(openTestDb(oldPath));
    const freshCols = norm(openTestDb(freshPath));
    expect(freshCols).toEqual(migratedCols);
    // And the grandfathered row really did migrate to WHITELISTED via the full init path.
    expect(migratedMgr.getTier("ada", "somebodypubkey")).toBe(TIER.WHITELISTED);

    await migratedMgr.stop?.();
    await freshMgr.stop?.();
  });
});
