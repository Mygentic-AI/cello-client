/**
 * THE SESSION SALT SURVIVES AN UPGRADE — Decisions Carried #8, and the upgrade test the DoD requires
 * for any client-side migration.
 *
 * ─── Why a column test is not enough here ──────────────────────────────────────────────────────
 *
 * `dod-agent-id-joinkey-migration` already asserts that a MIGRATED database has the same column SET
 * as a FRESH one, and that guard is what caught `content_salt` missing from the rebuild. But a
 * matching column set says nothing about the VALUES: a rebuild can create the column and copy no
 * data into it, and every existing assertion would still pass.
 *
 ─── ⚠️ WHAT THIS TEST ACTUALLY GUARDS, corrected after review (F8) ───────────────────────────
 *
 * The header used to sell a scarier story than the code can produce: that a dropped salt makes the
 * "does this session already have a salt?" lookup mint a fresh one and split the transcript. **That
 * lookup does not exist yet** (`SEALWIRE-1` will build it), and the fixture's state is unreachable
 * in production anyway — `needsRekey` returns true only when `sessions` lacks `agent_id`, and any
 * build able to WRITE `content_salt` also contains the agent-id migration and runs it first in the
 * same `initialize()`. So "no agent_id AND a populated content_salt" cannot occur on an operator's
 * machine.
 *
 * The REAL harm of omitting a column from the rebuild is more mundane and still worth a guard: the
 * ALTER has already run that boot, so it will not re-run — the process continues with the column
 * ABSENT, and the first statement naming `content_salt` fails with `no such column` on every send in
 * a salted session until the daemon is restarted.
 *
 * The test earns its place because it SURVIVES THE REVERT TEST: remove `content_salt` from
 * `createSql` and the SELECT throws `no such column`. That is genuine regression coverage of the
 * omission — via the column's existence rather than its values — and the value assertions cost
 * nothing on top. Kept, with the story corrected rather than the test deleted.
 *
 * ─── And it covers the other lane's columns too ────────────────────────────────────────────────
 *
 * `frozen_at` / `frozen_reason` are `CELLO_Support`'s (`DOD-M15-FREEZE-STATUS-1`), carried in this
 * migration because two lanes must not both edit `session-node-manager.ts`. Their failure mode on a
 * dropped value is just as specific: an upgrade would UN-FREEZE a session that was frozen because a
 * party signed with a key that was not the counterparty's. Asserted here because I carried the
 * columns, so the guarantee is mine to hold even though the behaviour is theirs.
 */

import { describe, it, expect } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { migrateSessionTablesToAgentId } from "../agent-id-migration.js";
import { ensureIdentitySchema } from "../db-identity-store.js";
import type { DaemonDatabase, Logger } from "../types.js";

/** Silent — this file asserts the DATA survives; the migration's own logging is covered elsewhere. */
const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} } as unknown as Logger;

const SALT = Buffer.from("11".repeat(32), "hex");

/**
 * A legacy (pre-`agent_id`) database whose sessions table ALREADY carries the new columns with
 * values in them.
 *
 * That combination is the one where data can be lost: the rebuild copies the INTERSECTION of the old
 * and new column lists, so a column present in the old table but missing from `createSql` is
 * silently dropped along with everything in it.
 */
function legacyDbWithSalt(): DatabaseSync {
  const db = new DatabaseSync(":memory:");
  ensureIdentitySchema(db as unknown as DaemonDatabase);
  db.exec(`
    CREATE TABLE sessions (
      session_id TEXT NOT NULL, agent_name TEXT NOT NULL, counterparty_pubkey TEXT NOT NULL,
      status TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
      message_count INTEGER NOT NULL DEFAULT 0, interrupted_at TEXT, relay_peer_id TEXT,
      relay_addrs TEXT, seal_legibility TEXT, sealed_root_hex TEXT, counterparty_primary_pubkey TEXT,
      content_salt BLOB, frozen_at INTEGER, frozen_reason TEXT,
      PRIMARY KEY (agent_name, session_id));
  `);
  db.prepare(
    `INSERT INTO agents (agent_id, agent_name, k_local_seed, k_local_pubkey, state, created_at, updated_at)
     VALUES (?, ?, x'00', ?, 'created', 1, 1)`,
  ).run("id-alice", "alice", "pub-alice");
  db.prepare(
    `INSERT INTO sessions (session_id, agent_name, counterparty_pubkey, status, created_at, updated_at,
                           content_salt, frozen_at, frozen_reason)
     VALUES (?, 'alice', 'cp', 'active', 1, 1, ?, ?, ?)`,
  ).run("sess-1", SALT, 1700000000000, "counterparty_key_mismatch");
  return db;
}

describe("Decisions Carried #8: the session salt survives the agent-id rebuild", () => {
  it("★ the salt BYTES survive, not merely the column", () => {
    const db = legacyDbWithSalt();
    migrateSessionTablesToAgentId(db as unknown as DaemonDatabase, silent);

    const row = db.prepare("SELECT content_salt FROM sessions WHERE session_id = 'sess-1'").get() as
      { content_salt: Uint8Array | null };
    expect(
      row.content_salt,
      "the rebuild dropped the salt. Every leaf hashed under it is now unverifiable, and the next " +
        "'does this session have a salt?' lookup will mint a fresh one and split the transcript at " +
        "the upgrade — silently, on a session that looks healthy.",
    ).not.toBeNull();
    expect(Buffer.from(row.content_salt!).toString("hex")).toBe(SALT.toString("hex"));
  });

  it("★ the other lane's freeze columns survive too — I carried them, so I hold the guarantee", () => {
    /**
     * `DOD-M15-FREEZE-STATUS-1` is `CELLO_Support`'s line; the columns ride in this migration only
     * because two lanes must not both edit `session-node-manager.ts`. A dropped value here would
     * UN-FREEZE a session frozen because a party signed with a key that was not the counterparty's —
     * on the one boot that carries the upgrade, which is precisely the restart the column exists to
     * survive.
     */
    const db = legacyDbWithSalt();
    migrateSessionTablesToAgentId(db as unknown as DaemonDatabase, silent);

    const row = db.prepare("SELECT frozen_at, frozen_reason FROM sessions WHERE session_id = 'sess-1'").get() as
      { frozen_at: number | null; frozen_reason: string | null };
    expect(row.frozen_at).toBe(1700000000000);
    expect(row.frozen_reason).toBe("counterparty_key_mismatch");
  });

  it("a session that never had a salt migrates to NULL, not to a fabricated value", () => {
    /**
     * The counterexample. Sessions opened before the column existed keep the unsalted hash, and the
     * absence must stay an absence — a migration that invented a salt would make those transcripts
     * unverifiable in the opposite direction.
     */
    const db = legacyDbWithSalt();
    db.prepare(
      `INSERT INTO sessions (session_id, agent_name, counterparty_pubkey, status, created_at, updated_at)
       VALUES ('sess-old', 'alice', 'cp', 'active', 1, 1)`,
    ).run();
    migrateSessionTablesToAgentId(db as unknown as DaemonDatabase, silent);

    const row = db.prepare("SELECT content_salt FROM sessions WHERE session_id = 'sess-old'").get() as
      { content_salt: Uint8Array | null };
    expect(row.content_salt).toBeNull();
  });
});
