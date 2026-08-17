/**
 * DOD-AGENT-ID-JOINKEY-1 — finish the migration REMOVE-001 started.
 *
 * `agent_name` was the original PRIMARY KEY of `agents`. REMOVE-001 added the stable surrogate
 * `agent_id` **specifically to make names reusable** (retire keeps the rows and FREES the name), and
 * migrated only the parent table. SEVEN child tables were left joining on the column that had just
 * become a mutable, reusable attribute:
 *
 *   sessions · seal_interrupted_artifacts · session_tree_leaves · transcript · message_watermarks ·
 *   contacts · retry_queue
 *
 * (`retry_queue` is the seventh — it predates REMOVE-001, so REMOVE-001 skipped seven, not six.)
 *
 * The hazard is not stale data. Retire an agent, create a new one with the freed name — a different
 * agent_id and a different K_local keypair — and every `WHERE agent_name = ?` hands the new identity
 * the dead one's transcript, its contact whitelist (an ACCESS-CONTROL list), and its interrupted
 * sessions. Resuming one would seal with the wrong keypair.
 *
 * This module carries `agent_id` into all seven and demotes `agent_name` to what it always was after
 * REMOVE-001: a display label on the parent table, with exactly one source of truth.
 *
 * ── Why this is safe, and why it deletes nothing ────────────────────────────────────────────────
 * Purely client-side. The directory has no `agent_name` column and never sees one (AC1's wire proof:
 * parties are identified by pubkey + session_id; a name reaches the wire only as the self-declared
 * `offered_moniker` display label, which this migration does not touch). No row content is destroyed:
 * every row is COPIED into the new table before the old one is dropped. Retire-reuse orphans need no
 * purge either — once joined on `agent_id`, a new same-named agent simply never matches them.
 *
 * ── Why one transaction ─────────────────────────────────────────────────────────────────────────
 * SQLite cannot alter a PRIMARY KEY, so each table must be REBUILT (create, copy, drop, rename).
 * SQLite DDL is transactional, so all seven rebuilds run inside ONE `BEGIN…COMMIT`: a crash rolls the
 * entire migration back atomically and the daemon reopens on the untouched original schema. There is
 * no half-migrated state to recover from, and therefore no recovery code to get wrong.
 *
 * ── Why the target schema is pinned literally here ──────────────────────────────────────────────
 * The DDL below duplicates what `session-node-manager` / `retry-queue` create on a fresh database.
 * That duplication is DELIBERATE. A migration must migrate to a FIXED target: if it read its target
 * from the live schema, a future column added upstream would silently change what this migration
 * produces on an old database, and the two shapes would drift apart unnoticed. The drift is instead
 * caught by a test that asserts a MIGRATED database's schema is byte-identical to a FRESH one.
 */

import type { Logger } from "./types.js";
import { withForeignKeysOff, type DaemonDatabase } from "./sqlcipher-db.js";

/** A table that must be re-keyed, with the exact shape it is re-keyed TO. */
interface RekeyTarget {
  readonly table: string;
  /** DDL for the rebuilt table, parameterised only by its name. */
  readonly createSql: (name: string) => string;
  /** Indexes to (re)create on the rebuilt table. */
  readonly indexSql: (name: string) => string[];
  /**
   * `strict` — `agent_name` is NOT NULL on this table, so EVERY row must resolve to an agent_id.
   * `nullable` — `retry_queue.agent_name` is nullable by design (legacy direct-retry rows are not
   * agent-scoped). NULL stays NULL: it means "not agent-scoped", which is TRUE and must survive.
   * Only a NON-NULL name that fails to resolve is a fatal, unresolvable row.
   */
  readonly backfill: "strict" | "nullable";
}

/**
 * EVERY COLUMN THE INLINE ALTERs ADD MUST APPEAR IN THE createSql BELOW.
 *
 * `initialize()` runs the ALTERs first and this rebuild second, and the rebuild carries only the
 * INTERSECTION of the old and new column sets. A column the ALTERs add and a createSql omits is
 * therefore DELETED on the one boot where a legacy database upgrades — silently, unrecoverably,
 * on an operator's machine. `sessions.read_at` was missing for exactly that reason: every dismissal
 * flag would have been dropped, after which `getEndedUnread` (which filters on `read_at IS NULL`)
 * throws `no such column` for the rest of that process.
 *
 * The parity test guards this, but only because it replays the ALTERs BEFORE the re-key, in the
 * order `initialize()` uses. Replaying them afterwards puts the column back and the comparison
 * passes over the top of the loss — which is how this survived.
 */
const REKEY_TARGETS: readonly RekeyTarget[] = [
  {
    table: "sessions",
    backfill: "strict",
    createSql: (t) => `
      CREATE TABLE ${t} (
        session_id TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        counterparty_pubkey TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        message_count INTEGER NOT NULL DEFAULT 0,
        interrupted_at TEXT,
        relay_peer_id TEXT,
        relay_addrs TEXT,
        seal_legibility TEXT,
        sealed_root_hex TEXT,
        counterparty_primary_pubkey TEXT,
        session_name TEXT,
        read_at INTEGER,
        counterparty_abandoned_at INTEGER,
        interrupted_by TEXT,
        PRIMARY KEY (agent_id, session_id)
      )`,
    indexSql: () => [],
  },
  {
    table: "seal_interrupted_artifacts",
    backfill: "strict",
    createSql: (t) => `
      CREATE TABLE ${t} (
        agent_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        role TEXT NOT NULL,
        own_leaf TEXT NOT NULL,
        counterparty_leaf TEXT NOT NULL,
        merkle_root TEXT NOT NULL,
        nonce TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (agent_id, session_id)
      )`,
    indexSql: () => [],
  },
  {
    table: "session_tree_leaves",
    backfill: "strict",
    createSql: (t) => `
      CREATE TABLE ${t} (
        agent_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        leaf_index INTEGER NOT NULL,
        leaf_kind TEXT NOT NULL,
        leaf_hash_hex TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (agent_id, session_id, leaf_index)
      )`,
    indexSql: () => [],
  },
  {
    table: "transcript",
    backfill: "strict",
    createSql: (t) => `
      CREATE TABLE ${t} (
        agent_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        sequence INTEGER NOT NULL,
        direction TEXT NOT NULL,
        blob BLOB NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (agent_id, session_id, sequence, direction)
      )`,
    indexSql: () => [],
  },
  {
    table: "message_watermarks",
    backfill: "strict",
    createSql: (t) => `
      CREATE TABLE ${t} (
        agent_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        last_delivered_seq INTEGER NOT NULL,
        PRIMARY KEY (agent_id, session_id)
      )`,
    indexSql: () => [],
  },
  {
    table: "contacts",
    backfill: "strict",
    createSql: (t) => `
      CREATE TABLE ${t} (
        agent_id TEXT NOT NULL,
        pubkey TEXT NOT NULL,
        added_at INTEGER NOT NULL,
        moniker TEXT,
        PRIMARY KEY (agent_id, pubkey)
      )`,
    indexSql: () => [],
  },
  {
    // The SEVENTH. DOD-LOOP-1 added `agent_name` here so two of the operator's agents could hold
    // awaiting content for the SAME session_id without colliding — then left the agent OUT of the
    // uniqueness constraint, which stayed `UNIQUE(session_id, nonce_hex)`. For an awaiting row,
    // nonce_hex IS the content hash, so two local agents parking identical content in one session
    // collided, and the collision was swallowed into memory and lost on the next restart.
    //
    // The correct constraint falls out of the re-key. It is expressed as a UNIQUE INDEX over
    // COALESCE(agent_id, '') rather than a table constraint, because SQLite treats NULLs as DISTINCT
    // in a UNIQUE constraint: with a bare UNIQUE(agent_id, session_id, nonce_hex), the legacy
    // agent-less direct-retry rows (agent_id NULL) would lose the (session_id, nonce_hex) dedup they
    // have always had. COALESCE folds every agent-less row into one bucket, preserving exactly the
    // old semantics for them while giving each agent its own namespace.
    table: "retry_queue",
    backfill: "nullable",
    createSql: (t) => `
      CREATE TABLE ${t} (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id      TEXT    NOT NULL,
        agent_id        TEXT,
        nonce_hex       TEXT    NOT NULL,
        content_blob    BLOB    NOT NULL,
        queued_at       INTEGER NOT NULL,
        attempts        INTEGER NOT NULL DEFAULT 1,
        position        INTEGER NOT NULL,
        awaiting_ack    INTEGER NOT NULL DEFAULT 0,
        content_hash_hex TEXT
      )`,
    indexSql: (t) => [
      `CREATE INDEX IF NOT EXISTS retry_queue_by_session_position ON ${t}(session_id, position ASC)`,
      `CREATE UNIQUE INDEX IF NOT EXISTS retry_queue_agent_session_nonce ON ${t}(COALESCE(agent_id, ''), session_id, nonce_hex)`,
    ],
  },
] as const;

export interface AgentIdMigrationResult {
  readonly migrated: boolean;
  /** Rows copied, per rebuilt table. Absent tables are omitted. */
  readonly rowCounts: Readonly<Record<string, number>>;
}

function columnsOf(db: DaemonDatabase, table: string): string[] {
  return (db.prepare(`PRAGMA table_info(${table})`).all() as unknown as Array<{ name: string }>).map((c) => c.name);
}

function tableExists(db: DaemonDatabase, table: string): boolean {
  return (
    db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(table) !== undefined
  );
}

/**
 * The `agent_name → agent_id` map, over ALL agent rows INCLUDING retired ones (a retired agent's rows
 * must backfill to its OWN id and then sit inert — never be re-attributed to the live agent that
 * reused its name).
 *
 * If any name resolves to more than one agent_id the map is AMBIGUOUS and the migration ABORTS. It
 * does not guess, does not prefer the newest, does not prefer the oldest. A wrong attribution here
 * would silently bind one identity's transcript, contacts and interrupted sessions to a DIFFERENT
 * keypair — which is precisely the defect this migration exists to remove, except made permanent,
 * unauditable, and blessed by a migration. A loud abort costs a wipe on a single-operator machine; a
 * silent guess costs correctness forever.
 *
 * (A timestamp-based disambiguation is available in principle — rows written after the new agent's
 * creation must belong to it, since a retired agent cannot write. It is deliberately NOT used: it
 * depends on all seven tables carrying a trustworthy timestamp, and cleverness buys nothing on a
 * database we would happily wipe.)
 */
function buildNameToAgentId(db: DaemonDatabase): Map<string, string> {
  const rows = db
    .prepare("SELECT agent_name, agent_id FROM agents")
    .all() as unknown as Array<{ agent_name: string; agent_id: string }>;

  const map = new Map<string, string>();
  const ambiguous = new Set<string>();
  for (const r of rows) {
    if (map.has(r.agent_name)) ambiguous.add(r.agent_name);
    map.set(r.agent_name, r.agent_id);
  }
  if (ambiguous.size > 0) {
    throw new Error(
      `agent_id_backfill_ambiguous: agent name(s) [${[...ambiguous].sort().join(", ")}] resolve to more ` +
        `than one agent_id (a retired agent's name was reused). The migration cannot know which identity ` +
        `owns the existing session rows and refuses to guess — attributing them to the wrong keypair is ` +
        `the very defect it exists to remove. Resolve by hand or start from a fresh database.`,
    );
  }
  return map;
}

/** Does this table still need re-keying? True iff it exists and has no `agent_id` column. */
function needsRekey(db: DaemonDatabase, table: string): boolean {
  if (!tableExists(db, table)) return false;
  return !columnsOf(db, table).includes("agent_id");
}

/**
 * Re-key the seven child tables from `agent_name` to `agent_id`. Idempotent: a table that already has
 * an `agent_id` column is skipped, so a second call is a no-op. All rebuilds share ONE transaction.
 *
 * Throws (leaving the database untouched) on:
 *   - an ambiguous `agent_name → agent_id` map (a reused retired name),
 *   - any row whose non-null `agent_name` does not resolve to an agent,
 *   - any row count that does not match pre-migration.
 *
 * Never half-commits, never silently drops a row, never invents an agent_id.
 */
export function migrateSessionTablesToAgentId(db: DaemonDatabase, logger: Logger): AgentIdMigrationResult {
  const pending = REKEY_TARGETS.filter((t) => needsRekey(db, t.table));
  if (pending.length === 0) return { migrated: false, rowCounts: {} };

  // Ambiguity is checked BEFORE the transaction opens: nothing has been touched when it throws. It
  // is logged with the same failure event as an in-transaction abort — a refusal to migrate is a
  // loud event regardless of WHERE in the process it was detected.
  let nameToId: Map<string, string>;
  try {
    nameToId = buildNameToAgentId(db);
  } catch (err) {
    logger.error("daemon.migration.agent_id_backfill.failed", {
      tables: pending.map((t) => t.table),
      reason: err instanceof Error ? err.message : String(err),
    });
    throw err;
  }

  const before = new Map<string, number>();
  for (const t of pending) {
    before.set(t.table, (db.prepare(`SELECT COUNT(*) AS n FROM ${t.table}`).get() as { n: number }).n);
  }

  const rowCounts: Record<string, number> = {};

  // FOREIGN KEYS OFF, OUTSIDE THE TRANSACTION — and it must be outside, or it does nothing.
  //
  // `contacts` is one of the tables rebuilt below, and it is the FK PARENT of
  // `contact_trust_signals` (M10 / DOD-STORE-CLIENT-1). Since M10-D19 turned FK enforcement ON,
  // `DROP TABLE contacts` is an implicit DELETE that fires ON DELETE CASCADE and silently empties
  // every received trust signal on every agent. The row-count guards below would not notice: they
  // count `contacts`, not its children.
  //
  // And `PRAGMA foreign_keys` is a NO-OP inside a transaction — SQLite ignores it without a word —
  // so disabling FKs after `BEGIN` (the intuitive place) would look correct and cascade anyway.
  // `withForeignKeysOff` toggles it here, VERIFIES it took effect, and runs `PRAGMA
  // foreign_key_check` on the way out so a rebuild that leaves a dangling reference fails loudly
  // instead of surfacing as a mystery insert failure days later.
  return withForeignKeysOff(db, logger, () => {
    db.exec("BEGIN");
    try {
      for (const target of pending) {
        const oldCols = columnsOf(db, target.table);
        const tmp = `${target.table}_rekey_new`;

        db.exec(target.createSql(tmp));

        // Copy every column the OLD table has that the NEW table also has (minus agent_name, which is
        // replaced by agent_id). A pre-DOD-LOOP-1 retry_queue lacks agent_name/awaiting_ack entirely;
        // taking the intersection handles every historical shape without a per-version special case.
        const newCols = columnsOf(db, tmp);
        const carried = oldCols.filter((c) => c !== "agent_name" && c !== "id" && newCols.includes(c));

        const hasName = oldCols.includes("agent_name");
        if (hasName) {
          // Resolve through a JOIN on the parent so the mapping is the database's, not this process's.
          // An unresolvable row is DROPPED by the inner join and caught by the count check below —
          // for `strict` tables. For `nullable` (retry_queue), a NULL name must survive, so LEFT JOIN.
          const join = target.backfill === "strict" ? "JOIN" : "LEFT JOIN";
          db.exec(
            `INSERT INTO ${tmp} (agent_id${carried.length ? ", " + carried.join(", ") : ""})
             SELECT a.agent_id${carried.length ? ", " + carried.map((c) => `t.${c}`).join(", ") : ""}
             FROM ${target.table} t ${join} agents a ON a.agent_name = t.agent_name`,
          );
        } else {
          // No name to resolve (pre-DOD-LOOP-1 retry_queue): agent_id stays NULL — "not agent-scoped".
          if (target.backfill === "strict") {
            throw new Error(
              `agent_id_backfill_impossible: table '${target.table}' has neither agent_name nor agent_id`,
            );
          }
          db.exec(
            `INSERT INTO ${tmp} (${carried.join(", ")}) SELECT ${carried.map((c) => `t.${c}`).join(", ")} FROM ${target.table} t`,
          );
        }

        const after = (db.prepare(`SELECT COUNT(*) AS n FROM ${tmp}`).get() as { n: number }).n;
        const expected = before.get(target.table)!;
        if (after !== expected) {
          throw new Error(
            `agent_id_backfill_row_count_mismatch: table '${target.table}' had ${expected} row(s) before and ` +
              `${after} after the copy. A row failed to resolve to an agent_id (orphaned ${target.table}.agent_name ` +
              `with no matching agents row), or a name matched more than one agent. Refusing to commit.`,
          );
        }

        // Completeness. `strict` → every row must carry an agent_id. `nullable` → only rows that HAD a
        // name must; a row that was always agent-less legitimately stays NULL.
        const unresolved =
          target.backfill === "strict"
            ? (db.prepare(`SELECT COUNT(*) AS n FROM ${tmp} WHERE agent_id IS NULL`).get() as { n: number }).n
            : hasName
              ? (
                  db
                    .prepare(
                      `SELECT COUNT(*) AS n FROM ${target.table} t WHERE t.agent_name IS NOT NULL
                       AND NOT EXISTS (SELECT 1 FROM agents a WHERE a.agent_name = t.agent_name)`,
                    )
                    .get() as { n: number }
                ).n
              : 0;
        if (unresolved > 0) {
          throw new Error(
            `agent_id_backfill_incomplete: table '${target.table}' has ${unresolved} row(s) whose agent could not ` +
              `be resolved to a stable agent_id. Refusing to commit a table with an unattributable row.`,
          );
        }

        db.exec(`DROP TABLE ${target.table}`);
        db.exec(`ALTER TABLE ${tmp} RENAME TO ${target.table}`);
        for (const sql of target.indexSql(target.table)) db.exec(sql);

        rowCounts[target.table] = after;
      }
      db.exec("COMMIT");
    } catch (err) {
      // SQLite may have already aborted the transaction; a failing ROLLBACK must not mask the real error.
      try {
        db.exec("ROLLBACK");
      } catch {
        /* the failing statement may have already aborted the txn */
      }
      logger.error("daemon.migration.agent_id_backfill.failed", {
        tables: pending.map((t) => t.table),
        reason: err instanceof Error ? err.message : String(err),
      });
      throw err;
    }

    logger.info("daemon.migration.agent_id_backfill", {
      tables: Object.keys(rowCounts),
      rowCounts,
      agentsMapped: nameToId.size,
    });

    return { migrated: true, rowCounts };
  });
}
