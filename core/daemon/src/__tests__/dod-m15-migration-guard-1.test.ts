/**
 * DOD-M15-MIGRATION-GUARD-1 — the upgrade guard covers all seven rebuilt tables, not one.
 *
 * ─── What goes wrong, in the order an operator lives it ────────────────────────────────────────
 *
 * They upgrade. On the ONE boot where their old database is re-keyed from `agent_name` to
 * `agent_id`, `migrateSessionTablesToAgentId` REBUILDS seven tables from a DDL pinned inside
 * `agent-id-migration.ts` and copies the INTERSECTION of the old and new column lists. A column the
 * running code adds by inline `ALTER TABLE`, but that pinned DDL omits, is therefore DROPPED — and
 * then re-added EMPTY seconds later by the same `ALTER`. Nothing throws. Every check afterwards
 * shows the column present. Only the DATA is gone, and only for people who upgraded.
 *
 * It has happened four times: `read_at`, `diverged_at`, `content_salt`, and `retry_queue`'s signed
 * ordering record. The last one is the one to hold on to — without it the recipient places recovered
 * content at its ARRIVAL index instead of its witnessed sequence, the two transcripts part, and the
 * session can never seal bilaterally again.
 *
 * ─── Why the existing guard could not catch it ─────────────────────────────────────────────────
 *
 * `dod-agent-id-joinkey-migration` is the guard for exactly this class, and it works: it replays the
 * inline ALTERs BEFORE the re-key, in the order the daemon actually boots. Replaying them afterwards
 * puts the column back and the comparison passes over the top of the loss.
 *
 * But it replays only `sessions`' ALTERs. The other six rebuilt tables have nothing between a
 * forgotten column and silent data loss — and `retry_queue`'s ALTERs live in a different file, run
 * from a different constructor, which is precisely why they were missed.
 *
 * And it compares COLUMN SETS. A column set is what already passes while the data is gone: the
 * column is present after the rebuild, and empty. **This file asserts on VALUES.**
 *
 * ─── Two rules, and they point in OPPOSITE directions ──────────────────────────────────────────
 *
 * The obvious reading — "every client-side column belongs in the pinned DDL" — is wrong, and acting
 * on it breaks something. The real rule is about WHEN a column can exist:
 *
 *   A column belongs in the pinned DDL **iff it can already be present on a legacy,
 *   `agent_name`-keyed table at the moment the re-key runs.**
 *
 * `sessions`' columns and `contacts.moniker` are added by ALTERs that run BEFORE the re-key in the
 * same boot. `retry_queue`'s are added by a constructor that runs after — but on the second boot of
 * an old database they are already there, because a previous boot added them. All of those must be
 * in the DDL.
 *
 * `contacts`' four tier columns must NOT be, and this is the trap: `migrateContactsAddTierMetadata`
 * runs AFTER the re-key and gates a ONE-TIME grandfather on the columns not existing yet — it
 * promotes every pre-existing contact to WHITELISTED only in the invocation that first adds `tier`.
 * Put those columns in the pinned DDL and the re-key creates them on the legacy database, `toAdd`
 * comes back empty, the grandfather never runs, and **every contact the operator had already
 * approved reads as UNKNOWN.** Their address book silently stops auto-accepting.
 *
 * So this file asserts BOTH directions. A guard that only pushed columns into the DDL would cause
 * that failure while reporting success.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { migrateSessionTablesToAgentId } from "../agent-id-migration.js";
import { migrateContactsAddTierMetadata, TIER } from "../contacts-tier-migration.js";
import { ensureIdentitySchema } from "../db-identity-store.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";
import type { Logger } from "../types.js";

const SRC = join(dirname(fileURLToPath(import.meta.url)), "..");

function silentLogger(): Logger {
  return { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} };
}

/** Comments are prose. A guard that reads code must not be satisfiable by writing a comment. */
function stripComments(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");
}

const SEVEN = [
  "sessions", "seal_interrupted_artifacts", "session_tree_leaves",
  "transcript", "message_watermarks", "contacts", "retry_queue",
] as const;

/**
 * The pre-migration schema as REMOVE-001 left it: seven children keyed on the mutable `agent_name`.
 * Written out literally so this builds a genuine legacy database rather than asking the code under
 * test what "legacy" means — the same reason the sibling guard does.
 */
const LEGACY_DDL = `
  CREATE TABLE sessions (
    session_id TEXT NOT NULL, agent_name TEXT NOT NULL, counterparty_pubkey TEXT NOT NULL,
    status TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
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
    agent_name TEXT NOT NULL, pubkey TEXT NOT NULL, added_at INTEGER NOT NULL,
    PRIMARY KEY (agent_name, pubkey));
  CREATE TABLE retry_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL, nonce_hex TEXT NOT NULL,
    content_blob BLOB NOT NULL, queued_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 1,
    position INTEGER NOT NULL, awaiting_ack INTEGER NOT NULL DEFAULT 0, content_hash_hex TEXT,
    agent_name TEXT, UNIQUE(session_id, nonce_hex));
`;

// ─── Reading the ALTERs out of the SOURCE, so a new one is replayed without anyone remembering ───

/**
 * Every `ALTER TABLE <t> ADD COLUMN <ddl>` written as a literal in a source file.
 *
 * Parsed rather than hand-listed on purpose. A hand-listed replay is a second place to remember,
 * and the entire defect being guarded here IS a forgotten second place. Add a column to
 * `session-node-manager.ts` and this test replays it on the next run, with nobody in the loop.
 */
function literalAlters(text: string, table: string): string[] {
  const out: string[] = [];
  const re = new RegExp(`ALTER TABLE ${table} ADD COLUMN ([^"'\`]+)`, "g");
  for (const m of stripComments(text).matchAll(re)) out.push(m[1]!.trim());
  return out;
}

/**
 * `retry-queue.ts` adds its columns from a `{ name, type }` array in a loop, so the ALTER is a
 * template and the column names are data. Parsed from the array.
 */
function retryQueueAlters(text: string): string[] {
  const stripped = stripComments(text);
  const loop = /ALTER TABLE retry_queue ADD COLUMN \$\{col\.name\} \$\{col\.type\}/.test(stripped);
  expect(loop, "retry-queue.ts no longer adds columns by the `${col.name} ${col.type}` template — " +
    "this parser is now reading a shape that does not exist, and would report ZERO columns to " +
    "replay, which is a silent pass. Update the parser before updating the loop.").toBe(true);
  const out: string[] = [];
  for (const m of stripped.matchAll(/\{\s*name:\s*"(\w+)",\s*type:\s*"(\w+)"\s*\}/g)) {
    out.push(`${m[1]!} ${m[2]!}`);
  }
  return out;
}

/** The ALTERs to replay BEFORE the re-key, keyed by table, read live from source. */
function altersBeforeRekey(): Record<string, string[]> {
  const manager = readFileSync(join(SRC, "session-node-manager.ts"), "utf8");
  const retry = readFileSync(join(SRC, "retry-queue.ts"), "utf8");
  return {
    sessions: literalAlters(manager, "sessions"),
    contacts: literalAlters(manager, "contacts"),
    // NOT from `contacts-tier-migration.ts` — those run AFTER the re-key and must not be present
    // before it. See the header, and the second test below which pins that.
    retry_queue: retryQueueAlters(retry),
  };
}

// ─── Seeding a VALUE in every column, so the assertion is about data and not shape ───────────────

type ColInfo = { name: string; type: string; notnull: number };

const columnsOf = (db: DatabaseSync, t: string): ColInfo[] =>
  db.prepare(`PRAGMA table_info(${t})`).all() as unknown as ColInfo[];

/**
 * A value distinguishable from every other value in the database, derived from where it lives.
 * If a rebuild copies the wrong column into the wrong slot, a shared sentinel would still compare
 * equal; this one names its own table and column, so a mix-up is visible in the failure message.
 */
function sentinel(table: string, col: ColInfo, i: number): string | number | Uint8Array {
  const type = col.type.toUpperCase();
  if (type.includes("BLOB")) return new Uint8Array([0xc0, 0xde, i, table.length, col.name.length]);
  if (type.includes("INT")) return 900_000 + i * 1000 + col.name.length;
  return `sentinel:${table}:${col.name}`;
}

function seedOneRow(db: DatabaseSync, table: string, agentName: string): Map<string, unknown> {
  const cols = columnsOf(db, table);
  const values = new Map<string, unknown>();
  cols.forEach((c, i) => {
    // `agent_name` is the thing being re-keyed away; it must resolve to a real agent, so it is the
    // one column that carries a meaningful value rather than a sentinel.
    values.set(c.name, c.name === "agent_name" ? agentName : sentinel(table, c, i));
  });
  const names = [...values.keys()];
  db.prepare(
    `INSERT INTO ${table} (${names.join(", ")}) VALUES (${names.map(() => "?").join(", ")})`,
  ).run(...names.map((n) => values.get(n) as never));
  return values;
}

function legacyDb(): DatabaseSync {
  const db = new DatabaseSync(":memory:");
  ensureIdentitySchema(db as unknown as DaemonDatabase);
  db.exec(LEGACY_DDL);
  db.prepare(
    `INSERT INTO agents (agent_id, agent_name, k_local_seed, k_local_pubkey, state, created_at, updated_at)
     VALUES ('id-alice','alice',x'00','pub-a','created',1,1)`,
  ).run();
  return db;
}

describe("DOD-M15-MIGRATION-GUARD-1 — the upgrade preserves DATA in all seven rebuilt tables", () => {
  it("every value written before the re-key is still there after it", () => {
    /**
     * The whole point of this test is the two things the sibling guard does not do: it covers all
     * SEVEN tables rather than `sessions` alone, and it asserts on VALUES rather than column names.
     * A column set is exactly what still passes while the data is gone.
     */
    const db = legacyDb();

    // 1. Bring the legacy tables up to the column set a real machine would have at re-key time,
    //    replaying the inline ALTERs read out of the source files.
    const alters = altersBeforeRekey();
    expect(
      alters["sessions"]!.length,
      "no ALTER TABLE sessions ADD COLUMN literals were found in session-node-manager.ts — the " +
        "parser is reading a shape that no longer exists, and an empty replay is a silent pass",
    ).toBeGreaterThan(5);
    expect(
      alters["retry_queue"]!.length,
      "no retry_queue columns parsed out of retry-queue.ts — same silent-pass risk",
    ).toBeGreaterThan(0);

    for (const [table, ddls] of Object.entries(alters)) {
      for (const ddl of ddls) {
        try { db.exec(`ALTER TABLE ${table} ADD COLUMN ${ddl}`); }
        catch { /* already present in the legacy DDL above */ }
      }
    }

    // 2. Write a distinguishable value into EVERY column of EVERY rebuilt table.
    const seeded = new Map<string, Map<string, unknown>>();
    for (const t of SEVEN) seeded.set(t, seedOneRow(db, t, "alice"));

    // 3. The re-key.
    migrateSessionTablesToAgentId(db as unknown as DaemonDatabase, silentLogger());

    /**
     * The ONE column the rebuild deliberately does not carry. `carried` in `agent-id-migration.ts`
     * filters `id` out by name, so the copied rows are renumbered from 1.
     *
     * That is safe, and it is worth saying WHY rather than just excusing it: `retry_queue.id` is a
     * surrogate `AUTOINCREMENT` key that nothing outside the table holds across a restart — the
     * queue is re-read from disk on every boot, and its ORDER comes from `position`, which is
     * carried and asserted like every other value. Renumbering a key nobody kept is not data loss.
     *
     * Listed rather than skipped silently, and asserted to be hit below: if the migration ever
     * starts carrying `id`, or this column stops existing, the exemption is stale and says so.
     */
    const REASSIGNED_BY_DESIGN: Record<string, string> = {
      "retry_queue.id": "surrogate AUTOINCREMENT key, not held across a restart; order comes from `position`",
    };
    const exemptionsHit = new Set<string>();

    // 4. Every value must still be there.
    const lost: string[] = [];
    for (const t of SEVEN) {
      const row = db.prepare(`SELECT * FROM ${t}`).get() as Record<string, unknown> | undefined;
      if (row === undefined) { lost.push(`${t}: the ROW is gone entirely`); continue; }
      for (const [col, want] of seeded.get(t)!) {
        if (col === "agent_name") continue; // re-keyed away by design; agent_id is asserted below
        if (REASSIGNED_BY_DESIGN[`${t}.${col}`] !== undefined) {
          exemptionsHit.add(`${t}.${col}`);
          continue;
        }
        if (!(col in row)) {
          lost.push(`${t}.${col}: column DROPPED by the rebuild — missing from the pinned DDL in agent-id-migration.ts`);
          continue;
        }
        const got = row[col];
        const same = want instanceof Uint8Array
          ? got instanceof Uint8Array && Buffer.from(got).equals(Buffer.from(want))
          : got === want;
        if (!same) lost.push(`${t}.${col}: value changed — wrote ${String(want)}, read back ${String(got)}`);
      }
      expect(row["agent_id"], `${t}: the row must be re-attributed to the agent's stable id`).toBe("id-alice");
    }

    expect(
      lost,
      `The upgrade LOST data:\n  ${lost.join("\n  ")}\n\n` +
        `A column added by an inline ALTER and omitted from the pinned DDL in agent-id-migration.ts ` +
        `is dropped on the one boot a legacy database upgrades, then re-added EMPTY by the same ` +
        `ALTER — so the schema looks correct afterwards and only the operator's data is gone. Add ` +
        `the column to that table's createSql. Do NOT "fix" this by removing the ALTER.`,
    ).toEqual([]);

    expect(
      [...exemptionsHit].sort(),
      "an exemption in REASSIGNED_BY_DESIGN was never reached — either the column is gone or the " +
        "migration now carries it. Re-read the reason before deleting or widening the entry.",
    ).toEqual(Object.keys(REASSIGNED_BY_DESIGN).sort());

    db.close();
  });

  it("the contacts TIER columns are absent from the pinned DDL, and the grandfather depends on it", () => {
    /**
     * ─── THE OPPOSITE DIRECTION, AND IT IS EASY TO BREAK WHILE FIXING THE TEST ABOVE ───────────
     *
     * `migrateContactsAddTierMetadata` runs AFTER the re-key and promotes every pre-existing contact
     * to WHITELISTED exactly once — in the invocation that first adds the `tier` column. It detects
     * that by the column being absent.
     *
     * Put the tier columns in the pinned DDL and the re-key creates them on the legacy database
     * first. `toAdd` then comes back empty, the migration returns early, the one-time grandfather
     * never runs, and every contact the operator had already approved reads NULL → UNKNOWN.
     * **Their address book stops auto-accepting people it accepted yesterday**, with no error.
     *
     * This is asserted end-to-end rather than by reading the DDL: the property that matters is the
     * grandfather actually running, not the text of a CREATE TABLE.
     */
    const db = legacyDb();
    db.exec(`INSERT INTO contacts (agent_name, pubkey, added_at) VALUES ('alice','pk-known',1)`);

    migrateSessionTablesToAgentId(db as unknown as DaemonDatabase, silentLogger());

    const afterRekey = columnsOf(db, "contacts").map((c) => c.name);
    expect(
      afterRekey,
      "the re-key created a tier column on a legacy database. `migrateContactsAddTierMetadata` " +
        "gates its ONE-TIME grandfather on these columns being absent, so it will now return early " +
        "and every already-approved contact will read UNKNOWN. Remove them from contacts' createSql.",
    ).not.toContain("tier");

    migrateContactsAddTierMetadata(db as unknown as DaemonDatabase, silentLogger());

    const tier = (db.prepare("SELECT tier FROM contacts WHERE pubkey = 'pk-known'").get() as { tier: number }).tier;
    expect(
      tier,
      "a contact that existed before the upgrade was not grandfathered. The operator approved this " +
        "person; after upgrading, their agent no longer will.",
    ).toBe(TIER.WHITELISTED);

    db.close();
  });

  it("no rebuilt table gains an ALTER in a file this guard does not read", () => {
    /**
     * The reason the four escapes escaped: `retry_queue`'s ALTERs live in a different file from
     * `sessions`', run from a different constructor, and the guard only knew about one file.
     *
     * So the guard now polices its OWN coverage. If someone adds an `ALTER TABLE <rebuilt> ADD
     * COLUMN` in a file not listed here, this goes red and says what to do — rather than the replay
     * above silently skipping it and the whole file passing while a column is unguarded.
     */
    const READ_BY_THIS_GUARD: Record<string, string> = {
      "session-node-manager.ts": "replayed BEFORE the re-key (sessions', and contacts.moniker)",
      "retry-queue.ts": "replayed BEFORE the re-key — its constructor runs later, but on the second boot of an old database the columns are already present",
      "contacts-tier-migration.ts": "deliberately NOT replayed: runs AFTER the re-key, and its columns must NOT be in the pinned DDL — see the grandfather test above",
      "agent-id-migration.ts": "the migration under test; its ALTERs are the rebuild's own",
    };

    const files: string[] = [];
    for (const entry of readdirSync(SRC)) {
      if (!entry.endsWith(".ts")) continue;
      const text = stripComments(readFileSync(join(SRC, entry), "utf8"));
      if (SEVEN.some((t) => new RegExp(`ALTER TABLE ${t} ADD COLUMN`).test(text))) files.push(entry);
    }

    const unknown = files.filter((f) => !(f in READ_BY_THIS_GUARD));
    expect(
      unknown,
      `These files add a column to a REBUILT table and this guard does not read them:\n` +
        `  ${unknown.join("\n  ")}\n\n` +
        `The replay above will skip them, so the column is unguarded and will be dropped on the ` +
        `one boot a legacy database upgrades. Decide which side it is on — present before the ` +
        `re-key (add it to the pinned DDL and to this guard's file list) or added after (it must ` +
        `NOT be in the pinned DDL) — then record it here with the reason.`,
    ).toEqual([]);
  });
});
