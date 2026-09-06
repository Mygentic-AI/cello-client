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
 * It has happened three times — `read_at`, `diverged_at`, `content_salt` — each caught before
 * shipping by the sibling guard, which covers `sessions` and nothing else.
 *
 * ─── ONE CLAIM THAT IS REPEATED IN THIS REPO AND IS NOT TRUE ───────────────────────────────────
 *
 * `retry_queue`'s `structure1_cbor` / `structure2_cbor` are described in `agent-id-migration.ts`
 * and in this line's own DoD as a fourth instance and "a live data-loss bug". **Nobody ever lost
 * an ordering record.** Checked against history rather than reasoned from the code:
 *
 *   - the re-key shipped `173d34f`, 2026-07-10, and is ONE-SHOT (`needsRekey` is false forever once
 *     `agent_id` exists);
 *   - `structure1_cbor` shipped `6cea544`, 2026-08-05, four weeks LATER;
 *   - `RetryQueue` is constructed exactly once, at `daemon.ts:1905`, after `initialize()`.
 *
 * So the only database on which `retry_queue` is ever rebuilt predates the column by a month and
 * has nothing to lose. The intersection copy drops nothing; the constructor then adds the column
 * empty, correctly.
 *
 * **The guard is still worth having, and the reason is the interesting part:** what makes that loss
 * unreachable is the ORDER of two calls, and that order is held in place by a comment
 * (`retry-queue.ts`, "Do not reorder") rather than by any mechanism. The DDL entry and this replay
 * are what turn a convention into something that fails loudly when it is broken.
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
 * same boot, so they must be in the DDL.
 *
 * `retry_queue`'s are replayed before it here too, and that models a state no shipped version can
 * actually produce (see above). Deliberately conservative: it holds the invariant that the "do not
 * reorder" comment asserts, so moving that constructor ahead of the re-key fails HERE instead of on
 * an operator's machine.
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
import { migrateSessionTablesToAgentId, REKEYED_TABLES } from "../agent-id-migration.js";
import { migrateContactsAddTierMetadata, TIER } from "../contacts-tier-migration.js";
import { ensureIdentitySchema } from "../db-identity-store.js";
import { addColumnIfMissing } from "../column-birth.js";
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

/**
 * Taken from the migration, NOT typed out again. A local copy gets shorter than the migration's
 * list the day an eighth table is added, and it never goes red doing it — so the one table nobody
 * remembered to guard would be the one table nobody checks. That is the shape of every escape this
 * migration has already had, and a guard is the last place to reproduce it.
 */
const SEVEN = REKEYED_TABLES;

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
/**
 * Every JS string-literal BODY in `text`, comments excluded — in ONE pass.
 *
 * Stripping comments first and then finding literals is what the earlier version did, and it is
 * wrong in a way review pass 2 named and this file's own unit test then reproduced: a `//` or `/*`
 * INSIDE a string literal is not a comment, but the stripper cannot tell, so it ate the rest of the
 * line — and the `ALTER TABLE` on the next line vanished silently.
 *
 * Comment state and string state are the same scan or they are wrong. A single walk knows which one
 * it is in; two passes each guess about the other.
 *
 * A regex literal containing a quote could still mis-seed this scan. That risk is bounded rather
 * than argued away: a mis-scan changes the parsed COUNT, and the ground-truth assertion in the data
 * test compares that count against the raw source. This parser can no longer fail quietly.
 */
function stringLiterals(text: string): string[] {
  const out: string[] = [];
  let i = 0;
  while (i < text.length) {
    const c = text[i]!;
    if (c === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") i += 1;
      continue;
    }
    if (c === "/" && text[i + 1] === "*") {
      i += 2;
      while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i += 1;
      i += 2;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      i += 1;
      let buf = "";
      let escaped = false;
      while (i < text.length) {
        const d = text[i]!;
        if (escaped) { buf += d; escaped = false; i += 1; continue; }
        if (d === "\\") { escaped = true; i += 1; continue; }
        if (d === c) { i += 1; break; }
        buf += d;
        i += 1;
      }
      out.push(buf);
      continue;
    }
    i += 1;
  }
  return out;
}

function literalAlters(text: string, table: string): string[] {
  const out: string[] = [];
  /**
   * The capture runs to the END OF THE STRING LITERAL, not to the first quote.
   *
   * It used to be `([^"'\`]+)`, which stops dead at a quote — so
   * `ADD COLUMN origin TEXT NOT NULL DEFAULT 'received'` parsed as
   * `origin TEXT NOT NULL DEFAULT`, which is a SQL syntax error, which the replay then swallowed.
   * The column was never added, never seeded, never checked, and the guard stayed green. That exact
   * shape is already written twice in the file this parses (`held_content.origin`); the next one to
   * land on a rebuilt table would have been invisible.
   */
  const inner = new RegExp(`^ALTER TABLE ${table} ADD COLUMN (.+)$`, "i");
  for (const literal of stringLiterals(text)) {
    const sql = literal.trim().replace(/\s+/g, " ");
    const hit = inner.exec(sql);
    if (hit === null) continue;
    const ddl = hit[1]!.trim();
    // A template hole (`${col.name}`) means the column names are DATA, not text — a different
    // parser's job. Skipping it here silently would be a hole, so it is asserted separately.
    if (ddl.includes("${")) continue;
    out.push(ddl);
  }
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
  /**
   * Scoped to the `for (const col of [ … ])` array that feeds the ALTER, not the whole file. An
   * unscoped match would pick up any unrelated `{ name, type }` object added later and invent a
   * column, failing with a message that sends the reader to the wrong place.
   */
  const arrayStart = stripped.indexOf("for (const col of [");
  expect(arrayStart, "retry-queue.ts no longer feeds its ALTER from a `for (const col of [` array")
    .toBeGreaterThan(-1);
  const arrayEnd = stripped.indexOf("]", arrayStart);
  const array = stripped.slice(arrayStart, arrayEnd);

  const out: string[] = [];
  // `type` captures to the closing quote, not one word: a column declared
  // `{ name: "priority", type: "INTEGER NOT NULL DEFAULT 0" }` parsed as NOTHING under `(\w+)`,
  // and a parser that matches nothing is a guard that passes.
  for (const m of array.matchAll(/\{\s*name:\s*"([^"]+)",\s*type:\s*"([^"]+)"\s*\}/g)) {
    out.push(`${m[1]!} ${m[2]!}`);
  }
  return out;
}

/** The ALTERs to replay BEFORE the re-key, keyed by table, read live from source. */
function altersBeforeRekey(): Record<string, string[]> {
  // 037-SESSIONCORE moved the schema out of session-node-manager.ts into session-schema.ts. The
  // ALTERs this guard replays are read from where they now live, so the guard cannot end up
  // parsing a file with no ALTERs in it and passing on an empty replay.
  const manager = readFileSync(join(SRC, "session-schema.ts"), "utf8");
  const retry = readFileSync(join(SRC, "retry-queue.ts"), "utf8");
  return {
    sessions: literalAlters(manager, "sessions"),
    contacts: literalAlters(manager, "contacts"),
    // DOD-M15-SEALWIRE-1 bullet 5 added authorship columns to `transcript`, by literal ALTER in the
    // same file — so the generic parser reads them and this line is all the guard needed.
    transcript: literalAlters(manager, "transcript"),
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

/**
 * ─── THE PARSERS ARE UNIT-TESTED, BECAUSE THEIR FIXES OTHERWISE HAVE NO TEETH ──────────────────
 *
 * Review pass 2 reverted all three parser fixes below and the whole file stayed GREEN — every one
 * produces identical output against today's sources, because no current column happens to use the
 * shapes they were fixed for. The bypasses were proven by hand-mutating source files and that
 * evidence was never committed, so the next edit reintroducing any of them would pass the gate.
 *
 * That is this file's own thesis turned on itself: a checker which silently matches nothing reports
 * success either way. These cases are the committed proof.
 */
describe("DOD-M15-MIGRATION-GUARD-1 — the source parsers survive the shapes that broke them", () => {
  it("literalAlters reads a column whose DEFAULT contains a quote", () => {
    // The pass-1 defect. `([^"'`]+)` stopped at the apostrophe, yielding
    // `origin TEXT NOT NULL DEFAULT` — invalid SQL, swallowed by the replay's bare catch.
    // This shape is already written twice in the file this parses (`held_content.origin`).
    const src = `db.exec("ALTER TABLE sessions ADD COLUMN origin TEXT NOT NULL DEFAULT 'received'");`;
    expect(literalAlters(src, "sessions")).toEqual(["origin TEXT NOT NULL DEFAULT 'received'"]);
  });

  it("literalAlters is not confused by a // or /* inside an EARLIER string literal", () => {
    // `stripComments` runs before literal-finding, so a comment marker inside a string can eat the
    // line that follows it. The colon guard covers `https://`; these are the uncovered shapes.
    const slash = `const a = "x // y";\ndb.exec("ALTER TABLE sessions ADD COLUMN read_at INTEGER");`;
    const block = `const a = "x /* y";\ndb.exec("ALTER TABLE sessions ADD COLUMN read_at INTEGER");`;
    expect(literalAlters(slash, "sessions"), "a // inside a string swallowed the ALTER").toEqual(["read_at INTEGER"]);
    expect(literalAlters(block, "sessions"), "a /* inside a string swallowed the ALTER").toEqual(["read_at INTEGER"]);
  });

  it("literalAlters still ignores a real comment", () => {
    expect(literalAlters(`// db.exec("ALTER TABLE sessions ADD COLUMN ghost TEXT");`, "sessions")).toEqual([]);
  });

  it("retryQueueAlters reads a multi-word type, and ignores a decoy outside the array", () => {
    // Pass-1 F2: `(\w+)` parsed a multi-word type to NOTHING. F4: an unscoped match invented columns.
    const src = `
      const decoy = { name: "not_a_column", type: "TEXT" };
      for (const col of [
        { name: "structure1_cbor", type: "BLOB" },
        { name: "priority", type: "INTEGER NOT NULL DEFAULT 0" },
      ]) {
        this.#db.exec(\`ALTER TABLE retry_queue ADD COLUMN \${col.name} \${col.type}\`);
      }`;
    expect(retryQueueAlters(src)).toEqual([
      "structure1_cbor BLOB",
      "priority INTEGER NOT NULL DEFAULT 0",
    ]);
  });
});

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
      "no ALTER TABLE sessions ADD COLUMN literals were found in session-schema.ts — the " +
        "parser is reading a shape that no longer exists, and an empty replay is a silent pass",
    ).toBeGreaterThan(5);
    expect(
      alters["retry_queue"]!.length,
      "no retry_queue columns parsed out of retry-queue.ts — same silent-pass risk",
    ).toBeGreaterThan(0);

    /**
     * ─── THE REPLAY IS LOUD. A BARE `catch {}` HERE MADE THIS WHOLE FILE A DECORATION ──────────
     *
     * It used to be `try { … } catch { /* already present *​/ }`, which cannot tell "already
     * present" from "the parser handed me broken SQL". A mis-parsed column then failed to apply,
     * was never seeded, was never checked — and the test passed. That is the precise anti-pattern
     * `column-birth.ts` exists to condemn, committed inside the guard whose whole thesis is that a
     * checker which silently matches nothing reports success either way.
     *
     * `addColumnIfMissing` swallows ONLY `duplicate column name` and rethrows everything else.
     */
    /**
     * ─── GROUND TRUTH: what the SOURCE contains, measured without the pinned DDL ────────────────
     *
     * The inverse assertion further down derives its expectation from the pinned DDL, which makes
     * it structurally incapable of catching the one failure this whole file exists for: a column
     * that is missing from the pinned DDL **and** missed by the parser is in neither set, so
     * nothing reddens and the operator loses the data. Review pass 2 proved that deductively.
     *
     * This closes it from the other side. Count the raw `ALTER TABLE <t> ADD COLUMN` occurrences in
     * the UNSTRIPPED source and require the parser to have produced exactly that many. It measures
     * the gap between *present in source* and *parsed*, which is the actual failure mode, and it
     * depends on nothing else.
     *
     * **Deliberately the RAW source, not the comment-stripped one.** A stripped count would move
     * together with the parser if `stripComments` itself corrupted the text — both would shrink and
     * agree, which is the same false-agreement shape being closed here. Raw and stripped both read
     * 17/1 today (measured), so raw costs nothing and catches strictly more. If a genuine ALTER is
     * ever written inside a comment this goes red: fix it by not writing SQL in a comment.
     */
    const groundTruth: Record<string, { table: string; file: string }> = {
      sessions: { table: "sessions", file: "session-schema.ts" },
      contacts: { table: "contacts", file: "session-schema.ts" },
      transcript: { table: "transcript", file: "session-schema.ts" },
    };
    for (const [key, { table, file }] of Object.entries(groundTruth)) {
      const raw = readFileSync(join(SRC, file), "utf8");
      const occurrences = (raw.match(new RegExp(`ALTER TABLE ${table} ADD COLUMN`, "g")) ?? []).length;
      expect(
        alters[key]!.length,
        `${file} contains ${String(occurrences)} 'ALTER TABLE ${table} ADD COLUMN' statements but ` +
          `the parser produced ${String(alters[key]!.length)}. A column present in the source and ` +
          `missed by the parser is never replayed, never seeded and never checked — and if it is ` +
          `also missing from the pinned DDL, that is exactly the silent upgrade data loss this ` +
          `file exists to prevent. Fix the parser; do not adjust this count.`,
      ).toBe(occurrences);
    }
    // retry_queue's columns are data in an array, not statements — count the entries the same way.
    const rqRaw = readFileSync(join(SRC, "retry-queue.ts"), "utf8");
    const rqEntries = (rqRaw.match(/\{\s*name:\s*"/g) ?? []).length;
    expect(
      alters["retry_queue"]!.length,
      `retry-queue.ts declares ${String(rqEntries)} { name, type } column entries but the parser ` +
        `produced ${String(alters["retry_queue"]!.length)}.`,
    ).toBe(rqEntries);

    for (const [table, ddls] of Object.entries(alters)) {
      for (const ddl of ddls) {
        addColumnIfMissing(db as unknown as DaemonDatabase, silentLogger(), {
          table,
          column: ddl.split(/\s+/)[0]!,
          sql: `ALTER TABLE ${table} ADD COLUMN ${ddl}`,
        });
      }
    }

    /**
     * ─── THE INVERSE ASSERTION: every column the MIGRATION knows about must have been replayed ──
     *
     * The floors above (`> 5`, `> 0`) are weak: they catch a parser that breaks completely, not one
     * that quietly returns fewer columns than it should. And the seeded map is built from whatever
     * the replay managed to add, so a parser miss SHRINKS the loop rather than reddening it — the
     * hand-maintained-list hollow shape, one level down.
     *
     * So the coverage is measured against what the system itself declares. Run the migration on an
     * EMPTY legacy database to obtain the pinned target schema without exporting it, then require
     * every one of its columns to be present on the table this test is about to seed. A column the
     * pinned DDL carries and the replay missed is a column this test silently stopped checking.
     */
    const pinnedProbe = legacyDb();
    migrateSessionTablesToAgentId(pinnedProbe as unknown as DaemonDatabase, silentLogger());
    const unreplayed: string[] = [];
    for (const t of SEVEN) {
      const replayed = new Set(columnsOf(db, t).map((c) => c.name));
      for (const c of columnsOf(pinnedProbe, t)) {
        // `agent_id` is created BY the migration; it is not something the replay could add.
        if (c.name === "agent_id" || replayed.has(c.name)) continue;
        unreplayed.push(`${t}.${c.name}`);
      }
    }
    pinnedProbe.close();
    expect(
      unreplayed,
      `The pinned DDL carries these columns but the replay never added them, so this test does NOT ` +
        `check them:\n  ${unreplayed.join("\n  ")}\n\n` +
        `Either the source parser stopped recognising the ALTER that adds one — the failure this ` +
        `guard is most likely to have — or the column is genuinely added after the re-key, in ` +
        `which case it must NOT be in the pinned DDL at all. Do not silence this by seeding the ` +
        `column by hand: the point is that the replay comes from the source.`,
    ).toEqual([]);

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
      "session-schema.ts":
        "replayed BEFORE the re-key (sessions', and contacts.moniker). Held by " +
        "session-node-manager.ts until 037-SESSIONCORE split the schema into its own file; this " +
        "guard follows the ALTERs rather than the filename, which is why moving them turned it " +
        "RED instead of silently emptying the replay.",
      "retry-queue.ts": "replayed BEFORE the re-key — its constructor runs later, but on the second boot of an old database the columns are already present",
      "contacts-tier-migration.ts": "deliberately NOT replayed: runs AFTER the re-key, and its columns must NOT be in the pinned DDL — see the grandfather test above",
      "agent-id-migration.ts": "the migration under test; its ALTERs are the rebuild's own",
      "trust-signal-store.ts":
        "flagged by the VARIABLE-table rule, and checked rather than waved through: its list is " +
        "[\"wallet_trust_signals\", \"contact_trust_signals\"] — neither is rebuilt. Re-read that " +
        "list before trusting this entry; it is the list, not the file, that makes it safe.",
    };

    const files: string[] = [];
    for (const entry of readdirSync(SRC)) {
      if (!entry.endsWith(".ts")) continue;
      const text = stripComments(readFileSync(join(SRC, entry), "utf8"));
      if (SEVEN.some((t) => new RegExp(`ALTER TABLE ${t} ADD COLUMN`).test(text))) { files.push(entry); continue; }
      /**
       * A VARIABLE table name is flagged too, and it must be: `ALTER TABLE ${table} ADD COLUMN` is
       * already written in this codebase (`trust-signal-store.ts`, over a list). A police that only
       * reads literal names cannot tell whether that list contains a rebuilt table, and the answer
       * can change without this file being touched. Flagging is the conservative direction — a
       * false positive costs one line in the map below; a false negative costs an operator's data.
       */
      if (/ALTER TABLE \$\{\w+\} ADD COLUMN/.test(text)) files.push(entry);
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
