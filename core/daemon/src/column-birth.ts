/**
 * COLUMN BIRTH — adding a column to a table an operator already holds data in.
 *
 * `ALTER TABLE … ADD COLUMN` throws when the column is already there, and that throw is the guard:
 * it is how a birth-gated migration stays idempotent without a version table nobody maintains. The
 * pattern is right. The way it was written twice in this codebase was not:
 *
 *     try { db.exec(sql); } catch { }
 *
 * A bare catch cannot tell "already present" — the expected, benign case, which happens on every
 * start after the first — from a schema that is actually broken. So a real failure produced no log
 * line, no throw, and no symptom at the point of failure. The only evidence would be every later
 * query on that column failing, in a different subsystem, with a message that names neither the
 * migration nor the table.
 *
 * That matters most exactly where it is least observable: the FIRST run on a new machine. A second
 * operator, or a fresh database, is where a migration executes for real — and it was the one place
 * the code was guaranteed to say nothing.
 *
 * So: match the benign case by its message and return; anything else is logged under its own event
 * and rethrown. Rethrowing is the deliberate half. If the column cannot be added, every query that
 * reads it fails anyway — the choice is not between working and failing, it is between failing at
 * startup with the cause named and failing later somewhere else with the cause lost.
 */

import type { Logger } from "./types.js";

/**
 * SQLite's wording for "this column is already here", which is the whole benign case.
 *
 * Matched on the MESSAGE rather than a code because the driver surfaces a plain `Error`. Anchored
 * to the phrase rather than the column name so one expression covers every call site — and
 * deliberately NOT a loose `/duplicate/`, which would also swallow a duplicate-table or
 * duplicate-index failure that has nothing to do with this column.
 */
const ALREADY_PRESENT = /duplicate column name/i;

/**
 * Run one `ADD COLUMN`, treating "already present" as success and everything else as a fault.
 *
 * `table` and `column` are for the log line only — the SQL is the authority. They are separate
 * arguments rather than parsed out of it because a regex over SQL is a second, worse parser, and
 * the caller already knows both.
 */
export function addColumnIfMissing(
  db: { exec(sql: string): void },
  logger: Logger,
  input: { table: string; column: string; sql: string },
): void {
  try {
    db.exec(input.sql);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    if (ALREADY_PRESENT.test(message)) return;
    // NAMED, at error, before the rethrow — so the cause is in the log even if something upstream
    // catches the throw and reports it as a generic startup failure.
    logger.error("db.column_birth.failed", {
      table: input.table,
      column: input.column,
      sql: input.sql,
      error: message,
    });
    throw err;
  }
}
