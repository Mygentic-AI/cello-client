/**
 * COLUMN BIRTH — the migration guard that could not report its own failure.
 *
 * Both birth-gated `ADD COLUMN` sites in this codebase were `try { … } catch { }`. That cannot tell
 * "already present" — which happens on every start after the first — from a schema that is broken.
 * A real failure produced no log line, no throw, and no symptom where it happened; the only
 * evidence was every later query on the column failing somewhere else entirely.
 *
 * The case it hurts most is the FIRST run on a new machine, which is the one place a migration
 * actually executes and the one place the old code was guaranteed to stay silent.
 *
 * `node:sqlite` here is the test-file allowance; production is SQLCipher.
 */

import { describe, it, expect } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { addColumnIfMissing } from "../column-birth.js";
import type { Logger } from "../types.js";

function recordingLogger(): { logger: Logger; events: Array<{ event: string; fields: Record<string, unknown> }> } {
  const events: Array<{ event: string; fields: Record<string, unknown> }> = [];
  const push = (event: string, fields?: Record<string, unknown>) => {
    events.push({ event, fields: fields ?? {} });
  };
  const logger = { debug: push, info: push, warn: push, error: push, child: () => logger } as unknown as Logger;
  return { logger, events };
}

function newDb() {
  const db = new DatabaseSync(":memory:");
  db.exec("CREATE TABLE t (id INTEGER PRIMARY KEY)");
  return db;
}

const ADD_C = { table: "t", column: "c", sql: "ALTER TABLE t ADD COLUMN c INTEGER" };

describe("addColumnIfMissing — the benign case is silent, everything else is loud", () => {
  it("adds the column on a database that does not have it", () => {
    const db = newDb();
    const { logger, events } = recordingLogger();
    addColumnIfMissing(db, logger, ADD_C);

    db.prepare("INSERT INTO t (id, c) VALUES (1, 7)").run();
    expect((db.prepare("SELECT c FROM t WHERE id = 1").get() as { c: number }).c).toBe(7);
    // Nothing to say on the path that worked.
    expect(events).toEqual([]);
  });

  it("is IDEMPOTENT and silent on a re-run — the case that happens on every restart", () => {
    const db = newDb();
    const { logger, events } = recordingLogger();
    addColumnIfMissing(db, logger, ADD_C);
    addColumnIfMissing(db, logger, ADD_C);
    addColumnIfMissing(db, logger, ADD_C);
    // A log line here would fire on every daemon start forever, which is how a real one gets
    // filtered out.
    expect(events).toEqual([]);
  });

  it("PRESERVES existing rows — a birth-gated column must not cost the data it is added beside", () => {
    const db = newDb();
    db.prepare("INSERT INTO t (id) VALUES (42)").run();
    addColumnIfMissing(db, recordingLogger().logger, ADD_C);
    const row = db.prepare("SELECT id, c FROM t WHERE id = 42").get() as { id: number; c: number | null };
    expect(row.id).toBe(42);
    expect(row.c).toBeNull();
  });

  it("THROWS and logs when the failure is not 'already present'", () => {
    // The whole point. A missing table is a real schema fault, and the old bare catch turned it
    // into silence — the daemon carried on with a column that does not exist and failed later, in
    // another subsystem, with a message naming neither this migration nor this table.
    const db = newDb();
    const { logger, events } = recordingLogger();
    const bad = { table: "nope", column: "c", sql: "ALTER TABLE nope ADD COLUMN c INTEGER" };

    expect(() => addColumnIfMissing(db, logger, bad)).toThrow();
    const failure = events.find((e) => e.event === "db.column_birth.failed");
    expect(failure, "a real migration failure was not logged").toBeDefined();
    // Named well enough to act on without reading the code: which table, which column, and the
    // driver's own message.
    expect(failure!.fields).toMatchObject({ table: "nope", column: "c" });
    expect(String(failure!.fields["error"])).not.toBe("");
  });

  it("does not swallow a DUPLICATE TABLE error just because it says 'duplicate'", () => {
    // The match is anchored to "duplicate column name" rather than a loose /duplicate/ for exactly
    // this: a different duplicate fault must not be absorbed by a guard written for this one.
    const db = newDb();
    const { logger } = recordingLogger();
    expect(() =>
      addColumnIfMissing(db, logger, { table: "t", column: "n/a", sql: "CREATE TABLE t (id INTEGER)" }),
    ).toThrow();
  });
});
