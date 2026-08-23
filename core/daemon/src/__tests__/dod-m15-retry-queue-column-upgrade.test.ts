/**
 * THE RETRY QUEUE KEEPS ITS ORDERING RECORD ACROSS AN UPGRADE — found while starting
 * `DOD-M15-SEALWIRE-1` bullet 6 part B2b, and **pre-existing rather than introduced by it.**
 *
 * ─── The defect, reproduced before it was believed ─────────────────────────────────────────────
 *
 * `agent-id-migration.ts` rebuilds seven tables from a pinned DDL and copies the INTERSECTION of the
 * old and new column lists. Its own header says the rule that follows from that:
 *
 *   > "EVERY COLUMN THE INLINE ALTERs ADD MUST APPEAR IN THE createSql BELOW."
 *
 * `retry_queue`'s `createSql` omitted `structure1_cbor` and `structure2_cbor`, which
 * `retry-queue.ts`'s constructor adds by idempotent `ALTER TABLE`. Measured by replaying the real
 * boot order against a legacy database that held both columns with data in them:
 *
 *   COLUMNS AFTER REBUILD: id,session_id,agent_id,nonce_hex,content_blob,queued_at,attempts,
 *                          position,awaiting_ack,content_hash_hex
 *
 * Both columns gone. They come BACK moments later — the `RetryQueue` constructor runs after the
 * migration and re-adds them — which is what makes this so quiet: the schema looks right afterwards
 * and only the DATA is missing.
 *
 * ─── Why losing it matters, in the words of the code that wrote it ─────────────────────────────
 *
 * `structure1_cbor`/`structure2_cbor` are the relay's signed ordering record, carried so a parked
 * entry is self-ordering on recovery. `daemon.ts`'s backstop says what their absence costs: *"the
 * receiver's `#witnessedSeq` map is in-memory and empty after a restart, so arrival order there means
 * a wrong leaf index and a divergent tree."*
 *
 * So: upgrade a daemon with queued retries → those rows lose their ordering record → the recipient
 * places the content at its arrival index instead of its witnessed sequence → the trees part → the
 * session can no longer seal bilaterally. On the ONE boot that carries the upgrade, silently.
 *
 * ─── Why the existing guard did not catch it ───────────────────────────────────────────────────
 *
 * `dod-agent-id-joinkey-migration` compares a MIGRATED database's column set against a FRESH one and
 * is the guard that has already caught this class three times (`read_at`, `diverged_at`,
 * `content_salt`). It replays the inline ALTERs in the real order — **but only the `sessions` ones.**
 * `retry_queue`'s two ALTERs live in a different file, run from a different constructor, and were
 * never replayed, so the comparison never saw them.
 */

import { describe, it, expect } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { migrateSessionTablesToAgentId } from "../agent-id-migration.js";
import { ensureIdentitySchema } from "../db-identity-store.js";
import type { DaemonDatabase, Logger } from "../types.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} } as unknown as Logger;

const S1 = Buffer.from("de".repeat(24), "hex");
const S2 = Buffer.from("ca".repeat(16), "hex");

/**
 * A legacy (pre-`agent_id`) database whose `retry_queue` ALREADY carries the ordering columns with
 * values in them — the shape any daemon that queued a retry before upgrading actually has.
 */
function legacyDbWithOrderingRecord(): DatabaseSync {
  const db = new DatabaseSync(":memory:");
  ensureIdentitySchema(db as unknown as DaemonDatabase);
  db.exec(`
    CREATE TABLE retry_queue (
      id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL, nonce_hex TEXT NOT NULL,
      content_blob BLOB NOT NULL, queued_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 1,
      position INTEGER NOT NULL, awaiting_ack INTEGER NOT NULL DEFAULT 0, content_hash_hex TEXT,
      agent_name TEXT, structure1_cbor BLOB, structure2_cbor BLOB, content_hash_alg TEXT,
      UNIQUE(session_id, nonce_hex));
  `);
  db.prepare(
    `INSERT INTO agents (agent_id, agent_name, k_local_seed, k_local_pubkey, state, created_at, updated_at)
     VALUES ('id-alice','alice',x'00','pub-alice','created',1,1)`,
  ).run();
  db.prepare(
    `INSERT INTO retry_queue
       (session_id, agent_name, nonce_hex, content_blob, queued_at, position,
        structure1_cbor, structure2_cbor, content_hash_alg)
     VALUES ('s1','alice','aa',x'01',1,1,?,?,?)`,
  ).run(S1, S2, "hmac-sha256-salt-v1");
  return db;
}

describe("the agent-id rebuild carries every column retry-queue.ts adds", () => {
  it("★ the ORDERING RECORD survives — losing it silently splits the transcript on upgrade", () => {
    const db = legacyDbWithOrderingRecord();
    migrateSessionTablesToAgentId(db as unknown as DaemonDatabase, silent);

    const row = db
      .prepare("SELECT structure1_cbor, structure2_cbor FROM retry_queue WHERE nonce_hex='aa'")
      .get() as { structure1_cbor: Uint8Array | null; structure2_cbor: Uint8Array | null };
    expect(
      row.structure1_cbor,
      "without the relay's signed ordering record the recipient places this content at its ARRIVAL " +
        "index rather than its witnessed sequence, and the two trees part — on the one boot that upgrades",
    ).not.toBeNull();
    expect(Buffer.from(row.structure1_cbor!).toString("hex")).toBe(S1.toString("hex"));
    expect(Buffer.from(row.structure2_cbor!).toString("hex")).toBe(S2.toString("hex"));
  });

  it("★ the CONTENT-HASH ALGORITHM survives — part B2b's own column, added without repeating the bug", () => {
    /**
     * The reason this file exists at all: B2b needs `retry_queue` to remember which algorithm a
     * queued message was hashed under, because the crash-backstop park producer has no other source
     * for it — the frame is long gone. Adding a column to this table without adding it to the
     * rebuild is precisely the defect above, and it has now been made three times on this milestone.
     */
    const db = legacyDbWithOrderingRecord();
    migrateSessionTablesToAgentId(db as unknown as DaemonDatabase, silent);

    const row = db
      .prepare("SELECT content_hash_alg FROM retry_queue WHERE nonce_hex='aa'")
      .get() as { content_hash_alg: string | null };
    expect(
      row.content_hash_alg,
      "a queued message that loses its algorithm is re-parked as sha256 and refused by the recipient",
    ).toBe("hmac-sha256-salt-v1");
  });

  it("★ a row that never had an algorithm migrates to NULL, not to a fabricated value", () => {
    /**
     * The counterexample, and it is load-bearing rather than symmetry: `undefined`/NULL is what
     * `resolveContentHashAlg` reads as "a peer that predates the field", which is the only value
     * meaning legacy. A migration that invented `"sha256"` here would erase the distinction between
     * "we recorded sha256" and "we recorded nothing" — the collapse B1 and B2a both had to fix.
     */
    const db = legacyDbWithOrderingRecord();
    db.prepare(
      `INSERT INTO retry_queue (session_id, agent_name, nonce_hex, content_blob, queued_at, position)
       VALUES ('s1','alice','bb',x'02',1,2)`,
    ).run();
    migrateSessionTablesToAgentId(db as unknown as DaemonDatabase, silent);

    const row = db
      .prepare("SELECT content_hash_alg FROM retry_queue WHERE nonce_hex='bb'")
      .get() as { content_hash_alg: string | null };
    expect(row.content_hash_alg).toBeNull();
  });
});
