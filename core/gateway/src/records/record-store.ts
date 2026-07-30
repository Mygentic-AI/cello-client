/**
 * M9-REC-001 — local security-pass records.
 *
 * The gateway records what it did to EVERY message it screens — clean / redacted / blocked / warned —
 * in the gateway's SQLCipher store, opened with the daemon's key (DOD-M9B-STORE-1; INV-4 as amended).
 * Each record is hash-chained to the
 * prior one (a per-record fingerprint over the record fields + the previous fingerprint), so a NAIVELY
 * edited, deleted (mid-chain), or reordered record breaks the chain and `verifyChain()` returns false.
 * A CLEAN pass is recorded too: an ABSENT record for a delivered message is itself evidence of suppression.
 *
 * Local limit (the chain is an UNKEYED sha256): an actor with DB write access can still TAIL-TRUNCATE the
 * most recent records or rewrite the WHOLE chain consistently and pass `verifyChain()`. Detecting that
 * needs the Phase-2 attested head anchored on the directory (M9-ATTEST-001) — this store is the local
 * half; the fingerprint computed here is exactly what that head attests.
 *
 * This is the cheap, local half of #5 (tamper-proof records). Sending each fingerprint to the directory
 * for cross-node tamper detection is Phase-2 (M9-ATTEST-001); the fingerprint computed here is exactly
 * what gets attested, so Phase 2 is an add, not a rework.
 */
import { openEncryptedStoreDb, type StoreDb, type StoreEventSink } from "../store/encrypted-db.js";
import { createHash } from "node:crypto";

export type RecordDisposition = "clean" | "redact" | "block" | "warn";
export type RecordDirection = "inbound" | "outbound";

export interface RecordInput {
  direction: RecordDirection;
  disposition: RecordDisposition;
  /** Hex SHA-256 of the exact bytes the gateway screened — binds the record to the content. */
  contentHash: string;
  reason?: string;
  correlationId?: string;
}

export interface SecurityRecord extends RecordInput {
  seq: number;
  fingerprint: string;
  recordedAt: number;
}

const DDL = `
CREATE TABLE IF NOT EXISTS security_records (
  seq              INTEGER PRIMARY KEY,
  direction        TEXT    NOT NULL,
  disposition      TEXT    NOT NULL,
  content_hash     TEXT    NOT NULL,
  reason           TEXT    NOT NULL,
  correlation_id   TEXT    NOT NULL,
  fingerprint      TEXT    NOT NULL,
  prev_fingerprint TEXT    NOT NULL,
  recorded_at      INTEGER NOT NULL
);
`;

/** The hash-chain fingerprint over a record's fields + the prior record's fingerprint. */
function fingerprintOf(
  seq: number,
  direction: string,
  disposition: string,
  contentHash: string,
  reason: string,
  correlationId: string,
  prevFingerprint: string,
): string {
  return createHash("sha256")
    .update(`${seq}|${direction}|${disposition}|${contentHash}|${reason}|${correlationId}|${prevFingerprint}`)
    .digest("hex");
}

export class GatewayRecordStore {
  readonly #db: StoreDb;
  #closed = false;

  /** Opens (creating if absent) the encrypted store at `dbPath`, keyed by the raw 32-byte key in
   *  `keyFilePath` — the daemon's own key file (M9B-D8/D9). Throws GatewayStoreError fail-closed. */
  constructor(dbPath: string, keyFilePath: string, onEvent?: StoreEventSink) {
    this.#db = openEncryptedStoreDb(dbPath, keyFilePath, onEvent);
    this.#db.exec(DDL);
  }

  /** Append a security-pass record for one screened message, hash-chained to the prior record. */
  record(input: RecordInput): SecurityRecord {
    const reason = input.reason ?? "";
    const correlationId = input.correlationId ?? "";
    const recordedAt = Date.now();
    // Read-latest-then-insert as one transaction so two processes on the same file cannot both write
    // the same seq and collide on the PRIMARY KEY (matches CFG-001 L1).
    this.#db.exec("BEGIN IMMEDIATE");
    let seq: number;
    let prevFingerprint: string;
    let fingerprint: string;
    try {
      const latest = this.#latest();
      seq = (latest?.seq ?? 0) + 1;
      prevFingerprint = latest?.fingerprint ?? "";
      fingerprint = fingerprintOf(seq, input.direction, input.disposition, input.contentHash, reason, correlationId, prevFingerprint);
      this.#db
        .prepare(
          `INSERT INTO security_records
             (seq, direction, disposition, content_hash, reason, correlation_id, fingerprint, prev_fingerprint, recorded_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(seq, input.direction, input.disposition, input.contentHash, reason, correlationId, fingerprint, prevFingerprint, recordedAt);
      this.#db.exec("COMMIT");
    } catch (err) {
      this.#db.exec("ROLLBACK");
      throw err;
    }

    return {
      seq,
      direction: input.direction,
      disposition: input.disposition,
      contentHash: input.contentHash,
      ...(input.reason !== undefined ? { reason: input.reason } : {}),
      ...(input.correlationId !== undefined ? { correlationId: input.correlationId } : {}),
      fingerprint,
      recordedAt,
    };
  }

  /** Every record, oldest first. */
  all(): SecurityRecord[] {
    const rows = this.#db
      .prepare(`SELECT seq, direction, disposition, content_hash, reason, correlation_id, fingerprint, recorded_at FROM security_records ORDER BY seq ASC`)
      .all() as Array<{ seq: number; direction: string; disposition: string; content_hash: string; reason: string; correlation_id: string; fingerprint: string; recorded_at: number }>;
    return rows.map((r) => ({
      seq: r.seq,
      direction: r.direction as RecordDirection,
      disposition: r.disposition as RecordDisposition,
      contentHash: r.content_hash,
      ...(r.reason !== "" ? { reason: r.reason } : {}),
      ...(r.correlation_id !== "" ? { correlationId: r.correlation_id } : {}),
      fingerprint: r.fingerprint,
      recordedAt: r.recorded_at,
    }));
  }

  count(): number {
    const row = this.#db.prepare(`SELECT COUNT(*) AS n FROM security_records`).get() as { n: number };
    return row.n;
  }

  /** Recompute the whole chain and confirm every stored fingerprint + prev-link matches (tamper check). */
  verifyChain(): boolean {
    const rows = this.#db
      .prepare(`SELECT seq, direction, disposition, content_hash, reason, correlation_id, fingerprint, prev_fingerprint FROM security_records ORDER BY seq ASC`)
      .all() as Array<{ seq: number; direction: string; disposition: string; content_hash: string; reason: string; correlation_id: string; fingerprint: string; prev_fingerprint: string }>;
    let prevFingerprint = "";
    for (const r of rows) {
      if (r.prev_fingerprint !== prevFingerprint) return false; // a deleted/reordered predecessor
      const expected = fingerprintOf(r.seq, r.direction, r.disposition, r.content_hash, r.reason, r.correlation_id, prevFingerprint);
      if (expected !== r.fingerprint) return false; // an edited field
      prevFingerprint = r.fingerprint;
    }
    return true;
  }

  /**
   * Fold the WAL back into the main file WITHOUT closing (review F1/F2). Closing unlinks
   * `-wal`/`-shm` for every process sharing the file, including the daemon's long-lived handles.
   */
  checkpoint(): void {
    this.#db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#db.close();
  }

  #latest(): { seq: number; fingerprint: string } | undefined {
    return this.#db
      .prepare(`SELECT seq, fingerprint FROM security_records ORDER BY seq DESC LIMIT 1`)
      .get() as { seq: number; fingerprint: string } | undefined;
  }
}
