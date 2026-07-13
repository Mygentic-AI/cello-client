/**
 * Normalize the persisted FROST blobs to the canonical CBOR encoding.
 *
 * `frost_commitments` and `frost_verifying_shares` may hold an older encoding (cbor-x tag-64 or its
 * record extension) alongside the canonical one; cbor-x decodes all three, which is why a mixed
 * column reads correctly and can go unnoticed. This makes the column hold ONE encoding, so a reader
 * that is not cbor-x can parse it.
 *
 * Decode, re-encode canonically, rewrite only if the bytes differ. Self-checking and idempotent: a
 * canonical blob re-encodes to itself and is skipped, so there is no "have I run yet?" flag to get
 * wrong and a second run is a no-op.
 *
 * FAILS SAFE, PER ROW. These blobs are FROST key material. A row that cannot be decoded is LEFT
 * EXACTLY AS IT WAS and reported — never dropped, never half-written, never guessed at. Destroying a
 * share makes the agent permanently unable to sign or seal, which is strictly worse than leaving it
 * in an old encoding that still decodes. Nobody may lose a key to this migration.
 */
import { encodeCbor, decodeCbor } from "@cello-protocol/protocol-types";
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";

/** The columns written by both producers. Both hold CBOR; both must hold the canonical encoding. */
const CBOR_BLOB_COLUMNS = ["frost_commitments", "frost_verifying_shares"] as const;

function toBytes(v: unknown): Uint8Array | null {
  if (v instanceof Uint8Array) return v;
  if (Buffer.isBuffer(v)) return new Uint8Array(v as Buffer);
  return null;
}

/**
 * Do two decoded CBOR values carry the same DATA?
 *
 * Compares byte CONTENT, never container class. cbor-x decodes a byte string to a Node Buffer and a
 * tag-64 to a Uint8Array — identical bytes, different wrapper. A class-sensitive compare
 * (`JSON.stringify`, `toEqual`) calls those unequal and refuses every genuine migration.
 */
function sameDecodedValue(a: unknown, b: unknown): boolean {
  const ab = toBytes(a);
  const bb = toBytes(b);
  if (ab || bb) {
    return ab !== null && bb !== null && Buffer.from(ab).equals(Buffer.from(bb));
  }
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    return a.every((v, i) => sameDecodedValue(v, b[i]));
  }
  if (a && b && typeof a === "object" && typeof b === "object") {
    const ao = a as Record<string, unknown>;
    const bo = b as Record<string, unknown>;
    const ak = Object.keys(ao).sort();
    const bk = Object.keys(bo).sort();
    if (ak.length !== bk.length || ak.some((k, i) => k !== bk[i])) return false;
    return ak.every((k) => sameDecodedValue(ao[k], bo[k]));
  }
  return Object.is(a, b);
}

/**
 * Rewrite any non-canonically-encoded FROST blob in `agents` to the canonical encoding.
 * Idempotent. Safe to run on every daemon start.
 */
export function migrateCborBlobsToCanonical(db: DaemonDatabase, logger: Logger): void {
  // The table may predate these columns (fresh DB, or an install that never registered).
  const columns = new Set(
    (db.prepare("PRAGMA table_info(agents)").all() as Array<{ name: string }>).map((c) => c.name),
  );
  const present = CBOR_BLOB_COLUMNS.filter((c) => columns.has(c));
  if (present.length === 0) return;

  const rows = db
    .prepare(`SELECT agent_id, ${present.join(", ")} FROM agents`)
    .all() as Array<Record<string, unknown>>;

  let rewritten = 0;
  let skipped = 0;

  for (const row of rows) {
    const agentId = String(row["agent_id"]);

    for (const column of present) {
      const stored = toBytes(row[column]);
      if (!stored || stored.length === 0) continue; // never registered / no share — nothing to do

      let canonical: Uint8Array;
      try {
        canonical = encodeCbor(decodeCbor(stored));
      } catch (err: unknown) {
        // Undecodable key material — leave it alone.
        skipped++;
        logger.warn("daemon.cbor.migration.undecodable", {
          agentId,
          column,
          bytes: stored.length,
          error: err instanceof Error ? err.message : String(err),
        });
        continue;
      }

      if (Buffer.from(canonical).equals(Buffer.from(stored))) continue; // already canonical

      // Verify BEFORE writing: re-encoding must preserve the VALUE, not merely produce bytes. If it
      // ever altered the decoded content, refuse rather than persist a corrupted share.
      if (!sameDecodedValue(decodeCbor(canonical), decodeCbor(stored))) {
        skipped++;
        logger.error("daemon.cbor.migration.value_changed", {
          agentId,
          column,
          guidance: "re-encoding altered the decoded value; the blob was NOT rewritten",
        });
        continue;
      }

      db.prepare(`UPDATE agents SET ${column} = ? WHERE agent_id = ?`).run(
        Buffer.from(canonical),
        agentId,
      );
      rewritten++;
      logger.info("daemon.cbor.migration.rewritten", { agentId, column, bytes: canonical.length });
    }
  }

  if (rewritten > 0 || skipped > 0) {
    logger.info("daemon.cbor.migration.complete", { rewritten, skipped, rows: rows.length });
  }
}
