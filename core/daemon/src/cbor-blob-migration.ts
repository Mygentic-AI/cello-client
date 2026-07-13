/**
 * §1.1 — normalize the persisted FROST blobs to ONE CBOR encoding.
 *
 * `frost_commitments` and `frost_verifying_shares` were written by two producers in two formats:
 * `registration-manager` used the canonical encoder (raw CBOR byte strings), while
 * `session-ceremony`'s refresh path used cbor-x's bare `encode` (TAG-64 typed arrays). So an agent's
 * share blobs CHANGED FORMAT the first time it ran `cello_refresh_shares`, and both formats are on
 * disk in the field right now. It only ever worked because cbor-x's decoder reads both.
 *
 * Both producers now use `encodeCbor`. This rewrites what is already stored so the column holds one
 * encoding, and a reader that is not cbor-x can rely on it.
 *
 * HOW IT DECIDES: decode the blob (cbor-x reads both formats), re-encode canonically, and rewrite
 * ONLY if the bytes differ. That makes it self-checking and idempotent — a canonical blob re-encodes
 * to itself and is skipped, so a second run is a no-op and there is no "have I run yet?" flag to get
 * wrong. It also means the migration cannot be fooled by a blob that merely LOOKS tagged.
 *
 * FAILS SAFE, PER ROW: the blobs are FROST key material. A row we cannot decode is LEFT EXACTLY AS
 * IT WAS and logged — never dropped, never half-written, never "fixed" with a guess. A share we
 * cannot read is a share we must not touch: destroying it makes the agent permanently unable to sign
 * or seal, which is strictly worse than leaving it in an old-but-working encoding that cbor-x still
 * decodes. The whole point of the migration is that nobody ever loses a key to it.
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
 * Compares byte content, not container class. cbor-x decodes a raw byte string to a Node Buffer and
 * a tag-64 to a Uint8Array — the same four bytes in two wrappers. Anything that compares by class
 * (`JSON.stringify`, `toEqual`) calls those different and would refuse every real migration, which
 * is exactly the bug this comment exists to stop someone re-introducing.
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
        // Undecodable key material. Leave it alone — see FAILS SAFE above.
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

      // Re-decode what we are about to write and compare it to what we read, BEFORE we write it.
      // Re-encoding must preserve the VALUE, not merely produce bytes. If canonicalizing ever
      // changed the decoded content, this refuses rather than persist a corrupted share — the one
      // outcome that would leave an agent unable to sign.
      //
      // Compare BYTES, not containers. cbor-x hands a raw byte string back as a Node Buffer and a
      // tag-64 back as a Uint8Array — identical bytes, different wrapper. A JSON.stringify compare
      // sees those as different values and refuses every genuine migration.
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
