/**
 * Positions the other side filed with the relay whose MESSAGE this side never received.
 *
 * The relay announces a leaf (its hash and the author's signed Structure 1) separately from the
 * message itself. If the other side files a hash and withholds the content, this side's
 * "last seen" can move past a message it does not hold. A close signed then claims that position
 * while the local tree lacks the message, so both seals fail at the directory. Checking before the
 * close is signed lets it refuse by name instead.
 */
import { decodeStructure1 } from "@cello-protocol/protocol-types";
import type { DaemonDatabase } from "./sqlcipher-db.js";
import { extractErrorMessage } from "./error-message.js";

const LEAF_KIND_MSG = 0;

/** The close-time form: the check guards a close, so it must never be the thing that breaks one. */
export function withheldPositionsOrNone(
  db: DaemonDatabase | null | undefined,
  logger: { warn(event: string, ctx?: Record<string, unknown>): void },
  args: () => Parameters<typeof withheldPositions>[1],
): number[] {
  if (!db) return [];
  try {
    return withheldPositions(db, args());
  } catch (err: unknown) {
    logger.warn("session.seal.withheld_check.failed", { reason: extractErrorMessage(err) });
    return [];
  }
}

export function withheldPositions(
  db: DaemonDatabase,
  a: { agentId: string; agentPubkeyHex: string; sessionId: string; relaySessionHex: string; upToSeq: number },
): number[] {
  for (const t of ["session_seal_leaves", "session_tree_leaves"]) {
    if (db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(t) === undefined) return [];
  }
  const held = new Set(
    (db.prepare("SELECT leaf_hash_hex AS h FROM session_tree_leaves WHERE agent_id = ? AND session_id = ?")
      .all(a.agentId, a.sessionId) as Array<{ h: string }>).map((r) => r.h),
  );
  const missing: number[] = [];
  for (const r of db
    .prepare(
      `SELECT sequence_number AS seq, structure1_cbor AS s1 FROM session_seal_leaves
        WHERE agent_pubkey = ? AND session_id = ? AND leaf_kind = ? AND sequence_number <= ?
        ORDER BY sequence_number`,
    )
    .all(a.agentPubkeyHex, a.relaySessionHex, LEAF_KIND_MSG, a.upToSeq) as Array<{ seq: number; s1: Uint8Array }>) {
    const d = decodeStructure1(r.s1 instanceof Uint8Array ? r.s1 : new Uint8Array(r.s1));
    if (!d.ok || Buffer.from(d.fields.senderPubkey).toString("hex") === a.agentPubkeyHex) continue;
    if (!held.has(Buffer.from(d.fields.contentHash).toString("hex"))) missing.push(r.seq);
  }
  return missing;
}
