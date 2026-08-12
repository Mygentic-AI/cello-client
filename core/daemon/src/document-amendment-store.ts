/**
 * DOD-MP-AMEND-1 (daemon half) — the append-only amendment store.
 *
 * One row per epoch per document, holding the amendment AS RECEIVED — the wire bytes, never a
 * re-encode. The bytes are the truth: `chain` decodes them on read, so what replay consumes is
 * exactly what was signed, and a codec asymmetry can never silently rewrite an agreed record
 * (the class of defect TRACE-1 found in the proposal codec).
 *
 * The store owns persistence and chain SHAPE:
 * - **Contiguity** — epoch N appends only onto N-1 rows. An out-of-order arrival is refused by
 *   name, not buffered; amendment-lag buffering is DOD-MP-INBOUND-N-1's design, and until it
 *   lands the honest behaviour is a loud refusal the sender retries.
 * - **Fork refusal** — a different amendment at an occupied epoch is `document_amendment_conflict`,
 *   first record kept. Two rivals for one epoch is a governance fork; absorbing either silently
 *   would have two holders replay different arrangements with no error anywhere.
 * - **Idempotent redelivery** — the same bytes again is `recorded: false`, not an error and not a
 *   second row.
 *
 * What the store does NOT judge: signatures, policy, subject semantics. `deriveArrangement`
 * (protocol-types) rules on those at every consumption, and the inbound path rules BEFORE
 * appending. A row in this table is a claim to be replayed, not an admitted fact.
 */

import {
  decodeDocumentAmendment,
  documentAmendmentHash,
  type DocumentAmendmentEnvelope,
} from "@cello-protocol/protocol-types";
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";

/**
 * Shared with `DocumentStore`, which also execs this (the :353 shared-definition precedent there):
 * every epoch producer already holds a DocumentStore, and `currentDocumentEpoch` reads this table
 * through it — so the table must exist whichever module constructs first. Keep the two consumers
 * on THIS one string.
 */
export const DOCUMENT_AMENDMENTS_CREATE_SQL = `
  CREATE TABLE IF NOT EXISTS document_amendments (
    owner_agent_id  TEXT    NOT NULL,
    document_id     TEXT    NOT NULL,
    epoch_id        INTEGER NOT NULL,
    amendment_hash  TEXT    NOT NULL,
    received_bytes  BLOB    NOT NULL,
    recorded_at     INTEGER NOT NULL,
    PRIMARY KEY (owner_agent_id, document_id, epoch_id)
  );
`;

export interface MembershipVerdict {
  state: "holder" | "removed" | "untouched";
  epochId: number | null;
}

/**
 * The last membership event naming this agent in an ordered chain — ONE implementation, because
 * two walks (the inbound refusal's and the publish gate's) disagreeing about whether someone was
 * removed is two daemons disagreeing about the arrangement.
 */
export function walkMembership(
  chain: readonly DocumentAmendmentEnvelope[],
  agentId: string,
): MembershipVerdict {
  let state: MembershipVerdict["state"] = "untouched";
  let epochId: number | null = null;
  for (const env of chain) {
    if (env.body.subject_agent_id !== agentId) continue;
    if (env.body.kind === "add_holder") {
      state = "holder";
      epochId = env.body.epoch_id;
    } else if (env.body.kind === "remove_holder") {
      state = "removed";
      epochId = env.body.epoch_id;
    }
  }
  return { state, epochId };
}

export interface AmendmentAppendResult {
  /** False on an idempotent redelivery — the row already existed with the same hash. */
  recorded: boolean;
  epochId: number;
  /** Hex of the amendment's TBS hash. */
  amendmentHash: string;
}

export class DocumentAmendmentStore {
  readonly #db: DaemonDatabase;
  readonly #logger: Logger;

  constructor(db: DaemonDatabase, logger: Logger) {
    this.#db = db;
    this.#logger = logger;
    this.#db.exec(DOCUMENT_AMENDMENTS_CREATE_SQL);
  }

  /**
   * Append one amendment from its wire bytes. Decodes first — malformed bytes refuse with the
   * decoder's named reason and nothing is stored.
   */
  append(
    ownerAgentId: string,
    documentId: string,
    receivedBytes: Uint8Array,
    nowMs: number,
  ): AmendmentAppendResult {
    const env = decodeDocumentAmendment(receivedBytes);
    if (env.body.document_id !== documentId) {
      throw new Error(
        `document_amendment_wrong_document: the bytes name ${env.body.document_id}, appending ` +
          `under ${documentId}`,
      );
    }
    const epochId = env.body.epoch_id;
    const hash = Buffer.from(documentAmendmentHash(env.body)).toString("hex");

    const existing = this.#db
      .prepare(
        `SELECT amendment_hash FROM document_amendments
          WHERE owner_agent_id = ? AND document_id = ? AND epoch_id = ?`,
      )
      .get(ownerAgentId, documentId, epochId) as { amendment_hash?: string } | undefined;
    if (existing) {
      if (existing.amendment_hash === hash) {
        return { recorded: false, epochId, amendmentHash: hash };
      }
      this.#logger.error("document.amendment.conflict", {
        documentId,
        epochId,
        storedHash: existing.amendment_hash,
        rivalHash: hash,
      });
      throw new Error(
        `document_amendment_conflict: epoch ${epochId} of ${documentId} already holds ` +
          `${existing.amendment_hash} and a rival amendment ${hash} arrived — a governance fork, ` +
          `refused with the first record kept`,
      );
    }

    const prior = this.currentEpoch(ownerAgentId, documentId);
    if (epochId !== prior + 1) {
      throw new Error(
        `document_amendment_chain_gap: epoch ${epochId} cannot append onto epoch ${prior} — ` +
          `amendments land contiguously, and an out-of-order arrival is retried by its sender, ` +
          `never buffered silently`,
      );
    }

    this.#db
      .prepare(
        `INSERT INTO document_amendments
           (owner_agent_id, document_id, epoch_id, amendment_hash, received_bytes, recorded_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .run(
        ownerAgentId,
        documentId,
        epochId,
        hash,
        // Copied — the caller may reuse or zero its buffer after we return.
        Buffer.from(receivedBytes),
        nowMs,
      );
    this.#logger.info("document.amendment.recorded", {
      documentId,
      epochId,
      amendmentHash: hash,
      kind: env.body.kind,
    });
    return { recorded: true, epochId, amendmentHash: hash };
  }

  /** The ordered chain, decoded from the stored received bytes. */
  chain(ownerAgentId: string, documentId: string): DocumentAmendmentEnvelope[] {
    const rows = this.#db
      .prepare(
        `SELECT received_bytes FROM document_amendments
          WHERE owner_agent_id = ? AND document_id = ?
          ORDER BY epoch_id ASC`,
      )
      .all(ownerAgentId, documentId) as Array<{ received_bytes: Uint8Array }>;
    return rows.map((r) => decodeDocumentAmendment(new Uint8Array(r.received_bytes)));
  }

  /**
   * DOD-MP-REMOVE-1 — this agent's LAST membership event in the recorded chain.
   * "holder" = admitted (or never touched by any membership amendment — genesis membership is
   * the CALLER's fact, not this table's); "removed" = the last event naming them was
   * remove_holder, with the epoch it happened at, so a refusal can name the removal rather than
   * a generic condition. Reads the recorded chain only — validity was ruled before append
   * (the standing invariant).
   */
  membershipOf(
    ownerAgentId: string,
    documentId: string,
    agentId: string,
  ): MembershipVerdict {
    return walkMembership(this.chain(ownerAgentId, documentId), agentId);
  }

  /** The highest recorded epoch, or 0 — genesis — when no amendment exists. */
  currentEpoch(ownerAgentId: string, documentId: string): number {
    const r = this.#db
      .prepare(
        `SELECT MAX(epoch_id) AS max_epoch FROM document_amendments
          WHERE owner_agent_id = ? AND document_id = ?`,
      )
      .get(ownerAgentId, documentId) as { max_epoch?: number | null } | undefined;
    return r?.max_epoch ?? 0;
  }
}
