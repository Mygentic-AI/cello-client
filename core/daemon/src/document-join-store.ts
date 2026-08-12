/**
 * DOD-MP-JOIN-1 (daemon half) — the join-offer store: pending consent, both roles, settle-once.
 *
 * One table for both sides of a join (the `document_proposals` precedent): the INVITEE holds the
 * offer they received — as RECEIVED BYTES, validated before recording — and the INVITER holds the
 * offer they authored plus the invitee's signed answer when it arrives. Keyed on
 * `(owner, amendment_hash)`: the admitting amendment is the fact being consented to, and a
 * re-invitation after a refusal is a new amendment with a new hash — a new row, never a
 * reopened one.
 *
 * A refused-at-arrival offer (bad chain, wrong invitee, version mismatch) is RECORDED refused
 * with its reason rather than dropped — a dropped offer is indistinguishable from an inviter who
 * never sent one.
 */

import {
  decodeDocumentJoinOffer,
  decodeDocumentJoinAnswer,
  buildDocumentJoinAnswerTbs,
  type DocumentJoinOffer,
  type DocumentJoinAnswer,
} from "@cello-protocol/protocol-types";
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";

const CREATE_SQL = `
  CREATE TABLE IF NOT EXISTS document_join_offers (
    owner_agent_id   TEXT    NOT NULL,
    document_id      TEXT    NOT NULL,
    amendment_hash   TEXT    NOT NULL,
    role             TEXT    NOT NULL,
    inviter_agent_id TEXT    NOT NULL,
    invitee_agent_id TEXT    NOT NULL,
    received_bytes   BLOB    NOT NULL,
    state            TEXT    NOT NULL,
    reason           TEXT,
    answer_bytes     BLOB,
    created_at       INTEGER NOT NULL,
    decided_at       INTEGER,
    PRIMARY KEY (owner_agent_id, amendment_hash)
  );
`;

export type JoinOfferState = "pending" | "accepted" | "refused";
export type JoinOfferRole = "invitee" | "inviter";

export interface JoinOfferRecord {
  documentId: string;
  amendmentHash: string;
  role: JoinOfferRole;
  inviterAgentId: string;
  inviteeAgentId: string;
  offer: DocumentJoinOffer;
  state: JoinOfferState;
  reason: string | null;
  createdAtMs: number;
  decidedAtMs: number | null;
}

export class DocumentJoinStore {
  readonly #db: DaemonDatabase;
  readonly #logger: Logger;

  constructor(db: DaemonDatabase, logger: Logger) {
    this.#db = db;
    this.#logger = logger;
    this.#db.exec(CREATE_SQL);
  }

  /**
   * Record an ARRIVING offer under the invitee's key — already validated by the caller; a
   * validation refusal is recorded as `refused` with its reason, never dropped. First arrival's
   * bytes are the permanent record; a redelivery changes nothing.
   */
  recordIncoming(
    ownerAgentId: string,
    wire: Uint8Array,
    amendmentHash: string,
    verdict: { state: "pending" } | { state: "refused"; reason: string },
    nowMs: number,
  ): { state: JoinOfferState; reason?: string } {
    const offer = decodeDocumentJoinOffer(wire);
    this.#db
      .prepare(
        `INSERT INTO document_join_offers
           (owner_agent_id, document_id, amendment_hash, role, inviter_agent_id, invitee_agent_id,
            received_bytes, state, reason, created_at, decided_at)
         VALUES (?, ?, ?, 'invitee', ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (owner_agent_id, amendment_hash) DO NOTHING`,
      )
      .run(
        ownerAgentId,
        offer.document_id,
        amendmentHash,
        offer.inviter_agent_id,
        offer.invitee_agent_id,
        Buffer.from(wire),
        verdict.state,
        verdict.state === "refused" ? verdict.reason : null,
        nowMs,
        verdict.state === "refused" ? nowMs : null,
      );
    // Read back — on a redelivery the INSERT did nothing and the operator's earlier decision
    // stands; reporting our intended state would announce a decided offer as pending.
    const stored = this.get(ownerAgentId, amendmentHash);
    const state = stored?.state ?? verdict.state;
    const reason = stored?.reason ?? (verdict.state === "refused" ? verdict.reason : undefined);
    this.#logger.info("document.join.offer_recorded", {
      documentId: offer.document_id,
      amendmentHash,
      state,
    });
    return { state, ...(reason ? { reason } : {}) };
  }

  /** Record an offer WE authored, pending the invitee's answer. */
  recordOutgoing(ownerAgentId: string, wire: Uint8Array, amendmentHash: string, nowMs: number): void {
    const offer = decodeDocumentJoinOffer(wire);
    this.#db
      .prepare(
        `INSERT INTO document_join_offers
           (owner_agent_id, document_id, amendment_hash, role, inviter_agent_id, invitee_agent_id,
            received_bytes, state, reason, created_at, decided_at)
         VALUES (?, ?, ?, 'inviter', ?, ?, ?, 'pending', NULL, ?, NULL)
         ON CONFLICT (owner_agent_id, amendment_hash) DO NOTHING`,
      )
      .run(
        ownerAgentId,
        offer.document_id,
        amendmentHash,
        offer.inviter_agent_id,
        offer.invitee_agent_id,
        Buffer.from(wire),
        nowMs,
      );
  }

  /**
   * The INVITEE's local decision. Settle-once: only a pending row decides, and the caller learns
   * whether THIS call decided it — an already-decided offer is a fact to report, not an error.
   */
  decide(
    ownerAgentId: string,
    amendmentHash: string,
    accepted: boolean,
    reason: string | null,
    nowMs: number,
  ): { decided: boolean; state: JoinOfferState } {
    const r = this.#db
      .prepare(
        `UPDATE document_join_offers
            SET state = ?, reason = ?, decided_at = ?
          WHERE owner_agent_id = ? AND amendment_hash = ? AND role = 'invitee' AND state = 'pending'`,
      )
      .run(accepted ? "accepted" : "refused", reason, nowMs, ownerAgentId, amendmentHash);
    const stored = this.get(ownerAgentId, amendmentHash);
    return { decided: (r.changes ?? 0) > 0, state: stored?.state ?? "pending" };
  }

  /**
   * Record the invitee's signed ANSWER on the inviter's side. The caller verifies the signature
   * against the invitee named in the STORED offer first. Settle-once: a contradicting second
   * answer is refused with both records retained (the stored answer stands).
   */
  recordAnswer(
    ownerAgentId: string,
    wire: Uint8Array,
    verify: (agentId: string, tbs: Uint8Array, signature: Uint8Array) => boolean,
    nowMs: number,
  ): { ok: true; answer: DocumentJoinAnswer; settled: boolean } | { ok: false; reason: string } {
    const answer = decodeDocumentJoinAnswer(wire);
    const stored = this.get(ownerAgentId, answer.amendment_hash);
    if (!stored || stored.role !== "inviter") {
      return {
        ok: false,
        reason:
          `join_answer_unknown_offer: no offer of ours is settled by amendment ` +
          `${answer.amendment_hash.slice(0, 16)}…`,
      };
    }
    if (answer.invitee_agent_id !== stored.inviteeAgentId) {
      return {
        ok: false,
        reason: `join_answer_wrong_invitee: the answer names ${answer.invitee_agent_id} and the ` +
          `offer invited ${stored.inviteeAgentId}`,
      };
    }
    if (!verify(stored.inviteeAgentId, buildDocumentJoinAnswerTbs(answer), answer.signature)) {
      return {
        ok: false,
        reason: `join_answer_signature_invalid: the answer does not verify against the invitee ` +
          `${stored.inviteeAgentId}`,
      };
    }
    if (stored.state !== "pending") {
      const contradicts =
        (stored.state === "accepted") !== answer.accepted;
      if (contradicts) {
        this.#logger.error("document.join.answer_contradiction", {
          documentId: stored.documentId,
          amendmentHash: answer.amendment_hash,
          stored: stored.state,
          arriving: answer.accepted ? "accepted" : "refused",
        });
        return {
          ok: false,
          reason:
            "join_answer_contradiction: this offer was already settled with the opposite answer — " +
            "settle once; both signed answers are retained in the log",
        };
      }
      return { ok: true, answer, settled: false };
    }
    this.#db
      .prepare(
        `UPDATE document_join_offers
            SET state = ?, reason = ?, answer_bytes = ?, decided_at = ?
          WHERE owner_agent_id = ? AND amendment_hash = ? AND state = 'pending'`,
      )
      .run(
        answer.accepted ? "accepted" : "refused",
        answer.refusal_reason,
        Buffer.from(wire),
        nowMs,
        ownerAgentId,
        answer.amendment_hash,
      );
    this.#logger.info("document.join.answer_recorded", {
      documentId: stored.documentId,
      amendmentHash: answer.amendment_hash,
      accepted: answer.accepted,
    });
    return { ok: true, answer, settled: true };
  }

  get(ownerAgentId: string, amendmentHash: string): JoinOfferRecord | null {
    const r = this.#db
      .prepare(
        `SELECT * FROM document_join_offers WHERE owner_agent_id = ? AND amendment_hash = ?`,
      )
      .get(ownerAgentId, amendmentHash) as Record<string, unknown> | undefined;
    return r ? rowToRecord(r) : null;
  }

  /** Auto-refused arrivals — surfaced so the refusal sentence reaches an operator. */
  refusedFor(ownerAgentId: string): JoinOfferRecord[] {
    const rows = this.#db
      .prepare(
        `SELECT * FROM document_join_offers
          WHERE owner_agent_id = ? AND role = 'invitee' AND state = 'refused'
          ORDER BY created_at ASC`,
      )
      .all(ownerAgentId) as Array<Record<string, unknown>>;
    return rows.map(rowToRecord);
  }

  /** Offers THIS owner authored — the inviter's view of who has answered what. */
  outgoingFor(ownerAgentId: string): JoinOfferRecord[] {
    const rows = this.#db
      .prepare(
        `SELECT * FROM document_join_offers
          WHERE owner_agent_id = ? AND role = 'inviter'
          ORDER BY created_at ASC`,
      )
      .all(ownerAgentId) as Array<Record<string, unknown>>;
    return rows.map(rowToRecord);
  }

  /** Offers awaiting THIS owner's consent — the inbox surface. */
  pendingFor(ownerAgentId: string): JoinOfferRecord[] {
    const rows = this.#db
      .prepare(
        `SELECT * FROM document_join_offers
          WHERE owner_agent_id = ? AND role = 'invitee' AND state = 'pending'
          ORDER BY created_at ASC`,
      )
      .all(ownerAgentId) as Array<Record<string, unknown>>;
    return rows.map(rowToRecord);
  }
}

function rowToRecord(r: Record<string, unknown>): JoinOfferRecord {
  return {
    documentId: r["document_id"] as string,
    amendmentHash: r["amendment_hash"] as string,
    role: r["role"] as JoinOfferRole,
    inviterAgentId: r["inviter_agent_id"] as string,
    inviteeAgentId: r["invitee_agent_id"] as string,
    offer: decodeDocumentJoinOffer(new Uint8Array(r["received_bytes"] as Uint8Array)),
    state: r["state"] as JoinOfferState,
    reason: (r["reason"] as string | null) ?? null,
    createdAtMs: r["created_at"] as number,
    decidedAtMs: (r["decided_at"] as number | null) ?? null,
  };
}
