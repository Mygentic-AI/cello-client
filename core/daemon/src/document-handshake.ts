/**
 * DOD-DOC-HANDSHAKE-1 — the document handshake, daemon side (§16.3).
 *
 * Mirrors the attestation-consent pattern operators already understand: a proposal arrives, sits
 * as a pending item, and is accepted or refused once. On accept both sides mint the document from
 * the agreed starting content.
 *
 * ── WHY ACCEPTANCE IS COMPARE-AND-SET ─────────────────────────────────────────────────────────
 *
 * `UPDATE … WHERE consent_state = 'pending'`, and the row count is the answer. Read-then-write
 * would let two concurrent accepts — an agent and a CLI, or two windows on one machine, both real
 * on a multi-attended daemon — each see `pending`, each create the document, and each report
 * success. Worse in the other direction: a REFUSED proposal re-read as pending would be accepted
 * after the operator declined it, which is the one outcome consent exists to make impossible.
 *
 * The same reasoning applies to refuse. Both transitions are terminal and both are guarded.
 *
 * ── WHY THE SEAM IS CHECKED AGAIN HERE ────────────────────────────────────────────────────────
 *
 * `seamViolation` already ran when the proposal was recorded. It runs again at accept because the
 * proposer and the accepter run DIFFERENT BUILDS: a peer one version ahead can propose a value
 * this build cannot honour, and if only the proposer validated, whichever side is newer would
 * silently decide the terms for both. Re-checking at the transition is also what makes an upgrade
 * safe — a proposal recorded under an older build cannot be accepted under rules it predates.
 */

import {
  decodeDocumentProposal,
  documentIdFromProposal,
  encodeDocumentProposal,
  seamViolation,
  DOCUMENT_FEATURE_VERSION,
  type DocumentConsentState,
  type DocumentProposalEnvelope,
} from "@cello-protocol/protocol-types";
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";

const CREATE_PROPOSALS_SQL = `
  CREATE TABLE IF NOT EXISTS document_proposals (
    owner_agent_id  TEXT    NOT NULL,
    document_id     TEXT    NOT NULL,
    proposer_agent_id TEXT  NOT NULL,
    peer_agent_id   TEXT    NOT NULL,
    -- The proposal envelope as it arrived. Kept whole rather than exploded into columns, because
    -- document_id is the hash of exactly these bytes: reconstructing them from columns would make
    -- the identity depend on this schema's round-trip fidelity forever.
    envelope        BLOB    NOT NULL,
    consent_state   TEXT    NOT NULL CHECK (consent_state IN ('pending', 'accepted', 'refused')),
    -- Why it was refused, when it was. An operator who declined a proposal weeks ago, or whose
    -- daemon declined it on a seam violation, has no other record of which it was.
    refusal_reason  TEXT,
    created_at      INTEGER NOT NULL,
    decided_at      INTEGER,
    PRIMARY KEY (owner_agent_id, document_id),
    CHECK (consent_state <> 'refused' OR refusal_reason IS NOT NULL)
  );
`;

export interface DocumentProposalRecord {
  documentId: string;
  proposerAgentId: string;
  peerAgentId: string;
  envelope: DocumentProposalEnvelope;
  consentState: DocumentConsentState;
  refusalReason?: string;
  createdAtMs: number;
  decidedAtMs?: number;
}

export type AcceptOutcome =
  | { ok: true; documentId: string; envelope: DocumentProposalEnvelope }
  | { ok: false; reason: string; detail: string };

export class DocumentHandshake {
  readonly #db: DaemonDatabase;
  readonly #logger: Logger;

  constructor(db: DaemonDatabase, logger: Logger) {
    this.#db = db;
    this.#logger = logger;
    this.#db.exec(CREATE_PROPOSALS_SQL);
  }

  /**
   * Record an arriving proposal as PENDING, or refuse it outright.
   *
   * A seam violation or a version mismatch is recorded as `refused` with its reason rather than
   * dropped, so the operator can see that a peer tried and why it could not proceed. A dropped
   * proposal is indistinguishable from a peer that never sent one.
   */
  recordProposal(
    ownerAgentId: string,
    wire: Uint8Array,
    nowMs: number,
  ): { documentId: string; state: DocumentConsentState; reason?: string } {
    const envelope = decodeDocumentProposal(wire);
    const documentId = documentIdFromProposal(envelope);

    const incompatible =
      envelope.feature_version === DOCUMENT_FEATURE_VERSION
        ? null
        : `document_feature_version_mismatch: the proposal declares document feature version ` +
          `${envelope.feature_version} and this client speaks ${DOCUMENT_FEATURE_VERSION}`;
    const reason = incompatible ?? seamViolation(envelope.properties);

    this.#db
      .prepare(
        `INSERT INTO document_proposals
           (owner_agent_id, document_id, proposer_agent_id, peer_agent_id, envelope,
            consent_state, refusal_reason, created_at, decided_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (owner_agent_id, document_id) DO NOTHING`,
      )
      .run(
        ownerAgentId,
        documentId,
        envelope.proposer_agent_id,
        envelope.peer_agent_id,
        Buffer.from(encodeDocumentProposal(envelope)),
        reason ? "refused" : "pending",
        reason,
        nowMs,
        reason ? nowMs : null,
      );

    if (reason) {
      this.#logger.warn("document.proposal.refused", { documentId, reason, autoRefused: true });
      return { documentId, state: "refused", reason };
    }
    this.#logger.info("document.proposal.pending", {
      documentId,
      proposerAgentId: envelope.proposer_agent_id,
    });
    return { documentId, state: "pending" };
  }

  /** Proposals still awaiting a decision — the operator's inbox for documents. */
  pending(ownerAgentId: string): DocumentProposalRecord[] {
    return this.#rows(ownerAgentId, "WHERE owner_agent_id = ? AND consent_state = 'pending'", []);
  }

  get(ownerAgentId: string, documentId: string): DocumentProposalRecord | null {
    const rows = this.#rows(
      ownerAgentId,
      "WHERE owner_agent_id = ? AND document_id = ?",
      [documentId],
    );
    return rows[0] ?? null;
  }

  /**
   * Accept a pending proposal. Compare-and-set: the transition happens iff the row was still
   * pending, and the affected-row count is what says so.
   */
  accept(ownerAgentId: string, documentId: string, nowMs: number): AcceptOutcome {
    const record = this.get(ownerAgentId, documentId);
    if (!record) {
      return {
        ok: false,
        reason: "document_proposal_unknown",
        detail: `no proposal ${documentId.slice(0, 16)}… for this agent`,
      };
    }

    // Re-checked at the transition, not merely at arrival — the proposer runs a different build.
    const violation = seamViolation(record.envelope.properties);
    if (violation) {
      return { ok: false, reason: "document_seam_violation", detail: violation };
    }

    const info = this.#db
      .prepare(
        `UPDATE document_proposals SET consent_state = 'accepted', decided_at = ?
          WHERE owner_agent_id = ? AND document_id = ? AND consent_state = 'pending'`,
      )
      .run(nowMs, ownerAgentId, documentId);

    if (Number(info.changes) === 0) {
      // The row exists but was not pending. Naming the state it IS in is the whole value of the
      // message: "already accepted" and "you refused this" are different facts to an operator, and
      // a generic failure would read as a bug in the handshake.
      const now = this.get(ownerAgentId, documentId);
      return {
        ok: false,
        reason: "document_proposal_not_pending",
        detail:
          `proposal ${documentId.slice(0, 16)}… is ${now?.consentState ?? "gone"}` +
          (now?.refusalReason ? ` (${now.refusalReason})` : "") +
          " — a consent decision is made once",
      };
    }

    this.#logger.info("document.proposal.accepted", { documentId });
    return { ok: true, documentId, envelope: record.envelope };
  }

  /** Refuse a pending proposal. Same compare-and-set guard; a reason is mandatory. */
  refuse(
    ownerAgentId: string,
    documentId: string,
    reason: string,
    nowMs: number,
  ): { ok: true } | { ok: false; reason: string; detail: string } {
    if (reason.trim().length === 0) {
      // The column's CHECK enforces this too. Refused here so the caller gets a usable error
      // rather than a constraint violation naming a column.
      throw new Error("document_refusal_reason_required: a refusal must say why");
    }
    const info = this.#db
      .prepare(
        `UPDATE document_proposals SET consent_state = 'refused', refusal_reason = ?, decided_at = ?
          WHERE owner_agent_id = ? AND document_id = ? AND consent_state = 'pending'`,
      )
      .run(reason, nowMs, ownerAgentId, documentId);

    if (Number(info.changes) === 0) {
      const now = this.get(ownerAgentId, documentId);
      return {
        ok: false,
        reason: "document_proposal_not_pending",
        detail: `proposal ${documentId.slice(0, 16)}… is ${now?.consentState ?? "unknown"} — a consent decision is made once`,
      };
    }
    this.#logger.info("document.proposal.refused", { documentId, reason, autoRefused: false });
    return { ok: true };
  }

  #rows(ownerAgentId: string, where: string, extra: unknown[]): DocumentProposalRecord[] {
    const rows = this.#db
      .prepare(`SELECT * FROM document_proposals ${where} ORDER BY created_at ASC, rowid ASC`)
      .all(ownerAgentId, ...extra) as Array<Record<string, unknown>>;
    return rows.map((r) => ({
      documentId: r["document_id"] as string,
      proposerAgentId: r["proposer_agent_id"] as string,
      peerAgentId: r["peer_agent_id"] as string,
      envelope: decodeDocumentProposal(new Uint8Array(r["envelope"] as Uint8Array)),
      consentState: r["consent_state"] as DocumentConsentState,
      refusalReason: (r["refusal_reason"] as string | null) ?? undefined,
      createdAtMs: r["created_at"] as number,
      decidedAtMs: (r["decided_at"] as number | null) ?? undefined,
    }));
  }
}
