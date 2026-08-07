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
  buildDocumentProposalTbs,
  decodeDocumentProposal,
  documentFeatureIncompatibility,
  documentIdFromProposal,
  encodeDocumentProposal,
  seamViolation,
  type DocumentConsentState,
  type DocumentProposalEnvelope,
} from "@cello-protocol/protocol-types";
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";
import { addColumnIfMissing } from "./column-birth.js";

/**
 * Verify a proposal's signature against the agent that claims to have made it.
 *
 * INJECTED and REQUIRED — this class cannot resolve `proposer_agent_id` to a public key, and a
 * default implementation would be a default answer to "is this authentic". The composition root
 * wires the real one.
 */
export type ProposalSignatureVerifier = (
  proposerAgentId: string,
  tbs: Uint8Array,
  signature: Uint8Array,
) => boolean;

/**
 * NOTE FOR THE NEXT COLUMN. `CREATE TABLE IF NOT EXISTS` is correct only while no daemon has ever
 * created this table — true today, since it is new in an unreleased milestone. The moment any dev
 * or staging DB holds it, adding a column here returns silently and that column never appears on
 * an upgraded database while fresh installs get it. That divergence has already shipped once in
 * this repo (see `consent-migration.ts`). Any future column needs a `PRAGMA table_info` birth-gated
 * ALTER under `BEGIN IMMEDIATE`, following that file.
 */
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

/**
 * COLUMN BIRTH for the peer's answer to a proposal WE authored (the `document_proposal_ack` frame).
 *
 * Separate from the CREATE because a daemon that already holds proposals must gain the columns
 * without losing them. `ALTER TABLE ... ADD COLUMN` throws on a re-run, which is why each is
 * wrapped rather than guarded by a version number nobody maintains.
 *
 * Distinct from `consent_state`, which is OUR decision about THEIR proposal. Overloading one column
 * for both directions is how "we accepted" and "they accepted" become indistinguishable — and the
 * operator surface exists precisely to tell those apart.
 */
const PEER_DECISION_COLUMNS = [
  { column: "peer_accepted", sql: "ALTER TABLE document_proposals ADD COLUMN peer_accepted INTEGER" },
  { column: "peer_reason", sql: "ALTER TABLE document_proposals ADD COLUMN peer_reason TEXT" },
  { column: "peer_decided_at", sql: "ALTER TABLE document_proposals ADD COLUMN peer_decided_at INTEGER" },
  // DID OUR OFFER ACTUALLY LEAVE? Nothing durable recorded it, so `peerAccepted: null` meant both
  // "they have not decided" and "they were never asked" — and the shipped skill told the operator
  // to WAIT, which is wrong for the second. The only place the send outcome ever appeared was the
  // transient response to the propose call itself.
  { column: "proposal_sent_at", sql: "ALTER TABLE document_proposals ADD COLUMN proposal_sent_at INTEGER" },
];

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
  readonly #verify: ProposalSignatureVerifier;

  constructor(db: DaemonDatabase, logger: Logger, verify: ProposalSignatureVerifier) {
    this.#db = db;
    this.#logger = logger;
    this.#verify = verify;
    this.#db.exec(CREATE_PROPOSALS_SQL);
    for (const { column, sql } of PEER_DECISION_COLUMNS) {
      addColumnIfMissing(this.#db, this.#logger, { table: "document_proposals", column, sql });
    }
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

    // AUTHENTICITY FIRST, and it is fatal rather than a recorded refusal. The operator's consent
    // decision rests entirely on the proposal having come from the agent it names, and an
    // unverified proposal must not reach the inbox at all — `ON CONFLICT DO NOTHING` means the
    // FIRST arrival's bytes are the permanent record for a document_id, so anyone who observed the
    // honest proposal (and therefore knows the nonce) could race a byte-variant carrying junk,
    // win the primary key, and permanently poison the id while the honest proposal is silently
    // discarded. The proposer would have to re-propose under a new nonce with no signal why.
    if (!this.#verify(envelope.proposer_agent_id, buildDocumentProposalTbs(envelope), envelope.signature)) {
      this.#logger.error("document.proposal.signature_invalid", {
        documentId,
        proposerAgentId: envelope.proposer_agent_id,
      });
      throw new Error(
        `document_proposal_signature_invalid: the proposal claims to come from ` +
          `${envelope.proposer_agent_id} but its signature does not verify against that agent`,
      );
    }

    // ADDRESSED TO US. `ownerAgentId` comes from the caller and `peer_agent_id` comes from the
    // wire, and on a multi-agent daemon — which is why owner_agent_id is in the key at all — an
    // unchecked pair lets a proposal addressed to agent Z be recorded under agent Y and accepted
    // BY agent Y. Consent would then be taken from a party the proposal never named, while the
    // document_id (which does commit to peer_agent_id) says otherwise, with no error anywhere.
    if (envelope.peer_agent_id !== ownerAgentId) {
      this.#logger.warn("document.proposal.wrong_peer", {
        documentId,
        addressedTo: envelope.peer_agent_id,
        recordedFor: ownerAgentId,
      });
      throw new Error(
        `document_proposal_wrong_peer: this proposal is addressed to ${envelope.peer_agent_id}, ` +
          `not to ${ownerAgentId} — consent belongs to the agent the proposer named`,
      );
    }

    // The HUMAN answer, not a machine label. The clause exists because the alternative to a
    // sentence is a proposal that is never answered, which surfaces as a hang and gets diagnosed
    // as a network fault — and because "upgrade" is useless without saying WHOSE client.
    const incompatible = documentFeatureIncompatibility(envelope.feature_version);
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

    // READ BACK THE ROW, do not report what we intended. On a redelivery the INSERT does nothing —
    // correct — and returning the state we would have written announces a decision the operator
    // already made as still awaiting one, and logs an arrival that did not happen.
    const stored = this.get(ownerAgentId, documentId);
    const state = stored?.consentState ?? (reason ? "refused" : "pending");
    const storedReason = stored?.refusalReason ?? reason ?? undefined;

    if (state === "refused") {
      this.#logger.warn("document.proposal.refused", {
        documentId,
        reason: storedReason,
        autoRefused: true,
      });
      return { documentId, state, reason: storedReason };
    }
    if (state === "pending") {
      this.#logger.info("document.proposal.pending", {
        documentId,
        proposerAgentId: envelope.proposer_agent_id,
      });
    }
    return { documentId, state, ...(storedReason ? { reason: storedReason } : {}) };
  }

  /**
   * Record a proposal WE authored, so it can be re-sent without minting a new one.
   *
   * The proposer had no record of the envelope it sent. That is fine until the send fails — an
   * offline peer is the ordinary case — and then the document exists locally with no way to reach
   * the counterparty: re-proposing mints a fresh nonce, hence a fresh `document_id`, hence a second
   * document, leaving the first as an orphan the operator cannot explain or clear.
   *
   * Stored `accepted`, because we consented by authoring it — so it never appears in our own inbox
   * (`pending` filters on state), which would be an offer to ourselves.
   *
   * Deliberately NOT routed through `recordProposal`: that path's checks are for a proposal
   * ARRIVING — verify the signature against the named proposer, and refuse one not addressed to us.
   * Ours is addressed to the peer by definition, so reusing that path would require weakening the
   * check that stops a proposal being recorded under an agent it never named.
   */
  recordOutgoing(ownerAgentId: string, envelope: DocumentProposalEnvelope, nowMs: number): string {
    const documentId = documentIdFromProposal(envelope);
    this.#db
      .prepare(
        `INSERT INTO document_proposals
           (owner_agent_id, document_id, proposer_agent_id, peer_agent_id, envelope,
            consent_state, refusal_reason, created_at, decided_at)
         VALUES (?, ?, ?, ?, ?, 'accepted', NULL, ?, ?)
         ON CONFLICT (owner_agent_id, document_id) DO NOTHING`,
      )
      .run(
        ownerAgentId,
        documentId,
        envelope.proposer_agent_id,
        envelope.peer_agent_id,
        Buffer.from(encodeDocumentProposal(envelope)),
        nowMs,
        nowMs,
      );
    return documentId;
  }

  /**
   * Record the PEER's answer to a proposal we authored.
   *
   * The caller verifies the signature first — this only stores. Kept as its own method rather than
   * folded into `accept`/`refuse` because those are OUR decision about THEIR proposal, and this is
   * the mirror: their decision about ours. Collapsing them would put a peer-controlled reason
   * through a path whose refusal text is written by the local operator.
   *
   * SETTLE ONCE. A second, contradicting answer is refused rather than applied: a peer that
   * accepted must not be able to later claim it refused, or the proposer tears down a document the
   * peer is still editing.
   */
  recordPeerDecision(
    ownerAgentId: string,
    documentId: string,
    /**
     * WHO IS ANSWERING. Required, and checked against the proposal's own peer.
     *
     * The caller verifies the ack's signature against the agent the frame NAMES, which proves the
     * frame is authentic and says nothing about whether that agent was ever entitled to answer. Any
     * third party with a session to us could sign a well-formed ack for a document we proposed to
     * someone else, and it landed as that someone's decision — reported to the operator as "they
     * said no" for a peer who never saw it. Worse, settle-once is by VALUE, so the real peer's
     * later genuine answer contradicts and is discarded: the poisoned state is permanent.
     *
     * Verified is not authorized. The control path (`recordPeerClose`, `recordPeerKill`) has
     * carried this check from the start; the ack path was written without it.
     */
    ackerAgentId: string,
    decision: { accepted: boolean; reason?: string; decidedAtMs: number },
  ): { ok: true } | { ok: false; reason: string; detail: string } {
    const record = this.get(ownerAgentId, documentId);
    if (!record) {
      return {
        ok: false,
        reason: "document_proposal_unknown",
        detail: `no proposal ${documentId.slice(0, 16)}… authored by this agent`,
      };
    }
    if (ackerAgentId !== record.peerAgentId) {
      this.#logger.warn("document.proposal.ack_not_peer", {
        documentId,
        claimedBy: ackerAgentId,
        peerAgentId: record.peerAgentId,
      });
      return {
        ok: false,
        reason: "document_proposal_ack_not_peer",
        detail:
          `${ackerAgentId} is not the party this proposal was addressed to (${record.peerAgentId}), ` +
          `so their answer is not the decision it asks for`,
      };
    }
    if (record.proposerAgentId !== ownerAgentId) {
      // Their answer to their OWN proposal is not a thing. Recording it would overwrite this
      // operator's consent decision with the counterparty's assertion about it.
      return {
        ok: false,
        reason: "document_proposal_not_ours",
        detail: `proposal ${documentId.slice(0, 16)}… was authored by the peer, not by this agent`,
      };
    }
    const already = this.#peerDecision(ownerAgentId, documentId);
    if (already !== null) {
      if (already === decision.accepted) return { ok: true };
      return {
        ok: false,
        reason: "document_proposal_ack_contradicts",
        detail:
          `the peer already answered this proposal with ${already ? "accepted" : "refused"} and now ` +
          `says ${decision.accepted ? "accepted" : "refused"} — a decision is made once, and both ` +
          `signatures are retained`,
      };
    }
    this.#db
      .prepare(
        `UPDATE document_proposals SET peer_accepted = ?, peer_reason = ?, peer_decided_at = ?
          WHERE owner_agent_id = ? AND document_id = ?`,
      )
      .run(decision.accepted ? 1 : 0, decision.reason ?? null, decision.decidedAtMs, ownerAgentId, documentId);
    this.#logger.info("document.proposal.answered", {
      documentId,
      accepted: decision.accepted,
      reason: decision.reason,
    });
    return { ok: true };
  }

  /** The peer's answer to a proposal we authored: true accepted, false refused, null unanswered. */
  peerDecision(ownerAgentId: string, documentId: string): boolean | null {
    return this.#peerDecision(ownerAgentId, documentId);
  }

  /**
   * The peer's answer AND the words they sent with it.
   *
   * The reason was stored and never read by anything — write-only, which defeats the entire
   * justification for putting it on the wire and making it mandatory there: "a refusal the proposer
   * cannot see a reason for leaves them unable to propose anything better". Enforced at the
   * signature, discarded at the last hop.
   */
  peerAnswer(
    ownerAgentId: string,
    documentId: string,
  ): { accepted: boolean | null; reason: string | null } {
    const row = this.#db
      .prepare(
        "SELECT peer_accepted, peer_reason FROM document_proposals WHERE owner_agent_id = ? AND document_id = ?",
      )
      .get(ownerAgentId, documentId) as { peer_accepted: number | null; peer_reason: string | null } | undefined;
    if (!row || row.peer_accepted === null) return { accepted: null, reason: null };
    return { accepted: row.peer_accepted === 1, reason: row.peer_reason ?? null };
  }

  #peerDecision(ownerAgentId: string, documentId: string): boolean | null {
    const row = this.#db
      .prepare("SELECT peer_accepted FROM document_proposals WHERE owner_agent_id = ? AND document_id = ?")
      .get(ownerAgentId, documentId) as { peer_accepted: number | null } | undefined;
    return row?.peer_accepted === null || row?.peer_accepted === undefined ? null : row.peer_accepted === 1;
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
      // TRANSITION, do not just refuse the call. Leaving the row pending gives the operator an
      // inbox entry they can never clear, carrying no reason — while the arrival path records one
      // for the identical condition. Two behaviours for one fact, and the one that persists is the
      // one with no explanation attached.
      if (record.consentState === "pending") {
        this.#db
          .prepare(
            `UPDATE document_proposals SET consent_state = 'refused', refusal_reason = ?,
                    decided_at = ?
              WHERE owner_agent_id = ? AND document_id = ? AND consent_state = 'pending'`,
          )
          .run(violation, nowMs, ownerAgentId, documentId);
        this.#logger.warn("document.proposal.refused", {
          documentId,
          reason: violation,
          autoRefused: true,
          at: "accept",
        });
      }
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
      // A PROPOSAL THAT DOES NOT EXIST IS NOT ONE THAT WAS ALREADY DECIDED. `accept` checks for the
      // row first and answers `document_proposal_unknown`; this went straight to the UPDATE, found
      // zero changes, and reported a typo'd id as "is unknown — a consent decision is made once".
      // That asserts a decision was recorded, about a proposal nobody ever made, and sends the
      // operator looking for who made it.
      if (!now) {
        return {
          ok: false,
          reason: "document_proposal_unknown",
          detail:
            `no proposal ${documentId.slice(0, 16)}… for this agent — check the id against ` +
            `cello_doc_inbox`,
        };
      }
      return {
        ok: false,
        reason: "document_proposal_not_pending",
        detail: `proposal ${documentId.slice(0, 16)}… is ${now.consentState} — a consent decision is made once`,
      };
    }
    this.#logger.info("document.proposal.refused", { documentId, reason, autoRefused: false });
    return { ok: true };
  }

  /** Record that OUR proposal for this document actually left the machine. */
  markProposalSent(ownerAgentId: string, documentId: string, nowMs: number): void {
    this.#db
      .prepare(
        `UPDATE document_proposals SET proposal_sent_at = ?
          WHERE owner_agent_id = ? AND document_id = ? AND proposal_sent_at IS NULL`,
      )
      .run(nowMs, ownerAgentId, documentId);
  }

  /** Has our proposal for this document left? False also covers "we never authored one". */
  proposalSent(ownerAgentId: string, documentId: string): boolean {
    const row = this.#db
      .prepare(
        `SELECT proposal_sent_at FROM document_proposals
          WHERE owner_agent_id = ? AND document_id = ? AND proposal_sent_at IS NOT NULL LIMIT 1`,
      )
      .get(ownerAgentId, documentId) as { proposal_sent_at?: number } | undefined;
    return row !== undefined;
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
