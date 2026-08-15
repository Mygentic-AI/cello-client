/**
 * SYNC-P3 (R10, R17–R20, R36) — the responder half of the reconcile exchange.
 *
 * Given a peer's position for one document, decide from OUR OWN state alone whether they may be
 * answered at all (the four entitlement classes, R17), and if so compute exactly what they lack:
 * governance entries first, then content envelopes, never anything in their refusal set (R36).
 * The reply carries our own position so the initiator can send step 3 if WE are behind — the
 * exchange is symmetric by construction.
 *
 * Everything here is derived at the moment of the exchange from the entry set and the envelope
 * log. There is no per-peer record consulted and none written (R8/R9): asked twice, we answer
 * twice, identically — idempotence is not bookkeeping, it is the absence of bookkeeping.
 */

import {
  decodeDocumentAmendment,
  documentAmendmentHash,
  encodeDocumentUpdateEnvelope,
  DOCUMENT_UPDATE_ENCODING_V1,
  type DocumentReconcileBlock,
  type GovernancePosition,
  type ContentPosition,
  type DocumentStateView,
} from "@cello-protocol/protocol-types";
import type { DocumentEnvelopeRow } from "./document-store.js";
import type { AuthorWatermark } from "./document-amendment-store.js";

/** The reads the engine needs — a seam so the tests exercise decisions, not plumbing. */
export interface ReconcileReads {
  deriveState(documentId: string): { ok: true; state: DocumentStateView } | { ok: false; reason: string };
  watermarks(documentId: string): Map<string, AuthorWatermark>;
  entriesByAuthorAfter(documentId: string, author: string, afterSeq: number): Uint8Array[];
  envelopeLog(documentId: string): DocumentEnvelopeRow[];
  /** Hashes THIS holder has refused — its own decisions, surfaced into its position (R36). */
  refusedHashes(documentId: string): string[];
  /** The interim membership walk — "removed" is the one verdict consulted here. */
  membershipState(documentId: string, agentId: string): "holder" | "removed" | "untouched";
  /** The signed genesis proposal bytes — the anchor a joiner-with-nothing must be handed. */
  genesisBytes(documentId: string): Uint8Array | null;
  /**
   * R32 — the LAST removal entry naming this agent plus its full ancestor closure, as wire
   * bytes in a foldable order, or null when no removal names them. This is what a removed
   * holder is owed: enough to derive their own removal and nothing authored after it.
   */
  removalClosure(documentId: string, agentId: string): Uint8Array[] | null;
}

export type ReconcileAnswer = {
  block: DocumentReconcileBlock;
  /** True when the peer's position shows them holding something we lack — step 3 is wanted. */
  peerAhead: boolean;
  /** True when the byte budget cut the payload short — the peer's next exchange gets the rest. */
  truncated: boolean;
};

/** A mutable byte allowance shared across the blocks of one reply frame (P3 review F3). */
export interface ReplyBudget {
  remainingBytes: number;
}

/** Our own position for one document — step 1's payload, and the position half of every reply. */
export function buildReconcileBlock(
  reads: ReconcileReads,
  documentId: string,
): DocumentReconcileBlock {
  const governance: GovernancePosition[] = [...reads.watermarks(documentId)]
    .map(([author, mark]) => ({
      author,
      seq: mark.seq,
      head_hashes: [...mark.headHashes].sort(),
    }))
    .sort((a, b) => (a.author < b.author ? -1 : 1));

  const content: ContentPosition[] = contentPositions(reads.envelopeLog(documentId));

  return {
    document_id: documentId,
    governance,
    content,
    refused: [...reads.refusedHashes(documentId)].sort(),
    entries: [],
    envelopes: [],
  };
}

function contentPositions(log: DocumentEnvelopeRow[]): ContentPosition[] {
  const bySender = new Map<string, DocumentEnvelopeRow[]>();
  for (const row of log) {
    const rows = bySender.get(row.senderAgentId);
    if (rows) rows.push(row);
    else bySender.set(row.senderAgentId, [row]);
  }
  return [...bySender]
    .map(([author, rows]) => ({
      author,
      count: rows.length,
      head_hash: rows[rows.length - 1]!.envelopeHash,
    }))
    .sort((a, b) => (a.author < b.author ? -1 : 1));
}

/**
 * Answer a peer's position for one document. The entitlement ruling comes FIRST and from our
 * own state alone (R18); a refusal rides the BLOCK (never silenced by a batch, review F4), and
 * a refusal-bearing block carries EMPTY positions — a stranger learns nothing about where this
 * holder stands. The removed holder is the one refusal that also DELIVERS: their own removal
 * and its ancestors travel with the terminal ruling (R32), so a holder who was offline at
 * removal time can derive why the document went quiet.
 */
export function respondToReconcile(
  reads: ReconcileReads,
  peerAgentId: string,
  peerBlock: DocumentReconcileBlock,
  budget?: ReplyBudget,
): ReconcileAnswer {
  const documentId = peerBlock.document_id;
  const refusalBlock = (reason: string, terminal: boolean, entries: Uint8Array[] = []): ReconcileAnswer => ({
    block: {
      document_id: documentId,
      governance: [],
      content: [],
      refused: [],
      entries,
      envelopes: [],
      refusal: { reason, terminal },
    },
    peerAhead: false,
    truncated: false,
  });

  const derived = reads.deriveState(documentId);
  if (!derived.ok) {
    return refusalBlock(`document_reconcile_underivable: ${derived.reason}`, false);
  }
  const state = derived.state;

  // R17 — the four classes, from OUR state, never a stored flag.
  const isParticipant = state.participants.has(peerAgentId);
  const isInvited = state.invited.has(peerAgentId);
  if (!isParticipant && !isInvited) {
    if (reads.membershipState(documentId, peerAgentId) === "removed") {
      // R32: the ruling is terminal, but it DELIVERS — the removal entry and its ancestors,
      // so the removed holder can derive their own removal, surface it with its reason, and
      // stop asking. Idempotent like everything here: asking again gets the same closure.
      const closure = reads.removalClosure(documentId, peerAgentId) ?? [];
      return refusalBlock(
        `document_reconcile_removed: this holder was removed — the removal is forward-only ` +
          `(the copy is theirs); the removal entry and its ancestors are attached so their own ` +
          `derivation can say so, and there is nothing further to reconcile`,
        true,
        closure,
      );
    }
    // R18 + R19: refused by name, NON-terminal, and the sentence says why it is not final — a
    // legitimate joiner is exactly this refusal whenever their inviter's admission has not yet
    // reached us, and a terminal answer here would strand them (the failure R19 names).
    return refusalBlock(
      `document_reconcile_stranger: ${peerAgentId} is not a party to this document AS THIS ` +
        `HOLDER CURRENTLY DERIVES IT — non-terminal: if you were admitted, the admission may ` +
        `not have reached us yet; reconcile again after your inviter's entries spread`,
      false,
    );
  }

  const peerRefused = new Set(peerBlock.refused);
  const block = buildReconcileBlock(reads, documentId);
  let truncated = false;
  const spend = (wire: Uint8Array): boolean => {
    if (!budget) return true;
    if (budget.remainingBytes < wire.length) {
      truncated = true;
      return false;
    }
    budget.remainingBytes -= wire.length;
    return true;
  };

  // Governance difference — R12 says these apply first, so they are FIRST in the frame.
  const peerGov = new Map(peerBlock.governance.map((g) => [g.author, g]));
  const entries: Uint8Array[] = [];
  for (const mine of block.governance) {
    const theirs = peerGov.get(mine.author);
    // Behind: everything past their contiguous seq. Fork at the SAME seq (heads differ):
    // re-offer from one before the fork point, so both branches reach them and their fold —
    // like ours — rules on the fork (the Entry 48 §3 detection path).
    let fromSeq: number | null = null;
    if (!theirs) fromSeq = 0;
    else if (theirs.seq < mine.seq) fromSeq = theirs.seq;
    else if (
      theirs.seq === mine.seq &&
      [...theirs.head_hashes].sort().join(",") !== mine.head_hashes.join(",")
    ) {
      fromSeq = Math.max(0, mine.seq - 1);
    }
    if (fromSeq === null) continue;
    for (const wire of reads.entriesByAuthorAfter(documentId, mine.author, fromSeq)) {
      const hash = Buffer.from(documentAmendmentHash(decodeDocumentAmendment(wire).body)).toString(
        "hex",
      );
      if (peerRefused.has(hash)) continue; // R36: nothing refused is ever re-offered
      if (!spend(wire)) break;
      entries.push(wire);
    }
    if (truncated) break;
  }

  // Content difference — the sender-chain suffix past the peer's count, re-encoded losslessly
  // from the log rows (the join-offer snapshot precedent). Refused rows carry no payload and
  // cannot be re-offered; the hole they leave is named by OUR refusal set in the block.
  const peerContent = new Map(peerBlock.content.map((c) => [c.author, c]));
  const log = reads.envelopeLog(documentId);
  const bySender = new Map<string, DocumentEnvelopeRow[]>();
  for (const row of log) {
    const rows = bySender.get(row.senderAgentId);
    if (rows) rows.push(row);
    else bySender.set(row.senderAgentId, [row]);
  }
  const envelopes: Uint8Array[] = [];
  for (const [author, rows] of [...bySender].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
    if (truncated) break;
    const theirs = peerContent.get(author);
    const from = theirs ? theirs.count : 0;
    for (const row of rows.slice(from)) {
      if (row.kind !== "update" || row.payload === null) continue;
      if (peerRefused.has(row.envelopeHash)) continue;
      const wire = new Uint8Array(
        encodeDocumentUpdateEnvelope({
          type: "document_update",
          document_id: row.documentId,
          epoch_id: row.epochId,
          doc_prev_hash: row.docPrevHash,
          sender_agent_id: row.senderAgentId,
          sender_client_id: row.senderClientId ?? 0,
          update_encoding: DOCUMENT_UPDATE_ENCODING_V1,
          state_vector: row.stateVector,
          governance_parents: [...row.governanceParents],
          update: row.payload,
          signature: row.signature,
        }),
      );
      if (!spend(wire)) break;
      envelopes.push(wire);
    }
  }

  // Is the PEER ahead of us anywhere? Then the initiator owes step 3.
  const myGov = new Map(block.governance.map((g) => [g.author, g]));
  const myContent = new Map(block.content.map((c) => [c.author, c]));
  const peerAhead =
    peerBlock.governance.some((g) => {
      const mine = myGov.get(g.author);
      if (!mine) return g.seq > 0;
      if (g.seq > mine.seq) return true;
      return (
        g.seq === mine.seq &&
        [...g.head_hashes].sort().join(",") !== mine.head_hashes.join(",")
      );
    }) ||
    peerBlock.content.some((c) => {
      const mine = myContent.get(c.author);
      return mine ? c.count > mine.count : c.count > 0;
    });

  // A peer whose position is EMPTY holds nothing — a joiner (spec §4: "simply very far
  // behind"). Hand them the anchor everything derives from; it is the one record that is not an
  // entry, and the bootstrap on their side is idempotent.
  const peerHoldsNothing =
    peerBlock.governance.length === 0 && peerBlock.content.length === 0;
  const genesis = peerHoldsNothing ? reads.genesisBytes(documentId) : null;

  return {
    block: { ...block, entries, envelopes, ...(genesis ? { genesis } : {}) },
    peerAhead,
    truncated,
  };
}
