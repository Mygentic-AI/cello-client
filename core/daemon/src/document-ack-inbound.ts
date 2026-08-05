/**
 * DOD-DOC-INBOUND-2 — consuming an arriving ACK. This is what closes DELIVERY-2's loop.
 *
 * Without it a sent envelope's outcome is `admitted: null` forever: the worker knows the content
 * left and nothing more, so it re-sends on the ack timeout and eventually stalls the document at
 * the unacked ceiling.
 *
 * ── EVERY CHECK HERE GUARDS ONE OF TWO IRREVERSIBLE CONSEQUENCES ──────────────────────────────
 *
 * An ack SETTLES an envelope. Admitted, it stops being redelivered; rejected, the sender rolls back
 * local work and supersedes. Both are things an unauthenticated party must not be able to cause, so
 * the order is:
 *
 *   1. DECODE            — refuse malformed input before interpreting any of it.
 *   2. KNOW the document — an ack for a document we do not hold settles nothing that exists.
 *   3. ACKER is the peer — a document is a pairwise agreement; nobody else's answer settles it.
 *   4. VERIFY            — before any write. An unsigned ack that silenced a delivery would drop
 *                          the content from the pending set with neither operator ever learning it
 *                          was never applied — the silent divergence the two-layer design exists to
 *                          prevent.
 *   5. THE ENVELOPE IS OURS — we authored it, and it is in the log. An ack for a peer-authored
 *                          envelope settles a delivery that was never ours to make; an ack for an
 *                          envelope that is not there is a bug or a probe, and recording it would
 *                          put a claim about a nonexistent delivery into a permanent record.
 *   6. SETTLE            — mark acked; on a rejection also record it durably on the publishing side,
 *                          because an operator needs to know WHY their work was refused after a
 *                          restart, not merely that it was.
 */

import { decodeDocumentAck, buildDocumentAckTbs } from "@cello-protocol/protocol-types";
import type { DocumentStore } from "./document-store.js";
import type { DocumentRejections } from "./document-rejection.js";
import type { Logger } from "./types.js";

export type AckInboundResult =
  | { ok: true; admitted: boolean; envelopeHash: string }
  | { ok: false; reason: string; detail: string };

export interface DocumentAckInboundDeps {
  store: DocumentStore;
  rejections: DocumentRejections;
  logger: Logger;
  /**
   * Verify the ack signature against `acker_agent_id`. INJECTED and REQUIRED — this module cannot
   * resolve an agent id to a public key, and a default would be a default answer to the one
   * question that must never have one.
   */
  verifySignature(ackerAgentId: string, tbs: Uint8Array, signature: Uint8Array): boolean;
}

export class DocumentAckInbound {
  readonly #d: DocumentAckInboundDeps;

  constructor(deps: DocumentAckInboundDeps) {
    this.#d = deps;
  }

  receive(
    ownerAgentId: string,
    wire: Uint8Array,
    nowMs: number,
    correlationId = "ack",
  ): AckInboundResult {
    // 1. DECODE.
    let ack;
    try {
      ack = decodeDocumentAck(wire);
    } catch (err: unknown) {
      const detail = err instanceof Error ? err.message : String(err);
      this.#d.logger.warn("document.ack.malformed", { detail, correlationId });
      // One reason code with the upstream message in the detail — the decoder's named refusals and
      // raw CBOR errors both arrive here, and building a code out of the message turns the second
      // kind into English prose nothing can match on.
      return { ok: false, reason: "document_ack_malformed", detail };
    }

    // 2. KNOW the document.
    const doc = this.#d.store.getDocument(ownerAgentId, ack.document_id);
    if (!doc) {
      return {
        ok: false,
        reason: "document_unknown",
        detail: `no document ${ack.document_id.slice(0, 16)}… for this agent`,
      };
    }

    // 3. The acker must be THIS document's peer.
    if (ack.acker_agent_id !== doc.peerAgentId) {
      this.#d.logger.warn("document.ack.not_peer", {
        documentId: ack.document_id,
        ackerAgentId: ack.acker_agent_id,
        peerAgentId: doc.peerAgentId,
        correlationId,
      });
      return {
        ok: false,
        reason: "document_ack_not_peer",
        // The peer's identity is not disclosed to a party that has not authenticated.
        detail: "you are not a party to this document",
      };
    }

    // 4. VERIFY, before any write.
    if (!this.#d.verifySignature(ack.acker_agent_id, buildDocumentAckTbs(ack), ack.signature)) {
      this.#d.logger.error("document.ack.signature_invalid", {
        documentId: ack.document_id,
        ackerAgentId: ack.acker_agent_id,
        envelopeHash: ack.envelope_hash,
        correlationId,
      });
      return {
        ok: false,
        reason: "document_ack_signature_invalid",
        detail:
          `the ack claims to come from ${ack.acker_agent_id} but its signature does not verify ` +
          `against that agent — nothing was settled`,
      };
    }

    // 5. The envelope must be one WE authored, and it must exist.
    const row = this.#d.store
      .getEnvelopeLog(ownerAgentId, ack.document_id)
      .find((e) => e.envelopeHash === ack.envelope_hash);
    if (!row) {
      return {
        ok: false,
        reason: "document_ack_envelope_unknown",
        detail: `envelope ${ack.envelope_hash.slice(0, 16)}… is not in this document's log`,
      };
    }
    if (row.senderAgentId !== ownerAgentId) {
      return {
        ok: false,
        reason: "document_ack_not_author",
        detail:
          `envelope ${ack.envelope_hash.slice(0, 16)}… was authored by ${row.senderAgentId}, not by ` +
          `you — there is no delivery of ours for this ack to settle`,
      };
    }

    // 6. SETTLE. `markAcked` is idempotent and returns whether this was the first — a redelivered
    // ack must not move the recorded time, or the delivery record says the peer confirmed at a
    // moment it did not.
    const first = this.#d.store.markAcked(ownerAgentId, ack.document_id, ack.envelope_hash, nowMs);

    if (!ack.admitted) {
      // Durable on the publishing side. A log line would not survive the restart after which the
      // operator asks why their work never landed — and this is also what bounds the retry on the
      // side that actually loops.
      this.#d.rejections.recordIncomingRejection(ownerAgentId, ack.document_id, {
        rejectionEnvelopeHash: ackRecordHash(ack.envelope_hash, ack.acked_at_ms),
        rejectedEnvelopeHash: ack.envelope_hash,
        reason: ack.rejection_reason ?? "document_rejected",
        fromAgentId: ack.acker_agent_id,
      });
      return { ok: true, admitted: false, envelopeHash: ack.envelope_hash };
    }

    this.#d.logger.info("document.ack.admitted", {
      documentId: ack.document_id,
      envelopeHash: ack.envelope_hash,
      firstAck: first,
      correlationId,
    });
    return { ok: true, admitted: true, envelopeHash: ack.envelope_hash };
  }
}

/**
 * The identity of the RECEIVED-rejection row.
 *
 * Derived from the acked envelope and the acker's own timestamp — both signed — so a redelivered
 * ack collapses onto the same row instead of advancing the round. Deriving it from anything local
 * (a clock read here, a counter) would make every redelivery a new rejection, and three of those
 * stall the document.
 */
function ackRecordHash(envelopeHash: string, ackedAtMs: number): string {
  return `${envelopeHash}:${ackedAtMs}`;
}
