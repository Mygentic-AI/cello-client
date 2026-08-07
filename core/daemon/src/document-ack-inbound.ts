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
  /**
   * Called once an envelope is SETTLED — admitted or rejected, both of which end the delivery.
   *
   * Exists so the sender can stop holding a session open waiting for an answer that has arrived.
   * Optional because settling is complete without it; nothing here depends on anyone listening.
   */
  onSettled?(ownerAgentId: string, envelopeHash: string): void;
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

    // 6. SETTLE ONCE. The wire type's own header states this contract: nothing binds an ack to the
    // acker's chain, so one acker can produce a valid ADMISSION and a valid REJECTION for the same
    // envelope. Applying the later one would let a peer that admitted an envelope later claim it
    // refused it — and the sender would roll back work the peer already holds. A second,
    // CONTRADICTING ack is an error; a second identical one is an ordinary redelivery.
    const alreadyAcked = row.ackedAtMs != null;
    if (alreadyAcked) {
      // ENVELOPE-scoped. The document-scoped reader answers a different question, and using it
      // here would make a rejection of any OTHER envelope in this document read as a rejection of
      // this one — so an honest redelivered admission would be refused as a contradiction the
      // moment anything else in the document had ever been refused.
      const previouslyRejected = this.#d.store.rejectionReceivedFor(
        ownerAgentId,
        ack.document_id,
        ack.envelope_hash,
      );
      const contradicts = ack.admitted === previouslyRejected;
      if (contradicts) {
        this.#d.logger.error("document.ack.contradiction", {
          documentId: ack.document_id,
          envelopeHash: ack.envelope_hash,
          ackerAgentId: ack.acker_agent_id,
          nowSays: ack.admitted ? "admitted" : "rejected",
          correlationId,
        });
        return {
          ok: false,
          reason: "document_ack_contradiction",
          detail:
            `${ack.acker_agent_id} already settled envelope ${ack.envelope_hash.slice(0, 16)}… and ` +
            `now says the opposite — this envelope stays settled as it was, and both claims are ` +
            `retained`,
        };
      }
      // An identical redelivery. Nothing to do, and nothing to complain about.
      return { ok: true, admitted: ack.admitted, envelopeHash: ack.envelope_hash };
    }

    // `markAcked` is idempotent and returns whether this was the first — a redelivered ack must not
    // move the recorded time, or the delivery record says the peer confirmed at a moment it did not.
    const first = this.#d.store.markAcked(ownerAgentId, ack.document_id, ack.envelope_hash, nowMs);
    // ANNOUNCE THE SETTLE, before the admitted/rejected split — both outcomes end the delivery, and
    // a waiter that only heard about admissions would keep a session open through every rejection.
    this.#d.onSettled?.(ownerAgentId, ack.envelope_hash);

    if (!ack.admitted) {
      // Durable on the publishing side. A log line would not survive the restart after which the
      // operator asks why their work never landed — and this is also what bounds the retry on the
      // side that actually loops.
      this.#d.rejections.recordIncomingRejection(ownerAgentId, ack.document_id, {
        rejectionEnvelopeHash: ackRecordHash(ack.envelope_hash),
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
 * The identity of the RECEIVED-rejection row: the REFUSED ENVELOPE, and nothing else.
 *
 * ONE REFUSED ENVELOPE IS ONE ROUND, however many acks for it arrive.
 *
 * This used to mix in the acker's `acked_at_ms` on the reasoning that both fields are signed, so a
 * redelivered ack would collapse onto the same row. That reasoning had a false premise: acks are
 * not stored and redelivered — `sendAck` builds a fresh `DocumentAck` with `acked_at_ms: Date.now()`
 * every time it answers. So two acks for the SAME envelope carried two different timestamps and
 * became two rows, advancing the round twice.
 *
 * That is not hypothetical. Delivery re-sends on a 1s first backoff, so an ordinary in-flight
 * overlap — the sender re-sends while the first ack is still on the wire, both land — produced two
 * rounds from one refusal. `MAX_REJECTED_ROUNDS` is 3, so routine delivery overlap could stall a
 * shared document with no hostility involved. That is the same denial of service the 5b
 * already-rejected guard in `document-inbound.ts` was written to close, arriving through the other
 * side of the same loop.
 */
function ackRecordHash(envelopeHash: string): string {
  return envelopeHash;
}
