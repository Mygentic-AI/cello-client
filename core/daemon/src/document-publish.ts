/**
 * DOD-DOC-DELIVERY-1 (outbound half) — turning a local edit into a signed envelope in the log.
 *
 * Publish is fire-and-forget by design (§16.4): it writes the envelope and returns. Delivery is the
 * worker's job, and pending is derived from the log, so the only thing publish has to get right is
 * that what it writes is complete, signed, and correctly chained.
 *
 * ── WHAT IS PUBLISHED IS A DIFF AGAINST THE PEER'S STATE VECTOR ───────────────────────────────
 *
 * Not the whole document. §3.2 step 3 and §7: an update computed against what the peer has already
 * seen carries exactly the operations they lack — including, after a rejection, the refused
 * operations PLUS their inverses, which is what lets supersession converge. Publishing the full
 * state instead would work but would re-send the entire document on every edit, and would lose the
 * property that makes the rejection protocol terminate.
 *
 * The peer's state vector is the one they last told us about. Absent — before they have ever
 * published — the diff is against an empty document, which is the whole state and correct.
 *
 * ── THE CHAIN LINK IS READ, NEVER GUESSED ─────────────────────────────────────────────────────
 *
 * `doc_prev_hash` is our own last envelope for this document, read from the log at publish time. A
 * cached value would go stale the moment anything else appended — a rejection, a withdrawal — and a
 * wrong link is not a soft failure: the peer refuses it and, if it is ever replayed locally, the
 * document stops rebuilding.
 */

import type * as Y from "yjs";
import {
  buildDocumentUpdateTbs,
  documentEnvelopeHash,
  DOCUMENT_EPOCH_V1,
  DOCUMENT_UPDATE_ENCODING_V1,
  type DocumentUpdateEnvelope,
} from "@cello-protocol/protocol-types";
import type { DocumentStore } from "./document-store.js";
import type { DocumentEngine } from "./document-engine.js";
import type { Logger } from "./types.js";

export type PublishResult =
  | { ok: true; envelopeHash: string; bytes: number }
  | { ok: false; reason: string; detail: string };

export interface DocumentPublishDeps {
  store: DocumentStore;
  engine: DocumentEngine;
  logger: Logger;
  /** Sign as the owning agent, over the update envelope's TBS. */
  sign(ownerAgentId: string, tbs: Uint8Array): Promise<Uint8Array>;
  /** The owning agent's own id — which is its pubkey hex (M14-D5) — for the envelope's sender. */
  senderIdFor(ownerAgentId: string): string | null;
  /** May this agent publish into this document right now? LIFECYCLE-1 owns the answer. */
  canPublish(ownerAgentId: string, documentId: string): { ok: true } | { ok: false; reason: string; detail: string };
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export class DocumentPublish {
  readonly #d: DocumentPublishDeps;

  constructor(deps: DocumentPublishDeps) {
    this.#d = deps;
  }

  /**
   * Publish the live document's state as an update the peer does not yet have.
   *
   * Returns the envelope hash so a caller can follow it — a publish that says only "ok" gives an
   * operator nothing to correlate with what later lands or stalls.
   */
  async publish(
    ownerAgentId: string,
    documentId: string,
    doc: Y.Doc,
    nowMs: number,
  ): Promise<PublishResult> {
    const document = this.#d.store.getDocument(ownerAgentId, documentId);
    if (!document) {
      return {
        ok: false,
        reason: "document_unknown",
        detail: `no document ${documentId.slice(0, 16)}… for this agent`,
      };
    }

    // LIFECYCLE-1 decides. A closed, killed, stalled or platform-paused agent must not publish, and
    // the reason it gives is the one the operator needs — not a generic refusal from here.
    const allowed = this.#d.canPublish(ownerAgentId, documentId);
    if (!allowed.ok) return { ok: false, reason: allowed.reason, detail: allowed.detail };

    const senderId = this.#d.senderIdFor(ownerAgentId);
    if (senderId === null) {
      return {
        ok: false,
        reason: "document_publish_no_identity",
        detail: `no signing identity for ${ownerAgentId}, so an envelope cannot be authored`,
      };
    }

    // THE PEER's state vector, from their most recent envelope — not our own snapshot. Our
    // snapshot answers "what have we not yet materialized", which is a different question whose
    // answer looks plausible: it produced an update every time, so a republish with no new edits
    // appended a second envelope instead of reporting that there was nothing to say.
    const peerStateVector =
      this.#d.store.peerStateVector(ownerAgentId, documentId, document.peerAgentId) ?? undefined;
    const update = this.#d.engine.encodeState(doc, peerStateVector);

    // NOTHING NEW is a different question from what to SEND, and conflating them was a bug. The
    // update is a diff against the PEER's state vector, so before they have ever published it is
    // the whole document — non-empty however long we have gone without editing. Whether there is
    // anything new is a fact about US: compare our current state vector against the one our own
    // last envelope carried.
    const ourLast = this.#d.store.lastPublishedStateVector(ownerAgentId, documentId, senderId);
    const ourNow = this.#d.engine.encodeStateVector(doc);
    if (ourLast !== null && equalBytes(ourLast, ourNow)) {
      // Publishing anyway would append a leaf, cost a delivery, and converge nothing.
      return {
        ok: false,
        reason: "document_nothing_to_publish",
        detail: "nothing has changed in this document since your last publish",
      };
    }
    if (update.length === 0) {
      return {
        ok: false,
        reason: "document_nothing_to_publish",
        detail: "the peer already has everything in this document",
      };
    }

    const envelope: DocumentUpdateEnvelope = {
      type: "document_update",
      document_id: documentId,
      epoch_id: DOCUMENT_EPOCH_V1,
      // READ, never cached. Anything else appended since — a rejection, a withdrawal — moves this,
      // and a wrong link is refused by the peer and stops the document rebuilding locally.
      doc_prev_hash: this.#d.store.lastEnvelopeHashBySender(ownerAgentId, documentId, senderId),
      sender_agent_id: senderId,
      sender_client_id: doc.clientID,
      update_encoding: DOCUMENT_UPDATE_ENCODING_V1,
      state_vector: ourNow,
      update,
      signature: new Uint8Array(0),
    };
    envelope.signature = await this.#d.sign(ownerAgentId, buildDocumentUpdateTbs(envelope));
    const envelopeHash = documentEnvelopeHash(envelope);

    const appended = this.#d.store.appendEnvelope(ownerAgentId, {
      envelopeHash,
      documentId,
      senderAgentId: senderId,
      docPrevHash: envelope.doc_prev_hash,
      epochId: envelope.epoch_id,
      signature: envelope.signature,
      stateVector: envelope.state_vector,
      payload: update,
      kind: "update",
      referencesEnvelopeHash: null,
      // Recorded so the peer's authorship binding is derived from what we SIGNED, matching what the
      // inbound path stores for their envelopes.
      senderClientId: doc.clientID,
      createdAtMs: nowMs,
    });
    if (!appended) {
      // The same content published twice hashes the same, so this is a genuine no-op rather than a
      // fault — but it is reported, because a caller that believes it published something new and
      // waits for it to deliver would wait forever.
      return {
        ok: false,
        reason: "document_already_published",
        detail: `this exact update is already in the log as ${envelopeHash.slice(0, 16)}…`,
      };
    }

    this.#d.logger.info("document.published", {
      documentId,
      envelopeHash,
      bytes: update.length,
      senderClientId: doc.clientID,
    });
    // Fire and forget: the delivery worker derives pending FROM THE LOG, so writing the envelope is
    // the whole of publishing. Nothing here waits for a peer.
    return { ok: true, envelopeHash, bytes: update.length };
  }
}
