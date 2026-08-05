/**
 * DOD-DOC-INBOUND-1 — the receiving half (§3.2, §14, §16.4).
 *
 * Every P2 unit built a piece of this. ENVELOPE-1 decodes and checks the chain link, GATE-1
 * decides, REJECT-1 records a refusal and quarantines the bytes, ENGINE-1 applies. Nothing owned
 * assembling them, and assembling them is not clerical work — **the order is the security
 * property**. A check performed after admission is a check that did not protect anything.
 *
 * The order, and what each step is protecting:
 *
 *   1. DECODE          — refuse malformed input before any of it is interpreted.
 *   2. KNOW the document — an envelope for a document we do not hold has no context to judge it in.
 *   3. SENDER is the peer — a document is a pairwise agreement; a third party's envelope does not
 *                          belong here at all, and is not a rejection case (there is no
 *                          collaboration to supersede).
 *   4. VERIFY the signature — BEFORE the gate. The gate runs pluggable rules, and eventually
 *                          screening, over peer-controlled bytes; running them first means those
 *                          rules process input from a party we have not authenticated. An
 *                          unverified envelope is also not REJECTED — a rejection is a protocol act
 *                          that presumes an authenticated counterparty, and writing a 0x05 leaf
 *                          naming an unauthenticated sender puts their claim in our permanent log.
 *   5. CHAIN link      — a redelivery is benign and must still ACK (delivery retries by design, and
 *                          a redelivery that goes unacked never lets the sender settle it); a gap
 *                          or a fork refuses.
 *   6. GATE            — the §3.2 validation, against a TRIAL copy so a refusal cannot have landed.
 *   7. ADMIT or REJECT — and either way, ANSWER. A rejection is an ack for delivery purposes: the
 *                          peer has decided, so the sender must stop retrying and supersede.
 */

import * as Y from "yjs";
import {
  decodeDocumentUpdateEnvelope,
  documentEnvelopeHash,
  buildDocumentUpdateTbs,
  verifyDocumentChainLink,
  type DocumentUpdateEnvelope,
} from "@cello-protocol/protocol-types";
import type { DocumentStore } from "./document-store.js";
import type { DocumentEngine } from "./document-engine.js";
import type { DocumentGate } from "./document-gate.js";
import type { DocumentRejections } from "./document-rejection.js";
import type { Logger } from "./types.js";

export type InboundResult =
  | { ok: true; admitted: true; envelopeHash: string; duplicate: boolean }
  | { ok: true; admitted: false; envelopeHash: string; rejectionReason: string; duplicate: false }
  | { ok: false; reason: string; detail: string };

export interface DocumentInboundDeps {
  store: DocumentStore;
  engine: DocumentEngine;
  gate: DocumentGate;
  rejections: DocumentRejections;
  logger: Logger;
  /**
   * Verify the envelope signature against `sender_agent_id`. INJECTED and REQUIRED — this module
   * cannot resolve an agent id to a public key, and a default would be a default answer to "is this
   * authentic", which is the one question that must never have one.
   */
  verifySignature(senderAgentId: string, tbs: Uint8Array, signature: Uint8Array): boolean;
  /** The live document to apply admitted updates to. */
  liveDocFor(ownerAgentId: string, documentId: string): Y.Doc;
  /** clientIDs this peer is known to write under — the binding GATE-1's rule (h) needs. */
  boundClientIds(ownerAgentId: string, documentId: string): number[];
  /** The rejection's own signature, state vector and nonce. Never fabricated here. */
  crypto(): { signature: Uint8Array; stateVector: Uint8Array; nonce: string };
}

export class DocumentInbound {
  readonly #d: DocumentInboundDeps;

  constructor(deps: DocumentInboundDeps) {
    this.#d = deps;
  }

  receive(
    ownerAgentId: string,
    wire: Uint8Array,
    nowMs: number,
    opts: { appendOnly?: boolean } = {},
  ): InboundResult {
    // 1. DECODE.
    let env: DocumentUpdateEnvelope;
    try {
      env = decodeDocumentUpdateEnvelope(wire);
    } catch (err: unknown) {
      const detail = err instanceof Error ? err.message : String(err);
      this.#d.logger.warn("document.inbound.malformed", { detail });
      // ONE reason code, with the upstream message in the detail. Two kinds of failure arrive here:
      // our own decoder's named refusals ("document_envelope_missing_field: …"), and CBOR/lib0
      // errors from bytes that are not a CBOR map at all ("Data read, but end of buffer not
      // reached"). Splitting the message on ":" turned the second kind into a reason code made of
      // English prose, which nothing can match on and which reads as a crash rather than a refusal.
      return { ok: false, reason: "document_inbound_malformed", detail };
    }

    const envelopeHash = documentEnvelopeHash(env);

    // 2. KNOW the document.
    const doc = this.#d.store.getDocument(ownerAgentId, env.document_id);
    if (!doc) {
      return {
        ok: false,
        reason: "document_unknown",
        detail: `no document ${env.document_id.slice(0, 16)}… for this agent`,
      };
    }

    // 3. The sender must be THIS document's peer.
    if (env.sender_agent_id !== doc.peerAgentId) {
      this.#d.logger.warn("document.inbound.not_peer", {
        documentId: env.document_id,
        senderAgentId: env.sender_agent_id,
        peerAgentId: doc.peerAgentId,
      });
      return {
        ok: false,
        reason: "document_sender_not_peer",
        detail:
          `${env.sender_agent_id} is not this document's peer (${doc.peerAgentId}) — a document is ` +
          `a pairwise agreement, so there is no collaboration here to supersede`,
      };
    }

    // 4. VERIFY, before the gate. See the header.
    if (!this.#d.verifySignature(env.sender_agent_id, buildDocumentUpdateTbs(env), env.signature)) {
      this.#d.logger.error("document.inbound.signature_invalid", {
        documentId: env.document_id,
        senderAgentId: env.sender_agent_id,
        envelopeHash,
      });
      return {
        ok: false,
        reason: "document_signature_invalid",
        detail:
          `the envelope claims to come from ${env.sender_agent_id} but its signature does not ` +
          `verify against that agent — nothing was recorded`,
      };
    }

    // 5. CHAIN. A redelivery is expected traffic and must still be answered.
    const known = new Set(
      this.#d.store
        .getEnvelopeLog(ownerAgentId, env.document_id)
        .filter((e) => e.senderAgentId === env.sender_agent_id)
        .map((e) => e.envelopeHash),
    );
    const head = this.#d.store.lastEnvelopeHashBySender(ownerAgentId, env.document_id, env.sender_agent_id);
    let duplicate: boolean;
    try {
      duplicate = verifyDocumentChainLink(env, { head, known }).duplicate;
    } catch (err: unknown) {
      const detail = err instanceof Error ? err.message : String(err);
      this.#d.logger.warn("document.inbound.chain_refused", { documentId: env.document_id, detail });
      return { ok: false, reason: detail.split(":")[0] ?? "document_chain_broken", detail };
    }
    if (duplicate) {
      // ACK, and change nothing. Not acking would leave the sender retrying an envelope we already
      // hold, forever; applying it again is unnecessary (Yjs is idempotent) and appending it again
      // is refused by the store anyway.
      this.#d.logger.info("document.inbound.duplicate", { documentId: env.document_id, envelopeHash });
      return { ok: true, admitted: true, envelopeHash, duplicate: true };
    }

    // 6. GATE — against the LIVE doc, which the gate itself trials on a copy.
    const live = this.#d.liveDocFor(ownerAgentId, env.document_id);
    const verdict = this.#d.gate.validate(
      live,
      env.update,
      {
        documentId: env.document_id,
        senderAgentId: env.sender_agent_id,
        senderClientIds: this.#d.boundClientIds(ownerAgentId, env.document_id),
        declaredDocumentId: env.document_id,
        declaredEncoding: env.update_encoding,
        appendOnly: opts.appendOnly ?? false,
      },
      nowMs,
    );

    if (!verdict.admit) {
      // 7a. REJECT. The bytes are held, a 0x05 leaf references them, and the peer is ANSWERED —
      // a rejection is an ack for delivery purposes, so the sender stops retrying and supersedes.
      this.#d.rejections.reject(ownerAgentId, env.document_id, {
        rejectedEnvelopeHash: envelopeHash,
        quarantined: verdict.quarantined,
        reason: verdict.reason,
        detail: verdict.detail,
        senderAgentId: env.sender_agent_id,
        rejectedDocPrevHash: env.doc_prev_hash,
        rule: verdict.rule,
        limit: verdict.limit,
        ...this.#d.crypto(),
      });
      return {
        ok: true,
        admitted: false,
        envelopeHash,
        rejectionReason: verdict.reason,
        duplicate: false,
      };
    }

    // 7b. ADMIT. The log first, then the live document: an update applied but not logged is one
    // the operator can read and cannot rebuild, and a rebuild is how the document survives a
    // restart. The other order loses content; this order at worst repeats an idempotent apply.
    this.#d.store.appendEnvelope(ownerAgentId, {
      envelopeHash,
      documentId: env.document_id,
      senderAgentId: env.sender_agent_id,
      docPrevHash: env.doc_prev_hash,
      epochId: env.epoch_id,
      signature: env.signature,
      stateVector: env.state_vector,
      payload: env.update,
      kind: "update",
      referencesEnvelopeHash: null,
      createdAtMs: nowMs,
    });
    this.#d.engine.applyUpdateOrThrow(live, env.update);

    this.#d.logger.info("document.inbound.admitted", { documentId: env.document_id, envelopeHash });
    return { ok: true, admitted: true, envelopeHash, duplicate: false };
  }
}
