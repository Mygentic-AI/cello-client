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
import type { DocumentStore, DocumentProperties } from "./document-store.js";
import type { DocumentEngine } from "./document-engine.js";
import type { DocumentGate } from "./document-gate.js";
import type { DocumentRejections } from "./document-rejection.js";
import type { Logger } from "./types.js";

export type InboundResult =
  | { ok: true; admitted: true; envelopeHash: string; duplicate: boolean }
  | {
      ok: true;
      admitted: false;
      envelopeHash: string;
      rejectionReason: string;
      duplicate: false;
      /** The signed `document_rejection` to put on the wire. Absent when this refusal is a repeat. */
      rejectionWire?: Uint8Array;
    }
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
  /**
   * Sign as the OWNING agent, over the rejection's canonical preimage (DOD-DOC-REJECT-2).
   *
   * Takes the agent so it cannot sign with the wrong key. ASYNC, and that is what makes `receive`
   * async: signing goes through a key provider, and REJECT-1 requires a real signature rather than
   * a placeholder.
   */
  sign(ownerAgentId: string, tbs: Uint8Array): Promise<Uint8Array>;
}

/** The agreed property, read from the row rather than from whoever called us. */
function appendOnly(doc: { properties: DocumentProperties }): boolean {
  return doc.properties.append_only === true;
}

export class DocumentInbound {
  readonly #d: DocumentInboundDeps;

  constructor(deps: DocumentInboundDeps) {
    this.#d = deps;
  }

  /**
   * The clientIDs this sender has SIGNED for on this document: the one this envelope declares,
   * plus every one previously admitted from them. Both are authenticated — each arrived inside a
   * verified TBS — so the set can only grow through signatures the peer actually made.
   */
  #boundClientIds(ownerAgentId: string, env: DocumentUpdateEnvelope): number[] {
    return [
      ...new Set<number>([
        env.sender_client_id,
        ...this.#d.store.senderClientIdsFor(ownerAgentId, env.document_id, env.sender_agent_id),
      ]),
    ];
  }

  /**
   * ASYNC because a gate refusal must SIGN a `0x05` leaf, and signing goes through an async key
   * provider. REJECT-1 refuses to fabricate a signature — an all-zero placeholder in an immutable
   * log is indistinguishable from a real one that fails to verify — so the async is real, not
   * incidental.
   *
   * The session content path still decides the LEAF KIND synchronously; `DocumentFrameRouter`
   * splits the two, and serializes the handling per owner so an envelope's predecessor is always
   * stored before its successor is checked.
   */
  async receive(
    ownerAgentId: string,
    wire: Uint8Array,
    nowMs: number,
    correlationId = "inbound",
  ): Promise<InboundResult> {
    // 1. DECODE.
    let env: DocumentUpdateEnvelope;
    try {
      env = decodeDocumentUpdateEnvelope(wire);
    } catch (err: unknown) {
      const detail = err instanceof Error ? err.message : String(err);
      this.#d.logger.warn("document.inbound.malformed", { detail, correlationId });
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

    // 2b. The document must still ACCEPT. `acceptsUpdates` exists for exactly this and carries a
    // comment describing the bug it was written to fix — "after a restart the document row said
    // `stalled` while the daemon happily accepted updates on it". The only inbound path in the
    // codebase was reintroducing it, and a killed document is defined by LIFECYCLE-1 as one that
    // stops accepting.
    if (doc.status === "killed" || doc.status === "closed") {
      return {
        ok: false,
        reason: doc.status === "killed" ? "document_killed" : "document_closed",
        detail:
          doc.status === "killed"
            ? "this document was ended locally and no longer accepts updates"
            : "this document was closed by agreement and no longer accepts updates",
      };
    }
    const accepts = this.#d.rejections.acceptsUpdates(ownerAgentId, env.document_id);
    if (!accepts.ok) {
      // The stall reason, composed by the unit that owns the stall. Reporting this envelope's own
      // gate verdict instead would send an operator to the append-only rule for a document that has
      // been frozen for days.
      return { ok: false, reason: accepts.reason, detail: accepts.detail };
    }

    // 3. The sender must be THIS document's peer.
    if (env.sender_agent_id !== doc.peerAgentId) {
      this.#d.logger.warn("document.inbound.not_peer", {
        documentId: env.document_id,
        senderAgentId: env.sender_agent_id,
        peerAgentId: doc.peerAgentId,
        correlationId,
      });
      return {
        ok: false,
        reason: "document_sender_not_peer",
        // The peer's identity is NOT in the reply. This sender has not authenticated, and anyone
        // reaching the channel with a guessed or leaked document_id would otherwise learn who the
        // owner collaborates with. The full detail is in the warn above, where it belongs.
        detail: "you are not a party to this document",
      };
    }

    // 4. VERIFY, before the gate. See the header.
    if (!this.#d.verifySignature(env.sender_agent_id, buildDocumentUpdateTbs(env), env.signature)) {
      this.#d.logger.error("document.inbound.signature_invalid", {
        documentId: env.document_id,
        senderAgentId: env.sender_agent_id,
        envelopeHash,
        correlationId,
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
    // Hash-only. Reading the whole log meant materializing every payload BLOB on every inbound
    // update, just to build a set for one membership test.
    const known = this.#d.store.knownEnvelopeHashesBySender(
      ownerAgentId,
      env.document_id,
      env.sender_agent_id,
    );
    const head = this.#d.store.lastEnvelopeHashBySender(ownerAgentId, env.document_id, env.sender_agent_id);
    let duplicate: boolean;
    try {
      duplicate = verifyDocumentChainLink(env, { head, known }).duplicate;
    } catch (err: unknown) {
      const detail = err instanceof Error ? err.message : String(err);
      this.#d.logger.warn("document.inbound.chain_refused", {
        documentId: env.document_id,
        correlationId,
        detail,
      });
      // MATCHED against the known set, not split on ":". This file explains sixty lines earlier why
      // splitting an upstream message produces reason codes made of English prose — and the old
      // `?? "document_chain_broken"` fallback mislabelled a FORK as a gap, which is precisely the
      // distinction the envelope module went out of its way to create.
      const reason = ["document_chain_forked", "document_chain_broken"].find((r) =>
        detail.startsWith(r),
      );
      return { ok: false, reason: reason ?? "document_chain_refused", detail };
    }
    if (duplicate) {
      // ACK, and change nothing. Not acking would leave the sender retrying an envelope we already
      // hold, forever; applying it again is unnecessary (Yjs is idempotent) and appending it again
      // is refused by the store anyway.
      this.#d.logger.info("document.inbound.duplicate", {
        documentId: env.document_id,
        senderAgentId: env.sender_agent_id,
        envelopeHash,
        correlationId,
      });
      return { ok: true, admitted: true, envelopeHash, duplicate: true };
    }

    // 5b. ALREADY REJECTED? A rejected envelope's hash is deliberately never written to the log, so
    // it is not in `known` and a redelivery is NOT a duplicate. Without this it re-ran the gate,
    // was rejected again, and `reject()` minted a fresh nonce — advancing the retry round. Since
    // MAX_REJECTED_ROUNDS is 3, a peer whose ACKS ARE BEING LOST — which is delivery's ordinary
    // retry behaviour — permanently stalled the shared document in three attempts, with no
    // hostility required. Hostile, it was a one-line denial of service.
    //
    // Re-answered with the RECORDED reason: the peer needs the same answer it was given before, so
    // it supersedes rather than retries.
    const alreadyRejected = this.#d.store
      .listQuarantined(ownerAgentId, env.document_id)
      .find((q) => q.rejectedEnvelopeHash === envelopeHash);
    if (alreadyRejected) {
      this.#d.logger.info("document.inbound.already_rejected", {
        documentId: env.document_id,
        envelopeHash,
        correlationId,
      });
      return {
        ok: true,
        admitted: false,
        envelopeHash,
        rejectionReason: alreadyRejected.reason,
        duplicate: false,
      };
    }

    // 6. GATE — against the LIVE doc, which the gate itself trials on a copy.
    const live = this.#d.liveDocFor(ownerAgentId, env.document_id);
    const verdict = this.#d.gate.validate(
      live,
      env.update,
      {
        documentId: env.document_id,
        senderAgentId: env.sender_agent_id,
        // DERIVED from authenticated data, not from a seam nobody produces. ENVELOPE-1 puts
        // `sender_client_id` inside the signed TBS precisely because "this envelope is where it is
        // learned" — and the assembler was decoding it, verifying the signature over it, and then
        // throwing it away, leaving rule (h) wired to a function with no implementation. Left as a
        // seam it would default to wrong in whichever direction its implementer guessed: `[]`
        // refuses every peer update, the union of everything observed admits anything.
        //
        // §14 forbids persisting a clientID for REUSE; recording which ones a peer has SIGNED for
        // is the opposite — it is the binding the gate's rule exists to check.
        senderClientIds: this.#boundClientIds(ownerAgentId, env),
        declaredDocumentId: env.document_id,
        declaredEncoding: env.update_encoding,
        // THE PERSISTED PROPERTY, not a caller option defaulting to off. append_only is agreed at
        // the handshake and stored on the row, and the gate's own header says it "is the only thing
        // standing between a bound peer and erasure" — rule (h) provably cannot see a deletion.
        // Taking it from an option meant a document configured append-only was unprotected unless
        // every future call site remembered to pass the flag.
        appendOnly: appendOnly(doc),
        // The AGREED profile, from the same persisted row and for the same reason.
        ...(typeof doc.properties.content_profile === "string"
          ? { contentProfile: doc.properties.content_profile }
          : {}),
      },
      nowMs,
    );

    if (!verdict.admit) {
      // 7a. REJECT. The bytes are held, a 0x05 leaf references them, and the peer is ANSWERED —
      // a rejection is an ack for delivery purposes, so the sender stops retrying and supersedes.
      const rejection = await this.#d.rejections.reject(ownerAgentId, env.document_id, {
        rejectedEnvelopeHash: envelopeHash,
        quarantined: verdict.quarantined,
        reason: verdict.reason,
        detail: verdict.detail,
        senderAgentId: env.sender_agent_id,
        rejectedDocPrevHash: env.doc_prev_hash,
        rule: verdict.rule,
        limit: verdict.limit,
        // The OWNER signs its own rejection, over the canonical preimage (DOD-DOC-REJECT-2).
        sign: (tbs) => this.#d.sign(ownerAgentId, tbs),
        nowMs,
      });
      return {
        ok: true,
        admitted: false,
        envelopeHash,
        // The signed refusal, for the caller to transmit. Absent on a duplicate — we already told
        // them once, and re-sending would advance their round counter for a retry that never
        // happened, driving the document to `stalled` early.
        ...(rejection.wire ? { rejectionWire: rejection.wire } : {}),
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
      // Recorded so the authorship binding for this peer is derived from what they SIGNED, not
      // from a seam somebody has to remember to implement.
      senderClientId: env.sender_client_id,
      createdAtMs: nowMs,
    });
    this.#d.engine.applyUpdateOrThrow(live, env.update);

    // §3.2 step 4: admit AND CLEAR THE QUARANTINE. This is the supersession closing — the held
    // bytes are released, the chain bridge stub for the superseded envelope goes with them, and
    // `document.supersession.admitted` finally has a producer. Without it the entries stayed held
    // forever and the event was a name with nothing behind it.
    if (env.doc_prev_hash !== null) {
      this.#d.rejections.clearQuarantine(ownerAgentId, env.document_id, env.doc_prev_hash);
    }

    this.#d.logger.info("document.inbound.admitted", {
      documentId: env.document_id,
      senderAgentId: env.sender_agent_id,
      envelopeHash,
      correlationId,
    });
    return { ok: true, admitted: true, envelopeHash, duplicate: false };
  }
}
