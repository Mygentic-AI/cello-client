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
 *   2. VERIFY the signature — FIRST, because everything after it is either a judgement about a
 *                          party or an ANSWER to one. It needs nothing but the envelope: the agent
 *                          id is the Ed25519 public key (M14-D5). It ran at step 4 until a live
 *                          defect forced it earlier — see `terminal` on InboundResult. An
 *                          unverified envelope is also not REJECTED: a rejection is a protocol act
 *                          that presumes an authenticated counterparty, and writing a 0x05 leaf
 *                          naming an unauthenticated sender puts their claim in our permanent log.
 *   3. KNOW the document — an envelope for a document we do not hold has no context to judge it in.
 *                          TERMINAL: we will never hold it, so the sender is told and stops.
 *   4. SENDER is the peer — a document is a pairwise agreement; a third party's envelope does not
 *                          belong here at all, and is not a rejection case (there is no
 *                          collaboration to supersede). Refused SILENTLY — see `terminal`.
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
  // `terminal?: undefined` is what makes this a DISCRIMINATED union rather than two overlapping
  // shapes. Without it a caller holding an `InboundResult` cannot even read `.terminal` to narrow —
  // the property does not exist on this arm — so the router could not tell the two apart.
  | { ok: false; reason: string; detail: string; terminal?: undefined }
  /**
   * A TERMINAL refusal — redelivering this envelope can never change the answer, and the sender was
   * AUTHENTICATED, so their delivery is settled with a rejection ack rather than left outstanding.
   * The plain refusal above means "stay silent and let them retry".
   *
   * Both conditions are load-bearing. Without terminal, a peer who refused the proposal is
   * redelivered to indefinitely (found live: 74 sends). Without authentication, the ack answers
   * whoever reached the channel rather than a known party.
   *
   * `terminal` AND `envelopeHash` are ONE variant, not two optional fields, because the router can
   * only act when it has both — and with them independent, setting `terminal` while forgetting the
   * hash produced no ack, no log line, and silently reinstated the defect this unit closed. A type
   * that can express the broken state eventually will.
   */
  | { ok: false; reason: string; detail: string; terminal: true; envelopeHash: string };

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
  /** DOD-MP-REMOVE-1 — the sender's last membership event in the recorded amendment chain. */
  membershipOf(
    ownerAgentId: string,
    documentId: string,
    agentId: string,
  ): { state: "holder" | "removed" | "untouched" };
  /**
   * DOD-MP-INBOUND-N-1 — the CURRENT derived holders, or null when the chain does not derive.
   * When it derives, membership is the WHOLE sender gate — the genesis-peer column is a
   * bilateral-legacy fallback, never a permanent credential (the same rule the ack gate
   * learned in FANOUT-1's review).
   */
  currentHolders(ownerAgentId: string, documentId: string): string[] | null;
  /**
   * SYNC-G1 — the derived state AT the envelope's signed governance frontier (R20's input).
   * `missing` names ancestors not yet held: the caller answers NON-terminally and the exchange
   * delivers governance first.
   */
  deriveAtFrontier(
    ownerAgentId: string,
    documentId: string,
    frontier: readonly string[],
  ):
    | {
        ok: true;
        participants: ReadonlySet<string>;
        invited: ReadonlySet<string>;
        /** R30: content whose named world is already ENDED is refused everywhere. */
        ended: "closed" | "killed" | null;
      }
    | { ok: false; reason: string; missing?: string[] };
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

    // 2. VERIFY the signature — BEFORE the document is even looked up.
    //
    // It used to run at step 4, after the lookup and the peer check, and the header's reasoning for
    // that was sound as far as it went: verify before the GATE, so pluggable rules never process
    // bytes from a party we have not authenticated. Verifying EARLIER satisfies that strictly more.
    //
    // What forced the move is `terminal` below. A terminal refusal is answered with a SIGNED ack
    // addressed to `sender_agent_id`, and producing one for a sender we have not authenticated
    // would answer whoever reached the channel rather than a known peer. Authentication has to
    // precede the first refusal we are willing to answer, and `document_unknown` is now one.
    //
    // It needs nothing from the document: the agent id IS the Ed25519 public key (M14-D5), so this
    // is self-contained on the envelope. The cost is an Ed25519 verify (~50µs) on envelopes for
    // documents we do not hold — paid to avoid a delivery that never settles.
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

    // 3. KNOW the document.
    const doc = this.#d.store.getDocument(ownerAgentId, env.document_id);
    if (!doc) {
      // TERMINAL. We hold no such document and never will — this is what the far side of a REFUSED
      // proposal looks like, and it was leaving the sender redelivering forever: the router only
      // acks `ok: true` results, so an `ok: false` refusal settled nothing and the delivery worker
      // re-sent on every tick. Observed live on `662743b1…`, stuck at `pendingSent: 1`.
      //
      // Safe to answer because step 2 authenticated the sender, and it discloses nothing they do
      // not already have: they authored an envelope for this document_id, and the answer is "no".
      return {
        ok: false,
        reason: "document_unknown",
        terminal: true,
        envelopeHash,
        detail: `no document ${env.document_id.slice(0, 16)}… for this agent`,
      };
    }

    // 4. THE SENDER GATE (DOD-MP-INBOUND-N-1), BEFORE any lifecycle answer — the order is the
    // disclosure boundary: every later branch may answer with a SIGNED ACK, and an ack to a
    // non-party confirms the document exists and what state it is in. When the chain DERIVES,
    // derived membership is
    // the whole gate — a joined third holder's envelope is as admissible as the genesis peer's,
    // and a removed genesis peer's is not admissible at all. Only when the chain cannot answer
    // (bilateral legacy, no genesis record) does the row's peer column stand in.
    // SYNC-G1 (R20): admissibility is ruled AT THE ENVELOPE'S SIGNED FRONTIER — the governance
    // world its author actually held — never at our current state, which refuses a removed
    // author's legitimate earlier work and breaks convergence for every holder who was behind
    // at removal time (the AC14 case; the old epoch-equality gate broke it three documented
    // times). An honest removed daemon names a frontier containing its own removal and refuses
    // HERE, by name (AC13); a backdating daemon admits exactly what an honest holder at that
    // position could have authored — the same bounded concession the governance fold accepted,
    // and the fold's removal dominance keeps such a daemon out of governance regardless.
    const senderHolders = this.#d.currentHolders(ownerAgentId, env.document_id);
    let senderIsParty: boolean;
    if (senderHolders === null) {
      // Bilateral legacy — no derivable chain; the row's peer column is the membership. The
      // membership WALK still rules removal here (there is no frontier world to consult), so a
      // removed legacy peer is refused by name, never re-admitted through the row.
      const legacyMembership = this.#d.membershipOf(
        ownerAgentId, env.document_id, env.sender_agent_id,
      );
      if (legacyMembership.state === "removed") {
        this.#d.logger.warn("document.inbound.sender_removed", {
          documentId: env.document_id,
          senderAgentId: env.sender_agent_id,
          correlationId,
        });
        return {
          ok: false,
          reason: "document_sender_removed",
          terminal: true,
          envelopeHash,
          detail:
            "this holder was removed from the document — the removal is forward-only (your " +
            "copy is yours), but new edits are no longer accepted",
        };
      }
      senderIsParty = env.sender_agent_id === doc.peerAgentId;
    } else {
      const at = this.#d.deriveAtFrontier(
        ownerAgentId, env.document_id, env.governance_parents,
      );
      if (!at.ok) {
        // Ancestors not held: the governance is IN FLIGHT — non-terminal, the exchange
        // delivers governance before content and this envelope admits on redelivery.
        this.#d.logger.warn("document.inbound.governance_in_flight", {
          documentId: env.document_id,
          senderAgentId: env.sender_agent_id,
          missing: at.missing ?? [],
          correlationId,
        });
        return {
          ok: false,
          reason: "document_governance_in_flight",
          envelopeHash,
          detail:
            `this update names governance ancestors this holder does not yet hold — ` +
            `reconcile delivers governance first; retry after it lands`,
        };
      }
      // R30 / AC16: an ending among the envelope's own named ancestors means its author KNEW
      // the document was over when they wrote — refused everywhere, terminally, including from
      // a modified daemon: the parents are inside the signature.
      if (at.ended !== null) {
        this.#d.logger.warn("document.inbound.authored_after_ending", {
          documentId: env.document_id,
          senderAgentId: env.sender_agent_id,
          ended: at.ended,
          correlationId,
        });
        return {
          ok: false,
          reason: "document_authored_after_ending",
          terminal: true,
          envelopeHash,
          detail:
            `this update names a governance world in which the document was already ` +
            `${at.ended} - content authored after an ending is refused everywhere (R30)`,
        };
      }
      senderIsParty = at.participants.has(env.sender_agent_id);
    }
    if (!senderIsParty) {
      // A REMOVED former holder is upgraded from the silent stranger-refusal to the TERMINAL
      // named one (REMOVE-1 review F4): they hold the removal fact already — no new disclosure —
      // and the silent path left their delivery worker redelivering forever, which is the exact
      // silent drop the DoD line forbids. A true stranger still gets silence.
      const formerHolder = this.#d.membershipOf(ownerAgentId, env.document_id, env.sender_agent_id);
      if (formerHolder.state === "removed") {
        this.#d.logger.warn("document.inbound.sender_removed", {
          documentId: env.document_id,
          senderAgentId: env.sender_agent_id,
          correlationId,
        });
        return {
          ok: false,
          reason: "document_sender_removed",
          terminal: true,
          envelopeHash,
          detail:
            "this holder was removed from the document — the removal is forward-only (your " +
            "copy is yours), but new edits are no longer accepted",
        };
      }
      // The wire stays silent (the disclosure decision stands); the LOG names the refusal, so
      // the operator debugging "the new collaborator's edits aren't landing" has a line to find.
      // An admission still in flight resolves by the sender's ordinary retry after it lands.
      this.#d.logger.warn("document.inbound.not_peer", {
        documentId: env.document_id,
        senderAgentId: env.sender_agent_id,
        peerAgentId: doc.peerAgentId,
        correlationId,
      });
      return {
        ok: false,
        reason: "document_sender_not_peer",
        // The peer's identity is NOT in the reply, and there is NO ack — silence is the answer. A
        // third party is authenticated as themselves but is not a party to this document, so
        // nothing about it is theirs to learn.
        //
        // A residual one-bit oracle remains and is accepted deliberately: a prober who already
        // holds a valid document_id learns "exists" from the ABSENCE of an ack, since an unknown
        // document answers and a known one does not. Closing that would mean acking non-parties,
        // which discloses strictly more. It is bounded by document_id being a 32-byte hash
        // (`documentIdFromProposal`), unguessable and never published.
        detail: "you are not a party to this document",
      };
    }

    // 4a. A DAEMON THAT KNOWS ITSELF REMOVED STOPS APPLYING (DOD-MP-REMOVE-1's other half):
    // "new edits stop flowing either way" is a lie if the removed party's own daemon keeps
    // admitting what still arrives from holders whose worker has not yet gated. TERMINAL — the
    // sender's delivery settles instead of retrying at a door that will never open.
    const selfMembership = this.#d.store.removedFromArrangement(ownerAgentId, env.document_id);
    if (selfMembership.removed) {
      this.#d.logger.warn("document.inbound.recipient_removed", {
        documentId: env.document_id,
        correlationId,
      });
      return {
        ok: false,
        reason: "document_recipient_removed",
        terminal: true,
        envelopeHash,
        detail:
          "this daemon was removed from the document's arrangement — the local copy remains, " +
          "but new edits are no longer applied",
      };
    }

    // 4b (SYNC-G1): the epoch-equality ruling and the current-state removed-sender check are
    // GONE — both are the causal sender gate's job now, ruled at the envelope's signed
    // frontier before anything else ran. (D7: the epoch stamp itself dies with this phase.)
    // 5. The document must still ACCEPT. `acceptsUpdates` exists for exactly this and carries a
    // comment describing the bug it was written to fix — "after a restart the document row said
    // `stalled` while the daemon happily accepted updates on it". The only inbound path in the
    // codebase was reintroducing it, and a killed document is defined by LIFECYCLE-1 as one that
    // stops accepting.
    if (doc.status === "killed" || doc.status === "closed") {
      // TERMINAL, and for the same reason `document_stalled` below is NOT: these are DECISIONS.
      // Nothing the sender does makes a killed or closed document accept this envelope, so leaving
      // their delivery outstanding buys nothing and costs a redelivery per tick, forever.
      return {
        ok: false,
        reason: doc.status === "killed" ? "document_killed" : "document_closed",
        terminal: true,
        envelopeHash,
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
        // THE COMPARISON ITSELF, not just its verdict.
        //
        // The stall path was chased through three fixes on the strength of "the chain was refused",
        // and each fix was reasoned about rather than measured. What was never printed is the only
        // thing that decides it: the link the sender claimed, the head we were holding, and whether
        // we had seen it before. A refusal that names its verdict and hides its inputs is why that
        // took three rounds — the same shape as reading a log tail for an event that is emitted
        // earlier, twice today.
        claimedPrev: env.doc_prev_hash,
        ourHead: head,
        prevIsKnown: env.doc_prev_hash !== null && known.has(env.doc_prev_hash),
        knownCount: known.size,
      });
      // MATCHED against the known set, not split on ":". This file explains sixty lines earlier why
      // splitting an upstream message produces reason codes made of English prose — and the old
      // `?? "document_chain_broken"` fallback mislabelled a FORK as a gap, which is precisely the
      // distinction the envelope module went out of its way to create.
      const reason = ["document_chain_forked", "document_chain_broken"].find((r) =>
        detail.startsWith(r),
      );
      // A FORK IS TERMINAL; A GAP IS NOT. The distinction the envelope module went out of its way
      // to create decides this too. A gap means the predecessor has not arrived YET, so redelivery
      // is exactly the recovery path and the sender must keep trying. A fork means the sender
      // chained onto something that is not our head and never was — our log is append-only, so
      // there is no repair, and no number of redeliveries changes the answer.
      //
      // Left non-terminal, a fork walked to the unacked ceiling and surfaced as "Their client may
      // not support shared documents yet" — an error naming the wrong subsystem entirely, for a
      // condition the receiver had diagnosed precisely.
      if (reason === "document_chain_forked") {
        return { ok: false, reason, detail, terminal: true, envelopeHash };
      }
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
      governanceParents: [...env.governance_parents],
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
