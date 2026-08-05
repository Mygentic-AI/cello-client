/**
 * DOD-DOC-TOOLS-1 — the operator's surface onto documents.
 *
 * Until this module existed, nothing in production called `createDocument`. Every unit below it was
 * built and tested, and none of it was reachable: no operator could propose a document, so no
 * document existed, so the delivery sweep was a no-op by construction and the inbound path never
 * had anything addressed to it. The layer was complete and unreachable, which reads exactly like a
 * layer that works.
 *
 * ── WHY PROPOSE AND ACCEPT ARE SEPARATE VERBS ─────────────────────────────────────────────────
 *
 * A document is a standing agreement to apply a counterparty's signed operations to local state.
 * That is a larger grant than receiving a message, and §16.3 puts a human consent decision in front
 * of it. Accepting is the moment the operator agrees; everything after is the CRDT converging
 * without asking again. So the proposal is recorded, listed, and answered once — never inferred
 * from the first update arriving.
 *
 * ── WRITE IS FULL-CONTENT, NOT A PATCH ────────────────────────────────────────────────────────
 *
 * `cello_doc_write` takes the document's whole new text and the engine diffs it against the live
 * doc. An agent that emits a patch has to be right about offsets in a document its peer is
 * concurrently editing, and a wrong offset in a CRDT is not a rejected patch — it is a permanent,
 * silent corruption that both sides converge on. Full content moves that problem to a diff run
 * against the state the operator actually saw.
 */

import { randomBytes, randomUUID } from "node:crypto";
import * as Y from "yjs";
import {
  encodeDocumentProposal,
  buildDocumentProposalTbs,
  documentIdFromProposal,
  seamViolation,
  ASSURANCE_TIER_V1,
  TOPOLOGY_V1,
  DOCUMENT_FEATURE_VERSION,
  encodeDocumentProposalAck,
  buildDocumentProposalAckTbs,
  DOCUMENT_PROPOSAL_ACK_VERSION,
  MAX_PROPOSAL_REFUSAL_REASON_LENGTH,
  type DocumentProposalAck,
  type DocumentProposalEnvelope,
} from "@cello-protocol/protocol-types";
import type { IpcHandler } from "./ipc-server.js";
import type { Logger } from "./types.js";
import type { DocumentLayer } from "./document-layer.js";
import type { DocumentPublish } from "./document-publish.js";
import type { DocumentDeliveryTransport } from "./document-delivery.js";
import { lineHunks } from "./document-write-path.js";

/** Document types the notification/diff path understands. Anything else is stored, not diffed. */
const DEFAULT_DOCUMENT_TYPE = "markdown";

export interface DocumentHandlerDeps {
  handlers: Map<string, IpcHandler>;
  logger: Logger;
  layer: DocumentLayer;
  publish: DocumentPublish;
  /** Per-agent, because a session and a signature both belong to exactly one agent. */
  transportFor(agentName: string): DocumentDeliveryTransport;
  /** Which agent is this call for? Resolved from the connection, or named explicitly. */
  resolveAgent(connectionId: string, explicit?: string): string | null;
  /** Agent NAME to the stable owner key every document row is scoped by (M14-D5). */
  ownerKeyFor(agentName: string): string | null;
  /** Sign as the named agent. */
  sign(agentName: string, tbs: Uint8Array): Promise<Uint8Array>;
  now(): number;
}

interface Resolved {
  agentName: string;
  ownerAgentId: string;
}

export function registerDocumentHandlers(deps: DocumentHandlerDeps): void {
  const { handlers, logger, layer, publish } = deps;

  /**
   * Resolve the agent AND its owner key together, because a handler that has one without the other
   * is a handler that will pick the wrong scope. Returns a refusal the handler returns verbatim.
   */
  function resolve(
    params: Record<string, unknown> | undefined,
    connectionId: string,
  ): Resolved | { ok: false; reason: string; guidance: string } {
    const explicit = typeof params?.agent === "string" ? params.agent : undefined;
    const agentName = deps.resolveAgent(connectionId, explicit);
    if (agentName === null) {
      return {
        ok: false,
        reason: "no_current_agent",
        guidance: "Call cello_use_agent first, or pass 'agent' to say which agent this is for.",
      };
    }
    const ownerAgentId = deps.ownerKeyFor(agentName);
    if (ownerAgentId === null) {
      return {
        ok: false,
        reason: "agent_identity_unavailable",
        guidance: `Agent '${agentName}' has no signing identity loaded, so it cannot hold documents.`,
      };
    }
    return { agentName, ownerAgentId };
  }

  const isRefusal = (r: Resolved | { ok: false }): r is { ok: false; reason: string; guidance: string } =>
    (r as { ok?: false }).ok === false;

  // ─── propose ──────────────────────────────────────────────────────────────────────────────

  handlers.set("cello_doc_propose", async (params, connectionId) => {
    const who = resolve(params, connectionId);
    if (isRefusal(who)) return who;

    // RETRY PATH. A proposal whose send failed left a real local document and an unreachable peer;
    // proposing again would mint a fresh nonce, hence a fresh document_id, hence a SECOND document —
    // leaving the first an orphan the operator cannot explain or clear. Given the id, the stored
    // envelope is re-sent unchanged, so the peer sees the offer that was always meant for them.
    const retryId = typeof params?.document_id === "string" ? params.document_id : "";
    if (retryId.length > 0) {
      const stored = layer.handshake.get(who.ownerAgentId, retryId);
      if (!stored || stored.proposerAgentId !== who.ownerAgentId) {
        return {
          ok: false,
          reason: "document_proposal_not_ours",
          guidance:
            `No proposal ${retryId.slice(0, 16)}… authored by this agent. Omit 'document_id' to ` +
            `make a new proposal, or see cello_doc_list.`,
        };
      }
      const resendId = randomUUID();
      const resent = await deps.transportFor(who.agentName).sendBytes({
        peerAgentId: stored.envelope.peer_agent_id,
        documentId: retryId,
        bytes: encodeDocumentProposal(stored.envelope),
        correlationId: resendId,
      });
      logger.info("document.proposal.resent", { documentId: retryId, sent: resent.ok, correlationId: resendId });
      if (!resent.ok) {
        return { ok: false, reason: resent.reason, guidance: resent.detail ?? "The peer is still unreachable." };
      }
      return { ok: true, documentId: retryId, proposalSent: true, peerAgentId: stored.envelope.peer_agent_id };
    }

    const peerAgentId = typeof params?.peer_pubkey === "string" ? params.peer_pubkey.toLowerCase() : "";
    if (!/^[0-9a-f]{64}$/.test(peerAgentId)) {
      return {
        ok: false,
        reason: "invalid_peer_pubkey",
        guidance:
          "cello_doc_propose requires 'peer_pubkey' — the counterparty's 32-byte hex K_local " +
          "public key, which is also their agent id. See cello_contacts.",
      };
    }
    if (peerAgentId === who.ownerAgentId) {
      // A document with yourself converges trivially and has no counterparty to consent, but every
      // downstream unit would treat it as a real peer — including the delivery worker, which would
      // dial the daemon it is running in.
      return {
        ok: false,
        reason: "document_peer_is_self",
        guidance: "A document needs a counterparty. 'peer_pubkey' is this agent's own key.",
      };
    }

    const documentType = typeof params?.document_type === "string" ? params.document_type : DEFAULT_DOCUMENT_TYPE;
    const startingText = typeof params?.starting_content === "string" ? params.starting_content : "";

    // THE STARTING CONTENT IS A YJS UPDATE, not a string, and that is the whole reason it is on the
    // proposal at all (§16.3 step 1). Both sides apply THESE BYTES, so epoch zero is byte-identical
    // on both. Each side building its own doc from the same template string produces two documents
    // that look the same and never converge — different client ids, different item ids, and every
    // subsequent edit interleaving against a history the other has not got.
    let startingContent: Uint8Array | null = null;
    if (startingText.length > 0) {
      const seed = new Y.Doc();
      // PINNED. A random client id would put the proposer's identity in the shared epoch-zero
      // state, so the same proposal sent twice would produce different bytes and a different
      // document_id — and the id is meant to be a function of what was proposed.
      seed.clientID = 1;
      seed.getText("content").insert(0, startingText);
      startingContent = Y.encodeStateAsUpdate(seed);
    }

    const properties = {
      assurance_tier: ASSURANCE_TIER_V1,
      schema_enforcement: false,
      topology: TOPOLOGY_V1,
      append_only: params?.append_only === true,
    };
    const violation = seamViolation(properties);
    if (violation) {
      // Refused HERE rather than sent and refused by the peer: proposing something this build knows
      // its counterparty must reject wastes a round trip and leaves a refused row on both sides.
      return { ok: false, reason: "document_seam_violation", guidance: violation };
    }

    const envelope: DocumentProposalEnvelope = {
      type: "document_proposal",
      feature_version: DOCUMENT_FEATURE_VERSION,
      proposer_agent_id: who.ownerAgentId,
      peer_agent_id: peerAgentId,
      document_type: documentType,
      properties,
      starting_content: startingContent,
      // Distinguishes two otherwise identical proposals. Without it, proposing the same document to
      // the same peer twice collides on document_id and the second silently does nothing.
      nonce: new Uint8Array(randomBytes(16)),
      proposed_at_ms: deps.now(),
      signature: new Uint8Array(0),
    };
    envelope.signature = await deps.sign(who.agentName, buildDocumentProposalTbs(envelope));
    const documentId = documentIdFromProposal(envelope);

    // LOCAL FIRST, then send. The reverse order loses the document if the process dies between the
    // two, and the peer would then hold a document whose proposer has no record of proposing it —
    // every update they send refused as `document_unknown`, with nothing on this side to explain it.
    layer.store.createDocument({
      documentId,
      ownerAgentId: who.ownerAgentId,
      peerAgentId,
      documentType,
      properties,
      status: "active",
      createdAtMs: envelope.proposed_at_ms,
    });
    // The envelope itself, so a failed send is recoverable rather than a dead end. See
    // `DocumentHandshake.recordOutgoing`.
    layer.handshake.recordOutgoing(who.ownerAgentId, envelope, envelope.proposed_at_ms);
    if (startingContent) {
      // Applied to OUR live doc from the same bytes the peer will apply, for the same reason they
      // are on the wire at all.
      Y.applyUpdate(layer.live.get(who.ownerAgentId, documentId), startingContent);
    }

    const correlationId = randomUUID();
    const sent = await deps.transportFor(who.agentName).sendBytes({
      peerAgentId,
      documentId,
      bytes: encodeDocumentProposal(envelope),
      correlationId,
    });
    logger.info("document.proposed", { documentId, peerAgentId, sent: sent.ok, correlationId });

    if (!sent.ok) {
      // The document EXISTS and the proposal did not arrive. Both facts are reported, because
      // reporting only the failure would hide a real local row and reporting only success would
      // have the operator wait for a consent decision the peer was never asked to make.
      return {
        ok: true,
        documentId,
        proposalSent: false,
        reason: sent.reason,
        guidance:
          `The document was created locally but the proposal did not reach the peer (${sent.reason}). ` +
          `Once they are online, run cello_doc_propose again with document_id='${documentId}' to ` +
          `re-send this same offer — do not propose a new one, that would make a second document.`,
      };
    }
    return { ok: true, documentId, proposalSent: true, peerAgentId };
  });

  /**
   * Tell the proposer what was decided.
   *
   * BEST-EFFORT, and the caller says so rather than failing the decision. Consent is local and
   * final the moment the operator makes it — refusing to accept a document because the counterparty
   * is momentarily unreachable would hand any network blip a veto over the operator's own choice.
   * What an unsent ack costs is that the proposer keeps waiting, which the surface reports as
   * unanswered rather than as a refusal.
   */
  async function tellProposer(
    who: Resolved,
    documentId: string,
    proposerAgentId: string,
    accepted: boolean,
    reason: string | undefined,
  ): Promise<boolean> {
    const ack: DocumentProposalAck = {
      type: "document_proposal_ack",
      ack_version: DOCUMENT_PROPOSAL_ACK_VERSION,
      document_id: documentId,
      acker_agent_id: who.ownerAgentId,
      accepted,
      ...(accepted ? {} : { refusal_reason: (reason ?? "declined").slice(0, MAX_PROPOSAL_REFUSAL_REASON_LENGTH) }),
      decided_at_ms: deps.now(),
      signature: new Uint8Array(0),
    };
    ack.signature = await deps.sign(who.agentName, buildDocumentProposalAckTbs(ack));
    const sent = await deps.transportFor(who.agentName).sendBytes({
      peerAgentId: proposerAgentId,
      documentId,
      bytes: encodeDocumentProposalAck(ack),
      correlationId: randomUUID(),
    });
    if (!sent.ok) {
      logger.warn("document.proposal.ack_unsent", { documentId, accepted, reason: sent.reason });
    }
    return sent.ok;
  }

  // ─── inbox / accept / refuse ──────────────────────────────────────────────────────────────

  handlers.set("cello_doc_inbox", async (params, connectionId) => {
    const who = resolve(params, connectionId);
    if (isRefusal(who)) return who;
    const pending = layer.handshake.pending(who.ownerAgentId);
    return {
      ok: true,
      proposals: pending.map((p) => ({
        documentId: p.documentId,
        proposerAgentId: p.proposerAgentId,
        documentType: p.envelope.document_type,
        appendOnly: p.envelope.properties.append_only,
        hasStartingContent: p.envelope.starting_content !== null,
        proposedAtMs: p.envelope.proposed_at_ms,
      })),
    };
  });

  handlers.set("cello_doc_accept", async (params, connectionId) => {
    const who = resolve(params, connectionId);
    if (isRefusal(who)) return who;
    const documentId = typeof params?.document_id === "string" ? params.document_id : "";
    if (documentId.length === 0) {
      return { ok: false, reason: "invalid_document_id", guidance: "Pass 'document_id' from cello_doc_inbox." };
    }

    const outcome = layer.handshake.accept(who.ownerAgentId, documentId, deps.now());
    if (!outcome.ok) return { ok: false, reason: outcome.reason, guidance: outcome.detail };

    // THE CONSENT AND THE DOCUMENT ARE ONE ACT. `accept` moves the proposal row; without this the
    // operator has agreed to a document that does not exist, and the peer's first update is refused
    // as `document_unknown` — a refusal that names a real condition and explains nothing.
    layer.store.createDocument({
      documentId,
      ownerAgentId: who.ownerAgentId,
      peerAgentId: outcome.envelope.proposer_agent_id,
      documentType: outcome.envelope.document_type,
      properties: outcome.envelope.properties,
      status: "active",
      createdAtMs: deps.now(),
    });
    if (outcome.envelope.starting_content) {
      Y.applyUpdate(layer.live.get(who.ownerAgentId, documentId), outcome.envelope.starting_content);
    }
    logger.info("document.accepted", { documentId, proposerAgentId: outcome.envelope.proposer_agent_id });
    const told = await tellProposer(who, documentId, outcome.envelope.proposer_agent_id, true, undefined);
    return { ok: true, documentId, peerAgentId: outcome.envelope.proposer_agent_id, proposerNotified: told };
  });

  handlers.set("cello_doc_refuse", async (params, connectionId) => {
    const who = resolve(params, connectionId);
    if (isRefusal(who)) return who;
    const documentId = typeof params?.document_id === "string" ? params.document_id : "";
    const reason = typeof params?.reason === "string" && params.reason.length > 0 ? params.reason : "declined_by_operator";
    if (documentId.length === 0) {
      return { ok: false, reason: "invalid_document_id", guidance: "Pass 'document_id' from cello_doc_inbox." };
    }
    const proposal = layer.handshake.get(who.ownerAgentId, documentId);
    const outcome = layer.handshake.refuse(who.ownerAgentId, documentId, reason, deps.now());
    if (!outcome.ok) return { ok: false, reason: outcome.reason, guidance: outcome.detail };
    // The REASON travels. A refusal the proposer cannot see the reason for leaves them unable to
    // propose anything better, which is what makes people abandon a protocol rather than adjust.
    const told = proposal
      ? await tellProposer(who, documentId, proposal.proposerAgentId, false, reason)
      : false;
    return { ok: true, documentId, proposerNotified: told };
  });

  // ─── list / read / write ──────────────────────────────────────────────────────────────────

  handlers.set("cello_doc_list", async (params, connectionId) => {
    const who = resolve(params, connectionId);
    if (isRefusal(who)) return who;
    return {
      ok: true,
      documents: layer.lifecycle.list(who.ownerAgentId, deps.now()).map((d) => {
        // WHOSE OFFER WAS IT, and has the other side actually shown up?
        //
        // Without these three fields, `cello_doc_list` renders identically for a document the peer
        // refused, one whose offer never reached them, and one being actively co-edited — the only
        // moving part is `pendingUnsent`, which also moves for a peer who is merely offline. An
        // operator cannot tell "they said no" from "they are asleep", and those want opposite
        // actions.
        const proposal = layer.handshake.get(who.ownerAgentId, d.documentId);
        return {
          ...d,
          proposedByUs: proposal?.proposerAgentId === who.ownerAgentId,
          // THE PEER'S OWN SIGNED ANSWER — true accepted, false refused, null not yet heard. This
          // replaced an inference ("they have published into it") that could not tell refused from
          // unreceived from accepted-but-untouched, two of which want the operator to act.
          peerAccepted: layer.handshake.peerDecision(who.ownerAgentId, d.documentId),
          // Kept alongside it, because they answer different questions: whether they agreed, and
          // whether anything has actually come back. A document accepted an hour ago with nothing
          // in it is a fine state; it is just not the same state.
          peerHasPublished:
            layer.store.knownEnvelopeHashesBySender(who.ownerAgentId, d.documentId, d.peerAgentId).size > 0,
          consentState: proposal?.consentState ?? null,
        };
      }),
    };
  });

  handlers.set("cello_doc_read", async (params, connectionId) => {
    const who = resolve(params, connectionId);
    if (isRefusal(who)) return who;
    const documentId = typeof params?.document_id === "string" ? params.document_id : "";
    if (documentId.length === 0) {
      return { ok: false, reason: "invalid_document_id", guidance: "Pass 'document_id' from cello_doc_list." };
    }
    const document = layer.store.getDocument(who.ownerAgentId, documentId);
    if (!document) {
      return {
        ok: false,
        reason: "document_unknown",
        guidance: `No document ${documentId.slice(0, 16)}… for this agent. See cello_doc_list.`,
      };
    }
    // THROWS rather than returning empty when the log cannot be rebuilt — see LiveDocuments.get. An
    // empty document handed to an agent here would be written back over the peer's real content.
    const doc = layer.live.get(who.ownerAgentId, documentId);
    const content = doc.getText("content").toString();
    // THE READ IS THE BOOKMARK. `cello_doc_diff` answers "what changed since I looked", and looking
    // is this call. Marking on an arriving update instead would erase the very change the diff
    // exists to show, silently, at the moment it arrived.
    layer.notifications.markRead(who.ownerAgentId, documentId, content, deps.now());
    // And the unread notice is cleared, because it has now been read. Leaving it would keep an
    // inbox entry for something the agent is holding in its hands.
    layer.notifications.clear(who.ownerAgentId, documentId);
    return {
      ok: true,
      documentId,
      documentType: document.documentType,
      peerAgentId: document.peerAgentId,
      status: document.status,
      content,
    };
  });

  handlers.set("cello_doc_diff", async (params, connectionId) => {
    const who = resolve(params, connectionId);
    if (isRefusal(who)) return who;
    const documentId = typeof params?.document_id === "string" ? params.document_id : "";
    if (documentId.length === 0) {
      return { ok: false, reason: "invalid_document_id", guidance: "Pass 'document_id' from cello_doc_list." };
    }
    const document = layer.store.getDocument(who.ownerAgentId, documentId);
    if (!document) {
      return {
        ok: false,
        reason: "document_unknown",
        guidance: `No document ${documentId.slice(0, 16)}… for this agent. See cello_doc_list.`,
      };
    }

    const after = layer.live.get(who.ownerAgentId, documentId).getText("content").toString();
    const before = layer.notifications.lastSeen(who.ownerAgentId, documentId);
    if (before === null) {
      // NEVER READ is not "nothing changed", and it is not an empty before either. Diffing against
      // "" would render a first look at a long document as an enormous change the agent then treats
      // as "what just arrived" — and act on. Said plainly instead.
      return {
        ok: false,
        reason: "document_never_read",
        guidance:
          `You have not read ${documentId.slice(0, 16)}… yet, so there is nothing to compare against. ` +
          `Call cello_doc_read first; the diff answers "what changed since I looked".`,
      };
    }

    const rendered = layer.notifications.diff(document.documentType, before, after, documentId);
    // The STATS come from the same pair of texts, so an agent branching on `overlap` is branching on
    // the same comparison it is being shown.
    const stats = layer.notifications.diffStats(documentId, before, after, null, document.documentType);
    if (!rendered.ok) {
      // The stats still stand — they are structural and type-independent — so a document type this
      // build cannot render is not a document an agent has to read blind.
      return { ok: true, documentId, unchanged: before === after, diff: null, reason: rendered.reason, stats };
    }
    return {
      ok: true,
      documentId,
      unchanged: before === after,
      diff: rendered.diff,
      ...(rendered.fallback !== undefined ? { fallback: rendered.fallback } : {}),
      stats,
    };
  });

  handlers.set("cello_doc_write", async (params, connectionId) => {
    const who = resolve(params, connectionId);
    if (isRefusal(who)) return who;
    const documentId = typeof params?.document_id === "string" ? params.document_id : "";
    if (documentId.length === 0) {
      return { ok: false, reason: "invalid_document_id", guidance: "Pass 'document_id' from cello_doc_list." };
    }
    if (typeof params?.content !== "string") {
      return {
        ok: false,
        reason: "invalid_content",
        guidance:
          "cello_doc_write takes 'content' — the document's COMPLETE new text, not a patch. The " +
          "daemon diffs it against the current state, so offsets cannot go stale under a " +
          "concurrent edit by the peer.",
      };
    }
    const content = params.content;

    const document = layer.store.getDocument(who.ownerAgentId, documentId);
    if (!document) {
      return {
        ok: false,
        reason: "document_unknown",
        guidance: `No document ${documentId.slice(0, 16)}… for this agent. See cello_doc_list.`,
      };
    }

    const doc = layer.live.get(who.ownerAgentId, documentId);
    const text = doc.getText("content");
    const before = text.toString();
    if (before === content) {
      return { ok: true, documentId, changed: false, published: false };
    }
    // LINE HUNKS, never a whole-text replace — and this is not a preference, it is measured.
    //
    // `delete(0, len); insert(0, content)` can only delete the items THIS side has seen. A peer's
    // concurrently-inserted items survive the delete and are spliced into the new text as orphan
    // fragments. Against yjs at this version:
    //
    //   both sides full-replace "original" with "AAA" / "BBB"  →  "AAABBB" on BOTH sides
    //   "Hello world", peer inserts " dear", we replace w/ "Goodbye"  →  " dearGoodbye"
    //
    // The first is the ORDINARY case for an API whose contract is "send back the complete text",
    // and it converges two whole documents concatenated — signed and published by both parties. It
    // is exactly the "a wrong offset in a CRDT is a permanent corruption both sides converge on"
    // outcome the full-content contract was chosen to avoid; the mechanism moved and the failure
    // did not.
    //
    // `lineHunks` touches only the lines that actually changed, so untouched regions keep their
    // items and a peer's concurrent edit to them merges. Same function `DocumentWritePath.#foldText`
    // uses, whose header records the same hazard for the file path — one folding rule, not two.
    const hunks = lineHunks(before, content);
    // ONE TRANSACTION, so the whole edit is a single Yjs update rather than several — a peer
    // applying them separately would pass through states no operator ever wrote.
    doc.transact(() => {
      // Back to front, so earlier offsets stay valid as later ones are rewritten.
      for (const hunk of [...hunks].reverse()) {
        if (hunk.to > hunk.from) text.delete(hunk.from, hunk.to - hunk.from);
        if (hunk.insert.length > 0) text.insert(hunk.from, hunk.insert);
      }
    });

    const result = await publish.publish(who.ownerAgentId, documentId, doc, deps.now());
    if (!result.ok) {
      // The EDIT IS APPLIED locally and is not published. Reported as such: an operator told the
      // write failed would write it again, and the second write would be a no-op diff against the
      // text it already applied — the change silently never leaving.
      return {
        ok: true,
        documentId,
        changed: true,
        published: false,
        reason: result.reason,
        guidance: result.detail,
      };
    }
    // Delivery is the worker's, not this call's — publish is fire-and-forget by design (§16.4), and
    // a write that blocked on an offline peer would make editing a shared document depend on the
    // other party being awake.
    return { ok: true, documentId, changed: true, published: true, envelopeHash: result.envelopeHash };
  });

  // ─── close / kill ─────────────────────────────────────────────────────────────────────────

  handlers.set("cello_doc_close", async (params, connectionId) => {
    const who = resolve(params, connectionId);
    if (isRefusal(who)) return who;
    const documentId = typeof params?.document_id === "string" ? params.document_id : "";
    if (documentId.length === 0) {
      return { ok: false, reason: "invalid_document_id", guidance: "Pass 'document_id' from cello_doc_list." };
    }
    const outcome = await layer.lifecycle.close(who.ownerAgentId, documentId, deps.now());
    if (!outcome.ok) return { ok: false, reason: outcome.reason, guidance: outcome.detail };
    // BILATERAL. The document settles when both sides have said it, so "closed" is not this call's
    // answer to give — reporting it would tell an operator the collaboration is over while the peer
    // is still editing.
    return {
      ok: true,
      documentId,
      status: layer.store.getDocument(who.ownerAgentId, documentId)?.status ?? "unknown",
    };
  });

  handlers.set("cello_doc_kill", async (params, connectionId) => {
    const who = resolve(params, connectionId);
    if (isRefusal(who)) return who;
    const documentId = typeof params?.document_id === "string" ? params.document_id : "";
    if (documentId.length === 0) {
      return { ok: false, reason: "invalid_document_id", guidance: "Pass 'document_id' from cello_doc_list." };
    }
    const outcome = await layer.lifecycle.kill(who.ownerAgentId, documentId, deps.now());
    if (!outcome.ok) return { ok: false, reason: outcome.reason, guidance: outcome.detail };
    // `peerNotified` is REPORTED, never hidden behind ok. A kill is deliberately independent of the
    // peer being reachable — a decision to stop that depends on the other party being online is not
    // a decision to stop — but an operator who believes the peer was told, when they were not, will
    // not understand why updates keep arriving.
    return { ok: true, documentId, peerNotified: outcome.peerNotified, note: outcome.note };
  });

  logger.debug("document.handlers.registered", {
    verbs: ["propose", "inbox", "accept", "refuse", "list", "read", "diff", "write", "close", "kill"],
  });
}
