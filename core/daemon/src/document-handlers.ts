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
import { lineHunks, isSupportedDocumentType, SUPPORTED_DOCUMENT_TYPES } from "./document-write-path.js";
import { profileViolation } from "./document-profile.js";
import { screenText, SCREEN_RULE_ID } from "./document-screen.js";

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

  /**
   * Documents holding an edit that was APPLIED to the live doc and never published.
   *
   * In memory deliberately, and it is not a shortcut: an unpublished edit exists only in the live
   * `Y.Doc`, which is rebuilt from the envelope log on restart — so the edit and this flag are lost
   * together. A durable flag would outlive the thing it describes and send the operator flushing
   * something that no longer exists.
   */
  const unpublishedEdits = new Set<string>();
  const unpublishedKey = (ownerAgentId: string, documentId: string) => `${ownerAgentId}\u0000${documentId}`;

  /**
   * Has the peer REFUSED this document? If so, nothing may be published into it.
   *
   * Without this a refused document keeps authoring envelopes: each one is signed, leafed, and
   * delivered forever to a peer who has no such document and answers `document_unknown` every time.
   * The operator's surface meanwhile shows `active` with a pending count that never clears — the
   * exact shape of a collaboration that has silently stopped working, which is the failure this
   * milestone exists to not have.
   *
   * Checked HERE rather than in `DocumentLifecycle.canPublish` because the consent decision lives in
   * the handshake, and giving lifecycle a handshake dependency to answer one question would put the
   * proposal protocol inside the status machine.
   *
   * UNANSWERED IS NOT REFUSED. Publishing before the peer has decided is normal and load-bearing —
   * the update waits in the log and delivers when they accept, which is what makes proposing to an
   * offline peer work at all.
   */
  function peerRefused(who: Resolved, documentId: string): { ok: false; reason: string; guidance: string } | null {
    const answer = layer.handshake.peerAnswer(who.ownerAgentId, documentId);
    if (answer.accepted !== false) return null;
    return {
      ok: false,
      reason: "document_peer_refused",
      guidance:
        `Your peer refused this document${answer.reason ? ` — they said: "${answer.reason}"` : ""}. ` +
        `Nothing published into it can ever reach them, so this write was not recorded. Propose a ` +
        `new document if you want to try again with different terms.`,
    };
  }

  /**
   * Write the document out as a file, or return null when no workspace is configured.
   *
   * Failures are LOGGED AND SWALLOWED, deliberately and only here: the file is a projection of the
   * document, not the document. A disk problem must not fail a proposal or a consent decision that
   * is otherwise complete and already recorded — the operator would be left with a peer who thinks
   * they agreed and a local state that says they did not.
   */
  async function materialize(
    ownerAgentId: string,
    documentId: string,
    documentType: string,
  ): Promise<string | null> {
    if (!layer.writePath) return null;
    try {
      return await layer.writePath.materialize(
        ownerAgentId,
        documentId,
        documentType,
        layer.live.get(ownerAgentId, documentId),
      );
    } catch (err: unknown) {
      logger.warn("document.file.materialize_failed", {
        documentId,
        reason: err instanceof Error ? err.message : String(err),
      });
      return null;
    }
  }

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
      layer.handshake.markProposalSent(who.ownerAgentId, retryId, deps.now());
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
    // REFUSED AT THE DOOR, because a type only some verbs can serve is worse than no support at all.
    // `document_type` was previously unvalidated: "yaml" created a real, signed, peer-accepted
    // document whose file materialisation threw and was swallowed, returning `filePath: null` with
    // no explanation while the tool description promises a path. "json" was worse — genuinely
    // supported by DocumentWritePath (map root) and not by read/write/diff (text root), so it read
    // as empty, wrote into a root nothing projects, and diffed as unchanged forever.
    if (!isSupportedDocumentType(documentType)) {
      return {
        ok: false,
        reason: "document_type_unsupported",
        guidance:
          `'${documentType}' is not a document type this build can serve. Supported: ` +
          `${[...SUPPORTED_DOCUMENT_TYPES].sort().join(", ")}. Nothing was created, so there is ` +
          `nothing to clean up — re-propose with a supported type.`,
      };
    }
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
    // THE FILE EXISTS FROM THE START. Materializing lazily would mean the first `cello_doc_publish`
    // has no recorded projection to diff against and refuses — correct, and a bad first experience
    // for something the operator never had to ask for.
    const proposeFilePath = await materialize(who.ownerAgentId, documentId, documentType);

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
    layer.handshake.markProposalSent(who.ownerAgentId, documentId, deps.now());
    return { ok: true, documentId, proposalSent: true, peerAgentId, filePath: proposeFilePath };
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
    // BEST-EFFORT MEANS BEST-EFFORT FOR A THROW TOO, and it did not.
    //
    // The header above states the contract: consent is local and final, and an unsent ack must not
    // fail the decision. That held only for a RETURNED failure. `sign` goes through a key provider
    // and `sendBytes` opens a session — a directory negotiation, a dial, and a seal ceremony on its
    // last line — any of which can throw. Nothing caught them.
    //
    // By the time this runs, `accept` has already committed the consent transition and created the
    // document. So a throw here reached the IPC boundary as `internal_error` with "An unexpected
    // error occurred", the operator re-ran accept, and got "a consent decision is made once" — which
    // reads as a bug in the handshake rather than a send that failed after the decision stuck.
    try {
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
    } catch (err: unknown) {
      // Same outcome as a returned failure, and reported the same way: the peer was not told. The
      // caller already surfaces that as `proposerNotified: false`.
      logger.warn("document.proposal.ack_threw", {
        documentId,
        accepted,
        error: err instanceof Error ? err.message : String(err),
      });
      return false;
    }
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

    // THE SAME REFUSAL ON THE RECEIVING SIDE. Guarding only `propose` leaves an accepter able to
    // take on a document it cannot serve, and the party harmed is the one who did not choose the
    // type. A peer running an older or a different build can still offer anything.
    if (!isSupportedDocumentType(outcome.envelope.document_type)) {
      return {
        ok: false,
        reason: "document_type_unsupported",
        guidance:
          `Your peer proposed a '${outcome.envelope.document_type}' document, which this build ` +
          `cannot serve (supported: ${[...SUPPORTED_DOCUMENT_TYPES].sort().join(", ")}). The ` +
          `proposal is left undecided rather than accepted into a document that would read as ` +
          `empty — use cello_doc_refuse if you want it gone, and tell them which types you take.`,
      };
    }

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
    const acceptFilePath = await materialize(who.ownerAgentId, documentId, outcome.envelope.document_type);
    logger.info("document.accepted", { documentId, proposerAgentId: outcome.envelope.proposer_agent_id });
    const told = await tellProposer(who, documentId, outcome.envelope.proposer_agent_id, true, undefined);
    return {
      ok: true,
      documentId,
      peerAgentId: outcome.envelope.proposer_agent_id,
      proposerNotified: told,
      filePath: acceptFilePath,
    };
  });

  handlers.set("cello_doc_refuse", async (params, connectionId) => {
    const who = resolve(params, connectionId);
    if (isRefusal(who)) return who;
    const documentId = typeof params?.document_id === "string" ? params.document_id : "";
    // TRIMMED before the emptiness test. `document-handshake.refuse` THROWS on a whitespace-only
    // reason, and this guard only checked length — so `{ reason: "   " }` reached it and surfaced
    // as `internal_error`, for a refusal that is otherwise perfectly valid.
    const given = typeof params?.reason === "string" ? params.reason.trim() : "";
    const reason = given.length > 0 ? given : "declined_by_operator";
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
        const peerAnswer = layer.handshake.peerAnswer(who.ownerAgentId, d.documentId);
        return {
          ...d,
          proposedByUs: proposal?.proposerAgentId === who.ownerAgentId,
          // THE PEER'S OWN SIGNED ANSWER — true accepted, false refused, null not yet heard. This
          // replaced an inference ("they have published into it") that could not tell refused from
          // unreceived from accepted-but-untouched, two of which want the operator to act.
          //
          // The REASON comes with it. It was stored and read by nothing, which defeats why it is
          // mandatory on the wire: a refusal whose reason the proposer cannot see leaves them
          // unable to propose anything better.
          peerAccepted: peerAnswer.accepted,
          peerRefusalReason: peerAnswer.reason,
          // Kept alongside it, because they answer different questions: whether they agreed, and
          // whether anything has actually come back. A document accepted an hour ago with nothing
          // in it is a fine state; it is just not the same state.
          peerHasPublished:
            layer.store.knownEnvelopeHashesBySender(who.ownerAgentId, d.documentId, d.peerAgentId).size > 0,
          consentState: proposal?.consentState ?? null,
          // DID OUR OFFER LEAVE? Only meaningful for a document WE proposed — for one we accepted
          // there is no offer of ours to have sent. Without this, `peerAccepted: null` meant both
          // "they are thinking" and "they were never asked", and the shipped guidance said WAIT,
          // which is wrong for the second and leaves the operator waiting on nothing.
          proposalSent:
            proposal?.proposerAgentId === who.ownerAgentId
              ? layer.handshake.proposalSent(who.ownerAgentId, d.documentId)
              : null,
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
    // OUR OWN edited lines, so `overlap` is a computed answer rather than the reassuring null three
    // instruction sheets were telling agents to trust. Null here still means "not computed" — we
    // have not written since the read — and `diffStats` keeps that distinct from "no conflict",
    // which is the whole reason its parameter is required.
    const myEdits = layer.notifications.myEditedLines(who.ownerAgentId, documentId);
    const stats = layer.notifications.diffStats(documentId, before, after, myEdits, document.documentType);
    if (!rendered.ok) {
      // The stats still stand — they are structural and type-independent — so a document type this
      // build cannot render is not a document an agent has to read blind.
      // NOT `reason` ON AN `ok: true`. That key is the daemon's FAILURE convention everywhere else —
      // `json-out.ts` documents `ok: false` as the one failure shape — so an agent branching on
      // `result.reason` reads this perfectly good stats-only diff as an error and stops.
      return {
        ok: true,
        documentId,
        unchanged: before === after,
        diff: null,
        diffUnavailableReason: rendered.reason,
        stats,
      };
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

    const refused = peerRefused(who, documentId);
    if (refused) return refused;

    const doc = layer.live.get(who.ownerAgentId, documentId);
    const text = doc.getText("content");
    const before = text.toString();
    if (before === content) {
      // NO TEXT CHANGE IS NOT ALWAYS NOTHING TO DO, and this returned here unconditionally — which
      // made an applied-but-unpublished edit UNRECOVERABLE.
      //
      // The sequence: a write applies the text to the live doc, `publish.publish` then refuses (the
      // platform is paused), and the handler correctly reports `changed: true, published: false`.
      // The edit is now in the document and in no log — and pending is derived from the log, so
      // nothing will ever deliver it. The operator's natural retry is to write the same text again,
      // which landed HERE and was answered `changed: false, published: false`: a cheerful no-op
      // over a permanent divergence. `cello_doc_publish` could not flush it either — it diffs the
      // FILE, which already matches.
      //
      // GATED ON A RECORDED FACT, not on asking `publish` whether anything is owed. Its own guard
      // only fires once we have published before (`lastPublishedStateVector !== null`), so on a
      // first write it would publish the whole document on every unchanged call — a leaf and a
      // delivery for nothing, which the neighbouring test pins against.
      //
      // The flag lives in memory ON PURPOSE: an unpublished edit is itself in-memory only. The live
      // doc is rebuilt from the envelope log, and the edit is by definition not in it, so both are
      // lost on restart together. A durable flag would outlive the thing it describes.
      if (unpublishedEdits.has(unpublishedKey(who.ownerAgentId, documentId))) {
        // Screened here too. A flush publishes text that was folded in on an EARLIER call, so
        // skipping it would be a way for content to reach the peer without ever passing the check.
        const stuckFault = screenText(doc.getText("content").toString());
        if (stuckFault) {
          return {
            ok: false,
            reason: "document_content_refused",
            guidance:
              `The edit waiting to be published contains ${stuckFault.codepoints.join(", ")}, which ` +
              `your peer's screening refuses. Correct the file and publish again.`,
            detail: JSON.stringify({ rule: SCREEN_RULE_ID, ...stuckFault }),
          };
        }
        const flushed = await publish.publish(who.ownerAgentId, documentId, doc, deps.now());
        if (flushed.ok) {
          unpublishedEdits.delete(unpublishedKey(who.ownerAgentId, documentId));
          layer.notifications.markWritten(who.ownerAgentId, documentId, content);
          await materialize(who.ownerAgentId, documentId, document.documentType);
          return {
            ok: true,
            documentId,
            changed: false,
            published: true,
            envelopeHash: flushed.envelopeHash,
            guidance:
              "The text was already what you sent, but an earlier edit had been applied without " +
              "reaching your peer. It has gone out now.",
          };
        }
        return {
          ok: true,
          documentId,
          changed: false,
          published: false,
          reason: flushed.reason,
          guidance:
            `An earlier edit is applied locally and still has not reached your peer ` +
            `(${flushed.reason}). ${flushed.detail ?? ""}`.trim(),
        };
      }
      return { ok: true, documentId, changed: false, published: false };
    }

    // AUTHORING-SIDE PROFILE CHECK (DOD-DOC-PROFILE-1, §16.7-14). Caught where the character was
    // WRITTEN, so it never becomes a rejection round: the peer's gate would refuse this envelope,
    // the refusal would advance the retry counter, and three of those stall the document. Refusing
    // here costs one call and no protocol state.
    //
    // This is ERGONOMICS, not security, and the distinction is load-bearing — the receiver's gate
    // runs the identical check and stays authoritative, because a sender's client can be patched or
    // compromised while the sender themselves is a good actor. Deleting this makes CELLO more
    // annoying; deleting the receiver's makes it unsafe.
    const profileFault = profileViolation(
      typeof document.properties.content_profile === "string"
        ? document.properties.content_profile
        : undefined,
      content,
    );
    // AUTHORING-SIDE SCREENING (DOD-DOC-SCREEN-1, §16.6). The receiver's gate refuses these and
    // stays authoritative; this catches them where the character was WRITTEN so it never becomes a
    // rejection round. Three rejected rounds stall the document, and a stall from a character the
    // operator cannot see in their own editor is the worst version of that.
    //
    // FRICTION REDUCTION AMONG GOOD ACTORS, never a boundary — the sender's client can be patched
    // or compromised while the sender is a good actor, which is why the receiving gate exists and
    // why this one cannot replace it. Same function on both sides (`screenText`), so the two cannot
    // disagree about what is refused.
    // SENDER ADOPTS THE RECEIVER'S RULE (DOD-DOC-SCREEN-1, §16.7-16).
    //
    // Every codepoint THIS peer has already refused for THIS document, learned from their own signed
    // refusals. Rules compose toward strict: once they have said no to a character, emitting it
    // again spends a refusal round on an answer we have already been given — and three rounds stall
    // the document, so an avoidable one is expensive.
    //
    // This is what the machine-readable refusal detail was FOR. A refusal that carried only prose
    // could be read by an operator and adopted by nobody.
    const adopted = layer.store.adoptedRefusedCodepoints(who.ownerAgentId, documentId);
    if (adopted.size > 0) {
      const offenders = new Set<string>();
      const offsets: number[] = [];
      let at = 0;
      for (const ch of content) {
        const cp = `U+${ch.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}`;
        if (adopted.has(cp)) {
          offenders.add(cp);
          offsets.push(at);
        }
        at++;
      }
      // Markers are matched as substrings, exactly as the screen matches them.
      for (const marker of [...adopted].filter((c) => !c.startsWith("U+"))) {
        let idx = content.indexOf(marker);
        while (idx !== -1) {
          offenders.add(marker);
          offsets.push([...content.slice(0, idx)].length);
          idx = content.indexOf(marker, idx + marker.length);
        }
      }
      if (offenders.size > 0) {
        offsets.sort((a, b) => a - b);
        return {
          ok: false,
          reason: "document_peer_rule_adopted",
          guidance:
            `Your peer has already refused ${[...offenders].join(", ")} in this document ` +
            `(${offsets.length} occurrence(s), first at character ${offsets[0]}). Sending it again ` +
            `would spend a refusal round on an answer they have given — and three of those stall ` +
            `the document. Remove it and write again.`,
          detail: JSON.stringify({ rule: SCREEN_RULE_ID, adopted: true, codepoints: [...offenders], count: offsets.length, offsets }),
        };
      }
    }

    const screenFault = screenText(content);
    if (screenFault) {
      return {
        ok: false,
        reason: "document_content_refused",
        guidance:
          `Your peer's screening will refuse ${screenFault.codepoints.join(", ")} ` +
          `(${screenFault.count} occurrence(s), first at character ${screenFault.offsets[0]}). ` +
          `These are characters that make what a reader SEES differ from what the document SAYS, or ` +
          `that address a reader's model rather than the reader. Remove them and write again — ` +
          `sending as-is costs a rejection round, and three of those stall the document.`,
        detail: JSON.stringify({ rule: SCREEN_RULE_ID, ...screenFault }),
      };
    }
    if (profileFault) {
      return {
        ok: false,
        reason: "document_profile_violation",
        guidance:
          `This document was agreed as '${profileFault.profile}', which does not allow ` +
          `${profileFault.codepoints.join(", ")} (${profileFault.count} occurrence(s), first at ` +
          `character ${profileFault.offsets[0]}). The profile is fixed for the life of the document ` +
          `— it was bound into the id when your peer accepted it — so change the text rather than ` +
          `the setting.`,
        detail: JSON.stringify(profileFault),
      };
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
      // REMEMBER IT, so the retry above can flush it. Without this the operator's next identical
      // write is indistinguishable from an ordinary no-op and the edit never leaves.
      unpublishedEdits.add(unpublishedKey(who.ownerAgentId, documentId));
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
    // WHAT WE WROTE, against the current read mark. Without it `cello_doc_diff` shows our own edits
    // back to us as "what changed since I looked" — which the tool description frames as the
    // COUNTERPARTY's contribution — and `overlap` has nothing to separate mine from theirs.
    unpublishedEdits.delete(unpublishedKey(who.ownerAgentId, documentId));
    layer.notifications.markWritten(who.ownerAgentId, documentId, content);
    // AND THE FILE. `cello_doc_write` changes the document; without this the operator's own
    // projection on disk is stale the moment they use it, and the two surfaces disagree about the
    // document they both claim to show.
    //
    // Worse than cosmetic: `cello_doc_publish` diffs the FILE against the last recorded projection,
    // so a stale file either refuses as `document_file_stale` or — if it happened to match an older
    // baseline — republishes text the document has already moved past. Found on the first live
    // two-agent smoke, where the author's own file was missing the line she had just written.
    const writtenFile = await materialize(who.ownerAgentId, documentId, document.documentType);
    // Delivery is the worker's, not this call's — publish is fire-and-forget by design (§16.4), and
    // a write that blocked on an offline peer would make editing a shared document depend on the
    // other party being awake.
    return {
      ok: true,
      documentId,
      changed: true,
      published: true,
      envelopeHash: result.envelopeHash,
      // THE FILE'S FATE, SURFACED. `materialize` swallows its error — right for propose and accept,
      // where a disk fault must not fail a completed consent decision, and wrong here. The comment
      // above this call already spells out the consequence: a stale file makes the NEXT
      // `cello_doc_publish` refuse as `document_file_stale`, or worse, republish text the document
      // has moved past. The cause was a swallowed error one call earlier that only a daemon-log
      // reader would ever see.
      fileUpdated: writtenFile !== null,
      ...(writtenFile === null
        ? {
            guidance:
              "The change was published, but your local file could not be rewritten. Read the " +
              "document rather than the file, and expect cello_doc_publish to refuse as " +
              "document_file_stale until the file is back in step.",
          }
        : {}),
    };
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
    const status = layer.store.getDocument(who.ownerAgentId, documentId)?.status ?? "unknown";
    // BILATERAL. The document settles when both sides have said it, so "closed" is not this call's
    // answer to give — reporting it would tell an operator the collaboration is over while the peer
    // is still editing.
    //
    // `peerNotified` is reported for the same reason `kill` reports it, and its absence here was an
    // asymmetry with teeth: `status: "active"` after a close is INDISTINGUISHABLE from "sent fine,
    // they have not answered yet". Control frames are fire-once — unlike update envelopes they are
    // not in the log and the delivery sweep never retries them — so a close sent while the peer was
    // offline means the document can never settle, forever, with nothing on either screen.
    return {
      ok: true,
      documentId,
      status,
      peerNotified: outcome.peerNotified,
      ...(outcome.peerNotified
        ? {}
        : {
            guidance:
              `Your close was recorded but did not reach the peer, so the document cannot settle ` +
              `until they hear it. A close is not retried — run cello_doc_close again when they ` +
              `are back, or cello_doc_kill if you need it over now.`,
          }),
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

  handlers.set("cello_doc_publish", async (params, connectionId) => {
    const who = resolve(params, connectionId);
    if (isRefusal(who)) return who;
    const documentId = typeof params?.document_id === "string" ? params.document_id : "";
    if (documentId.length === 0) {
      return { ok: false, reason: "invalid_document_id", guidance: "Pass 'document_id' from cello_doc_list." };
    }
    if (!layer.writePath) {
      return {
        ok: false,
        reason: "document_files_unavailable",
        guidance: "This daemon has no document workspace configured, so there is no file to publish from.",
      };
    }
    const document = layer.store.getDocument(who.ownerAgentId, documentId);
    if (!document) {
      return {
        ok: false,
        reason: "document_unknown",
        guidance: `No document ${documentId.slice(0, 16)}… for this agent. See cello_doc_list.`,
      };
    }

    const refusedByPeer = peerRefused(who, documentId);
    if (refusedByPeer) return refusedByPeer;

    const doc = layer.live.get(who.ownerAgentId, documentId);
    let update: Uint8Array | null;
    try {
      // Diffs the FILE against the last recorded projection and folds the difference in as local
      // operations. Refuses loudly on a stale baseline rather than diffing against something the
      // document has moved past — which would read a peer's admitted content as a deliberate
      // deletion and publish it as one.
      update = await layer.writePath.publish(who.ownerAgentId, documentId, document.documentType, doc);
    } catch (err: unknown) {
      const reason = err instanceof Error && "reason" in err ? String((err as { reason: unknown }).reason) : "document_file_error";
      return {
        ok: false,
        reason,
        guidance: err instanceof Error ? err.message : String(err),
      };
    }
    if (update === null) {
      // NOTHING NEW ON DISK — but an earlier publish may have FOLDED an edit in and then failed to
      // publish it, in which case the file now matches the projection and there is nothing left to
      // diff. Without this branch that edit can never leave: the operator clears the cause, publishes
      // again, and gets a clean "nothing to do" over a change the peer has never seen — with
      // `cello_doc_list` agreeing, because pending is derived from the envelope log and no envelope
      // was ever written. Same recovery `cello_doc_write` has; it was missing here while the comment
      // below claimed parity.
      if (unpublishedEdits.has(unpublishedKey(who.ownerAgentId, documentId))) {
        const flushed = await publish.publish(who.ownerAgentId, documentId, doc, deps.now());
        if (!flushed.ok) {
          return { ok: true, documentId, changed: false, published: false, reason: flushed.reason, guidance: flushed.detail };
        }
        unpublishedEdits.delete(unpublishedKey(who.ownerAgentId, documentId));
        layer.notifications.markWritten(who.ownerAgentId, documentId, doc.getText("content").toString());
        return { ok: true, documentId, changed: true, published: true, envelopeHash: flushed.envelopeHash };
      }
      // A publish is an INTENT. Nothing changed on disk, so there is nothing to say, and saying it
      // anyway costs a leaf and a round trip.
      return { ok: true, documentId, changed: false, published: false };
    }

    // SCREEN WHAT THE FILE IS ABOUT TO SEND. `cello_doc_write` catches an offending character at the
    // keystroke so it never becomes a rejection round — and three rejection rounds stall a document
    // permanently. The file path ran none of it, on the surface §4.1 calls PRIMARY: a human editing
    // in their editor, or an agent with file tools. A zero-width space pasted from a web page is
    // invisible in both, and the refusal arrives later from the peer with no clue where it came from.
    //
    // Screened AFTER the fold because the fold is what produces the text; the edit is therefore
    // already in the local document when this refuses. The flag is deliberately NOT set: flushing
    // later would publish the offending bytes unscreened. Correcting the file is what removes it,
    // and the guidance says so.
    const publishScreenFault = screenText(doc.getText("content").toString());
    if (publishScreenFault) {
      return {
        ok: false,
        reason: "document_content_refused",
        guidance:
          `Your peer's screening will refuse ${publishScreenFault.codepoints.join(", ")} ` +
          `(${publishScreenFault.count} occurrence(s), first at character ` +
          `${publishScreenFault.offsets[0]}). These are characters that make what a reader SEES ` +
          `differ from what the document SAYS, or that address a reader's model rather than the ` +
          `reader — they are easy to paste in without seeing them. Nothing was sent. Remove them ` +
          `from the file and publish again; sending as-is costs a rejection round, and three of ` +
          `those stall the document.`,
        detail: JSON.stringify({ rule: SCREEN_RULE_ID, ...publishScreenFault }),
      };
    }

    const result = await publish.publish(who.ownerAgentId, documentId, doc, deps.now());
    if (!result.ok) {
      // The file's edits are already FOLDED INTO the document — same shape as cello_doc_write's
      // applied-but-unpublished case, and reported the same way, because an operator told this
      // failed would edit again and the second publish would diff against a projection that already
      // contains their change.
      // REMEMBER IT, so the branch above can flush it. This is what made the comment's claim of
      // parity with `cello_doc_write` true rather than aspirational.
      unpublishedEdits.add(unpublishedKey(who.ownerAgentId, documentId));
      return { ok: true, documentId, changed: true, published: false, reason: result.reason, guidance: result.detail };
    }
    layer.notifications.markWritten(who.ownerAgentId, documentId, doc.getText("content").toString());
    return { ok: true, documentId, changed: true, published: true, envelopeHash: result.envelopeHash };
  });

  logger.debug("document.handlers.registered", {
    // DERIVED from what was actually registered, never hand-typed. The list it replaced was a
    // second source of truth for the one question this line exists to answer, and it could drift
    // from the handler map without anything noticing — which is the same four-place-lockstep
    // failure this surface has already had twice.
    // Matched on `_doc_` and logged WHOLE rather than stripped of a `cello_doc_` prefix: the
    // §2b source audit reads cello_* tokens out of this file to prove the daemon never names a
    // tool that does not exist, and a bare prefix literal reads to it as exactly that — a dead
    // command. The audit was right to flag it; the literal is what had to go.
    verbs: [...handlers.keys()].filter((k) => k.includes("_doc_")).sort(),
  });
}
