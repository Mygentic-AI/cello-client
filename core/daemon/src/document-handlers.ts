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
  deriveDocumentState,
  documentGovernancePolicy,
  arrangementGenesisFromProposal,
  documentAmendmentHash,
  buildDocumentMultisigTbs,
  encodeDocumentAmendment,
  type DocumentAmendmentBody,
  type DocumentAmendmentEnvelope,
  buildDocumentProposalTbs,
  documentIdFromProposal,
  seamViolation,
  ASSURANCE_TIER_V1,
  TOPOLOGY_DEFAULT,
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
import type { DocumentDeliveryTransport } from "./document-delivery-transport.js";
import { lineHunks, isSupportedDocumentType, SUPPORTED_DOCUMENT_TYPES } from "./document-write-path.js";
import { openingNoticeFor, rootForDocumentType } from "./document-types.js";
import { projectDocumentText, parseJsonDocument, applyJsonToMap } from "./document-json.js";
import { classifyRemovals } from "./document-write-guard.js";
import { normalizeWatchPaths } from "./document-watch.js";
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

/** Ends a fragment with a full stop unless it already ends in one — see the refusal below. */
function withStop(text: string): string {
  return /[.!?]$/.test(text.trimEnd()) ? text : `${text.trimEnd()}.`;
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
  ): Promise<{ path: string | null; reason?: string; detail?: string }> {
    if (!layer.writePath) return { path: null, reason: "document_files_unavailable" };
    try {
      const path = await layer.writePath.materialize(
        ownerAgentId,
        documentId,
        documentType,
        layer.live.get(ownerAgentId, documentId),
      );
      return { path };
    } catch (err: unknown) {
      // THE REASON TRAVELS TO THE CALLER, not just to the log. `propose` and `accept` returned
      // `filePath: null` and said nothing, while the tool description promises "returns its path" —
      // so an operator looking for a file that is not there had no way to learn why without reading
      // the daemon log. `cello_doc_write` was given `fileUpdated` and guidance for exactly this;
      // these two were not.
      const reason = err instanceof Error && "reason" in err
        ? String((err as { reason: unknown }).reason)
        : "document_file_error";
      const detail = err instanceof Error ? err.message : String(err);
      logger.warn("document.file.materialize_failed", { documentId, reason, detail });
      return { path: null, reason, detail };
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
      // SEEDED INTO THE ROOT THE TYPE USES. A JSON document seeded into the text root would be
      // accepted, materialize as `{}`, and read as empty on both sides — the starting content
      // silently discarded while every surface reported success.
      if (rootForDocumentType(documentType) === "map") {
        const seeded = parseJsonDocument(startingText);
        if (!seeded.ok) {
          return {
            ok: false,
            reason: "document_content_unparseable",
            guidance:
              `This is a JSON document and starting_content is not valid JSON (${seeded.detail}). ` +
              `Nothing was created, so there is nothing to clean up.`,
          };
        }
        applyJsonToMap(seed.getMap("data"), seeded.value, seed);
      } else {
        seed.getText("content").insert(0, startingText);
      }
      startingContent = Y.encodeStateAsUpdate(seed);
    }

    // THE ADMIN SET IS ALWAYS WRITTEN, NEVER SILENTLY ABSENT (GOVERN-1: the creation flow makes
    // the choice legible). No `admins` param means EVERYONE — both genesis participants — and
    // that default is recorded explicitly in the signed proposal rather than implied by an
    // absent field, so the invitee consents to a stated rule, not a convention.
    const rawAdmins = params?.admins;
    if (rawAdmins !== undefined && (!Array.isArray(rawAdmins) || rawAdmins.length === 0)) {
      return {
        ok: false,
        reason: "document_admins_invalid",
        guidance:
          "admins must be a non-empty list of 64-hex pubkeys, or omitted for everyone-is-admin. " +
          "Nothing was created.",
      };
    }
    const adminSet = rawAdmins === undefined
      ? [who.ownerAgentId, peerAgentId]
      : [...new Set(rawAdmins as string[])];
    for (const admin of adminSet) {
      if (admin !== who.ownerAgentId && admin !== peerAgentId) {
        return {
          ok: false,
          reason: "document_admins_invalid",
          guidance:
            `${String(admin).slice(0, 16)}… is not a party to this document — a creation admin ` +
            `must be you or the counterparty (admins are always holders). Nothing was created.`,
        };
      }
    }
    const properties = {
      assurance_tier: ASSURANCE_TIER_V1,
      schema_enforcement: false,
      topology: TOPOLOGY_DEFAULT,
      append_only: params?.append_only === true,
      admin_set: adminSet,
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
    const proposeFile = await materialize(who.ownerAgentId, documentId, documentType);

    const correlationId = randomUUID();
    const sent = await deps.transportFor(who.agentName).sendBytes({
      peerAgentId,
      documentId,
      bytes: encodeDocumentProposal(envelope),
      correlationId,
    });
    // `document.proposal.sent` per the DoD taxonomy. It was `document.proposed`, which reads as
    // the same fact but does not match what an operator or a log query is told to look for.
    logger.info("document.proposal.sent", { documentId, peerAgentId, sent: sent.ok, correlationId });

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
    return {
      ok: true,
      documentId,
      proposalSent: true,
      peerAgentId,
      filePath: proposeFile.path,
      // A file that RUNS when opened says so where the operator is handed its path — see
      // `openingNoticeFor`. Only html carries one today, and only because a peer can write into it.
      ...(proposeFile.path !== null && openingNoticeFor(documentType) !== undefined
        ? { fileNotice: openingNoticeFor(documentType) }
        : {}),
      // Said out loud rather than left as a silent null against a description that promises a path.
      ...(proposeFile.path === null
        ? {
            fileUnavailableReason: proposeFile.reason,
            guidance:
              `The document exists and the offer was sent, but no file was written for it ` +
              `(${proposeFile.reason}${proposeFile.detail ? `: ${proposeFile.detail}` : ""}). Use ` +
              `cello_doc_read and cello_doc_write, which do not need the file.`,
          }
        : {}),
    };
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
      // SYNC-P4 (D5 deleted): open invitations, DERIVED — a document this daemon holds whose
      // entry set says this agent is an invited seat. The operator consents to what their own
      // daemon computed from the signed record, not to a carried snapshot; cello_doc_accept
      // re-derives at the moment of consequence. The inviter shown is the author of the admit
      // entry naming this agent (the genesis proposer for a genesis-named seat).
      joins: layer.store
        .listDocuments(who.ownerAgentId)
        .filter((d) => d.status === "active")
        .flatMap((d) => {
          const genesisRecord = layer.handshake.get(who.ownerAgentId, d.documentId);
          if (!genesisRecord) return [];
          const derived = deriveDocumentState(
            arrangementGenesisFromProposal(genesisRecord.envelope),
            layer.amendments.chain(who.ownerAgentId, d.documentId),
            documentGovernancePolicy,
            layer.verifySignature,
          );
          if (!derived.ok || !derived.state.invited.has(who.ownerAgentId)) return [];
          const admit = layer.amendments
            .chain(who.ownerAgentId, d.documentId)
            .find(
              (e) => e.body.kind === "add_holder" && e.body.subject_agent_id === who.ownerAgentId,
            );
          return [
            {
              documentId: d.documentId,
              inviterAgentId:
                admit?.body.author_agent_id ?? genesisRecord.envelope.proposer_agent_id,
              participants: [...derived.state.participants].sort(),
              invited: [...derived.state.invited].sort(),
              admins: [...derived.state.admins].sort(),
              properties: derived.state.properties,
              assuranceTier: "authenticated",
              documentType: d.documentType,
            },
          ];
        }),
    };
  });

  // The join-answer frame died with D5 — the consent/refusal ENTRY is the answer, and it fans out.

  handlers.set("cello_doc_accept", async (params, connectionId) => {
    const who = resolve(params, connectionId);
    if (isRefusal(who)) return who;
    const documentId = typeof params?.document_id === "string" ? params.document_id : "";
    if (documentId.length === 0) {
      return { ok: false, reason: "invalid_document_id", guidance: "Pass 'document_id' from cello_doc_inbox." };
    }

    // THE CURE FOR A HALF-CONSENTED DOCUMENT (P2 review F2): if this agent already holds the
    // document but its own derivation says it is still an INVITED seat, the earlier accept
    // recorded the decision and then failed to record the consent entry — and both decision rows
    // are settled, so neither branch below can run again. Re-running accept authors the missing
    // consent, which is exactly what the failure guidance promises.
    if (layer.store.getDocument(who.ownerAgentId, documentId)) {
      const genesisRecord = layer.handshake.get(who.ownerAgentId, documentId);
      if (genesisRecord) {
        const standing = deriveDocumentState(
          arrangementGenesisFromProposal(genesisRecord.envelope),
          layer.amendments.chain(who.ownerAgentId, documentId),
          documentGovernancePolicy,
          layer.verifySignature,
        );
        if (standing.ok && standing.state.invited.has(who.ownerAgentId)) {
          // THE JOIN PATH (SYNC-P4, D5 deleted): the document arrived through the exchange, this
          // agent derives as an invited seat, and accepting IS authoring the consent entry (R21)
          // — which travels to every holder over the same carrier as everything else. Until it
          // reaches them, their fold shows this agent invited, not participating. Idempotent by
          // re-run: a consent that failed to record is authored on the next accept.
          const consent = await authorConsent(who, documentId);
          if (!consent.ok) {
            return {
              ok: false,
              reason: "document_consent_unrecorded",
              guidance:
                `You hold this document but your consent entry is not recorded ` +
                `(${consent.reason}) — run cello_doc_accept again once the named condition ` +
                `clears.`,
            };
          }
          const doc = layer.store.getDocument(who.ownerAgentId, documentId)!;
          const joinFile = await materialize(who.ownerAgentId, documentId, doc.documentType);
          return {
            ok: true,
            documentId,
            joined: true,
            consentEntry: consent.entryHash,
            consentDelivered: consent.holdersNotified,
            filePath: joinFile.path,
            ...(joinFile.path !== null && openingNoticeFor(doc.documentType) !== undefined
              ? { fileNotice: openingNoticeFor(doc.documentType) }
              : {}),
          };
        }
      }
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
    const acceptFile = await materialize(who.ownerAgentId, documentId, outcome.envelope.document_type);
    // R21: the accept IS this agent's consent entry — the proposer's fold shows this agent
    // invited until the entry reaches them over the amendment carrier.
    const consent = await authorConsent(who, documentId);
    if (!consent.ok) {
      logger.warn("document.consent.unrecorded", {
        documentId,
        reason: consent.reason,
      });
    }
    // NOT re-logged here. `DocumentHandshake` already emits `document.proposal.accepted` for this
    // exact fact, and two events for one act make every count of "how many were accepted" wrong
    // depending on which name the query used.
    const told = await tellProposer(who, documentId, outcome.envelope.proposer_agent_id, true, undefined);
    return {
      ok: true,
      documentId,
      peerAgentId: outcome.envelope.proposer_agent_id,
      proposerNotified: told,
      ...(consent.ok
        ? { consentEntry: consent.entryHash, consentDelivered: consent.holdersNotified }
        : { consentUnrecorded: consent.reason }),
      filePath: acceptFile.path,
      // Matters MORE here than on propose: the type came from the PROPOSER's envelope, so the
      // accepter is being handed an executable file they did not choose the format of.
      ...(acceptFile.path !== null && openingNoticeFor(outcome.envelope.document_type) !== undefined
        ? { fileNotice: openingNoticeFor(outcome.envelope.document_type) }
        : {}),
      ...(acceptFile.path === null
        ? {
            fileUnavailableReason: acceptFile.reason,
            guidance:
              `You accepted the document and it is live, but no file was written for it ` +
              `(${acceptFile.reason}${acceptFile.detail ? `: ${acceptFile.detail}` : ""}). Use ` +
              `cello_doc_read and cello_doc_write, which do not need the file.`,
          }
        : {}),
    };
  });

  /**
   * DOD-MP-INVITE-FANOUT-1 — fan a governance amendment to the CURRENT holders, durably.
   *
   * ONE implementation for every site that fans one. There were four — invite, re-invite, remove,
   * and remove's re-send — each with its own copy of the same best-effort loop, and the review found
   * that wiring durability into one of them left the other three losing membership changes exactly
   * as before. The re-invite is the verb the tool's own guidance tells an operator to run when a
   * holder is out of step, so it carrying the defect meant the documented cure did nothing.
   *
   * RECORD THE DEBT FIRST. The send below is a fast path, never the guarantee: a daemon that dies
   * between here and the send still owes the amendment on restart.
   *
   * A successful send is recorded as SENT, not acked — their daemon received the frame, and whether
   * it RECORDED it is a separate fact it can refuse. The row settles for real when that holder acks
   * any envelope at this epoch or later, which proves they applied it.
   */
  const fanOutAmendment = async (args: {
    agentName: string;
    ownerAgentId: string;
    documentId: string;
    amendmentHashHex: string;
    amendmentBytes: Uint8Array;
    holders: readonly string[];
    verb: string;
  }): Promise<Record<string, boolean>> => {
    const told: Record<string, boolean> = {};
    for (const holder of args.holders) {
      try {
        const sent = await deps.transportFor(args.agentName).sendBytes({
          peerAgentId: holder,
          documentId: args.documentId,
          bytes: args.amendmentBytes,
          correlationId: randomUUID(),
        });
        // PARKED IS NOT NOTIFIED. The relay took it because the holder had no live counterparty.
        const landed = sent.ok && sent.parked !== true;
        told[holder] = landed;
        if (!landed) {
          // NAMED, NOT JUST COUNTED. This used to record `false` with no log line anywhere, so the
          // only trace of a lost membership change was a boolean inside an `ok: true` response.
          logger.warn("document.amendment.holder_unnotified", {
            documentId: args.documentId,
            holderAgentId: holder,
            verb: args.verb,
            reason: sent.ok ? "relay_parked" : sent.reason,
            detail: sent.ok
              ? "the relay is holding it — the holder had no live counterparty"
              : sent.detail,
          });
        }
      } catch (err: unknown) {
        told[holder] = false;
        // A throw used to be swallowed whole.
        logger.warn("document.amendment.holder_unnotified", {
          documentId: args.documentId,
          holderAgentId: holder,
          verb: args.verb,
          reason: "amendment_send_threw",
          detail: err instanceof Error ? err.message : String(err),
        });
      }
    }
    return told;
  };

  /**
   * SYNC-P2 (R21/R22) — author THIS agent's consent entry for a document they were named into,
   * append it locally, and fan it to the derived participants over the amendment carrier. Both
   * accept branches (a bilateral proposal, a join offer) call this: consenting IS authoring your
   * first entry, and until it reaches the others their fold shows you invited, not participating.
   */
  const authorConsent = async (who: {
    agentName: string;
    ownerAgentId: string;
  }, documentId: string, kind: "consent" | "refuse_join" | "close" | "kill" = "consent"): Promise<
    | { ok: true; entryHash: string; holdersNotified: Record<string, boolean> }
    | { ok: false; reason: string }
  > => {
    const genesisRecord = layer.handshake.get(who.ownerAgentId, documentId);
    if (!genesisRecord) return { ok: false, reason: "document_genesis_missing" };
    const genesisArr = arrangementGenesisFromProposal(genesisRecord.envelope);
    let chain: ReturnType<typeof layer.amendments.chain>;
    try {
      chain = layer.amendments.chain(who.ownerAgentId, documentId);
    } catch (err: unknown) {
      return {
        ok: false,
        reason: `document_chain_undecodable: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
    const derived = deriveDocumentState(genesisArr, chain, documentGovernancePolicy, layer.verifySignature);
    if (!derived.ok) return { ok: false, reason: derived.reason };
    // R29's author-side mirror of the R30 inbound gate: an ended world takes no further entries.
    // Every other holder would refuse this entry (their gate finds the ending in its closure), so
    // authoring it would only fork this daemon away from the agreement everyone else has settled —
    // the concrete case being a late kill rewriting "closed by agreement" as a unilateral end.
    if (derived.state.ended !== null) {
      return { ok: false, reason: derived.state.ended === "killed" ? "document_killed" : "document_closed" };
    }
    const body: DocumentAmendmentBody = {
      document_id: documentId,
      kind,
      subject_agent_id: who.ownerAgentId,
      // A refusal names nothing it agrees to — it is the subject's own signed no (R24).
      property_change:
        kind === "consent"
          ? {
              key: "consents_to",
              value: `${String(derived.state.properties["assurance_tier"])}/${DOCUMENT_FEATURE_VERSION}`,
            }
          : null,
      state_hash: null,
      authored_at_ms: deps.now(),
      author_agent_id: who.ownerAgentId,
      author_seq:
        (layer.amendments.watermarks(who.ownerAgentId, documentId).get(who.ownerAgentId)?.seq ??
          0) + 1,
      parents: [...derived.state.frontier],
    };
    const entryHash = documentAmendmentHash(body);
    const multisigTbs = buildDocumentMultisigTbs({
      document_id: documentId,
      subject_kind: "document_amendment",
      subject_hash: entryHash,
      required_signers: [who.ownerAgentId],
    });
    const consent: DocumentAmendmentEnvelope = {
      body,
      collection: {
        document_id: documentId,
        subject_kind: "document_amendment",
        subject_hash: entryHash,
        required_signers: [who.ownerAgentId],
        signatures: [
          { signer_agent_id: who.ownerAgentId, signature: await deps.sign(who.agentName, multisigTbs) },
        ],
      },
    };
    // The same author-your-own-void guard every local authoring site carries.
    const withNew = deriveDocumentState(
      genesisArr, [...chain, consent], documentGovernancePolicy, layer.verifySignature,
    );
    if (!withNew.ok) return { ok: false, reason: withNew.reason };
    const entryHex = Buffer.from(entryHash).toString("hex");
    const inert =
      withNew.state.voids.find((v) => v.hash === entryHex) ??
      withNew.state.excluded.find((e) => e.hash === entryHex);
    if (inert) return { ok: false, reason: inert.reason };
    const bytes = new Uint8Array(encodeDocumentAmendment(consent));
    layer.amendments.append(who.ownerAgentId, documentId, bytes, deps.now());
    const holdersNotified = await fanOutAmendment({
      agentName: who.agentName,
      ownerAgentId: who.ownerAgentId,
      documentId,
      amendmentHashHex: entryHex,
      amendmentBytes: bytes,
      holders: [...withNew.state.participants, ...withNew.state.invited].filter(
        (p) => p !== who.ownerAgentId,
      ),
      verb: kind,
    });
    // SYNC-P4: the AUTHOR'S own status projection — the inbound path projects on receipt, and
    // the authoring daemon must not read "active" for a document its own entry just ended.
    if ((kind === "close" || kind === "kill") && withNew.state.ended !== null) {
      layer.store.setDocumentStatus(
        who.ownerAgentId,
        documentId,
        withNew.state.ended === "killed" ? "killed" : "closed",
      );
    }
    return { ok: true, entryHash: entryHex, holdersNotified };
  };

  /**
   * M14B / DOD-MP-JOIN-1 — invite a third party into an existing document.
   *
   * One admin's signature authors the admitting amendment (D2); the invitee's own consent makes
   * the join real (their accept, on their daemon). VALIDATE-THEN-APPEND: the chain including the
   * new amendment replays through the real policy before one byte lands — the AMEND-1 standing
   * condition at its second production append site. The offer carries the genesis, the whole
   * chain, and the update-log snapshot re-encoded from rows (lossless: the client id is a
   * column, the encoding a pinned constant — the same re-encode the delivery path ships).
   * Existing holders get the amendment frame BEST-EFFORT at P1; the epoch gate makes a missed
   * one loud, and durable per-holder delivery is FANOUT-1.
   */
  handlers.set("cello_doc_invite", async (params, connectionId) => {
    const who = resolve(params, connectionId);
    if (isRefusal(who)) return who;
    const documentId = typeof params?.document_id === "string" ? params.document_id : "";
    const invitee = typeof params?.invitee_pubkey === "string" ? params.invitee_pubkey : "";
    if (documentId.length === 0) {
      return { ok: false, reason: "invalid_document_id", guidance: "Pass 'document_id' from cello_doc_list." };
    }
    if (!/^[0-9a-f]{64}$/.test(invitee)) {
      return {
        ok: false,
        reason: "invalid_invitee_pubkey",
        guidance: "invitee_pubkey must be the 64-hex agent id — see cello_contacts.",
      };
    }
    const doc = layer.store.getDocument(who.ownerAgentId, documentId);
    if (!doc) {
      return { ok: false, reason: "document_unknown", guidance: `No document ${documentId.slice(0, 16)}… for this agent.` };
    }
    if (doc.status !== "active") {
      return {
        ok: false,
        reason: "document_not_active",
        guidance: `This document is ${doc.status} — only an active document can admit a holder.`,
      };
    }
    const genesisRecord = layer.handshake.get(who.ownerAgentId, documentId);
    if (!genesisRecord) {
      return {
        ok: false,
        reason: "document_genesis_missing",
        guidance: "The document has a row but no stored genesis proposal to replay from — this is a local-state fault, not the peer's.",
      };
    }
    const genesisArr = arrangementGenesisFromProposal(genesisRecord.envelope);
    const chain = layer.amendments.chain(who.ownerAgentId, documentId);
    const derived = deriveDocumentState(genesisArr, chain, documentGovernancePolicy, layer.verifySignature);
    if (!derived.ok) {
      return { ok: false, reason: "document_chain_invalid", guidance: derived.reason };
    }
    if (!derived.state.admins.has(who.ownerAgentId)) {
      return {
        ok: false,
        reason: "document_not_admin",
        guidance:
          `Inviting takes an admin's signature and this agent holds no admin power here. ` +
          `Current admins: ${[...derived.state.admins].join(", ")}.`,
      };
    }
    if (derived.state.participants.has(invitee)) {
      return {
        ok: false,
        reason: "document_already_holder",
        guidance: "That agent already holds this document — there is nothing to invite them to.",
      };
    }
    if (derived.state.invited.has(invitee)) {
      // A RE-RUN while the invitation is open: the admitting entry is already in the chain, so
      // authoring afresh would only mint a void. Re-send the NOTICE (SYNC-R25) — initiating a
      // reconcile exchange is idempotent by construction, and the invitee's empty-handed answer
      // pulls the genesis and the whole entry set across. The other holders are re-fanned the
      // admitting entry too: one who missed it is wedged, refusing the invitee by name.
      const admitting = chain.find(
        (e) => e.body.kind === "add_holder" && e.body.subject_agent_id === invitee,
      );
      const priorHash = admitting
        ? Buffer.from(documentAmendmentHash(admitting.body)).toString("hex")
        : null;
      const renotice = await layer.initiateReconcile(who.ownerAgentId, invitee, [documentId]);
      let holdersNotified: Record<string, boolean> = {};
      if (admitting && priorHash !== null) {
        holdersNotified = await fanOutAmendment({
          agentName: who.agentName,
          ownerAgentId: who.ownerAgentId,
          documentId,
          amendmentHashHex: priorHash,
          amendmentBytes: new Uint8Array(encodeDocumentAmendment(admitting)),
          holders: [...derived.state.participants, ...derived.state.invited].filter(
            (holder) => holder !== who.ownerAgentId && holder !== invitee,
          ),
          verb: "re-invite",
        });
      }
      return {
        ok: true,
        documentId,
        inviteeAgentId: invitee,
        amendmentHash: priorHash,
        resent: true,
        noticeSent: renotice.ok,
        holdersNotified,
      };
    }

    const body: DocumentAmendmentBody = {
      document_id: documentId,
      kind: "add_holder",
      subject_agent_id: invitee,
      property_change: null,
      state_hash: null,
      authored_at_ms: deps.now(),
      // SYNC-P1 — the causal fields: authored on the fold's frontier.
      author_agent_id: who.ownerAgentId,
      author_seq:
        (layer.amendments.watermarks(who.ownerAgentId, documentId).get(who.ownerAgentId)?.seq ??
          0) + 1,
      parents: [...derived.state.frontier],
    };
    const amendHash = documentAmendmentHash(body);
    const multisigTbs = buildDocumentMultisigTbs({
      document_id: documentId,
      subject_kind: "document_amendment",
      subject_hash: amendHash,
      required_signers: [who.ownerAgentId],
    });
    const amendment: DocumentAmendmentEnvelope = {
      body,
      collection: {
        document_id: documentId,
        subject_kind: "document_amendment",
        subject_hash: amendHash,
        required_signers: [who.ownerAgentId],
        signatures: [
          { signer_agent_id: who.ownerAgentId, signature: await deps.sign(who.agentName, multisigTbs) },
        ],
      },
    };
    // VALIDATE-BEFORE-APPEND, on the exact bytes about to land.
    const withNew = deriveDocumentState(
      genesisArr, [...chain, amendment], documentGovernancePolicy, layer.verifySignature,
    );
    if (!withNew.ok) {
      return { ok: false, reason: "document_amendment_invalid", guidance: withNew.reason };
    }
    // A locally-authored entry must TAKE EFFECT — a fold-void entry is admissible history when a
    // peer sends it, but authoring one ourselves would be publishing an act we already know is
    // inert, and the void's reason is the refusal the operator needs.
    {
      const candidateHex = Buffer.from(amendHash).toString("hex");
      const inert =
        withNew.state.voids.find((v) => v.hash === candidateHex) ??
        withNew.state.excluded.find((e) => e.hash === candidateHex);
      if (inert) {
        return { ok: false, reason: "document_amendment_invalid", guidance: inert.reason };
      }
    }
    const amendmentBytes = new Uint8Array(encodeDocumentAmendment(amendment));
    layer.amendments.append(who.ownerAgentId, documentId, amendmentBytes, deps.now());

    const amendHashHex = Buffer.from(amendHash).toString("hex");
    // THE NOTICE (SYNC-R25, replacing the D5 offer): no bespoke frame carrying history — the
    // inviter initiates a reconcile exchange naming the document. The invitee's daemon answers
    // the unheld position with an empty hand, and the step-2 reply carries the genesis and the
    // whole entry set (the P3 bootstrap). Losing the notice strands nothing: the admission is in
    // the chain, and any later exchange with any holder delivers it.
    const notice = await layer.initiateReconcile(who.ownerAgentId, invitee, [documentId]);
    const offerSent = notice.ok;
    if (!notice.ok) {
      logger.warn("document.join.notice_unsent", { documentId, reason: notice.reason });
    }
    // DOD-MP-INVITE-FANOUT-1 — RECORD WHAT IS OWED BEFORE TRYING TO SEND IT.
    //
    // The loop below is a fast path, not the guarantee. It used to be both, and that is the whole
    // defect: one failed send lost a membership change permanently, because nothing remained owing
    // anywhere. A content edit has always had a pending row, a retry schedule and restart survival;
    // the governance act that decides who is a party to the document had none of them.
    //
    // Seeding first also makes the crash window safe: a daemon that dies between here and the send
    // still owes the amendment on restart.
    const owedHolders = [...derived.state.participants, ...derived.state.invited].filter(
      (holder) => holder !== who.ownerAgentId && holder !== invitee,
    );
    const holdersTold = await fanOutAmendment({
      agentName: who.agentName,
      ownerAgentId: who.ownerAgentId,
      documentId,
      amendmentHashHex: amendHashHex,
      amendmentBytes,
      holders: owedHolders,
      verb: "invite",
    });
    logger.info("document.join.invited", { documentId, invitee, noticeSent: offerSent });
    return {
      ok: true,
      documentId,
      inviteeAgentId: invitee,
      amendmentHash: amendHashHex,
      noticeSent: offerSent,
      holdersNotified: holdersTold,
      ...(offerSent
        ? {}
        : {
            guidance:
              "The admission is recorded and the invitation exists, but the notice did not reach " +
              "the invitee — they may be offline. Re-run cello_doc_invite with the same invitee " +
              "once they are reachable: it re-sends the notice rather than authoring a second " +
              "entry.",
          }),
    };
  });

  /**
   * DOD-MP-REMOVE-1 — remove a holder, forward-only. Two shapes, one verb: an admin removing a
   * non-admin holder, and a holder removing THEMSELVES (voluntary leave — always theirs, per
   * D3). What removal means is exactly and only: delivery to them stops and their new edits
   * refuse naming the removal. Their copy is theirs forever — no surface claims more. Removing
   * a fellow ADMIN refuses here the way the policy refuses it everywhere (demote first, under
   * remove_admin's all-others rule — whose cross-daemon signature gathering is a parked design
   * note, Entry 10).
   */
  handlers.set("cello_doc_remove", async (params, connectionId) => {
    const who = resolve(params, connectionId);
    if (isRefusal(who)) return who;
    const documentId = typeof params?.document_id === "string" ? params.document_id : "";
    const holder = typeof params?.holder_pubkey === "string" ? params.holder_pubkey : "";
    if (documentId.length === 0) {
      return { ok: false, reason: "invalid_document_id", guidance: "Pass 'document_id' from cello_doc_list." };
    }
    if (!/^[0-9a-f]{64}$/.test(holder)) {
      return {
        ok: false,
        reason: "invalid_holder_pubkey",
        guidance: "holder_pubkey must be the 64-hex agent id of a current holder.",
      };
    }
    const doc = layer.store.getDocument(who.ownerAgentId, documentId);
    if (!doc) {
      return { ok: false, reason: "document_unknown", guidance: `No document ${documentId.slice(0, 16)}… for this agent.` };
    }
    const genesisRecord = layer.handshake.get(who.ownerAgentId, documentId);
    if (!genesisRecord) {
      return {
        ok: false,
        reason: "document_genesis_missing",
        guidance: "The document has a row but no stored genesis proposal to replay from.",
      };
    }
    const genesisArr = arrangementGenesisFromProposal(genesisRecord.envelope);
    const chain = layer.amendments.chain(who.ownerAgentId, documentId);
    const derived = deriveDocumentState(genesisArr, chain, documentGovernancePolicy, layer.verifySignature);
    if (!derived.ok) {
      return { ok: false, reason: "document_chain_invalid", guidance: derived.reason };
    }
    if (!derived.state.participants.has(holder) && !derived.state.invited.has(holder)) {
      // ALREADY REMOVED is the HEALING path, not a refusal (REMOVE-1 review F3): a holder who
      // was offline at removal time never learned, and no other verb can ever re-send the
      // removal amendment — a second cello_doc_remove is the invite-retry precedent. A subject
      // the chain never touched still refuses.
      if (layer.standingOf(who.ownerAgentId, documentId, holder) === "removed") {
        const removal = [...chain].reverse().find(
          (e) => e.body.kind === "remove_holder" && e.body.subject_agent_id === holder,
        );
        let resendTold: Record<string, boolean> = {};
        if (removal) {
          const bytes = new Uint8Array(encodeDocumentAmendment(removal));
          const remaining = [...derived.state.participants, ...derived.state.invited].filter(
            (m) => m !== who.ownerAgentId && m !== holder,
          );
          // The healing re-send is durable for the holders who REMAIN, for the same reason the
          // re-invite is: it is the verb an operator runs precisely because someone is out of step,
          // so it must not be the one that gives up quietest.
          resendTold = await fanOutAmendment({
            agentName: who.agentName,
            ownerAgentId: who.ownerAgentId,
            documentId,
            amendmentHashHex: Buffer.from(documentAmendmentHash(removal.body)).toString("hex"),
            amendmentBytes: bytes,
            holders: remaining,
            verb: "remove-resend",
          });
          if (holder !== who.ownerAgentId) {
            try {
              const sent = await deps.transportFor(who.agentName).sendBytes({
                peerAgentId: holder, documentId, bytes, correlationId: randomUUID(),
              });
              resendTold[holder] = sent.ok && sent.parked !== true;
            } catch {
              resendTold[holder] = false;
            }
          }
        }
        return {
          ok: true,
          documentId,
          removedAgentId: holder,
          resent: true,
          holdersNotified: resendTold,
        };
      }
      return {
        ok: false,
        reason: "document_not_holder",
        guidance: "That agent does not hold this document — there is nobody to remove.",
      };
    }

    const body: DocumentAmendmentBody = {
      document_id: documentId,
      kind: "remove_holder",
      subject_agent_id: holder,
      property_change: null,
      state_hash: null,
      authored_at_ms: deps.now(),
      // SYNC-P1 — the causal fields: authored on the fold's frontier.
      author_agent_id: who.ownerAgentId,
      author_seq:
        (layer.amendments.watermarks(who.ownerAgentId, documentId).get(who.ownerAgentId)?.seq ??
          0) + 1,
      parents: [...derived.state.frontier],
    };
    const amendHash = documentAmendmentHash(body);
    const multisigTbs = buildDocumentMultisigTbs({
      document_id: documentId,
      subject_kind: "document_amendment",
      subject_hash: amendHash,
      required_signers: [who.ownerAgentId],
    });
    const amendment: DocumentAmendmentEnvelope = {
      body,
      collection: {
        document_id: documentId,
        subject_kind: "document_amendment",
        subject_hash: amendHash,
        required_signers: [who.ownerAgentId],
        signatures: [
          { signer_agent_id: who.ownerAgentId, signature: await deps.sign(who.agentName, multisigTbs) },
        ],
      },
    };
    // VALIDATE-BEFORE-APPEND — the policy rules here: a non-admin removing someone else, or any
    // single admin trying to expel a fellow admin through the holder door, refuses with the
    // policy's own sentence. Voluntary self-leave passes for anyone.
    const withNew = deriveDocumentState(
      genesisArr, [...chain, amendment], documentGovernancePolicy, layer.verifySignature,
    );
    if (!withNew.ok) {
      return { ok: false, reason: "document_amendment_invalid", guidance: withNew.reason };
    }
    // A locally-authored entry must TAKE EFFECT — a fold-void entry is admissible history when a
    // peer sends it, but authoring one ourselves would be publishing an act we already know is
    // inert, and the void's reason is the refusal the operator needs.
    {
      const candidateHex = Buffer.from(amendHash).toString("hex");
      const inert =
        withNew.state.voids.find((v) => v.hash === candidateHex) ??
        withNew.state.excluded.find((e) => e.hash === candidateHex);
      if (inert) {
        return { ok: false, reason: "document_amendment_invalid", guidance: inert.reason };
      }
    }
    const amendmentBytes = new Uint8Array(encodeDocumentAmendment(amendment));
    layer.amendments.append(who.ownerAgentId, documentId, amendmentBytes, deps.now());
    // SYNC-P4 (R27): a removal can COMPLETE a standing agreement — everyone who remains has
    // agreed — and that now falls out of the DERIVATION; the author's daemon projects it here,
    // exactly as receiving daemons project on arrival.
    {
      const afterRemove = layer.deriveEnded(who.ownerAgentId, documentId);
      if (afterRemove?.ended) {
        layer.store.setDocumentStatus(
          who.ownerAgentId,
          documentId,
          afterRemove.ended === "killed" ? "killed" : "closed",
        );
      }
    }
    // The amendment travels to EVERY current holder INCLUDING the removed one — being told is
    // how their daemon surfaces the removal to their operator. Best-effort at P1, per holder,
    // reported never assumed.
    // DOD-MP-INVITE-FANOUT-1 — the REMAINING holders get the durable fan-out. A holder who misses
    // a removal keeps delivering to, and accepting edits from, someone the chain has removed —
    // silently and permanently, which is the same defect the invite had and is worse, because here
    // the stale holder keeps honouring a membership that has been revoked.
    const holdersTold = await fanOutAmendment({
      agentName: who.agentName,
      ownerAgentId: who.ownerAgentId,
      documentId,
      amendmentHashHex: Buffer.from(amendHash).toString("hex"),
      amendmentBytes,
      holders: [...withNew.state.participants, ...withNew.state.invited].filter(
        (m) => m !== who.ownerAgentId,
      ),
      verb: "remove",
    });
    // THE REMOVED HOLDER IS TOLD ONCE, and is deliberately NOT owed a durable retry: delivery to
    // them stopping is what removal MEANS, so a queue that kept redialling them would contradict
    // the act it is announcing. Forward-only cuts both ways — we tell them, we do not pursue them.
    if (holder !== who.ownerAgentId) {
      try {
        const sent = await deps.transportFor(who.agentName).sendBytes({
          peerAgentId: holder, documentId, bytes: amendmentBytes, correlationId: randomUUID(),
        });
        holdersTold[holder] = sent.ok && sent.parked !== true;
        if (!holdersTold[holder]) {
          logger.warn("document.amendment.holder_unnotified", {
            documentId, holderAgentId: holder, verb: "remove-subject",
            reason: sent.ok ? "relay_parked" : sent.reason,
            detail: sent.ok ? "the relay is holding it" : sent.detail,
          });
        }
      } catch (err: unknown) {
        holdersTold[holder] = false;
        logger.warn("document.amendment.holder_unnotified", {
          documentId, holderAgentId: holder, verb: "remove-subject",
          reason: "amendment_send_threw",
          detail: err instanceof Error ? err.message : String(err),
        });
      }
    }
    logger.info("document.holder_removed", {
      documentId, holder, voluntary: holder === who.ownerAgentId,
    });
    return {
      ok: true,
      documentId,
      removedAgentId: holder,
      voluntary: holder === who.ownerAgentId,
      holdersNotified: holdersTold,
      guidance:
        "Removal is forward-only: their existing copy and its history remain theirs — new edits " +
        "simply no longer flow either way.",
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
    // THE NEW-MODEL INVITATION (SYNC-P3): the document arrived through the exchange and this
    // agent derives as an INVITED seat — declining is authoring your own signed refuse_join
    // entry (R24), which reaches every holder over the same carrier as everything else and
    // settles the inviter's surface from the record itself.
    if (layer.store.getDocument(who.ownerAgentId, documentId)) {
      const genesisRecord = layer.handshake.get(who.ownerAgentId, documentId);
      if (genesisRecord) {
        const standing = deriveDocumentState(
          arrangementGenesisFromProposal(genesisRecord.envelope),
          layer.amendments.chain(who.ownerAgentId, documentId),
          documentGovernancePolicy,
          layer.verifySignature,
        );
        if (standing.ok && standing.state.invited.has(who.ownerAgentId)) {
          const refusal = await authorConsent(who, documentId, "refuse_join");
          if (!refusal.ok) {
            return {
              ok: false,
              reason: "document_refusal_unrecorded",
              guidance: `Your refusal entry could not be recorded (${refusal.reason}) — run ` +
                `cello_doc_refuse again once the named condition clears.`,
            };
          }
          return {
            ok: true,
            documentId,
            joined: false,
            refusalEntry: refusal.entryHash,
            refusalDelivered: refusal.holdersNotified,
          };
        }
      }
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
    // M14B / DOD-MP-JOIN-1 — the inviter's view of every offer they authored: who has answered,
    // who is still thinking, and the refusal prose when there is one. Without this the answer
    // arrived, flipped a row, and reached nobody; a refused-but-admitted holder additionally
    // needs removing (REMOVE-1) and nothing else prompts it.
    // THE DERIVED ARRANGEMENT, per document (enforcer review G0). Until now nothing surfaced who
    // holds a document or who governs it: an operator could not answer "who is in this?", and
    // "all holders derive the same arrangement" — the governance line's headline claim — was
    // unassertable from outside the process. DERIVED here, never stored: each daemon computes it
    // from its OWN chain, which is exactly the property worth comparing across machines.
    const unavailable = (reason: string): Record<string, unknown> => ({
      // THE KEYS ARE ALWAYS PRESENT, null on failure. Dropping them made `row.participants`
      // undefined, which a consumer coerces to [] and reads as "nobody holds this" — a
      // materially wrong answer to the question this surface exists to answer. `null` cannot
      // be mistaken for an empty membership; an absent key already was, in this unit's own
      // enforcer helper.
      participants: null,
      admins: null,
      properties: null,
      arrangementUnavailable: reason,
    });
    const arrangementFor = (
      documentId: string,
      genesisRecord: ReturnType<typeof layer.handshake.get>,
    ): Record<string, unknown> => {
      // The SAME name the invite path uses for the same fault, carrying the same sentence —
      // one condition should not have two names, and the one an operator reads should be the
      // one that says whose fault it is.
      if (!genesisRecord) {
        return unavailable(
          "document_genesis_missing: the document has a row but no stored genesis proposal to " +
            "replay from — this is a local-state fault, not the peer's",
        );
      }
      // CONTAINED. `chain()` decodes every stored amendment and `documentIdFromProposal` parses
      // the genesis — both THROW on bytes this build cannot read (a client downgrade past an
      // amendment kind is the reachable case). Uncontained, that throw escapes the row, escapes
      // the map, and the operator asking "what documents do I have?" gets NOTHING because one
      // chain would not decode.
      try {
        const derived = deriveDocumentState(
          arrangementGenesisFromProposal(genesisRecord.envelope),
          layer.amendments.chain(who.ownerAgentId, documentId),
          documentGovernancePolicy,
          layer.verifySignature,
        );
        if (!derived.ok) return unavailable(derived.reason);
        return {
          participants: [...derived.state.participants].sort(),
          invited: [...derived.state.invited].sort(),
          admins: [...derived.state.admins].sort(),
          properties: derived.state.properties,
          // WAS THE ADMIN SET DECLARED, OR DEFAULTED? A genesis from before the admin slot
          // existed carries none, and the replay hands both parties admin power. Rendering that
          // identically to a declared set would have this surface state as agreed fact something
          // the code decided — so it says which it is.
          adminSetDefaulted: genesisRecord.envelope.properties.admin_set === undefined,
        };
      } catch (err: unknown) {
        return unavailable(
          `document_chain_undecodable: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    };

    // SYNC-P4 (D5 deleted): the invitation ledger IS the entry set. An open invitation is an
    // invited seat in the derivation; a refusal is the subject's own refuse_join entry in the
    // chain. No stored offer rows — asked twice, the record answers twice, identically.
    const outgoingJoins = layer.store
      .listDocuments(who.ownerAgentId)
      .flatMap((d) => {
        const genesisRecord = layer.handshake.get(who.ownerAgentId, d.documentId);
        if (!genesisRecord) return [];
        let chain;
        try {
          chain = layer.amendments.chain(who.ownerAgentId, d.documentId);
        } catch {
          return [];
        }
        const derived = deriveDocumentState(
          arrangementGenesisFromProposal(genesisRecord.envelope),
          chain,
          documentGovernancePolicy,
          layer.verifySignature,
        );
        if (!derived.ok) return [];
        const open = [...derived.state.invited]
          .filter((seat) => seat !== who.ownerAgentId)
          .map((seat) => ({ documentId: d.documentId, inviteeAgentId: seat, state: "pending" as const }));
        const refusedSeats = chain
          .filter((e) => e.body.kind === "refuse_join")
          .map((e) => e.body.subject_agent_id)
          .filter((seat): seat is string => seat !== null && seat !== who.ownerAgentId)
          .filter(
            (seat) =>
              !derived.state.participants.has(seat) && !derived.state.invited.has(seat),
          );
        const refused = [...new Set(refusedSeats)].map((seat) => ({
          documentId: d.documentId,
          inviteeAgentId: seat,
          state: "refused" as const,
        }));
        return [...open, ...refused];
      });
    return {
      ok: true,
      ...(outgoingJoins.length > 0 ? { joinOffers: outgoingJoins } : {}),
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
        const arrangement = arrangementFor(d.documentId, proposal);
        // DOD-MP-REMOVE-FEEDBACK-1 — the SENTENCE for a fact the row already carried.
        //
        // The row has shipped `removed: true` since REMOVE-1. What was missing is that a bare flag
        // is not feedback: it does not say when, it does not say the copy is still yours, and it
        // does not say what actually stopped. So this completes the existing signal rather than
        // adding a second name for it computed by a second walk of the same chain.
        //
        // NAMED `yourStanding`, NOT `yourAccess`: your access to the copy did not change — reading
        // it still works and the file is still on disk, which the sentence itself says. A surface
        // that renders a badge from the key alone would show "access: removed", which is the
        // confiscation reading FORWARD-ONLY-REMOVAL exists to forbid.
        //
        // ALWAYS PRESENT, exactly as `participants` is: an absent key is read as "fine", so on a
        // chain this build cannot decode — where `removedFromArrangement` honestly cannot tell —
        // it says `unknown` rather than going quiet and rendering a removed holder as a holder.
        const standing: "removed" | "holder" | "unknown" =
          arrangement["arrangementUnavailable"] !== undefined
            ? "unknown"
            : (d as { removed?: boolean }).removed === true
              ? "removed"
              : "holder";
        const removedAtEpoch = (d as { removedAtEpoch?: number }).removedAtEpoch;
        return {
          ...d,
          yourStanding: standing,
          ...(standing === "removed"
            ? {
                standingGuidance:
                  `You are no longer a holder of this document` +
                  (removedAtEpoch === undefined ? `. ` : `, as of epoch ${removedAtEpoch}. `) +
                  `Your copy and its full history remain yours, and you can still read it here or ` +
                  `open the file. What changed is only the flow of edits: yours no longer publish ` +
                  `to the other holders, and theirs no longer reach you.`,
              }
            : {}),
          ...(standing === "unknown"
            ? {
                standingGuidance:
                  `This daemon cannot read this document's amendment chain, so it cannot tell ` +
                  `whether you are still a holder. Nothing here should be taken as confirmation ` +
                  `that you are.`,
              }
            : {}),
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
          // WHO HOLDS IT AND WHO GOVERNS IT — derived from THIS daemon's own chain (G0).
          // `proposal` is passed rather than re-fetched: it is the same SQL read and the same
          // CBOR decode of the same bytes, already in hand.
          ...arrangement,
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
    // TYPE-AWARE. A JSON document's content is in the MAP root; reading the text root would answer
    // `content: ""` for a full document — the exact "an empty document handed to an agent gets
    // written back over the peer's real content" hazard this path warns about above.
    const content = projectDocumentText(doc, document.documentType);
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

  /**
   * DOD-DOC-WATCH-1 — declare which paths of a document should wake this agent.
   *
   * RECEIVER-LOCAL and nothing goes on the wire. A peer cannot make this agent wake by claiming a
   * field matters, nor suppress a wake by omitting one; the receiver decides from what actually
   * changed in its own copy.
   *
   * An EMPTY list clears the watch, and clearing is the only way to stop being nudged — there is no
   * separate unwatch verb to fall out of step with this one.
   */
  handlers.set("cello_doc_watch", async (params, connectionId) => {
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
    const raw = Array.isArray(params?.paths) ? (params.paths as unknown[]).filter((p): p is string => typeof p === "string") : null;
    if (raw === null) {
      // LISTED, not silently treated as "clear". A caller that omits `paths` is asking what is set,
      // and answering "cleared" would turn a read into a destructive act.
      return { ok: true, documentId, paths: layer.notifications.watches(who.ownerAgentId, documentId) };
    }
    let paths: string[];
    try {
      paths = normalizeWatchPaths(raw);
    } catch (err: unknown) {
      return {
        ok: false,
        reason: "watch_path_invalid",
        guidance: err instanceof Error ? err.message : String(err),
      };
    }
    layer.notifications.setWatches(who.ownerAgentId, documentId, paths);
    logger.info("document.watch.set", { documentId, paths: paths.length });
    return {
      ok: true,
      documentId,
      paths,
      ...(paths.length === 0
        ? { guidance: "Watch cleared — this document will no longer wake you." }
        : {
            guidance:
              `You will be woken once when any of these move, and not again until you read the ` +
              `document. Nothing was sent to your counterparty: this is local to you.`,
          }),
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

    const after = projectDocumentText(layer.live.get(who.ownerAgentId, documentId), document.documentType);
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
    const before = projectDocumentText(doc, document.documentType);
    const isMapRoot = rootForDocumentType(document.documentType) === "map";

    // PARSED BEFORE ANYTHING IS TOUCHED. A structured document must not partially apply a write
    // that does not parse — the operator would be left with half their edit in a signed envelope
    // and no way to tell which half.
    const parsedWrite = isMapRoot ? parseJsonDocument(content) : null;
    if (parsedWrite !== null && !parsedWrite.ok) {
      return {
        ok: false,
        reason: "document_content_unparseable",
        guidance:
          `This is a JSON document and what you sent is not valid JSON (${parsedWrite.detail}). ` +
          `Nothing was changed. Send the COMPLETE document, not a fragment — cello_doc_read gives ` +
          `you the current text to edit.`,
      };
    }
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
        const stuckFault = screenText(projectDocumentText(doc, document.documentType));
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
    // DOD-DOC-STALE-WRITE-1 — WOULD THIS WRITE DELETE SOMETHING THE AUTHOR NEVER SAW?
    //
    // `content` is the COMPLETE text, so anything absent from it is a deletion. That contract is
    // right — a patch API means stale offsets, which in a CRDT is permanent corruption both sides
    // converge on — but it cannot distinguish "I read their paragraph and do not want it" from
    // "their paragraph arrived while I was typing". Both are the same bytes.
    //
    // Measured live 2026-08-09: a peer's paragraph admitted at 12:35:41.807 was destroyed by a write
    // published at 12:35:42.033. The lost text was the smaller harm — the signed record cannot tell
    // the two apart either, so the accident is permanently attributed as a deliberate rejection of
    // the counterparty's work.
    //
    // The read mark holds the exact text last read, durably, which is enough to tell them apart.
    // Refusal is conditioned on REMOVAL, never on staleness alone: a write that only ADDS is never
    // refused, or proposing a document and writing to it before reading would refuse for nothing.
    // GATED ON WHETHER THE DOCUMENT MOVED UNDER THEM. If no peer update has been admitted since
    // this agent last looked, its view IS current by construction and every removal in its text is
    // something it put there or read — nothing to protect, and refusing would be pure friction.
    //
    // This is what makes the guard quiet. The first version asked only "was this line in your last
    // read", which refused every EDIT of an existing line by an author who had not called read —
    // changing a line removes the old line's text. Two existing tests caught it.
    const unreadFromPeer = layer.notifications.unreadFromPeer(who.ownerAgentId, documentId);
    const verdict =
      unreadFromPeer > 0
        ? classifyRemovals(before, content, layer.notifications.knownTexts(who.ownerAgentId, documentId))
        : { removed: [], deliberate: [], unseen: [], refuse: false };
    if (verdict.refuse) {
      // The diff travels WITH the refusal. This is the moment the author can still act: they are
      // about to destroy it, rather than the peer discovering it gone hours later — and unlike the
      // peer, the author can tell whether they meant it.
      logger.info("document.write.refused.unseen_removal", {
        documentId,
        unseen: verdict.unseen.length,
        unreadFromPeer,
      });
      return {
        ok: false,
        reason: "document_write_would_delete_unseen",
        currentContent: before,
        unseenRemovals: verdict.unseen,
        guidance:
          `This write would delete ${verdict.unseen.length} line(s) you have not read — your ` +
          `counterparty changed the document after you last looked at it. Nothing was changed. ` +
          `The current text is in 'currentContent' and what you would have removed is in ` +
          `'unseenRemovals'. Re-apply your edit on top of the current text and write again. If you ` +
          `DO want those lines gone, read the document first — a removal you have read is recorded ` +
          `as a deliberate act rather than refused.`,
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
    // REFUSE A TERMINAL DOCUMENT BEFORE TOUCHING THE LOCAL COPY.
    //
    // `peerRefused` was checked above; the terminal statuses were not. A write into a closed, killed
    // or stalled document applied the hunks, failed at `canPublish`, and returned
    // `{ok: true, changed: true, published: false}` while adding the document to the stuck-edit set
    // — where no flush can ever succeed, because the document is terminal. The operator's next
    // `cello_doc_read` then showed text that is in no envelope log and no peer's copy, and that
    // vanishes on the next daemon restart when the live document is rebuilt from the log.
    //
    // Scoped to the TERMINAL statuses on purpose. `agent_platform_paused` is the recoverable case
    // the mutate-then-remember path was built for and keeps its behaviour: the edit is real, it is
    // held, and clearing the pause flushes it.
    const publishable = layer.lifecycle.canPublish(who.ownerAgentId, documentId);
    if (!publishable.ok && publishable.reason !== "agent_platform_paused") {
      return {
        ok: false,
        reason: publishable.reason,
        guidance:
          // PUNCTUATED. `detail` comes from several producers and not all of them end in a stop,
          // so the two sentences ran together — "…no longer publish to the other holders Nothing
          // was changed locally…" — on the one line this DoD calls actionable.
          `${withStop(publishable.detail ?? "This document can no longer accept writes.")} Nothing was ` +
          `changed locally — an edit applied here could never be published or recovered, and would ` +
          `disappear the next time the daemon restarted.`,
      };
    }

    // ONE TRANSACTION either way, so the whole edit is a single Yjs update rather than several — a
    // peer applying them separately would pass through states no operator ever wrote.
    if (parsedWrite !== null && parsedWrite.ok) {
      // PER KEY AND AT EVERY DEPTH, which is the whole reason a JSON document uses the map root.
      // Two agents editing different fields produce disjoint operations and both survive — including
      // two fields inside the SAME nested object, which was the defect: a nested object stored as a
      // plain value is one item, so two writes to it are two writes to one item and one is lost.
      //
      // Untouched keys are not rewritten at any depth. Writing a key back with an identical value is
      // still a CRDT operation and would clobber a peer's concurrent edit to a field this agent
      // never looked at.
      applyJsonToMap(doc.getMap("data"), parsedWrite.value, doc);
    } else {
      const hunks = lineHunks(before, content);
      doc.transact(() => {
        // Back to front, so earlier offsets stay valid as later ones are rewritten.
        for (const hunk of [...hunks].reverse()) {
          if (hunk.to > hunk.from) text.delete(hunk.from, hunk.to - hunk.from);
          if (hunk.insert.length > 0) text.insert(hunk.from, hunk.insert);
        }
      });
    }

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
    // A removal the author HAD read is the "second refusal" — a deliberate editorial act. Recorded
    // as one, so it is distinguishable later from the accident this guard now prevents.
    if (verdict.deliberate.length > 0) {
      logger.info("document.write.removal.deliberate", {
        documentId,
        lines: verdict.deliberate.length,
      });
    }
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
    // SYNC-P4 (R26/R27): closing is authoring YOUR OWN close entry — the same self-signed act
    // consent is, traveling the same carrier, settling by DERIVATION when every current
    // participant has one. No control frame, no fan-out bookkeeping, no fire-once anything: a
    // close that has not reached someone yet is just a difference the next exchange closes.
    const closed = await authorConsent(who, documentId, "close");
    if (!closed.ok) {
      return {
        ok: false,
        reason: "document_close_unrecorded",
        guidance: `Your close entry could not be recorded (${closed.reason}).`,
      };
    }
    const derived = layer.governanceFrontierFor(who.ownerAgentId, documentId) !== null
      ? layer.deriveEnded(who.ownerAgentId, documentId)
      : null;
    return {
      ok: true,
      documentId,
      closeEntry: closed.entryHash,
      closeDelivered: closed.holdersNotified,
      // DERIVED, at this instant: "closed" only when everyone seated has agreed — one party
      // alone is never the whole agreement, and the surface says who is still being waited on.
      ended: derived?.ended ?? null,
      waitingOn: derived?.waitingOn ?? [],
    };
  });

  handlers.set("cello_doc_kill", async (params, connectionId) => {
    const who = resolve(params, connectionId);
    if (isRefusal(who)) return who;
    const documentId = typeof params?.document_id === "string" ? params.document_id : "";
    if (documentId.length === 0) {
      return { ok: false, reason: "invalid_document_id", guidance: "Pass 'document_id' from cello_doc_list." };
    }
    // SYNC-P4 (R28): a kill is one admin's own signed entry — immediate and one-sided the
    // moment it applies anywhere, independent of anyone being reachable (a decision to stop
    // that depends on the other party being online is not a decision to stop). It travels the
    // same carrier as everything else; a holder who has not received it yet is a difference
    // the next exchange closes.
    const killed = await authorConsent(who, documentId, "kill");
    if (!killed.ok) {
      return {
        ok: false,
        reason: "document_kill_unrecorded",
        guidance: `Your kill entry could not be recorded (${killed.reason}).`,
      };
    }
    return {
      ok: true,
      documentId,
      killEntry: killed.entryHash,
      killDelivered: killed.holdersNotified,
      ended: "killed",
    };
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
        layer.notifications.markWritten(who.ownerAgentId, documentId, projectDocumentText(doc, document.documentType));
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
    const publishScreenFault = screenText(projectDocumentText(doc, document.documentType));
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
    layer.notifications.markWritten(who.ownerAgentId, documentId, projectDocumentText(doc, document.documentType));
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
