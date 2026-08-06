/**
 * DOD-DOC-INBOUND-2 / DOD-DOC-DELIVERY-2 — the composition of the document layer.
 *
 * Everything M14 built is a unit with injected seams. This is where they become one thing, and it
 * is a module rather than a block inside `daemon.ts` for one reason: the assembly makes decisions.
 * Which verifier, which live-doc policy, and — the one that matters — whether the layer is present
 * at all.
 *
 * ── ALL OR NOTHING ────────────────────────────────────────────────────────────────────────────
 *
 * The layer is built completely or not built. There is no partially-wired mode, because every
 * half-wiring is a distinct silent failure: an inbound path with no ack producer leaves the peer
 * retrying until their document stalls; a delivery worker with no inbound counterpart publishes
 * envelopes nobody can answer. `DOD-DOC-DELIVERY-2` records that ordering constraint on its own
 * line, and this is where it is enforced instead of remembered.
 *
 * ── THE VERIFIER IS REQUIRED, AND RESOLVES THROUGH THE CALLER ─────────────────────────────────
 *
 * Signature verification needs an agent id → public key mapping, which lives with the daemon's
 * contact and session state rather than here. It is passed in, and there is no default: a default
 * would be a default answer to "is this authentic", and both inbound paths refuse rather than
 * admit when it says no.
 */

import { verify } from "@cello-protocol/crypto";
import { DocumentStore } from "./document-store.js";
import { DocumentEngine } from "./document-engine.js";
import { DocumentGate } from "./document-gate.js";
import { DocumentRejections } from "./document-rejection.js";
import { DocumentInbound } from "./document-inbound.js";
import { DocumentAckInbound } from "./document-ack-inbound.js";
import { DocumentFrameRouter } from "./document-frame-router.js";
import { LiveDocuments } from "./document-live-docs.js";
import { DocumentLifecycle } from "./document-lifecycle.js";
import { DocumentNotifications } from "./document-notify.js";
import { DocumentHandshake } from "./document-handshake.js";
import {
  decodeDocumentRejection,
  buildDocumentRejectionTbs,
  documentRejectionHash,
  decodeDocumentProposalAck,
  buildDocumentProposalAckTbs,
  decodeDocumentControl,
  buildDocumentControlTbs,
  decodeDocumentUpdateEnvelope,
  encodeDocumentAck,
  buildDocumentAckTbs,
  type DocumentAck,
} from "@cello-protocol/protocol-types";
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";

export interface DocumentLayerDeps {
  db: DaemonDatabase;
  logger: Logger;
  /**
   * The public key an agent id signs with, or null when this daemon cannot resolve one.
   *
   * REQUIRED. Returning null means "cannot verify", which both inbound paths treat as a refusal —
   * the same answer as a bad signature, because admitting an envelope we cannot authenticate is
   * the outcome the whole verify step exists to prevent.
   *
   * Injected rather than computed here even though M14-D5 makes a remote agent id BE its pubkey
   * hex, because the daemon may want to refuse a peer it has no contact for, or resolve through a
   * different binding later. `agentPublicKeyFromId` below is the default implementation.
   */
  publicKeyFor(agentId: string): Uint8Array | null;
  /**
   * The stable owner key for a daemon agent NAME — our own K_local pubkey hex (M14-D5).
   *
   * The session content path knows agents by name; every document row is scoped by owner key. Both
   * halves of the layer must agree, and the delivery sweep already uses the pubkey hex. See
   * `DocumentFrameRouterDeps.ownerKeyFor` for what a disagreement hides.
   */
  ownerKeyFor(agentName: string): string | null;
  /** Tell the peer about a unilateral end. Injected — the transport is not this layer's. */
  notifyPeer(
    documentId: string,
    verb: "kill" | "close",
  ): Promise<{ ok: true } | { ok: false; reason: string }>;
  /** Undo one envelope's operations on the live document, for withdraw. */
  rollback(
    ownerAgentId: string,
    documentId: string,
    envelopeHash: string,
  ): { ok: true } | { ok: false; reason: string };
  /**
   * Sign as a given agent. Takes the agent id so a rejection cannot be signed with the wrong key —
   * the first version took no arguments and the composition root reached for whichever key
   * provider was first in a map, which is fabricated crypto wearing a real signature.
   *
   * ASYNC because signing goes through a key provider, and that async is what forced the router to
   * split synchronous CLASSIFICATION from asynchronous HANDLING.
   */
  sign(ownerAgentId: string, tbs: Uint8Array): Promise<Uint8Array>;
  /**
   * Put an already-encoded frame on the wire to a peer — the ack, today.
   *
   * Injected because the transport is not this layer's, and REQUIRED for the same reason the layer
   * is all-or-nothing: an inbound path that cannot answer leaves every sender retrying until their
   * document stalls.
   */
  sendFrame(
    ownerAgentId: string,
    peerAgentId: string,
    bytes: Uint8Array,
  ): Promise<{ ok: true } | { ok: false; reason: string }>;
}

export interface DocumentLayer {
  store: DocumentStore;
  handshake: DocumentHandshake;
  engine: DocumentEngine;
  live: LiveDocuments;
  lifecycle: DocumentLifecycle;
  notifications: DocumentNotifications;
  rejections: DocumentRejections;
  router: DocumentFrameRouter;
  /**
   * The hook `SessionNodeManager.setOnDocumentFrame` takes. Handed out ready-shaped so the
   * composition root does not re-derive the adapter — and so the `consumed` contract has exactly
   * one definition.
   */
  onDocumentFrame(
    agentName: string,
    sessionId: string,
    content: Uint8Array,
    senderPubkey: string,
    correlationId?: string,
  ): { consumed: boolean; kind?: string; ok?: boolean; reason?: string };
}

/**
 * The default `publicKeyFor`: a remote agent's id IS its K_local public key, hex-encoded (M14-D5).
 *
 * `agent_id` in this daemon is a LOCAL primary key on the `agents` table — it names rows in our own
 * database and cannot identify a remote peer. The pubkey is the only self-verifying identifier
 * available: the signature checks against it directly, with no lookup that could be stale, missing
 * or poisoned sitting on the critical path of every authentication.
 *
 * Malformed input returns null rather than throwing, and null is a refusal. An id that is not a
 * 32-byte hex key is not "a peer we have no key for" — it is a frame that does not follow the
 * protocol — but both must refuse, and refusing loudly at the verify step is where it belongs.
 */
export function agentPublicKeyFromId(agentId: string): Uint8Array | null {
  if (!/^[0-9a-f]{64}$/.test(agentId)) return null;
  return Uint8Array.from(Buffer.from(agentId, "hex"));
}

export function createDocumentLayer(deps: DocumentLayerDeps): DocumentLayer {
  const { db, logger } = deps;

  const store = new DocumentStore(db, logger);
  const engine = new DocumentEngine(logger);
  const gate = new DocumentGate(engine, {}, logger);
  const rejections = new DocumentRejections(store, logger);
  // Epoch zero comes from the stored PROPOSAL, not from the envelope log — see `LiveDocuments.get`.
  // Declared before `handshake` exists, so it is resolved lazily; a rebuild only ever happens long
  // after construction.
  const live = new LiveDocuments(store, engine, logger, (ownerAgentId, documentId) => {
    const record = handshake.get(ownerAgentId, documentId);
    return record?.envelope.starting_content ?? null;
  });
  const lifecycle = new DocumentLifecycle(store, logger, { notifyPeer: deps.notifyPeer }, deps.rollback);
  const notifications = new DocumentNotifications(store, logger);

  /**
   * One verifier for both paths. Ed25519 (RFC 8032) over the TBS the caller built.
   *
   * An UNKNOWN agent verifies as FALSE, and is logged distinctly. "We have no key for this peer"
   * and "the signature is wrong" both have to refuse — admitting what we cannot authenticate is
   * the outcome the verify step exists to prevent — but they are different things to tell an
   * operator, and only one of them is a peer misbehaving.
   *
   * No try/catch: `verify` already fails closed on a malformed key or signature (its own body is a
   * try returning false), so a catch here would be a branch nothing can reach.
   */
  const verifySignature = (agentId: string, tbs: Uint8Array, signature: Uint8Array): boolean => {
    const pubkey = deps.publicKeyFor(agentId);
    if (pubkey === null) {
      logger.warn("document.verify.no_key", { agentId });
      return false;
    }
    return verify(pubkey, tbs, signature);
  };

  const inbound = new DocumentInbound({
    store,
    engine,
    gate,
    rejections,
    logger,
    verifySignature,
    liveDocFor: (ownerAgentId, documentId) => live.get(ownerAgentId, documentId),
    sign: deps.sign,
  });

  const ackInbound = new DocumentAckInbound({ store, rejections, logger, verifySignature });

  // The handshake verifies a proposal against its NAMED proposer — the same resolver, so a forged
  // proposal is refused before it can occupy a document_id (ON CONFLICT DO NOTHING makes the first
  // arrival's bytes permanent for that id).
  const handshake = new DocumentHandshake(db, logger, verifySignature);

  const router = new DocumentFrameRouter({
    inbound,
    ackInbound,
    logger,
    ownerKeyFor: deps.ownerKeyFor,
    recordProposal: (ownerAgentId, wire, nowMs) => {
      // THROWS on a forged or misaddressed proposal, which the router contains and reports. That is
      // right: those are refusals, and nothing should be recorded for them.
      handshake.recordProposal(ownerAgentId, wire, nowMs);
    },
    // `_nowMs` unused: the received-rejection row takes its clock where it is written, and the
    // rejection's own SIGNED timestamp is inside the envelope. A second clock read here would put a
    // third time on one event.
    sendFrameToPeer: async (ownerAgentId, inResponseTo, bytes) => {
      // Addressed to whoever AUTHORED the envelope being answered, taken from the envelope itself
      // rather than from the document row: the row's peer and the envelope's sender are the same
      // party in a two-party document, and reading it from the signed bytes means a refusal can
      // only ever go back to the agent that actually sent the thing refused.
      const env = decodeDocumentUpdateEnvelope(inResponseTo);
      const sent = await deps.sendFrame(ownerAgentId, env.sender_agent_id, bytes);
      if (!sent.ok) {
        logger.warn("document.rejection.unsent", {
          documentId: env.document_id,
          peerAgentId: env.sender_agent_id,
          reason: sent.reason,
        });
      }
    },
    sendAck: async (ownerAgentId, wire, outcome) => {
      const env = decodeDocumentUpdateEnvelope(wire);
      const ack: DocumentAck = {
        type: "document_ack",
        // The wire version this build speaks. Inlined rather than imported because protocol-types
        // exports the domain and the codec but not the constant; the decoder pins it by value.
        ack_version: 1,
        document_id: env.document_id,
        envelope_hash: outcome.envelopeHash,
        acker_agent_id: ownerAgentId,
        admitted: outcome.admitted,
        ...(outcome.admitted ? {} : { rejection_reason: outcome.rejectionReason ?? "refused" }),
        acked_at_ms: Date.now(),
        signature: new Uint8Array(0),
      };
      ack.signature = await deps.sign(ownerAgentId, buildDocumentAckTbs(ack));
      // BEST-EFFORT, and it must be: an ack that could not be sent is not a reason to refuse
      // content we have already admitted. The sender redelivers on its own timer, and the
      // redelivery is acked too — which is the case this whole path exists to terminate.
      const sent = await deps.sendFrame(ownerAgentId, env.sender_agent_id, encodeDocumentAck(ack));
      if (!sent.ok) {
        logger.warn("document.ack.unsent", {
          documentId: env.document_id,
          envelopeHash: outcome.envelopeHash,
          reason: sent.reason,
          correlationId: outcome.correlationId,
        });
      }
    },
    recordControl: (ownerAgentId, wire, nowMs) => {
      const control = decodeDocumentControl(wire);
      // VERIFIED FIRST. A kill frame ends a collaboration; unsigned, anyone reaching the channel
      // could end any document between any two parties and each operator would believe the other
      // walked away.
      if (!verifySignature(control.sender_agent_id, buildDocumentControlTbs(control), control.signature)) {
        throw new Error(
          `document_control_signature_invalid: the ${control.verb} claims to come from ` +
            `${control.sender_agent_id} but its signature does not verify against that agent`,
        );
      }
      const verdict =
        control.verb === "kill"
          ? lifecycle.recordPeerKill(ownerAgentId, control.document_id, control.sender_agent_id, nowMs)
          : lifecycle.recordPeerClose(ownerAgentId, control.document_id, control.sender_agent_id, nowMs);
      if (!verdict.ok) {
        // Refusals here are real: an unknown document, or a sender who is not this document's peer.
        // Thrown so the router reports them rather than recording an end nobody was entitled to.
        throw new Error(`${verdict.reason}: ${verdict.detail}`);
      }
    },
    recordProposalAck: (ownerAgentId, wire, _nowMs) => {
      const ack = decodeDocumentProposalAck(wire);
      // VERIFIED against the agent it names, before anything is written. A refusal ack makes the
      // proposer stop waiting and, at the surface, reads as "they said no" — so unsigned, anyone on
      // the channel could make a proposal appear refused by a party who never saw it, and the two
      // operators would each believe the other walked away.
      if (!verifySignature(ack.acker_agent_id, buildDocumentProposalAckTbs(ack), ack.signature)) {
        throw new Error(
          `document_proposal_ack_signature_invalid: the answer claims to come from ` +
            `${ack.acker_agent_id} but its signature does not verify against that agent`,
        );
      }
      // The acker is passed through and CHECKED against the proposal's peer. Verifying the
      // signature proves the frame is authentic; it says nothing about whether its author was
      // entitled to answer this proposal.
      const stored = handshake.recordPeerDecision(ownerAgentId, ack.document_id, ack.acker_agent_id, {
        accepted: ack.accepted,
        ...(ack.refusal_reason !== undefined ? { reason: ack.refusal_reason } : {}),
        decidedAtMs: ack.decided_at_ms,
      });
      if (!stored.ok) {
        // SETTLE ONCE — a contradicting second answer is an error, never an update. A peer that
        // accepted must not be able to later claim it refused, or the proposer tears down a
        // document the peer is still editing.
        throw new Error(`${stored.reason}: ${stored.detail}`);
      }
    },
    recordRejection: (ownerAgentId, wire, _nowMs) => {
      const env = decodeDocumentRejection(wire);
      if (!verifySignature(env.rejecting_agent_id, buildDocumentRejectionTbs(env), env.signature)) {
        // A rejection stops the sender retrying and makes them supersede. Unsigned, anyone on the
        // channel could freeze a document by asserting a refusal nobody made.
        throw new Error(
          `document_rejection_signature_invalid: the rejection claims to come from ` +
            `${env.rejecting_agent_id} but its signature does not verify against that agent`,
        );
      }
      rejections.recordIncomingRejection(ownerAgentId, env.document_id, {
        rejectionEnvelopeHash: documentRejectionHash(env),
        rejectedEnvelopeHash: env.rejected_envelope_hash,
        reason: env.reason,
        detail: env.detail,
        fromAgentId: env.rejecting_agent_id,
      });
    },
  });

  return {
    store,
    handshake,
    engine,
    live,
    lifecycle,
    notifications,
    rejections,
    router,
    onDocumentFrame: (agentName, _sessionId, content, _senderPubkey, correlationId) =>
      // `agentName` names the owning agent for the session; the router maps it to the owner KEY
      // that scopes the store. The session id and the sender's transport pubkey are unused: a
      // document is bound to its PEER by the handshake, not to whichever session carried the
      // frame, and the envelope's own signed `sender_agent_id` is what the inbound path checks
      // against that binding. Trusting the transport identity instead would let a frame arriving
      // on any session act on any document that session's peer happens to share.
      router.routeSync(agentName, content, Date.now(), correlationId ?? "frame"),
  };
}
