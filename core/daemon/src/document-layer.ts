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
import { screeningRule, SCREEN_RULE_ID } from "./document-screen.js";
import { DocumentRejections } from "./document-rejection.js";
import { DocumentInbound } from "./document-inbound.js";
import { DocumentAckInbound } from "./document-ack-inbound.js";
import { DocumentFrameRouter } from "./document-frame-router.js";
import { LiveDocuments } from "./document-live-docs.js";
import { DocumentLifecycle } from "./document-lifecycle.js";
import { DocumentNotifications } from "./document-notify.js";
import { DocumentHandshake } from "./document-handshake.js";
import { DocumentWritePath } from "./document-write-path.js";
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
import { LEAF_KIND_REJECT } from "./session-relay-client.js";
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
  /**
   * Where documents are materialized as files. Absent disables the file surface entirely — the
   * content verbs still work, and nothing silently half-writes.
   */
  workspaceRoot?: string;
  sendFrame(
    ownerAgentId: string,
    peerAgentId: string,
    bytes: Uint8Array,
    /**
     * The witnessed leaf DOMAIN. Omitted means the document kind (0x04), which is right for an ack;
     * a REFUSAL passes 0x05. The directory discriminates on it when it builds the seal certificate,
     * so a refusal recorded as a message is a refusal the certificate reports as something said.
     */
    leafKind?: number,
  ): Promise<{ ok: true } | { ok: false; reason: string }>;
}

export interface DocumentLayer {
  store: DocumentStore;
  /** The file projection, or null when no workspace root was configured. */
  writePath: DocumentWritePath | null;
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
  /**
   * Resolve when this envelope is SETTLED by the peer, or false when `timeoutMs` elapses first.
   *
   * The delivery transport holds a session it opened open until this resolves. See the comment on
   * `DocumentTransportDeps.awaitAck`: the seal tears the session down and the teardown drops
   * content still held for ordering, so sealing before the answer arrives can delete an ack that
   * was correctly sent and correctly received.
   *
   * Resolves IMMEDIATELY if the envelope is already settled — the ack can win the race with the
   * caller, and a waiter that only listened for future events would then wait out the full grace
   * period on every fast peer.
   */
  awaitAck(
    ownerAgentId: string,
    envelopeHash: string,
    timeoutMs: number,
  ): Promise<{ admitted: boolean } | null>;
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
  // DOD-DOC-SCREEN-1 — REGISTERED, not merely written.
  //
  // The gate has carried a comment saying this rule plugs in here since the gate was built, and the
  // rule not existing was the whole gap: document content reached the CRDT with no content gate at
  // all, because the message sanitizer is deliberately kept off this path (it REWRITES, and
  // rewriting a replica is permanent divergence).
  //
  // Registered at construction rather than by a caller, for the reason this milestone learned four
  // separate times — a unit with no caller reads exactly like a working one. If this line is
  // deleted the screening tests still pass, so `document-surface-e2e` asserts a refusal end to end.
  gate.addRule(SCREEN_RULE_ID, screeningRule);
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
  // THE FILE SURFACE. Built, tested and instantiated NOWHERE until now — the same defect the tool
  // surface had: a complete unit with no production caller reads exactly like a working feature.
  // Without it §4.1's whole premise is missing, because a human collaborating on a document edits a
  // file in their editor, and an agent with file tools reaches for them before any MCP verb.
  const writePath = deps.workspaceRoot ? new DocumentWritePath(engine, deps.workspaceRoot, logger) : null;

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

  // WAITERS for `awaitAck`, keyed by owner + envelope. A Set per key because two callers may wait
  // on the same envelope (a redelivery racing the original), and dropping one of them would leave a
  // session held open for the full grace period with the answer already in hand.
  const ackWaiters = new Map<string, Set<(admitted: boolean) => void>>();
  const waiterKey = (ownerAgentId: string, envelopeHash: string) => `${ownerAgentId}\u0000${envelopeHash}`;

  const ackInbound = new DocumentAckInbound({
    store,
    rejections,
    logger,
    verifySignature,
    onSettled: (ownerAgentId, envelopeHash, admitted) => {
      const key = waiterKey(ownerAgentId, envelopeHash);
      const waiting = ackWaiters.get(key);
      if (!waiting) return;
      ackWaiters.delete(key);
      // The OUTCOME, not just the fact of one. A caller told only "answered" has to report the
      // envelope as still in flight, which is how `document.delivery.sweep { delivered: N }` came
      // to be permanently 0 — a sweep that delivered nothing looked identical to a healthy one.
      for (const wake of waiting) wake(admitted);
    },
  });

  const awaitAck = async (ownerAgentId: string, envelopeHash: string, timeoutMs: number) => {
    // ALREADY SETTLED WINS. The ack round trip was measured at 4ms on a local pair; the caller
    // reaches this line after a network send. Checking the store first is not an optimisation —
    // without it the common case waits out the entire grace period for an answer already recorded.
    const already = store.envelopeSettlement(ownerAgentId, envelopeHash);
    if (already) return already;

    const key = waiterKey(ownerAgentId, envelopeHash);
    return new Promise<{ admitted: boolean } | null>((resolve) => {
      let timer: ReturnType<typeof setTimeout>;
      const wake = (admitted: boolean) => {
        clearTimeout(timer);
        resolve({ admitted });
      };
      const set = ackWaiters.get(key) ?? new Set<(admitted: boolean) => void>();
      set.add(wake);
      ackWaiters.set(key, set);
      timer = setTimeout(() => {
        // DEREGISTER on the way out. A waiter left in the map for an envelope that is never acked
        // is a leak the length of the daemon's life, and `unref` is deliberately NOT used: the
        // grace period must be able to hold the process just as the seal it precedes does.
        const current = ackWaiters.get(key);
        current?.delete(wake);
        if (current && current.size === 0) ackWaiters.delete(key);
        resolve(null);
      }, timeoutMs);
    });
  };

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
    rewriteFile: async (ownerAgentId, inResponseTo) => {
      if (!writePath) return;
      const env = decodeDocumentUpdateEnvelope(inResponseTo);
      const document = store.getDocument(ownerAgentId, env.document_id);
      if (!document) return;
      await writePath.materialize(
        ownerAgentId,
        env.document_id,
        document.documentType,
        live.get(ownerAgentId, env.document_id),
      );
    },
    noticeInboundUpdate: (ownerAgentId, inResponseTo) => {
      const env = decodeDocumentUpdateEnvelope(inResponseTo);
      // COUNTED FROM THE LOG, not incremented blindly: envelopes redeliver, and a counter bumped on
      // every arrival would drift upward on ordinary retries and tell the operator there is more to
      // read than there is.
      const unread = notifications.unreadFromPeer(ownerAgentId, env.document_id);
      notifications.notice(ownerAgentId, env.document_id, unread, Date.now());
    },
    sendFrameToPeer: async (ownerAgentId, inResponseTo, bytes) => {
      // Addressed to whoever AUTHORED the envelope being answered, taken from the envelope itself
      // rather than from the document row: the row's peer and the envelope's sender are the same
      // party in a two-party document, and reading it from the signed bytes means a refusal can
      // only ever go back to the agent that actually sent the thing refused.
      const env = decodeDocumentUpdateEnvelope(inResponseTo);
      const sent = await deps.sendFrame(ownerAgentId, env.sender_agent_id, bytes, LEAF_KIND_REJECT);
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
    writePath,
    handshake,
    engine,
    live,
    lifecycle,
    notifications,
    rejections,
    router,
    awaitAck,
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
