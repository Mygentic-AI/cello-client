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
}

export interface DocumentLayer {
  store: DocumentStore;
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
  const live = new LiveDocuments(store, engine, logger);
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
  const router = new DocumentFrameRouter({ inbound, ackInbound, logger });

  return {
    store,
    engine,
    live,
    lifecycle,
    notifications,
    rejections,
    router,
    onDocumentFrame: (agentName, _sessionId, content, _senderPubkey, correlationId) =>
      // `agentName` is the owning agent for the session, which is the scope every document call is
      // keyed by. The session id and the sender's transport pubkey are deliberately unused: a
      // document is bound to its PEER by the handshake, not to whichever session carried the
      // frame, and the envelope's own signed `sender_agent_id` is what the inbound path checks
      // against that binding. Trusting the transport identity instead would let a frame arriving
      // on any session act on any document that session's peer happens to share.
      router.routeSync(agentName, content, Date.now(), correlationId ?? "frame"),
  };
}
