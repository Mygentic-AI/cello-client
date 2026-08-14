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

import { createHash } from "node:crypto";
import { verify } from "@cello-protocol/crypto";
import { DocumentStore } from "./document-store.js";
import { DocumentEngine } from "./document-engine.js";
import { DocumentGate } from "./document-gate.js";
import { screeningRule, SCREEN_RULE_ID } from "./document-screen.js";
import { DocumentRejections } from "./document-rejection.js";
import { DocumentInbound } from "./document-inbound.js";
import { DocumentAckInbound } from "./document-ack-inbound.js";
import { DocumentAmendmentStore } from "./document-amendment-store.js";
import { DocumentJoinStore } from "./document-join-store.js";
import { DocumentFrameRouter } from "./document-frame-router.js";
import { LiveDocuments } from "./document-live-docs.js";
import { DocumentLifecycle } from "./document-lifecycle.js";
import { DocumentNotifications, changedKeyPaths } from "./document-notify.js";
import { matchWatchedPaths, matchingWatches } from "./document-watch.js";
import { projectDocumentText } from "./document-json.js";
import { rootForDocumentType } from "./document-types.js";
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
  buildDocumentUpdateTbs,
  documentEnvelopeHash,
  buildDocumentJoinAnswerTbs,
  encodeDocumentJoinAnswer,
  buildDocumentJoinOfferTbs,
  decodeDocumentJoinOffer,
  decodeDocumentAmendment,
  decodeDocumentProposal,
  encodeDocumentProposalAck,
  DOCUMENT_PROPOSAL_ACK_VERSION,
  MAX_PROPOSAL_REFUSAL_REASON_LENGTH,
  type DocumentProposalAck,
  documentAmendmentHash,
  validateDocumentJoinOffer,
  documentGovernancePolicy,
  arrangementGenesisFromProposal,
  deriveDocumentState,
  checkEntryAdmissible,
  type DocumentAmendmentEnvelope,
  type DocumentJoinAnswer,
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
  /**
   * DOD-DOC-WATCH-1 — ring the operator's agent because a path IT declared it was waiting on has
   * moved. Injected: the doorbell is the daemon's, not this layer's.
   *
   * Called ONLY on a watch hit. A document update raises no doorbell otherwise (§11.3) and that
   * stands — this is the narrow exception an agent asked for by name.
   */
  nudge?(ownerAgentId: string, documentId: string, paths: readonly string[]): void;
  /**
   * Tell EVERY current holder about an end. Injected — the transport is not this layer's.
   * Per-holder because a document has N holders (DOD-MP-CONTROL-N-1), not one counterparty.
   */
  notifyPeer(
    documentId: string,
    verb: "kill" | "close",
  ): Promise<
    | { ok: true; holdersNotified: Record<string, boolean>; holderFailures: Record<string, string> }
    | { ok: false; reason: string }
  >;
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
  /** M14B — the amendment chain (write path; reads go through `store.currentDocumentEpoch`). */
  amendments: DocumentAmendmentStore;
  /** M14B — join offers pending consent, both roles. */
  joins: DocumentJoinStore;
  /** The layer's one Ed25519 verifier seam — for handlers that run the replay themselves. */
  verifySignature(agentId: string, tbs: Uint8Array, signature: Uint8Array): boolean;
  /** M14B / FANOUT-1 — current holders derived from the chain; null when underivable. */
  holdersFor(ownerAgentId: string, documentId: string): string[] | null;
  /**
   * Who a control frame must be addressed to — everyone but the owner, derived (DOD-MP-CONTROL-N-1).
   * Refuses by name rather than falling back to the genesis peer, which after a removal is the one
   * party the frame must not reach.
   */
  controlHolders(
    ownerAgentId: string,
    documentId: string,
  ): { ok: true; holders: readonly string[] } | { ok: false; reason: string };
  isCurrentHolder(ownerAgentId: string, documentId: string, agentId: string): boolean;
  /** M14B / DOD-MP-JOIN-1 — the invitee's consent decisions. Validate-everything-then-mutate. */
  acceptJoin(ownerAgentId: string, amendmentHash: string, nowMs: number): Promise<
    | { ok: true; documentId: string; inviterAgentId: string; documentType: string; applied: number; answerBytes: Uint8Array }
    | { ok: false; reason: string; detail: string }
  >;
  refuseJoin(ownerAgentId: string, amendmentHash: string, reason: string | null, nowMs: number): Promise<
    | { ok: true; documentId: string; inviterAgentId: string; answerBytes: Uint8Array }
    | { ok: false; reason: string; detail: string }
  >;
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
    expectedAckerAgentId: string,
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
  const lifecycle = new DocumentLifecycle(
    store,
    logger,
    { notifyPeer: deps.notifyPeer },
    deps.rollback,
    undefined,
    // DOD-MP-CONTROL-N-1 — the inbound gate. `holdersFor` is declared below and resolved lazily,
    // the same shape `live` uses above; the gate is only ever called long after construction.
    // Wired HERE rather than left to the daemon so every consumer of the layer — including the
    // e2e fixture — gets the real derivation and cannot silently keep the bilateral gate.
    (ownerAgentId, documentId) => {
      // LEGACY vs UNKNOWN, decided HERE because only this scope can tell them apart: no genesis
      // record means no chain at all — a bilateral document predating amendments, for which the
      // peer column IS the membership. A genesis record whose chain will not replay is a different
      // fact, and one this daemon must not paper over by assuming two parties.
      if (!handshake.get(ownerAgentId, documentId)) return { kind: "legacy" as const };
      const holders = holdersFor(ownerAgentId, documentId);
      return holders === null
        ? { kind: "unknown" as const, reason: "document_chain_underivable" }
        : { kind: "derived" as const, holders };
    },
  );
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
    membershipOf: (ownerAgentId, documentId, agentId) =>
      amendments.membershipOf(ownerAgentId, documentId, agentId),
    currentHolders: (ownerAgentId: string, documentId: string) =>
      holdersFor(ownerAgentId, documentId),
    sign: deps.sign,
  });

  // WAITERS for `awaitAck`, keyed by owner + envelope. A Set per key because two callers may wait
  // on the same envelope (a redelivery racing the original), and dropping one of them would leave a
  // session held open for the full grace period with the answer already in hand.
  // KEYED BY ACKER TOO (FANOUT-1 review H1): an envelope-keyed waiter let ANY holder's ack —
  // including a redelivered one from an already-settled holder — resolve the grace wait for
  // whichever holder was being dialed, and the worker then settled the DIALED holder's row for
  // content that never reached them. §7-1's silent divergence, through the sender's own
  // bookkeeping.
  const ackWaiters = new Map<string, Set<(admitted: boolean) => void>>();
  const waiterKey = (ownerAgentId: string, envelopeHash: string, ackerAgentId: string) =>
    `${ownerAgentId}\u0000${envelopeHash}\u0000${ackerAgentId}`;

  const ackInbound = new DocumentAckInbound({
    store,
    rejections,
    logger,
    verifySignature,
    currentHolders: (o: string, d: string) => holdersFor(o, d),
    onSettled: (ownerAgentId, envelopeHash, ackerAgentId, admitted) => {
      const key = waiterKey(ownerAgentId, envelopeHash, ackerAgentId);
      const waiting = ackWaiters.get(key);
      if (!waiting) return;
      ackWaiters.delete(key);
      // The OUTCOME, not just the fact of one. A caller told only "answered" has to report the
      // envelope as still in flight, which is how `document.delivery.sweep { delivered: N }` came
      // to be permanently 0 — a sweep that delivered nothing looked identical to a healthy one.
      for (const wake of waiting) wake(admitted);
    },
  });

  const awaitAck = async (
    ownerAgentId: string,
    envelopeHash: string,
    expectedAckerAgentId: string,
    timeoutMs: number,
  ) => {
    // ALREADY SETTLED WINS — by THE HOLDER BEING DIALED (H1): the per-acker read first, the
    // envelope-level read only for the zero-row bilateral legacy.
    const already =
      store.holderSettlement(ownerAgentId, envelopeHash, expectedAckerAgentId) ??
      store.envelopeSettlement(ownerAgentId, envelopeHash);
    if (already) return already;

    const key = waiterKey(ownerAgentId, envelopeHash, expectedAckerAgentId);
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
  // M14B / DOD-MP-JOIN-1 — the amendment chain and the join-consent stores. The membership READ
  // path (`currentDocumentEpoch`) has run through DocumentStore since AMEND-1; these are the
  // WRITE path, and every append below validates first (the standing AMEND-1 condition).
  const amendments = new DocumentAmendmentStore(db, logger);
  const joins = new DocumentJoinStore(db, logger);

  /**
   * M14B / DOD-MP-FANOUT-1 — the CURRENT holders of a document, derived from genesis + the
   * recorded chain. Null when the document is unknown or its chain does not derive — NOT an
   * empty list, because "nobody holds this" and "this cannot be answered" are different facts
   * and the worker schedules them differently.
   */
  const holdersFor = (ownerAgentId: string, documentId: string): string[] | null => {
    const genesisRecord = handshake.get(ownerAgentId, documentId);
    if (!genesisRecord) {
      // The SAME event the publish refusal points at — an operator hunting
      // document.holders.underivable must find it for BOTH null causes (review M6).
      logger.error("document.holders.underivable", {
        documentId,
        reason: "no_genesis_record: the document has a row but no stored genesis proposal",
      });
      return null;
    }
    // CONTAINED. `chain()` decodes every stored amendment and THROWS on bytes this build cannot
    // read, and this function's own contract is to return null when it cannot derive — so the throw
    // escaped past every caller written against that contract. It reached the operator on
    // `cello_doc_write` as a raw `Data read, but end of buffer not reached`: a CBOR library naming
    // where it surfaced, in place of the refusal the publish path was already holding ready.
    let derived: ReturnType<typeof deriveDocumentState>;
    try {
      derived = deriveDocumentState(
        arrangementGenesisFromProposal(genesisRecord.envelope),
        amendments.chain(ownerAgentId, documentId),
        documentGovernancePolicy,
        verifySignature,
      );
    } catch (err: unknown) {
      logger.error("document.holders.undecodable", {
        documentId,
        reason: err instanceof Error ? err.message : String(err),
      });
      return null;
    }
    if (!derived.ok) {
      logger.error("document.holders.underivable", {
        documentId,
        reason: derived.reason,
      });
      return null;
    }
    return [...derived.state.participants];
  };

  /**
   * Who a control frame (`close`, `kill`) must be addressed to — DOD-MP-CONTROL-N-1.
   *
   * THIS LIVES HERE, not as a closure in the composition root, for the reason
   * `document-control-notifier.ts`'s own header records about itself: a closure in `daemon.ts` has
   * no test, so every fixture hand-copies it, and a hand-copy cannot disagree with the original.
   * The first draft of this WAS such a closure and had already drifted — it re-derived the
   * arrangement itself and so never emitted `document.holders.underivable`, leaving the control
   * path invisible to the exact log search meant to find it.
   *
   * Everyone EXCEPT the owner, because the owner is the one doing the ending. A chain that will
   * not derive is refused by name rather than falling back to the genesis `peerAgentId` — that
   * fallback is the original defect, and after a removal it aims the frame at precisely the
   * removed holder.
   */
  const controlHolders = (
    ownerAgentId: string,
    documentId: string,
  ): { ok: true; holders: readonly string[] } | { ok: false; reason: string } => {
    // LEGACY FIRST, and for the same reason the settle path checks it first: a document with no
    // stored genesis proposal has NO CHAIN, so the peer column is not a fallback — it IS the
    // membership. Without this branch the send path refused the very condition the settle path
    // calls legacy, so no close frame ever left, neither side recorded the other's close, and such
    // a document could never be ended by agreement at all. Reachable two ways: documents proposed
    // before `recordOutgoing` shipped, and a crash between `createDocument` and `recordOutgoing`,
    // which run in that order.
    //
    // The two paths must agree about what "cannot answer" means. Their disagreeing is the whole
    // shape of this milestone's defects.
    const doc = store.getDocument(ownerAgentId, documentId);
    if (doc && !handshake.get(ownerAgentId, documentId)) {
      return { ok: true, holders: [doc.peerAgentId] };
    }
    let derivedHolders: readonly string[] | null;
    try {
      derivedHolders = holdersFor(ownerAgentId, documentId);
    } catch (err: unknown) {
      // CONTAINED for the same reason `cello_doc_list` contains it: a chain this build cannot
      // decode THROWS, and an uncontained throw would take down the close/kill verb entirely
      // rather than reporting why the frame could not be addressed.
      return {
        ok: false,
        reason: `document_chain_undecodable: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
    // A chain that EXISTS and will not replay keeps the refusal — it may name holders we cannot
    // see, and addressing the genesis peer alone there is the original defect.
    if (derivedHolders === null) return { ok: false, reason: "document_holders_underivable" };
    return { ok: true, holders: derivedHolders.filter((p) => p !== ownerAgentId).sort() };
  };

  /** Is this agent a CURRENT holder — the ack gate's membership question. */
  const isCurrentHolder = (ownerAgentId: string, documentId: string, agentId: string): boolean => {
    const holders = holdersFor(ownerAgentId, documentId);
    return holders !== null && holders.includes(agentId);
  };

  /** Sign and send a join answer — best-effort, never a veto over the local decision. */
  const sendJoinAnswer = async (
    ownerAgentId: string,
    inviterAgentId: string,
    documentId: string,
    amendmentHash: string,
    accepted: boolean,
    reason: string | null,
  ): Promise<void> => {
    try {
      const answer: DocumentJoinAnswer = {
        type: "document_join_answer",
        document_id: documentId,
        amendment_hash: amendmentHash,
        invitee_agent_id: ownerAgentId,
        accepted,
        refusal_reason: accepted ? null : reason,
        answered_at_ms: Date.now(),
        signature: new Uint8Array(0),
      };
      answer.signature = await deps.sign(ownerAgentId, buildDocumentJoinAnswerTbs(answer));
      await deps.sendFrame(ownerAgentId, inviterAgentId, encodeDocumentJoinAnswer(answer));
    } catch (err: unknown) {
      logger.warn("document.join.answer_send_failed", {
        documentId,
        amendmentHash,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  };

  /** Re-send the STANDING decision for an already-decided offer a redelivery just matched. */
  const resendJoinAnswer = async (
    ownerAgentId: string,
    amendmentHash: string,
    inviterAgentId: string,
  ): Promise<void> => {
    const record = joins.get(ownerAgentId, amendmentHash);
    if (!record || record.state === "pending") return;
    await sendJoinAnswer(
      ownerAgentId,
      inviterAgentId,
      record.documentId,
      amendmentHash,
      record.state === "accepted",
      record.reason,
    );
  };

  const router = new DocumentFrameRouter({
    inbound,
    ackInbound,
    logger,
    ownerKeyFor: deps.ownerKeyFor,
    recordProposal: (ownerAgentId, wire, nowMs) => {
      // THROWS on a forged or misaddressed proposal, which the router contains and reports. That is
      // right: those are refusals, and nothing should be recorded for them.
      const recorded = handshake.recordProposal(ownerAgentId, wire, nowMs);
      // BOTH ENDS GET THE SENTENCE (TOPOLOGY-1 review F1, the join path's rule applied here):
      // an arrival auto-refusal — seam violation, version mismatch — used to write its sentence
      // to OUR database and answer the proposer with silence, a hang they diagnose as a network
      // fault. The signed refusal ack now travels best-effort; the proposal verified against its
      // named proposer at record time, so the answer goes to an authenticated party.
      const refusalReason = recorded.reason;
      if (recorded.state === "refused" && refusalReason !== undefined) {
        const proposal = decodeDocumentProposal(wire);
        void (async () => {
          try {
            const ack: DocumentProposalAck = {
              type: "document_proposal_ack",
              ack_version: DOCUMENT_PROPOSAL_ACK_VERSION,
              document_id: recorded.documentId,
              acker_agent_id: ownerAgentId,
              accepted: false,
              refusal_reason: refusalReason.slice(0, MAX_PROPOSAL_REFUSAL_REASON_LENGTH),
              decided_at_ms: Date.now(),
              signature: new Uint8Array(0),
            };
            ack.signature = await deps.sign(ownerAgentId, buildDocumentProposalAckTbs(ack));
            await deps.sendFrame(
              ownerAgentId, proposal.proposer_agent_id, encodeDocumentProposalAck(ack),
            );
          } catch (err: unknown) {
            logger.warn("document.proposal.auto_refusal_ack_failed", {
              documentId: recorded.documentId,
              error: err instanceof Error ? err.message : String(err),
            });
          }
        })();
      }
    },
    recordJoinOffer: (ownerAgentId, wire, nowMs) => {
      const offer = decodeDocumentJoinOffer(wire);
      // ADDRESSED TO US — the same multi-agent-daemon rule recordProposal enforces: consent
      // belongs to the agent the inviter named, and a throw here is contained by the router.
      if (offer.invitee_agent_id !== ownerAgentId) {
        throw new Error(
          `document_join_wrong_invitee: this offer is addressed to ${offer.invitee_agent_id}, ` +
            `not to ${ownerAgentId}`,
        );
      }
      const validation = validateDocumentJoinOffer(offer, documentGovernancePolicy, verifySignature);
      if (validation.ok) {
        const stored = joins.recordIncoming(
          ownerAgentId, wire, validation.pendingAmendmentHash, { state: "pending" }, nowMs,
        );
        // REDELIVERY OF A DECIDED OFFER RE-SENDS THE ANSWER. A lost answer was otherwise lost
        // forever: the invitee's decision stood, the inviter's row sat pending, and the
        // inviter's only lever — re-inviting, which redelivers this exact offer — reached a
        // DO-NOTHING insert. Now that redelivery is the recovery: the standing decision is
        // re-signed and travels again. Best-effort, like every answer.
        if (stored.state !== "pending") {
          void resendJoinAnswer(ownerAgentId, validation.pendingAmendmentHash, offer.inviter_agent_id);
        }
        return;
      }
      // A REFUSAL IS RECORDED — AND ANSWERED — ONLY WHEN IT IS AUTHENTICATED. The first cut
      // recorded every refusal under the admitting amendment's hash, and that was a standing
      // veto: any party holding the amendment bytes (every holder gets them in the fan-out)
      // could deliver a garbage offer FIRST, occupy the real settle key with a refused row, and
      // the genuine offer would arrive to a DO-NOTHING insert — the admin's admission silently
      // suppressed, both operators seeing nothing. So: an offer whose signature does not verify
      // against its named inviter THROWS (contained + logged, nothing recorded — the forged-
      // proposal treatment), and an authenticated refusal is recorded under the hash of ITS OWN
      // BYTES — visible to the operator, never able to occupy a real join's settle key.
      if (!verifySignature(offer.inviter_agent_id, buildDocumentJoinOfferTbs(offer), offer.signature)) {
        throw new Error(validation.reason);
      }
      const refusalKey = createHash("sha256").update(wire).digest("hex");
      joins.recordIncoming(
        ownerAgentId, wire, refusalKey, { state: "refused", reason: validation.reason }, nowMs,
      );
      // BOTH ENDS get the sentence: the refusal answer travels back to the authenticated
      // inviter, settling their row with the reason — the version-mismatch sentence was written
      // for a human and was reaching a database column. The settle key is the admitting
      // amendment's hash when one is recoverable (the inviter's row lives under it).
      const last = offer.amendments[offer.amendments.length - 1];
      if (last !== undefined) {
        try {
          const settleKey = Buffer.from(
            documentAmendmentHash(decodeDocumentAmendment(last).body),
          ).toString("hex");
          void sendJoinAnswer(
            ownerAgentId, offer.inviter_agent_id, offer.document_id, settleKey, false, validation.reason,
          );
        } catch {
          // No recoverable settle key — the refusal stays visible locally and the inviter's
          // re-invite (which redelivers) will meet the same recorded refusal.
        }
      }
    },
    recordJoinAnswer: (ownerAgentId, wire, nowMs) => {
      const r = joins.recordAnswer(ownerAgentId, wire, verifySignature, nowMs);
      // A refusal is a verdict the router contains and reports — never a silent drop.
      if (!r.ok) throw new Error(r.reason);
    },
    recordAmendment: (ownerAgentId, wire, nowMs) => {
      // An entry reaching an EXISTING holder. The door refuses only what no future entry can
      // ever make good — a broken collection binding, an unproven author, a failed signature
      // (checkEntryAdmissible). Everything semantic is the FOLD's ruling at consumption, and a
      // fold-void entry is still history (F4): bouncing it here would leave two holders holding
      // different sets.
      const env = decodeDocumentAmendment(wire);
      const documentId = env.body.document_id;
      if (!store.getDocument(ownerAgentId, documentId)) {
        throw new Error(`document_unknown: no document ${documentId.slice(0, 16)}… for this agent`);
      }
      const record = handshake.get(ownerAgentId, documentId);
      if (!record) {
        throw new Error(
          `document_genesis_missing: ${documentId.slice(0, 16)}… has a row but no stored genesis ` +
            `proposal to replay from`,
        );
      }
      const admissible = checkEntryAdmissible(env, verifySignature);
      if (!admissible.ok) throw new Error(admissible.reason);
      // THE STRANGER DOOR (SYNC-R18, interim until P3's full entitlement classes): a fold-void
      // entry is history only when its author is KNOWN to this document — a genesis party or
      // someone an EFFECTIVE admission names (which covers invited and removed authors, whose
      // earlier work must still converge, R20). Effective, not merely held: a hostile holder can
      // mint a self-signed, fold-void admission naming any key, and counting it would hand that
      // key an unbounded license to grow every holder's entry set (review F4). A stranger's
      // governance is refused by name, never stored.
      const author = env.body.author_agent_id;
      const genesisArr = arrangementGenesisFromProposal(record.envelope);
      let authorKnown =
        genesisArr.proposerAgentId === author || genesisArr.peerAgentId === author;
      if (!authorKnown) {
        const held = amendments.chain(ownerAgentId, documentId);
        const doorDerived = deriveDocumentState(
          genesisArr,
          held,
          documentGovernancePolicy,
          verifySignature,
        );
        if (!doorDerived.ok) throw new Error(doorDerived.reason);
        const inert = new Set([
          ...doorDerived.state.voids.map((v) => v.hash),
          ...doorDerived.state.excluded.map((e) => e.hash),
        ]);
        authorKnown = held.some(
          (e) =>
            e.body.kind === "add_holder" &&
            e.body.subject_agent_id === author &&
            !inert.has(Buffer.from(documentAmendmentHash(e.body)).toString("hex")),
        );
      }
      if (!authorKnown) {
        throw new Error(
          `document_author_stranger: ${author} is neither a genesis party nor named by any ` +
            `effective admission — a stranger's governance is refused, not stored`,
        );
      }
      const appended = amendments.append(ownerAgentId, documentId, wire, nowMs);
      // Post-apply surfacing runs for EVERYTHING that just applied: the direct arrival, and
      // every held entry this arrival promoted (review F2 — the held path silently dropped the
      // removal notice and the lifecycle completion, reintroducing the stuck-`active` defect
      // CLOSE-N-1 fixed, on exactly the out-of-order path the pending table exists for).
      const surfaceApplied = (applied: DocumentAmendmentEnvelope) => {
        // DOD-MP-REMOVE-1 — a removal NAMING THIS AGENT is applied and SURFACED, not just
        // stored: the row flips to `removed` (publishes refuse locally, naming the condition;
        // the copy, the file, the history all remain — forward-only by doctrine), and the event
        // is the operator's notice. Everyone else's arrangement changes are visible through
        // list/inbox derivation; being written out of one is the change an operator must not
        // miss.
        if (
          applied.body.kind === "remove_holder" &&
          applied.body.subject_agent_id === ownerAgentId
        ) {
          logger.warn("document.removed_from", {
            documentId,
            epochId: applied.body.epoch_id,
            removedBy: applied.collection.required_signers.join(","),
          });
        }
        // DOD-MP-CLOSE-N-1 — a membership change can COMPLETE an agreement. Removing the one
        // holder who had not closed leaves everyone who remains in agreement; without this the
        // document stayed `active` forever reporting that it waited on nobody.
        if (applied.body.kind === "remove_holder" || applied.body.kind === "add_holder") {
          lifecycle.onMembershipChanged(
            ownerAgentId,
            documentId,
            applied.body.kind === "remove_holder"
              ? (applied.body.subject_agent_id ?? undefined)
              : undefined,
          );
        }
      };
      // An entry held for missing parents (R14) is recorded but NOT applied — its notices wait
      // with it and fire on promotion. The store's `document.entry.held` event is the trace.
      if (!appended.held) surfaceApplied(env);
      for (const promoted of appended.promoted) surfaceApplied(promoted.envelope);
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

      // DOD-DOC-WATCH-1 — the selective nudge.
      //
      // Matched against what changed since THIS agent last READ, not against this envelope. Per
      // envelope re-fires on redelivery and on the peer's every keystroke; the net difference from
      // the read mark asks the question an operator actually has — has the thing I am waiting on
      // moved since I saw it — and self-cancels the moment they read.
      //
      // Wrapped whole: a notification is a courtesy on a path whose real job (admitting the peer's
      // update) has already succeeded, and must never be able to fail it.
      try {
        const watches = notifications.watches(ownerAgentId, env.document_id);
        if (watches.length === 0) return;
        if (!notifications.nudgeOwed(ownerAgentId, env.document_id)) return;
        const document = store.getDocument(ownerAgentId, env.document_id);
        if (!document) return;
        const seen = notifications.lastSeen(ownerAgentId, env.document_id);
        const after = projectDocumentText(live.get(ownerAgentId, env.document_id), document.documentType);
        // NEVER READ is not "everything changed" for the purposes of a nudge — the agent has not
        // established a baseline, so there is nothing it can be waiting on a change to.
        if (seen === null || seen === after) return;
        // A text document has no key paths, so the only thing it can report is that it moved. That
        // is why the whole-document watch has to be spelled `*` rather than implied.
        const paths =
          rootForDocumentType(document.documentType) === "map"
            ? changedKeyPaths(seen, after) ?? ["*"]
            : ["*"];
        const hits = matchWatchedPaths(watches, paths);
        if (hits.length === 0) return;
        // THE AGENT'S OWN PATTERNS travel, never the changed paths. A changed path can carry a key
        // the PEER named, and a doorbell body is an unscreened route into the agent's context —
        // see `matchingWatches`. The precise field comes from cello_doc_diff, which IS screened.
        const firedWatches = matchingWatches(watches, paths);
        notifications.markNudged(ownerAgentId, env.document_id, Date.now());
        logger.info("document.watch.nudged", {
          documentId: env.document_id,
          paths: hits.length,
          watches: firedWatches.length,
        });
        deps.nudge?.(ownerAgentId, env.document_id, firedWatches);
      } catch (err: unknown) {
        logger.warn("document.watch.nudge_failed", {
          documentId: env.document_id,
          error: err instanceof Error ? err.message : String(err),
        });
      }
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

  /**
   * M14B / DOD-MP-JOIN-1 — the invitee's ACCEPT: consent becomes a held document.
   *
   * VALIDATE EVERYTHING, THEN MUTATE. The stored offer is re-validated at the moment of
   * consequence (validate-before-append, on the bytes that will be appended), and the whole
   * envelope-log snapshot is verified — every signature, every document binding — before one row
   * lands. A snapshot with one bad envelope refuses the accept naming it, because skipping it
   * silently would hand the joiner a document that reads complete and diverges from every other
   * holder (NO-SILENT-DROP).
   *
   * Historical log envelopes are accepted at the epoch their SIGNED bytes claim — the inbound
   * epoch gate is for live arrivals; a snapshot legitimately spans epochs 0..N.
   */
  const acceptJoin = async (ownerAgentId: string, amendmentHash: string, nowMs: number) => {
    const record = joins.get(ownerAgentId, amendmentHash);
    if (!record || record.role !== "invitee") {
      return {
        ok: false as const,
        reason: "join_unknown_offer",
        detail: `no join offer for this agent settles on ${amendmentHash.slice(0, 16)}…`,
      };
    }
    if (record.state !== "pending") {
      return {
        ok: false as const,
        reason: "join_already_decided",
        detail: `this offer was already ${record.state} — a consent decision is made once`,
      };
    }
    const validation = validateDocumentJoinOffer(record.offer, documentGovernancePolicy, verifySignature);
    if (!validation.ok) {
      // Recorded, not just returned: an offer that no longer validates is a settled fact.
      joins.decide(ownerAgentId, amendmentHash, false, validation.reason, nowMs);
      return { ok: false as const, reason: "join_offer_invalid", detail: validation.reason };
    }
    const documentId = record.documentId;

    // WHO MAY APPEAR IN THE SNAPSHOT: anyone who held the document at ANY epoch of the carried
    // chain — the genesis pair plus every add_holder subject (a removed holder's history stays
    // legal). Without this, a malicious inviter plants envelopes signed by keys they control
    // under identities that were never holders, and the joiner materializes content no
    // legitimate holder ever saw — silent divergence the live path's sender-is-peer check
    // would have refused.
    const everHeld = new Set<string>([
      validation.genesis.proposer_agent_id,
      validation.genesis.peer_agent_id,
    ]);
    for (const amendment of validation.amendments) {
      if (amendment.body.kind === "add_holder" && amendment.body.subject_agent_id !== null) {
        everHeld.add(amendment.body.subject_agent_id);
      }
    }

    // The WHOLE snapshot verified before any mutation.
    const verified: Array<Parameters<typeof store.appendEnvelope>[1]> = [];
    for (let i = 0; i < record.offer.envelope_log.length; i++) {
      const bytes = record.offer.envelope_log[i]!;
      let env;
      try {
        env = decodeDocumentUpdateEnvelope(bytes);
      } catch (err: unknown) {
        return {
          ok: false as const,
          reason: "join_log_invalid",
          detail: `snapshot envelope ${i} does not decode: ${err instanceof Error ? err.message : String(err)}`,
        };
      }
      if (env.document_id !== documentId) {
        return {
          ok: false as const,
          reason: "join_log_invalid",
          detail: `snapshot envelope ${i} names document ${env.document_id.slice(0, 16)}…, not this one`,
        };
      }
      if (!verifySignature(env.sender_agent_id, buildDocumentUpdateTbs(env), env.signature)) {
        return {
          ok: false as const,
          reason: "join_log_invalid",
          detail: `snapshot envelope ${i} does not verify against its sender ${env.sender_agent_id}`,
        };
      }
      if (!everHeld.has(env.sender_agent_id)) {
        return {
          ok: false as const,
          reason: "join_log_invalid",
          detail:
            `snapshot envelope ${i} is signed by ${env.sender_agent_id}, who never held this ` +
            `document at any epoch of the carried chain — refused before anything materializes`,
        };
      }
      verified.push({
        envelopeHash: documentEnvelopeHash(env),
        documentId,
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
    }

    // Mutations, in dependency order: genesis (LiveDocuments reads starting_content from it),
    // the chain (idempotent on redelivery), the row, the log, the live rebuild, the file.
    handshake.recordJoined(ownerAgentId, record.offer.genesis, nowMs);
    try {
      for (const bytes of record.offer.amendments) {
        amendments.append(ownerAgentId, documentId, bytes, nowMs);
      }
    } catch (err: unknown) {
      // TWO ADMINS INVITED THE SAME AGENT INDEPENDENTLY: each offer's chain is self-consistent
      // and both sat pending, but their admitting amendments rival at one epoch — the second
      // accept hits the store's fork refusal mid-append. Settled as refused with the conflict's
      // own reason rather than thrown: a raw exception left the row pending and every retry
      // rethrowing, a wedge the operator could not see past.
      const reason = err instanceof Error ? err.message : String(err);
      joins.decide(ownerAgentId, amendmentHash, false, reason, nowMs);
      return { ok: false as const, reason: "join_conflicting_admission", detail: reason };
    }
    if (!store.getDocument(ownerAgentId, documentId)) {
      store.createDocument({
        documentId,
        ownerAgentId,
        // The inviter is this holder's live counterpart until fan-out delivery (P2) — the
        // participants that MATTER derive from the amendment chain (Entry 9's decision).
        peerAgentId: record.inviterAgentId,
        documentType: validation.genesis.document_type,
        properties: validation.genesis.properties,
        status: "active",
        createdAtMs: nowMs,
      });
    }
    for (const row of verified) store.appendEnvelope(ownerAgentId, row);
    const doc = live.get(ownerAgentId, documentId);
    if (writePath) {
      await writePath.materialize(ownerAgentId, documentId, validation.genesis.document_type, doc);
    }
    joins.decide(ownerAgentId, amendmentHash, true, null, nowMs);

    const answer: DocumentJoinAnswer = {
      type: "document_join_answer",
      document_id: documentId,
      amendment_hash: amendmentHash,
      invitee_agent_id: ownerAgentId,
      accepted: true,
      refusal_reason: null,
      answered_at_ms: nowMs,
      signature: new Uint8Array(0),
    };
    answer.signature = await deps.sign(ownerAgentId, buildDocumentJoinAnswerTbs(answer));
    logger.info("document.join.accepted", { documentId, amendmentHash, applied: verified.length });
    return {
      ok: true as const,
      documentId,
      inviterAgentId: record.inviterAgentId,
      documentType: validation.genesis.document_type,
      applied: verified.length,
      answerBytes: encodeDocumentJoinAnswer(answer),
    };
  };

  /** The invitee's REFUSE — local and final; the signed answer travels best-effort. */
  const refuseJoin = async (ownerAgentId: string, amendmentHash: string, reason: string | null, nowMs: number) => {
    const record = joins.get(ownerAgentId, amendmentHash);
    if (!record || record.role !== "invitee") {
      return {
        ok: false as const,
        reason: "join_unknown_offer",
        detail: `no join offer for this agent settles on ${amendmentHash.slice(0, 16)}…`,
      };
    }
    const decided = joins.decide(ownerAgentId, amendmentHash, false, reason, nowMs);
    if (!decided.decided) {
      return {
        ok: false as const,
        reason: "join_already_decided",
        detail: `this offer was already ${decided.state} — a consent decision is made once`,
      };
    }
    const answer: DocumentJoinAnswer = {
      type: "document_join_answer",
      document_id: record.documentId,
      amendment_hash: amendmentHash,
      invitee_agent_id: ownerAgentId,
      accepted: false,
      refusal_reason: reason,
      answered_at_ms: nowMs,
      signature: new Uint8Array(0),
    };
    answer.signature = await deps.sign(ownerAgentId, buildDocumentJoinAnswerTbs(answer));
    logger.info("document.join.refused", { documentId: record.documentId, amendmentHash });
    return {
      ok: true as const,
      documentId: record.documentId,
      inviterAgentId: record.inviterAgentId,
      answerBytes: encodeDocumentJoinAnswer(answer),
    };
  };

  return {
    amendments,
    joins,
    verifySignature,
    holdersFor,
    controlHolders,
    isCurrentHolder,
    acceptJoin,
    refuseJoin,
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
