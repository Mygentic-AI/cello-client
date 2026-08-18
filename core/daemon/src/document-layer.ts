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
import { DocumentAmendmentStore } from "./document-amendment-store.js";
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
  decodeDocumentUpdateEnvelope,
  encodeDocumentAmendment,
  decodeDocumentAmendment,
  decodeDocumentProposal,
  encodeDocumentProposal,
  documentIdFromProposal,
  buildDocumentProposalTbs,
  encodeDocumentProposalAck,
  DOCUMENT_PROPOSAL_ACK_VERSION,
  MAX_PROPOSAL_REFUSAL_REASON_LENGTH,
  type DocumentProposalAck,
  documentAmendmentHash,
  documentGovernancePolicy,
  arrangementGenesisFromProposal,
  deriveDocumentState,
  deriveDocumentStateAt,
  checkEntryAdmissible,
  decodeDocumentReconcile,
  encodeDocumentReconcile,
  DOCUMENT_RECONCILE_EXCHANGE_VERSION,
  type DocumentAmendmentEnvelope,
} from "@cello-protocol/protocol-types";
import { LEAF_KIND_REJECT } from "./session-relay-client.js";
import {
  buildReconcileBlock,
  respondToReconcile,
  type ReconcileReads,
} from "./document-reconcile-engine.js";
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
  /**
   * A PEER REFUSED OUR EXCHANGE. Wired to the scheduler so the refusal can slow the asking down.
   *
   * Without it the refusal is logged and dropped, and the sweep — which can only see whether the
   * frame was SENT — retries at full speed forever. Optional so a layer built without a scheduler
   * (every unit fixture) needs no wiring; the scheduler treats the signal as a DELAY, never a
   * prohibition (R41).
   */
  onPeerRefusal?(ownerAgentId: string, peerAgentId: string, terminal: boolean): void;
}

export interface DocumentLayer {
  /**
   * DOD-M12B-SHUTDOWN-1 — refuse every further outbound reconcile, whichever caller asks.
   *
   * The reconcile scheduler is only one of four routes to `initiateReconcile`; `nudgeSeats` and the
   * two invite notices reach it directly, and every document verb is still served while the daemon
   * tears down, because the IPC server is the last thing stopped. Gating the scheduler alone left
   * three paths dialling peers and opening sessions on the way out.
   *
   * Idempotent and one-way. The reconcile exchange is idempotent (R40), so a refused reconcile is
   * deferred to the next process, never lost.
   */
  stopReconciling(): void;
  store: DocumentStore;
  /** The file projection, or null when no workspace root was configured. */
  writePath: DocumentWritePath | null;
  handshake: DocumentHandshake;
  engine: DocumentEngine;
  live: LiveDocuments;
  lifecycle: DocumentLifecycle;
  notifications: DocumentNotifications;
  rejections: DocumentRejections;
  /** M14B — the entry chain: the fork-tolerant store the fold derives from. */
  amendments: DocumentAmendmentStore;
  /** The layer's one Ed25519 verifier seam — for handlers that run the replay themselves. */
  verifySignature(agentId: string, tbs: Uint8Array, signature: Uint8Array): boolean;
  /** M14B / FANOUT-1 — current holders derived from the chain; null when underivable. */
  holdersFor(ownerAgentId: string, documentId: string): string[] | null;
  isCurrentHolder(ownerAgentId: string, documentId: string, agentId: string): boolean;
  /** SYNC-P5 (R43) — the sweep's (party → shared active documents) map, seats from the fold. */
  sweepTargets(ownerAgentId: string): Map<string, string[]>;
  /** SYNC-R46 — one party's sync state from the display cache (never a correctness input). */
  partySync(
    ownerAgentId: string,
    documentId: string,
    partyAgentId: string,
  ): { sync: "in_sync" | "behind" | "unseen"; lastSyncedAtMs: number | null; blockedBy?: string };
  /**
   * DOD-DOC-PUSH-NOT-POLL-1 — what we hold that this party has not confirmed receiving, as a
   * comparable fingerprint; `null` when there is nothing. The sweep's ONLY reason to speak.
   */
  pendingFor(ownerAgentId: string, documentId: string, partyAgentId: string): string | null;
  /** SYNC-D8 — the ONE derivation of an agent's standing (R17 + removed/unknown), from the fold. */
  standingOf(
    ownerAgentId: string,
    documentId: string,
    agentId: string,
  ): "participant" | "invited" | "removed" | "stranger" | "unknown";
  /**
   * SYNC-P3 — step 1 of the reconcile exchange: send this holder's position for the named
   * documents to a peer. Everything after that is symmetric and handled by the frame router.
   */
  initiateReconcile(
    ownerAgentId: string,
    peerAgentId: string,
    documentIds: readonly string[],
  ): Promise<{ ok: true } | { ok: false; reason: string }>;
  /**
   * SYNC-G1 — the fold's governance frontier for a document, or null when it cannot be
   * derived. Publish stamps this into every envelope's signed TBS as content's causal anchor.
   */
  governanceFrontierFor(ownerAgentId: string, documentId: string): string[] | null;
  /**
   * SYNC-P4 (R27/R28) — the DERIVED ending and who a pending close still waits on. Null when
   * the document cannot be derived.
   */
  deriveEnded(
    ownerAgentId: string,
    documentId: string,
  ): { ended: "closed" | "killed" | null; waitingOn: string[] } | null;
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
    // SYNC-D8 — "was this owner written out?" answered by the same fold as everything else.
    (ownerAgentId, documentId) => standingOf(ownerAgentId, documentId, ownerAgentId) === "removed",
    // Review F2 — "is it ended?" answered by the fold too; `derived: false` hands the pre-pivot
    // bilateral record back to its column.
    (ownerAgentId, documentId) => {
      const derived = reconcileReads(ownerAgentId).deriveState(documentId);
      return derived.ok
        ? { derived: true, ended: derived.state.ended }
        : { derived: false, ended: null };
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
    standingOf: (ownerAgentId, documentId, agentId) => standingOf(ownerAgentId, documentId, agentId),
    // The CONTENT door: strictly participants (R17 — invited seats receive, never author).
    currentHolders: (ownerAgentId: string, documentId: string) =>
      participantsFor(ownerAgentId, documentId),
    // SYNC-G1 — the world an envelope's signed frontier names (R20's input for the causal gate).
    deriveAtFrontier: (ownerAgentId: string, documentId: string, frontier: readonly string[]) => {
      const record = handshake.get(ownerAgentId, documentId);
      if (!record) return { ok: false as const, reason: "document_genesis_missing" };
      try {
        const at = deriveDocumentStateAt(
          arrangementGenesisFromProposal(record.envelope),
          amendments.chain(ownerAgentId, documentId),
          frontier,
          documentGovernancePolicy,
          verifySignature,
        );
        if (!at.ok) return { ok: false as const, reason: at.reason, missing: at.missing };
        return {
          ok: true as const,
          participants: at.state.participants,
          invited: at.state.invited,
          ended: at.state.ended,
        };
      } catch (err: unknown) {
        return {
          ok: false as const,
          reason: `document_chain_undecodable: ${err instanceof Error ? err.message : String(err)}`,
        };
      }
    },
    sign: deps.sign,
  });

  // The handshake verifies a proposal against its NAMED proposer — the same resolver, so a forged
  // proposal is refused before it can occupy a document_id (ON CONFLICT DO NOTHING makes the first
  // arrival's bytes permanent for that id).
  const handshake = new DocumentHandshake(db, logger, verifySignature);
  // M14B / DOD-MP-JOIN-1 — the amendment chain and the join-consent stores. The membership READ
  // path (`currentDocumentEpoch`) has run through DocumentStore since AMEND-1; these are the
  // WRITE path, and every append below validates first (the standing AMEND-1 condition).
  const amendments = new DocumentAmendmentStore(db, logger);

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
    // PARTICIPANTS ∪ INVITED (P2 review F4/F5): this is the "who is seated" set — delivery
    // targets, control-frame addressing, and the close agreement all reach every seat, because a
    // peer whose consent entry is still in flight must neither be starved of the entries they
    // will need nor ended around. An invited seat still cannot AUTHOR anything but its own
    // consent/refusal — the CONTENT door checks `participantsFor`, and the fold enforces it for
    // governance regardless of who we send to.
    return [...derived.state.participants, ...derived.state.invited];
  };

  /**
   * Strictly-consented participants — the CONTENT-AUTHORSHIP set (R17: an invited seat may
   * receive, never author). The inbound sender gate checks this; everything delivery-facing uses
   * `holdersFor`, which also counts invited seats.
   */
  const participantsFor = (ownerAgentId: string, documentId: string): string[] | null => {
    const genesisRecord = handshake.get(ownerAgentId, documentId);
    if (!genesisRecord) return null;
    let derived: ReturnType<typeof deriveDocumentState>;
    try {
      derived = deriveDocumentState(
        arrangementGenesisFromProposal(genesisRecord.envelope),
        amendments.chain(ownerAgentId, documentId),
        documentGovernancePolicy,
        verifySignature,
      );
    } catch {
      return null;
    }
    if (!derived.ok) return null;
    return [...derived.state.participants];
  };

  /**
   * SYNC-D8 — the ONE derivation of an agent's standing in a document, from the fold. The old
   * old linear membership walk was a second derivation that could disagree with
   * the fold about who is seated; every consumer now asks this.
   *
   *  - participant / invited: seated, per R17.
   *  - removed: not seated, and an APPLIED remove_holder entry names them (fold-void removals
   *    do not count — a void contributed nothing, F4).
   *  - stranger: not seated, never removed.
   *  - unknown: the chain does not derive (no genesis, undecodable bytes) — callers must not
   *    treat this as any of the other four.
   */
  const standingOf = (
    ownerAgentId: string,
    documentId: string,
    agentId: string,
  ): "participant" | "invited" | "removed" | "stranger" | "unknown" => {
    const derived = reconcileReads(ownerAgentId).deriveState(documentId);
    if (!derived.ok) return "unknown";
    if (derived.state.participants.has(agentId)) return "participant";
    if (derived.state.invited.has(agentId)) return "invited";
    const inert = new Set([
      ...derived.state.voids.map((v) => v.hash),
      ...derived.state.excluded.map((e) => e.hash),
    ]);
    let chain: DocumentAmendmentEnvelope[];
    try {
      chain = [...amendments.chain(ownerAgentId, documentId)];
    } catch {
      return "unknown";
    }
    for (const env of chain) {
      if (env.body.kind !== "remove_holder" || env.body.subject_agent_id !== agentId) continue;
      const hash = Buffer.from(documentAmendmentHash(env.body)).toString("hex");
      if (!inert.has(hash)) return "removed";
    }
    return "stranger";
  };

  /**
   * SYNC-R46 / spec §9 — one party's sync state, from the DISPLAY CACHE against our own
   * positions. ONE implementation for the list surface and the sweep's believed-current
   * suppression (R43) — two copies of "are they behind" is two daemons disagreeing about who
   * needs an exchange. Never a correctness input (R44).
   */
  /**
   * DOD-DOC-PUSH-NOT-POLL-1 — WHAT WE HOLD THAT THIS PARTY HAS NOT CONFIRMED RECEIVING, as a
   * fingerprint the scheduler compares and never interprets; `null` means nothing is pending.
   *
   * This is the SAME comparison that answers "are they behind" on the list surface, deliberately
   * written once: two copies of it is two daemons disagreeing about who needs an exchange. The
   * list projects it to a boolean; the sweep needs the VALUE, because it must tell an unchanged
   * holding (already offered — go quiet) from a new one (a trigger — speak now).
   *
   * A party with no view row at all has confirmed nothing, so everything we hold is pending.
   *
   * NOT the retired `pendingContent` count (R47): that was an operator-facing number no ledger
   * could make truthful. This never leaves the scheduler, and holds no authority — R41 stands,
   * it may only delay an exchange.
   */
  const pendingFor = (
    ownerAgentId: string,
    documentId: string,
    partyAgentId: string,
  ): string | null => {
    const view = store.partyView(ownerAgentId, documentId, partyAgentId);
    const parts: string[] = [];
    for (const [author, mark] of amendments.watermarks(ownerAgentId, documentId)) {
      if (mark.seq > (view?.govSeqs[author] ?? 0)) parts.push(`g:${author}:${mark.seq}`);
    }
    for (const [author, count] of store.envelopeCountsBySender(ownerAgentId, documentId)) {
      if (count > (view?.contentCounts[author] ?? 0)) parts.push(`c:${author}:${count}`);
    }
    if (parts.length === 0) return null;
    parts.sort();
    return parts.join(",");
  };

  const partySync = (
    ownerAgentId: string,
    documentId: string,
    partyAgentId: string,
  ): { sync: "in_sync" | "behind" | "unseen"; lastSyncedAtMs: number | null; blockedBy?: string } => {
    const view = store.partyView(ownerAgentId, documentId, partyAgentId);
    if (!view) return { sync: "unseen", lastSyncedAtMs: null };
    const behind = pendingFor(ownerAgentId, documentId, partyAgentId) !== null;
    const blockedBy =
      view.refused.length === 0
        ? undefined
        : view.refused.find((hash) =>
            store.getEnvelopeLog(ownerAgentId, documentId).some((row) => row.docPrevHash === hash),
          );
    return {
      sync: behind ? "behind" : "in_sync",
      lastSyncedAtMs: view.lastExchangeMs,
      ...(blockedBy ? { blockedBy } : {}),
    };
  };

  /**
   * SYNC-P5 (R43) — every (party → shared ACTIVE documents) pair one owner's sweep considers.
   * Seats come from the FOLD, per document; an ended or underivable document contributes
   * nothing, which is what lets a converged-and-ended document reach quiescence.
   */
  const sweepTargets = (ownerAgentId: string): Map<string, string[]> => {
    const targets = new Map<string, string[]>();
    for (const doc of store.listDocuments(ownerAgentId)) {
      if (doc.status !== "active") continue;
      const derived = reconcileReads(ownerAgentId).deriveState(doc.documentId);
      if (!derived.ok || derived.state.ended !== null) continue;
      const seats = [...derived.state.participants, ...derived.state.invited];
      // A HOLDER THAT NO LONGER HOLDS A SEAT HAS NOTHING TO EXCHANGE.
      //
      // Removal is forward-only: the copy and its history stay ours to read, but edits no longer
      // publish outward and theirs no longer arrive. So there is, by derivation, nothing left to
      // reconcile — and the peers say so, refusing with `terminal: true` and the words "there is
      // nothing further to reconcile".
      //
      // Without this the sweep derived its targets from the OTHER seats and never asked whether we
      // still occupied one, so a removed holder asked forever: measured 105 refusals against one
      // document in 85 minutes, every one of them terminal, every one of them asked again.
      //
      // The cost is not the wasted dial. Each attempt opens a session and pushes ack frames, and
      // every frame consumes a relay canonical position while the receiving tree does not advance
      // with it. That is what drives a conversation's tree behind the relay counter and strands
      // real messages behind an ordering gap that nothing fills.
      if (!seats.includes(ownerAgentId)) continue;
      for (const seat of seats) {
        if (seat === ownerAgentId) continue;
        const docs = targets.get(seat);
        if (docs) docs.push(doc.documentId);
        else targets.set(seat, [doc.documentId]);
      }
    }
    return targets;
  };

  /** Is this agent a CURRENT holder — the ack gate's membership question. */
  const isCurrentHolder = (ownerAgentId: string, documentId: string, agentId: string): boolean => {
    const holders = holdersFor(ownerAgentId, documentId);
    return holders !== null && holders.includes(agentId);
  };

  const recordAmendmentImpl = (ownerAgentId: string, wire: Uint8Array, nowMs: number): void => {
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
          removedBy: applied.collection.required_signers.join(","),
        });
      }
      // THE ARRIVING CONSENT IS THE JOIN ANSWER (SYNC-P3, the D5 replacement): an inviter's
      // pending row settles from the entry itself — the subject's own signed yes or no — so
      // the legacy answer frame carries nothing the record does not. Settle-once semantics
      // SYNC-P4 (R27/R28, review F2): the stored status is a DISPLAY PROJECTION of the derived
      // ending — recomputed on EVERY applied entry, in BOTH directions. One-way, kind-gated
      // syncing let two holders converge on the fold while holding different status columns
      // forever: a concurrently-authored admission re-opens the derivation (an invited seat
      // blocks closure), and nothing ever wrote `active` back. The derivation is the truth; the
      // column exists so the list surface does not re-derive every row, and no correctness gate
      // reads it for endings anymore (canPublish/canAdmit ask the fold).
      {
        const derivedEnd = reconcileReads(ownerAgentId).deriveState(documentId);
        if (derivedEnd.ok) {
          const current = store.getDocument(ownerAgentId, documentId)?.status;
          if (derivedEnd.state.ended !== null && current === "active") {
            store.setDocumentStatus(
              ownerAgentId,
              documentId,
              derivedEnd.state.ended === "killed" ? "killed" : "closed",
            );
            logger.info("document.ended.derived", { documentId, ended: derivedEnd.state.ended });
          } else if (
            derivedEnd.state.ended === null &&
            (current === "closed" || current === "killed")
          ) {
            store.setDocumentStatus(ownerAgentId, documentId, "active");
            logger.info("document.reopened.derived", { documentId });
          }
        }
      }
    };
    // An entry held for missing parents (R14) is recorded but NOT applied — its notices wait
    // with it and fire on promotion. The store's `document.entry.held` event is the trace.
    if (!appended.held) surfaceApplied(env);
    for (const promoted of appended.promoted) surfaceApplied(promoted.envelope);
  };

  const rewriteFileImpl = async (ownerAgentId: string, inResponseTo: Uint8Array): Promise<void> => {
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
  };

  const noticeInboundUpdateImpl = (ownerAgentId: string, inResponseTo: Uint8Array): void => {
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
  };

  /** SYNC-P3 — the reads the reconcile engine consumes, over THIS owner's stores. */
  const reconcileReads = (ownerAgentId: string): ReconcileReads => ({
    deriveState: (documentId) => {
      const record = handshake.get(ownerAgentId, documentId);
      if (!record) return { ok: false, reason: "document_genesis_missing" };
      try {
        return deriveDocumentState(
          arrangementGenesisFromProposal(record.envelope),
          amendments.chain(ownerAgentId, documentId),
          documentGovernancePolicy,
          verifySignature,
        );
      } catch (err: unknown) {
        return {
          ok: false,
          reason: `document_chain_undecodable: ${err instanceof Error ? err.message : String(err)}`,
        };
      }
    },
    watermarks: (documentId) => amendments.watermarks(ownerAgentId, documentId),
    entriesByAuthorAfter: (documentId, author, afterSeq) =>
      amendments.entriesByAuthorAfter(ownerAgentId, documentId, author, afterSeq),
    envelopeLog: (documentId) => store.getEnvelopeLog(ownerAgentId, documentId),
    refusedHashes: (documentId) =>
      rejections.quarantined(ownerAgentId, documentId).map((q) => q.rejectedEnvelopeHash),
    // SYNC-R35: the exact signed frames, from the quarantine — rows born before the column hold
    // none, and the exchange simply has nothing to attach for them.
    refusalRecords: (documentId) =>
      rejections
        .quarantined(ownerAgentId, documentId)
        .map((q) => q.rejectionWire)
        .filter((w): w is Uint8Array => w !== undefined),
    standingOf: (documentId, agentId) => standingOf(ownerAgentId, documentId, agentId),
    genesisBytes: (documentId) => {
      const record = handshake.get(ownerAgentId, documentId);
      return record ? new Uint8Array(encodeDocumentProposal(record.envelope)) : null;
    },
    removalClosure: (documentId, agentId) => {
      // The LAST removal naming them, plus every ancestor — walked over the held entry set.
      const chain = amendments.chain(ownerAgentId, documentId);
      const byHash = new Map(
        chain.map((env) => [
          Buffer.from(documentAmendmentHash(env.body)).toString("hex"),
          env,
        ]),
      );
      let removalHash: string | null = null;
      for (const [hash, env] of byHash) {
        if (env.body.kind === "remove_holder" && env.body.subject_agent_id === agentId) {
          removalHash = hash;
        }
      }
      if (!removalHash) return null;
      const wanted = new Set<string>([removalHash]);
      const queue = [removalHash];
      while (queue.length > 0) {
        const env = byHash.get(queue.pop()!);
        if (!env) continue;
        for (const parent of env.body.parents) {
          if (!wanted.has(parent)) {
            wanted.add(parent);
            queue.push(parent);
          }
        }
      }
      // Foldable order: parents before children — the chain read is already epoch/seq ordered.
      return chain
        .filter((env) =>
          wanted.has(Buffer.from(documentAmendmentHash(env.body)).toString("hex")),
        )
        .map((env) => new Uint8Array(encodeDocumentAmendment(env)));
    },
  });

  /**
   * SYNC-P3 — one arriving reconcile frame, all three steps. Apply what it carries (governance
   * entries FIRST, R12 — through the same causal door every amendment takes; then content
   * envelopes through the same inbound gate every update takes), then answer: a version this
   * build does not speak or a stranger gets the named refusal ON the frame; a peer that lacks
   * something gets the difference; a converged exchange gets silence — which is what terminates
   * it (R15: idempotence is the absence of a difference, not bookkeeping).
   */
  const handleReconcile = async (
    ownerAgentId: string,
    wire: Uint8Array,
    senderAgentId: string,
    nowMs: number,
    correlationId: string,
  ): Promise<{ ok: boolean; reason?: string }> => {
    const frame = decodeDocumentReconcile(wire);
    if (frame.refusal) {
      // The peer's answer to OUR exchange — a fact to surface, never to retry blindly.
      logger.warn("document.reconcile.refused_by_peer", {
        senderAgentId, reason: frame.refusal.reason, terminal: frame.refusal.terminal, correlationId,
      });
      // ACTED ON, not merely surfaced. The comment above has always said "never to retry blindly",
      // and until now nothing downstream could tell a refusal from a success.
      deps.onPeerRefusal?.(ownerAgentId, senderAgentId, frame.refusal.terminal);
      return { ok: true };
    }
    for (const block of frame.documents) {
      if (block.refusal) {
        logger.warn("document.reconcile.refused_by_peer", {
          documentId: block.document_id, senderAgentId,
          reason: block.refusal.reason, terminal: block.refusal.terminal, correlationId,
        });
        deps.onPeerRefusal?.(ownerAgentId, senderAgentId, block.refusal.terminal);
      }
    }
    if (frame.exchange_version !== DOCUMENT_RECONCILE_EXCHANGE_VERSION) {
      const reason =
        `document_reconcile_version: you speak exchange version ${frame.exchange_version} and ` +
        `this holder speaks ${DOCUMENT_RECONCILE_EXCHANGE_VERSION} — upgrade together; there is ` +
        `no dual-speak mode`;
      logger.warn("document.reconcile.version_refused", { senderAgentId, correlationId, reason });
      await deps.sendFrame(
        ownerAgentId, senderAgentId,
        encodeDocumentReconcile({
          type: "document_reconcile",
          exchange_version: DOCUMENT_RECONCILE_EXCHANGE_VERSION,
          documents: [],
          refusal: { reason, terminal: false },
        }),
      );
      return { ok: false, reason: "document_reconcile_version" };
    }
    const reads = reconcileReads(ownerAgentId);
    const replyBlocks = [];
    // One reply frame's payload allowance, shared across its blocks (review F3): headroom under
    // the router's 2 MiB frame ceiling so positions, hashes, and CBOR overhead always fit.
    const replyBudget = { remainingBytes: 1_500_000 };
    for (const block of frame.documents) {
      // THE NOTICE, RECEIVED (R25): a position for a document this holder does not hold, with
      // no genesis attached, IS the invitation pointer — the frame already names the document
      // and the session names the inviter. The answer is our EMPTY position ("I hold nothing;
      // send everything"), and the peer's reply carries the genesis and the lot. Two empty
      // hands stay silent, so nothing ping-pongs.
      if (!block.genesis && !store.getDocument(ownerAgentId, block.document_id)) {
        const peerClaimsAnything =
          block.governance.length > 0 || block.content.length > 0 ||
          block.entries.length > 0 || block.envelopes.length > 0;
        if (peerClaimsAnything) {
          replyBlocks.push({
            document_id: block.document_id,
            governance: [], content: [], refused: [], entries: [], envelopes: [],
          });
          logger.info("document.reconcile.notice_received", {
            documentId: block.document_id, viaAgentId: senderAgentId, correlationId,
          });
        }
        continue;
      }
      // THE JOINER BOOTSTRAP (spec §4 — a joiner is simply very far behind): a block carrying
      // the genesis for a document this holder does not have is the invitation arriving. The
      // anchor is validated the way every genesis is — its hash IS the document id, its
      // signature is the proposer's — and recording it is idempotent. The invitee then derives
      // their own standing (invited) from the entries that follow; their ACCEPT is the ordinary
      // consent-authoring accept.
      if (block.genesis && !store.getDocument(ownerAgentId, block.document_id)) {
        try {
          const genesisEnv = decodeDocumentProposal(block.genesis);
          if (documentIdFromProposal(genesisEnv) !== block.document_id) {
            throw new Error(
              "document_reconcile_genesis_mismatch: the carried genesis does not hash to the " +
                "block's document id — the anchor cannot be swapped",
            );
          }
          // THE ANCHOR IS VERIFIED, NOT TAKEN (P3 review F2): a proposal is only a proposal
          // under its proposer's own signature — an unsigned or forged genesis stored here
          // would attribute a document to someone who never made it, and hand any session
          // peer an unlimited license to grow this store with fabricated documents.
          if (
            !verifySignature(
              genesisEnv.proposer_agent_id,
              buildDocumentProposalTbs(genesisEnv),
              genesisEnv.signature,
            )
          ) {
            throw new Error(
              `document_reconcile_genesis_unsigned: the carried genesis does not verify ` +
                `against its named proposer ${genesisEnv.proposer_agent_id}`,
            );
          }
          // AND IT MUST NAME US (F2's entitlement half): this holder bootstraps only a
          // document it is a party to — the genesis peer, or the subject of an admission
          // carried in the same block. Anything else is a stranger's document and is refused,
          // not stored.
          const namedAsGenesisPeer = genesisEnv.peer_agent_id === ownerAgentId;
          const namedByAdmission = block.entries.some((entryWire) => {
            try {
              const env = decodeDocumentAmendment(entryWire);
              return env.body.kind === "add_holder" && env.body.subject_agent_id === ownerAgentId;
            } catch {
              return false;
            }
          });
          if (!namedAsGenesisPeer && !namedByAdmission) {
            throw new Error(
              "document_reconcile_not_invited: the carried world names this holder nowhere — " +
                "neither the genesis peer nor the subject of any carried admission; a document " +
                "we are no party to is refused, not stored",
            );
          }
          handshake.recordJoined(ownerAgentId, block.genesis, nowMs);
          store.createDocument({
            documentId: block.document_id,
            ownerAgentId,
            // The GENESIS FACT, not the messenger (F6): the peer column is the proposer's —
            // whoever's session happened to carry the frame may be any holder (forwarding).
            peerAgentId: genesisEnv.proposer_agent_id,
            documentType: genesisEnv.document_type,
            properties: genesisEnv.properties,
            status: "active",
            createdAtMs: nowMs,
          });
          logger.info("document.reconcile.joined", {
            documentId: block.document_id, viaAgentId: senderAgentId, correlationId,
          });
        } catch (err: unknown) {
          logger.warn("document.reconcile.genesis_refused", {
            documentId: block.document_id, senderAgentId, correlationId,
            reason: err instanceof Error ? err.message : String(err),
          });
          continue;
        }
      }
      // APPLY FIRST (R12 order: governance, then content). Both doors are the ordinary ones —
      // idempotent, held-until-whole, refusal-recording — so a redelivered exchange changes
      // nothing.
      for (const entryWire of block.entries) {
        try {
          recordAmendmentImpl(ownerAgentId, entryWire, nowMs);
        } catch (err: unknown) {
          logger.warn("document.reconcile.entry_refused", {
            documentId: block.document_id, senderAgentId, correlationId,
            reason: err instanceof Error ? err.message : String(err),
          });
        }
      }
      // SYNC-R35: the sender's SIGNED refusal records — verified against their named refuser
      // and recorded as received rejections, exactly as a directly-sent frame would be. This is
      // how a third holder wedged behind a refused hash learns its name and reason (F5/F8), and
      // how the refusal keeps traveling once the refuser is gone. Idempotent by primary key.
      for (const refusalWire of block.refusals ?? []) {
        try {
          const rej = decodeDocumentRejection(new Uint8Array(refusalWire));
          if (rej.document_id !== block.document_id) {
            throw new Error("document_refusal_document_mismatch: the record names another document");
          }
          if (!verifySignature(rej.rejecting_agent_id, buildDocumentRejectionTbs(rej), rej.signature)) {
            throw new Error(
              `document_rejection_signature_invalid: the refusal claims to come from ` +
                `${rej.rejecting_agent_id} but its signature does not verify against that agent`,
            );
          }
          rejections.recordIncomingRejection(ownerAgentId, rej.document_id, {
            rejectionEnvelopeHash: documentRejectionHash(rej),
            rejectedEnvelopeHash: rej.rejected_envelope_hash,
            reason: rej.reason,
            detail: rej.detail,
            fromAgentId: rej.rejecting_agent_id,
          });
        } catch (err: unknown) {
          logger.warn("document.reconcile.refusal_record_refused", {
            documentId: block.document_id, senderAgentId, correlationId,
            reason: err instanceof Error ? err.message : String(err),
          });
        }
      }
      for (const envWire of block.envelopes) {
        const res = await inbound.receive(ownerAgentId, envWire, nowMs, correlationId);
        if (res.ok && res.admitted) {
          try {
            noticeInboundUpdateImpl(ownerAgentId, envWire);
          } catch { /* the notice is a row; the content is already the truth */ }
          void rewriteFileImpl(ownerAgentId, envWire).catch((err: unknown) => {
            logger.warn("document.reconcile.rewrite_failed", {
              correlationId,
              reason: err instanceof Error ? err.message : String(err),
            });
          });
        }
      }
      const answer = respondToReconcile(reads, senderAgentId, block, replyBudget);
      // SYNC-P5 (spec §9): the block's position IS what this party last claimed — recorded as
      // the display cache the list surface reads (in_sync|behind|unseen). AFTER the entitlement
      // ruling (P5 review F9): a stranger's claimed position is not worth a row. Never consulted
      // for correctness (R44).
      if (!answer.block.refusal && store.getDocument(ownerAgentId, block.document_id)) {
        store.recordPartyView(
          ownerAgentId,
          block.document_id,
          senderAgentId,
          {
            govSeqs: Object.fromEntries(block.governance.map((g) => [g.author, g.seq])),
            contentCounts: Object.fromEntries(block.content.map((c) => [c.author, c.count])),
            refused: [...block.refused],
          },
          nowMs,
        );
      }
      if (answer.block.refusal) {
        // Per-document, on the block (review F4) — a batch never silences one document's no.
        logger.warn("document.reconcile.refused", {
          documentId: block.document_id, senderAgentId,
          reason: answer.block.refusal.reason, terminal: answer.block.refusal.terminal,
          correlationId,
        });
        replyBlocks.push(answer.block);
        continue;
      }
      if (answer.truncated) {
        // The byte budget cut the payload (review F3) — LOUD, never a silently-oversized frame
        // the router would drop as unshaped. The exchange is idempotent: the peer's next
        // initiate picks up from its advanced position.
        logger.warn("document.reconcile.truncated", {
          documentId: block.document_id, senderAgentId, correlationId,
        });
      }
      // Refusal records RIDE replies; they never CAUSE one — counting them here would make any
      // document with one standing refusal answer every exchange forever, and the exchange is
      // terminated by silence. The wedge they exist to cure (F5) always involves a real
      // difference, so they are on board whenever they matter.
      const hasDifference = answer.block.entries.length > 0 || answer.block.envelopes.length > 0;
      if (hasDifference || answer.peerAhead) {
        replyBlocks.push(answer.block);
      }
    }
    if (replyBlocks.length > 0) {
      await deps.sendFrame(
        ownerAgentId, senderAgentId,
        encodeDocumentReconcile({
          type: "document_reconcile",
          exchange_version: DOCUMENT_RECONCILE_EXCHANGE_VERSION,
          documents: replyBlocks,
        }),
      );
    }
    return { ok: true };
  };

  /** SYNC-P3 — step 1: send our position for these documents to a peer. */
  // DOD-M12B-SHUTDOWN-1: THE CHOKE POINT for outbound reconciles. The scheduler is only one of the
  // four callers — `nudgeSeats` and the two invite notices reach here directly, outside it — so
  // gating the scheduler alone left three paths still dialling on the way out. `cello_doc_write`,
  // `cello_doc_publish` and `cello_doc_invite` are all still SERVED during shutdown, because the
  // IPC server is the last thing stopped, so this is not a theoretical window.
  let reconcileStopped = false;

  const initiateReconcile = async (
    ownerAgentId: string,
    peerAgentId: string,
    documentIds: readonly string[],
  ): Promise<{ ok: true } | { ok: false; reason: string }> => {
    if (reconcileStopped) return { ok: false, reason: "daemon_shutting_down" };
    const reads = reconcileReads(ownerAgentId);
    const blocks = documentIds.map((id) => buildReconcileBlock(reads, id));
    const sent = await deps.sendFrame(
      ownerAgentId, peerAgentId,
      encodeDocumentReconcile({
        type: "document_reconcile",
        exchange_version: DOCUMENT_RECONCILE_EXCHANGE_VERSION,
        documents: blocks,
      }),
    );
    if (!sent.ok) return { ok: false, reason: sent.reason ?? "document_reconcile_send_failed" };
    logger.info("document.reconcile.initiated", { peerAgentId, documents: documentIds.length });
    return { ok: true };
  };

  const router = new DocumentFrameRouter({
    inbound,
    handleReconcile,
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
    recordAmendment: recordAmendmentImpl,
    // `_nowMs` unused: the received-rejection row takes its clock where it is written, and the
    // rejection's own SIGNED timestamp is inside the envelope. A second clock read here would put a
    // third time on one event.
    rewriteFile: rewriteFileImpl,
    noticeInboundUpdate: noticeInboundUpdateImpl,
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
    /** DOD-M12B-SHUTDOWN-1 — see the interface. One-way, idempotent, and the single place that
     *  closes the whole class rather than one of the four callers. */
    stopReconciling(): void { reconcileStopped = true; },
    amendments,
    verifySignature,
    holdersFor,
    isCurrentHolder,
    standingOf,
    partySync,
    pendingFor,
    sweepTargets,
    initiateReconcile,
    governanceFrontierFor: (ownerAgentId: string, documentId: string) => {
      const derived = reconcileReads(ownerAgentId).deriveState(documentId);
      if (!derived.ok) {
        // NAMED, not collapsed to null (review F4): the derivation's own reason — a missing
        // genesis, undecodable bytes, a fold refusal — is the thing the operator hunts for,
        // and the old holders gate logged it while this gate ran first and said nothing.
        logger.error("document.frontier.underivable", { documentId, reason: derived.reason });
        return null;
      }
      return [...derived.state.frontier];
    },
    deriveEnded: (ownerAgentId: string, documentId: string) => {
      const derived = reconcileReads(ownerAgentId).deriveState(documentId);
      if (!derived.ok) return null;
      return {
        ended: derived.state.ended,
        // Who the ending still waits on: every participant without a close entry, AND every open
        // invitation — an invited seat IS a seat (Entry 54), so a close cannot settle around it.
        waitingOn: [
          ...[...derived.state.participants].filter(
            (participant) => !derived.state.closedBy.has(participant),
          ),
          ...derived.state.invited,
        ],
      };
    },
    store,
    writePath,
    handshake,
    engine,
    live,
    lifecycle,
    notifications,
    rejections,
    router,
    onDocumentFrame: (agentName, _sessionId, content, senderPubkey, correlationId) =>
      // `agentName` names the owning agent for the session; the router maps it to the owner KEY
      // that scopes the store. The session id and the sender's transport pubkey are unused: a
      // document is bound to its PEER by the handshake, not to whichever session carried the
      // frame, and the envelope's own signed `sender_agent_id` is what the inbound path checks
      // against that binding. Trusting the transport identity instead would let a frame arriving
      // on any session act on any document that session's peer happens to share.
      router.routeSync(agentName, content, Date.now(), correlationId ?? "frame", senderPubkey),
  };
}
