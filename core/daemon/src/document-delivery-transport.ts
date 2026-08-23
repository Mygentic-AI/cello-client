/**
 * DOD-DOC-DELIVERY-2 — the transport behind `DocumentDeliveryTransport` (§16.4).
 *
 * DELIVERY-1 built the scheduler and the bookkeeping against an injected seam. This is the seam's
 * implementation: the first NON-HANDLER consumer of the session machinery, which is what makes it
 * interesting — every other caller of `SessionNegotiator` runs because an agent asked for
 * something, and this one runs because a document has a pending envelope and nobody is watching.
 *
 * ── REUSE BEFORE OPEN, AND WHY THAT ORDER ─────────────────────────────────────────────────────
 *
 * §16.4: "the daemon uses the most recent active session with that peer or opens one". Reuse first,
 * because opening is the expensive half — a directory negotiation, a dial, and a seal — and a
 * backlog of pending envelopes for one peer would otherwise pay it per envelope. It is also the
 * behaviour an operator expects when they are mid-conversation about the document: the change lands
 * in the same sealed record as the discussion. (SYNC-D10: the explicit session hint is deleted —
 * the daemon's reuse-most-recent choice is the whole rule.)
 *
 * ── WHAT AN ACK IS HERE, AND WHAT IT IS NOT ───────────────────────────────────────────────────
 *
 * `sendContent` reports that the content left, or was PARKED at the relay for an offline peer. That
 * is a transport fact. The DoD's ack is a different one — "the peer's daemon confirms admission (or
 * rejection)" — and it can only come from the peer's inbound document handler, which is its own
 * line. So this adapter returns `admitted: null`: SENT, not acked.
 *
 * That third state is not hedging; both two-valued answers are dishonest here. `true` would mark
 * the envelope acknowledged in the log while the peer may never have applied it, and the log being
 * right about what the peer holds is the entire reason pending is derived from it. `false` would
 * count a send that WORKED as a failure and re-send content already in flight — the
 * permanent-redelivery shape this milestone has already fixed once. The worker records the envelope
 * as delivered, leaves it unacked, and asks again on the capped backoff.
 */

// `wireContentHash` is no longer imported here: every outbound hash in this file now comes from
// `SessionNodeManager.contentHashForSession`, which returns the hash and its ALGORITHM together
// (`DOD-M15-SEALWIRE-1` part B2b). A direct call would be a hash computed without deciding — or
// recording — how it was made, which is the state that made a version skew look like a tamper.
import { reachabilityFromDiscovery, DiscoveryUnavailableError } from "./document-reachability.js";
import type { DiscoveryOutcome } from "./cross-node-negotiation.js";
import { LEAF_KIND_DOC } from "./session-relay-client.js";
import type { Logger } from "./types.js";
import { createSessionSuspects, TERMINAL_ISH_REFUSALS } from "./delivery-session-suspects.js";

export interface DocumentTransportDeps {
  /**
   * Take this frame's position in OUR OWN session tree, after it has gone out — the `0x04` doc leaf.
   *
   * `cello_send` does this and the document path did not, and the consequence is not a missing
   * audit record: the tree is the sequence space both sides count in, so a sender that skips it
   * falls one behind per frame and the peer silently drops what it has already consumed.
   */
  /** DOD-M12B-INDEX-1: `assignedSeq` is the relay's position for this frame — the leaf goes THERE,
   *  not at the tail. A document leaf rides the same session sequence counter a message does, so it
   *  is subject to exactly the same divergence. Undefined when no relay answered. */
  appendLeaf(agentName: string, sessionId: string, contentHash: Uint8Array, frameBytes: Uint8Array, correlationId: string, assignedSeq?: number): { placed: boolean; leafIndex: number | null };
  /** The agent this worker delivers for. One worker per attended agent. */
  agentName: string;
  /** `runDiscoveryLookup`, supplied by the composition root — it lives in a closure there. */
  lookupPeer(peerAgentId: string, correlationId: string): Promise<DiscoveryOutcome>;
  /**
   * Close and SEAL a session this adapter opened. §16.4: the autonomous session "still happens
   * because it carries signing, encryption, and the seal" — an opened session left running is a
   * live node the operator did not start and that never produces the sealed record the whole
   * design exists for.
   */
  sealSession(agentName: string, sessionId: string, correlationId: string): Promise<void>;
  /** Active sessions with this peer, most recent LAST. */
  activeSessionsWith(agentName: string, peerAgentId: string): string[];
  /** The existing initiate path: negotiate, dial, create the session node. */
  openSession(
    agentName: string,
    peerAgentId: string,
    correlationId: string,
  ): Promise<{ ok: true; sessionId: string } | { ok: false; reason: string; guidance?: string }>;
  /**
   * `SessionNodeManager.contentHashForSession` — the ONE place that decides how this session's
   * outbound content is hashed, returning the hash and its algorithm together (`DOD-M15-SEALWIRE-1`
   * part B2b). Injected rather than imported so this module keeps its single dependency on the
   * manager, and so a test cannot compute a hash the manager would not.
   */
  contentHashForSession(
    agentName: string,
    sessionId: string,
    content: Uint8Array,
  ): { hash: Uint8Array; alg: string };
  /** `SessionNodeManager.sendContent`. */
  sendContent(
    agentName: string,
    sessionId: string,
    content: Uint8Array,
    contentHash: Uint8Array,
    correlationId: string,
    /**
     * The witnessed DOMAIN — see the note on `DOCUMENT_LEAF_KIND` below.
     *
     * ⚠️ REQUIRED, like its two neighbours, and this interface is why. A function of LOWER arity is
     * assignable to one of higher arity, so an adapter that drops a trailing argument type-checks
     * silently — which is exactly how this parameter was lost for a whole release
     * (*"0.0.145 shipped the fix everywhere except here"*). Optional parameters make that assignment
     * invisible twice over. Required, a dropped argument is a compile error.
     */
    leafKind: number,
    /** `DOD-M15-SEALWIRE-1` part B2b — the algorithm `contentHash` was produced under. */
    contentHashAlg: string,
  ): Promise<
    // DOD-M12B-INDEX-1: `sequenceNumber` is the relay's position for this frame, carried so the
    // leaf can be placed there rather than at the tail. Absent when no relay answered.
    | { ok: true; delivered: true; relayRefusal?: string; sequenceNumber?: number }
    | { ok: true; delivered: false; parked: true; relayRefusal?: string; sequenceNumber?: number }
    | { ok: false; reason: string; error: string; sequenceNumber?: number }
  >;
  logger: Logger;
}

/**
 * Everything this transport sends is document-domain traffic, so 0x04 is the default rather than
 * something each call site remembers. A refusal overrides it with 0x05 — the two are distinguished
 * for the same reason, and only the caller knows which it is holding.
 *
 * WHY IT MATTERS AT ALL. The seal certificate is built by the DIRECTORY from the leaves the RELAY
 * witnessed, never from the sender's local tree. `seal-legibility.ts` excludes doc/reject leaves
 * from `final_message` and from `answered`, and says why: a document update is applied MECHANICALLY
 * by the peer's daemon with no agent involved, so counting one as a reply would let a peer's daemon
 * satisfy the unanswered-tail check on its operator's behalf. Both exclusions were dead code while
 * this path submitted every document leaf as a MESSAGE.
 */
export const DOCUMENT_LEAF_KIND = LEAF_KIND_DOC;

/**
 * The document frame carrier (SYNC-P4: D1/D2/D4 deleted — this used to live in the delivery
 * worker's module). Two capabilities survive: a reachability probe, and putting already-encoded
 * bytes on a session the transport opens or reuses then seals. There is no `deliver` and no ack
 * wait — content confirmation is the peer's position at the next reconcile exchange.
 */
export interface DocumentDeliveryTransport {
  /**
   * Is the peer reachable right now? `discovery_lookup` today. Returns false rather than throwing
   * for an ordinary "not online"; a throw means the LOOKUP failed, which is a different fact and
   * must not be recorded as the peer being away.
   */
  isPeerReachable(
    peerAgentId: string,
    correlationId: string,
  ): Promise<{ reachable: boolean; unknownAgent: boolean }>;
  /**
   * Send already-encoded bytes to a peer over the open-or-reuse-then-seal path. `documentId` is
   * for the log line only. `parked: true` means the relay took it because the peer had no live
   * counterparty — it is NOT with them yet, and only the next exchange proves anything landed.
   */
  sendBytes(input: {
    peerAgentId: string;
    documentId: string;
    bytes: Uint8Array;
    correlationId: string;
    /** The witnessed leaf DOMAIN. Defaults to the document kind (0x04); a refusal passes 0x05. */
    leafKind?: number;
  }): Promise<
    | { ok: true; sessionId: string; sessionOpened: boolean; parked?: boolean }
    | { ok: false; reason: string; detail?: string }
  >;
}

export function createDocumentDeliveryTransport(
  deps: DocumentTransportDeps,
): DocumentDeliveryTransport {
  // DOD-MP-SESSION-RETIRE-1 (remaining half) — sessions this worker has stopped REUSING because
  // they keep answering terminally. Per transport instance, in memory, destroying nothing: see
  // delivery-session-suspects.ts for why `relay_session_gone` is handled here and not by retiring.
  const suspects = createSessionSuspects();

  /**
   * One place that decides what a send outcome says about the SESSION.
   *
   * A refusal is obvious. The subtle case is a send that SUCCEEDED while the relay refused the
   * leaf: the content reached the peer directly and the session's record stopped growing. That is
   * a fact about the session, not about the peer, and reading `ok` alone both hid it and cleared
   * the evidence of every earlier occurrence.
   */
  function noteSendOutcome(
    sessionId: string,
    sent:
      | { ok: true; delivered?: boolean; parked?: boolean; relayRefusal?: string }
      | { ok: false; reason: string; error?: string },
  ): void {
    if (!sent.ok) {
      if (TERMINAL_ISH_REFUSALS.has(sent.reason)) suspects.noteFailure(sessionId, sent.reason);
      return;
    }
    if (sent.relayRefusal !== undefined && TERMINAL_ISH_REFUSALS.has(sent.relayRefusal)) {
      suspects.noteFailure(sessionId, sent.relayRefusal);
      return;
    }
    suspects.noteSuccess(sessionId);
  }

  /**
   * Acquire a session with the peer — the most recent active one, else a fresh dial (SYNC-D10).
   *
   * ONE implementation for every document frame kind. A proposal that opened its own session by a
   * separate code path would drift on which session gets reused and on whether a session this
   * daemon opened is sealed, and both are unrecoverable after the fact.
   */
  async function acquireSession(
    peerAgentId: string,
    correlationId: string,
  ): Promise<
    | { ok: true; sessionId: string; sessionOpened: boolean }
    | { ok: false; reason: string; detail?: string }
  > {
    const active = deps.activeSessionsWith(deps.agentName, peerAgentId);
    // Most recent LAST — activeSessionsWith is ordered oldest-first by the daemon's adapter.
    //
    // DOD-MP-SESSION-RETIRE-1 — a session that has answered terminally more than once is skipped
    // rather than retired. If it really is finished, delivery routes around it instead of
    // resubmitting into it forever; if the relay merely bounced and lost its memory, the cost is
    // one extra session and the old one is untouched. Nothing is destroyed on an ambiguous signal.
    const reusable = active.filter((id) => !suspects.isSuspect(id));
    if (reusable.length > 0) {
      return { ok: true, sessionId: reusable[reusable.length - 1]!, sessionOpened: false };
    }
    if (active.length > 0) {
      deps.logger.warn("document.delivery.session.bypassed", {
        peerAgentId,
        skipped: active.length,
        correlationId,
        impact:
          "every open session with this holder has refused terminally more than once — opening a " +
          "fresh one; the old sessions are left intact",
      });
    }
    const opened = await deps.openSession(deps.agentName, peerAgentId, correlationId);
    if (!opened.ok) {
      // The upstream reason verbatim. `document_delivery_threw` is reserved for a genuine
      // programming fault; a dial that was refused should say it was refused.
      return { ok: false, reason: opened.reason, detail: opened.guidance };
    }
    return { ok: true, sessionId: opened.sessionId, sessionOpened: true };
  }

  return {
    async isPeerReachable(peerAgentId: string, correlationId: string) {
      // The PASS's correlation id, threaded through. A per-peer constant was fabricated here, so
      // every `directory.discovery.lookup` this worker ever emitted carried the same string and
      // none of them joined to the pass — breaking the thread at exactly the hop an operator needs
      // when nothing is syncing.
      const outcome = await deps.lookupPeer(peerAgentId, correlationId);
      // Throws on everything that is not an answer about the peer — see document-reachability.ts.
      // The worker treats the throw as `lookup_failed` and keeps it out of the offline-peer count.
      // The unknown-agent bit is RETURNED rather than logged here, so the worker can announce it
      // against the document it belongs to.
      return reachabilityFromDiscovery(outcome);
    },

    async sendBytes(input) {
      const { peerAgentId, documentId, bytes, correlationId } = input;
      const session = await acquireSession(peerAgentId, correlationId);
      if (!session.ok) return session;

      // THE WIRE HASH, domain-separated. This was `sha256(bytes)`, and the receiver recomputes
      // `sha256(0x00 || bytes)` for every frame — so the send reported success, `parked: false`,
      // and the peer discarded it at the authenticity check before the document layer was ever
      // consulted. Found by two real daemons; no in-process test could see it, because both sides
      // of those compute the hash with the same function.
      // B2b: one decision point for the hash AND its algorithm. This site is the reason that matters
      // — it is one of the two that got the ORIGINAL hash expression wrong, and the failure was
      // invisible from here (see the paragraph above). Four sites independently deciding whether to
      // salt would be that same defect with a worse outcome: a message hashed one way and labelled
      // another is refused by every peer, including a correct one.
      const { hash, alg } = deps.contentHashForSession(deps.agentName, session.sessionId, bytes);
      const sent = await deps.sendContent(deps.agentName, session.sessionId, bytes, hash, correlationId, input.leafKind ?? DOCUMENT_LEAF_KIND, alg);
      // DOD-MP-SESSION-RETIRE-1 — a working send breaks the run; a terminal-ish answer extends it.
      //
      // `relayRefusal` IS CHECKED FIRST, and that is the whole unit. The fully-sealed case answers
      // `relay_session_gone`, which is deliberately not terminal — so the send warns, delivers
      // directly, and returns SUCCESS for a leaf the relay never witnessed. Reading `ok` alone made
      // the counter unreachable AND made every such send clear it, so a session whose record was
      // permanently gone stayed in rotation forever.
      noteSendOutcome(session.sessionId, sent);
      if (!sent.ok) {
        // Sealed even on a send failure, for the same reason as below: a session this daemon opened
        // and walked away from is a live node the operator never started. A failed send is exactly
        // when that is most likely to happen.
        if (session.sessionOpened) await deps.sealSession(deps.agentName, session.sessionId, correlationId);
        return { ok: false, reason: sent.reason, detail: sent.error };
      }
      // APPEND OUR OWN LEAF, exactly as `cello_send` does after a successful send.
      //
      // Not bookkeeping. The daemon's session tree is the sequence space both sides count in, and a
      // sender that puts content on the wire without taking its leaf position leaves its own chain
      // one behind for every frame it sends. The peer then sees a sequence it has already consumed
      // and drops the frame — silently, because a duplicate is a normal event, so nothing is logged
      // anywhere and the send reports success with `parked: false`.
      //
      // It hid behind an accident: with no prior traffic every frame is sequence 0, so the FIRST
      // document frame in a fresh session arrives and everything after it does not. Adding one
      // ordinary message before the exchange moved the failure earlier, which is what named the
      // cause.
      // THE FRAME BYTES, not the hash. When the leaf cannot be placed yet the bytes are held, and a
      // hold is released by writing its content to the transcript — so handing this the hash would
      // put 32 bytes of digest in the operator's transcript as a message they sent, and annex the
      // same 32 bytes into the sealed record.
      const placed = deps.appendLeaf(deps.agentName, session.sessionId, hash, bytes, correlationId, sent.sequenceNumber);
      deps.logger.info("document.frame.sent", {
        documentId,
        // Whether the leaf is IN the chain yet. This hook is delivery-critical — a sender that skips
        // its leaf falls one behind per frame and the peer silently drops what it has already
        // consumed — so "sent" must not read the same when the leaf is merely held.
        leafCommitted: placed.placed,
        leafIndex: placed.leafIndex,
        sessionId: session.sessionId,
        sessionOpened: session.sessionOpened,
        bytes: bytes.length,
        parked: sent.delivered === false,
        correlationId,
      });
      if (session.sessionOpened) await deps.sealSession(deps.agentName, session.sessionId, correlationId);
      // `parked` SURVIVES THE RETURN. It was computed one line above, logged, and discarded — and a
      // caller that reads `ok` alone cannot tell "the holder has it" from "the relay is holding it
      // because the holder had no live counterparty". For an amendment that difference is the whole
      // fact: there is no ack frame, so a caller which clears its debt on `ok` loses the membership
      // change the moment the relay parks it.
      return {
        ok: true,
        sessionId: session.sessionId,
        sessionOpened: session.sessionOpened,
        parked: sent.delivered === false,
      };
    },

  };
}

export { DiscoveryUnavailableError };
