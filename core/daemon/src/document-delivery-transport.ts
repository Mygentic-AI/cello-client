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
 * in the same sealed record as the discussion, without anyone passing a session hint.
 *
 * An explicit `sessionHint` overrides the choice but NOT the validation — a hint naming a session
 * that is not active with this peer is refused rather than silently replaced by the daemon's own
 * pick, because the one reason to pass a hint is to control which sealed record the change lands
 * in, and quietly choosing a different one defeats exactly that.
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

import type { DocumentDeliveryTransport } from "./document-delivery.js";
import { wireContentHash } from "./wire-content-hash.js";
import type { DocumentEnvelopeRow } from "./document-store.js";
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
  appendLeaf(agentName: string, sessionId: string, contentHash: Uint8Array, correlationId: string): void;
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
  /** `SessionNodeManager.sendContent`. */
  sendContent(
    agentName: string,
    sessionId: string,
    content: Uint8Array,
    contentHash: Uint8Array,
    correlationId: string,
    /** The witnessed DOMAIN — see the note on `DOCUMENT_LEAF_KIND` below. */
    leafKind?: number,
  ): Promise<
    | { ok: true; delivered: true; relayRefusal?: string }
    | { ok: true; delivered: false; parked: true; relayRefusal?: string }
    | { ok: false; reason: string; error: string }
  >;
  /** Encode a document envelope row onto the wire, and its content hash. */
  encodeEnvelope(envelope: DocumentEnvelopeRow): { bytes: Uint8Array; hash: Uint8Array };
  /**
   * Wait for the peer to ANSWER this envelope, bounded. Resolves true if the ack landed.
   *
   * The seal below tears the session down, and the teardown drops any content still held for
   * ordering — so an ack that arrives correctly and is held for a gap is DELETED rather than
   * applied. Measured on a live daemon: the ack was sent, logged `session.content.held`, and the
   * session was destroyed three seconds later with it still buffered. The sender then re-sent the
   * envelope every tick until the unacked ceiling retired it.
   *
   * Waiting here is deliberately indifferent to WHY the answer is slow — held for ordering, a slow
   * relay, a busy peer. The rule is simply that we do not tear down the channel an answer is due
   * on until it has arrived or we have given up on it.
   */
  /** Waits for THE DIALED HOLDER'S answer — any other holder's ack must not resolve it (H1). */
  awaitAck(
    envelopeHash: string,
    expectedAckerAgentId: string,
    timeoutMs: number,
  ): Promise<{ admitted: boolean } | null>;
  /**
   * Try to fill this session's ordering gaps, so anything HELD can be released.
   *
   * Without it the grace above cannot help in the very case it was written for. An ack whose
   * canonical sequence lands ahead of our tree is HELD, and held content is not routed to the
   * document layer at all — it waits for `#releaseHeld`, which only runs when the missing
   * in-between sequence arrives. So the ack sits in a buffer, nothing settles, the grace expires in
   * full, and the seal then discards it. The wait alone converted a fast silent failure into a slow
   * one.
   *
   * A no-op when the session has no gap, so the ordinary delivery pays nothing.
   */
  drainHeld(sessionId: string, correlationId: string): Promise<void>;
  logger: Logger;
}

/**
 * How long a session WE opened stays up waiting for the peer's answer.
 *
 * Sized against the observed round trip, not guessed: on a live cross-region session the ack was
 * on the wire ~375ms after the frame landed, and the seal ceremony itself takes ~3s. Ten seconds
 * covers a slow relay and a park-and-recover round without keeping an autonomous session alive
 * long enough to be mistaken for a conversation.
 */
export const DELIVERY_ACK_GRACE_MS = 10_000;

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
   * Acquire a session with the peer — the hint, then the most recent active one, then a fresh dial.
   *
   * ONE implementation for every document frame kind. A proposal that opened its own session by a
   * separate code path would drift on which session gets reused and on whether a session this
   * daemon opened is sealed, and both are unrecoverable after the fact.
   */
  async function acquireSession(
    peerAgentId: string,
    sessionHint: string | undefined,
    correlationId: string,
  ): Promise<
    | { ok: true; sessionId: string; sessionOpened: boolean }
    | { ok: false; reason: string; detail?: string }
  > {
    const active = deps.activeSessionsWith(deps.agentName, peerAgentId);
    if (sessionHint !== undefined) {
      if (!active.includes(sessionHint)) {
        // Refused, not replaced. The only reason to pass a hint is to control which sealed record
        // the change lands in; quietly substituting the daemon's own pick would defeat exactly
        // that, and it would do so silently.
        return {
          ok: false,
          reason: "document_session_hint_invalid",
          detail:
            `session ${sessionHint.slice(0, 16)}… is not an active session with ${peerAgentId}, ` +
            `so the change cannot be placed in that record`,
        };
      }
      if (suspects.isSuspect(sessionHint)) {
        // HONOURED, NOT SUBSTITUTED — the only reason to pass a hint is to control which sealed
        // record the change lands in, and quietly picking another session would defeat exactly
        // that. But a caller aiming at a session whose record is gone should be told.
        deps.logger.warn("document.delivery.session.hint_suspect", {
          peerAgentId,
          sessionId: sessionHint,
          correlationId,
          impact:
            "this session has answered terminally more than once — the change is being placed in " +
            "it as asked, and its record may no longer be growing",
        });
      }
      return { ok: true, sessionId: sessionHint, sessionOpened: false };
    }
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
      const { peerAgentId, documentId, bytes, sessionHint, correlationId } = input;
      const session = await acquireSession(peerAgentId, sessionHint, correlationId);
      if (!session.ok) return session;

      // THE WIRE HASH, domain-separated. This was `sha256(bytes)`, and the receiver recomputes
      // `sha256(0x00 || bytes)` for every frame — so the send reported success, `parked: false`,
      // and the peer discarded it at the authenticity check before the document layer was ever
      // consulted. Found by two real daemons; no in-process test could see it, because both sides
      // of those compute the hash with the same function.
      const hash = wireContentHash(bytes);
      const sent = await deps.sendContent(deps.agentName, session.sessionId, bytes, hash, correlationId, input.leafKind ?? DOCUMENT_LEAF_KIND);
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
      deps.appendLeaf(deps.agentName, session.sessionId, hash, correlationId);
      deps.logger.info("document.frame.sent", {
        documentId,
        sessionId: session.sessionId,
        sessionOpened: session.sessionOpened,
        bytes: bytes.length,
        parked: sent.delivered === false,
        correlationId,
      });
      if (session.sessionOpened) await deps.sealSession(deps.agentName, session.sessionId, correlationId);
      return { ok: true, sessionId: session.sessionId, sessionOpened: session.sessionOpened };
    },

    async deliver(input) {
      const { peerAgentId, documentId, envelope, sessionHint, correlationId } = input;

      const session = await acquireSession(peerAgentId, sessionHint, correlationId);
      if (!session.ok) return session;
      const { sessionId, sessionOpened } = session;

      const { bytes, hash } = deps.encodeEnvelope(envelope);
      const sent = await deps.sendContent(deps.agentName, sessionId, bytes, hash, correlationId, DOCUMENT_LEAF_KIND);
      // DOD-MP-SESSION-RETIRE-1 — same accounting on the envelope path. Both paths acquire through
      // `acquireSession`, so a session judged on one is skipped by the other; splitting the record
      // would let a session that keeps refusing envelopes still be picked for the next frame.
      noteSendOutcome(sessionId, sent);
      if (sent.ok) deps.appendLeaf(deps.agentName, sessionId, hash, correlationId);
      if (!sent.ok) {
        // SEAL WHAT WE OPENED, on the failure path too. This branch walked away from a session it
        // had just dialled — a live node the operator never started, with no sealed record, which
        // is precisely what the rule twenty lines below says the seal exists to prevent. A failed
        // send is when it is most likely to happen, not least.
        if (sessionOpened) await deps.sealSession(deps.agentName, sessionId, correlationId);
        return { ok: false, reason: sent.reason, detail: sent.error };
      }

      deps.logger.info("document.delivery.sent", {
        documentId,
        sessionId,
        sessionOpened,
        parked: sent.delivered === false,
        correlationId,
      });

      // SEAL what we opened. §16.4: the autonomous session still happens because it carries
      // signing, encryption and the seal — the ceremony goes to zero, the seal does not. A session
      // this adapter opened and walked away from is a live node the operator never started, and
      // the sealed record the design exists to produce is never produced. A session we REUSED is
      // not ours to close: its owner decides when that conversation ends.
      // PARKED CONTENT CANNOT BE ACKED, so waiting for one is spending the pass budget on a
      // certainty. `delivered: false` means the peer was offline and the relay took the frame; the
      // ack comes whenever they next come online, which is not within any grace. Waiting here also
      // fired `ack_grace_expired` on a designed, benign state — a warning on the normal case.
      const answerPossible = sent.delivered !== false;
      // The peer's ANSWER, when one arrives inside the grace. Reported back as `admitted` so the
      // worker records a settled delivery instead of an in-flight one.
      let settlement: { admitted: boolean } | null = null;
      if (sessionOpened && answerPossible && input.ackGraceMs > 0) {
        // WAIT FOR THE ANSWER BEFORE TEARING DOWN THE CHANNEL IT COMES BACK ON.
        //
        // The seal destroys the session, and the teardown drops content still held for ordering.
        // Sealing straight after the send therefore raced the peer's ack and, on a real network,
        // lost: 90 re-sends of one envelope against a ceiling of 5.
        //
        // A REUSED session is untouched by this — it is not ours to close, so its owner keeps it
        // alive and the ack has all the time it needs. That asymmetry is exactly why every spine
        // enforcer passed: they open a conversation first, so the worker always reused one.
        // The SMALLER of this envelope's share and the standard grace. The caller spends a budget
        // across the whole sweep pass; see DELIVERY_ACK_GRACE_BUDGET_MS.
        const graceMs = Math.min(DELIVERY_ACK_GRACE_MS, input.ackGraceMs);
        // UNSTICK BEFORE WAITING. If the ack is already sitting in the hold buffer, no amount of
        // waiting produces it — the release is driven by the missing sequence arriving, not by
        // time. Ordering-complete sessions return immediately.
        // CONTAINED. A drain failure must not fail a delivery whose content has already left — the
        // same contract the ack itself has. Uncontained, a relay hiccup during the drain would
        // surface as `document_delivery_threw` and re-send content the peer already holds.
        await deps.drainHeld(sessionId, correlationId).catch((err: unknown) => {
          deps.logger.warn("document.delivery.drain_threw", {
            documentId,
            sessionId,
            correlationId,
            reason: err instanceof Error ? err.message : String(err),
          });
        });
        settlement = await deps.awaitAck(envelope.envelopeHash, input.peerAgentId, graceMs);
        if (!settlement) {
          // NOT a failure of the send — the content left and the peer may still answer later. Said
          // out loud because a seal that discards a held ack is otherwise invisible, and this is
          // the only moment anything knows it is about to happen.
          deps.logger.warn("document.delivery.ack_grace_expired", {
            documentId,
            envelopeHash: envelope.envelopeHash,
            sessionId,
            graceMs,
            correlationId,
          });
        }
      }
      // SEAL WHAT WE OPENED — unconditionally, whether or not we waited. The wait is about giving
      // an answer time to arrive; the seal is about never leaving an autonomous session running.
      // Making the seal conditional on the wait would trade one defect for a worse one.
      if (sessionOpened) {
        await deps.sealSession(deps.agentName, sessionId, correlationId);
      }

      // SENT, NOT ACKED — `admitted: null`. The content left (or was parked for an offline peer),
      // which is a transport fact; the DoD's ack is the peer's daemon confirming admission, and
      // that answer comes from the inbound document handler, which is its own line.
      //
      // Neither of the two-valued answers is available honestly. `true` would mark the envelope
      // acknowledged in the log while the peer may never have applied it — and the log being right
      // about what the peer holds is the entire reason pending is derived from it. `false` would
      // count a send that WORKED as a failure and re-send content already in flight, which is the
      // permanent-redelivery shape this milestone already fixed once.
      // THE ANSWER IF WE HAVE IT. `null` still means "left, unanswered" — the honest third state —
      // but an ack that landed inside the grace is no longer thrown away as if it had not.
      return {
        ok: true,
        sessionId,
        sessionOpened,
        admitted: settlement ? settlement.admitted : null,
        // PARKED, reported rather than inferred. The worker cannot tell it from an ordinary
        // awaiting-answer send otherwise, and the two need different retry schedules.
        parked: sent.delivered === false,
      };
    },
  };
}

export { DiscoveryUnavailableError };
