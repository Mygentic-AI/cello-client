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
import type { Logger } from "./types.js";

export interface DocumentTransportDeps {
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
  ): Promise<
    | { ok: true; delivered: true }
    | { ok: true; delivered: false; parked: true }
    | { ok: false; reason: string; error: string }
  >;
  /** Encode a document envelope row onto the wire, and its content hash. */
  encodeEnvelope(envelope: DocumentEnvelopeRow): { bytes: Uint8Array; hash: Uint8Array };
  logger: Logger;
}

export function createDocumentDeliveryTransport(
  deps: DocumentTransportDeps,
): DocumentDeliveryTransport {
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
      return { ok: true, sessionId: sessionHint, sessionOpened: false };
    }
    // Most recent LAST — activeSessionsWith is ordered oldest-first by the daemon's adapter.
    if (active.length > 0) return { ok: true, sessionId: active[active.length - 1]!, sessionOpened: false };
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
      const sent = await deps.sendContent(deps.agentName, session.sessionId, bytes, hash, correlationId);
      if (!sent.ok) {
        // Sealed even on a send failure, for the same reason as below: a session this daemon opened
        // and walked away from is a live node the operator never started. A failed send is exactly
        // when that is most likely to happen.
        if (session.sessionOpened) await deps.sealSession(deps.agentName, session.sessionId, correlationId);
        return { ok: false, reason: sent.reason, detail: sent.error };
      }
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
      const sent = await deps.sendContent(deps.agentName, sessionId, bytes, hash, correlationId);
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
      return { ok: true, sessionId, sessionOpened, admitted: null };
    },
  };
}

export { DiscoveryUnavailableError };
