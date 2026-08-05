/**
 * DOD-DOC-DELIVERY-1 — daemon-autonomous delivery (§16.4).
 *
 * Publish writes the envelope to the log and returns. Delivery is somebody else's job, and that
 * somebody is this worker: it derives what is pending FROM THE LOG, checks the peer is reachable
 * before dialing, opens or reuses a session itself, delivers, and records the ack — with zero agent
 * attention on either end. Two agents in opposite time zones sync overnight without either agent
 * doing anything.
 *
 * ── PENDING IS DERIVED, NEVER HELD ────────────────────────────────────────────────────────────
 *
 * "Unacknowledged envelopes I authored" is a WHERE clause over the log, and that is the whole
 * definition. A queue in memory does not survive a restart — the daemon is a long-running local
 * process that gets restarted routinely — and a queue in its own table is a second source of truth
 * that can disagree with the log about what was sent. The attempt counter and the next-attempt
 * time live on the envelope row for the same reason: a backoff that resets on restart is not a
 * backoff, and a daemon restarting in a reconnect loop would hammer an unreachable peer at full
 * rate forever.
 *
 * ── WHY LOOKUP BEFORE DIAL ────────────────────────────────────────────────────────────────────
 *
 * §16.4's design is presence-driven push, but there is no presence subscription today (parked,
 * M14-P4). Without one, the honest substitute is: ask the directory whether the peer is reachable,
 * and if it is not, do not burn a dial — schedule a retry on a capped backoff. Dialing an offline
 * peer to find out it is offline is the same information at much higher cost, and it is the cost
 * that would be paid on every pending envelope, on every tick, for as long as the peer is away.
 */

import type { DocumentStore, DocumentEnvelopeRow } from "./document-store.js";
import type { Logger } from "./types.js";

/**
 * The transport seam. Narrow on purpose (M4 rule: add to an interface only when a failing test or
 * a production behaviour requires it) — the worker's job is scheduling and bookkeeping, and every
 * dial-level concern belongs to the adapter behind this.
 */
export interface DocumentDeliveryTransport {
  /**
   * Is the peer reachable right now? `discovery_lookup` today. Returns false rather than throwing
   * for an ordinary "not online"; a throw means the LOOKUP failed, which is a different fact and
   * must not be recorded as the peer being away.
   */
  isPeerReachable(peerAgentId: string): Promise<boolean>;
  /**
   * Deliver one envelope over a session the transport opens or reuses (§16.4: daemon-chooses by
   * default; `sessionHint` is the one case with audit value — the agent is mid-conversation about
   * the document and wants the discussion and the change in one sealed record).
   */
  deliver(input: {
    peerAgentId: string;
    documentId: string;
    envelope: DocumentEnvelopeRow;
    sessionHint?: string;
  }): Promise<{ ok: true; sessionId: string } | { ok: false; reason: string; detail?: string }>;
}

/** Backoff schedule in ms: ~1s, 5s, 30s, 2m, 10m, then capped. */
export const DELIVERY_BACKOFF_MS = [1_000, 5_000, 30_000, 120_000, 600_000] as const;
/**
 * The cap. Capped rather than unbounded because the peer coming back online is the event we are
 * waiting for and it can happen at any time — an exponential curve with no ceiling would leave a
 * peer that returned after a long absence waiting hours for a delivery that is ready to go.
 */
export const DELIVERY_BACKOFF_CAP_MS = 900_000;

export function backoffFor(attempts: number): number {
  const idx = Math.min(attempts, DELIVERY_BACKOFF_MS.length - 1);
  return Math.min(DELIVERY_BACKOFF_MS[idx] ?? DELIVERY_BACKOFF_CAP_MS, DELIVERY_BACKOFF_CAP_MS);
}

export interface DeliveryTickResult {
  attempted: number;
  delivered: number;
  deferred: number;
  failed: number;
}

export class DocumentDelivery {
  readonly #store: DocumentStore;
  readonly #transport: DocumentDeliveryTransport;
  readonly #logger: Logger;

  constructor(store: DocumentStore, transport: DocumentDeliveryTransport, logger: Logger) {
    this.#store = store;
    this.#transport = transport;
    this.#logger = logger;
  }

  /**
   * One pass over what is due. Returns counts rather than throwing on a per-envelope failure: one
   * unreachable peer must not stop delivery to every other peer, which is precisely the "works
   * only when all nodes are healthy" shape the project forbids.
   */
  async tick(
    ownerAgentId: string,
    peerFor: (documentId: string) => string | null,
    nowMs: number,
    opts: { sessionHint?: string } = {},
  ): Promise<DeliveryTickResult> {
    const pending = this.#store.pendingDeliveries(ownerAgentId, nowMs);
    const result: DeliveryTickResult = { attempted: 0, delivered: 0, deferred: 0, failed: 0 };

    // Group by document so one reachability lookup serves every pending envelope for that peer.
    // Per-envelope lookups would multiply directory traffic by the size of the backlog, which is
    // largest exactly when the peer has been away longest.
    const byDocument = new Map<string, DocumentEnvelopeRow[]>();
    for (const e of pending) {
      const list = byDocument.get(e.documentId);
      if (list) list.push(e);
      else byDocument.set(e.documentId, [e]);
    }

    for (const [documentId, envelopes] of byDocument) {
      const peerAgentId = peerFor(documentId);
      if (peerAgentId === null) {
        // No peer means the document row is gone or malformed. Log it and defer rather than
        // dropping the envelopes: they are the operator's work, and silently abandoning them is
        // the one outcome an append-only log is supposed to make impossible.
        this.#logger.error("document.delivery.no_peer", { documentId, pending: envelopes.length });
        result.failed += envelopes.length;
        continue;
      }

      let reachable: boolean;
      try {
        reachable = await this.#transport.isPeerReachable(peerAgentId);
      } catch (err: unknown) {
        // A FAILED LOOKUP IS NOT AN OFFLINE PEER. Recording it as "away" would report a directory
        // outage to the operator as their collaborator being absent — an error substituted for a
        // different error, and one that sends them to ask the wrong person.
        this.#logger.warn("document.delivery.lookup_failed", {
          documentId,
          peerAgentId,
          reason: err instanceof Error ? err.message : String(err),
        });
        this.#defer(ownerAgentId, documentId, envelopes, nowMs);
        result.deferred += envelopes.length;
        continue;
      }

      if (!reachable) {
        this.#logger.info("document.delivery.peer_unreachable", {
          documentId,
          peerAgentId,
          pending: envelopes.length,
        });
        this.#defer(ownerAgentId, documentId, envelopes, nowMs);
        result.deferred += envelopes.length;
        continue;
      }

      for (const envelope of envelopes) {
        result.attempted += 1;
        let outcome: Awaited<ReturnType<DocumentDeliveryTransport["deliver"]>>;
        try {
          outcome = await this.#transport.deliver({
            peerAgentId,
            documentId,
            envelope,
            sessionHint: opts.sessionHint,
          });
        } catch (err: unknown) {
          // A THROW IS A FAILURE, never a success. Wrapped here rather than left to propagate so
          // one envelope's transport fault does not abandon the rest of the backlog mid-pass.
          outcome = {
            ok: false,
            reason: "document_delivery_threw",
            detail: err instanceof Error ? err.message : String(err),
          };
        }

        if (outcome.ok) {
          // The ack IS the admission (or the rejection — a 0x05 is an ack for delivery purposes;
          // supersession is REJECT-1's job). Recording delivery without an ack would leave the
          // worker believing the peer has content it may never have received.
          const first = this.#store.markAcked(ownerAgentId, documentId, envelope.envelopeHash, nowMs);
          this.#logger.info("document.delivery.acked", {
            documentId,
            envelopeHash: envelope.envelopeHash,
            sessionId: outcome.sessionId,
            firstAck: first,
          });
          result.delivered += 1;
        } else {
          const attempts = this.#store.recordDeliveryAttempt(
            ownerAgentId,
            documentId,
            envelope.envelopeHash,
            nowMs + backoffFor(envelope.attempts ?? 0),
          );
          this.#logger.warn("document.delivery.failed", {
            documentId,
            envelopeHash: envelope.envelopeHash,
            reason: outcome.reason,
            detail: outcome.detail,
            attempts,
          });
          result.failed += 1;
        }
      }
    }

    return result;
  }

  #defer(
    ownerAgentId: string,
    documentId: string,
    envelopes: readonly DocumentEnvelopeRow[],
    nowMs: number,
  ): void {
    for (const e of envelopes) {
      this.#store.recordDeliveryAttempt(
        ownerAgentId,
        documentId,
        e.envelopeHash,
        nowMs + backoffFor(e.attempts ?? 0),
      );
    }
  }
}
