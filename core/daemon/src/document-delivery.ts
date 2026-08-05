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
  isPeerReachable(
    peerAgentId: string,
    correlationId: string,
  ): Promise<{ reachable: boolean; unknownAgent: boolean }>;
  /**
   * Deliver one envelope over a session the transport opens or reuses (§16.4: daemon-chooses by
   * default; `sessionHint` is the one case with audit value — the agent is mid-conversation about
   * the document and wants the discussion and the change in one sealed record).
   */
  /**
   * `ok` means the peer's daemon ANSWERED about this envelope — it is not "the peer liked it".
   * `admitted: false` is a rejection (§3.2's `0x05`), and a rejection IS an ack for delivery
   * purposes: the peer has decided, so there is nothing left to retry. Without the distinction the
   * adapter has to map a rejection onto one of two lies — `ok: true` makes the delivery record say
   * the peer admitted content it refused, and `ok: false` redelivers an envelope the peer has
   * already ruled on, forever, re-triggering their gate and their retry counter until the document
   * stalls for reasons the operator cannot see.
   *
   * `sessionOpened` distinguishes a session this delivery opened from one it reused — the audit
   * distinction §16.4 cares about, and unrecoverable after the fact.
   */
  deliver(input: {
    peerAgentId: string;
    documentId: string;
    envelope: DocumentEnvelopeRow;
    sessionHint?: string;
    correlationId: string;
  }): Promise<
    | {
        ok: true;
        sessionId: string;
        sessionOpened: boolean;
        /**
         * `true` admitted, `false` rejected — both are ACKS, the peer has decided. `null` means the
         * envelope LEFT (or was parked for an offline peer) and no answer has come back yet.
         *
         * The third state is not hedging; both two-valued answers are dishonest for a send whose
         * outcome is unknown. `true` marks the envelope acknowledged in the log while the peer may
         * never have applied it — and the log being right about what the peer holds is the entire
         * reason pending is derived from it. `false` counts a send that WORKED as a failure and
         * re-sends content already in flight.
         */
        admitted: boolean | null;
        rejectionReason?: string;
      }
    | { ok: false; reason: string; detail?: string }
  >;
}

/**
 * Backoff schedule in ms: ~1s, 5s, 30s, 2m, 10m, then the last entry repeats.
 *
 * The final entry IS the cap — there is no separate ceiling constant. There was one, set to 900s,
 * and it was unreachable: the index clamp meant the schedule never produced a value above 600s, so
 * the exported "cap" was a number the code could not emit and the tests were using it as a synonym
 * for "much later". A documented limit the implementation cannot reach is worse than none.
 *
 * Capped at all because the peer coming back online is the event we are waiting for and it can
 * happen at any moment — an uncapped curve leaves a peer that returned after a long absence waiting
 * hours for a delivery that has been ready the whole time.
 */
export const DELIVERY_BACKOFF_MS = [1_000, 5_000, 30_000, 120_000, 600_000] as const;
export const DELIVERY_BACKOFF_CAP_MS = DELIVERY_BACKOFF_MS[DELIVERY_BACKOFF_MS.length - 1];

/**
 * How long to wait for an ACK after a SUCCESSFUL send, before sending again.
 *
 * Deliberately NOT the failure backoff. "How long do I wait after a failure" and "how long do I
 * wait for an answer" are different questions, and reusing the first for the second re-sent a
 * successfully-delivered envelope one second later — and every resend is not free: `sendContent`
 * witnesses a message-leaf hash to the relay and appends a leaf to the session chain, so a
 * never-acked envelope would pollute the peer's sealed conversation record forever.
 */
export const DELIVERY_ACK_TIMEOUT_MS = DELIVERY_BACKOFF_CAP_MS;

/**
 * How many times an envelope may be SENT without ever being acknowledged before the document
 * stalls.
 *
 * A peer that will never answer must eventually stop being treated as a transient. Without a
 * ceiling, an envelope sent to a peer whose client cannot ack — which is every peer until the
 * inbound handler ships on both sides — is re-sent forever and is indistinguishable, in the log
 * and in `list`, from one that is about to land.
 */
export const DELIVERY_MAX_UNACKED_SENDS = 5;

/**
 * A document whose peer cannot be resolved is not transient, so it gets the cap immediately rather
 * than climbing to it — but it DOES get scheduled. See the `no_peer` branch.
 */
export const DELIVERY_UNRESOLVABLE_RETRY_MS = DELIVERY_BACKOFF_CAP_MS;

export function backoffFor(attempts: number): number {
  const idx = Math.min(Math.max(attempts, 0), DELIVERY_BACKOFF_MS.length - 1);
  return DELIVERY_BACKOFF_MS[idx]!;
}

export interface DeliveryTickResult {
  attempted: number;
  delivered: number;
  /** Sent (or parked) with no answer yet — in flight, neither done nor failed. */
  sent: number;
  /** Answered but refused. Acked all the same — the peer has decided. */
  rejected: number;
  deferred: number;
  failed: number;
}

export class DocumentDelivery {
  readonly #store: DocumentStore;
  readonly #transport: DocumentDeliveryTransport;
  readonly #logger: Logger;
  #inFlight: Promise<DeliveryTickResult> | null = null;

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
    opts: { sessionHints?: ReadonlyMap<string, string>; correlationId?: string } = {},
  ): Promise<DeliveryTickResult> {
    // NO RE-ENTRY. Nothing marks a row in-flight until its outcome lands, so a `deliver` slower
    // than the tick interval — a dial to a distant peer is exactly that — would have the next tick
    // return the same rows and dial again: two autonomous sessions and two seals for one envelope,
    // and the loser's markAcked returning false, which logs as if the PEER had redelivered an ack.
    if (this.#inFlight) return this.#inFlight;
    const run = this.#run(ownerAgentId, peerFor, nowMs, opts);
    this.#inFlight = run;
    try {
      return await run;
    } finally {
      this.#inFlight = null;
    }
  }

  async #run(
    ownerAgentId: string,
    peerFor: (documentId: string) => string | null,
    nowMs: number,
    opts: { sessionHints?: ReadonlyMap<string, string>; correlationId?: string },
  ): Promise<DeliveryTickResult> {
    // Minted once per pass and threaded through every event, so an operator can tie a failure back
    // to the lookup that preceded it and the session that carried it. Delivery is precisely the
    // async multi-step flow the convention exists for: lookup, dial, deliver, ack — across ticks
    // and across restarts.
    const correlationId = opts.correlationId ?? `dlv-${ownerAgentId.slice(0, 8)}-${nowMs}`;
    const pending = this.#store.pendingDeliveries(ownerAgentId, nowMs);
    const result: DeliveryTickResult = {
      attempted: 0, delivered: 0, sent: 0, rejected: 0, deferred: 0, failed: 0,
    };

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
        // No peer means the document row is gone or malformed, which is NOT transient — so it goes
        // straight to the cap rather than climbing to it, and crucially it is SCHEDULED. Skipping
        // the schedule made this the one exit that never self-corrects: the rows stayed due on
        // every tick forever, emitting an error line each time, and — because the pending window
        // is ordered and bounded — they filled it and starved every other document. The operator's
        // work on an unrelated document would silently never leave the machine, with the only
        // signal being an error naming a different one.
        this.#logger.error("document.delivery.no_peer", {
          documentId,
          pending: envelopes.length,
          correlationId,
        });
        for (const e of envelopes) {
          this.#store.recordDeliveryAttempt(
            ownerAgentId,
            documentId,
            e.envelopeHash,
            nowMs + DELIVERY_UNRESOLVABLE_RETRY_MS,
          );
        }
        result.failed += envelopes.length;
        continue;
      }

      let reach: { reachable: boolean; unknownAgent: boolean };
      try {
        reach = await this.#transport.isPeerReachable(peerAgentId, correlationId);
      } catch (err: unknown) {
        // A FAILED LOOKUP IS NOT AN OFFLINE PEER. Recording it as "away" would report a directory
        // outage to the operator as their collaborator being absent — an error substituted for a
        // different error, and one that sends them to ask the wrong person.
        this.#logger.warn("document.delivery.lookup_failed", {
          documentId,
          peerAgentId,
          correlationId,
          reason: err instanceof Error ? err.message : String(err),
        });
        this.#defer(ownerAgentId, documentId, envelopes, nowMs);
        result.deferred += envelopes.length;
        continue;
      }

      if (!reach.reachable) {
        // The unknown-agent case is announced AGAINST THE DOCUMENT, not in a separate line that
        // cannot be joined to it. "This address does not resolve" and "your collaborator stepped
        // away" are different things to tell an operator, and the second is what they saw for both.
        this.#logger.info(
          reach.unknownAgent ? "document.delivery.peer_unknown" : "document.delivery.peer_unreachable",
          { documentId, peerAgentId, pending: envelopes.length, correlationId },
        );
        this.#defer(ownerAgentId, documentId, envelopes, nowMs);
        result.deferred += envelopes.length;
        continue;
      }

      for (const envelope of envelopes) {
        result.attempted += 1;
        // CLAIM THE ROW BEFORE DIALING. Scheduling only on the outcome leaves the row due for the
        // whole duration of the dial, and leaves it due FOREVER if the daemon dies mid-dial. The
        // claim is corrected below when the outcome lands.
        const attempts = this.#store.recordDeliveryAttempt(
          ownerAgentId,
          documentId,
          envelope.envelopeHash,
          nowMs + backoffFor(envelope.attempts ?? 0),
        );
        let outcome: Awaited<ReturnType<DocumentDeliveryTransport["deliver"]>>;
        try {
          outcome = await this.#transport.deliver({
            peerAgentId,
            documentId,
            envelope,
            // Per DOCUMENT. One hint applied to every envelope in the pass refused every OTHER
            // document's delivery — their peer's active sessions cannot contain this document's
            // session — so an unrelated update failed and backed off, citing a session the
            // operator never associated with it.
            sessionHint: opts.sessionHints?.get(documentId),
            correlationId,
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

        if (outcome.ok && outcome.admitted === null) {
          // IN FLIGHT. The content left and the peer has not answered.
          this.#store.markDelivered(ownerAgentId, documentId, envelope.envelopeHash, nowMs);
          // RE-SCHEDULE ON THE ACK TIMEOUT, overwriting the pre-dial failure claim. That claim is
          // `backoffFor(attempts)`, which for a first send is ONE SECOND — so a successfully
          // delivered envelope was re-sent a second later, and every resend appends a leaf to the
          // peer's sealed conversation record. The failure backoff answers a different question.
          this.#store.recordDeliveryAttempt(
            ownerAgentId,
            documentId,
            envelope.envelopeHash,
            nowMs + DELIVERY_ACK_TIMEOUT_MS,
          );
          this.#logger.info("document.delivery.sent", {
            documentId,
            envelopeHash: envelope.envelopeHash,
            sessionId: outcome.sessionId,
            sessionOpened: outcome.sessionOpened,
            unackedSends: attempts,
            correlationId,
          });
          result.sent += 1;

          if (attempts >= DELIVERY_MAX_UNACKED_SENDS) {
            // A peer that will never answer must stop being a transient. Otherwise this envelope is
            // re-sent forever and looks, in the log and in `list`, exactly like one about to land.
            this.#store.setDocumentStatus(ownerAgentId, documentId, "stalled");
            this.#logger.error("document.delivery.unacked_limit", {
              documentId,
              envelopeHash: envelope.envelopeHash,
              sends: attempts,
              correlationId,
              detail:
                `this update has been delivered ${attempts} times without the peer's daemon ever ` +
                `confirming it — the document has stopped publishing. Their client may not support ` +
                `shared documents yet.`,
            });
          }
        } else if (outcome.ok) {
          // ACK = the peer's daemon ANSWERED, admitted or not. A rejection is an ack for delivery
          // purposes (§3.2's 0x05): the peer has decided, so there is nothing left to retry, and
          // retrying would re-trigger their gate and their retry counter until the document stalls
          // for reasons the operator cannot see. Supersession is REJECT-1's job, not the worker's.
          const first = this.#store.markAcked(ownerAgentId, documentId, envelope.envelopeHash, nowMs);
          this.#logger.info("document.delivery.session", {
            documentId,
            sessionId: outcome.sessionId,
            opened: outcome.sessionOpened,
            correlationId,
          });
          if (outcome.admitted) {
            this.#logger.info("document.delivery.acked", {
              documentId,
              envelopeHash: envelope.envelopeHash,
              sessionId: outcome.sessionId,
              firstAck: first,
              correlationId,
            });
            result.delivered += 1;
          } else {
            this.#logger.warn("document.delivery.rejected", {
              documentId,
              envelopeHash: envelope.envelopeHash,
              sessionId: outcome.sessionId,
              reason: outcome.rejectionReason,
              correlationId,
            });
            result.rejected += 1;
          }
        } else {
          this.#logger.warn("document.delivery.failed", {
            documentId,
            envelopeHash: envelope.envelopeHash,
            reason: outcome.reason,
            detail: outcome.detail,
            attempts,
            correlationId,
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
