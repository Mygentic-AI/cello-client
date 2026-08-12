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
  /**
   * Send already-encoded bytes to a peer over the same open-or-reuse-then-seal path `deliver` uses.
   *
   * Exists for the frames that are NOT in the envelope log and therefore have no delivery record to
   * schedule: a proposal (there is no document yet), an ack, a rejection. Those still have to reach
   * the peer, and the alternative — a second implementation of session acquisition — would drift on
   * exactly the things that matter here: which session gets reused, and whether one this daemon
   * opened gets sealed.
   *
   * `documentId` is for the log line only; nothing about the send depends on it.
   */
  sendBytes(input: {
    peerAgentId: string;
    documentId: string;
    bytes: Uint8Array;
    sessionHint?: string;
    correlationId: string;
    /**
     * The witnessed leaf DOMAIN. Defaults to the document kind (0x04); a refusal passes 0x05.
     * Only the caller knows which frame it is holding, and the directory's legibility rules
     * discriminate on it — see `DOCUMENT_LEAF_KIND` in document-delivery-transport.ts.
     */
    leafKind?: number;
  }): Promise<
    | { ok: true; sessionId: string; sessionOpened: boolean }
    | { ok: false; reason: string; detail?: string }
  >;
  deliver(input: {
    peerAgentId: string;
    documentId: string;
    envelope: DocumentEnvelopeRow;
    sessionHint?: string;
    correlationId: string;
    /**
     * How long THIS envelope may hold an opened session waiting for the peer's ack.
     *
     * A BUDGET SPENT ACROSS THE PASS, not a per-envelope allowance. The wait is awaited inside
     * three nested sequential loops — agents, then documents, then envelopes — so a fixed 10s each
     * meant a backlog of 100 to one silent peer could burn ~1000 seconds during which NO other
     * agent's documents were swept at all. And a peer that never acks is the ordinary case during a
     * version rollout, which this repo does continuously because both sides float `latest`.
     *
     * Zero means do not wait. The seal still happens; only the grace is skipped.
     */
    ackGraceMs: number;
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
        /**
         * The relay took it because the peer had no live counterparty on that session.
         *
         * Distinct from `admitted: null`, which covers both a live send awaiting an answer and this.
         * The two want different retry schedules and were given the same one — see the scheduling
         * branch in `#run`.
         */
        parked: boolean;
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
/**
 * Total ack-grace one sweep pass may spend, across every agent, document and envelope in it.
 *
 * The wait exists so a session we opened is not torn down before the peer's answer arrives. It is
 * capped as a PASS budget because the loops it sits inside are sequential: a per-envelope allowance
 * meant one silent peer with a backlog could hold the sweep for the better part of an hour, and the
 * only symptom would be other agents' documents quietly not syncing.
 *
 * 30s ≈ three full graces. Enough for the ordinary case (one or two opened sessions per pass, ack
 * back in well under a second) without letting an unresponsive peer own the pass.
 */
export const DELIVERY_ACK_GRACE_BUDGET_MS = 30_000;

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
  /**
   * One pass over what is due, PER (document, holder). Returns counts rather than throwing on a
   * per-target failure: one unreachable HOLDER must not stop delivery to any other — the same
   * "works only when all nodes are healthy" shape the project forbids, now per holder.
   */
  async tick(
    ownerAgentId: string,
    holdersFor: (documentId: string) => string[] | null,
    nowMs: number,
    opts: {
      sessionHints?: ReadonlyMap<string, string>;
      correlationId?: string;
      /** Our own wire sender id. Defaults to the owner key for callers whose ids coincide. */
      senderAgentId?: string;
    } = {},
  ): Promise<DeliveryTickResult> {
    if (this.#inFlight) return this.#inFlight;
    const run = this.#run(ownerAgentId, holdersFor, nowMs, opts);
    this.#inFlight = run;
    try {
      return await run;
    } finally {
      this.#inFlight = null;
    }
  }

  async #run(
    ownerAgentId: string,
    holdersFor: (documentId: string) => string[] | null,
    nowMs: number,
    opts: {
      sessionHints?: ReadonlyMap<string, string>;
      correlationId?: string;
      senderAgentId?: string;
    },
  ): Promise<DeliveryTickResult> {
    let graceBudgetRemainingMs = DELIVERY_ACK_GRACE_BUDGET_MS;
    const correlationId = opts.correlationId ?? `dlv-${ownerAgentId.slice(0, 8)}-${nowMs}`;
    const senderAgentId = opts.senderAgentId ?? ownerAgentId;

    // LEGACY bilateral rows gain their per-holder twin before anything is read — idempotent
    // insurance, journaled (Entry 14): pre-fan-out backlogs are near-empty at alpha.
    this.#store.backfillBilateralDeliveries(ownerAgentId, senderAgentId, nowMs);

    const pending = this.#store.pendingHolderDeliveries(ownerAgentId, nowMs);
    const result: DeliveryTickResult = {
      attempted: 0, delivered: 0, sent: 0, rejected: 0, deferred: 0, failed: 0,
    };

    // Grouped (document, holder): one derivation and one reachability probe serve every pending
    // envelope for that pair.
    const byDocument = new Map<string, Map<string, Array<{ attempts: number; envelope: DocumentEnvelopeRow }>>>();
    for (const p of pending) {
      let holders = byDocument.get(p.documentId);
      if (!holders) {
        holders = new Map();
        byDocument.set(p.documentId, holders);
      }
      const list = holders.get(p.holderAgentId);
      if (list) list.push(p);
      else holders.set(p.holderAgentId, [p]);
    }

    for (const [documentId, holderGroups] of byDocument) {
      const currentHolders = holdersFor(documentId);
      if (currentHolders === null) {
        // The document row is gone or its chain does not derive — NOT transient. Scheduled at
        // the cap so the rows never starve anything, exactly the old no_peer discipline.
        this.#logger.error("document.delivery.no_holders", {
          documentId,
          pending: [...holderGroups.values()].reduce((n, l) => n + l.length, 0),
          correlationId,
        });
        for (const [holder, rows] of holderGroups) {
          for (const r of rows) {
            this.#store.scheduleHolderRetry(
              ownerAgentId, documentId, r.envelope.envelopeHash, holder,
              nowMs + DELIVERY_UNRESOLVABLE_RETRY_MS,
            );
          }
          result.failed += rows.length;
        }
        continue;
      }
      const currentSet = new Set(currentHolders);

      for (const [holderAgentId, rows] of holderGroups) {
        // A holder the arrangement no longer includes — removed, or never derivable — is
        // RETIRED, announced: our decision, not evidence about them (DOD-MP-REMOVE-1's
        // delivery-stop clause, generalized per holder).
        if (
          !currentSet.has(holderAgentId) ||
          this.#store.memberRemoved(ownerAgentId, documentId, holderAgentId).removed
        ) {
          const retiredHashes = this.#store.abandonHolderDeliveries(
            ownerAgentId, documentId, holderAgentId, nowMs,
          );
          for (const hash of retiredHashes) {
            this.#store.reconcileEnvelopeSettlement(ownerAgentId, documentId, hash, nowMs);
          }
          this.#logger.info("document.delivery.peer_removed", {
            documentId, holderAgentId, retired: retiredHashes.length, correlationId,
          });
          continue;
        }

        let reach: { reachable: boolean; unknownAgent: boolean };
        try {
          reach = await this.#transport.isPeerReachable(holderAgentId, correlationId);
        } catch (err: unknown) {
          // A FAILED LOOKUP IS NOT AN OFFLINE HOLDER — deferred, per holder, without an attempt.
          this.#logger.warn("document.delivery.lookup_failed", {
            documentId, holderAgentId, correlationId,
            reason: err instanceof Error ? err.message : String(err),
          });
          for (const r of rows) {
            // Deferrals ESCALATE the schedule (an offline holder must not be redialed at full
            // rate forever) without touching the SENDS ceiling — waiting is not sending.
            this.#store.recordHolderAttempt(
              ownerAgentId, documentId, r.envelope.envelopeHash, holderAgentId,
              nowMs + backoffFor(r.attempts),
            );
          }
          result.deferred += rows.length;
          continue;
        }
        if (!reach.reachable) {
          this.#logger.info(
            reach.unknownAgent ? "document.delivery.peer_unknown" : "document.delivery.peer_unreachable",
            { documentId, holderAgentId, pending: rows.length, correlationId },
          );
          for (const r of rows) {
            this.#store.recordHolderAttempt(
              ownerAgentId, documentId, r.envelope.envelopeHash, holderAgentId,
              nowMs + backoffFor(r.attempts),
            );
          }
          result.deferred += rows.length;
          continue;
        }

        for (const row of rows) {
          const envelope = row.envelope;
          result.attempted += 1;
          // CLAIM THE ROW BEFORE DIALING — due-forever-on-crash-mid-dial is the same hazard it
          // always was, per holder now.
          this.#store.recordHolderAttempt(
            ownerAgentId, documentId, envelope.envelopeHash, holderAgentId,
            nowMs + backoffFor(row.attempts),
          );
          let outcome: Awaited<ReturnType<DocumentDeliveryTransport["deliver"]>>;
          const graceStartedAt = Date.now();
          try {
            outcome = await this.#transport.deliver({
              peerAgentId: holderAgentId,
              documentId,
              envelope,
              ackGraceMs: Math.max(0, graceBudgetRemainingMs),
              sessionHint: opts.sessionHints?.get(documentId),
              correlationId,
            });
          } catch (err: unknown) {
            outcome = {
              ok: false,
              reason: "document_delivery_threw",
              detail: err instanceof Error ? err.message : String(err),
            };
          } finally {
            graceBudgetRemainingMs -= Date.now() - graceStartedAt;
          }

          if (outcome.ok && outcome.admitted === null) {
            // IN FLIGHT for THIS holder. Parked and live sends want DIFFERENT retry schedules,
            // but both LEFT the machine — the sent-vs-never-left surface counts either (review
            // M7: reporting relay-parked content as "never left" mislabels a delivery that the
            // relay is holding for them).
            this.#store.markHolderDelivered(
              ownerAgentId, documentId, envelope.envelopeHash, holderAgentId, nowMs,
            );
            const sends = this.#store.recordHolderSend(
              ownerAgentId, documentId, envelope.envelopeHash, holderAgentId,
            );
            this.#store.scheduleHolderRetry(
              ownerAgentId, documentId, envelope.envelopeHash, holderAgentId,
              nowMs + (outcome.parked ? backoffFor(row.attempts) : DELIVERY_ACK_TIMEOUT_MS),
            );
            this.#logger.info("document.delivery.sent", {
              documentId,
              envelopeHash: envelope.envelopeHash,
              holderAgentId,
              sessionId: outcome.sessionId,
              sessionOpened: outcome.sessionOpened,
              unackedSends: sends,
              correlationId,
            });
            result.sent += 1;

            if (sends >= DELIVERY_MAX_UNACKED_SENDS) {
              // THIS HOLDER is exhausted — retired, announced, and only theirs. The document
              // stalls ONLY when every current holder is exhausted: one silent peer stopping a
              // living collaboration is the exact availability failure the milestone forbids.
              this.#store.abandonSingleHolderDelivery(
                ownerAgentId, documentId, envelope.envelopeHash, holderAgentId, nowMs,
              );
              this.#store.reconcileEnvelopeSettlement(
                ownerAgentId, documentId, envelope.envelopeHash, nowMs,
              );
              this.#logger.error("document.delivery.unacked_limit", {
                documentId,
                envelopeHash: envelope.envelopeHash,
                holderAgentId,
                sends,
                correlationId,
                detail:
                  `this update has been delivered ${sends} times to this holder without their ` +
                  `daemon ever confirming it — delivery TO THEM is retired; every other holder ` +
                  `is unaffected. Check document.delivery.ack_grace_expired, ` +
                  `session.content.held.discarded, and whether their daemon has yet received ` +
                  `the amendment that added you (their log would show ` +
                  `document.inbound.sender_unknown_epoch_ahead) before concluding their client ` +
                  `is at fault.`,
              });
              const allExhausted = currentHolders
                .filter((h) => h !== senderAgentId)
                .every((h) => !this.#store.holderHasPending(ownerAgentId, documentId, h));
              if (allExhausted) {
                this.#store.setDocumentStatus(ownerAgentId, documentId, "stalled");
                this.#logger.error("document.delivery.stalled_all_holders", {
                  documentId, correlationId,
                });
              }
            }
          } else if (outcome.ok) {
            const first = this.#store.ackHolderDelivery(
              ownerAgentId, documentId, envelope.envelopeHash, holderAgentId, nowMs,
            );
            // The envelope-level record follows the ONE terminal rule (review M3).
            this.#store.reconcileEnvelopeSettlement(
              ownerAgentId, documentId, envelope.envelopeHash, nowMs,
            );
            this.#logger.info("document.delivery.session", {
              documentId, holderAgentId, sessionId: outcome.sessionId,
              opened: outcome.sessionOpened, correlationId,
            });
            if (outcome.admitted) {
              this.#logger.info("document.delivery.acked", {
                documentId, envelopeHash: envelope.envelopeHash, holderAgentId,
                sessionId: outcome.sessionId, firstAck: first, correlationId,
              });
              result.delivered += 1;
            } else {
              this.#logger.warn("document.delivery.rejected", {
                documentId, envelopeHash: envelope.envelopeHash, holderAgentId,
                sessionId: outcome.sessionId, reason: outcome.rejectionReason, correlationId,
              });
              result.rejected += 1;
            }
          } else {
            this.#logger.warn("document.delivery.failed", {
              documentId, envelopeHash: envelope.envelopeHash, holderAgentId,
              reason: outcome.reason, detail: outcome.detail, attempts: row.attempts + 1,
              correlationId,
            });
            result.failed += 1;
          }
        }
      }
    }

    return result;
  }
}
