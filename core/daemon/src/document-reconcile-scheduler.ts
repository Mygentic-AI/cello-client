/**
 * SYNC-P5 (R39–R43) — WHEN reconciling is attempted. The exchange itself (P3) is stateless and
 * idempotent; this module only decides moments, and every piece of state it holds is VOLATILE
 * scheduling state in the R41 sense: it may delay an exchange, it must never forbid one, gate
 * admissibility, or survive a restart as authority. Losing all of it costs at most one sweep
 * interval of latency.
 *
 * The three triggers (R39):
 *  1. committing an entry / publishing — the layer nudges directly (P4's `nudgeSeats` and the
 *     entry fan-out); not this module's job.
 *  2. a party becoming reachable — `onReachable`, wired to session establishment. An explicit
 *     reachability signal RESETS backoff: the backoff modeled "they do not answer", and here
 *     they demonstrably just did.
 *  3. the periodic sweep — `sweep`, wired to a timer. Bounded per R43: batched per party (R16's
 *     cap is the exchange's own), and — DOD-DOC-PUSH-NOT-POLL-1 — it speaks only for a party we
 *     HOLD something for. A timer is not a reason to speak.
 *
 * R42: the in-flight mark is TIME-BOUNDED and released LOUDLY on expiry. An unbounded in-flight
 * mark is the stall this milestone already paid for twice.
 *
 * DOD-DOC-PUSH-NOT-POLL-1 (Andre, 2026-08-18) — WHAT THE TIMER MAY NO LONGER DO, and what it cost.
 * The suppressor used to be a BELIEF with an expiry: a party was skipped only while every shared
 * document read in_sync AND had been exchanged within ten minutes. Past the window it asked again
 * whether or not anything had changed. Measured live: three agents, thirty documents, the freshest
 * exchange days old, and one stale timestamp kept a whole party — fourteen documents — sweeping
 * every 120 seconds forever. Each of those frames takes a position in the CONVERSATION's hash
 * chain, so a quiet document spends a real conversation's sequence numbers: 34 positions on one
 * live session, 2 of them actual messages, and the seal refused `session_incomplete`.
 *
 * The rule now: WE SPEAK WHEN WE HOLD SOMETHING THE PARTY HAS NOT CONFIRMED RECEIVING, and an
 * unchanged holding is offered once, not on every tick. Nothing pending, no frame, no position.
 *
 * THE TRADE, STATED RATHER THAN HIDDEN: `pendingFor` can only see what we hold that they lack —
 * never what they hold that we lack — so removing the expiry removes the timer-driven PULL. The
 * pull moves onto the two triggers that are events rather than clocks: their publish nudges us
 * (R39 trigger 1), and a session with them coming up sweeps everything (`onReachable`, which
 * deliberately does NOT inherit the pending gate).
 */

import type { Logger } from "./types.js";

/** How long one attempt may hold the in-flight mark before the sweep stops honoring it. */
export const RECONCILE_INFLIGHT_BOUND_MS = 60_000;
/** First back-off step for a party that did not answer; doubles per consecutive failure. */
export const RECONCILE_BACKOFF_BASE_MS = 30_000;
export const RECONCILE_BACKOFF_CAP_MS = 15 * 60_000;
/** R16's per-frame batching ceiling, honored by chunking a party's documents. */
export const RECONCILE_BATCH_CAP = 32;

export interface ReconcileSchedulerDeps {
  now(): number;
  logger: Logger;
  /**
   * Every (party → shared ACTIVE documents) pair one owner's sweep should consider. DERIVED by
   * the caller from the fold — the scheduler never decides who is a party.
   */
  sweepTargets(ownerAgentId: string): Map<string, string[]>;
  /**
   * DOD-DOC-PUSH-NOT-POLL-1 — WHAT we hold on this document that this party has not confirmed
   * receiving, as a comparable fingerprint; `null` when there is nothing. Derived by the caller
   * from the same comparison that answers "are they behind" on the list surface — two copies of
   * that question is two daemons disagreeing about who needs an exchange.
   *
   * Compared, never interpreted: the scheduler only asks whether it changed since it last spoke.
   */
  pendingFor(ownerAgentId: string, documentId: string, partyAgentId: string): string | null;
  initiateReconcile(
    ownerAgentId: string,
    peerAgentId: string,
    documentIds: readonly string[],
  ): Promise<{ ok: true } | { ok: false; reason?: string }>;
  /**
   * Test-pace override for the failure backoff (the enforcers' lesson: a restarted daemon's
   * first attempts can fail while its own signaling settles, and the production 30s-doubling
   * ladder walks a fast-sweep test out of its window). Omitted = the production constants.
   */
  backoffBaseMs?: number;
}

interface PartyState {
  nextAttemptMs: number;
  failures: number;
  inFlightUntilMs: number | null;
  /** The holding we last put on the wire for this party; `null` = we have not spoken yet. */
  lastPendingSignature: string | null;
  /** Times we have offered that holding unchanged; drives the same ladder as silence. */
  repeats: number;
  /**
   * How long to stay quiet about an UNCHANGED holding. Deliberately NOT `nextAttemptMs`: that one
   * is armed by a peer failing or refusing and may never be bypassed (REFUSAL-BACKOFF-1), while
   * this one is armed only by us having nothing new to say — so a real change may step over it.
   */
  quietUntilMs: number;
}

export interface SweepResult {
  attempted: number;
  skippedBackoff: number;
  skippedInFlight: number;
  skippedNothingPending: number;
  failed: number;
}

export class ReconcileScheduler {
  readonly #d: ReconcileSchedulerDeps;
  /** Volatile by design (R41): keyed per (owner, party); dies with the process. */
  readonly #state = new Map<string, PartyState>();
  /** DOD-M12B-SHUTDOWN-1: set by stop(); every entry point refuses once it is true. */
  #stopped = false;

  constructor(deps: ReconcileSchedulerDeps) {
    this.#d = deps;
  }

  /**
   * DOD-M12B-SHUTDOWN-1 — refuse all further work. Idempotent, and one-way on purpose.
   *
   * Clearing the sweep timer stops the NEXT tick and nothing else: the pass already running walks
   * every agent, and each step dials a peer and opens a session. Measured 2026-08-17 — `cello
   * logout` reported the daemon down, the socket was already gone, and the process ran on for 30+
   * seconds still logging `document.reconcile.sweep`, dialling on its way out. It took a signal to
   * exit. A shutdown that keeps starting new outbound work is not draining.
   *
   * Guarded at the top of the two entry points that START work — `sweep` and `onReachable` — so
   * `sweepTargets`, a database read, is not run either, AND inside the sweep's own party loop so a
   * pass already running stops at the next party rather than finishing its round. `noteRefusal`
   * deliberately still runs: it records an outcome and starts nothing.
   *
   * Never un-set: a reachability trigger firing from a session tearing down during shutdown must
   * not be able to restart the sweeper on the way out.
   */
  stop(): void {
    if (this.#stopped) return;
    this.#stopped = true;
    this.#d.logger.info("document.reconcile.stopped", {
      reason: "shutdown",
      impact: "no further reconcile attempts will be started",
    });
  }

  #key(ownerAgentId: string, peerAgentId: string): string {
    return `${ownerAgentId}\u0000${peerAgentId}`;
  }

  #stateFor(key: string): PartyState {
    let s = this.#state.get(key);
    if (!s) {
      s = {
        nextAttemptMs: 0,
        failures: 0,
        inFlightUntilMs: null,
        lastPendingSignature: null,
        repeats: 0,
        quietUntilMs: 0,
      };
      this.#state.set(key, s);
    }
    return s;
  }

  /**
   * R39's second trigger: this party is demonstrably reachable RIGHT NOW — a session with them
   * just came up. Backoff is reset (it modeled silence; they answered) and the attempt fires
   * for every shared document, in R16-capped batches.
   *
   * DELIBERATELY EXEMPT FROM THE PENDING GATE (DOD-DOC-PUSH-NOT-POLL-1). The gate can only see
   * what we hold that they lack; the exchange is the only thing that sees the other direction.
   * Take the gate off the timer and this becomes where the PULL lives, so gating it here too
   * would leave nothing that ever asks.
   */
  async onReachable(ownerAgentId: string, peerAgentId: string): Promise<void> {
    if (this.#stopped) return;
    const docs = this.#d.sweepTargets(ownerAgentId).get(peerAgentId);
    if (!docs || docs.length === 0) return;
    const s = this.#stateFor(this.#key(ownerAgentId, peerAgentId));
    s.failures = 0;
    s.repeats = 0;
    s.nextAttemptMs = 0;
    s.quietUntilMs = 0;
    // They answered, so whatever we last offered is stale as a comparison: the next sweep treats
    // its holding as new and speaks at full speed once.
    s.lastPendingSignature = null;
    await this.#attempt(ownerAgentId, peerAgentId, docs, s, null);
  }

  /**
   * A PEER ANSWERED "NO". That is an answer, and it must slow the asking down.
   *
   * `#attempt` can only see whether the FRAME WAS SENT — the refusal arrives later, on its own
   * inbound frame, and until now it was logged and dropped. So a peer refusing every exchange was
   * indistinguishable from a peer answering fine: `failures` reset to 0, `nextAttemptMs` to now,
   * and the sweep asked again immediately. Measured 321 attempts against two documents in 85
   * minutes, refused every time, zero successes.
   *
   * R41 IS PRESERVED: this DELAYS an exchange, it never forbids one. A terminal refusal jumps
   * straight to the cap rather than retiring the party, because "terminal" is one holder's current
   * derivation — a later entry can make the same exchange admissible again, and scheduling state
   * must never be the thing that forbids it. `onReachable` still clears it outright.
   */
  noteRefusal(ownerAgentId: string, peerAgentId: string, terminal: boolean): void {
    const s = this.#stateFor(this.#key(ownerAgentId, peerAgentId));
    const now = this.#d.now();
    const base = this.#d.backoffBaseMs ?? RECONCILE_BACKOFF_BASE_MS;
    if (terminal) {
      s.nextAttemptMs = now + RECONCILE_BACKOFF_CAP_MS;
    } else {
      s.failures += 1;
      s.nextAttemptMs = now + Math.min(base * 2 ** (s.failures - 1), RECONCILE_BACKOFF_CAP_MS);
    }
    this.#d.logger.info("document.reconcile.refusal_backoff", {
      peerAgentId, terminal, failures: s.failures, nextAttemptInMs: s.nextAttemptMs - now,
    });
  }

  /** R39's third trigger — one bounded pass for one owner. */
  async sweep(ownerAgentId: string): Promise<SweepResult> {
    const result: SweepResult = {
      attempted: 0, skippedBackoff: 0, skippedInFlight: 0, skippedNothingPending: 0, failed: 0,
    };
    // DOD-M12B-SHUTDOWN-1: the in-flight pass stops HERE, not at the next timer tick.
    if (this.#stopped) return result;
    const now = this.#d.now();
    for (const [peerAgentId, docs] of this.#d.sweepTargets(ownerAgentId)) {
      // DOD-M12B-SHUTDOWN-1: INSIDE the loop, not only at the entry. A guard on entry alone stops
      // the NEXT agent while the one being swept goes on dialling every remaining party — which on
      // a single-agent daemon, the measured case, buys nothing at all. Each of those dials can
      // create a session node AFTER gracefulShutdown has already flipped active rows to interrupted
      // and snapshotted the node list, leaving a row nothing will clear and a node nobody stops.
      if (this.#stopped) break;
      if (docs.length === 0) continue;
      const s = this.#stateFor(this.#key(ownerAgentId, peerAgentId));
      if (s.inFlightUntilMs !== null) {
        if (now < s.inFlightUntilMs) {
          result.skippedInFlight += 1;
          continue;
        }
        // RELEASED LOUDLY (R42): an attempt held its mark past the bound. The mark is dropped
        // so the sweep proceeds — an unbounded in-flight mark is the stall this milestone
        // already paid for twice.
        this.#d.logger.warn("document.reconcile.inflight_expired", {
          peerAgentId, heldMs: now - (s.inFlightUntilMs - RECONCILE_INFLIGHT_BOUND_MS),
        });
        s.inFlightUntilMs = null;
      }
      if (now < s.nextAttemptMs) {
        result.skippedBackoff += 1;
        continue;
      }
      // DOD-DOC-PUSH-NOT-POLL-1 — the only reason to speak: we hold something they have not
      // confirmed receiving. A document with nothing pending contributes no frame and no
      // sequence position, however long ago it last exchanged.
      const pendingDocs: string[] = [];
      const parts: string[] = [];
      for (const documentId of docs) {
        const pending = this.#d.pendingFor(ownerAgentId, documentId, peerAgentId);
        if (pending === null) continue;
        pendingDocs.push(documentId);
        parts.push(`${documentId}=${pending}`);
      }
      if (pendingDocs.length === 0) {
        result.skippedNothingPending += 1;
        continue;
      }
      const signature = parts.join("\n");
      // Offered already, and nothing has changed since. A real change steps over this — it is a
      // trigger (R39), not noise — but the refusal/failure backoff above is never stepped over.
      if (signature === s.lastPendingSignature && now < s.quietUntilMs) {
        result.skippedBackoff += 1;
        continue;
      }
      result.attempted += 1;
      const ok = await this.#attempt(ownerAgentId, peerAgentId, pendingDocs, s, signature);
      if (!ok) result.failed += 1;
    }
    return result;
  }

  async #attempt(
    ownerAgentId: string,
    peerAgentId: string,
    docs: readonly string[],
    s: PartyState,
    signature: string | null,
  ): Promise<boolean> {
    // Read BEFORE the send: whether this round is a re-offer decides the cadence below.
    const repeat = signature !== null && signature === s.lastPendingSignature;
    const started = this.#d.now();
    s.inFlightUntilMs = started + RECONCILE_INFLIGHT_BOUND_MS;
    let allOk = true;
    try {
      for (let i = 0; i < docs.length; i += RECONCILE_BATCH_CAP) {
        // DOD-M12B-SHUTDOWN-1: between batches too — one party can carry many documents, and each
        // batch is another dial.
        if (this.#stopped) break;
        const batch = docs.slice(i, i + RECONCILE_BATCH_CAP);
        const sent = await this.#d.initiateReconcile(ownerAgentId, peerAgentId, batch);
        if (!sent.ok) {
          allOk = false;
          this.#d.logger.warn("document.reconcile.sweep_attempt_failed", {
            peerAgentId, documents: batch.length, reason: sent.reason ?? "send_failed",
          });
          break; // one dead transport answers for the whole party this round
        }
      }
    } catch (err: unknown) {
      allOk = false;
      this.#d.logger.warn("document.reconcile.sweep_attempt_failed", {
        peerAgentId, reason: err instanceof Error ? err.message : String(err),
      });
    } finally {
      s.inFlightUntilMs = null;
    }
    const now = this.#d.now();
    const base = this.#d.backoffBaseMs ?? RECONCILE_BACKOFF_BASE_MS;
    if (allOk) {
      s.failures = 0;
      s.nextAttemptMs = now;
      // THE SEND SUCCEEDING MEANS THE FRAME WENT OUT, NEVER THAT THE PARTY ACTED ON IT. An
      // invitation nobody accepts stays pending forever, so without this the sweep re-offered the
      // identical holding on every tick — one frame each, each one spending a position in the
      // conversation's hash chain. Every re-offer doubles the silence, up to the same cap.
      s.repeats = repeat ? s.repeats + 1 : 1;
      s.lastPendingSignature = signature;
      s.quietUntilMs = now + Math.min(base * 2 ** (s.repeats - 1), RECONCILE_BACKOFF_CAP_MS);
    } else {
      s.failures += 1;
      s.nextAttemptMs = now + Math.min(base * 2 ** (s.failures - 1), RECONCILE_BACKOFF_CAP_MS);
    }
    return allOk;
  }
}
