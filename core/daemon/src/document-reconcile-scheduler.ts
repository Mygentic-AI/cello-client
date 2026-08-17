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
 *     cap is the exchange's own), suppressed for parties believed current (display cache only —
 *     R44 permits it precisely because a wrong suppression costs latency, never correctness),
 *     and backed off for parties that do not answer.
 *
 * R42: the in-flight mark is TIME-BOUNDED and released LOUDLY on expiry. An unbounded in-flight
 * mark is the stall this milestone already paid for twice.
 */

import type { Logger } from "./types.js";

/** How long one attempt may hold the in-flight mark before the sweep stops honoring it. */
export const RECONCILE_INFLIGHT_BOUND_MS = 60_000;
/** First back-off step for a party that did not answer; doubles per consecutive failure. */
export const RECONCILE_BACKOFF_BASE_MS = 30_000;
export const RECONCILE_BACKOFF_CAP_MS = 15 * 60_000;
/**
 * A party whose every shared document reads in_sync, heard from within this window, is believed
 * current and skipped (R43). Past the window the sweep asks anyway — the cache is a belief.
 */
export const RECONCILE_BELIEVED_CURRENT_MS = 10 * 60_000;
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
   * Display-cache read (R44-safe): in_sync/behind/unseen plus when this party last exchanged.
   * Used ONLY to suppress, never to forbid — an unseen or behind party is always fair game.
   */
  partySync(
    ownerAgentId: string,
    documentId: string,
    partyAgentId: string,
  ): { sync: "in_sync" | "behind" | "unseen"; lastSyncedAtMs: number | null };
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
  /**
   * Same test-pace escape for the believed-current window — see backoffBaseMs. CLAMPED to the
   * production constant as a CEILING (review F5): the backoff has a cap and this did not, and an
   * override longer than the production window would let one mis-set environment variable suppress
   * sweeps for as long as it liked. R41 permits scheduling state to DELAY an exchange, never to
   * forbid one, so the only direction this knob may move is shorter.
   */
  believedCurrentMs?: number;
}

interface PartyState {
  nextAttemptMs: number;
  failures: number;
  inFlightUntilMs: number | null;
}

export interface SweepResult {
  attempted: number;
  skippedBackoff: number;
  skippedInFlight: number;
  skippedCurrent: number;
  failed: number;
}

export class ReconcileScheduler {
  readonly #d: ReconcileSchedulerDeps;
  /** Volatile by design (R41): keyed per (owner, party); dies with the process. */
  readonly #state = new Map<string, PartyState>();

  constructor(deps: ReconcileSchedulerDeps) {
    this.#d = deps;
  }

  #key(ownerAgentId: string, peerAgentId: string): string {
    return `${ownerAgentId}\u0000${peerAgentId}`;
  }

  #stateFor(key: string): PartyState {
    let s = this.#state.get(key);
    if (!s) {
      s = { nextAttemptMs: 0, failures: 0, inFlightUntilMs: null };
      this.#state.set(key, s);
    }
    return s;
  }

  /**
   * R39's second trigger: this party is demonstrably reachable RIGHT NOW — a session with them
   * just came up. Backoff is reset (it modeled silence; they answered) and the attempt fires
   * for every shared document, in R16-capped batches.
   */
  async onReachable(ownerAgentId: string, peerAgentId: string): Promise<void> {
    const docs = this.#d.sweepTargets(ownerAgentId).get(peerAgentId);
    if (!docs || docs.length === 0) return;
    const s = this.#stateFor(this.#key(ownerAgentId, peerAgentId));
    s.failures = 0;
    s.nextAttemptMs = 0;
    await this.#attempt(ownerAgentId, peerAgentId, docs, s);
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
      attempted: 0, skippedBackoff: 0, skippedInFlight: 0, skippedCurrent: 0, failed: 0,
    };
    const now = this.#d.now();
    for (const [peerAgentId, docs] of this.#d.sweepTargets(ownerAgentId)) {
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
      // Believed current (R43): every shared document in_sync and heard from recently. The
      // cache may be wrong — that costs one suppression window of latency, never correctness
      // (R40: the next exchange recovers anything).
      const believedWindow = Math.min(
        this.#d.believedCurrentMs ?? RECONCILE_BELIEVED_CURRENT_MS,
        RECONCILE_BELIEVED_CURRENT_MS,
      );
      const current = docs.every((documentId) => {
        const view = this.#d.partySync(ownerAgentId, documentId, peerAgentId);
        return (
          view.sync === "in_sync" &&
          view.lastSyncedAtMs !== null &&
          now - view.lastSyncedAtMs < believedWindow
        );
      });
      if (current) {
        result.skippedCurrent += 1;
        continue;
      }
      result.attempted += 1;
      const ok = await this.#attempt(ownerAgentId, peerAgentId, docs, s);
      if (!ok) result.failed += 1;
    }
    return result;
  }

  async #attempt(
    ownerAgentId: string,
    peerAgentId: string,
    docs: readonly string[],
    s: PartyState,
  ): Promise<boolean> {
    const started = this.#d.now();
    s.inFlightUntilMs = started + RECONCILE_INFLIGHT_BOUND_MS;
    let allOk = true;
    try {
      for (let i = 0; i < docs.length; i += RECONCILE_BATCH_CAP) {
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
    if (allOk) {
      s.failures = 0;
      s.nextAttemptMs = now; // the believed-current check is the steady-state suppressor
    } else {
      s.failures += 1;
      const base = this.#d.backoffBaseMs ?? RECONCILE_BACKOFF_BASE_MS;
      s.nextAttemptMs = now + Math.min(base * 2 ** (s.failures - 1), RECONCILE_BACKOFF_CAP_MS);
    }
    return allOk;
  }
}
