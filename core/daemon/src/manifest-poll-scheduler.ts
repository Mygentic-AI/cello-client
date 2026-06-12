/**
 * M7-MANIFEST-002 — Manifest poll scheduler implementations.
 *
 * IManifestPollScheduler schedules the background manifest poll that keeps the
 * in-memory manifest current over long-lived daemon sessions.
 *
 * RandomizedPollScheduler: production implementation — fires after a random delay
 * in the 6-12 hour window (prevents thundering-herd against the directory).
 *
 * ImmediatePollScheduler: test stub — fires once with a configurable delay (0ms default).
 * Exported from @cello-protocol/transport.
 */

import type { IManifestPollScheduler } from "@cello-protocol/transport";

// Re-export the test stub for convenience
export { ImmediatePollScheduler } from "@cello-protocol/transport";
export type { IManifestPollScheduler };

// ─── RandomizedPollScheduler (production) ─────────────────────────────────────

const POLL_MIN_MS = 6 * 60 * 60 * 1000;  // 6 hours
const POLL_MAX_MS = 12 * 60 * 60 * 1000; // 12 hours

/**
 * RandomizedPollScheduler — fires after a random interval between 6 and 12 hours.
 *
 * The randomization window prevents thundering-herd scenarios where many agents
 * all poll simultaneously. Each agent picks an independent random delay.
 */
export class RandomizedPollScheduler implements IManifestPollScheduler {
  #timer: ReturnType<typeof setTimeout> | null = null;
  readonly #minMs: number;
  readonly #maxMs: number;

  constructor(opts?: { minMs?: number; maxMs?: number }) {
    this.#minMs = opts?.minMs ?? POLL_MIN_MS;
    this.#maxMs = opts?.maxMs ?? POLL_MAX_MS;
  }

  scheduleNext(callbackFn: () => Promise<void>): void {
    this.cancel();
    const delay = this.#minMs + Math.random() * (this.#maxMs - this.#minMs);
    this.#timer = setTimeout(() => {
      this.#timer = null;
      callbackFn().catch(() => {
        // Poll errors are logged by the caller; scheduling errors don't crash the daemon
      });
    }, delay);
  }

  cancel(): void {
    if (this.#timer !== null) {
      clearTimeout(this.#timer);
      this.#timer = null;
    }
  }
}
