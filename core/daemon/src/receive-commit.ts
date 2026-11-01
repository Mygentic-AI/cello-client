/**
 * Delivery commits for the web endpoint — M15D 001-DAEMON, contract C3.
 *
 * A local socket write proves only that the bytes reached the kernel; the web endpoint still has an
 * HTTP response to flush to a client that may already have hung up. So on an endpoint socket
 * `cello_receive` marks nothing read: it returns a `commit` token, and the endpoint sends
 * `session.receive.commit { token }` once its client has the response. A token not redeemed within
 * 60 s expires and the messages stay unread — the next receive returns them again.
 */
import { randomUUID } from "node:crypto";
import type { Logger } from "./types.js";

export const RECEIVE_COMMIT_TTL_MS = 60_000;

export class ReceiveCommits {
  readonly #pending = new Map<string, { commit: () => void; timer: ReturnType<typeof setTimeout> }>();
  constructor(private readonly logger: Logger, private readonly ttlMs: number = RECEIVE_COMMIT_TTL_MS) {}

  issue(commit: () => void, ctx: Record<string, unknown>): string {
    const token = randomUUID();
    const timer = setTimeout(() => {
      this.#pending.delete(token);
      this.logger.warn("session.receive.commit.expired", {
        ...ctx, ttlMs: this.ttlMs,
        impact: "the endpoint never confirmed delivery, so these messages stay unread and the next cello_receive returns them",
      });
    }, this.ttlMs);
    timer.unref?.();
    this.#pending.set(token, { commit, timer });
    return token;
  }

  /** Mark the messages read. False for an unknown, expired or already-used token. */
  redeem(token: string): boolean {
    const entry = this.#pending.get(token);
    if (!entry) return false;
    clearTimeout(entry.timer);
    this.#pending.delete(token);
    entry.commit();
    return true;
  }
}
