/**
 * M9-OUT-004 — per-agent-identity outbound rate limiting.
 *
 * A sliding-window counter keyed on the AGENT IDENTITY (peer-id / agent name), never a source IP —
 * so a compromised or runaway agent cannot flood a peer or use volume as an exfiltration channel,
 * while a normal agent's traffic is never throttled or delayed. Pure in-memory, deterministic with
 * an injectable clock.
 *
 * The cap is a configured value (M9-CFG-001 owns the config; this is the enforcement). A throttled
 * verdict carries a distinct `rate_limited` reason and a retry-after, surfaced to the agent through
 * the outbound seam's never-hang feedback (M9-CORE-001 / M9-FEED-001).
 */
export interface RateLimitConfig {
  /** Max messages allowed per agent within the window. */
  maxPerWindow: number;
  /** The sliding-window length, in milliseconds. */
  windowMs: number;
}

export interface RateLimitVerdict {
  limited: boolean;
  reason?: "rate_limited";
  guidance?: string;
  /** Milliseconds until the agent may send again (only when limited). */
  retryAfterMs?: number;
}

export class OutboundRateLimiter {
  readonly #config: RateLimitConfig;
  readonly #now: () => number;
  // agent identity → ascending timestamps of ALLOWED sends still inside the window.
  readonly #sends = new Map<string, number[]>();

  constructor(config: RateLimitConfig, now: () => number = () => Date.now()) {
    this.#config = config;
    this.#now = now;
  }

  /**
   * Account one send attempt for `agentIdentity`. Returns `{limited:false}` and records the send
   * when under the cap; returns a throttle verdict WITHOUT recording when at/over the cap (a
   * throttled attempt must not consume or extend a slot).
   */
  check(agentIdentity: string): RateLimitVerdict {
    const now = this.#now();
    const windowStart = now - this.#config.windowMs;

    const all = this.#sends.get(agentIdentity);
    // Drop timestamps that have aged out of the window.
    const live = all ? all.filter((t) => t > windowStart) : [];

    if (live.length >= this.#config.maxPerWindow) {
      // At/over the cap — throttle. Retry once the OLDEST in-window send expires.
      this.#sends.set(agentIdentity, live); // keep the pruned list; do NOT record this attempt
      const oldest = live[0];
      const retryAfterMs = Math.max(1, oldest + this.#config.windowMs - now);
      return {
        limited: true,
        reason: "rate_limited",
        guidance:
          `Outbound rate limit reached for this agent (${this.#config.maxPerWindow} messages per ` +
          `${Math.round(this.#config.windowMs / 1000)}s). This message was not sent. ` +
          `Wait about ${Math.ceil(retryAfterMs / 1000)}s and retry; the window slides as older messages age out.`,
        retryAfterMs,
      };
    }

    live.push(now);
    this.#sends.set(agentIdentity, live);
    return { limited: false };
  }
}
