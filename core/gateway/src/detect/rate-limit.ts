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
import { operatorCanRun } from "../screen/affordance.js";
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

  /** The in-window timestamps for `agentIdentity` (read-only — prunes aged-out entries). */
  #live(agentIdentity: string, now: number): number[] {
    const all = this.#sends.get(agentIdentity);
    return all ? all.filter((t) => t > now - this.#config.windowMs) : [];
  }

  /**
   * READ-ONLY rate check — does NOT consume a slot. Returns a throttle verdict when the agent is
   * at/over the cap, else `{limited:false}`. Use this to GATE a send; commit the slot with
   * `record()` only once the message actually reaches the wire (M2 review — block/warn must not
   * count, and a warn→re-send must not double-count).
   */
  peek(agentIdentity: string): RateLimitVerdict {
    const now = this.#now();
    const live = this.#live(agentIdentity, now);
    if (live.length >= this.#config.maxPerWindow) {
      const oldest = live[0];
      const retryAfterMs = Math.max(1, oldest + this.#config.windowMs - now);
      return {
        limited: true,
        reason: "rate_limited",
        guidance:
          `Outbound rate limit reached for this agent (${this.#config.maxPerWindow} messages per ` +
          `${Math.round(this.#config.windowMs / 1000)}s). This message was not sent. ` +
          `WHAT YOU CAN DO NOW: wait about ${Math.ceil(retryAfterMs / 1000)}s and retry — the window ` +
          `slides as older messages age out, so this clears itself.\n` +
          operatorCanRun("rate_max_per_window", "<higher number>"),
        retryAfterMs,
      };
    }
    return { limited: false };
  }

  /** Commit one sent message against `agentIdentity`'s cap (call only when it reaches the wire). */
  record(agentIdentity: string): void {
    const now = this.#now();
    const live = this.#live(agentIdentity, now);
    live.push(now);
    this.#sends.set(agentIdentity, live);
  }

  /**
   * Account one send attempt: `peek()` then `record()` when under the cap. A throttled attempt
   * records nothing. (Convenience for standalone use; the composition uses peek + conditional record.)
   */
  check(agentIdentity: string): RateLimitVerdict {
    const v = this.peek(agentIdentity);
    if (!v.limited) this.record(agentIdentity);
    return v;
  }
}
