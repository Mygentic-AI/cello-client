/**
 * The outbound screen composition.
 *
 * Chains the built outbound detectors into one verdict, per the §6 governance model: each stage
 * publishes events with a disposition (observe / redact / block / warn); the driver decides control
 * flow by the strongest disposition (block > warn > redact > allow) and applies redactions to the
 * content. A block short-circuits (the message never leaves). This is the gateway-side outbound
 * screen the spawned gateway runs; the daemon-side cello_send rendering of this verdict (the
 * four-outcome return + the stateless governance re-send) is M9-FEED-001.
 *
 * Secret detection (M9-OUT-001) is decision-coupled (RE2 / gitleaks) and slots in here as another
 * `redact` stage once its binding is chosen.
 */
import { OutboundRateLimiter, type RateLimitConfig } from "../detect/rate-limit.js";
import { OutboundPIIScreener } from "../detect/pii.js";
import { screenOutboundExfil } from "../detect/exfil.js";
import type { GovernanceEvent } from "../types.js";

export type { GovernanceEvent };

export interface OutboundVerdict {
  /** The control-flow disposition for cello_send (M9-FEED-001 renders it to the agent). */
  disposition: "allow" | "redact" | "block" | "warn";
  /** The (possibly redacted) content to act on. For block, the original is returned (not sent). */
  content: Uint8Array;
  events: GovernanceEvent[];
}

export interface OutboundScreenerOptions {
  /** PII values the operator has whitelisted (own contact details). */
  piiWhitelist?: string[];
  /** Per-agent outbound rate limit. Omit to disable rate limiting. */
  rateLimit?: RateLimitConfig;
  piiBulkThreshold?: number;
  piiCumulativeThreshold?: number;
  /** Injectable clock (for the rate limiter) — tests pass a controllable one. */
  now?: () => number;
}

export interface OutboundScreenContext {
  agentName: string;
  sessionId: string;
}

const TEXT_DECODER = new TextDecoder("utf-8", { fatal: false });
const TEXT_ENCODER = new TextEncoder();

export class OutboundScreener {
  readonly #rateLimiter?: OutboundRateLimiter;
  readonly #pii: OutboundPIIScreener;

  constructor(opts: OutboundScreenerOptions = {}) {
    if (opts.rateLimit) this.#rateLimiter = new OutboundRateLimiter(opts.rateLimit, opts.now);
    this.#pii = new OutboundPIIScreener({
      whitelist: opts.piiWhitelist ?? [],
      ...(opts.piiBulkThreshold !== undefined ? { bulkThreshold: opts.piiBulkThreshold } : {}),
      ...(opts.piiCumulativeThreshold !== undefined ? { cumulativeThreshold: opts.piiCumulativeThreshold } : {}),
    });
  }

  screen(content: Uint8Array, ctx: OutboundScreenContext): OutboundVerdict {
    // 1. Rate limit — cheapest, and a throttle short-circuits (don't screen what won't be sent).
    if (this.#rateLimiter) {
      const rl = this.#rateLimiter.check(ctx.agentName);
      if (rl.limited) {
        return {
          disposition: "block",
          content,
          events: [{ stage: "rate_limit", disposition: "block", category: "rate_limit", reason: rl.guidance ?? "rate limit reached" }],
        };
      }
    }

    const events: GovernanceEvent[] = [];

    // 2. Exfiltration — an injection artifact in output is a hard block (short-circuit).
    const ex = screenOutboundExfil(content);
    if (ex.disposition === "block") {
      return {
        disposition: "block",
        content,
        events: ex.events.map((e) => ({ stage: "exfil", disposition: "block" as const, category: e.category, reason: e.reason })),
      };
    }
    let workingText = ex.text; // exfil redactions (invisible strip / image neutralize / blob redact) applied
    for (const e of ex.events) {
      events.push({ stage: "exfil", disposition: "redact", category: e.category, reason: e.reason });
    }

    // 3. PII — non-whitelisted values warn (need a governance decision before send).
    const pii = this.#pii.screen(content, ctx.sessionId);
    for (const e of pii.events) {
      events.push({ stage: "pii", disposition: "warn", category: e.category, reason: `personal data (${e.category})`, flagId: e.flagId });
    }

    // (Secrets — M9-OUT-001 — slot in here as a redact stage once the RE2/gitleaks binding lands.)

    const outContent = workingText === ex.text && ex.events.length === 0 ? content : TEXT_ENCODER.encode(workingText);
    const disposition = events.some((e) => e.disposition === "block")
      ? "block"
      : events.some((e) => e.disposition === "warn")
        ? "warn"
        : events.some((e) => e.disposition === "redact")
          ? "redact"
          : "allow";
    return { disposition, content: outContent, events };
  }
}

/** Decode helper exposed for callers rendering a verdict's content. */
export function verdictText(v: OutboundVerdict): string {
  return TEXT_DECODER.decode(v.content);
}
