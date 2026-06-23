/**
 * The inbound screen composition.
 *
 * Runs IN-001's deterministic sanitizer and produces a verdict: a size-cap breach blocks; any
 * sanitization change (invisible strip / confusables / decode / special-token strip) is a `redact`
 * that delivers the SANITIZED text plus per-step notes; a pure entropy hit is an advisory `observe`
 * note on otherwise-unchanged content. The DeBERTa injection scanner (M9-IN-002, decision-coupled)
 * slots in here as a `block` stage. Delivery of the sanitized text + notes to the agent via
 * cello_receive's security_context is M9-FEED-001 / the gate.
 */
import { sanitizeInbound } from "../detect/sanitize.js";
import { scanInjectionPatterns } from "../detect/injection-patterns.js";
import type { GovernanceEvent } from "./outbound.js";

export interface InboundVerdict {
  disposition: "allow" | "redact" | "block";
  /** The sanitized content to deliver (equals input when nothing changed; original on block). */
  content: Uint8Array;
  events: GovernanceEvent[];
}

export interface InboundScreenerOptions {
  maxBytes?: number;
}

const TEXT_ENCODER = new TextEncoder();

export class InboundScreener {
  readonly #maxBytes?: number;

  constructor(opts: InboundScreenerOptions = {}) {
    this.#maxBytes = opts.maxBytes;
  }

  screen(content: Uint8Array): InboundVerdict {
    const r = sanitizeInbound(content, this.#maxBytes !== undefined ? { maxBytes: this.#maxBytes } : {});

    if (r.blocked) {
      return {
        disposition: "block",
        content,
        events: [{ stage: "sanitize", disposition: "block", category: `sanitize:${r.blocked.reason}`, reason: r.blocked.guidance }],
      };
    }

    // Only steps that change the DELIVERED text are `redact`; decode (detection-only) and entropy
    // are advisory `observe` notes on otherwise-unchanged content (M1 review).
    const MUTATING = new Set(["invisible_strip", "confusables", "special_tokens"]);
    const events: GovernanceEvent[] = r.notes.map((n) => ({
      stage: "sanitize",
      disposition: MUTATING.has(n.step) ? "redact" : "observe",
      category: `sanitize:${n.step}`,
      reason: n.detail,
    }));

    // Step-9: deterministic injection-pattern matching on the DECODED form (decode-then-rescan),
    // via RE2 (ReDoS-safe). High-signal but reported as `observe` — the agent + the Layer-2 semantic
    // scanner / policy decide; CELLO surfaces evidence, it does not police content (a block on a
    // single pattern would brick legitimate discussion of prompt injection).
    for (const id of scanInjectionPatterns(r.decodedForScan)) {
      events.push({
        stage: "injection_scan",
        disposition: "observe",
        category: `injection:${id}`,
        reason: `matched known injection pattern '${id}' in the decoded content`,
      });
    }

    const mutated = r.notes.some((n) => MUTATING.has(n.step));
    return {
      disposition: mutated ? "redact" : "allow",
      content: mutated ? TEXT_ENCODER.encode(r.text) : content,
      events,
    };
  }
}
