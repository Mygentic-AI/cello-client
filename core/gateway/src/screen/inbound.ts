/**
 * The inbound screen composition.
 *
 * Runs IN-001's deterministic sanitizer, IN-003's language allowlist, and (when a model is loaded)
 * IN-002's semantic injection scanner, then produces a verdict:
 *   - a size-cap breach → a TERMINAL block (oversized content stays oversized on redelivery);
 *   - a confident non-allowlisted language (IN-003) → a TERMINAL block;
 *   - a high-score injection (IN-002, when the scanner is available) → a TERMINAL block;
 *   - any sanitization change (invisible strip / confusables / special-token strip) → a `redact`
 *     that delivers the SANITIZED text plus per-step notes;
 *   - a pure entropy hit, a decode signal, or a Step-9 / IN-002-`flag` injection signal → an
 *     advisory `observe` note on otherwise-unchanged, delivered content.
 *
 * "TERMINAL" means the daemon records a leaf + acknowledges (the sender stops) but never delivers
 * the content — distinct from the fail-closed TRANSIENT block a down gateway returns, which stays
 * un-acked for redelivery. Language and injection run on the SANITIZED text (what the agent would
 * see), so confusable lookalikes normalized to Latin are judged as Latin, not held.
 */
import { sanitizeInbound } from "../detect/sanitize.js";
import { scanInjectionPatterns } from "../detect/injection-patterns.js";
import { screenInboundLanguage, type LanguageOptions } from "../detect/language.js";
import { InjectionScanner } from "../detect/injection-scanner.js";
import type { GovernanceEvent } from "./outbound.js";

export interface InboundVerdict {
  disposition: "allow" | "redact" | "block";
  /** The sanitized content to deliver (equals input when nothing changed; original on block). */
  content: Uint8Array;
  events: GovernanceEvent[];
  /** True on a content-rejection block (language / injection / size) — the daemon records + acks
   *  but never delivers. Absent on `allow`/`redact`. See ScreenVerdict.terminal. */
  terminal?: boolean;
  /** A machine-stable reason for a terminal block (e.g. `inbound_language_blocked`). */
  reason?: string;
  /** Actionable text the agent sees on a terminal block (INV-7). */
  guidance?: string;
}

export interface InboundScreenerOptions {
  maxBytes?: number;
  /** IN-003 language allowlist options (default: English / Latin script). */
  language?: LanguageOptions;
  /** IN-002 semantic injection scanner. Default: a null scanner (Layer-2 off — graceful degrade). */
  injectionScanner?: InjectionScanner;
}

const TEXT_ENCODER = new TextEncoder();

export class InboundScreener {
  readonly #maxBytes?: number;
  readonly #language?: LanguageOptions;
  readonly #injection: InjectionScanner;

  constructor(opts: InboundScreenerOptions = {}) {
    this.#maxBytes = opts.maxBytes;
    this.#language = opts.language;
    // No scanner injected ⇒ a null-classifier scanner: available()===false, so it never blocks.
    this.#injection = opts.injectionScanner ?? new InjectionScanner(null);
  }

  async screen(content: Uint8Array): Promise<InboundVerdict> {
    const r = sanitizeInbound(content, this.#maxBytes !== undefined ? { maxBytes: this.#maxBytes } : {});

    if (r.blocked) {
      // A size/length-cap breach is a CONTENT property — redelivering the same oversized bytes would
      // breach the cap again, so this is terminal (record + ack, never deliver), not a redelivery hold.
      return {
        disposition: "block",
        content,
        events: [{ stage: "sanitize", disposition: "block", category: `sanitize:${r.blocked.reason}`, reason: r.blocked.guidance }],
        terminal: true,
        reason: `inbound_${r.blocked.reason}`,
        guidance: r.blocked.guidance,
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

    // The text the agent would actually see — sanitized (confusables normalized, invisibles stripped).
    // Language and injection judge THIS, not the raw bytes: a confusable-Latin word is Latin here.
    const deliveredText = r.text;

    // IN-003: language allowlist. A message confidently in a non-allowlisted script (default: only
    // Latin/English) is held — a TERMINAL block (the same bytes are the same language on redelivery).
    const lang = screenInboundLanguage(deliveredText, this.#language ?? {});
    if (!lang.allowed) {
      return {
        disposition: "block",
        content,
        events: [...events, {
          stage: "language",
          disposition: "block",
          category: `language:${lang.script}`,
          reason: lang.reason ?? "non-allowlisted language",
        }],
        terminal: true,
        reason: "inbound_language_blocked",
        guidance: lang.reason ?? "This message is in a language outside the gateway allowlist; it was not delivered.",
      };
    }

    // IN-002: semantic injection scanner (Layer-2). Off when no model is loaded — available()===false,
    // so the call short-circuits and inbound behaviour is unchanged until the model is installed.
    if (this.#injection.available()) {
      const scan = await this.#injection.scan(deliveredText);
      if (scan.verdict === "block") {
        return {
          disposition: "block",
          content,
          events: [...events, {
            stage: "injection_scan",
            disposition: "block",
            category: "injection:semantic",
            reason: `semantic injection score ${scan.score} ≥ block threshold`,
          }],
          terminal: true,
          reason: "inbound_injection_blocked",
          guidance: "This message was classified as a prompt-injection attempt and was not delivered to the agent.",
        };
      }
      if (scan.verdict === "flag") {
        // Below the block bar — surface as evidence, still deliver (CELLO surfaces, does not police).
        events.push({
          stage: "injection_scan",
          disposition: "observe",
          category: "injection:semantic",
          reason: `semantic injection score ${scan.score} (flagged, below block threshold)`,
        });
      }
    }

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
      content: mutated ? TEXT_ENCODER.encode(deliveredText) : content,
      events,
    };
  }
}
