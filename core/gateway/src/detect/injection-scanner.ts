/**
 * M9-IN-002 — inbound Layer-2 semantic injection scanner.
 *
 * Classifies the SANITIZED inbound text (from M9-IN-001) with an in-process DeBERTa-v3-small model
 * (protectai/deberta-v3-small-prompt-injection-v2, fp32 ONNX — Andre 2026-06-23), catching prompt
 * injections that survive deterministic Layer-1 sanitization. No network call during inference: the
 * model is pre-downloaded weights loaded into process memory (SI-001 / INV-1).
 *
 * The model is NOT bundled (it is large): it is downloaded once with explicit operator consent +
 * a pinned SHA-256 (see model-installer.ts). When it is absent, Layer-2 is OFF and Layer-1 still
 * runs — the gateway degrades gracefully, it never fails closed on a missing optional model.
 *
 * The classifier is injected behind `InjectionClassifier` so the verdict logic here is pure and
 * unit-tested without the model; the real classifier (transformers.js over the local ONNX) is the
 * production implementation and is exercised by a gated real-inference test.
 */

export type InjectionVerdict = "block" | "flag" | "pass";

/**
 * Score thresholds (0–100). Score GOVERNS the verdict — a label that disagrees never overrides it.
 *
 * **`BLOCK_THRESHOLD` bites only when the scanner is constructed with `blocking: true`
 * (026-NOBLOCK).** By default the scanner never blocks: a score at or above this bar is a FLAG, and
 * the message is delivered with the finding attached. Andre, 2026-09-24: on the first live channel
 * test the model scored ordinary agent-to-agent coordination at 99 ("What were your seq 3 and 4?"
 * alone scores 92), which silently deadlocked a working session. Until per-tier blocking is wired,
 * the model only FLAGS. The bar itself stays high and PROVISIONAL (DOD-M9C-SCREENWIRE-1): measured
 * 2026-09-17 against 1,200 real benign messages, the shipped model scores 2.1% of them at ≥70, so
 * even with blocking on the bar is deliberately near-certainty. Flagged content is delivered with
 * the finding attached, which is where most of the defence lives anyway.
 */
export const BLOCK_THRESHOLD = 99;
export const FLAG_THRESHOLD = 35;

/**
 * Construction options for {@link InjectionScanner}.
 */
export interface InjectionScannerOptions {
  /**
   * When false (the default), a score at or above BLOCK_THRESHOLD is a FLAG: the message is
   * delivered with the finding attached. Andre, 2026-09-24: the model scored ordinary agent
   * coordination at 99 on the first live channel test. Turned on per tier later, never globally.
   */
  blocking?: boolean;
}

export function scoreToVerdict(score: number, blocking = false): InjectionVerdict {
  if (score >= BLOCK_THRESHOLD) return blocking ? "block" : "flag";
  if (score >= FLAG_THRESHOLD) return "flag";
  return "pass";
}

/** The pluggable model. `injectionProbability` is the model's P(injection) in [0,1]. */
export interface InjectionClassifier {
  classify(text: string): Promise<{ injectionProbability: number; label?: string }>;
}

/**
 * What the classifier scored and on WHICH text — the provenance of a verdict, for the operator's log.
 *
 * Deliberately a hash and a length, never the text: this is written to a log, and the protocol's
 * promise is that the conversation stays with its participants. To check a suspected input, hash the
 * candidate (sha256 over its UTF-8 bytes) and compare `copySha256`.
 */
export interface InjectionScanDetail {
  /** The model's unrounded P(injection), 0..1. */
  probability: number;
  /** The integer score the verdict was decided on (`probability` × 100, rounded). */
  score: number;
  verdict: InjectionVerdict;
  /**
   * Which copy of the message produced the winning (highest) score: `scan` is the cleaned,
   * decoded detection copy; `raw` the bytes as received; `hidden` a smuggled-instruction channel.
   */
  copy: "scan" | "raw" | "hidden";
  /** UTF-8 byte length of exactly the text the model read on the winning copy. */
  copyBytes: number;
  /** sha256 (hex) of those bytes. */
  copySha256: string;
  /** How many distinct copies were scored (duplicates are scored once; a block ends the loop early). */
  copiesScanned: number;
  /** How many copies the classifier FAILED on; absent when none did. */
  degraded?: number;
  /**
   * The trailing turn marker the sending tool appends (`OVER`, `WRAP` or `STANDBY`) when the winning
   * copy ends with one, else null. It is CELLO's own signal, not something the sender wrote, yet it
   * is in the text the model reads — so it is named rather than left to be inferred from byte counts.
   */
  signalMarker: "OVER" | "WRAP" | "STANDBY" | null;
}

export interface ScanResult {
  /** false when Layer-2 is off (no model/runtime) — Layer-1 still ran; the message is not blocked here. */
  available: boolean;
  score?: number;
  /**
   * The model's UNROUNDED P(injection) in [0,1]. `score` is this rounded to an integer, and the
   * verdict compares the ROUNDED value — so 0.9856 scores 99 and blocks at a 99 bar. Carried so an
   * operator can see that rounding rather than infer it.
   */
  probability?: number;
  verdict?: InjectionVerdict;
  /** The model's raw label (informational only — the SCORE governs the verdict, AC-003). */
  label?: string;
}

export class InjectionScanner {
  readonly #classifier: InjectionClassifier | null;
  readonly #blocking: boolean;

  /**
   * @param classifier the in-process model, or null when Layer-2 is unavailable (graceful degrade).
   * @param opts `blocking: true` makes a score ≥ BLOCK_THRESHOLD a terminal block. The default is
   *   false — the scanner FLAGS such a score and delivers it (026-NOBLOCK). Production passes nothing.
   */
  constructor(classifier: InjectionClassifier | null, opts: InjectionScannerOptions = {}) {
    this.#classifier = classifier;
    this.#blocking = opts.blocking === true;
  }

  available(): boolean {
    return this.#classifier !== null;
  }

  async scan(text: string): Promise<ScanResult> {
    if (!this.#classifier) return { available: false };
    // A CLASSIFIER FAULT DEGRADES LAYER 2; it does not jam the path. The production classifier
    // throws deliberately on a label set it does not recognise, and an uncaught throw here reaches
    // the gateway's outer catch as `screen_error` — a block with no `terminal`, which the daemon
    // reads as TRANSIENT and redelivers forever, on a condition that is permanent and identical on
    // every retry. Unavailable-and-announced is the honest answer to a broken model.
    let classified: { injectionProbability: number; label?: string };
    try {
      classified = await this.#classifier.classify(text);
    } catch (err) {
      process.stderr.write(
        `cello-gateway: semantic injection scan FAILED, Layer 2 degraded for this message: ` +
        `${err instanceof Error ? err.message : String(err)}\n`,
      );
      return { available: false };
    }
    const { injectionProbability, label } = classified;
    const score = Math.round(Math.max(0, Math.min(1, injectionProbability)) * 100);
    // The score governs the verdict (AC-003): a model `label` of SAFE with a high score still blocks.
    return {
      available: true,
      score,
      probability: Math.max(0, Math.min(1, injectionProbability)),
      verdict: scoreToVerdict(score, this.#blocking),
      label,
    };
  }
}
