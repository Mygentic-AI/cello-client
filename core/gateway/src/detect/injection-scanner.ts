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
 * **The block bar is PROVISIONAL and deliberately high (DOD-M9C-SCREENWIRE-1).** Measured on
 * 2026-09-17 against 1,200 real benign messages, the shipped model scores 2.1% of them at ≥70 —
 * one ordinary message in fifty refused. A screener that blocks one in fifty of a stranger's
 * messages is not a screener anyone will keep installed, so until `002-SCREENCORPUS` measures the
 * bar the classifier FLAGS what it is unsure of and blocks only what it is nearly certain about.
 * Flagged content is still delivered with the finding attached, which is where most of the defence
 * lives anyway.
 */
export const BLOCK_THRESHOLD = 99;
export const FLAG_THRESHOLD = 35;

export function scoreToVerdict(score: number): InjectionVerdict {
  if (score >= BLOCK_THRESHOLD) return "block";
  if (score >= FLAG_THRESHOLD) return "flag";
  return "pass";
}

/** The pluggable model. `injectionProbability` is the model's P(injection) in [0,1]. */
export interface InjectionClassifier {
  classify(text: string): Promise<{ injectionProbability: number; label?: string }>;
}

export interface ScanResult {
  /** false when Layer-2 is off (no model/runtime) — Layer-1 still ran; the message is not blocked here. */
  available: boolean;
  score?: number;
  verdict?: InjectionVerdict;
  /** The model's raw label (informational only — the SCORE governs the verdict, AC-003). */
  label?: string;
}

export class InjectionScanner {
  readonly #classifier: InjectionClassifier | null;

  /** @param classifier the in-process model, or null when Layer-2 is unavailable (graceful degrade). */
  constructor(classifier: InjectionClassifier | null) {
    this.#classifier = classifier;
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
    return { available: true, score, verdict: scoreToVerdict(score), label };
  }
}
