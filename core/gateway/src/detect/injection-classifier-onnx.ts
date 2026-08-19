/**
 * DOD-DOC-SCREEN-CLASSIFIER-1 — the production classifier, and the reason it loads lazily.
 *
 * `InjectionScanner` has always taken an `InjectionClassifier` and has always been unit-tested with
 * a fake one. What never existed was an implementation backed by the real model, and — more to the
 * point — nothing ever CONSTRUCTED one: the gateway built `new InboundScreener()` with no
 * arguments, so the scanner fell back to its null classifier, reported itself unavailable, and the
 * call site short-circuited. Layer 2 was off in every shipped build, for messages and documents
 * alike, while the gateway announced mode `enforcing`.
 *
 * ── WHY THE RUNTIME IS AN OPTIONAL, LAZY IMPORT ───────────────────────────────────────────────
 *
 * The weights are already opt-in: ~568 MB, downloaded once, only on explicit operator consent. A
 * runtime that every operator installs to support a model most of them have not downloaded is the
 * same cost in a place they cannot decline it — and install size is a user-facing cost here, not an
 * abstract metric, because cello-mcp is a local node that operators reinstall on every version bump.
 *
 * So the ONNX runtime is imported dynamically, inside a try, and its absence is a NAMED, LOGGED
 * degradation rather than a crash. That mirrors what the installer already promises: "the gateway
 * never fails closed on a missing OPTIONAL model."
 *
 * ── WHAT THIS DELIBERATELY DOES NOT DO ────────────────────────────────────────────────────────
 *
 * It does not silently decide the answer. Every path returns either a working classifier or `null`
 * WITH a reason the caller logs. A classifier that quietly scored everything 0 would be worse than
 * no classifier at all: the gateway would report Layer 2 available and block nothing.
 */
import { join } from "node:path";
import { isModelInstalled } from "./model-installer.js";
import type { InjectionClassifier } from "./injection-scanner.js";

/** The transformers.js entry point, resolved at runtime. Absent in a default install by design. */
const RUNTIME_MODULE = "@huggingface/transformers";

export interface ClassifierLoad {
  classifier: InjectionClassifier | null;
  /** Why Layer 2 is off, when it is. Always set when `classifier` is null — never a silent null. */
  reason?: string;
}

/**
 * The transformers.js text-classification shape, narrowed to what is actually read.
 *
 * Typed structurally rather than imported: the package is an optional runtime dependency, so a
 * type-only import would make the build require what the install deliberately does not ship.
 */
type Pipe = (text: string, opts?: { top_k?: number }) => Promise<Array<{ label: string; score: number }>>;
type PipelineFactory = (task: string, model: string, opts?: Record<string, unknown>) => Promise<Pipe>;

/**
 * Build the classifier, or say why not.
 *
 * @param modelDir where `installModel` put the weights.
 * @param importImpl injectable for tests — production passes nothing and gets the real import.
 */
export async function loadInjectionClassifier(
  modelDir: string,
  importImpl?: (specifier: string) => Promise<unknown>,
): Promise<ClassifierLoad> {
  if (!(await isModelInstalled(modelDir))) {
    return {
      classifier: null,
      // NAMES WHAT EXISTS. Pointing at a command nobody built is the same defect this branch fixed in
    // cello_doc_remove's tool description; the installer has no CLI caller yet, so say so.
    reason:
      `no model at ${modelDir} — semantic injection screening is OFF. The weights are not fetched ` +
      `by any command yet (DOD-DOC-SCREEN-CLASSIFIER-1 owes one); set CELLO_GATEWAY_MODEL_DIR to a ` +
      `directory holding them to enable it`,
    };
  }

  let mod: unknown;
  try {
    // Indirection through a variable: a bare dynamic import of a name that is not a dependency is
    // resolved eagerly by some bundlers, which would turn an optional runtime into a hard one.
    const doImport = importImpl ?? ((s: string) => import(/* @vite-ignore */ s));
    mod = await doImport(RUNTIME_MODULE);
  } catch (err) {
    return {
      classifier: null,
      reason: `the model is installed but its runtime (${RUNTIME_MODULE}) is not: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  // THE GLOBAL SWITCH, not just the per-call option. "No network call during inference" (SI-001 /
  // INV-1) rested entirely on `local_files_only` below — one option, on one call, in a library whose
  // default is to fetch from the hub. `allowRemoteModels = false` is the library's own kill switch
  // and it is what makes the property hold rather than a comment claiming it does.
  const env = (mod as { env?: Record<string, unknown> }).env;
  if (env && typeof env === "object") {
    env["allowRemoteModels"] = false;
    env["allowLocalModels"] = true;
  }

  const factory = (mod as { pipeline?: PipelineFactory }).pipeline;
  if (typeof factory !== "function") {
    return { classifier: null, reason: `${RUNTIME_MODULE} exports no 'pipeline' — refusing to guess at its shape` };
  }

  let pipe: Pipe;
  try {
    // LOCAL FILES ONLY. The scanner's contract is "no network call during inference" (SI-001 /
    // INV-1); letting the runtime fall back to fetching from the hub would break it silently, and
    // would also bypass the installer's integrity checks entirely.
    pipe = await factory("text-classification", join(modelDir), { local_files_only: true });
  } catch (err) {
    return {
      classifier: null,
      reason: `the model failed to load from ${modelDir}: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  return {
    classifier: {
      async classify(text: string): Promise<{ injectionProbability: number; label?: string }> {
        // EVERY label, not the top one. `scoreToVerdict` is governed by P(injection), and asking
        // for only the winner returns SAFE's score when the text is benign — which would read as a
        // LOW injection probability for exactly the same reason it read as a high one. The scanner
        // already documents that the score governs and a disagreeing label never overrides it;
        // that only holds if the score handed to it is the injection score.
        const scores = await pipe(text, { top_k: 0 });
        const injection = scores.find((s) => s.label.toUpperCase() === "INJECTION");
        if (injection) return { injectionProbability: injection.score, label: injection.label };
        const safe = scores.find((s) => s.label.toUpperCase() === "SAFE");
        if (safe) return { injectionProbability: 1 - safe.score, label: safe.label };
        // A label set this build does not recognise. REFUSE TO SCORE rather than invent one: a
        // fabricated 0 would report Layer 2 as working while blocking nothing.
        throw new Error(`classifier returned no INJECTION or SAFE label (got: ${scores.map((s) => s.label).join(", ")})`);
      },
    },
  };
}
