/**
 * DOD-DOC-SCREEN-CLASSIFIER-1 — the production classifier, and the reason it loads lazily.
 *
 * INTEGRITY IS THE CALLER'S TO CHECK, and `bin/cello-gateway.ts` checks it: this function gates on
 * file EXISTENCE, which cannot tell a swapped model from the verified one. The composition root
 * asks `screenerState` first and refuses to call this at all when the digests do not match
 * (DOD-M9C-SCREENINSTALL-1). Calling it directly over unverified files is a way to load a model
 * nobody checked.
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
import { resolveScreenerRuntime } from "./screener-state.js";
import { SCREENER_MODEL } from "./screener-model-manifest.js";
import { buildWindows, aggregateWindowScores } from "./injection-windows.js";

interface TokenizerLike {
  encode(text: string): number[];
  decode(ids: number[], opts?: { skip_special_tokens?: boolean }): string;
}

/**
 * P(injection) from one window's label scores.
 *
 * EVERY label, not the winner: asking for the top label alone returns the BENIGN score on benign
 * text, which reads as a low injection probability for the same reason it read as a high one.
 *
 * Patronus emits `injection` / `benign`; older guards emit `INJECTION` / `SAFE`. Both are read, and
 * an unrecognised set THROWS rather than inventing a number — a fabricated 0 reports Layer 2 as
 * working while blocking nothing. Until DOD-M9C-SCREENWIRE-1 this knew only INJECTION/SAFE, so the
 * shipped model threw on every benign message and Layer 2 reported itself degraded.
 */
export function injectionProbabilityOf(scores: ReadonlyArray<{ label: string; score: number }>): { probability: number; label: string } {
  if (scores.length === 0) {
    throw new Error("classifier returned NO labels — the pipeline was asked for none (top_k), so nothing was scored");
  }
  const byLabel = (name: string) => scores.find((s) => s.label.toUpperCase() === name);
  const injection = byLabel("INJECTION");
  if (injection) return { probability: injection.score, label: injection.label };
  const complement = byLabel("BENIGN") ?? byLabel("SAFE");
  if (complement) return { probability: 1 - complement.score, label: complement.label };
  throw new Error(`classifier returned no INJECTION, BENIGN or SAFE label (got: ${scores.map((s) => s.label).join(", ")})`);
}
import { pathToFileURL } from "node:url";
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
/** `top_k: null` asks for every label; `0` asks for none and returns an empty array. */
type Pipe = (text: string, opts?: { top_k?: number | null }) => Promise<Array<{ label: string; score: number }>>;
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
      // NAMES WHAT EXISTS. This used to say the weights were "not fetched by any command yet",
      // which was true and is no longer: DOD-M9C-SCREENINSTALL-1 built the command. Guidance that
      // names a verb nobody built is a defect; so is guidance that outlives the gap it described.
      reason:
        `no model at ${modelDir} — semantic injection screening is OFF. Install it with ` +
        `'cello screener install' (about 241 MB), or set CELLO_GATEWAY_MODEL_DIR to a directory ` +
        `that already holds the model files`,
    };
  }

  // DOD-M9C-SCREENINSTALL-1: the runtime lives in CELLO's own directory (see `screener-state.ts`
  // for why a global npm install is unreachable from an ESM import), so the loader asks for the
  // file that resolution found, and falls back to the bare specifier for a workspace install.
  const resolvedRuntime = resolveScreenerRuntime();
  const runtimeSpecifier = resolvedRuntime ? pathToFileURL(resolvedRuntime).href : RUNTIME_MODULE;

  let mod: unknown;
  try {
    // Indirection through a variable: a bare dynamic import of a name that is not a dependency is
    // resolved eagerly by some bundlers, which would turn an optional runtime into a hard one.
    const doImport = importImpl ?? ((s: string) => import(/* @vite-ignore */ s));
    mod = await doImport(runtimeSpecifier);
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

  /**
   * The message as windows of TEXT, cut on token boundaries.
   *
   * The pipeline carries the model's own tokenizer, so the split is in the units the window is
   * measured in. Without a tokenizer the honest thing is one window: guessing a character count
   * would cut mid-token and change what the model reads.
   */
  async function textWindows(text: string, pipeline: Pipe): Promise<string[]> {
    const tok = (pipeline as unknown as { tokenizer?: TokenizerLike }).tokenizer;
    if (!tok || typeof tok.encode !== "function" || typeof tok.decode !== "function") return [text];
    let ids: number[];
    try {
      ids = tok.encode(text);
    } catch {
      return [text];
    }
    if (ids.length <= SCREENER_MODEL.windowTokens) return [text];
    return buildWindows(ids, SCREENER_MODEL.windowTokens, SCREENER_MODEL.windowOverlapTokens).map((w) =>
      tok.decode(w, { skip_special_tokens: true }),
    );
  }

  return {
    classifier: {
      async classify(text: string): Promise<{ injectionProbability: number; label?: string }> {
        // EVERY label, not the top one. `scoreToVerdict` is governed by P(injection), and asking
        // for only the winner returns SAFE's score when the text is benign — which would read as a
        // LOW injection probability for exactly the same reason it read as a high one. The scanner
        // already documents that the score governs and a disagreeing label never overrides it;
        // that only holds if the score handed to it is the injection score.
        // WINDOWED, so nothing past the model's window goes unscreened. A single call truncates,
        // and a truncated scan is a gap that looks exactly like coverage.
        const windows = await textWindows(text, pipe);
        const scores: number[] = [];
        let lastLabel: string | undefined;
        for (const window of windows) {
          // `top_k: null` means EVERY label. `top_k: 0` — what this passed until
          // DOD-M9C-SCREENWIRE-1 — returns an EMPTY array from the real library, so the classifier
          // threw on every message it was asked to score. Every test mocked the pipe, so the option
          // that reaches the model was the one thing none of them exercised.
          const result = await pipe(window, { top_k: null });
          const { probability, label } = injectionProbabilityOf(result);
          scores.push(probability);
          lastLabel = label;
        }
        return { injectionProbability: aggregateWindowScores(scores), ...(lastLabel ? { label: lastLabel } : {}) };
      },
    },
  };
}
