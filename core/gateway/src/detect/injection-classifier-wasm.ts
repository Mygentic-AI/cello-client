/**
 * 080-SCREENERCPU — the same model through onnxruntime-web's WASM kernels.
 *
 * The fallback for CPUs whose native int8 kernels give wrong scores (x86 without AVX512-VNNI).
 * transformers.js in Node rejects `device: "wasm"`, so this drives onnxruntime-web directly, fed by
 * the model's own tokenizer, over the same `onnx/model.onnx`, windows and aggregation as native.
 *
 * onnxruntime-web is already installed in the screener runtime directory as a dependency of
 * transformers — nothing new is downloaded. Its `.wasm` is loaded from that local package, never a
 * CDN: `wasmPaths` is set to the package's own `dist/` before any session is created.
 */
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import { resolveScreenerRuntime, screenerRuntimeDir } from "./screener-state.js";
import { SCREENER_MODEL } from "./screener-model-manifest.js";
import { textWindows, aggregateWindowScores, type WindowTokenizer } from "./injection-windows.js";
import type { ClassifierLoad } from "./injection-classifier-onnx.js";

const WASM_MODULE = "onnxruntime-web";

interface OrtTensor { data: ArrayLike<number | bigint>; dims: readonly number[] }
interface OrtSession {
  inputNames: readonly string[];
  outputNames: readonly string[];
  run(feeds: Record<string, unknown>): Promise<Record<string, OrtTensor>>;
}
interface OrtModule {
  env: { wasm: { wasmPaths?: unknown; numThreads?: number } };
  Tensor: new (type: "int64", data: BigInt64Array, dims: readonly number[]) => unknown;
  InferenceSession: { create(bytes: Uint8Array, opts: { executionProviders: string[] }): Promise<OrtSession> };
}
type Tokenizer = WindowTokenizer & ((text: string) => Record<string, { data: ArrayLike<number | bigint>; dims: readonly number[] }>);

/** onnxruntime-web from CELLO's runtime directory, or beside transformers when npm nested it. */
function resolveOrtWeb(): string | null {
  const bases = [join(screenerRuntimeDir(), "resolver.cjs")];
  const transformers = resolveScreenerRuntime();
  if (transformers) bases.push(transformers);
  for (const base of bases) {
    try {
      return createRequire(base).resolve(WASM_MODULE);
    } catch {
      /* try the next */
    }
  }
  return null;
}

const fail = (reason: string): ClassifierLoad => ({ classifier: null, reason });
const msg = (err: unknown): string => (err instanceof Error ? err.message : String(err));

export async function loadWasmInjectionClassifier(modelDir: string): Promise<ClassifierLoad> {
  const ortPath = resolveOrtWeb();
  if (!ortPath) return fail(`${WASM_MODULE} is not installed in ${screenerRuntimeDir()}`);
  const transformersPath = resolveScreenerRuntime();
  if (!transformersPath) return fail(`@huggingface/transformers is not installed in ${screenerRuntimeDir()} (the tokenizer comes from it)`);

  let ort: OrtModule;
  let AutoTokenizer: { from_pretrained(dir: string, o: Record<string, unknown>): Promise<Tokenizer> };
  let labelIndex: number;
  let session: OrtSession;
  let tokenizer: Tokenizer;
  try {
    ort = (await import(/* @vite-ignore */ pathToFileURL(ortPath).href)) as OrtModule;
    const tf = (await import(/* @vite-ignore */ pathToFileURL(transformersPath).href)) as {
      AutoTokenizer: typeof AutoTokenizer;
      env?: Record<string, unknown>;
    };
    if (tf.env) {
      tf.env["allowRemoteModels"] = false;
      tf.env["allowLocalModels"] = true;
    }
    AutoTokenizer = tf.AutoTokenizer;
    // The package's own dist/, as a file URL: the runtime never reaches for a CDN.
    ort.env.wasm.wasmPaths = pathToFileURL(`${dirname(ortPath)}/`).href;
    ort.env.wasm.numThreads = 1;

    const config = JSON.parse(await readFile(join(modelDir, "config.json"), "utf8")) as { id2label?: Record<string, string> };
    const entry = Object.entries(config.id2label ?? {}).find(([, label]) => label.toLowerCase() === "injection");
    if (!entry) return fail(`config.json in ${modelDir} has no 'injection' label in id2label — refusing to guess the index`);
    labelIndex = Number(entry[0]);

    session = await ort.InferenceSession.create(await readFile(join(modelDir, "onnx", "model.onnx")), { executionProviders: ["wasm"] });
    tokenizer = await AutoTokenizer.from_pretrained(modelDir, { local_files_only: true });
  } catch (err) {
    return fail(`the WASM classifier failed to load from ${modelDir}: ${msg(err)}`);
  }

  async function scoreWindow(text: string): Promise<number> {
    const enc = tokenizer(text);
    const feeds: Record<string, unknown> = {};
    for (const name of session.inputNames) {
      const t = enc[name];
      if (!t) throw new Error(`the tokenizer produced no '${name}', which the model requires`);
      feeds[name] = new ort.Tensor("int64", BigInt64Array.from(Array.from(t.data, (v) => BigInt(v))), t.dims);
    }
    const out = await session.run(feeds);
    const logits = Array.from(out[session.outputNames[0]!]!.data, Number);
    const max = Math.max(...logits);
    const exps = logits.map((l) => Math.exp(l - max));
    const p = exps[labelIndex]! / exps.reduce((a, b) => a + b, 0);
    if (!Number.isFinite(p)) throw new Error(`the model returned no usable logit at index ${labelIndex}`);
    return p;
  }

  return {
    classifier: {
      async classify(text: string) {
        const windows = textWindows(text, tokenizer, SCREENER_MODEL.windowTokens, SCREENER_MODEL.windowOverlapTokens);
        const scores: number[] = [];
        for (const w of windows) scores.push(await scoreWindow(w));
        return { injectionProbability: aggregateWindowScores(scores), label: "injection" };
      },
    },
  };
}
