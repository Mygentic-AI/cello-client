/**
 * DOD-M9C-SCREENINSTALL-1 — is the Layer-2 screener actually usable?
 *
 * One function, because the answer has to be the same in the daemon log, `cello_status` and the CLI.
 * Three consumers reading three different checks is how "installed" came to mean three things.
 *
 * Four states, and the two in the middle are the point:
 *  - `not_installed` — no model, no runtime. Layer 2 is off BY CHOICE. Layer 1 still runs.
 *  - `half_installed` — one half without the other. A FAULT, not a choice: weights with no runtime
 *    cannot screen, and a runtime with no weights screens nothing. Reporting it as "not installed"
 *    hides a broken install behind a decision the operator never made.
 *  - `broken` — the files are there and they are wrong: a digest mismatch or a missing file. Loudest
 *    state, and it names the file, because this is the one that looks fine from a distance.
 *  - `ready` — every file present and verified, runtime present.
 *
 * `isModelInstalled` in `model-installer.ts` answers a narrower question — do the paths exist — and
 * cannot tell a truncated file from a good one. It is not a substitute for this.
 */
import { stat } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { createRequire } from "node:module";
import { SCREENER_MODEL } from "./screener-model-manifest.js";
import { sha256File } from "./model-installer.js";

/**
 * Where the model lives. Keyed by the pinned revision, so a future revision installs beside the old
 * one instead of half-overwriting it — a mixed directory is the `broken` state nobody can explain.
 * `CELLO_GATEWAY_MODEL_DIR` still wins, because the gateway has always honoured it.
 */
export function screenerModelDir(): string {
  return process.env["CELLO_GATEWAY_MODEL_DIR"] || join(homedir(), ".cello", "screener", SCREENER_MODEL.revision);
}

/** The module the classifier loads. Named once so the CLI, the state check and the loader agree. */
export const SCREENER_RUNTIME_MODULE = "@huggingface/transformers";

/**
 * Where the runtime is installed, and why it is not `npm install -g`.
 *
 * A global npm install puts the package in npm's global root, and **Node's ESM resolver does not
 * look there**: a bare `import("@huggingface/transformers")` from a globally installed CLI resolves
 * against that CLI's own package tree and fails. Proven on 2026-09-17 — the model verified 5/5 and
 * the runtime still read as missing with the package installed, and `NODE_PATH` does not help
 * either, because ESM ignores it.
 *
 * So the runtime lives in a directory CELLO owns and is imported by ABSOLUTE path. That also
 * survives an npm upgrade of the CLI, which would otherwise wipe anything written into its tree.
 */
export function screenerRuntimeDir(): string {
  return process.env["CELLO_SCREENER_RUNTIME_DIR"] || join(homedir(), ".cello", "screener-runtime");
}

/**
 * The absolute file the loader imports, or null when the runtime is not installed there.
 *
 * Resolved with `require.resolve` FROM the runtime directory, because that honours the package's
 * `exports` map. Importing the package DIRECTORY instead picks its CommonJS `main` with no
 * conditions applied, and Node then refuses it with ERR_AMBIGUOUS_MODULE_SYNTAX — measured
 * 2026-09-17, and it is why this returns a file rather than a directory.
 */
export function resolveScreenerRuntime(): string | null {
  try {
    const require = createRequire(join(screenerRuntimeDir(), "resolver.cjs"));
    return require.resolve(SCREENER_RUNTIME_MODULE);
  } catch {
    return null;
  }
}

/**
 * Does the runtime resolve from here? A dynamic import in a try/catch, deliberately: the gateway
 * must not take a hard dependency on a 487 MB package that most installs will never have.
 */
export async function runtimeAvailable(importImpl?: (s: string) => Promise<unknown>): Promise<boolean> {
  const doImport = importImpl ?? ((s: string) => import(/* @vite-ignore */ s));
  // CELLO's own directory first — that is where `cello screener install` puts it. The bare
  // specifier second, for a workspace or an operator who installed it as a dependency themselves.
  const resolved = resolveScreenerRuntime();
  for (const specifier of [...(resolved ? [pathToFileURL(resolved).href] : []), SCREENER_RUNTIME_MODULE]) {
    try {
      await doImport(specifier);
      return true;
    } catch {
      /* try the next */
    }
  }
  return false;
}

export type ScreenerStateName = "not_installed" | "half_installed" | "broken" | "ready";

export interface ScreenerStatus {
  state: ScreenerStateName;
  /** The pinned commit this manifest expects — two installs of different revisions are different. */
  revision: string;
  model: { filesPresent: number; filesExpected: number; verified: boolean };
  runtimePresent: boolean;
  /** Which half is absent, for `half_installed`. */
  missing: Array<"model" | "runtime">;
  /** For `broken`: what is wrong, naming the file. */
  problem?: string;
}

export interface ScreenerStateOptions {
  /** Where the model files live. */
  dir: string;
  /** Whether the runtime module resolves. The caller decides — the gateway must not import it. */
  runtimePresent: boolean;
  /**
   * Verify every file's SHA-256 (default true). The digest is what proves the bytes; size alone
   * passes for a same-length forgery. Tests turn it off to isolate the presence checks.
   */
  verifyDigests?: boolean;
}

export async function screenerState(opts: ScreenerStateOptions): Promise<ScreenerStatus> {
  const verify = opts.verifyDigests ?? true;
  let present = 0;
  let problem: string | undefined;
  const absent: string[] = [];

  for (const f of SCREENER_MODEL.files) {
    const path = join(opts.dir, f.path);
    let size: number;
    try {
      size = (await stat(path)).size;
    } catch {
      absent.push(f.path); // judged below: some present + some absent is a half-written install
      continue;
    }
    present++;
    if (problem !== undefined) continue;
    if (size !== f.size) {
      problem = `${f.path} is ${size} bytes, expected ${f.size}`;
    } else if (verify && (await sha256File(path)) !== f.sha256) {
      problem = `${f.path} does not match its pinned SHA-256 — the file is not the one we verified`;
    }
  }

  const expected = SCREENER_MODEL.files.length;
  const model = { filesPresent: present, filesExpected: expected, verified: present === expected && problem === undefined };
  const base = { revision: SCREENER_MODEL.revision, model, runtimePresent: opts.runtimePresent };

  // Partially present is BROKEN, not "not installed": an install died halfway and the next run must
  // not read the leftovers as a deliberate absence.
  if (present > 0 && present < expected) {
    return { ...base, state: "broken", missing: [], problem: problem ?? `${absent.length} model file(s) missing: ${absent.join(", ")}` };
  }
  if (present === expected && problem !== undefined) {
    return { ...base, state: "broken", missing: [], problem };
  }

  const missing: Array<"model" | "runtime"> = [];
  if (present === 0) missing.push("model");
  if (!opts.runtimePresent) missing.push("runtime");
  if (missing.length === 2) return { ...base, state: "not_installed", missing };
  if (missing.length === 1) return { ...base, state: "half_installed", missing };
  return { ...base, state: "ready", missing: [] };
}

/**
 * May the classifier be loaded? Only from a `ready` install.
 *
 * `broken` is the state this exists for: the files are present, so an existence check says yes, and
 * the gateway then announces `layer2=active` over a model whose digests do not match. Presence is
 * not integrity, and the decision belongs at the composition root, where the state is already known.
 */
export function classifierLoadable(s: ScreenerStatus): { load: boolean; reason?: string } {
  if (s.state === "ready") return { load: true };
  if (s.state === "broken") {
    return { load: false, reason: `model FAILED verification and was NOT loaded: ${s.problem ?? "unknown fault"} — repair it with 'cello screener install --repair'` };
  }
  return { load: false, reason: `classifier not installed (${s.state}) — install it with 'cello screener install'` };
}

/** One sentence per state, and every sentence that is not `ready` names the command that fixes it. */
export function describeScreenerState(s: ScreenerStatus): string {
  const fix = "Run: cello screener install";
  switch (s.state) {
    case "ready":
      return `Screening: 2 of 2 layers active (classifier ${s.revision.slice(0, 8)} verified).`;
    case "not_installed":
      return `Screening: 1 of 2 layers active (classifier not installed). ${fix}`;
    case "half_installed":
      return `Screening: 1 of 2 layers active — the ${s.missing.join(" and ")} is missing, so the classifier cannot run. ${fix}`;
    case "broken":
      return `Screening: 1 of 2 layers active — the classifier is BROKEN: ${s.problem ?? "unknown fault"}. ${fix}`;
  }
}
