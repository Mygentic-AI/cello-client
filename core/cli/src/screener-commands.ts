/**
 * DOD-M9C-SCREENINSTALL-1 — `cello screener install` / `cello screener status`.
 *
 * The moment the operator is asked. `npm install` cannot be that moment: it runs headless in CI,
 * inside agent harnesses and under `npx`, and it ends when npm decides. So the ask lives at a
 * command we own, and at login (`describeScreenerState` supplies that line).
 *
 * **Consent covers BOTH halves.** Weights without the runtime cannot screen a single message, so
 * installing one without the other is a fault, not a partial success. One question, both parts.
 *
 * **Every operator-facing string here was approved by Andre** (2026-09-15, sizes corrected
 * 2026-09-17). Do not reword them in passing: the wording is his, and the tests assert the SUBSTANCE
 * each string must carry — both sources, both sizes, the manual path — so a reworded prompt that
 * silently drops the download size fails.
 */
import { spawn } from "node:child_process";
import {
  SCREENER_MODEL,
  describeScreenerState,
  installModel,
  runtimeAvailable,
  screenerModelDir,
  screenerRuntimeDir,
  screenerState,
  SCREENER_RUNTIME_MODULE,
  type InstallResult,
} from "@cello-protocol/gateway";

export interface CliOutput { stdout: string; stderr: string; exitCode: number }

/** The gateway's logger shape, narrowed to what this file emits. */
export interface ScreenerLogger {
  info(event: string, fields?: Record<string, unknown>): void;
  error(event: string, fields?: Record<string, unknown>): void;
}

/**
 * `domain.noun.verb`, with one correlationId minted per install and threaded through every event of
 * that install — so a failed download and the state it left behind are one story in the log rather
 * than two unrelated lines.
 */
function newCorrelationId(): string {
  return `screener-install-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

/**
 * Measured on 2026-09-17, not estimated: the model is 130.7 MB and the runtime's packages are
 * 110 MB compressed, unpacking to 487 MB (224 MB of which is prebuilt binaries for the platforms
 * the operator is NOT on — `DOD-M9C-RUNTIME-SLIM-1`, post-launch). An operator waits on the
 * download and lives with the disk, so the prompt states both.
 */
const DOWNLOAD_MB = 241;
const DISK_MB = 618;

/** Andre's consent prompt, verbatim. */
export function consentPrompt(): string {
  return [
    "CELLO's security screening has two layers, and only one is active.",
    "The deterministic rules are already running: fast pattern matching",
    "that stops many known attacks. We recommend pairing them with a",
    "prompt-injection classifier, which is designed to catch a different",
    "set of attacks.",
    "",
    "This downloads:",
    "  • Patronus Wolf Defender model, from Hugging Face — 131 MB",
    "  • Transformers.js by Hugging Face, with Microsoft's ONNX Runtime,",
    `    from npm — ~110 MB (both open source)`,
    "",
    `Total: about ${DOWNLOAD_MB} MB to download, about ${DISK_MB} MB on disk.`,
    "Every file is checked against its published SHA-256.",
    "",
    "Prefer to do it yourself? For instructions, run: cello screener install --manual",
  ].join("\n");
}

/** What `--manual` prints. Every value is read from the manifest — a second copy would drift. */
export function screenerManualInstructions(dir: string): string {
  const files = SCREENER_MODEL.files
    .map((f) => `  ${f.path}\n    ${SCREENER_MODEL.baseUrl}${f.path}\n    ${f.size} bytes   sha256 ${f.sha256}`)
    .join("\n");
  return [
    "Manual install. Nothing has been downloaded.",
    "",
    `1. Download these files from ${SCREENER_MODEL.repo} at revision ${SCREENER_MODEL.revision}:`,
    "",
    files,
    "",
    `2. Put them under, keeping the paths above:  ${dir}`,
    "",
    `3. Install the runtime:  npm install --prefix ${screenerRuntimeDir()} ${SCREENER_RUNTIME_MODULE}`,
    "",
    "4. Verify what you installed:  cello screener status",
    "",
    "Every file is checked against the SHA-256 above, whoever downloaded it.",
  ].join("\n");
}

export interface ScreenerCommandOptions {
  /** Where the model lives. Defaults to the revision-keyed directory the gateway reads. */
  dir?: string;
  /** Injected for tests; production asks the module loader. */
  runtimePresent?: boolean;
  verifyDigests?: boolean;
}

async function currentState(opts: ScreenerCommandOptions) {
  const dir = opts.dir ?? screenerModelDir();
  const runtimePresent = opts.runtimePresent ?? (await runtimeAvailable());
  return {
    dir,
    status: await screenerState({
      dir,
      runtimePresent,
      ...(opts.verifyDigests !== undefined ? { verifyDigests: opts.verifyDigests } : {}),
    }),
  };
}

export async function screenerStatusCommand(opts: ScreenerCommandOptions = {}): Promise<CliOutput> {
  const { dir, status } = await currentState(opts);
  const lines = [describeScreenerState(status), `Model directory: ${dir}`];
  if (status.state !== "not_installed") {
    lines.push(`Model files: ${status.model.filesPresent}/${status.model.filesExpected}${status.model.verified ? " (all digests verified)" : ""}`);
    lines.push(`Runtime (${SCREENER_RUNTIME_MODULE}): ${status.runtimePresent ? "present" : "missing"}`);
  }
  return { stdout: lines.join("\n") + "\n", stderr: "", exitCode: 0 };
}

export interface ScreenerInstallOptions extends ScreenerCommandOptions {
  /** `--yes`: proceed without asking. Required on a machine with nobody at the keyboard. */
  assumeYes: boolean;
  /** Whether a human can answer. False in CI, under `npx`, inside an agent harness. */
  interactive: boolean;
  fetchImpl?: typeof fetch;
  /** Injected for tests. Production downloads and verifies through the gateway's installer. */
  installModelImpl?: (dir: string) => Promise<InstallResult>;
  /** Injected for tests. Production shells out to npm. */
  installRuntime?: () => Promise<void>;
  /** Injected for tests: does the runtime resolve once we have installed it? */
  runtimeCheckAfterInstall?: () => Promise<boolean>;
  onProgress?: (line: string) => void;
  logger?: ScreenerLogger;
}

/**
 * Into CELLO's own directory, NOT `npm install -g`.
 *
 * A globally installed package is unreachable from an ESM `import` in a globally installed CLI —
 * measured 2026-09-17, the model verified 5/5 while the runtime still read as missing, and NODE_PATH
 * does not help because ESM ignores it. `--prefix` puts it somewhere we can resolve from, and an
 * npm upgrade of the CLI cannot wipe it.
 */
async function npmInstallRuntime(): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const child = spawn("npm", ["install", "--prefix", screenerRuntimeDir(), SCREENER_RUNTIME_MODULE], { stdio: "inherit" });
    child.on("error", reject);
    child.on("exit", (code) => (code === 0 ? resolve() : reject(new Error(`npm exited ${code}`))));
  });
}

export async function screenerInstallCommand(opts: ScreenerInstallOptions): Promise<CliOutput> {
  const { dir, status } = await currentState(opts);
  const correlationId = newCorrelationId();
  const log = opts.logger;
  log?.info("screener.install.started", { correlationId, state: status.state, dir, revision: status.revision });

  if (status.state === "ready") {
    log?.info("screener.install.skipped", { correlationId, reason: "already_installed" });
    return { stdout: `Already installed and verified.\n${describeScreenerState(status)}\n`, stderr: "", exitCode: 0 };
  }
  if (status.state === "broken") {
    // Loudest state: files are present and wrong. Never quietly re-download over them — say what is
    // wrong first, because a corrupted install that silently "fixes itself" hides a real fault.
    log?.error("screener.install.refused", { correlationId, reason: "broken_install", problem: status.problem });
    return {
      stdout: "",
      stderr: `The installed classifier is BROKEN: ${status.problem}\nDelete ${dir} and run this command again to reinstall.\n`,
      exitCode: 1,
    };
  }

  // Consent. Without it nothing is fetched — not the model, not the runtime.
  if (!opts.assumeYes) {
    log?.info("screener.install.consent_required", { correlationId, interactive: opts.interactive });
    const tail = opts.interactive
      ? "\nRun `cello screener install --yes` to proceed."
      : "\nNo terminal to ask at. Run `cello screener install --yes` to proceed.";
    return { stdout: consentPrompt() + tail + "\n", stderr: "", exitCode: 1 };
  }

  const progress = opts.onProgress ?? ((line: string) => process.stderr.write(line + "\n"));
  const needModel = status.model.filesPresent === 0 || !status.model.verified;
  const needRuntime = !status.runtimePresent;

  if (needModel) {
    progress(`Downloading the model (131 MB) to ${dir} …`);
    const install = opts.installModelImpl
      ? await opts.installModelImpl(dir)
      : await installModel({
          dir,
          consent: true,
          ...(opts.fetchImpl ? { fetchImpl: opts.fetchImpl } : {}),
          onProgress: (file, index, total) => progress(`  [${index + 1}/${total}] ${file}`),
        });
    if (!install.installed) {
      log?.error("screener.model.install.failed", { correlationId, error: install.error });
      return { stdout: "", stderr: `The model install FAILED: ${install.error ?? "unknown error"}\nNothing unverified was left on disk.\n`, exitCode: 1 };
    }
  }

  if (needRuntime) {
    progress(`Installing the runtime (${SCREENER_RUNTIME_MODULE}) …`);
    try {
      await (opts.installRuntime ?? npmInstallRuntime)();
    } catch (err) {
      log?.error("screener.runtime.install.failed", { correlationId, error: err instanceof Error ? err.message : String(err) });
      return { stdout: "", stderr: `The runtime install FAILED: ${err instanceof Error ? err.message : String(err)}\nThe model is installed; the classifier cannot run until the runtime is too.\n`, exitCode: 1 };
    }
  }

  // Re-read the state rather than assuming the install worked: "we ran the installer" is not
  // evidence, and a half-finished install must report as half-finished.
  const runtimeNow = opts.runtimeCheckAfterInstall
    ? await opts.runtimeCheckAfterInstall()
    : await runtimeAvailable();
  const after = await screenerState({
    dir,
    runtimePresent: runtimeNow,
    ...(opts.verifyDigests !== undefined ? { verifyDigests: opts.verifyDigests } : {}),
  });
  if (after.state !== "ready") {
    log?.error("screener.install.incomplete", { correlationId, state: after.state, problem: after.problem });
    return { stdout: "", stderr: `Install did not complete: ${describeScreenerState(after)}\n`, exitCode: 1 };
  }
  log?.info("screener.install.complete", { correlationId, dir, revision: after.revision, filesVerified: after.model.filesPresent });
  return { stdout: `${describeScreenerState(after)}\nModel directory: ${dir}\n`, stderr: "", exitCode: 0 };
}
