/**
 * spawnGatewaySidecar — launch the gateway as a child process.
 *
 * The composition root (the daemon bin in local mode) and the integration test both use this:
 * the gateway is a genuinely separate OS process, reached only over its socket. Resolves once
 * the child has printed its READY line (so the caller never races a not-yet-listening socket).
 */
import { spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";

/** Printed by the gateway bin on stdout once it is listening. */
export const GATEWAY_READY_TOKEN = "GATEWAY_READY";

export interface SpawnGatewayOptions {
  socketPath: string;
  /**
   * The gateway entry to run. Defaults to this package's built dist bin
   * (dist/bin/cello-gateway.js) run with node — the production path.
   */
  entryPath?: string;
  /** Extra env for the child. */
  env?: Record<string, string>;
  /** How long to wait for the READY line before giving up. */
  readyTimeoutMs?: number;
}

export interface SpawnedGateway {
  /**
   * What the child reported about Layer 2 on its ready line — `active`, or `off:<reason>`.
   *
   * Carried out of the child DELIBERATELY. It used to be written to the gateway's stderr, which is
   * drained into a tail this module only surfaces when the spawn FAILS — so on a successful boot
   * the state was captured and discarded, and "is semantic screening on?" had no answer anywhere.
   * The parent logs this; that log line is the whole point.
   */
  readonly layer2: string;
  readonly socketPath: string;
  readonly pid: number | undefined;
  readonly process: ChildProcess;
  stop(): Promise<void>;
}

const DEFAULT_READY_TIMEOUT_MS = 10_000;

function defaultEntryPath(): string {
  // dist/spawn.js → dist/bin/cello-gateway.js
  return new URL("./bin/cello-gateway.js", import.meta.url).pathname;
}

export async function spawnGatewaySidecar(opts: SpawnGatewayOptions): Promise<SpawnedGateway> {
  const entry = opts.entryPath ?? defaultEntryPath();
  const child = spawn(process.execPath, [entry], {
    // stdin is a PIPE, not "ignore", and it is the child's death switch (review F5). A daemon that
    // dies without running its shutdown path — SIGKILL, a crash, the OOM killer — leaves the
    // gateway alive holding the encrypted store's write lock. The NEXT daemon's gateway then hits
    // `store_locked`, exits before ready, and with no auto-restart (M9B-D14) that daemon spends its
    // whole life fail-closed on one boot log line. When the parent dies the kernel closes this
    // pipe, and the child exits on the `end` event.
    stdio: ["pipe", "pipe", "pipe"],
    env: {
      ...process.env,
      ...opts.env,
      CELLO_GATEWAY_SOCKET: opts.socketPath,
    },
  });

  const readyTimeoutMs = opts.readyTimeoutMs ?? DEFAULT_READY_TIMEOUT_MS;
  let layer2 = "unreported";

  // DRAIN the child's stderr and keep the tail. Two reasons, and the first one is the whole point:
  // every refusal the gateway can produce — a missing key file, a locked store, a leftover
  // plaintext store, each with its own code and its own guidance — is written HERE. Without a
  // listener it went into a pipe nobody read, and the only thing the caller ever saw was
  // "gateway sidecar exited before ready (code 1)" — a message naming where the failure surfaced
  // and nothing about what went wrong. Second: an unread pipe fills, and the gateway writes a
  // stderr line per screen error, so a long-running gateway would eventually block on it.
  // A ChildProcess with no `error` listener turns a spawn-level failure (EMFILE, ENOMEM, EACCES)
  // into an UNCAUGHT exception on a later tick — outside the caller's try — which would kill the
  // daemon at boot rather than letting it degrade to the announced fail-closed mode (review F11).
  // The promise below rejects on `exit`; this makes sure `error` cannot escape in the meantime.
  let stderrTail = "";
  const MAX_STDERR_TAIL = 8_192;
  child.stderr?.on("data", (chunk: Buffer) => {
    stderrTail = (stderrTail + chunk.toString("utf8")).slice(-MAX_STDERR_TAIL);
  });
  /** The child's own words, appended to a failure so the CAUSE travels with the symptom. */
  const withChildStderr = (message: string): string =>
    stderrTail.trim() ? `${message}\n--- gateway stderr ---\n${stderrTail.trim()}` : message;

  await new Promise<void>((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill("SIGKILL");
      reject(new Error(withChildStderr(`gateway sidecar did not become ready within ${readyTimeoutMs}ms`)));
    }, readyTimeoutMs);

    const onStdout = (chunk: Buffer) => {
      const text = chunk.toString("utf8");
      if (text.includes(GATEWAY_READY_TOKEN)) {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        child.stdout?.off("data", onStdout);
        // ABSENT IS NOT FINE, and it is not "off" either: an older child that does not report at
        // all is a different fact from one reporting Layer 2 disabled, and calling it `off` would
        // invent a state nobody observed.
        const m = /layer2=(\S+)/.exec(text);
        layer2 = m?.[1] ?? "unreported";
        resolve();
      }
    };
    child.stdout?.on("data", onStdout);
    const fail = (message: string): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new Error(withChildStderr(message)));
    };
    child.once("exit", (code) => fail(`gateway sidecar exited before ready (code ${code})`));
    // The spawn itself failing is a different cause from the child exiting, and the operator needs
    // to be able to tell them apart.
    child.once("error", (err: Error) => fail(`gateway sidecar could not be spawned: ${err.message}`));
  });

  return {
    layer2,
    socketPath: opts.socketPath,
    pid: child.pid,
    process: child,
    async stop(): Promise<void> {
      if (child.exitCode !== null || child.signalCode !== null) return;
      child.kill("SIGTERM");
      // Give it a moment to stop cleanly, then force. Clear the force timer if it exits first so
      // no stray timer lingers (L4 review).
      const exited = once(child, "exit");
      let forceTimer: ReturnType<typeof setTimeout> | undefined;
      const forced = new Promise<void>((resolve) => {
        forceTimer = setTimeout(() => { child.kill("SIGKILL"); resolve(); }, 2_000);
        if (typeof (forceTimer as { unref?: () => void }).unref === "function") (forceTimer as { unref: () => void }).unref();
      });
      try {
        await Promise.race([exited, forced]);
      } finally {
        if (forceTimer) clearTimeout(forceTimer);
      }
    },
  };
}
