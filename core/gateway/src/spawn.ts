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
  /** When set, the gateway appends one request-log line per screen request here. */
  requestLogPath?: string;
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
    stdio: ["ignore", "pipe", "pipe"],
    env: {
      ...process.env,
      ...opts.env,
      CELLO_GATEWAY_SOCKET: opts.socketPath,
      ...(opts.requestLogPath ? { CELLO_GATEWAY_REQUEST_LOG: opts.requestLogPath } : {}),
    },
  });

  const readyTimeoutMs = opts.readyTimeoutMs ?? DEFAULT_READY_TIMEOUT_MS;

  await new Promise<void>((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill("SIGKILL");
      reject(new Error(`gateway sidecar did not become ready within ${readyTimeoutMs}ms`));
    }, readyTimeoutMs);

    const onStdout = (chunk: Buffer) => {
      if (chunk.toString("utf8").includes(GATEWAY_READY_TOKEN)) {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        child.stdout?.off("data", onStdout);
        resolve();
      }
    };
    child.stdout?.on("data", onStdout);
    child.once("exit", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new Error(`gateway sidecar exited before ready (code ${code})`));
    });
  });

  return {
    socketPath: opts.socketPath,
    pid: child.pid,
    process: child,
    async stop(): Promise<void> {
      if (child.exitCode !== null || child.signalCode !== null) return;
      child.kill("SIGTERM");
      // Give it a moment to stop cleanly, then force.
      const exited = once(child, "exit");
      const forced = new Promise<void>((resolve) => {
        const t = setTimeout(() => { child.kill("SIGKILL"); resolve(); }, 2_000);
        if (typeof (t as { unref?: () => void }).unref === "function") (t as { unref: () => void }).unref();
      });
      await Promise.race([exited, forced]);
    },
  };
}
