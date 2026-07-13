/**
 * Test helper: spawn the REAL cello-daemon binary as a separate OS process.
 *
 * Why this exists (DOD-DAEMON-CLEANUP-1 / DOD-SINGLE-DAEMON-1): both defects are about one daemon
 * process acting on state that ANOTHER process owns — a lock whose pid is not its own, a socket it
 * did not create, a kernel lock another process holds. None of that can be reproduced by an
 * in-process daemon, which shares the test runner's pid and its file locks. `daemon.lock` written
 * with `process.pid` would look "ours" to an in-process daemon no matter what, and a POSIX lock the
 * test process already holds is not contended by a second connection in that same process. This
 * trap already bit DOD-LOGOUT-WAIT-1's first AC2 attempt.
 *
 * So: a real `node --import tsx bin/cello-daemon.ts` child, with its own pid. Extends the pattern
 * established by `binary.test.ts` (AC-011) rather than inventing a second one.
 */

import { spawn, type ChildProcess } from "node:child_process";
import { mkdtemp, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FileKeyProvider } from "@cello-protocol/crypto";

/**
 * A real daemon is expensive to start: a fresh node process, tsx transpiling the whole daemon (6k+
 * lines) and its dependency graph, the SQLCipher native module, the DB, agent loading. On an idle
 * machine that is 2-3 seconds. But vitest runs test FILES in parallel, so several of these can be
 * booting at once — and CI is slower than a dev laptop. A budget that is merely "usually enough"
 * produces a suite that goes red for reasons that have nothing to do with the code under test, which
 * is worse than useless: it teaches everyone to re-run instead of read. Be generous.
 */
const SPAWN_WAIT_MS = 30_000;

export interface SpawnedDaemon {
  readonly child: ChildProcess;
  readonly pid: number;
  /** Everything the daemon has written to stdout+stderr so far. */
  output(): string;
  /** Resolve with the parsed JSON log line for `event`, or reject on timeout/exit. */
  waitForEvent(event: string, timeoutMs?: number): Promise<Record<string, unknown>>;
  /** Resolve when the process exits. */
  waitForExit(timeoutMs?: number): Promise<{ code: number | null; signal: NodeJS.Signals | null }>;
  kill(signal: NodeJS.Signals): void;
  /** SIGTERM and wait for a clean exit (the graceful-shutdown path). */
  stopGracefully(timeoutMs?: number): Promise<{ code: number | null; signal: NodeJS.Signals | null }>;
}

/** A temp CELLO_DIR with one real agent key — the shape `binary.test.ts` proves the daemon boots on. */
export async function makeCelloDir(prefix = "cello-singleton-"): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), prefix));
  const agentDir = join(dir, "agents", "singleton-test-agent");
  await mkdir(agentDir, { recursive: true });
  await FileKeyProvider.load(join(agentDir, "key"));
  return dir;
}

export async function cleanupCelloDir(dir: string | undefined): Promise<void> {
  if (dir) await rm(dir, { recursive: true, force: true });
}

export function spawnRealDaemon(celloDir: string, env: Record<string, string> = {}): SpawnedDaemon {
  const daemonBin = join(import.meta.dirname, "../../bin/cello-daemon.ts");
  const child = spawn(process.execPath, ["--import", "tsx", daemonBin], {
    // tsx is a devDep of THIS package (pnpm isolated layout) — pin cwd to the package root so
    // `--import tsx` resolves under a workspace-root vitest run too.
    cwd: join(import.meta.dirname, "../../.."),
    env: { ...process.env, CELLO_DIR: celloDir, CELLO_VERSION: "0.0.1-singleton-test", ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });

  let buf = "";
  child.stdout?.on("data", (c: Buffer) => { buf += c.toString("utf-8"); });
  child.stderr?.on("data", (c: Buffer) => { buf += c.toString("utf-8"); });

  let exited: { code: number | null; signal: NodeJS.Signals | null } | null = null;
  child.on("exit", (code, signal) => { exited = { code, signal }; });

  const findEvent = (name: string): Record<string, unknown> | null => {
    for (const line of buf.split("\n")) {
      if (!line.trim()) continue;
      try {
        const parsed = JSON.parse(line) as Record<string, unknown>;
        if (parsed.event === name) return parsed;
      } catch { /* not a JSON log line */ }
    }
    return null;
  };

  return {
    child,
    get pid(): number {
      if (child.pid === undefined) throw new Error("daemon child has no pid");
      return child.pid;
    },
    output: () => buf,
    async waitForEvent(event: string, timeoutMs = SPAWN_WAIT_MS): Promise<Record<string, unknown>> {
      const deadline = Date.now() + timeoutMs;
      while (Date.now() < deadline) {
        const found = findEvent(event);
        if (found) return found;
        if (exited) {
          throw new Error(`daemon exited (code ${exited.code}) before "${event}".\n--- output ---\n${buf}`);
        }
        await new Promise((r) => setTimeout(r, 50));
      }
      throw new Error(`timed out waiting for "${event}".\n--- output ---\n${buf}`);
    },
    async waitForExit(timeoutMs = SPAWN_WAIT_MS): Promise<{ code: number | null; signal: NodeJS.Signals | null }> {
      const deadline = Date.now() + timeoutMs;
      while (Date.now() < deadline) {
        if (exited) return exited;
        await new Promise((r) => setTimeout(r, 50));
      }
      throw new Error(`daemon did not exit within ${timeoutMs}ms.\n--- output ---\n${buf}`);
    },
    kill(signal: NodeJS.Signals): void {
      if (!exited) child.kill(signal);
    },
    async stopGracefully(timeoutMs = SPAWN_WAIT_MS) {
      if (!exited) child.kill("SIGTERM");
      return this.waitForExit(timeoutMs);
    },
  };
}

/** Every JSON log line the daemon emitted with this event name. */
export function logEvents(output: string, event: string): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = [];
  for (const line of output.split("\n")) {
    if (!line.trim()) continue;
    try {
      const parsed = JSON.parse(line) as Record<string, unknown>;
      if (parsed.event === event) out.push(parsed);
    } catch { /* not a JSON log line */ }
  }
  return out;
}
