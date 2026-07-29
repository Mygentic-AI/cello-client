/**
 * DOD-M9C-GATE-1 — THE ENFORCER, and the lesson of this whole milestone encoded as a test.
 *
 * M9's original gate spawned real processes and screened real messages, and it was green for weeks
 * while the shipped product screened NOTHING. The gate injected the gateway client itself — it
 * proved the layer works WHEN CONNECTED and hid that only the test connected it. Every daemon in
 * the field announced `mode:"passthrough"` the whole time.
 *
 * So this test may not construct a gateway client, may not call `startDaemon` in-process, and may
 * not set `config.securityGateway`. It spawns the BUILT `cello-daemon` binary — the exact artifact
 * an operator runs — and reads what the product itself does. Anything less is theatre.
 *
 * The bar an informed skeptic applies: run the daemon and grep the log for the mode.
 */
import { describe, it, expect, beforeAll, beforeEach, afterEach } from "vitest";
import { spawn, execFileSync, type ChildProcess } from "node:child_process";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const PKG_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const REPO_ROOT = join(PKG_ROOT, "..", "..");
const DAEMON_BIN = join(PKG_ROOT, "dist", "bin", "cello-daemon.js");

interface BootedDaemon {
  child: ChildProcess;
  /** Every structured log line the daemon has written to stdout so far. */
  lines: () => Array<Record<string, unknown>>;
  stderr: () => string;
}

/** Boot the SHIPPED binary against a throwaway CELLO_DIR and wait for a named event. */
async function bootDaemon(celloDir: string, waitFor: string, timeoutMs = 30_000): Promise<BootedDaemon> {
  const child = spawn(process.execPath, [DAEMON_BIN], {
    env: {
      ...process.env,
      CELLO_DIR: celloDir,
      // No directory to reach in this test; the daemon tolerates it and still boots its own parts.
      CELLO_DIRECTORY_URL: "http://127.0.0.1:1",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });

  const parsed: Array<Record<string, unknown>> = [];
  let stderrBuf = "";
  let stdoutBuf = "";
  child.stdout!.on("data", (chunk: Buffer) => {
    stdoutBuf += chunk.toString("utf8");
    const parts = stdoutBuf.split("\n");
    stdoutBuf = parts.pop() ?? "";
    for (const line of parts) {
      if (!line.trim()) continue;
      try { parsed.push(JSON.parse(line) as Record<string, unknown>); } catch { /* not a log line */ }
    }
  });
  child.stderr!.on("data", (chunk: Buffer) => { stderrBuf += chunk.toString("utf8"); });

  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (parsed.some((l) => l.event === waitFor)) {
      return { child, lines: () => [...parsed], stderr: () => stderrBuf };
    }
    if (child.exitCode !== null) {
      throw new Error(`daemon exited (${child.exitCode}) before '${waitFor}'. stderr: ${stderrBuf}`);
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  child.kill("SIGKILL");
  throw new Error(`daemon never logged '${waitFor}' within ${timeoutMs}ms. stderr: ${stderrBuf}`);
}

async function stopDaemon(d: BootedDaemon): Promise<void> {
  if (d.child.exitCode !== null) return;
  d.child.kill("SIGTERM");
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline && d.child.exitCode === null) {
    await new Promise((r) => setTimeout(r, 100));
  }
  if (d.child.exitCode === null) d.child.kill("SIGKILL");
}

describe("DOD-M9C-GATE-1 — the SHIPPED daemon runs the security layer", () => {
  let dir: string;
  let booted: BootedDaemon | undefined;

  beforeAll(() => {
    // Build both packages: the daemon bin spawns the gateway bin out of the gateway's dist.
    execFileSync("npx", ["tsc", "--build", "core/gateway", "core/daemon"], {
      cwd: REPO_ROOT, stdio: "pipe", timeout: 300_000,
    });
  }, 320_000);

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "cello-m9c-gate-"));
  });
  afterEach(async () => {
    if (booted) { await stopDaemon(booted); booted = undefined; }
    await rm(dir, { recursive: true, force: true });
  });

  it("announces mode:'enforcing' at boot — the field an operator greps, from a stock install", async () => {
    booted = await bootDaemon(dir, "security.gateway.connected");
    const event = booted.lines().find((l) => l.event === "security.gateway.connected")!;

    // THE assertion this milestone exists for. It said "passthrough" on every real daemon for weeks.
    expect(event.mode).toBe("enforcing");

    // And it is not merely a relabelled stub: the sidecar is a real OS process.
    const spawned = booted.lines().find((l) => l.event === "security.gateway.spawned");
    expect(spawned, "the daemon must actually spawn the screening process").toBeDefined();
    expect(typeof spawned!.pid).toBe("number");
    expect(spawned!.pid).toBeGreaterThan(0);

    // No shipped path may construct the always-allow stub (INV-9).
    expect(booted.lines().some((l) => l.mode === "passthrough")).toBe(false);
  }, 60_000);

  it("creates its ENCRYPTED store beside the daemon's own database, under the same key", async () => {
    booted = await bootDaemon(dir, "security.gateway.spawned");
    // Give the sidecar a moment to open its store.
    await new Promise((r) => setTimeout(r, 1_500));

    const storePath = join(dir, "gateway.db");
    expect(existsSync(storePath), "the gateway store must live in the backed-up directory").toBe(true);
    // The key is the daemon's own — one key, one backup unit (policy D-3).
    expect(existsSync(join(dir, "sessions.db.key"))).toBe(true);

    // Ciphertext, not a plaintext SQLite file.
    const head = (await readFile(storePath)).subarray(0, 16);
    expect(head.equals(Buffer.from("SQLite format 3\0", "latin1"))).toBe(false);
  }, 60_000);

  it("the environment cannot loosen a guard on the shipped daemon either (D-5, end to end)", async () => {
    // The daemon spawns the sidecar with its own env, and the removed variables are inert. Booting
    // with the most permissive values must change nothing about how it comes up.
    const child = spawn(process.execPath, [DAEMON_BIN], {
      env: {
        ...process.env,
        CELLO_DIR: dir,
        CELLO_DIRECTORY_URL: "http://127.0.0.1:1",
        CELLO_GATEWAY_AUTONOMOUS_OVERRIDE: "1",
        CELLO_GATEWAY_PII_WHITELIST: "secret@leak.example",
        CELLO_GATEWAY_RATE_MAX_PER_WINDOW: "9999",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const lines: Array<Record<string, unknown>> = [];
    let buf = "";
    child.stdout!.on("data", (c: Buffer) => {
      buf += c.toString("utf8");
      const parts = buf.split("\n");
      buf = parts.pop() ?? "";
      for (const line of parts) {
        if (!line.trim()) continue;
        try { lines.push(JSON.parse(line) as Record<string, unknown>); } catch { /* ignore */ }
      }
    });
    booted = { child, lines: () => [...lines], stderr: () => "" };

    const deadline = Date.now() + 30_000;
    while (Date.now() < deadline && !lines.some((l) => l.event === "security.gateway.connected")) {
      await new Promise((r) => setTimeout(r, 100));
    }
    const event = lines.find((l) => l.event === "security.gateway.connected");
    expect(event, "the daemon must still come up").toBeDefined();
    expect(event!.mode).toBe("enforcing");
    // No config row can have been written by an environment variable — the store is the only way in.
    const { GatewayConfigStore } = await import("@cello-protocol/gateway");
    await new Promise((r) => setTimeout(r, 1_500));
    const store = new GatewayConfigStore(join(dir, "gateway.db"), join(dir, "sessions.db.key"));
    try {
      expect(store.history("autonomous_override")).toEqual([]);
      expect(store.history("pii_whitelist")).toEqual([]);
      expect(store.history("rate_max_per_window")).toEqual([]);
    } finally {
      store.close();
    }
  }, 60_000);

  it("SIGTERM takes the sidecar down with the daemon — no orphan holding the store lock", async () => {
    booted = await bootDaemon(dir, "security.gateway.spawned");
    const spawned = booted.lines().find((l) => l.event === "security.gateway.spawned")!;
    const sidecarPid = spawned.pid as number;

    const alive = (pid: number): boolean => {
      try { process.kill(pid, 0); return true; } catch { return false; }
    };
    expect(alive(sidecarPid)).toBe(true);

    await stopDaemon(booted);
    booted = undefined;

    // An orphaned gateway would hold the encrypted store's write lock against the next daemon.
    const deadline = Date.now() + 10_000;
    while (Date.now() < deadline && alive(sidecarPid)) {
      await new Promise((r) => setTimeout(r, 100));
    }
    expect(alive(sidecarPid), "the screening process must not outlive the daemon").toBe(false);
  }, 60_000);
});
