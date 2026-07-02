/**
 * CELLO-M7-DAEMON-001 — Binary integration test (AC-011)
 *
 * Spawns the actual cello-daemon binary as a child process and asserts
 * daemon.started fires with all required fields. A test that directly
 * constructs DaemonServer without starting the binary does NOT satisfy AC-011.
 */

import { describe, it, expect, afterEach } from "vitest";
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtemp, rm, mkdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { FileKeyProvider } from "@cello-protocol/crypto";

describe("daemon binary (AC-011)", () => {
  let tempDir: string;
  let child: ChildProcess | null = null;

  afterEach(async () => {
    if (child && !child.killed) {
      child.kill("SIGTERM");
      await new Promise<void>((resolve) => {
        child!.on("exit", () => resolve());
        setTimeout(resolve, 2000);
      });
    }
    if (tempDir) {
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  it("spawns daemon binary and receives daemon.started with pid, ipcSocketPath, agentCount", async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-bin-test-"));

    // Create an agent directory with a valid key
    const agentsDir = join(tempDir, "agents");
    await mkdir(join(agentsDir, "binary-test-agent"), { recursive: true });
    await FileKeyProvider.load(join(agentsDir, "binary-test-agent", "key"));

    const daemonBin = join(import.meta.dirname, "../bin/cello-daemon.ts");
    const socketPath = join(tempDir, "daemon.sock");

    child = spawn(
      process.execPath,
      ["--import", "tsx", daemonBin],
      {
        // tsx is a devDep of THIS package (pnpm isolated layout) — pin the child's cwd to
        // the package root so `--import tsx` resolves under a workspace-root vitest run too.
        cwd: join(import.meta.dirname, "../.."),
        env: {
          ...process.env,
          CELLO_DIR: tempDir,
          CELLO_VERSION: "0.0.1-binary-test",
        },
        stdio: ["ignore", "pipe", "pipe"],
      },
    );

    const startedEvent = await new Promise<Record<string, unknown>>((resolve, reject) => {
      let buf = "";
      const timeout = setTimeout(() => reject(new Error("Timed out waiting for daemon.started")), 10_000);

      child!.stdout!.on("data", (chunk: Buffer) => {
        buf += chunk.toString("utf-8");
        const lines = buf.split("\n");
        for (const line of lines) {
          if (!line.trim()) continue;
          try {
            const event = JSON.parse(line) as Record<string, unknown>;
            if (event.event === "daemon.started") {
              clearTimeout(timeout);
              resolve(event);
              return;
            }
          } catch {
            // Not JSON yet
          }
        }
      });

      child!.on("error", (err) => {
        clearTimeout(timeout);
        reject(err);
      });

      child!.on("exit", (code) => {
        clearTimeout(timeout);
        reject(new Error(`Daemon exited with code ${code}`));
      });
    });

    // Assert daemon.started fields
    expect(startedEvent.event).toBe("daemon.started");
    expect(typeof startedEvent.pid).toBe("number");
    expect(startedEvent.pid).toBeGreaterThan(0);
    expect(startedEvent.ipcSocketPath).toBe(socketPath);
    expect(startedEvent.agentCount).toBe(1);

    // Assert socket file exists
    const socketStat = await stat(socketPath);
    expect(socketStat.isSocket()).toBe(true);
    expect(socketStat.mode & 0o777).toBe(0o600);
  }, 15_000);
});
