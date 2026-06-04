/**
 * CELLO-M6B-001 — Integration tests for cello-mcp PID lock file
 *
 * AC-004: Verify that client.startup.prior.process.killed appears in stderr
 *   BEFORE any DB-open log event. This proves the kill-prior-process step
 *   executes before opening SQLCipher.
 *
 * Test type: integration (spawns real cello-mcp child processes)
 * MANDATORY: --pool-options.threads.maxThreads=1
 *
 * PREREQUISITE: This test spawns the compiled binary at dist/bin/cello-mcp.js.
 *   Run `pnpm run build` before running this test if the binary doesn't exist.
 *   The test will be skipped if dist/ hasn't been built.
 *
 * AC-004 FULL COVERAGE DESIGN:
 * ═══════════════════════════════════════════════════════════════════════════════
 * AC-004 requires that client.startup.prior.process.killed appears BEFORE the
 * "cello: opening database" line in processB's stderr. This is the ordering
 * invariant that prevents the original 30-second timeout bug (where DB was
 * opened before lock was acquired, causing processB to wait 30s for the SQLCipher
 * write lock rather than killing processA first).
 *
 * The test spawns processA as a simple Node.js script that writes the lock file
 * and blocks. ProcessB is the real cello-mcp binary. ProcessB must:
 *   1. Find the lock file from processA
 *   2. Kill processA (logging client.startup.prior.process.killed)
 *   3. Proceed to open the database ("cello: opening database...")
 *
 * This verifies the ordering invariant directly from processB's log stream.
 * If cello-mcp.ts were reordered to open DB before acquiring the lock, processB
 * would deadlock on the SQLCipher write lock (30s timeout) before printing the
 * kill event — the DB open line would appear first or the test would time out.
 *
 * Ordering Revert Detection:
 * If the lock acquisition is moved after DB open in cello-mcp.ts:
 *   - ProcessB would attempt to open the DB while processA holds the write lock
 *   - The "cello: opening database..." line would appear before kill event
 *   - expect(killPos).toBeLessThan(dbOpenPos) would fail
 * The test catches the regression.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { randomBytes } from "node:crypto";

const __dirname = dirname(fileURLToPath(import.meta.url));

let testDir: string;

beforeEach(() => {
  testDir = mkdtempSync(join(tmpdir(), "cello-m6b-001-"));
});

afterEach(() => {
  try {
    rmSync(testDir, { recursive: true, force: true });
  } catch {
    // Silent cleanup
  }
});

// ─── Helpers ───────────────────────────────────────────────────────────────────

/** Build a valid 37-byte CELLO key file synchronously */
function buildKeyFile(keyPath: string): void {
  const KEY_FILE_MAGIC = Buffer.from([0xce, 0x11, 0x0e, 0x01]);
  const KEY_FILE_VERSION = 0x01;
  const seed = randomBytes(32);
  const buf = Buffer.concat([KEY_FILE_MAGIC, Buffer.from([KEY_FILE_VERSION]), seed]);
  mkdirSync(dirname(keyPath), { recursive: true });
  writeFileSync(keyPath, buf);
}

// ─── AC-004: Kill-before-DB ordering ────────────────────────────────────────────

describe("AC-004: Kill prior process BEFORE opening DB", () => {
  it("client.startup.prior.process.killed appears before DB-open log in processB stderr", async () => {
    const binPath = resolve(__dirname, "../../dist/bin/cello-mcp.js");
    if (!existsSync(binPath)) {
      console.warn(`Skipping AC-004 integration test: binary not built at ${binPath}. Run 'pnpm run build' first.`);
      return;
    }

    // Set up a .cello directory in the test dir (used as HOME override for processB)
    const celloDir = join(testDir, ".cello");
    const lockFilePath = join(celloDir, "cello-mcp.pid");
    const keyFile = join(celloDir, "key");
    const dbPath = join(celloDir, "client.db");

    // Build a valid key file for processB
    buildKeyFile(keyFile);

    // Spawn processA — a simple Node.js script that writes the lock file and holds it.
    // ProcessA represents a prior cello-mcp that is blocking the lock file path.
    // It does NOT open the SQLCipher database — the DB write lock belongs to processB's
    // attempt. The ordering test focuses on processB's stderr log stream:
    //   kill event MUST appear before "cello: opening database"
    // If cello-mcp.ts is reordered to open DB before acquiring lock, processB would
    // deadlock on the SQLCipher write lock before logging the kill event.
    const scriptA = `
      const fs = require("fs");
      const path = require("path");
      const lockPath = ${JSON.stringify(lockFilePath)};
      fs.mkdirSync(path.dirname(lockPath), { recursive: true });
      fs.writeFileSync(lockPath, String(process.pid), "utf8");
      // Block indefinitely to hold the lock file — processB must kill this process
      setInterval(() => {}, 1000);
    `;

    let processA: ReturnType<typeof spawn> | undefined;
    let processB: ReturnType<typeof spawn> | undefined;

    try {
      processA = spawn(process.execPath, ["-e", scriptA], {
        stdio: "ignore",
        detached: false,
      });

      // Wait for processA to write the lock file (poll every 50ms)
      await new Promise<void>((resolve, reject) => {
        const deadline = Date.now() + 5000;
        const interval = setInterval(() => {
          if (existsSync(lockFilePath)) {
            clearInterval(interval);
            resolve();
          } else if (Date.now() > deadline) {
            clearInterval(interval);
            reject(new Error("processA did not write lock file within 5s"));
          }
        }, 50);
      });

      // Spawn processB — the real cello-mcp binary.
      // Use HOME override so getLockFilePath() computes the same lockFilePath as above.
      // CELLO_ENV=local so path validation allows paths outside ~/.cello/ (testDir != real home).
      processB = spawn(process.execPath, [binPath], {
        stdio: ["ignore", "ignore", "pipe"],
        env: {
          ...process.env,
          HOME: testDir,
          CELLO_KEY_FILE: keyFile,
          CELLO_DB_PATH: dbPath,
          CELLO_ENV: "local",
          // Do NOT set CELLO_LOCK_FILE_PATH — let it compute from HOME
          // Do NOT set CELLO_DIRECTORY_MULTIADDR — no network needed for this test
        },
      });

      let stderrB = "";
      processB.stderr?.on("data", (chunk: Buffer) => {
        stderrB += chunk.toString();
      });

      // Wait until processB logs "cello: opening database" OR "cello: ready" OR exits.
      // 10s is enough time for the kill-and-lock cycle plus SQLCipher open attempt.
      await new Promise<void>((resolve) => {
        const interval = setInterval(() => {
          if (
            stderrB.includes("cello: opening database") ||
            stderrB.includes("cello: ready") ||
            stderrB.includes("client.startup.lock.write.failed")
          ) {
            clearInterval(interval);
            resolve();
          }
        }, 100);
        processB!.on("exit", () => {
          clearInterval(interval);
          resolve();
        });
        setTimeout(() => {
          clearInterval(interval);
          resolve();
        }, 10000);
      });

      // ── Assertions ──────────────────────────────────────────────────────────

      const killEventPattern = /client\.startup\.prior\.process\.killed/;
      const dbOpenPattern = /cello: opening database/;

      const killMatch = stderrB.match(killEventPattern);
      const dbOpenMatch = stderrB.match(dbOpenPattern);

      if (!killMatch || !dbOpenMatch) {
        console.error("=== STDERR from processB ===");
        console.error(stderrB);
        console.error("=== END STDERR ===");
      }

      // Both events must appear in processB's stderr
      expect(killMatch, "kill event must appear in stderr").not.toBeNull();
      expect(dbOpenMatch, "DB-open line must appear in stderr").not.toBeNull();

      // The ordering invariant: kill BEFORE DB open
      const killPos = stderrB.indexOf(killMatch![0]);
      const dbOpenPos = stderrB.indexOf(dbOpenMatch![0]);
      expect(killPos, "kill event must precede DB-open event").toBeLessThan(dbOpenPos);
    } finally {
      if (processA) {
        try { processA.kill("SIGKILL"); } catch { /* already dead */ }
      }
      if (processB) {
        try { processB.kill("SIGKILL"); } catch { /* already dead */ }
      }
    }
  }, 15000);
});
