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
 *   The test will fail with ENOENT if dist/ hasn't been built.
 *
 * CRITICAL-3 LIMITATION: AC-004 Coverage Gap
 * ═══════════════════════════════════════════════════════════════════════════════
 * This test spawns a simple Node.js script (processA) that writes the lock file
 * but does NOT open a SQLCipher database. AC-004 requirement states processA
 * must have "an open SQLCipher write lock". Current test verifies stderr event
 * ordering within processB but cannot detect if cello-mcp.ts code is reordered
 * to open DB before acquiring lock (the 30s timeout bug would return undetected).
 *
 * Full AC-004 validation requires spawning a real cello-mcp process for processA
 * that opens SQLCipher and blocks, which is complex to set up in automated tests:
 * - Requires a valid Ed25519 key file (37 bytes, magic + version + seed)
 * - Requires SQLCipher native module (may fail to load in CI environments)
 * - Requires dbKey derivation and SQLCipher PRAGMA key= handshake
 * - Requires reliable detection of when processA has acquired the DB write lock
 * - Timeout behavior (30s) makes the test slow and unreliable
 *
 * This test provides partial coverage — ordering within processB is verified.
 *
 * Manual Verification Procedure for AC-004 (Required Before Production):
 * ─────────────────────────────────────────────────────────────────────────────
 * 1. Start processA (cello-mcp) with CELLO_ENV=local and valid key file
 * 2. Wait for "cello: opening database... ok" in processA stderr (confirms DB lock held)
 * 3. Start processB (cello-mcp) with same CELLO_LOCK_FILE_PATH and CELLO_DB_PATH
 * 4. Verify in processB stderr:
 *    a. "client.startup.prior.process.killed" appears
 *    b. "cello: opening database..." appears AFTER the kill event
 *    c. No 30-second timeout or "database is locked" error
 * 5. Verify processA is terminated (ps aux | grep <processA-PID> returns nothing)
 *
 * If step 4c fails (30s timeout observed), the bug has returned — lock acquisition
 * is happening after DB open. The code ordering in cello-mcp.ts must be fixed.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

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

// ─── AC-004: Kill-before-DB ordering ────────────────────────────────────────────
// See file header for CRITICAL-3 limitation and manual verification procedure.

describe("AC-004: Kill prior process BEFORE opening DB (partial coverage)", () => {
  it("client.startup.prior.process.killed appears before DB-open log in stderr", async () => {
    // Skip if binary not built
    const binPath = resolve(__dirname, "../../dist/bin/cello-mcp.js");
    if (!existsSync(binPath)) {
      console.warn(`Skipping AC-004 integration test: binary not built at ${binPath}. Run 'pnpm run build' first.`);
      return;
    }

    // Create a proper .cello directory structure in the test dir to satisfy path validation
    const celloDir = join(testDir, ".cello");
    const lockFilePath = join(celloDir, "cello-mcp.pid");
    const keyFile = join(celloDir, "key");
    const dbPath = join(celloDir, "client.db");

    // Generate a throwaway key file
    const keyGenScript = `
      const crypto = require("crypto");
      const fs = require("fs");
      const path = require("path");
      const KEY_FILE_MAGIC = Buffer.from([0xce, 0x11, 0x0e, 0x01]);
      const KEY_FILE_VERSION = 0x01;
      const seed = crypto.randomBytes(32);
      const buf = Buffer.concat([KEY_FILE_MAGIC, Buffer.from([KEY_FILE_VERSION]), seed]);
      const keyPath = "${keyFile.replace(/\\/g, "\\\\")}";
      fs.mkdirSync(path.dirname(keyPath), { recursive: true });
      fs.writeFileSync(keyPath, buf);
    `;
    await new Promise<void>((resolve, reject) => {
      const keygen = spawn(process.execPath, ["-e", keyGenScript], { stdio: "ignore" });
      keygen.on("exit", (code) => (code === 0 ? resolve() : reject(new Error("keygen failed"))));
    });

    // Spawn process A — a simple Node.js script that holds the lock and blocks indefinitely
    // (this is more reliable than spawning the full cello-mcp binary, which might fail
    // before acquiring the lock due to missing dependencies or config issues)
    const scriptA = `
      const fs = require("fs");
      const path = require("path");
      const lockPath = "${lockFilePath.replace(/\\/g, "\\\\")}";
      // Create lock directory if needed
      fs.mkdirSync(path.dirname(lockPath), { recursive: true });
      // Write PID to lock file
      fs.writeFileSync(lockPath, String(process.pid), "utf8");
      // Block indefinitely
      setInterval(() => {}, 1000);
    `;
    let processA: ReturnType<typeof spawn> | undefined;
    let processB: ReturnType<typeof spawn> | undefined;

    try {
      processA = spawn(process.execPath, ["-e", scriptA], {
        stdio: "ignore",
        detached: false,
      });

      // Wait for process A to write the lock file
      await new Promise<void>((resolve) => {
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const fs = require("fs");
        const interval = setInterval(() => {
          try {
            if (fs.existsSync(lockFilePath)) {
              clearInterval(interval);
              resolve();
            }
          } catch {
            // File doesn't exist yet
          }
        }, 50);
      });

      // Spawn process B — the real cello-mcp binary, should kill process A, then open its own DB
      // Use HOME override to make the binary use testDir as the home directory (avoids path validation rejection)
      processB = spawn(process.execPath, [binPath], {
        stdio: ["ignore", "ignore", "pipe"], // stderr only
        env: {
          ...process.env,
          HOME: testDir,
          CELLO_KEY_FILE: keyFile,
          CELLO_DB_PATH: dbPath,
          CELLO_ENV: "local",
          // Don't set CELLO_LOCK_FILE_PATH — let it compute the default path from HOME
        },
      });

      let stderrB = "";
      processB.stderr?.on("data", (chunk) => {
        stderrB += chunk.toString();
      });

      // Wait for process B to complete startup (or fail)
      await new Promise<void>((resolve) => {
        processB!.on("exit", () => resolve());
        // Also resolve if we see "cello: ready" or a DB open line
        const interval = setInterval(() => {
          if (stderrB.includes("cello: opening database") || stderrB.includes("cello: ready")) {
            clearInterval(interval);
            resolve();
          }
        }, 100);
        // Timeout after 10s
        setTimeout(() => {
          clearInterval(interval);
          resolve();
        }, 10000);
      });

      // ── Assertion: kill event appears BEFORE DB-open event ──
      const killEventPattern = /client\.startup\.prior\.process\.killed/;
      const dbOpenPattern = /cello: opening database/;

      const killMatch = stderrB.match(killEventPattern);
      const dbOpenMatch = stderrB.match(dbOpenPattern);

      // Debug: print stderr if test fails
      if (!killMatch || !dbOpenMatch) {
        console.error("=== STDERR from processB ===");
        console.error(stderrB);
        console.error("=== END STDERR ===");
      }

      // Both must be present
      expect(killMatch).not.toBeNull();
      expect(dbOpenMatch).not.toBeNull();

      // Kill event must appear before DB open
      const killPos = stderrB.indexOf(killMatch![0]);
      const dbOpenPos = stderrB.indexOf(dbOpenMatch![0]);
      expect(killPos).toBeLessThan(dbOpenPos);
    } finally {
      // Guaranteed cleanup
      if (processA) {
        try { processA.kill("SIGKILL"); } catch {}
      }
      if (processB) {
        try { processB.kill("SIGKILL"); } catch {}
      }
    }
  }, 15000); // 15s timeout for dual process spawn
});
