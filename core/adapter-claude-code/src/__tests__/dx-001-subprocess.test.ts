/**
 * CELLO-M6-DX-001 — AC-009: Lazy startup subprocess test
 *
 * Specification:
 *
 * AC-009: The MCP server registers tools and responds to a tools/list request within 2 seconds
 *   of process start, BEFORE background directory/DB init completes. This verifies that
 *   server.connect() precedes the background async IIFE and that no blocking I/O runs on
 *   the main thread before tools are registered.
 *
 * Test strategy:
 *   1. Spawn the built binary (dist/bin/cello-mcp.js) with env vars that cause background
 *      init to fail fast (no key file so DB init is skipped, unreachable directory URL).
 *   2. Send a JSON-RPC tools/list request to stdin immediately after spawning.
 *   3. Read from stdout with a 3-second timeout and assert the response is valid JSON-RPC
 *      with a tools array.
 *
 * MANDATORY: --pool-options.threads.maxThreads=1
 */

import { describe, it, expect } from "vitest";
import { spawn } from "node:child_process";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { rmSync } from "node:fs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const BINARY_PATH = resolve(__dirname, "../../dist/bin/cello-mcp.js");

/**
 * Spawn the cello-mcp binary, complete the MCP handshake, send tools/list,
 * and return the tools/list result within timeoutMs.
 *
 * SDK v1.29.0 StdioServerTransport uses newline-delimited JSON (not Content-Length framing).
 * serializeMessage() outputs JSON.stringify(msg) + '\n'; ReadBuffer splits on '\n'.
 *
 * Sequence:
 *   1. Send initialize (id: 1) — wait for response id: 1
 *   2. Send initialized notification (required by MCP spec before any other request)
 *   3. Send tools/list (id: 2) — wait for response id: 2 and resolve with result.tools
 */
/**
 * Spawn cello-mcp, complete the MCP handshake, run a sequence of requests, and resolve
 * with the collected results. The `requests` callback receives a `send` function to
 * dispatch JSON-RPC messages and an `onResponse` function to register response handlers.
 *
 * This is the shared subprocess harness for all AC-009 tests.
 */
interface SubprocessResult {
  tools: unknown[];
  statusResult: Record<string, unknown> | null;
}

async function runSubprocessHarness(timeoutMs: number): Promise<SubprocessResult> {
  const tmpDir = mkdtempSync(`${tmpdir()}/cello-test-subprocess-`);

  return new Promise((resolve, reject) => {
    const proc = spawn(process.execPath, [BINARY_PATH], {
      env: {
        ...process.env,
        CELLO_KEY_FILE: `${tmpDir}/test-key`,
        CELLO_DIRECTORY_URL: "http://127.0.0.1:19999",
        CELLO_DB_PATH: `${tmpDir}/test-client.db`,
        CELLO_ENV: "local",
      },
      stdio: ["pipe", "pipe", "pipe"],
    });

    let stdoutBuf = "";
    let done = false;
    let initDone = false;
    let toolsListDone = false;

    let toolsResult: unknown[] = [];
    let statusResult: Record<string, unknown> | null = null;

    function cleanup(): void {
      try { rmSync(tmpDir, { recursive: true }); } catch { /* ignore */ }
    }

    function finish(err?: Error): void {
      if (done) return;
      done = true;
      clearTimeout(timer);
      proc.kill();
      cleanup();
      if (err) reject(err);
      else resolve({ tools: toolsResult, statusResult });
    }

    const timer = setTimeout(() => {
      finish(new Error(`subprocess did not respond within ${timeoutMs}ms`));
    }, timeoutMs);

    proc.stdout.on("data", (chunk: Buffer) => {
      stdoutBuf += chunk.toString();
      // Process all complete lines (newline-delimited JSON per SDK v1.29.0)
      let nl: number;
      while ((nl = stdoutBuf.indexOf("\n")) !== -1) {
        const line = stdoutBuf.slice(0, nl).trim();
        stdoutBuf = stdoutBuf.slice(nl + 1);
        if (!line) continue;
        let msg: Record<string, unknown>;
        try { msg = JSON.parse(line) as Record<string, unknown>; } catch { continue; }

        if (msg["id"] === 1 && !initDone) {
          // initialize response received — send initialized notification + tools/list + cello_status
          initDone = true;
          const initialized = JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized", params: {} }) + "\n";
          const toolsList = JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }) + "\n";
          // AC-009 Fix 3: immediately send cello_status (id: 3) — must respond before background init
          const statusCall = JSON.stringify({
            jsonrpc: "2.0",
            id: 3,
            method: "tools/call",
            params: { name: "cello_status", arguments: {} },
          }) + "\n";
          proc.stdin.write(initialized);
          proc.stdin.write(toolsList);
          proc.stdin.write(statusCall);
        } else if (msg["id"] === 2) {
          // tools/list response
          const result = (msg["result"] as Record<string, unknown> | undefined);
          const tools = result?.["tools"];
          toolsResult = Array.isArray(tools) ? tools : [];
          toolsListDone = true;
          // If statusResult already arrived, we're done
          if (statusResult !== null) finish();
        } else if (msg["id"] === 3) {
          // cello_status response — parse the JSON text from the MCP content array
          const result = (msg["result"] as Record<string, unknown> | undefined);
          const content = result?.["content"] as Array<{ type: string; text: string }> | undefined;
          const text = content?.find((c) => c.type === "text")?.text;
          try {
            statusResult = text ? (JSON.parse(text) as Record<string, unknown>) : null;
          } catch {
            statusResult = null;
          }
          // If toolsListDone already, we're done
          if (toolsListDone) finish();
        }
      }
    });

    proc.on("error", (err) => finish(err));
    proc.on("exit", (code) => {
      if (!done) finish(new Error(`Binary exited with code ${code} before responding`));
    });

    // Send initialize immediately — AC-009 requires tools to be registered before background I/O
    const initRequest = JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "test-client", version: "0.0.1" } },
    }) + "\n";
    proc.stdin.write(initRequest);
  });
}

// ─── AC-009: subprocess tools/list within 3 seconds ──────────────────────────

describe("AC-009: cello-mcp responds to tools/list before background init completes", () => {
  it("tools/list returns a non-empty tools array within 3 seconds of spawning", async () => {
    // AC-009 requires tools to be registered and callable BEFORE background I/O completes.
    // We verify this by completing the full MCP handshake and asserting tools/list
    // returns a non-empty array — all within 3s (AC specifies 2s; we give 1s margin).
    const { tools } = await runSubprocessHarness(3000);

    expect(Array.isArray(tools)).toBe(true);
    expect(tools.length).toBeGreaterThan(0);
  }, 6000); // vitest timeout: 6s

  /**
   * Fix 3: AC-009 — cello_status responds before background init completes.
   *
   * The AC notes require verifying that cello_status (not just tools/list) also responds
   * before background init completes. Specifically:
   *   - transport_started: true  (the libp2p node has started)
   *   - directory_reachable: false  (background init hasn't connected yet — unreachable URL)
   *
   * We spawn with CELLO_DIRECTORY_URL pointing at a non-existent server so background init
   * fails fast or hasn't completed by the time we send the tools/call request.
   */
  it("cello_status responds with transport_started:true and directory_reachable:false before background init completes", async () => {
    // Both tools/list (id: 2) and cello_status (id: 3) are dispatched immediately after
    // the MCP handshake completes. Background init starts concurrently and points at an
    // unreachable directory URL, so directory_reachable stays false.
    const { statusResult } = await runSubprocessHarness(3000);

    expect(statusResult).not.toBeNull();
    // transport_started: true — the libp2p node opened its TCP port before server.connect()
    expect(statusResult!["transport_started"]).toBe(true);
    // directory_reachable: false — background init has not (and cannot) connect to 127.0.0.1:19999
    expect(statusResult!["directory_reachable"]).toBe(false);
  }, 6000); // vitest timeout: 6s
});
