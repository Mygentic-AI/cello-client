/**
 * CELLO-M7-MCP-001 — Adapter IPC proxy tests
 *
 * Specification understanding:
 * - AC-008: daemon_not_running exit code 1
 * - AC-010: ipc_deserialization_error recovery
 * - AC-014: Distinct reason codes, no swallowed exceptions
 * - AC-017: Static grep — no crypto imports in adapter
 * - AC-020: --version, TTY detection, stderr tee
 * - SI-002: No key material in adapter (grep-verified)
 *
 * These tests verify the thin proxy adapter behavior. Tests that require
 * the full daemon+adapter integration (AC-001 through AC-007) are in the
 * daemon package since the daemon hosts the handlers.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { createServer, type Server } from "node:net";

// ─── AC-017 + SI-002: Static analysis — no crypto imports in adapter ───
describe("MCP-001 AC-017/SI-002: no crypto imports in adapter", () => {
  const adapterSrcDir = join(import.meta.dirname, "..", "bin");

  it("cello-mcp.ts does not import FileKeyProvider", () => {
    const src = readFileSync(join(adapterSrcDir, "cello-mcp.ts"), "utf8");
    expect(src).not.toContain("FileKeyProvider");
  });

  it("cello-mcp.ts does not import FrostThresholdSigner", () => {
    const src = readFileSync(join(adapterSrcDir, "cello-mcp.ts"), "utf8");
    expect(src).not.toContain("FrostThresholdSigner");
  });

  it("cello-mcp.ts does not import createNode", () => {
    const src = readFileSync(join(adapterSrcDir, "cello-mcp.ts"), "utf8");
    expect(src).not.toContain("createNode");
  });

  it("cello-mcp.ts does not import SQLCipherClientStore", () => {
    const src = readFileSync(join(adapterSrcDir, "cello-mcp.ts"), "utf8");
    expect(src).not.toContain("SQLCipherClientStore");
  });

  it("cello-mcp.ts does not import bootstrapNetworkKeyShares", () => {
    const src = readFileSync(join(adapterSrcDir, "cello-mcp.ts"), "utf8");
    expect(src).not.toContain("bootstrapNetworkKeyShares");
  });

  it("cello-mcp.ts does not import deriveDbKey", () => {
    const src = readFileSync(join(adapterSrcDir, "cello-mcp.ts"), "utf8");
    expect(src).not.toContain("deriveDbKey");
  });

  it("no file in adapter src/ imports key material types", () => {
    const srcDir = join(import.meta.dirname, "..");
    // Check all *.ts files in src/ (non-test)
    const files = readdirSync(srcDir).filter(
      (f: string) => f.endsWith(".ts") && !f.includes("test")
    );
    for (const file of files) {
      const content = readFileSync(join(srcDir, file), "utf8");
      expect(content).not.toContain("FileKeyProvider");
      expect(content).not.toContain("deriveDbKey");
    }
    // Check bin/
    const binDir = join(srcDir, "bin");
    if (existsSync(binDir)) {
      const binFiles = readdirSync(binDir).filter((f) => f.endsWith(".ts"));
      for (const file of binFiles) {
        const content = readFileSync(join(binDir, file), "utf8");
        expect(content).not.toContain("FileKeyProvider");
        expect(content).not.toContain("deriveDbKey");
      }
    }
  });
});

// ─── AC-010: IPC deserialization error recovery ───
describe("MCP-001 AC-010: ipc_deserialization_error recovery", () => {
  it("adapter recovers from a single malformed IPC response", async () => {
    // We test the IPC proxy logic directly by creating a fake daemon server
    // that sends one bad frame then resumes normal operation.
    const { IpcProxy } = await import("../ipc-proxy.js");

    const tempDir = await mkdtemp(join(tmpdir(), "cello-mcp001-deser-"));
    const socketPath = join(tempDir, "test.sock");

    let server: Server | null = null;
    try {
      // Create fake daemon that sends garbage for request ID "bad" and valid for others
      server = createServer((socket) => {
        let buffer = "";
        socket.on("data", (chunk) => {
          buffer += chunk.toString();
          let idx: number;
          while ((idx = buffer.indexOf("\n")) !== -1) {
            const line = buffer.slice(0, idx);
            buffer = buffer.slice(idx + 1);
            if (!line.trim()) continue;

            const req = JSON.parse(line);
            if (req.method === "trigger_bad_frame") {
              // Send malformed JSON
              socket.write("not-valid-json\n");
            } else {
              // Send valid response
              socket.write(JSON.stringify({ id: req.id, result: { ok: true } }) + "\n");
            }
          }
        });
      });

      await new Promise<void>((resolve) => server!.listen(socketPath, resolve));

      const proxy = new IpcProxy(socketPath);
      await proxy.connect();

      // First: trigger bad frame
      const badResult = await proxy.call("trigger_bad_frame", {});
      expect(badResult).toEqual({
        ok: false,
        reason: "ipc_deserialization_error",
        guidance: expect.stringContaining("malformed response"),
      });

      // Second: normal call should succeed (recovery)
      const goodResult = await proxy.call("cello_list_agents", {});
      expect(goodResult).toEqual({ ok: true });

      proxy.close();
    } finally {
      if (server) {
        await new Promise<void>((resolve) => server!.close(() => resolve()));
      }
      await rm(tempDir, { recursive: true, force: true });
    }
  });
});

// ─── AC-020: --version, TTY detection, stderr tee ───
describe("MCP-001 AC-020: binary behaviors", () => {
  // Resolve tsx binary from pnpm store (not hoisted to root node_modules/.bin/)
  function findTsx(): string {
    const candidates = [
      join(import.meta.dirname, "../../../../node_modules/.bin/tsx"),
      join(import.meta.dirname, "../../../../node_modules/.pnpm/node_modules/.bin/tsx"),
      join(import.meta.dirname, "../../../daemon/node_modules/.bin/tsx"),
    ];
    for (const p of candidates) {
      if (existsSync(p)) return p;
    }
    throw new Error(`tsx not found in any candidate path: ${candidates.join(", ")}`);
  }

  it("--version flag prints version matching package.json and exits 0", async () => {
    const { execFileSync } = await import("node:child_process");
    const pkg = JSON.parse(readFileSync(join(import.meta.dirname, "../../package.json"), "utf8"));
    const tsxPath = findTsx();
    const binPath = join(import.meta.dirname, "../bin/cello-mcp.ts");

    const output = execFileSync(tsxPath, [binPath, "--version"], {
      encoding: "utf8",
      timeout: 10000,
      env: { ...process.env, NODE_ENV: "test" },
    });
    expect(output.trim()).toBe(pkg.version);
  });

  it("exits 1 with daemon_not_running when no daemon socket exists", async () => {
    const { execFileSync } = await import("node:child_process");
    const tsxPath = findTsx();
    const binPath = join(import.meta.dirname, "../bin/cello-mcp.ts");

    try {
      execFileSync(tsxPath, [binPath], {
        encoding: "utf8",
        timeout: 10000,
        // stdin must not be a TTY (it won't be in execFileSync)
        // HOME points to nonexistent dir → no daemon.sock → exit 1
        env: { ...process.env, NODE_ENV: "test", HOME: "/tmp/cello-mcp001-noexist" },
      });
      expect.fail("should have exited with non-zero");
    } catch (err: unknown) {
      const e = err as { status: number; stderr: string };
      expect(e.status).toBe(1);
      expect(e.stderr).toContain("cello login");
    }
  });
});

// ─── CELLO-M7-DAEMON-004 (round-2 BLOCKING): producer side of the session_id
// param contract. The daemon consumes the snake_case public field `session_id`;
// this verifies the shipped producer (cello-mcp.ts → IpcProxy) actually emits it
// VERBATIM on the wire — closing the producer/consumer loop the original bug split.
describe("DAEMON-004: IpcProxy forwards session_id verbatim (real proxy wire shape)", () => {
  it("proxy.call(cello_send/cello_receive/cello_close_session) puts snake_case session_id on the wire, never camelCase", async () => {
    const { IpcProxy } = await import("../ipc-proxy.js");

    const tempDir = await mkdtemp(join(tmpdir(), "cello-d004-proxy-"));
    const socketPath = join(tempDir, "test.sock");
    const capturedFrames: Array<{ method: string; params: Record<string, unknown> }> = [];

    let server: Server | null = null;
    try {
      server = createServer((socket) => {
        let buffer = "";
        socket.on("data", (chunk) => {
          buffer += chunk.toString();
          let idx: number;
          while ((idx = buffer.indexOf("\n")) !== -1) {
            const line = buffer.slice(0, idx);
            buffer = buffer.slice(idx + 1);
            if (!line.trim()) continue;
            const req = JSON.parse(line) as { id: string; method: string; params: Record<string, unknown> };
            capturedFrames.push({ method: req.method, params: req.params });
            socket.write(JSON.stringify({ id: req.id, result: { ok: true } }) + "\n");
          }
        });
      });
      await new Promise<void>((resolve) => server!.listen(socketPath, resolve));

      const proxy = new IpcProxy(socketPath);
      await proxy.connect();

      const SID = "ab".repeat(32);
      // Exactly the param shapes cello-mcp.ts forwards (see bin/cello-mcp.ts L164/172/187).
      await proxy.call("cello_send", { session_id: SID, content: "hi" });
      await proxy.call("cello_receive", { session_id: SID, timeout_ms: 1000 });
      await proxy.call("cello_close_session", { session_id: SID });
      proxy.close();

      for (const method of ["cello_send", "cello_receive", "cello_close_session"]) {
        const frame = capturedFrames.find((f) => f.method === method);
        expect(frame, `${method} frame must reach the wire`).toBeDefined();
        expect(frame!.params.session_id, `${method} must carry snake_case session_id`).toBe(SID);
        expect(frame!.params).not.toHaveProperty("sessionId");
      }
    } finally {
      if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  it("cello-mcp.ts forwards the snake_case session_id field for all three session tools", () => {
    const src = readFileSync(join(import.meta.dirname, "..", "bin", "cello-mcp.ts"), "utf8");
    expect(src).toContain('proxy.call("cello_send", { session_id, content })');
    expect(src).toContain('proxy.call("cello_receive", { session_id, timeout_ms, since_seq })'); // M8C-SINCESEQ-1: + since_seq
    expect(src).toContain('proxy.call("cello_close_session", { session_id })');
  });
});

// ─── AC-014: Distinct reason codes ───
describe("MCP-001 AC-014: distinct reason codes", () => {
  it("ipc_proxy returns ipc_connection_lost when socket is closed", async () => {
    const { IpcProxy } = await import("../ipc-proxy.js");

    const tempDir = await mkdtemp(join(tmpdir(), "cello-mcp001-lost-"));
    const socketPath = join(tempDir, "test.sock");

    let server: Server | null = null;
    try {
      server = createServer((socket) => {
        // Close immediately after connection
        setTimeout(() => socket.destroy(), 50);
      });

      await new Promise<void>((resolve) => server!.listen(socketPath, resolve));

      const proxy = new IpcProxy(socketPath);
      await proxy.connect();

      // Wait for socket to be closed by server
      await new Promise((r) => setTimeout(r, 100));

      const result = await proxy.call("anything", {});
      expect(result).toEqual({
        ok: false,
        reason: "ipc_connection_lost",
        guidance: expect.stringContaining("daemon was lost"),
      });

      proxy.close();
    } finally {
      if (server) {
        await new Promise<void>((resolve) => server!.close(() => resolve()));
      }
      await rm(tempDir, { recursive: true, force: true });
    }
  });
});
