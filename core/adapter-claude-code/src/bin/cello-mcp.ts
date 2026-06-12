#!/usr/bin/env node
/**
 * cello-mcp — thin stdio-to-IPC proxy (M7)
 *
 * Connects to the running CELLO daemon via ~/.cello/daemon.sock and proxies
 * all MCP tool calls through IPC. Holds no key material, opens no database,
 * creates no libp2p node. Per-connection agent state is managed by the daemon.
 *
 * Startup:
 *   1. --version flag
 *   2. TTY detection (print "run cello login first")
 *   3. Connect to daemon IPC socket
 *   4. If ENOENT/ECONNREFUSED → exit 1 with daemon_not_running
 *   5. Send ipc.connect frame
 *   6. Open MCP stdio server
 *   7. Register IPC proxy for every tool
 *   8. On socket close → ipc_connection_lost for all subsequent calls
 */

import { homedir } from "node:os";
import { join } from "node:path";
import { createWriteStream } from "node:fs";
import { IpcProxy } from "../ipc-proxy.js";

// AC-020 (1): --version flag — exit cleanly with the package version.
// Must precede TTY detection so `cello-mcp --version` works in any context.
if (process.argv.includes("--version") || process.argv.includes("-v")) {
  const { createRequire: cr } = await import("node:module");
  const req = cr(import.meta.url);
  const pkg = req("../../package.json") as { version: string };
  process.stdout.write(`${pkg.version}\n`);
  process.exit(0);
}

// AC-020 (2): TTY detection — if stdin is a TTY, print instructions and exit.
if (process.stdin.isTTY) {
  const { createRequire: cr } = await import("node:module");
  const req = cr(import.meta.url);
  const pkg = req("../../package.json") as { version: string };
  process.stdout.write(
    `cello-mcp v${pkg.version}\n` +
    "\n" +
    "This is a CELLO MCP server. It communicates with the CELLO daemon process.\n" +
    "\n" +
    "Run `cello login` to start the daemon first, then use this as an MCP server:\n" +
    "  claude mcp add cello -- cello-mcp\n" +
    "\n" +
    "Then restart Claude Code (or run /mcp) to activate CELLO.\n",
  );
  process.exit(0);
}

// AC-020 (3): Tee stderr to a log file for diagnostics.
const stderrLog = createWriteStream("/tmp/cello-mcp-stderr.log", { flags: "a" });
const origWrite = process.stderr.write.bind(process.stderr) as typeof process.stderr.write;
process.stderr.write = (
  chunk: string | Uint8Array,
  encodingOrCb?: BufferEncoding | ((err?: Error | null) => void),
  cb?: (err?: Error | null) => void,
): boolean => {
  stderrLog.write(chunk);
  if (typeof encodingOrCb === "function") {
    return origWrite(chunk as string, encodingOrCb);
  } else if (encodingOrCb !== undefined) {
    return origWrite(chunk as string, encodingOrCb, cb);
  }
  return origWrite(chunk as string);
};

// Connect to daemon IPC socket
const socketPath = join(homedir(), ".cello", "daemon.sock");
const proxy = new IpcProxy(socketPath);

try {
  await proxy.connect();
} catch (err: unknown) {
  const code = (err as NodeJS.ErrnoException).code;
  if (code === "ENOENT" || code === "ECONNREFUSED") {
    process.stderr.write("cello-mcp: daemon not running — run `cello login` to start it\n");
  } else {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(`cello-mcp: failed to connect to daemon — ${msg}\n`);
  }
  process.exit(1);
}

// Send ipc.connect frame to register this connection as MCP client
const connectResult = await proxy.call("ipc.connect", { clientType: "mcp" });
if (connectResult && typeof connectResult === "object" && "reason" in (connectResult as Record<string, unknown>)) {
  const r = connectResult as { reason: string; message?: string };
  if (r.reason === "version_mismatch") {
    process.stderr.write("cello-mcp: daemon version mismatch — run `cello logout && cello login` to restart with a compatible daemon\n");
    process.exit(1);
  }
}

// Open MCP stdio server
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

// Read version from package.json (same source as --version flag)
const { createRequire: cr2 } = await import("node:module");
const req2 = cr2(import.meta.url);
const pkgForServer = req2("../../package.json") as { version: string };

function jsonText(value: unknown): { content: [{ type: "text"; text: string }] } {
  return { content: [{ type: "text" as const, text: JSON.stringify(value) }] };
}

const server = new McpServer({
  name: "cello",
  version: pkgForServer.version,
});

// ─── Agent management tools ─────────────────────────────────────────────────

server.tool("cello_start_agent", "Bring a registered CELLO agent online so it can participate in sessions", {
  name: z.string().describe("Agent name to start"),
}, async ({ name }) => {
  const result = await proxy.call("cello_start_agent", { name });
  return jsonText(result);
});

server.tool("cello_stop_agent", "Take an online CELLO agent offline (back to registered state)", {
  name: z.string().describe("Agent name to stop"),
}, async ({ name }) => {
  const result = await proxy.call("cello_stop_agent", { name });
  return jsonText(result);
});

server.tool("cello_use_agent", "Set which online agent this connection routes tool calls to", {
  name: z.string().describe("Agent name to set as current for this connection"),
}, async ({ name }) => {
  const result = await proxy.call("cello_use_agent", { name });
  return jsonText(result);
});

server.tool("cello_list_agents", "List all agents with state from this connection's perspective", {}, async () => {
  const result = await proxy.call("cello_list_agents");
  return jsonText(result);
});

// ─── Session tools (proxied through daemon) ─────────────────────────────────

server.tool("cello_initiate_session", "Start a new CELLO session with a target agent", {
  target_pubkey: z.string().describe("Hex-encoded public key of the target agent"),
}, async ({ target_pubkey }) => {
  const result = await proxy.call("cello_initiate_session", { target_pubkey });
  return jsonText(result);
});

server.tool("cello_await_session", "Wait for an inbound session request", {
  timeout_ms: z.number().optional().describe("Timeout in milliseconds (default: 30000)"),
}, async ({ timeout_ms }) => {
  const result = await proxy.call("cello_await_session", { timeout_ms });
  return jsonText(result);
});

server.tool("cello_send", "Send a message in an active session", {
  session_id: z.string().describe("Session ID"),
  content: z.string().describe("Message content (UTF-8 text)"),
}, async ({ session_id, content }) => {
  const result = await proxy.call("cello_send", { session_id, content });
  return jsonText(result);
});

server.tool("cello_receive", "Receive a message from an active session", {
  session_id: z.string().describe("Session ID"),
  timeout_ms: z.number().optional().describe("Timeout in milliseconds (default: 30000)"),
}, async ({ session_id, timeout_ms }) => {
  const result = await proxy.call("cello_receive", { session_id, timeout_ms });
  return jsonText(result);
});

server.tool("cello_receive_session", "Receive messages from an active session (alias)", {
  session_id: z.string().describe("Session ID"),
  timeout_ms: z.number().optional().describe("Timeout in milliseconds (default: 30000)"),
}, async ({ session_id, timeout_ms }) => {
  const result = await proxy.call("cello_receive_session", { session_id, timeout_ms });
  return jsonText(result);
});

server.tool("cello_close_session", "Close an active session and trigger the seal ceremony", {
  session_id: z.string().describe("Session ID to close"),
}, async ({ session_id }) => {
  const result = await proxy.call("cello_close_session", { session_id });
  return jsonText(result);
});

server.tool("cello_list_sessions", "List all sessions for the current agent", {}, async () => {
  const result = await proxy.call("cello_list_sessions");
  return jsonText(result);
});

// ─── Status and utility tools ───────────────────────────────────────────────

server.tool("cello_status", "Get daemon and agent status", {}, async () => {
  const result = await proxy.call("cello_status");
  return jsonText(result);
});

server.tool("cello_backup", "Backup agent state to configured storage", {}, async () => {
  const result = await proxy.call("cello_backup");
  return jsonText(result);
});

server.tool("cello_restore", "Restore agent state from backup", {}, async () => {
  const result = await proxy.call("cello_restore");
  return jsonText(result);
});

server.tool("cello_get_sealed_receipt", "Get the sealed receipt for a closed session", {
  session_id: z.string().describe("Session ID"),
}, async ({ session_id }) => {
  const result = await proxy.call("cello_get_sealed_receipt", { session_id });
  return jsonText(result);
});

server.tool("cello_get_inclusion_proof", "Get inclusion proof for a message in a sealed session", {
  session_id: z.string().describe("Session ID"),
  content_hash: z.string().describe("Content hash to prove inclusion of"),
}, async ({ session_id, content_hash }) => {
  const result = await proxy.call("cello_get_inclusion_proof", { session_id, content_hash });
  return jsonText(result);
});

// ─── Connect stdio transport ─────────────────────────────────────────────────
await server.connect(new StdioServerTransport());
