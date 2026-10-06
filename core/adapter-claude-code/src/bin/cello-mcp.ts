#!/usr/bin/env node
/**
 * cello-mcp — thin stdio-to-IPC proxy.
 *
 * Connects to the running CELLO daemon via ~/.cello/daemon.sock and proxies
 * all MCP tool calls through IPC. Holds no key material, opens no database,
 * creates no libp2p node. Per-connection agent state is managed by the daemon.
 */

import { homedir } from "node:os";
import { join } from "node:path";
import { createWriteStream, mkdirSync } from "node:fs";
import { getDaemonIpcEndpoint } from "../ipc-endpoint.js";
import { IpcProxy } from "../ipc-proxy.js";
import { forwardDaemonNotifications } from "../channel-forward.js";
import { summarizeInboundFrame } from "../frame-trace.js";
import { registerCelloTools } from "../cello-tools.js";
import { installDaemonGate } from "../daemon-gate.js";
import { logEvent } from "../shim-log.js";

// --version flag — exit cleanly with the package version.
// Must precede TTY detection so `cello-mcp --version` works in any context.
if (process.argv.includes("--version") || process.argv.includes("-v")) {
  const { createRequire: cr } = await import("node:module");
  const req = cr(import.meta.url);
  const pkg = req("../../package.json") as { version: string };
  process.stdout.write(`${pkg.version}\n`);
  process.exit(0);
}

// TTY detection — if stdin is a TTY, print instructions and exit.
if (process.stdin.isTTY) {
  const { createRequire: cr } = await import("node:module");
  const req = cr(import.meta.url);
  const pkg = req("../../package.json") as { version: string };
  process.stdout.write(
    `cello-mcp v${pkg.version}\n` +
    "\n" +
    "This is a CELLO MCP server. It communicates with the CELLO daemon process.\n" +
    "\n" +
    "Run `cello login` to start the daemon first, then install the CELLO plugin:\n" +
    "  /plugin marketplace add Mygentic-AI/cello-client\n" +
    "  /plugin install cello@cello-protocol\n" +
    "\n" +
    "Then restart Claude Code to activate CELLO.\n",
  );
  process.exit(0);
}

// Resolve CELLO_DIR once (honored exactly as cello-daemon and the cello CLI do) and
// ensure it exists. Used for BOTH the diagnostics log and the daemon socket below, so
// every per-home isolation boundary CELLO_DIR establishes is respected — the stderr tee
// included, which must never land in a single global file shared across homes.
const celloDir = process.env.CELLO_DIR || join(homedir(), ".cello");
mkdirSync(celloDir, { recursive: true });

// Tee stderr to a log file under the home for diagnostics.
const stderrLog = createWriteStream(join(celloDir, "cello-mcp-stderr.log"), { flags: "a" });
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

// Connect to daemon IPC socket under the same CELLO_DIR resolved above — otherwise an
// operator (or test) running the daemon under a non-default home would have cello-mcp
// look in ~/.cello and fail to find the socket.
const socketPath = getDaemonIpcEndpoint(celloDir);
// RECONNECT-001: clientType is handed to the proxy so it can replay `ipc.connect` after a daemon
// restart. Without it the reconnected socket has no registered client and no current agent.
const proxy = new IpcProxy(socketPath, { clientType: "mcp" });
await installDaemonGate(proxy);

// Open MCP stdio server
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

// Read version from package.json (same source as --version flag)
const { createRequire: cr2 } = await import("node:module");
const req2 = cr2(import.meta.url);
const pkgForServer = req2("../../package.json") as { version: string };

const server = new McpServer(
  {
    name: "cello",
    version: pkgForServer.version,
  },
  // CELLO-M8C-WAKE-001 (channel stage 1): declare the claude/channel capability so a `--channels`
  // Claude Code session negotiates it and the daemon's doorbell notifications reach the model's
  // context. Content never rides — see the bridge below.
  { capabilities: { experimental: { "claude/channel": {} } } },
);

registerCelloTools(server, proxy);

// ─── Connect stdio transport ─────────────────────────────────────────────────
const transport = new StdioServerTransport();
await server.connect(transport);

// ─── CELLO_MCP_TRACE: what the CLIENT actually sent ──────────────────────────
// Wraps the transport's message hook, which is the LAST point where an inbound frame still exists
// unaltered — the SDK validates `arguments` against the tool's zod shape before any handler of ours
// runs, so a dropped parameter reaches us only as "expected string, received undefined" with no
// record of what arrived. That gap is why a Cowork/`remote-devices` bridge failure could not be
// diagnosed from this side at all (2026-07-29 discussion log). Off by default; message content is
// never recorded verbatim — see frame-trace.ts.
if (process.env.CELLO_MCP_TRACE === "1") {
  const inner = transport.onmessage?.bind(transport);
  transport.onmessage = (msg) => {
    // The trace must never be able to break the call it is observing: a throw here would take down
    // a tool call that would otherwise have worked, turning a diagnostic into an outage.
    try {
      const { event, ...context } = summarizeInboundFrame(msg);
      logEvent(event, context);
    } catch (err: unknown) {
      logEvent("mcp.frame.trace.failed", { error: err instanceof Error ? err.message : String(err) });
    }
    inner?.(msg);
  };
  logEvent("mcp.frame.trace.enabled", {});
}

forwardDaemonNotifications(proxy, server);
