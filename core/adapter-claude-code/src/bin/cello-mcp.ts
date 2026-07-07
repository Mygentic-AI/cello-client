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
import { createWriteStream, mkdirSync } from "node:fs";
import { IpcProxy } from "../ipc-proxy.js";
import { buildChannelParams } from "../channel-params.js";

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

// Resolve CELLO_DIR once (honored exactly as cello-daemon and the cello CLI do) and
// ensure it exists. Used for BOTH the diagnostics log and the daemon socket below, so
// every per-home isolation boundary CELLO_DIR establishes is respected — including the
// stderr tee, which previously went to a single global /tmp file shared across homes.
const celloDir = process.env.CELLO_DIR || join(homedir(), ".cello");
mkdirSync(celloDir, { recursive: true });

// AC-020 (3): Tee stderr to a log file under the home for diagnostics.
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
const socketPath = join(celloDir, "daemon.sock");
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

// Structured diagnostics for the shim. The shim holds no injected logger (it is a thin proxy),
// so it writes `domain.noun.verb` events as JSON to the stderr tee — never console.log.
function logEvent(event: string, context: Record<string, unknown> = {}): void {
  process.stderr.write(JSON.stringify({ event, ...context }) + "\n");
}

const server = new McpServer(
  {
    name: "cello",
    version: pkgForServer.version,
  },
  // CELLO-M8C-WAKE-001 (channel stage 1): declare the claude/channel capability so a `--channels`
  // Claude Code session negotiates it and the daemon's doorbell notifications reach the model's
  // context (mirrors the legacy in-process server.ts). Content never rides — see the bridge below.
  { capabilities: { experimental: { "claude/channel": {} } } },
);

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

// ─── Contact whitelist tools (CC-9) ─────────────────────────────────────────
// The per-agent whitelist is load-bearing after CC-1: a known contact is fast-tracked and exempt
// from unknown-sender screening + the ABUSE-1 acceptance caps. These forward to the daemon handlers
// (cello_contact_list/add/remove) so an agent driving via MCP can see and manage its own whitelist —
// previously CLI-only (`cello contact …`). Per-agent: defaults to the current agent, or pass { agent }.

server.tool("cello_contact_list", "List an agent's contact whitelist — the peers it treats as known/trusted (fast-tracked, exempt from unknown-sender screening and anti-spam caps). Defaults to the current agent; pass { agent } to target another.", {
  agent: z.string().optional().describe("Agent name whose whitelist to list (defaults to the current agent)"),
}, async ({ agent }) => {
  const result = await proxy.call("cello_contact_list", agent ? { agent } : {});
  return jsonText(result);
});

server.tool("cello_contact_add", "Add a peer (by hex public key) to an agent's contact whitelist — a known/trusted contact is fast-tracked and exempt from unknown-sender screening and anti-spam caps. Defaults to the current agent.", {
  pubkey: z.string().describe("Hex-encoded public key of the peer to add"),
  agent: z.string().optional().describe("Agent name whose whitelist to add to (defaults to the current agent)"),
}, async ({ pubkey, agent }) => {
  const result = await proxy.call("cello_contact_add", agent ? { pubkey, agent } : { pubkey });
  return jsonText(result);
});

server.tool("cello_contact_remove", "Remove a peer (by hex public key) from an agent's contact whitelist — they revert to unknown (screened, and subject to the anti-spam acceptance caps). Defaults to the current agent.", {
  pubkey: z.string().describe("Hex-encoded public key of the peer to remove"),
  agent: z.string().optional().describe("Agent name whose whitelist to remove from (defaults to the current agent)"),
}, async ({ pubkey, agent }) => {
  const result = await proxy.call("cello_contact_remove", agent ? { pubkey, agent } : { pubkey });
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
  governance_decisions: z
    .record(z.string(), z.enum(["redact", "allow_once", "allow_always"]))
    .optional()
    .describe(
      "Optional governance re-send (M9-FEED-001). When a prior cello_send returned governance_warn " +
      "with flags, re-send the SAME content plus this map of {flagId: \"redact\"|\"allow_once\"|" +
      "\"allow_always\"} to resolve each flagged item. Omitted flags default to redact.",
    ),
}, async ({ session_id, content, governance_decisions }) => {
  const result = await proxy.call("cello_send", {
    session_id,
    content,
    ...(governance_decisions !== undefined ? { governance_decisions } : {}),
  });
  return jsonText(result);
});

server.tool("cello_receive", "Receive a message from an active session. With since_seq, instead returns a batch of all messages received after that sequence number (stateless catch-up for away-then-return — no replay race).", {
  session_id: z.string().describe("Session ID"),
  timeout_ms: z.number().optional().describe("Timeout in milliseconds (default: 30000). Ignored when since_seq is set."),
  since_seq: z.number().optional().describe("Catch-up mode: return all messages with sequence > since_seq as a batch, instead of waiting for the next live message."),
}, async ({ session_id, timeout_ms, since_seq }) => {
  const result = await proxy.call("cello_receive", { session_id, timeout_ms, since_seq });
  return jsonText(result);
});

server.tool("cello_receive_session", "Receive messages from an active session (alias)", {
  session_id: z.string().describe("Session ID"),
  timeout_ms: z.number().optional().describe("Timeout in milliseconds (default: 30000)"),
}, async ({ session_id, timeout_ms }) => {
  const result = await proxy.call("cello_receive_session", { session_id, timeout_ms });
  return jsonText(result);
});

server.tool("cello_close_session", "Close a session. Normally triggers the bilateral seal ceremony (both parties get a notarized receipt). Pass force:true ONLY to abandon a half-open session that can never be sealed — a handshake the counterparty never joined, whose normal close hangs/rejects on the seal; force marks it terminal locally with no seal so it leaves the open list.", {
  session_id: z.string().describe("Session ID to close"),
  force: z.boolean().optional().describe("Force-abandon a provably unsealable half-open session (no bilateral seal). Do NOT use on a healthy session — it forfeits the notarized receipt."),
}, async ({ session_id, force }) => {
  const result = await proxy.call("cello_close_session", force ? { session_id, force } : { session_id });
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

server.tool("cello_check_notifications", "Check for pending inbound session requests and unread messages (the push-loss reconciler — discovers anything missed while this session was away). scope 'current' (default) checks the current agent; 'all' checks every loaded agent.", {
  scope: z.enum(["current", "all"]).optional().describe("'current' (default) = current agent only; 'all' = every loaded agent, labelled"),
}, async ({ scope }) => {
  const result = await proxy.call("cello_check_notifications", scope ? { scope } : {});
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

server.tool("cello_get_transcript", "Get the durable, readable conversation transcript for a session (sent + received messages, in order) — recoverable after a daemon restart", {
  session_id: z.string().describe("Session ID"),
}, async ({ session_id }) => {
  const result = await proxy.call("cello_get_transcript", { session_id });
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

// ─── Channel stage 1 (CELLO-M8C-WAKE-001): forward daemon notifications ──────────
// The daemon's NotificationDispatcher pushes content-free doorbell frames over IPC
// ({ notification: <type>, data: {...} }). The shim translates each into an MCP
// `notifications/claude/channel` event so a live `--channels` session wakes in-context. This is
// adapter-specific wire translation (the shim's job); the daemon owns the dispatch behavior.
// Registered AFTER server.connect so the transport is live. Registered generically so every
// current type (agent_state_changed / agent_current_changed / session_state_changed) AND the
// future `cello_message` (MSGWAKE) ride the same hop — no per-type allowlist that would silently
// drop a new type.
proxy.onNotification((frame) => {
  // The daemon frame's `data` blob is content-free (agent, type, agentName, sessionId, state,
  // counterpartyPubkey) — no message content ever rides a push (INV-CONTENTFREE / SI-001).
  const data = (frame as { data?: Record<string, unknown> }).data ?? {};
  const type = typeof data["type"] === "string" ? (data["type"] as string) : String(frame["notification"]);
  const agent = data["agent"];
  // Translate the raw daemon frame into Claude Code's channel contract: `{ content, meta }`.
  // Forwarding the bare frame as `params` (no `content`) is why the doorbell never surfaced —
  // Claude Code needs a `content` field to render the <channel> tag body (BUILD-JOURNAL Entry 43).
  // buildChannelParams synthesizes a content-free announcement; message content still never rides.
  const params = buildChannelParams(data);
  server.server
    .notification({ method: "notifications/claude/channel", params })
    .then(() => {
      logEvent("notification.channel.forwarded", { type, agent });
    })
    .catch((err: unknown) => {
      // C5 error fidelity (D7 porting trap): the push is fire-and-forget, but a failure is NEVER
      // silent. The transport may have closed; record the real reason so a missing wake is
      // explainable. Recovery is INBOX / cello_await_session on reattach (INV-PUSHPULL).
      const message = err instanceof Error ? err.message : String(err);
      logEvent("notification.push.failed", { type, agent, error: message });
    });
});
