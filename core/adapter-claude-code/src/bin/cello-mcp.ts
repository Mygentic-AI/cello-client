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
import { IpcProxy } from "../ipc-proxy.js";
import { buildChannelParams } from "../channel-params.js";

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
    "Run `cello login` to start the daemon first, then use this as an MCP server:\n" +
    "  claude mcp add cello -- cello-mcp\n" +
    "\n" +
    "Then restart Claude Code (or run /mcp) to activate CELLO.\n",
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
const socketPath = join(celloDir, "daemon.sock");
// RECONNECT-001: clientType is handed to the proxy so it can replay `ipc.connect` after a daemon
// restart. Without it the reconnected socket has no registered client and no current agent.
const proxy = new IpcProxy(socketPath, { clientType: "mcp" });

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
  // context. Content never rides — see the bridge below.
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

server.tool("cello_agents", "List all agents with state from this connection's perspective", {}, async () => {
  const result = await proxy.call("cello_list_agents");
  return jsonText(result);
});

// ─── Contact whitelist tools (CC-9) ─────────────────────────────────────────
// The per-agent whitelist is load-bearing: a known contact is fast-tracked and exempt from the
// unknown-sender gate + the ABUSE-1 acceptance caps. Those caps ARE enforced. CONTENT screening
// (prompt-injection defense) is NOT: the daemon runs PassthroughGatewayClient, so no tool
// description here may tell the operator's agent that message text is screened.

server.tool("cello_contacts", "List an agent's contact whitelist — the peers it treats as known/trusted (fast-tracked, exempt from the unknown-sender gate and anti-spam caps). Defaults to the current agent; pass { agent } to target another.", {
  agent: z.string().optional().describe("Agent name whose whitelist to list (defaults to the current agent)"),
}, async ({ agent }) => {
  const result = await proxy.call("cello_contact_list", agent ? { agent } : {});
  return jsonText(result);
});

server.tool("cello_contact_add", "Add a peer (by hex public key) to an agent's address book — a deliberate add makes them a KNOWN contact (higher reachability and anti-spam caps than a stranger, but NOT auto-accepted when you're away). Promote them to whitelisted/vip with cello_contact_set_tier to let them reach you unattended. Optionally set your own pet name (moniker). Defaults to the current agent.", {
  pubkey: z.string().describe("Hex-encoded public key of the peer to add"),
  moniker: z.string().optional().describe("Optional pet name for this contact (1-64 chars: letters, digits, '-' or '_') — always wins over the name they offer"),
  agent: z.string().optional().describe("Agent name whose whitelist to add to (defaults to the current agent)"),
}, async ({ pubkey, moniker, agent }) => {
  const params: Record<string, unknown> = { pubkey };
  if (moniker !== undefined) params.moniker = moniker;
  if (agent) params.agent = agent;
  const result = await proxy.call("cello_contact_add", params);
  return jsonText(result);
});

// MONIKER-3: rename/clear a contact's pet name. Forward-only (D7).
server.tool("cello_contact_set_moniker", "Set (or clear, by passing null) YOUR pet name for an existing contact — the top-priority display name shown for them (always wins over the name they offer). Defaults to the current agent.", {
  pubkey: z.string().describe("Hex-encoded public key of the contact to rename"),
  moniker: z.string().nullable().describe("The pet name to set (1-64 chars: letters, digits, '-' or '_'), or null to clear it"),
  agent: z.string().optional().describe("Agent name whose contact to rename (defaults to the current agent)"),
}, async ({ pubkey, moniker, agent }) => {
  const result = await proxy.call("cello_contact_set_moniker", agent ? { pubkey, moniker, agent } : { pubkey, moniker });
  return jsonText(result);
});

// DOD-CONTACT-VIEW-1: set a contact's reachability tier. Forward-only (D7).
server.tool("cello_contact_set_tier", "Set a contact's reachability tier: 0=blocked (refused, indistinguishable from a full inbox), 1=unknown (stranger caps), 2=known (a real contact — richer away replies, larger caps), 3=whitelisted (auto-accepted when you're away), 4=vip (highest caps). Every tier is still bounded — a higher tier only RAISES limits, it never removes them. It does NOT change content screening, which is not yet active: message text currently passes through unscreened at every tier. Defaults to the current agent.", {
  pubkey: z.string().describe("Hex-encoded public key of the contact"),
  tier: z.number().int().min(0).max(4).describe("0=blocked, 1=unknown, 2=known, 3=whitelisted, 4=vip"),
  agent: z.string().optional().describe("Agent name whose contact to set (defaults to the current agent)"),
}, async ({ pubkey, tier, agent }) => {
  const result = await proxy.call("cello_contact_set_tier", agent ? { pubkey, tier, agent } : { pubkey, tier });
  return jsonText(result);
});

// DOD-AWAY-TIER-1: per-contact away message. Forward-only (D7).
server.tool("cello_contact_set_away", "Set (or clear, by passing null) a custom away message for a specific contact — the text they receive when they reach you and you're away. It is the most specific level of away-text resolution (per-contact → per-tier → agent default → system default). Defaults to the current agent.", {
  pubkey: z.string().describe("Hex-encoded public key of the contact"),
  message: z.string().nullable().describe("The away text to send this contact, or null to clear it"),
  agent: z.string().optional().describe("Agent name whose contact to set (defaults to the current agent)"),
}, async ({ pubkey, message, agent }) => {
  const result = await proxy.call("cello_contact_set_away", agent ? { pubkey, message, agent } : { pubkey, message });
  return jsonText(result);
});

server.tool("cello_contact_remove", "Remove a peer (by hex public key) from an agent's address book — they revert to unknown (stranger anti-spam caps). Defaults to the current agent.", {
  pubkey: z.string().describe("Hex-encoded public key of the peer to remove"),
  agent: z.string().optional().describe("Agent name whose whitelist to remove from (defaults to the current agent)"),
}, async ({ pubkey, agent }) => {
  const result = await proxy.call("cello_contact_remove", agent ? { pubkey, agent } : { pubkey });
  return jsonText(result);
});

// MONIKER-1: outbound-name override. Forward-only (D7 — validation and persistence live in the
// daemon's cello_set_moniker; the shim adds no logic).
server.tool("cello_moniker", "Set (or clear, by passing null) an agent's outbound display name — what a counterparty's doorbell shows. Defaults to the agent name; local-only, never sent to the directory. 1-64 chars: letters, digits, '-' or '_'. Defaults to the current agent.", {
  moniker: z.string().nullable().describe("The outbound name to set, or null to clear the override (reverts to the agent name)"),
  agent: z.string().optional().describe("Agent name whose outbound name to set (defaults to the current agent)"),
}, async ({ moniker, agent }) => {
  const result = await proxy.call("cello_set_moniker", agent ? { moniker, agent } : { moniker });
  return jsonText(result);
});

// DOD-SETTINGS-SURFACE-1: per-agent reachability-policy settings. Forward-only (D7 — the daemon owns
// key + value validation). This is what makes the tier bound overrides and the per-tier / agent-default
// away messages operator-reachable.
server.tool("cello_settings_get", "Read a per-agent reachability-policy setting (a single key), or ALL set values when no key is given. An unset key returns null — the built-in default is used. Keys: bounds.<tier>.max_sessions, bounds.<tier>.max_bytes (tier = unknown|known|whitelisted|vip), away.default, away.tier.<tier>. Defaults to the current agent.", {
  key: z.string().optional().describe("The setting key to read; omit to list every set value"),
  agent: z.string().optional().describe("Agent whose settings to read (defaults to the current agent)"),
}, async ({ key, agent }) => {
  const params: Record<string, unknown> = {};
  if (key !== undefined) params.key = key;
  if (agent) params.agent = agent;
  const result = await proxy.call("cello_settings_get", params);
  return jsonText(result);
});

server.tool("cello_settings_set", "Set a per-agent reachability-policy setting. A bound override (bounds.<tier>.max_sessions / max_bytes; tier = unknown|known|whitelisted|vip) must be a FINITE POSITIVE INTEGER — a higher value raises the bound, never removes it (Infinity/negative/0 are refused). An away text (away.default, away.tier.<tier>) is the message a sender at that tier gets when you're away. Unknown keys are refused. Defaults to the current agent.", {
  key: z.string().describe("The setting key (see the list in cello_settings_get)"),
  value: z.union([z.string(), z.number()]).describe("The value — an integer for a bound, a text for an away message"),
  agent: z.string().optional().describe("Agent whose setting to write (defaults to the current agent)"),
}, async ({ key, value, agent }) => {
  const result = await proxy.call("cello_settings_set", agent ? { key, value, agent } : { key, value });
  return jsonText(result);
});

// ─── Session tools (proxied through daemon) ─────────────────────────────────

server.tool("cello_initiate_session", "Start a new CELLO session with a target agent", {
  target_pubkey: z.string().describe("Hex-encoded public key of the target agent"),
  agent: z.string().optional().describe("Agent to act as for this call (defaults to the current agent)"),
}, async ({ target_pubkey, agent }) => {
  const result = await proxy.call("cello_initiate_session", agent ? { target_pubkey, agent } : { target_pubkey });
  return jsonText(result);
});

server.tool("cello_await_session", "Wait for an inbound session request", {
  timeout_ms: z.number().optional().describe("Timeout in milliseconds (default: 30000)"),
  agent: z.string().optional().describe("Agent to wait as (defaults to the current agent)"),
}, async ({ timeout_ms, agent }) => {
  const result = await proxy.call("cello_await_session", agent ? { timeout_ms, agent } : { timeout_ms });
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
  agent: z.string().optional().describe("Agent to send as (defaults to the current agent)"),
}, async ({ session_id, content, governance_decisions, agent }) => {
  const result = await proxy.call("cello_send", {
    session_id,
    content,
    ...(governance_decisions !== undefined ? { governance_decisions } : {}),
    ...(agent ? { agent } : {}),
  });
  return jsonText(result);
});

server.tool("cello_receive", "Receive a message from an active session. With since_seq, instead returns a batch of all messages received after that sequence number (stateless catch-up for away-then-return — no replay race).", {
  session_id: z.string().describe("Session ID"),
  timeout_ms: z.number().optional().describe("Timeout in milliseconds (default: 30000). Ignored when since_seq is set."),
  since_seq: z.number().optional().describe("Catch-up mode: return all messages with sequence > since_seq as a batch, instead of waiting for the next live message."),
  agent: z.string().optional().describe("Agent to receive as (defaults to the current agent)"),
}, async ({ session_id, timeout_ms, since_seq, agent }) => {
  const result = await proxy.call("cello_receive", agent
    ? { session_id, timeout_ms, since_seq, agent }
    : { session_id, timeout_ms, since_seq });
  return jsonText(result);
});

server.tool("cello_close_session", "Close a session. Normally triggers the bilateral seal ceremony (both parties get a notarized receipt). Pass force:true ONLY to abandon a half-open session that can never be sealed — a handshake the counterparty never joined, whose normal close hangs/rejects on the seal; force marks it terminal locally with no seal so it leaves the open list. Name the session while you close it: you have just had the conversation, so this is the moment you know what it was.", {
  session_id: z.string().describe("Session ID to close"),
  force: z.boolean().optional().describe("Force-abandon a provably unsealable half-open session (no bilateral seal). Do NOT use on a healthy session — it forfeits the notarized receipt."),
  session_name: z.string().nullable().optional().describe("A short human-readable label for this conversation, e.g. 'Q3 budget review with Bob'. PRIVATE TO YOU: never sent to the counterparty, the relay, or the directory. Optional — leave it out if you cannot describe the session accurately; an unnamed session is a signal it did not close cleanly, so do not invent one."),
  agent: z.string().optional().describe("Agent whose session to close (defaults to the current agent)"),
}, async ({ session_id, force, session_name, agent }) => {
  const result = await proxy.call("cello_close_session", {
    session_id,
    ...(force ? { force } : {}),
    // `session_name` is forwarded whenever the key is PRESENT, including an explicit null — the
    // truthiness shortcut used for `force`/`agent` would silently drop it.
    ...(session_name !== undefined ? { session_name } : {}),
    ...(agent ? { agent } : {}),
  });
  return jsonText(result);
});

server.tool("cello_name_session", "Name (or rename) one of your sessions so you can tell it apart from the others. Works on ANY session — active, interrupted, or long sealed — because naming an old conversation for the record is the point. Pass null to clear the name. PRIVATE TO YOU: the name is never sent to the counterparty, the relay, or the directory, and it cannot change anything the protocol does.", {
  session_id: z.string().describe("Session ID to name"),
  session_name: z.string().nullable().describe("The label, e.g. 'The deploy postmortem' — or null to clear it"),
  agent: z.string().optional().describe("Agent whose session to name (defaults to the current agent)"),
}, async ({ session_id, session_name, agent }) => {
  const result = await proxy.call("cello_name_session", agent
    ? { session_id, session_name, agent }
    : { session_id, session_name });
  return jsonText(result);
});

server.tool("cello_sessions", "List all sessions for the current agent", {
  agent: z.string().optional().describe("Agent whose sessions to list (defaults to the current agent)"),
}, async ({ agent }) => {
  const result = await proxy.call("cello_list_sessions", agent ? { agent } : {});
  return jsonText(result);
});

// ─── Status and utility tools ───────────────────────────────────────────────

server.tool("cello_status", "Get daemon and agent status", {}, async () => {
  const result = await proxy.call("cello_status");
  return jsonText(result);
});

server.tool("cello_inbox", "Check for pending inbound session requests and unread messages (the push-loss reconciler — discovers anything missed while this session was away). scope 'current' (default) checks the current agent; 'all' checks every loaded agent.", {
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

server.tool("cello_sealed_receipt", "Get the sealed receipt for a closed session", {
  session_id: z.string().describe("Session ID"),
  agent: z.string().optional().describe("Agent whose receipt to read (defaults to the current agent)"),
}, async ({ session_id, agent }) => {
  const result = await proxy.call("cello_get_sealed_receipt", agent ? { session_id, agent } : { session_id });
  return jsonText(result);
});

server.tool("cello_transcript", "Get the durable, readable conversation transcript for a session (sent + received messages, in order) — recoverable after a daemon restart", {
  session_id: z.string().describe("Session ID"),
  agent: z.string().optional().describe("Agent whose transcript to read (defaults to the current agent)"),
}, async ({ session_id, agent }) => {
  const result = await proxy.call("cello_get_transcript", agent ? { session_id, agent } : { session_id });
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
  // Claude Code needs a `content` field to render the channel tag body — forwarding the bare frame
  // as `params` (no `content`) means the doorbell never surfaces at all.
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
