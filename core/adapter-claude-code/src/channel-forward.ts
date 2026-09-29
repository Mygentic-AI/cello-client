/**
 * Forward daemon doorbell notifications to an MCP client as `notifications/claude/channel`.
 *
 * Shared by the stdio and HTTP entrypoints. `permitAgent` lets an entrypoint that restricts which
 * agents it serves drop a frame about an agent it does not serve (the HTTP endpoint); the stdio shim
 * serves every agent and passes nothing.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { IpcProxy } from "./ipc-proxy.js";
import { buildChannelParams } from "./channel-params.js";
import { logEvent } from "./shim-log.js";

export function forwardDaemonNotifications(
  proxy: IpcProxy,
  server: McpServer,
  permitAgent: (frame: Record<string, unknown>) => boolean = () => true,
): void {
// ─── Channel stage 1 (CELLO-M8C-WAKE-001): forward daemon notifications ──────────
// The daemon's NotificationDispatcher pushes content-free doorbell frames over IPC
// ({ notification: <type>, data: {...} }). The shim translates each into an MCP
// `notifications/claude/channel` event so a live `--channels` session wakes in-context. This is
// adapter-specific wire translation (the shim's job); the daemon owns the dispatch behavior.
// Registered AFTER server.connect so the transport is live. Registered generically so every
// current type (agent_state_changed / agent_current_changed / session_state_changed) AND the
// future `cello_message` (MSGWAKE) ride the same hop — no per-type allowlist that would silently
// drop a new type.
// The daemon coming BACK is an event too, and it was the one nobody sent. `shutdown` is pushed by
// the dying daemon; a fresh one cannot push anything, because it has never heard of this client. So
// the shim announces its own reconnect — the only party that knows both that the daemon died and
// that it is back. Without it, `cello logout && cello login` left the agent holding a ⚠️ "daemon
// stopped" notice forever, and the agent_current_changed from the handshake replay was the only
// hint anything had recovered.
proxy.onReconnect(() => {
  const agent = proxy.currentAgent;
  const data: Record<string, unknown> = agent ? { agent } : {};
  const params = buildChannelParams(data, "daemon_reconnected");
  server.server
    .notification({ method: "notifications/claude/channel", params })
    .then(() => logEvent("notification.channel.forwarded", { type: "daemon_reconnected", agent }))
    .catch((err: unknown) => {
      const message = err instanceof Error ? err.message : String(err);
      logEvent("notification.push.failed", { type: "daemon_reconnected", agent, error: message });
    });
});

proxy.onNotification((frame) => {
  if (!permitAgent(frame)) return;
  // The daemon frame's `data` blob is content-free (agent, type, agentName, sessionId, state,
  // counterpartyPubkey) — no message content ever rides a push (INV-CONTENTFREE / SI-001).
  const data = (frame as { data?: Record<string, unknown> }).data ?? {};
  const type = typeof data["type"] === "string" ? (data["type"] as string) : String(frame["notification"]);
  const agent = data["agent"];
  // Translate the raw daemon frame into Claude Code's channel contract: `{ content, meta }`.
  // Claude Code needs a `content` field to render the channel tag body — forwarding the bare frame
  // as `params` (no `content`) means the doorbell never surfaces at all.
  // buildChannelParams synthesizes a content-free announcement; message content still never rides.
  // `type` is passed in: it was resolved above with the `frame.notification` fallback that the
  // frame actually uses. Letting buildChannelParams re-derive it from `data` is what produced the
  // generic `CELLO event: cello_event.` doorbell in production.
  const params = buildChannelParams(data, type);
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
}
