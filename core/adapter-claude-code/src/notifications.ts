import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { buildChannelParams } from "./channel-params.js";

/**
 * Push a claude/channel wake-up notification to the connected Claude Code session.
 * Message content is never included — the agent calls cello_receive to retrieve it. The payload
 * is Claude Code's channel contract `{ content, meta }` (see channel-params.ts): `content` is a
 * fixed, content-free doorbell announcement (NOT message text), `meta` carries only type + sender
 * pubkey. SI-001 (ADAPTER-001) holds — no message content rides the push.
 */
export async function pushChannelNotification(server: McpServer, from: string): Promise<void> {
  try {
    await server.server.notification({
      method: "notifications/claude/channel",
      params: buildChannelParams({ type: "cello_message", from }),
    });
  } catch {
    // Transport may not be connected or may have closed — silently swallow
  }
}

/**
 * Push a cello_session_request claude/channel notification to the connected Claude Code session.
 * Carries only counterparty pubkey and session_id in `meta` — no content, no multiaddrs, no trust
 * data. SI-001 (ADAPTER-002): the payload's routing fields are exactly type, from, and session_id;
 * `content` is a fixed doorbell announcement, never message content. The agent calls
 * cello_await_session to retrieve the full session details.
 */
export async function pushSessionRequestNotification(
  server: McpServer,
  from: string,
  sessionId: string,
): Promise<void> {
  try {
    await server.server.notification({
      method: "notifications/claude/channel",
      params: buildChannelParams({ type: "cello_session_request", from, session_id: sessionId }),
    });
  } catch {
    // Transport may not be connected or may have closed — silently swallow
  }
}
