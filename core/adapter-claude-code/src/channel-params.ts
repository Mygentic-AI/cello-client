/**
 * Claude Code channel notification contract — payload translation.
 *
 * Claude Code's `notifications/claude/channel` requires a specific `params` shape
 * (https://code.claude.com/docs/en/channels-reference#notification-format):
 *   - `content` (string): the event body, delivered as the BODY of the `<channel>` tag.
 *   - `meta`    (Record<string,string>): each entry becomes a `<channel>` ATTRIBUTE. Keys must be
 *     `[a-zA-Z0-9_]` — Claude Code silently DROPS keys with hyphens or other characters.
 * A notification with no `content` field produces no tag body and is silently dropped — which is
 * exactly why the doorbell never surfaced in-context (M8C DOD-LIVE-1, BUILD-JOURNAL Entry 43): the
 * shim was forwarding the raw daemon frame (`{ type, from, ... }`) as `params`, with no `content`.
 *
 * INV-CONTENTFREE / SI-001 is PRESERVED, not weakened: `content` here is a FIXED doorbell
 * announcement synthesized ONLY from content-free routing fields (type, counterparty pubkey,
 * session id, state). The shim never receives message bytes, so it structurally cannot leak them;
 * the operator still calls `cello_receive` to fetch the actual message. "Content-free" means no
 * MESSAGE content — it never meant "omit Claude Code's required `content` field," which is the
 * conflation that shipped the broken doorbell.
 */

function short(v: unknown): string {
  const s = v == null ? "" : String(v);
  return s.length > 12 ? `${s.slice(0, 12)}…` : s;
}

/** Human-readable, content-free doorbell announcement for the `<channel>` tag body. */
function doorbellText(type: string, data: Record<string, unknown>): string {
  const session = short(data["session_id"] ?? data["sessionId"]);
  switch (type) {
    case "cello_message":
      return `CELLO: a new message is waiting (session ${session}, from ${short(data["from"])}). Call cello_receive to read it.`;
    case "cello_session_request":
      return `CELLO: an incoming session request from ${short(data["from"])} (session ${session}). Call cello_await_session to accept it.`;
    case "session_state_changed":
      return `CELLO: session ${session} for ${short(data["agentName"] ?? data["agent"] ?? "your agent")} is now "${String(data["state"] ?? "changed")}". Call cello_list_sessions, then cello_receive.`;
    case "agent_state_changed":
      return `CELLO: agent ${short(data["agent"])} is now ${String(data["state"] ?? "changed")}.`;
    case "agent_current_changed":
      return `CELLO: current agent changed to ${short(data["toAgent"] ?? data["agent"])}.`;
    default:
      return `CELLO event: ${type}.`;
  }
}

/**
 * Translate a content-free daemon doorbell frame's `data` blob into the Claude Code channel
 * `params` contract. Every scalar routing field with an identifier-safe key becomes a `meta`
 * attribute; a synthesized, content-free announcement becomes `content` (the tag body). A defensive
 * skip of any `content` key ensures a daemon frame can never smuggle message text into the body.
 */
export function buildChannelParams(
  data: Record<string, unknown>,
): { content: string; meta: Record<string, string> } {
  const type = typeof data["type"] === "string" ? (data["type"] as string) : "cello_event";
  const meta: Record<string, string> = {};
  for (const [k, v] of Object.entries(data)) {
    // Identifier-safe keys only (Claude Code drops others); scalars only; never a `content` key
    // (belt-and-suspenders for INV-CONTENTFREE — the body is synthesized here, never carried).
    if (k === "content") continue;
    if (!/^[a-zA-Z0-9_]+$/.test(k)) continue;
    if (v == null || typeof v === "object") continue;
    meta[k] = String(v);
  }
  return { content: doorbellText(type, data), meta };
}
