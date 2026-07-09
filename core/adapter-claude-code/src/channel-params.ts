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

/** Shim-side fingerprint — mirrors the daemon's who-label format for old-daemon frames. */
function shimFingerprint(pubkey: unknown): string {
  const s = typeof pubkey === "string" && pubkey.length >= 8 ? pubkey.slice(0, 8) : null;
  return s !== null ? `agent ${s}…` : "agent unknown…";
}

/**
 * MONIKER-4 AC3/AC4 — the rendered counterparty label.
 *  - whoKnown true → plain (the operator's own pet name — deliberate trust, CC-1).
 *  - whoKnown false + fingerprint → plain (derived identity, not a claim). The discriminator is
 *    UNFORGEABLE: MONIKER_RE excludes spaces, and every fingerprint contains one.
 *  - whoKnown false + name → `"Bob" (self-declared)` — rendered as a claim; the marker itself
 *    cannot be forged because the charset excludes quotes and parentheses.
 *
 * The marker says the name came from its owner rather than from the operator. `whoKnown` is true
 * only when the operator has set a local pet name, so it appears for every contact they have not
 * named — not only new ones. Nothing in the protocol ever verifies a name.
 *  - No `who` at all (old daemon) → shim-side fingerprint of the counterparty key. Never blank.
 * Names are NEVER truncated (only fingerprints shorten, by construction).
 */
function renderWho(data: Record<string, unknown>): string {
  const who = typeof data["who"] === "string" && data["who"].length > 0 ? data["who"] : null;
  if (who === null) return shimFingerprint(data["counterpartyPubkey"] ?? data["from"]);
  if (data["whoKnown"] === true) return who;
  return who.includes(" ") ? who : `"${who}" (self-declared)`;
}

/** Human-readable, content-free doorbell announcement for the `<channel>` tag body.
 *  MONIKER-4 AC3: the label LEADS; session IDs stay out of the body (they remain as `<channel>`
 *  meta attributes, where tools read them). */
function doorbellText(type: string, data: Record<string, unknown>): string {
  switch (type) {
    case "cello_message":
      return `📩 CELLO — ${renderWho(data)} sent a message. Run cello_receive to read it.`;
    case "cello_session_request":
      return `📞 CELLO — ${renderWho(data)} wants to connect. Run cello_await_session to accept.`;
    case "session_state_changed": {
      const who = renderWho(data);
      // Review F1: agent names share MONIKER_RE (≤64 chars) — AC3's "never truncates a name"
      // applies to YOUR agent name too; only fingerprints shorten.
      const yourAgent = String(data["agentName"] ?? data["agent"] ?? "your agent");
      switch (String(data["state"] ?? "changed")) {
        case "created":
          return `📞 CELLO — ${who} wants to connect with ${yourAgent}. Run cello_await_session to accept.`;
        case "active":
          return `✅ CELLO — you're connected to ${who}.`;
        case "sealed":
          return `🔒 CELLO — session with ${who} sealed. Receipt saved.`;
        case "closed":
          // The frame carries state, not who closed it — attributing the action would be a lie
          // half the time (spec AC3 note).
          return `👋 CELLO — session with ${who} ended.`;
        default:
          return `CELLO — session with ${who} is now "${String(data["state"] ?? "changed")}".`;
      }
    }
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
