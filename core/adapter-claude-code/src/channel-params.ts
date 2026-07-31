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
    // Agent NAMES are never shortened. These two cases ran the name through a 12-char `short()`
    // helper and rendered "CELLO_Feedba…", contradicting the rule stated in the
    // session_state_changed branch above ("AC3's 'never truncates a name' applies to YOUR agent name
    // too; only fingerprints shorten"). A mangled name reads like a different agent. Removing the
    // last two callers left `short()` with none — fingerprints are rendered by shimFingerprint,
    // which slices independently — so it was deleted rather than left as a helper nobody calls.
    case "agent_state_changed":
      return `CELLO: agent ${String(data["agent"] ?? "your agent")} is now ${String(data["state"] ?? "changed")}.`;
    case "agent_current_changed":
      return `CELLO — you are now acting as ${String(data["toAgent"] ?? data["agent"] ?? "your agent")}.`;
    // The counterpart to `shutdown`, and the reason this exists: after `cello logout && cello login`
    // the operator was told the daemon STOPPED and never told it came back. The reconnect only wrote
    // to the shim's stderr, which no agent reads. The only thing that did arrive was the
    // agent_current_changed from the handshake replay — an agent-switch notice standing in for an
    // announcement that did not exist, which is why the doorbell read as wrong rather than missing.
    case "daemon_reconnected":
      return `✅ CELLO — the local daemon is back${data["agent"] !== undefined ? ` and you are acting as ${String(data["agent"])}` : ""}. Tools work again.`;
    case "shutdown":
      // ACTIONABLE, not suppressed. The daemon dying is the one housekeeping event the operator
      // must know about: every cello_* tool is about to fail, and the failure (`daemon_not_running`)
      // reads like a protocol bug rather than "your daemon stopped." Name the recovery here.
      return `⚠️ CELLO — the local daemon stopped. Tools will fail until you run \`cello login\`.`;
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
  type: string,
): { content: string; meta: Record<string, string> } {
  // `type` is REQUIRED and comes from the caller, which resolved it as
  // `data.type ?? String(frame.notification)`. It is deliberately NOT re-derived from `data` here:
  // real daemon frames carry the type on `frame.notification`, not in `data`, so a local
  // `data.type ?? "cello_event"` fallback silently bypassed every announcement below and rendered
  // the placeholder `CELLO event: cello_event.` in production while every test passed — the test
  // fixtures were the only frames that ever had `data.type` (2026-07-30).
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
