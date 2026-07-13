/**
 * DOD-SESSION-NAME-1 — validation for a session's human-readable name.
 *
 * This lives in the DAEMON, not in protocol-types, and that is deliberate: a session name is local
 * and cosmetic. protocol-types holds the wire encoders and the TBS builders — putting a validator
 * there would say the name is protocol, and the next reader would reasonably wire it into a frame.
 * It is a sticky note on your own copy of the folder.
 *
 * It is NOT handle-shaped. Do not reach for MONIKER_RE: a moniker is a handle a counterparty sees,
 * so it is deliberately narrow; this is a DESCRIPTION ("Q3 budget review with Bob") that only its
 * author reads. Letters, digits, spaces, punctuation, accents, CJK and emoji are all legal.
 */

/** Free text, but bounded: long enough for a sentence, short enough to list in a terminal. */
export const SESSION_NAME_MAX_LENGTH = 200;

/** C0 (including \n, \r, \t, \0), DEL, and C1. Rejected, never stripped. */
const CONTROL_CHARS = /[\u0000-\u001F\u007F-\u009F]/;

export type SessionNameResult =
  | { ok: true; value: string | null }
  | { ok: false; reason: "session_name_not_a_string" | "session_name_control_chars" | "session_name_too_long"; guidance: string };

/**
 * Validate a session name.
 *
 * Returns the trimmed name, or `null` for "no name" — which is a legal, meaningful value, not a
 * failure. `null`, `undefined` and an all-whitespace string all mean CLEAR.
 *
 * Rejects rather than repairs. A 201-character name is refused, not truncated, and a name carrying
 * a newline is refused, not stripped: silently altering what the operator typed and then storing it
 * under their name is worse than telling them it was wrong. Each refusal names its own cause, so
 * "why was my name rejected" never requires reading the daemon log.
 */
export function validateSessionName(raw: unknown): SessionNameResult {
  if (raw === null || raw === undefined) return { ok: true, value: null };

  if (typeof raw !== "string") {
    return {
      ok: false,
      reason: "session_name_not_a_string",
      guidance: "A session name must be a string (or null to clear it).",
    };
  }

  // Control characters are checked BEFORE trimming: trim() would silently eat a leading \n or \t
  // and let a name through that the operator never meant to type — and a name that renders across
  // two lines corrupts every listing it appears in.
  if (CONTROL_CHARS.test(raw)) {
    return {
      ok: false,
      reason: "session_name_control_chars",
      guidance: "A session name cannot contain control characters (newlines, tabs, NUL). It is a single-line label — spaces, punctuation, accents and emoji are all fine.",
    };
  }

  const trimmed = raw.trim();
  if (trimmed.length === 0) return { ok: true, value: null };

  if (trimmed.length > SESSION_NAME_MAX_LENGTH) {
    return {
      ok: false,
      reason: "session_name_too_long",
      guidance: `A session name is at most ${SESSION_NAME_MAX_LENGTH} characters (this one is ${trimmed.length}). It is refused rather than truncated — a half-name is a name you did not choose.`,
    };
  }

  return { ok: true, value: trimmed };
}
