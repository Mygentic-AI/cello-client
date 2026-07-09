/**
 * MONIKER-0 — the single home of the agent-name / moniker charset rule
 * (M8C-MONIKER-SPEC §MONIKER-0).
 *
 * This is a WIRE CONTRACT: the moniker crosses the wire on the session offer
 * frame (MONIKER-2), and the charset is the entire injection defense — by
 * construction it excludes newlines, control characters, quotes, parentheses,
 * spaces, markup, and all non-ASCII, so a name cannot break a `<channel>` tag,
 * forge a trust marker, or carry a homoglyph. There is no sanitizer subsystem.
 *
 * ONE constant, shared by agent names and monikers — not two (AC4). The agent
 * name is the default outbound moniker (MONIKER-1 AC1), so the rules cannot
 * legitimately diverge; anyone relaxing agent names is widening the wire
 * charset and must confront that here.
 *
 * The reject battery in __tests__/moniker.test.ts is the actual defense; this
 * constant is just its address. Do not change the regex without a named test
 * telling you exactly which protection you are removing.
 */
export const MONIKER_RE = /^[a-zA-Z0-9_-]{1,64}$/;

/**
 * Validate a raw value against MONIKER_RE.
 *
 * Returns the input VERBATIM when valid, `null` otherwise. Never throws, never
 * transforms: stripping disallowed characters is a mutation oracle (it would
 * construct "CELLO_Support" out of "C*E*L*L*O*_*S*u*p*p*o*r*t" for a sender
 * blocked from sending the real thing). Reject, never strip.
 */
export function validateMoniker(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  return MONIKER_RE.test(raw) ? raw : null;
}
