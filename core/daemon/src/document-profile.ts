/**
 * DOD-DOC-PROFILE-1 — the content profile: an ALLOWLIST, agreed at the handshake.
 *
 * ── WHY AN ALLOWLIST WHEN A DENYLIST ALREADY EXISTS ───────────────────────────────────────────
 *
 * `document-screen.ts` is the denylist: it argues about characters, one at a time, in an open-ended
 * space, and every argument happens mid-document with whoever is working ambushed by it. A profile
 * inverts that. Only this character space is permitted, so violations are unambiguous — and the
 * decision moves to CONSENT, which is the real win. "Do I want a Devanagari document with this
 * person" is a question an operator can answer once, with a human already engaged, about the whole
 * document. "What is U+200D doing at offset 412" is not a question anyone can answer.
 *
 * ── THE THREE CONSTRAINTS ─────────────────────────────────────────────────────────────────────
 *
 *   NAMED AND CLOSED. A free-form profile is a negotiation again, and named profiles are what let
 *   an operator hold a standing policy — "never auto-accept `unicode-text` from an unendorsed
 *   contact". A sixth name is a protocol decision, not a caller's choice.
 *
 *   CODEPOINT SETS, NOT ADJECTIVES. A profile enforced by a heuristic is a promise we do not keep,
 *   and "looks like markdown" is a heuristic. Every profile below is a predicate over code points.
 *
 *   ENFORCED IN BOTH PLACES, for different reasons (§16.7-14). At authoring, so a stray character
 *   is caught where it was written and never becomes a rejection round — that is ERGONOMICS. At
 *   receipt, because the sender's enforcement is unverifiable — that is SECURITY. The second is not
 *   redundant with the first: a sender's client can be patched, or simply compromised while the
 *   sender themselves is a good actor.
 *
 * ── NARROWING ONLY ────────────────────────────────────────────────────────────────────────────
 *
 * Every profile, including the widest, still refuses what `document-screen.ts` refuses. A profile
 * may only narrow the space, never widen it — otherwise choosing `unicode-text` would be a way to
 * opt OUT of screening, and a peer could ask for that at consent time in the same breath as asking
 * for Japanese.
 */

/** A violation, in the same machine-readable shape every refusal on this path uses. */
export interface ProfileViolation {
  profile: string;
  codepoints: string[];
  count: number;
  offsets: number[];
}

/** Shape of text, in every profile: the two characters that are structure rather than content. */
const TAB = 0x09;
const NEWLINE = 0x0a;
const CARRIAGE_RETURN = 0x0d;

/**
 * Refused by EVERY profile — the floor `document-screen.ts` sets, restated here so a profile cannot
 * be used to bypass it. Kept as its own set rather than imported so the two can be read
 * independently: this one is "no profile may admit these", which is a different claim from "the
 * default rules refuse these".
 */
const NEVER = new Set<number>([
  0x200b, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069,
]);

function isShapingChar(cp: number): boolean {
  return cp === TAB || cp === NEWLINE || cp === CARRIAGE_RETURN;
}

/** Printable ASCII. Control characters are not content — they address whatever renders them. */
function isPrintableAscii(cp: number): boolean {
  return cp >= 0x20 && cp <= 0x7e;
}

/**
 * The closed set. Each value answers one question: may this code point appear?
 *
 * `ascii-markdown` and `ascii-text` are the same space today — markdown's syntax is printable ASCII.
 * They are kept distinct because the NAME is what an operator consents to and what a future diff
 * renderer keys on, and collapsing them would make "this is a markdown document" unstateable.
 */
export const CONTENT_PROFILES: Record<string, (cp: number) => boolean> = {
  "ascii-text": (cp) => isShapingChar(cp) || isPrintableAscii(cp),
  "ascii-markdown": (cp) => isShapingChar(cp) || isPrintableAscii(cp),
  // JSON is ASCII-only BY DESIGN: `é` is how JSON carries `é`. Admitting the raw character too
  // would mean two documents that parse identically have different bytes, and a CRDT replica's
  // whole claim is that they do not.
  json: (cp) => isShapingChar(cp) || isPrintableAscii(cp),
  // The wide profiles admit anything that is not explicitly refused — including every sample the
  // sanitizer audit destroyed. A profile that refused Devanagari orthography or a family emoji
  // would be that same failure wearing a different name.
  "unicode-text": (cp) => !NEVER.has(cp),
  "unicode-markdown": (cp) => !NEVER.has(cp),
};

export function isKnownProfile(name: string | undefined): boolean {
  return typeof name === "string" && Object.hasOwn(CONTENT_PROFILES, name);
}

function formatCodepoint(cp: number): string {
  return `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`;
}

/**
 * Check text against a profile. Null admits.
 *
 * AN UNKNOWN OR ABSENT PROFILE ENFORCES NOTHING, and this is the one fail-open on the document
 * path. A document agreed before profiles existed carries none, and refusing all of its updates
 * would break a working document to enforce a rule its two parties never agreed to. The screening
 * denylist still applies to it — that is the floor, and it is why failing open here is bounded
 * rather than a hole.
 */
export function profileViolation(
  profile: string | undefined,
  text: string,
): ProfileViolation | null {
  if (!isKnownProfile(profile)) return null;
  const allows = CONTENT_PROFILES[profile!]!;

  const codepoints = new Set<string>();
  const offsets: number[] = [];
  let index = 0;
  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    if (!allows(cp) || NEVER.has(cp)) {
      codepoints.add(formatCodepoint(cp));
      offsets.push(index);
    }
    // CODE POINTS, not UTF-16 units — the offsets exist for a human or an agent to find the
    // character in their own editor, and one that lands mid-surrogate in a document containing an
    // emoji is worse than none.
    index++;
  }
  if (codepoints.size === 0) return null;
  return { profile: profile!, codepoints: [...codepoints], count: offsets.length, offsets };
}
