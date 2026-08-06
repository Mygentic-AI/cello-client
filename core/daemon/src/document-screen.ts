/**
 * DOD-DOC-SCREEN-1 — the document content gate: REFUSE, never mutate.
 *
 * ── WHY A DOCUMENT DOES NOT GET THE MESSAGE SANITIZER ─────────────────────────────────────────
 *
 * The inbound message path may REWRITE content on a `redact` verdict: the operator sees a sanitized
 * form while the leaf still binds the original. That is right for conversation and catastrophic for
 * a document. Measured on 2026-08-05 against eighteen realistic samples, six were silently altered:
 *
 *   कर्‍म → कर्म          a different Hindi word; the ZWJ is orthography in Devanagari
 *   👨‍👩‍👧 → 👨👩👧      one family emoji becomes three separate people
 *   Ｈｅｌｌｏ → Hello      full-width is how CJK users type
 *   ﬁle is ½ → file is 1⁄2   ligatures and fractions normalised away
 *   <|im_start|> → ␠      a document ABOUT prompt formats loses its subject
 *
 * For a CRDT replica that is not a false positive. It is permanent divergence: the receiver applies
 * different bytes than the sender signed, both sides believe they converged, and nothing reports
 * it. And screening the PROJECTION instead does not help — documents are read-WRITE, so the next
 * write-back diffs the operator's screened file against their replica and publishes the redaction
 * as a real, signed edit that deletes the peer's content.
 *
 * So this rule has exactly two outcomes: carry the text exactly, or refuse the envelope. There is
 * no third return value, and that is deliberate — a rule that COULD return replacement text would
 * eventually be used to.
 *
 * ── WHAT IT REFUSES, AND WHY THAT LIST IS SHORT ───────────────────────────────────────────────
 *
 * Only characters whose presence changes what the text MEANS to a reader or a model, independent of
 * language:
 *
 *   - BIDI overrides and isolates, which make what an operator reads differ from what the document
 *     says. In a shared document that is a signature on content the signer did not see.
 *   - Chat-template control markers, which are not content in any document — they are an attempt to
 *     address the reader's model rather than the reader.
 *
 * NOT on the list: zero-width joiners, full-width forms, ligatures, typographic punctuation,
 * combining marks. Every one of those is legitimate text in some language, and refusing them would
 * make CELLO unusable for the operators most likely to need it. Zero-width SPACE is refused —
 * it joins nothing, and its only use in a document is to hide a boundary.
 *
 * This is the denylist half. `DOD-DOC-PROFILE-1` adds the allowlist: a codepoint set agreed at the
 * handshake and bound into `document_id`, which is a stronger instrument because it is decided at
 * consent rather than argued at the boundary. This rule stays underneath it — a profile a peer
 * never agreed to cannot be used to smuggle a BIDI override.
 */

import type { GateRule, ProjectedDiff, GateContext } from "./document-gate.js";
import { profileViolation } from "./document-profile.js";

/** Named so a refusal can say which rule fired without the sender parsing prose (§16.7-6). */
export const SCREEN_RULE_ID = "document_content_screen";

/** Named separately so a refusal says whether the AGREED profile or the default floor refused. */
export const PROFILE_RULE_ID = "document_content_profile";

/**
 * Codepoints refused anywhere in inserted text.
 *
 * Every entry needs a reason that survives the question "is this legitimate in some language?" —
 * because for almost every invisible character the answer is yes, and the audit above is what
 * happens when that question is not asked.
 */
const REFUSED_CODEPOINTS = new Set<number>([
  0x200b, // ZERO WIDTH SPACE — joins nothing; in a document it only hides a boundary
  0x202a, // LEFT-TO-RIGHT EMBEDDING
  0x202b, // RIGHT-TO-LEFT EMBEDDING
  0x202c, // POP DIRECTIONAL FORMATTING
  0x202d, // LEFT-TO-RIGHT OVERRIDE
  0x202e, // RIGHT-TO-LEFT OVERRIDE — renders text as something other than it is
  0x2066, // LEFT-TO-RIGHT ISOLATE
  0x2067, // RIGHT-TO-LEFT ISOLATE
  0x2068, // FIRST STRONG ISOLATE
  0x2069, // POP DIRECTIONAL ISOLATE
]);

/**
 * Markers that address the READER'S MODEL rather than the reader.
 *
 * Matched as literal substrings, and deliberately not as a regex over "anything angle-bracketed":
 * a document about prompt engineering legitimately discusses these, and the audit caught exactly
 * that case being erased. Refusing is honest — the operator is told and can quote it differently —
 * where erasing changed the document's subject without saying so.
 */
const REFUSED_MARKERS = ["<|im_start|>", "<|im_end|>", "<|endoftext|>", "<|system|>"];

/** `U+XXXX`, uppercase, at least four digits — the form a human reads and a machine can match. */
function formatCodepoint(cp: number): string {
  return `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`;
}

/**
 * The rule. Null admits; anything else refuses.
 *
 * Offsets are in CODE POINTS, not UTF-16 units, because they exist for a human or an agent to find
 * the character in their own editor — and an offset that lands mid-surrogate in a document with an
 * emoji in it is worse than none.
 */
export const screeningRule: GateRule = (diff: ProjectedDiff, context: GateContext) => {
  const text = diff.inserted;
  if (text.length === 0) return null;

  // THE AGREED PROFILE FIRST (DOD-DOC-PROFILE-1). An allowlist is the stronger instrument — the
  // decision was made once, at consent, by a human who was engaged — so when a document has one it
  // answers before the denylist argues character by character.
  //
  // It cannot WIDEN anything: every profile still refuses what the denylist below refuses, so a
  // peer cannot ask for a permissive profile at consent time as a way out of screening. Enforced
  // here because the sender's own enforcement is unverifiable; that is the security half, and the
  // authoring check is the ergonomics half, not a substitute for it.
  const violation = profileViolation(context.contentProfile, text);
  if (violation) {
    return {
      reason: "document_profile_violation",
      detail: JSON.stringify({ rule: PROFILE_RULE_ID, ...violation }),
    };
  }

  const codepoints = new Set<string>();
  const offsets: number[] = [];

  let index = 0;
  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    if (REFUSED_CODEPOINTS.has(cp)) {
      codepoints.add(formatCodepoint(cp));
      offsets.push(index);
    }
    index++;
  }

  for (const marker of REFUSED_MARKERS) {
    let at = text.indexOf(marker);
    while (at !== -1) {
      codepoints.add(marker);
      // Converted to a code-point offset for the same reason as above — `indexOf` counts UTF-16.
      offsets.push([...text.slice(0, at)].length);
      at = text.indexOf(marker, at + marker.length);
    }
  }

  if (codepoints.size === 0) return null;

  offsets.sort((a, b) => a - b);
  return {
    reason: "document_content_refused",
    // MACHINE-READABLE (§16.7-6). The default resolution is that the SENDER adopts the receiver's
    // rule for this document — rules compose toward strict — and that only works if the sender can
    // tell which character to stop emitting. Prose cannot carry that.
    //
    // Every distinct offender is named, not just the first: one round trip per character would be a
    // rejection round each, and the protocol stalls at three.
    detail: JSON.stringify({
      rule: SCREEN_RULE_ID,
      codepoints: [...codepoints],
      count: offsets.length,
      offsets,
    }),
  };
};
