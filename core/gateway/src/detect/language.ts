/**
 * M9-IN-003 — inbound language allowlist (default: English).
 *
 * Holds inbound content confidently in a non-allowlisted language, so a jailbreak phrased in a
 * low-resource language can't dodge English-trained screening — WITHOUT blocking legitimate short
 * messages on a guess (AC-002), and with no model and no network call (INV-1).
 *
 * v1 uses dominant Unicode SCRIPT (the story's "script inspection covers most of it"): a message
 * confidently dominated by a non-Latin script (Cyrillic, Greek, Arabic, Hebrew, CJK, Devanagari,
 * Thai, …) is outside the {English=Latin} allowlist and is held. Latin-script text is allowed —
 * distinguishing Latin-script LANGUAGES (English vs French/Spanish) needs a trained classifier and
 * is a separate design session (Andre, 2026-06-23). Short / low-letter-count messages are allowed.
 *
 * This is the DETECTOR. Delivering the held note to the operator + the terminal-block inbound
 * handling (ack-and-record without delivering, distinct from the transient fail-closed hold) is the
 * integration step (M9-FEED-001 / the gate / the L4 terminal-vs-transient split).
 */

/** A coarse script bucket. `latin` is the default allowlist; everything else is a non-Latin script. */
export type Script =
  | "latin" | "cyrillic" | "greek" | "arabic" | "hebrew" | "han" | "kana" | "hangul"
  | "devanagari" | "thai" | "other";

/**
 * Every script name the allowlist accepts. Exported so the config layer can REJECT a name that
 * means nothing — `language_allow=klingon` was stored, gated and hash-chained like a real setting
 * and then matched no script, which is a guard that reads as configured and screens as if it were
 * not.
 */
export const SCRIPTS: readonly Script[] = [
  "latin", "cyrillic", "greek", "arabic", "hebrew", "han", "kana", "hangul",
  "devanagari", "thai", "other",
];
export const isScript = (v: unknown): v is Script => SCRIPTS.includes(v as Script);

export interface LanguageVerdict {
  /** false → held (confident non-allowlisted language). */
  allowed: boolean;
  /** The dominant non-allowlisted script, when held. */
  script?: Script;
  /** A legible note naming the script + how to allow it (held messages only). */
  reason?: string;
}

export interface LanguageOptions {
  /** Allowed scripts. Default ["latin"] (English). */
  allow?: Script[];
  /** Minimum letter count to make a confident call. Below this, always allow (AC-002). Default 12. */
  minLetters?: number;
  /** Minimum dominant-script share to hold. Default 0.5. */
  minShare?: number;
}

/**
 * Exported for tests that need to MEASURE an exemplar's script composition. A test that hand-copies
 * this bucketing drifts the moment a bucket is added here, and its "measured" counts quietly stop
 * describing the classifier they claim to measure. Not re-exported from the package index — this is
 * the module's own boundary, not public API.
 */
export function scriptOf(cp: number): Script | null {
  // Returns the script for a LETTER codepoint, or null for non-letters (digits/punct/space/emoji).
  // Combining marks carry no script of their own — counted as letters they let a few underline or
  // Zalgo marks outvote the Latin they decorate (DOD-M9C-SCREENBASE-1).
  if ((cp >= 0x300 && cp <= 0x36f) || (cp >= 0x1ab0 && cp <= 0x1aff) || (cp >= 0x1dc0 && cp <= 0x1dff) ||
      (cp >= 0x20d0 && cp <= 0x20ff) || (cp >= 0xfe20 && cp <= 0xfe2f)) return null;
  // IPA extensions, phonetic extensions and Latin Extended-C/D hold small caps and turned letters —
  // decorated Latin, not a foreign language.
  if ((cp >= 0x41 && cp <= 0x5a) || (cp >= 0x61 && cp <= 0x7a) ||
      (cp >= 0xc0 && cp <= 0x2af) || (cp >= 0x1d00 && cp <= 0x1dbf) || (cp >= 0x1e00 && cp <= 0x1eff) ||
      (cp >= 0x2c60 && cp <= 0x2c7f) || (cp >= 0xa720 && cp <= 0xa7ff)) return "latin";
  if (cp >= 0x400 && cp <= 0x4ff) return "cyrillic";
  if ((cp >= 0x370 && cp <= 0x3ff) || (cp >= 0x1f00 && cp <= 0x1fff)) return "greek";
  if ((cp >= 0x600 && cp <= 0x6ff) || (cp >= 0x750 && cp <= 0x77f)) return "arabic";
  if (cp >= 0x590 && cp <= 0x5ff) return "hebrew";
  if ((cp >= 0x4e00 && cp <= 0x9fff) || (cp >= 0x3400 && cp <= 0x4dbf)) return "han";
  if (cp >= 0x3040 && cp <= 0x30ff) return "kana";
  if ((cp >= 0xac00 && cp <= 0xd7af) || (cp >= 0x1100 && cp <= 0x11ff)) return "hangul";
  if (cp >= 0x900 && cp <= 0x97f) return "devanagari";
  if (cp >= 0xe00 && cp <= 0xe7f) return "thai";
  // A letter we don't bucket finely — count it as "other" only if it is clearly a letter.
  if (cp > 0x2bf && !(cp >= 0x2000 && cp <= 0x2bff)) return "other";
  return null;
}

const SCRIPT_LABEL: Record<Script, string> = {
  latin: "Latin", cyrillic: "Cyrillic", greek: "Greek", arabic: "Arabic", hebrew: "Hebrew",
  han: "Han/CJK", kana: "Japanese kana", hangul: "Korean Hangul", devanagari: "Devanagari",
  thai: "Thai", other: "a non-Latin",
};

export function screenInboundLanguage(text: string, opts: LanguageOptions = {}): LanguageVerdict {
  const allow = new Set<Script>(opts.allow ?? ["latin"]);
  const minLetters = opts.minLetters ?? 12;
  const minShare = opts.minShare ?? 0.5;

  const counts = new Map<Script, number>();
  let total = 0;
  for (const ch of text) {
    const s = scriptOf(ch.codePointAt(0)!);
    if (!s) continue;
    counts.set(s, (counts.get(s) ?? 0) + 1);
    total++;
  }

  // Not enough letters to be confident → allow (don't block short/ambiguous, AC-002).
  if (total < minLetters) return { allowed: true };

  let dominant: Script = "latin";
  let max = 0;
  for (const [s, n] of counts) if (n > max) { max = n; dominant = s; }

  // Allowed script dominant, or the dominant non-allowed script isn't a clear majority → allow.
  if (allow.has(dominant) || max / total < minShare) return { allowed: true };

  return {
    allowed: false,
    script: dominant,
    reason:
      `This message is predominantly ${SCRIPT_LABEL[dominant]} script, outside the gateway's ` +
      `language allowlist.`,
  };
}
