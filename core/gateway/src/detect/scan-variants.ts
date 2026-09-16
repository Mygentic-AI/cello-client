/**
 * DOD-M9C-SCREENBASE-1 — scan variants: the disguises a receiving LLM can still read, undone in
 * copies that ONLY the injection-pattern matcher sees. Nothing here reaches the delivered text.
 *
 * Why variants and not one "normalized" string: each undo is lossy in a different direction (folding
 * digits to letters wrecks a version number; joining single letters wrecks an acronym). Applied to a
 * copy that is only pattern-matched, that loss costs nothing — a benign message has no attack
 * wording in ANY variant — while the disguised attack has it in at least one.
 *
 * No thresholds and no context rules, by design: the screener is public, and a threshold is a
 * published recipe for passing it. The only question each variant answers is "does attack wording
 * appear once this disguise is undone?".
 *
 * Linear time: every transform is a single pass over code points or a regex with no nested
 * quantifiers, because this runs on adversary-controlled content before any pattern engine.
 */
import { stripInvisible } from "./sanitize.js";

export interface ScanVariant {
  /** Stable name of the disguise this variant undoes — carried into the governance event. */
  kind: string;
  text: string;
}

// Small-caps and other Latin letter forms that NFKC does not fold.
const LETTER_FORMS: Record<string, string> = {
  "ᴀ": "a", "ʙ": "b", "ᴄ": "c", "ᴅ": "d", "ᴇ": "e", "ꜰ": "f", "ɢ": "g", "ʜ": "h", "ɪ": "i", "ᴊ": "j",
  "ᴋ": "k", "ʟ": "l", "ᴍ": "m", "ɴ": "n", "ᴏ": "o", "ᴘ": "p", "ǫ": "q", "ʀ": "r", "ꜱ": "s", "ᴛ": "t",
  "ᴜ": "u", "ᴠ": "v", "ᴡ": "w", "ʏ": "y", "ᴢ": "z",
};

/** NFKD, drop every combining mark, fold small caps, lowercase. Accents, underlines, Zalgo gone. */
function foldLetters(text: string): string {
  const stripped = text.normalize("NFKD").replace(/\p{M}/gu, "");
  let out = "";
  for (const ch of stripped) out += LETTER_FORMS[ch] ?? ch;
  // NFKC renders parenthesized letters as "(a)"; a run of them is a disguised word.
  return out.replace(/\(([a-z])\)/gi, "$1").toLowerCase();
}

/** Letters written one at a time with single separators ("i g n o r e", "i.g.n.o.r.e") joined. */
function joinSpacedLetters(text: string): string {
  // Groups of words are separated by 2+ spaces (or a newline) in spaced text; inside a group,
  // single characters separated by one space or one punctuation mark are one word.
  return text
    .split(/\s{2,}|\n/)
    .map((group) => {
      const tokens = group.split(/[ ._\-*·]/);
      return tokens.length > 2 && tokens.every((t) => t.length <= 1) ? tokens.join("") : group;
    })
    .join(" ");
}

/** snake_case, kebab-case, dotted and camelCase identifiers split back into words. */
function splitJoinedWords(text: string): string {
  return text.replace(/([a-z])([A-Z])/g, "$1 $2").replace(/[_\-.]+/g, " ");
}

const LEET: Record<string, string> = {
  "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g", "@": "a", "$": "s", "!": "i", "|": "l",
};
function foldLeet(text: string): string {
  let out = "";
  for (const ch of text) out += LEET[ch] ?? ch;
  return out;
}

export function scanVariants(decodedForScan: string): ScanVariant[] {
  const variants: ScanVariant[] = [{ kind: "decoded", text: decodedForScan }];
  const add = (kind: string, text: string): void => {
    if (!variants.some((v) => v.text === text)) variants.push({ kind, text });
  };

  const base = stripInvisible(decodedForScan).text;
  const folded = foldLetters(base);
  add("folded_letters", folded);
  add("spaced_letters_joined", joinSpacedLetters(folded));
  add("joined_words_split", foldLetters(splitJoinedWords(base)));
  add("leetspeak", foldLeet(folded));
  add("spaces_removed", folded.replace(/[\s_\-.]+/g, ""));
  return variants;
}
