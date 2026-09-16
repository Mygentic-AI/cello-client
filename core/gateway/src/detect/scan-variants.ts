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
import { decodeEncoded, readHiddenChannels, stripInvisible } from "./sanitize.js";

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

/**
 * snake_case, kebab-case, dotted and camelCase identifiers split back into words. The separator must
 * sit BETWEEN letters: splitting a sentence-ending "." joined two sentences into one phrase, and
 * "Don't forget. Previous instructions still apply." read as an override command.
 */
function splitJoinedWords(text: string): string {
  return text.replace(/([a-z])([A-Z])/g, "$1 $2").replace(/([a-zA-Z])[_\-.]+([a-zA-Z])/g, "$1 $2");
}

const LEET: Record<string, string> = {
  "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g", "@": "a", "$": "s", "!": "i", "|": "l",
};
function foldLeet(text: string): string {
  let out = "";
  for (const ch of text) out += LEET[ch] ?? ch;
  return out;
}

// Upside-down ("turned") letters back to Latin. Only ever applied in its own variant: it swaps
// b/q, d/p and n/u, which would wreck ordinary text.
const TURNED: Record<string, string> = {
  "ɐ": "a", "q": "b", "ɔ": "c", "p": "d", "ǝ": "e", "ɟ": "f", "ƃ": "g", "ɥ": "h", "ᴉ": "i", "ı": "i",
  "ɾ": "j", "ʞ": "k", "ɯ": "m", "u": "n", "d": "p", "b": "q", "ɹ": "r", "ʇ": "t", "n": "u", "ʌ": "v",
  "ʍ": "w", "ʎ": "y", "˙": ".",
};
function unturn(text: string): string {
  let out = "";
  for (const ch of text.toLowerCase()) out += TURNED[ch] ?? ch;
  return out;
}

function reverse(text: string): string {
  return [...text].reverse().join("");
}

/**
 * Caesar shift by n. Only ROT13 and ROT3 get a variant: measured over the whole corpus, the other
 * 23 shifts earned three rows between them and tripled the worst-case screening time of a 1 MB
 * message. A1Z26 and every other shift earned nothing at all.
 */
function caesar(text: string, n: number): string {
  return text.replace(/[a-z]/gi, (c) => {
    const base = c <= "Z" ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + n) % 26) + base);
  });
}

/** Atbash: a↔z, b↔y. Its own inverse. */
function atbash(text: string): string {
  return text.replace(/[a-z]/gi, (c) => {
    const base = c <= "Z" ? 65 : 97;
    return String.fromCharCode(base + 25 - (c.charCodeAt(0) - base));
  });
}

/** ROT47 over printable ASCII. */
function rot47(text: string): string {
  return text.replace(/[!-~]/g, (c) => String.fromCharCode(33 + ((c.charCodeAt(0) - 33 + 47) % 94)));
}

/** "01001001 01100111" → the ASCII it spells. */
function decodeBinaryRuns(text: string): string {
  return text.replace(/(?:[01]{8}[\s,]{0,2}){4,}/g, (run) => {
    const bits = run.replace(/[^01]/g, "");
    let out = "";
    for (let i = 0; i + 8 <= bits.length; i += 8) out += String.fromCharCode(parseInt(bits.slice(i, i + 8), 2));
    return /^[\x20-\x7e\n]+$/.test(out) ? out : run;
  });
}

function rot13(text: string): string {
  return text.replace(/[a-z]/gi, (c) => {
    const base = c <= "Z" ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });
}

/**
 * Unicode Tag characters (U+E0000 block) back to the ASCII they shadow, plus whatever the other
 * invisible channels carry. The sanitizer strips tag characters before `decodedForScan` exists, so
 * this matters for text that only BECOMES tag characters later — the decoding of a base64 run, or a
 * nested HTML-entity escape. The sanitizer's own `hiddenText` covers what arrived as tags directly.
 */
function untag(text: string): string {
  let out = "";
  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    out += cp > 0xe0000 && cp < 0xe007f ? String.fromCodePoint(cp - 0xe0000) : ch;
  }
  const hidden = readHiddenChannels(text);
  return hidden.length > 0 ? `${out} ${hidden}` : out;
}

/** A decoded blob counts only if it reads as text — binary data (an image, a hash) is left alone. */
function readable(s: string): boolean {
  const visible = stripInvisible(untag(s)).text;
  if (visible.length < 4) return false;
  let ok = 0;
  for (const ch of visible) if (/[\p{L}\p{N}\p{P}\p{Zs}\n]/u.test(ch)) ok++;
  return ok / [...visible].length >= 0.9;
}

/** Replace every base64 run that decodes to readable text with its decoding. */
function decodeBase64Runs(text: string): string {
  return text.replace(/[A-Za-z0-9+/_-]{16,}={0,2}/g, (run) => {
    const s = Buffer.from(run.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
    return readable(s) ? stripInvisible(untag(s)).text : run;
  });
}

/** Replace every run of 8+ hex byte pairs that decodes to readable text with its decoding. */
function decodeHexRuns(text: string): string {
  return text.replace(/(?:[0-9a-f]{2}[\s:]?){8,}/gi, (run) => {
    const hex = run.replace(/[\s:]/g, "");
    const s = Buffer.from(hex, "hex").toString("utf8");
    return readable(s) ? s : run;
  });
}

/**
 * @param decodedForScan the sanitizer's detection copy.
 * @param hiddenText what the stripped invisible codepoints carried (see `SanitizeResult.hiddenText`).
 */
export function scanVariants(decodedForScan: string, hiddenText = ""): ScanVariant[] {
  const variants: ScanVariant[] = [{ kind: "decoded", text: decodedForScan }];
  const add = (kind: string, text: string): void => {
    if (text.length > 0 && !variants.some((v) => v.text === text)) variants.push({ kind, text });
  };
  add("hidden_codepoints", hiddenText);

  // decodedForScan has had ONE decode pass; nested encodings (%2520) need more. Three is enough for
  // any nesting a model would still unwrap, and bounds the work.
  let redecoded = decodedForScan;
  for (let i = 0; i < 3; i++) {
    const d = decodeEncoded(redecoded);
    if (!d.changed) break;
    redecoded = d.text;
  }
  add("nested_encoding", redecoded);

  add("unicode_tags", stripInvisible(untag(redecoded)).text);

  const base = stripInvisible(redecoded).text;
  add("base64", decodeBase64Runs(base));
  add("hex", decodeHexRuns(base));
  const folded = foldLetters(base);
  const turned = unturn(base);
  add("reversed", reverse(folded));
  add("upside_down", reverse(turned));
  add("upside_down_unreversed", turned);
  add("rot13", rot13(base));
  add("atbash", atbash(base));
  add("rot47", rot47(base));
  add("binary", decodeBinaryRuns(base));
  add("caesar_3", caesar(base, 23));
  add("folded_letters", folded);
  add("spaced_letters_joined", joinSpacedLetters(folded));
  add("joined_words_split", foldLetters(splitJoinedWords(base)));
  add("leetspeak", foldLeet(folded));
  // Sentence punctuation stays: removing "." would join "…forget. Previous instructions…" into one
  // phrase and read as an override command.
  add("spaces_removed", folded.replace(/[\s_-]+/g, ""));
  return variants;
}
