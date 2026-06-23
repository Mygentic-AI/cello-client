/**
 * M9-IN-001 — inbound Layer-1 deterministic sanitization.
 *
 * Pure function, no model, no network (INV-1). Runs the ordered steps from the attack-corpus §1
 * pipeline that need no external engine: size cap (first — AC-005), invisible/smuggled-Unicode
 * strip (AC-001 / SI-001), confusables normalization (NFKC + script-lookalike map), encoded-
 * payload decode, Shannon-entropy scoring (AC-003), and chat-template/special-token strip (AC-004).
 *
 * The Step-9 injection-pattern match (AC-002) is a SEPARATE concern: it requires a linear-time
 * RE2 engine (no native RegExp — ReDoS). The RE2 binding is a pending decision, so that step is
 * not wired here yet; this module exposes the sanitized text + notes that the pattern matcher and
 * the M9-IN-002 scanner will consume.
 */

/** Default per-message byte cap — mirrors the daemon's 1 MB content cap. */
export const DEFAULT_MAX_BYTES = 1_000_000;

export interface SanitizationNote {
  step: "invisible_strip" | "confusables" | "decode" | "entropy" | "special_tokens";
  detail: string;
  count?: number;
}

export interface SanitizeResult {
  /** The DELIVERED text: invisible-strip + confusables + special-token strip. Empty on `blocked`. */
  text: string;
  /**
   * The delivered text with encodings additionally decoded — for DETECTION ONLY (the pattern
   * matcher / entropy). Never delivered to the agent: decoding %XX / &#..; / \x.. in a legitimate
   * URL or code snippet would corrupt content the receiver needs (M1 review / decode-then-rescan).
   */
  decodedForScan: string;
  /** Per-step detection notes (only steps that fired). */
  notes: SanitizationNote[];
  /** A suspicion signal for high-entropy (encoded-blob) content. 0 = nothing suspicious. */
  entropySuspicion: number;
  /** Set when the message is rejected outright (e.g. over the size cap) — text is empty. */
  blocked?: { reason: string; guidance: string };
}

export interface SanitizeOptions {
  maxBytes?: number;
}

// ── Step 1: invisible / smuggled-Unicode strip ───────────────────────────────
// Codepoints that are invisible (or direction-altering) to a human but tokenize for an LLM.
const SINGLE_SMUGGLE = new Set<number>([
  0x00ad, // soft hyphen
  0x200b, 0x200c, 0x200d, // zero-width space / non-joiner / joiner
  0x2060, 0x2061, 0x2062, 0x2063, 0x2064, // word joiner + invisible math operators
  0xfeff, // BOM / zero-width no-break space
  0x202a, 0x202b, 0x202c, 0x202d, 0x202e, // bidi embeddings / overrides / pop
  0x2066, 0x2067, 0x2068, 0x2069, // bidi isolates
]);
function isSmuggled(cp: number): boolean {
  if (SINGLE_SMUGGLE.has(cp)) return true;
  if (cp >= 0xe0000 && cp <= 0xe007f) return true; // Tags block
  if (cp >= 0xfe00 && cp <= 0xfe0f) return true; // variation selectors
  if (cp >= 0xe0100 && cp <= 0xe01ef) return true; // variation selectors supplement
  return false;
}
export function stripInvisible(text: string): { text: string; removed: number } {
  let out = "";
  let removed = 0;
  for (const ch of text) {
    if (isSmuggled(ch.codePointAt(0)!)) { removed++; continue; }
    out += ch;
  }
  return { text: out, removed };
}

// ── Step 3: confusables normalization ────────────────────────────────────────
// NFKC folds full-width, mathematical-alphanumeric, enclosed, and other compatibility lookalikes
// to their base form. NFKC does NOT touch cross-script confusables (Cyrillic/Greek letters that
// merely LOOK Latin), so those get an explicit map. (A full Unicode confusables.txt integration —
// 6,800+ pairs — is a follow-up; this covers the common attack scripts.)
const CYRILLIC_GREEK_CONFUSABLES: Record<string, string> = {
  // Cyrillic → Latin
  "а": "a", "е": "e", "о": "o", "с": "c", "р": "p", "х": "x",
  "у": "y", "к": "k", "м": "m", "т": "t", "н": "h", "в": "b",
  "и": "u", "ѕ": "s", "і": "i", "ј": "j", "һ": "h", "ԁ": "d",
  "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H",
  "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X", "Ѕ": "S",
  "І": "I", "Ј": "J",
  // Greek → Latin
  "ο": "o", "ν": "v", "α": "a", "ρ": "p", "υ": "u", "κ": "k",
  "Α": "A", "Β": "B", "Ε": "E", "Κ": "K", "Μ": "M", "Ν": "N",
  "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X",
};
function normalizeConfusables(text: string): { text: string; changed: boolean; count: number } {
  const nfkc = text.normalize("NFKC");
  let count = 0;
  const mapped = [...nfkc].map((ch) => {
    const r = CYRILLIC_GREEK_CONFUSABLES[ch];
    if (r !== undefined) { count++; return r; }
    return ch;
  }).join("");
  return { text: mapped, changed: mapped !== text, count };
}

// ── Step 6: encoded-payload decode ───────────────────────────────────────────
// Decode HTML entities, percent-encoding, and \x / \u escapes so a word hidden behind an encoding
// surfaces for downstream pattern matching. (Base64/other-radix BLOCKS are handled by entropy
// scoring + the Step-7 hidden-instruction handling, not decoded blindly here.)
const NAMED_ENTITIES: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " };
function decodeEncoded(text: string): { text: string; changed: boolean; count: number } {
  let count = 0;
  let out = text;
  out = out.replace(/&#x([0-9a-f]+);/gi, (_m, h: string) => { count++; return safeFromCodePoint(parseInt(h, 16)); });
  out = out.replace(/&#(\d+);/g, (_m, d: string) => { count++; return safeFromCodePoint(parseInt(d, 10)); });
  out = out.replace(/&([a-z]+);/gi, (m, name: string) => {
    const v = NAMED_ENTITIES[name.toLowerCase()];
    if (v === undefined) return m;
    count++; return v;
  });
  out = out.replace(/%([0-9a-f]{2})/gi, (_m, h: string) => { count++; return safeFromCodePoint(parseInt(h, 16)); });
  out = out.replace(/\\x([0-9a-f]{2})/gi, (_m, h: string) => { count++; return safeFromCodePoint(parseInt(h, 16)); });
  out = out.replace(/\\u\{?([0-9a-f]{1,6})\}?/gi, (_m, h: string) => { count++; return safeFromCodePoint(parseInt(h, 16)); });
  return { text: out, changed: out !== text, count };
}
function safeFromCodePoint(cp: number): string {
  if (!Number.isFinite(cp) || cp < 0 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return "";
  try { return String.fromCodePoint(cp); } catch { return ""; }
}

// ── Step 8: Shannon-entropy scoring ──────────────────────────────────────────
// An encoded payload (base64/hex blob) is a long, space-free, high-entropy token; ordinary prose
// is short tokens with lower per-character entropy. Count the suspicious tokens.
const ENTROPY_MIN_TOKEN_LEN = 20;
const ENTROPY_BITS_THRESHOLD = 4.0;
function shannonBits(s: string): number {
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of freq.values()) { const p = c / s.length; h -= p * Math.log2(p); }
  return h;
}
// An encoded-blob candidate is a long run drawn purely from a base64/base64url/hex alphabet —
// which excludes URLs, file paths, and prose (they carry `:` `/` `.` or whitespace). This keeps
// the entropy signal on actual encoded payloads, not legitimate long tokens like a URL.
const ENCODED_CHARSET = /^[A-Za-z0-9+/=_-]+$/;
/** The space-free, encoded-alphabet, high-entropy tokens (encoded-blob candidates) in `text`. */
export function highEntropyTokens(text: string): string[] {
  const found: string[] = [];
  for (const token of text.split(/\s+/)) {
    if (token.length < ENTROPY_MIN_TOKEN_LEN) continue;
    if (!ENCODED_CHARSET.test(token)) continue;
    if (shannonBits(token) >= ENTROPY_BITS_THRESHOLD) found.push(token);
  }
  return found;
}
function scoreEntropy(text: string): number {
  return highEntropyTokens(text).length;
}

// ── Step 9 (markers): chat-template / special-token strip ────────────────────
// Removes privileged-turn markers so they cannot be re-interpreted as a system/instruction turn.
// These are bounded literals/anchored patterns (no catastrophic backtracking) — distinct from the
// RE2 injection-pattern step (AC-002), which is parked on the RE2 binding decision.
const LITERAL_MARKERS = ["[SYSTEM]", "[/SYSTEM]", "<<SYS>>", "<</SYS>>", "[INST]", "[/INST]", "SYSTEM PROMPT:", "<system>", "</system>"];
function stripSpecialTokens(text: string): { text: string; removed: number } {
  let out = text;
  let removed = 0;
  for (const lit of LITERAL_MARKERS) {
    const parts = out.split(lit);
    if (parts.length > 1) { removed += parts.length - 1; out = parts.join(" "); }
  }
  out = out.replace(/<\|[a-z0-9_]+\|>/gi, () => { removed++; return " "; });
  out = out.replace(/###\s*(instruction|response|system|human|assistant)\b:?/gi, () => { removed++; return " "; });
  out = out.replace(/<\/?s>/gi, () => { removed++; return " "; });
  return { text: out, removed };
}

// ── The pipeline ─────────────────────────────────────────────────────────────
export function sanitizeInbound(content: Uint8Array, opts: SanitizeOptions = {}): SanitizeResult {
  const maxBytes = opts.maxBytes ?? DEFAULT_MAX_BYTES;
  const notes: SanitizationNote[] = [];

  // AC-005: size cap FIRST — before any decode/normalize work.
  if (content.length > maxBytes) {
    return {
      text: "",
      decodedForScan: "",
      notes: [],
      entropySuspicion: 0,
      blocked: {
        reason: "content_too_large",
        guidance: `Inbound message is ${content.length} bytes, over the ${maxBytes}-byte cap. ` +
          "It was rejected before sanitization; the sender must split it into smaller messages.",
      },
    };
  }

  let text = new TextDecoder("utf-8", { fatal: false }).decode(content);

  const inv = stripInvisible(text);
  if (inv.removed > 0) notes.push({ step: "invisible_strip", detail: "stripped invisible/smuggled-Unicode codepoints", count: inv.removed });
  text = inv.text;

  const conf = normalizeConfusables(text);
  if (conf.changed) notes.push({ step: "confusables", detail: "normalized lookalike characters to their base form", count: conf.count });
  text = conf.text;

  const tok = stripSpecialTokens(text);
  if (tok.removed > 0) notes.push({ step: "special_tokens", detail: "stripped chat-template / special-token markers", count: tok.removed });
  text = tok.text;

  // Decode is DETECTION-ONLY (decode-then-rescan): it feeds the pattern matcher + entropy, and is
  // NOT applied to the delivered `text` — decoding %XX / &#..; / \x.. / \u.. in a legitimate URL,
  // code snippet, or quoted entity would silently corrupt content the receiver needs (M1 review).
  const dec = decodeEncoded(text);
  if (dec.changed) notes.push({ step: "decode", detail: "encoded payload detected (decoded for rescan; delivered form unchanged)", count: dec.count });
  const decodedForScan = dec.text;

  const entropySuspicion = scoreEntropy(decodedForScan);
  if (entropySuspicion > 0) notes.push({ step: "entropy", detail: "high-entropy encoded-blob segment(s) detected", count: entropySuspicion });

  return { text, decodedForScan, notes, entropySuspicion };
}
