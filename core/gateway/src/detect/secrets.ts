/**
 * M9-OUT-001 — outbound secret detection + redaction.
 *
 * Adopts the FULL gitleaks dictionary (222 detectors, MIT — see ./gitleaks-rules.ts) plus the
 * generic keyword-proximity + entropy catch-all (gitleaks' own `generic-api-key` rule, so coverage
 * is not limited to enumerated formats), with gitleaks' value-level false-positive layer (stopwords
 * + allow-regexes + per-rule entropy thresholds). Secrets redact by DEFAULT — leaking a credential is
 * essentially never intended; the rare deliberate send goes through the M9-FEED-001 governance
 * re-send.
 *
 * Every pattern runs on the RE2 engine (the rules are RE2-authored), so a crafted message can never
 * cause catastrophic backtracking. The keyword pre-filter (run a rule only when one of its keywords
 * appears) keeps the 222-rule scan fast. Compile once at gateway startup, after initLinearRegex().
 */
import { LinearRegex } from "./linear-regex.js";
import { GITLEAKS_RULES, GITLEAKS_STOPWORDS, GITLEAKS_ALLOW_REGEXES } from "./gitleaks-rules.js";

interface CompiledRule { id: string; re: LinearRegex; keywords: string[]; entropy: number }

let RULES: CompiledRule[] | null = null;

/**
 * The ids of the secret rules that ACTUALLY COMPILED — see `injectionPatternIds` for why the active
 * set rather than the source list. `compileSecretRules` deliberately skips a rule that will not
 * compile under RE2, so the two can differ, and the digest must follow what is really running.
 */
export function secretRuleIds(): string[] | null {
  return RULES === null ? null : RULES.map((r) => r.id);
}
let STOPWORDS: string[] = [];
let ALLOW: LinearRegex[] = [];

/** Compile the rule set + the false-positive layer. Returns how many of the 222 rules compiled. */
export function compileSecretRules(): { compiled: number; total: number } {
  const compiled: CompiledRule[] = [];
  for (const r of GITLEAKS_RULES) {
    try {
      compiled.push({ id: r.id, re: new LinearRegex(r.regex), keywords: r.keywords, entropy: r.entropy });
    } catch {
      // A rule that does not compile under RE2 is skipped rather than crashing the gateway.
    }
  }
  RULES = compiled;
  STOPWORDS = GITLEAKS_STOPWORDS.map((s) => s.toLowerCase());
  ALLOW = GITLEAKS_ALLOW_REGEXES.map((s) => {
    try { return new LinearRegex(s); } catch { return null; }
  }).filter((x): x is LinearRegex => x !== null);
  return { compiled: compiled.length, total: GITLEAKS_RULES.length };
}

export function secretRulesReady(): boolean {
  return RULES !== null;
}

export interface SecretFinding { ruleId: string }
export interface SecretScanResult { text: string; findings: SecretFinding[] }

function shannonBits(s: string): number {
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of freq.values()) { const p = c / s.length; h -= p * Math.log2(p); }
  return h;
}

/** gitleaks' value-level false-positive layer: stopword substring, allow-regex, or below entropy. */
function isFalsePositive(value: string, ruleEntropy: number): boolean {
  const lower = value.toLowerCase();
  if (STOPWORDS.some((sw) => lower.includes(sw))) return true;
  if (ALLOW.some((re) => re.test(value))) return true;
  if (ruleEntropy > 0 && shannonBits(value) < ruleEntropy) return true;
  return false;
}

/**
 * Redact every detected secret in `input` with a typed placeholder `[REDACTED:<rule-id>]`. The
 * delivered text never contains a detected secret value (SI-001). Returns the redacted text + the
 * rules that fired. Returns the input unchanged if the rules were never compiled.
 */
export function redactSecrets(input: string): SecretScanResult {
  if (!RULES) return { text: input, findings: [] };
  let text = input;
  const findings: SecretFinding[] = [];
  const lowerContent = input.toLowerCase();

  for (const rule of RULES) {
    // Keyword pre-filter: skip a rule unless one of its keywords appears (gitleaks' fast path).
    if (rule.keywords.length > 0 && !rule.keywords.some((k) => lowerContent.includes(k))) continue;

    // Collect every real-secret value this rule matches (scanning the whole text without a global
    // flag, by advancing past each match).
    const secrets = new Set<string>();
    let offset = 0;
    let guard = 0;
    while (offset < text.length && guard++ < 1000) {
      const m = rule.re.exec(text.slice(offset));
      if (!m || m.index === undefined) break;
      const value = (m[1] ?? m[0]) || "";
      if (value && !isFalsePositive(value, rule.entropy)) secrets.add(value);
      offset += m.index + Math.max(1, m[0].length);
    }
    for (const value of secrets) {
      text = text.split(value).join(`[REDACTED:${rule.id}]`);
      findings.push({ ruleId: rule.id });
    }
  }

  return { text, findings };
}
