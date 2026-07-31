/**
 * M9-IN-001 Step-9 — deterministic injection-pattern matching (attack-corpus §1.6).
 *
 * Runs the known role-marker / override / jailbreak / boundary patterns against the DECODED form of
 * an inbound message (decode-then-rescan), via the RE2 engine so a crafted message can never cause
 * catastrophic backtracking (AC-002). These are HIGH-SIGNAL but deterministic, so Step-9 reports the
 * matches as a signal in the inbound security context (the agent + the Layer-2 semantic scanner /
 * the operator's policy decide what to do) — it is not, by itself, an auto-block. CELLO is not a
 * moderation tool; this surfaces evidence, it does not police content.
 *
 * Patterns are RE2 syntax (no backreferences / lookaround — RE2 has none, and they are what make
 * backtracking possible). Compile once at gateway startup, after initLinearRegex().
 */
import { LinearRegex } from "./linear-regex.js";

interface CompiledPattern { id: string; re: LinearRegex }

let compiled: CompiledPattern[] | null = null;

const PATTERN_SOURCES: Array<{ id: string; src: string }> = [
  // Role-hijacking / chat-template markers (the delimiter tokens from instruction-tuned training).
  { id: "role_marker", src: "\\[/?(?:system|inst|sys)\\]|<\\|im_(?:start|end)\\|>|<\\|(?:system|user|assistant)\\|>|<</?sys>>|\\bsystem prompt:" },
  // Override commands.
  { id: "override", src: "(?:ignore|disregard|forget)\\s+(?:all\\s+|your\\s+|the\\s+|any\\s+|previously\\s+)*(?:previous|prior|above|earlier|the)\\s+(?:instructions|prompts?|context|messages?|rules?|directions?)" },
  { id: "override_explicit", src: "forget everything (?:above|before)|your new instructions are|new[_ ]paradigm" },
  // Persona replacement / mode unlocks.
  { id: "persona", src: "\\byou are now\\b|\\bdeveloper mode\\b|\\bdo anything now\\b|\\bDAN mode\\b" },
  // Jailbreak structural markers (L1B3RT4S).
  { id: "jailbreak", src: "jailbreak\\s*[:>]|<jailbreak>|\\[liberated\\]|<new_paradigm>" },
  // Fake turn-boundary injection.
  { id: "boundary", src: "-{3,}\\s*end of (?:user|system) (?:message|prompt)|={3,}\\s*end system prompt" },
  // Leetspeak variants (1337.mkd).
  { id: "leetspeak", src: "1gn0r3\\s+pr3v10u5|\\bsy5t3m\\s*:" },
];

/** Compile the pattern set. Call once at gateway startup, after `initLinearRegex()` resolves. */
export function compileInjectionPatterns(): void {
  compiled = PATTERN_SOURCES.map(({ id, src }) => ({ id, re: new LinearRegex(src, "i") }));
}

/**
 * The ids of the patterns that ACTUALLY COMPILED, in corpus order — the input to the intake
 * scanner's derived `scanner_version` (`M10B-D15`).
 *
 * The ACTIVE set, not the source list, and the difference is the point: if two deployments compile
 * different subsets (a different RE2 build, a rule that fails to compile), their digests diverge —
 * which is what makes "byte-identical across nodes" mechanically checkable rather than aspirational.
 * Returns null when nothing is compiled, so a caller that must fail closed can tell "no rules" from
 * "not ready".
 */
export function injectionPatternIds(): string[] | null {
  return compiled === null ? null : compiled.map((c) => c.id);
}

/** Whether the patterns are compiled (the RE2 engine was initialized). */
export function injectionPatternsReady(): boolean {
  return compiled !== null;
}

/**
 * The ids of the injection patterns that match `text`. Empty when nothing matches OR when the engine
 * was never initialized (Step-9 is then skipped — the deterministic Layer-1 steps still ran).
 */
export function scanInjectionPatterns(text: string): string[] {
  if (!compiled) return [];
  const hits: string[] = [];
  for (const { id, re } of compiled) {
    if (re.test(text)) hits.push(id);
  }
  return hits;
}
