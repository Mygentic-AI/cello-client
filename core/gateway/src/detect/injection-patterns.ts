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
  // Up to three filler words between the verb and "previous" ("ignore all of your previous…"), and
  // the space-free form a joined-words disguise leaves ("ignoreallpreviousinstructions").
  // DOD-M9C-SCREENBASE-1 widened the verbs and the nouns: "disregard all previous guidelines",
  // "bypass your safety restrictions", "override your programming" were flagged by none of these.
  { id: "override", src: "(?:ignore|disregard|forget|bypass|override|skip|abandon|set aside)\\s+(?:\\w+\\s+){0,3}(?:previous|prior|above|earlier|the|your|all|any|safety|content|ethical)\\s+(?:\\w+\\s+)?(?:instructions|prompts?|context|messages?|rules?|directions?|guidelines|polic(?:y|ies)|constraints|restrictions|programming|directives|safeguards|filters|limitations)|(?:ignore|disregard|forget)(?:all|your|the|any)*(?:previous|prior|above|earlier)(?:instructions|prompts?|rules?|directions?|guidelines)" },
  { id: "override_explicit", src: "forget everything (?:above|before|you know)|your new instructions are|new[_ ]paradigm|from now on,?\\s+you (?:are|will|must|shall)\\b|you (?:are|will) no longer (?:bound|restricted|limited)|you are no longer an? (?:ai|assistant|language model)" },
  // Persona replacement / mode unlocks.
  { id: "persona", src: "\\byou are now\\b|\\bdeveloper mode\\b|\\bdo anything now\\b|\\bDAN mode\\b|\\bpretend (?:you are|that you are) (?:an? )?(?:ai|assistant|model|chatbot) (?:with(?:out)?|that has no)\\b|\\bstay in character\\b|\\b(?:unfiltered|uncensored|unrestricted|jailbroken) (?:mode|ai|assistant|version|response)|\\bwithout any (?:restrictions|filters|limitations|censorship)\\b|\\bno (?:ethical|moral) (?:guidelines|restrictions|constraints)\\b" },
  // Jailbreak structural markers (L1B3RT4S) and template placeholders left in pasted jailbreaks.
  { id: "jailbreak", src: "jailbreak\\s*[:>]|<jailbreak>|\\[liberated\\]|<new_paradigm>|\\[insert prompt here\\]|\\bjailbroken\\b" },
  // Attempts to read the agent's own instructions out.
  { id: "prompt_extraction", src: "(?:reveal|show|print|repeat|output|display|tell me|give me|share|leak)\\s+(?:\\w+\\s+){0,3}(?:system prompt|initial (?:instructions|prompt)|hidden (?:instructions|prompt)|(?:your|the) (?:instructions|prompt|rules) (?:above|verbatim|word for word))|what (?:is|are|were) your (?:system prompt|initial instructions|original instructions)" },
  // Demands for secrets, often with a threat attached.
  { id: "secret_request", src: "(?:provide|give|share|send|tell|reveal)\\s+(?:me\\s+)?(?:\\w+\\s+){0,2}(?:confidential|sensitive|private|secret|classified|internal) (?:information|data|details|records|files)|(?:share|reveal|give me|send me|tell me) (?:your|the) (?:password|passwords|api keys?|credentials|secret keys?|private keys?|access tokens?)" },
  { id: "coercion", src: "\\bor (?:else )?i will (?:expose|leak|report|publish|delete|destroy|shut)|\\bor face (?:severe |serious )?consequences\\b" },
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
