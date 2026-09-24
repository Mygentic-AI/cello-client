/**
 * The outbound screen composition.
 *
 * Chains the built outbound detectors into one verdict, per the §6 governance model: each stage
 * publishes events with a disposition (observe / redact / block / warn); the driver decides control
 * flow by the strongest disposition (block > warn > redact > allow) and applies redactions to the
 * content. A block short-circuits (the message never leaves). This is the gateway-side outbound
 * screen the spawned gateway runs; the daemon-side cello_send rendering of this verdict (the
 * four-outcome return + the stateless governance re-send) is M9-FEED-001.
 *
 * Secret detection (M9-OUT-001) is decision-coupled (RE2 / gitleaks) and slots in here as another
 * `redact` stage once its binding is chosen.
 */
import { OutboundRateLimiter, type RateLimitConfig } from "../detect/rate-limit.js";
import { AFFORDANCE_PREFIX } from "./affordance.js";
import { OutboundPIIScreener, type PIIEvent } from "../detect/pii.js";
import { screenOutboundExfil } from "../detect/exfil.js";
import { redactSecrets } from "../detect/secrets.js";
import type { GovernanceEvent, GovernanceDecision } from "../types.js";

export type { GovernanceEvent };

export interface OutboundVerdict {
  /** The control-flow disposition for cello_send (M9-FEED-001 renders it to the agent). */
  disposition: "allow" | "redact" | "block" | "warn";
  /** The (possibly redacted) content to act on. For block, the original is returned (not sent). */
  content: Uint8Array;
  events: GovernanceEvent[];
  /** A distinct top-level reason for a block (e.g. `rate_limited`), surfaced to the agent (L1). */
  reason?: string;
  /** Actionable guidance for a block/warn outcome. */
  guidance?: string;
  /**
   * M16 031: how many KNOWN public keys were protected through the stages (0 when none). The bin
   * logs the count (never the values) as `security.screen.outbound.known_keys`.
   */
  knownKeysProtected?: number;
}

export interface OutboundScreenerOptions {
  /** PII values the operator has whitelisted (own contact details). */
  piiWhitelist?: string[];
  /** Per-agent outbound rate limit. Omit to disable rate limiting. */
  rateLimit?: RateLimitConfig;
  piiBulkThreshold?: number;
  piiCumulativeThreshold?: number;
  /** Injectable clock (for the rate limiter) — tests pass a controllable one. */
  now?: () => number;
  /**
   * Whether the agent may autonomously override a PII warn with `allow_once` / `allow_always` (INV-4
   * gateway config). DEFAULT FALSE: the agent's only autonomous lever is `redact`; allowing a value
   * out is a human action (whitelist). M9-CFG-001 will source this from the gateway config DB.
   */
  autonomousOverride?: boolean;
}

export interface OutboundScreenContext {
  agentName: string;
  sessionId: string;
  /** The agent's decisions on a governance re-send, keyed by flagId (M9-FEED-001 §6). */
  governanceDecisions?: Record<string, GovernanceDecision>;
  /**
   * M16 031: the KNOWN public keys (lowercase 64-hex) the daemon recognised in this message — its
   * own agents' and channels' keys, the sender's contacts, the channels it follows, and the
   * session's counterparty. The daemon fills this (only it knows them); NEVER any private key
   * material. Outbound only. Each occurrence is replaced with a letters-only placeholder before the
   * stages run and restored afterwards, so a public key passes secrets/exfil/PII untouched while
   * every other 64-hex token is screened exactly as today.
   */
  knownPublicKeys?: string[];
}

const TEXT_DECODER = new TextDecoder("utf-8", { fatal: false });
const TEXT_ENCODER = new TextEncoder();

/**
 * The placeholder prefix a protected key is swapped for. LETTERS ONLY, no digits — a digit run
 * would itself trip the phone check (the very defect this unit fixes). The suffix is a base-26
 * letter sequence (A, B, … Z, AA, …), so `CELLOPUBKEYA`, `CELLOPUBKEYB`, …
 */
const PLACEHOLDER_PREFIX = "CELLOPUBKEY";

/** Turn a 0-based index into a letters-only suffix: 0→A, 25→Z, 26→AA, … */
function indexToLetters(i: number): string {
  let n = i;
  let out = "";
  do {
    out = String.fromCharCode(65 + (n % 26)) + out;
    n = Math.floor(n / 26) - 1;
  } while (n >= 0);
  return out;
}

/**
 * Replace each KNOWN public key that appears in `text` with a letters-only placeholder, returning a
 * `restore` that puts the exact keys back. Pure and unit-tested (M16 031 test 5).
 *
 * Only keys that actually occur are protected. If a placeholder string we would assign is ALREADY
 * present in the text, we protect NOTHING (restore would otherwise corrupt that pre-existing text) —
 * the message is then screened exactly as today.
 */
export function protectKnownKeys(
  text: string,
  keys: string[],
): { text: string; restore: (t: string) => string; count: number } {
  const identity = { text, restore: (t: string): string => t, count: 0 };
  const present = [...new Set(keys)].filter((k) => k.length > 0 && text.includes(k));
  if (present.length === 0) return identity;

  const mapping = present.map((key, i) => ({ key, placeholder: PLACEHOLDER_PREFIX + indexToLetters(i) }));
  // Refuse if any placeholder already occurs — restoring it would rewrite text we did not protect.
  if (mapping.some((m) => text.includes(m.placeholder))) return identity;

  let protectedText = text;
  for (const m of mapping) protectedText = protectedText.split(m.key).join(m.placeholder);
  // Restore longest placeholder first, so a shorter placeholder is never matched inside a longer one.
  const ordered = [...mapping].sort((a, b) => b.placeholder.length - a.placeholder.length);
  const restore = (t: string): string => {
    let out = t;
    for (const m of ordered) out = out.split(m.placeholder).join(m.key);
    return out;
  };
  return { text: protectedText, restore, count: mapping.length };
}

export class OutboundScreener {
  readonly #rateLimiter?: OutboundRateLimiter;
  readonly #pii: OutboundPIIScreener;
  readonly #autonomousOverride: boolean;

  constructor(opts: OutboundScreenerOptions = {}) {
    if (opts.rateLimit) this.#rateLimiter = new OutboundRateLimiter(opts.rateLimit, opts.now);
    this.#autonomousOverride = opts.autonomousOverride ?? false;
    this.#pii = new OutboundPIIScreener({
      whitelist: opts.piiWhitelist ?? [],
      ...(opts.piiBulkThreshold !== undefined ? { bulkThreshold: opts.piiBulkThreshold } : {}),
      ...(opts.piiCumulativeThreshold !== undefined ? { cumulativeThreshold: opts.piiCumulativeThreshold } : {}),
    });
  }

  screen(content: Uint8Array, ctx: OutboundScreenContext): OutboundVerdict {
    // 1. Rate limit — a READ-ONLY gate (M2): a throttle short-circuits; a passing peek does NOT
    //    consume a slot. We commit one only if the message actually goes out (allow/redact), below.
    if (this.#rateLimiter) {
      const rl = this.#rateLimiter.peek(ctx.agentName);
      if (rl.limited) {
        return {
          disposition: "block",
          content,
          reason: rl.reason ?? "rate_limited", // distinct top-level reason (L1)
          guidance: rl.guidance,
          events: [{ stage: "rate_limit", disposition: "block", category: "rate_limit", reason: rl.guidance ?? "rate limit reached" }],
        };
      }
    }

    const events: GovernanceEvent[] = [];

    // M16 031: protect KNOWN public keys BEFORE any stage. Each key the daemon recognised is swapped
    // for a letters-only placeholder here and restored on the returned content, so a public key passes
    // secrets/exfil/PII untouched while every other 64-hex token is screened exactly as today. If a
    // placeholder string already occurs in the text, protectKnownKeys refuses and nothing is protected.
    const protection = protectKnownKeys(TEXT_DECODER.decode(content), ctx.knownPublicKeys ?? []);

    // 2. Secrets (M9-OUT-001) — redact-by-default, and FIRST: a known credential gets its TYPED
    //    placeholder ([REDACTED:<rule>]) before exfil's generic high-entropy redactor would mask it
    //    as an opaque blob, so the agent is told WHAT leaked.
    let workingText = protection.text;
    const sec = redactSecrets(workingText);
    workingText = sec.text;
    for (const f of sec.findings) {
      events.push({ stage: "secrets", disposition: "redact", category: `secret:${f.ruleId}`, reason: "a credential was redacted before send" });
    }

    // 3. Exfiltration — on the secrets-redacted text. An injection artifact in output is a hard block.
    const ex = screenOutboundExfil(TEXT_ENCODER.encode(workingText));
    if (ex.disposition === "block") {
      // No distinct top-level reason → the daemon uses the §6 standard `blocked_by_governance`; the
      // specific cause (injection artifact) rides in blocks[].category. (Only rate-limit overrides the
      // top-level reason, per OUT-004.) The guidance carries the human-readable cause.
      return {
        disposition: "block",
        content,
        guidance: ex.events[0]?.reason,
        events: ex.events.map((e) => ({ stage: "exfil", disposition: "block" as const, category: e.category, reason: e.reason })),
        ...(protection.count > 0 ? { knownKeysProtected: protection.count } : {}),
      };
    }
    for (const e of ex.events) {
      events.push({ stage: "exfil", disposition: "redact", category: e.category, reason: e.reason });
    }
    workingText = ex.text;

    // 4. PII — non-whitelisted values warn (need a governance decision before send). On a RE-SEND
    //    (ctx.governanceDecisions present) the warn is RESOLVED here per the agent's per-flag decision,
    //    gated by autonomous_override (M9-FEED-001 §6 / SI-002). Stateless: flagIds are re-derived from
    //    the re-scanned content, so a decision only applies to the exact value it was computed for.
    //    Scan the WORKED text (after secrets/exfil), not the original (code-review LOW): so the flagId
    //    basis matches the redaction target, and a value already redacted by secrets/exfil does not also
    //    raise a PII warn whose redaction would be a no-op.
    const pii = this.#pii.screen(TEXT_ENCODER.encode(workingText), ctx.sessionId);
    let piiTransformed = false;
    if (pii.events.length > 0) {
      const resolved = this.#resolvePII(pii.events, ctx.governanceDecisions);
      if (resolved.reWarn) {
        // FIRST call (no decisions) OR a decision the gateway REFUSES (allow_* with override off):
        // terminal NOT-SENT, the agent re-sends with a decision (or the operator whitelists). No rate
        // slot is consumed (the message did not go out). The returned content still reflects the
        // ALWAYS-applied secrets/exfil redactions (deterministic, decision-free) — only the PII values
        // stay intact, since they are exactly what is awaiting a decision.
        const warnTransformed = sec.findings.length > 0 || ex.events.length > 0;
        return {
          // Restore the protected keys before the content is rendered to the agent (placeholders
          // must never surface). When nothing was transformed we return the original bytes, which
          // already carry the real keys.
          disposition: "warn",
          content: warnTransformed ? TEXT_ENCODER.encode(protection.restore(workingText)) : content,
          events: [...events, ...resolved.warnEvents],
          ...(resolved.guidance ? { guidance: resolved.guidance } : {}),
          ...(protection.count > 0 ? { knownKeysProtected: protection.count } : {}),
        };
      }
      // All PII items resolved to redact/allowed → apply redactions to the worked text and send.
      for (const r of resolved.redact) {
        workingText = workingText.split(r.value).join(`[REDACTED:${r.category}]`);
        events.push({ stage: "pii", disposition: "redact", category: r.category, reason: `personal data (${r.category}) redacted per governance decision`, flagId: r.flagId });
        piiTransformed = true;
      }
      for (const w of resolved.whitelistAddRequested) {
        // allow_always under autonomous override: the value flows NOW (allow_once), but PERSISTING it
        // to the whitelist is a human action — raise the request to the operator (ops-agent). The
        // persistence itself is M9-CFG-001 / the ops-agent; here it is surfaced as an observe event.
        events.push({ stage: "pii", disposition: "observe", category: "pii:whitelist_add_requested", reason: `operator confirmation required to persist ${w.category} to the whitelist (allow_always)`, flagId: w.flagId });
      }
      // resolved.allowOnce values are left verbatim in workingText (the agent's explicit decision).
    }

    // Secrets + exfil + per-decision PII redactions are the content transforms; deliver the worked text
    // iff anything changed (block sources already short-circuited, so only redact / allow remain here).
    // The protected keys are restored on the worked text — a known public key that survived the stages
    // as a placeholder goes back to its real value, so the agent's send is byte-identical for that key.
    const transformed = sec.findings.length > 0 || ex.events.length > 0 || piiTransformed;
    const outContent = transformed ? TEXT_ENCODER.encode(protection.restore(workingText)) : content;
    const disposition = events.some((e) => e.disposition === "redact") ? "redact" : "allow";

    // M2: commit a rate slot ONLY when the message will actually reach the wire (allow/redact) —
    // not for a block/warn that is held, and not twice across a warn → governance re-send.
    if (this.#rateLimiter && (disposition === "allow" || disposition === "redact")) {
      this.#rateLimiter.record(ctx.agentName);
    }
    return { disposition, content: outContent, events, ...(protection.count > 0 ? { knownKeysProtected: protection.count } : {}) };
  }

  /**
   * Apply the agent's governance decisions to the PII warn flags (M9-FEED-001 §6 / SI-002).
   * - No decisions at all → re-warn (the FIRST-call NOT-SENT: the agent must decide).
   * - Per flag: `redact` (or OMITTED → default redact) → redact. `allow_once` → allowed iff override
   *   is ON, else REJECTED → re-warn. `allow_always` → allowed-now + whitelist-add-requested iff
   *   override is ON, else REJECTED → re-warn.
   * If ANY flag is rejected, the whole send re-warns (nothing goes out half-decided).
   */
  #resolvePII(
    flags: PIIEvent[],
    decisions: Record<string, GovernanceDecision> | undefined,
  ): {
    reWarn: boolean;
    warnEvents: GovernanceEvent[];
    guidance?: string;
    redact: PIIEvent[];
    allowOnce: PIIEvent[];
    whitelistAddRequested: PIIEvent[];
  } {
    const warnEvent = (e: PIIEvent): GovernanceEvent =>
      ({ stage: "pii", disposition: "warn", category: e.category, reason: `personal data (${e.category})`, flagId: e.flagId });

    // First call: no decision blob at all → the standard warn (NOT SENT), agent re-sends with decisions.
    if (decisions === undefined) {
      return { reWarn: true, warnEvents: flags.map(warnEvent), redact: [], allowOnce: [], whitelistAddRequested: [] };
    }

    const redact: PIIEvent[] = [];
    const allowOnce: PIIEvent[] = [];
    const whitelistAddRequested: PIIEvent[] = [];
    const rejected: PIIEvent[] = [];
    for (const f of flags) {
      const d = decisions[f.flagId] ?? "redact"; // omitted (incl. a stale/changed flagId) → redact
      if (d === "redact") { redact.push(f); continue; }
      // allow_once / allow_always both require the override to be ON to let a value out autonomously.
      if (!this.#autonomousOverride) { rejected.push(f); continue; }
      if (d === "allow_once") allowOnce.push(f);
      else { allowOnce.push(f); whitelistAddRequested.push(f); } // allow_always = allow_once + persist-request
    }

    if (rejected.length > 0) {
      // SI-002: the agent cannot self-authorize sending PII with the override off — re-warn, naming the
      // only autonomous lever (redact) and the human path (the operator whitelists / enables override).
      return {
        reWarn: true,
        warnEvents: rejected.map(warnEvent),
        // TELL THE AGENT WHAT IT CAN DO. The recurring failure this closes: an agent hits a guard,
        // is told what happened, and is never told what is available — so it retries the same thing,
        // or gives up, or invents a workaround. It cannot run the loosening commands itself (that is
        // the point of the gate), but it CAN relay them, and relaying an exact command is the
        // difference between a stuck operator and a two-second fix.
        guidance:
          `${AFFORDANCE_PREFIX} NOT SENT. ${rejected.length} item(s) cannot be allowed ` +
          `autonomously because ` +
          `autonomous_override is OFF.\n` +
          `WHAT YOU CAN DO NOW: re-send with those flag(s) set to "redact" — the value is replaced ` +
          `by a typed placeholder and the message goes.\n` +
          `IF THE FLAG IS WRONG (a date, an id, your own address), relay these to your operator to ` +
          `run in their terminal. DO NOT run them yourself and do not work around the guard:\n` +
          `  cello config list                          # FIRST — 'set' REPLACES the whitelist\n` +
          `  cello config set pii_whitelist <existing,values,plus,new>\n` +
          `  cello config set autonomous_override true  # or: let agents clear their own flags\n` +
          `Either prompts them to confirm once. To see exactly what fired: cello policy log`,
        redact: [], allowOnce: [], whitelistAddRequested: [],
      };
    }
    return { reWarn: false, warnEvents: [], redact, allowOnce, whitelistAddRequested };
  }
}

/** Decode helper exposed for callers rendering a verdict's content. */
export function verdictText(v: OutboundVerdict): string {
  return TEXT_DECODER.decode(v.content);
}
