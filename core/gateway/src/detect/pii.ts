/**
 * M9-OUT-002 — outbound PII: whitelist + warn (NOT blanket redaction).
 *
 * Detects email / phone / SSN / credit-card / IP, passes whitelisted values (the operator's own
 * registered contact details) silently, and warns on the rest — so sharing your own contact is
 * frictionless while a contact-list dump is caught. A bulk dump is ONE escalated warn (severity),
 * and a sustained per-session drip escalates too (SI-001). Pure detection + deterministic flag ids;
 * the warn UX / allow-once / WebAuthn-whitelist-add re-send is M9-FEED-001.
 *
 * All patterns are anchored / negated-class (linear time — no RE2 engine needed). Cross-category
 * overlaps (a phone pattern also matching an SSN/IP/card span) are resolved by priority so each
 * value is counted once, in its most specific category.
 */
import { createHash } from "node:crypto";

export type PIICategory = "pii:email" | "pii:ip" | "pii:ssn" | "pii:credit_card" | "pii:phone";

export interface PIIEvent {
  category: PIICategory;
  value: string;
  /** Deterministic id over (category, value) — the handle the agent passes on a governance re-send. */
  flagId: string;
}

export interface PIIResult {
  disposition: "allow" | "warn";
  severity?: "normal" | "bulk";
  events: PIIEvent[];
  count: number;
}

export interface PIIScreenerOptions {
  /** The operator's whitelisted PII values (own email/phone …). Normalized on construction. */
  whitelist: string[];
  /** Distinct non-whitelisted values in ONE message at/above which the warn is bulk. Default 5. */
  bulkThreshold?: number;
  /** Distinct non-whitelisted values across a SESSION at/above which warns escalate to bulk (drip). Default 20. */
  cumulativeThreshold?: number;
}

interface Candidate { start: number; end: number; category: PIICategory; value: string; priority: number }

const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const SSN_RE = /\b\d{3}-\d{2}-\d{4}\b/g;
const CC_RE = /\b(?:\d[ -]?){13,19}\b/g;
const PHONE_RE = /\+?\d[\d\s().-]{7,}\d/g;

function flagIdFor(category: string, value: string): string {
  return createHash("sha256").update(`${category}:${value}`).digest("hex").slice(0, 12);
}

function luhnValid(digits: string): boolean {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (d < 0 || d > 9) return false;
    if (alt) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
    alt = !alt;
  }
  return digits.length > 0 && sum % 10 === 0;
}

function validIp(value: string): boolean {
  const parts = value.split(".");
  return parts.length === 4 && parts.every((p) => { const n = Number(p); return p.length > 0 && n >= 0 && n <= 255; });
}

function normalizeEmail(v: string): string { return v.toLowerCase(); }
function normalizePhone(v: string): string { return v.replace(/\D/g, ""); }
function normalizeForWhitelist(category: PIICategory, value: string): string {
  if (category === "pii:email") return normalizeEmail(value);
  if (category === "pii:phone") return normalizePhone(value);
  return value;
}

export class OutboundPIIScreener {
  readonly #whitelist: Set<string>;
  readonly #bulkThreshold: number;
  readonly #cumulativeThreshold: number;
  // sessionId → the distinct (category:value) keys of non-whitelisted PII seen across the session.
  readonly #sessionDistinct = new Map<string, Set<string>>();

  constructor(opts: PIIScreenerOptions) {
    // Whitelist is stored normalized two ways (email lowercase, phone digits) so a raw value matches.
    this.#whitelist = new Set([
      ...opts.whitelist.map(normalizeEmail),
      ...opts.whitelist.map(normalizePhone).filter((p) => p.length > 0),
    ]);
    this.#bulkThreshold = opts.bulkThreshold ?? 5;
    this.#cumulativeThreshold = opts.cumulativeThreshold ?? 20;
  }

  screen(content: Uint8Array, sessionId: string): PIIResult {
    const text = new TextDecoder("utf-8", { fatal: false }).decode(content);

    const candidates: Candidate[] = [];
    const collect = (re: RegExp, category: PIICategory, priority: number, accept: (v: string) => boolean) => {
      for (const m of text.matchAll(re)) {
        const value = m[0];
        if (!accept(value)) continue;
        candidates.push({ start: m.index ?? 0, end: (m.index ?? 0) + value.length, category, value, priority });
      }
    };
    collect(EMAIL_RE, "pii:email", 0, () => true);
    collect(IP_RE, "pii:ip", 1, validIp);
    collect(SSN_RE, "pii:ssn", 2, () => true);
    collect(CC_RE, "pii:credit_card", 3, (v) => luhnValid(v.replace(/[^0-9]/g, "")));
    collect(PHONE_RE, "pii:phone", 4, (v) => v.replace(/\D/g, "").length >= 7);

    // Resolve overlaps: a higher-priority (more specific) match wins its character span.
    candidates.sort((a, b) => a.priority - b.priority || a.start - b.start);
    const taken: Array<[number, number]> = [];
    const accepted: Candidate[] = [];
    for (const c of candidates) {
      if (taken.some(([s, e]) => c.start < e && c.end > s)) continue;
      taken.push([c.start, c.end]);
      accepted.push(c);
    }

    // Drop whitelisted values; dedupe identical (category,value) within the message.
    const byKey = new Map<string, PIIEvent>();
    for (const c of accepted) {
      if (this.#whitelist.has(normalizeForWhitelist(c.category, c.value))) continue;
      const key = `${c.category}:${c.value}`;
      if (!byKey.has(key)) byKey.set(key, { category: c.category, value: c.value, flagId: flagIdFor(c.category, c.value) });
    }
    const events = [...byKey.values()];
    if (events.length === 0) return { disposition: "allow", events: [], count: 0 };

    // Per-session cumulative view (SI-001 drip).
    let distinct = this.#sessionDistinct.get(sessionId);
    if (!distinct) { distinct = new Set(); this.#sessionDistinct.set(sessionId, distinct); }
    for (const e of events) distinct.add(`${e.category}:${e.value}`);

    const count = events.length;
    const bulk = count >= this.#bulkThreshold || distinct.size >= this.#cumulativeThreshold;
    return { disposition: "warn", severity: bulk ? "bulk" : "normal", events, count };
  }
}
