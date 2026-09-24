/**
 * M16 031-KEYSASKEYS — a 64-hex token the daemon KNOWS is a public key passes every outbound stage
 * untouched; anything else is screened exactly as today.
 *
 * The live defect (2026-09-24): sending a channel key `channel key: <64-hex>` came back
 * `[REDACTED:generic-api-key]` (the secrets stage), and the chunked form was held as `pii:phone`
 * (the PII stage matched digit runs inside the hex). An agent could not send a public key at all.
 *
 * These tests use the REAL `OutboundScreener` (not a stub), so the protect → screen → restore step
 * is exercised against the same detectors production runs.
 */
import { describe, it, expect, beforeAll } from "vitest";
import { initLinearRegex } from "../detect/linear-regex.js";
import { compileSecretRules } from "../detect/secrets.js";
import { compileInjectionPatterns } from "../detect/injection-patterns.js";
import { OutboundScreener, protectKnownKeys } from "../screen/outbound.js";

// A realistic public key (the CLAUDE.md demo pubkey): 64 lowercase hex.
const K = "ce0fa3d0642cc07e0dd614ae919e3d8b1864bbaae4bdf4494dc9430f72501cfc";
// A different random 64-hex value the daemon does NOT know — must still be redacted.
const U = "7f3a9c2e18b4d6a05e9271c3f8b0a6d4e2c1957038af6b4d92e0c1a7538bd964";
// A 64-hex value whose 16-char chunks read as long digit runs, so the CHUNKED form warns pii:phone
// (each chunk begins with a letter, so it is not a credit-card span, and 15 digits satisfy PHONE_RE).
const K2 = "a234567812345678".repeat(4);

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
const dec = (b: Uint8Array): string => new TextDecoder().decode(b);

describe("M16 031 — known public keys pass outbound governance unchanged", () => {
  beforeAll(async () => {
    await initLinearRegex();
    compileSecretRules();
    compileInjectionPatterns();
  });

  it("test 1: a known key passes untouched — allow, byte-equal to the input, no secret/pii events", () => {
    const screener = new OutboundScreener();
    const text = `channel key: ${K}`;
    const v = screener.screen(enc(text), { agentName: "a", sessionId: "s", knownPublicKeys: [K] });
    expect(v.disposition).toBe("allow");
    expect(dec(v.content)).toBe(text);
    expect(v.events.some((e) => e.category.startsWith("secret:") || e.category.startsWith("pii:"))).toBe(false);
  });

  it("test 2: chunks of a known key are NOT protected — the chunked form still warns pii:phone", () => {
    const screener = new OutboundScreener();
    const chunked = (K2.match(/.{1,16}/g) as string[]).join(" ");
    const v = screener.screen(enc(`channel key: ${chunked}`), {
      agentName: "a",
      sessionId: "s",
      knownPublicKeys: [K2],
    });
    // Only whole-token matches are protected; the split digits still trip the phone check.
    expect(v.events.some((e) => e.category === "pii:phone")).toBe(true);
  });

  it("test 3: an unknown 64-hex value is still redacted as generic-api-key", () => {
    const screener = new OutboundScreener();
    const v = screener.screen(enc(`channel key: ${U}`), { agentName: "a", sessionId: "s", knownPublicKeys: [K] });
    expect(v.disposition).toBe("redact");
    expect(v.events.some((e) => e.category === "secret:generic-api-key")).toBe(true);
    expect(dec(v.content)).not.toContain(U);
  });

  it("test 4: mixed — known K stays intact, unknown U is redacted", () => {
    const screener = new OutboundScreener();
    const text = `known key: ${K}; unknown key: ${U}`;
    const v = screener.screen(enc(text), { agentName: "a", sessionId: "s", knownPublicKeys: [K] });
    expect(dec(v.content)).toContain(K); // the known key survives every stage
    expect(dec(v.content)).not.toContain(U); // the unknown key is redacted
    expect(v.events.some((e) => e.category === "secret:generic-api-key")).toBe(true);
  });

  it("test 5: protectKnownKeys round-trips, and refuses when a placeholder string is already present", () => {
    const p = protectKnownKeys(`key ${K}`, [K]);
    expect(p.text).not.toContain(K); // the key is replaced by a letters-only placeholder
    expect(p.restore(p.text)).toBe(`key ${K}`); // and restored exactly

    // If a placeholder string already occurs in the text, protect NOTHING (screen it as today).
    const already = `CELLOPUBKEYA and ${K}`;
    const refused = protectKnownKeys(already, [K]);
    expect(refused.text).toBe(already);
    expect(refused.restore(refused.text)).toBe(already);
  });
});
