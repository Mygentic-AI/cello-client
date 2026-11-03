/**
 * The email and phone checks are OFF by default and an operator turns them on.
 *
 * Owner decision, 2026-11-03. People sending an email address usually mean to, and the phone pattern
 * reads ordinary coding text as phone numbers: `0.0.260 0.0.133` and `100 200 300 400` both held a
 * message until someone answered. Both are now switches, following `language_enforce`: on is
 * tightening and free, off is loosening and needs a person at the terminal.
 *
 * What these pin: each switch controls only its own category, the other checks stay on, and turning a
 * check back off is gated exactly like every other loosening. That the running gateway defaults to
 * off is proven against a real gateway process in the daemon's m9-core-001-seam test.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { OutboundPIIScreener } from "../detect/pii.js";
import { OutboundScreener } from "../screen/outbound.js";
import { GatewayConfigStore } from "../config/config-store.js";

const enc = (t: string) => new TextEncoder().encode(t);
const cats = (s: OutboundPIIScreener, t: string) => s.screen(enc(t), `s-${Math.random()}`).events.map((e) => e.category);

const EMAIL = "write to someone@example.org";
const PHONE = "call 415-555-2671";

describe("each check has its own switch", () => {
  it("with both off, neither an email nor a phone number is flagged", () => {
    const s = new OutboundPIIScreener({ whitelist: [], checkEmail: false, checkPhone: false });
    expect(cats(s, `${EMAIL}, ${PHONE}`)).toEqual([]);
  });

  it("turning on email flags emails and leaves phone numbers alone", () => {
    const s = new OutboundPIIScreener({ whitelist: [], checkEmail: true, checkPhone: false });
    expect(cats(s, `${EMAIL}, ${PHONE}`)).toEqual(["pii:email"]);
  });

  it("turning on phone flags phone numbers and leaves emails alone", () => {
    const s = new OutboundPIIScreener({ whitelist: [], checkEmail: false, checkPhone: true });
    expect(cats(s, `${EMAIL}, ${PHONE}`)).toEqual(["pii:phone"]);
  });

  it("the other checks stay on with both off: SSN, card and IP are still flagged", () => {
    const s = new OutboundPIIScreener({ whitelist: [], checkEmail: false, checkPhone: false });
    expect(cats(s, "ssn 123-45-6789")).toContain("pii:ssn");
    expect(cats(s, "card 4111 1111 1111 1111")).toContain("pii:credit_card");
    expect(cats(s, "host 8.8.8.8")).toContain("pii:ip");
  });

  it("coding text that held a message before now goes through", () => {
    const s = new OutboundPIIScreener({ whitelist: [], checkEmail: false, checkPhone: false });
    for (const t of ["versions 0.0.260 0.0.133", "sizes 100 200 300 400", "timestamp 1793636189240", "Co-Authored-By: Claude <noreply@anthropic.com>"]) {
      expect(cats(s, t)).toEqual([]);
    }
  });

  it("the class alone checks everything: only the running gateway's settings turn a check off", () => {
    const s = new OutboundPIIScreener({ whitelist: [] });
    expect(cats(s, `${EMAIL}, ${PHONE}`).sort()).toEqual(["pii:email", "pii:phone"]);
  });

  it("the outbound screener passes the switches through", () => {
    const off = new OutboundScreener({ piiCheckEmail: false, piiCheckPhone: false });
    const on = new OutboundScreener({ piiCheckEmail: true, piiCheckPhone: true });
    const ctx = { agentName: "a", sessionId: "s" };
    expect(off.screen(enc(`${EMAIL}, ${PHONE}`), ctx).disposition).toBe("allow");
    expect(on.screen(enc(`${EMAIL}, ${PHONE}`), ctx).disposition).toBe("warn");
  });
});

describe("the switches follow the terminal rule", () => {
  let dir: string;
  let store: GatewayConfigStore;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "cello-pii-switch-"));
    const key = join(dir, "store.key");
    await writeFile(key, randomBytes(32), { mode: 0o600 });
    store = new GatewayConfigStore(join(dir, "config.db"), key);
  });
  afterEach(async () => {
    store.close();
    await rm(dir, { recursive: true, force: true });
  });

  for (const key of ["pii_check_email", "pii_check_phone"]) {
    it(`${key}: turning it on is free`, () => {
      const r = store.set(key, true);
      expect(r.ok).toBe(true);
    });

    it(`${key}: turning it off afterwards needs confirmation, and nothing changes without it`, () => {
      store.set(key, true);
      const refused = store.set(key, false);
      expect(refused.ok).toBe(false);
      expect(!refused.ok && refused.direction).toBe("loosen");
      expect(store.get(key)).toBe(true);
      expect(store.set(key, false, { confirmed: true }).ok).toBe(true);
      expect(store.get(key)).toBe(false);
    });

    it(`${key}: a value that is not true or false is refused, not stored`, () => {
      expect(() => store.set(key, "off")).toThrow(/invalid value/);
      expect(store.get(key)).toBeUndefined();
    });
  }
});
