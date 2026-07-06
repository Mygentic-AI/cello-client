/**
 * M9-OUT-002 — outbound PII: whitelist + warn (NOT blanket redaction). Detect email/phone/SSN/CC/IP,
 * pass whitelisted values silently, warn on the rest; a contact-dump is one escalated bulk warn; a
 * sustained per-session drip escalates. Unit altitude. The warn UX / re-send is M9-FEED-001.
 */
import { describe, it, expect } from "vitest";
import { OutboundPIIScreener } from "../detect/pii.js";

const enc = (s: string) => new TextEncoder().encode(s);

describe("M9-OUT-002 OutboundPIIScreener", () => {
  it("AC-001: a whitelisted value (the operator's own email) passes silently — no warn, no redaction", () => {
    const s = new OutboundPIIScreener({ whitelist: ["alice@acme.example", "+1 555 010 2000"] });
    const r = s.screen(enc("You can reach me at alice@acme.example anytime."), "sess-1");
    expect(r.disposition).toBe("allow");
    expect(r.events).toHaveLength(0);
  });

  it("AC-001: the whitelist is NORMALIZED equality, not substring — a near-miss still warns; a re-cased / re-spaced form still passes", () => {
    const s = new OutboundPIIScreener({ whitelist: ["alice@acme.example", "+1 555 010 2000"] });
    // A different full address that merely CONTAINS the whitelisted email as a substring must warn.
    expect(s.screen(enc("send to alice@acme.example.attacker.com please"), "s").disposition).toBe("warn");
    // The whitelisted email in a different case still passes (email normalization is case-fold).
    expect(s.screen(enc("write ALICE@acme.example"), "s").disposition).toBe("allow");
    // The whitelisted phone sent as bare digits still passes (phone normalization strips non-digits).
    expect(s.screen(enc("call 15550102000 now"), "s").disposition).toBe("allow");
  });

  it("AC-002: a single non-whitelisted email produces a warn naming the value + category (not a pass, not a silent redact)", () => {
    const s = new OutboundPIIScreener({ whitelist: ["alice@acme.example"] });
    const r = s.screen(enc("Forward it to bob@other.example please."), "sess-1");
    expect(r.disposition).toBe("warn");
    expect(r.severity).toBe("normal");
    expect(r.events).toHaveLength(1);
    expect(r.events[0].category).toBe("pii:email");
    expect(r.events[0].value).toBe("bob@other.example");
    expect(r.events[0].flagId).toMatch(/^[0-9a-f]{8,}$/); // a deterministic flag id for the re-send
  });

  it("the flag id is deterministic over (category, value) — the same value yields the same id across screens", () => {
    const s = new OutboundPIIScreener({ whitelist: [] });
    const a = s.screen(enc("ping carol@x.example"), "s1").events[0].flagId;
    const b = s.screen(enc("again carol@x.example"), "s2").events[0].flagId;
    expect(a).toBe(b);
  });

  it("AC-003: a 30-contact dump produces ONE high-severity bulk warn carrying the count, not 30 separate warns", () => {
    const contacts = Array.from({ length: 30 }, (_, i) => `user${i}@corp.example`).join("\n");
    const s = new OutboundPIIScreener({ whitelist: [], bulkThreshold: 5 });
    const r = s.screen(enc("Contact list:\n" + contacts), "sess-bulk");
    expect(r.disposition).toBe("warn");
    expect(r.severity).toBe("bulk");
    expect(r.count).toBe(30);
  });

  it("SI-001: a drip of one new value per message still warns each time, and the per-session cumulative escalates to bulk", () => {
    const s = new OutboundPIIScreener({ whitelist: [], bulkThreshold: 100, cumulativeThreshold: 5 });
    const sev: string[] = [];
    for (let i = 0; i < 7; i++) {
      const r = s.screen(enc(`new contact: drip${i}@leak.example`), "drip-session");
      expect(r.disposition).toBe("warn"); // every single one warns — never silently emitted
      sev.push(r.severity!);
    }
    // Pin the EXACT boundary (off-by-one trap): with cumulativeThreshold 5, the 1st–4th distinct
    // values (indices 0–3) are `normal`; the 5th (index 4) is the first to reach the cumulative cap
    // and flips to `bulk`, and it stays bulk after.
    expect(sev.slice(0, 4)).toEqual(["normal", "normal", "normal", "normal"]);
    expect(sev[4]).toBe("bulk");
    expect(sev[5]).toBe("bulk");
    // A DIFFERENT session is unaffected by this one's cumulative count.
    expect(s.screen(enc("one off: solo@elsewhere.example"), "other-session").severity).toBe("normal");
  });

  it("detects SSN, credit card (Luhn-valid), and IP — and ignores a Luhn-invalid card-shaped number", () => {
    const s = new OutboundPIIScreener({ whitelist: [] });
    const r = s.screen(enc("ssn 123-45-6789 card 4242 4242 4242 4242 ip 203.0.113.42"), "s");
    const cats = new Set(r.events.map((e) => e.category));
    expect(cats.has("pii:ssn")).toBe(true);
    expect(cats.has("pii:credit_card")).toBe(true);
    expect(cats.has("pii:ip")).toBe(true);

    const bad = s.screen(enc("order number 1234 5678 9012 3456 here"), "s2"); // Luhn-invalid
    expect(bad.events.some((e) => e.category === "pii:credit_card")).toBe(false);
  });

  it("a message with no PII passes clean", () => {
    const s = new OutboundPIIScreener({ whitelist: [] });
    const r = s.screen(enc("Thanks, talk soon."), "s");
    expect(r.disposition).toBe("allow");
    expect(r.events).toHaveLength(0);
  });
});
