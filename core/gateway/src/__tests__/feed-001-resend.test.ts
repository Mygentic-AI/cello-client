/**
 * M9-FEED-001 inc 4 — the stateless governance_decisions re-send (§6 / SI-002).
 *
 * The security core: an agent CANNOT autonomously authorize sending flagged PII. Its only autonomous
 * lever is `redact`; `allow_once` / `allow_always` are honored ONLY when the gateway's autonomous_override
 * is ON (a human/operator decision, INV-4). A decision applies ONLY to the exact value its flagId was
 * derived from — a stale/changed flagId can never mis-apply an allow to different content (SI-002).
 */
import { describe, it, expect } from "vitest";
import { OutboundScreener, verdictText } from "../screen/outbound.js";

const enc = (s: string) => new TextEncoder().encode(s);
const ctx = (extra: object = {}) => ({ agentName: "alice", sessionId: "s1", ...extra });

/** Screen once with no decisions to obtain the deterministic flagId for the warned value. */
function flagIdFor(screener: OutboundScreener, content: string, category = "pii:email"): string {
  const v = screener.screen(enc(content), ctx());
  const f = v.events.find((e) => e.disposition === "warn" && e.category === category);
  if (!f?.flagId) throw new Error("no warn flag produced");
  return f.flagId;
}

describe("M9-FEED-001 inc 4 — governance re-send", () => {
  it("FIRST call (no decisions): non-whitelisted PII → warn, NOT sent, flag carries a flagId", () => {
    const s = new OutboundScreener();
    const v = s.screen(enc("reach me at stranger@other.example"), ctx());
    expect(v.disposition).toBe("warn");
    const warn = v.events.find((e) => e.disposition === "warn");
    expect(warn?.category).toBe("pii:email");
    expect(typeof warn?.flagId).toBe("string");
    expect(verdictText(v)).toContain("stranger@other.example"); // not sent → original returned, unredacted
  });

  it("re-send {flagId: redact}: the value is redacted with a typed placeholder and the message sends", () => {
    const s = new OutboundScreener();
    const content = "reach me at stranger@other.example";
    const id = flagIdFor(s, content);
    const v = s.screen(enc(content), ctx({ governanceDecisions: { [id]: "redact" } }));
    expect(v.disposition).toBe("redact");
    expect(verdictText(v)).toContain("[REDACTED:pii:email]");
    expect(verdictText(v)).not.toContain("stranger@other.example");
  });

  it("re-send with the flag OMITTED → defaults to redact (sends redacted), never silently allowed", () => {
    const s = new OutboundScreener();
    const content = "reach me at stranger@other.example";
    // a decisions map that does NOT mention this flag (an unrelated id) → the real flag defaults to redact
    const v = s.screen(enc(content), ctx({ governanceDecisions: { deadbeef0000: "allow_once" } }));
    expect(v.disposition).toBe("redact");
    expect(verdictText(v)).not.toContain("stranger@other.example");
  });

  it("SI-002: allow_once is REJECTED when autonomous_override is OFF (default) → re-warn, value NOT sent", () => {
    const s = new OutboundScreener(); // override OFF
    const content = "reach me at stranger@other.example";
    const id = flagIdFor(s, content);
    const v = s.screen(enc(content), ctx({ governanceDecisions: { [id]: "allow_once" } }));
    expect(v.disposition).toBe("warn"); // re-warned, NOT sent
    expect(v.guidance).toMatch(/autonomous_override is OFF/i);
    expect(verdictText(v)).toContain("stranger@other.example"); // original returned (unsent), not redacted
  });

  it("allow_always is REJECTED when override is OFF → re-warn", () => {
    const s = new OutboundScreener();
    const content = "reach me at stranger@other.example";
    const id = flagIdFor(s, content);
    const v = s.screen(enc(content), ctx({ governanceDecisions: { [id]: "allow_always" } }));
    expect(v.disposition).toBe("warn");
  });

  it("allow_once with override ON → the value is sent VERBATIM (the human-enabled lever)", () => {
    const s = new OutboundScreener({ autonomousOverride: true });
    const content = "reach me at stranger@other.example";
    const id = flagIdFor(new OutboundScreener(), content); // flagId is value-derived, override-independent
    const v = s.screen(enc(content), ctx({ governanceDecisions: { [id]: "allow_once" } }));
    expect(v.disposition).toBe("allow");
    expect(verdictText(v)).toContain("stranger@other.example"); // sent as the agent decided
  });

  it("allow_always with override ON → value sent + a whitelist-add request is raised (persistence is the human's)", () => {
    const s = new OutboundScreener({ autonomousOverride: true });
    const content = "reach me at stranger@other.example";
    const id = flagIdFor(new OutboundScreener(), content);
    const v = s.screen(enc(content), ctx({ governanceDecisions: { [id]: "allow_always" } }));
    expect(verdictText(v)).toContain("stranger@other.example");
    expect(v.events.some((e) => e.category === "pii:whitelist_add_requested")).toBe(true);
  });

  it("SI-002 stateless: an allow decision keyed to a DIFFERENT value cannot leak the actual value", () => {
    const s = new OutboundScreener({ autonomousOverride: true });
    // flagId computed for victim@a.example, but the content actually contains attacker@b.example.
    const staleId = flagIdFor(new OutboundScreener(), "mail victim@a.example");
    const v = s.screen(enc("mail attacker@b.example"), ctx({ governanceDecisions: { [staleId]: "allow_once" } }));
    // the stale id doesn't match the real flag → the real flag defaults to redact → value NOT sent.
    expect(v.disposition).toBe("redact");
    expect(verdictText(v)).not.toContain("attacker@b.example");
  });

  it("mixed: one allow_once (override ON) + one omitted → allowed value present, omitted value redacted", () => {
    const s = new OutboundScreener({ autonomousOverride: true });
    const content = "emails one@x.example and two@y.example";
    const id1 = flagIdFor(new OutboundScreener(), content); // first warn flag (one@x.example)
    const v = s.screen(enc(content), ctx({ governanceDecisions: { [id1]: "allow_once" } }));
    const text = verdictText(v);
    expect(text).toContain("one@x.example"); // allowed
    expect(text).not.toContain("two@y.example"); // omitted → redacted
    expect(text).toContain("[REDACTED:pii:email]");
  });
});
