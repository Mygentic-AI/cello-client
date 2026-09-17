/**
 * DOD-M9C-SCREENPASSIVE-1 — our own outage is not a finding about the counterparty.
 *
 * With the RE2 patterns uncompiled, `scanInjectionPatterns` returns nothing and the screener says
 * so — correctly, since a screener that quietly stops screening is this milestone's founding defect.
 * But that state was pushed as an `injection:` category, so every message in such a gateway arrived
 * wrapped as "FLAGGED: patterns_unavailable": a warning on every message, blaming the sender for a
 * broken startup here.
 *
 * This file NEVER calls `compileInjectionPatterns` — that absence is the fixture, so it lives alone.
 */
import { describe, it, expect } from "vitest";
import { InboundScreener } from "../screen/inbound.js";

const enc = new TextEncoder();
const dec = new TextDecoder();

describe("SCREENPASSIVE: pattern screening down", () => {
  it("names the outage as ours and does not flag the message", async () => {
    const v = await new InboundScreener().screen(enc.encode("Thanks, see you tomorrow."));
    const delivered = dec.decode(v.content);
    expect(delivered).toContain("Pattern screening did not run");
    expect(delivered).not.toContain("FLAGGED");
    expect(delivered).toContain("Thanks, see you tomorrow.");
  });

  it("still says it in the events, so the log and the agent agree", async () => {
    const v = await new InboundScreener().screen(enc.encode("Thanks, see you tomorrow."));
    expect(v.events.some((e) => e.category === "injection:patterns_unavailable")).toBe(true);
  });

  it("does not pretend the message was screened — it is a redact, not a clean allow", async () => {
    const v = await new InboundScreener().screen(enc.encode("Thanks, see you tomorrow."));
    expect(v.disposition).toBe("redact");
  });
});
