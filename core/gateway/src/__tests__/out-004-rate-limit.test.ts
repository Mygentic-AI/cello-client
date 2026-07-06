/**
 * M9-OUT-004 — per-agent-identity outbound rate limiting. Pure in-memory sliding window, keyed on
 * the agent identity (NOT a source IP). Unit altitude. An injectable clock makes the window
 * deterministic.
 */
import { describe, it, expect } from "vitest";
import { OutboundRateLimiter } from "../detect/rate-limit.js";

function fakeClock(start = 1_000_000) {
  let t = start;
  return { now: () => t, advance: (ms: number) => { t += ms; } };
}

describe("M9-OUT-004 OutboundRateLimiter", () => {
  it("AC-002: under the cap, every send is allowed with no throttle and no delay", () => {
    const clk = fakeClock();
    const rl = new OutboundRateLimiter({ maxPerWindow: 5, windowMs: 10_000 }, clk.now);
    for (let i = 0; i < 5; i++) {
      const v = rl.check("alice");
      expect(v.limited).toBe(false);
      expect(v.retryAfterMs).toBeUndefined();
    }
  });

  it("AC-001: the N+1th send in the window is throttled with a distinct rate_limited reason + retry guidance", () => {
    const clk = fakeClock();
    const rl = new OutboundRateLimiter({ maxPerWindow: 3, windowMs: 10_000 }, clk.now);
    expect(rl.check("alice").limited).toBe(false); // 1
    expect(rl.check("alice").limited).toBe(false); // 2
    expect(rl.check("alice").limited).toBe(false); // 3
    const v = rl.check("alice"); // 4th — over the cap
    expect(v.limited).toBe(true);
    expect(v.reason).toBe("rate_limited");
    expect(typeof v.guidance).toBe("string");
    expect(v.guidance).toMatch(/retry|window|wait/i);
    expect(v.retryAfterMs).toBeGreaterThan(0);
  });

  it("the window slides: after it elapses, sends are allowed again", () => {
    const clk = fakeClock();
    const rl = new OutboundRateLimiter({ maxPerWindow: 2, windowMs: 10_000 }, clk.now);
    rl.check("alice");
    rl.check("alice");
    expect(rl.check("alice").limited).toBe(true); // capped
    clk.advance(10_001); // the window passes
    expect(rl.check("alice").limited).toBe(false); // allowed again
  });

  it("the limit is keyed on the agent IDENTITY: one agent at its cap does not throttle another", () => {
    const clk = fakeClock();
    const rl = new OutboundRateLimiter({ maxPerWindow: 2, windowMs: 10_000 }, clk.now);
    rl.check("alice");
    rl.check("alice");
    expect(rl.check("alice").limited).toBe(true); // alice capped
    expect(rl.check("bob").limited).toBe(false); // bob unaffected
    expect(rl.check("bob").limited).toBe(false);
    expect(rl.check("bob").limited).toBe(true); // bob has his own bucket
  });

  it("a throttled check does NOT consume a slot — the count stays at the cap, not above it", () => {
    const clk = fakeClock();
    const rl = new OutboundRateLimiter({ maxPerWindow: 1, windowMs: 10_000 }, clk.now);
    expect(rl.check("alice").limited).toBe(false); // 1 (at cap)
    rl.check("alice"); // throttled
    rl.check("alice"); // throttled
    // Half the window in, the single allowed send is what expires — so after windowMs from THAT
    // send (not from the throttled attempts) the agent is allowed again.
    clk.advance(10_001);
    expect(rl.check("alice").limited).toBe(false);
  });
});
