/**
 * The empty-roster affordance. These tests are about CONTENT, not formatting, because the defect
 * was never a formatting one: the old message was well-formed and said nothing useful.
 *
 * A reader who only sees this text must be able to answer three questions without going anywhere
 * else: what do I run now, where does the token come from, and why might I not be able to get one.
 * Each assertion below is one of those, so a future edit that drops the cohort sentence to "tidy
 * up" fails here rather than silently restoring the wasted trip to Telegram.
 */

import { describe, it, expect } from "vitest";
import { NO_AGENTS_GUIDANCE, WAITLIST_URL } from "../onboarding-guidance.js";

describe("NO_AGENTS_GUIDANCE", () => {
  it("states the machine has no agents, in plain words", () => {
    expect(NO_AGENTS_GUIDANCE).toMatch(/no agents on this machine/i);
  });

  it("names the cohort gate BEFORE the Telegram step, which is the whole point", () => {
    const cohortAt = NO_AGENTS_GUIDANCE.search(/cohort/i);
    const telegramAt = NO_AGENTS_GUIDANCE.search(/telegram/i);
    expect(cohortAt).toBeGreaterThanOrEqual(0);
    expect(telegramAt).toBeGreaterThanOrEqual(0);
    // Ordering is the requirement. Mentioning both but leading with Telegram sends the operator
    // to ask for a token they cannot be given yet — the exact failure this text prevents.
    expect(cohortAt).toBeLessThan(telegramAt);
  });

  it("points at the waitlist so someone who never signed up knows where to start", () => {
    expect(NO_AGENTS_GUIDANCE).toContain(WAITLIST_URL);
    expect(WAITLIST_URL).toBe("https://cello.mygentic.ai/waitlist");
  });

  it("names both commands, so the next keystroke is never a guess", () => {
    expect(NO_AGENTS_GUIDANCE).toContain("cello create-agent");
    expect(NO_AGENTS_GUIDANCE).toContain("cello register-agent");
  });

  it("says create-agent needs no token — a gated operator must still have something that works", () => {
    // Without this, "gated" and "broken" are indistinguishable to a new user.
    expect(NO_AGENTS_GUIDANCE).toMatch(/no token needed|needs no permission|costs nothing/i);
  });

  it("carries no ANSI escapes — it is rendered by a terminal AND passed to an agent over IPC", () => {
    // The shim JSON-encodes this into a tool result, where an escape sequence reaches the model as
    // literal garbage rather than colour. Neither surface can assume a TTY. Written as 
    // The pattern holds a real ESC byte, so it renders as an invisible character in a diff —
    // that is expected here, not a corrupted file.
    expect(NO_AGENTS_GUIDANCE).not.toMatch(/\[/);
  });
});
