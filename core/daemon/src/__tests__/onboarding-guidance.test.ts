/**
 * The empty-roster hint. A reader must be able to answer two questions without going anywhere
 * else: what do I run now, and what happens when I run it. It must not send anyone for a token.
 */

import { describe, it, expect } from "vitest";
import { noAgentsGuidance, WAITLIST_URL } from "../onboarding-guidance.js";

const NO_AGENTS_GUIDANCE = noAgentsGuidance();

describe("NO_AGENTS_GUIDANCE", () => {
  it("states the machine has no agents, in plain words", () => {
    expect(NO_AGENTS_GUIDANCE).toMatch(/no agents on this machine/i);
  });

  it("names both commands, in order, so the next keystroke is never a guess", () => {
    const create = NO_AGENTS_GUIDANCE.indexOf("cello create-agent <name>");
    const register = NO_AGENTS_GUIDANCE.indexOf("cello register-agent <name>");
    expect(create).toBeGreaterThanOrEqual(0);
    expect(register).toBeGreaterThan(create);
  });

  it("says the first registration prints a link to approve this device", () => {
    expect(NO_AGENTS_GUIDANCE).toMatch(/prints a link and a code/);
    expect(NO_AGENTS_GUIDANCE).toMatch(/approve/);
  });

  it("names no token, no bot and no Telegram", () => {
    expect(NO_AGENTS_GUIDANCE).not.toMatch(/token/i);
    expect(NO_AGENTS_GUIDANCE).not.toMatch(/telegram/i);
    expect(NO_AGENTS_GUIDANCE).not.toContain("@Cello");
  });

  it("points someone not yet invited at Get Early Access", () => {
    expect(NO_AGENTS_GUIDANCE).toContain(`Get Early Access: ${WAITLIST_URL}`);
    expect(WAITLIST_URL).toBe("https://celloprotocol.com/waitlist");
  });
});
