/**
 * The empty-roster affordance. These tests are about CONTENT and ORDER, not prose, because the
 * defect was never a formatting one: the old message was well-formed and said nothing useful.
 *
 * A reader must be able to answer three questions without going anywhere else: what do I run now,
 * where does the token come from, and — only if it applies to them — why might the bot refuse.
 * Each assertion is one of those, so an edit that drops a piece to "tidy up" fails here.
 */

import { describe, it, expect } from "vitest";
import {
  noAgentsGuidance,
  botHandle,
  WAITLIST_URL,
  BOT_HANDLE_PRODUCTION,
  BOT_HANDLE_STAGING,
} from "../onboarding-guidance.js";

// Every test states the environment explicitly. Reading process.env here would make the suite
// pass or fail on the shell it was launched from.
const NO_AGENTS_GUIDANCE = noAgentsGuidance("production");

describe("NO_AGENTS_GUIDANCE", () => {
  it("states the machine has no agents, in plain words", () => {
    expect(NO_AGENTS_GUIDANCE).toMatch(/no agents on this machine/i);
  });

  it("leads with the three-step happy path, and puts the cohort gate BELOW it", () => {
    const stepsAt = NO_AGENTS_GUIDANCE.indexOf("cello create-agent");
    const gateAt = NO_AGENTS_GUIDANCE.search(/waitlist token/i);
    expect(stepsAt).toBeGreaterThanOrEqual(0);
    expect(gateAt).toBeGreaterThanOrEqual(0);
    /**
     * ORDER IS THE REQUIREMENT, and this assertion was inverted on purpose.
     *
     * The first version led with the gate, to save a wasted trip to Telegram. But the gate's own
     * first step is "is this Telegram ID already linked? → proceed" — once the waitlist token is
     * burned the condition is permanently satisfied. Leading with it makes everyone past that
     * point read a standing warning about a door they already walked through, every time they
     * have no agent on a machine. The happy path leads; the gate is a condition underneath.
     */
    expect(stepsAt).toBeLessThan(gateAt);
  });

  it("names the bot by HANDLE, not by description", () => {
    // Every other mention in the product says "the CELLO Operations Agent on Telegram", which
    // leaves a reader knowing they need a bot and unable to search for it.
    expect(NO_AGENTS_GUIDANCE).toContain(BOT_HANDLE_PRODUCTION);
    expect(BOT_HANDLE_PRODUCTION).toBe("@CelloConnectBot");
  });

  it("distinguishes the AGENT token from the WAITLIST token", () => {
    // Two different things: one grants network access once and is burned; the other authorizes
    // one agent to register. Calling both "your token" is how a support thread becomes unanswerable.
    expect(NO_AGENTS_GUIDANCE).toMatch(/agent token/i);
    expect(NO_AGENTS_GUIDANCE).toMatch(/waitlist token/i);
  });

  it("never calls the waitlist token a 'telegram token'", () => {
    // `cello-ops-agent-telegram-bot-token` is the bot's own API credential and already owns that
    // name in the infrastructure.
    expect(NO_AGENTS_GUIDANCE).not.toMatch(/telegram token/i);
  });

  it("points at the waitlist so someone who never signed up knows where to start", () => {
    expect(NO_AGENTS_GUIDANCE).toContain(WAITLIST_URL);
    expect(WAITLIST_URL).toBe("https://cello.mygentic.ai/waitlist");
  });

  it("names both commands, so the next keystroke is never a guess", () => {
    expect(NO_AGENTS_GUIDANCE).toContain("cello create-agent");
    expect(NO_AGENTS_GUIDANCE).toContain("cello register-agent");
  });

  it("frames the gate as a condition, so a reader past it can skip the paragraph", () => {
    expect(NO_AGENTS_GUIDANCE).toMatch(/first time with the bot\?/i);
  });
});

describe("botHandle — which bot an operator is sent to", () => {
  it("sends a staging operator to the staging bot", () => {
    expect(botHandle("staging")).toBe(BOT_HANDLE_STAGING);
    expect(noAgentsGuidance("staging")).toContain("@CelloConnectStagingBot");
  });

  it("sends everyone else to production, INCLUDING an unset environment", () => {
    /**
     * This is the fail-safe direction and the reason the mapping is a whitelist of one.
     *
     * `resolveCelloEnv` defaults an unset CELLO_ENV to "local", and the overwhelmingly common
     * case is an operator who installed from npm and set nothing. Were the check inverted — "is
     * this production?" — that operator would be sent to the staging bot, which cannot issue them
     * anything and would look like the product being broken. Pointing a misconfigured staging box
     * at the real bot is the recoverable error; the reverse is not.
     */
    for (const env of ["production", "local", "dev", "test", undefined, "", "STAGING", "stage"]) {
      expect(botHandle(env), `CELLO_ENV=${String(env)} must resolve to production`).toBe(
        BOT_HANDLE_PRODUCTION,
      );
    }
  });

  it("never names both bots in one message", () => {
    // An operator should see exactly one handle to act on. Two is a choice they cannot make.
    for (const env of ["production", "staging"]) {
      const text = noAgentsGuidance(env);
      const both =
        text.includes(BOT_HANDLE_PRODUCTION) && text.includes(BOT_HANDLE_STAGING);
      expect(both, `CELLO_ENV=${env} showed both handles`).toBe(false);
    }
  });
});
