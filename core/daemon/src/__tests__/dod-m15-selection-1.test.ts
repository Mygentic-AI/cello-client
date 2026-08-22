/**
 * DOD-M15-SELECTION-1 / DOD-M15-IPCVISIBLE-1 — a connection is never bound to an agent it did not
 * select, and when a fallback happens it is said out loud.
 *
 * ─── The defect, in the shape an operator met it ───────────────────────────────────────────────
 *
 * `resolveCurrentAgent` ended with:
 *
 *     if (onlineAgents.size === 1) return [...onlineAgents][0];
 *
 * So a connection that had selected nothing acted as whichever agent happened to be the only one
 * online. On a shared daemon that can be **a different operator's agent**, which is how this was
 * found: after a restart a released agent was silently reinstated under someone else's name.
 *
 * ─── Why the fallback is worse than it looks, even when it picks "right" ───────────────────────
 *
 * It produces a HALF-ATTENDED state. Tools resolve a subject and work; the notification dispatcher
 * routes doorbells by the connection's *registered* current agent, which the fallback never sets.
 * So the session sends and receives but never wakes — and that reads as the protocol dropping
 * messages, not as a selection that was never made.
 *
 * ─── AND WHY THE BEHAVIOUR IS UNCHANGED HERE ───────────────────────────────────────────────────
 *
 * My first attempt switched the fallback off for MCP on exactly that reasoning, and four existing
 * tests said no. CC-3 introduced it deliberately, to fix "the post-/mcp-reconnect papercut" — a
 * reconnected session with one agent online used to hard-fail `no_current_agent`.
 *
 * The DoD's answer is narrower than removal — *"if a fallback is wanted it is EXPLICIT in the
 * response, not announced as an accomplished fact"* — and it sequences the work: *"diagnosis
 * first… with the trigger field from DOD-M15-IPCVISIBLE-1 distinguishing replay from fallback in
 * one run."*
 *
 * So this file pins ATTRIBUTION, which is the precondition, and the behaviour change waits for the
 * diagnosis attribution makes possible. Writing it down because the instinct to just switch the
 * fallback off is strong and wrong, and the next person will have it too.
 */

import { describe, it, expect } from "vitest";
import { resolveCurrentAgentFor, type SelectionTrigger } from "../agent-selection.js";

interface Recorded { agent: string | null; trigger: SelectionTrigger }

function resolve(opts: {
  clientType: "mcp" | "cli";
  currentAgent?: string | null;
  clearedAgent?: string;
  online: string[];
  explicit?: string;
}): Recorded {
  /**
   * `undefined` until reported — NOT pre-seeded with a plausible default.
   *
   * It was initialised to `{agent:null, trigger:"none"}`, which made the "reports a trigger on
   * EVERY path" test below VACUOUS: a branch that returned without reporting left the initialiser
   * in place, `expect(agent).toBe(recorded.agent)` compared null to null and passed, and the test
   * named after the property asserted nothing about it. Review found it by mutating a `return
   * report(null,"none")` into a bare `return null` — green.
   */
  let recorded: Recorded | undefined;
  const agent = resolveCurrentAgentFor({
    connState: {
      currentAgent: opts.currentAgent ?? null,
      clientType: opts.clientType,
      ...(opts.clearedAgent !== undefined ? { clearedAgent: opts.clearedAgent } : {}),
    },
    onlineAgents: new Set(opts.online),
    ...(opts.explicit !== undefined ? { explicitAgent: opts.explicit } : {}),
    onResolved: (a, t) => { recorded = { agent: a, trigger: t }; },
  });
  expect(
    recorded,
    "this resolution reported NOTHING — the branch it took has no attribution, which is the defect " +
      "DOD-M15-IPCVISIBLE-1 exists to remove",
  ).toBeDefined();
  expect(agent, "the returned agent and the reported agent must be the same thing").toBe(recorded!.agent);
  return recorded!;
}

describe("DOD-M15-SELECTION-1: a live session is never bound to an agent it did not choose", () => {
  it("★ the sole-online fallback is ATTRIBUTABLE on both surfaces", () => {
    /**
     * The precondition `DOD-M15-SELECTION-1` depends on. The behaviour is unchanged — CC-3 added
     * this fallback deliberately, to fix the post-reconnect papercut where a session with exactly
     * one agent online hard-failed `no_current_agent`. What was missing is that it was SILENT: an
     * operator's explicit selection and a fallback nobody made arrived identically, so a switch
     * nobody asked for could not be told from one they did.
     */
    for (const clientType of ["mcp", "cli"] as const) {
      const r = resolve({ clientType, online: ["alice"] });
      expect(r.agent, `${clientType}: the fallback still resolves — behaviour is unchanged`).toBe("alice");
      expect(
        r.trigger,
        `${clientType}: the fallback must be attributable — explicit and replay were distinguishable ` +
          `and this was not`,
      ).toBe("fallback");
    }
  });

  it("no fallback when the choice is AMBIGUOUS — two agents online means neither is implied", () => {
    // Guessing between two identities is not a convenience, it is a coin flip with the operator's
    // name on it.
    expect(resolve({ clientType: "cli", online: ["alice", "bob"] }).agent).toBeNull();
    expect(resolve({ clientType: "mcp", online: ["alice", "bob"] }).agent).toBeNull();
  });

  it("an EXPLICIT selection wins on both surfaces and is recorded as explicit", () => {
    for (const clientType of ["mcp", "cli"] as const) {
      const r = resolve({ clientType, online: ["alice"], explicit: "bob" });
      expect(r.agent).toBe("bob");
      expect(r.trigger).toBe("explicit");
    }
  });

  it("a connection that HAS selected keeps its selection — the fallback never overrides a choice", () => {
    const r = resolve({ clientType: "mcp", currentAgent: "bob", online: ["alice"] });
    expect(r.agent).toBe("bob");
    expect(r.trigger).toBe("selected");
  });

  it("an INVOLUNTARY clear blocks the fallback, and is recorded as such", () => {
    /**
     * `clearedAgent` means the connection's agent was shut down or removed UNDERNEATH it — do not
     * guess a replacement.
     *
     * It is NOT set by a voluntary `cello_stop_using_agent`, and that distinction is load-bearing:
     * an operator choosing to hold nothing stays eligible for the fallback, while a connection
     * whose agent vanished does not. Getting these the same way round is why the trigger is named
     * `cleared` rather than `released`.
     */
    for (const clientType of ["mcp", "cli"] as const) {
      const r = resolve({ clientType, clearedAgent: "alice", online: ["alice"] });
      expect(r.agent, `${clientType}: a taken-away choice must not be silently replaced`).toBeNull();
      expect(r.trigger).toBe("cleared");
    }
  });

  it("reports a trigger on EVERY path — an unattributed resolution is the thing being fixed", () => {
    // If any branch forgot to report, the log would show a gap exactly where the ambiguity lives.
    const cases: Recorded[] = [
      resolve({ clientType: "mcp", online: ["alice"] }),
      resolve({ clientType: "cli", online: ["alice"] }),
      resolve({ clientType: "cli", online: [] }),
      resolve({ clientType: "mcp", currentAgent: "bob", online: [] }),
      resolve({ clientType: "cli", clearedAgent: "alice", online: ["alice"] }),
      resolve({ clientType: "mcp", online: ["a", "b"] }),
    ];
    for (const c of cases) {
      expect(typeof c.trigger, "every resolution reports how it was reached").toBe("string");
      expect(c.trigger.length).toBeGreaterThan(0);
    }
  });
});
