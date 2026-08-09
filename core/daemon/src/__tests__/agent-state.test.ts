/**
 * The agent-state ladder — one rung at a time, plus the precedence that makes it honest.
 *
 * The defect this replaces, in the operator's words: an agent said `online` whether or not anybody
 * was there to answer, whether or not it had ever been registered, and whether or not a directory
 * was reachable. "Online should be the final perfect state" (Andre, 2026-08-09) — so it now means
 * ready AND attended, and every weaker condition has its own word.
 */
import { describe, it, expect } from "vitest";
import { resolveAgentState, type AgentStateInputs } from "../agent-state.js";

/** A fully healthy, attended agent. Each test bends exactly one fact away from this. */
const HEALTHY: AgentStateInputs = {
  loadFailed: false,
  hasFrostShare: true,
  deliberatelyOffline: false,
  started: true,
  signalingConnected: true,
  attendance: 1,
};

describe("the agent-state ladder", () => {
  it("online: ready AND someone is attending", () => {
    expect(resolveAgentState(HEALTHY)).toBe("online");
  });

  it("unattended: ready, but nobody is home to answer", () => {
    // The rung that did not exist. A caller reaching this agent gets the away message, and the away
    // flow ENDS a session — which is how two unattended agents once sealed a conversation nobody
    // had. It rendered identically to a live agent.
    expect(resolveAgentState({ ...HEALTHY, attendance: 0 })).toBe("unattended");
  });

  it("connecting: started, not yet on the directory", () => {
    expect(resolveAgentState({ ...HEALTHY, signalingConnected: false })).toBe("connecting");
  });

  it("stopped: registered, not running here", () => {
    expect(resolveAgentState({ ...HEALTHY, started: false })).toBe("stopped");
  });

  it("paused: the operator switched it off, and that is the kill switch working", () => {
    expect(resolveAgentState({ ...HEALTHY, deliberatelyOffline: true })).toBe("paused");
  });

  it("unregistered: created here, the directory has never heard of it", () => {
    // Every agent on disk used to load as "registered" whether or not it ever was, so the state
    // between `cello create-agent` and `cello register-agent` was indistinguishable from working.
    expect(resolveAgentState({ ...HEALTHY, hasFrostShare: false })).toBe("unregistered");
  });

  it("load_failed: the identity would not load", () => {
    expect(resolveAgentState({ ...HEALTHY, loadFailed: true })).toBe("load_failed");
  });
});

describe("precedence — the worst fact wins, and that is what stops the lie", () => {
  it("attendance NEVER masks a dead signaling stream", () => {
    // The whole point. If attendance could win, an attended agent with no directory connection would
    // read `online` — which is the exact "looks healthy, cannot work" state the enum replaces.
    expect(resolveAgentState({ ...HEALTHY, signalingConnected: false, attendance: 3 })).toBe("connecting");
  });

  it("attendance NEVER masks an agent that was never registered", () => {
    expect(resolveAgentState({ ...HEALTHY, hasFrostShare: false, attendance: 3 })).toBe("unregistered");
  });

  it("paused outranks connecting — a deliberate switch-off is not a fault to diagnose", () => {
    // Reporting a signaling problem on an agent the operator turned off is noise about something
    // they do not care about, and it makes the kill switch working look broken.
    expect(resolveAgentState({ ...HEALTHY, deliberatelyOffline: true, signalingConnected: false })).toBe("paused");
  });

  it("unregistered outranks paused — pausing something unreachable is not the headline", () => {
    expect(resolveAgentState({ ...HEALTHY, hasFrostShare: false, deliberatelyOffline: true })).toBe("unregistered");
  });

  it("load_failed outranks everything", () => {
    expect(
      resolveAgentState({
        loadFailed: true,
        hasFrostShare: false,
        deliberatelyOffline: true,
        started: false,
        signalingConnected: false,
        attendance: 0,
      }),
    ).toBe("load_failed");
  });

  it("a stopped agent is stopped, not unattended — nobody attends a thing that is not running", () => {
    expect(resolveAgentState({ ...HEALTHY, started: false, attendance: 0 })).toBe("stopped");
  });
});
