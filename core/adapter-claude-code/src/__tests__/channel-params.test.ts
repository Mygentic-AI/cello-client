/**
 * Unit tests for buildChannelParams — the daemon-frame → Claude Code channel `{ content, meta }`
 * translation. This is the test that was MISSING and let the broken doorbell ship: the old tests
 * asserted "no content field," conflating INV-CONTENTFREE with omitting Claude Code's REQUIRED
 * `content` field, so the pushed events never rendered (BUILD-JOURNAL Entry 43).
 */
import { setupV3Tests, describe, it, expect } from "@claude-flow/testing";
import { buildChannelParams } from "../channel-params.js";

setupV3Tests();

describe("buildChannelParams — Claude Code channel contract", () => {
  it("ALWAYS produces a non-empty `content` string (the <channel> tag body Claude Code requires)", () => {
    for (const frame of [
      { type: "cello_message", from: "aa".repeat(32), session_id: "bb".repeat(16) },
      { type: "cello_session_request", from: "cc".repeat(32), session_id: "dd".repeat(16) },
      { type: "session_state_changed", agent: "alice", agentName: "alice", sessionId: "ee".repeat(16), state: "created", counterpartyPubkey: "ff".repeat(32) },
      { type: "agent_state_changed", agent: "alice", state: "online" },
      { type: "agent_current_changed", agent: "alice", toAgent: "bob" },
      { type: "some_future_type", agent: "alice" },
      {}, // no type at all
    ]) {
      const { content } = buildChannelParams(frame);
      expect(typeof content).toBe("string");
      expect(content.length).toBeGreaterThan(0);
    }
  });

  it("puts routing fields in `meta` with identifier-safe keys (Claude Code drops hyphenated keys)", () => {
    const { meta } = buildChannelParams({ type: "cello_message", from: "aa".repeat(32), session_id: "s1" }, "cello_message");
    expect(meta.type).toBe("cello_message");
    expect(meta.from).toBe("aa".repeat(32));
    expect(meta.session_id).toBe("s1");
    for (const k of Object.keys(meta)) expect(k).toMatch(/^[a-zA-Z0-9_]+$/);
  });

  it("INV-CONTENTFREE / SI-001: never carries a `content` key from the frame into meta, and drops non-scalars", () => {
    // A defensively-malicious frame that tries to smuggle message text via a `content` key or an
    // object value must not leak into the pushed payload.
    const { content, meta } = buildChannelParams({
      type: "cello_message",
      from: "aa".repeat(32),
      content: "secret message body that must never ride the push",
      blob: { nested: "also dropped" } as unknown as string,
    }, "cello_message");
    expect(JSON.stringify(meta)).not.toContain("secret message body");
    expect(content).not.toContain("secret message body");
    expect(meta).not.toHaveProperty("blob");
    expect(meta).not.toHaveProperty("content");
  });

  it("drops keys with hyphens or other non-identifier characters (they'd be silently dropped by Claude Code anyway)", () => {
    const { meta } = buildChannelParams({ type: "cello_message", "bad-key": "x", "ok_key": "y" }, "cello_message" as Record<string, unknown>);
    expect(meta).not.toHaveProperty("bad-key");
    expect(meta.ok_key).toBe("y");
  });

  it("cello_message content names the routing hints (session/from) but not message text", () => {
    const { content } = buildChannelParams({ type: "cello_message", from: "abc123", session_id: "sess789" }, "cello_message");
    expect(content).toContain("cello_receive"); // tells the operator what to do
    expect(content.toLowerCase()).toContain("message");
  });
});

// ─── MONIKER-4 AC3/AC4 — the legible doorbell copy ──────────────────────────

describe("MONIKER-4: doorbell copy leads with who; IDs leave the body; self-declared names are marked", () => {
  const base = {
    agent: "bob", agentName: "bob",
    sessionId: "ee".repeat(16),
    counterpartyPubkey: "cd".repeat(32),
  };

  it("created: known contact renders plain and the session id is NOT in the body (meta keeps it)", () => {
    const { content, meta } = buildChannelParams({ ...base, type: "session_state_changed", state: "created", who: "MyAlice", whoKnown: true }, "session_state_changed");
    expect(content).toContain("MyAlice");
    expect(content).toContain("wants to connect");
    expect(content).toContain("bob"); // {yourAgent}
    expect(content).toContain("cello_await_session");
    // 8 e's — matches ANY truncation of the session id (the old copy emitted 12 via short()).
    expect(content).not.toContain("ee".repeat(4)); // no session id fragment in the body
    expect(meta.sessionId).toBe("ee".repeat(16));  // …but meta still carries it in full
    expect(meta.who).toBe("MyAlice");
    expect(meta.whoKnown).toBe("true");
  });

  it("created: a self-declared offered name renders as a claim — quoted + (self-declared)", () => {
    const { content } = buildChannelParams({ ...base, type: "session_state_changed", state: "created", who: "Bob", whoKnown: false }, "session_state_changed");
    expect(content).toContain('"Bob" (self-declared)');
  });

  it("created: a fingerprint renders PLAIN — it is derived identity, not a claim", () => {
    const { content } = buildChannelParams({ ...base, type: "session_state_changed", state: "created", who: "agent cdcdcdcd…", whoKnown: false }, "session_state_changed");
    expect(content).toContain("agent cdcdcdcd…");
    expect(content).not.toContain('"agent'); // never quoted
    expect(content).not.toContain("(self-declared)");
  });

  it("sealed and closed use the state-only phrasing (the frame carries state, not who closed)", () => {
    const sealed = buildChannelParams({ ...base, type: "session_state_changed", state: "sealed", who: "MyAlice", whoKnown: true }, "session_state_changed").content;
    expect(sealed).toContain("session with MyAlice sealed");
    const closed = buildChannelParams({ ...base, type: "session_state_changed", state: "closed", who: "MyAlice", whoKnown: true }, "session_state_changed").content;
    expect(closed).toContain("session with MyAlice ended");
    expect(closed).not.toContain("MyAlice ended the session");
  });

  it("cello_message leads with who and keeps the receive hint", () => {
    const { content } = buildChannelParams({ type: "cello_message", from: "cd".repeat(32), session_id: "ee".repeat(16), who: "MyAlice", whoKnown: true }, "cello_message");
    expect(content).toContain("MyAlice sent a message");
    expect(content).toContain("cello_receive");
    expect(content).not.toContain("ee".repeat(4));
  });

  it("a 64-char name is never truncated in the body (only fingerprints shorten)", () => {
    const long = "A".repeat(64);
    const { content } = buildChannelParams({ ...base, type: "session_state_changed", state: "created", who: long, whoKnown: true }, "session_state_changed");
    expect(content).toContain(long);
  });

  it("review F1: YOUR agent name is not truncated either — agent names share the 64-char rule", () => {
    const { content } = buildChannelParams({ ...base, agentName: "research_assistant", type: "session_state_changed", state: "created", who: "MyAlice", whoKnown: true }, "session_state_changed");
    expect(content).toContain("research_assistant");
  });

  it("old-daemon frame (no who) degrades to a shim-side fingerprint — never blank, never the old ID-first copy", () => {
    const { content } = buildChannelParams({ ...base, type: "session_state_changed", state: "created" }, "session_state_changed");
    expect(content).toContain(`agent ${"cd".repeat(4)}…`); // fingerprint of counterpartyPubkey
    const msg = buildChannelParams({ type: "cello_message", from: "cd".repeat(32), session_id: "s1" }, "cello_message").content;
    expect(msg).toContain(`agent ${"cd".repeat(4)}…`);
  });
});

/**
 * The live defect (2026-07-30): three doorbells in one session rendered as the useless generic
 * `CELLO event: cello_event.` even though the shipped shim HAS per-type text for every one of them.
 *
 * Cause: the type is resolved TWICE. `cello-mcp.ts` resolves it as
 * `data.type ?? String(frame.notification)`; `buildChannelParams` re-derived it from `data.type`
 * alone and fell through to the literal "cello_event". Real daemon frames carry the type on
 * `frame.notification`, NOT in `data` — so every hand-written announcement was bypassed in
 * production while every test passed, because every fixture above puts `type` inside `data`.
 *
 * The fix is to stop re-deriving: the caller passes the type it already resolved.
 */
describe("buildChannelParams — the type comes from the caller, not from data", () => {
  it("renders per-type text when the type is NOT in `data` (the real daemon frame shape)", () => {
    const { content } = buildChannelParams({ agent: "alice", toAgent: "bob" }, "agent_current_changed");
    expect(content).not.toContain("cello_event");
    // Asserts that the AGENT-SWITCH branch ran, not its exact prose — the wording changed when the
    // message was rewritten in operator terms, and pinning the sentence made a copy edit look like
    // a regression of the type-resolution bug this test actually guards.
    expect(content).toContain("bob");
  });

  it("a real message frame with no `data.type` still announces a message, not a generic event", () => {
    const { content } = buildChannelParams({ from: "aa".repeat(32), session_id: "s1" }, "cello_message");
    expect(content).toContain("sent a message");
    expect(content).toContain("cello_receive");
  });

  it("a daemon shutdown is ACTIONABLE, not silent and not generic — it names the recovery", () => {
    const { content } = buildChannelParams({}, "shutdown");
    expect(content).toContain("cello login");
  });

  it("an unknown future type still renders its own name, never the placeholder", () => {
    const { content } = buildChannelParams({ agent: "alice" }, "some_future_type");
    expect(content).toContain("some_future_type");
  });
});


// The doorbell after `cello logout && cello login`. The operator got "⚠️ the daemon stopped" and then
// nothing when it came back — the reconnect only reached the shim's stderr. What DID arrive was an
// agent-switch notice from the handshake replay, standing in for an announcement that did not exist.
describe("daemon lifecycle: coming back is an event, and names are not truncated", () => {
  it("announces the daemon returning, and names the restored agent", () => {
    const { content } = buildChannelParams({ agent: "CELLO_Feedback" }, "daemon_reconnected");
    expect(content).toContain("daemon is back");
    expect(content).toContain("CELLO_Feedback");
    expect(content).not.toContain("stopped");
  });

  it("still announces the return when no agent was selected", () => {
    const { content } = buildChannelParams({}, "daemon_reconnected");
    expect(content).toContain("daemon is back");
    expect(content).not.toContain("undefined");
    expect(content).not.toContain("null");
  });

  it("NEVER truncates an agent name — `short()` is for fingerprints, not names", () => {
    // It rendered "CELLO_Feedba…", contradicting the rule the session_state_changed branch states
    // outright. A mangled name reads as a different agent.
    for (const type of ["agent_current_changed", "agent_state_changed", "daemon_reconnected"]) {
      const { content } = buildChannelParams(
        { agent: "CELLO_Feedback", toAgent: "CELLO_Feedback", state: "online" },
        type,
      );
      expect(content, `${type} truncated the agent name`).toContain("CELLO_Feedback");
      expect(content, `${type} left an ellipsis in a name`).not.toContain("…");
    }
  });

  it("says what the agent switch MEANS, not which internal field changed", () => {
    const { content } = buildChannelParams({ toAgent: "Ms_Chelly" }, "agent_current_changed");
    expect(content).toContain("you are now acting as Ms_Chelly");
  });
});
