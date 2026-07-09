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
    const { meta } = buildChannelParams({ type: "cello_message", from: "aa".repeat(32), session_id: "s1" });
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
    });
    expect(JSON.stringify(meta)).not.toContain("secret message body");
    expect(content).not.toContain("secret message body");
    expect(meta).not.toHaveProperty("blob");
    expect(meta).not.toHaveProperty("content");
  });

  it("drops keys with hyphens or other non-identifier characters (they'd be silently dropped by Claude Code anyway)", () => {
    const { meta } = buildChannelParams({ type: "cello_message", "bad-key": "x", "ok_key": "y" } as Record<string, unknown>);
    expect(meta).not.toHaveProperty("bad-key");
    expect(meta.ok_key).toBe("y");
  });

  it("cello_message content names the routing hints (session/from) but not message text", () => {
    const { content } = buildChannelParams({ type: "cello_message", from: "abc123", session_id: "sess789" });
    expect(content).toContain("cello_receive"); // tells the operator what to do
    expect(content.toLowerCase()).toContain("message");
  });
});

// ─── MONIKER-4 AC3/AC4 — the legible doorbell copy ──────────────────────────

describe("MONIKER-4: doorbell copy leads with who; IDs leave the body; unverified names are marked", () => {
  const base = {
    agent: "bob", agentName: "bob",
    sessionId: "ee".repeat(16),
    counterpartyPubkey: "cd".repeat(32),
  };

  it("created: known contact renders plain and the session id is NOT in the body (meta keeps it)", () => {
    const { content, meta } = buildChannelParams({ ...base, type: "session_state_changed", state: "created", who: "MyAlice", whoKnown: true });
    expect(content).toContain("MyAlice");
    expect(content).toContain("wants to connect");
    expect(content).toContain("bob"); // {yourAgent}
    expect(content).toContain("cello_await_session");
    expect(content).not.toContain("ee".repeat(8)); // no session id fragment in the body
    expect(meta.sessionId).toBe("ee".repeat(16));  // …but meta still carries it in full
    expect(meta.who).toBe("MyAlice");
    expect(meta.whoKnown).toBe("true");
  });

  it("created: an unverified offered name renders as a claim — quoted + (unverified)", () => {
    const { content } = buildChannelParams({ ...base, type: "session_state_changed", state: "created", who: "Bob", whoKnown: false });
    expect(content).toContain('"Bob" (unverified)');
  });

  it("created: a fingerprint renders PLAIN — it is derived identity, not a claim", () => {
    const { content } = buildChannelParams({ ...base, type: "session_state_changed", state: "created", who: "agent cdcdcdcd…", whoKnown: false });
    expect(content).toContain("agent cdcdcdcd…");
    expect(content).not.toContain('"agent'); // never quoted
    expect(content).not.toContain("(unverified)");
  });

  it("sealed and closed use the state-only phrasing (the frame carries state, not who closed)", () => {
    const sealed = buildChannelParams({ ...base, type: "session_state_changed", state: "sealed", who: "MyAlice", whoKnown: true }).content;
    expect(sealed).toContain("session with MyAlice sealed");
    const closed = buildChannelParams({ ...base, type: "session_state_changed", state: "closed", who: "MyAlice", whoKnown: true }).content;
    expect(closed).toContain("session with MyAlice ended");
    expect(closed).not.toContain("MyAlice ended the session");
  });

  it("cello_message leads with who and keeps the receive hint", () => {
    const { content } = buildChannelParams({ type: "cello_message", from: "cd".repeat(32), session_id: "ee".repeat(16), who: "MyAlice", whoKnown: true });
    expect(content).toContain("MyAlice sent a message");
    expect(content).toContain("cello_receive");
    expect(content).not.toContain("ee".repeat(8));
  });

  it("a 64-char name is never truncated in the body (only fingerprints shorten)", () => {
    const long = "A".repeat(64);
    const { content } = buildChannelParams({ ...base, type: "session_state_changed", state: "created", who: long, whoKnown: true });
    expect(content).toContain(long);
  });

  it("old-daemon frame (no who) degrades to a shim-side fingerprint — never blank, never the old ID-first copy", () => {
    const { content } = buildChannelParams({ ...base, type: "session_state_changed", state: "created" });
    expect(content).toContain(`agent ${"cd".repeat(4)}…`); // fingerprint of counterpartyPubkey
    const msg = buildChannelParams({ type: "cello_message", from: "cd".repeat(32), session_id: "s1" }).content;
    expect(msg).toContain(`agent ${"cd".repeat(4)}…`);
  });
});
