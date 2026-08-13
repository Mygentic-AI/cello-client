/**
 * DOD-MP-SESSION-RETIRE-1, the remaining half — the SAFE completion.
 *
 * The observed case (`session_sealed`) is fixed: the daemon retires the session and the next
 * delivery opens a fresh one. The FULLY-sealed case answers `relay_session_gone`, which is
 * deliberately NOT terminal, and the reviewer's proposed fix — add it to the terminal set — was
 * REFUSED on evidence: `relay-node.ts` defaults to `InMemoryRelayStore`, so a relay restart or MIG
 * roll makes every client see that string for sessions that are perfectly alive. Made terminal, it
 * would retire every live session on every client whenever the relay bounces — the sovereign-node
 * invariant inverted.
 *
 * `relay_session_gone` conflates "this session is over" with "the relay lost its memory", and
 * destroying durable local state on the ambiguous one is the wrong move under one of the two
 * readings.
 *
 * So this destroys NOTHING. It stops the delivery worker REUSING a session that keeps refusing,
 * so the next acquire opens a fresh one. Correct under both readings: if the session really is
 * over, we route around it; if the relay merely bounced, we opened one extra session and the old
 * one remains untouched and usable by the conversation path.
 */

import { describe, it, expect } from "vitest";
import {
  createSessionSuspects,
  TERMINAL_ISH_REFUSALS,
} from "../delivery-session-suspects.js";

describe("DOD-MP-SESSION-RETIRE-1 — a session that keeps refusing stops being REUSED", () => {
  it("is not suspect on the FIRST refusal — one blip must not churn a live session", () => {
    const s = createSessionSuspects();
    s.noteFailure("s-1", "relay_session_gone");
    // A relay that bounced answers this for a healthy session. Reacting instantly would open a new
    // session on every transient hiccup, which is churn, not availability.
    expect(s.isSuspect("s-1")).toBe(false);
  });

  it("IS suspect once the refusals REPEAT — the DoD's 'repeated terminal refusals'", () => {
    const s = createSessionSuspects();
    s.noteFailure("s-1", "relay_session_gone");
    s.noteFailure("s-1", "relay_session_gone");
    expect(s.isSuspect("s-1")).toBe(true);
  });

  it("counts only the TERMINAL-ISH reasons — an offline peer is not a bad session", () => {
    const s = createSessionSuspects();
    s.noteFailure("s-1", "transport_unavailable");
    s.noteFailure("s-1", "counterparty_offline");
    s.noteFailure("s-1", "transport_unavailable");
    // Abandoning a session because the far end is asleep would open a fresh session per sweep for
    // as long as they stay away, each one sealed moments later.
    expect(s.isSuspect("s-1")).toBe(false);
  });

  it("a SUCCESS clears the count — the run must be consecutive", () => {
    const s = createSessionSuspects();
    s.noteFailure("s-1", "session_sealed");
    s.noteSuccess("s-1");
    s.noteFailure("s-1", "session_sealed");
    // Two failures either side of a working send are not a dead session; they are a flaky link.
    expect(s.isSuspect("s-1")).toBe(false);
  });

  it("suspicion is PER SESSION — one bad session never condemns another with the same peer", () => {
    const s = createSessionSuspects();
    s.noteFailure("s-dead", "session_sealed");
    s.noteFailure("s-dead", "session_sealed");
    expect(s.isSuspect("s-dead")).toBe(true);
    // The healthy session with the same counterparty must stay usable — the per-session discipline
    // the retirement fix already established.
    expect(s.isSuspect("s-live")).toBe(false);
  });

  it("names relay_session_gone alongside the two the daemon already treats as terminal", () => {
    // The whole point of the unit: this string is the one the fully-sealed case answers, and it is
    // handled HERE — where the response is non-destructive — rather than in TERMINAL_RELAY_REFUSALS,
    // where the response would be to destroy local state.
    expect([...TERMINAL_ISH_REFUSALS].sort()).toEqual(
      ["relay_session_gone", "session_not_found", "session_sealed"],
    );
  });

  it("forgets a suspect session once it is no longer offered — no unbounded growth", () => {
    const s = createSessionSuspects();
    for (let i = 0; i < 500; i++) {
      s.noteFailure(`s-${i}`, "session_sealed");
      s.noteFailure(`s-${i}`, "session_sealed");
    }
    // A daemon that runs for months must not accumulate a row per session it ever gave up on.
    expect(s.size()).toBeLessThanOrEqual(256);
    // And the most recent judgement is the one that survives eviction.
    expect(s.isSuspect("s-499")).toBe(true);
  });
});
