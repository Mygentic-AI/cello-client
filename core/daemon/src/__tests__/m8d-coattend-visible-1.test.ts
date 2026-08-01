/**
 * DOD-COATTEND-VISIBLE-1 — make the theft VISIBLE (M8D Tier 0, the launch gate).
 *
 * Two sessions attend one agent. A message arrives. One session gets it; the other is told
 * `{ ok: true, content: null, guidance: "No content arrived within timeout_ms…" }` — word for word
 * what a QUIET COUNTERPARTY produces — and the plain blocking receive writes nothing to the log on
 * either outcome, so the theft leaves no trace anywhere.
 *
 * This line does NOT change delivery. `takeReceivedContent` stays a destructive `buf.shift()`, the
 * doorbell stays multicast, no attach is refused. It changes only what the operator is TOLD. The
 * redesign is Tier 1 (DOD-COATTEND-1).
 *
 * Clause coverage (journal Entry 1):
 * - C1 (AC1): the loser's answer carries a MACHINE-READABLE discriminator, not a reworded string.
 * - C2 (AC1): the quiet-counterparty case is unchanged and is distinguishable from C1 — the control
 *   that stops C1 from being satisfied by labelling every empty receive a theft.
 * - C3 (AC3): the blocking receive logs on BOTH outcomes, and the theft logs at WARN.
 * - C4 (AC2): the attendance count rides cello_use_agent, cello_status and the arrival alert.
 * - C5 (AC4): a second session attaching to an attended agent is TOLD, and is NOT refused.
 * - C6 (AC2): isAttended's decision is untouched — counting is additive.
 * - C7: the discriminator clears once the loser has caught up. It reports UNSEEN content, not "a
 *   sibling exists" — a flag that never clears is a flag nobody reads.
 * - C8 (review HIGH): a FRESH connection whose predecessor died is told nothing arrived. C7 only
 *   ever asked what the SAME connection sees; this asks what a NEW one sees, which is the `cello`
 *   CLI's only mode and every reconnect's first mode.
 * - C9 (review MEDIUM): a theft AND a dead counterparty are both true — `reason` names the
 *   terminal, actionable condition and the theft rides as a field.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";

const SID = "cd".repeat(32);

describe("DOD-COATTEND-VISIBLE-1: two sessions on one agent — the loser is told, and the log remembers", () => {
  let fx: TwoConnectionFixture;

  beforeEach(async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-m8d-visible-" });
  });

  afterEach(async () => {
    await fx.cleanup();
  });

  it("C2 (AC1, the control): a genuinely quiet counterparty is UNCHANGED and stays distinguishable", async () => {
    await fx.createSession(SID, "alice");
    const connA = await fx.connectAs("alice");
    await fx.connectAs("alice"); // attended by two, but NOTHING ever arrives

    const quiet = (await connA.send("cello_receive", { session_id: SID, timeout_ms: 100 })) as Record<string, unknown>;
    expect(quiet).toMatchObject({ ok: true, content: null });
    // No theft happened, so no theft is claimed. Without this, C1 is satisfied by labelling every
    // empty receive a theft — which tells the operator nothing and is worse than the silence.
    expect(quiet.reason).toBeUndefined();
    expect(quiet.taken_by_sibling).toBeUndefined();
    expect(String(quiet.guidance)).toMatch(/No content arrived within timeout_ms/);
  });

  it("C4 (AC2): the attendance count rides cello_use_agent, cello_status, and the arrival alert", async () => {
    await fx.createSession(SID, "alice");

    const connA = await fx.connectAs("alice");
    const statusAlone = (await connA.send("cello_status", {})) as Record<string, unknown>;
    const aliceAlone = (statusAlone.agents as Array<Record<string, unknown>>).find((a) => a.name === "alice");
    expect(aliceAlone?.attendance).toBe(1);

    // The SECOND attach reports the count it is joining — this is the return the operator reads.
    const connB = await fx.connect();
    const attach = (await connB.send("cello_use_agent", { name: "alice" })) as Record<string, unknown>;
    expect(attach.ok).toBe(true);
    expect(attach.attendance).toBe(2);

    const statusTogether = (await connA.send("cello_status", {})) as Record<string, unknown>;
    const aliceTogether = (statusTogether.agents as Array<Record<string, unknown>>).find((a) => a.name === "alice");
    expect(aliceTogether?.attendance).toBe(2);

    // The arrival alert. The doorbell is content-free routing metadata — an attendance count is
    // routing metadata; anything naming WHAT arrived is not.
    const doorbells: Array<Record<string, unknown>> = [];
    connB.onNotification((n) => {
      if (n.notification === "cello_message") doorbells.push((n.data ?? {}) as Record<string, unknown>);
    });
    await fx.ingestReceived("alice", SID, "from bob");
    await new Promise((r) => setTimeout(r, 150));

    expect(doorbells.length).toBeGreaterThan(0);
    expect(doorbells[0].attendance).toBe(2);
    expect(JSON.stringify(doorbells[0])).not.toMatch(/from bob/);

    // ...and it drops back when a session goes away, so the number is live rather than a high-water mark.
    connB.close();
    await new Promise((r) => setTimeout(r, 150));
    const statusAfter = (await connA.send("cello_status", {})) as Record<string, unknown>;
    const aliceAfter = (statusAfter.agents as Array<Record<string, unknown>>).find((a) => a.name === "alice");
    expect(aliceAfter?.attendance).toBe(1);
  });

  it("C5 (AC4): a second attach is TOLD it is not alone — and is NOT refused (exclusivity by the back door)", async () => {
    await fx.connectAs("alice");
    const connB = await fx.connect();

    const attach = (await connB.send("cello_use_agent", { name: "alice" })) as Record<string, unknown>;
    // Refusing here would be exclusivity, rejected permanently (spec §3). It must SUCCEED.
    expect(attach.ok).toBe(true);
    expect(attach.attendance).toBe(2);
    expect(String(attach.co_attendance_guidance)).toMatch(/session/i);

    const coattended = fx.eventsNamed("agent.attend.coattended");
    expect(coattended).toHaveLength(1);
    expect(coattended[0].ctx).toMatchObject({ agentName: "alice", attendance: 2 });

    // The FIRST attach was alone, so it must not have been told it was in company.
    const first = (await (await fx.connect()).send("cello_use_agent", { name: "alice" })) as Record<string, unknown>;
    expect(first.attendance).toBe(3);
  });

  it("C6 (AC2): counting is ADDITIVE — the away path's attendance decision is untouched", async () => {
    // isAttended() returns a boolean on first match and deliberately never counts. M8C-AWAY-1's
    // auto-ack suppression hangs off it, so a count that replaced it could silently move the away
    // behavior of every agent. An attended agent must still suppress its away reply.
    await fx.createSession(SID, "alice");
    await fx.connectAs("alice");

    await fx.ingestReceived("alice", SID, "from bob");
    await new Promise((r) => setTimeout(r, 150));

    expect(fx.eventsNamed("session.away.response.sent")).toHaveLength(0);
  });

  // ─── SUPERSEDED BY DOD-COATTEND-1 (Tier 1), 2026-08-01 ────────────────────────────────────
  //
  // This file used to carry five clauses asserting that the loser of a race is TOLD a sibling took
  // its message: the machine-readable discriminator, the WARN, the clearing behaviour, the
  // fresh-connection case, and the both-true-with-counterparty-gone case.
  //
  // Tier 1 removed the theft. Delivery now reads a durable record against a per-connection
  // bookmark, so both attached sessions receive the same message and nothing is taken from anyone.
  // Those clauses asserted the VISIBILITY OF A DEFECT THAT NO LONGER OCCURS — keeping them would
  // pin the defect, which is the opposite of what they were written for.
  //
  // What Tier 0 delivered and this file still guards: the attendance count on every surface, that
  // attaching is never refused, that `isAttended`'s away decision did not move, and that a
  // genuinely quiet counterparty still reads as quiet. The new behaviour is asserted on two real
  // connections in m8d-coattend-1.test.ts.
  //
  // The `taken_by_sibling_session` discriminator itself is deliberately NOT deleted in this unit:
  // deadness is proven by deletion plus a red build, never by "nothing reaches it today", and the
  // drift and relay-degraded paths have not been re-examined against it. That is its own unit.
  it("C10 (supersession): what WAS a theft is now a delivery — both sessions get the message", async () => {
    await fx.createSession(SID, "alice");
    const connA = await fx.connectAs("alice");
    const connB = await fx.connectAs("alice");

    await fx.ingestReceived("alice", SID, "from bob");

    const a = (await connA.send("cello_receive", { session_id: SID, timeout_ms: 2_000 })) as Record<string, unknown>;
    const b = (await connB.send("cello_receive", { session_id: SID, timeout_ms: 2_000 })) as Record<string, unknown>;

    expect(a.content).toBe("from bob");
    expect(b.content, "the second session is no longer robbed — that is Tier 1").toBe("from bob");
    // ...and neither is told about a theft, because none happened.
    expect(a.reason).toBeUndefined();
    expect(b.reason).toBeUndefined();
    expect(fx.eventsNamed("session.receive.taken_by_sibling")).toHaveLength(0);
    // Tier 0's logging is what survives, and it still fires for both readers.
    expect(fx.eventsNamed("session.receive.delivered").length).toBeGreaterThanOrEqual(2);
  });
});
