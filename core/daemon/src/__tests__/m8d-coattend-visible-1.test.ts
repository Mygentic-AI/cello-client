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

  it("C1 (AC1): the session that lost the race is told a SIBLING took it — a machine-readable reason, not prose", async () => {
    await fx.createSession(SID, "alice");
    const connA = await fx.connectAs("alice");
    const connB = await fx.connectAs("alice");

    await fx.ingestReceived("alice", SID, "from bob");

    // A wins the race and DRAINS the shared buffer (today's behavior, unchanged by this line).
    const won = (await connA.send("cello_receive", { session_id: SID, timeout_ms: 500 })) as Record<string, unknown>;
    expect(won.content).toBe("from bob");

    // B polls an empty buffer and times out. Today it is told, verbatim, what a quiet counterparty
    // produces. It must instead be told that a sibling connection consumed a message it never saw.
    const lost = (await connB.send("cello_receive", { session_id: SID, timeout_ms: 100 })) as Record<string, unknown>;
    expect(lost.ok).toBe(true);
    expect(lost.content).toBeNull();

    // THE DISCRIMINATOR. `reason` is the field this return already uses to discriminate its other
    // branch (`counterparty_gone`), so a caller that switches on it needs no new shape.
    expect(lost.reason).toBe("taken_by_sibling_session");
    expect(lost.taken_by_sibling).toMatchObject({ count: 1, last_sequence: 0 });
    expect((lost.taken_by_sibling as Record<string, unknown>).connections).toHaveLength(1);

    // Prose is the PRESENTATION of the discriminator, so it must also differ — but the assertion
    // above is what makes this a fix rather than a rewording.
    expect(String(lost.guidance)).toMatch(/another|sibling|session/i);
    expect(String(lost.guidance)).not.toMatch(/^No content arrived within timeout_ms/);
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

  it("C3 (AC3): the blocking receive logs on BOTH outcomes, and a theft is a WARN", async () => {
    await fx.createSession(SID, "alice");
    const connA = await fx.connectAs("alice");
    const connB = await fx.connectAs("alice");

    await fx.ingestReceived("alice", SID, "from bob");
    await connA.send("cello_receive", { session_id: SID, timeout_ms: 500 });
    await connB.send("cello_receive", { session_id: SID, timeout_ms: 100 });
    // A third receive on a session with nothing outstanding — the plain empty outcome.
    await connA.send("cello_receive", { session_id: SID, timeout_ms: 100 });

    const delivered = fx.eventsNamed("session.receive.delivered");
    expect(delivered).toHaveLength(1);
    expect(delivered[0].ctx).toMatchObject({ sessionId: SID, agentName: "alice", sequenceNumber: 0, attendance: 2 });
    expect(delivered[0].ctx.connectionId).toBeTruthy();
    expect(delivered[0].ctx.correlationId).toBeTruthy();

    const stolen = fx.eventsNamed("session.receive.taken_by_sibling");
    expect(stolen).toHaveLength(1);
    // A theft is not routine bookkeeping — it must be findable at WARN, the level the operator greps.
    expect(stolen[0].level).toBe("warn");
    expect(stolen[0].ctx).toMatchObject({ sessionId: SID, agentName: "alice", takenCount: 1, lastTakenSeq: 0, attendance: 2 });
    // The taking connection is named, so the log ALONE reconstructs the race.
    expect(Array.isArray(stolen[0].ctx.takenBy)).toBe(true);
    expect((stolen[0].ctx.takenBy as string[])[0]).not.toBe(stolen[0].ctx.connectionId);

    const empty = fx.eventsNamed("session.receive.empty");
    expect(empty).toHaveLength(1);
    expect(empty[0].ctx).toMatchObject({ sessionId: SID, agentName: "alice", timeoutMs: 100 });

    // INV-CONTENTFREE: none of the three carries the message or anything derived from it.
    for (const e of [...delivered, ...stolen, ...empty]) {
      expect(JSON.stringify(e.ctx)).not.toMatch(/from bob/);
    }
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

  it("C7: the discriminator reports UNSEEN content — it clears once the loser catches up", async () => {
    await fx.createSession(SID, "alice");
    const connA = await fx.connectAs("alice");
    const connB = await fx.connectAs("alice");

    await fx.ingestReceived("alice", SID, "from bob");
    await connA.send("cello_receive", { session_id: SID, timeout_ms: 500 });

    const lost = (await connB.send("cello_receive", { session_id: SID, timeout_ms: 100 })) as Record<string, unknown>;
    expect(lost.reason).toBe("taken_by_sibling_session");

    // B catches up through the documented door. The content is no longer unseen by B, so a second
    // empty receive is now a genuinely quiet counterparty — and must say so.
    await connB.send("cello_get_transcript", { session_id: SID });

    const quietNow = (await connB.send("cello_receive", { session_id: SID, timeout_ms: 100 })) as Record<string, unknown>;
    expect(quietNow.reason).toBeUndefined();
    expect(String(quietNow.guidance)).toMatch(/No content arrived within timeout_ms/);
  });
});
