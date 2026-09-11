import { describe, it, expect } from "vitest";
import { createCollapsingLogger, LOG_COLLAPSE_MAX_KEYS } from "../log-collapse.js";
import type { Logger } from "../types.js";

/**
 * DOD-M15-LOGBOUND-1, part A — a repeating log line is written once and then COUNTED.
 *
 * The measured file that produced this order was 176 MB, and 95% of it was one byte-identical
 * line repeated 413,589 times. The disk was the smaller half: that loop hid behind its own
 * output for eleven hours.
 */

function recorder(): { sink: Logger; lines: { level: string; event: string; ctx: Record<string, unknown> }[] } {
  const lines: { level: string; event: string; ctx: Record<string, unknown> }[] = [];
  const push = (level: string) => (event: string, ctx: Record<string, unknown>) => {
    lines.push({ level, event, ctx });
  };
  return { sink: { debug: push("debug"), info: push("info"), warn: push("warn"), error: push("error") }, lines };
}

/** The storm, exactly as it appeared: same event, same session, same reason, every time. */
const STORM = {
  agentName: "Mac_Coder_1",
  sessionId: "1643d35ed9c35162b4eae6f65066d3f7",
  reason: "stream_failed",
  impact: "this side's half of the session key never reached the counterparty",
};

describe("DOD-M15-LOGBOUND-1 A: repeated lines collapse to first + order-of-magnitude milestones", () => {
  it("writes a line repeated 400,000 times six times, not 400,000 times (Done When 1)", () => {
    const { sink, lines } = recorder();
    let clock = 1_000;
    const log = createCollapsingLogger(sink, () => clock);

    for (let i = 0; i < 400_000; i++) {
      clock += 250; // the measured storm was ~4/second
      log.error("session.key.announce.failed", { ...STORM });
    }

    // 1st, 10th, 100th, 1,000th, 10,000th, 100,000th — six writes for 400,000 occurrences.
    expect(lines.length).toBe(6);
    expect(lines.map((l) => l.ctx["repeatedCount"])).toEqual([undefined, 10, 100, 1_000, 10_000, 100_000]);
  });

  it("every milestone names the count so far AND how long the run has been going (Done When 1)", () => {
    const { sink, lines } = recorder();
    let clock = 0;
    const log = createCollapsingLogger(sink, () => clock);

    for (let i = 0; i < 100; i++) {
      log.error("session.key.announce.failed", { ...STORM });
      clock += 1_000;
    }

    const tenth = lines[1];
    expect(tenth?.ctx["repeatedCount"]).toBe(10);
    // First occurrence at t=0, tenth at t=9,000.
    expect(tenth?.ctx["repeatWindowMs"]).toBe(9_000);
    expect(lines[2]?.ctx["repeatWindowMs"]).toBe(99_000);
  });

  it("a hundred DIFFERENT sessions emitting the same event once each produce a hundred lines (Done When 2)", () => {
    const { sink, lines } = recorder();
    const log = createCollapsingLogger(sink, () => 0);

    for (let i = 0; i < 100; i++) {
      log.error("session.key.announce.failed", { ...STORM, sessionId: `session-${i}` });
    }

    // The fan-out is the shape you most need to see. Reporting it as "x100" would be strictly
    // worse than the noise this unit removes.
    expect(lines.length).toBe(100);
    expect(lines.every((l) => l.ctx["repeatedCount"] === undefined)).toBe(true);
  });

  it("the same event and session under a DIFFERENT reason is a different fact (Done When 2)", () => {
    const { sink, lines } = recorder();
    const log = createCollapsingLogger(sink, () => 0);

    log.error("session.key.announce.failed", { ...STORM, reason: "stream_failed" });
    log.error("session.key.announce.failed", { ...STORM, reason: "peer_unreachable" });

    expect(lines.length).toBe(2);
  });

  it("the same event and session at a different LEVEL is a different fact", () => {
    const { sink, lines } = recorder();
    const log = createCollapsingLogger(sink, () => 0);

    log.warn("session.key.announce.failed", { ...STORM });
    log.error("session.key.announce.failed", { ...STORM });

    expect(lines.length).toBe(2);
  });

  it("the first occurrence of any event is never suppressed (Done When 3)", () => {
    const { sink, lines } = recorder();
    const log = createCollapsingLogger(sink, () => 0);

    for (let i = 0; i < 50; i++) log.info(`event.number.${i}`, { sessionId: "s", reason: "r" });

    expect(lines.length).toBe(50);
  });

  it("a line carrying NEITHER a sessionId NOR a reason does not collapse at all", () => {
    const { sink, lines } = recorder();
    const log = createCollapsingLogger(sink, () => 0);

    // The key cannot be built from what this call site passes. Losing the saving is correct
    // where losing the distinction is not — so it is written every time, as today.
    for (let i = 0; i < 25; i++) log.debug("transport.connections.observed", { total: 1, inbound: 0 });

    expect(lines.length).toBe(25);
  });

  it("passes the payload through unchanged on a first occurrence", () => {
    const { sink, lines } = recorder();
    const log = createCollapsingLogger(sink, () => 0);

    log.error("session.key.announce.failed", { ...STORM });

    expect(lines[0]?.ctx).toEqual(STORM);
    expect(lines[0]?.ctx["repeatedCount"]).toBeUndefined();
  });

  it("a milestone carries the MOST RECENT context, so a field that changed mid-run is still visible", () => {
    const { sink, lines } = recorder();
    const log = createCollapsingLogger(sink, () => 0);

    for (let i = 0; i < 10; i++) {
      log.error("session.key.announce.failed", { ...STORM, correlationId: `corr-${i}` });
    }

    // The key is event+session+reason and deliberately NOT the whole line: a retry loop that
    // minted a fresh correlationId per attempt would otherwise collapse nothing, which is
    // exactly the storm shape. The milestone republishes the latest context so the varying
    // field is not lost.
    expect(lines[1]?.ctx["correlationId"]).toBe("corr-9");
  });

  it("a periodic event whose NUMBER is changing is not folded into one line", () => {
    const { sink, lines } = recorder();
    const log = createCollapsingLogger(sink, () => 0);

    // The realistic near-miss. `transport.connections.observed` carries a session id and reports a
    // connection total on a timer. Keyed on event and session alone, a total climbing to 300 would
    // read as one line saying "x300" and the only thing worth seeing would be gone.
    for (let total = 1; total <= 300; total++) {
      log.debug("transport.connections.observed", { sessionId: "standing_receiver_b1b15eb5", total });
    }

    expect(lines.length).toBe(300);
    expect(lines[299]?.ctx["total"]).toBe(300);
  });

  it("a flapping value collapses per VALUE, so a stuck loop is still cheap", () => {
    const { sink, lines } = recorder();
    const log = createCollapsingLogger(sink, () => 0);

    // 2,000 observations alternating between two totals: two runs, each collapsing on its own.
    for (let i = 0; i < 2_000; i++) {
      log.debug("transport.connections.observed", { sessionId: "s", total: i % 2 });
    }

    // 1,000 occurrences of each value: 1st, 10th, 100th, 1,000th — eight lines, not 2,000.
    expect(lines.length).toBe(8);
  });

  it("the collapse table is BOUNDED — it cannot become the unbounded thing it removes", () => {
    const { sink, lines } = recorder();
    const log = createCollapsingLogger(sink, () => 0);

    for (let i = 0; i < LOG_COLLAPSE_MAX_KEYS * 3; i++) {
      log.error("event.with.many.keys", { sessionId: `s-${i}`, reason: "r" });
    }

    // Every one is a first occurrence and every one is written; the point is that the table
    // holding them does not grow without limit.
    expect(lines.length).toBe(LOG_COLLAPSE_MAX_KEYS * 3);
  });

  it("evicting a key re-reports the next occurrence as a first, never silently drops it", () => {
    const { sink, lines } = recorder();
    const log = createCollapsingLogger(sink, () => 0);

    log.error("storm", { ...STORM });
    // Push the storm key out of the table.
    for (let i = 0; i < LOG_COLLAPSE_MAX_KEYS; i++) log.error("filler", { sessionId: `f-${i}`, reason: "r" });
    const before = lines.length;
    log.error("storm", { ...STORM });

    // Over-reporting on eviction is the safe direction; silence is not.
    expect(lines.length).toBe(before + 1);
  });
});
