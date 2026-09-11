import { describe, it, expect } from "vitest";
import { createCollapsingLogger, LOG_COLLAPSE_MAX_KEYS, STORM_BURST, STORM_WINDOW_MS } from "../log-collapse.js";
import type { Logger } from "../types.js";

/**
 * DOD-M15-LOGBOUND-1, part A — a FLOODING log line is written once and then COUNTED.
 *
 * The measured file that produced this order was 180 MB, and 95% of it was one line repeated
 * 413,590 times. The disk was the smaller half: that loop hid behind its own output for eleven
 * hours.
 *
 * The gate is a RATE and not a count, and the tests that matter most here are the ones that prove
 * what is NOT suppressed — an ordinary handful of repeats, and a slow chronic failure. A first
 * build gated on count alone turned a three-attempt retry into one line and a once-an-hour failure
 * into silence, which is a worse defect than the noise it removed.
 */

function recorder(): { sink: Logger; lines: { level: string; event: string; ctx: Record<string, unknown> }[] } {
  const lines: { level: string; event: string; ctx: Record<string, unknown> }[] = [];
  const push = (level: string) => (event: string, ctx: Record<string, unknown>) => {
    lines.push({ level, event, ctx });
  };
  return { sink: { debug: push("debug"), info: push("info"), warn: push("warn"), error: push("error") }, lines };
}

/** The storm's real payload shape, including the `attempt` counter the retry chain carries. */
const STORM = {
  agentName: "Mac_Coder_1",
  sessionId: "1643d35ed9c35162b4eae6f65066d3f7",
  reason: "stream_failed",
  errorName: "Error",
  errorCode: "ERR_STREAM",
  impact: "this side's half of the session key never reached the counterparty",
};

describe("DOD-M15-LOGBOUND-1 A: what is NOT suppressed", () => {
  it("a bounded retry that fails three times prints THREE lines, not one", () => {
    const { sink, lines } = recorder();
    let clock = 0;
    const log = createCollapsingLogger(sink, () => clock);

    // The confirmed regression in the first build. An operator whose standing receiver cannot
    // bind must be able to tell a retry that ran from a retry that never fired.
    for (let attempt = 0; attempt < 3; attempt++) {
      clock += 500;
      log.error("session.node.create.failed", {
        sessionId: "standing_receiver_9603a541",
        agentName: "standing_receiver:bob",
        reason: "bind_failed",
        error: "listen EADDRINUSE: address already in use",
      });
    }

    expect(lines.length).toBe(3);
  });

  it("everything below the burst threshold is written in full", () => {
    const { sink, lines } = recorder();
    let clock = 0;
    const log = createCollapsingLogger(sink, () => clock);

    for (let i = 0; i < STORM_BURST; i++) {
      clock += 100;
      log.error("session.key.announce.failed", { ...STORM });
    }

    expect(lines.length).toBe(STORM_BURST);
    expect(lines.every((l) => l.ctx["repeatedCount"] === undefined)).toBe(true);
  });

  it("a CHRONIC failure — once an hour, forever — is never suppressed", () => {
    const { sink, lines } = recorder();
    let clock = 0;
    const log = createCollapsingLogger(sink, () => clock);

    // A hundred hours of a sweep failing once an hour. Under a count-based gate this would print
    // on the 1st, 10th and 100th and be silent for the four days in between.
    for (let hour = 0; hour < 100; hour++) {
      clock += 3_600_000;
      log.warn("trust_signal.sweep.failed", { sessionId: "sweep", reason: "node_unreachable" });
    }

    expect(lines.length).toBe(100);
  });

  it("a periodic event on a timer is not suppressed, whatever its payload does", () => {
    const { sink, lines } = recorder();
    let clock = 0;
    const log = createCollapsingLogger(sink, () => clock);

    // `transport.connections.observed` carries a connection total that changes. It fires on a
    // timer, so it never floods, so every value is written.
    for (let total = 1; total <= 300; total++) {
      clock += 5_000;
      log.debug("transport.connections.observed", { sessionId: "standing_receiver_b1b15eb5", reason: "tick", total });
    }

    expect(lines.length).toBe(300);
    expect(lines[299]?.ctx["total"]).toBe(300);
  });

  it("a hundred DIFFERENT sessions emitting the same event once each produce a hundred lines", () => {
    const { sink, lines } = recorder();
    const log = createCollapsingLogger(sink, () => 0);

    for (let i = 0; i < 100; i++) log.error("session.key.announce.failed", { ...STORM, sessionId: `session-${i}` });

    // The fan-out is the shape you most need to see. Reporting it as "x100" would be strictly
    // worse than the noise this unit removes.
    expect(lines.length).toBe(100);
  });

  it("the same event and session under a DIFFERENT reason is a different fact", () => {
    const { sink, lines } = recorder();
    let clock = 0;
    const log = createCollapsingLogger(sink, () => clock);

    for (let i = 0; i < 200; i++) {
      clock += 10;
      log.error("session.key.announce.failed", { ...STORM, reason: i % 2 === 0 ? "stream_failed" : "peer_unreachable" });
    }

    // Two independent storms, each gated on its own rate — never merged into one count.
    const reasons = new Set(lines.map((l) => l.ctx["reason"]));
    expect(reasons).toEqual(new Set(["stream_failed", "peer_unreachable"]));
  });

  it("the same event and session at a different LEVEL is a different fact", () => {
    const { sink, lines } = recorder();
    const log = createCollapsingLogger(sink, () => 0);

    log.warn("session.key.announce.failed", { ...STORM });
    log.error("session.key.announce.failed", { ...STORM });

    expect(lines.length).toBe(2);
  });

  it("the first occurrence of any event is never suppressed", () => {
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
    for (let i = 0; i < 500; i++) log.debug("directory.signaling.connected", { directoryNodeId: "gcp-usc1" });

    expect(lines.length).toBe(500);
  });
});

describe("DOD-M15-LOGBOUND-1 A: what IS suppressed, and how it reports itself", () => {
  it("400,000 occurrences at the measured rate become a readable handful (Done When 1)", () => {
    const { sink, lines } = recorder();
    let clock = 0;
    const log = createCollapsingLogger(sink, () => clock);

    for (let attempt = 0; attempt < 400_000; attempt++) {
      clock += 250; // the measured storm was ~4/second
      log.error("session.key.announce.failed", { ...STORM, attempt });
    }

    // 20 written in full, the 21st announcing the collapse, then the 10th/100th/1,000th/
    // 10,000th/100,000th suppressed occurrence.
    expect(lines.length).toBeLessThan(30);
    expect(lines.length).toBeGreaterThan(STORM_BURST);
  });

  it("a milestone carries the MOST RECENT payload, so a field that changed mid-fold is visible", () => {
    const { sink, lines } = recorder();
    let clock = 0;
    const log = createCollapsingLogger(sink, () => clock);

    for (let attempt = 0; attempt < 200; attempt++) {
      clock += 50;
      log.error("session.key.announce.failed", { ...STORM, attempt });
    }

    // This is the documented mitigation for keying on event+session+reason rather than the whole
    // payload: the varying field is not lost, it is republished at each milestone.
    const milestone = lines.filter((l) => typeof l.ctx["repeatedCount"] === "number").pop();
    expect(milestone?.ctx["attempt"]).toBeGreaterThan(100);
  });

  it("an `attempt` counter in the payload does NOT defeat the collapse", () => {
    const { sink, lines } = recorder();
    let clock = 0;
    const log = createCollapsingLogger(sink, () => clock);

    // The event this unit exists for carries a per-iteration counter. Keying on the whole payload
    // looked tighter and would have collapsed nothing at all on the one path that produced 168 MB.
    for (let attempt = 0; attempt < 5_000; attempt++) {
      clock += 60;
      log.error("session.key.announce.failed", { ...STORM, attempt });
    }

    expect(lines.length).toBeLessThan(30);
  });

  it("the line that trips the gate SAYS that lines behind it are being dropped", () => {
    const { sink, lines } = recorder();
    let clock = 0;
    const log = createCollapsingLogger(sink, () => clock);

    for (let i = 0; i <= STORM_BURST; i++) {
      clock += 100;
      log.error("session.key.announce.failed", { ...STORM });
    }

    // An operator should never have to infer that the log is dropping lines.
    const tripped = lines[lines.length - 1];
    expect(tripped?.ctx["repeatsCollapsing"]).toBe(true);
    expect(tripped?.ctx["repeatRatePerWindow"]).toBeGreaterThan(STORM_BURST);
  });

  it("the closing line's window is the FLOOD, not the flood plus the silence that ended it", () => {
    const { sink, lines } = recorder();
    let clock = 0;
    const log = createCollapsingLogger(sink, () => clock);

    // 500 lines at 50ms — 20/second, over 25 seconds.
    for (let i = 0; i < 500; i++) { clock += 50; log.error("e", { sessionId: "s", reason: "r" }); }
    clock += 6 * 60 * 60 * 1000; // six hours of silence
    log.error("e", { sessionId: "s", reason: "r" });

    // Fold the idle gap into the elapsed time and 19 lines/second is reported as 1.3 an hour —
    // a trickle, when it was the storm. This is the one line the redesign added for diagnosis.
    const closing = lines.find((l) => l.ctx["repeatEnded"] === true);
    expect(closing?.ctx["repeatWindowMs"] as number).toBeLessThan(30_000);
  });

  it("suppression does NOT latch — a flood that backs off starts printing again", () => {
    const { sink, lines } = recorder();
    let clock = 0;
    const log = createCollapsingLogger(sink, () => clock);

    // Trip the gate fast.
    for (let i = 0; i < 30; i++) { clock += 100; log.error("e", { sessionId: "s", reason: "r" }); }
    const afterBurst = lines.length;

    // Then back off to one every nine seconds — never idle for a full window, so the only exit
    // from suppression would be silence that never comes. Under a latching gate these 200
    // occurrences over half an hour produce two or three lines: the chronic-failure silence this
    // redesign exists to remove, re-entered through a different door.
    for (let i = 0; i < 200; i++) { clock += 9_000; log.error("e", { sessionId: "s", reason: "r" }); }

    expect(lines.length - afterBurst).toBeGreaterThan(100);
  });

  it("every milestone names the count so far AND how long the run has been going (Done When 1)", () => {
    const { sink, lines } = recorder();
    let clock = 0;
    const log = createCollapsingLogger(sink, () => clock);

    for (let i = 0; i < 2_000; i++) {
      clock += 100;
      log.error("session.key.announce.failed", { ...STORM });
    }

    const milestones = lines.filter((l) => typeof l.ctx["repeatedCount"] === "number");
    expect(milestones.length).toBeGreaterThan(0);
    for (const m of milestones) {
      expect(typeof m.ctx["repeatWindowMs"]).toBe("number");
      expect(m.ctx["repeatWindowMs"] as number).toBeGreaterThan(0);
    }
  });

  it("when the flood STOPS, the total is reported rather than left dangling", () => {
    const { sink, lines } = recorder();
    let clock = 0;
    const log = createCollapsingLogger(sink, () => clock);

    for (let i = 0; i < 500; i++) {
      clock += 50;
      log.error("session.key.announce.failed", { ...STORM });
    }
    // Quiet for longer than a window, then one more occurrence.
    clock += STORM_WINDOW_MS * 2;
    log.error("session.key.announce.failed", { ...STORM });

    const closing = lines.find((l) => l.ctx["repeatEnded"] === true);
    expect(closing).toBeDefined();
    expect(closing?.ctx["repeatedCount"]).toBeGreaterThan(400);
  });

  it("after a flood ends, the SAME key floods again and is reported again from scratch", () => {
    const { sink, lines } = recorder();
    let clock = 0;
    const log = createCollapsingLogger(sink, () => clock);

    const burst = (): void => {
      for (let i = 0; i < 200; i++) { clock += 50; log.error("e", { sessionId: "s", reason: "r" }); }
    };
    burst();
    clock += STORM_WINDOW_MS * 3;
    const before = lines.length;
    burst();

    // A second storm is a second fact. It must not inherit the first one's suppression.
    expect(lines.length - before).toBeGreaterThan(STORM_BURST);
  });
});

describe("DOD-M15-LOGBOUND-1 A: the table cannot become the thing it removes", () => {
  it("the collapse table is BOUNDED — an overrun forgets the oldest run", () => {
    const { sink, lines } = recorder();
    let clock = 0;
    const log = createCollapsingLogger(sink, () => clock);

    // Put one key into a fold, then overrun the table with keys that never repeat.
    for (let i = 0; i <= STORM_BURST * 2; i++) { clock += 50; log.error("victim", { sessionId: "v", reason: "r" }); }
    for (let i = 0; i < LOG_COLLAPSE_MAX_KEYS * 2; i++) {
      clock += 1;
      log.error("filler", { sessionId: `s-${i}`, reason: "r" });
    }
    const before = lines.filter((l) => l.event === "victim").length;
    log.error("victim", { sessionId: "v", reason: "r" });

    // The observable consequence of the bound: the victim's run is gone, so its next occurrence
    // is a FIRST occurrence again — written in full, not folded. Without eviction it would still
    // be suppressed and this line would not appear.
    const after = lines.filter((l) => l.event === "victim");
    expect(after.length).toBe(before + 1);
    expect(after[after.length - 1]?.ctx["repeatedCount"]).toBeUndefined();
  });

  it("a run evicted MID-FOLD reports its total rather than taking it away", () => {
    const { sink, lines } = recorder();
    let clock = 0;
    const log = createCollapsingLogger(sink, () => clock);

    for (let i = 0; i < 500; i++) { clock += 20; log.error("victim", { sessionId: "v", reason: "r" }); }
    for (let i = 0; i < LOG_COLLAPSE_MAX_KEYS * 2; i++) {
      clock += 1;
      log.error("filler", { sessionId: `s-${i}`, reason: "r" });
    }

    const closing = lines.find((l) => l.event === "victim" && l.ctx["repeatEnded"] === true);
    expect(closing).toBeDefined();
    expect(closing?.ctx["repeatedCount"]).toBeGreaterThan(400);
  });

  it("eviction is LRU, so a FLOODING key survives a stream of single-use keys", () => {
    const { sink, lines } = recorder();
    let clock = 0;
    const log = createCollapsingLogger(sink, () => clock);

    // Get the storm key into suppression.
    for (let i = 0; i <= STORM_BURST * 2; i++) { clock += 50; log.error("storm", { ...STORM }); }
    const countBefore = lines.filter((l) => l.event === "storm").length;

    // Now push far more single-use keys through the table than it can hold, interleaving the
    // storm so it stays recently-used. Under insertion-order eviction the storm key is dropped
    // and its count restarts — the one number that made the storm diagnosable, destroyed.
    for (let i = 0; i < LOG_COLLAPSE_MAX_KEYS * 2; i++) {
      clock += 1;
      log.error("session.tree.appended", { sessionId: `s-${i}`, reason: "appended" });
      log.error("storm", { ...STORM });
    }

    const stormLines = lines.filter((l) => l.event === "storm");
    const counts = stormLines.map((l) => l.ctx["repeatedCount"]).filter((c): c is number => typeof c === "number");
    // Still one run: the counts only ever climb, never restart.
    expect(stormLines.length - countBefore).toBeLessThan(10);
    expect(counts).toEqual([...counts].sort((a, b) => a - b));
  });

  it("a fold that simply STOPS is closed out without needing its own next occurrence", () => {
    const { sink, lines } = recorder();
    let clock = 0;
    const log = createCollapsingLogger(sink, () => clock);

    for (let i = 0; i < 500; i++) { clock += 20; log.error("dead.storm", { sessionId: "d", reason: "r" }); }
    // The cause is fixed and that key never fires again. Some OTHER key keeps logging.
    clock += STORM_WINDOW_MS * 2;
    for (let i = 0; i < 3; i++) { clock += 100; log.info("something.else", { sessionId: `o-${i}`, reason: "r" }); }

    // Without the amortised sweep the last word on the measured 413,590-line storm would have been
    // repeatedCount: 100000 — understating it fourfold, with nothing saying it had ended.
    const closing = lines.find((l) => l.event === "dead.storm" && l.ctx["repeatEnded"] === true);
    expect(closing).toBeDefined();
    expect(closing?.ctx["repeatedCount"]).toBeGreaterThan(400);
  });
});
