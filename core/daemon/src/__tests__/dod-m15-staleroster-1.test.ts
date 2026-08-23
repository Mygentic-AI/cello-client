/**
 * DOD-M15-STALEROSTER-1 — a stale reading refuses to present itself as current.
 *
 * ─── What was measured, twice, on two machines ─────────────────────────────────────────────────
 *
 * Both daemons displayed directory node failures from minutes long past while `curl` reached all
 * three nodes in 37–184 ms. The operator is debugging an outage that ended before they looked.
 *
 * ─── The producer/consumer map, CORRECTED after review ─────────────────────────────────────────
 *
 * This header first claimed `resolveConsortiumRoster` had ONE caller — the failover path — so the
 * sweep ran only while the daemon was unhealthy. **False.** It has ten callers: the failover
 * resolver, four session and seal ceremony handlers, the auto-ack broker reconnect, `cello_refresh`,
 * `cello_get_submission_results`, three cross-node session-setup paths and the seal broker.
 *
 * The real shape is **an IDLE daemon never re-measures**. Every caller is activity-driven, so the
 * reading is refreshed by ceremonies and session setup and by nothing else — and sitting idle is
 * what a daemon does between conversations. The measured symptom is a failing reading seeded at boot
 * that nothing afterwards overwrote.
 *
 * ─── And the harder half: absent and healthy look identical ────────────────────────────────────
 *
 * The block was emitted only when the failure list was non-empty, so "nothing has ever looked"
 * rendered exactly like "all three nodes answered".
 *
 * The first draft of this file blamed an EXPIRED manifest for that state. Also false — a daemon
 * whose manifest fails verification REFUSES TO START (ADV-002). The one reachable route is no
 * manifest provider at all, which is DESIGNED: local dev, the e2e harness, or a CELLO_DIRECTORY_URL
 * that is not byte-equal to a bundled endpoint. It gets its own calm wording, because an alarm there
 * would fire on every local run.
 *
 * The line forbids the tempting fix: *"Do not fix it by hiding the field when stale — absent and
 * healthy must not look alike."* So the reading declares its own age instead.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { startDaemon, connectToDaemon, type DaemonHandle, type DaemonConfig } from "../index.js";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import {
  classifyRosterReading,
  describeRosterFreshness,
  startRosterSweep,
  ROSTER_STALE_AFTER_MS,
  ROSTER_SWEEP_INTERVAL_MS,
} from "../roster-freshness.js";

const NOW = Date.parse("2026-08-23T12:00:00.000Z");
const iso = (msAgo: number): string => new Date(NOW - msAgo).toISOString();

describe("DOD-M15-STALEROSTER-1: classifying the age of a reading", () => {
  it("a reading taken seconds ago is fresh", () => {
    const r = classifyRosterReading(iso(3_000), NOW);
    expect(r.kind).toBe("fresh");
    expect(r.kind === "fresh" && r.ageMs).toBe(3_000);
  });

  it("★ a reading older than the staleness bound is STALE, not fresh", () => {
    // The measured defect: minutes-old failures presented as the present tense.
    const r = classifyRosterReading(iso(ROSTER_STALE_AFTER_MS + 1_000), NOW);
    expect(
      r.kind,
      "a reading older than the bound was reported as current — this is the defect measured twice " +
        "on two machines, where a daemon showed node failures from minutes past while curl reached " +
        "all three nodes in under 200 ms",
    ).toBe("stale");
  });

  it("the boundary belongs to fresh — exactly at the bound is not yet stale", () => {
    expect(classifyRosterReading(iso(ROSTER_STALE_AFTER_MS), NOW).kind).toBe("fresh");
    expect(classifyRosterReading(iso(ROSTER_STALE_AFTER_MS + 1), NOW).kind).toBe("stale");
  });

  it("★ never measured is its OWN kind — it is not 'fresh and clean'", () => {
    /**
     * The half that is easy to miss: with no reading at all, treating the empty failure list as
     * health tells an operator their directory is fine when the daemon has never once looked.
     *
     * (This comment used to say an EXPIRED manifest reaches here. It does not — that daemon refuses
     * to start. See the file header.)
     */
    expect(classifyRosterReading(null, NOW).kind).toBe("never_measured");
  });

  it("a reading from the FUTURE is not treated as infinitely fresh", () => {
    // Clock skew, a restored snapshot, or an operator changing the system clock. A negative age
    // must not be allowed to satisfy the freshness bound forever.
    const r = classifyRosterReading(new Date(NOW + 60_000).toISOString(), NOW);
    expect(r.kind, "a future timestamp is not a measurement of the present").toBe("stale");
  });

  it("an unparseable timestamp is stale, never fresh", () => {
    expect(classifyRosterReading("not-a-date", NOW).kind).toBe("stale");
  });
});

describe("DOD-M15-STALEROSTER-1: what the operator is told", () => {
  it("★ a stale reading says so IN THE READING, and keeps the failures visible", () => {
    /**
     * *"Do not fix it by hiding the field when stale — absent and healthy must not look alike."*
     * Suppression would trade a wrong answer for no answer, and no answer renders as health.
     */
    const d = describeRosterFreshness(classifyRosterReading(iso(9 * 60_000), NOW));
    expect(d.stale, "the reading must declare its own staleness").toBe(true);
    expect(d.age_seconds).toBe(540);
    expect(d.checked_at).toBe(iso(9 * 60_000));
    expect(
      d.freshness_guidance,
      "it must warn that the failures listed may already be over, or the operator debugs an " +
        "outage that ended before they looked",
    ).toMatch(/may no longer be true|already have recovered/i);
  });

  it("a fresh reading is NOT decorated — a marker on the normal case is not a marker", () => {
    const d = describeRosterFreshness(classifyRosterReading(iso(2_000), NOW));
    expect(d.stale, "every reading carrying a staleness flag trains the reader to ignore it").toBe(false);
    expect(d.freshness_guidance).toBeUndefined();
  });

  it("★ never-measured WITH a manifest is an alarm: nothing has finished looking", () => {
    // Different facts need different words: "stale" means we looked a while ago; "never" means no
    // sweep has completed. A manifest IS configured here, so this one is worth worrying about.
    const d = describeRosterFreshness(classifyRosterReading(null, NOW), { manifestConfigured: true });
    expect(d.measurement).toBe("never");
    expect(d.stale).toBe(true);
    expect(d.checked_at).toBeNull();
    expect(d.age_seconds).toBeNull();
    // THE CLAIM, not the token (review F-weak): /never/i passed on "we never got around to it".
    expect(
      d.freshness_guidance,
      "it must say the absence of failures is not evidence of health",
    ).toMatch(/not evidence of health/i);
    expect(
      d.freshness_guidance,
      "and route to the cause when it persists",
    ).toMatch(/directory\.roster\.sweep\.failed/);
  });

  it("★ never-measured with NO manifest is CALM — it is a designed configuration, not a fault", () => {
    /**
     * Review F2. The first cut treated every unmeasured daemon as an alarm, which fires on every
     * local-dev run and every e2e-harness spin-up: a signal on the designed normal case, which this
     * same unit forbids elsewhere. It still EMITS — the line rules out hiding the field — but it
     * must not read as breakage.
     */
    const d = describeRosterFreshness(classifyRosterReading(null, NOW), { manifestConfigured: false });
    expect(d.measurement).toBe("not_configured");
    expect(d.stale, "there is no reading to be stale — nothing is being measured at all").toBe(false);
    expect(
      d.freshness_guidance,
      "it must name the real reachable cause: no consortium manifest is configured",
    ).toMatch(/no consortium manifest is configured/i);
    expect(
      d.freshness_guidance,
      "and the trap that produces it against a REAL directory — a hostname is not byte-equal to a " +
        "bundled endpoint, which silently turns directory identity authentication off too",
    ).toMatch(/byte-equal/i);
    expect(
      d.freshness_guidance,
      "it must NOT blame an expired manifest: that daemon refuses to start, so this cause cannot " +
        "produce this state (review F1 — error substitution in brand-new operator prose)",
    ).not.toMatch(/EXPIRED/);
    expect(
      d.freshness_guidance,
      "nor send the operator to a log family that has no lines on this path",
    ).not.toMatch(/directory\.auth\.manifest/);
  });

  it("★ a failing sweep reaches the RESPONSE, not just the log", () => {
    /**
     * Review F4, invariant 2. The freshness bound is 5 minutes and the sweep runs every 90–180 s, so
     * the first two or three consecutive failures all land while the reading still reports
     * stale:false — the operator is handed a frozen reading presented as current, which is this
     * line's own defect arriving through the fix's failure path.
     */
    const d = describeRosterFreshness(classifyRosterReading(iso(2_000), NOW), {
      manifestConfigured: true,
      lastSweepError: { event: "directory.roster.sweep.failed", error: "dns exploded", at: iso(1_000), consecutive: 2 },
    });
    expect(d.stale, "PRECONDITION: still inside the freshness bound — this is the blind window").toBe(false);
    expect(
      d.last_sweep_error,
      "a sweep that has failed twice running is invisible to the agent: the reading still says " +
        "fresh, and the only account of the failure is a log line nobody is reading",
    ).toBeDefined();
    expect(d.last_sweep_error?.error).toContain("dns exploded");
    expect(d.last_sweep_error?.consecutive).toBe(2);
  });
});

describe("DOD-M15-STALEROSTER-1: the interval and the bound are not just a comment", () => {
  it("★ a healthy daemon cannot flap between fresh and stale", () => {
    /**
     * Review F3 — the unit's load-bearing arithmetic was asserted by nothing but a header comment.
     * Changing ROSTER_SWEEP_INTERVAL_MS from 90_000 to 900_000 (one extra zero) left every test in
     * the repo green while making every healthy production daemon permanently stale.
     *
     * Worst case between two writes = the scheduler's MAX interval + the slowest sweep. The
     * randomized scheduler is constructed with max = 2x the interval, and the patient probe's
     * ceiling is 20 s, so that is the number the bound has to beat.
     */
    const worstSweepMs = 20_000; // PERSISTENT_PROBE total ceiling, directory-bootstrap.ts
    const worstGapMs = ROSTER_SWEEP_INTERVAL_MS * 2 + worstSweepMs;
    expect(
      worstGapMs,
      `The slowest possible gap between two roster measurements (${worstGapMs} ms) exceeds the ` +
        `staleness bound (${ROSTER_STALE_AFTER_MS} ms), so a HEALTHY daemon goes stale between ` +
        "sweeps. cello_status would then warn about a reading that is doing exactly what it is " +
        "supposed to do — a signal that fires on the normal case.",
    ).toBeLessThan(ROSTER_STALE_AFTER_MS);
  });
});

describe("DOD-M15-STALEROSTER-1: the sweep runs even when nothing is broken", () => {
  const scheduler = () => {
    let pending: (() => Promise<void>) | null = null;
    return {
      scheduleNext(fn: () => Promise<void>) {
        pending = fn;
      },
      cancel() {
        pending = null;
      },
      async fire() {
        const fn = pending;
        pending = null;
        if (fn) await fn();
      },
      get armed() {
        return pending !== null;
      },
    };
  };

  it("★ the sweep re-arms itself, so a healthy daemon keeps measuring", async () => {
    /**
     * THE ACTUAL FIX. Before this, the only caller of the sweep was the failover path, so a daemon
     * that recovered stopped measuring and the last failing reading became permanent.
     */
    const s = scheduler();
    const sweep = vi.fn().mockResolvedValue(undefined);
    startRosterSweep({ scheduler: s, sweep, logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() } });

    expect(s.armed, "the sweep must be armed at startup").toBe(true);
    await s.fire();
    expect(sweep).toHaveBeenCalledTimes(1);
    expect(s.armed, "and re-armed after it runs, or it measures exactly once and freezes again").toBe(true);
    await s.fire();
    expect(sweep).toHaveBeenCalledTimes(2);
  });

  it("★ a sweep that THROWS still re-arms — one bad probe must not stop the clock forever", async () => {
    /**
     * The failure mode that would reintroduce the exact defect being fixed, silently: a rejected
     * sweep that skips the re-arm leaves the reading frozen with nothing in the log saying
     * measurement has stopped.
     */
    const s = scheduler();
    const sweep = vi.fn().mockRejectedValue(new Error("dns exploded"));
    const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn() };
    startRosterSweep({ scheduler: s, sweep, logger });

    await s.fire();
    expect(s.armed, "a throwing sweep stopped the clock — the reading freezes and nothing says so").toBe(true);
    expect(logger.error, "and the failure must be LOUD, not swallowed").toHaveBeenCalled();
    const [event, ctx] = logger.error.mock.calls[0] as [string, Record<string, unknown>];
    expect(event).toBe("directory.roster.sweep.failed");
    expect(String(ctx["error"]), "the upstream cause must survive into the log").toContain("dns exploded");
  });

  it("stopping cancels the schedule and prevents a re-arm from an in-flight sweep", async () => {
    const s = scheduler();
    let stop: (() => void) | null = null;
    const sweep = vi.fn().mockImplementation(async () => {
      stop?.();
    });
    stop = startRosterSweep({ scheduler: s, sweep, logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() } });

    await s.fire();
    expect(
      s.armed,
      "a sweep that completes after shutdown re-armed the timer, which keeps a stopped daemon " +
        "probing the network",
    ).toBe(false);
  });
});

describe("DOD-M15-STALEROSTER-1: a real daemon that has never measured does not read as healthy", () => {
  let dir: string;
  let handle: DaemonHandle | null = null;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "m15-staleroster-"));
  });
  afterEach(async () => {
    if (handle) await handle.stop("graceful").catch(() => {});
    handle = null;
    await rm(dir, { recursive: true, force: true });
  });

  it("★ cello_status reports the roster as UNMEASURED rather than omitting the block", async () => {
    /**
     * The end-to-end shape of the second half. This daemon has no consortium manifest, so the
     * startup gate returns without sweeping — the same code path an EXPIRED manifest takes.
     *
     * Before this unit the block was emitted only when the failure list was non-empty, so this
     * daemon reported no directory trouble at all: byte-identical to a daemon whose three nodes had
     * just answered. An operator reading that concludes the directory is fine while the daemon has
     * never once looked.
     */
    handle = await startDaemon({
      securityGateway: new PassthroughGatewayClient(),
      celloDir: dir,
      socketPath: join(dir, "daemon.sock"),
      lockFilePath: join(dir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger: { debug() {}, info() {}, warn() {}, error() {} },
    } as DaemonConfig);

    const c = await connectToDaemon(join(dir, "daemon.sock"));
    await c.send("ipc.connect", { clientType: "mcp" });
    const status = (await c.send("cello_status", {})) as Record<string, unknown>;
    c.close();

    const block = status["directory_endpoints_unresolved"] as Record<string, unknown> | undefined;
    expect(
      block,
      "the block was omitted, so a daemon that has NEVER measured directory reachability is " +
        "indistinguishable from one whose nodes all answered a moment ago",
    ).toBeDefined();
    expect(
      block?.["measurement"],
      "this daemon has NO manifest provider, which is the designed local-dev configuration — it " +
        "must be reported as not-configured rather than as a fault",
    ).toBe("not_configured");
    expect(block?.["checked_at"], "there is no measurement, so there is no timestamp").toBeNull();
    expect(
      String(block?.["freshness_guidance"]),
      "and it must name the real cause rather than the expired-manifest story, which cannot " +
        "produce this state because that daemon refuses to start",
    ).toMatch(/no consortium manifest is configured/i);

    /**
     * THE VALUE, not its absence — hollow-test question 4 and review F8. The original asserted only
     * `.not.toMatch(/could not resolve these directory endpoints/)`, which `guidance: ""` passes,
     * and so does `guidance: "all nodes healthy"` — the exact reading this block exists to prevent.
     */
    const guidance = String(block?.["guidance"]);
    expect(
      guidance,
      "the empty node list must be stated as an UNKNOWN, not left to read as an all-clear",
    ).toMatch(/not mean the nodes are healthy/i);
    expect(
      guidance,
      "and it must not claim endpoints failed to resolve — none are listed",
    ).not.toMatch(/could not\s+resolve these directory endpoints/);
  }, 30_000);
});

describe("DOD-M15-STALEROSTER-1: the daemon actually STARTS the sweep", () => {
  /**
   * THE REVERT TEST FOUND THIS GAP, and it is the one that mattered.
   *
   * Disabling the daemon's sweep wiring entirely — `const rosterSweepScheduler = false && …` — left
   * all thirteen tests above green. They proved `startRosterSweep` re-arms; nothing proved the
   * daemon ever called it. The whole point of the line is that a HEALTHY daemon keeps measuring, and
   * that was the untested half.
   *
   * The scheduler is injectable for exactly this reason, following `registryPollScheduler`.
   */
  let tempDir: string;
  let handle: DaemonHandle | null = null;

  const manifest = () => {
    const hour = 3_600_000;
    return {
      version: 1,
      not_before: new Date(Date.now() - hour).toISOString(),
      expires: new Date(Date.now() + hour).toISOString(),
      // A closed local port, so the probe refuses immediately rather than waiting on a timeout.
      nodes: [{ nodeId: "dead-1", pubkey: "b".repeat(64), region: "us-east-1", provider: "aws", endpoint: "http://127.0.0.1:1" }],
      signatures: [{ officerIndex: 0, signature: "c".repeat(128) }],
    };
  };

  /** A scheduler that hands the tick back so the test drives it, instead of waiting 90 seconds. */
  function controllable() {
    let pending: (() => Promise<void>) | null = null;
    return {
      scheduleNext(fn: () => Promise<void>) { pending = fn; },
      cancel() { pending = null; },
      async fire() { const f = pending; pending = null; if (f) await f(); },
      get armed() { return pending !== null; },
    };
  }

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "m15-staleroster-wired-"));
  });
  afterEach(async () => {
    if (handle) await handle.stop("test_cleanup").catch(() => {});
    handle = null;
    await rm(tempDir, { recursive: true, force: true });
  });

  it("★ a daemon with a manifest arms the sweep at startup and re-arms it after each tick", async () => {
    const sched = controllable();
    handle = await startDaemon({
      securityGateway: new PassthroughGatewayClient(),
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger: { debug() {}, info() {}, warn() {}, error() {} },
      manifestProvider: {
        loadAndVerify: vi.fn(async () => manifest()),
        getCurrentManifest: vi.fn(() => manifest()),
        updateManifest: vi.fn(),
      },
      manifestRootKeys: ["a".repeat(64)],
      manifestThreshold: 1,
      rosterSweepScheduler: sched,
    } as unknown as DaemonConfig);

    expect(
      sched.armed,
      "the daemon never armed the roster sweep, so the reading freezes the moment the failover " +
        "path stops being taken — the exact defect this line reports",
    ).toBe(true);

    const c = await connectToDaemon(join(tempDir, "daemon.sock"));
    await c.send("ipc.connect", { clientType: "mcp" });
    const before = (await c.send("cello_status", {})) as Record<string, unknown>;
    const beforeAt = (before["directory_endpoints_unresolved"] as Record<string, unknown>)["checked_at"];

    // One tick of the background sweep — the thing that could not happen before this unit.
    await sched.fire();
    expect(sched.armed, "and it must re-arm, or it measures exactly once and freezes again").toBe(true);

    const after = (await c.send("cello_status", {})) as Record<string, unknown>;
    c.close();
    const afterAt = (after["directory_endpoints_unresolved"] as Record<string, unknown>)["checked_at"];

    expect(
      afterAt,
      "the sweep ran but the reading did not move — cello_status is still answering from the boot " +
        "measurement, which is what 'frozen' means",
    ).not.toBe(beforeAt);
  }, 30_000);
});

describe("DOD-M15-STALEROSTER-1: a slower sweep cannot overwrite a newer reading", () => {
  /**
   * Review F6, and the finding my wrong producer/consumer map hid. Believing there was ONE writer
   * is exactly why I did not ask what happens when two sweeps overlap — and they now do, routinely:
   * the background sweep uses the patient probe (up to ~16 s) while the failover resolver uses
   * FAST_PROBE (2 s), on a timer that fires every 90-180 s.
   *
   * The write stamped COMPLETION, so whichever finished last won and was labelled "measured now,
   * 0 seconds old". A slow-but-healthy node flips in and out of the block and every version of it
   * claims to be current.
   */
  it("★ a sweep that STARTED earlier but finished later is discarded for the reading", async () => {
    const { createConsortiumRouting } = await import("../consortium-bootstrap.js");
    const events: string[] = [];
    const logger = {
      debug: () => {}, info: (e: string) => events.push(e), warn: () => {}, error: () => {},
    };

    // Node "slow" takes 60ms to answer; "fast" answers immediately. Two overlapping sweeps.
    const manifest = {
      version: 1,
      not_before: new Date(Date.now() - 3_600_000).toISOString(),
      expires: new Date(Date.now() + 3_600_000).toISOString(),
      nodes: [{ nodeId: "n1", pubkey: "b".repeat(64), region: "r", provider: "p", endpoint: "http://127.0.0.1:1" }],
      signatures: [{ officerIndex: 0, signature: "c".repeat(128) }],
    };

    let delayMs = 0;
    const routing = createConsortiumRouting({
      manifestProvider: {
        loadAndVerify: async () => manifest,
        getCurrentManifest: () => manifest,
        updateManifest: () => {},
      },
      logger,
      fetchFn: (async () => {
        await new Promise((r) => setTimeout(r, delayMs));
        throw new Error("refused");
      }) as unknown as typeof fetch,
    } as never);

    // Sweep A starts first and is SLOW.
    delayMs = 80;
    const slow = routing.resolveConsortiumRoster();
    await new Promise((r) => setTimeout(r, 10));
    // Sweep B starts later and is FAST — it lands first and its reading is the newer measurement.
    delayMs = 0;
    await routing.resolveConsortiumRoster();
    const afterFast = routing.getUnresolvedSweptAt();
    await slow;
    const afterSlow = routing.getUnresolvedSweptAt();

    expect(
      afterSlow,
      "the slower sweep -- which began BEFORE the one already recorded -- overwrote the newer " +
        "reading and stamped it as current, so cello_status reports a measurement older than the " +
        "one it discarded while claiming it is the freshest available",
    ).toBe(afterFast);
    expect(
      events,
      "and the discard must be stated, not silent — a sweep whose result went nowhere is exactly " +
        "the kind of thing that reads as a bug six months later",
    ).toContain("directory.roster.sweep.superseded");
  }, 30_000);
});

describe("DOD-M15-STALEROSTER-1: a sweep that measured nothing does not report success", () => {
  it("★ no verified manifest is stated, not silently treated as a clean sweep", async () => {
    /**
     * Review F13 (pre-existing, surfaced by this unit). `resolveConsortiumRoster` returned null
     * before the write AND before any log when there was no current manifest, so "there was nothing
     * to probe" and "everything probed fine" produced identical observable behaviour: no failures,
     * no error, no change to the reading.
     *
     * That was harmless while the only callers were activity-driven and had their own error paths.
     * It stops being harmless the moment a background timer calls it every 90 seconds: the sweep
     * ticks forever, never throws, never moves the reading, and reports nothing at all. A sweep that
     * succeeds at doing nothing is the silent-fallback shape this milestone keeps finding.
     */
    const { createConsortiumRouting } = await import("../consortium-bootstrap.js");
    const warned: Array<{ event: string; ctx: Record<string, unknown> }> = [];
    const routing = createConsortiumRouting({
      manifestProvider: {
        loadAndVerify: async () => null,
        // No CURRENT manifest — the state the early return exists for.
        getCurrentManifest: () => null,
        updateManifest: () => {},
      },
      logger: {
        debug: () => {},
        info: () => {},
        warn: (event: string, ctx?: Record<string, unknown>) => warned.push({ event, ctx: ctx ?? {} }),
        error: () => {},
      },
    } as never);

    const before = routing.getUnresolvedSweptAt();
    const result = await routing.resolveConsortiumRoster();

    expect(result, "no manifest means no roster — null, not an empty success").toBeNull();
    expect(
      routing.getUnresolvedSweptAt(),
      "and the reading must NOT be stamped as freshly measured: nothing was measured",
    ).toBe(before);
    expect(
      warned.map((w) => w.event),
      "a sweep that measured nothing must say so — otherwise the background timer succeeds every " +
        "90 seconds forever while the reading never moves, and nothing anywhere records why",
    ).toContain("directory.roster.sweep.no_manifest");
    expect(
      String(warned[0]?.ctx["impact"]),
      "and it must name the consequence, not just the condition",
    ).toMatch(/keeps whatever reading it already had/i);
  }, 30_000);
});

describe("DOD-M15-STALEROSTER-1: a sweep completing after shutdown acts on nothing", () => {
  it("★ a sweep still running when stop() lands does not fire callbacks or log", async () => {
    /**
     * Review F10. A sweep takes up to ~16s with a node down and the cycle is 90-180s, so a stop()
     * arriving mid-sweep is ordinary rather than exotic. Before this, the completing sweep still ran
     * its callbacks and still logged — against a daemon that had already reported itself stopped.
     * In-process that means writing through a logger whose test has finished.
     */
    let pending: (() => Promise<void>) | null = null;
    const sched = {
      scheduleNext(fn: () => Promise<void>) { pending = fn; },
      cancel() { pending = null; },
      async fire() { const f = pending; pending = null; if (f) await f(); },
      get armed() { return pending !== null; },
    };

    const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn() };
    const onSweepError = vi.fn();
    const onSweepSuccess = vi.fn();
    let stop: (() => void) | null = null;

    stop = startRosterSweep({
      scheduler: sched,
      // The sweep throws, AND the daemon stops while it is in flight.
      sweep: async () => { stop?.(); throw new Error("network gone"); },
      logger,
      onSweepError,
      onSweepSuccess,
    });

    await sched.fire();

    expect(
      onSweepError,
      "a sweep that failed after shutdown wrote its error into the status surface of a daemon " +
        "that no longer exists",
    ).not.toHaveBeenCalled();
    expect(
      logger.error,
      "and logged through a logger whose owner has already torn down",
    ).not.toHaveBeenCalled();
    expect(sched.armed, "and it must not re-arm a stopped sweep").toBe(false);
  });
});

describe("DOD-M15-STALEROSTER-1: the background sweep uses the PATIENT probe", () => {
  it("★ swapping the sweep to FAST_PROBE is caught", async () => {
    /**
     * Review F7. Nothing asserted the budget, so changing `resolveConsortiumRoster()` to
     * `resolveConsortiumRoster(FAST_PROBE)` in the daemon left every test green.
     *
     * It matters because the two budgets answer different questions. FAST_PROBE (2 s per attempt)
     * exists ONLY because the failover resolver runs inside the 10 s signaling wait — it is a
     * deadline imposed by the caller, not a judgement about how long a healthy node may take.
     * Nothing waits on the background sweep, so borrowing that deadline would mark a slow but
     * perfectly healthy node "unresolved" and put it in the operator's status block. This unit
     * exists to stop the status block lying about node reachability; using the impatient budget
     * would make it lie in a new direction.
     *
     * DOD-M15-BOOTSTRAP-1's own review record notes a budget regression here already "moved rather
     * than went away" once, which is why this is pinned rather than trusted to a comment.
     */
    const { createConsortiumRouting } = await import("../consortium-bootstrap.js");
    const { PERSISTENT_PROBE } = await import("../directory-bootstrap.js");

    const manifest = {
      version: 1,
      not_before: new Date(Date.now() - 3_600_000).toISOString(),
      expires: new Date(Date.now() + 3_600_000).toISOString(),
      nodes: [{ nodeId: "n1", pubkey: "b".repeat(64), region: "r", provider: "p", endpoint: "http://127.0.0.1:1" }],
      signatures: [{ officerIndex: 0, signature: "c".repeat(128) }],
    };

    // Count probe attempts. PERSISTENT_PROBE allows more attempts than FAST_PROBE, so the attempt
    // count distinguishes the two budgets without reaching into private state.
    let attempts = 0;
    const routing = createConsortiumRouting({
      manifestProvider: {
        loadAndVerify: async () => manifest,
        getCurrentManifest: () => manifest,
        updateManifest: () => {},
      },
      logger: { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} },
      fetchFn: (async () => {
        attempts++;
        throw new Error("ECONNREFUSED");
      }) as unknown as typeof fetch,
    } as never);

    // Exactly how the daemon calls it for the background sweep: no budget argument, so the
    // module default (PERSISTENT_PROBE) applies.
    await routing.resolveConsortiumRoster();
    const patientAttempts = attempts;

    attempts = 0;
    const { FAST_PROBE } = await import("../directory-bootstrap.js");
    await routing.resolveConsortiumRoster(FAST_PROBE);
    const fastAttempts = attempts;

    expect(
      PERSISTENT_PROBE.attempts,
      "PRECONDITION: the two budgets must actually differ in attempts, or this test cannot tell " +
        "them apart and would pass on the regression it exists to catch",
    ).toBeGreaterThan(FAST_PROBE.attempts);
    expect(
      patientAttempts,
      "the background sweep is using the impatient budget meant for the failover path's 10 s " +
        "deadline, so a slow-but-healthy node will be reported unresolved in cello_status",
    ).toBeGreaterThan(fastAttempts);
  }, 30_000);

  it("★ and the DAEMON calls it that way — asserted at the wiring, not just the function", async () => {
    /**
     * The lesson from the wiring gap this unit already hit once: proving `resolveConsortiumRoster`
     * defaults to the patient budget says nothing about how the daemon INVOKES it. Mutating
     * `sweep: () => resolveConsortiumRoster()` to `resolveConsortiumRoster(FAST_PROBE)` leaves the
     * function-level test above perfectly green.
     *
     * So this drives a real daemon tick and counts the probes that actually leave.
     */
    const { PERSISTENT_PROBE, FAST_PROBE } = await import("../directory-bootstrap.js");
    const dir2 = await mkdtemp(join(tmpdir(), "m15-staleroster-budget-"));
    let pending: (() => Promise<void>) | null = null;
    const sched = {
      scheduleNext(fn: () => Promise<void>) { pending = fn; },
      cancel() { pending = null; },
      async fire() { const f = pending; pending = null; if (f) await f(); },
    };
    const manifest = {
      version: 1,
      not_before: new Date(Date.now() - 3_600_000).toISOString(),
      expires: new Date(Date.now() + 3_600_000).toISOString(),
      nodes: [{ nodeId: "n1", pubkey: "b".repeat(64), region: "r", provider: "p", endpoint: "http://127.0.0.1:1" }],
      signatures: [{ officerIndex: 0, signature: "c".repeat(128) }],
    };
    let attempts = 0;
    const h = await startDaemon({
      securityGateway: new PassthroughGatewayClient(),
      celloDir: dir2,
      socketPath: join(dir2, "daemon.sock"),
      lockFilePath: join(dir2, "daemon.lock"),
      maxConnections: 8,
      version: "0.0.1-test",
      logger: { debug() {}, info() {}, warn() {}, error() {} },
      manifestProvider: {
        loadAndVerify: async () => manifest,
        getCurrentManifest: () => manifest,
        updateManifest: () => {},
      },
      manifestRootKeys: ["a".repeat(64)],
      manifestThreshold: 1,
      rosterSweepScheduler: sched,
      fetchFn: (async () => { attempts++; throw new Error("ECONNREFUSED"); }) as unknown as typeof fetch,
    } as unknown as DaemonConfig);

    try {
      attempts = 0; // discard the startup sweep; measure only the BACKGROUND tick
      await sched.fire();
      expect(
        attempts,
        `The background sweep spent ${attempts} probe attempts on one node. FAST_PROBE allows ` +
          `${FAST_PROBE.attempts} and PERSISTENT_PROBE allows ${PERSISTENT_PROBE.attempts}: this is ` +
          "the impatient budget, which exists only because the failover resolver runs inside a 10 s " +
          "signaling deadline. Nothing waits on this sweep, and borrowing that deadline reports " +
          "slow-but-healthy nodes as unresolved in cello_status.",
      ).toBeGreaterThan(FAST_PROBE.attempts);
    } finally {
      await h.stop("test_cleanup").catch(() => {});
      await rm(dir2, { recursive: true, force: true });
    }
  }, 30_000);
});
