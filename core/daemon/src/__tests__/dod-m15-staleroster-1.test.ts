/**
 * DOD-M15-STALEROSTER-1 — a stale reading refuses to present itself as current.
 *
 * ─── What was measured, twice, on two machines ─────────────────────────────────────────────────
 *
 * Both daemons displayed directory node failures from minutes long past while `curl` reached all
 * three nodes in 37–184 ms. The operator is debugging an outage that ended before they looked.
 *
 * ─── The producer/consumer map, which says why it freezes ──────────────────────────────────────
 *
 *   PRODUCER   `resolveConsortiumRoster` (consortium-bootstrap.ts) — the ONLY writer of
 *              `unresolvedNodes` / `unresolvedSweptAt`.
 *   CALLER     exactly one: `createRosterAwareEndpointResolver`'s `getConsortiumRoster`, i.e. the
 *              FAILOVER path.
 *   CONSUMER   `unresolvedNodesForStatus` in daemon.ts.
 *
 * So the sweep runs only while the daemon is UNHEALTHY. The moment the primary resolves again, the
 * failover path stops being taken, no sweep ever runs, and the reading freezes at the last failing
 * measurement — permanently, for the life of the process.
 *
 * ─── And the harder half: absent and healthy look identical ────────────────────────────────────
 *
 * The block is emitted only when the failure list is non-empty, so "no sweep has ever run" renders
 * exactly like "all three nodes answered". That is not hypothetical: `verifyStartupManifest` returns
 * WITHOUT sweeping on four paths — no manifest configured, a manifest that is not yet valid, an
 * EXPIRED manifest, and a version rollback. A daemon whose consortium manifest has expired reports
 * no directory trouble whatsoever.
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
     * The half that is easy to miss. `verifyStartupManifest` returns without sweeping on four
     * paths, including an EXPIRED manifest. With no reading at all, treating the empty failure list
     * as health tells an operator their directory is fine when the daemon has never once looked.
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

  it("★ never-measured says NOT MEASURED — it does not borrow the word 'stale'", () => {
    // Different facts need different words: "stale" means we looked a while ago; "never measured"
    // means we have never looked. Only the second can hide an expired manifest.
    const d = describeRosterFreshness(classifyRosterReading(null, NOW));
    expect(d.stale).toBe(true);
    expect(d.checked_at).toBeNull();
    expect(d.age_seconds).toBeNull();
    expect(
      d.freshness_guidance,
      "and it must name the reason this happens — the startup manifest gate returned without " +
        "sweeping, which an expired manifest causes",
    ).toMatch(/never/i);
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
    expect(block?.["stale"], "an unmeasured reading must not present as current").toBe(true);
    expect(block?.["checked_at"], "there is no measurement, so there is no timestamp").toBeNull();
    expect(
      String(block?.["freshness_guidance"]),
      "and it must say nothing has looked, naming the expired-manifest cause",
    ).toMatch(/NEVER measured/);
    expect(
      String(block?.["guidance"]),
      "the node guidance must not claim endpoints failed to resolve — none are listed",
    ).not.toMatch(/could not\s+resolve these directory endpoints/);
  }, 30_000);
});
