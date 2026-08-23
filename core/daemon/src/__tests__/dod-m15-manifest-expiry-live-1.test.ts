/**
 * DOD-M15-MANIFEST-EXPIRY-LIVE-1 — a running daemon notices its own trust anchor expiring.
 *
 * ─── What is actually unchecked ────────────────────────────────────────────────────────────────
 *
 * The consortium manifest's validity window is enforced in exactly one place: `verifyStartupManifest`,
 * at boot. After that, **nothing looks at it again for the life of the process.**
 *
 *   `consortium-bootstrap.ts` — `expiresAt <= now` → refuse to start. STARTUP ONLY.
 *   `http-manifest-poll.ts`   — `new Date(manifest.expires) <= now` → refuse to ADOPT. This checks
 *                               the manifest being FETCHED, never the one already held.
 *
 * And the second one makes it worse rather than better: a daemon whose held manifest has expired
 * keeps polling, keeps refusing to adopt anything expired, and keeps using the expired anchor it
 * already has. The check that exists reads as if this were covered.
 *
 * Worse still on the PRODUCTION DEFAULT: the bundled-manifest path wires **no poll scheduler at
 * all** (`manifest-deps.ts` — "the bundled roster is static"), so there is not even a fetch that
 * might have noticed.
 *
 * ─── Why an expired anchor matters, concretely ─────────────────────────────────────────────────
 *
 * The manifest is the trust anchor for directory identity authentication (step 6) and for the node
 * roster a threshold ceremony draws from. An expiry is not bookkeeping: past it, those signatures no
 * longer warrant the CURRENT consortium. A node removed for cause is still trusted by a daemon
 * holding the old manifest, and it is trusted silently.
 *
 * ─── What this deliberately does NOT do ────────────────────────────────────────────────────────
 *
 * It does not kill a running daemon at the expiry instant. Startup already fails closed, which is
 * the right place to refuse; tearing down a live daemon mid-conversation on a wall-clock boundary
 * trades a slow security decay for immediate, total unavailability — and would do it to every
 * operator simultaneously, since they share the bundled manifest's date. Runtime's job is to say so,
 * loudly, in the log AND in the response, early enough to act.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { startDaemon, connectToDaemon, type DaemonHandle, type DaemonConfig } from "../index.js";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import {
  classifyManifestValidity,
  describeManifestValidity,
  MANIFEST_EXPIRY_WARNING_MS,
} from "../manifest-validity.js";

const NOW = Date.parse("2026-08-23T12:00:00.000Z");
const at = (msFromNow: number): string => new Date(NOW + msFromNow).toISOString();
const DAY = 86_400_000;

const manifest = (over: { expires?: string; not_before?: string } = {}) => ({
  version: 2,
  not_before: over.not_before ?? at(-365 * DAY),
  expires: over.expires ?? at(365 * DAY),
  nodes: [],
  signatures: [],
});

describe("DOD-M15-MANIFEST-EXPIRY-LIVE-1: classifying a held manifest", () => {
  it("a manifest well inside its window is valid", () => {
    expect(classifyManifestValidity(manifest(), NOW).state).toBe("valid");
  });

  it("★ a manifest past its expiry is EXPIRED — the state nothing checked after boot", () => {
    const v = classifyManifestValidity(manifest({ expires: at(-1_000) }), NOW);
    expect(
      v.state,
      "the daemon is authenticating directories and drawing ceremony rosters from a manifest whose " +
        "signatures no longer warrant the current consortium, and nothing anywhere says so",
    ).toBe("expired");
  });

  it("★ a manifest inside the warning window says so BEFORE it expires", () => {
    /**
     * Warning only at the instant of expiry would be useless: the operator finds out when their
     * daemon is already running on a dead anchor. The window has to be long enough to rotate.
     */
    const v = classifyManifestValidity(manifest({ expires: at(MANIFEST_EXPIRY_WARNING_MS - DAY) }), NOW);
    expect(v.state).toBe("expiring_soon");
    expect(v.secondsRemaining).toBeGreaterThan(0);
  });

  it("outside the warning window it is plain valid — not a standing alarm", () => {
    // A warning that is always on is not a warning. This is the milestone's most repeated finding.
    const v = classifyManifestValidity(manifest({ expires: at(MANIFEST_EXPIRY_WARNING_MS + DAY) }), NOW);
    expect(v.state, "an alarm that fires for the whole life of a valid manifest is noise").toBe("valid");
  });

  it("a manifest whose window has not opened is its own state, not 'valid'", () => {
    expect(classifyManifestValidity(manifest({ not_before: at(DAY) }), NOW).state).toBe("not_yet_valid");
  });

  it("★ an UNPARSEABLE expiry is treated as expired, never as valid", () => {
    /**
     * `new Date("nonsense") <= now` is false, because every comparison with NaN is false — so the
     * startup check's own shape would wave a garbage timestamp through as if it were in-window.
     * Valid is the answer that costs security, so nothing unmeasurable may reach it.
     */
    const v = classifyManifestValidity(manifest({ expires: "not-a-date" }), NOW);
    expect(v.state, "a manifest with an unreadable expiry must not be treated as in-window").toBe("expired");
  });

  it("a null manifest is not_configured, and is not an alarm", () => {
    expect(classifyManifestValidity(null, NOW).state).toBe("not_configured");
  });
});

describe("DOD-M15-MANIFEST-EXPIRY-LIVE-1: what the operator is told", () => {
  it("a valid manifest contributes NOTHING to the status surface", () => {
    expect(describeManifestValidity(classifyManifestValidity(manifest(), NOW))).toBeUndefined();
  });

  it("★ an expired manifest names the consequence, not just the date", () => {
    const d = describeManifestValidity(classifyManifestValidity(manifest({ expires: at(-2 * DAY) }), NOW));
    expect(d?.["manifest_expired"]).toBe(true);
    expect(
      String(d?.["manifest_validity_guidance"]),
      "a date alone does not tell an operator what is now weaker — it must say the roster and the " +
        "directory identity check are running on an anchor that no longer warrants them",
    ).toMatch(/no longer/i);
    expect(
      String(d?.["manifest_validity_guidance"]),
      "and it must say the daemon KEEPS RUNNING, or the operator assumes it failed closed like " +
        "startup does",
    ).toMatch(/still running|has not stopped|keeps/i);
  });

  it("★ an expiring manifest gives a number of days, not an adjective", () => {
    const d = describeManifestValidity(
      classifyManifestValidity(manifest({ expires: at(3 * DAY) }), NOW),
    );
    expect(d?.["manifest_expires_in_days"]).toBe(3);
    expect(d?.["manifest_expired"]).toBe(false);
  });
});

describe("DOD-M15-MANIFEST-EXPIRY-LIVE-1: the check actually runs while the daemon runs", () => {
  it("★ a transition into expiry is logged ONCE, not on every check", async () => {
    /**
     * The check rides the roster sweep, which fires every 90-180 s. Logging on every tick would put
     * the same line in the log hundreds of times a day, which is how a real signal becomes scroll.
     * The transition is the event; the state is already in `cello_status`.
     */
    const { startManifestValidityWatch } = await import("../manifest-validity.js");
    const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn() };
    let now = NOW;
    const m = manifest({ expires: at(1_000) });

    const check = startManifestValidityWatch({
      getManifest: () => m,
      logger,
      now: () => now,
    });

    check();
    expect(logger.error, "still valid — nothing to say").not.toHaveBeenCalled();

    now = NOW + 5_000; // crossed the expiry
    check();
    expect(logger.error, "the crossing must be loud").toHaveBeenCalledTimes(1);
    expect(logger.error.mock.calls[0]?.[0]).toBe("directory.auth.manifest.expired.live");

    check();
    check();
    expect(
      logger.error,
      "the same expiry logged on every sweep tick would print hundreds of times a day and bury " +
        "itself — the transition is the event",
    ).toHaveBeenCalledTimes(1);
  });

  it("★ a manifest REPLACED with a valid one re-arms the warning", async () => {
    /**
     * The counterexample. Latching the transition must not make the warning fire-once-forever: an
     * operator who rotates the manifest and later lets the new one lapse has to hear about it again.
     */
    const { startManifestValidityWatch } = await import("../manifest-validity.js");
    const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn() };
    let now = NOW;
    let m = manifest({ expires: at(1_000) });

    const check = startManifestValidityWatch({ getManifest: () => m, logger, now: () => now });

    now = NOW + 5_000;
    check();
    expect(logger.error).toHaveBeenCalledTimes(1);

    // Rotated: a fresh manifest, well in-window.
    m = { ...manifest({ expires: at(400 * DAY) }), version: 3 };
    check();
    // ...which later lapses too.
    now = NOW + 401 * DAY;
    check();
    expect(
      logger.error,
      "the second manifest's expiry was swallowed because the latch never reset — an operator who " +
        "rotated once would never be warned again",
    ).toHaveBeenCalledTimes(2);
  });

  it("★ rotating to ANOTHER near-expiry manifest warns again, without passing through valid", async () => {
    /**
     * The revert test found this gap: collapsing the latch key to the bare STATE stayed green,
     * because the test above happens to pass through a valid state in between, which resets a bare
     * latch just as well as a keyed one.
     *
     * The case that separates them has no valid state in between — an operator warned that manifest
     * A expires in four days rotates to manifest B, which is itself already inside the warning
     * window (a stale artefact, or one minted with a short window). The state never leaves
     * `expiring_soon`, so a bare latch says nothing and the operator believes they have fixed it.
     * The key includes the expiry date for exactly this.
     */
    const { startManifestValidityWatch } = await import("../manifest-validity.js");
    const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn() };
    let m = manifest({ expires: at(4 * DAY) });
    const check = startManifestValidityWatch({ getManifest: () => m, logger, now: () => NOW });

    check();
    expect(logger.warn, "PRECONDITION: manifest A must warn").toHaveBeenCalledTimes(1);

    // Rotated to a DIFFERENT manifest that is also inside the warning window. Still expiring_soon.
    m = manifest({ expires: at(2 * DAY) });
    check();

    expect(
      logger.warn,
      "the replacement manifest is ALSO about to expire and nothing said so, because the latch " +
        "keyed on the state alone and the state never changed. The operator rotated, saw silence, " +
        "and concluded they were fine.",
    ).toHaveBeenCalledTimes(2);
    expect(logger.warn.mock.calls[1]?.[1]?.["expiresAt"]).toBe(at(2 * DAY));
  });
});

describe("DOD-M15-MANIFEST-EXPIRY-LIVE-1: the DAEMON surfaces it, not just the module", () => {
  /**
   * Asserted at the wiring, first time rather than after a revert test catches it. Twice in this
   * milestone a module-level test has proved a helper works while nothing proved the daemon calls
   * it — once for the roster sweep, once for its probe budget. Both were invisible until the guard
   * was deleted and the suite stayed green.
   */
  let dir: string;
  let handle: DaemonHandle | null = null;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "m15-manifest-expiry-"));
  });
  afterEach(async () => {
    if (handle) await handle.stop("test_cleanup").catch(() => {});
    handle = null;
    await rm(dir, { recursive: true, force: true });
  });

  /**
   * Boot VALID, then let the manifest lapse — which is the only way a daemon can reach this state,
   * and the reason the defect exists.
   *
   * A daemon cannot be started on an already-expired manifest: startup fails closed (ADV-002), and
   * an earlier draft of this test proved exactly that by failing. The real path is that the daemon
   * started while the manifest was in-window and kept running past the date, so `getCurrentManifest`
   * returns the lapsed one on every read after that. Swapping what the provider returns models the
   * passage of wall-clock time without making the test wait for it.
   */
  async function bootWith(expires: string): Promise<Record<string, unknown>> {
    const nodes = [{ nodeId: "n1", pubkey: "b".repeat(64), region: "r", provider: "p", endpoint: "http://127.0.0.1:1" }];
    const signatures = [{ officerIndex: 0, signature: "c".repeat(128) }];
    const notBefore = new Date(Date.now() - 400 * DAY).toISOString();
    // What startup verifies: in-window, so the daemon is allowed to run at all.
    const atBoot = { version: 1, not_before: notBefore, expires: new Date(Date.now() + 400 * DAY).toISOString(), nodes, signatures };
    // What the daemon holds later, once the clock has moved past the date under test.
    const held = { version: 1, not_before: notBefore, expires, nodes, signatures };
    let booted = false;
    const m = atBoot;
    void m;
    handle = await startDaemon({
      securityGateway: new PassthroughGatewayClient(),
      celloDir: dir,
      socketPath: join(dir, "daemon.sock"),
      lockFilePath: join(dir, "daemon.lock"),
      maxConnections: 8,
      version: "0.0.1-test",
      logger: { debug() {}, info() {}, warn() {}, error() {} },
      manifestProvider: {
        loadAndVerify: async () => atBoot,
        getCurrentManifest: () => (booted ? held : atBoot),
        updateManifest: () => {},
      },
      manifestRootKeys: ["a".repeat(64)],
      manifestThreshold: 1,
      fetchFn: (async () => { throw new Error("ECONNREFUSED"); }) as unknown as typeof fetch,
    } as unknown as DaemonConfig);

    booted = true; // time passes; the held manifest is now the one under test

    const c = await connectToDaemon(join(dir, "daemon.sock"));
    await c.send("ipc.connect", { clientType: "mcp" });
    const status = (await c.send("cello_status", {})) as Record<string, unknown>;
    c.close();
    return status;
  }

  it("★ a daemon running on an EXPIRED manifest says so in cello_status", async () => {
    /**
     * The manifest is loaded through an injected provider, which is how a daemon reaches this state
     * in life too: it started while the manifest was valid and kept running past the date. Startup's
     * own gate is not re-run, which is the entire defect.
     */
    const status = await bootWith(new Date(Date.now() - 2 * DAY).toISOString());

    expect(
      status["manifest_expired"],
      "the daemon is authenticating directories and drawing ceremony rosters from a lapsed anchor, " +
        "and cello_status reported nothing about it",
    ).toBe(true);
    const guidance = String(status["manifest_validity_guidance"]);
    expect(guidance, "it must name what is now weaker").toMatch(/no longer warrant/i);
    expect(
      guidance,
      "and it must warn against the obvious wrong move — restarting fails CLOSED, turning a " +
        "degraded daemon into a dead one",
    ).toMatch(/REFUSE to start|fails closed/i);
  }, 30_000);

  it("★ a healthy manifest contributes NOTHING to the status surface", async () => {
    const status = await bootWith(new Date(Date.now() + 400 * DAY).toISOString());
    expect(
      status["manifest_expired"],
      "a field present for the years a manifest is valid is furniture, and it teaches the reader " +
        "to skip the block that matters",
    ).toBeUndefined();
    expect(status["manifest_validity_guidance"]).toBeUndefined();
  }, 30_000);

  it("★ a manifest inside the warning window warns BEFORE the deadline", async () => {
    const status = await bootWith(new Date(Date.now() + 3 * DAY).toISOString());
    expect(status["manifest_expired"]).toBe(false);
    expect(status["manifest_expires_in_days"]).toBe(2); // floor of just-under-3 days
    expect(
      String(status["manifest_validity_guidance"]),
      "warning at the instant of expiry is useless — it must say rotation is needed and that the " +
        "daemon will keep running rather than failing closed",
    ).toMatch(/KEEPS RUNNING/i);
  }, 30_000);
});

describe("DOD-M15-MANIFEST-EXPIRY-LIVE-1: the gaps the review found in these tests", () => {
  let dir: string;
  let handle: DaemonHandle | null = null;

  beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), "m15-expiry-gaps-")); });
  afterEach(async () => {
    if (handle) await handle.stop("test_cleanup").catch(() => {});
    handle = null;
    await rm(dir, { recursive: true, force: true });
  });

  function controllable() {
    let pending: (() => Promise<void>) | null = null;
    return {
      scheduleNext(fn: () => Promise<void>) { pending = fn; },
      cancel() { pending = null; },
      async fire() { const f = pending; pending = null; if (f) await f(); },
    };
  }

  async function boot(heldExpires: string, heldNotBefore?: string) {
    const nodes = [{ nodeId: "n1", pubkey: "b".repeat(64), region: "r", provider: "p", endpoint: "http://127.0.0.1:1" }];
    const signatures = [{ officerIndex: 0, signature: "c".repeat(128) }];
    const okNotBefore = new Date(Date.now() - 400 * DAY).toISOString();
    const atBoot = { version: 1, not_before: okNotBefore, expires: new Date(Date.now() + 400 * DAY).toISOString(), nodes, signatures };
    const held = { version: 1, not_before: heldNotBefore ?? okNotBefore, expires: heldExpires, nodes, signatures };
    let booted = false;
    const events: Array<{ event: string; ctx: Record<string, unknown> }> = [];
    const sched = controllable();
    handle = await startDaemon({
      securityGateway: new PassthroughGatewayClient(),
      celloDir: dir,
      socketPath: join(dir, "daemon.sock"),
      lockFilePath: join(dir, "daemon.lock"),
      maxConnections: 8,
      version: "0.0.1-test",
      logger: {
        debug() {}, info() {},
        warn: (event: string, ctx?: Record<string, unknown>) => events.push({ event, ctx: ctx ?? {} }),
        error: (event: string, ctx?: Record<string, unknown>) => events.push({ event, ctx: ctx ?? {} }),
      },
      manifestProvider: {
        loadAndVerify: async () => atBoot,
        getCurrentManifest: () => (booted ? held : atBoot),
        updateManifest: () => {},
      },
      manifestRootKeys: ["a".repeat(64)],
      manifestThreshold: 1,
      rosterSweepScheduler: sched,
      fetchFn: (async () => { throw new Error("ECONNREFUSED"); }) as unknown as typeof fetch,
    } as unknown as DaemonConfig);
    booted = true;
    return { events, sched };
  }

  it("★ F1: the SWEEP TICK calls the check — the only unprompted signal there is", async () => {
    /**
     * Deleting `checkManifestValidity()` from the sweep left all sixteen tests green, because the
     * daemon-level ones read `cello_status`, which computes validity independently, and no tick ever
     * fired inside a 31 ms test.
     *
     * What that left unproven is the half that works when nobody is looking. The status field
     * requires an operator to run a command; the LOG LINE is the durable record and the only thing
     * that fires on its own — and in production it is delivered exclusively by that one deletable
     * line. My own test-file header claimed the wiring was asserted. It was asserted for the status
     * field and not for this.
     */
    const { events, sched } = await boot(new Date(Date.now() - 2 * DAY).toISOString());

    expect(
      events.map((e) => e.event),
      "PRECONDITION: nothing should have fired before the first tick",
    ).not.toContain("directory.auth.manifest.expired.live");

    await sched.fire();

    expect(
      events.map((e) => e.event),
      "the daemon never re-checked its trust anchor on the sweep tick, so the ONLY unprompted " +
        "signal that a live daemon is running on an expired manifest never fires. An operator who " +
        "does not happen to run cello_status is never told at all.",
    ).toContain("directory.auth.manifest.expired.live");
  }, 30_000);

  it("★ F2: the CLI status surface carries it too, not just the MCP one", async () => {
    /**
     * Two separate spread sites. `cello_status` is the MCP handler; `status` is what `cello status`
     * calls from the CLI, and it JSON-stringifies the whole response, so the fields do reach the
     * operator. Only the MCP one was asserted — deleting the CLI spread was green.
     *
     * Scenario: an operator with no MCP client attached, 40 days past expiry, runs `cello status`
     * and sees a roster block reporting `current` with nothing about the anchor.
     */
    await boot(new Date(Date.now() - 40 * DAY).toISOString());
    const c = await connectToDaemon(join(dir, "daemon.sock"));
    await c.send("ipc.connect", { clientType: "cli" });
    const cli = (await c.send("status", {})) as Record<string, unknown>;
    c.close();

    expect(
      cli["manifest_expired"],
      "`cello status` — the surface an operator without an MCP client uses — said nothing about a " +
        "trust anchor that lapsed 40 days ago",
    ).toBe(true);
    expect(String(cli["manifest_validity_guidance"])).toMatch(/no longer|NO ASSURANCE/i);
  }, 30_000);

  it("★ F8: the not_yet_valid path is reachable at RUNTIME, and now says so", async () => {
    /**
     * Review F8: nothing exercised this state past the classifier. It is reachable exactly one way —
     * startup and the poll both REFUSE a not-yet-valid manifest, so the only live route is the clock
     * moving BACKWARD past `not_before`: a wrong RTC, a VM resume, NTP not yet synced. Which is
     * precisely the case the guidance was written for, and precisely the case nothing tested.
     */
    const { events, sched } = await boot(
      new Date(Date.now() + 400 * DAY).toISOString(),
      new Date(Date.now() + 10 * DAY).toISOString(), // window opens in the future = clock went back
    );
    await sched.fire();

    const c = await connectToDaemon(join(dir, "daemon.sock"));
    await c.send("ipc.connect", { clientType: "mcp" });
    const status = (await c.send("cello_status", {})) as Record<string, unknown>;
    c.close();

    expect(status["manifest_not_yet_valid"]).toBe(true);
    expect(
      String(status["manifest_validity_guidance"]),
      "the overwhelmingly likely cause is this machine's clock, and the guidance must say so first",
    ).toMatch(/clock/i);
    expect(events.map((e) => e.event)).toContain("directory.auth.manifest.not.yet.valid.live");
  }, 30_000);

  it("★ F3 end-to-end: a MALFORMED not_before is reported, not waved through as valid", async () => {
    const { events, sched } = await boot(
      new Date(Date.now() + 400 * DAY).toISOString(),
      "2026-13-01T00:00:00Z", // month thirteen
    );
    await sched.fire();

    const c = await connectToDaemon(join(dir, "daemon.sock"));
    await c.send("ipc.connect", { clientType: "mcp" });
    const status = (await c.send("cello_status", {})) as Record<string, unknown>;
    c.close();

    expect(
      status["manifest_window_unreadable"],
      "a manifest whose not_before does not parse was classified as VALID and reported nothing — " +
        "the fail-open this unit's own comment claimed was impossible",
    ).toBe(true);
    expect(
      String(status["manifest_validity_guidance"]),
      "and it must say MALFORMED rather than stale — a different problem with a different fix",
    ).toMatch(/MALFORMED|cannot be parsed/i);
    expect(events.map((e) => e.event)).toContain("directory.auth.manifest.window.unreadable");
  }, 30_000);
});

describe("DOD-M15-MANIFEST-EXPIRY-LIVE-1: the warning window is pinned to something real", () => {
  it("★ F7: the window must outlast the gap between two checks", async () => {
    /**
     * Review F7. Every test expressed its input as `MANIFEST_EXPIRY_WARNING_MS ± DAY`, so the
     * relationships held at ANY value: raising 7 days to 365 left the whole suite green while making
     * the warning fire for the final YEAR of the bundled manifest's four-year window — furniture,
     * the exact anti-pattern this file's own comment names.
     *
     * Same shape as the fix one unit earlier, where one extra zero on the sweep interval was
     * likewise invisible.
     */
    const { ROSTER_SWEEP_INTERVAL_MS } = await import("../roster-freshness.js");
    const worstGapBetweenChecksMs = ROSTER_SWEEP_INTERVAL_MS * 2 + 20_000;
    expect(
      MANIFEST_EXPIRY_WARNING_MS,
      "the warning window is shorter than the worst gap between two checks, so a manifest could " +
        "pass from valid to expired without any tick ever observing expiring_soon — the warning " +
        "would simply never fire",
    ).toBeGreaterThan(worstGapBetweenChecksMs);
  });

  it("★ F7: and must be a small fraction of the shipped manifest's own window", async () => {
    const { BUNDLED_CONSORTIUM_MANIFEST } = await import("../bundled-consortium-manifest.js");
    const windowMs =
      Date.parse(BUNDLED_CONSORTIUM_MANIFEST.expires) - Date.parse(BUNDLED_CONSORTIUM_MANIFEST.not_before);
    expect(
      MANIFEST_EXPIRY_WARNING_MS / windowMs,
      `The warning window is ${((MANIFEST_EXPIRY_WARNING_MS / windowMs) * 100).toFixed(1)}% of the ` +
        "shipped manifest's entire validity period. A warning that is on for a meaningful fraction " +
        "of a manifest's life is furniture, not a warning, and it teaches the operator to skip the " +
        "block that matters.",
    ).toBeLessThan(0.02);
  });
});

describe("DOD-M15-MANIFEST-EXPIRY-LIVE-1: the remedy matches where the manifest came from", () => {
  /**
   * Review F5, and the revert test proved it was unheld: making every origin take the "rotate the
   * file" branch left the whole suite green.
   *
   * This is Invariant 2's third check — does the remedy WORK? On the bundled path there is no file
   * and no poll, so "rotate the manifest" is not an action that operator can perform, and the
   * workaround they reach for instead silently disables directory identity authentication.
   */
  const expired = () => classifyManifestValidity(manifest({ expires: at(-2 * DAY) }), NOW);

  it("★ the BUNDLED path is told to upgrade the package, and warned off the trap", () => {
    const g = String(describeManifestValidity(expired(), "bundled")?.["manifest_validity_guidance"]);
    expect(g, "there is no file to replace on this path").toMatch(/upgrade the @cello-protocol\/connect/i);
    expect(
      g,
      "and it must name the workaround that must NOT be used — repointing CELLO_DIRECTORY_URL " +
        "starts the daemon with directory identity authentication switched off, so a stuck operator " +
        "would 'fix' a security warning by disabling a security control",
    ).toMatch(/Do NOT repoint CELLO_DIRECTORY_URL/i);
    expect(g, "and must not tell them to replace a file that does not exist").not.toMatch(
      /Replace the manifest file/i,
    );
  });

  it("★ the FILE path is told to replace the file", () => {
    const g = String(describeManifestValidity(expired(), "file")?.["manifest_validity_guidance"]);
    expect(g).toMatch(/Replace the manifest file at CELLO_CONSORTIUM_MANIFEST/i);
    expect(g, "and must not send a file-path operator chasing a package upgrade").not.toMatch(
      /upgrade the @cello-protocol\/connect/i,
    );
  });
});

describe("DOD-M15-MANIFEST-EXPIRY-LIVE-1: no anchor at all is not the same as a healthy one", () => {
  it("★ not_configured says so instead of rendering identically to a valid manifest", () => {
    /**
     * Found by the NEXT unit's review. `describeManifestValidity` returned `undefined` for both
     * `valid` and `not_configured`, so a daemon holding no consortium manifest whatsoever looked
     * byte-identical to one holding a fully valid, in-window trust anchor.
     *
     * That is the same defect `STALEROSTER-1` was written to fix — absent and healthy must not look
     * alike — reintroduced one spread above the code fixing it, in the same status response.
     */
    const d = describeManifestValidity(classifyManifestValidity(null, NOW));
    expect(
      d,
      "a daemon with NO trust anchor reported exactly what a daemon with a healthy one reports: " +
        "nothing. The absence of an expiry warning read as evidence of a good manifest.",
    ).toBeDefined();
    expect(d?.["manifest_anchor"]).toBe("none");
    expect(
      String(d?.["manifest_validity_guidance"]),
      "and it must say the silence is not evidence of health",
    ).toMatch(/not evidence of a healthy/i);
  });

  it("a VALID manifest still contributes nothing — the rule is not abandoned, only scoped", () => {
    expect(describeManifestValidity(classifyManifestValidity(manifest(), NOW))).toBeUndefined();
  });
});
