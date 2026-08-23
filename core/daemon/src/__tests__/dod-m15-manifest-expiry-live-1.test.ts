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
