/**
 * DOD-M15-DIRAUTH-1 — directory authentication cannot be silently skipped.
 *
 * ─── The producer/consumer map, GREPPED not assumed ────────────────────────────────────────────
 *
 * I have shipped a false "the only caller is…" claim in three consecutive units, so this one was
 * enumerated before a word of it was written.
 *
 *   DECIDED   `manifest-deps.ts` — a challenge verifier is built ONLY when the resolved directory
 *             URL matches a bundled endpoint after NORMALISATION (trim, drop trailing slash,
 *             lowercase). Otherwise it returns `{}` and logs `daemon.manifest.bundled.skipped` ONCE
 *             at startup.
 *   ENFORCED  `signaling-connect.ts` step 6 — `if (verifier) { … }`. When a verifier exists this
 *             FAILS CLOSED correctly: missing proof throws, a bad signature throws.
 *   SKIPPED   the same `if (verifier)`. With no verifier the whole block is stepped over, on every
 *             connect and every reconnect.
 *
 * **Correction (review F4).** This header first claimed nothing was logged at that site. False, and
 * falsifiable in one grep: `directory.signaling.connected` carries `verified: !!verifier` six lines
 * later, every connect and every reconnect. The skip is logged twice over. The reason this unit
 * exists is not an absent log — it is that **a log is not a control**: an agent reading
 * `cello_status` cannot grep `daemon.log`, and the agent-facing surface said nothing either way.
 *
 * NOT the live path, despite its own comment saying otherwise: `signaling-manager.ts`'s
 * `processStep5Frame` (*"called inside production connect() after auth_ok"*) has no production
 * caller — its `no_challenge_verifier` branch returns without logging, and nothing reaches it. It is
 * a parallel implementation, and mistaking it for the enforcement point is exactly the error this
 * header exists to avoid.
 *
 * ─── What is actually wrong ────────────────────────────────────────────────────────────────────
 *
 * The string match is a workaround, not a fix, and the DoD line says so: *"That is why the production
 * directory URL is a raw IP: the fail-open is known and was worked around with string matching."*
 * Normalisation forgives case and a trailing slash; it does not forgive DNS. So an operator who does
 * the most natural thing in the world — put a hostname in `CELLO_DIRECTORY_URL` — silently loses
 * directory identity authentication.
 *
 * The consequence is not abstract. Step 6 is what stops a `/bootstrap` MITM redirecting failover to
 * a rogue directory. Without it the client will authenticate to whatever answers.
 *
 * ─── What this unit does, and does not ─────────────────────────────────────────────────────────
 *
 * It does NOT remove the skip: local dev and the e2e harness legitimately run against a directory
 * the bundle cannot describe, and enforcing there would reject every connection.
 *
 * It makes the skip impossible to MISS, and makes it refusable:
 *   1. the agent-facing response says directory authentication is off, and why;
 *   2. `CELLO_REQUIRE_DIRECTORY_AUTH=1` turns the skip into a refusal, for an operator who would
 *      rather not connect than connect unauthenticated.
 *
 * Resolving the bootstrap coordinate over an authenticated channel — the line's second bullet — is a
 * protocol change and is carried, not smuggled in here.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { startDaemon, connectToDaemon, type DaemonHandle, type DaemonConfig } from "../index.js";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { describeDirectoryAuth, directoryAuthRequired } from "../directory-auth-posture.js";

describe("DOD-M15-DIRAUTH-1: the posture is stated, not inferred from silence", () => {
  it("★ ENFORCED contributes a field that says so — the operator can confirm it, not just hope", () => {
    /**
     * Deliberately NOT the usual "healthy adds nothing" shape, and this is the one place in the
     * milestone where that inverts. Everywhere else a field on the good path is furniture. Here the
     * whole defect is that OFF and ON are distinguished only by the absence of a log line nobody
     * reads — so "I checked and it is on" has to be an answer the operator can actually get.
     */
    const d = describeDirectoryAuth({ verifierPresent: true, directoryUrl: "http://1.2.3.4:9090" });
    expect(d["directory_authentication"]).toBe("enforced");
    expect(d["directory_authentication_guidance"]).toBeUndefined();
  });

  it("★ DISABLED says which URL caused it and what to change", () => {
    const d = describeDirectoryAuth({ verifierPresent: false, directoryUrl: "http://dir.example.com:9090" });
    expect(d["directory_authentication"]).toBe("disabled");
    const g = String(d["directory_authentication_guidance"]);
    expect(g, "the URL is the cause and must be quoted back").toContain("dir.example.com");
    expect(
      g,
      "it must name the concrete exposure — step 6 is what stops a /bootstrap MITM redirecting " +
        "failover to a rogue directory",
    ).toMatch(/rogue directory|MITM/i);
    expect(
      g,
      "and the fix: matched against a bundled endpoint after normalisation, so a HOSTNAME for the " +
        "same machine does not match — which is the trap",
    ).toMatch(/normalisation|hostname/i);
    expect(
      g,
      "the remedy must WORK: CELLO_CONSORTIUM_MANIFEST alone makes the daemon refuse to start with " +
        "a DIFFERENT error, because the two companion variables are mandatory (review F3)",
    ).toMatch(/CELLO_CONSORTIUM_ROOT_KEYS/);
    expect(g).toMatch(/CELLO_CONSORTIUM_THRESHOLD/);
    expect(
      g,
      "and the off-switch must name its VALUES — an operator on a k8s ConfigMap often cannot unset " +
        "a key, only set it to something (review F8)",
    ).toMatch(/0, false, no or off/);
  });

  it("a LOCAL directory is disabled-but-expected, and says that instead of raising alarm", () => {
    /**
     * Local dev and the e2e harness run their own directory on 127.0.0.1. The bundle cannot describe
     * it, so the skip is correct there. Same posture, different prose: an alarm on the designed case
     * is the failure this milestone finds more than any other.
     */
    const d = describeDirectoryAuth({ verifierPresent: false, directoryUrl: "http://127.0.0.1:9090" });
    expect(d["directory_authentication"]).toBe("disabled");
    expect(d["directory_authentication_expected"]).toBe(true);
    expect(
      String(d["directory_authentication_guidance"]),
      "it must say this is the designed local configuration rather than implying a compromise",
    ).toMatch(/local|development|harness/i);
  });

  it("★ a PUBLIC directory with auth off is NOT marked expected — that is the dangerous one", () => {
    const d = describeDirectoryAuth({ verifierPresent: false, directoryUrl: "https://dir.example.com" });
    expect(
      d["directory_authentication_expected"],
      "a client talking to a PUBLIC directory with identity authentication off is weaker than its " +
        "operator believes, and must not be filed alongside local development",
    ).toBe(false);
  });
});

describe("DOD-M15-DIRAUTH-1: an operator can demand it", () => {
  it("off by default — enforcing everywhere would reject every local-dev connection", () => {
    expect(directoryAuthRequired({})).toBe(false);
  });

  it("★ CELLO_REQUIRE_DIRECTORY_AUTH=1 makes the skip a refusal", () => {
    expect(directoryAuthRequired({ CELLO_REQUIRE_DIRECTORY_AUTH: "1" })).toBe(true);
    expect(directoryAuthRequired({ CELLO_REQUIRE_DIRECTORY_AUTH: "true" })).toBe(true);
  });

  it("whitespace and case are tolerated on the OFF values", () => {
    /**
     * Review §4: deleting `.trim().toLowerCase()` left the suite green. The docstring claimed the
     * behaviour and nothing asserted it — and it is exactly the shape a compose file or a systemd
     * drop-in produces, where a trailing space is invisible in the source.
     */
    expect(directoryAuthRequired({ CELLO_REQUIRE_DIRECTORY_AUTH: " 0 " })).toBe(false);
    expect(directoryAuthRequired({ CELLO_REQUIRE_DIRECTORY_AUTH: "FALSE" })).toBe(false);
    expect(directoryAuthRequired({ CELLO_REQUIRE_DIRECTORY_AUTH: "Off" })).toBe(false);
    expect(directoryAuthRequired({ CELLO_REQUIRE_DIRECTORY_AUTH: "  " })).toBe(false);
  });

  it("an unrecognised value does NOT silently mean off", () => {
    /**
     * The shape that would undo the whole unit: an operator sets
     * `CELLO_REQUIRE_DIRECTORY_AUTH=yes`, believes they have demanded authentication, and gets the
     * permissive default because the parser only recognised "1" and "true". A security opt-in that
     * silently fails to apply is worse than not offering it.
     */
    expect(directoryAuthRequired({ CELLO_REQUIRE_DIRECTORY_AUTH: "yes" })).toBe(true);
    expect(directoryAuthRequired({ CELLO_REQUIRE_DIRECTORY_AUTH: "on" })).toBe(true);
    // Only the explicit negatives turn it off.
    expect(directoryAuthRequired({ CELLO_REQUIRE_DIRECTORY_AUTH: "0" })).toBe(false);
    expect(directoryAuthRequired({ CELLO_REQUIRE_DIRECTORY_AUTH: "false" })).toBe(false);
    expect(directoryAuthRequired({ CELLO_REQUIRE_DIRECTORY_AUTH: "" })).toBe(false);
  });
});

describe("DOD-M15-DIRAUTH-1: the daemon surfaces the posture", () => {
  let dir: string;
  let handle: DaemonHandle | null = null;

  beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), "m15-dirauth-")); });
  afterEach(async () => {
    if (handle) await handle.stop("test_cleanup").catch(() => {});
    handle = null;
    await rm(dir, { recursive: true, force: true });
  });

  it("★ cello_status states the posture on a daemon with NO verifier", async () => {
    /**
     * Asserted at the wiring, because a module test proving the helper works has now twice failed to
     * notice that the daemon never called it.
     */
    handle = await startDaemon({
      securityGateway: new PassthroughGatewayClient(),
      celloDir: dir,
      socketPath: join(dir, "daemon.sock"),
      lockFilePath: join(dir, "daemon.lock"),
      maxConnections: 8,
      version: "0.0.1-test",
      logger: { debug() {}, info() {}, warn() {}, error() {} },
    } as DaemonConfig);

    const c = await connectToDaemon(join(dir, "daemon.sock"));
    await c.send("ipc.connect", { clientType: "mcp" });
    const status = (await c.send("cello_status", {})) as Record<string, unknown>;
    c.close();

    expect(
      status["directory_authentication"],
      "the posture was not stated at all, so an operator cannot tell whether directory identity " +
        "authentication is running — which is the entire defect: OFF and ON differ only by the " +
        "absence of a log line",
    ).toBe("disabled");
  }, 30_000);

  it("★ and states ENFORCED when a verifier IS wired", async () => {
    handle = await startDaemon({
      securityGateway: new PassthroughGatewayClient(),
      celloDir: dir,
      socketPath: join(dir, "daemon.sock"),
      lockFilePath: join(dir, "daemon.lock"),
      maxConnections: 8,
      version: "0.0.1-test",
      logger: { debug() {}, info() {}, warn() {}, error() {} },
      challengeVerifier: { verifyChallenge: vi.fn(() => ({ valid: true })) },
    } as unknown as DaemonConfig);

    const c = await connectToDaemon(join(dir, "daemon.sock"));
    await c.send("ipc.connect", { clientType: "mcp" });
    const status = (await c.send("cello_status", {})) as Record<string, unknown>;
    c.close();

    expect(
      status["directory_authentication"],
      "a daemon that IS enforcing must be able to say so — otherwise the field only ever appears " +
        "as bad news and an operator cannot confirm a healthy posture",
    ).toBe("enforced");
  }, 30_000);
});

describe("DOD-M15-DIRAUTH-1: the demand is enforced at STARTUP, not deferred", () => {
  let dir: string;
  let handle: DaemonHandle | null = null;
  const saved = process.env["CELLO_REQUIRE_DIRECTORY_AUTH"];

  beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), "m15-dirauth-strict-")); });
  afterEach(async () => {
    if (handle) await handle.stop("test_cleanup").catch(() => {});
    handle = null;
    if (saved === undefined) delete process.env["CELLO_REQUIRE_DIRECTORY_AUTH"];
    else process.env["CELLO_REQUIRE_DIRECTORY_AUTH"] = saved;
    await rm(dir, { recursive: true, force: true });
  });

  const cfg = (extra: Record<string, unknown> = {}) => ({
    securityGateway: new PassthroughGatewayClient(),
    celloDir: dir,
    socketPath: join(dir, "daemon.sock"),
    lockFilePath: join(dir, "daemon.lock"),
    maxConnections: 8,
    version: "0.0.1-test",
    logger: { debug() {}, info() {}, warn() {}, error() {} },
    ...extra,
  }) as unknown as DaemonConfig;

  it("★ with the demand set and no verifier, the daemon REFUSES TO START", async () => {
    /**
     * At startup rather than at connect time, deliberately. A daemon that comes up and then silently
     * declines every session is a worse failure than one that does not come up and says why: the
     * first looks like the protocol is broken, the second names its own cause. Same shape as
     * ADV-002, which refuses on an unverifiable manifest for the same reason.
     */
    process.env["CELLO_REQUIRE_DIRECTORY_AUTH"] = "1";
    await expect(
      startDaemon(cfg()),
      "the operator demanded directory identity authentication and the daemon started anyway, " +
        "without it — the demand was accepted and then ignored, which is worse than not offering it",
    ).rejects.toThrow(/CELLO_REQUIRE_DIRECTORY_AUTH/);
  }, 30_000);

  it("★ and the refusal explains the byte-equality trap, because that is the usual cause", async () => {
    process.env["CELLO_REQUIRE_DIRECTORY_AUTH"] = "1";
    const err = await startDaemon(cfg()).then(
      (h) => { handle = h; return null; },
      (e: unknown) => e as Error,
    );
    expect(err).not.toBeNull();
    expect(
      err?.message,
      "an operator whose hostname resolves to exactly the right machine will otherwise conclude " +
        "the check is broken rather than that the comparison is byte-equality",
    ).toMatch(/NORMALISATION|hostname/i);
    expect(
      err?.message,
      "and it must NOT claim byte-equality — case and a trailing slash ARE forgiven, so an operator " +
        "told that would hunt a capital letter and never find it (review F7)",
    ).not.toMatch(/byte-equal/i);
    expect(err?.message, "and it must name the ways out").toMatch(/CELLO_CONSORTIUM_MANIFEST/);
  }, 30_000);

  it("with a verifier present the demand is satisfied and the daemon starts", async () => {
    // The counterexample: the gate must fire on the ABSENCE of a verifier, not on the flag.
    process.env["CELLO_REQUIRE_DIRECTORY_AUTH"] = "1";
    handle = await startDaemon(cfg({ challengeVerifier: { verifyChallenge: vi.fn(() => ({ valid: true })) } }));
    const c = await connectToDaemon(join(dir, "daemon.sock"));
    await c.send("ipc.connect", { clientType: "mcp" });
    const status = (await c.send("cello_status", {})) as Record<string, unknown>;
    c.close();
    expect(status["directory_authentication"]).toBe("enforced");
  }, 30_000);

  it("without the demand, a daemon with no verifier still starts — local dev must keep working", async () => {
    delete process.env["CELLO_REQUIRE_DIRECTORY_AUTH"];
    handle = await startDaemon(cfg());
    expect(handle, "enforcing unconditionally would reject every local-dev and e2e connection").toBeDefined();
  }, 30_000);
});

describe("DOD-M15-DIRAUTH-1: the gaps the review enumerated as revert-green", () => {
  let dir: string;
  let handle: DaemonHandle | null = null;
  const saved = process.env["CELLO_REQUIRE_DIRECTORY_AUTH"];
  const savedUrl = process.env["CELLO_DIRECTORY_URL"];

  beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), "m15-dirauth-gaps-")); });
  afterEach(async () => {
    if (handle) await handle.stop("test_cleanup").catch(() => {});
    handle = null;
    if (saved === undefined) delete process.env["CELLO_REQUIRE_DIRECTORY_AUTH"];
    else process.env["CELLO_REQUIRE_DIRECTORY_AUTH"] = saved;
    if (savedUrl === undefined) delete process.env["CELLO_DIRECTORY_URL"];
    else process.env["CELLO_DIRECTORY_URL"] = savedUrl;
    await rm(dir, { recursive: true, force: true });
  });

  const cfg = (extra: Record<string, unknown> = {}) => ({
    securityGateway: new PassthroughGatewayClient(),
    celloDir: dir,
    socketPath: join(dir, "daemon.sock"),
    lockFilePath: join(dir, "daemon.lock"),
    maxConnections: 8,
    version: "0.0.1-test",
    logger: { debug() {}, info() {}, warn() {}, error() {} },
    ...extra,
  }) as unknown as DaemonConfig;

  it("★ the CLI `status` verb carries the posture too, not just cello_status", async () => {
    /**
     * Review F2, and this is the SECOND unit running to ship the identical omission — the previous
     * one's own test file documents it. Two copy-pasted spread sites, one asserted. `status` is what
     * `cello status` calls and JSON-dumps, so it is the surface an operator with no MCP client sees.
     */
    handle = await startDaemon(cfg());
    const c = await connectToDaemon(join(dir, "daemon.sock"));
    await c.send("ipc.connect", { clientType: "cli" });
    const cli = (await c.send("status", {})) as Record<string, unknown>;
    c.close();
    expect(
      cli["directory_authentication"],
      "`cello status` said nothing about whether directory identity authentication is running",
    ).toBe("disabled");
  }, 30_000);

  it("★ a refused start leaves NOTHING behind — the next start with a verifier succeeds", async () => {
    /**
     * Review F1's real consequence, asserted rather than argued. The refusal used to run after the
     * identity migration, after the DB and key were created, and after every active session was
     * marked interrupted. Moving it to pure-config-validation position means a refused start is a
     * no-op on disk — and the way to prove that is to refuse, then start properly on the SAME
     * celloDir and see a working daemon.
     */
    process.env["CELLO_REQUIRE_DIRECTORY_AUTH"] = "1";
    await expect(startDaemon(cfg())).rejects.toThrow(/CELLO_REQUIRE_DIRECTORY_AUTH/);

    handle = await startDaemon(cfg({ challengeVerifier: { verifyChallenge: vi.fn(() => ({ valid: true })) } }));
    const c = await connectToDaemon(join(dir, "daemon.sock"));
    await c.send("ipc.connect", { clientType: "mcp" });
    const status = (await c.send("cello_status", {})) as Record<string, unknown>;
    c.close();
    expect(
      status["directory_authentication"],
      "the refused start left the directory in a state the next start could not recover from",
    ).toBe("enforced");
  }, 30_000);

  it("★ the refusal is LOUD in the log, not only in the thrown error", async () => {
    /**
     * Review §4: both refusal tests passed a silent logger, so deleting the whole
     * `directory.auth.required.unavailable` block was green. Invariant 2 wants the log half AND the
     * response half; only the response half had a test.
     */
    process.env["CELLO_REQUIRE_DIRECTORY_AUTH"] = "1";
    const events: Array<{ event: string; ctx: Record<string, unknown> }> = [];
    const logger = {
      debug() {}, info() {}, warn() {},
      error: (event: string, ctx?: Record<string, unknown>) => events.push({ event, ctx: ctx ?? {} }),
    };
    await expect(startDaemon(cfg({ logger }))).rejects.toThrow();

    const rec = events.find((e) => e.event === "directory.auth.required.unavailable");
    expect(rec, "a refused startup that logs nothing leaves no forensic record of WHY").toBeDefined();
    expect(rec?.ctx["directoryUrl"], "the log must name the URL that was judged").toBeDefined();
    expect(
      String(rec?.ctx["guidance"]),
      "and carry a remedy that works — all three manifest variables, not just the first",
    ).toMatch(/CELLO_CONSORTIUM_ROOT_KEYS/);
  }, 30_000);

  it("★ a LOOPBACK directory is expected-and-calm at the WIRING, not just in the helper", async () => {
    /**
     * Review F6 + §4: the daemon tests asserted only the single string "disabled", so hardcoding
     * `expected: false` — or dropping the guidance entirely — stayed green. That is the only test
     * that would have caught the two classifiers disagreeing, and it is the shape a compose-based
     * dev loop actually runs.
     */
    process.env["CELLO_DIRECTORY_URL"] = "http://127.0.0.1:9099";
    handle = await startDaemon(cfg());
    const c = await connectToDaemon(join(dir, "daemon.sock"));
    await c.send("ipc.connect", { clientType: "mcp" });
    const status = (await c.send("cello_status", {})) as Record<string, unknown>;
    c.close();

    expect(status["directory_authentication"]).toBe("disabled");
    expect(
      status["directory_authentication_expected"],
      "a loopback directory is the DESIGNED local configuration — printing the rogue-directory " +
        "alarm on every local status call is a signal that fires on the normal case",
    ).toBe(true);
    expect(String(status["directory_authentication_guidance"])).toMatch(/local|harness|development/i);
  }, 30_000);
});

describe("DOD-M15-DIRAUTH-1: the guidance does not blame a cause it never checked", () => {
  it("★ F5: with no CELLO_DIRECTORY_URL set, it does NOT accuse a hostname", () => {
    /**
     * `resolveDirectoryUrl` with the env var unset returns a RANDOM bundled endpoint, freshly picked
     * on every call. So the first cut printed a different URL on consecutive status reads, and the
     * refusal asserted "the usual cause is a DNS hostname" while quoting a URL that IS a bundled
     * endpoint — a cause that cannot produce the state being described.
     */
    const d = describeDirectoryAuth({
      verifierPresent: false,
      directoryUrl: "http://1.2.3.4:9090",
      urlExplicitlyConfigured: false,
    });
    const g = String(d["directory_authentication_guidance"]);
    expect(
      g,
      "it accused a hostname while quoting a bundled endpoint address — the operator would go and " +
        "check DNS for a URL that matched fine",
    ).not.toMatch(/HOSTNAME/);
    expect(g, "the honest explanation is that no verifier was supplied").toMatch(/no challenge verifier was supplied/i);
    expect(
      d["directory_authentication_directory_url"],
      "and a randomly re-picked URL must not be printed as though it were a configured setting",
    ).toBeUndefined();
  });

  it("★ F6: an UPPERCASE loopback URL is still recognised as local", () => {
    /**
     * The two classifiers disagreed: `manifest-deps` tests the NORMALISED url, this module tested
     * the raw one with a case-sensitive regex. So `HTTP://127.0.0.1:9090` was logged as benign local
     * dev by one and reported as a rogue-directory risk by the other — the alarm firing on the
     * designed case, on every status call of a compose-based dev loop.
     */
    const d = describeDirectoryAuth({ verifierPresent: false, directoryUrl: "HTTP://127.0.0.1:9090" });
    expect(d["directory_authentication_expected"]).toBe(true);
  });

  it("★ F6: a leading space from a .env or compose value does not flip it to alarming", () => {
    const d = describeDirectoryAuth({ verifierPresent: false, directoryUrl: " http://127.0.0.1:9090" });
    expect(d["directory_authentication_expected"]).toBe(true);
  });
});
