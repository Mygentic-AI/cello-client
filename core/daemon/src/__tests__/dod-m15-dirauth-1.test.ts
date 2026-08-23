/**
 * DOD-M15-DIRAUTH-1 — directory authentication cannot be silently skipped.
 *
 * ─── The producer/consumer map, GREPPED not assumed ────────────────────────────────────────────
 *
 * I have shipped a false "the only caller is…" claim in three consecutive units, so this one was
 * enumerated before a word of it was written.
 *
 *   DECIDED   `manifest-deps.ts` — a challenge verifier is built ONLY when the resolved directory
 *             URL byte-matches a bundled endpoint. Otherwise it returns `{}` and logs
 *             `daemon.manifest.bundled.skipped` ONCE at startup.
 *   ENFORCED  `signaling-connect.ts` step 6 — `if (verifier) { … }`. When a verifier exists this
 *             FAILS CLOSED correctly: missing proof throws, a bad signature throws.
 *   SKIPPED   the same `if (verifier)`. With no verifier the whole block is stepped over, on every
 *             connect and every reconnect, and **nothing is logged at that site at all.**
 *
 * NOT the live path, despite its own comment saying otherwise: `signaling-manager.ts`'s
 * `processStep5Frame` (*"called inside production connect() after auth_ok"*) has no production
 * caller — its `no_challenge_verifier` branch returns without logging, and nothing reaches it. It is
 * a parallel implementation, and mistaking it for the enforcement point is exactly the error this
 * header exists to avoid.
 *
 * ─── What is actually wrong ────────────────────────────────────────────────────────────────────
 *
 * The byte-match is a workaround, not a fix, and the DoD line says so: *"That is why the production
 * directory URL is a raw IP: the fail-open is known and was worked around with string matching."*
 * A DNS name pointing at the very same machine does not match, so an operator who does the most
 * natural thing in the world — put a hostname in `CELLO_DIRECTORY_URL` — silently loses directory
 * identity authentication.
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
      "and the fix: byte-equality against a bundled endpoint, so a HOSTNAME for the same machine " +
        "does not match — which is the trap",
    ).toMatch(/byte-equal|hostname/i);
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
    ).toMatch(/BYTE-EQUALITY|hostname/i);
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
