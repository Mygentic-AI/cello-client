/**
 * CELLO-M7-REGISTRATION — cello_register handler single-flight guard (review M1)
 *
 * The directory's registration reply frames carry no agent identifier, so two
 * concurrent registrations over the one shared directory signaling stream would
 * cross-wire. The handler serializes registration daemon-wide. This test drives
 * the real CLI→IPC→handler path and proves the second concurrent call is rejected
 * with registration_already_in_progress, deterministically (no timing race on the
 * assertion) by blocking the directory endpoint resolver.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { startDaemon, type DaemonHandle } from "../daemon.js";
import { connectToDaemon } from "../ipc-client.js";
import { FileKeyProvider } from "@cello-protocol/crypto";
import type { Logger, DaemonConfig } from "../types.js";

describe("cello_register single-flight guard", () => {
  let tempDir: string;
  let handle: DaemonHandle | null;
  let logger: Logger;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-reg-handler-"));
    handle = null;
    logger = { debug() {}, info() {}, warn() {}, error() {} };
  });

  afterEach(async () => {
    if (handle) {
      try { await handle.stop("test_cleanup"); } catch { /* already stopped */ }
    }
    await rm(tempDir, { recursive: true, force: true });
  });

  it("rejects a concurrent registration with registration_already_in_progress", async () => {
    const agentsDir = join(tempDir, "agents");
    await mkdir(join(agentsDir, "alice"), { recursive: true });
    await FileKeyProvider.load(join(agentsDir, "alice", "key"));

    // Block directory endpoint resolution so the first registration claims the
    // single-flight slot and parks there while the second call arrives.
    let releaseResolver!: () => void;
    const resolverGate = new Promise<void>((r) => { releaseResolver = r; });
    const config: DaemonConfig = {
    securityGateway: new PassthroughGatewayClient(),
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger,
      directoryEndpointResolver: async () => {
        await resolverGate;
        return null; // after release, resolution "fails" → first call ends in directory_unreachable
      },
    };
    handle = await startDaemon(config);
    const client = await connectToDaemon(config.socketPath);

    // First registration: passes validation, claims the slot, parks in the resolver.
    const first = client.send("cello_register", { agent: "alice", preAuthToken: "t1" }) as Promise<{ ok: boolean; reason?: string }>;
    // Let the daemon process the first request and reach the resolver await.
    await new Promise((r) => setTimeout(r, 80));

    // Second registration while the first holds the slot → rejected.
    const second = (await client.send("cello_register", { agent: "alice", preAuthToken: "t2" })) as { ok: boolean; reason?: string };
    expect(second.ok).toBe(false);
    expect(second.reason).toBe("registration_already_in_progress");

    // Release the first; it ends in directory_unreachable (resolver returned null),
    // and crucially the slot is freed (finally), so a later registration could proceed.
    releaseResolver();
    const firstResult = await first;
    expect(firstResult.ok).toBe(false);
    expect(firstResult.reason).toBe("directory_unreachable");

    client.close();
  });

  it("returns missing_preauth_token when the token is absent", async () => {
    const agentsDir = join(tempDir, "agents");
    await mkdir(join(agentsDir, "alice"), { recursive: true });
    await FileKeyProvider.load(join(agentsDir, "alice", "key"));
    const config: DaemonConfig = {
    securityGateway: new PassthroughGatewayClient(),
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger,
    };
    handle = await startDaemon(config);
    const client = await connectToDaemon(config.socketPath);
    const result = (await client.send("cello_register", { agent: "alice" })) as { ok: boolean; reason?: string };
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("missing_preauth_token");
    client.close();
  });
});

/**
 * DOD-M15-EXPIRY-CONSUMER-POLICY-1 — registration PROCEEDS on a manifest outside its window.
 *
 * ⚠️ WRITTEN BECAUSE REVIEW MEASURED THAT THE BRANCH HAD NEVER RUN — 2869 daemon tests green and
 * zero coverage, because every test above builds a daemon with no `manifestProvider` at all.
 *
 * ─── WHY THIS IS A SOURCE ASSERTION AND NOT AN IPC ONE, STATED RATHER THAN GLOSSED ──────────────
 *
 * I wrote the IPC version first and it could not reach the branch. Two things stop it, and both are
 * worth knowing because each one CONFIRMS a claim this line rests on:
 *
 *   1. **A daemon will not START on an expired manifest** — *"the daemon cannot start with an
 *      unverified manifest when manifestProvider is configured."* That is the fail-closed startup
 *      gate the whole decision leans on, demonstrated instead of assumed, and it is exactly why the
 *      state can only be reached by a manifest lapsing under a daemon already running.
 *   2. **The check sits after `waitForSignalingConnected(…, 10_000)`** — deliberately, because it is
 *      about the DKG roster and not about attempting a registration. So reaching it in-process needs
 *      a live directory, which is a spine-lane cost for a log line.
 *
 * **The PERMIT half is the decision, and it is what this pins.** A later "make the three consumers
 * consistent" refactor turning this into a refusal would strand every running daemon whose manifest
 * lapsed — and with no test, nothing would go red. So the assertion is: the lapsed branch reports
 * and does NOT refuse.
 */
describe("DOD-M15-EXPIRY-CONSUMER-POLICY-1: the lapsed branch reports and does NOT refuse", () => {
  it("★ the branch contains a warn and NO refusal — the permit half, pinned", async () => {
    const { readFileSync } = await import("node:fs");
    const src = readFileSync(join(import.meta.dirname, "..", "register-handler.ts"), "utf8");

    const start = src.indexOf("const lapsed = manifestValidity.state");
    expect(start, "the lapsed decision must exist").toBeGreaterThan(-1);
    const end = src.indexOf("const consortiumRoster", start);
    expect(end, "…and the roster resolution must follow it").toBeGreaterThan(start);
    const branch = src.slice(start, end);

    expect(
      branch.includes('logger.warn("registration.manifest.lapsed"'),
      "the operator must be told — a bare dkg_below_threshold later names an exit point with no cause",
    ).toBe(true);
    expect(
      /return\s*\{\s*ok:\s*false/.test(branch),
      "and it must NOT refuse. Refusing would strand a running daemon, because a restart without a " +
        "replacement manifest never comes back — this is the decision, not an oversight",
    ).toBe(false);
  });

  it("★ it fires on every out-of-window state, not just `expired`", async () => {
    const { readFileSync } = await import("node:fs");
    const src = readFileSync(join(import.meta.dirname, "..", "register-handler.ts"), "utf8");
    const start = src.indexOf("const lapsed = manifestValidity.state");
    const branch = src.slice(start, src.indexOf("if (lapsed)", start));

    // `unreadable_window` is the one that matters most: the hardened startup gate stops it booting,
    // but a manifest POLLED IN after startup can still put a running daemon into it.
    for (const state of ["expired", "unreadable_window", "not_yet_valid"]) {
      expect(branch.includes(`"${state}"`), `${state} must be reported, not silently dealt against`).toBe(true);
    }
  });
});
