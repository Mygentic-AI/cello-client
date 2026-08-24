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
import { registerRegisterHandler } from "../register-handler.js";
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
 * DOD-M15-EXPIRY-CONSUMER-POLICY-1 — registration PROCEEDS on a manifest outside its window, and
 * says so.
 *
 * ⚠️ THIS REPLACES TWO SOURCE-TEXT ASSERTIONS THAT WERE HOLLOW, and the bypass is worth recording
 * because it is subtle: they read the handler's own source and asserted a `logger.warn` appeared
 * between two markers and no `return { ok: false` did. **Change one argument — pass `null` instead
 * of the manifest to `classifyManifestValidity` — and the event never fires in production while
 * both tests still pass**, because the text between the markers is byte-identical. They survived
 * deletion and not neutering, which is the failure mode that actually ships.
 *
 * I wrote them because I could not reach the branch at IPC altitude: a daemon will not START on an
 * expired manifest, and the check sits after a 10 s signaling wait. Both true — and both irrelevant,
 * because `registerRegisterHandler` injects EVERY dependency on that path. The seam was one level
 * down from where I was testing.
 */
describe("DOD-M15-EXPIRY-CONSUMER-POLICY-1: a lapsed manifest is reported, and does NOT block", () => {
  it("★ emits registration.manifest.lapsed AND still proceeds past it", async () => {
    const warns: Array<{ event: string; ctx: Record<string, unknown> }> = [];
    const handlers = new Map<string, (p: Record<string, unknown> | undefined, c: string) => Promise<unknown>>();
    const logger: Logger = {
      debug() {}, info() {}, error() {},
      warn(event, ctx) { warns.push({ event, ctx: (ctx ?? {}) as Record<string, unknown> }); },
    };

    const expired = {
      version: 3,
      not_before: "2020-01-01T00:00:00Z",
      expires: "2020-06-01T00:00:00Z",
      nodes: [{ nodeId: "n1", pubkey: "aa".repeat(32), region: "local", provider: "gcp", endpoint: "http://127.0.0.1:1", role: "validator" }],
    };

    let reachedRoster = false;
    registerRegisterHandler({
      handlers: handlers as never,
      logger,
      keyProviders: new Map([["alice", { getPublicKey: async () => new Uint8Array(32).fill(1) } as never]]),
      getPersistence: () => ({}) as never,
      getAgentSignaling: () => ({ signaling: {} as never, getNode: () => null }),
      // TRUE: the 10 s wait is the thing that stopped an IPC-level test reaching the branch.
      waitForSignalingConnected: async () => true,
      dropAgentSignaling: async () => {},
      startAgentInternal: () => ({ ok: true }),
      directoryEndpointResolver: async () => ({ peerId: "12D3KooWX", multiaddr: "/ip4/127.0.0.1/tcp/1" }) as never,
      loadedAgents: [{ name: "alice", pubkey: "11".repeat(32), keyProvider: {} as never }],
      registrationGuidance: () => "guidance",
      manifestProvider: {
        loadAndVerify: async () => expired as never,
        getCurrentManifest: () => { reachedRoster = true; return expired as never; },
        updateManifest: () => {},
      } as never,
    });

    const handler = handlers.get("cello_register")!;
    expect(handler, "the handler must be registered").toBeDefined();
    await handler({ agent: "alice", preAuthToken: "t1" }, "conn-1").catch(() => undefined);

    const lapsed = warns.find((w) => w.event === "registration.manifest.lapsed");
    expect(
      lapsed,
      "the operator must be told the roster came from a manifest outside its window — a later " +
        "dkg_below_threshold names an exit point with no cause anywhere",
    ).toBeDefined();
    expect(lapsed!.ctx["state"]).toBe("expired");

    expect(
      reachedRoster,
      "and it must have gone ON to resolve the roster — the PERMIT half. Refusing here would strand " +
        "a running daemon, since a restart without a replacement manifest never comes back",
    ).toBe(true);
  });
});
