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
import { PassthroughGatewayClient } from "@cello-protocol/gateway";
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
