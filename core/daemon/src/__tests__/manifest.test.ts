/**
 * M7-MANIFEST-002 — Daemon manifest loading tests.
 *
 * AC mapping:
 *   AC-002: FileManifestProvider reads and verifies manifest file
 *   AC-003: loadAndVerify throws on signature failure
 *   AC-004: startDaemon emits directory.auth.manifest.verified on success
 *   AC-007: Expired manifest blocks connection — daemon logs manifest.expired
 *   AC-008: Version rollback detected — daemon logs manifest.version.rollback
 *   AC-012: Poll scheduler is started after successful manifest load
 *   AC-015: Composition root wires manifest components correctly
 *   SI-002: Expired manifest causes daemon to skip directory connection
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createServer, type Server } from "node:http";
import {
  makeTestManifest,
  TEST_CONSORTIUM_ROOT_KEYS,
  TEST_CONSORTIUM_THRESHOLD,
  TEST_DIRECTORY_NODE_KEYPAIR,
} from "@cello-protocol/crypto";
import {
  TestManifestProvider,
  InMemoryManifestVersionStore,
  ImmediatePollScheduler,
} from "@cello-protocol/transport";
import { PassthroughGatewayClient } from "@cello-protocol/gateway";
import { startDaemon, type DaemonHandle } from "../daemon.js";
import { FileManifestProvider } from "../manifest-loader.js";
import type { Logger, DaemonConfig } from "../types.js";
import type { ConsortiumManifest } from "@cello-protocol/protocol-types";
import type { IManifestPollScheduler } from "@cello-protocol/transport";

// ─── Test helpers ──────────────────────────────────────────────────────────────

function makeLogger(): Logger & {
  events: Array<{ level: string; event: string; context: Record<string, unknown> }>;
} {
  const events: Array<{ level: string; event: string; context: Record<string, unknown> }> = [];
  return {
    events,
    debug(event: string, context: Record<string, unknown>) { events.push({ level: "debug", event, context }); },
    info(event: string, context: Record<string, unknown>) { events.push({ level: "info", event, context }); },
    warn(event: string, context: Record<string, unknown>) { events.push({ level: "warn", event, context }); },
    error(event: string, context: Record<string, unknown>) { events.push({ level: "error", event, context }); },
  };
}

function makeTestNode(nodeId: string, pubkeyHex: string) {
  return {
    nodeId,
    pubkey: pubkeyHex,
    region: "us-east-1",
    provider: "aws" as const,
    endpoint: "wss://test.cello.test:443",
  };
}

function makeValidManifest(version = 1): ConsortiumManifest {
  return makeTestManifest(
    [makeTestNode("test-node-us-east-1", TEST_DIRECTORY_NODE_KEYPAIR.publicKeyHex)],
    { version, expires: "2030-01-01T00:00:00Z" },
  ) as ConsortiumManifest;
}

function makeExpiredManifest(): ConsortiumManifest {
  return makeTestManifest(
    [makeTestNode("test-node-us-east-1", TEST_DIRECTORY_NODE_KEYPAIR.publicKeyHex)],
    { expires: "2020-01-01T00:00:00Z" },
  ) as ConsortiumManifest;
}

// ─── FileManifestProvider tests ───────────────────────────────────────────────

describe("AC-002: FileManifestProvider — manifest file loading", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-manifest-test-"));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("loads and verifies a valid manifest from a JSON file", async () => {
    const manifest = makeValidManifest();
    const manifestPath = join(tempDir, "consortium-manifest.json");
    await writeFile(manifestPath, JSON.stringify(manifest), "utf-8");

    const provider = new FileManifestProvider(manifestPath);
    const result = await provider.loadAndVerify(TEST_CONSORTIUM_ROOT_KEYS, TEST_CONSORTIUM_THRESHOLD);

    expect(result.nodes[0].nodeId).toBe("test-node-us-east-1");
    expect(result.version).toBe(1);
  });

  it("caches the manifest after loadAndVerify", async () => {
    const manifest = makeValidManifest();
    const manifestPath = join(tempDir, "consortium-manifest.json");
    await writeFile(manifestPath, JSON.stringify(manifest), "utf-8");

    const provider = new FileManifestProvider(manifestPath);
    const loaded = await provider.loadAndVerify(TEST_CONSORTIUM_ROOT_KEYS, TEST_CONSORTIUM_THRESHOLD);
    expect(provider.getCurrentManifest()).toBeDefined();
    expect(provider.getCurrentManifest()?.version).toBe(loaded.version);
  });

  it("AC-003: throws on signature verification failure", async () => {
    const manifest = makeTestManifest([makeTestNode("node-1", "00".repeat(32))]);
    const badRootKeys = ["00".repeat(32), "00".repeat(32), "00".repeat(32), "00".repeat(32), "00".repeat(32)];
    const manifestPath = join(tempDir, "bad-manifest.json");
    await writeFile(manifestPath, JSON.stringify(manifest), "utf-8");

    const provider = new FileManifestProvider(manifestPath);
    await expect(
      provider.loadAndVerify(badRootKeys, 3)
    ).rejects.toThrow(/manifest_signature_invalid/);
  });

  it("throws on missing file", async () => {
    const provider = new FileManifestProvider(join(tempDir, "nonexistent.json"));
    await expect(
      provider.loadAndVerify(TEST_CONSORTIUM_ROOT_KEYS, TEST_CONSORTIUM_THRESHOLD)
    ).rejects.toThrow(/manifest_file_unreadable/);
  });

  it("throws on invalid JSON", async () => {
    const manifestPath = join(tempDir, "invalid.json");
    await writeFile(manifestPath, "{not valid json}", "utf-8");

    const provider = new FileManifestProvider(manifestPath);
    await expect(
      provider.loadAndVerify(TEST_CONSORTIUM_ROOT_KEYS, TEST_CONSORTIUM_THRESHOLD)
    ).rejects.toThrow(/manifest_parse_failed/);
  });
});

// ─── Daemon startup with manifest loading ─────────────────────────────────────

describe("AC-004: startDaemon manifest loading at startup", () => {
  let tempDir: string;
  let handle: DaemonHandle | null;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-daemon-manifest-"));
    handle = null;
  });

  afterEach(async () => {
    if (handle) {
      try { await handle.stop("test_cleanup"); } catch { /* ignore cleanup errors */ }
    }
    await rm(tempDir, { recursive: true, force: true });
  });

  function makeBaseConfig(logger: Logger, overrides?: Partial<DaemonConfig>): DaemonConfig {
    return {
      securityGateway: new PassthroughGatewayClient(),
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger,
      ...overrides,
    };
  }

  it("emits directory.auth.manifest.verified when manifest loads successfully", async () => {
    const logger = makeLogger();
    const manifest = makeValidManifest();
    const manifestProvider = new TestManifestProvider(manifest);
    const versionStore = new InMemoryManifestVersionStore();

    handle = await startDaemon(makeBaseConfig(logger, {
      manifestProvider,
      manifestRootKeys: TEST_CONSORTIUM_ROOT_KEYS,
      manifestThreshold: TEST_CONSORTIUM_THRESHOLD,
      manifestVersionStore: versionStore,
    }));

    const verifiedEvent = logger.events.find((e) => e.event === "directory.auth.manifest.verified");
    expect(verifiedEvent).toBeDefined();
    expect(verifiedEvent?.context.manifestVersion).toBe(1);
  });

  it("AC-007 / SI-002 / ADV-002: expired manifest causes fatal startup error when manifestProvider configured", async () => {
    const logger = makeLogger();
    const expiredManifest = makeExpiredManifest();
    const manifestProvider = new TestManifestProvider(expiredManifest);

    await expect(startDaemon(makeBaseConfig(logger, {
      manifestProvider,
      manifestRootKeys: TEST_CONSORTIUM_ROOT_KEYS,
      manifestThreshold: TEST_CONSORTIUM_THRESHOLD,
    }))).rejects.toThrow(/Manifest verification failed/);

    const expiredEvent = logger.events.find((e) => e.event === "directory.auth.manifest.expired");
    expect(expiredEvent).toBeDefined();
    expect(expiredEvent?.context.manifestVersion).toBe(1);
  });

  it("AC-008 / ADV-002: version rollback causes fatal startup error when manifestProvider configured", async () => {
    const logger = makeLogger();
    const manifest = makeValidManifest(5);
    const manifestProvider = new TestManifestProvider(manifest);
    const versionStore = new InMemoryManifestVersionStore();
    await versionStore.persistVersion(10);

    await expect(startDaemon(makeBaseConfig(logger, {
      manifestProvider,
      manifestRootKeys: TEST_CONSORTIUM_ROOT_KEYS,
      manifestThreshold: TEST_CONSORTIUM_THRESHOLD,
      manifestVersionStore: versionStore,
    }))).rejects.toThrow(/Manifest verification failed/);

    const rollbackEvent = logger.events.find((e) => e.event === "directory.auth.manifest.version.rollback");
    expect(rollbackEvent).toBeDefined();
    expect(rollbackEvent?.context.manifestVersion).toBe(5);
    expect(rollbackEvent?.context.lastSeenVersion).toBe(10);
  });

  it("ADV-007: manifest poll is NO LONGER deferred when a scheduler is configured (DOD-AUTH-2)", async () => {
    // The poll used to be a deferred stub (directory.auth.manifest.poll.deferred). DOD-AUTH-2
    // activated it: the keystone SignalingManager now starts polling on connect. This guards
    // against the deferral regressing back in. (The actual dispatch over the live stream is
    // proven by the transport poll-on-connect unit test + the J-AUTH live binary test — a
    // daemon unit harness has no real directory stream to dispatch onto.)
    const logger = makeLogger();
    const manifest = makeValidManifest();
    const manifestProvider = new TestManifestProvider(manifest);

    const scheduler: IManifestPollScheduler = {
      scheduleNext(_cb) { /* no-op */ },
      cancel() { /* no-op */ },
    };

    handle = await startDaemon(makeBaseConfig(logger, {
      manifestProvider,
      manifestRootKeys: TEST_CONSORTIUM_ROOT_KEYS,
      manifestThreshold: TEST_CONSORTIUM_THRESHOLD,
      manifestPollScheduler: scheduler,
    }));

    expect(logger.events.find((e) => e.event === "directory.auth.manifest.poll.deferred")).toBeUndefined();
    // The manifest still loads + verifies — activation didn't break the startup gate.
    expect(logger.events.find((e) => e.event === "directory.auth.manifest.verified")).toBeDefined();
  });

  it("CONN-001 AC-004: the HTTP manifest poll runs with ZERO agents and adopts a newer manifest", async () => {
    // This daemon has NO agents (fresh tempDir, no agents configured) — the exact condition
    // the keystone could not poll under (it borrowed the primary agent's identity). The poll
    // moved to daemon-level HTTP (DOD-CONN-3): it must fire and adopt with zero agents.
    const logger = makeLogger();
    const v1 = makeValidManifest(1);
    const v2 = makeValidManifest(2);
    const manifestProvider = new TestManifestProvider(v1);
    const versionStore = new InMemoryManifestVersionStore();

    // In-process directory: serves the newer (v2) manifest at GET /manifest.
    const server: Server = createServer((req, res) => {
      if (req.method === "GET" && req.url === "/manifest") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(v2));
        return;
      }
      res.writeHead(404);
      res.end();
    });
    await new Promise<void>((r) => server.listen(0, r));
    const addr = server.address();
    const port = typeof addr === "object" && addr ? addr.port : 0;

    try {
      handle = await startDaemon(makeBaseConfig(logger, {
        manifestProvider,
        manifestRootKeys: TEST_CONSORTIUM_ROOT_KEYS,
        manifestThreshold: TEST_CONSORTIUM_THRESHOLD,
        manifestVersionStore: versionStore,
        manifestPollScheduler: new ImmediatePollScheduler(),
        directoryHttpUrl: `http://127.0.0.1:${port}`,
      }));

      // The poll fires on a timer; wait for the adopt (no agents involved at all).
      const deadline = Date.now() + 3000;
      while (Date.now() < deadline && manifestProvider.getCurrentManifest()?.version !== 2) {
        await new Promise((r) => setTimeout(r, 25));
      }

      expect(manifestProvider.getCurrentManifest()?.version).toBe(2);
      expect(await versionStore.getLastSeenVersion()).toBe(2);
      const success = logger.events.find((e) => e.event === "directory.auth.manifest.poll.success");
      expect(success).toBeDefined();
      expect(success?.context.newVersion).toBe(2);
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  });

  it("equal version passes (same version as last-seen is not a rollback)", async () => {
    const logger = makeLogger();
    const manifest = makeValidManifest(42);
    const manifestProvider = new TestManifestProvider(manifest);
    const versionStore = new InMemoryManifestVersionStore();
    await versionStore.persistVersion(42);

    handle = await startDaemon(makeBaseConfig(logger, {
      manifestProvider,
      manifestRootKeys: TEST_CONSORTIUM_ROOT_KEYS,
      manifestThreshold: TEST_CONSORTIUM_THRESHOLD,
      manifestVersionStore: versionStore,
    }));

    expect(logger.events.find((e) => e.event === "directory.auth.manifest.version.rollback")).toBeUndefined();
    expect(logger.events.find((e) => e.event === "directory.auth.manifest.verified")).toBeDefined();
  });

  it("backward compat: works without manifestProvider (DAEMON-001 tests unaffected)", async () => {
    const logger = makeLogger();
    handle = await startDaemon(makeBaseConfig(logger));
    expect(logger.events.find((e) => e.event === "daemon.started")).toBeDefined();
  });

  it("manifestVerified field appears in daemon.started event", async () => {
    const logger = makeLogger();
    const manifest = makeValidManifest();
    const manifestProvider = new TestManifestProvider(manifest);
    const versionStore = new InMemoryManifestVersionStore();

    handle = await startDaemon(makeBaseConfig(logger, {
      manifestProvider,
      manifestRootKeys: TEST_CONSORTIUM_ROOT_KEYS,
      manifestThreshold: TEST_CONSORTIUM_THRESHOLD,
      manifestVersionStore: versionStore,
    }));

    const startedEvent = logger.events.find((e) => e.event === "daemon.started");
    expect(startedEvent).toBeDefined();
    expect(startedEvent?.context.manifestVerified).toBe(true);
  });

  it("ADV-002: manifestVerified=false with manifestProvider configured throws (fatal)", async () => {
    const logger = makeLogger();
    const expiredManifest = makeExpiredManifest();
    const manifestProvider = new TestManifestProvider(expiredManifest);

    await expect(startDaemon(makeBaseConfig(logger, {
      manifestProvider,
      manifestRootKeys: TEST_CONSORTIUM_ROOT_KEYS,
      manifestThreshold: TEST_CONSORTIUM_THRESHOLD,
    }))).rejects.toThrow(/Manifest verification failed/);

    // daemon.started is never emitted when startup throws
    expect(logger.events.find((e) => e.event === "daemon.started")).toBeUndefined();
  });

  it("ADV-006: manifestProvider without manifestRootKeys throws config error", async () => {
    const logger = makeLogger();
    const manifest = makeValidManifest();
    const manifestProvider = new TestManifestProvider(manifest);

    await expect(startDaemon(makeBaseConfig(logger, {
      manifestProvider,
      // manifestRootKeys intentionally omitted
      manifestThreshold: TEST_CONSORTIUM_THRESHOLD,
    }))).rejects.toThrow(/manifestProvider requires manifestRootKeys/);
  });

  it("ADV-008: manifestThreshold=0 throws config error", async () => {
    const logger = makeLogger();
    const manifest = makeValidManifest();
    const manifestProvider = new TestManifestProvider(manifest);

    await expect(startDaemon(makeBaseConfig(logger, {
      manifestProvider,
      manifestRootKeys: TEST_CONSORTIUM_ROOT_KEYS,
      manifestThreshold: 0,
    }))).rejects.toThrow(/manifestProvider requires manifestRootKeys.*manifestThreshold/);
  });
});
