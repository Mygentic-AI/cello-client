/**
 * CELLO-M7-CONN-001 (DOD-CONN-3) — HTTP consortium-manifest poll.
 *
 * The manifest poll moves off the (deleted) keystone signaling stream to
 * unauthenticated HTTP: the daemon GETs ${directoryUrl}/manifest, verifies the
 * threshold signature against locally-pinned root keys, applies anti-rollback +
 * expiry, and adopts only a newer valid manifest. Runs daemon-level (no agent
 * identity, no signaling connection) — the property the keystone could never provide.
 *
 * The TUF semantics (verify / anti-rollback / refuse-expired / never-trust-the-
 * directory-for-content) must be PRESERVED across the transport change — these
 * tests pin them over HTTP. Red-first: fails until http-manifest-poll.ts exists.
 */

import { describe, it, expect, afterEach } from "vitest";
import { createServer, type Server } from "node:http";
import { makeTestManifest, TEST_CONSORTIUM_ROOT_KEYS, TEST_CONSORTIUM_THRESHOLD } from "@cello-protocol/crypto";
import { InMemoryManifestVersionStore, TestManifestProvider } from "@cello-protocol/transport";
import { pollManifestOverHttp } from "../http-manifest-poll.js";

const noopLogger = { debug() {}, info() {}, warn() {}, error() {} };

const NODES = [
  { nodeId: "us-east-1", pubkey: "a".repeat(64), region: "us-east-1", provider: "aws" as const, endpoint: "/dns4/dir-us1/tcp/80/ws/p2p/12D3KooWUs1" },
];

let servers: Server[] = [];
afterEach(async () => {
  await Promise.all(servers.map((s) => new Promise<void>((r) => s.close(() => r()))));
  servers = [];
});

/** Serve whatever getBody() returns at GET /manifest (null → 503), on a random port. */
async function serve(getBody: () => unknown | null): Promise<string> {
  const server = createServer((req, res) => {
    if (req.method === "GET" && req.url === "/manifest") {
      const body = getBody();
      if (body === null) { res.writeHead(503, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: "not ready" })); return; }
      res.writeHead(200, { "Content-Type": "application/json" }); res.end(JSON.stringify(body)); return;
    }
    res.writeHead(404); res.end();
  });
  servers.push(server);
  await new Promise<void>((r) => server.listen(0, r));
  const addr = server.address();
  const port = typeof addr === "object" && addr ? addr.port : 0;
  return `http://127.0.0.1:${port}`;
}

function makeDeps(opts?: { seedVersion?: number; seedManifest?: unknown }) {
  const versionStore = new InMemoryManifestVersionStore();
  const provider = new TestManifestProvider();
  if (opts?.seedManifest) provider.updateManifest(opts.seedManifest as never);
  return {
    versionStore,
    provider,
    deps: {
      manifestProvider: provider,
      manifestVersionStore: versionStore,
      rootKeys: TEST_CONSORTIUM_ROOT_KEYS,
      threshold: TEST_CONSORTIUM_THRESHOLD,
      logger: noopLogger,
    },
  };
}

describe("CONN-001 HTTP manifest poll", () => {
  it("AC-003: adopts a newer, validly-signed manifest fetched over HTTP", async () => {
    const v1 = makeTestManifest(NODES, { version: 1 });
    const v2 = makeTestManifest(NODES, { version: 2 });
    const { versionStore, provider, deps } = makeDeps({ seedManifest: v1 });
    await versionStore.persistVersion(1);
    const url = await serve(() => v2);

    const out = await pollManifestOverHttp({ directoryUrl: url, ...deps });

    expect(out).toMatchObject({ ok: true, adopted: true, oldVersion: 1, newVersion: 2 });
    expect(provider.getCurrentManifest()?.version).toBe(2);
    expect(await versionStore.getLastSeenVersion()).toBe(2);
  });

  it("AC-004: runs with ZERO agents — the poll needs no agent identity or signaling connection", async () => {
    // The module touches no agent state by construction; a successful adopt with only a
    // version store + provider (no agents anywhere) is the property the keystone lacked.
    const v5 = makeTestManifest(NODES, { version: 5 });
    const { provider, deps } = makeDeps();
    const url = await serve(() => v5);

    const out = await pollManifestOverHttp({ directoryUrl: url, ...deps });

    expect(out).toMatchObject({ ok: true, adopted: true });
    expect(provider.getCurrentManifest()?.version).toBe(5);
  });

  it("AC-005: rejects a forged manifest (bad officer signatures) — TUF preserved over HTTP", async () => {
    const forged = makeTestManifest(NODES, { version: 9 });
    forged.signatures = forged.signatures.map((s) => ({ ...s, signature: "f".repeat(128) }));
    const { provider, deps } = makeDeps();
    const url = await serve(() => forged);

    const out = await pollManifestOverHttp({ directoryUrl: url, ...deps });

    expect(out).toEqual({ ok: false, reason: "manifest_signature_invalid" });
    expect(provider.getCurrentManifest()).toBeNull();
  });

  it("AC-005: rejects a rolled-back manifest (version < trusted)", async () => {
    const v3 = makeTestManifest(NODES, { version: 3 });
    const { versionStore, deps } = makeDeps();
    await versionStore.persistVersion(5);
    const url = await serve(() => v3);

    const out = await pollManifestOverHttp({ directoryUrl: url, ...deps });

    expect(out).toEqual({ ok: false, reason: "manifest_version_rollback" });
    expect(await versionStore.getLastSeenVersion()).toBe(5);
  });

  it("AC-005: rejects an expired manifest (refuse, hold trusted)", async () => {
    const expired = makeTestManifest(NODES, { version: 2, notBefore: "2020-01-01T00:00:00Z", expires: "2020-02-01T00:00:00Z" });
    const { provider, deps } = makeDeps();
    const url = await serve(() => expired);

    const out = await pollManifestOverHttp({ directoryUrl: url, ...deps });

    expect(out).toEqual({ ok: false, reason: "manifest_expired" });
    expect(provider.getCurrentManifest()).toBeNull();
  });

  it("does not adopt a manifest that is not yet valid (not_before in the future)", async () => {
    const future = makeTestManifest(NODES, { version: 2, notBefore: "2099-01-01T00:00:00Z", expires: "2099-02-01T00:00:00Z" });
    const { provider, deps } = makeDeps();
    const url = await serve(() => future);

    const out = await pollManifestOverHttp({ directoryUrl: url, ...deps });

    expect(out).toEqual({ ok: false, reason: "manifest_not_yet_valid" });
    expect(provider.getCurrentManifest()).toBeNull();
  });

  it("is a no-op when the served version equals the trusted version (already current)", async () => {
    const v2 = makeTestManifest(NODES, { version: 2 });
    const { versionStore, deps } = makeDeps();
    await versionStore.persistVersion(2);
    const url = await serve(() => v2);

    const out = await pollManifestOverHttp({ directoryUrl: url, ...deps });

    expect(out).toMatchObject({ ok: true, adopted: false });
  });

  it("DB-001: on an unreachable endpoint, returns manifest_http_unreachable and keeps the cached manifest", async () => {
    const v1 = makeTestManifest(NODES, { version: 1 });
    const { provider, deps } = makeDeps({ seedManifest: v1 });
    // A port that nothing is listening on.
    const out = await pollManifestOverHttp({ directoryUrl: "http://127.0.0.1:1", ...deps });

    expect(out).toEqual({ ok: false, reason: "manifest_http_unreachable" });
    // The cached manifest is untouched — a poll failure never disturbs the daemon.
    expect(provider.getCurrentManifest()?.version).toBe(1);
  });
});
