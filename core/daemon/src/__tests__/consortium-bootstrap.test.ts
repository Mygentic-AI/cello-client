/**
 * consortium-bootstrap — the startup manifest gate and the consortium routing it feeds.
 *
 * This block lived inside startDaemon's 6,255-line body (daemon.ts:405-553), so every one of
 * these paths could previously only be reached by standing up a whole daemon — which is why
 * daemon.ts sat at 66% coverage. Extracting it makes the failure branches directly reachable:
 * a clock outside the validity window, an anti-rollback hit, a load that throws, and a roster
 * that only partly resolves are all ordinary unit tests here.
 *
 * The gate's contract, in one line: it reports what it found and NEVER decides what to do about
 * it. Refusing to start is startDaemon's call, because startDaemon owns the DB handle and the
 * singleton lock that a refusal has to release.
 */
import { describe, it, expect, vi } from "vitest";
import type { ConsortiumManifest } from "@cello-protocol/protocol-types";
import type { IManifestProvider, IManifestVersionStore } from "@cello-protocol/transport";
import { verifyStartupManifest, createConsortiumRouting } from "../consortium-bootstrap.js";

function makeLogger() {
  return { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() };
}
type TestLogger = ReturnType<typeof makeLogger>;

/** Did the logger emit this event, at this level? */
function logged(logger: TestLogger, level: "info" | "warn" | "error", event: string): boolean {
  return logger[level].mock.calls.some((c: unknown[]) => c[0] === event);
}

const ROOT_KEYS = ["a".repeat(64)];
const THRESHOLD = 1;

function node(nodeId: string, endpoint = `https://${nodeId}.example.com`) {
  return { nodeId, pubkey: "b".repeat(64), region: "us-east-1", provider: "aws" as const, endpoint };
}

function makeManifest(over: Partial<ConsortiumManifest> = {}): ConsortiumManifest {
  const hour = 3_600_000;
  return {
    version: 7,
    not_before: new Date(Date.now() - hour).toISOString(),
    expires: new Date(Date.now() + hour).toISOString(),
    nodes: [node("n1"), node("n2")],
    signatures: [{ officerIndex: 0, signature: "c".repeat(128) }],
    ...over,
  };
}

function makeProvider(manifest: ConsortiumManifest | Error): IManifestProvider {
  return {
    loadAndVerify: vi.fn(async () => {
      if (manifest instanceof Error) throw manifest;
      return manifest;
    }),
    getCurrentManifest: vi.fn(() => (manifest instanceof Error ? null : manifest)),
    updateManifest: vi.fn(),
  } as unknown as IManifestProvider;
}

function makeVersionStore(lastSeen: number | null = null): IManifestVersionStore & { persisted: number[] } {
  const persisted: number[] = [];
  return {
    persisted,
    getLastSeenVersion: vi.fn(async () => lastSeen),
    persistVersion: vi.fn(async (v: number) => { persisted.push(v); }),
  } as unknown as IManifestVersionStore & { persisted: number[] };
}

/** A fetch that resolves /bootstrap for exactly the named hosts, and 500s for the rest. */
function bootstrapFetch(reachable: string[]): typeof fetch {
  return (async (url: string | URL) => {
    const u = String(url);
    const ok = reachable.some((host) => u.includes(host));
    if (!ok) return { ok: false, status: 500, json: async () => ({}) } as Response;
    return {
      ok: true,
      status: 200,
      json: async () => ({ multiaddr: "/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWTestPeerIdValueForUnitTest" }),
    } as Response;
  }) as unknown as typeof fetch;
}

describe("verifyStartupManifest — the gate reports, it does not decide", () => {
  it("no manifestProvider (M6 back-compat): reports unverified at version 0, with an empty roster and no error", async () => {
    const logger = makeLogger();
    const result = await verifyStartupManifest({
      manifestVersionStore: makeVersionStore(),
      logger,
    });

    expect(result.manifestVerified).toBe(false);
    expect(result.verifiedManifestVersion).toBe(0);
    expect(result.consortiumEndpoints).toEqual([]);
    // Absence of a provider is a configuration, not a failure — it must not log an error.
    expect(logger.error).not.toHaveBeenCalled();
  });

  it("valid manifest inside its window: verifies, persists the version, and resolves the roster", async () => {
    const logger = makeLogger();
    const store = makeVersionStore(null);
    const result = await verifyStartupManifest({
      manifestProvider: makeProvider(makeManifest()),
      manifestRootKeys: ROOT_KEYS,
      manifestThreshold: THRESHOLD,
      manifestVersionStore: store,
      logger,
      fetchFn: bootstrapFetch(["n1", "n2"]),
    });

    expect(result.manifestVerified).toBe(true);
    expect(result.verifiedManifestVersion).toBe(7);
    expect(result.consortiumEndpoints).toHaveLength(2);
    expect(store.persisted).toEqual([7]);
    expect(logged(logger, "info", "directory.auth.manifest.verified")).toBe(true);
    expect(logged(logger, "info", "directory.consortium.resolved")).toBe(true);
  });

  it("a manifest whose not_before is in the future is REFUSED, not accepted early", async () => {
    const logger = makeLogger();
    const store = makeVersionStore();
    const result = await verifyStartupManifest({
      manifestProvider: makeProvider(makeManifest({ not_before: new Date(Date.now() + 3_600_000).toISOString() })),
      manifestRootKeys: ROOT_KEYS,
      manifestThreshold: THRESHOLD,
      manifestVersionStore: store,
      logger,
    });

    expect(result.manifestVerified).toBe(false);
    expect(logged(logger, "error", "directory.auth.manifest.not.yet.valid")).toBe(true);
    // Never persist the version of a manifest we refused — that would poison anti-rollback.
    expect(store.persisted).toEqual([]);
  });

  it("an expired manifest is REFUSED", async () => {
    const logger = makeLogger();
    const store = makeVersionStore();
    const result = await verifyStartupManifest({
      manifestProvider: makeProvider(makeManifest({ expires: new Date(Date.now() - 1_000).toISOString() })),
      manifestRootKeys: ROOT_KEYS,
      manifestThreshold: THRESHOLD,
      manifestVersionStore: store,
      logger,
    });

    expect(result.manifestVerified).toBe(false);
    expect(logged(logger, "error", "directory.auth.manifest.expired")).toBe(true);
    expect(store.persisted).toEqual([]);
  });

  it("ANTI-ROLLBACK: a manifest older than the last one we saw is REFUSED", async () => {
    const logger = makeLogger();
    const store = makeVersionStore(9); // we have already seen v9
    const result = await verifyStartupManifest({
      manifestProvider: makeProvider(makeManifest({ version: 7 })),
      manifestRootKeys: ROOT_KEYS,
      manifestThreshold: THRESHOLD,
      manifestVersionStore: store,
      logger,
    });

    expect(result.manifestVerified).toBe(false);
    expect(logged(logger, "error", "directory.auth.manifest.version.rollback")).toBe(true);
    expect(store.persisted).toEqual([]);
  });

  it("the same version again is ACCEPTED (a restart on an unchanged manifest is not a rollback)", async () => {
    const logger = makeLogger();
    const store = makeVersionStore(7);
    const result = await verifyStartupManifest({
      manifestProvider: makeProvider(makeManifest({ version: 7 })),
      manifestRootKeys: ROOT_KEYS,
      manifestThreshold: THRESHOLD,
      manifestVersionStore: store,
      logger,
      fetchFn: bootstrapFetch(["n1", "n2"]),
    });

    expect(result.manifestVerified).toBe(true);
    // Re-persisting the same version is the correct no-op, and pins that the accept branch is the
    // one we took — not an early return that skipped the persist entirely.
    expect(store.persisted).toEqual([7]);
  });

  it("a load that THROWS reports unverified — it never leaks the exception into startup", async () => {
    const logger = makeLogger();
    const result = await verifyStartupManifest({
      manifestProvider: makeProvider(new Error("manifest_signature_invalid")),
      manifestRootKeys: ROOT_KEYS,
      manifestThreshold: THRESHOLD,
      manifestVersionStore: makeVersionStore(),
      logger,
    });

    expect(result.manifestVerified).toBe(false);
    expect(logged(logger, "error", "directory.auth.manifest.load.failed")).toBe(true);
  });

  it("a partly-reachable roster still verifies, but is logged as PARTIAL — degraded is not healthy", async () => {
    const logger = makeLogger();
    const result = await verifyStartupManifest({
      manifestProvider: makeProvider(makeManifest()),
      manifestRootKeys: ROOT_KEYS,
      manifestThreshold: THRESHOLD,
      manifestVersionStore: makeVersionStore(),
      logger,
      fetchFn: bootstrapFetch(["n1"]), // n2 is down
    });

    // Redundancy invariant: one node down must NOT strand the rest.
    expect(result.manifestVerified).toBe(true);
    expect(result.consortiumEndpoints).toHaveLength(1);
    expect(logged(logger, "warn", "directory.consortium.partial")).toBe(true);
    expect(logged(logger, "info", "directory.consortium.resolved")).toBe(false);
  });

  it("a roster where NOTHING resolves is logged at ERROR, never buried at info", async () => {
    const logger = makeLogger();
    const result = await verifyStartupManifest({
      manifestProvider: makeProvider(makeManifest()),
      manifestRootKeys: ROOT_KEYS,
      manifestThreshold: THRESHOLD,
      manifestVersionStore: makeVersionStore(),
      logger,
      fetchFn: bootstrapFetch([]), // every node down
    });

    expect(result.consortiumEndpoints).toEqual([]);
    expect(logged(logger, "error", "directory.consortium.none")).toBe(true);
  });
});

describe("createConsortiumRouting", () => {
  it("without a directoryEndpointResolver (in-process test path) there is no failover resolver, and getFailoverEndpoint yields null", async () => {
    const logger = makeLogger();
    const routing = createConsortiumRouting({
      manifestProvider: makeProvider(makeManifest()),
      manifestVersionStore: makeVersionStore(),
      manifestRootKeys: ROOT_KEYS,
      manifestThreshold: THRESHOLD,
      logger,
    });

    expect(routing.failoverEndpointResolver).toBeUndefined();
    expect(await routing.getFailoverEndpoint()).toBeNull();
  });

  it("with a directoryEndpointResolver it builds a roster-aware failover resolver that returns the primary while it is up", async () => {
    const logger = makeLogger();
    const primary = { url: "https://primary.example.com", peerId: "12D3KooWPrimary", multiaddr: "/ip4/1.2.3.4/tcp/4001" };
    const routing = createConsortiumRouting({
      manifestProvider: makeProvider(makeManifest()),
      manifestVersionStore: makeVersionStore(),
      manifestRootKeys: ROOT_KEYS,
      manifestThreshold: THRESHOLD,
      directoryEndpointResolver: async () => primary as never,
      logger,
    });

    expect(routing.failoverEndpointResolver).toBeDefined();
    expect(await routing.getFailoverEndpoint()).toEqual(primary);
  });

  it("resolveConsortiumRoster returns null when no manifest is configured — a single-node ceremony, not an empty roster", async () => {
    const logger = makeLogger();
    const routing = createConsortiumRouting({
      manifestVersionStore: makeVersionStore(),
      logger,
    });

    // null ≠ [] here, and the difference is load-bearing: [] means "a consortium with no reachable
    // nodes" (refuse), null means "no consortium configured" (M6/M7 single-node back-compat).
    expect(await routing.resolveConsortiumRoster()).toBeNull();
  });

  it("resolveConsortiumRoster RE-RESOLVES the live roster at ceremony time, not the startup snapshot", async () => {
    const logger = makeLogger();
    const routing = createConsortiumRouting({
      manifestProvider: makeProvider(makeManifest()),
      manifestVersionStore: makeVersionStore(),
      manifestRootKeys: ROOT_KEYS,
      manifestThreshold: THRESHOLD,
      logger,
      fetchFn: bootstrapFetch(["n1", "n2"]),
    });

    expect(await routing.resolveConsortiumRoster()).toHaveLength(2);
  });

  it("resolveConsortiumRoster returns [] — NOT null — when a manifest IS configured but no node is reachable", async () => {
    const logger = makeLogger();
    const routing = createConsortiumRouting({
      manifestProvider: makeProvider(makeManifest()),
      manifestVersionStore: makeVersionStore(),
      manifestRootKeys: ROOT_KEYS,
      manifestThreshold: THRESHOLD,
      logger,
      fetchFn: bootstrapFetch([]), // the whole consortium is down
    });

    // The distinction the ceremony layer depends on: [] is "a consortium whose nodes are all
    // unreachable" and MUST be refused against the threshold. Collapsing it to null here would
    // silently downgrade a dead consortium into a single-node back-compat ceremony.
    expect(await routing.resolveConsortiumRoster()).toEqual([]);
  });

  // Launch triage item 6 — "online" does not mean reachable.
  //
  // The startup sweep is the ONE that matters for this defect. On 2026-07-31 a cached NXDOMAIN meant
  // no directory endpoint resolved from the moment the daemon booted; `dns_error` was in the log 26
  // times per node FROM STARTUP, and the operator was shown three errors that each named a different
  // innocent subsystem. The operator-facing store was empty the whole time, because this sweep
  // resolved the roster and threw the per-node failures away — it logged a count and kept no detail.
  //
  // So the first `cello status` after boot, which is exactly what someone runs, could say nothing.
  it("startup sweep REPORTS which nodes failed and why — not just how many resolved", async () => {
    const logger = makeLogger();
    const result = await verifyStartupManifest({
      manifestProvider: makeProvider(makeManifest()),
      manifestVersionStore: makeVersionStore(),
      manifestRootKeys: ROOT_KEYS,
      manifestThreshold: THRESHOLD,
      logger,
      fetchFn: bootstrapFetch(["n1"]), // n2 is unreachable
    });

    // The half that already worked: n1 resolved.
    expect(result.consortiumEndpoints.map((e) => e.nodeId)).toEqual(["n1"]);

    // The half that was discarded: WHICH node, and WHY. A count cannot be carried to an operator.
    expect(result.unresolvedNodes.map((f) => f.nodeId)).toEqual(["n2"]);
    expect(result.unresolvedNodes[0].reason).toBe("http_error");
  });

  it("startup sweep reports an EMPTY unresolved list when every node resolves", async () => {
    const logger = makeLogger();
    const result = await verifyStartupManifest({
      manifestProvider: makeProvider(makeManifest()),
      manifestVersionStore: makeVersionStore(),
      manifestRootKeys: ROOT_KEYS,
      manifestThreshold: THRESHOLD,
      logger,
      fetchFn: bootstrapFetch(["n1", "n2"]),
    });

    expect(result.unresolvedNodes).toEqual([]);
  });

  it("routing seeded with the startup failures reports them BEFORE any later sweep runs", () => {
    const logger = makeLogger();
    const startupFailures = [{ nodeId: "n2", endpoint: "https://n2.example.com", reason: "dns_error", detail: "ENOTFOUND" }];
    const routing = createConsortiumRouting({
      manifestProvider: makeProvider(makeManifest()),
      manifestVersionStore: makeVersionStore(),
      manifestRootKeys: ROOT_KEYS,
      manifestThreshold: THRESHOLD,
      initialUnresolvedNodes: startupFailures,
      logger,
    });

    // Without the seed this is [] until some ceremony happens to resolve the roster — which is
    // precisely the window the operator is in when they run `cello status` and get told nothing.
    expect(routing.getUnresolvedNodes()).toEqual(startupFailures);
  });

  it("a later sweep REPLACES the seeded startup failures — a node that recovered must drop out", async () => {
    const logger = makeLogger();
    const routing = createConsortiumRouting({
      manifestProvider: makeProvider(makeManifest()),
      manifestVersionStore: makeVersionStore(),
      manifestRootKeys: ROOT_KEYS,
      manifestThreshold: THRESHOLD,
      initialUnresolvedNodes: [{ nodeId: "n2", endpoint: "https://n2.example.com", reason: "dns_error" }],
      fetchFn: bootstrapFetch(["n1", "n2"]),
      logger,
    });

    await routing.resolveConsortiumRoster();

    // Stale complaints are worse than none: an operator chasing a node that is now fine.
    expect(routing.getUnresolvedNodes()).toEqual([]);
  });

  it("no manifestPollScheduler: no poll is started, and stopHttpManifestPoll is absent", () => {
    const logger = makeLogger();
    const routing = createConsortiumRouting({
      manifestProvider: makeProvider(makeManifest()),
      manifestVersionStore: makeVersionStore(),
      manifestRootKeys: ROOT_KEYS,
      manifestThreshold: THRESHOLD,
      logger,
    });

    expect(routing.stopHttpManifestPoll).toBeUndefined();
  });

  it("with a scheduler and full manifest deps, the HTTP manifest poll IS started and is stoppable", () => {
    const logger = makeLogger();
    const scheduler = { scheduleNext: vi.fn(), cancel: vi.fn() };
    const routing = createConsortiumRouting({
      manifestProvider: makeProvider(makeManifest()),
      manifestVersionStore: makeVersionStore(),
      manifestRootKeys: ROOT_KEYS,
      manifestThreshold: THRESHOLD,
      manifestPollScheduler: scheduler as never,
      directoryHttpUrl: "https://directory.example.com",
      logger,
    });

    expect(scheduler.scheduleNext).toHaveBeenCalled();
    expect(routing.stopHttpManifestPoll).toBeInstanceOf(Function);
    routing.stopHttpManifestPoll?.();
  });

  it("a scheduler with an EMPTY root-key set does not start the poll — it would verify against nothing", () => {
    const logger = makeLogger();
    const scheduler = { scheduleNext: vi.fn(), cancel: vi.fn() };
    const routing = createConsortiumRouting({
      manifestProvider: makeProvider(makeManifest()),
      manifestVersionStore: makeVersionStore(),
      manifestRootKeys: [],
      manifestThreshold: THRESHOLD,
      manifestPollScheduler: scheduler as never,
      directoryHttpUrl: "https://directory.example.com",
      logger,
    });

    expect(scheduler.scheduleNext).not.toHaveBeenCalled();
    expect(routing.stopHttpManifestPoll).toBeUndefined();
  });
});
