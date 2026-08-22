/**
 * The startup consortium gate, and the routing it feeds.
 *
 * Two functions, and the split between them is the point:
 *
 *   1. verifyStartupManifest — loads and verifies the consortium manifest, checks its validity
 *      window and anti-rollback, and resolves the verified node set to live directory endpoints.
 *      It REPORTS what it found. It does NOT decide what to do about a failure.
 *
 *   2. createConsortiumRouting — builds the roster-aware failover resolver and starts the HTTP
 *      manifest poll.
 *
 * They are separate because startDaemon must be able to REFUSE TO START between them (ADV-002:
 * a configured manifestProvider that fails verification is fatal). That refusal has to close the
 * DB and release the singleton lock — both owned by startDaemon, neither this module's business —
 * and it must happen BEFORE the manifest poll starts, or a refused startup leaks a live timer.
 * Fusing these into one call would either drag the lock in here or leak that timer.
 */
import type { Logger } from "./types.js";
import type { ConsortiumManifest } from "@cello-protocol/protocol-types";
import type {
  IManifestProvider,
  IManifestVersionStore,
  IManifestPollScheduler,
} from "@cello-protocol/transport";
import { randomUUID } from "node:crypto";
import { startHttpManifestPoll } from "./http-manifest-poll.js";
import type { ProbeBudget } from "./directory-bootstrap.js";
import type { DirectoryEndpoint } from "./signaling-connect.js";
import {
  resolveDirectoryUrl,
  manifestNodesToEndpoints, FAST_PROBE,
  type NodeResolveFailure,
  createRosterAwareEndpointResolver,
  type ConsortiumEndpoint,
} from "./directory-bootstrap.js";

export interface ManifestGateDeps {
  manifestProvider?: IManifestProvider;
  manifestRootKeys?: readonly string[];
  manifestThreshold?: number;
  manifestVersionStore: IManifestVersionStore;
  logger: Logger;
  /** Injectable fetch, threaded to the /bootstrap probes. Defaults to global fetch. */
  fetchFn?: typeof fetch;
}

export interface ManifestGateResult {
  /** True only when a manifest was loaded, verified, in-window, and not a rollback. */
  manifestVerified: boolean;
  /** The verified manifest's version — 0 on the no-manifest back-compat path. */
  verifiedManifestVersion: number;
  /**
   * The verified node set resolved to REACHABLE directory endpoints. May be shorter than the
   * manifest's node list (a down node is skipped, not fatal — a T-of-N ceremony needs only T),
   * and is empty on the back-compat path or when nothing resolved.
   */
  consortiumEndpoints: ConsortiumEndpoint[];
  /**
   * The VERIFIED manifest itself, or null on every path that did not verify one.
   *
   * Returned because a sealed submission needs the manifest's `intake_key` at request time, long
   * after startup (M10B / DOD-END-SURFACE-1, the refusal-message carrier). Set ONLY alongside
   * `manifestVerified = true`, so an unverified manifest can never reach a consumer: a sealing key
   * read off an unverified manifest is a key an attacker chose, which would seal the operator's
   * words to the attacker instead of the portal.
   */
  verifiedManifest: ConsortiumManifest | null;
  /**
   * WHICH nodes did not resolve, and why — the operator-facing counterpart to the count above.
   *
   * This sweep runs at boot, and for the failure it exists to describe that is the only sweep that
   * has run when the operator first looks. It used to log `directory.consortium.partial` with a
   * count and discard the detail, so `cello status` could say nothing at all while every session
   * failed. That is the 2026-07-31 incident: `dns_error` in the log 26 times per node from startup,
   * the operator shown `counterparty_offline` → `directory_below_threshold` → `ceremony_exhausted`,
   * and an hour spent concluding the protocol was broken.
   *
   * Empty on every path that resolved nothing to complain about — including the back-compat path,
   * where an empty list means "no sweep ran", not "all healthy". The status surface says which
   * nodes failed rather than asserting all-good, for exactly that reason.
   */
  unresolvedNodes: NodeResolveFailure[];
  /**
   * When the sweep above ran (ISO), or null if none did.
   *
   * A reading with no timestamp asserts the PRESENT. On 2026-08-09 all three endpoints failed with
   * ENETUNREACH — a real network blip on the operator's machine, gone within a minute — and the
   * status block went on reporting "this daemon cannot resolve these directory endpoints" as a
   * current fact long after it had recovered. True when taken, false when read.
   */
  unresolvedSweptAt: string | null;
}

/**
 * Load + verify the manifest, then resolve its node set to live endpoints.
 *
 * Every failure is REPORTED (manifestVerified: false) and logged, never thrown — the caller owns
 * the refuse-to-start decision, because only it can release what a refusal must release.
 */
export async function verifyStartupManifest(deps: ManifestGateDeps): Promise<ManifestGateResult> {
  const { manifestProvider, manifestRootKeys, manifestThreshold, manifestVersionStore, logger, fetchFn } = deps;

  let manifestVerified = false;
  let verifiedManifestVersion = 0;
  let consortiumEndpoints: ConsortiumEndpoint[] = [];
  let verifiedManifest: ConsortiumManifest | null = null;
  const unresolvedNodes: NodeResolveFailure[] = [];
  let unresolvedSweptAt: string | null = null;

  if (!manifestProvider || !manifestRootKeys || manifestThreshold === undefined) {
    return { manifestVerified, verifiedManifestVersion, consortiumEndpoints, verifiedManifest, unresolvedNodes, unresolvedSweptAt };
  }

  try {
    const manifest = await manifestProvider.loadAndVerify(manifestRootKeys, manifestThreshold);

    const now = new Date();
    const notBefore = new Date(manifest.not_before);
    const expiresAt = new Date(manifest.expires);

    if (now < notBefore) {
      logger.error("directory.auth.manifest.not.yet.valid", {
        manifestVersion: manifest.version,
        notBefore: manifest.not_before,
      });
      return { manifestVerified, verifiedManifestVersion, consortiumEndpoints, verifiedManifest, unresolvedNodes, unresolvedSweptAt };
    }
    if (expiresAt <= now) {
      logger.error("directory.auth.manifest.expired", {
        manifestVersion: manifest.version,
        expiresAt: manifest.expires,
      });
      return { manifestVerified, verifiedManifestVersion, consortiumEndpoints, verifiedManifest, unresolvedNodes, unresolvedSweptAt };
    }

    // Anti-rollback. Equal versions are fine (a restart on an unchanged manifest); only a STRICTLY
    // older version is a rollback attempt.
    const lastSeen = await manifestVersionStore.getLastSeenVersion();
    if (lastSeen !== null && manifest.version < lastSeen) {
      logger.error("directory.auth.manifest.version.rollback", {
        manifestVersion: manifest.version,
        lastSeenVersion: lastSeen,
      });
      return { manifestVerified, verifiedManifestVersion, consortiumEndpoints, verifiedManifest, unresolvedNodes, unresolvedSweptAt };
    }

    await manifestVersionStore.persistVersion(manifest.version);
    manifestVerified = true;
    verifiedManifestVersion = manifest.version;
    // Retained ONLY here — on the one path where the signatures, the window, and the anti-rollback
    // check have all passed.
    verifiedManifest = manifest;
    logger.info("directory.auth.manifest.verified", {
      manifestVersion: manifest.version,
      signerCount: manifest.signatures.length,
    });

    // DOD-MANIFEST-1: resolve the FULL verified node set — this is the roster a T-of-N ceremony
    // fans out to. Availability-aware: a down node is skipped and the rest still resolve. The
    // threshold gate lives in the ceremony layer (DOD-DKG-1); it NEVER falls back to the single
    // hardcoded endpoint for a missing node, which would mask a down/forged node as healthy.
    consortiumEndpoints = await manifestNodesToEndpoints(manifest.nodes, {
      logger,
      fetchFn,
      // The detail this sweep used to throw away. See ManifestGateResult.unresolvedNodes.
      onNodeUnresolved: (f) => unresolvedNodes.push(f),
    });
    unresolvedSweptAt = new Date().toISOString();
    const declaredNodes = manifest.nodes.length;
    const resolvedNodes = consortiumEndpoints.length;
    // Carry the nodeId↔peerId pairing (not just peerIds) so a consumer can verify each manifest
    // identity is bound to the right live directory, not merely that the set has the right size.
    const consortiumLog = {
      manifestVersion: manifest.version,
      declaredNodes,
      resolvedNodes,
      nodes: consortiumEndpoints.map((e) => ({ nodeId: e.nodeId, peerId: e.peerId })),
    };
    // Degraded ≠ healthy: a shrunken or empty roster must be loud, never buried at info.
    if (resolvedNodes === 0) {
      logger.error("directory.consortium.none", consortiumLog);
    } else if (resolvedNodes < declaredNodes) {
      logger.warn("directory.consortium.partial", consortiumLog);
    } else {
      logger.info("directory.consortium.resolved", consortiumLog);
    }
  } catch (err: unknown) {
    logger.error("directory.auth.manifest.load.failed", {
      error: err instanceof Error ? err.message : String(err),
    });
  }

  return { manifestVerified, verifiedManifestVersion, consortiumEndpoints, verifiedManifest, unresolvedNodes, unresolvedSweptAt };
}

export interface ConsortiumRoutingDeps {
  manifestProvider?: IManifestProvider;
  manifestRootKeys?: readonly string[];
  manifestThreshold?: number;
  manifestVersionStore: IManifestVersionStore;
  manifestPollScheduler?: IManifestPollScheduler;
  directoryHttpUrl?: string;
  directoryEndpointResolver?: () => Promise<DirectoryEndpoint | null>;
  logger: Logger;
  fetchFn?: typeof fetch;
  /**
   * What the startup sweep already found unresolvable, so the operator surface is populated from
   * boot rather than from whenever the first ceremony happens to run. See the seeding note inside.
   */
  initialUnresolvedNodes?: readonly NodeResolveFailure[];
  /** When that startup sweep ran, so the surface can say how old the reading is. */
  initialUnresolvedSweptAt?: string | null;
}

export interface ConsortiumRouting {
  /**
   * The roster for a session/seal FROST ceremony, re-resolved at ceremony time from the CURRENT
   * verified manifest. NULL (not []) when no manifest is configured — the difference is
   * load-bearing: null means "single-node ceremony, M6/M7 back-compat"; [] means "a consortium
   * whose nodes are all unreachable", which the ceremony layer must refuse.
   */
  resolveConsortiumRoster: () => Promise<ConsortiumEndpoint[] | null>;
  /**
   * Roster-aware failover over the injected primary resolver (FINDING-4, the bootstrap SPOF).
   * ONE instance, so signaling and ceremonies share sticky state and fail over TOGETHER — they
   * must not end up talking to two different directory nodes. Undefined on the in-process test
   * path, where there is no primary resolver to wrap.
   */
  failoverEndpointResolver: (() => Promise<DirectoryEndpoint | null>) | undefined;
  /**
   * Which consortium nodes this daemon currently cannot resolve, and why.
   *
   * Exists so `cello status` can answer "can I actually reach the directory?" rather than only
   * "is my signaling socket up?". Those differ: libp2p signaling dials multiaddrs from the bundled
   * manifest and stays connected, so every agent reports online while anything needing the HTTP
   * endpoint — the roster, and therefore every threshold ceremony — fails.
   */
  getUnresolvedNodes: () => NodeResolveFailure[];
  /** When the reading getUnresolvedNodes returns was taken (ISO), or null if no sweep has run. */
  getUnresolvedSweptAt: () => string | null;
  /** Nodes the VERIFIED manifest declares — the denominator a threshold is computed from. */
  getDeclaredNodeCount: () => number | null;
  /** Null-safe accessor for the ceremony/handler getDirectoryEndpoint sites. */
  getFailoverEndpoint: () => Promise<DirectoryEndpoint | null>;
  /** Stops the daemon-level HTTP manifest poll. Undefined when no poll was started. */
  stopHttpManifestPoll: (() => void) | undefined;
}

export function createConsortiumRouting(deps: ConsortiumRoutingDeps): ConsortiumRouting {
  const {
    manifestProvider, manifestRootKeys, manifestThreshold, manifestVersionStore,
    manifestPollScheduler, directoryHttpUrl, directoryEndpointResolver, logger, fetchFn,
  } = deps;

  // LAST failure per node, not a running count — the operator needs the current state, and a node
  // that has started resolving again must drop out rather than linger as a stale complaint. Cleared
  // per sweep: every resolve attempt rebuilds this from what actually failed that time.
  //
  // SEEDED from the startup sweep, because otherwise this is empty until some ceremony happens to
  // resolve a roster — and the operator's first `cello status` after boot lands squarely in that
  // window. That silence is the whole reason item 6 exists. The seed is a starting value, not a
  // floor: the first real sweep replaces it, so a node that has recovered stops being reported.
  let unresolvedNodes: NodeResolveFailure[] = [...(deps.initialUnresolvedNodes ?? [])];
  let unresolvedSweptAt: string | null = deps.initialUnresolvedSweptAt ?? null;
  const getUnresolvedNodes = (): NodeResolveFailure[] => [...unresolvedNodes];
  const getUnresolvedSweptAt = (): string | null => unresolvedSweptAt;

  const resolveConsortiumRoster = async (budget?: ProbeBudget): Promise<ConsortiumEndpoint[] | null> => {
    const m = manifestProvider?.getCurrentManifest();
    if (!m) return null;
    const failures: NodeResolveFailure[] = [];
    const endpoints = await manifestNodesToEndpoints(m.nodes, {
      logger,
      fetchFn,
      onNodeUnresolved: (f) => failures.push(f),
      ...(budget ? { probeBudget: budget } : {}),
    });
    unresolvedNodes = failures;
    unresolvedSweptAt = new Date().toISOString();
    return endpoints;
  };

  /**
   * How many nodes the VERIFIED MANIFEST declares — no probe, no derivation.
   *
   * DOD-M15-ERRSTRING-1 (review MEDIUM-2). The roster-shortfall note first computed
   * `declared = reachable + unresolved`, which silently undercounts: `manifestNodesToEndpoints`
   * also drops nodes for an invalid endpoint and for a peer-id mismatch, and neither calls
   * `onNodeUnresolved`. With 5 declared, 2 peer-id mismatches and 1 probe failure, that arithmetic
   * yields a threshold of 2 and the note reports ceremonies CAN complete — when the real threshold
   * is 3 and they cannot. The line whose job is to name a shortfall would have denied it.
   *
   * Worse, when every drop is a silent one the note is empty — mute on exactly the security-relevant
   * case, since a peer-id mismatch is a node you most want named.
   */
  const getDeclaredNodeCount = (): number | null => manifestProvider?.getCurrentManifest()?.nodes.length ?? null;

  // DECLARED membership, straight off the verified manifest — no probe. Lets the resolver reject a
  // primary that resolves but belongs to a different consortium (the compiled-in default URL after
  // a consortium move) without mistaking a momentarily-down member for a non-member.
  const getManifestPeerIds = (): Set<string> | null => {
    const m = manifestProvider?.getCurrentManifest();
    if (!m) return null;
    const ids = m.nodes.map((n) => n.peerId).filter((p): p is string => typeof p === "string" && p.length > 0);
    return ids.length > 0 ? new Set(ids) : null;
  };

  const failoverEndpointResolver = directoryEndpointResolver
    ? createRosterAwareEndpointResolver({
        primaryResolver: directoryEndpointResolver,
        // FAST_PROBE (review HIGH-1): this resolver runs inside the 10 s signaling wait, and the
        // roster sweep is its slowest leg — Promise.all waits for the slowest node, so one
        // unreachable node cost 16 s here while the failover path had already spent 8 s on the
        // primary. Persistence belongs to startup and the background poll, where nothing waits.
        getConsortiumRoster: () => resolveConsortiumRoster(FAST_PROBE),
        getManifestPeerIds,
        logger,
      })
    : undefined;

  const getFailoverEndpoint = async (): Promise<DirectoryEndpoint | null> =>
    failoverEndpointResolver ? await failoverEndpointResolver() : null;

  // CELLO-M7-CONN-001 (DOD-CONN-3): the daemon-level manifest poll — it adopts a newer manifest
  // independent of any agent identity, and so runs even with ZERO agents (the keystone it replaced
  // could not). Off on the M6 back-compat path (no scheduler), and off without real root keys: a
  // poll that verifies against an empty key set verifies against nothing.
  let stopHttpManifestPoll: (() => void) | undefined;
  if (manifestPollScheduler && manifestProvider && manifestRootKeys && manifestRootKeys.length > 0 && manifestThreshold && manifestThreshold >= 1) {
    stopHttpManifestPoll = startHttpManifestPoll({
      scheduler: manifestPollScheduler,
      directoryUrl: directoryHttpUrl ?? resolveDirectoryUrl(process.env),
      manifestProvider,
      manifestVersionStore,
      rootKeys: manifestRootKeys,
      threshold: manifestThreshold,
      logger,
      mintCorrelationId: () => randomUUID(),
    });
  }

  return { resolveConsortiumRoster, failoverEndpointResolver, getFailoverEndpoint, getUnresolvedNodes, getUnresolvedSweptAt, getDeclaredNodeCount, stopHttpManifestPoll };
}
