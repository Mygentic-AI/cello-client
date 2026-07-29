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
import type {
  IManifestProvider,
  IManifestVersionStore,
  IManifestPollScheduler,
} from "@cello-protocol/transport";
import { randomUUID } from "node:crypto";
import { startHttpManifestPoll } from "./http-manifest-poll.js";
import type { DirectoryEndpoint } from "./signaling-connect.js";
import {
  resolveDirectoryUrl,
  manifestNodesToEndpoints,
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

  if (!manifestProvider || !manifestRootKeys || manifestThreshold === undefined) {
    return { manifestVerified, verifiedManifestVersion, consortiumEndpoints };
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
      return { manifestVerified, verifiedManifestVersion, consortiumEndpoints };
    }
    if (expiresAt <= now) {
      logger.error("directory.auth.manifest.expired", {
        manifestVersion: manifest.version,
        expiresAt: manifest.expires,
      });
      return { manifestVerified, verifiedManifestVersion, consortiumEndpoints };
    }

    // Anti-rollback. Equal versions are fine (a restart on an unchanged manifest); only a STRICTLY
    // older version is a rollback attempt.
    const lastSeen = await manifestVersionStore.getLastSeenVersion();
    if (lastSeen !== null && manifest.version < lastSeen) {
      logger.error("directory.auth.manifest.version.rollback", {
        manifestVersion: manifest.version,
        lastSeenVersion: lastSeen,
      });
      return { manifestVerified, verifiedManifestVersion, consortiumEndpoints };
    }

    await manifestVersionStore.persistVersion(manifest.version);
    manifestVerified = true;
    verifiedManifestVersion = manifest.version;
    logger.info("directory.auth.manifest.verified", {
      manifestVersion: manifest.version,
      signerCount: manifest.signatures.length,
    });

    // DOD-MANIFEST-1: resolve the FULL verified node set — this is the roster a T-of-N ceremony
    // fans out to. Availability-aware: a down node is skipped and the rest still resolve. The
    // threshold gate lives in the ceremony layer (DOD-DKG-1); it NEVER falls back to the single
    // hardcoded endpoint for a missing node, which would mask a down/forged node as healthy.
    consortiumEndpoints = await manifestNodesToEndpoints(manifest.nodes, { logger, fetchFn });
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

  return { manifestVerified, verifiedManifestVersion, consortiumEndpoints };
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

  const resolveConsortiumRoster = async (): Promise<ConsortiumEndpoint[] | null> => {
    const m = manifestProvider?.getCurrentManifest();
    return m ? await manifestNodesToEndpoints(m.nodes, { logger, fetchFn }) : null;
  };

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
        getConsortiumRoster: resolveConsortiumRoster,
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

  return { resolveConsortiumRoster, failoverEndpointResolver, getFailoverEndpoint, stopHttpManifestPoll };
}
