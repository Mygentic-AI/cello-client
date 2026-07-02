/**
 * M7 Keystone (Part 1) — directory endpoint bootstrap for the daemon.
 *
 * Ports the proven M6 bootstrap path from the cello-mcp adapter
 * (core/adapter-claude-code/src/config.ts) into the daemon, which is the cello
 * client going forward. The daemon must not depend on the adapter (the adapter
 * sits ABOVE the daemon as a thin IPC proxy), so the logic lives here.
 *
 * Mechanism (unchanged from M6):
 *   1. resolveDirectoryUrl(env): CELLO_DIRECTORY_URL or the production ALB URL.
 *   2. GET ${url}/bootstrap → { multiaddr } containing "/p2p/<peerId>".
 *   3. The peer ID is the segment after the final "/p2p/" in the multiaddr.
 *
 * The resolver caches the first successful resolution and re-attempts on each
 * connect until it succeeds, so a daemon that starts before the directory is
 * reachable will connect once the bootstrap endpoint comes up (the transport
 * SignalingManager retries connect()).
 */

import type { ConsortiumNode } from "@cello-protocol/protocol-types";
import type { DirectoryEndpoint } from "./signaling-connect.js";
import type { Logger } from "./types.js";

/** Production directory HTTP endpoint (ALB / Route53 — ALB terminates TLS, internal HTTP). */
export const PRODUCTION_DIRECTORY_URL = "http://directory-us1.cello.mygentic.ai";

/**
 * Resolve the directory URL from the environment, falling back to the production
 * endpoint when CELLO_DIRECTORY_URL is not set. Matches the M6 adapter contract.
 */
export function resolveDirectoryUrl(env: Record<string, string | undefined> = process.env): string {
  return env["CELLO_DIRECTORY_URL"] ?? PRODUCTION_DIRECTORY_URL;
}

/**
 * Auto-discover the directory multiaddr via GET /bootstrap on the directory HTTP
 * endpoint. Returns the multiaddr (which embeds the peer ID after "/p2p/"), or null.
 */
export async function fetchBootstrapMultiaddr(
  directoryUrl: string,
  fetchFn: typeof fetch = fetch,
): Promise<string | null> {
  const bootstrapUrl = `${directoryUrl.replace(/\/$/, "")}/bootstrap`;
  const ac = new AbortController();
  const timeout = setTimeout(() => ac.abort(), 5000);
  try {
    const resp = await fetchFn(bootstrapUrl, { signal: ac.signal });
    if (!resp.ok) return null;
    const json = (await resp.json()) as { multiaddr?: unknown };
    if (typeof json.multiaddr === "string" && json.multiaddr.includes("/p2p/")) {
      return json.multiaddr;
    }
    return null;
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Extract the libp2p peer ID from a multiaddr — the segment after the final
 * "/p2p/". Returns null if absent.
 */
export function parsePeerIdFromMultiaddr(multiaddr: string): string | null {
  const idx = multiaddr.lastIndexOf("/p2p/");
  if (idx === -1) return null;
  const peerId = multiaddr.slice(idx + "/p2p/".length).split("/")[0];
  return peerId && peerId.length > 0 ? peerId : null;
}

// ─── DOD-MANIFEST-1: consortium manifest node set → N directory endpoints ──────

/** A resolved consortium directory node: its manifest identity + live dial coordinate. */
export interface ConsortiumEndpoint {
  /** The node's stable consortium identifier (from the manifest). */
  nodeId: string;
  /** The node's Ed25519 pubkey (from the manifest) — used for step-6 identity + addressing. */
  pubkey: string;
  /** The libp2p peer ID resolved from the node's live /bootstrap. */
  peerId: string;
  /** The libp2p multiaddr resolved from the node's live /bootstrap. */
  multiaddr: string;
}

/**
 * Validate + normalise a manifest node `endpoint` to the HTTP(S) base used for its
 * `/bootstrap` probe, or return `null` if it is not a usable bootstrap base.
 *
 * CONTRACT (M8B-DECISIONS): a manifest `endpoint` is the node's HTTP(S) `/bootstrap`
 * base — production directories serve `/bootstrap` over plaintext HTTP behind the ALB
 * (matching PRODUCTION_DIRECTORY_URL, which is `http://…:80`). The wss libp2p DIAL
 * address is returned BY `/bootstrap`; it is NOT the endpoint. So we deliberately do
 * NOT accept (or port-guess) a `wss://host:443` value — mapping that to
 * `http://host:443` would speak plaintext to the TLS port and silently fail. Anything
 * that is not `http(s)://` (a bare multiaddr, a wss dial address, a typo) is a config
 * error in officer-SIGNED data: return null so the caller logs it DISTINCTLY from a
 * transient outage and never dials a wrong port. A single trailing slash is stripped
 * (fetchBootstrapMultiaddr appends `/bootstrap`).
 */
export function mapEndpointToBootstrapBase(endpoint: string): string | null {
  const noSlash = endpoint.replace(/\/$/, "");
  if (noSlash.startsWith("http://") || noSlash.startsWith("https://")) return noSlash;
  return null;
}

export interface ManifestResolveOptions {
  logger: Logger;
  /** Injectable fetch for testing. */
  fetchFn?: typeof fetch;
}

/**
 * Resolve every consortium node in the manifest's node set to a live directory
 * endpoint by probing each node's `/bootstrap` (in parallel, order preserved).
 *
 * AVAILABILITY-AWARE (CLAUDE.md redundancy invariant): a node whose bootstrap is
 * unreachable is SKIPPED with a warning — one node down must never strand the others,
 * because a T-of-N ceremony only needs T of the N. Returns the resolved subset
 * (possibly empty). The CALLER decides whether the resolved count meets the threshold;
 * this function NEVER silently substitutes the single hardcoded endpoint for a missing
 * node — that would defeat sovereignty by masking a down/forged node as healthy.
 */
export async function manifestNodesToEndpoints(
  nodes: readonly ConsortiumNode[],
  opts: ManifestResolveOptions,
): Promise<ConsortiumEndpoint[]> {
  const fetchFn = opts.fetchFn ?? fetch;
  const resolved = await Promise.all(
    nodes.map(async (node): Promise<ConsortiumEndpoint | null> => {
      const base = mapEndpointToBootstrapBase(node.endpoint);
      if (base === null) {
        // PERMANENT config error in SIGNED manifest data — logged distinctly from a
        // transient `unresolved` so a bad endpoint is never mistaken for a node that's
        // merely down (fail loud, don't silently skip-as-if-outage).
        opts.logger.error("directory.consortium.node.endpoint_invalid", {
          nodeId: node.nodeId,
          endpoint: node.endpoint,
        });
        return null;
      }
      const multiaddr = await fetchBootstrapMultiaddr(base, fetchFn);
      if (!multiaddr) {
        opts.logger.warn("directory.consortium.node.unresolved", {
          nodeId: node.nodeId,
          endpoint: node.endpoint,
        });
        return null;
      }
      const peerId = parsePeerIdFromMultiaddr(multiaddr);
      if (!peerId) {
        opts.logger.error("directory.consortium.node.no_peer_id", { nodeId: node.nodeId, multiaddr });
        return null;
      }
      return { nodeId: node.nodeId, pubkey: node.pubkey, peerId, multiaddr };
    }),
  );
  return resolved.filter((e): e is ConsortiumEndpoint => e !== null);
}

export interface DirectoryEndpointResolverOptions {
  logger: Logger;
  /** Defaults to resolveDirectoryUrl(process.env). */
  directoryUrl?: string;
  /** Injectable fetch for testing. */
  fetchFn?: typeof fetch;
  /**
   * Whether a fresh /bootstrap failure falls back to the last known-good endpoint (default true).
   *
   * FINDING-4: set FALSE when this resolver is used as the PRIMARY probe inside
   * createRosterAwareEndpointResolver. There, the stale-last-known-good fallback is HARMFUL — it
   * masks a dead primary (a fresh failure returns the cached dead endpoint, so the wrapper never
   * observes the primary as "down" and never fails over to the roster). With staleFallback:false a
   * fresh failure returns null, and the roster becomes the real (and only) fallback. The default
   * (true) preserves the M6/single-node backward-compat behavior for callers that are NOT wrapped.
   */
  staleFallback?: boolean;
}

/**
 * Build an async `getDirectoryEndpoint` for createSignalingConnect.
 *
 * Re-resolves the bootstrap on EVERY call (i.e. every connect attempt) so a
 * directory address change — failover, DNS/port change, or peer-ID rotation — is
 * picked up on the next reconnect. The last successfully-resolved endpoint is kept
 * only as a fallback: if a fresh fetch fails, the resolver returns the last
 * known-good endpoint so a transient /bootstrap blip doesn't strand a working daemon.
 */
export function createDirectoryEndpointResolver(
  opts: DirectoryEndpointResolverOptions,
): () => Promise<DirectoryEndpoint | null> {
  const directoryUrl = opts.directoryUrl ?? resolveDirectoryUrl();
  const fetchFn = opts.fetchFn ?? fetch;
  const staleFallback = opts.staleFallback ?? true;
  let lastGood: DirectoryEndpoint | null = null;

  return async function getDirectoryEndpoint(): Promise<DirectoryEndpoint | null> {
    const multiaddr = await fetchBootstrapMultiaddr(directoryUrl, fetchFn);
    if (multiaddr) {
      const peerId = parsePeerIdFromMultiaddr(multiaddr);
      if (peerId) {
        // Log only when the resolved endpoint actually changes (avoids per-connect noise).
        if (!lastGood || lastGood.multiaddr !== multiaddr) {
          opts.logger.info("directory.bootstrap.resolved", { directoryUrl, peerId });
        }
        lastGood = { peerId, multiaddr };
        return lastGood;
      }
      opts.logger.error("directory.bootstrap.no_peer_id", { directoryUrl, multiaddr });
    } else {
      opts.logger.warn("directory.bootstrap.unavailable", { directoryUrl });
    }
    // Fresh resolution failed — reuse the last known-good endpoint if we have one AND stale fallback
    // is enabled. When disabled (the failover-wrapper's primary probe), a fresh failure is reported
    // as null so the roster can take over instead of the caller looping on a dead endpoint.
    if (staleFallback && lastGood) {
      opts.logger.warn("directory.bootstrap.using_last_known", { directoryUrl, peerId: lastGood.peerId });
      return lastGood;
    }
    return null;
  };
}

// ─── FINDING-4: roster-aware directory failover (bootstrap SPOF fix) ────────────

export interface RosterAwareResolverOptions {
  /**
   * Resolve the PRIMARY (configured) directory endpoint — typically the result of
   * createDirectoryEndpointResolver (probes CELLO_DIRECTORY_URL's /bootstrap).
   */
  primaryResolver: () => Promise<DirectoryEndpoint | null>;
  /**
   * Resolve the CURRENTLY-REACHABLE consortium roster. Each member returned has already
   * had its /bootstrap probed (manifestNodesToEndpoints skips unreachable nodes), so a
   * member's presence in the returned array IS its reachability. NULL on the M6/M7
   * back-compat path (no consortium manifest configured) → no failover, primary-only.
   */
  getConsortiumRoster: () => Promise<ConsortiumEndpoint[] | null>;
  logger: Logger;
  /**
   * Test seam: order the fallback candidates. Production defaults to a Fisher-Yates
   * shuffle so clients don't stampede one node when the primary goes down (CLAUDE.md
   * redundancy invariant). Tests inject an identity shuffle for deterministic ordering.
   */
  shuffle?: <T>(items: T[]) => T[];
}

/** In-place-safe Fisher-Yates shuffle returning a NEW array (never mutates the input). */
function fisherYatesShuffle<T>(items: T[]): T[] {
  const out = items.slice();
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

/**
 * Wrap a single-node primary resolver with the consortium roster so the signaling
 * dialer (and the ceremony endpoint that shares this instance) route AROUND a down
 * primary directory node instead of retrying the single primary URL forever — the
 * FINDING-4 bootstrap SPOF fix, honoring the sovereign-node REDUNDANCY invariant.
 *
 * Selection policy, per getDirectoryEndpoint() call:
 *   1. Sticky-until-fail — while riding a non-primary fallback, KEEP it as long as it's
 *      still in the reachable roster. Do NOT churn back to the primary when it recovers
 *      (no flapping / reconnect storm). The fallback's multiaddr is refreshed from the
 *      fresh roster match each call.
 *   2. Primary-first — otherwise try the configured node. This is also the healthy
 *      steady state: when the primary resolves, we return WITHOUT probing the roster
 *      (no per-connect roster cost while everything is nominal).
 *   3. Fallback — if the primary is down, fail over to a reachable roster member. The
 *      order is randomized (across the members other than the dead primary) so clients
 *      spread across the survivors. Emits directory.bootstrap.failover on a change so an
 *      operator sees the client is now running on a non-home node.
 *   4. Return null only when NOTHING resolves (primary down AND roster empty/absent) —
 *      the unchanged all-nodes-down failure mode, no crash.
 *
 * ONE instance is shared across the daemon's signaling connect and its ceremony
 * getDirectoryEndpoint so signaling + ceremonies stay on the SAME directory node and
 * fail over together (a coherent per-daemon directory selection).
 *
 * Scope note (FINDING-4 sufficiency, unproven): stickiness here is by ROSTER
 * REACHABILITY, not by observed connect success — the resolver is not told whether a
 * dial/auth against the returned endpoint actually succeeded. A node whose /bootstrap
 * resolves is served by that same node, so resolvable ≈ connectable in practice; the
 * live kill-primary failover test is the real proof that presence resolution, relay
 * assignment, and the FROST ceremony all work against a non-home directory.
 */
export function createRosterAwareEndpointResolver(
  opts: RosterAwareResolverOptions,
): () => Promise<DirectoryEndpoint | null> {
  const shuffle = opts.shuffle ?? fisherYatesShuffle;
  // The endpoint we last returned, and whether it is a non-primary fallback we're riding.
  let current: DirectoryEndpoint | null = null;
  let stuckToFallback = false;
  // The primary's own identity, learned whenever the primary last resolved. Used to EXCLUDE the
  // primary from the fallback set even when `current` no longer points at it — a flapping primary
  // whose independent roster probe still lists it must never be re-picked as its own fallback.
  let primaryPeerId: string | null = null;

  return async function getDirectoryEndpoint(): Promise<DirectoryEndpoint | null> {
    // 1. Sticky-until-fail: keep the current fallback while it is still reachable.
    if (stuckToFallback && current) {
      const roster = await opts.getConsortiumRoster();
      const match = roster?.find((e) => e.peerId === current!.peerId);
      if (match) {
        // Refresh the multiaddr from the fresh roster resolution; identity is unchanged.
        current = { peerId: match.peerId, multiaddr: match.multiaddr };
        return current;
      }
      // The fallback fell out of the reachable roster → re-select below.
      opts.logger.warn("directory.bootstrap.failover.lost", { peerId: current.peerId });
    }

    // 2. Primary-first (and the healthy steady state — no roster probe when it resolves).
    const primary = await opts.primaryResolver();
    if (primary) {
      if (stuckToFallback) {
        opts.logger.info("directory.bootstrap.failover", { to: primary.peerId, restored: true });
      }
      current = primary;
      primaryPeerId = primary.peerId;
      stuckToFallback = false;
      return primary;
    }

    // 3. Primary is down → fail over to a reachable roster member (randomized order).
    const roster = await opts.getConsortiumRoster();
    if (roster && roster.length > 0) {
      // Exclude the (now-dead/flapping) primary and the current pointer; any OTHER reachable member
      // is valid. Falls back to the full roster only if excluding leaves nothing (all members are
      // the excluded ones — e.g. the roster is just the primary itself).
      const excluded = new Set([current?.peerId, primaryPeerId].filter((p): p is string => !!p));
      const others = roster.filter((e) => !excluded.has(e.peerId));
      const ordered = shuffle(others.length > 0 ? others : roster);
      const chosen = ordered[0];
      const next: DirectoryEndpoint = { peerId: chosen.peerId, multiaddr: chosen.multiaddr };
      if (!current || current.peerId !== chosen.peerId) {
        opts.logger.warn("directory.bootstrap.failover", {
          from: current?.peerId ?? null,
          to: chosen.peerId,
          nodeId: chosen.nodeId,
        });
      }
      current = next;
      stuckToFallback = true;
      return next;
    }

    // 4. Nothing resolves.
    return null;
  };
}
