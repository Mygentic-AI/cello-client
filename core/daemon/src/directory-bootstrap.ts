/**
 * Directory endpoint bootstrap for the daemon.
 *
 * The logic lives here, not in the adapter: the daemon must not depend on the
 * adapter, which sits ABOVE it as a thin IPC proxy.
 *
 * Mechanism:
 *   1. resolveDirectoryUrl(env): CELLO_DIRECTORY_URL or PRODUCTION_DIRECTORY_URL.
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

/**
 * Production directory HTTP endpoint — the cold-boot fallback when CELLO_DIRECTORY_URL is unset.
 *
 * THIS MUST BE ONE OF THE `endpoint` VALUES IN THE BUNDLED MANIFEST, byte for byte. `buildManifestDeps`
 * loads the bundled roster only when the resolved directory URL matches a node in it, and otherwise
 * falls through to the pre-roster path with NO step-6 directory authentication — so a value that
 * merely reaches the same machine, such as a DNS name for the same host, silently disables the
 * defense against a MITM redirecting /bootstrap to a rogue directory. It fails open and quietly,
 * which is why the requirement is stated here rather than left to be rediscovered.
 *
 * Hence an address and not a name: the manifest carries addresses, and the manifest is signed. Those
 * addresses are reserved (`google_compute_address`, held across instance replacement), so they are
 * stable by construction rather than by luck. `directory-use1.cello.mygentic.ai` also resolves here
 * and is fine for humans and curl — it just cannot be this constant until the manifest carries names.
 *
 * Port 9090 serves /bootstrap. 8080 speaks the libp2p WebSocket upgrade and answers plain HTTP with
 * 400, which resolves as zero reachable nodes from a perfectly valid manifest.
 */
export const PRODUCTION_DIRECTORY_URL = "http://34.75.172.108:9090";

/**
 * Resolve the directory URL from the environment, falling back to the production
 * endpoint when CELLO_DIRECTORY_URL is not set.
 */
export function resolveDirectoryUrl(env: Record<string, string | undefined> = process.env): string {
  return env["CELLO_DIRECTORY_URL"] ?? PRODUCTION_DIRECTORY_URL;
}

/**
 * Failure class of a /bootstrap probe. DNS-INCIDENT R3 (2026-07-24): a blanket
 * `catch { return null }` collapsed every distinct failure into one indistinguishable
 * `unresolved` warning, so a machine-wide negative-DNS-cache outage (all names
 * fail getaddrinfo, servers fully healthy) logged identically to a real server
 * outage. `reason: "dns_error"` on all nodes at once now points at local
 * resolution, not the directories.
 * Incident: trustless-cello docs/planning/discussion_logs/2026-07-24_1630_post-wake-directory-dns-resolution-incident.md
 */
export type BootstrapFailureReason = "dns_error" | "connect_error" | "timeout" | "http_error" | "bad_response";

export type BootstrapResult =
  | { ok: true; multiaddr: string }
  | { ok: false; reason: BootstrapFailureReason; detail?: string };

/** DNS-level getaddrinfo failures vs transport-level connection failures. */
const DNS_CODES = new Set(["ENOTFOUND", "EAI_AGAIN"]);

/** Walk an error's `cause` chain for the first Node `code` (undici nests the coded error). */
function findErrorCode(err: unknown): string | null {
  let cur: unknown = err;
  for (let depth = 0; depth < 5 && cur instanceof Error; depth++) {
    const code = (cur as Error & { code?: unknown }).code;
    if (typeof code === "string") return code;
    cur = cur.cause;
  }
  return null;
}

function classifyFetchError(err: unknown): { reason: BootstrapFailureReason; detail?: string } {
  if (err instanceof Error && err.name === "AbortError") return { reason: "timeout", detail: "AbortError" };
  const code = findErrorCode(err);
  if (code !== null) {
    if (DNS_CODES.has(code)) return { reason: "dns_error", detail: code };
    return { reason: "connect_error", detail: code };
  }
  return { reason: "connect_error", detail: err instanceof Error ? err.message : String(err) };
}

/**
 * Auto-discover the directory multiaddr via GET /bootstrap, classifying failures
 * so callers can log a `reason` that distinguishes "this machine cannot resolve
 * the name" from "the server is down" from "the payload is wrong".
 */
export async function fetchBootstrapResult(
  directoryUrl: string,
  fetchFn: typeof fetch = fetch,
): Promise<BootstrapResult> {
  const bootstrapUrl = `${directoryUrl.replace(/\/$/, "")}/bootstrap`;
  const ac = new AbortController();
  const timeout = setTimeout(() => ac.abort(), 5000);
  try {
    let resp: Response;
    try {
      resp = await fetchFn(bootstrapUrl, { signal: ac.signal });
    } catch (err: unknown) {
      return { ok: false, ...classifyFetchError(err) };
    }
    if (!resp.ok) return { ok: false, reason: "http_error", detail: String(resp.status) };
    let json: { multiaddr?: unknown };
    try {
      json = (await resp.json()) as { multiaddr?: unknown };
    } catch (err: unknown) {
      return { ok: false, reason: "bad_response", detail: err instanceof Error ? err.message : String(err) };
    }
    if (typeof json.multiaddr === "string" && json.multiaddr.includes("/p2p/")) {
      return { ok: true, multiaddr: json.multiaddr };
    }
    return { ok: false, reason: "bad_response", detail: "multiaddr missing or lacks /p2p/" };
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Auto-discover the directory multiaddr via GET /bootstrap on the directory HTTP
 * endpoint. Returns the multiaddr (which embeds the peer ID after "/p2p/"), or null.
 * Thin compatibility wrapper over fetchBootstrapResult (which carries the failure class).
 */
export async function fetchBootstrapMultiaddr(
  directoryUrl: string,
  fetchFn: typeof fetch = fetch,
): Promise<string | null> {
  const result = await fetchBootstrapResult(directoryUrl, fetchFn);
  return result.ok ? result.multiaddr : null;
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

// ─── Consortium manifest node set → N directory endpoints ──────

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
 * CONTRACT: a manifest `endpoint` is the node's HTTP(S) `/bootstrap` base — production
 * directories serve `/bootstrap` over plaintext HTTP on port 9090, directly (there is no load
 * balancer in front of them), matching PRODUCTION_DIRECTORY_URL. 8080 on the same host speaks the
 * libp2p WebSocket upgrade and answers plain HTTP with 400, so pointing this at 8080 resolves as
 * zero reachable nodes from a perfectly valid manifest. The wss libp2p DIAL address is
 * returned BY `/bootstrap`; it is NOT the endpoint. Do NOT accept (or port-guess) a
 * `wss://host:443` value — mapping that to `http://host:443` speaks plaintext to the
 * TLS port and silently fails. Anything
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
 * AVAILABILITY-AWARE (the sovereign-node redundancy invariant): a node whose bootstrap is
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
      const probe = await fetchBootstrapResult(base, fetchFn);
      if (!probe.ok) {
        opts.logger.warn("directory.consortium.node.unresolved", {
          nodeId: node.nodeId,
          endpoint: node.endpoint,
          reason: probe.reason,
          detail: probe.detail,
        });
        return null;
      }
      const multiaddr = probe.multiaddr;
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
   * MUST be FALSE when this resolver is the PRIMARY probe inside createRosterAwareEndpointResolver.
   * There, the stale-last-known-good fallback is HARMFUL — it masks a dead primary (a fresh failure
   * returns the cached dead endpoint, so the wrapper never observes the primary as "down" and never
   * fails over to the roster). With staleFallback:false a fresh failure returns null, and the roster
   * becomes the real (and only) fallback. The default (true) is for unwrapped single-node callers.
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
    const probe = await fetchBootstrapResult(directoryUrl, fetchFn);
    if (probe.ok) {
      const multiaddr = probe.multiaddr;
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
      opts.logger.warn("directory.bootstrap.unavailable", {
        directoryUrl,
        reason: probe.reason,
        detail: probe.detail,
      });
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

// ─── Roster-aware directory failover (no bootstrap SPOF) ────────────

export interface RosterAwareResolverOptions {
  /**
   * Resolve the PRIMARY (configured) directory endpoint — typically the result of
   * createDirectoryEndpointResolver (probes CELLO_DIRECTORY_URL's /bootstrap).
   */
  primaryResolver: () => Promise<DirectoryEndpoint | null>;
  /**
   * Resolve the CURRENTLY-REACHABLE consortium roster. Each member returned has already
   * had its /bootstrap probed (manifestNodesToEndpoints skips unreachable nodes), so a
   * member's presence in the returned array IS its reachability. NULL when no consortium
   * manifest is configured → no failover, primary-only.
   */
  getConsortiumRoster: () => Promise<ConsortiumEndpoint[] | null>;
  logger: Logger;
  /**
   * Test seam: order the fallback candidates. Production defaults to a Fisher-Yates
   * shuffle so clients don't stampede one node when the primary goes down (the redundancy
   * invariant). Tests inject an identity shuffle for deterministic ordering.
   */
  shuffle?: <T>(items: T[]) => T[];
  /**
   * DECLARED consortium member peer ids, from the verified manifest. Local and free — never a
   * network probe. Absent (or empty) disables the membership check entirely, which is the M6
   * back-compat path where there is no manifest to be a member of.
   */
  getManifestPeerIds?: () => Set<string> | null;
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
 * sovereign-node REDUNDANCY invariant.
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
 * Scope note: stickiness here is by ROSTER REACHABILITY, not by observed connect success
 * — the resolver is not told whether a dial/auth against the returned endpoint actually
 * succeeded. A node whose /bootstrap resolves is served by that same node, so resolvable ≈
 * connectable in practice; only a live kill-primary failover test proves that presence
 * resolution, relay assignment, and the FROST ceremony all work against a non-home directory.
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

  /** Pick a reachable roster member that is neither the current pointer nor the primary. */
  function selectFallback(roster: ConsortiumEndpoint[]): DirectoryEndpoint {
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

    // 2. Primary-first (and the healthy steady state — no roster probe once the primary is known
    //    to be a consortium member).
    const primary = await opts.primaryResolver();
    if (primary) {
      // A primary that RESOLVES but is not a MEMBER of this consortium is a black hole, and used to
      // be a permanent one: failover triggered only on UNREACHABILITY, so the compiled-in default
      // URL after a consortium move resolved forever while every connection died at step-6 identity
      // auth with `key_not_in_manifest`. Reachability was never the right test.
      //
      // Checked against DECLARED manifest membership, never against the reachable roster. The
      // roster is the set that answered /bootstrap just now; a genuine member that is momentarily
      // down is absent from it, and disqualifying on that would route around a node that is merely
      // restarting — turning a blip into a failover. Membership is also LOCAL, so this costs no
      // probe at all and the healthy path is unchanged.
      const members = opts.getManifestPeerIds?.() ?? null;
      if (members && members.size > 0 && !members.has(primary.peerId)) {
        opts.logger.warn("directory.bootstrap.primary.not_in_consortium", {
          peerId: primary.peerId,
          memberCount: members.size,
        });
        primaryPeerId = primary.peerId; // exclude it from the fallback pick below
        const roster = await opts.getConsortiumRoster();
        if (roster && roster.length > 0) return selectFallback(roster);
        // No reachable member either — return null so the caller retries rather than hand back a
        // directory we KNOW will reject us.
        return null;
      }
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
