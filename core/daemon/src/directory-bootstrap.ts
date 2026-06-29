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
 * Map a manifest node `endpoint` to the HTTP base used for its `/bootstrap` probe.
 * The manifest endpoint is the node's public address (e.g. `wss://host:443`, with the
 * ALB terminating TLS), but `/bootstrap` is served over plain HTTP behind that ALB
 * (matching PRODUCTION_DIRECTORY_URL, which is `http://`). So `http(s)://` is used as
 * is; `ws://`/`wss://` map to `http://`. A trailing slash is stripped because
 * fetchBootstrapMultiaddr appends `/bootstrap`. (M8B-DECISIONS: reuse `endpoint` as the
 * node's reachable HTTP base rather than adding a separate bootstrapUrl field.)
 */
export function mapEndpointToBootstrapBase(endpoint: string): string {
  const noSlash = endpoint.replace(/\/$/, "");
  if (noSlash.startsWith("wss://")) return "http://" + noSlash.slice("wss://".length);
  if (noSlash.startsWith("ws://")) return "http://" + noSlash.slice("ws://".length);
  return noSlash;
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
    // Fresh resolution failed — reuse the last known-good endpoint if we have one.
    if (lastGood) {
      opts.logger.warn("directory.bootstrap.using_last_known", { directoryUrl, peerId: lastGood.peerId });
      return lastGood;
    }
    return null;
  };
}
