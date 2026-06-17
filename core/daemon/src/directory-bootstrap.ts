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

export interface DirectoryEndpointResolverOptions {
  logger: Logger;
  /** Defaults to resolveDirectoryUrl(process.env). */
  directoryUrl?: string;
  /** Injectable fetch for testing. */
  fetchFn?: typeof fetch;
}

/**
 * Build an async `getDirectoryEndpoint` for createSignalingConnect. Caches the
 * first successful resolution; re-attempts the bootstrap fetch until then.
 */
export function createDirectoryEndpointResolver(
  opts: DirectoryEndpointResolverOptions,
): () => Promise<DirectoryEndpoint | null> {
  const directoryUrl = opts.directoryUrl ?? resolveDirectoryUrl();
  const fetchFn = opts.fetchFn ?? fetch;
  let cached: DirectoryEndpoint | null = null;

  return async function getDirectoryEndpoint(): Promise<DirectoryEndpoint | null> {
    if (cached) return cached;

    const multiaddr = await fetchBootstrapMultiaddr(directoryUrl, fetchFn);
    if (!multiaddr) {
      opts.logger.warn("directory.bootstrap.unavailable", { directoryUrl });
      return null;
    }
    const peerId = parsePeerIdFromMultiaddr(multiaddr);
    if (!peerId) {
      opts.logger.error("directory.bootstrap.no_peer_id", { directoryUrl, multiaddr });
      return null;
    }
    cached = { peerId, multiaddr };
    opts.logger.info("directory.bootstrap.resolved", { directoryUrl, peerId });
    return cached;
  };
}
