/**
 * CELLO adapter runtime configuration.
 *
 * AC-003 (REPOSPLIT-002): CELLO_DIRECTORY_URL defaults to the production directory
 * ALB endpoint. No CELLO_RELAY_MULTIADDR constant exists — relay multiaddr is
 * dynamically assigned per-session by the directory.
 */

/** Production directory HTTP endpoint (ALB / Route53 — ALB terminates TLS, internal HTTP). */
export const PRODUCTION_DIRECTORY_URL = "http://directory-us1.cello.mygentic.ai";

/**
 * Resolve the directory URL from the environment, falling back to the
 * production endpoint when CELLO_DIRECTORY_URL is not set.
 *
 * @param env - process.env or a test substitute
 */
export function resolveDirectoryUrl(env: Record<string, string | undefined> = process.env): string {
  return env["CELLO_DIRECTORY_URL"] ?? PRODUCTION_DIRECTORY_URL;
}

/**
 * Auto-discover the directory multiaddr via GET /bootstrap on the directory HTTP endpoint.
 *
 * Pseudocode (fetch strategy):
 *   1. GET ${directoryUrl}/bootstrap with 5s AbortController timeout
 *   2. On HTTP 200 + JSON { multiaddr: string } containing "/p2p/" → return multiaddr
 *   3. On HTTP non-200, network error, or invalid JSON → return null
 *
 * @param directoryUrl - Base URL of the directory HTTP endpoint
 * @param fetchFn - fetch implementation (injectable for testing)
 * @returns The resolved multiaddr string, or null on failure
 */
export async function fetchBootstrapMultiaddr(
  directoryUrl: string,
  fetchFn: typeof fetch = fetch,
): Promise<string | null> {
  const bootstrapUrl = `${directoryUrl}/bootstrap`;
  try {
    const ac = new AbortController();
    const timeout = setTimeout(() => ac.abort(), 5000);
    let resp: Response;
    try {
      resp = await fetchFn(bootstrapUrl, { signal: ac.signal });
    } finally {
      clearTimeout(timeout);
    }
    if (!resp.ok) {
      return null;
    }
    const json = await resp.json() as { multiaddr?: unknown };
    if (typeof json.multiaddr === "string" && json.multiaddr.includes("/p2p/")) {
      return json.multiaddr;
    }
    return null;
  } catch {
    return null;
  }
}
