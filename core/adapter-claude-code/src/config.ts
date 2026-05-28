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
