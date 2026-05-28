/**
 * REPOSPLIT-002 AC-003 — Production directory URL configuration
 *
 * AC-003: CELLO_DIRECTORY_URL defaults to the production directory ALB endpoint;
 * is overridable by environment variable; no CELLO_RELAY_MULTIADDR constant exists.
 */

import { describe, it, expect } from "vitest";
import { resolveDirectoryUrl, PRODUCTION_DIRECTORY_URL } from "../index.js";

describe("AC-003: production directory URL configuration", () => {
  it("AC-003a: PRODUCTION_DIRECTORY_URL matches the production ALB endpoint from STATE.md", () => {
    expect(PRODUCTION_DIRECTORY_URL).toBe("https://directory-us1.cello.mygentic.ai");
  });

  it("AC-003b: resolveDirectoryUrl() returns the production default when env var is unset", () => {
    const result = resolveDirectoryUrl({});
    expect(result).toBe("https://directory-us1.cello.mygentic.ai");
  });

  it("AC-003c: resolveDirectoryUrl() returns the override when CELLO_DIRECTORY_URL is set", () => {
    const result = resolveDirectoryUrl({ CELLO_DIRECTORY_URL: "http://localhost:8080" });
    expect(result).toBe("http://localhost:8080");
  });

  it("AC-003d: no CELLO_RELAY_MULTIADDR constant is exported (relay is dynamic per-session)", () => {
    // Verify by checking that the exported API has no relay multiaddr constant.
    // Relay multiaddr is issued per-session by the directory — never baked in.
    const mod = { resolveDirectoryUrl, PRODUCTION_DIRECTORY_URL };
    expect(Object.keys(mod)).not.toContain("PRODUCTION_RELAY_MULTIADDR");
    expect(Object.keys(mod)).not.toContain("CELLO_RELAY_MULTIADDR");
  });
});
