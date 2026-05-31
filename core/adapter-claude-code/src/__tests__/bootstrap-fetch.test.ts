/**
 * Bootstrap multiaddr auto-discovery tests.
 *
 * Specification:
 *
 * AC-1: When the bootstrap endpoint returns a valid multiaddr, fetchBootstrapMultiaddr
 *   resolves it and returns the string. This simulates cello-mcp auto-discovering
 *   CELLO_DIRECTORY_MULTIADDR when it is not set by the user.
 *
 * AC-2: When the bootstrap endpoint returns 503, fetchBootstrapMultiaddr returns null
 *   so cello-mcp falls through to threshold-signing-unavailable without crashing.
 *
 * AC-3: When fetch throws (network error, timeout), fetchBootstrapMultiaddr returns null
 *   so cello-mcp falls through gracefully.
 *
 * AC-4: A multiaddr without /p2p/ is rejected (returns null) so a misconfigured
 *   directory cannot feed a bad multiaddr to the FROST bootstrap.
 */

import { describe, it, expect } from "vitest";
import { fetchBootstrapMultiaddr } from "../config.js";

const VALID_MULTIADDR = "/dns4/directory-us1.cello.mygentic.ai/tcp/80/ws/p2p/12D3KooWTestPeerId0000";

// ─── AC-1: valid bootstrap response ───────────────────────────────────────────

describe("fetchBootstrapMultiaddr: AC-1 valid response", () => {
  it("returns the multiaddr on HTTP 200 with valid JSON", async () => {
    const mockFetch = async (_url: string, _opts?: RequestInit): Promise<Response> =>
      new Response(JSON.stringify({ multiaddr: VALID_MULTIADDR, peerId: "12D3KooWTestPeerId0000" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });

    const result = await fetchBootstrapMultiaddr("http://directory-us1.cello.mygentic.ai", mockFetch as typeof fetch);
    expect(result).toBe(VALID_MULTIADDR);
  });

  it("calls the correct URL: ${directoryUrl}/bootstrap", async () => {
    let calledUrl = "";
    const mockFetch = async (url: string, _opts?: RequestInit): Promise<Response> => {
      calledUrl = url as string;
      return new Response(JSON.stringify({ multiaddr: VALID_MULTIADDR }), { status: 200 });
    };

    await fetchBootstrapMultiaddr("http://localhost:9090", mockFetch as typeof fetch);
    expect(calledUrl).toBe("http://localhost:9090/bootstrap");
  });
});

// ─── AC-2: 503 not-ready response ─────────────────────────────────────────────

describe("fetchBootstrapMultiaddr: AC-2 503 not ready", () => {
  it("returns null when bootstrap endpoint returns 503", async () => {
    const mockFetch = async (_url: string, _opts?: RequestInit): Promise<Response> =>
      new Response(JSON.stringify({ error: "not ready" }), { status: 503 });

    const result = await fetchBootstrapMultiaddr("http://directory-us1.cello.mygentic.ai", mockFetch as typeof fetch);
    expect(result).toBeNull();
  });
});

// ─── AC-3: network error / timeout graceful fallback ──────────────────────────

describe("fetchBootstrapMultiaddr: AC-3 network error", () => {
  it("returns null when fetch throws (network unreachable)", async () => {
    const mockFetch = async (_url: string, _opts?: RequestInit): Promise<Response> => {
      throw new Error("fetch failed: ECONNREFUSED");
    };

    const result = await fetchBootstrapMultiaddr("http://unreachable.example.com", mockFetch as typeof fetch);
    expect(result).toBeNull();
  });

  it("returns null when fetch is aborted (timeout)", async () => {
    const mockFetch = async (_url: string, _opts?: RequestInit): Promise<Response> => {
      throw new DOMException("The operation was aborted", "AbortError");
    };

    const result = await fetchBootstrapMultiaddr("http://slow-directory.example.com", mockFetch as typeof fetch);
    expect(result).toBeNull();
  });
});

// ─── AC-4: invalid multiaddr rejected ─────────────────────────────────────────

describe("fetchBootstrapMultiaddr: AC-4 invalid multiaddr rejected", () => {
  it("returns null when response multiaddr lacks /p2p/ component", async () => {
    const mockFetch = async (_url: string, _opts?: RequestInit): Promise<Response> =>
      new Response(JSON.stringify({ multiaddr: "/dns4/directory-us1.cello.mygentic.ai/tcp/80/ws" }), { status: 200 });

    const result = await fetchBootstrapMultiaddr("http://directory-us1.cello.mygentic.ai", mockFetch as typeof fetch);
    expect(result).toBeNull();
  });

  it("returns null when response contains no multiaddr field", async () => {
    const mockFetch = async (_url: string, _opts?: RequestInit): Promise<Response> =>
      new Response(JSON.stringify({ peerId: "12D3KooW..." }), { status: 200 });

    const result = await fetchBootstrapMultiaddr("http://directory-us1.cello.mygentic.ai", mockFetch as typeof fetch);
    expect(result).toBeNull();
  });
});
