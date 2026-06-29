/**
 * M7 Keystone (Part 1) — directory bootstrap tests.
 *
 * Covers the ported M6 bootstrap path: URL resolution, GET /bootstrap fetch,
 * peer-ID extraction, and the caching/retry resolver.
 */

import { describe, it, expect, vi } from "vitest";
import {
  PRODUCTION_DIRECTORY_URL,
  resolveDirectoryUrl,
  fetchBootstrapMultiaddr,
  parsePeerIdFromMultiaddr,
  createDirectoryEndpointResolver,
  mapEndpointToBootstrapBase,
  manifestNodesToEndpoints,
} from "../directory-bootstrap.js";
import type { Logger } from "../types.js";

const silentLogger: Logger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};

const PEER = "12D3KooWS46wUj6NYvoAsocxZnxth5EgYD2ZXCm7coMkXUWgS1j3";
const MULTIADDR = `/dns4/directory-us1.cello.mygentic.ai/tcp/80/ws/p2p/${PEER}`;

function jsonResponse(body: unknown, ok = true): Response {
  return {
    ok,
    json: async () => body,
  } as unknown as Response;
}

describe("resolveDirectoryUrl", () => {
  it("returns CELLO_DIRECTORY_URL when set", () => {
    expect(resolveDirectoryUrl({ CELLO_DIRECTORY_URL: "http://dev.example" })).toBe("http://dev.example");
  });

  it("falls back to the production URL when unset", () => {
    expect(resolveDirectoryUrl({})).toBe(PRODUCTION_DIRECTORY_URL);
  });
});

describe("parsePeerIdFromMultiaddr", () => {
  it("extracts the peer ID after /p2p/", () => {
    expect(parsePeerIdFromMultiaddr(MULTIADDR)).toBe(PEER);
  });

  it("returns null when there is no /p2p/ segment", () => {
    expect(parsePeerIdFromMultiaddr("/dns4/host/tcp/80/ws")).toBeNull();
  });

  it("stops at the next slash after the peer ID", () => {
    expect(parsePeerIdFromMultiaddr(`/dns4/host/tcp/80/ws/p2p/${PEER}/p2p-circuit`)).toBe(PEER);
  });

  it("uses the LAST /p2p/ segment (circuit relay addresses)", () => {
    const relayAddr = `/dns4/relay/tcp/443/wss/p2p/RELAYID/p2p-circuit/p2p/${PEER}`;
    expect(parsePeerIdFromMultiaddr(relayAddr)).toBe(PEER);
  });
});

describe("fetchBootstrapMultiaddr", () => {
  it("returns the multiaddr on HTTP 200 with a valid /p2p/ payload", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ multiaddr: MULTIADDR }));
    const result = await fetchBootstrapMultiaddr("http://dir.example", fetchFn as unknown as typeof fetch);
    expect(result).toBe(MULTIADDR);
    expect(fetchFn).toHaveBeenCalledWith("http://dir.example/bootstrap", expect.anything());
  });

  it("strips a trailing slash from the directory URL", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ multiaddr: MULTIADDR }));
    await fetchBootstrapMultiaddr("http://dir.example/", fetchFn as unknown as typeof fetch);
    expect(fetchFn).toHaveBeenCalledWith("http://dir.example/bootstrap", expect.anything());
  });

  it("returns null on non-200", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ multiaddr: MULTIADDR }, false));
    expect(await fetchBootstrapMultiaddr("http://dir.example", fetchFn as unknown as typeof fetch)).toBeNull();
  });

  it("returns null when the payload has no /p2p/", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ multiaddr: "/dns4/host/tcp/80/ws" }));
    expect(await fetchBootstrapMultiaddr("http://dir.example", fetchFn as unknown as typeof fetch)).toBeNull();
  });

  it("returns null when multiaddr is missing/non-string", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ notMultiaddr: 1 }));
    expect(await fetchBootstrapMultiaddr("http://dir.example", fetchFn as unknown as typeof fetch)).toBeNull();
  });

  it("returns null on network error (fetch throws)", async () => {
    const fetchFn = vi.fn(async () => {
      throw new Error("ECONNREFUSED");
    });
    expect(await fetchBootstrapMultiaddr("http://dir.example", fetchFn as unknown as typeof fetch)).toBeNull();
  });
});

describe("createDirectoryEndpointResolver", () => {
  it("re-resolves on every call (per-connect re-resolution, picks up address changes)", async () => {
    const otherPeer = "12D3KooWOTHERotherotherotherotherotherotherotherother";
    const otherAddr = `/dns4/dir2/tcp/443/wss/p2p/${otherPeer}`;
    const fetchFn = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ multiaddr: MULTIADDR }))
      .mockResolvedValueOnce(jsonResponse({ multiaddr: otherAddr }));
    const resolver = createDirectoryEndpointResolver({
      logger: silentLogger,
      directoryUrl: "http://dir.example",
      fetchFn: fetchFn as unknown as typeof fetch,
    });

    expect(await resolver()).toEqual({ peerId: PEER, multiaddr: MULTIADDR });
    expect(await resolver()).toEqual({ peerId: otherPeer, multiaddr: otherAddr });
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });

  it("returns null and re-attempts until the bootstrap succeeds", async () => {
    const fetchFn = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({}, false)) // first attempt fails, no last-good yet
      .mockResolvedValueOnce(jsonResponse({ multiaddr: MULTIADDR })); // second succeeds
    const resolver = createDirectoryEndpointResolver({
      logger: silentLogger,
      directoryUrl: "http://dir.example",
      fetchFn: fetchFn as unknown as typeof fetch,
    });

    expect(await resolver()).toBeNull();
    expect(await resolver()).toEqual({ peerId: PEER, multiaddr: MULTIADDR });
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });

  it("falls back to the last known-good endpoint when a later fetch fails", async () => {
    const fetchFn = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ multiaddr: MULTIADDR })) // succeeds → cached as last-good
      .mockResolvedValueOnce(jsonResponse({}, false)); // transient failure → reuse last-good
    const resolver = createDirectoryEndpointResolver({
      logger: silentLogger,
      directoryUrl: "http://dir.example",
      fetchFn: fetchFn as unknown as typeof fetch,
    });

    expect(await resolver()).toEqual({ peerId: PEER, multiaddr: MULTIADDR });
    expect(await resolver()).toEqual({ peerId: PEER, multiaddr: MULTIADDR });
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });
});

// ─── DOD-MANIFEST-1: manifest node set → N directory endpoints ─────────────────
describe("mapEndpointToBootstrapBase", () => {
  it("maps a wss:// endpoint to its http:// bootstrap base (ALB terminates TLS)", () => {
    expect(mapEndpointToBootstrapBase("wss://directory-us1.cello.mygentic.ai:443")).toBe(
      "http://directory-us1.cello.mygentic.ai:443",
    );
  });

  it("maps ws:// to http://", () => {
    expect(mapEndpointToBootstrapBase("ws://host:8080")).toBe("http://host:8080");
  });

  it("passes an http:// endpoint through unchanged (the harness/dev form)", () => {
    expect(mapEndpointToBootstrapBase("http://127.0.0.1:5001")).toBe("http://127.0.0.1:5001");
  });

  it("strips a trailing slash", () => {
    expect(mapEndpointToBootstrapBase("http://127.0.0.1:5001/")).toBe("http://127.0.0.1:5001");
  });
});

describe("manifestNodesToEndpoints", () => {
  const NODES = [
    { nodeId: "node-0", pubkey: "a".repeat(64), region: "us-east-1", provider: "aws", endpoint: "http://127.0.0.1:5001" },
    { nodeId: "node-1", pubkey: "b".repeat(64), region: "eu-central-1", provider: "gcp", endpoint: "http://127.0.0.1:5002" },
    { nodeId: "node-2", pubkey: "c".repeat(64), region: "ap-northeast-1", provider: "azure", endpoint: "http://127.0.0.1:5003" },
  ];

  /** A fetch that returns a distinct, port-keyed multiaddr for each node's /bootstrap. */
  function portKeyedFetch(failPorts: string[] = []): typeof fetch {
    return vi.fn(async (url: string | URL) => {
      const port = String(url).match(/:(\d+)\/bootstrap/)?.[1] ?? "0";
      if (failPorts.includes(port)) return jsonResponse({}, false);
      return jsonResponse({ multiaddr: `/ip4/127.0.0.1/tcp/${port}/p2p/PEER${port}` });
    }) as unknown as typeof fetch;
  }

  it("resolves ALL N nodes to {nodeId, pubkey, peerId, multiaddr}", async () => {
    const eps = await manifestNodesToEndpoints(NODES, { fetchFn: portKeyedFetch(), logger: silentLogger });
    expect(eps).toHaveLength(3);
    expect(eps).toEqual([
      { nodeId: "node-0", pubkey: "a".repeat(64), peerId: "PEER5001", multiaddr: "/ip4/127.0.0.1/tcp/5001/p2p/PEER5001" },
      { nodeId: "node-1", pubkey: "b".repeat(64), peerId: "PEER5002", multiaddr: "/ip4/127.0.0.1/tcp/5002/p2p/PEER5002" },
      { nodeId: "node-2", pubkey: "c".repeat(64), peerId: "PEER5003", multiaddr: "/ip4/127.0.0.1/tcp/5003/p2p/PEER5003" },
    ]);
  });

  it("is availability-aware: a node whose /bootstrap fails is SKIPPED, the rest still resolve", async () => {
    // Redundancy invariant (CLAUDE.md): one node down must not strand the others.
    const eps = await manifestNodesToEndpoints(NODES, { fetchFn: portKeyedFetch(["5002"]), logger: silentLogger });
    expect(eps.map((e) => e.nodeId)).toEqual(["node-0", "node-2"]);
  });

  it("returns an empty array when NO node resolves (caller decides — never a silent single-endpoint fallback)", async () => {
    const eps = await manifestNodesToEndpoints(NODES, {
      fetchFn: portKeyedFetch(["5001", "5002", "5003"]),
      logger: silentLogger,
    });
    expect(eps).toEqual([]);
  });
});
