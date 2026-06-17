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
