/**
 * M7 Keystone (Part 1) — directory bootstrap tests.
 *
 * Covers the ported M6 bootstrap path: URL resolution, GET /bootstrap fetch,
 * peer-ID extraction, and the caching/retry resolver.
 */

import { describe, it, expect, vi } from "vitest";
import {
  resolveDirectoryUrl,
  fetchBootstrapMultiaddr,
  fetchBootstrapResult,
  parsePeerIdFromMultiaddr,
  createDirectoryEndpointResolver,
  createRosterAwareEndpointResolver,
  mapEndpointToBootstrapBase,
  manifestNodesToEndpoints,
  type ConsortiumEndpoint,
} from "../directory-bootstrap.js";
import { BUNDLED_CONSORTIUM_MANIFEST } from "../bundled-consortium-manifest.js";
import type { DirectoryEndpoint } from "../signaling-connect.js";
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

  it("falls back to a RANDOM bundled endpoint when unset — not always the same one", () => {
    // The old behaviour returned PRODUCTION_DIRECTORY_URL (gcp-use1). Now it picks randomly so
    // clients spread across the consortium from cold boot rather than piling onto one node.
    // The result must still be one of the bundled endpoints (same step-6 safety property).
    const url = resolveDirectoryUrl({});
    const bundledEndpoints = BUNDLED_CONSORTIUM_MANIFEST.nodes.map((n) => String((n as Record<string, unknown>)["endpoint"]));
    expect(bundledEndpoints).toContain(url);
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

// ─── DNS-INCIDENT R3 (2026-07-24): failure-class visibility ──────────────────
// The blanket `catch { return null }` collapsed DNS failure, connection failure,
// timeout, and malformed payloads into one indistinguishable `unresolved` log,
// which is why a machine-wide negative-DNS-cache outage looked identical to a
// server outage. fetchBootstrapResult classifies; the log events carry `reason`.

/** Mirror of Node/undici's `fetch failed` TypeError with a coded cause. */
function undiciError(code: string): Error {
  return Object.assign(new TypeError("fetch failed"), {
    cause: Object.assign(new Error(code), { code }),
  });
}

describe("fetchBootstrapResult failure classification", () => {
  it("classifies getaddrinfo ENOTFOUND as dns_error", async () => {
    const fetchFn = vi.fn(async () => {
      throw undiciError("ENOTFOUND");
    });
    const r = await fetchBootstrapResult("http://dir.example", fetchFn as unknown as typeof fetch);
    // DOD-M15-BOOTSTRAP-1: `attempts` is asserted rather than matched loosely, so these classification
    // tests also pin the retry policy — a DNS blip is TRANSIENT and gets the full three probes.
    expect(r).toEqual({ ok: false, reason: "dns_error", detail: "ENOTFOUND", attempts: 3 });
  });

  it("classifies EAI_AGAIN as dns_error", async () => {
    const fetchFn = vi.fn(async () => {
      throw undiciError("EAI_AGAIN");
    });
    const r = await fetchBootstrapResult("http://dir.example", fetchFn as unknown as typeof fetch);
    expect(r).toEqual({ ok: false, reason: "dns_error", detail: "EAI_AGAIN", attempts: 3 });
  });

  it("classifies ECONNREFUSED as connect_error", async () => {
    const fetchFn = vi.fn(async () => {
      throw undiciError("ECONNREFUSED");
    });
    const r = await fetchBootstrapResult("http://dir.example", fetchFn as unknown as typeof fetch);
    expect(r).toEqual({ ok: false, reason: "connect_error", detail: "ECONNREFUSED", attempts: 3 });
  });

  it("classifies an AbortError as timeout", async () => {
    const fetchFn = vi.fn(async () => {
      throw Object.assign(new Error("This operation was aborted"), { name: "AbortError" });
    });
    const r = await fetchBootstrapResult("http://dir.example", fetchFn as unknown as typeof fetch);
    expect(r).toEqual({ ok: false, reason: "timeout", detail: "AbortError", attempts: 3 });
  });

  it("classifies non-2xx as http_error with the status", async () => {
    const fetchFn = vi.fn(async () => ({ ok: false, status: 503, json: async () => ({}) }) as unknown as Response);
    const r = await fetchBootstrapResult("http://dir.example", fetchFn as unknown as typeof fetch);
    // DETERMINISTIC — the server answered. One probe, not three: retrying spends the budget to
    // receive the same 503 again and delays every other node in the roster.
    expect(r).toEqual({ ok: false, reason: "http_error", detail: "503", attempts: 1 });
  });

  it("classifies unparseable JSON as bad_response", async () => {
    const fetchFn = vi.fn(async () => ({
      ok: true,
      json: async () => {
        throw new SyntaxError("Unexpected token");
      },
    }) as unknown as Response);
    const r = await fetchBootstrapResult("http://dir.example", fetchFn as unknown as typeof fetch);
    expect(r).toMatchObject({ ok: false, reason: "bad_response" });
  });

  it("classifies a payload without /p2p/ as bad_response", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ multiaddr: "/dns4/host/tcp/80/ws" }));
    const r = await fetchBootstrapResult("http://dir.example", fetchFn as unknown as typeof fetch);
    expect(r).toMatchObject({ ok: false, reason: "bad_response" });
  });

  it("returns ok+multiaddr on success", async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ multiaddr: MULTIADDR }));
    const r = await fetchBootstrapResult("http://dir.example", fetchFn as unknown as typeof fetch);
    // The happy path costs exactly ONE probe — the retry must not add latency when nothing is wrong.
    expect(r).toEqual({ ok: true, multiaddr: MULTIADDR, attempts: 1 });
  });
});

describe("failure reason threads into log events", () => {
  it("directory.consortium.node.unresolved carries reason + detail", async () => {
    const events: Array<{ event: string; ctx: Record<string, unknown> }> = [];
    const logger: Logger = {
      ...silentLogger,
      warn: (event, ctx) => events.push({ event, ctx: (ctx ?? {}) as Record<string, unknown> }),
    };
    const fetchFn = vi.fn(async () => {
      throw undiciError("ENOTFOUND");
    });
    const nodes = [{ nodeId: "us-east-1", pubkey: "pk1", endpoint: "http://dir.example" }];
    const out = await manifestNodesToEndpoints(nodes as never, { logger, fetchFn: fetchFn as unknown as typeof fetch });
    expect(out).toEqual([]);
    const unresolved = events.find((e) => e.event === "directory.consortium.node.unresolved");
    expect(unresolved?.ctx).toMatchObject({ nodeId: "us-east-1", reason: "dns_error", detail: "ENOTFOUND" });
  });

  it("directory.bootstrap.unavailable carries reason + detail", async () => {
    const events: Array<{ event: string; ctx: Record<string, unknown> }> = [];
    const logger: Logger = {
      ...silentLogger,
      warn: (event, ctx) => events.push({ event, ctx: (ctx ?? {}) as Record<string, unknown> }),
    };
    const fetchFn = vi.fn(async () => {
      throw undiciError("ECONNREFUSED");
    });
    const resolve = createDirectoryEndpointResolver({
      logger,
      directoryUrl: "http://dir.example",
      fetchFn: fetchFn as unknown as typeof fetch,
    });
    expect(await resolve()).toBeNull();
    const unavailable = events.find((e) => e.event === "directory.bootstrap.unavailable");
    expect(unavailable?.ctx).toMatchObject({ reason: "connect_error", detail: "ECONNREFUSED" });
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

  // FINDING-4: when this resolver is the roster-aware failover wrapper's PRIMARY probe, the
  // stale-last-known-good fallback is HARMFUL — it hides a dead primary (a fresh fetch failure
  // returns the cached dead endpoint, so the wrapper never sees the primary as "down" and never
  // fails over). staleFallback:false makes a fresh failure return null, so the roster takes over.
  it("staleFallback:false returns null on a fresh failure (does NOT reuse last-known-good)", async () => {
    const fetchFn = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ multiaddr: MULTIADDR })) // succeeds once
      .mockResolvedValueOnce(jsonResponse({}, false)); // then dies → must report null, not stale
    const resolver = createDirectoryEndpointResolver({
      logger: silentLogger,
      directoryUrl: "http://dir.example",
      fetchFn: fetchFn as unknown as typeof fetch,
      staleFallback: false,
    });
    expect(await resolver()).toEqual({ peerId: PEER, multiaddr: MULTIADDR });
    expect(await resolver()).toBeNull();
  });
});

// ─── FINDING-4: roster-aware directory failover (bootstrap SPOF fix) ────────────
//
// The signaling dialer must route around a down PRIMARY directory node using the
// consortium roster it already holds — instead of retrying the single primary URL
// forever. createRosterAwareEndpointResolver wraps the primary (single-URL) resolver
// with the resolved roster: primary-first, randomized fallback on primary failure,
// sticky-until-fail (no flapping back to a recovered primary), null only when NOTHING
// resolves. Each roster member returned by getConsortiumRoster is already reachable
// (its /bootstrap resolved), so a member's presence in the roster IS its reachability.
// M12: a primary that RESOLVES but is not a CONSORTIUM MEMBER is a black hole. Failover used to
// trigger only on UNREACHABILITY, so the compiled-in default URL after a consortium move resolved
// forever while every connection died at step-6 auth with `key_not_in_manifest`. Membership, not
// reachability, is the test.
describe("M12: roster failover routes around a reachable NON-MEMBER primary", () => {
  const OUTSIDER: DirectoryEndpoint = { peerId: "PEERoutsider", multiaddr: "/ip4/127.0.0.1/tcp/9999/p2p/PEERoutsider" };
  const A: ConsortiumEndpoint = { nodeId: "gcp-a", pubkey: "a".repeat(64), peerId: "PEERa", multiaddr: "/ip4/127.0.0.1/tcp/5001/p2p/PEERa" };
  const B: ConsortiumEndpoint = { nodeId: "gcp-b", pubkey: "b".repeat(64), peerId: "PEERb", multiaddr: "/ip4/127.0.0.1/tcp/5002/p2p/PEERb" };

  it("a reachable primary ABSENT from the roster is rejected and a member is used", async () => {
    const resolve = createRosterAwareEndpointResolver({
      primaryResolver: async () => OUTSIDER, // always resolves — the black hole
      getConsortiumRoster: async () => [A, B],
      getManifestPeerIds: () => new Set([A.peerId, B.peerId]),
      logger: silentLogger,
      shuffle: (xs) => xs,
    });
    const got = await resolve();
    expect(got?.peerId).not.toBe(OUTSIDER.peerId);
    expect([A.peerId, B.peerId]).toContain(got?.peerId);
  });

  it("NO manifest membership (M6 back-compat) leaves the primary untouched", async () => {
    const resolve = createRosterAwareEndpointResolver({
      primaryResolver: async () => OUTSIDER,
      getConsortiumRoster: async () => [],
      getManifestPeerIds: () => null,
      logger: silentLogger,
      shuffle: (xs) => xs,
    });
    expect((await resolve())?.peerId).toBe(OUTSIDER.peerId);
  });

  it("a member that is momentarily ABSENT from the reachable roster is NOT disqualified", async () => {
    // The distinction that matters: membership is DECLARED, the roster is who answered just now.
    // Checking against the roster would route around a node that is merely restarting.
    const resolve = createRosterAwareEndpointResolver({
      primaryResolver: async () => ({ peerId: A.peerId, multiaddr: A.multiaddr }),
      getConsortiumRoster: async () => [B], // A is a member but did NOT answer this probe
      getManifestPeerIds: () => new Set([A.peerId, B.peerId]),
      logger: silentLogger,
      shuffle: (xs) => xs,
    });
    expect((await resolve())?.peerId).toBe(A.peerId);
  });

  it("a member primary costs NO roster probe at all — membership is local", async () => {
    let rosterProbes = 0;
    const resolve = createRosterAwareEndpointResolver({
      primaryResolver: async () => ({ peerId: A.peerId, multiaddr: A.multiaddr }),
      getConsortiumRoster: async () => { rosterProbes++; return [A, B]; },
      getManifestPeerIds: () => new Set([A.peerId, B.peerId]),
      logger: silentLogger,
      shuffle: (xs) => xs,
    });
    for (let i = 0; i < 3; i++) expect((await resolve())?.peerId).toBe(A.peerId);
    expect(rosterProbes).toBe(0);
  });
});

describe("createRosterAwareEndpointResolver (FINDING-4 failover)", () => {
  const US1: DirectoryEndpoint = { peerId: "PEERus1", multiaddr: "/ip4/127.0.0.1/tcp/5001/p2p/PEERus1" };
  const US1_C: ConsortiumEndpoint = { nodeId: "us1", pubkey: "a".repeat(64), peerId: "PEERus1", multiaddr: US1.multiaddr! };
  const EU1_C: ConsortiumEndpoint = { nodeId: "eu1", pubkey: "b".repeat(64), peerId: "PEEReu1", multiaddr: "/ip4/127.0.0.1/tcp/5002/p2p/PEEReu1" };
  const AP1_C: ConsortiumEndpoint = { nodeId: "ap1", pubkey: "c".repeat(64), peerId: "PEERap1", multiaddr: "/ip4/127.0.0.1/tcp/5003/p2p/PEERap1" };

  // Deterministic "shuffle" for tests that assert order: identity (no reordering).
  const identityShuffle = <T,>(items: T[]): T[] => items;

  it("1. primary unreachable + roster has a reachable member → returns that member", async () => {
    const resolver = createRosterAwareEndpointResolver({
      primaryResolver: async () => null, // us1 down
      getConsortiumRoster: async () => [EU1_C], // us1 not in roster (it's down), eu1 reachable
      logger: silentLogger,
      shuffle: identityShuffle,
    });
    expect(await resolver()).toEqual({ peerId: "PEEReu1", multiaddr: EU1_C.multiaddr });
  });

  it("2. sticky: once on a fallback, keeps it while reachable (primary not re-probed)", async () => {
    const primaryResolver = vi.fn(async () => null); // us1 stays down
    const getConsortiumRoster = vi.fn(async () => [EU1_C, AP1_C]);
    const resolver = createRosterAwareEndpointResolver({
      primaryResolver,
      getConsortiumRoster,
      logger: silentLogger,
      shuffle: identityShuffle, // → eu1 chosen first
    });
    const first = await resolver();
    expect(first?.peerId).toBe("PEEReu1");
    const second = await resolver();
    expect(second?.peerId).toBe("PEEReu1"); // same node — no flapping
    // The sticky path returns before re-probing the primary → primary consulted only on the first call.
    expect(primaryResolver).toHaveBeenCalledTimes(1);
  });

  it("3. sticky-until-fail: primary recovers while on a fallback → does NOT churn back to primary", async () => {
    let primaryUp = false;
    const primaryResolver = vi.fn(async () => (primaryUp ? US1 : null));
    const getConsortiumRoster = vi.fn(async () => (primaryUp ? [US1_C, EU1_C, AP1_C] : [EU1_C, AP1_C]));
    const resolver = createRosterAwareEndpointResolver({
      primaryResolver,
      getConsortiumRoster,
      logger: silentLogger,
      shuffle: identityShuffle,
    });
    const first = await resolver();
    expect(first?.peerId).toBe("PEEReu1"); // failed over to eu1
    primaryUp = true; // us1 comes back
    const second = await resolver();
    expect(second?.peerId).toBe("PEEReu1"); // stays on eu1 — sticky-until-fail
  });

  it("4. all nodes down → null (empty roster AND null roster / back-compat)", async () => {
    const emptyRoster = createRosterAwareEndpointResolver({
      primaryResolver: async () => null,
      getConsortiumRoster: async () => [],
      logger: silentLogger,
    });
    expect(await emptyRoster()).toBeNull();

    const noManifest = createRosterAwareEndpointResolver({
      primaryResolver: async () => null,
      getConsortiumRoster: async () => null, // no consortium manifest configured
      logger: silentLogger,
    });
    expect(await noManifest()).toBeNull();
  });

  it("5. regression: primary reachable → primary selected, roster never probed (healthy path)", async () => {
    const primaryResolver = vi.fn(async () => US1);
    const getConsortiumRoster = vi.fn(async () => [US1_C, EU1_C, AP1_C]);
    const resolver = createRosterAwareEndpointResolver({ primaryResolver, getConsortiumRoster, logger: silentLogger });
    expect(await resolver()).toEqual(US1);
    expect(await resolver()).toEqual(US1);
    expect(getConsortiumRoster).not.toHaveBeenCalled(); // no roster cost while the primary is healthy
  });

  it("6. on primary failure it fails over to a DIFFERENT node and emits directory.bootstrap.failover", async () => {
    const events: Array<{ event: string; ctx: Record<string, unknown> }> = [];
    const logger: Logger = { ...silentLogger, warn: (event, ctx) => events.push({ event, ctx: ctx ?? {} }) };
    let primaryUp = true;
    const resolver = createRosterAwareEndpointResolver({
      primaryResolver: async () => (primaryUp ? US1 : null),
      getConsortiumRoster: async () => (primaryUp ? [US1_C, EU1_C] : [EU1_C]),
      logger,
      shuffle: identityShuffle,
    });
    expect((await resolver())?.peerId).toBe("PEERus1"); // primary healthy
    primaryUp = false; // us1 dies
    const failed = await resolver();
    expect(failed?.peerId).toBe("PEEReu1"); // routed around the dead primary
    const failover = events.find((e) => e.event === "directory.bootstrap.failover");
    expect(failover).toBeDefined();
    expect(failover?.ctx["to"]).toBe("PEEReu1");
  });

  it("7. COMPOSITION: a REAL primary resolver that dies after a success fails over to the roster (not the stale dead primary)", async () => {
    // The bug the isolated tests missed: createDirectoryEndpointResolver caches last-known-good and,
    // without staleFallback:false, returns the STALE dead primary on every later fetch failure — so the
    // wrapper's branch-2 ("primary healthy") wins forever and the roster fallback is never reached. This
    // composes the real resolver (as production does) and asserts the live kill-primary path works.
    const US1_MA = US1.multiaddr!;
    const fetchFn = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ multiaddr: US1_MA })) // startup: us1 healthy
      .mockResolvedValue(jsonResponse({}, false)); // us1 dead thereafter (fresh failures)
    const primaryResolver = createDirectoryEndpointResolver({
      logger: silentLogger,
      directoryUrl: "http://us1",
      fetchFn: fetchFn as unknown as typeof fetch,
      staleFallback: false, // as the failover wrapper's primary: report the dead node as null
    });
    const resolver = createRosterAwareEndpointResolver({
      primaryResolver,
      getConsortiumRoster: async () => [EU1_C], // us1 down → not in roster; eu1 reachable
      logger: silentLogger,
      shuffle: identityShuffle,
    });
    expect((await resolver())?.peerId).toBe("PEERus1"); // startup on the healthy primary
    expect((await resolver())?.peerId).toBe("PEEReu1"); // primary died → routed to eu1, NOT stale us1
  });

  it("8. after failing over, a flapping primary that reappears in the roster is NOT re-selected", async () => {
    // Hardening (reviewer #5): the fallback must exclude the PRIMARY's identity, not only the current
    // pointer — otherwise a flapping primary whose independent roster probe still lists it could be
    // re-picked as its own fallback.
    let primaryHealthy = true;
    const primaryResolver = async () => (primaryHealthy ? US1 : null);
    // Explicit roster sequence: eu1-only failover, then eu1 drops out while the primary flaps back in.
    const rosterQueue: ConsortiumEndpoint[][] = [[EU1_C], [US1_C, AP1_C]];
    const getConsortiumRoster = async () => rosterQueue.shift() ?? [US1_C, AP1_C];
    const resolver = createRosterAwareEndpointResolver({
      primaryResolver,
      getConsortiumRoster,
      logger: silentLogger,
      shuffle: identityShuffle, // identity → head of the list, so US1_C would be picked unless excluded
    });
    expect((await resolver())?.peerId).toBe("PEERus1"); // healthy → primary (records primary identity)
    primaryHealthy = false;
    expect((await resolver())?.peerId).toBe("PEEReu1"); // consumes [EU1_C] → eu1 (current, sticky)
    // 3rd call: sticky check consumes [US1_C,AP1_C] (eu1 gone) → branch3 default [US1_C,AP1_C];
    // us1 is the flapping primary → excluded → ap1 (NOT the dead primary).
    expect((await resolver())?.peerId).toBe("PEERap1");
  });
});

// ─── DOD-MANIFEST-1: manifest node set → N directory endpoints ─────────────────
describe("mapEndpointToBootstrapBase", () => {
  it("passes an http:// endpoint through unchanged (the contract: endpoint IS the http base)", () => {
    expect(mapEndpointToBootstrapBase("http://127.0.0.1:5001")).toBe("http://127.0.0.1:5001");
  });

  it("passes an https:// endpoint through", () => {
    expect(mapEndpointToBootstrapBase("https://directory-us1.cello.mygentic.ai")).toBe(
      "https://directory-us1.cello.mygentic.ai",
    );
  });

  it("strips a trailing slash", () => {
    expect(mapEndpointToBootstrapBase("http://127.0.0.1:5001/")).toBe("http://127.0.0.1:5001");
  });

  it("returns null for a wss:// dial address — NOT port-guessed to plaintext:443", () => {
    // The wss address is what /bootstrap RETURNS, not the bootstrap base. Mapping it to
    // http://host:443 would speak plaintext to the TLS port and silently fail — refuse it.
    expect(mapEndpointToBootstrapBase("wss://directory-us1.cello.mygentic.ai:443")).toBeNull();
  });

  it("returns null for a bare multiaddr (a config error in signed data, not a base)", () => {
    expect(mapEndpointToBootstrapBase("/ip4/127.0.0.1/tcp/0")).toBeNull();
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

  it("REFUSES a node whose probe returns a peer id the signed manifest does not declare", async () => {
    // The manifest declares peerId inside the SIGNED body. When the plaintext /bootstrap probe answers
    // with a different one, the signed roster and the live response disagree about who this node is —
    // which is what a redirected or substituted /bootstrap looks like. Before this the declared value
    // was decorative: the client dialled whatever the probe returned.
    const declared = [{ ...NODES[0], peerId: "PEER5001" }, { ...NODES[1], peerId: "SOMEONE-ELSE" }];
    const errors: Array<{ event: string; detail: Record<string, unknown> }> = [];
    const logger = {
      ...silentLogger,
      error: (event: string, detail?: Record<string, unknown>) => errors.push({ event, detail: detail ?? {} }),
    };

    const eps = await manifestNodesToEndpoints(declared as never, {
      fetchFn: portKeyedFetch(),
      logger: logger as never,
    });

    // The honest node still resolves — one bad entry must not strand the consortium.
    expect(eps.map((e) => e.nodeId)).toEqual(["node-0"]);
    const mismatch = errors.find((e) => e.event === "directory.consortium.node.peer_id_mismatch");
    expect(mismatch, "the refusal must name its cause, not be a silent skip").toBeDefined();
    expect(mismatch?.detail["declaredPeerId"]).toBe("SOMEONE-ELSE");
    expect(mismatch?.detail["probePeerId"]).toBe("PEER5002");
  });

  it("tolerates a node that declares NO peer id — pre-field manifests must still resolve", async () => {
    // Treating "not declared" as "mismatch" would strand every node in a manifest written before the
    // field existed, turning a hardening measure into an outage.
    const eps = await manifestNodesToEndpoints(NODES, { fetchFn: portKeyedFetch(), logger: silentLogger });
    expect(eps).toHaveLength(3);
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

  it("skips a node with a non-http(s) endpoint (signed config error) and resolves the rest", async () => {
    // A bare multiaddr in signed manifest data is a PERMANENT config error, distinct from a
    // transient outage. It must be dropped (never dialed at a guessed port), the others resolve.
    const badNodes = [
      NODES[0],
      { ...NODES[1], endpoint: "/ip4/127.0.0.1/tcp/0" }, // invalid: not an http(s) base
      NODES[2],
    ];
    const eps = await manifestNodesToEndpoints(badNodes, { fetchFn: portKeyedFetch(), logger: silentLogger });
    expect(eps.map((e) => e.nodeId)).toEqual(["node-0", "node-2"]);
  });
});
