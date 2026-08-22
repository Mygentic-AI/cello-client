/**
 * M7 Keystone (Part 2) — signalingConnect dialer tests.
 *
 * Guard paths (no endpoint / no identity / dial failure) and a happy-path
 * handshake against a faked CelloNode + stream that speaks the same
 * length-prefixed CBOR the directory does.
 */

import { describe, it, expect, vi } from "vitest";
import { Encoder, decode } from "cbor-x";
import * as lp from "it-length-prefixed";
import { createSignalingConnect, type SignalingAuthIdentity } from "../signaling-connect.js";
import type { Logger } from "../types.js";

const silentLogger: Logger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};

const CBOR_ENC = new Encoder({ tagUint8Array: false });
const PEER = "12D3KooWS46wUj6NYvoAsocxZnxth5EgYD2ZXCm7coMkXUWgS1j3";
const MULTIADDR = `/dns4/dir/tcp/80/ws/p2p/${PEER}`;

/** lp-frame a CBOR-encoded frame, exactly as the directory wire does. */
function encodeFrame(frame: unknown): Uint8Array {
  const cbor = CBOR_ENC.encode(frame) as Uint8Array;
  return lp.encode.single(cbor).subarray();
}

const fakeKeyProvider = {
  getPublicKey: async () => new Uint8Array(32),
  sign: vi.fn(async () => new Uint8Array(64)),
};

const validIdentity = (): SignalingAuthIdentity => ({
  keyProvider: fakeKeyProvider,
  pubkeyHex: "aa".repeat(32),
});

/** Build a fake directory-facing node whose stream emits the given frames. */
function makeFakeNode(frames: Uint8Array[]) {
  const stream = {
    async *[Symbol.asyncIterator]() {
      for (const f of frames) yield f;
    },
    send: vi.fn(),
    abort: vi.fn(),
  };
  const node = {
    start: vi.fn(async () => {}),
    stop: vi.fn(async () => {}),
    dial: vi.fn(async () => ({ peerId: PEER })),
    newStream: vi.fn(async () => stream),
    getPeerId: () => "12D3KooWSELFselfselfselfselfselfselfselfselfself",
    listenAddresses: () => ["/ip4/127.0.0.1/tcp/40001"],
  };
  return { node, stream };
}

describe("createSignalingConnect — guard paths", () => {
  it("throws directory_endpoint_unknown when no endpoint is resolved", async () => {
    const connect = createSignalingConnect({
      getDirectoryEndpoint: () => null,
      getAuthIdentity: validIdentity,
      logger: silentLogger,
    });
    await expect(connect()).rejects.toThrow("directory_endpoint_unknown");
  });

  it("throws no_agent_identity when no agent is registered", async () => {
    const connect = createSignalingConnect({
      getDirectoryEndpoint: () => ({ peerId: PEER, multiaddr: MULTIADDR }),
      getAuthIdentity: () => null,
      logger: silentLogger,
    });
    await expect(connect()).rejects.toThrow("no_agent_identity");
  });

  it("throws directory_dial_failed and stops the node when newStream fails", async () => {
    const node = {
      start: vi.fn(async () => {}),
      stop: vi.fn(async () => {}),
      dial: vi.fn(async () => ({ peerId: PEER })),
      newStream: vi.fn(async () => {
        throw new Error("connection_lost");
      }),
      getPeerId: () => "self",
      listenAddresses: () => [],
    };
    const connect = createSignalingConnect({
      getDirectoryEndpoint: () => ({ peerId: PEER, multiaddr: MULTIADDR }),
      getAuthIdentity: validIdentity,
      logger: silentLogger,
      createDirectoryNode: async () => node as never,
    });
    await expect(connect()).rejects.toThrow("directory_dial_failed");
    expect(node.stop).toHaveBeenCalled();
  });
});

describe("createSignalingConnect — handshake (M6 path, step-6 off)", () => {
  it("completes the handshake and returns a ConnectResult", async () => {
    const nonce = new Uint8Array(32).fill(7);
    const { node, stream } = makeFakeNode([
      encodeFrame({ type: "signaling_auth_challenge", nonce }),
      encodeFrame({ type: "signaling_auth_ok" }),
    ]);

    const connect = createSignalingConnect({
      getDirectoryEndpoint: () => ({ peerId: PEER, multiaddr: MULTIADDR }),
      getAuthIdentity: validIdentity,
      logger: silentLogger,
      createDirectoryNode: async () => node as never,
      getManifestVersion: () => 0,
    });

    const result = await connect();

    // Node was started and the signaling stream opened with the right protocol.
    expect(node.start).toHaveBeenCalled();
    expect(node.newStream).toHaveBeenCalledWith(PEER, "/cello/signaling/1.0.0");
    // K_local signed the challenge.
    expect(fakeKeyProvider.sign).toHaveBeenCalledTimes(1);
    // Sent the auth response AND the peer_info_announce.
    expect(stream.send).toHaveBeenCalledTimes(2);
    // No step-6 verifier → directoryNodeId falls back to the endpoint peer ID.
    expect(result.directoryNodeId).toBe(PEER);
    expect(result.manifestVersion).toBe(0);
  });

  // Cross-node item 3: the visiting flag rides the auth response ONLY when deps.visiting is set.
  it("sets visiting:true in signaling_auth_response iff deps.visiting is set", async () => {
    async function firstSentFrame(stream: { send: { mock: { calls: unknown[][] } } }): Promise<Record<string, unknown>> {
      const sent = stream.send.mock.calls[0][0] as { subarray?: () => Uint8Array } | Uint8Array;
      const bytes = (sent as { subarray?: () => Uint8Array }).subarray ? (sent as { subarray: () => Uint8Array }).subarray() : (sent as Uint8Array);
      const src = (async function* () { yield bytes; })();
      for await (const framed of lp.decode(src)) {
        const u = (framed as { subarray?: () => Uint8Array }).subarray ? (framed as { subarray: () => Uint8Array }).subarray() : (framed as unknown as Uint8Array);
        return decode(u) as Record<string, unknown>;
      }
      throw new Error("no frame captured");
    }

    // Visiting connection → flag present.
    {
      const { node, stream } = makeFakeNode([encodeFrame({ type: "signaling_auth_challenge", nonce: new Uint8Array(32).fill(3) }), encodeFrame({ type: "signaling_auth_ok" })]);
      await createSignalingConnect({ getDirectoryEndpoint: () => ({ peerId: PEER, multiaddr: MULTIADDR }), getAuthIdentity: validIdentity, logger: silentLogger, createDirectoryNode: async () => node as never, visiting: true })();
      const authResp = await firstSentFrame(stream);
      expect(authResp["type"]).toBe("signaling_auth_response");
      expect(authResp["visiting"]).toBe(true);
    }
    // Home connection → flag omitted (backward compatible).
    {
      const { node, stream } = makeFakeNode([encodeFrame({ type: "signaling_auth_challenge", nonce: new Uint8Array(32).fill(4) }), encodeFrame({ type: "signaling_auth_ok" })]);
      await createSignalingConnect({ getDirectoryEndpoint: () => ({ peerId: PEER, multiaddr: MULTIADDR }), getAuthIdentity: validIdentity, logger: silentLogger, createDirectoryNode: async () => node as never })();
      const authResp = await firstSentFrame(stream);
      expect(authResp["type"]).toBe("signaling_auth_response");
      expect(authResp["visiting"]).toBeUndefined();
    }
  });

  it("rejects when the first frame is not an auth challenge", async () => {
    const { node } = makeFakeNode([encodeFrame({ type: "something_else" })]);
    const connect = createSignalingConnect({
      getDirectoryEndpoint: () => ({ peerId: PEER, multiaddr: MULTIADDR }),
      getAuthIdentity: validIdentity,
      logger: silentLogger,
      createDirectoryNode: async () => node as never,
    });
    await expect(connect()).rejects.toThrow("directory_auth_unexpected_frame");
    expect(node.stop).toHaveBeenCalled();
  });

  it("rejects a non-32-byte nonce", async () => {
    const { node } = makeFakeNode([encodeFrame({ type: "signaling_auth_challenge", nonce: new Uint8Array(16) })]);
    const connect = createSignalingConnect({
      getDirectoryEndpoint: () => ({ peerId: PEER, multiaddr: MULTIADDR }),
      getAuthIdentity: validIdentity,
      logger: silentLogger,
      createDirectoryNode: async () => node as never,
    });
    await expect(connect()).rejects.toThrow("directory_auth_bad_nonce");
  });

  it("rejects when the directory does not return auth_ok", async () => {
    const nonce = new Uint8Array(32).fill(1);
    const { node } = makeFakeNode([
      encodeFrame({ type: "signaling_auth_challenge", nonce }),
      encodeFrame({ type: "signaling_auth_error", reason: "unknown_pubkey" }),
    ]);
    const connect = createSignalingConnect({
      getDirectoryEndpoint: () => ({ peerId: PEER, multiaddr: MULTIADDR }),
      getAuthIdentity: validIdentity,
      logger: silentLogger,
      createDirectoryNode: async () => node as never,
    });
    await expect(connect()).rejects.toThrow("directory_auth_rejected");
  });
});

// ─── DOD-NAT-REACHABILITY-1 (Phase 2): relay endpoints ride signaling_auth_ok ──
//
// The reservation must exist BEFORE any session (the standing receiver must be
// reachable for the first inbound request to arrive at all), so the directory
// hands its healthy relay pool to the agent at auth time — over the SAME
// authenticated stream that later carries session_assignment frames. A fresh
// agent with no session history is reachable from its first agent-online.

describe("createSignalingConnect — relay endpoints from signaling_auth_ok", () => {
  const RELAY_PEER = "12D3KooWQYV9dGMFoRzNStwpXztXaBUjtPqi6aU76ZgUriHhKust";

  it("well-formed relay_endpoints are surfaced through onRelayEndpoints", async () => {
    const nonce = new Uint8Array(32).fill(7);
    const { node } = makeFakeNode([
      encodeFrame({ type: "signaling_auth_challenge", nonce }),
      encodeFrame({
        type: "signaling_auth_ok",
        relay_endpoints: [{ peer_id: RELAY_PEER, multiaddrs: ["/ip4/10.0.0.5/tcp/4001"] }],
      }),
    ]);
    const received: Array<Array<{ peerId: string; addrs: string[] }>> = [];
    const connect = createSignalingConnect({
      getDirectoryEndpoint: () => ({ peerId: PEER, multiaddr: MULTIADDR }),
      getAuthIdentity: validIdentity,
      logger: silentLogger,
      createDirectoryNode: async () => node as never,
      onRelayEndpoints: (eps) => { received.push(eps); },
    });
    await connect();
    expect(received).toEqual([[{ peerId: RELAY_PEER, addrs: ["/ip4/10.0.0.5/tcp/4001"] }]]);
  });

  it("malformed relay_endpoints are DROPPED per entry, never thrown — auth must not fail on a bad hint", async () => {
    const nonce = new Uint8Array(32).fill(8);
    const { node } = makeFakeNode([
      encodeFrame({ type: "signaling_auth_challenge", nonce }),
      encodeFrame({
        type: "signaling_auth_ok",
        relay_endpoints: [
          { peer_id: 42, multiaddrs: ["/ip4/1.2.3.4/tcp/1"] },          // bad peer_id type
          { peer_id: RELAY_PEER },                                       // missing multiaddrs
          { peer_id: RELAY_PEER, multiaddrs: ["/ip4/10.0.0.5/tcp/4001", 7] }, // bad addr entry
          { peer_id: RELAY_PEER, multiaddrs: ["/ip4/10.0.0.6/tcp/4001"] },    // the one valid entry
        ],
      }),
    ]);
    const received: Array<Array<{ peerId: string; addrs: string[] }>> = [];
    const connect = createSignalingConnect({
      getDirectoryEndpoint: () => ({ peerId: PEER, multiaddr: MULTIADDR }),
      getAuthIdentity: validIdentity,
      logger: silentLogger,
      createDirectoryNode: async () => node as never,
      onRelayEndpoints: (eps) => { received.push(eps); },
    });
    const result = await connect();
    expect(result.directoryNodeId).toBe(PEER); // handshake unaffected
    expect(received).toEqual([[{ peerId: RELAY_PEER, addrs: ["/ip4/10.0.0.6/tcp/4001"] }]]);
  });

  it("absent relay_endpoints (old directory) → onRelayEndpoints not called, handshake unaffected", async () => {
    const nonce = new Uint8Array(32).fill(9);
    const { node } = makeFakeNode([
      encodeFrame({ type: "signaling_auth_challenge", nonce }),
      encodeFrame({ type: "signaling_auth_ok" }),
    ]);
    const received: unknown[] = [];
    const connect = createSignalingConnect({
      getDirectoryEndpoint: () => ({ peerId: PEER, multiaddr: MULTIADDR }),
      getAuthIdentity: validIdentity,
      logger: silentLogger,
      createDirectoryNode: async () => node as never,
      onRelayEndpoints: (eps) => { received.push(eps); },
    });
    const result = await connect();
    expect(result.directoryNodeId).toBe(PEER);
    expect(received).toEqual([]);
  });

  /**
   * DOD-M15-SURFACE-1 — the directory-facing node must not bind a port.
   *
   * SOURCE-LEVEL ON PURPOSE, and the reason is a real limitation worth stating rather than hiding:
   * every test in this file injects `createDirectoryNode`, so none of them reaches the `createNode`
   * call this asserts on. A behavioural test would have to let the real construction run and then
   * dial a real directory, which this suite cannot do. The behaviour that an empty listen config
   * genuinely binds nothing is pinned where it IS observable — `core/transport`'s node suite.
   *
   * What this guards is the regression: someone restoring `/ip4/0.0.0.0/tcp/0` here, on a node that
   * registers no protocol handler and that the directory never dials, giving every operator an open
   * port again. That is a one-line edit and it would otherwise pass every test in the repo.
   */
  it("DOD-M15-SURFACE-1: the directory-facing node is constructed with NO listen addresses", async () => {
    const { readFileSync } = await import("node:fs");
    const raw = readFileSync(new URL("../signaling-connect.ts", import.meta.url), "utf-8");
    // Comments stripped first — the reasoning beside this call NAMES the address it removed, so a
    // naive scan matches the explanation instead of the code. Same treatment `msg-022`'s parity
    // test applies for the same reason.
    const src = raw.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
    // Review F5: the slice ends at the object literal's CLOSING BRACE, not at an interior key. Cut
    // short at `autonatResponder`, an address reintroduced after it — as `announceAddresses`, say —
    // escaped all three assertions below.
    const from = src.indexOf("await createNode({");
    const call = src.slice(from, src.indexOf("});", from) + 3);

    expect(call, "the createNode call must be found — this test is worthless if the slice missed").toContain("keyProvider");
    expect(call, "and the slice must reach the end of the literal, not stop at an interior key").toContain("autonatResponder");
    expect(call).toMatch(/listenAddresses:\s*\[\s*\]/);
    expect(call, "no interface binding may return here").not.toMatch(/0\.0\.0\.0/);
    expect(call, "nor a loopback one — this node needs no socket at all").not.toMatch(/127\.0\.0\.1/);
  });
});
