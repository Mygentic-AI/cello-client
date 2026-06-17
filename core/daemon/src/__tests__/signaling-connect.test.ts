/**
 * M7 Keystone (Part 2) — signalingConnect dialer tests.
 *
 * Guard paths (no endpoint / no identity / dial failure) and a happy-path
 * handshake against a faked CelloNode + stream that speaks the same
 * length-prefixed CBOR the directory does.
 */

import { describe, it, expect, vi } from "vitest";
import { Encoder } from "cbor-x";
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
