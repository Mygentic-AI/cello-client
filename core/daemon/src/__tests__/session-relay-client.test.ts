/**
 * M7 DOD-SPINE-6 / MSG-001-3b — relay witness client: wire-format correctness.
 *
 * The live connect/auth/submit round-trip is exercised by J-SPINE against the real
 * relay binary. These tests pin the two crypto-bearing pieces that MUST match the
 * relay's server-side contract byte-for-byte (relay-node.ts), with real Ed25519 —
 * no mocks — so a format drift fails here instead of silently desyncing live.
 */
import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { decode } from "cbor-x";
import { generateKeypair, verify } from "@cello-protocol/crypto";
import {
  AgentRelayClient,
  buildRelayAuthPayload,
  encodeStructure1,
  RELAY_AUTH_DOMAIN,
} from "../session-relay-client.js";
import type { Logger } from "../types.js";

const noopLogger: Logger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
} as unknown as Logger;

describe("session-relay-client: relay auth payload", () => {
  it("builds SHA-256(domain || nonce || pubkey) — the exact bytes the relay verifies", async () => {
    const kp = generateKeypair();
    const pubkey = await kp.getPublicKey();
    const nonce = new Uint8Array(32).fill(0x42);

    const payload = buildRelayAuthPayload(nonce, pubkey);

    // Independently reconstruct the relay's authMsg (relay-node #handleRelayStream).
    const expected = new Uint8Array(
      createHash("sha256")
        .update(Buffer.concat([Buffer.from(RELAY_AUTH_DOMAIN, "utf8"), nonce, pubkey]))
        .digest(),
    );
    expect(Buffer.from(payload).equals(Buffer.from(expected))).toBe(true);

    // A signature over the payload verifies under the agent key (the relay's check).
    const sig = await kp.sign(payload);
    expect(verify(pubkey, payload, sig)).toBe(true);
  });
});

describe("session-relay-client: Structure 1", () => {
  it("encodes [1, content_hash, sender_pubkey, session_id, last_seen_seq, ts] decodable by the relay", async () => {
    const kp = generateKeypair();
    const senderPubkey = await kp.getPublicKey();
    const contentHash = new Uint8Array(32).fill(0xab);
    const sessionId = new Uint8Array(16).fill(0x01);
    const lastSeenSeq = 0;
    const timestamp = 1_750_000_000_000;

    const s1 = encodeStructure1(contentHash, senderPubkey, sessionId, lastSeenSeq, timestamp);

    // Mirror the relay's decodeStructure1: a 6-element array with the exact field shapes.
    const arr = decode(s1) as unknown[];
    expect(Array.isArray(arr)).toBe(true);
    expect(arr.length).toBe(6);
    expect(arr[0]).toBe(1);
    expect(Buffer.from(arr[1] as Uint8Array).equals(Buffer.from(contentHash))).toBe(true);
    expect(Buffer.from(arr[2] as Uint8Array).equals(Buffer.from(senderPubkey))).toBe(true);
    expect(Buffer.from(arr[3] as Uint8Array).equals(Buffer.from(sessionId))).toBe(true);
    expect(arr[4]).toBe(lastSeenSeq);
    expect(Number(arr[5])).toBe(timestamp);
  });

  it("signature over the raw Structure 1 bytes verifies (relay verifies the exact bytes, not a re-encode)", async () => {
    const kp = generateKeypair();
    const senderPubkey = await kp.getPublicKey();
    const s1 = encodeStructure1(new Uint8Array(32).fill(0x07), senderPubkey, new Uint8Array(16).fill(0x09), 3, 1_750_000_000_001);

    const sig = await kp.sign(s1);
    // The relay calls verify(sender_pubkey, frame.structure1_cbor, sender_signature).
    expect(verify(senderPubkey, s1, sig)).toBe(true);
  });
});

describe("AgentRelayClient: per-agent multi-session bookkeeping (H1)", () => {
  // The relay keys delivery by agent pubkey, so ONE client serves all of an agent's
  // sessions. These assert the session registry + lifecycle without a live relay (the
  // wire round-trip is covered by J-SPINE).
  async function makeClient(): Promise<AgentRelayClient> {
    const kp = generateKeypair();
    return new AgentRelayClient({
      relayPeerId: "12D3KooWRelay",
      relayAddrs: ["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWRelay"],
      keyProvider: kp,
      senderPubkey: await kp.getPublicKey(),
      logger: noopLogger,
    });
  }

  it("tracks multiple sessions and only reports empty when all are removed", async () => {
    const client = await makeClient();
    expect(client.hasSessions()).toBe(false);
    client.registerSession("aaaa");
    client.registerSession("bbbb");
    expect(client.hasSessions()).toBe(true);
    client.unregisterSession("aaaa");
    expect(client.hasSessions()).toBe(true); // bbbb still present — client must NOT close
    client.unregisterSession("bbbb");
    expect(client.hasSessions()).toBe(false);
    client.close();
  });

  it("registerSession is idempotent (re-register does not duplicate)", async () => {
    const client = await makeClient();
    client.registerSession("aaaa");
    client.registerSession("aaaa");
    client.unregisterSession("aaaa");
    expect(client.hasSessions()).toBe(false);
    client.close();
  });

  it("submitMessageHash after close returns a named failure, not a hang", async () => {
    const client = await makeClient();
    client.close();
    const fakeNode = { dial: async () => {}, newStream: async () => { throw new Error("closed"); } } as never;
    const r = await client.submitMessageHash(fakeNode, new Uint8Array(16), new Uint8Array(32));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("relay_client_closed");
  });
});
