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
import { Encoder, decode } from "cbor-x";
import * as lp from "it-length-prefixed";
import { generateKeypair, verify } from "@cello-protocol/crypto";
import {
  AgentRelayClient,
  buildRelayAuthPayload,
  encodeStructure1,
  RELAY_AUTH_DOMAIN,
} from "../session-relay-client.js";
import type { Logger } from "../types.js";

const CBOR_ENC = new Encoder({ tagUint8Array: false });

const noopLogger: Logger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
} as unknown as Logger;

const fakeNode = { dial: async () => {}, newStream: async () => { throw new Error("no-stream"); } } as never;

/**
 * A controllable fake relay stream + node. Captures outbound frames (decoded from the
 * length-prefixed wire) and lets the test push inbound frames the client's reader consumes.
 */
function makeFakeRelay() {
  const inbound: Uint8Array[] = [];
  let notify: (() => void) | null = null;
  let ended = false;
  const sentFrames: Record<string, unknown>[] = [];

  const stream = {
    send: (b: { subarray?: () => Uint8Array } | Uint8Array) => {
      // b is lp.encode.single(cbor) — un-frame it via lp.decode to read the CBOR back.
      const bytes = b instanceof Uint8Array ? b : (b.subarray ? b.subarray() : (b as unknown as Uint8Array));
      void (async () => {
        for await (const chunk of lp.decode([bytes] as unknown as AsyncIterable<Uint8Array>)) {
          const u8 = chunk instanceof Uint8Array ? chunk : (chunk as { subarray(): Uint8Array }).subarray();
          sentFrames.push(decode(u8) as Record<string, unknown>);
        }
      })();
    },
    close: async () => { ended = true; notify?.(); },
    async *[Symbol.asyncIterator]() {
      while (!ended) {
        while (inbound.length) yield inbound.shift()!;
        if (ended) return;
        await new Promise<void>((r) => { notify = r; });
        notify = null;
      }
    },
  };

  const push = (frame: Record<string, unknown>): void => {
    const encoded = lp.encode.single(CBOR_ENC.encode(frame) as Uint8Array);
    inbound.push(encoded instanceof Uint8Array ? encoded : (encoded as { subarray(): Uint8Array }).subarray());
    notify?.();
  };

  const node = { dial: async () => {}, newStream: async () => stream } as never;
  return { node, push, sentFrames };
}

const tick = () => new Promise((r) => setTimeout(r, 5));

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
    client.registerSession("aaaa", fakeNode);
    client.registerSession("bbbb", fakeNode);
    expect(client.hasSessions()).toBe(true);
    client.unregisterSession("aaaa");
    expect(client.hasSessions()).toBe(true); // bbbb still present — client must NOT close
    client.unregisterSession("bbbb");
    expect(client.hasSessions()).toBe(false);
    client.close();
  });

  it("registerSession is idempotent (re-register does not duplicate)", async () => {
    const client = await makeClient();
    client.registerSession("aaaa", fakeNode);
    client.registerSession("aaaa", fakeNode);
    client.unregisterSession("aaaa");
    expect(client.hasSessions()).toBe(false);
    client.close();
  });

  it("submitMessageHash after close returns a named failure, not a hang", async () => {
    const client = await makeClient();
    client.close();
    const r = await client.submitMessageHash(fakeNode, new Uint8Array(16), new Uint8Array(32));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("relay_client_closed");
  });

  // The H1 fix's load-bearing correctness: each session's submit must carry ITS OWN
  // last_seen_seq, never an agent-global one — else a newer session looks "ahead" of the
  // relay's per-session counter and gets rejected (last_seen_seq_ahead). Regression for the
  // second-review BLOCKING finding.
  it("BLOCKING regression: a second session submits last_seen_seq from its OWN counter, not agent-global", async () => {
    const kp = generateKeypair();
    const client = new AgentRelayClient({
      relayPeerId: "12D3KooWRelay",
      relayAddrs: ["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWRelay"],
      keyProvider: kp,
      senderPubkey: await kp.getPublicKey(),
      logger: noopLogger,
    });
    const relay = makeFakeRelay();
    const sidA = new Uint8Array(16).fill(0x0a);
    const sidB = new Uint8Array(16).fill(0x0b);
    client.registerSession(Buffer.from(sidA).toString("hex"), relay.node);
    client.registerSession(Buffer.from(sidB).toString("hex"), relay.node);

    // Drive the relay's challenge → auth_ok so the client authenticates on first submit.
    const submit1 = client.submitMessageHash(relay.node, sidA, new Uint8Array(32).fill(1));
    await tick();
    relay.push({ type: "relay_auth_challenge", nonce: new Uint8Array(32).fill(7) });
    await tick();
    relay.push({ type: "relay_auth_ok" });
    await tick();
    // Session A's first leaf → relay assigns seq 5 (and echoes/acks).
    relay.push({ type: "hash_submit_ack", sequence_number: 5 });
    expect((await submit1).ok).toBe(true);

    // Now session B's FIRST submit. Its own relay counter is 0, so it must send last_seen_seq 0
    // — NOT session A's 5. With the old agent-global #lastSeen this would be 5 → relay rejects.
    const submit2 = client.submitMessageHash(relay.node, sidB, new Uint8Array(32).fill(2));
    await tick();
    relay.push({ type: "hash_submit_ack", sequence_number: 1 });
    expect((await submit2).ok).toBe(true);

    // Decode the two hash_submit frames the client actually sent and read last_seen_seq (S1[4]).
    const submits = relay.sentFrames.filter((f) => f["type"] === "hash_submit");
    expect(submits.length).toBe(2);
    const s1A = decode(submits[0]!["structure1_cbor"] as Uint8Array) as unknown[];
    const s1B = decode(submits[1]!["structure1_cbor"] as Uint8Array) as unknown[];
    expect(s1A[4]).toBe(0); // session A's first submit: last_seen_seq 0
    expect(s1B[4]).toBe(0); // session B's first submit: last_seen_seq 0 (NOT 5) — the fix
    client.close();
  });

  it("DOD-MSG-4: submitMessageHash returns the relay's structure2_cbor paired with the sent structure1_cbor", async () => {
    const kp = generateKeypair();
    const client = new AgentRelayClient({
      relayPeerId: "12D3KooWRelay",
      relayAddrs: ["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWRelay"],
      keyProvider: kp,
      senderPubkey: await kp.getPublicKey(),
      logger: noopLogger,
    });
    const relay = makeFakeRelay();
    const sid = new Uint8Array(16).fill(0x0c);
    client.registerSession(Buffer.from(sid).toString("hex"), relay.node);

    const submit = client.submitMessageHash(relay.node, sid, new Uint8Array(32).fill(9));
    await tick();
    relay.push({ type: "relay_auth_challenge", nonce: new Uint8Array(32).fill(7) });
    await tick();
    relay.push({ type: "relay_auth_ok" });
    await tick();
    // The relay's ack now carries the committed Structure2 (opaque bytes here — the round-trip is
    // what matters; real Structure2 verification is the receiver's job in increment 3).
    const fakeS2 = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]);
    relay.push({ type: "hash_submit_ack", sequence_number: 3, structure2_cbor: fakeS2 });

    const res = await submit;
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.sequence_number).toBe(3);
      // structure2_cbor is the relay's record, echoed straight from the ack.
      expect(res.structure2_cbor && Buffer.from(res.structure2_cbor).toString("hex")).toBe(Buffer.from(fakeS2).toString("hex"));
      // structure1_cbor is the sender-signed bytes actually put on the wire (paired with the ack).
      const sent = relay.sentFrames.find((f) => f["type"] === "hash_submit");
      expect(res.structure1_cbor && Buffer.from(res.structure1_cbor).toString("hex")).toBe(
        Buffer.from(sent!["structure1_cbor"] as Uint8Array).toString("hex"),
      );
    }
    client.close();
  });
});

describe("AgentRelayClient: client_record_assignment (FED-OPTIONB-SETUP-001)", () => {
  // Under Option B the directory no longer dials the relay; the CLIENT presents the directory-signed
  // assignment via a client_record_assignment frame. These pin #doRecord's edge logic (idempotency,
  // submit-gating, named-failure-on-reject) that the live spine only exercises on the happy path.
  const carry = () => ({
    participantA: new Uint8Array(32).fill(0xa1),
    participantB: new Uint8Array(32).fill(0xb2),
    sessionTimestamp: 1_750_000_000_000,
    assignmentSignature: new Uint8Array(64).fill(0xc3),
  });

  it("presents the assignment exactly ONCE (idempotent) and gates the first hash_submit on it", async () => {
    const kp = generateKeypair();
    const client = new AgentRelayClient({
      relayPeerId: "12D3KooWRelay",
      relayAddrs: ["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWRelay"],
      keyProvider: kp,
      senderPubkey: await kp.getPublicKey(),
      logger: noopLogger,
    });
    const relay = makeFakeRelay();
    const sid = new Uint8Array(16).fill(0x0d);
    // registerSession with an assignment → eager #doRecord fires on the submit chain.
    client.registerSession(Buffer.from(sid).toString("hex"), relay.node, undefined, carry());
    await tick();
    relay.push({ type: "relay_auth_challenge", nonce: new Uint8Array(32).fill(7) });
    await tick();
    relay.push({ type: "relay_auth_ok" });
    await tick();
    relay.push({ type: "assignment_ok" });
    await tick();

    // A submit now — the session is already recorded, so #doSubmit's #doRecord is a no-op (no 2nd frame).
    const submit = client.submitMessageHash(relay.node, sid, new Uint8Array(32).fill(1));
    await tick();
    relay.push({ type: "hash_submit_ack", sequence_number: 1 });
    expect((await submit).ok).toBe(true);

    const records = relay.sentFrames.filter((f) => f["type"] === "client_record_assignment");
    expect(records.length).toBe(1); // idempotent: eager record only; submit-gate saw recorded=true
    expect(Buffer.from(records[0]!["session_id"] as Uint8Array).equals(Buffer.from(sid))).toBe(true);
    expect((records[0]!["assignment_signature"] as Uint8Array).length).toBe(64);
    expect(Buffer.from(records[0]!["participant_a"] as Uint8Array).equals(Buffer.from(carry().participantA))).toBe(true);
    // The submit was gated AFTER the record (record frame precedes the hash_submit on the wire).
    const recordIdx = relay.sentFrames.findIndex((f) => f["type"] === "client_record_assignment");
    const submitIdx = relay.sentFrames.findIndex((f) => f["type"] === "hash_submit");
    expect(recordIdx).toBeGreaterThanOrEqual(0);
    expect(submitIdx).toBeGreaterThan(recordIdx);
    client.close();
  });

  it("surfaces assignment_invalid as a NAMED warn (never silently treats the session as recorded)", async () => {
    const logs: string[] = [];
    const capLogger = {
      debug() {}, info() {},
      warn(event: string) { logs.push(event); },
      error() {},
    } as unknown as Logger;
    const kp = generateKeypair();
    const client = new AgentRelayClient({
      relayPeerId: "12D3KooWRelay",
      relayAddrs: ["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWRelay"],
      keyProvider: kp,
      senderPubkey: await kp.getPublicKey(),
      logger: capLogger,
    });
    const relay = makeFakeRelay();
    const sid = new Uint8Array(16).fill(0x0e);
    client.registerSession(Buffer.from(sid).toString("hex"), relay.node, undefined, carry());
    await tick();
    relay.push({ type: "relay_auth_challenge", nonce: new Uint8Array(32).fill(7) });
    await tick();
    relay.push({ type: "relay_auth_ok" });
    await tick();
    // The relay rejects the assignment (e.g. forged/non-consortium signature).
    relay.push({ type: "assignment_invalid", reason: "directory_signature_invalid" });
    await tick();

    // The client DID present the assignment, and the rejection is surfaced LOUD (not a silent success).
    expect(relay.sentFrames.some((f) => f["type"] === "client_record_assignment")).toBe(true);
    expect(logs.includes("session.relay.assignment.invalid")).toBe(true);
    client.close();
  });
});
