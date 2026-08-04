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
import { DatabaseSync } from "node:sqlite";
import { Encoder, decode } from "cbor-x";
import * as lp from "it-length-prefixed";
import { generateKeypair, verify, buildRelayAckTbs, msgLeafHash, ctrlLeafHash, docLeafHash, rejectLeafHash, opaqueLeafHash } from "@cello-protocol/crypto";
import {
  AgentRelayClient,
  buildRelayAuthPayload,
  encodeStructure1,
  RELAY_AUTH_DOMAIN,
  LEAF_KIND_MSG,
  LEAF_KIND_CTRL,
  LEAF_KIND_DOC,
  LEAF_KIND_REJECT,
} from "../session-relay-client.js";
import { RelayReceiptStore } from "../relay-receipt-store.js";
import { SessionSealLeafStore } from "../session-seal-leaf-store.js";
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

describe("AgentRelayClient: session_not_found is transient, not terminal (DOD-FIRSTMSG-WITNESS-1)", () => {
  // §7a: a session's FIRST message is submitted before the relay holds the session, is rejected
  // `session_not_found`, and is NEVER resubmitted — so the relay's counter never counts it and the
  // certificate (rebuilt EXCLUSIVELY from relay-witnessed leaves, §7d) omits the opening message.
  //
  // Proven from the live log (23 of 25 submit failures): in EVERY case the relay's
  // `session.relay.assignment.recorded` lands 5 ms – 2.1 s AFTER the failed submit. The relay is
  // reachable and answering — it just does not hold the session YET. That makes `session_not_found`
  // a TRANSIENT state with a bounded, self-clearing cause, and it must be distinguished from
  // `relay_unavailable` (a genuine outage, where proceeding unwitnessed is correct so the inbox
  // stays readable).
  const carry = () => ({
    participantA: new Uint8Array(32).fill(0xa1),
    participantB: new Uint8Array(32).fill(0xb2),
    sessionTimestamp: 1_750_000_000_000,
    assignmentSignature: new Uint8Array(64).fill(0xc3),
  });

  const connectedClient = async () => {
    const kp = generateKeypair();
    const client = new AgentRelayClient({
      relayPeerId: "12D3KooWRelay",
      relayAddrs: ["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWRelay"],
      keyProvider: kp,
      senderPubkey: await kp.getPublicKey(),
      logger: noopLogger,
    });
    return client;
  };

  it("RETRIES the submit when the relay answers session_not_found for a session it never recorded", async () => {
    // This is the live shape of all 23 first-message failures: the SUBMITTING side had no
    // assignment to present (the inbound path dropped `relay_directory_signature`, fixed
    // separately), so it could not create the relay session itself and depended on the
    // counterparty's record landing — which the log shows arriving 5 ms – 2.1 s LATER.
    // The retry is what turns that lost race into a witnessed leaf.
    const client = await connectedClient();
    const relay = makeFakeRelay();
    const sid = new Uint8Array(16).fill(0x7a);

    client.registerSession(Buffer.from(sid).toString("hex"), relay.node);
    await tick();

    const submit = client.submitMessageHash(relay.node, sid, new Uint8Array(32).fill(1));
    await tick();
    relay.push({ type: "relay_auth_challenge", nonce: new Uint8Array(32).fill(7) });
    await tick();
    relay.push({ type: "relay_auth_ok" });
    await tick();
    // The relay does not hold the session yet. This is the EXACT live failure.
    relay.push({ type: "hash_submit_error", reason: "session_not_found" });
    await tick();
    // In the live window the counterparty's record lands here — the retry now succeeds.
    relay.push({ type: "hash_submit_ack", sequence_number: 1 });

    const result = await submit;
    // The leaf ends up WITNESSED. Before the fix this returned
    // { ok: false, reason: "session_not_found" } and the daemon appended it unwitnessed forever,
    // leaving the record one ahead of the relay for the life of the session — the receipt defect.
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.sequence_number).toBe(1);
    expect(relay.sentFrames.filter((f) => f["type"] === "hash_submit").length).toBe(2);
    // Nothing to present, so nothing was recorded — the retry did not invent an assignment.
    expect(relay.sentFrames.some((f) => f["type"] === "client_record_assignment")).toBe(false);
    client.close();
  });

  it("retries session_not_found a BOUNDED number of times — a relay that never holds it fails loudly", async () => {
    const client = await connectedClient();
    const relay = makeFakeRelay();
    const sid = new Uint8Array(16).fill(0x7b);

    client.registerSession(Buffer.from(sid).toString("hex"), relay.node);
    await tick();

    const submit = client.submitMessageHash(relay.node, sid, new Uint8Array(32).fill(2));
    await tick();
    relay.push({ type: "relay_auth_challenge", nonce: new Uint8Array(32).fill(7) });
    await tick();
    relay.push({ type: "relay_auth_ok" });
    await tick();
    // The relay refuses every time — an unbounded retry would hang the send path forever
    // (constraint 3: an inbox must stay readable).
    for (let i = 0; i < 6; i++) {
      relay.push({ type: "hash_submit_error", reason: "session_not_found" });
      await tick();
    }

    const result = await submit;
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("session_not_found");
    // Bounded: it gave up rather than retrying indefinitely.
    const submits = relay.sentFrames.filter((f) => f["type"] === "hash_submit").length;
    expect(submits).toBeGreaterThan(1);
    expect(submits).toBeLessThanOrEqual(3);
    client.close();
  });

  it("a TERMINALLY rejected assignment never submits blind — it fails with its own reason", async () => {
    // AC3: #doRecord's return value is no longer discarded. A relay that cleanly rejected the
    // assignment (assignment_invalid) will reject it again, so submitting would be doomed traffic
    // and retrying would storm the shared per-agent stream. Before the fix this sent the frame
    // anyway and surfaced the relay's `session_not_found` — the wrong subsystem entirely.
    const client = await connectedClient();
    const relay = makeFakeRelay();
    const sid = new Uint8Array(16).fill(0x7e);

    client.registerSession(Buffer.from(sid).toString("hex"), relay.node, undefined, carry());
    await tick();
    relay.push({ type: "relay_auth_challenge", nonce: new Uint8Array(32).fill(7) });
    await tick();
    relay.push({ type: "relay_auth_ok" });
    await tick();
    relay.push({ type: "assignment_invalid", reason: "directory_signature_invalid" });
    await tick();

    const result = await client.submitMessageHash(relay.node, sid, new Uint8Array(32).fill(5));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("relay_assignment_rejected");
    // No doomed hash_submit went on the wire, and no re-present storm.
    expect(relay.sentFrames.some((f) => f["type"] === "hash_submit")).toBe(false);
    expect(relay.sentFrames.filter((f) => f["type"] === "client_record_assignment").length).toBe(1);
    client.close();
  });

  it("NEVER re-presents for a session it already recorded — a sealed session must not be resurrected", async () => {
    // The relay DESTROYS a session on seal (relay-node.ts confirmSeal) and on idle sweep, and keeps
    // NO tombstone — its store re-creates any absent key fresh (seq_counter 0, empty leaf_log,
    // status "active"). So a post-seal send gets `session_not_found`, byte-identical to the
    // first-message race. Re-presenting the still-valid assignment there would RESURRECT the sealed
    // session as a ghost with an empty log — and 2 of the 25 live failures are exactly that shape.
    // The discriminator has to be OUR state (did we record it?), never the relay's reason string.
    const client = await connectedClient();
    const relay = makeFakeRelay();
    const sid = new Uint8Array(16).fill(0x7d);

    client.registerSession(Buffer.from(sid).toString("hex"), relay.node, undefined, carry());
    await tick();
    relay.push({ type: "relay_auth_challenge", nonce: new Uint8Array(32).fill(7) });
    await tick();
    relay.push({ type: "relay_auth_ok" });
    await tick();
    relay.push({ type: "assignment_ok" });
    await tick();
    const recordsAfterRegister = relay.sentFrames.filter((f) => f["type"] === "client_record_assignment").length;
    expect(recordsAfterRegister).toBe(1); // the session IS recorded

    const submit = client.submitMessageHash(relay.node, sid, new Uint8Array(32).fill(4));
    await tick();
    relay.push({ type: "hash_submit_error", reason: "session_not_found" });
    await tick();

    const result = await submit;
    // Reported as what it actually is, not as the race.
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("relay_session_gone");
    // THE assertion: no second assignment was presented, so nothing was recreated on the relay.
    expect(relay.sentFrames.filter((f) => f["type"] === "client_record_assignment").length).toBe(1);
    expect(relay.sentFrames.filter((f) => f["type"] === "hash_submit").length).toBe(1);
    client.close();
  });

  it("does NOT retry a non-transient rejection — a different reason is returned as-is", async () => {
    const client = await connectedClient();
    const relay = makeFakeRelay();
    const sid = new Uint8Array(16).fill(0x7c);

    client.registerSession(Buffer.from(sid).toString("hex"), relay.node, undefined, carry());
    await tick();
    relay.push({ type: "relay_auth_challenge", nonce: new Uint8Array(32).fill(7) });
    await tick();
    relay.push({ type: "relay_auth_ok" });
    await tick();
    relay.push({ type: "assignment_ok" });
    await tick();

    const submit = client.submitMessageHash(relay.node, sid, new Uint8Array(32).fill(3));
    await tick();
    // `session_sealed` is a TERMINAL answer — retrying it would be pointless traffic masking a real
    // state. NOTE: this is NOT the shape of the 2 post-seal failures in the live log; those reported
    // `session_not_found`, because confirmSeal DESTROYS the relay's session entry rather than
    // marking it sealed. `session_sealed` only fires in the narrow sealing/seal_rejected window.
    // That case is covered by the "never re-presents for a session it already recorded" test above.
    relay.push({ type: "hash_submit_error", reason: "session_sealed" });

    const result = await submit;
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("session_sealed");
    expect(relay.sentFrames.filter((f) => f["type"] === "hash_submit").length).toBe(1);
    client.close();
  });
});

describe("AgentRelayClient: sealLeafStore capture (F1 — FED-OPTIONB-SEAL-001)", () => {
  // F1 blocking: the daemon capture path is the PRODUCER of the seal carry. These prove that
  // the sealLeafStore receives the correct data from both own-leaf acks and counterparty leaf_delivers.
  const makeStores = () => {
    const db = new DatabaseSync(":memory:");
    return {
      sealLeafStore: new SessionSealLeafStore(db, noopLogger),
      receiptStore: new RelayReceiptStore(db, noopLogger),
    };
  };

  it("own-leaf hash_submit_ack → store has relay receipt fields (relay_id, relay_timestamp, relay_signature)", async () => {
    const { sealLeafStore, receiptStore } = makeStores();
    const relayKp = generateKeypair();
    const relayPub = await relayKp.getPublicKey();
    const relayIdHex = Buffer.from(relayPub).toString("hex");
    const kp = generateKeypair();
    const pub = await kp.getPublicKey();
    const pubHex = Buffer.from(pub).toString("hex");
    const client = new AgentRelayClient({
      relayPeerId: "12D3KooWRelay",
      relayAddrs: ["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWRelay"],
      keyProvider: kp,
      senderPubkey: pub,
      logger: noopLogger,
      receiptStore,
      sealLeafStore,
    });
    const relay = makeFakeRelay();
    const sid = new Uint8Array(16).fill(0xf1);
    const sidHex = Buffer.from(sid).toString("hex");
    client.registerSession(sidHex, relay.node);

    // The content hash that will be inside Structure1 (the submit produces it from this).
    const contentHash = new Uint8Array(32).fill(1);
    const submit = client.submitMessageHash(relay.node, sid, contentHash);
    await tick();
    relay.push({ type: "relay_auth_challenge", nonce: new Uint8Array(32).fill(7) });
    await tick();
    relay.push({ type: "relay_auth_ok" });
    await tick();

    // Build a REAL relay signature over the ACK TBS (so evaluateRelayAck returns "store").
    const ts = 12345;
    const seq = 1;
    const tbs = buildRelayAckTbs(contentHash, seq, ts);
    const relaySig = await relayKp.sign(tbs);
    const fakeS2 = new Uint8Array([0x01, 0x02, 0x03]);
    relay.push({
      type: "hash_submit_ack",
      sequence_number: seq,
      structure2_cbor: fakeS2,
      relay_id: relayIdHex,
      timestamp: ts,
      relay_signature: relaySig,
    });
    const res = await submit;
    expect(res.ok).toBe(true);

    // The sealLeafStore must have an entry for this leaf WITH receipt fields.
    const carry = sealLeafStore.getCarry(pubHex, sidHex);
    expect(carry.length).toBe(1);
    expect(carry[0].sequenceNumber).toBe(seq);
    expect(carry[0].senderPubkeyHex).toBe(pubHex);
    expect(carry[0].relayId).toBe(relayIdHex);
    expect(carry[0].relayTimestamp).toBe(ts);
    expect(carry[0].relaySignatureHex).toBe(Buffer.from(relaySig).toString("hex"));
    expect(carry[0].structure2Cbor).toBeTruthy();
    expect(carry[0].structure1Cbor).toBeTruthy();
    client.close();
  });

  it("counterparty leaf_deliver → store has no relay receipt fields", async () => {
    const { sealLeafStore } = makeStores();
    const kp = generateKeypair();
    const pub = await kp.getPublicKey();
    const pubHex = Buffer.from(pub).toString("hex");
    const client = new AgentRelayClient({
      relayPeerId: "12D3KooWRelay",
      relayAddrs: ["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWRelay"],
      keyProvider: kp,
      senderPubkey: pub,
      logger: noopLogger,
      sealLeafStore,
    });
    const relay = makeFakeRelay();
    const sid = new Uint8Array(16).fill(0xf2);
    const sidHex = Buffer.from(sid).toString("hex");
    let leafDelivered = false;
    client.registerSession(sidHex, relay.node, (_frame) => { leafDelivered = true; });

    // Authenticate the stream (leaf_deliver requires an active stream).
    const submit = client.submitMessageHash(relay.node, sid, new Uint8Array(32).fill(2));
    await tick();
    relay.push({ type: "relay_auth_challenge", nonce: new Uint8Array(32).fill(7) });
    await tick();
    relay.push({ type: "relay_auth_ok" });
    await tick();
    relay.push({ type: "hash_submit_ack", sequence_number: 1 });
    await submit;

    // Now simulate a counterparty leaf_deliver (authored by someone else).
    const counterpartyPub = new Uint8Array(32).fill(0xcc);
    const s1Cbor = CBOR_ENC.encode([1, new Uint8Array(32).fill(0xdd), counterpartyPub, sid, 0, 1_750_000_000_000]);
    const s2Cbor = new Uint8Array([0x04, 0x05, 0x06]);
    relay.push({
      type: "leaf_deliver",
      session_id: sid,
      sequence_number: 2,
      leaf_kind: 0,
      structure1_cbor: s1Cbor,
      structure2_cbor: s2Cbor,
    });
    await tick();

    expect(leafDelivered).toBe(true);
    // The counterparty leaf is stored WITHOUT receipt fields.
    const carry = sealLeafStore.getCarry(pubHex, sidHex);
    const counterpartyLeaf = carry.find((l) => l.sequenceNumber === 2);
    expect(counterpartyLeaf).toBeDefined();
    expect(counterpartyLeaf!.senderPubkeyHex).toBe(Buffer.from(counterpartyPub).toString("hex"));
    expect(counterpartyLeaf!.relayId).toBeUndefined();
    expect(counterpartyLeaf!.relayTimestamp).toBeUndefined();
    expect(counterpartyLeaf!.relaySignatureHex).toBeUndefined();
    expect(counterpartyLeaf!.structure2Cbor).toBeTruthy();
    expect(counterpartyLeaf!.structure1Cbor).toBeTruthy();
    client.close();
  });

  it("own-echoed leaf_deliver → no duplicate receiptless row (immutability)", async () => {
    const { sealLeafStore, receiptStore } = makeStores();
    const relayKp = generateKeypair();
    const relayPub = await relayKp.getPublicKey();
    const relayIdHex = Buffer.from(relayPub).toString("hex");
    const kp = generateKeypair();
    const pub = await kp.getPublicKey();
    const pubHex = Buffer.from(pub).toString("hex");
    const client = new AgentRelayClient({
      relayPeerId: "12D3KooWRelay",
      relayAddrs: ["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWRelay"],
      keyProvider: kp,
      senderPubkey: pub,
      logger: noopLogger,
      receiptStore,
      sealLeafStore,
    });
    const relay = makeFakeRelay();
    const sid = new Uint8Array(16).fill(0xf3);
    const sidHex = Buffer.from(sid).toString("hex");
    client.registerSession(sidHex, relay.node);

    // Submit own leaf → ack captures it WITH receipt.
    const contentHash = new Uint8Array(32).fill(3);
    const submit = client.submitMessageHash(relay.node, sid, contentHash);
    await tick();
    relay.push({ type: "relay_auth_challenge", nonce: new Uint8Array(32).fill(7) });
    await tick();
    relay.push({ type: "relay_auth_ok" });
    await tick();
    const ts = 999;
    const seq = 1;
    const tbs = buildRelayAckTbs(contentHash, seq, ts);
    const relaySig = await relayKp.sign(tbs);
    relay.push({
      type: "hash_submit_ack",
      sequence_number: seq,
      structure2_cbor: new Uint8Array([0x07, 0x08]),
      relay_id: relayIdHex,
      timestamp: ts,
      relay_signature: relaySig,
    });
    await submit;

    // The relay echoes our OWN leaf back as leaf_deliver (this happens in the protocol).
    // Build a Structure1 authored by US so #isOwnLeaf detects it.
    const s1Cbor = CBOR_ENC.encode([1, contentHash, pub, sid, 0, 1_750_000_000_000]);
    relay.push({
      type: "leaf_deliver",
      session_id: sid,
      sequence_number: seq,
      leaf_kind: 0,
      structure1_cbor: s1Cbor,
      structure2_cbor: new Uint8Array([0x07, 0x08]),
    });
    await tick();

    // MUST still have exactly ONE record at seq 1 — the FIRST (with receipt), not a receiptless duplicate.
    const carry = sealLeafStore.getCarry(pubHex, sidHex);
    const atSeq1 = carry.filter((l) => l.sequenceNumber === 1);
    expect(atSeq1.length).toBe(1);
    expect(atSeq1[0].relayId).toBe(relayIdHex);
    expect(atSeq1[0].relaySignatureHex).toBe(Buffer.from(relaySig).toString("hex"));
    client.close();
  });
});

// ─── DOD-DOC-LEAF-1: the wire leaf-kind bytes ARE the crypto domain prefixes ──
//
// The wire byte and the hash prefix are one agreement: the relay receives the byte
// and computes the leaf hash from it, while the client computes the same hash from
// its domain function. If the two ever disagree the roots diverge silently, which is
// exactly the failure a domain-separated leaf type exists to prevent. These tests are
// the serialization pin for the new constants (M14-PROCEDURE §5 no-consumer exception —
// the submitting consumer arrives with the document envelope in P2).
describe("DOD-DOC-LEAF-1: leaf-kind wire bytes", () => {
  it("the four wire bytes are 0x00/0x02/0x04/0x05 and are mutually distinct", () => {
    expect(LEAF_KIND_MSG).toBe(0x00);
    expect(LEAF_KIND_CTRL).toBe(0x02);
    expect(LEAF_KIND_DOC).toBe(0x04);
    expect(LEAF_KIND_REJECT).toBe(0x05);
    expect(new Set([LEAF_KIND_MSG, LEAF_KIND_CTRL, LEAF_KIND_DOC, LEAF_KIND_REJECT]).size).toBe(4);
  });

  it("each wire byte reproduces its domain's leaf hash exactly", () => {
    const data = new TextEncoder().encode("leaf payload");
    const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
    expect(hex(opaqueLeafHash(LEAF_KIND_MSG, data))).toBe(hex(msgLeafHash(data)));
    expect(hex(opaqueLeafHash(LEAF_KIND_CTRL, data))).toBe(hex(ctrlLeafHash(data)));
    expect(hex(opaqueLeafHash(LEAF_KIND_DOC, data))).toBe(hex(docLeafHash(data)));
    expect(hex(opaqueLeafHash(LEAF_KIND_REJECT, data))).toBe(hex(rejectLeafHash(data)));
  });

  it("no document byte collides with the RFC 6962 internal-node prefix 0x01", () => {
    expect(LEAF_KIND_DOC).not.toBe(0x01);
    expect(LEAF_KIND_REJECT).not.toBe(0x01);
  });
});
