/**
 * The controllable fake relay stream + node, shared by every `AgentRelayClient` test.
 *
 * Extracted from `session-relay-client.test.ts` when `dod-m15-sealwire-1-sender-leg.test.ts` needed
 * the same rig. Moved rather than copied: a second hand-written relay stub would drift from this one
 * exactly as the trust-signal envelope fixture drifted from the real wire format — silently, until a
 * field was appended and only one of the two knew about it.
 *
 * It captures outbound frames decoded from the length-prefixed wire, and lets a test push inbound
 * frames the client's reader consumes.
 */

import { createHash } from "node:crypto";
import { Encoder, decode } from "cbor-x";
import * as lp from "it-length-prefixed";
import { generateKeypair, buildRelayAckTbs } from "@cello-protocol/crypto";
import type { Logger } from "../types.js";

const CBOR_ENC = new Encoder({ tagUint8Array: false });

export const noopLogger: Logger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
} as unknown as Logger;

/** A node that cannot open a stream — for asserting failures that must never reach the wire. */
export const fakeNode = {
  dial: async () => {},
  newStream: async () => { throw new Error("no-stream"); },
} as never;

export interface FakeRelay {
  node: never;
  push: (frame: Record<string, unknown>) => void;
  sentFrames: Record<string, unknown>[];
}

/**
 * Acknowledge the LAST leaf the client actually submitted, with a real ordering attestation over it.
 *
 * 069-ORDERPROOF: an ack now has to be signed over the content hash the client sent, so a test can
 * no longer push a bare `{ sequence_number }`. The hash is read back out of the submit frame rather
 * than passed in — a test that had to restate it could restate it wrongly and would then be
 * asserting against an attestation for a message nobody sent.
 *
 * `over` is merged last, so a test that wants a BAD attestation (a stranger's key, a forged
 * sequence) overrides exactly the field it is about and leaves the rest genuine.
 */
export async function pushAck(
  relay: FakeRelay,
  sessionId: Uint8Array,
  sequenceNumber: number,
  over: Record<string, unknown> = {},
): Promise<void> {
  const submits = relay.sentFrames.filter((f) => f["type"] === "hash_submit");
  const last = submits[submits.length - 1];
  const s1 = last?.["structure1_cbor"];
  const fields = s1 instanceof Uint8Array ? (decode(s1) as unknown[]) : [];
  const contentHash = fields[1] instanceof Uint8Array ? (fields[1] as Uint8Array) : new Uint8Array(32);
  relay.push({
    type: "hash_submit_ack",
    sequence_number: sequenceNumber,
    ...(await fakeRelayAttestation(sessionId, contentHash, sequenceNumber)),
    ...over,
  });
}

/**
 * @param opts.autoRecordAssignment answer `client_record_assignment` with `assignment_ok`, which is
 *   what a real relay does and what a session registered WITH its anchor waits for (069-ORDERPROOF).
 *   Defaults ON. Turn it OFF in a test that is ABOUT the record handshake — those drive the answer
 *   themselves, and an auto-answer would settle the very exchange they are measuring.
 */
export function makeFakeRelay(opts: { autoRecordAssignment?: boolean } = {}): FakeRelay {
  const autoRecordAssignment = opts.autoRecordAssignment ?? true;
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
          const frame = decode(u8) as Record<string, unknown>;
          sentFrames.push(frame);
          /**
           * 069-ORDERPROOF: answer `client_record_assignment`, because a session registered WITH an
           * assignment now has to be — the client presents it and waits before it will submit
           * anything. A test needs the assignment to carry the relay anchor, so leaving this
           * unanswered would stall every submit on the record timeout instead of on anything the
           * test is about. A real relay answers; so does this one.
           */
          if (autoRecordAssignment && frame["type"] === "client_record_assignment") push({ type: "assignment_ok" });
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

export const tick = (): Promise<unknown> => new Promise((r) => setTimeout(r, 5));

// ─── 069-ORDERPROOF: the relay's ordering attestation, for every fake that has to produce one ──
//
// The client refuses a leaf whose position no ASSIGNED relay attested, and "assigned" means the
// relay key on the directory-signed assignment. So a fake relay has to hold a key and a test has to
// name that key in the session's assignment, exactly as production does. Both are one call each.
//
// ONE keypair for the whole suite, deliberately: a per-test key would let a test pass while naming
// a relay other than the one that signed, which is the case these helpers exist to make impossible
// to write by accident.

const RELAY_KP = generateKeypair();
let relayPubkeyHexCache = "";

/** The fake relay's ack-signing pubkey, hex — what a session assignment carries as `relay_id`. */
export async function fakeRelayPubkeyHex(): Promise<string> {
  if (!relayPubkeyHexCache) relayPubkeyHexCache = Buffer.from(await RELAY_KP.getPublicKey()).toString("hex");
  return relayPubkeyHexCache;
}

/**
 * The minimal assignment carry a test registers a session with, so the client has an ANCHOR to
 * verify attestations against. Only `relayPubkeyHex` is load-bearing here; the rest is shape.
 */
export async function fakeRelayAnchor(): Promise<{
  participantA: Uint8Array; participantB: Uint8Array; sessionTimestamp: number; relayPubkeyHex: string;
}> {
  return {
    participantA: new Uint8Array(32).fill(0xa1),
    participantB: new Uint8Array(32).fill(0xb2),
    sessionTimestamp: 1_700_000_000_000,
    relayPubkeyHex: await fakeRelayPubkeyHex(),
    // NO `assignmentSignature`: this is the ANCHOR only. A carry that also carried one would make
    // the client present `client_record_assignment` and wait for an answer, which every fixture
    // using this would then have to provide — and the two facts are separate since this order.
  };
}

/** A deterministic stand-in for the running root at a position. No fake here rebuilds a tree. */
export const fakeRunningRoot = (n: number): Uint8Array =>
  new Uint8Array(createHash("sha256").update(`fake-relay-running-root:${n}`).digest());

/**
 * The four fields a relay attaches to an ack and to a delivery. Signed over the real statement with
 * the real builder, so a test cannot pass against a weaker one.
 */
export async function fakeRelayAttestation(
  sessionId: Uint8Array,
  contentHash: Uint8Array,
  sequenceNumber: number,
  opts: { timestamp?: number; runningRoot?: Uint8Array; signWith?: ReturnType<typeof generateKeypair> } = {},
): Promise<{ relay_id: string; relay_signature: Uint8Array; timestamp: number; running_root: Uint8Array }> {
  const timestamp = opts.timestamp ?? 1_719_800_000_000;
  const running_root = opts.runningRoot ?? fakeRunningRoot(sequenceNumber);
  const kp = opts.signWith ?? RELAY_KP;
  const relay_id = opts.signWith
    ? Buffer.from(await opts.signWith.getPublicKey()).toString("hex")
    : await fakeRelayPubkeyHex();
  return {
    relay_id,
    relay_signature: new Uint8Array(
      await kp.sign(buildRelayAckTbs(sessionId, contentHash, sequenceNumber, running_root, timestamp)),
    ),
    timestamp,
    running_root,
  };
}
