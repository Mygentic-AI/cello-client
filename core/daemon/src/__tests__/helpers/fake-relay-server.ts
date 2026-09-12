/**
 * An in-process relay that ORDERS leaves, so a test can drive the real send and seal paths.
 *
 * EXTRACTED FROM `m8c-away-1.test.ts` rather than written again (the fixture rule). That file had
 * the only copy that both authenticates and answers `hash_submit` with a real sequence number,
 * which is what makes `sendContent` take its witnessed branch and `submitSealLeaf` reach the relay
 * at all. A second copy would have meant the day the leaf protocol changes, half the suite keeps
 * passing against the old one.
 *
 * Two things were added for `DOD-M15-SEALPRECOND-1`, both defaulted off:
 *
 *  - `onLeaf` — the relay tells the test what it ordered, and WHEN. The seal defect is measured as
 *    "the ctrl leaf was submitted while the tree still held two leaves", so a test needs to observe
 *    the tree at the instant of the submit, not afterwards.
 *  - `onDirectStream` — a hook that fires INSIDE the direct-delivery `newStream`, which is the only
 *    place a test can stand between the relay ordering a send and the caller appending its leaf.
 *    That window is the entire subject of the order; a test that cannot enter it cannot prove
 *    anything about it.
 */
import { Encoder, decode } from "cbor-x";
import * as lp from "it-length-prefixed";
import type { CelloNode } from "@cello-protocol/transport";
import type { Stream } from "@libp2p/interface";
import { fakeRelayAttestation, fakeRelayPubkeyHex } from "../relay-client-fake.js";

const CBOR_ENC = new Encoder({ tagUint8Array: false });

export const FAKE_RELAY_PEER_ID = "12D3KooWFakeRelayForOneshotTest";
export const FAKE_RELAY_ADDR = "/ip4/127.0.0.1/tcp/2/p2p/fake-relay-oneshot";

/** What the relay saw, in the order it saw it. `leafKind` 0 is a message, 2 is a seal ctrl leaf. */
export interface OrderedLeaf {
  sequenceNumber: number;
  leafKind: number;
}

export interface FakeRelayOpts {
  /** Called synchronously as the relay assigns a sequence — before the client is told. */
  onLeaf?: (leaf: OrderedLeaf) => void;
  /**
   * Deliver every ordered leaf to every connected stream as `leaf_deliver`, which is what a real
   * relay does and what gives a SECOND daemon its ordering. Default OFF: the existing callers have
   * one client, and echoing leaves back at it would change their auto-acknowledge behaviour.
   */
  broadcastLeaves?: boolean;
}

export function makeFakeRelayServer(opts: FakeRelayOpts = {}) {
  let seq = 0;
  const ordered: OrderedLeaf[] = [];
  const streams: Array<(frame: Record<string, unknown>) => void> = [];
  /**
   * ONE SEQUENCE PER CONTENT HASH — the relay orders a MESSAGE, not a submission.
   *
   * Both parties submit the same leaf (the sender when it sends, the receiver when it
   * acknowledges), and a relay that numbered each submission separately would hand the two sides
   * different positions for the same message: every leaf after the first lands ahead of its own
   * tail and is held forever. That is a fixture artifact with no counterpart in production, and it
   * makes a two-party test unable to reach any of the states it was written for.
   */
  const bySubmission = new Map<string, OrderedLeaf>();
  function openStream() {
    const inbound: Uint8Array[] = [];
    let notify: (() => void) | null = null;
    let ended = false;
    const push = (frame: Record<string, unknown>): void => {
      const encoded = lp.encode.single(CBOR_ENC.encode(frame) as Uint8Array);
      inbound.push(encoded instanceof Uint8Array ? encoded : (encoded as { subarray(): Uint8Array }).subarray());
      notify?.();
    };
    const stream = {
      send: (b: { subarray?: () => Uint8Array } | Uint8Array) => {
        const bytes = b instanceof Uint8Array ? b : (b.subarray ? b.subarray() : (b as unknown as Uint8Array));
        void (async () => {
          for await (const chunk of lp.decode([bytes] as unknown as AsyncIterable<Uint8Array>)) {
            const u8 = chunk instanceof Uint8Array ? chunk : (chunk as { subarray(): Uint8Array }).subarray();
            const frame = decode(u8) as Record<string, unknown>;
            if (frame["type"] === "relay_auth_response") push({ type: "relay_auth_ok" });
            // 069-ORDERPROOF: a session registered with its assignment anchor presents it and waits
            // for this answer before it will submit. A real relay answers; so does this one.
            else if (frame["type"] === "client_record_assignment") push({ type: "assignment_ok" });
            else if (frame["type"] === "hash_submit") {
              const s1 = frame["structure1_cbor"];
              const key = s1 instanceof Uint8Array ? Buffer.from(s1).toString("hex") : String(s1);
              const already = bySubmission.get(key);
              const leaf: OrderedLeaf = already ?? {
                sequenceNumber: ++seq,
                leafKind: typeof frame["leaf_kind"] === "number" ? (frame["leaf_kind"] as number) : 0,
              };
              /**
               * 069-ORDERPROOF: this relay SIGNS its ordering, because the client now refuses a
               * leaf whose position no ASSIGNED relay attested. An unsigned fixture would put every
               * test on the path a client takes when a relay is unfit to witness, which is not the
               * path any of them are about. The signing key is the suite's shared fake relay key,
               * so a test names the same relay in its assignment that actually signed.
               */
              const attest = (sessionId: unknown, contentHash: Uint8Array, n: number) =>
                fakeRelayAttestation(
                  sessionId instanceof Uint8Array ? sessionId : new Uint8Array(16),
                  contentHash,
                  n,
                );
              // The content hash is index 1 of Structure 1, which is what the relay attests over.
              const s1Arr = s1 instanceof Uint8Array ? (decode(s1) as unknown[]) : [];
              const contentHash = s1Arr[1] instanceof Uint8Array ? (s1Arr[1] as Uint8Array) : new Uint8Array(32);
              if (already) {
                // A re-submission of a leaf already ordered: acknowledge with the SAME position and
                // do not witness it twice.
                push({
                  type: "hash_submit_ack",
                  sequence_number: leaf.sequenceNumber,
                  ...(await attest(frame["session_id"], contentHash, leaf.sequenceNumber)),
                });
                continue;
              }
              bySubmission.set(key, leaf);
              ordered.push(leaf);
              // BEFORE the ack, deliberately: the tree state a test wants to inspect is the one that
              // existed when the relay committed the position, not the one after the client reacts.
              opts.onLeaf?.(leaf);
              const attestation = await attest(frame["session_id"], contentHash, leaf.sequenceNumber);
              push({ type: "hash_submit_ack", sequence_number: leaf.sequenceNumber, ...attestation });
              if (opts.broadcastLeaves) {
                // The witness, to everyone on the session — the submitter included, exactly as the
                // real relay echoes it. Whether a leaf is one's own is decided by the CLIENT from
                // the sender pubkey inside `structure1_cbor`, never by a field the relay sets, so
                // the same frame is correct for every recipient.
                const witness = {
                  type: "leaf_deliver",
                  sequence_number: leaf.sequenceNumber,
                  session_id: frame["session_id"],
                  leaf_kind: leaf.leafKind,
                  structure1_cbor: frame["structure1_cbor"],
                  sender_signature: frame["sender_signature"],
                  // 069-ORDERPROOF: the SAME attestation the sender's ack carries, so the recipient
                  // holds it too — which is the whole of unit 2.
                  ...attestation,
                };
                for (const to of streams) to(witness);
              }
            }
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
    push({ type: "relay_auth_challenge", nonce: new Uint8Array(32).fill(7) });
    streams.push(push);
    return stream;
  }
  return {
    openStream,
    ordered: () => [...ordered],
    ctrlSubmits: () => [] as unknown[],
    /** The key a test puts in the assignment as `relay_id` — the anchor the client verifies against. */
    relayPubkeyHex: fakeRelayPubkeyHex,
  };
}

/** A libp2p node that goes nowhere. */
export class FakeNode implements Partial<CelloNode> {
  readonly #peerId = `fake-${Math.random().toString(36).slice(2)}`;
  /** Fail the NEXT direct send only — a transient hand-off failure. */
  failNextStream = false;
  async start(): Promise<void> {}
  async stop(): Promise<void> {}
  getPeerId(): string { return this.#peerId; }
  listenAddresses(): string[] { return ["/ip4/127.0.0.1/tcp/0"]; }
  async dial(_a: string): Promise<{ peerId: string }> { return { peerId: "remote" }; }
  async handle(_p: string, _h: unknown): Promise<void> {}
  /** Real nodes drop a peer that sent a frame on the wrong session; the refusal path calls this. */
  async hangUp(_peer: string): Promise<void> {}
  getProtocols(): string[] { return []; }
  getConnections(): Array<{ peerId: string; encryption: string | undefined }> { return []; }
  onPeerConnect(_h: (p: string) => void): void {}
  onPeerDisconnect(_h: (p: string) => void): void {}
  getDialability(): { dialable: boolean; publicAddr: string | null } { return { dialable: false, publicAddr: null }; }
  onDialabilityChange(_l: (d: { dialable: boolean; publicAddr: string | null }) => void): () => void { return () => {}; }
  async newStream(_peer: string, _proto: string): Promise<Stream> {
    if (this.failNextStream) {
      this.failNextStream = false;
      throw new Error("connection_lost: counterparty stream dead");
    }
    return { send() {}, async close() {}, abort() {}, status: "open" } as unknown as Stream;
  }
}

/** A FakeNode whose relay-peer streams reach the fake relay; everything else is a no-op stream. */
export class FakeRelayAwareNode extends FakeNode {
  /**
   * Fires inside the DIRECT-delivery `newStream`, i.e. after the relay has ordered this send and
   * before the caller places its leaf. Awaited, so a test can run a whole close inside the window.
   */
  onDirectStream?: () => void | Promise<void>;
  /**
   * Every byte this node hands to a DIRECT (non-relay) stream. That is the counterparty's copy of
   * the message, and feeding it to a second daemon's real inbound handler is what makes a two-daemon
   * test possible without two libp2p stacks.
   */
  onDirectSend?: (bytes: Uint8Array) => void;
  constructor(private readonly fakeRelay: ReturnType<typeof makeFakeRelayServer>) { super(); }
  async dial(_addr: unknown): Promise<{ peerId: string }> { return { peerId: FAKE_RELAY_PEER_ID }; }
  async newStream(peerId: unknown, _proto: unknown): Promise<Stream> {
    if (String(peerId) === FAKE_RELAY_PEER_ID) return this.fakeRelay.openStream() as unknown as Stream;
    if (this.onDirectStream) {
      const hook = this.onDirectStream;
      // ONE SHOT: the hook usually starts a close, and re-entering it from the close's own sends
      // would recurse. Cleared before it runs, not after.
      this.onDirectStream = undefined;
      await hook();
    }
    const forward = this.onDirectSend;
    return {
      send(b: Uint8Array | { subarray(): Uint8Array }) {
        forward?.(b instanceof Uint8Array ? b : b.subarray());
      },
      async close() {}, abort() {}, status: "open",
    } as unknown as Stream;
  }
}
