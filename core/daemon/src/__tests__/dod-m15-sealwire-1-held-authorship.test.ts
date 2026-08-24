/**
 * THE HELD SEND KEEPS ITS PROOF — `DOD-M15-SEALWIRE-1` bullet 5, THE case the argument exists for.
 *
 * ─── ⚠️ THIS FILE WAS DELETED AS A DUPLICATE AND HAD TO BE RESTORED. READ THIS BEFORE MERGING IT. ──
 *
 * `dod-m15-sealwire-1-sent-proof-wired.test.ts` has a held-path test too, and the two look
 * interchangeable. **They are not, and deleting either one leaves a hole the other cannot see.**
 *
 *   - **That one covers the CARRIER.** It calls `snm.placeOwnLeaf(...)` DIRECTLY with a hand-built
 *     proof, so it proves the held entry carries authorship through to the released row. Delete the
 *     carry at `session-node-manager.ts` and it reddens.
 *   - **THIS one covers the CALL SITES.** It drives a real `cello_send` over IPC, so the proof has to
 *     travel `sendContent` → `sentAuthorship` → the production `placeOwnLeaf` argument. Mutate either
 *     production call site in `session-content-handlers.ts` to `undefined` and it reddens.
 *
 * **Measured, and this is why the file is back:** with both production call sites passing `undefined`,
 * the entire package stayed green — **278 files, 2910 tests, zero red** — because no production call
 * site is anywhere in the other test's call graph. I deleted this file on the grounds that it
 * duplicated ~70 lines of relay harness. The harness duplication was real; **the coverage was not
 * duplicated at all**, and I traded the only test of the wiring for a tidier fixture.
 *
 * That is `placeOwnLeaf`'s own JSDoc lesson arriving one hop upstream: three call sites once omitted
 * the argument entirely and nothing went red, because **an argument that is never exercised looks
 * exactly like an argument that is correct.**
 *
 * ─── Why this file had to exist before the bullet could close ──────────────────────────────────
 *
 * `placeOwnLeaf` takes an `authorship` argument. The witnessed end-to-end test drives a real send
 * through a real acking relay and asserts the stored row carries a signature — and it passes with
 * that argument mutated to `undefined`. Measured, both directions, same file:
 *
 *   - `recordTranscriptMessage(..., sentAuthorship(sendResult))` → `undefined`: **RED**, 1 failed.
 *   - `placeOwnLeaf(..., "msg", sentAuthorship(sendResult))`     → `undefined`: **GREEN**, 3 passed.
 *
 * **That is structural, not a gap in that test.** On the DELIVERED path `placeOwnLeaf`'s argument is
 * dead by construction: the row's proof arrives from the `recordTranscriptMessage` call below it. The
 * argument is load-bearing in exactly one case — when the leaf is **HELD** behind a sequence gap —
 * and on that path `recordTranscriptMessage` never runs at all, because it sits inside
 * `if (placed.placed)`. The held entry is then the ONLY carrier of the proof to the eventual row.
 *
 * So the sixth writer had no executing test, and the bullet was closed on evidence that could not
 * see it. This is that test: a WITNESSED send, HELD behind a gap, RELEASED, and the released row
 * checked for a real 64-byte signature and the 32-byte key it verifies against.
 *
 * ─── What a user loses without it ─────────────────────────────────────────────────────────────
 *
 * Two people are talking. One message arrives out of order, so the next thing you send waits its
 * turn — completely normal, invisible, happens whenever the network reorders. Your message is
 * witnessed and signed by the relay on the way out. When it finally lands in your transcript, the
 * signature is gone: the row says you wrote it and carries nothing that proves it. It is
 * indistinguishable from a message the relay never saw — so the one record that could later settle
 * "did you send this?" silently cannot.
 *
 * ─── The local acking relay, and why it is not the shared fixture ─────────────────────────────
 *
 * `two-connection-fixture` points its relay at a dead address on port 1, so nothing is ever witnessed
 * through it and there is legitimately no signature to store. The witnessed test solved that with a
 * local acking relay; this file needs the same thing **plus a controllable starting sequence**, so
 * the relay can assign a number AHEAD of the tree and force the hold.
 *
 * Kept local rather than promoted, deliberately: two files now want it and the third should be the
 * one that pays for a shared helper. Noted so the duplication is a decision rather than drift.
 */

import { describe, it, expect, afterEach } from "vitest";
import * as lp from "it-length-prefixed";
import { Encoder, decode } from "cbor-x";
import type { CelloNode } from "@cello-protocol/transport";
import type { Stream } from "@libp2p/interface";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";

const CBOR_ENC = new Encoder({ tagUint8Array: false });
/** The peer id `two-connection-fixture` configures when `relay: true`. */
const FIXTURE_RELAY_PEER = "12D3KooWFixtureRelay";
const SID = "b7".repeat(32);

/**
 * An acking relay whose first assigned sequence is `startSeq + 1`.
 *
 * The gap is the whole point: assign a number ahead of this side's frontier and `placeOwnLeaf` must
 * HOLD rather than append, which is the only path where the authorship argument does anything.
 */
function makeAckingRelay(startSeq: number) {
  let seq = startSeq;
  function openStream() {
    const inbound: Uint8Array[] = [];
    let notify: (() => void) | null = null;
    let ended = false;
    const push = (frame: Record<string, unknown>): void => {
      const enc = lp.encode.single(CBOR_ENC.encode(frame) as Uint8Array);
      inbound.push(enc instanceof Uint8Array ? enc : (enc as { subarray(): Uint8Array }).subarray());
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
            else if (frame["type"] === "hash_submit") push({ type: "hash_submit_ack", sequence_number: ++seq });
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
    return stream;
  }
  return { openStream };
}

/** A node whose relay-peer streams reach the acking relay; everything else is inert. */
function makeRelayAwareNode(relay: ReturnType<typeof makeAckingRelay>): CelloNode {
  return {
    async start() {}, async stop() {},
    getPeerId: () => "fake-sender",
    listenAddresses: () => ["/ip4/127.0.0.1/tcp/0"],
    async dial() { return { peerId: FIXTURE_RELAY_PEER }; },
    async handle() {}, getProtocols: () => [], getConnections: () => [],
    onPeerConnect() {}, onPeerDisconnect() {},
    getDialability: () => ({ dialable: false, publicAddr: null }),
    onDialabilityChange: () => () => {},
    async newStream(peerId: unknown): Promise<Stream> {
      if (String(peerId) === FIXTURE_RELAY_PEER) return relay.openStream() as unknown as Stream;
      return { send() {}, async close() {}, abort() {}, status: "open" } as unknown as Stream;
    },
  } as unknown as CelloNode;
}

interface Row {
  sequence: number;
  direction: string;
  attribution: string;
  sender_pubkey: string | null;
  sender_sig: Uint8Array | null;
}

describe("DOD-M15-SEALWIRE-1 bullet 5 — a HELD send keeps its proof to the row", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  function sentRows(agent: string, sessionId: string): Row[] {
    const db = fx!.snm.getDb()!;
    const agentId = (db
      .prepare("SELECT agent_id FROM agents WHERE agent_name = ? AND state != 'retired'")
      .get(agent) as { agent_id: string }).agent_id;
    return db
      .prepare(
        `SELECT sequence, direction, attribution, sender_pubkey, sender_sig
           FROM transcript WHERE agent_id = ? AND session_id = ? AND direction = 'sent'
          ORDER BY sequence ASC`,
      )
      .all(agentId, sessionId) as unknown as Row[];
  }

  it("★★ WITNESSED, HELD BEHIND A GAP, THEN RELEASED — the row still carries the signature", async () => {
    /**
     * The whole bullet in one path. The relay assigns sequence 2 while this side's tree is empty, so
     * the send is HELD rather than appended — `recordTranscriptMessage` is skipped entirely and the
     * held entry becomes the sole carrier of the proof. Two inbound messages then fill the gap,
     * `ingestReceivedContent` drains the hold, and the released row is read back out of SQLite.
     *
     * **Mutate `placeOwnLeaf`'s `authorship` argument to `undefined` and THIS is the test that goes
     * red.** The witnessed delivered-path test stays green, which is exactly why it could not close
     * this bullet.
     */
    const relay = makeAckingRelay(1); // first ack = 2, one ahead of an empty tree
    fx = await startTwoConnectionFixture({
      dirPrefix: "cello-held-authorship-",
      node: makeRelayAwareNode(relay),
    });
    await fx.createSession(SID, "alice", "bobpubkeyhex", undefined, { relay: true });

    const client = await fx.connectAs("alice");
    const res = (await client.send("cello_send", {
      session_id: SID, content: "held behind a gap, and provably mine",
    })) as { ok?: boolean; held?: boolean; sequence_number?: number };

    expect(
      res.held,
      `precondition: the send must be HELD, not delivered — if it appended, this test measures the ` +
      `delivered path and proves nothing. Got ${JSON.stringify(res)}`,
    ).toBe(true);
    expect(
      sentRows("alice", SID).length,
      "precondition: nothing is in the transcript yet, because a held send skips recordTranscriptMessage",
    ).toBe(0);

    // Fill the gap. `ingestReceivedContent` is what drains the hold — `seedReceived` appends a leaf
    // directly and would never trigger the release, which would make this test green for the wrong
    // reason.
    await fx.ingestReceived("alice", SID, "their first");
    await fx.ingestReceived("alice", SID, "their second");

    const rows = sentRows("alice", SID);
    expect(
      rows.length,
      "the held send must reach the transcript once the gap is filled — if it never lands, the " +
      "assertion below would pass vacuously on an empty set",
    ).toBe(1);

    const row = rows[0]!;
    expect(row.attribution, "we wrote it, whatever proof it carries").toBe("self_authored");
    expect(
      row.sender_sig,
      "THE ASSERTION THIS WHOLE BULLET EXISTS FOR. The relay witnessed and signed this send; being " +
      "held behind a gap is a scheduling detail and must not cost the proof. A null here means the " +
      "released row is indistinguishable from a send the relay never saw.",
    ).not.toBeNull();
    expect(row.sender_sig!.length, "a 64-byte Ed25519 signature").toBe(64);
    expect(
      row.sender_pubkey,
      "and the key it verifies against, taken from inside the signed Structure-1 bytes",
    ).toMatch(/^[0-9a-f]{64}$/);
  }, 60_000);
});
