/**
 * DOD-M15-SEALWIRE-1 bullet 5 — THE WIRING, EXECUTED.
 *
 * ─── Why this file exists, and it is the review finding rather than a nicety ────────────────────
 *
 * Both lanes shipped the sent half with **zero execution of the path**. The three tests in
 * `dod-m15-sealwire-1-authorship.test.ts` call `recordTranscriptMessage` directly with hand-built
 * bytes (`fill(0x7e)`, `fill(0x5a)`), so they prove the STORE accepts a pubkey and a signature and
 * say nothing about whether anything ever hands it one.
 *
 * **The concrete bypass:** delete `authorship` from `sendContent`'s return, delete all five
 * call-site arguments, and that entire suite stays green.
 *
 * And it was not theoretical — review found **two of the five call sites were dead by
 * construction**, sitting inside `if (!sendResult.ok)` while the helper read `r.ok ? … : undefined`.
 * They typechecked. They looked wired. They could never fire. That is invisible to any test that
 * does not drive a real send.
 *
 * ─── ⚠️ WHAT THIS DOES AND DOES NOT COVER — corrected after the first version asserted more ────
 *
 * My first version drove `cello_send` over IPC and asserted the stored row carries a signature. **It
 * failed, and the code was not the reason.** `two-connection-fixture`'s relay points at
 * `/ip4/127.0.0.1/tcp/1` — a dead address — so nothing is ever witnessed through it, no submit
 * happens, and there is legitimately nothing signed to store. **I asserted a precondition the
 * fixture never establishes**, which is the same mistake as the rest of this bullet wearing
 * different clothes.
 *
 * So what is covered here:
 *   1. **The dead-wiring defect itself**, at the seam it lived in — `sentAuthorship` must read the
 *      proof off the FAILURE shape as well as the success one. That is the assertion that was false
 *      in shipped code, and it is unit-exact rather than incidental.
 *   2. **The honest negative** — an unwitnessed send stores no signature and fabricates none.
 *
 * **STILL NOT COVERED, and named so it is not mistaken for done:** a WITNESSED send driven end to
 * end, asserting the stored row carries the proof. That needs a relay that actually acks;
 * `m8c-away-1.test.ts` has one (`makeFakeRelayServerOneshot` plus its node subclass), and promoting
 * it into a shared helper is the way in. **Carried, not silently skipped.**
 */

import { describe, it, expect, afterEach } from "vitest";
import * as lp from "it-length-prefixed";
import { Encoder, decode } from "cbor-x";
import type { CelloNode, Stream } from "@cello-protocol/transport";
import { startTwoConnectionFixture, msgLeafHash, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import { sentAuthorship } from "../session-content-handlers.js";

const CBOR_ENC = new Encoder({ tagUint8Array: false });
/** The peer id `two-connection-fixture` configures when `relay: true`. */
const FIXTURE_RELAY_PEER = "12D3KooWFixtureRelay";

/**
 * A relay that ACTUALLY ACKS — the piece the fixture is missing.
 *
 * `two-connection-fixture` points its relay at a dead loopback address, so nothing is ever
 * witnessed through it. That is fine for the park tests it was built for and fatal for this one:
 * with no ack there is no signature, and an assertion that a row carries proof fails for a reason
 * that has nothing to do with the code. Same shape as `m8c-away-1`'s oneshot server.
 */
function makeAckingRelay() {
  let seq = 0;
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

const SID = "cc".repeat(32);

interface Row {
  direction: string;
  attribution: string;
  sender_pubkey: string | null;
  sender_sig: Uint8Array | null;
}

describe("DOD-M15-SEALWIRE-1 bullet 5 — a real send stores a real proof", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  function sentRows(agent: string, sessionId: string): Row[] {
    const db = fx!.snm.getDb()!;
    const agentId = (db
      .prepare("SELECT agent_id FROM agents WHERE agent_name = ? AND state != 'retired'")
      .get(agent) as { agent_id: string }).agent_id;
    return db
      .prepare(
        `SELECT direction, attribution, sender_pubkey, sender_sig
           FROM transcript WHERE agent_id = ? AND session_id = ? AND direction = 'sent'
          ORDER BY sequence ASC`,
      )
      .all(agentId, sessionId) as unknown as Row[];
  }

  it("★ THE DEAD-WIRING BUG, pinned: the helper must read the proof off BOTH result shapes", () => {
    /**
     * ⚠️ THE EXACT DEFECT REVIEW FOUND, and the one an end-to-end test would have caught only by
     * accident.
     *
     * `sentAuthorship` read `r.ok ? r.authorship : undefined`. Two of the five call sites live
     * inside `if (!sendResult.ok)` — so at those two it was **unconditionally undefined**. It
     * typechecked. It looked wired. It could never fire, and the consequence was that every
     * durably-queued send (witnessed, SIGNED, only the direct hand-off failed) wrote a row with no
     * proof while the proof sat in the result object.
     *
     * A failure-shaped result carrying `authorship` is not a contrivance: `sendContent`'s failure
     * member carries `sequenceNumber` for exactly the same reason, and has since long before this
     * bullet — *"a DURABLY QUEUED message still owns the position the relay witnessed for it."*
     */
    const proof = { senderPubkey: new Uint8Array(32).fill(0x11), senderSig: new Uint8Array(64).fill(0x22) };

    expect(
      sentAuthorship({ ok: true, delivered: true, sequenceNumber: 3, authorship: proof } as never),
      "the delivered path carries it",
    ).toBe(proof);

    expect(
      sentAuthorship({
        ok: false, reason: "session_stream_unavailable", error: "x", durable: true,
        sequenceNumber: 3, authorship: proof,
      } as never),
      "and so does the DURABLY QUEUED path — this is the assertion that was false in shipped code, " +
        "and the two call sites that read it are unreachable on any ok-gated read",
    ).toBe(proof);

    expect(
      sentAuthorship({ ok: false, reason: "no_node", error: "x", durable: false } as never),
      "a result with no proof yields none — never a placeholder",
    ).toBeUndefined();
  });

  it("★★ THE WITNESSED SEND, END TO END: a real relay ack puts a real signature on the row", async () => {
    /**
     * The assertion the whole bullet is for, and the one that was missing when both lanes called it
     * done. It drives `cello_send` over IPC → the real handler → `sendContent` → a relay that
     * genuinely ACKS → the signature captured on the submit → `SubmitResult` → `sentAuthorship()` →
     * the transcript write, then reads the stored bytes back out of SQLite.
     *
     * **Delete `authorship` from `sendContent`'s return, or from any of the call sites, and this is
     * the test that goes red.** Nothing else in the unit does.
     */
    const relay = makeAckingRelay();
    fx = await startTwoConnectionFixture({
      dirPrefix: "cello-sentproof-witnessed-",
      node: makeRelayAwareNode(relay),
    });
    await fx.createSession(SID, "alice", "bobpubkeyhex", undefined, { relay: true });

    const client = await fx.connectAs("alice");
    const res = (await client.send("cello_send", {
      session_id: SID, content: "a message whose authorship is provable",
    })) as { ok?: boolean; reason?: string };

    const rows = sentRows("alice", SID);
    expect(rows.length, `no sent row was written — got ${JSON.stringify(res)}`).toBeGreaterThan(0);
    const row = rows[0]!;

    expect(row.attribution, "we wrote it, so self_authored whatever proof it carries").toBe("self_authored");
    expect(
      row.sender_sig,
      "the relay witnessed and signed this send, so the row must carry the proof. A null here means " +
        "the path from the submit result to the transcript write is not connected — which is " +
        "exactly what shipped, typechecked, and passed every other test in this unit.",
    ).not.toBeNull();
    expect(row.sender_sig!.length, "a 64-byte Ed25519 signature").toBe(64);
    expect(row.sender_pubkey, "and the key it verifies against, taken from inside the signed bytes")
      .toMatch(/^[0-9a-f]{64}$/);
  });

  it("★ an UNWITNESSED send stores no proof, and does not fabricate one", async () => {
    /**
     * The pair, and the one that keeps the fix honest. Without a relay there is no submit, so no
     * Structure 1 goes on the wire and there is nothing signed to store. The row must record
     * `self_authored` with NO signature — the truthful answer — rather than a placeholder that
     * would make an unprovable row look provable.
     *
     * This is also the discriminator the schema comment now names: `self_authored` covers both, and
     * `sender_sig IS NOT NULL` is what separates them.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-sentproof-bare-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex");
    // NOTE: this fixture's relay (when enabled) points at /ip4/127.0.0.1/tcp/1 — a dead address, so
    // nothing is ever witnessed through it. That is why the WITNESSED half of this bullet is not
    // asserted here: see the header.

    const client = await fx.connectAs("alice");
    await client.send("cello_send", { session_id: SID, content: "no relay witnessed this" });

    const rows = sentRows("alice", SID);
    // ASSERTED, not skipped: an early return here would let this pass while proving nothing, which
    // is the shape the whole bullet keeps producing.
    expect(rows.length, "the send must still commit a leaf and write its row").toBeGreaterThan(0);
    expect(rows[0]!.attribution).toBe("self_authored");
    expect(
      rows[0]!.sender_sig,
      "nothing was signed, so nothing is stored — never a placeholder that implies a proof",
    ).toBeNull();
  });

  it("★★★ THE HELD PATH — the ONE case where placeOwnLeaf's authorship argument is load-bearing", async () => {
    /**
     * ⚠️ THIS IS THE TEST BULLET 5 WAS REOPENED FOR, and the reason the previous close was wrong.
     *
     * I closed this bullet on a mutation that reddened — and it reddened for the WRONG WRITER.
     * Removing `authorship` from `recordTranscriptMessage(...)` went red; removing it from
     * `placeOwnLeaf(..., sentAuthorship(...))` stayed **GREEN with 3 passing**. That is structural,
     * not a harness gap:
     *
     *   - On the DELIVERED path `placeOwnLeaf`'s authorship argument is **dead by construction** —
     *     the row's proof arrives from the `recordTranscriptMessage` call below it.
     *   - It is load-bearing in **exactly one case: when the leaf is HELD.** On that path
     *     `recordTranscriptMessage` never runs, because it sits inside `if (placed.placed)`.
     *     **The held entry is the only carrier of the proof**, and it had no executing test.
     *
     * So this drives the carrier end to end: hold a SENT leaf ahead of the tail, close the gap with
     * a received message, and read the row `#releaseHeld` writes.
     *
     * **Revert test, RUN:** delete `...(authorship ? { authorship } : {})` from the hold in
     * `placeOwnLeaf` and this goes red while every other test in this file stays green — which is
     * precisely the blind spot that let the premature close happen.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-sentproof-held-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex");

    const proof = { senderPubkey: new Uint8Array(32).fill(0x11), senderSig: new Uint8Array(64).fill(0x22) };
    const mine = new TextEncoder().encode("held behind a gap, and still provable");

    // Slot 1 with an empty tail: AHEAD of the frontier, so this is HELD, not appended.
    const placed = fx.snm.placeOwnLeaf(
      "alice", SID, Buffer.from(msgLeafHash(mine)).toString("hex"), mine, 1, "corr-held", "msg", proof,
    );
    expect(placed, "precondition: the send must actually be HELD — if it appended, this proves nothing")
      .toMatchObject({ placed: false });
    expect(sentRows("alice", SID).length, "precondition: and NOTHING is in the transcript yet").toBe(0);

    // Close the gap at slot 0. A just-appended leaf unblocks held arrivals whose turn is now next,
    // which is what runs `#releaseHeld` — the only path that writes a held SENT message's row.
    const theirs = new TextEncoder().encode("theirs, at slot zero");
    await fx.snm.ingestReceivedContent("alice", SID, theirs, msgLeafHash(theirs), "corr-recv", 0);

    const rows = sentRows("alice", SID);
    expect(rows.length, "the held message must now be in the transcript — the gap closed").toBe(1);
    expect(
      rows[0]!.sender_sig,
      "THE ASSERTION THE BULLET IS FOR: the proof must survive the hold. It is carried ONLY by the " +
        "held entry — `recordTranscriptMessage` never runs on this path — so a null here means " +
        "placeOwnLeaf's authorship argument is doing nothing, which is exactly what shipped and " +
        "exactly what the delivered-path mutation could not see.",
    ).not.toBeNull();
    expect(rows[0]!.sender_sig!.length, "a 64-byte Ed25519 signature, intact across the hold").toBe(64);
    expect(rows[0]!.sender_pubkey, "and the key it verifies against").toBe("11".repeat(32));
    expect(rows[0]!.attribution, "we wrote it, so self_authored — with a proof attached").toBe("self_authored");
  });

  it("★ and a hold that did NOT carry a proof stores none — the truthful negative", async () => {
    /**
     * The pair, and it keeps the assertion above honest: it must be reading a proof that travelled,
     * not one the release path invents. Same journey, no authorship handed in.
     *
     * This is also the shape of the documented restart gap — `held_content` has no authorship
     * columns, so a SENT message held behind a gap and released AFTER a restart legitimately has no
     * proof to carry. The daemon says so out loud (`session.content.released.authorship.lost`)
     * rather than writing a row that implies one.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-sentproof-heldbare-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex");

    const mine = new TextEncoder().encode("held behind a gap, unwitnessed");
    fx.snm.placeOwnLeaf("alice", SID, Buffer.from(msgLeafHash(mine)).toString("hex"), mine, 1, "corr-held", "msg", undefined);

    const theirs = new TextEncoder().encode("theirs, at slot zero");
    await fx.snm.ingestReceivedContent("alice", SID, theirs, msgLeafHash(theirs), "corr-recv", 0);

    const rows = sentRows("alice", SID);
    expect(rows.length, "the held message is still released — no proof is not a reason to lose it").toBe(1);
    expect(rows[0]!.sender_sig, "nothing was signed, so nothing is stored").toBeNull();
  });
});
