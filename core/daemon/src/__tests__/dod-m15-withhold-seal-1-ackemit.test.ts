/**
 * 033-ACKEMIT / `DOD-M15-WITHHOLD-SEAL-1` — an acknowledgement says what it acknowledged.
 *
 * ─── The failure, from the operator's chair ────────────────────────────────────────────────────
 *
 * Somebody says something to you in a conversation — an injection attempt, a wallet drain — and
 * then wants the paper trail not to contain it. They seal at N−1, leaving their last message out.
 * Every leaf validly signed, nothing false, only something missing.
 *
 * ─── Why that worked, and it is not where anyone looked first ──────────────────────────────────
 *
 * A sender signed `last_seen_seq`, which is a NUMBER. "I saw position 7" attests to a POSITION and
 * never to CONTENT. So the chain everyone believed existed was really two signatures meeting at the
 * relay: the counterparty signing a position, and the relay's receipt signing that the position
 * held hash X. Withhold the relay's half and a signed acknowledgement is an unbacked number.
 *
 * These tests pin the fix's two halves:
 *   EMIT   — every claim this daemon signs is v2 and carries the hash of what it actually received.
 *   CHECK  — the receiving daemon compares that hash against its OWN record, with no relay in the
 *            test at all. That is the half the DoD line exists for: the acknowledgement holds
 *            bilaterally, so withholding the witness no longer dissolves it.
 */
import { describe, it, expect, afterEach } from "vitest";
import { decode } from "cbor-x";
import * as lp from "it-length-prefixed";
import { encodeCbor, encodeStructure1, computeGenesisPrevRoot, STRUCTURE1_VERSION_V2 } from "@cello-protocol/protocol-types";
import { generateKeypair, sealSessionContent, buildRelayAckTbs } from "@cello-protocol/crypto";
import { AgentRelayClient, LEAF_KIND_MSG } from "../session-relay-client.js";
import { makeFakeRelay, tick, noopLogger } from "./relay-client-fake.js";
import { DatabaseSync } from "node:sqlite";
import { SessionSealLeafStore } from "../session-seal-leaf-store.js";
import { RelayReceiptStore } from "../relay-receipt-store.js";
import { encodeParkEnvelope, decodeParkEnvelope, PARK_ENVELOPE_VERSION_S1SIG } from "../park-envelope.js";
import { startTwoConnectionFixture, FakeNode, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import type { CelloNode } from "@cello-protocol/transport";
import { wireContentHash } from "../wire-content-hash.js";
import { relayAckHashRefusalNotice } from "../refusal-reasons.js";
import { SESSION_CONTENT_ENCRYPTION_V1 } from "../content-encryption-status.js";

const SID = "3c".repeat(32);
const PEER = "12D3KooWQYV9dGMFoRzNStwpXztXaBUjtPqi6aMghfATmPnRAENn";
const BODY = new TextEncoder().encode("the message they would rather the receipt did not contain");
/** The key `createSession` agrees for content encryption — the fixture's completed key exchange. */
const CONTENT_KEY = new Uint8Array(32).fill(0x7e);

/** A recognisable fill, so a wrong constant fails loudly instead of matching an all-zero default. */
const GENESIS = new Uint8Array(32).fill(0x9c);

/**
 * Index 6 as bytes, or a failure that NAMES what was there instead of crashing inside Buffer.
 *
 * Measured while making these tests fail on purpose: with the emitter reverted, two of them died on
 * `TypeError: The first argument must be of type string ... Received undefined` — a message that
 * sends the next reader to audit Buffer rather than to the field that went missing.
 */
/**
 * Every frame the daemon actually wrote to the wire, decoded.
 *
 * ⚠️ UN-FRAMED WITH `lp.decode`, NOT BY PROBING OFFSETS. The neighbouring suites strip the
 * length prefix by trying `subarray(0..3)` and taking the first offset that decodes — and a CBOR
 * decoder handed a wrong offset does not reliably throw: measured here, it returned an object with
 * NO KEYS, so `find(f => f.type === "content_frame")` reported "the send never reached the wire"
 * about a frame that was sitting right there. Reading the varint properly is the difference between
 * a test that measures the frame and one that measures the guess.
 */
async function sentFrames(node: CelloNode | null): Promise<Array<Record<string, unknown>>> {
  const raw = (node as unknown as { sent?: Uint8Array[] } | null)?.sent ?? [];
  const out: Array<Record<string, unknown>> = [];
  for (const framed of raw) {
    for await (const chunk of lp.decode([framed] as unknown as AsyncIterable<Uint8Array>)) {
      const u8 = chunk instanceof Uint8Array ? chunk : (chunk as { subarray(): Uint8Array }).subarray();
      out.push(decode(u8) as Record<string, unknown>);
    }
  }
  return out;
}

function ackHash(arr: unknown[]): Uint8Array {
  expect(arr.length, "v2 is SEVEN fields — six means the emitter was reverted").toBe(7);
  expect(arr[6], "index 6 must be the 32-byte ack hash").toBeInstanceOf(Uint8Array);
  return arr[6] as Uint8Array;
}

/**
 * Drive a client to authenticated, then read back the ONE `hash_submit` it wrote.
 *
 * Returns the decoded Structure 1 ARRAY — not the daemon's own re-decode of it. The signature is
 * over the ENCODED BYTES, so a test that reconstructs the fields it expects and compares those can
 * agree with a build that emits something else entirely; reading the array off the wire is what
 * makes the shape assertion mean the wire shape.
 */
async function submittedStructure1(opts: { genesis?: Uint8Array; deliverFirst?: { seq: number; contentHash: Uint8Array; senderPubkey: Uint8Array } } = {}): Promise<{
  arr: unknown[];
  result: { ok: boolean; reason?: string };
}> {
  const kp = generateKeypair();
  const client = new AgentRelayClient({
    relayPeerId: "12D3KooWRelay",
    relayAddrs: ["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWRelay"],
    keyProvider: kp,
    senderPubkey: await kp.getPublicKey(),
    logger: noopLogger,
  });
  const relay = makeFakeRelay();
  const sid = Uint8Array.from(Buffer.from(SID, "hex"));
  const sidHex = SID;
  client.registerSession(sidHex, relay.node, undefined, undefined, opts.genesis);

  let submit = client.submitMessageHash(relay.node, sid, wireContentHash(BODY), LEAF_KIND_MSG);
  await tick();
  relay.push({ type: "relay_auth_challenge", nonce: new Uint8Array(32).fill(7) });
  await tick();
  relay.push({ type: "relay_auth_ok" });
  await tick();
  relay.push({ type: "hash_submit_ack", sequence_number: 9 });
  let result = await submit;

  if (opts.deliverFirst) {
    /**
     * ⚠️ THE LEAF MUST LAND BEFORE THE SUBMIT WE READ, NOT DURING IT — this test was written the
     * other way round first and measured position 0 for a leaf it had already delivered.
     *
     * `#doSubmitOnce` encodes and SIGNS Structure 1 at the top of the call, so a `leaf_deliver`
     * pushed while a submit is in flight is genuinely too late for that claim — which is correct
     * behaviour, because the bytes were already signed. So the fixture drives a full submit to get
     * authenticated, delivers the counterparty's leaf, and reads the NEXT submit.
     *
     * The delivered leaf carries the counterparty's own signed Structure 1, and index 1 of THOSE
     * bytes is the hash this daemon must go on to acknowledge — never the relay-built structure2
     * beside it.
     */
    relay.push({
      type: "leaf_deliver",
      session_id: sid,
      sequence_number: opts.deliverFirst.seq,
      leaf_kind: LEAF_KIND_MSG,
      structure1_cbor: encodeStructure1({
        contentHash: opts.deliverFirst.contentHash,
        senderPubkey: opts.deliverFirst.senderPubkey,
        sessionId: sid,
        lastSeenSeq: 0,
        timestamp: 1_750_000_000_000,
        lastSeenHash: GENESIS,
      }),
      structure2_cbor: encodeCbor([opts.deliverFirst.seq]) as Uint8Array,
    });
    await tick();
    submit = client.submitMessageHash(relay.node, sid, wireContentHash(BODY), LEAF_KIND_MSG);
    await tick();
    relay.push({ type: "hash_submit_ack", sequence_number: 10 });
    result = await submit;
  }
  client.close();

  const submits = relay.sentFrames.filter((f) => f["type"] === "hash_submit");
  const submitted = submits[submits.length - 1];
  return {
    arr: submitted ? (decode(submitted["structure1_cbor"] as Uint8Array) as unknown[]) : [],
    result: result as { ok: boolean; reason?: string },
  };
}

describe("033-ACKEMIT — production EMITS what it saw", () => {
  it("★ every submit is a SEVEN-field, VERSION 2 Structure 1 — the shape, read off the wire", async () => {
    /**
     * The load-bearing emitter test. Revert `lastSeenHash` out of the encode call in
     * `#doSubmitOnce` and this reddens on `arr.length` and on `arr[0]`.
     *
     * ⚠️ IT ASSERTS THE VALUE, NOT THAT SOMETHING WAS THERE. "It did not refuse" and "it decoded"
     * are shadows — a build emitting six fields still produces a decodable array, and a build
     * emitting `undefined` at index 6 still produces a seven-element one. So the version tag, the
     * length and the 32 bytes are each named.
     */
    const { arr, result } = await submittedStructure1({ genesis: GENESIS });
    expect(result.ok, `the submit itself must succeed: ${result.reason}`).toBe(true);
    expect(arr.length, "v2 is SEVEN fields — six means the emitter was reverted").toBe(7);
    expect(arr[0], "the VERSION tag is what tells a reader index 6 is an ack hash, not a submission id").toBe(STRUCTURE1_VERSION_V2);
    expect(arr[6], "index 6 must be BYTES, not CBOR undefined dressed as a present key").toBeInstanceOf(Uint8Array);
    expect((arr[6] as Uint8Array).length, "a SHA-256 root is exactly 32 bytes — never a prefix").toBe(32);
  });

  it("★ the FIRST message of a session carries the session's GENESIS — the exact bytes, not zeros", async () => {
    /**
     * `last_seen_hash` IS A VALUE, NEVER AN ABSENCE. The first message has seen nothing, and that
     * case is a defined 32 bytes.
     *
     * ⚠️ THE EXEMPLAR IS THE REAL DERIVATION, NOT A STAND-IN. The genesis is computed here from
     * `computeGenesisPrevRoot` over real keys, so the assertion pins the value both sides actually
     * agree on. A test that passed its own fill through and checked the fill came back would stay
     * green if production substituted 32 zero bytes for a session it could not derive — which is
     * precisely the constant this must never be, because one identical across every session is one
     * an attacker can present for any session.
     */
    const a = await generateKeypair().getPublicKey();
    const b = await generateKeypair().getPublicKey();
    const realGenesis = computeGenesisPrevRoot(a, b, Uint8Array.from(Buffer.from(SID, "hex")), 1_750_000_000_000);

    const { arr, result } = await submittedStructure1({ genesis: realGenesis });
    expect(result.ok).toBe(true);
    expect(Buffer.from(ackHash(arr)).toString("hex")).toBe(Buffer.from(realGenesis).toString("hex"));
    expect(arr[4], "and it acknowledges POSITION ZERO — it has seen nothing yet").toBe(0);
    expect(
      Buffer.from(ackHash(arr)).equals(Buffer.alloc(32)),
      "32 zero bytes is the one value this may never be",
    ).toBe(false);
  });

  it("★ after a counterparty leaf, the claim acknowledges THAT leaf's content hash — position AND content move together", async () => {
    /**
     * The pair is the whole point. `last_seen_seq` keeps doing ordering and dedup work; the hash is
     * what makes the acknowledgement mean a MESSAGE rather than a number.
     *
     * The delivered hash is deliberately NOT the genesis, so a build that ignored the leaf and kept
     * emitting the seed fails here rather than passing on a value that happens to be 32 bytes.
     */
    const cp = generateKeypair();
    const cpPub = await cp.getPublicKey();
    const theirHash = wireContentHash(new TextEncoder().encode("what they actually said"));

    const { arr, result } = await submittedStructure1({
      genesis: GENESIS,
      deliverFirst: { seq: 4, contentHash: theirHash, senderPubkey: cpPub },
    });
    expect(result.ok).toBe(true);
    expect(arr[4], "the position advanced to the delivered leaf").toBe(4);
    expect(Buffer.from(ackHash(arr)).toString("hex")).toBe(Buffer.from(theirHash).toString("hex"));
    expect(
      Buffer.from(ackHash(arr)).toString("hex"),
      "and it is no longer the seed — a build that ignored the leaf would still be emitting that",
    ).not.toBe(Buffer.from(GENESIS).toString("hex"));
  });

  it("★ NO seed ⇒ v1 claiming POSITION ZERO — the one honest emission, and it asserts nothing", async () => {
    /**
     * ⚠️ **THE BOUND ON THIS UNIT, PINNED AS A TEST RATHER THAN LEFT IN A COMMENT.**
     *
     * A session registered with no genesis and no assignment to derive one from has nothing to
     * acknowledge, and the honest claim is `last_seen_seq: 0` with no hash: "I have seen nothing of
     * yours, and I assert nothing about your content."
     *
     * That is NOT the fail-open this unit closes. The hole is a claim naming a POSITION with no
     * content behind it — `last_seen_seq >= 1` and no hash — and the receiving daemon refuses
     * exactly that, which the receive-side test below pins. This names no position.
     *
     * An earlier version REFUSED the submit here, and it was wrong for a measurable reason:
     * sessions brokered without a relay assignment are real (the directory does not always return
     * one), and refusing left them unable to be witnessed at all — trading a hole this claim does
     * not have for a failure of the thing the product is for.
     */
    const { arr, result } = await submittedStructure1({ genesis: undefined });
    expect(result.ok, "the leaf is still witnessed — an unacknowledging claim is not a broken one").toBe(true);
    expect(arr.length, "SIX fields: there is no hash, and an invented one would be worse than none").toBe(6);
    expect(arr[0]).toBe(1);
    expect(arr[4], "and it names NO position, which is what makes the absent hash honest").toBe(0);
  });

  it("★ INDEX 6 IS EXCLUSIVE: a v2 claim carrying a submission id is REFUSED, not coerced", () => {
    /**
     * `DOD-M15-SUBMIT-ID-1` reserved index 6 for a sender-minted submission id and the relay
     * tolerates that shape. From this unit index 6 is the ack hash, and the two are mutually
     * exclusive ON THE WIRE — a length check cannot tell them apart, only the version tag can.
     *
     * The encoder is the enforcement point: there is no way to ask it for both, so a v2 claim
     * cannot carry a submission id and a caller that tries gets an exception rather than a frame
     * whose index 6 means whichever the reader guesses.
     */
    const senderPubkey = new Uint8Array(32).fill(0x11);
    const sessionId = new Uint8Array(16).fill(0x22);
    const contentHash = new Uint8Array(32).fill(0x33);

    // A malformed ack hash is REFUSED at the last point before signing — never silently dropped to
    // v1, which is the downgrade the layout exists to close.
    expect(() =>
      encodeStructure1({
        contentHash, senderPubkey, sessionId, lastSeenSeq: 1, timestamp: 1_750_000_000_000,
        lastSeenHash: new Uint8Array(16).fill(0x5b),
      }),
    ).toThrow(/32 bytes/);

    // And the shapes stay distinguishable: v1 six fields, v2 seven with the version saying so.
    const v1 = decode(encodeStructure1({ contentHash, senderPubkey, sessionId, lastSeenSeq: 1, timestamp: 1_750_000_000_000 })) as unknown[];
    const v2 = decode(encodeStructure1({ contentHash, senderPubkey, sessionId, lastSeenSeq: 1, timestamp: 1_750_000_000_000, lastSeenHash: new Uint8Array(32).fill(0x44) })) as unknown[];
    expect([v1.length, v1[0]]).toEqual([6, 1]);
    expect([v2.length, v2[0]]).toEqual([7, 2]);
  });
});


describe("033-ACKEMIT — the OTHER production emitter: an unwitnessed send", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  it("★ a send with NO relay signs a v2 claim too — the second emitter, which had no coverage at all", async () => {
    /**
     * ⚠️ **THIS TEST EXISTS BECAUSE A MUTATION SURVIVED, and that is the whole argument for it.**
     *
     * There are TWO production Structure 1 builders. `session-relay-client` builds the one that
     * rides a `hash_submit`; `#signOwnContentClaim` builds the one for the path where no submit
     * happens — a relay-degraded or relay-less send — and it is the emitter whose comment said "v1
     * DELIBERATELY" until this unit. With the whole suite green, deleting `lastSeenHash` from THAT
     * call site changed nothing: every emitter assertion was aimed at the other writer.
     *
     * A red on one writer proves only that AT LEAST ONE of them works. This aims at the other one.
     */
    let node: CelloNode | null = null;
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-ackemit-unwitnessed-", node: node = new FakeNode() as unknown as CelloNode });
    // NO `relay: true` — this session has no relay client at all, so nothing is witnessed and
    // `#signOwnContentClaim` is the only thing that can produce a claim for the frame.
    await fx.createSession(SID, "alice", "bb".repeat(32), PEER);

    const { hash, alg } = await fx.snm.contentHashForSession("alice", SID, BODY);
    const res = await fx.snm.sendContent("alice", SID, BODY, hash, "corr", LEAF_KIND_MSG, alg);
    expect(res.ok, "the send itself must work — this path is the relay-degraded one, not a failure").toBe(true);
    await new Promise((r) => setTimeout(r, 200));

    const frame = (await sentFrames(node)).find((f) => f["type"] === "content_frame");
    expect(frame, "the send must reach the wire for this to prove anything").toBeDefined();
    const arr = decode(frame!["structure1_cbor"] as Uint8Array) as unknown[];

    expect(arr.length, "SEVEN fields — six means this emitter was reverted while the other stayed").toBe(7);
    expect(arr[0]).toBe(STRUCTURE1_VERSION_V2);
    /**
     * THE VALUE, NOT THE SHAPE. The fixture seeds the session's genesis as 0x9c repeated — the
     * value a completed session open leaves — so this names what the claim acknowledges rather than
     * checking that 32 bytes of something are present.
     */
    expect(Buffer.from(ackHash(arr)).toString("hex")).toBe(Buffer.from(new Uint8Array(32).fill(0x9c)).toString("hex"));
    expect(arr[4], "nothing has been received on this session, so it acknowledges position zero").toBe(0);
  }, 60_000);
});

describe("034-CARRYLEAF — a message its sender never witnessed is witnessed by the receiver", () => {
  it("★★ the carried claim goes on the wire VERBATIM — the author's bytes and the author's signature", async () => {
    /**
     * ⚠️ **THE HALF THAT MUST BE ASSERTED AT THE WIRE, because both ways of getting it wrong are
     * invisible from anywhere else.**
     *
     * Re-encoding the author's Structure 1 changes the signed bytes, and the relay then refuses a
     * leaf that is perfectly valid — measured on this exact structure before, where a daemon-local
     * encoder emitted a timestamp as float64 where the published one promotes to uint64. Re-signing
     * it is worse: it turns their statement into ours, in a record whose whole value is that each
     * party's words are their own.
     *
     * So the assertion is byte equality on both fields, read back off the frame the client wrote.
     */
    const author = generateKeypair();
    const authorPub = await author.getPublicKey();
    const contentHash = wireContentHash(BODY);
    const theirClaim = encodeStructure1({
      contentHash,
      senderPubkey: authorPub,
      sessionId: Uint8Array.from(Buffer.from(SID, "hex")),
      lastSeenSeq: 3,
      timestamp: 1_750_000_000_000,
      lastSeenHash: new Uint8Array(32).fill(0x5a),
    });
    const theirSig = await author.sign(theirClaim);

    // OUR client — a different identity entirely. It is witnessing, not authoring.
    const us = generateKeypair();
    const client = new AgentRelayClient({
      relayPeerId: "12D3KooWRelay",
      relayAddrs: ["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWRelay"],
      keyProvider: us,
      senderPubkey: await us.getPublicKey(),
      logger: noopLogger,
    });
    const relay = makeFakeRelay();
    const sid = Uint8Array.from(Buffer.from(SID, "hex"));
    client.registerSession(SID, relay.node, undefined, undefined, GENESIS);

    const submit = client.witnessReceivedLeaf(relay.node, sid, contentHash, LEAF_KIND_MSG, {
      structure1Cbor: theirClaim,
      senderSignature: theirSig,
    });
    await tick();
    relay.push({ type: "relay_auth_challenge", nonce: new Uint8Array(32).fill(7) });
    await tick();
    relay.push({ type: "relay_auth_ok" });
    await tick();
    relay.push({ type: "hash_submit_ack", sequence_number: 4 });
    const res = await submit;
    client.close();

    expect(res.ok, `the witness submit must go through: ${JSON.stringify(res)}`).toBe(true);
    const frame = relay.sentFrames.find((f) => f["type"] === "hash_submit");
    expect(frame, "a hash_submit must reach the wire for this to prove anything").toBeDefined();
    expect(
      Buffer.from(frame!["structure1_cbor"] as Uint8Array).toString("hex"),
      "the AUTHOR's bytes, untouched — a re-encode makes the relay refuse a valid leaf",
    ).toBe(Buffer.from(theirClaim).toString("hex"));
    expect(
      Buffer.from(frame!["sender_signature"] as Uint8Array).toString("hex"),
      "and the AUTHOR's signature — signing it ourselves would turn their statement into ours",
    ).toBe(Buffer.from(theirSig).toString("hex"));

    /**
     * AND OUR OWN ACKNOWLEDGEMENT STATE IS NOT RESTATED INTO IT. `last_seen_seq` and
     * `last_seen_hash` inside those bytes are the AUTHOR's account of what THEY had seen. This
     * client's own seed is the genesis; if the carried path had rebuilt the claim, index 4 would
     * read 0 and index 6 would be the genesis instead of theirs.
     */
    const arr = decode(frame!["structure1_cbor"] as Uint8Array) as unknown[];
    expect(arr[4], "their last_seen_seq, not ours").toBe(3);
    expect(Buffer.from(ackHash(arr)).toString("hex")).toBe(Buffer.from(new Uint8Array(32).fill(0x5a)).toString("hex"));
  });

  it("★★★ THE WHOLE POINT: a leaf its author withheld ends up in the SEAL CARRY, which is what a receipt is built from", async () => {
    /**
     * ⚠️ **THIS IS THE PROPERTY `DOD-M15-WITHHOLD-SEAL-1` IS ABOUT, and every other test in this
     * file is a step on the way to it.**
     *
     * The seal carry is the leaf chain a unilateral seal hands the directory — it IS the receipt's
     * raw material. Before this unit both of its writers needed the relay to have spoken first, so
     * a message whose author never submitted it could never get in: the victim held the message,
     * held the author's signature over it, and still could not put it in their receipt.
     *
     * ⚠️ **THE FIXTURE IS THE PRODUCTION ONE — a SIGNED ack and a real `RelayReceiptStore`.** The
     * first version of this test wired neither, so `#captureReceipt` short-circuited and the
     * ack-path carry write never ran. In production it runs FIRST, and the store is
     * `INSERT OR IGNORE`, so the row this test inspects is the row that row WINS. Asserting against
     * the other one made a real defect — the ack path labelling the author as the submitter and
     * attaching a relay receipt to a leaf we did not write — invisible.
     */
    const author = generateKeypair();
    const authorPub = await author.getPublicKey();
    const contentHash = wireContentHash(BODY);
    const withheld = encodeStructure1({
      contentHash,
      senderPubkey: authorPub,
      sessionId: Uint8Array.from(Buffer.from(SID, "hex")),
      lastSeenSeq: 0,
      timestamp: 1_750_000_000_000,
      lastSeenHash: new Uint8Array(32).fill(0x9c),
    });
    const authorSig = await author.sign(withheld);

    const relayKp = generateKeypair();
    const relayIdHex = Buffer.from(await relayKp.getPublicKey()).toString("hex");
    const us = generateKeypair();
    const usPub = await us.getPublicKey();
    const db = new DatabaseSync(":memory:") as unknown as ConstructorParameters<typeof SessionSealLeafStore>[0];
    const sealLeafStore = new SessionSealLeafStore(db, noopLogger);
    const receiptStore = new RelayReceiptStore(db, noopLogger);
    const client = new AgentRelayClient({
      relayPeerId: "12D3KooWRelay",
      relayAddrs: ["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWRelay"],
      keyProvider: us,
      senderPubkey: usPub,
      logger: noopLogger,
      receiptStore,
      sealLeafStore,
    });
    const relay = makeFakeRelay();
    const sid = Uint8Array.from(Buffer.from(SID, "hex"));
    client.registerSession(SID, relay.node, undefined, undefined, GENESIS);

    const submit = client.witnessReceivedLeaf(relay.node, sid, contentHash, LEAF_KIND_MSG, {
      structure1Cbor: withheld,
      senderSignature: authorSig,
    });
    await tick();
    relay.push({ type: "relay_auth_challenge", nonce: new Uint8Array(32).fill(7) });
    await tick();
    relay.push({ type: "relay_auth_ok" });
    await tick();
    const seq = 7;
    const ts = 12345;
    const s2 = encodeCbor([seq, authorPub, contentHash, authorSig]) as Uint8Array;
    relay.push({
      type: "hash_submit_ack",
      sequence_number: seq,
      structure2_cbor: s2,
      relay_id: relayIdHex,
      timestamp: ts,
      relay_signature: await relayKp.sign(buildRelayAckTbs(contentHash, seq, ts)),
    });
    expect((await submit).ok, "the witness submit must be acked").toBe(true);
    await tick();
    client.close();

    const carry = sealLeafStore.getCarry(Buffer.from(usPub).toString("hex"), SID);
    const row = carry.find((l) => l.sequenceNumber === seq);
    expect(
      row,
      `the withheld leaf must be in the carry — this is the receipt's raw material:\n${JSON.stringify(carry.map((c) => ({ seq: c.sequenceNumber, sender: c.senderPubkeyHex.slice(0, 12) })))}`,
    ).toBeDefined();
    expect(
      row!.senderPubkeyHex,
      "attributed to its AUTHOR, taken from inside the bytes they signed — not to whoever handed it over",
    ).toBe(Buffer.from(authorPub).toString("hex"));
    expect(
      Buffer.from(row!.structure1Cbor).toString("hex"),
      "carrying the AUTHOR's own signed bytes — that is what makes it undeniable by them",
    ).toBe(Buffer.from(withheld).toString("hex"));
    /**
     * ⚠️ NO RELAY RECEIPT ON A LEAF WE DID NOT WRITE. A receipt is what pins OUR OWN leaves to a
     * sequence we could otherwise renumber; attaching one to somebody else's leaf would assert a
     * property about their message that our ack does not establish.
     */
    expect(row!.relaySignatureHex, "no receipt is attached to a leaf this agent did not author").toBeUndefined();
    expect(row!.relayId).toBeUndefined();
  });

  it("★★ AND THE AUTHOR KEEPS THEIR RECEIPT: our own leaf, witnessed by the counterparty, still enters our carry", async () => {
    /**
     * ⚠️ **THE REGRESSION THIS UNIT INTRODUCED AND ALMOST SHIPPED — review F2.**
     *
     * Once the counterparty can witness OUR leaf, the relay delivers it back to us and
     * `authoredByUs` is true, so the counterparty-leaf capture skipped it. We never submitted it,
     * so no ack arrived and the ack path wrote nothing either. **A permanent hole at that position
     * in our own carry** — the unilateral seal refuses a gapped chain, the bilateral one refuses to
     * co-sign a root it cannot judge, and the guidance for both sends the operator to `cello_receive`
     * and then to force-abandon. An honest sender whose relay hiccuped once lost the receipt for the
     * entire conversation, over a message sitting in their own transcript.
     *
     * **And the asymmetry is the security property, so it is asserted too.** The leaf is kept with
     * NO relay receipt, because we hold none. A bilateral seal needs a contiguous chain and now gets
     * one; a UNILATERAL seal additionally requires every one of OUR leaves to carry a receipt, so a
     * party who never witnesses their own messages still cannot seal alone on them. Keeping the leaf
     * must not quietly hand them that.
     */
    const us = generateKeypair();
    const usPub = await us.getPublicKey();
    const ourHash = wireContentHash(BODY);
    const ourClaim = encodeStructure1({
      contentHash: ourHash,
      senderPubkey: usPub,
      sessionId: Uint8Array.from(Buffer.from(SID, "hex")),
      lastSeenSeq: 0,
      timestamp: 1_750_000_000_000,
      lastSeenHash: GENESIS,
    });
    const ourSig = await us.sign(ourClaim);

    const db = new DatabaseSync(":memory:") as unknown as ConstructorParameters<typeof SessionSealLeafStore>[0];
    const sealLeafStore = new SessionSealLeafStore(db, noopLogger);
    const client = new AgentRelayClient({
      relayPeerId: "12D3KooWRelay",
      relayAddrs: ["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWRelay"],
      keyProvider: us,
      senderPubkey: usPub,
      logger: noopLogger,
      sealLeafStore,
    });
    const relay = makeFakeRelay();
    const sid = Uint8Array.from(Buffer.from(SID, "hex"));
    client.registerSession(SID, relay.node, undefined, undefined, GENESIS);

    // Get the client connected, then deliver OUR OWN leaf — witnessed by somebody else, so we
    // never saw an ack for it. This is exactly what a counter-submit by the counterparty produces.
    const warm = client.submitMessageHash(relay.node, sid, new Uint8Array(32).fill(0x01), LEAF_KIND_MSG);
    await tick();
    relay.push({ type: "relay_auth_challenge", nonce: new Uint8Array(32).fill(7) });
    await tick();
    relay.push({ type: "relay_auth_ok" });
    await tick();
    relay.push({ type: "hash_submit_ack", sequence_number: 1 });
    await warm;

    relay.push({
      type: "leaf_deliver",
      session_id: sid,
      sequence_number: 2,
      leaf_kind: LEAF_KIND_MSG,
      structure1_cbor: ourClaim,
      structure2_cbor: encodeCbor([2, usPub, ourHash, ourSig]) as Uint8Array,
    });
    await tick();
    client.close();

    const carry = sealLeafStore.getCarry(Buffer.from(usPub).toString("hex"), SID);
    const ours = carry.find((l) => l.sequenceNumber === 2);
    expect(
      ours,
      `our own leaf must not leave a hole just because somebody else witnessed it:\n${JSON.stringify(carry.map((c) => c.sequenceNumber))}`,
    ).toBeDefined();
    expect(ours!.senderPubkeyHex).toBe(Buffer.from(usPub).toString("hex"));
    expect(
      ours!.relaySignatureHex,
      "and with NO receipt — we hold none, and a unilateral seal must still refuse to stand on it",
    ).toBeUndefined();
  });

  it("★ a message with NO ordering record triggers the witness attempt; one WITH a record does not", async () => {
    /**
     * The trigger, at the level that decides it. A sender who witnessed their own leaf needs no
     * help, and submitting it again would spend a position on a duplicate — the replay the relay
     * refuses by name.
     *
     * The fixture has no reachable relay, so the attempt cannot SUCCEED here; what it can do is
     * prove the attempt was made, and that it is made for exactly one of the two shapes. The
     * success path is asserted at the wire above and end to end by the relay's own suite.
     */
    const author = generateKeypair();
    const authorPub = await author.getPublicKey();
    const contentHash = wireContentHash(BODY);
    const s1 = encodeStructure1({
      contentHash, senderPubkey: authorPub,
      sessionId: Uint8Array.from(Buffer.from(SID, "hex")),
      lastSeenSeq: 0, timestamp: 1_750_000_000_000, lastSeenHash: new Uint8Array(32).fill(0x9c),
    });
    const sig = await author.sign(s1);
    const s2 = encodeCbor([1, authorPub, contentHash, sig]) as Uint8Array;

    const attempts = async (withOrderingRecord: boolean, withLeafKind = true): Promise<number> => {
      const f = await startTwoConnectionFixture({ dirPrefix: "cello-carryleaf-trigger-" });
      try {
        await f.createSession(SID, "alice", Buffer.from(authorPub).toString("hex"), PEER);
        await f.snm.handleContentFrameForTest(
          "alice", SID,
          inboundFrame({
            structure1_cbor: s1,
            sender_signature: sig,
            ...(withLeafKind ? { leaf_kind: LEAF_KIND_MSG } : {}),
            ...(withOrderingRecord ? { structure2_cbor: s2 } : {}),
          }),
          PEER,
        );
        await new Promise((r) => setTimeout(r, 250));
        expect(
          f.snm.readTranscript("alice", SID).messages.filter((m) => m.direction === "received"),
          "PRECONDITION: the message must be ingested either way — refusing it would make the relay a precondition for reading mail",
        ).toHaveLength(1);
        // The session has no relay client, so the attempt announces itself by name here.
        return f.eventsNamed("session.content.witness_received.unavailable").length;
      } finally {
        await f.cleanup();
      }
    };

    /** The refusal reason a frame gets, or `undefined` when it was accepted. */
    const refusalFor = async (withLeafKind: boolean): Promise<string | undefined> => {
      const f = await startTwoConnectionFixture({ dirPrefix: "cello-carryleaf-refuse-" });
      try {
        await f.createSession(SID, "alice", Buffer.from(authorPub).toString("hex"), PEER);
        await f.snm.handleContentFrameForTest(
          "alice", SID,
          inboundFrame({ structure1_cbor: s1, sender_signature: sig, ...(withLeafKind ? {} : { leaf_kind: undefined }) }),
          PEER,
        );
        await new Promise((r) => setTimeout(r, 200));
        return f.snm.takeContentRefusals("alice", SID, "op")[0]?.reason;
      } finally {
        await f.cleanup();
      }
    };

    expect(await attempts(false), "a withheld message MUST be witnessed by its receiver").toBe(1);
    expect(await attempts(true), "one its sender already witnessed must NOT be re-submitted").toBe(0);
    /**
     * ⚠️ **A FRAME THAT NAMES NO LEAF DOMAIN IS REFUSED, and the lenient version of this was the
     * exploit path.**
     *
     * It used to deliver the message and merely decline to witness it, "because a peer too old to
     * send the field should be left alone". That sentence was inherited from a compatibility
     * argument that does not apply — CELLO is alpha with no users, and there is no older peer. What
     * the leniency bought was an opt-out: emit the shape an earlier build emitted and your message
     * is delivered AND permanently unwitnessable, which is the withholding this line exists to
     * stop, reachable by anyone willing to modify their client.
     *
     * A leaf kind selects a HASH DOMAIN, so guessing one is not an option either. Refused is the
     * only remaining answer, and it costs nothing real: every current sender names it.
     */
    expect(
      await refusalFor(false),
      "a frame that does not say which domain its leaf belongs to does not get in at all",
    ).toBe("authorship_proof_unusable");
  }, 120_000);
});

describe("034-CARRYLEAF — the MAILBOX route carries what the recipient needs to witness", () => {
  /**
   * ⚠️ **THE SECOND ROUTE, and without it the withholding attack stayed open on it — review F1.**
   *
   * The direct path is closed: a message arriving with no relay ordering record is witnessed by its
   * recipient using the author's signature carried beside the bytes it signs. The relay MAILBOX had
   * no such field — the envelope carried `structure1Cbor` and no signature over it, because
   * `parkSig` signs `(session_id, recipient_pubkey, content_hash)`, a different statement that the
   * relay will not accept for a counter-submit. So a counterparty who parked instead of
   * hand-delivering still truncated the record.
   */
  it("★★ a v4 envelope round-trips the author's ordering claim, its SIGNATURE, and its leaf domain", () => {
    const content = new TextEncoder().encode("the message they would rather you could not witness");
    const claim = new Uint8Array([0xa1, 0xa2, 0xa3]);
    const claimSig = new Uint8Array(64).fill(0x77);
    const parkSig = new Uint8Array(64).fill(0x11);
    const senderPubkey = new Uint8Array(32).fill(0x22);

    const bytes = encodeParkEnvelope({
      content, senderPubkey, parkSig,
      structure1Cbor: claim,
      structure1Signature: claimSig,
      leafKind: 0x04,
    });
    const env = decodeParkEnvelope(bytes);

    expect(env.version, "a signed ordering claim promotes the envelope to v4").toBe(PARK_ENVELOPE_VERSION_S1SIG);
    expect(Buffer.from(env.structure1Cbor!).toString("hex")).toBe(Buffer.from(claim).toString("hex"));
    expect(
      Buffer.from(env.structure1Signature!).toString("hex"),
      "the AUTHOR's signature over their own claim — the only form the relay accepts from a third party",
    ).toBe(Buffer.from(claimSig).toString("hex"));
    expect(env.leafKind, "and the domain, so a recovered leaf is never witnessed under a guess").toBe(0x04);
    /**
     * `parkSig` SURVIVES ALONGSIDE IT AND IS NOT THE SAME THING. It authenticates the DEPOSIT and
     * signs a different statement; conflating them is what would let a recipient hand the relay a
     * proof it refuses, and blame the wrong party for the refusal.
     */
    expect(Buffer.from(env.parkSig!).toString("hex")).toBe(Buffer.from(parkSig).toString("hex"));
  });

  it("★ an envelope with NO signature over the claim stays v2 — older peers keep reading their mail", () => {
    /**
     * The compatibility half, and it is not decoration: `SIGNED_ENVELOPE_VERSIONS` exists because
     * bumping a version constant once turned every envelope sitting in every relay mailbox into
     * `unsigned_envelope` — store-and-forward mail destroyed and reported as an attack.
     *
     * So a sender with nothing to sign emits exactly what it emitted before.
     */
    const env = decodeParkEnvelope(encodeParkEnvelope({
      content: new TextEncoder().encode("ordinary mail"),
      senderPubkey: new Uint8Array(32).fill(0x22),
      parkSig: new Uint8Array(64).fill(0x11),
      structure1Cbor: new Uint8Array([0xa1]),
    }));
    expect(env.version).toBe(2);
    expect(env.structure1Signature, "and it carries no signature to be confused for one").toBeUndefined();
  });
});

describe("033-ACKEMIT — what the operator is told when the RELAY refuses", () => {
  /**
   * ⚠️ **THIS SURFACE HAD NO TEST AT ALL, and the guard's own comment invoked the "a refusal nobody
   * hears" pattern while being itself unreachable from any test.** Deleting the whole
   * `noteContentRefusal` block left the suite green — the exact shape the block was written to
   * prevent, one level up.
   *
   * The fixture cannot produce a relay refusal (it has no relay answering `hash_submit_error`), and
   * a test that can only ever produce one value is the hollow shape this milestone keeps finding.
   * So the SENTENCES moved into a pure function and are held here; that the call site uses them is
   * held by the typechecker, since there is no second copy of the text to drift.
   */
  it("★ the two causes get different sentences, and neither sends the reader to the wrong party", () => {
    const fault = relayAckHashRefusalNotice(true, true);
    const mismatch = relayAckHashRefusalNotice(false, true);

    expect(fault.impact).not.toBe(mismatch.impact);
    expect(fault.guidance).not.toBe(mismatch.guidance);

    // A RELAY fault must not send the operator to their counterparty.
    expect(fault.guidance, "the fault is on the relay — nothing on this machine to change").toMatch(/fault is on the relay/i);
    expect(fault.guidance, "and it must not ask them to go and check with the other person").not.toMatch(/counterparty actually sent|out of band/i);

    // A MISMATCH is the one where confirming with the counterparty is the real move.
    expect(mismatch.guidance).toMatch(/out of band/i);
  });

  it("★★ the relay-fault remedy does NOT promise a retry onto a different relay — there is no such thing", () => {
    /**
     * Review F6. It said "sending again usually picks a healthy one." A session's relay is fixed by
     * the directory-signed assignment; nothing reassigns one, and relay handover is out of scope.
     * A resend goes to the SAME relay and produces the SAME refusal — so that sentence spent the
     * reader's trust as well as their time, which is worse than offering no remedy at all.
     *
     * The assertion names the retired promise rather than the replacement, because the replacement
     * can be reworded and the promise must never come back.
     */
    const { guidance } = relayAckHashRefusalNotice(true, true);
    expect(guidance, "no 'try again and you might get a better relay'").not.toMatch(/picks a healthy|another relay|different relay|try a different/i);
    expect(guidance, "it says the relay is FIXED for this session").toMatch(/keeps the relay its assignment names/i);
    expect(guidance, "and it names a move that actually exists").toMatch(/cello_close_session/);
  });
});

// ─────────────────────────────────────────────────────────────────────────────────────────────────

/** An inbound content frame, built the way a real sender builds one. `fields` is spread LAST. */
function inboundFrame(fields: Record<string, unknown>): Uint8Array {
  return lp.encode.single(encodeCbor({
    type: "content_frame",
    // 034-CARRYLEAF: production names the leaf DOMAIN on every content frame, and a frame without
    // one is refused — witnessing under a guessed domain puts a wrong statement in the record.
    leaf_kind: LEAF_KIND_MSG,
    session_id: SID,
    content_hash: wireContentHash(BODY),
    content_bytes: sealSessionContent(CONTENT_KEY, BODY),
    content_encryption: SESSION_CONTENT_ENCRYPTION_V1,
    ...fields,
  }) as Uint8Array).subarray();
}

describe("033-ACKEMIT — the receiving daemon CHECKS it, with NO RELAY ANYWHERE", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  /**
   * ⚠️ **THERE IS NO RELAY IN ANY OF THESE TESTS, AND THAT IS THE CLAUSE THE DoD LINE EXISTS FOR.**
   *
   * The fixture is two daemons on a direct connection. Nothing witnesses anything, no `hash_submit`
   * is made and no `leaf_deliver` arrives. Everything the check consumes is on the receiving
   * machine: the counterparty's own signed bytes, and our own tree. That is what "the acknowledgement
   * holds with no relay involved at all" means — and it is why withholding a submit no longer
   * dissolves the acknowledgement.
   */
  async function deliverClaim(opts: {
    lastSeenSeq: number;
    lastSeenHash?: Uint8Array;
    /** Mark the session diverged before the claim arrives — the state an unwitnessed append leaves. */
    diverged?: boolean;
    /** Leave our own leaf HELD rather than placed, which is what an ahead-of-tail position produces. */
    holdOwnLeafInsteadOfPlacing?: boolean;
  }): Promise<{
    notice: { reason: string; impact: string; guidance: string } | undefined;
    received: number;
  }> {
    const kp = generateKeypair();
    const senderPubkey = await kp.getPublicKey();
    const structure1 = encodeStructure1({
      contentHash: wireContentHash(BODY),
      senderPubkey,
      sessionId: Uint8Array.from(Buffer.from(SID, "hex")),
      lastSeenSeq: opts.lastSeenSeq,
      timestamp: 1_750_000_000_000,
      ...(opts.lastSeenHash ? { lastSeenHash: opts.lastSeenHash } : {}),
    });
    const signature = await kp.sign(structure1);

    fx = await startTwoConnectionFixture({ dirPrefix: "cello-ackemit-" });
    await fx.createSession(SID, "alice", Buffer.from(senderPubkey).toString("hex"), PEER);
    /**
     * OUR OWN leaf at relay position 1 — the message the counterparty is acknowledging.
     *
     * `holdOwnLeafInsteadOfPlacing` produces the other real state: the relay assigned this leaf a
     * position ahead of our tail, so `placeOwnLeaf` HELD it and it is not in the tree. The
     * counterparty already has it and acknowledges it; this side has it and has not placed it.
     */
    if (opts.holdOwnLeafInsteadOfPlacing) {
      fx.snm.holdOwnLeafForTest("alice", SID, 8, Buffer.from(new Uint8Array(32).fill(0xd1)).toString("hex"));
    } else {
      fx.snm.appendSessionLeaf("alice", SID, "msg", Buffer.from(new Uint8Array(32).fill(0xd1)).toString("hex"), undefined);
      // A SECOND leaf, so a genuine positional MISMATCH is expressible: a hash we really do hold,
      // named at a position where we hold a different one. Without it the only wrong hash available
      // is one we have never held, which is a different refusal entirely.
      fx.snm.appendSessionLeaf("alice", SID, "msg", Buffer.from(new Uint8Array(32).fill(0xd2)).toString("hex"), undefined);
    }
    if (opts.diverged) fx.snm.markSessionDiverged("alice", SID);

    await fx.snm.handleContentFrameForTest("alice", SID, inboundFrame({ structure1_cbor: structure1, sender_signature: signature }), PEER);

    const [notice] = fx.snm.takeContentRefusals("alice", SID, "op");
    return {
      notice,
      received: fx.snm.readTranscript("alice", SID).messages.filter((m) => m.direction === "received").length,
    };
  }

  it("★ a hash that does NOT match what we hold at that position is REFUSED — the message never enters the record", async () => {
    /**
     * The clause the whole unit is for. The signature verifies, the signer IS this session's
     * counterparty, the claim is about this content and this conversation — and it says they
     * received something we never sent.
     *
     * ⚠️ ASSERTS THE OUTCOME, NOT THE MECHANISM'S SHADOW. "A refusal was filed" would stay green if
     * some other check refused it, so the REASON is named — and the transcript is asserted empty,
     * because the fact that matters to the operator is that nothing was recorded.
     */
    const { notice, received } = await deliverClaim({ lastSeenSeq: 1, lastSeenHash: new Uint8Array(32).fill(0xd2) });
    expect(notice, "a refusal nobody hears is indistinguishable from the message never arriving").toBeDefined();
    /**
     * ⚠️ **NAMES THE SPECIFIC CAUSE, NOT THE CLASS** — review F5, and this assertion is what makes
     * the collapse it found visible. Three different causes previously surfaced under ONE reason
     * with ONE sentence, and a test asserting the shared name passed for all three: it proved a
     * refusal was filed, not that the right one was.
     */
    expect(notice!.reason).toBe("ack_hash_mismatch");
    expect(received, "a claim we cannot reconcile must not be recorded as delivered").toBe(0);
    // Names what was OBSERVED — never a conclusion about the counterparty the code did not reach.
    expect(
      notice!.impact,
      "the operator is told WHICH disagreement this is — a different message of theirs in the position they name — not a generic 'records disagree'",
    ).toMatch(/names a DIFFERENT message of yours in the position/);
    expect(notice!.impact).not.toMatch(/malicious|attack|lying/i);
    expect(notice!.guidance.startsWith("STOPPED ON PURPOSE"), `the notice must OPEN with its framing: ${JSON.stringify(notice!.guidance.slice(0, 60))}`).toBe(true);
    expect(notice!.guidance, "and it must name a next step the reader can perform").toMatch(/out of band/i);
  }, 60_000);

  it("★ the MATCHING hash is accepted — the check does not simply refuse everything", async () => {
    /**
     * The half that proves the test above is measuring the comparison and not a blanket refusal.
     * Same frame, same signer, same position — only the hash is the one we actually hold.
     */
    const { notice, received } = await deliverClaim({ lastSeenSeq: 1, lastSeenHash: new Uint8Array(32).fill(0xd1) });
    expect(notice, `an honest acknowledgement must not be refused: ${notice?.reason}`).toBeUndefined();
    expect(received, "and the message is delivered").toBe(1);
  }, 60_000);

  it("★ content this side has NEVER held is refused — however the position is chosen", async () => {
    /**
     * WHO CONTROLS THE ABSENCE. `last_seen_seq` is entirely the sender's to choose, so a check that
     * merely SKIPS a position it cannot find would be a free switch for turning the comparison off:
     * name position 999 and nothing is ever compared. The question asked is therefore about CONTENT
     * rather than about an index — the hash must be something this side actually holds — and a
     * chosen-at-will position cannot make that question go away.
     */
    const { notice, received } = await deliverClaim({ lastSeenSeq: 999, lastSeenHash: new Uint8Array(32).fill(0xee) });
    expect(notice, "content we have never held must REFUSE, never wave through").toBeDefined();
    expect(notice!.reason).toBe("ack_hash_unknown_content");
    expect(received).toBe(0);
  }, 60_000);

  it("★ a v1 claim that NAMES A POSITION is REFUSED — that is the unbacked number", async () => {
    /**
     * The fail-open this unit is closing, tested from the receiving side.
     *
     * An attacker who wants to evade a mismatch check simply never supplies a checkable proof, so
     * treating an absent `last_seen_hash` on a claim about OUR message as "fine, skip the check"
     * would recreate `DOD-M15-AUTHORSHIP-ABSENT-1` one layer down — a bad proof refused and a
     * missing one waved through.
     */
    const { notice, received } = await deliverClaim({ lastSeenSeq: 1 });
    expect(notice, "an absent acknowledgement of a real position is not a lenient case").toBeDefined();
    expect(notice!.reason).toBe("ack_hash_absent");
    expect(received).toBe(0);
    expect(notice!.guidance, "the likely cause IS their build here, and only they can fix it").toMatch(/upgrade/i);
    /**
     * AND THE OTHER TWO MUST NOT SAY THIS. A peer that sends an acknowledgement at all is on a build
     * NEWER than v1 by construction, so "ask them to upgrade" is impossible as a cause there — which
     * is exactly what the shared sentence used to tell them.
     */
  }, 60_000);

  it("★★ a RECEIVED message advances the acknowledgement — not the relay delivering its copy back", async () => {
    /**
     * ⚠️ **REVIEW F1: `#bumpLastSeen` had exactly ONE caller, inside the relay's `leaf_deliver`
     * handler — so the acknowledgement tracked what the RELAY DELIVERED, not what was RECEIVED.**
     *
     * On a direct session those are different events: the content arrives peer-to-peer and the
     * relay's copy of the leaf follows separately, so until it did, this daemon signed an
     * acknowledgement one message behind what it had actually read. The order's own words are "the
     * content hash of the last message this sender ACTUALLY RECEIVED", and the implementation had
     * stopped at "from the same store that already supplies `last_seen_seq`".
     *
     * **THERE IS NO RELAY IN THIS TEST.** A message arrives on the direct path carrying the sender's
     * signed ordering record; we ingest it; and the very next thing we send acknowledges THAT
     * message — by content, at the position the record named.
     */
    let node: CelloNode | null = null;
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-ackemit-received-", node: node = new FakeNode() as unknown as CelloNode });
    const kp = generateKeypair();
    const senderPubkey = await kp.getPublicKey();
    await fx.createSession(SID, "alice", Buffer.from(senderPubkey).toString("hex"), PEER);

    // Their message, at canonical position 1, with the relay's ordering record on the frame.
    const theirHash = wireContentHash(BODY);
    const s1 = encodeStructure1({
      contentHash: theirHash, senderPubkey,
      sessionId: Uint8Array.from(Buffer.from(SID, "hex")),
      lastSeenSeq: 0, timestamp: 1_750_000_000_000,
      lastSeenHash: new Uint8Array(32).fill(0x9c),
    });
    const sig = await kp.sign(s1);
    const s2 = encodeCbor([1, senderPubkey, theirHash, sig]) as Uint8Array;
    await fx.snm.handleContentFrameForTest("alice", SID, inboundFrame({ structure1_cbor: s1, sender_signature: sig, structure2_cbor: s2 }), PEER);

    expect(
      fx.snm.readTranscript("alice", SID).messages.filter((m) => m.direction === "received"),
      "PRECONDITION: their message must have been ingested, or this measures nothing",
    ).toHaveLength(1);
    console.log("DEBUG held=", JSON.stringify(fx.eventsNamed("session.content.held").map(e=>e.ctx)));
    console.log("DEBUG claim.unack=", fx.eventsNamed("session.content.claim.unacknowledged").length);

    // Now WE send. The claim must acknowledge their message — by content, at their position.
    const { hash, alg } = await fx.snm.contentHashForSession("alice", SID, new TextEncoder().encode("our reply"));
    await fx.snm.sendContent("alice", SID, new TextEncoder().encode("our reply"), hash, "corr", LEAF_KIND_MSG, alg);
    await new Promise((r) => setTimeout(r, 200));

    const sent = (await sentFrames(node)).filter((f) => f["type"] === "content_frame");
    const ours = decode(sent[sent.length - 1]!["structure1_cbor"] as Uint8Array) as unknown[];
    expect(ours[4], "position 1 — the message we just read, not 0").toBe(1);
    expect(
      Buffer.from(ackHash(ours)).toString("hex"),
      "and the CONTENT of it — a build that only advanced on leaf_deliver is still emitting the genesis here",
    ).toBe(Buffer.from(theirHash).toString("hex"));
  }, 60_000);

  it("★★ the RECEIVE-side genesis comparison actually compares — clause 3's other half", async () => {
    /**
     * ⚠️ **THIS BRANCH HAD NO TEST, and mutating its comparison to `true` reddened nothing.**
     *
     * The emitter's genesis bytes were pinned; the RECEIVER's comparison of them was not, so the
     * suite proved this daemon sends the right starting point and nothing proved it checks the one
     * it is sent. A peer could have named any 32 bytes as the session's starting point.
     *
     * The fixture agrees `0x9c` repeated as the genesis, so a claim naming anything else at position
     * zero is a claim about a starting point this session does not have.
     */
    const wrong = await deliverClaim({ lastSeenSeq: 0, lastSeenHash: new Uint8Array(32).fill(0x11) });
    expect(wrong.notice, "a wrong starting point at position zero must be refused").toBeDefined();
    expect(wrong.notice!.reason).toBe("ack_hash_mismatch");
    expect(wrong.received).toBe(0);

    if (fx) { await fx.cleanup(); fx = null; }

    const right = await deliverClaim({ lastSeenSeq: 0, lastSeenHash: new Uint8Array(32).fill(0x9c) });
    expect(right.notice, `and the session's real starting point is accepted: ${right.notice?.reason}`).toBeUndefined();
    expect(right.received, "which is what proves the test above measures a comparison").toBe(1);
  }, 120_000);

  it("★★ the three causes do NOT share one sentence — each names its own cause and its own remedy", async () => {
    /**
     * ⚠️ **THE TEST THAT WOULD HAVE CAUGHT THE COLLAPSE, and it is here because it did not exist.**
     *
     * All three causes surfaced under one reason carrying one impact and one guidance — a sentence
     * written for a fourth situation. For an ABSENT acknowledgement the impact was flatly false
     * ("the part that says which of your messages they had received does not match" — there is no
     * such part), and for the other two the guidance told the reader to ask their counterparty to
     * upgrade, which cannot be the cause: a peer who sends an acknowledgement at all is on a NEWER
     * build than one that does not.
     *
     * The previous tests asserted the SHARED name and passed in all three cases, which is what made
     * it invisible. This one asserts they DIFFER.
     */
    const absent = await deliverClaim({ lastSeenSeq: 1 });
    if (fx) { await fx.cleanup(); fx = null; }
    const mismatch = await deliverClaim({ lastSeenSeq: 1, lastSeenHash: new Uint8Array(32).fill(0xee) });

    expect(absent.notice!.reason).not.toBe(mismatch.notice!.reason);
    expect(absent.notice!.impact).not.toBe(mismatch.notice!.impact);
    expect(absent.notice!.guidance).not.toBe(mismatch.notice!.guidance);

    // The version remedy belongs to the ABSENT cause and to nothing else.
    expect(absent.notice!.guidance, "an older build IS the cause here").toMatch(/upgrade/i);
    expect(
      mismatch.notice!.guidance,
      "a peer that sent an acknowledgement is NOT on an older build — sending the operator to ask about a version spends their trust on the wrong question",
    ).not.toMatch(/upgrade/i);
    // And neither one accuses anybody.
    for (const n of [absent.notice!, mismatch.notice!]) {
      expect(n.impact + n.guidance, "name what was observed, never a conclusion about the peer").not.toMatch(/malicious|lying|attack/i);
    }
  }, 120_000);

  it("★★ DIVERGENCE does not switch the check off — the hole the attacker could open themselves", async () => {
    /**
     * ⚠️ **THE MOST SECURITY-RELEVANT TEST IN THIS UNIT, and the branch it covers previously had a
     * WAIVER on it defended by a false sentence.**
     *
     * The waiver read: *"Who controls this absence? Not the peer: divergence is caused by OUR submit
     * failing, and nothing the counterparty sends can produce it."* A counterparty who sends direct
     * and never submits makes us append unwitnessed, which puts our tree ahead of the relay's
     * counter, which makes our very next send land behind our own frontier and mark the session
     * DIVERGED. One withheld message plus one reply from us, and every later acknowledgement was
     * accepted unchecked — using the exact behaviour the check exists to catch.
     *
     * So a diverged session still refuses a hash we have never held. It loses only the POSITIONAL
     * strengthening, which really is meaningless once indices stop meaning relay positions.
     */
    const { notice, received } = await deliverClaim({
      lastSeenSeq: 1,
      lastSeenHash: new Uint8Array(32).fill(0xee),
      diverged: true,
    });
    expect(notice, "a diverged session must still refuse content it never held").toBeDefined();
    expect(notice!.reason).toBe("ack_hash_unknown_content");
    expect(received).toBe(0);
  }, 60_000);

  it("★ a HELD own leaf is acknowledged without being refused — a gap on OUR machine is not their fault", async () => {
    /**
     * The counterparty acknowledges a leaf of ours that the relay has already delivered to them and
     * that WE have not placed yet — `placeOwnLeaf` holds it whenever the assigned position runs
     * ahead of our tail. An index-only check answered "that position does not exist" and refused
     * their reply outright, then told the operator to abandon the conversation over a transient
     * hold on their own machine.
     *
     * The membership test is what makes this right: the content IS ours, held pending the gap, so
     * the claim is true and it is accepted.
     */
    const { notice, received } = await deliverClaim({
      lastSeenSeq: 9,
      lastSeenHash: new Uint8Array(32).fill(0xd1),
      holdOwnLeafInsteadOfPlacing: true,
    });
    expect(notice, `a held leaf is content we hold — refusing it blames the peer for our own gap: ${notice?.reason}`).toBeUndefined();
    expect(received).toBe(1);
  }, 60_000);

  it("★ a v1 claim naming NO position is ACCEPTED — and the difference between the two is the rule", async () => {
    /**
     * ⚠️ **THE COMPANION TO THE TEST ABOVE, AND IT IS THE ONE THAT MAKES THE RULE FALSIFIABLE.**
     *
     * Without it, "refuse every v1 claim" and "refuse a v1 claim that names a position" both pass
     * the test above, and the difference between them is whether every peer on an older build stops
     * being able to talk to this one.
     *
     * `last_seen_seq: 0` with no hash asserts nothing about our messages, so there is no check being
     * skipped. **The bound, stated:** a peer CAN decline to bind by never acknowledging anything —
     * which costs them their own ratification of our history rather than falsifying it, and is the
     * same under-claiming the relay has always allowed, since it refuses a `last_seen_seq` that runs
     * ahead of its counter and never one that lags.
     */
    const { notice, received } = await deliverClaim({ lastSeenSeq: 0 });
    expect(notice, `a claim that acknowledges nothing asserts nothing to refuse: ${notice?.reason}`).toBeUndefined();
    expect(received, "and the message is delivered").toBe(1);
  }, 60_000);
});
