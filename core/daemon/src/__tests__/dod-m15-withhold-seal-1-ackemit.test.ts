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
import { generateKeypair, sealSessionContent } from "@cello-protocol/crypto";
import { AgentRelayClient, LEAF_KIND_MSG } from "../session-relay-client.js";
import { makeFakeRelay, tick, noopLogger } from "./relay-client-fake.js";
import { startTwoConnectionFixture, FakeNode, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import type { CelloNode } from "@cello-protocol/transport";
import { wireContentHash } from "../wire-content-hash.js";
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

// ─────────────────────────────────────────────────────────────────────────────────────────────────

/** An inbound content frame, built the way a real sender builds one. `fields` is spread LAST. */
function inboundFrame(fields: Record<string, unknown>): Uint8Array {
  return lp.encode.single(encodeCbor({
    type: "content_frame",
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
  async function deliverClaim(opts: { lastSeenSeq: number; lastSeenHash?: Uint8Array }): Promise<{
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
    // OUR OWN leaf at relay position 1 — the message the counterparty is acknowledging. Placed
    // through the tree the same way a real send places it, so `hashAt(0)` answers what we sent.
    fx.snm.appendSessionLeaf("alice", SID, "msg", Buffer.from(new Uint8Array(32).fill(0xd1)).toString("hex"), undefined);

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
    const { notice, received } = await deliverClaim({ lastSeenSeq: 1, lastSeenHash: new Uint8Array(32).fill(0xee) });
    expect(notice, "a refusal nobody hears is indistinguishable from the message never arriving").toBeDefined();
    expect(notice!.reason).toBe("authorship_unacknowledged");
    expect(received, "a claim we cannot reconcile must not be recorded as delivered").toBe(0);
    // Names what was OBSERVED — never a conclusion about the counterparty the code did not reach.
    expect(notice!.impact, "the operator is told the two records disagree, not that anyone is lying").toMatch(/does not match your own record/);
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

  it("★ a position BEYOND our record is refused — the branch an attacker reaches for", async () => {
    /**
     * WHO CONTROLS THE ABSENCE. `last_seen_seq` is entirely the sender's to choose, so a check that
     * merely SKIPS a position it cannot find would be a free switch for turning the comparison off:
     * name position 999 and nothing is ever compared.
     *
     * It is also not something an honest peer does — they acknowledge a leaf WE authored, which we
     * placed ourselves, so it is in our tree by the time they can have seen it.
     */
    const { notice, received } = await deliverClaim({ lastSeenSeq: 999, lastSeenHash: new Uint8Array(32).fill(0xd1) });
    expect(notice, "an unfindable position must REFUSE, never wave through").toBeDefined();
    expect(notice!.reason).toBe("authorship_unacknowledged");
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
    expect(notice!.reason).toBe("authorship_unacknowledged");
    expect(received).toBe(0);
    expect(notice!.guidance, "the likely cause is their build, and only they can fix it").toMatch(/upgrade/i);
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
