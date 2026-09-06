/**
 * `DOD-M15-SELFCHAIN-1` — WHAT THE RECEIVING DAEMON DOES WITH A BROKEN SELF LINK.
 *
 * ─── The half of the unit that needs no relay ──────────────────────────────────────────────────
 *
 * The acknowledgement check asks whether the sender is right about what WE said. This one asks
 * whether they are right about what THEY said — and it is the check that makes the ORDER of a
 * conversation provable rather than merely its contents.
 *
 * Everything it consumes is on this machine: their own signed bytes, and our own record of what we
 * have accepted from them. A relay that is absent, slow, colluding or lying cannot change either,
 * and cannot wave a broken chain past us.
 *
 * ─── Why this file exists ──────────────────────────────────────────────────────────────────────
 *
 * It did not, and the check could have been deleted with every test in the repo still green. The
 * detection point had no assertion of any kind — not the refusal, not the wording, not the freeze.
 *
 * ─── The three outcomes, which are three different situations ──────────────────────────────────
 *
 *   1. The link names their last message → accepted. The ordinary case.
 *   2. The link names an EARLIER message of theirs that we do hold → accepted, and the gap is
 *      reported as OURS. Our copy can legitimately be behind theirs (a message held out of order,
 *      one the screen refused, one lost), and refusing there would be a fabricated tamper report
 *      against a party that did nothing.
 *   3. The link names something they never sent us → REFUSED, by its own name, with its own
 *      sentence, and the session FREEZES. Continuing writes a disputed order into the receipt.
 */

import { describe, it, expect, afterEach } from "vitest";
import { encodeCbor, encodeStructure1 } from "@cello-protocol/protocol-types";
import { generateKeypair, sealSessionContent } from "@cello-protocol/crypto";
import * as lp from "it-length-prefixed";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import { TEST_SESSION_GENESIS } from "./helpers/session-genesis.js";
import { wireContentHash } from "../wire-content-hash.js";
import { SESSION_CONTENT_ENCRYPTION_V1 } from "../content-encryption-status.js";

const SID = "5e".repeat(32);
const PEER = "12D3KooWQYV9dGMFoRzNStwpXztXaBUjtPqi6aMghfATmPnRAENn";
/** The key `createSession` agrees for content encryption — the fixture's completed key exchange. */
const CONTENT_KEY = new Uint8Array(32).fill(0x7e);
const wait = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

type Kp = ReturnType<typeof generateKeypair>;

/**
 * A content frame from the counterparty, with BOTH chain links stated by the caller.
 *
 * Stated rather than derived on purpose: the subject of every test here is what the receiver does
 * with a particular link, so a builder that computed the honest one would leave nothing to test.
 */
async function frameFrom(
  kp: Kp,
  body: string,
  links: { lastSeenHash: Uint8Array; prevOwnHash: Uint8Array },
): Promise<{ frame: Uint8Array; contentHash: Uint8Array }> {
  const content = new TextEncoder().encode(body);
  const contentHash = wireContentHash(content);
  const structure1 = encodeStructure1({
    contentHash,
    senderPubkey: await kp.getPublicKey(),
    sessionId: Buffer.from(SID, "hex"),
    lastSeenSeq: 0,
    timestamp: 1_750_000_000_000,
    lastSeenHash: links.lastSeenHash,
    prevOwnHash: links.prevOwnHash,
  });
  const frame = lp.encode.single(encodeCbor({
    type: "content_frame",
    session_id: SID,
    content_hash: contentHash,
    content_bytes: sealSessionContent(CONTENT_KEY, content),
    content_encryption: SESSION_CONTENT_ENCRYPTION_V1,
    structure1_cbor: structure1,
    sender_signature: await kp.sign(structure1),
  }) as Uint8Array).subarray();
  return { frame, contentHash };
}

describe("DOD-M15-SELFCHAIN-1: the receiver checks the sender's link to their own previous message", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  /** A live session whose counterparty is `kp`, with the fixture's agreed starting point. */
  async function session(kp: Kp): Promise<TwoConnectionFixture> {
    const f = await startTwoConnectionFixture({ dirPrefix: "cello-selfchain-recv-" });
    await f.createSession(SID, "alice", Buffer.from(await kp.getPublicKey()).toString("hex"), PEER);
    return f;
  }

  it("★ an honest chain of two messages is accepted — the guard is not a wall", async () => {
    /**
     * THE CONTROL, and it has to come first. A guard that refuses everything would satisfy every
     * "this is refused" test below while making the product unusable. This is the shape of an
     * ordinary conversation: their first message links to the session's starting point, their
     * second links to their first.
     */
    const them = generateKeypair();
    fx = await session(them);

    const first = await frameFrom(them, "one", {
      lastSeenHash: TEST_SESSION_GENESIS, prevOwnHash: TEST_SESSION_GENESIS,
    });
    await fx.snm.handleContentFrameForTest("alice", SID, first.frame, PEER);
    await wait(150);

    const second = await frameFrom(them, "two", {
      lastSeenHash: TEST_SESSION_GENESIS, prevOwnHash: first.contentHash,
    });
    await fx.snm.handleContentFrameForTest("alice", SID, second.frame, PEER);
    await wait(150);

    expect(
      fx.snm.takeContentRefusals("alice", SID, "op"),
      `an honest chain must not be refused.\n${JSON.stringify(fx.eventsNamed("session.content.refused"))}`,
    ).toHaveLength(0);
    const delivered = fx.snm.readTranscript("alice", SID).messages.filter((m) => m.direction === "received");
    expect(delivered, "both messages are delivered, in order").toHaveLength(2);
  });

  it("★★★ a link to a message they NEVER SENT is refused BY ITS OWN NAME, and the session freezes", async () => {
    /**
     * THE LOAD-BEARING TEST. Delete the self-link check and this goes red.
     *
     * The frame is otherwise perfect — right session, right content hash, encrypted under the
     * agreed key, correctly signed by this session's real counterparty. The ONLY thing wrong is
     * that it claims a predecessor of its own that this side has never held.
     */
    const them = generateKeypair();
    fx = await session(them);

    const first = await frameFrom(them, "one", {
      lastSeenHash: TEST_SESSION_GENESIS, prevOwnHash: TEST_SESSION_GENESIS,
    });
    await fx.snm.handleContentFrameForTest("alice", SID, first.frame, PEER);
    await wait(150);

    // A predecessor out of thin air.
    const forged = await frameFrom(them, "two", {
      lastSeenHash: TEST_SESSION_GENESIS, prevOwnHash: new Uint8Array(32).fill(0xde),
    });
    await fx.snm.handleContentFrameForTest("alice", SID, forged.frame, PEER);
    await wait(200);

    const [notice] = fx.snm.takeContentRefusals("alice", SID, "op");
    expect(
      notice,
      `a refusal nobody hears is indistinguishable from the message never arriving.\n${JSON.stringify(fx.eventsNamed("session.content.refused"))}`,
    ).toBeDefined();
    /**
     * ⚠️ NAME THE REASON ON THE SURFACE THE OPERATOR READS, not in a log field.
     *
     * It used to surface as `authorship_proof_unusable`, whose sentence says the proof was
     * "unreadable, or signed over different content" — neither is true here, and it sends the
     * reader to audit a decoder when the observation is that the conversation's order is in
     * dispute. `not.toBe` on the old name as well, so a regression to the generic wording cannot
     * pass by accident.
     */
    expect(notice!.reason).toBe("self_chain_mismatch");
    expect(notice!.reason).not.toBe("authorship_proof_unusable");
    /**
     * PIN THE OPENING AND THE SUBSTANCE. A substring match alone cannot see a sentence that lost
     * its head — this file's sibling shipped guidance beginning `NaNcopy in the relay mailbox…`
     * under a passing `/upgrade/i` assertion.
     */
    expect(notice!.guidance.startsWith("STOPPED ON PURPOSE")).toBe(true);
    expect(notice!.guidance, "it must name the ORDER, which is what is actually in dispute").toMatch(/ORDER/);
    expect(notice!.guidance, "and it must name an out-of-band move, the only one that settles it").toMatch(/OUT OF BAND/);
    expect(
      notice!.impact,
      "the impact must say the signature was FINE — sending them to chase a version number is the wrong subsystem",
    ).toMatch(/correctly signed/);

    // Not ingested.
    const delivered = fx.snm.readTranscript("alice", SID).messages.filter((m) => m.direction === "received");
    expect(delivered, "only the honest first message is in the record").toHaveLength(1);

    /**
     * ⚠️ AND IT ESCALATES. The order asks for refuse + tell the operator + name a next step +
     * FREEZE, and the freeze is the part that is visible in the session's own state rather than in
     * a notice somebody has to go and read. Only this one of the `unusable` causes freezes: the
     * acknowledgement causes say the sender is wrong about what WE said, which a drifted record
     * produces honestly.
     */
    expect(
      fx.eventsNamed("session.content.identity.frozen").length,
      "a conversation whose order is in dispute must not keep accepting messages",
    ).toBeGreaterThan(0);
  });

  it("★★ a link to an EARLIER message of theirs that we DO hold is accepted, and the gap is reported as OURS", async () => {
    /**
     * OUR OWN GAP IS NOT THEIR TAMPERING, and this is the test that keeps the guard honest.
     *
     * Our copy of a conversation can legitimately be behind theirs. Refusing here would produce a
     * fabricated tamper report — and a frozen session — every time a message of theirs was held out
     * of order or refused by the inbound screen. That is a worse failure than the one being
     * guarded: it is caused by us and blamed on them.
     */
    const them = generateKeypair();
    fx = await session(them);

    const first = await frameFrom(them, "one", {
      lastSeenHash: TEST_SESSION_GENESIS, prevOwnHash: TEST_SESSION_GENESIS,
    });
    await fx.snm.handleContentFrameForTest("alice", SID, first.frame, PEER);
    await wait(150);
    const second = await frameFrom(them, "two", {
      lastSeenHash: TEST_SESSION_GENESIS, prevOwnHash: first.contentHash,
    });
    await fx.snm.handleContentFrameForTest("alice", SID, second.frame, PEER);
    await wait(150);

    // A third message linking back to their FIRST — as if we had never accepted the second.
    const third = await frameFrom(them, "three", {
      lastSeenHash: TEST_SESSION_GENESIS, prevOwnHash: first.contentHash,
    });
    await fx.snm.handleContentFrameForTest("alice", SID, third.frame, PEER);
    await wait(200);

    expect(
      fx.snm.takeContentRefusals("alice", SID, "op"),
      `a gap in OUR copy must not be reported as THEIR tampering.\n${JSON.stringify(fx.eventsNamed("session.content.refused"))}`,
    ).toHaveLength(0);
    const behind = fx.eventsNamed("session.content.self_chain.behind");
    expect(behind.length, "and it must be reported, not silently waved through").toBeGreaterThan(0);
    expect(
      String(behind[0]!.ctx["impact"]),
      "the notice must say the gap is on THIS side — that is the whole distinction",
    ).toMatch(/gap is on this side/i);
    expect(
      fx.eventsNamed("session.content.identity.frozen").length,
      "and nothing freezes: this is not an accusation",
    ).toBe(0);
  });
});
