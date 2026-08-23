/**
 * THE SEND PATH ACTUALLY SALTS — `DOD-M15-SEALWIRE-1` bullet 6, part B2b-2, constraints 1, 2 and 5.
 *
 * Everything before this unit built plumbing that carried a value which could not break anything.
 * `contentHashForSession` returned `sha256` unconditionally, the frame carried the name, both park
 * producers and the durable queue carried it, and the receiver verified under it. This is the step
 * where the value changes.
 *
 * ─── Constraint 2 is what makes the feature exist at all, and it is not obvious ─────────────────
 *
 * Decision #8: the salt is agreed **before the first leaf is hashed**, and unit 1 made a late salt a
 * hard refusal. Put those together without a wait and the feature never turns on: the agreement runs
 * on peer connect, the operator's first message is usually already on its way, it hashes unsalted
 * because no salt is stored yet — and that first unsalted hash closes adoption **for the life of the
 * session**. Every session would fall back, permanently, and the logs would say so honestly while
 * the feature did nothing.
 *
 * So the first send waits for the agreement to settle. Bounded, because the alternative is a
 * conversation that hangs on a counterparty who is never going to answer.
 *
 * ─── And the wait must not become a stall (constraint 5) ───────────────────────────────────────
 *
 * A park-only session — the counterparty is offline, the message goes to the relay mailbox — never
 * agrees a salt at all, because the announcement hangs off `onPeerConnect` and there is no connect.
 * Waiting the full bound there would make every message to an offline peer pause for no reason and
 * then fall back anyway. **Nothing is pending, so nothing is waited for.**
 *
 * ─── The window Decision #8 actually names, which is not the one the row can see ───────────────
 *
 * `#saltAdoptionClosed` counts leaves, held content and in-flight sends. For the very FIRST message
 * of a session, none of the three exists at the moment the hash is computed — the leaf lands after
 * the send returns. So hashing itself has to close adoption, at hash time, or the agreement can
 * still complete in that window and produce exactly the split transcript the guard exists to stop.
 */

import { describe, it, expect, afterEach } from "vitest";
import { startTwoConnectionFixture, FakeNode, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import type { CelloNode } from "@cello-protocol/transport";
import { encodeCbor } from "@cello-protocol/protocol-types";
import { SALT_CONTRIBUTION_BYTES } from "@cello-protocol/crypto";
import { CONTENT_HASH_ALGS, contentHashFor } from "../wire-content-hash.js";
import * as lp from "it-length-prefixed";

const SID = "6b".repeat(32);
const PEER = "12D3KooWQYV9dGMFoRzNStwpXztXaBUjtPqi6aMghfATmPnRAENn";
const PEER_HALF = new Uint8Array(SALT_CONTRIBUTION_BYTES).fill(0x5c);
const BODY = new TextEncoder().encode("the message whose hash is the whole question");
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

function saltFrame(): Uint8Array {
  return lp.encode.single(encodeCbor({
    type: "session_salt_agreement", session_id: SID, contribution: PEER_HALF,
  }) as Uint8Array).subarray();
}

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

describe("DOD-M15-SEALWIRE-1 B2b-2: the send path consults the salt", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  it("★ a session WITH an agreed salt hashes salted, and names it", async () => {
    /**
     * The feature. Derived independently here — recomputed from the salt the daemon stored, under
     * the algorithm the daemon named — rather than compared against a value this test handed it,
     * which any consistent pair would satisfy including a wrong one.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-flip-on-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);
    await fx.snm.handleContentFrameForTest("alice", SID, saltFrame(), PEER);
    await wait(200);

    const salt = fx.snm.getSessionContentSalt("alice", SID);
    expect(salt, "precondition: the agreement must have produced a salt").not.toBeNull();

    const { hash, alg } = await fx.snm.contentHashForSession("alice", SID, BODY);
    expect(alg, "a session holding a salt must say it is salted, or the peer verifies under the wrong rule").toBe(CONTENT_HASH_ALGS.HMAC_SALT_V1);
    expect(
      hex(hash),
      "and the hash must actually BE the salted one — naming it without computing it is the mislabel every peer refuses as a tamper",
    ).toBe(hex(contentHashFor(BODY, { alg: CONTENT_HASH_ALGS.HMAC_SALT_V1, salt })));
    expect(
      hex(hash),
      "and it must NOT equal the unsalted hash, or the salt changed nothing and the correlation weakness is still there",
    ).not.toBe(hex(contentHashFor(BODY, { alg: CONTENT_HASH_ALGS.SHA256, salt: null })));
  }, 60_000);

  it("PIN (survives a revert of this unit): a session with NO salt hashes exactly as every shipped build does", async () => {
    /**
     * The fallback has to be byte-identical to the old behaviour, not merely "unsalted". A peer on
     * any published build computes plain sha256 and compares; anything else here is a refusal of
     * every message rather than a weaker hash.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-flip-off-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    const { hash, alg } = await fx.snm.contentHashForSession("alice", SID, BODY);
    expect(alg).toBe(CONTENT_HASH_ALGS.SHA256);
    expect(
      hex(hash),
      "an unsalted session must hash the way every build before this feature hashed — anything else breaks every peer, not just old ones",
    ).toBe(hex(contentHashFor(BODY, { alg: CONTENT_HASH_ALGS.SHA256, salt: null })));
  }, 60_000);

  it("★ the fallback is ANNOUNCED — once per session, not once per message", async () => {
    /**
     * Decision #15's fallback announcement. Both halves matter and the second is the one that gets
     * skipped: a warning that fires on every message of every unsalted session is not a signal, it
     * is a reason to filter the log — and the operator who filters it also filters the one session
     * where it meant something.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-flip-say-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    for (let i = 0; i < 5; i++) {
      await fx.snm.contentHashForSession("alice", SID, new TextEncoder().encode(`message ${i}`));
    }

    const said = fx.eventsNamed("session.content.unsalted");
    expect(said.length, "declining the protection must be stated once — silence is how this milestone's other defects looked").toBe(1);
    expect(
      String(said[0]!.ctx!["impact"]),
      "and it must say what the session loses, not merely that it is unsalted",
    ).toMatch(/relay|correlat|guess/i);
  }, 60_000);

  it("★ the first send WAITS for a pending agreement — without this the feature never turns on", async () => {
    /**
     * ⚠️ THE CONSTRAINT THAT MAKES THE OTHERS MEAN ANYTHING.
     *
     * The agreement is in flight when the operator's first message is composed. Without a wait it
     * hashes unsalted, and that first unsalted hash closes adoption permanently — so every session
     * falls back forever while every log line about it is true.
     *
     * The peer's contribution lands 150ms after the send begins. A send that does not wait resolves
     * `sha256` before it arrives.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-flip-wait-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);
    fx.snm.markSaltAgreementPendingForTest("alice", SID);

    const hashing = fx.snm.contentHashForSession("alice", SID, BODY);
    setTimeout(() => { void fx!.snm.handleContentFrameForTest("alice", SID, saltFrame(), PEER); }, 150);

    const { alg } = await hashing;
    expect(
      alg,
      "a send that races the agreement instead of waiting for it makes the salt unreachable in practice — the first message always wins, and it closes adoption",
    ).toBe(CONTENT_HASH_ALGS.HMAC_SALT_V1);
  }, 60_000);

  it("★ the wait is BOUNDED, and a counterparty that never answers does not hang the conversation", async () => {
    /**
     * The counterbalance, and getting it wrong trades a correlation weakness for a product that
     * stops sending. On timeout the session is unsalted for its life and says so — a decision, not a
     * retry that quietly happens again on the next message.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-flip-bound-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);
    fx.snm.markSaltAgreementPendingForTest("alice", SID, 250);

    const started = process.hrtime.bigint();
    const { alg } = await fx.snm.contentHashForSession("alice", SID, BODY);
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;

    expect(alg, "an unanswered agreement must fall back, not block").toBe(CONTENT_HASH_ALGS.SHA256);
    expect(elapsedMs, "and it must actually have waited — an immediate fallback is constraint 2 not implemented").toBeGreaterThan(150);
    expect(elapsedMs, "but not beyond its own bound").toBeLessThan(3_000);

    const timedOut = fx.eventsNamed("session.salt.agreement.timeout");
    expect(timedOut.length, "the decision must be recorded — this is the moment the session became permanently unsalted").toBe(1);
  }, 60_000);

  it("PIN (survives a revert; guards the park-only-waits mutant): a session with NOTHING pending does not wait", async () => {
    /**
     * Constraint 5. A park-only session never agrees a salt, because the announcement hangs off peer
     * connect and there is no connect. Waiting the bound there would pause every message to an
     * offline peer and then fall back anyway — a stall bought for nothing.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-flip-park-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    const started = process.hrtime.bigint();
    const { alg } = await fx.snm.contentHashForSession("alice", SID, BODY);
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;

    expect(alg).toBe(CONTENT_HASH_ALGS.SHA256);
    expect(
      elapsedMs,
      "with no agreement in flight there is nothing to wait for — pausing here delays every message to an offline counterparty",
    ).toBeLessThan(100);
  }, 60_000);

  it("★★ THE PRODUCTION PATH registers the agreement — peer connect, no test seam anywhere", async () => {
    /**
     * ⚠️ THE REVIEW'S BLOCKING FINDING, AND THE MOST IMPORTANT TEST IN THIS FILE.
     *
     * Every other wait test installs the pending agreement through `markSaltAgreementPendingForTest`.
     * That measures `#saltForHashing`'s waiting correctly — and measures NOTHING about whether a real
     * session ever reaches the state the seam fakes.
     *
     * It did not. `FakeNode.onPeerConnect` discarded its handler, so the daemon's peer-connect path
     * never ran in any daemon test, and `#sendSaltFrame`'s registration line could be **deleted with
     * the whole suite still green**. That line is what decides whether the salt feature can ever turn
     * on in production, so it was the one mutant that mattered and the one nothing could catch.
     *
     * This test uses NO seam. A counterparty connects, the daemon announces, a send begins while the
     * agreement is outstanding, the peer's contribution lands 150ms later, and the message must come
     * out salted.
     *
     * It also covers review Finding 2 by construction: the registration used to happen AFTER
     * `await newStream(...)`, so a send starting immediately after peer-connect found nothing pending
     * and permanently unsalted a session whose counterparty was right there.
     */
    const node = new FakeNode();
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-flip-real-", node: node as unknown as CelloNode });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    // The counterparty comes online. This is the only production trigger for the announcement.
    node.firePeerConnect(PEER);

    const hashing = fx.snm.contentHashForSession("alice", SID, BODY);
    setTimeout(() => { void fx!.snm.handleContentFrameForTest("alice", SID, saltFrame(), PEER); }, 150);
    const { alg } = await hashing;

    expect(
      fx.eventsNamed("session.salt.announced").length,
      "precondition: peer connect must actually have produced an announcement, or the wait below has nothing to wait for and this test proves nothing",
    ).toBeGreaterThan(0);
    expect(
      alg,
      "a send starting right after the counterparty connects must WAIT — registering the agreement after the dial leaves this window open, and a message in it unsalts the session permanently",
    ).toBe(CONTENT_HASH_ALGS.HMAC_SALT_V1);
  }, 60_000);

  it("★ a send that produced NOTHING does not unsalt the session for its life", async () => {
    /**
     * Review Finding 3, and it is the reachable one — the flag was set too eagerly, not too late.
     *
     * `cello_send` has three paths that compute the hash and then send nothing: a sibling send
     * holding the in-flight claim, the frontier moving under the send, and a non-durable failure.
     * In all three the session was permanently unsalted for a message that exists nowhere — no leaf,
     * no wire, no copy at the peer. B2b-2 made two of them MORE likely on a first message, because
     * the five-second wait widens the very interval the frontier re-check is watching.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-flip-abandon-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    const { alg } = await fx.snm.contentHashForSession("alice", SID, BODY);
    expect(alg, "precondition: hashed unsalted, which closes adoption").toBe(CONTENT_HASH_ALGS.SHA256);

    // The send is refused before anything leaves — the caller says so.
    fx.snm.abandonUnsaltedHash("alice", SID);

    await fx.snm.handleContentFrameForTest("alice", SID, saltFrame(), PEER);
    await wait(300);

    expect(
      fx.snm.getSessionContentSalt("alice", SID),
      "nothing was sent, so there is no transcript to split — the session must still be able to adopt a salt",
    ).not.toBeNull();
  }, 60_000);

  it("★ the fallback names WHICH of the six reasons it is — one sentence cannot serve five causes", async () => {
    /**
     * Review Finding 1, blocking. `#saltForHashing` returns null for six distinct conditions and the
     * announcement asserted one of them: *"expected when your counterparty runs a build that predates
     * the salt agreement… start a new session once they upgrade."*
     *
     * An operator whose counterparty was merely OFFLINE — the most common case, since a parked first
     * message unsalts the session by design — read that and went and told a fully up-to-date
     * counterparty to upgrade. The message named the exit point and pointed at the wrong machine.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-flip-reason-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    await fx.snm.contentHashForSession("alice", SID, BODY);

    const said = fx.eventsNamed("session.content.unsalted");
    expect(said.length).toBe(1);
    expect(
      said[0]!.ctx!["reason"],
      "no agreement was ever started here — the counterparty never connected",
    ).toBe("no_agreement_started");
    expect(
      String(said[0]!.ctx!["guidance"]),
      "and the guidance must NOT send this operator to their counterparty's build version, which was never involved",
    ).not.toMatch(/upgrade/i);
    expect(
      String(said[0]!.ctx!["guidance"]),
      "it must say what actually happened: nobody was there to agree with",
    ).toMatch(/not connected|offline/i);
  }, 60_000);

  it("★ HASHING closes adoption — the window the row cannot see", async () => {
    /**
     * ⚠️ Decision #8 says before the first leaf is HASHED. `#saltAdoptionClosed` counts leaves, held
     * content and in-flight sends, and for the very first message NONE of the three exists yet — the
     * leaf lands after the send returns.
     *
     * So a salt arriving between the hash and the leaf would be adopted, and the message already on
     * the wire would be the one unsalted leaf in an otherwise salted transcript. Hashing has to close
     * adoption itself, at the moment it happens.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-flip-window-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    const { alg } = await fx.snm.contentHashForSession("alice", SID, BODY);
    expect(alg, "precondition: this message hashed unsalted").toBe(CONTENT_HASH_ALGS.SHA256);
    expect(fx.snm.getSessionTree("alice", SID).size(), "precondition: and left NO leaf — the window").toBe(0);

    await fx.snm.handleContentFrameForTest("alice", SID, saltFrame(), PEER);
    await wait(300);

    expect(
      fx.snm.getSessionContentSalt("alice", SID),
      "a salt adopted after a message was hashed splits the transcript — and the tree cannot see that message yet",
    ).toBeNull();
    expect(
      fx.eventsNamed("session.salt.adoption.refused").length,
      "and the refusal is announced, exactly as for the leaf route",
    ).toBe(1);
  }, 60_000);
});
