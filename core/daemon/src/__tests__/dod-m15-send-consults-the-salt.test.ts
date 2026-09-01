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

  it("★★ TWO CONCURRENT SENDS: a sibling's refusal must not release the in-flight send's claim", async () => {
    /**
     * ⚠️ REVIEW PASS 2's BLOCKING FINDING (HIGH), AND THE TEST THAT WOULD HAVE CAUGHT IT.
     *
     * `#hashedWithoutSalt` was a `Set` — one flag per SESSION for a fact that is per MESSAGE — and
     * `abandonUnsaltedHash` deleted it outright. The `sibling_send_in_flight` path is the one path
     * whose defining precondition is that another send is mid-flight with an unsalted hash of its
     * own:
     *
     *   1. Connection A hashes unsalted and sets the flag.
     *   2. A enters `sendContent`, which awaits a full relay round trip before `#trackAwaitingAck`
     *      records anything — so A is invisible to every frontier count.
     *   3. Connection B hashes, sees A's claim, is refused, and abandons — **deleting A's flag.**
     *   4. The frontier now reads entirely empty. A salt frame arriving in that window is adopted.
     *   5. A's message lands as leaf 0 hashed sha256, in a session that hashes everything after it
     *      under HMAC.
     *
     * The split transcript, through a window a relay round trip wide. The previous test drove
     * `abandonUnsaltedHash` directly and could never see it: with one caller, a delete and a
     * decrement are indistinguishable.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-flip-sibling-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    // TWO messages hashed before either has produced a leaf — A and B, both in flight.
    const a = await fx.snm.contentHashForSession("alice", SID, BODY);
    const b = await fx.snm.contentHashForSession("alice", SID, new TextEncoder().encode("the sibling"));
    expect(a.alg, "precondition: both hashed unsalted").toBe(CONTENT_HASH_ALGS.SHA256);
    expect(b.alg, "precondition: both hashed unsalted").toBe(CONTENT_HASH_ALGS.SHA256);

    // B is refused and gives its claim back. A is STILL in flight.
    fx.snm.abandonUnsaltedHash("alice", SID);

    await fx.snm.handleContentFrameForTest("alice", SID, saltFrame(), PEER);
    await wait(300);

    expect(
      fx.snm.getSessionContentSalt("alice", SID),
      "one send abandoning must not re-open adoption while a sibling's unsalted message is still on its way to the wire — that message becomes the one sha256 leaf in an HMAC transcript",
    ).toBeNull();
    expect(
      fx.eventsNamed("session.salt.adoption.refused").length,
      "and the refusal must still be announced — the surviving claim is what keeps adoption closed",
    ).toBe(1);
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

    /**
     * Review pass 2, F3. `session.content.unsalted` already told this operator, at INFO, that the
     * session was *permanently* unsalted. That statement is now false, and a retraction logged below
     * the level of the claim it retracts is not a retraction — it is off wherever the false claim is
     * on.
     */
    const retracted = fx.eventsNamed("session.content.unsalted.retracted");
    expect(retracted.length, "the earlier 'permanently unsalted' line must be corrected").toBe(1);
    expect(
      retracted[0]!.level,
      "and at the level of the claim it retracts, or the operator keeps the wrong one",
    ).toBe("info");
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

  it("★ OUR OWN write failing does not blame the counterparty — and does not cost five seconds", async () => {
    /**
     * ⚠️ THE BEHAVIOUR CHANGE FROM REVIEW PASS 1, AND IT HAD NO TEST UNTIL THIS ONE.
     *
     * I defended NOT settling the waiter on a failed persist twice. Both defences were wrong. The
     * old code left the send holding for the full five seconds and then routed it through the
     * timeout, whose guidance says to go and check the counterparty's build version — for a fault
     * that is this machine's own disk.
     *
     * Two things must be true now, and the second is the one an operator feels: the reason names
     * OUR write, and the send does not pay the bound for a question already answered.
     *
     * The persist is made to fail the way production fails it — the session row is gone, so the
     * `UPDATE` matches nothing and `changes !== 1`. Not a stub: `#persistSessionSalt`'s real
     * no_session_row branch runs.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-flip-persistfail-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);
    fx.snm.markSaltAgreementPendingForTest("alice", SID);

    const agentId = (fx.snm.getDb().prepare("SELECT agent_id FROM agents WHERE agent_name = ?").get("alice") as { agent_id: string }).agent_id;
    fx.snm.getDb().prepare("DELETE FROM sessions WHERE agent_id = ? AND session_id = ?").run(agentId, SID);

    const started = process.hrtime.bigint();
    const hashing = fx.snm.contentHashForSession("alice", SID, BODY);
    setTimeout(() => { void fx!.snm.handleContentFrameForTest("alice", SID, saltFrame(), PEER); }, 100);
    const { alg } = await hashing;
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;

    expect(alg, "the salt was never stored, so the message must hash unsalted").toBe(CONTENT_HASH_ALGS.SHA256);
    expect(
      elapsedMs,
      "and it must NOT sit out the full bound — the agreement was answered, our own write is what failed, and five seconds of first-message latency is what the operator actually feels",
    ).toBeLessThan(2_000);

    const said = fx.eventsNamed("session.content.unsalted");
    expect(said.length).toBe(1);
    expect(
      said[0]!.ctx!["reason"],
      "the fault is local — reporting this as a timeout sends the operator to ask a counterparty who answered perfectly",
    ).toBe("our_persist_failed");
    expect(
      String(said[0]!.ctx!["guidance"]),
      "and the guidance must say so in words, not just in a code",
    ).toMatch(/THIS side|local, not theirs/i);
    /**
     * ⚠️ FORBIDDING THE WORD "upgrade" WAS WRONG, and the first version of this assertion did it —
     * the same mistake as forbidding "relay" in the park-error test. *"Do not ask them to upgrade"*
     * is the single most useful sentence here, because telling the counterparty to upgrade is
     * precisely the wrong move this reason exists to prevent. What must not appear is the
     * INSTRUCTION; the prohibition of it is the point.
     */
    expect(
      String(said[0]!.ctx!["guidance"]),
      "it must actively steer them AWAY from their counterparty's build, not merely avoid mentioning it",
    ).toMatch(/Do not ask them to upgrade/i);
    expect(
      String(said[0]!.ctx!["guidance"]),
      "and must name the event that identifies the failed write, so the operator has somewhere to go",
    ).toMatch(/session\.salt\.persist\.failed/);
  }, 60_000);

  it("★ an announce that never left releases the send immediately, rather than making it wait out the bound", async () => {
    /**
     * Review Finding 3's other half. Registering the pending BEFORE the dial closes the window where
     * a send finds nothing pending — but it opens a new one: if the dial itself fails, the frame
     * never left and there is nothing coming back, so a send holding on that agreement would wait the
     * full five seconds for an answer that cannot arrive.
     *
     * The catch settles it. This is the offline-mid-connect case, and the cost of getting it wrong is
     * five seconds on every first message to a counterparty whose connection just dropped.
     */
    const node = new FakeNode({ newStreamFails: true });
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-flip-announcefail-", node: node as unknown as CelloNode });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    node.firePeerConnect(PEER);
    await wait(100);

    expect(
      fx.eventsNamed("session.salt.announce.failed").length,
      "precondition: the announce must actually have failed, or this test is measuring the happy path",
    ).toBeGreaterThan(0);

    const started = process.hrtime.bigint();
    const { alg } = await fx.snm.contentHashForSession("alice", SID, BODY);
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;

    expect(alg).toBe(CONTENT_HASH_ALGS.SHA256);
    expect(
      elapsedMs,
      "a frame that never left has no answer coming — holding the send for the bound is five seconds spent on a certainty",
    ).toBeLessThan(2_000);

    /**
     * ⚠️ THE LABEL, AND ITS ABSENCE LET A MUTANT LIVE. This test asserted only the algorithm and the
     * latency, so reverting the reason to `"timeout"` survived the whole pass — predicted by the
     * reviewer and confirmed by re-running it.
     *
     * It matters because the two say opposite things about who is at fault. `agreement_timed_out`
     * means *your counterparty was connected and did not answer* and sends the operator to ask about
     * their build version. Here the frame never left this machine: they were never asked, and their
     * build has nothing to do with it. That is the substitution the closed reason set was built to
     * end, re-entering through the settle site the previous pass asked for.
     */
    const said = fx.eventsNamed("session.content.unsalted");
    expect(said.length).toBe(1);
    expect(
      said[0]!.ctx!["reason"],
      "a frame that never left is not a counterparty who did not answer — reporting it as one blames a peer that was never asked",
    ).toBe("our_announce_failed");
    expect(
      String(said[0]!.ctx!["guidance"]),
      "and the guidance must steer them away from the counterparty's build, not toward it",
    ).toMatch(/Do not ask them to upgrade/i);
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

describe("WHICH reason the peer gave survives to the operator — 006-CRYPTO finding 2", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  /**
   * `adoptionClosed` is a LABEL rather than a boolean, and `session-salt-agreement.ts` says why in
   * as many words: *"Making it a union means a caller cannot say `closed` without saying WHY…
   * Reporting a disk that will not answer as 'you already sent messages' points the operator at a
   * session they cannot fix instead of a database they can, and tells the counterparty something
   * untrue about them."*
   *
   * The label reached the log and was then dropped one call before the person who needed it:
   * `#settleSaltPending(…, "closed")` recorded only that it closed, and `#reasonForOutcome` mapped
   * every closure to `peer_closed_adoption`. All four reasons arrived as "they had already hashed
   * messages" — with a remedy, "start a new session", that is right for one of them and useless for
   * the others.
   */
  async function closedBy(label: string, prefix: string) {
    fx = await startTwoConnectionFixture({ dirPrefix: prefix });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);
    // An agreement must be IN FLIGHT for a terminal answer to be recorded against it — a settle with
    // nothing pending is a no-op, which would silently make every assertion below vacuous.
    fx.snm.markSaltAgreementPendingForTest("alice", SID);
    await fx.snm.handleSaltFrameForTest("alice", SID, { adoptionClosed: label });
    await fx.snm.contentHashForSession("alice", SID, BODY);
    const said = fx.eventsNamed("session.content.unsalted");
    expect(said.length, "PRECONDITION: the fallback was announced exactly once").toBe(1);
    return { reason: String(said[0]!.ctx!["reason"]), guidance: String(said[0]!.ctx!["guidance"]) };
  }

  it("★ a peer whose STORAGE failed is not reported as a peer who already sent messages", async () => {
    const { reason, guidance } = await closedBy("frontier_unreadable", "cello-closed-frontier-");
    expect(reason).toBe("peer_frontier_unreadable");
    expect(
      guidance,
      "the operator must not be told the counterparty's conversation started early — it did not, their disk would not answer",
    ).not.toMatch(/already hashed messages|started before yours/i);
    expect(
      guidance,
      "and the remedy must not be one that cannot work: the next session declines identically until their storage is fixed",
    ).toMatch(/will not help/i);
  }, 60_000);

  it("★ a peer that already hashed still reads exactly as it did — the common case is unchanged", async () => {
    const { reason, guidance } = await closedBy("already_hashing", "cello-closed-hashing-");
    expect(reason).toBe("peer_closed_adoption");
    expect(guidance).toMatch(/already hashed messages/i);
    expect(guidance).toMatch(/new session/i);
  }, 60_000);

  it("★ a stalled exchange names the LOCAL write that caused it, not the counterparty's build", async () => {
    const { reason, guidance } = await closedBy("exchange_stalled", "cello-closed-stalled-");
    expect(reason).toBe("peer_exchange_stalled");
    expect(
      guidance,
      "the cause is a failed write on THIS machine — sending the operator to their counterparty's build is the substitution this closed set exists to end",
    ).not.toMatch(/upgrade/i);
    expect(guidance).toMatch(/session\.salt\.persist\.failed/i);
  }, 60_000);

  it("★ an UNKNOWN label asserts nothing about the counterparty", async () => {
    /**
     * The default must be the non-asserting reason, not the most common one. This string is chosen
     * by the peer, so a build that does not recognise it knows only that they declined — and
     * rendering that as "they had already hashed messages" states something about a counterparty
     * that may simply be false, which is what sends an operator to raise a non-problem with them.
     */
    const { reason, guidance } = await closedBy("some_reason_from_a_newer_build", "cello-closed-unknown-");
    expect(reason).toBe("peer_closed_unspecified");
    expect(guidance).not.toMatch(/already hashed messages|storage|disk/i);
    expect(guidance, "it must point at where the actual label can be read").toMatch(/session\.salt\.adoption\.closed/i);
  }, 60_000);
});
