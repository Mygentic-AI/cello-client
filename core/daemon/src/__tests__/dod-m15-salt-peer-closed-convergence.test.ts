/**
 * WHEN THE PEER CLOSES ADOPTION, "NEITHER SIDE WILL USE A SALT" HAS TO BE TRUE — AND NOTHING
 * IRREVERSIBLE MAY HANG ON THEIR SAY-SO —
 * `DOD-M15-SALTSPLIT-1`, found from a live `CLOSEROOT-1` lead.
 *
 * ─── The user-visible failure, which is the worst kind this milestone has ─────────────────────
 *
 * Two agents are connected. One of them sends a message. The other one silently refuses it, and
 * every message after it, forever. The conversation is not slow and not erroring — from the sending
 * side it looks sent, and from the receiving side it looks quiet. The session can never be sealed,
 * because the two transcripts can no longer agree on a single leaf.
 *
 * ─── What produces it ────────────────────────────────────────────────────────────────────────
 *
 * The salt agreement has a terminal branch: a peer that cannot adopt a salt says so, and
 * `onPeerSaltFrame` returns `adoption_closed`. Both the pure function and the branch that executes
 * it state the outcome in a comment:
 *
 *     "Both sides then hold no salt and both KNOW it."
 *     "neither side will use a content salt for this session, and both now know it."
 *
 * **The code cannot deliver that, and the comment is how it survived review.** `#saltForHashing`
 * returns a held salt at its FIRST line, before it looks at adoption at all; the durable copy in
 * `sessions.content_salt` is written by exactly one method and cleared by none. So a side that has
 * already agreed a salt keeps hashing under it after learning the peer closed — while the peer,
 * holding no salt, refuses every one of those messages with `content_hash_salt_unavailable`.
 *
 * The precedence is what makes it reachable rather than theoretical: `hasClosed` is tested BEFORE
 * `state.ownSalt`, so holding a salt does not even change the verdict.
 *
 * ─── The counterbalance, named before the code ───────────────────────────────────────────────
 *
 * The obvious fix — erase our salt when the peer says it can never hold one — was built first, and
 * it was WRONG in a way worth keeping written down, because it looked defensible.
 *
 * **It is an authorization question, not a compatibility one.** Erasing performs an irreversible
 * destruction of durable key material on a peer's bare assertion, with nothing to check the claim
 * against. And the claim's own trigger is not a hostile or outdated peer: `frontier_unreadable` is a
 * healthy current peer that could not read its own state for one second. That side would have
 * permanently destroyed key material on this one.
 *
 * So the salt is **SUSPENDED, not destroyed**. A salt that is not used is inert; erasing is what
 * converted a transient disagreement into a permanent one. What the peer needs — we stop hashing
 * under it — happens immediately. What cannot be undone waits.
 *
 * **The mark is in memory and the erase is DEFERRED rather than cancelled**, because a durable mark
 * needs a column and this milestone has lost data twice in the rebuild DDL. In-memory alone would
 * split the transcript at the next restart (unsalted now, salted after a reboot), so the bytes are
 * erased at the first unsalted hash — the moment erasing becomes both harmless (nothing was hashed
 * under it) and required (keeping it would re-salt the session). Before that moment a corrected
 * announcement restores the session fully salted, which erasure makes impossible even in principle:
 * a salt is a one-way function of two halves and neither side can re-derive it alone.
 *
 * Where the salt is already SPENT, none of this applies: those leaves are hashed under a salt the
 * peer will never hold. Nothing may be suspended, nothing may be erased, nothing may be repaired,
 * and the only correct behaviour is to say so at ERROR — because switching to unsalted mid-session
 * would leave a transcript verifiable by no single rule, which is worse than an honestly dead one.
 */

import { describe, it, expect, afterEach } from "vitest";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import { encodeCbor } from "@cello-protocol/protocol-types";
import { SALT_CONTRIBUTION_BYTES, saltFingerprint } from "@cello-protocol/crypto";
import * as lp from "it-length-prefixed";

const SID = "7e".repeat(32);
const PEER = "12D3KooWQYV9dGMFoRzNStwpXztXaBUjtPqi6aMghfATmPnRAENn";
const PEER_HALF = new Uint8Array(SALT_CONTRIBUTION_BYTES).fill(0x3c);
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** The peer offers its half — this side derives and persists a salt. */
function contributionFrame(): Uint8Array {
  return lp.encode.single(encodeCbor({
    type: "session_salt_agreement", session_id: SID, contribution: PEER_HALF,
  }) as Uint8Array).subarray();
}

/** The peer says it can never adopt a salt for this session. Terminal. */
function closedFrame(): Uint8Array {
  return lp.encode.single(encodeCbor({
    type: "session_salt_agreement", session_id: SID, adoption_closed: "already_hashing",
  }) as Uint8Array).subarray();
}

function storedSalt(fx: TwoConnectionFixture): Uint8Array | null {
  const agentId = (fx.snm.getDb().prepare("SELECT agent_id FROM agents WHERE agent_name = ?").get("alice") as { agent_id: string }).agent_id;
  const row = fx.snm.getDb()
    .prepare("SELECT content_salt FROM sessions WHERE agent_id = ? AND session_id = ?")
    .get(agentId, SID) as { content_salt: Uint8Array | null } | undefined;
  return row?.content_salt ? new Uint8Array(row.content_salt) : null;
}

describe("DOD-M15-SALTSPLIT-1: a peer that closes adoption must leave both sides unsalted", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  it("★ PRECONDITION — a contribution before any leaf really does adopt a salt", async () => {
    // The anchor. Every assertion below is about losing this salt, so a run where it was never
    // adopted would pass them for the wrong reason.
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-saltsplit-pre-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    await fx.snm.handleContentFrameForTest("alice", SID, contributionFrame(), PEER);
    await wait(200);

    expect(storedSalt(fx), "a salt agreed at session open must be adopted").not.toBeNull();
  }, 60_000);

  it("★★ THE UNSPENT SALT IS SUSPENDED, THEN ERASED AT THE FIRST UNSALTED HASH", async () => {
    /**
     * We agreed a salt and have hashed nothing under it. The peer then tells us it can never adopt
     * one. Keeping ours means every message we send from here is refused by them.
     *
     * Nothing is lost by dropping it: an unsalted session is exactly as verifiable as every session
     * shipped before this feature existed, which is the trade the terminal branch already argues
     * for — it just never carried it out.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-saltsplit-unspent-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    await fx.snm.handleContentFrameForTest("alice", SID, contributionFrame(), PEER);
    await wait(200);
    expect(storedSalt(fx), "precondition: this side holds a salt").not.toBeNull();
    expect(fx.snm.getSessionTree("alice", SID).size(), "precondition: nothing hashed under it").toBe(0);

    await fx.snm.handleContentFrameForTest("alice", SID, closedFrame(), PEER);
    await wait(300);

    /**
     * ⚠️ THIS TEST USED TO ASSERT THE SALT WAS GONE HERE, AND THAT WAS THE WRONG CONTRACT.
     *
     * Erasing on a peer's bare assertion is an irreversible destruction of durable key material with
     * nothing to check the claim against — and the claim's own trigger includes a healthy peer that
     * could not read its own frontier for one second. The salt is SUSPENDED instead: not used, not
     * destroyed. What the peer needs (we stop hashing under it) is delivered; what cannot be undone
     * is not done yet.
     */
    expect(
      storedSalt(fx),
      "the bytes are KEPT — a peer that merely could not read its own state for a moment can restore " +
      "this session with its next announcement, and an erased salt cannot be re-derived from one side",
    ).not.toBeNull();

    const suspended = await fx.snm.contentHashForSession("alice", SID, new TextEncoder().encode("after the refusal"));
    expect(
      suspended.alg,
      "suspension must actually STOP the salt being used — otherwise every message we send is refused " +
      "by a counterparty that can never hold it, and the conversation dies while looking merely quiet",
    ).toBe("sha256");

    /**
     * And NOW it is erased, because this is the moment keeping it would do harm: the session has
     * hashed unsalted, so a salt surviving on disk would re-salt it at the next restart and split the
     * transcript down the middle by a reboot.
     */
    expect(
      storedSalt(fx),
      "once this session has actually hashed unsalted, keeping the salt would split the transcript at the next restart",
    ).toBeNull();

    /**
     * ⚠️ THE ROW IS NOT THE WHOLE STATE — the same mutant that survived in the adoption-rule file.
     * `#saltForHashing` reads the MEMORY CACHE first and never consults the row, so clearing only
     * the durable copy leaves this process salted for its whole life and unsalted after a restart:
     * a transcript split down the middle by a daemon restart instead of by a frame.
     */
    expect(
      fx.snm.getSessionContentSalt("alice", SID),
      "the cache must be cleared too — a row-only clear splits the transcript at the next restart",
    ).toBeNull();
  }, 60_000);

  it("★★ A LEAF AFTER SUSPENSION MUST NOT LET US HASH UNSALTED WHILE THE SALT SURVIVES — pass 2, F2", async () => {
    /**
     * ⚠️ THE REGRESSION MY OWN REDESIGN INTRODUCED, and the reviewer reproduced it through the real
     * inbound path rather than arguing it.
     *
     * The deferred erase was ordered before the `#hashedWithoutSalt` increment because that counter
     * closes adoption. **It is one of FOUR contributors.** Leaves, held rows and awaiting-ack close
     * adoption too — and the most ordinary event in the protocol closes it: *the peer sends its next
     * message.* So: suspend, the peer's message lands as a leaf, we send, the erase is REFUSED with
     * `already_hashing`, and we hashed `sha256` anyway with the salt still on disk. One
     * teardown-and-revive later — **no process restart needed** — the next hash is `hmac` again.
     * That is the split transcript, produced by the fix for the split transcript.
     *
     * The immediate-erase design this replaced could not produce it: a refused discard there simply
     * kept the session salted. **Suspension is what made "unsalted now, salted later" reachable.**
     *
     * So going unsalted and erasing the salt are ONE decision. If the salt cannot be erased, we keep
     * hashing under it — one rule for the whole session — and say so at ERROR. The counterparty may
     * refuse those messages; a dead session beats a transcript no single rule can verify.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-saltsplit-leafafter-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    await fx.snm.handleContentFrameForTest("alice", SID, contributionFrame(), PEER);
    await wait(200);
    const agreed = storedSalt(fx);
    expect(agreed, "precondition: a salt was agreed").not.toBeNull();

    await fx.snm.handleContentFrameForTest("alice", SID, closedFrame(), PEER);
    await wait(200);
    expect(fx.eventsNamed("session.salt.suspended").length, "precondition: suspended, bytes kept").toBe(1);

    // The peer keeps talking. This closes adoption — and nothing was hashed under OUR salt.
    fx.seedReceived("alice", SID, "the peer's next message");
    expect(fx.snm.getSessionTree("alice", SID).size(), "precondition: the frontier moved").toBeGreaterThan(0);

    const out = await fx.snm.contentHashForSession("alice", SID, new TextEncoder().encode("our reply"));

    expect(
      out.alg,
      "the salt could not be erased, so we must NOT go unsalted — one rule for the whole session. " +
      "Hashing sha256 here leaves the bytes on disk and the very next revival hashes hmac again.",
    ).toBe("hmac-sha256-salt-v1");
    expect(
      storedSalt(fx),
      "and the salt is still held, which is exactly why we may not hash unsalted",
    ).toEqual(agreed);
    expect(
      fx.eventsNamed("session.salt.split").length,
      "a session that will now have every message refused must say so at ERROR, not sit at INFO",
    ).toBeGreaterThan(0);
  }, 60_000);

  it("★★ A SUSPENDED SALT RESUMES when the peer turns out to hold the same one", async () => {
    /**
     * THE RECOVERY THE ERASE MADE IMPOSSIBLE, and the reason keeping the bytes is worth the extra
     * state. The peer's terminal frame can be wrong about itself — `frontier_unreadable` is a healthy
     * peer that could not read its own state for one second, not an old build. When it can read
     * again it announces a fingerprint, and if it matches the salt we kept, the session is simply
     * salted again with nothing lost.
     *
     * Erasure cannot reach this outcome even in principle: a salt is a one-way function of two
     * halves and neither side can re-derive it alone.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-saltsplit-resume-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    await fx.snm.handleContentFrameForTest("alice", SID, contributionFrame(), PEER);
    await wait(200);
    const agreed = storedSalt(fx);
    expect(agreed, "precondition: a salt was agreed").not.toBeNull();

    await fx.snm.handleContentFrameForTest("alice", SID, closedFrame(), PEER);
    await wait(200);
    expect(fx.eventsNamed("session.salt.suspended").length, "precondition: it is suspended, not erased").toBe(1);

    // The peer can read its own state again and announces the salt it holds — the same one.
    await fx.snm.handleContentFrameForTest(
      "alice", SID,
      lp.encode.single(encodeCbor({
        type: "session_salt_agreement", session_id: SID, fingerprint: saltFingerprint(agreed!),
      }) as Uint8Array).subarray(),
      PEER,
    );
    await wait(300);

    expect(fx.eventsNamed("session.salt.resumed").length, "the session must come back salted").toBe(1);
    const resumed = await fx.snm.contentHashForSession("alice", SID, new TextEncoder().encode("after recovery"));
    expect(
      resumed.alg,
      "resumed means USING it again — a log line saying 'resumed' over a session still hashing sha256 is the comment-asserts-a-property defect",
    ).toBe("hmac-sha256-salt-v1");
    expect(storedSalt(fx), "and the bytes are the ones we kept").toEqual(agreed);
  }, 60_000);

  it("★★ A SALTED HASH MID-FLIGHT COUNTS AS SPENT — review HIGH-2", async () => {
    /**
     * The window no count could see. `#saltAdoptionClosed` sums leaves, held content and
     * awaiting-ack entries; a hash that has been COMPUTED under the salt appears in none of them
     * until a relay round trip later. So a closed frame landing in that window found adoption "open"
     * and discarded the salt — while the message already on its way carried
     * `content_hash_alg: hmac-salt-v1` and a hash **nobody could ever recompute**, this daemon
     * included. The alg is copied verbatim into the parked envelope on expiry, so the round trip
     * does not hide it either.
     *
     * Driven the way the reviewer specified: start the hash, do NOT await it, deliver the frame.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-saltsplit-inflight-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    await fx.snm.handleContentFrameForTest("alice", SID, contributionFrame(), PEER);
    await wait(200);
    const held = storedSalt(fx);
    expect(held, "precondition: this side holds a salt").not.toBeNull();
    expect(fx.snm.getSessionTree("alice", SID).size(), "precondition: no leaf yet, so every count reads zero").toBe(0);

    // In flight: computed under the salt, nowhere a count can see it.
    const hashing = fx.snm.contentHashForSession("alice", SID, new TextEncoder().encode("mid-flight"));
    await fx.snm.handleContentFrameForTest("alice", SID, closedFrame(), PEER);
    await wait(300);

    expect(
      storedSalt(fx),
      "a message is already hashed under this salt and is mid-send — erasing it now puts a hash on " +
      "the wire that nothing, including this daemon, could ever recompute",
    ).toEqual(held);
    expect(
      fx.snm.getSessionContentSalt("alice", SID),
      "and the cache must hold it too, or the in-flight send finishes against a salt this process has forgotten",
    ).not.toBeNull();

    const out = await hashing;
    expect(out.alg, "the hash really was computed under the salt — otherwise this test proves nothing")
      .toBe("hmac-sha256-salt-v1");

    /**
     * ⚠️ THIS TEST SURVIVED ITS OWN MUTANT UNTIL PASS 2 — deleting `inFlight > 0 ||` from
     * `#suspendSalt` left all five tests GREEN.
     *
     * The three assertions above (row present, cache present, `alg === hmac`) all hold whether or not
     * the suspension was refused, because the erase is deferred: nothing about them distinguishes
     * "the guard refused" from "the guard never ran and the erase simply had not happened yet". The
     * test named the in-flight guard and measured the deferral.
     *
     * So: name the refusal itself, and prove the salt is still being USED afterwards.
     */
    expect(
      fx.eventsNamed("session.salt.suspend.refused").filter(
        (e) => e.ctx.reason === "salted_hash_in_flight",
      ).length,
      "the in-flight case must be REFUSED by name — without this the test passes with the guard deleted",
    ).toBe(1);
    const next = await fx.snm.contentHashForSession("alice", SID, new TextEncoder().encode("the one after"));
    expect(
      next.alg,
      "and the session must still be hashing under the salt — a refusal that leaves us unsalted anyway is the refusal not working",
    ).toBe("hmac-sha256-salt-v1");
  }, 60_000);

  it("★★ A SPENT SALT IS NEVER DISCARDED, AND THE SPLIT IS LOUD", async () => {
    /**
     * The unrecoverable half, and the reason the fix above is guarded rather than unconditional.
     *
     * Here the salt is already spent: a leaf is hashed under it. Discarding it now would leave this
     * session verifiable by no single rule — the split transcript Decision #8 forbids, arriving by
     * the repair rather than by the defect. So the salt stays, the two sides are permanently
     * incompatible, and the ONLY correct behaviour is to say so.
     *
     * Today this path logs `session.salt.adoption.refused` at WARN, whose impact reads *"nothing is
     * degraded relative to any shipped release, and no message is affected."* Every message this
     * operator sends is about to be refused by their counterparty. That sentence is the defect.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-saltsplit-spent-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    await fx.snm.handleContentFrameForTest("alice", SID, contributionFrame(), PEER);
    await wait(200);
    const spent = storedSalt(fx);
    expect(spent, "precondition: this side holds a salt").not.toBeNull();

    // Spend it: a leaf now exists that was hashed under this salt.
    fx.seedReceived("alice", SID, "a message hashed under the agreed salt");
    expect(fx.snm.getSessionTree("alice", SID).size(), "precondition: the salt is spent").toBeGreaterThan(0);

    await fx.snm.handleContentFrameForTest("alice", SID, closedFrame(), PEER);
    await wait(300);

    expect(
      storedSalt(fx),
      "a spent salt must NEVER be discarded — those leaves are hashed under it and dropping it splits the transcript",
    ).toEqual(spent);

    /**
     * ⚠️ ADDED BY REVIEW — THIS TEST HAD A SURVIVING MUTANT AND THE OTHER ONE DID NOT.
     *
     * Move `#sessionSalts.delete(...)` to the top of `#discardUnspentSalt`, before the guards, and
     * both tests stayed green: the spent case never reaches the `UPDATE`, so the ROW still matched,
     * and the `session.salt.split` check re-read through `#getSessionSalt`, which missed the cache,
     * re-read the row, and quietly repopulated it. Meanwhile the product was split exactly the way
     * this file's own comments warn about — unsalted in this process, salted after a restart.
     *
     * The unspent test asserted the cache; this one asserted only the row. Same method, two
     * assertions, one blind spot.
     */
    expect(
      fx.snm.getSessionContentSalt("alice", SID),
      "the cache must survive too — clearing it while the row keeps the salt splits the transcript at the next restart",
    ).toEqual(spent);

    const split = fx.eventsNamed("session.salt.split");
    expect(
      split.length,
      "the two sides are now permanently incompatible and the operator must be told — a WARN saying " +
      "'no message is affected' is false at the exact moment every message stops being accepted",
    ).toBeGreaterThan(0);
    /**
     * ⚠️ MY FIRST VERSION READ `split[0].impact` THROUGH A CAST AND GOT `''`.
     *
     * The fields live under `ctx`; `as { impact?: string }` asserted a shape the object never had,
     * and `?? ""` then turned the miss into an empty string that failed on the PATTERN — sending the
     * reader to look at the log line's wording for a defect that was in the test's own accessor.
     * That is precisely the laundering the `.toMatch` enforcer in the spine lane exists to catch,
     * committed here by the person who wrote it. Read through the typed `CapturedEvent` instead, so
     * a wrong field name is a compile error rather than an empty string.
     */
    expect(
      String(split[0].ctx.impact ?? ""),
      "the impact must say what the operator will SEE: their counterparty refuses everything they send",
    ).toMatch(/refus/i);
    expect(
      split[0].level,
      "ERROR, not WARN — the neighbouring `session.salt.adoption.refused` is a benign condition and " +
      "an operator who has learned to skim it must not skim this",
    ).toBe("error");
  }, 60_000);
});
