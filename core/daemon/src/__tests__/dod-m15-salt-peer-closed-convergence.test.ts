/**
 * WHEN THE PEER CLOSES ADOPTION, "NEITHER SIDE WILL USE A SALT" HAS TO BE TRUE —
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
 * Discarding a salt is destructive, and there is exactly one condition under which it is safe: this
 * side has hashed NOTHING under it yet. That is not a guess about timing — it is the same frontier
 * question `#saltAdoptionClosed` already answers, and the branch has already computed it. Where our
 * own adoption is still open, no leaf, no hold and no pending hash used the salt, so dropping it
 * costs a protection we had not yet spent and buys back a conversation.
 *
 * Where we HAVE spent it, the split is real and unrecoverable: those leaves are hashed under a salt
 * the peer will never hold. Nothing may be discarded, nothing may be repaired, and the only correct
 * behaviour is to say so at ERROR. The current WARN tells that operator *"nothing is broken and no
 * message was lost"* — while their counterparty refuses every message they send.
 */

import { describe, it, expect, afterEach } from "vitest";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import { encodeCbor } from "@cello-protocol/protocol-types";
import { SALT_CONTRIBUTION_BYTES } from "@cello-protocol/crypto";
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

  it("★★ THE UNSPENT SALT IS DISCARDED — this is the branch's own claim, made executable", async () => {
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

    expect(
      storedSalt(fx),
      "the peer can never adopt a salt, so holding ours means every message we send is refused by them " +
      "with content_hash_salt_unavailable — the conversation dies while looking merely quiet",
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
