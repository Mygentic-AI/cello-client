/**
 * A SALT IS ADOPTED ONLY BEFORE THE FIRST LEAF — `DOD-M15-SEALWIRE-1` bullet 6, part B2b-2.
 * Decisions Carried #8: *"Agreed at session open, BEFORE the first leaf is hashed. Every leaf uses
 * the same salt."*
 *
 * ─── Why this guard has to exist BEFORE salting turns on, not alongside it ─────────────────────
 *
 * Once `contentHashForSession` consults the salt, "is this session salted?" is answered fresh on
 * every send. A salt that arrives *after* messages have already been hashed therefore splits the
 * transcript down the middle: leaves 1–3 unsalted, leaves 4+ salted, one session, no marker saying
 * where the change happened.
 *
 * That is exactly the failure Decision #8 forbids, and it is worse than the correlation weakness the
 * salt exists to fix — a half-salted transcript cannot be verified by either rule.
 *
 * **The rule is what removes the need for a schema change.** Without it, "salted or not" would have
 * to be a durable per-session flag with its own column, its own migration, and its own entry in the
 * rebuild DDL (which is where this milestone has now lost data twice). With it, the question is
 * decided once and answered by `content_salt IS NULL` forever after.
 *
 * ─── The counterbalance, named before the code ────────────────────────────────────────────────
 *
 * Refusing a salt is not free: a session that fails to adopt one is a session with a weaker content
 * hash for its whole life. That is the RIGHT trade — an unsalted transcript is exactly as verifiable
 * as every transcript in existence today, whereas a split one is verifiable by nobody — but it must
 * be LOUD, because silently declining a protection is how this milestone's other defects looked.
 */

import { describe, it, expect, afterEach } from "vitest";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import { encodeCbor } from "@cello-protocol/protocol-types";
import { SALT_CONTRIBUTION_BYTES } from "@cello-protocol/crypto";
import * as lp from "it-length-prefixed";
import { LEAF_KIND_MSG } from "../session-relay-client.js";

const SID = "9c".repeat(32);
const PEER = "12D3KooWQYV9dGMFoRzNStwpXztXaBUjtPqi6aMghfATmPnRAENn";
const PEER_HALF = new Uint8Array(SALT_CONTRIBUTION_BYTES).fill(0x6a);
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

function saltFrame(): Uint8Array {
  return lp.encode.single(encodeCbor({
    type: "session_salt_agreement", session_id: SID, contribution: PEER_HALF,
  }) as Uint8Array).subarray();
}

function storedSalt(fx: TwoConnectionFixture): Uint8Array | null {
  const agentId = (fx.snm.getDb().prepare("SELECT agent_id FROM agents WHERE agent_name = ?").get("alice") as { agent_id: string }).agent_id;
  const row = fx.snm.getDb()
    .prepare("SELECT content_salt FROM sessions WHERE agent_id = ? AND session_id = ?")
    .get(agentId, SID) as { content_salt: Uint8Array | null } | undefined;
  return row?.content_salt ? new Uint8Array(row.content_salt) : null;
}

describe("Decision #8: the salt is adopted before the first leaf, or not at all", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  it("★ a salt agreed BEFORE any leaf is adopted — the normal case must keep working", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-adopt-a-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);
    expect(fx.snm.getSessionTree("alice", SID).size(), "precondition: no leaves yet").toBe(0);

    await fx.snm.handleContentFrameForTest("alice", SID, saltFrame(), PEER);
    await wait(200);

    expect(storedSalt(fx), "a salt agreed at session open must be adopted").not.toBeNull();
  }, 60_000);

  it("★ a salt arriving AFTER a leaf is REFUSED — it would split the transcript", async () => {
    /**
     * The whole point. Leaves 1..n are already hashed under the unsalted rule; adopting now would
     * hash n+1.. under a different one, in one session, with nothing recording where the change
     * happened. Neither half can then be verified by a single rule.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-adopt-b-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);
    fx.seedReceived("alice", SID, "a message that is already hashed");
    expect(fx.snm.getSessionTree("alice", SID).size(), "precondition: the session has a leaf").toBeGreaterThan(0);

    await fx.snm.handleContentFrameForTest("alice", SID, saltFrame(), PEER);
    await wait(300);

    expect(
      storedSalt(fx),
      "adopting a salt after the first leaf splits the transcript — half verifiable by one rule, half by another",
    ).toBeNull();

    /**
     * ⚠️ THE ROW IS NOT THE WHOLE STATE — a mutant made `#saltAdoptionClosed` return `{closed:true}`
     * unconditionally and this file stayed green on this test, because "no salt on disk" is exactly
     * what an unconditional refusal produces too.
     *
     * `session.salt.agreed` is the event that says this side considers itself salted, and it fires
     * from the memory cache, not from the row. Pinning it to zero is what separates *"the guard
     * refused"* from *"the write happened to fail"*: the first is the behaviour Decision #8 asks
     * for, the second is a bug wearing its result.
     */
    expect(
      fx.eventsNamed("session.salt.agreed").length,
      "the session must not BELIEVE it is salted either — an empty column with an agreed salt in memory is the split transcript, one restart later",
    ).toBe(0);
  }, 60_000);

  it("★ HELD content closes adoption too — a hold is content already hashed, it is just not in the tree yet", async () => {
    /**
     * ⚠️ WRITTEN BECAUSE A MUTANT SURVIVED. Dropping `held` from the frontier sum — counting only
     * `leaves + awaiting_ack` — left every test in this file green.
     *
     * A hold is a message whose content hash is ALREADY COMPUTED, sitting at a slot ahead of the
     * tail waiting for the gap to fill. Counting only what has landed in the tree therefore reads
     * "nothing hashed yet" for a session that has hashed several messages, adopts a salt, and then
     * releases those holds into a tree where the leaves around them were hashed the other way. That
     * is precisely the split transcript Decision #8 exists to prevent, arriving by the one route
     * that looks empty from the tree.
     *
     * It is also the review-F6 case in a different disguise: the frontier is not `tree.size()`.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-adopt-held-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    // A send assigned slot 3 with an empty tail: ahead of the frontier, so it is HELD, not appended.
    // `"msg", undefined` matches the three production call sites in `session-content-handlers.ts`
    // (`…, randomUUID(), "msg", sentAuthorship(sendResult)`). Both arguments are REQUIRED by
    // design — `DOD-M15-SEALWIRE-1` removed their defaults so a caller must state the leaf kind and
    // the authorship rather than inherit them silently. Nothing is witnessed here, so there is no
    // authorship to carry: this send is HELD, never submitted, which is the point of the case.
    const placed = fx.snm.placeOwnLeaf("alice", SID, "ab".repeat(32), new TextEncoder().encode("held, and already hashed"), 3, "corr-held", "msg", undefined);
    expect(placed, "precondition: the send must actually be HELD, not appended").toMatchObject({ placed: false });
    expect(fx.snm.getSessionTree("alice", SID).size(), "precondition: and the TREE must still look empty — that is the trap").toBe(0);

    await fx.snm.handleContentFrameForTest("alice", SID, saltFrame(), PEER);
    await wait(300);

    expect(
      storedSalt(fx),
      "a session with held content has already hashed messages — adopting now splits the transcript when those holds release",
    ).toBeNull();
    expect(
      fx.eventsNamed("session.salt.adoption.refused").length,
      "and the refusal must be announced for this route exactly as for the tree route",
    ).toBe(1);
  }, 60_000);

  it("★ a frontier that cannot be READ refuses — 'cannot tell' must never mean 'nothing hashed yet'", async () => {
    /**
     * ⚠️ ALSO WRITTEN BECAUSE A MUTANT SURVIVED. Flipping the catch to `closed: false` — treating an
     * unreadable frontier as an empty one — left this file green.
     *
     * This is the shape of guard failure that is hardest to see in review, because the code still
     * reads like a guard. A failed count is not zero. Inferring "no leaves" from "I could not count
     * the leaves" turns the one check standing between a session and a split transcript into a
     * formality that opens itself on exactly the disk trouble that should make it most careful.
     *
     * The corruption modelled here is narrow on purpose: the leaf table is gone, the `sessions` row
     * is not. So the salt path gets all the way past its own reads and fails only at the frontier —
     * which is the case the catch was written for, rather than a database that is broken everywhere.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-adopt-unreadable-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);
    fx.snm.getDb().exec("DROP TABLE session_tree_leaves");

    await fx.snm.handleContentFrameForTest("alice", SID, saltFrame(), PEER);
    await wait(300);

    expect(
      storedSalt(fx),
      "an unreadable frontier cannot rule out already-hashed content, so the salt must NOT be adopted",
    ).toBeNull();
    const refused = fx.eventsNamed("session.salt.adoption.refused");
    expect(refused.length, "and it must say so rather than declining in silence").toBe(1);
    expect(
      String(refused[0]!.ctx!["frontier"]),
      "the operator has to be able to tell 'I refused because you had messages' from 'I refused because I could not look' — they are different problems with different fixes",
    ).toMatch(/frontier_unreadable/);
  }, 60_000);

  it("★ the refusal is LOUD and says what the session loses, not just that it declined", async () => {
    /**
     * Silently declining a protection is how this milestone's other defects looked. The operator has
     * to be able to tell "this session is unsalted" from "this session failed to become salted", and
     * the second is the one that says something about their build or their counterparty.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-adopt-c-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);
    fx.seedReceived("alice", SID, "already hashed");

    await fx.snm.handleContentFrameForTest("alice", SID, saltFrame(), PEER);
    await wait(300);

    const refused = fx.eventsNamed("session.salt.adoption.refused");
    expect(refused.length, "declining a protection must be announced").toBe(1);
    expect(
      refused[0]!.level,
      "the side that DECLINED a protection warns; the side merely learning of it must not",
    ).toBe("warn");
    expect(
      String(refused[0]!.ctx!.detail),
      "it must name WHICH refusal this is — already_hashing and frontier_unreadable want opposite responses from the operator",
    ).toMatch(/already_hashing/);
    expect(
      String(refused[0]!.ctx!.detail),
      "and carry the counts behind it, so the claim can be checked against the session rather than taken on trust",
    ).toMatch(/leaves=\d+/);
    expect(
      String(refused[0]!.ctx!.impact),
      "it must say neither side will use one, not merely that this attempt failed",
    ).toMatch(/neither side will use|for the life of|stays unsalted/i);
    expect(
      String(refused[0]!.ctx!.guidance),
      "and must name the move that DOES work",
    ).toMatch(/start a new session/i);

    /**
     * ⚠️ THE PEER MUST BE TOLD — review F2, and this is the assertion the whole redesign turns on.
     *
     * A local refusal alone lets the two sides reach OPPOSITE verdicts, both correctly: the very
     * first message of a session is a leaf on the receiver before it is one on the sender, who is
     * still inside its own `await`. One adopts, one refuses, and nothing on the wire or in either row
     * records the disagreement — which, once salting is on, is a one-way dead conversation rather
     * than a weaker hash.
     */
    const announced = fx.eventsNamed("session.salt.announced");
    expect(
      announced.map((e) => e.ctx!["state"]),
      "the refusal must reach the WIRE as a REFUSAL — a peer told 'offering_contribution' will keep offering, and a peer told nothing will adopt a salt this side can never verify",
    ).toContain("adoption_closed");
  }, 60_000);

  it("★ the session STAYS usable — refusing the salt must not refuse the conversation", async () => {
    /**
     * The counterbalance. An unsalted transcript is exactly as verifiable as every transcript in
     * existence today; a frozen session is not a conversation. Getting this backwards would trade a
     * correlation weakness for a broken product, which is the wrong direction on every axis.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-adopt-d-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);
    fx.seedReceived("alice", SID, "already hashed");

    await fx.snm.handleContentFrameForTest("alice", SID, saltFrame(), PEER);
    await wait(300);

    expect(
      fx.eventsNamed("session.salt.adoption.refused").length,
      "precondition — without the refusal actually firing, everything below passes vacuously on a session that was never asked to refuse anything",
    ).toBe(1);
    expect(fx.eventsNamed("session.salt.frozen").length, "a refused adoption must NOT freeze the session").toBe(0);

    /**
     * ⚠️ NOT "it did not freeze" — THE CONVERSATION HAS TO STILL MOVE.
     *
     * Review: the original test asserted an absence and a revive, and both are satisfied by a
     * session that has quietly stopped being able to send. The refusal is upstream of
     * `contentHashForSession`, and the failure this guards against is that a refused session takes
     * the salted branch anyway, throws `content_hash_salt_unavailable` on its own send, and dies
     * without ever emitting a freeze.
     *
     * So: send a real message, and receive one. That is the product working.
     */
    const revived = await fx.snm.reviveSessionNode("alice", SID);
    expect(
      (revived as { reason?: string }).reason ?? "",
      "and the session must still be revivable — this is a weaker hash, not a broken conversation",
    ).not.toMatch(/frozen/);

    const body = new TextEncoder().encode("the conversation continues, just unsalted");
    const { hash, alg } = await fx.snm.contentHashForSession("alice", SID, body);
    expect(alg, "a refused session must hash the way it already hashed — naming a salted algorithm it holds no salt for is how every peer starts refusing it").toBe("sha256");
    await expect(
      fx.snm.sendContent("alice", SID, body, hash, "corr-after-refusal", LEAF_KIND_MSG, alg),
      "an unsalted session must still SEND — a refusal that silently ends the conversation is worse than the correlation weakness it avoids",
    ).resolves.not.toThrow();

    const before = fx.snm.getSessionTree("alice", SID).size();
    fx.seedReceived("alice", SID, "and it can still receive");
    expect(
      fx.snm.getSessionTree("alice", SID).size(),
      "and must still INGEST — the transcript keeps growing under the rule it started with",
    ).toBeGreaterThan(before);
  }, 60_000);
});
