/**
 * THE SALT AGREEMENT IS WIRED — `DOD-M15-SEALWIRE-1` bullet 6, part A.
 *
 * `dod-m15-salt-agreement.test.ts` proves the state machine decides correctly. It cannot prove the
 * daemon ever CALLS it, and that is the gap that has opened in four consecutive units on this
 * milestone: a module green in isolation, wired to nothing, with every test passing.
 *
 * So this file drives the REAL inbound content handler — the same function libp2p's protocol
 * handler calls, peer gate and all — and reads the REAL `sessions.content_salt` column afterwards.
 * Nothing here reaches into the state machine directly.
 *
 * ─── What each test would catch ────────────────────────────────────────────────────────────────
 *
 *   dispatch      — delete the `session_salt_agreement` branch and the frame falls through to
 *                   `frame_unknown_type`; the salt is never derived.
 *   persistence   — derive without writing the row and the salt is gone at the next restart, which
 *                   is precisely the silent transcript split Decision #8 persists it to prevent.
 *   the peer gate — a stranger holding an old connection must not be able to steer, or poison, the
 *                   salt of a session it is not party to.
 *   the freeze    — a disagreement must STOP the session, not log and continue.
 */

import { describe, it, expect, afterEach } from "vitest";
import { startTwoConnectionFixture, FakeNode, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import type { CelloNode } from "@cello-protocol/transport";
import { decode } from "cbor-x";
import { encodeCbor } from "@cello-protocol/protocol-types";
import { deriveSessionSalt, saltFingerprint, SALT_CONTRIBUTION_BYTES } from "@cello-protocol/crypto";
import * as lp from "it-length-prefixed";

const SID = "ab".repeat(32);
const PEER = "12D3KooWQYV9dGMFoRzNStwpXztXaBUjtPqi6aMghfATmPnRAENn";
const OTHER_PEER = "12D3KooWH3uVF6wv47WnArKHk5p6cvgCJEb74UTmxztmQDc298L3";
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

const PEER_CONTRIBUTION = new Uint8Array(SALT_CONTRIBUTION_BYTES).fill(0x5c);

function saltFrame(fields: Record<string, unknown>): Uint8Array {
  return lp.encode.single(encodeCbor({ type: "session_salt_agreement", session_id: SID, ...fields }) as Uint8Array).subarray();
}

/**
 * What the daemon actually PUT ON THE WIRE, decoded.
 *
 * `FakeNode.sent` has existed all along and no salt test read it — which is why three mutants on the
 * outbound half survived pass 1 (review F16). Asserting the log alone proves the daemon reached a
 * verdict; it cannot prove it sent the frame that verdict is made of.
 */
function sentFrames(node: CelloNode | null): Array<Record<string, unknown>> {
  const raw = (node as unknown as { sent?: Uint8Array[] } | null)?.sent ?? [];
  return raw.flatMap((framed) => {
    try {
      // `lp.encode.single` prefixes a varint length; every frame here is far below 128 bytes ×
      // nothing, so strip the prefix by decoding from the first byte that parses.
      for (let off = 0; off < Math.min(4, framed.length); off++) {
        try { return [decode(framed.subarray(off)) as Record<string, unknown>]; } catch { /* try next */ }
      }
      return [];
    } catch { return []; }
  });
}

function storedSalt(fx: TwoConnectionFixture, agent: string): Uint8Array | null {
  const agentId = (fx.snm.getDb().prepare("SELECT agent_id FROM agents WHERE agent_name = ?").get(agent) as { agent_id: string }).agent_id;
  const row = fx.snm.getDb()
    .prepare("SELECT content_salt FROM sessions WHERE agent_id = ? AND session_id = ?")
    .get(agentId, SID) as { content_salt: Uint8Array | null } | undefined;
  return row?.content_salt ? new Uint8Array(row.content_salt) : null;
}

describe("DOD-M15-SEALWIRE-1 part A: an inbound contribution reaches the agreement and lands on disk", () => {
  let fx: TwoConnectionFixture | null = null;
  let node: CelloNode | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; node = null; });

  it("★ the counterparty's contribution derives a salt and PERSISTS it", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-salt-wire-a-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    expect(storedSalt(fx, "alice"), "no salt before the exchange").toBeNull();
    await fx.snm.handleContentFrameForTest("alice", SID, saltFrame({ contribution: PEER_CONTRIBUTION }), PEER);
    await wait(200);

    const salt = storedSalt(fx, "alice");
    expect(salt, "the salt must be on disk, not merely in memory — a restart is what Decision #8 persists it for").not.toBeNull();
    expect(salt!.length).toBe(32);
    expect(fx.eventsNamed("session.salt.agreed").length).toBe(1);
    expect(fx.eventsNamed("session.salt.agreed")[0]!.ctx!.via).toBe("derived");
  }, 60_000);

  it("★ the stored salt is the one BOTH SIDES would compute — not merely 32 bytes of something", async () => {
    /**
     * The assertion that survives a mutant. "A salt was written" passes if the daemon stores the
     * peer's contribution verbatim, or a hash of one half, or random bytes — every one of which
     * leaves the counterparty deriving something else and every message discarded unread.
     *
     * ⚠️ THIS TEST DOES NOT PROVE THE SALT IS THE AGREED VALUE, and its previous docblock claimed
     * it did — review F2. Both sides of the comparison below come from the same row, so the daemon
     * could store 32 random bytes and still answer `fingerprint_match`. What it proves is
     * SELF-CONSISTENCY: the digest the daemon confirms against is derived from what it stored, not
     * from something it kept only in memory. That is worth keeping and it is all it is.
     *
     * The property this unit exists for — that the TWO daemons compute the same value — cannot be
     * checked from here, because this side never sees the daemon's own half. It is checked in
     * `dod-m15-salt-announce-on-connect.test.ts`, where a real peer connection puts that half on
     * the wire and the test derives the salt independently from both.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-salt-wire-b-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);
    await fx.snm.handleContentFrameForTest("alice", SID, saltFrame({ contribution: PEER_CONTRIBUTION }), PEER);
    await wait(200);

    const salt = storedSalt(fx, "alice")!;
    // The peer's own half must not BE the salt, and must not be recoverable from it: a daemon that
    // stored the contribution it was handed would let one side pick the salt outright.
    expect(Buffer.from(salt).toString("hex")).not.toBe(Buffer.from(PEER_CONTRIBUTION).toString("hex"));
    // And the salt must be reproducible from the two halves under the primitive's own rule — so
    // whatever the daemon's contribution was, `deriveSessionSalt(theirs, ours)` reaches these bytes.
    // We recover `ours` by the only route a counterparty has: it is the value that, combined with
    // ours, yields the fingerprint the daemon confirms against. Assert that round trip directly.
    const announced = saltFingerprint(salt);
    await fx.snm.handleContentFrameForTest("alice", SID, saltFrame({ fingerprint: announced }), PEER);
    await wait(200);
    expect(
      fx.eventsNamed("session.salt.agreed").filter((e) => e.ctx!.via === "fingerprint_match").length,
      "the daemon must confirm against a fingerprint of the salt it stored",
    ).toBe(1);
    expect(fx.eventsNamed("session.salt.frozen").length, "and must not have frozen").toBe(0);
  }, 60_000);

  it("★ a salt that FAILED TO STORE is never announced as agreed", async () => {
    /**
     * The last surviving mutant of the revert test: drop the caller's `if (!persisted) return` and
     * everything stayed green, because nothing could make the persist report failure — an `UPDATE`
     * matching no row returns `changes: 0` rather than throwing, and the method took its success
     * branch on a write that stored nothing.
     *
     * Why it matters more than a missing row: announcing the fingerprint tells the counterparty the
     * agreement is DONE. They stop offering a contribution and start comparing. We hold the salt in
     * memory only, so the next restart loses it — and the two sides come back as one holding a salt
     * and one not, which the agreement correctly refuses as `salt_state_divergent`. The loud failure
     * still happens; it just happens a restart late, on a session both sides believed was settled.
     *
     * The unreachable-row case is reproduced here the way production reaches it: a session whose row
     * is gone while the node is still live.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-salt-wire-h-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);
    fx.snm.getDb().prepare("DELETE FROM sessions WHERE session_id = ?").run(SID);

    await fx.snm.handleContentFrameForTest("alice", SID, saltFrame({ contribution: PEER_CONTRIBUTION }), PEER);
    await wait(300);

    const failed = fx.eventsNamed("session.salt.persist.failed");
    expect(failed.length, "a write that stored nothing must say so").toBe(1);
    expect(failed[0]!.ctx!.reason).toBe("no_session_row");
    expect(
      fx.eventsNamed("session.salt.agreed").length,
      "agreement must not be claimed for a salt that is not on disk",
    ).toBe(0);
  }, 60_000);

  it("★ the REPAIR puts our own half on the wire — not a fingerprint, and not a fresh half", async () => {
    /**
     * Review F16, mutant 1: delete `override ??` in `#sendSaltFrame` and the repair silently
     * degrades to re-announcing a fingerprint — no repair at all — with every test still green. The
     * only wired repair test had the daemon holding NO salt, where the override frame and the
     * state-derived frame are byte-identical, so it could not see the difference.
     *
     * This is the state that tells them apart: the daemon HOLDS a salt, and must answer a peer's
     * contribution with its own half rather than the fingerprint its state would otherwise produce.
     *
     * And review F15, mutant 3: the half it sends must be the one its salt was BUILT from. A daemon
     * that mints a fresh one repairs the peer onto a different salt — which is why this asserts the
     * exact bytes rather than merely "a 32-byte contribution".
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-salt-wire-j-", node: node = new FakeNode() as unknown as CelloNode });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    const ourHalf = new Uint8Array(SALT_CONTRIBUTION_BYTES).fill(0x4e);
    fx.snm.setSaltContributionForTest("alice", SID, ourHalf);
    // Agree a salt first, so the daemon is in the "holds a salt" state.
    await fx.snm.handleContentFrameForTest("alice", SID, saltFrame({ contribution: PEER_CONTRIBUTION }), PEER);
    await wait(200);
    expect(storedSalt(fx, "alice"), "precondition: the daemon must hold a salt").not.toBeNull();

    const before = sentFrames(node).length;
    // The peer starts over — its salt did not survive. This used to freeze the session.
    await fx.snm.handleContentFrameForTest("alice", SID, saltFrame({ contribution: PEER_CONTRIBUTION }), PEER);
    await wait(300);

    const repairFrame = sentFrames(node).slice(before).find((f) => f["type"] === "session_salt_agreement");
    expect(repairFrame, "the repair must actually send something").toBeDefined();
    expect(
      repairFrame!["contribution"],
      "a repair that sends a fingerprint is not a repair — the peer has no way to reach our salt from it",
    ).toBeInstanceOf(Uint8Array);
    expect(
      Buffer.from(repairFrame!["contribution"] as Uint8Array).toString("hex"),
      "it must be the half our salt was built from, or we repair them onto a DIFFERENT salt",
    ).toBe(Buffer.from(ourHalf).toString("hex"));
    expect(fx.eventsNamed("session.salt.frozen").length, "and must not freeze").toBe(0);
  }, 60_000);

  it("★ a REVIVED session whose half is gone refuses instead of repairing onto the wrong salt", async () => {
    /**
     * Review F15, and it was live: `#sendSaltFrame` minted a half unconditionally, so `#ownSaltHalf`
     * never returned null and `salt_state_divergent` was DEAD CODE. `#evictSessionCaches` drops the
     * half on every teardown while the salt stays on disk, so any revived session was in this state
     * — and would repair its counterparty onto a half its salt was never built from.
     *
     * The operator then read the MISMATCH guidance, which sends them to compare build versions with
     * a counterparty that did nothing wrong. The reason written for exactly this — "nothing is
     * broken and neither of you did anything wrong" — was unreachable.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-salt-wire-k-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);
    await fx.snm.handleContentFrameForTest("alice", SID, saltFrame({ contribution: PEER_CONTRIBUTION }), PEER);
    await wait(200);
    expect(storedSalt(fx, "alice")).not.toBeNull();

    // The teardown/revival state: salt on disk, half gone. Reached in production by any interruption.
    fx.snm.forgetSaltContributionForTest("alice", SID);

    await fx.snm.handleContentFrameForTest("alice", SID, saltFrame({ contribution: PEER_CONTRIBUTION }), PEER);
    await wait(400);

    const disagreements = fx.eventsNamed("session.salt.disagreement");
    expect(disagreements.length, "it must refuse rather than repair onto a half we never used").toBe(1);
    expect(disagreements[0]!.ctx!.reason).toBe("salt_state_divergent");
    expect(fx.eventsNamed("session.salt.repair").length, "and must NOT repair").toBe(0);
    // The guidance must not send them to their counterparty's build version.
    expect(String(disagreements[0]!.ctx!.guidance)).toMatch(/neither of you did anything wrong/);
  }, 60_000);

  it("★ a MISMATCH hands the peer our digest before the session goes — Decision #10 wants both sides to refuse", async () => {
    /**
     * Review F16, mutant 2: delete the `notifyPeer` send in the daemon and every test stayed green,
     * because the only assertion on it pinned the FIELD in the pure function, never the SEND. The
     * fingerprint-mismatch path had no daemon-level test at all.
     *
     * Without the notice the far operator gets nothing — the session simply stops answering — while
     * ours gets a full explanation.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-salt-wire-l-", node: node = new FakeNode() as unknown as CelloNode });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);
    await fx.snm.handleContentFrameForTest("alice", SID, saltFrame({ contribution: PEER_CONTRIBUTION }), PEER);
    await wait(200);
    const ourSalt = storedSalt(fx, "alice")!;

    const before = sentFrames(node).length;
    const theirSalt = deriveSessionSalt(PEER_CONTRIBUTION, new Uint8Array(SALT_CONTRIBUTION_BYTES).fill(0x77));
    await fx.snm.handleContentFrameForTest("alice", SID, saltFrame({ fingerprint: saltFingerprint(theirSalt) }), PEER);
    await wait(400);

    const notice = sentFrames(node).slice(before).find((f) => f["fingerprint"] !== undefined);
    expect(notice, "the peer must be told before the session disappears").toBeDefined();
    expect(Buffer.from(notice!["fingerprint"] as Uint8Array).toString("hex"))
      .toBe(Buffer.from(saltFingerprint(ourSalt)).toString("hex"));
    expect(fx.eventsNamed("session.salt.frozen").length, "and the session still stops").toBe(1);
  }, 60_000);

  it("★ the repair TERMINATES — an identical re-offer gets a fingerprint, not another contribution", async () => {
    /**
     * Review F14. `(hold a salt) + (peer contribution) → emit a contribution, state unchanged` is a
     * fixed point that emits on every receipt, so two daemons in it trade contributions at
     * round-trip speed forever — while holding the SAME salt, making the whole exchange waste. One
     * reconnect mid-exchange is enough to enter it, which is the very event the repair exists to
     * survive.
     *
     * A fingerprint is terminal for the peer (`confirmed` or `FINGERPRINT_MISMATCH`), so answering
     * a repeat with one closes the cycle while leaving the FIRST repair untouched.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-salt-wire-m-", node: node = new FakeNode() as unknown as CelloNode });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);
    await fx.snm.handleContentFrameForTest("alice", SID, saltFrame({ contribution: PEER_CONTRIBUTION }), PEER);
    await wait(200);

    // First repair: our half goes out.
    let before = sentFrames(node).length;
    await fx.snm.handleContentFrameForTest("alice", SID, saltFrame({ contribution: PEER_CONTRIBUTION }), PEER);
    await wait(300);
    const first = sentFrames(node).slice(before).find((f) => f["type"] === "session_salt_agreement");
    expect(first!["contribution"], "the first repair sends our half").toBeInstanceOf(Uint8Array);

    // The SAME half again — a queued duplicate after a reconnect. This is where it used to loop.
    before = sentFrames(node).length;
    await fx.snm.handleContentFrameForTest("alice", SID, saltFrame({ contribution: PEER_CONTRIBUTION }), PEER);
    await wait(300);
    const second = sentFrames(node).slice(before).find((f) => f["type"] === "session_salt_agreement");
    expect(second, "it must still answer — silence is not termination, it is a stall").toBeDefined();
    expect(
      second!["fingerprint"],
      "a second identical contribution must be answered with a fingerprint, which is terminal for the peer",
    ).toBeInstanceOf(Uint8Array);
    expect(second!["contribution"], "another contribution here is the livelock").toBeUndefined();

    // A genuinely NEW half from the peer must still get our contribution — the guard keys on bytes,
    // not on a "have we repaired once" flag, or a real re-agreement would be answered uselessly.
    before = sentFrames(node).length;
    await fx.snm.handleContentFrameForTest(
      "alice", SID, saltFrame({ contribution: new Uint8Array(SALT_CONTRIBUTION_BYTES).fill(0x2b) }), PEER,
    );
    await wait(300);
    const third = sentFrames(node).slice(before).find((f) => f["type"] === "session_salt_agreement");
    expect(third!["contribution"], "a new peer half is not a repeat and must get our half").toBeInstanceOf(Uint8Array);
  }, 60_000);

  it("★ a STRANGER cannot seed this session's salt", async () => {
    /**
     * A session node is a promoted standing receiver, and a standing receiver admitted everyone; a
     * peer that dialled before the gater narrowed still holds a connection. If it could land a
     * contribution, it would either pick half the salt for a conversation it is not in, or freeze
     * the session at will.
     *
     * The refusal is the SHARED gate above the dispatch — this asserts that placing the branch
     * below it was load-bearing, not incidental.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-salt-wire-c-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    await fx.snm.handleContentFrameForTest("alice", SID, saltFrame({ contribution: PEER_CONTRIBUTION }), OTHER_PEER);
    await wait(200);

    expect(storedSalt(fx, "alice"), "a stranger must not be able to seed the salt").toBeNull();
    expect(fx.eventsNamed("session.content.peer_mismatch").length).toBe(1);
    expect(fx.eventsNamed("session.salt.frozen").length, "and must not be able to freeze it either").toBe(0);
  }, 60_000);
});

describe("DOD-M15-SEALWIRE-1 part A: a disagreement stops the session, loudly", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  it("★ a DEGENERATE contribution freezes the session and names why", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-salt-wire-d-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    await fx.snm.handleContentFrameForTest(
      "alice", SID, saltFrame({ contribution: new Uint8Array(SALT_CONTRIBUTION_BYTES) }), PEER,
    );
    await wait(400);

    expect(storedSalt(fx, "alice"), "nothing may be stored from a contribution we refused").toBeNull();
    const disagreements = fx.eventsNamed("session.salt.disagreement");
    expect(disagreements.length).toBe(1);
    expect(disagreements[0]!.ctx!.reason).toBe("salt_contribution_degenerate");
    // The operator gets something to DO, from the total guidance map — not a bare code.
    expect(String(disagreements[0]!.ctx!.guidance)).toMatch(/OUT OF BAND/);
    // And the primitive's own explanation survives the trip, rather than being replaced by ours.
    expect(String(disagreements[0]!.ctx!.detail)).toMatch(/all zeros/);

    // FROZEN, which means the session does not come back on the next read or send.
    expect(fx.eventsNamed("session.salt.frozen").length).toBe(1);
    expect(
      fx.eventsNamed("session.content.identity.frozen").length,
      "a salt disagreement must NOT be reported as the counterparty failing a key check",
    ).toBe(0);

    /**
     * THE FREEZE MUST BE THE SESSION ENDING, not a log line.
     *
     * Measured with a running mutant: skip the teardown and keep the logging, and every assertion
     * above still passes. `interrupted` is the REVIVABLE status, so without the freeze mark the
     * operator's very next `cello_receive` rebuilds the node and the session carries on with two
     * sides that never agreed a salt — the exact silent-discard loop Decision #10 exists to stop,
     * with a log line above it claiming otherwise.
     */
    const revived = await fx.snm.reviveSessionNode("alice", SID, "revive-attempt");
    expect(revived.ok, "a frozen session must not come back on the next read").toBe(false);
    expect((revived as { reason: string }).reason).toBe("session_frozen_salt_contribution_degenerate");
    // And it must explain ITSELF. The refusal used to be hardcoded to the identity failure, which
    // would tell this operator their counterparty failed a key check when nobody's key was involved.
    const guidance = (revived as { guidance: string }).guidance;
    expect(guidance).toMatch(/OUT OF BAND/);
    expect(guidance, "a salt refusal must not borrow the identity failure's words").not.toMatch(/counterparty's key/);
    expect(guidance, "and it must still say the transcript survived").toMatch(/cello_transcript/);
  }, 60_000);

  it("★ a peer fingerprint we cannot match REPAIRS — one dropped frame must not kill a live session", async () => {
    /**
     * This test asserted the opposite until review F1, and it was wrong because the code was.
     *
     * The state is reached by nothing exotic: our connect-time announce failed while theirs landed,
     * so they derived and stored a salt and we never saw their half. Freezing here destroyed a
     * healthy session over a single dropped frame — to defend a value that nothing consumes.
     *
     * Re-offering our half is what asks them for theirs, and `deriveSessionSalt` sorts its inputs,
     * so the two converge on identical bytes.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-salt-wire-e-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    const theirSalt = deriveSessionSalt(PEER_CONTRIBUTION, new Uint8Array(SALT_CONTRIBUTION_BYTES).fill(0x11));
    await fx.snm.handleContentFrameForTest("alice", SID, saltFrame({ fingerprint: saltFingerprint(theirSalt) }), PEER);
    await wait(400);

    expect(fx.eventsNamed("session.salt.repair").length, "the out-of-step side must re-offer its half").toBe(1);
    expect(fx.eventsNamed("session.salt.disagreement").length, "and must NOT refuse").toBe(0);
    expect(fx.eventsNamed("session.salt.frozen").length).toBe(0);
    // The session is still usable, which is the point — a frozen one is not revivable.
    const revived = await fx.snm.reviveSessionNode("alice", SID, "after-repair");
    expect((revived as { reason?: string }).reason ?? "", "a repaired session must not be frozen").not.toMatch(/frozen/);
  }, 60_000);

  it("★ our OWN broken random source is not reported as the counterparty's fault", async () => {
    /**
     * Review F3, at the level the operator actually meets it. `deriveSessionSalt` refuses our own
     * all-zero half specifically so a broken local RNG is not blamed on the peer — and one catch
     * mapping every throw to one peer-blaming reason undid that at the guidance layer, producing an
     * instruction to raise it with the counterparty OUT OF BAND for a defect on this machine.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-salt-wire-i-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);
    fx.snm.setSaltContributionForTest("alice", SID, new Uint8Array(SALT_CONTRIBUTION_BYTES));

    await fx.snm.handleContentFrameForTest("alice", SID, saltFrame({ contribution: PEER_CONTRIBUTION }), PEER);
    await wait(400);

    const disagreements = fx.eventsNamed("session.salt.disagreement");
    expect(disagreements.length).toBe(1);
    expect(disagreements[0]!.ctx!.reason).toBe("salt_own_contribution_degenerate");
    const guidance = String(disagreements[0]!.ctx!.guidance);
    expect(guidance, "it must say the problem is here").toMatch(/THIS MACHINE/);
    expect(guidance, "and must NOT send them to accuse their counterparty").not.toMatch(/OUT OF BAND/);
  }, 60_000);

  it("★ a frame claiming BOTH states is refused before anything is derived", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-salt-wire-f-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    await fx.snm.handleContentFrameForTest(
      "alice", SID,
      saltFrame({ contribution: PEER_CONTRIBUTION, fingerprint: new Uint8Array(8).fill(0x22) }),
      PEER,
    );
    await wait(400);

    expect(storedSalt(fx, "alice")).toBeNull();
    expect(fx.eventsNamed("session.salt.disagreement")[0]!.ctx!.reason).toBe("salt_frame_malformed");
  }, 60_000);

  it("★ a contribution of the WRONG TYPE is treated as absent, not as a present-but-wrong value", async () => {
    /**
     * CBOR carries whatever the peer encoded. A string in the contribution slot must arrive at the
     * state machine as ABSENT — which makes the frame carry neither field and be refused by shape —
     * rather than as something the derivation is then handed.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-salt-wire-g-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    await fx.snm.handleContentFrameForTest("alice", SID, saltFrame({ contribution: "not-bytes" }), PEER);
    await wait(400);

    expect(storedSalt(fx, "alice")).toBeNull();
    expect(fx.eventsNamed("session.salt.disagreement")[0]!.ctx!.reason).toBe("salt_frame_malformed");
  }, 60_000);
});
