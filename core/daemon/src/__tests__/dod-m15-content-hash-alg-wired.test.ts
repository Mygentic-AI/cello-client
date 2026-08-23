/**
 * THE RECEIVER READS THE ALGORITHM OFF THE FRAME — `DOD-M15-SEALWIRE-1` part B1, wired.
 *
 * `dod-m15-content-hash-alg.test.ts` proves the three cases are decided correctly. It cannot prove
 * the daemon ever LOOKS at the field, and that is the gap that has opened in five consecutive units
 * on this milestone: a module green in isolation, wired to nothing.
 *
 * So this drives the real inbound content handler and the real `ingestReceivedContent`, and asserts
 * on the refusal reasons the daemon actually returns.
 *
 * ─── The distinction every test here is about ──────────────────────────────────────────────────
 *
 * Three ways a hash can fail to match, and only ONE of them is evidence of tampering:
 *
 *   the bytes were altered           → `content_hash_mismatch`   — a security signal
 *   they used an algorithm we lack   → `content_hash_alg_unknown` — their build is newer
 *   they salted and we hold no salt  → `content_hash_salt_unavailable` — our agreement never landed
 *
 * Collapsing them is how a routine version skew becomes a security incident in the operator's log —
 * and, worse, how a real tamper gets waved away as a skew.
 */

import { describe, it, expect, afterEach } from "vitest";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import { CONTENT_HASH_ALGS, wireContentHash } from "../wire-content-hash.js";
import { evaluateSealUpgrade } from "../seal-upgrade.js";
import { deriveSessionSalt, saltedContentHash, SALT_CONTRIBUTION_BYTES } from "@cello-protocol/crypto";
import { encodeCbor } from "@cello-protocol/protocol-types";
import * as lp from "it-length-prefixed";

const SID = "ef".repeat(32);
const PEER = "12D3KooWQYV9dGMFoRzNStwpXztXaBUjtPqi6aMghfATmPnRAENn";
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));
const CONTENT = new TextEncoder().encode("the number is 4200");
const PEER_HALF = new Uint8Array(SALT_CONTRIBUTION_BYTES).fill(0x5c);
const SID2 = "ab".repeat(32);

function contentFrame(fields: Record<string, unknown>): Uint8Array {
  return lp.encode.single(encodeCbor({
    type: "content_frame", session_id: SID, content_bytes: CONTENT, ...fields,
  }) as Uint8Array).subarray();
}

function saltFrame(fields: Record<string, unknown>): Uint8Array {
  return lp.encode.single(encodeCbor({
    type: "session_salt_agreement", session_id: SID, ...fields,
  }) as Uint8Array).subarray();
}

/** The salt the daemon agreed, read back from the row — the value a real counterparty would hold. */
function agreedSalt(fx: TwoConnectionFixture): Uint8Array {
  const agentId = (fx.snm.getDb().prepare("SELECT agent_id FROM agents WHERE agent_name = ?").get("alice") as { agent_id: string }).agent_id;
  const row = fx.snm.getDb()
    .prepare("SELECT content_salt FROM sessions WHERE agent_id = ? AND session_id = ?")
    .get(agentId, SID) as { content_salt: Uint8Array | null };
  return new Uint8Array(row.content_salt!);
}

describe("DOD-M15-SEALWIRE-1 part B1: an ABSENT name still works — every peer in existence today", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  it("★ a frame with no algorithm field verifies as sha256 and is ingested", async () => {
    /**
     * The compatibility assertion, and the one that would strand every live conversation if it
     * broke. Nothing in the field is not a peer doing something wrong — it is every peer on every
     * currently published build.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-alg-a-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    const res = await fx.snm.ingestReceivedContent("alice", SID, CONTENT, wireContentHash(CONTENT), "corr");
    expect(res.ok, "an unnamed frame must still be accepted").toBe(true);
  }, 60_000);

  it("★ an explicit sha256 name verifies identically to an absent one", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-alg-b-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    const res = await fx.snm.ingestReceivedContent(
      "alice", SID, CONTENT, wireContentHash(CONTENT), "corr", undefined, CONTENT_HASH_ALGS.SHA256,
    );
    expect(res.ok).toBe(true);
  }, 60_000);
});

describe("DOD-M15-SEALWIRE-1 part B1: a version skew is not a tamper", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  it("★ an UNKNOWN algorithm is refused by its own name, never as a hash mismatch", async () => {
    /**
     * The finding this unit exists for. Before the discriminator, a peer hashing differently
     * produced `content_hash_mismatch` on every frame — indistinguishable from someone altering
     * their messages — with the send succeeding and the receiver discarding silently.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-alg-c-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    const res = await fx.snm.ingestReceivedContent(
      "alice", SID, CONTENT, wireContentHash(CONTENT), "corr", undefined, "hmac-sha512-salt-v9",
    );
    expect(res.ok).toBe(false);
    expect(res.ok === false && res.reason).toBe("content_hash_alg_unknown");

    const failure = fx.eventsNamed("session.content.cross_check.failed").at(-1)!;
    // The unreadable NAME has to reach the log, or the operator cannot tell which build to chase.
    expect(failure.ctx!.declaredAlg).toBe("hmac-sha512-salt-v9");
    /**
     * ⚠️ THIS ASSERTION USED TO REQUIRE THE OPPOSITE, and it was wrong — review F1.
     *
     * It pinned the phrase "version difference, not tampering". That reads as reassurance and it is
     * inferred entirely from `content_hash_alg`, a field NO SIGNATURE COVERS — so in the one case
     * that matters it is inferred from the attacker. The message may say what we could not do; it
     * may not say what the sender did.
     */
    expect(String(failure.ctx!.impact)).toMatch(/could not be verified/);
    expect(
      String(failure.ctx!.impact),
      "the refusal must not certify the sender's innocence from an unsigned field",
    ).not.toMatch(/nothing was altered|nobody did anything wrong/i);
    expect(String(failure.ctx!.guidance), "and give them something to do").toMatch(/[Uu]pgrade/);
  }, 60_000);

  it("★ SALTED with no salt held is its own refusal — not a mismatch, not an unknown algorithm", async () => {
    /**
     * The third case, and it is genuinely different from the other two: we understand the algorithm
     * perfectly and simply lack the input. Reporting it as a mismatch would accuse the sender;
     * reporting it as an unknown algorithm would send the operator to upgrade a build that is
     * already current.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-alg-d-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    const someSalt = deriveSessionSalt(PEER_HALF, new Uint8Array(SALT_CONTRIBUTION_BYTES).fill(0x33));
    const res = await fx.snm.ingestReceivedContent(
      "alice", SID, CONTENT, saltedContentHash(someSalt, CONTENT), "corr", undefined, CONTENT_HASH_ALGS.HMAC_SALT_V1,
    );
    expect(res.ok).toBe(false);
    expect(res.ok === false && res.reason).toBe("content_hash_salt_unavailable");
    // Same correction as above: "Nothing was altered" is not knowable from here. What IS knowable,
    // and what the operator needs, is that we could not check and that the seal will not auto-close.
    const saltFailure = fx.eventsNamed("session.content.cross_check.failed").at(-1)!;
    expect(String(saltFailure.ctx!.impact)).toMatch(/could not be verified/);
    expect(String(saltFailure.ctx!.impact)).toMatch(/will not auto-co-sign/);
    // Review F6: three conditions leave us holding no salt and only one of them wants a close.
    expect(String(saltFailure.ctx!.guidance), "it must name the self-repairing case first").toMatch(/repairs itself|re-runs on the next reconnect/);
  }, 60_000);

  it("★ a REAL tamper is still reported as a tamper, and now says which algorithm it checked", async () => {
    /**
     * The counterbalance. Three new refusal reasons are worth nothing if they have quietly widened
     * the gap a genuine alteration slips through — so this asserts the security signal survives, and
     * that the log now carries the one field that makes a mismatch falsifiable: what we checked it
     * under. Without it, "the bytes were altered" and "we checked it the wrong way" look identical.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-alg-e-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    const res = await fx.snm.ingestReceivedContent(
      "alice", SID, CONTENT, wireContentHash(new TextEncoder().encode("the number is 9900")), "corr",
    );
    expect(res.ok).toBe(false);
    expect(res.ok === false && res.reason).toBe("content_hash_mismatch");
    expect(fx.eventsNamed("session.content.cross_check.failed").at(-1)!.ctx!.declaredAlg).toBe(CONTENT_HASH_ALGS.SHA256);
  }, 60_000);
});

describe("DOD-M15-SEALWIRE-1 part B1: a refusal must not switch the tamper detector off", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  /**
   * ⚠️ THE FINDING THIS BLOCK EXISTS FOR — review F1, and it was a security defect I shipped.
   *
   * `content_hash_alg` rides the frame ENVELOPE, which no signature covers: the sender's signature
   * is over `structure1_cbor`, which binds `content_hash` and nothing else. So the field is an
   * unauthenticated CLAIM by whoever sent the frame.
   *
   * Before B1, every frame failing the cross-check reached `#contentDesynced`, which gates
   * auto-co-signing and unilateral ratification. My two new branches returned BEFORE it. So:
   *
   *   sign hash H → send bytes that are not H's preimage → add `content_hash_alg: "anything-v9"`
   *   → the receiver refuses politely, records nothing, tells the operator "do not treat this as a
   *     security event" → and AUTO-CO-SIGNS at close.
   *
   * One unsigned string turned the tamper detector off. Nothing in the original unit asserted on
   * `#contentDesynced` at all, so moving the mark between branches was a mutant that survived
   * everything.
   */
  const CASES: Array<{ name: string; alg: string; hash: () => Uint8Array }> = [
    { name: "an unreadable algorithm name", alg: "anything-v9", hash: () => wireContentHash(CONTENT) },
    {
      name: "a salted claim on a session with no salt",
      alg: CONTENT_HASH_ALGS.HMAC_SALT_V1,
      hash: () => saltedContentHash(deriveSessionSalt(PEER_HALF, new Uint8Array(SALT_CONTRIBUTION_BYTES).fill(0x33)), CONTENT),
    },
  ];

  for (const c of CASES) {
    it(`★ ${c.name} still blocks the auto-seal — a refusal is not an excuse`, async () => {
      fx = await startTwoConnectionFixture({ dirPrefix: `cello-alg-sec-${c.alg.slice(0, 6)}-` });
      await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

      expect(fx.snm.getSealUpgradeReadiness("alice", SID).unverifiable, "precondition").toBeNull();
      await fx.snm.ingestReceivedContent("alice", SID, CONTENT, c.hash(), "corr", undefined, c.alg);

      const readiness = fx.snm.getSealUpgradeReadiness("alice", SID);
      expect(
        readiness.unverifiable,
        "content we could not verify must block co-signing, whatever the reason we could not",
      ).not.toBeNull();
      // ...and it must carry WHY, not just whether — review F-A. A boolean here is what let the
      // seal-upgrade consumer call an ordinary version skew a tamper.
      expect(readiness.unverifiable, "an ordinary refusal is not a tamper claim").toBe("unverifiable");
      expect(evaluateSealUpgrade(readiness).proceed, "and the kernel still refuses").toBe(false);
    }, 60_000);
  }

  it("★ but it is NOT reported as a tamper — an honest newer build must not raise a security alarm", async () => {
    /**
     * The counterbalance, named before the fix was written. Making both branches block the seal is
     * only half right: labelling an ordinary version difference `content_tamper` would train an
     * operator to dismiss the one alarm that means something.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-alg-sec-label-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);
    await fx.snm.ingestReceivedContent("alice", SID, CONTENT, wireContentHash(CONTENT), "corr", undefined, "anything-v9");

    const failure = fx.eventsNamed("session.content.cross_check.failed").at(-1)!;
    expect(
      String(failure.ctx!.impact),
      "it must not assert what the sender did — that is inferred from an unsigned field",
    ).not.toMatch(/nothing was altered|nobody did anything wrong/i);
    expect(String(failure.ctx!.guidance)).not.toMatch(/Do not treat this as a security event/i);
    // It must say the field is a claim, so nobody reads the refusal as proof of innocence.
    expect(String(failure.ctx!.impact)).toMatch(/claim by the sender|not covered by any signature/i);
  }, 60_000);

  /**
   * ⚠️ THESE THREE REPLACE ONE TEST WHOSE DECISIVE ASSERTION NEVER RAN — review F-B.
   *
   * It read `if (skipped.length > 0) expect(...)`, and `skipped` was ALWAYS empty: the auto-ack gate
   * has one production call site, inside the relay leaf handler behind
   * `leaf_kind === CTRL && !authored_by_us`, and the test only called `ingestReceivedContent`. So
   * the entire `content_tamper` vs `content_verification_unavailable` branch had no coverage
   * anywhere in the repo, and two mutants on it survived the full 4382-test gate — including
   * deleting the non-downgrade rule the test was named for.
   *
   * A conditional assertion is a wish. These drive the real gate and assert unconditionally.
   */
  it("★ a REAL tamper reaches the gate as content_tamper — the alarm the AC-008 rule keys on", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-alg-sec-alarm-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    await fx.snm.ingestReceivedContent(
      "alice", SID, CONTENT, wireContentHash(new TextEncoder().encode("different")), "corr",
    );
    fx.snm.runAutoAcknowledgeGateForTest("alice", SID);

    const skipped = fx.eventsNamed("session.seal.autoack.skipped");
    expect(skipped.length, "the gate must refuse to auto-co-sign").toBe(1);
    expect(skipped[0]!.ctx!.reason).toBe("content_tamper");
  }, 60_000);

  it("★ a VERSION SKEW reaches the same gate under a different name — refused, not alarmed", async () => {
    /**
     * The counterbalance, and the whole reason the label exists. Both refuse; only one is a security
     * claim. Emitting `content_tamper` for an honest peer on a newer build teaches an operator to
     * dismiss the alarm that matters.
     *
     * The name is also deliberately NOT `content_unverifiable` — that string is reserved for the
     * deferred "parked content unrecoverable" case, and reusing it would make the two
     * indistinguishable in the log the day that lands.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-alg-sec-skew-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    await fx.snm.ingestReceivedContent("alice", SID, CONTENT, wireContentHash(CONTENT), "corr", undefined, "junk-v1");
    fx.snm.runAutoAcknowledgeGateForTest("alice", SID);

    const skipped = fx.eventsNamed("session.seal.autoack.skipped");
    expect(skipped.length, "it must still refuse — the gate is binary").toBe(1);
    expect(skipped[0]!.ctx!.reason).toBe("content_verification_unavailable");
    expect(skipped[0]!.ctx!.reason, "an honest newer build must not raise the tamper alarm").not.toBe("content_tamper");
  }, 60_000);

  it("★ TAMPERED never downgrades — in BOTH orderings, and the second is the attacker's", async () => {
    /**
     * Ordering one is the obvious one: caught altering content, then send a junk algorithm name to
     * clear the alarm. Ordering two is the one review F-B pointed out was untested and is the one an
     * attacker would actually choose — send the cheap innocent-looking junk frame FIRST, then tamper,
     * hoping the earlier benign mark sticks.
     *
     * Asserting both is what pins the rule rather than the sequence I happened to think of.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-alg-sec-down-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);
    await fx.createSession(SID2, "alice", "bobpubkeyhex", PEER);

    // Tamper, then junk. The junk must NOT overwrite the tamper mark.
    await fx.snm.ingestReceivedContent(
      "alice", SID, CONTENT, wireContentHash(new TextEncoder().encode("different")), "corr",
    );
    await fx.snm.ingestReceivedContent("alice", SID, CONTENT, wireContentHash(CONTENT), "corr2", undefined, "junk-v1");
    fx.snm.runAutoAcknowledgeGateForTest("alice", SID);
    expect(
      fx.eventsNamed("session.seal.autoack.skipped").at(-1)!.ctx!.reason,
      "a junk algorithm name must not clear an alarm already raised",
    ).toBe("content_tamper");

    // Junk, then tamper — on a separate session so the two orderings cannot mask each other.
    await fx.snm.ingestReceivedContent("alice", SID2, CONTENT, wireContentHash(CONTENT), "corr3", undefined, "junk-v1");
    await fx.snm.ingestReceivedContent(
      "alice", SID2, CONTENT, wireContentHash(new TextEncoder().encode("different")), "corr4",
    );
    fx.snm.runAutoAcknowledgeGateForTest("alice", SID2);
    expect(
      fx.eventsNamed("session.seal.autoack.skipped").at(-1)!.ctx!.reason,
      "a tamper after a benign refusal must UPGRADE the mark, not be absorbed by it",
    ).toBe("content_tamper");
  }, 60_000);

  it("★ the seal-UPGRADE consumer draws the same distinction — the one the first fix missed", async () => {
    /**
     * Review F-A. The gate was made binary and the label moved into the log — in ONE consumer.
     * `evaluateSealUpgrade` had only a boolean to read, so it called every cause `content_tamper`,
     * at ERROR, with no guidance: an honest newer build raised a security alarm on B's reconnect.
     * That is the same defect the earlier fix was written to remove, at the consumer it did not check.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-alg-sec-upg-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);
    await fx.createSession(SID2, "alice", "bobpubkeyhex", PEER);

    await fx.snm.ingestReceivedContent("alice", SID, CONTENT, wireContentHash(CONTENT), "c", undefined, "junk-v1");
    await fx.snm.ingestReceivedContent(
      "alice", SID2, CONTENT, wireContentHash(new TextEncoder().encode("different")), "c",
    );

    const skew = evaluateSealUpgrade(fx.snm.getSealUpgradeReadiness("alice", SID));
    const tamper = evaluateSealUpgrade(fx.snm.getSealUpgradeReadiness("alice", SID2));
    // BOTH refuse — the kernel is unchanged and that is non-negotiable.
    expect(skew.proceed).toBe(false);
    expect(tamper.proceed).toBe(false);
    // And they refuse by DIFFERENT names, which is what decides ERROR-vs-WARN and what the operator
    // is sent to look for.
    expect(skew.proceed === false && skew.refuseReason).toBe("content_verification_unavailable");
    expect(tamper.proceed === false && tamper.refuseReason).toBe("content_tamper");
  }, 60_000);
});

describe("DOD-M15-SEALWIRE-1 part B1: the receiver can verify a SALTED frame once the salt is agreed", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  it("★ receiver-first, proven: a salted frame verifies against the salt the agreement produced", async () => {
    /**
     * The whole point of shipping the receiver before the sender. This side is now able to accept a
     * salted message even though nothing in this build sends one — which is what makes it safe for
     * part B2 to start salting later, and what would be missing if the order were reversed.
     *
     * The salt is the REAL one from the agreement (read back from the row), and the frame is hashed
     * the way a real counterparty holding the same salt would hash it.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-alg-f-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);
    await fx.snm.handleContentFrameForTest("alice", SID, saltFrame({ contribution: PEER_HALF }), PEER);
    await wait(200);

    const salt = agreedSalt(fx);
    const res = await fx.snm.ingestReceivedContent(
      "alice", SID, CONTENT, saltedContentHash(salt, CONTENT), "corr", undefined, CONTENT_HASH_ALGS.HMAC_SALT_V1,
    );
    expect(res.ok, "a salted frame must verify once the salt is agreed").toBe(true);
  }, 60_000);

  it("★ a salted frame hashed under a DIFFERENT salt is a mismatch — the salt actually binds", async () => {
    // Without this, "salted verifies" would pass for an implementation that ignored the salt.
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-alg-g-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);
    await fx.snm.handleContentFrameForTest("alice", SID, saltFrame({ contribution: PEER_HALF }), PEER);
    await wait(200);

    const wrongSalt = deriveSessionSalt(PEER_HALF, new Uint8Array(SALT_CONTRIBUTION_BYTES).fill(0x99));
    const res = await fx.snm.ingestReceivedContent(
      "alice", SID, CONTENT, saltedContentHash(wrongSalt, CONTENT), "corr", undefined, CONTENT_HASH_ALGS.HMAC_SALT_V1,
    );
    expect(res.ok).toBe(false);
    expect(res.ok === false && res.reason).toBe("content_hash_mismatch");
  }, 60_000);

  it("★ THE DAEMON READS THE FIELD OFF THE FRAME — not from its own state", async () => {
    /**
     * The wiring assertion, and the mutant it kills: drop `content_hash_alg` from the frame read in
     * the content-stream handler and every test above still passes, because they call
     * `ingestReceivedContent` directly. Only a frame driven through the REAL handler can prove the
     * field is plumbed.
     *
     * A daemon that decided salted-vs-unsalted from `content_salt IS NOT NULL` instead of from the
     * frame would pass the salted cases and fail here — which is the substantive error, not a
     * plumbing detail: whether a hash is salted is a fact about the SENDER, and this side holding a
     * salt says nothing about whether they used it.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-alg-h-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);
    await fx.snm.handleContentFrameForTest("alice", SID, saltFrame({ contribution: PEER_HALF }), PEER);
    await wait(200);
    expect(agreedSalt(fx).length, "precondition: this side holds a salt").toBe(32);

    // The peer has NOT upgraded: it sends an unsalted hash and names nothing. A daemon reading its
    // own row would salt the comparison and refuse this.
    await fx.snm.handleContentFrameForTest(
      "alice", SID, contentFrame({ content_hash: wireContentHash(CONTENT) }), PEER,
    );
    await wait(300);

    const failures = fx.eventsNamed("session.content.cross_check.failed");
    expect(
      failures.length,
      "holding a salt must not make us reject a peer that did not use one — the frame decides, not our row",
    ).toBe(0);
  }, 60_000);

  it("★ an explicit CBOR null in the field is LEGACY, and a number is refused as a non-string", async () => {
    /**
     * The seventh mutant, and it survived all twenty tests: change the frame read from a pass-through
     * to `String(declaredAlg)`. The pure tests exercise `resolveContentHashAlg(null)` and
     * `resolveContentHashAlg(42)` DIRECTLY, and every wired test put a string in the field — so
     * nothing covered the boundary where an arbitrary CBOR value crosses into the resolver.
     *
     * Both halves of the mutant are wrong in ways that matter. `null` is legacy-equivalent and must
     * be accepted; coerced it becomes `"null"` and the peer is refused. A number must be reported as
     * `(number)` so the operator sees a SHAPE problem; coerced it becomes the plausible-looking
     * `"42"`, which reads like a real algorithm name they should go and look up.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-alg-j-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    // Explicit null — a peer that encoded the field but left it empty. Legacy, so it must ingest.
    await fx.snm.handleContentFrameForTest(
      "alice", SID, contentFrame({ content_hash: wireContentHash(CONTENT), content_hash_alg: null }), PEER,
    );
    await wait(300);
    expect(
      fx.eventsNamed("session.content.cross_check.failed").length,
      "an explicit null must mean the same as an absent field, not the string \"null\"",
    ).toBe(0);

    // A number — not a name at all. Refused, and the log must say it was the wrong SHAPE.
    await fx.snm.handleContentFrameForTest(
      "alice", SID, contentFrame({ content_hash: wireContentHash(CONTENT), content_hash_alg: 42 }), PEER,
    );
    await wait(300);
    const failure = fx.eventsNamed("session.content.cross_check.failed").at(-1);
    expect(failure!.ctx!.reason).toBe("content_hash_alg_unknown");
    expect(
      failure!.ctx!.declaredAlg,
      "a coerced \"42\" reads like a real algorithm name; the operator must see it was not a string at all",
    ).toBe("(number)");
  }, 60_000);

  it("★ an unknown algorithm arriving on the REAL stream is refused there too", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-alg-i-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    await fx.snm.handleContentFrameForTest(
      "alice", SID,
      contentFrame({ content_hash: wireContentHash(CONTENT), content_hash_alg: "sha3-512-v2" }),
      PEER,
    );
    await wait(300);

    const failure = fx.eventsNamed("session.content.cross_check.failed").at(-1);
    expect(failure, "the handler must plumb the field, not drop it").toBeDefined();
    expect(failure!.ctx!.reason).toBe("content_hash_alg_unknown");
    expect(failure!.ctx!.declaredAlg).toBe("sha3-512-v2");
  }, 60_000);
});
