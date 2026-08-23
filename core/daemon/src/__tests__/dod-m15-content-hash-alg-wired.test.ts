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
import { deriveSessionSalt, saltedContentHash, SALT_CONTRIBUTION_BYTES } from "@cello-protocol/crypto";
import { encodeCbor } from "@cello-protocol/protocol-types";
import * as lp from "it-length-prefixed";

const SID = "ef".repeat(32);
const PEER = "12D3KooWQYV9dGMFoRzNStwpXztXaBUjtPqi6aMghfATmPnRAENn";
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));
const CONTENT = new TextEncoder().encode("the number is 4200");
const PEER_HALF = new Uint8Array(SALT_CONTRIBUTION_BYTES).fill(0x5c);

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
    expect(String(failure.ctx!.impact), "it must say plainly that this is not tampering").toMatch(/version difference, not tampering/);
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
    expect(String(fx.eventsNamed("session.content.cross_check.failed").at(-1)!.ctx!.impact)).toMatch(/Nothing was altered/);
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
