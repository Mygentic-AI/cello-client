/**
 * WHAT MAY WE ASSUME ABOUT A PEER THAT AGREED A SALT — `DOD-M15-SEALWIRE-1` bullet 6, part B2b-2,
 * constraint 4. Inherited from B2a review F6.
 *
 * ─── The constraint said "do NOT infer peer capability from the salt agreement" ─────────────────
 *
 * The worry was concrete and correct. Once a session salts, its parked copies become **v3** park
 * envelopes — the version that carries the algorithm name. A peer that agreed a salt but cannot
 * DECODE v3 refuses every one of them as `unsigned_envelope`, which is the **attacker** shape: it
 * does not drop the entry, it keeps re-pulling it, forever, while telling its operator it is being
 * attacked. The two features landed in separate commits, so a build cut between them would have the
 * agreement without the decoder.
 *
 * ─── Checked, and that build does not exist ────────────────────────────────────────────────────
 *
 * Both commits are in **no git tag** — the agreement (`b08e69b`) and the v3 decoder (`a59a041`)
 * alike. Neither has ever been released, and since the decoder is the later of the two, the next
 * release contains both. The interval build was never cut, so nobody is running one.
 *
 * That makes **"the agreement completed" a sound capability signal** — but only for as long as the
 * two remain inseparable, and that is not a property anything currently checks. Hence this file. It
 * does not add a handshake for a hazard that cannot occur; it makes the assumption the hazard's
 * absence rests on **falsifiable**, so that separating them later goes red here instead of silently
 * arming the attacker-shaped refusal.
 *
 * ─── And the OLD peer, which is the case that will actually happen ─────────────────────────────
 *
 * Every published build (0.0.156 and earlier) has neither feature. Verified against the last tag:
 * an unrecognised frame type on the content stream is logged and returned from — not an error, not
 * a stream close. So a salt frame reaching an old peer produces one WARN line on their side and
 * nothing else, no agreement is ever reached, and this side must therefore stay unsalted. That is
 * the fallback constraint 1 is built on, and it is asserted here because it is what makes the
 * capability signal safe rather than merely convenient.
 */

import { describe, it, expect, afterEach } from "vitest";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import { encodeCbor } from "@cello-protocol/protocol-types";
import { SALT_CONTRIBUTION_BYTES, generateKeypair } from "@cello-protocol/crypto";
import { decodeParkEnvelope, encodeParkEnvelope, authenticateParkedEntry, PARK_ENVELOPE_VERSION_ALG } from "../park-envelope.js";
import { buildParkContentTbs } from "@cello-protocol/protocol-types";
import { CONTENT_HASH_ALGS } from "../wire-content-hash.js";
import * as lp from "it-length-prefixed";

const SID = "3d".repeat(32);
const PEER = "12D3KooWQYV9dGMFoRzNStwpXztXaBUjtPqi6aMghfATmPnRAENn";
const PEER_HALF = new Uint8Array(SALT_CONTRIBUTION_BYTES).fill(0x2b);
const RECIPIENT = Uint8Array.from(Buffer.from("cd".repeat(32), "hex"));
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

function saltFrame(): Uint8Array {
  return lp.encode.single(encodeCbor({
    type: "session_salt_agreement", session_id: SID, contribution: PEER_HALF,
  }) as Uint8Array).subarray();
}

/** A frame type no build has ever known — what an OLD peer sees when a new one salts. */
function unknownFrame(): Uint8Array {
  return lp.encode.single(encodeCbor({
    type: "session_salt_agreement_v9_from_the_future", session_id: SID,
  }) as Uint8Array).subarray();
}

function storedSalt(fx: TwoConnectionFixture): Uint8Array | null {
  const agentId = (fx.snm.getDb().prepare("SELECT agent_id FROM agents WHERE agent_name = ?").get("alice") as { agent_id: string }).agent_id;
  const row = fx.snm.getDb()
    .prepare("SELECT content_salt FROM sessions WHERE agent_id = ? AND session_id = ?")
    .get(agentId, SID) as { content_salt: Uint8Array | null } | undefined;
  return row?.content_salt ? new Uint8Array(row.content_salt) : null;
}

describe("DOD-M15-SEALWIRE-1 B2b-2 constraint 4: the agreement is the capability signal, and here is why that is safe", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  it("★ a build that can AGREE a salt can also READ a v3 park envelope — the pairing the signal rests on", async () => {
    /**
     * ⚠️ THE GUARD THIS FILE EXISTS FOR.
     *
     * The whole argument for treating "they agreed" as "they can read v3" is that the two shipped
     * together and cannot be had separately. Nothing enforced that. If a later change puts the v3
     * decoder behind a flag, or drops v3 while leaving the agreement in place, that argument becomes
     * false in silence — and the consequence is not a degraded hash, it is a peer re-pulling a
     * message forever and reporting an attack.
     *
     * Asserted BEHAVIOURALLY, on one running daemon: the same build that reaches an agreement is
     * handed a v3 envelope and must read the algorithm back out of it. Checking that both source
     * files exist would pass on a build where the decoder is compiled in and never reached.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-cap-pair-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    await fx.snm.handleContentFrameForTest("alice", SID, saltFrame(), PEER);
    await wait(200);
    expect(storedSalt(fx), "precondition: this build must actually be able to agree a salt").not.toBeNull();

    /**
     * ⚠️ MEASURED. The first version of this test asserted `decodeParkEnvelope` and TWO mutants
     * survived it — dropping v3 from the signed-version set, and blanking the decoded algorithm.
     * A guard written to protect the pairing did not protect it, on its first run.
     *
     * The mistake was asserting the wrong function. `unsigned_envelope` — the attacker-shaped
     * refusal that re-pulls forever — is produced by `authenticateParkedEntry`, not by the decoder.
     * A build can decode a v3 envelope perfectly and still refuse it, which is exactly the failure,
     * so the decoder's own verdict says nothing about whether the mail arrives.
     *
     * Round-tripped through the REAL producer and the REAL authenticator, with a REAL signature, so
     * the assertion is "the mail is accepted", not "the bytes parse".
     */
    const kp = generateKeypair();
    const senderPubkey = await kp.getPublicKey();
    const content = new TextEncoder().encode("a salted message's parked copy");
    const contentHash = Uint8Array.from(Buffer.from("7f".repeat(32), "hex"));
    const v3 = encodeParkEnvelope({
      content,
      senderPubkey,
      parkSig: await kp.sign(buildParkContentTbs(SID, RECIPIENT, contentHash)),
      contentHashAlg: CONTENT_HASH_ALGS.HMAC_SALT_V1,
    });

    const decoded = decodeParkEnvelope(v3);
    /**
     * ⚠️ PIN THE VERSION FIRST, and this line is here because its absence hid the bug twice.
     *
     * The first two revisions of this test wrote `CONTENT_HASH_ALGS.HMAC_SHA256_SALT_V1` — a key
     * that does not exist (it is `HMAC_SALT_V1`). It evaluated to `undefined`, the encoder took the
     * **v2** branch, and the test never encoded a v3 envelope at all. Both mutants survived because
     * neither touches v2, and the closing assertion compared `undefined` to `undefined` and passed.
     *
     * A test that names a version in its title must assert it got one. Everything below is about v3
     * and means nothing if the bytes are v2.
     */
    expect(
      decoded?.version,
      "the envelope under test must actually BE v3 — a v2 envelope passes every assertion below while testing none of them",
    ).toBe(PARK_ENVELOPE_VERSION_ALG);

    const verdict = authenticateParkedEntry({
      env: decoded!,
      sessionIdHex: SID,
      recipientPubkey: RECIPIENT,
      contentHash,
      counterpartyPubkeyHex: Buffer.from(senderPubkey).toString("hex"),
    });
    expect(
      verdict,
      "a build that agrees salts but refuses its own v3 envelopes reports an ATTACK and re-pulls the entry forever — it never confirm-deletes it",
    ).toEqual({ ok: true });
    expect(
      decoded?.contentHashAlg,
      "and it must read the algorithm back out, or it verifies the message under the wrong rule and reports a tamper on a message nobody touched",
    ).toBe(CONTENT_HASH_ALGS.HMAC_SALT_V1);
  }, 60_000);

  it("★ a peer that does not speak the agreement leaves the session UNSALTED — no agreement, no salt", async () => {
    /**
     * The case that will actually happen: every published build predates both features. Verified
     * against the last release tag — an unrecognised frame type on the content stream is logged and
     * returned from, never an error and never a stream close — so a salt frame reaching an old peer
     * costs them one WARN line and produces no reply at all.
     *
     * This side must therefore stay unsalted, which is exactly what makes "they agreed" a usable
     * signal: silence is a NO, not a maybe. Driven with a frame type no build knows, which is what
     * this side's own frames look like to a peer that predates them.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-cap-old-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    await fx.snm.handleContentFrameForTest("alice", SID, unknownFrame(), PEER);
    await wait(200);

    expect(
      storedSalt(fx),
      "an unanswered agreement must not produce a salt — a side that salts alone sends messages its counterparty can never verify",
    ).toBeNull();
    expect(
      fx.eventsNamed("session.salt.agreed").length,
      "and it must not BELIEVE it agreed one either",
    ).toBe(0);
  }, 60_000);

  it("★ and the unknown frame is REPORTED, not swallowed — the old peer's side of the same exchange", async () => {
    /**
     * This is what the counterparty's log will show, and it is the only trace either operator gets
     * of a version mismatch. A silent drop here would make "my counterparty is on an old build" and
     * "the message never arrived" indistinguishable — and those have completely different fixes.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-cap-report-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    await fx.snm.handleContentFrameForTest("alice", SID, unknownFrame(), PEER);
    await wait(200);

    const seen = fx.eventsNamed("session.content.frame_unknown_type");
    expect(seen.length, "a frame we do not understand must leave a trace").toBe(1);
    expect(
      String(seen[0]!.ctx!["type"]),
      "and must name WHICH frame, or the operator cannot tell which feature their peer is missing",
    ).toBe("session_salt_agreement_v9_from_the_future");
  }, 60_000);
});
