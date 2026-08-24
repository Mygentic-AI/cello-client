/**
 * DOD-M15-HASHCORRELATE-1 — THE LINK NOBODY HAD WRITTEN.
 *
 * ─── The exposure, in the relay's chair ────────────────────────────────────────────────────────
 *
 * `wireContentHash(content) = SHA-256(0x00 ‖ content)` had nothing session-specific in it, so the
 * same message text produced the same 32 bytes in every conversation, between every pair of agents,
 * forever. A relay could correlate a message across sessions and across agent pairs, and — because
 * most traffic is short and predictable — precompute a table of common messages once and read it
 * everywhere. "yes". "approved". A name.
 *
 * ─── Why this file exists, when four other tests already cover the property ────────────────────
 *
 * Closing the exposure is a chain of four links, and I claimed the whole chain was untested. It is
 * not — three of the four were covered before I touched anything:
 *
 *   1. a FRESH contribution is minted per session          ← **nothing tested this**
 *   2. two fresh contributions → two different salts       — `dod-m15-session-salt.test.ts:62`
 *   3. different salts → different hashes                  — `…:147`, `…-wired.test.ts:569`
 *   4. the daemon actually hashes salted when it holds one — `dod-m15-send-consults-the-salt.test.ts:62`
 *
 * Link 1 is a daemon concern and none of the crypto tests can see it: they are handed salts as
 * parameters. `#saltContributionFor` caches on `(agentName, sessionId)` — **drop `sessionId` from
 * that key and every session between the same two agents shares one salt forever.** The correlation
 * exposure returns in full for that pair, and every crypto test, every wired test and every
 * assertion in `dod-m15-content-hash-alg.test.ts` stays GREEN, because the salt they are handed is
 * still a fine salt. It is simply the same one.
 *
 * ─── The design of the assertion, which is the load-bearing part ───────────────────────────────
 *
 * Both sessions are fed the **IDENTICAL peer contribution.** That is deliberate and it is what gives
 * the test teeth: with the peer's half held constant, the only thing that can make the two salts
 * differ is OUR OWN half being freshly minted per session. Vary both halves and the test passes for
 * the wrong reason — the peer would be doing the work, and a daemon that reused its own contribution
 * forever would sail through.
 *
 * It is also the real adversary. A peer that reuses a fixed contribution is not hypothetical; it is
 * how you would ATTACK this, and `dod-m15-session-salt.test.ts:70` covers the same idea one layer
 * down at the derivation. This is that adversary against the live daemon.
 */

import { describe, it, expect, afterEach } from "vitest";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import { encodeCbor } from "@cello-protocol/protocol-types";
import { SALT_CONTRIBUTION_BYTES } from "@cello-protocol/crypto";
import * as lp from "it-length-prefixed";

const SID_A = "aa".repeat(32);
const SID_B = "bb".repeat(32);
const PEER = "12D3KooWQYV9dGMFoRzNStwpXztXaBUjtPqi6aMghfATmPnRAENn";

/** ONE peer half, used for BOTH sessions — see the header. */
const PEER_HALF = new Uint8Array(SALT_CONTRIBUTION_BYTES).fill(0x5c);

/** The message a relay would look for: short, ordinary, and the same in both conversations. */
const BODY = new TextEncoder().encode("approved");

const wait = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

function saltFrame(sessionId: string): Uint8Array {
  return lp.encode.single(encodeCbor({
    type: "session_salt_agreement", session_id: sessionId, contribution: PEER_HALF,
  }) as Uint8Array).subarray();
}

describe("DOD-M15-HASHCORRELATE-1 — one message, two sessions, two different fingerprints", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  async function saltedSession(sessionId: string): Promise<void> {
    await fx!.createSession(sessionId, "alice", "bobpubkeyhex", PEER);
    await fx!.snm.handleContentFrameForTest("alice", sessionId, saltFrame(sessionId), PEER);
    await wait(200);
    expect(
      fx!.snm.getSessionContentSalt("alice", sessionId),
      `precondition: session ${sessionId.slice(0, 4)}… must hold an agreed salt, or this test is ` +
        "asserting something about the unsalted path by accident",
    ).not.toBeNull();
  }

  it("★ THE LINK: the same body in two sessions hashes to different bytes, with the peer's half held CONSTANT", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-hashcorr-" });
    await saltedSession(SID_A);
    await saltedSession(SID_B);

    const a = await fx.snm.contentHashForSession("alice", SID_A, BODY);
    const b = await fx.snm.contentHashForSession("alice", SID_B, BODY);

    // Both must actually BE salted — otherwise two unsalted hashes would be equal and this would
    // fail for the right-looking wrong reason, or two fallbacks could differ for some other cause.
    expect(a.alg, "session A must be hashing salted").toBe("hmac-sha256-salt-v1");
    expect(b.alg, "session B must be hashing salted").toBe("hmac-sha256-salt-v1");

    expect(
      hex(a.hash),
      "a relay holding BOTH conversations must not be able to tell these are the same message. The " +
        "peer contributed identical bytes to each, so if these hashes match, this daemon reused its " +
        "OWN contribution across sessions and the correlation exposure is live for this pair",
    ).not.toBe(hex(b.hash));
  });

  it("★ and the salts themselves differ — naming the cause, not just the symptom", async () => {
    /**
     * Asserted separately so a failure says WHICH link broke. If the hashes match, this line tells
     * the next reader whether the salts were equal (link 1 — the contribution was reused) or the
     * salts differed and the hashing ignored them (link 3/4). Without it, a red hash assertion sends
     * someone to read the HMAC code when the defect is a cache key.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-hashcorr-salt-" });
    await saltedSession(SID_A);
    await saltedSession(SID_B);

    const saltA = fx.snm.getSessionContentSalt("alice", SID_A)!;
    const saltB = fx.snm.getSessionContentSalt("alice", SID_B)!;
    expect(
      hex(saltA),
      "the two sessions must not share a salt — with the peer's half identical, equal salts mean " +
        "our own contribution was minted once and reused",
    ).not.toBe(hex(saltB));
  });

  it("★ WITHIN one session the same body still hashes identically — this is unlinkability, not randomness", async () => {
    /**
     * The direction that would break everything else if it were wrong. Dedup, ordering and the
     * tamper cross-check all depend on the same bytes producing the same hash inside a session. A
     * per-call random value would satisfy the two assertions above and destroy the protocol.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-hashcorr-same-" });
    await saltedSession(SID_A);

    const first = await fx.snm.contentHashForSession("alice", SID_A, BODY);
    const second = await fx.snm.contentHashForSession("alice", SID_A, BODY);
    expect(hex(first.hash), "the same message in the same session is the same hash").toBe(hex(second.hash));
  });
});
