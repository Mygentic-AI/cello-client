/**
 * "I CANNOT ADOPT" IS NOT "I HOLD NONE" — `DOD-M15-SALTSPLIT-1`, review pass 1, HIGH-1.
 *
 * ─── This is a regression I introduced, and it is worse than the defect it fixed ───────────────
 *
 * `DOD-M15-SALTSPLIT-1` made a side drop its salt when the peer announces `adoption_closed`. The
 * safety argument underneath it was *"the peer told us it can never adopt a salt, therefore the peer
 * holds none."* **That inference is false**, and on one reachable path the discard destroys a live,
 * agreed, MATCHING salt — manufacturing exactly the user-visible failure the unit exists to prevent.
 *
 * `adoption_closed: already_hashing` does not mean "I hold no salt". It means "I cannot adopt a NEW
 * one, because I have already hashed content." A side that holds salt S **and has spent it** says
 * precisely that when asked — because `onPeerSaltFrame` tests `ownAdoption.closed` BEFORE it tests
 * `ownSalt`. So it answers a matching fingerprint for the salt it is holding with a frame that reads,
 * to the receiver, as "I have nothing."
 *
 * ─── What a user lives through, and it is a session that USED to work ─────────────────────────
 *
 * 1. A and B agree salt S at session open. Both hold it. Nothing is wrong.
 * 2. A sends the first message. A leafs it — so A's frontier moves and A's adoption closes.
 *    Direct delivery fails (B is offline), so it parks.
 * 3. B comes online and announces its fingerprint of S — the ordinary reconnect handshake.
 * 4. A answers `adoption_closed: already_hashing`. True about ADOPTION, and read as "A holds none".
 * 5. B's adoption is still open, so B discards S — row and cache.
 * 6. **From here A hashes salted forever and B refuses every message A sends.** A's parked first
 *    message is refused on every drain and its operator is told to close the session.
 *
 * **Before `f7f742a` this session worked.** Nothing cleared B's salt, so the mismatch never arose.
 *
 * And the trigger is not exotic: any `#saltAdoptionClosed` throw on A — a retired agent, one
 * transient SQLCipher read error — returns `closed: true` with `frontier_unreadable` and announces
 * the same terminal label. **A momentary read failure on one machine would permanently destroy
 * durable key material on the other.**
 *
 * ─── The fix is precedence, not a new guard ──────────────────────────────────────────────────
 *
 * A side that already HOLDS a salt has nothing to adopt, so the adoption question does not apply to
 * it at all. `ownSalt` is answered first; `ownAdoption.closed` only decides for a side holding
 * nothing. That deletes the misleading announce at its source rather than teaching every receiver to
 * distrust it.
 */

import { describe, it, expect } from "vitest";
import { onPeerSaltFrame, SALT_ADOPTION_LABELS } from "../session-salt-agreement.js";
import { saltFingerprint, SESSION_SALT_BYTES } from "@cello-protocol/crypto";

/** The one salt both sides agreed. */
const S = new Uint8Array(SESSION_SALT_BYTES).fill(0x21);

describe("DOD-M15-SALTSPLIT-1 HIGH-1: a side holding a salt never announces that it holds none", () => {
  it("★★ SPENT + HOLDING + a matching fingerprint is CONFIRMED, not adoption_closed", () => {
    /**
     * A's chair, step 4 above. A holds S, A has leafed a message, B offers `fingerprint(S)`.
     *
     * The two sides agree. The only correct answer is that they agree.
     */
    const action = onPeerSaltFrame({
      ownSalt: S,
      ownContribution: null,
      ownAdoption: { closed: true, label: SALT_ADOPTION_LABELS.ALREADY_HASHING, why: "1 leaf" },
      frame: { fingerprint: saltFingerprint(S) },
    });

    expect(
      action.action,
      "A holds the very salt B is asking about. Answering `adoption_closed` tells B that A has " +
      "nothing — and B then erases its own copy of the SAME salt, splitting a session that worked.",
    ).toBe("confirmed");
  });

  it("★★ THE FULL EXCHANGE — B must not be told to throw away the salt it shares with A", () => {
    /**
     * Both halves, run end to end, because the damage is only visible across the pair: A's answer is
     * wrong, and B's response to it is CORRECT given what it was told. Neither side is
     * misbehaving — the frame is.
     */
    const aAnswer = onPeerSaltFrame({
      ownSalt: S,
      ownContribution: null,
      ownAdoption: { closed: true, label: SALT_ADOPTION_LABELS.ALREADY_HASHING, why: "1 leaf" },
      frame: { fingerprint: saltFingerprint(S) },
    });

    expect(
      "announce" in aAnswer ? aAnswer.announce?.adoptionClosed : undefined,
      "nothing may go on the wire saying A cannot hold a salt while A is holding one",
    ).toBeUndefined();

    // B's chair: whatever A sends, B must not end up discarding a salt A is still using. B only
    // discards on a terminal frame, so proving A never sends one proves B keeps S.
    const bSees = onPeerSaltFrame({
      ownSalt: S,
      ownContribution: null,
      ownAdoption: { closed: false },
      frame: "announce" in aAnswer && aAnswer.announce ? aAnswer.announce : { fingerprint: saltFingerprint(S) },
    });
    expect(
      bSees.action,
      "B holds the same salt and its adoption is open — the exchange must settle as agreement, " +
      "never as the terminal branch that makes B erase durable key material",
    ).not.toBe("adoption_closed");
  });

  it("★ A SIDE HOLDING NOTHING STILL CLOSES — the fix must not disable the real terminal case", () => {
    /**
     * The anchor, and the thing a naive precedence swap breaks. Adoption genuinely closed AND no
     * salt held is the case the terminal branch was built for: it must still announce, or two sides
     * sit waiting for an agreement neither can complete.
     */
    const action = onPeerSaltFrame({
      ownSalt: null,
      ownContribution: null,
      ownAdoption: { closed: true, label: SALT_ADOPTION_LABELS.ALREADY_HASHING, why: "3 leaves" },
      frame: { contribution: new Uint8Array(32).fill(0x44) },
    });

    expect(action.action, "no salt and no way to adopt one is exactly what this branch is for").toBe("adoption_closed");
  });

  it("★ AND A PEER THAT REALLY CLOSED STILL ENDS THE EXCHANGE for a side holding nothing", () => {
    // The other half of the anchor: the receiver's terminal path must survive too, or the
    // convergence this whole line delivers stops working.
    const action = onPeerSaltFrame({
      ownSalt: null,
      ownContribution: null,
      ownAdoption: { closed: false },
      frame: { adoptionClosed: SALT_ADOPTION_LABELS.ALREADY_HASHING },
    });

    expect(action.action, "we hold nothing and they can never adopt — terminal, and both know it").toBe("adoption_closed");
  });
});
