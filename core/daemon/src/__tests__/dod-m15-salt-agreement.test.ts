/**
 * THE SALT AGREEMENT — `DOD-M15-SEALWIRE-1` bullet 6, part A (Decisions Carried #8 and #10).
 *
 * The salt primitive can combine two contributions. This is the part that decides WHAT A FRAME
 * MEANS: who is expected to send what, when the two sides have converged, and — the half Decision
 * #10 is entirely about — when they have PROVABLY diverged and the session must stop rather than
 * limp.
 *
 * ─── The shape being tested, and why every branch is a refusal or a convergence ────────────────
 *
 * Exactly one of `contribution` / `fingerprint` rides each frame, and which one is present IS the
 * sender's state:
 *
 *   `contribution` present → "I hold no salt for this session; here is my half."
 *   `fingerprint`  present → "I already hold a salt; here is a one-way digest of it."
 *
 * That makes the four combinations exhaustive, and two of them are disagreements no retry can fix:
 * a side that holds a salt and a side that does not cannot converge, because the salt is a function
 * of two contributions that the holder no longer keeps. Saying so out loud is the whole point —
 * the alternative is the silent-discard loop `wire-content-hash.ts` already cost two daemons.
 */

import { describe, it, expect } from "vitest";
import {
  onPeerSaltFrame,
  ownSaltFrame,
  SALT_FREEZE_REASONS,
  SALT_FREEZE_GUIDANCE,
} from "../session-salt-agreement.js";
import { deriveSessionSalt, saltFingerprint, SALT_CONTRIBUTION_BYTES } from "@cello-protocol/crypto";

const OURS = new Uint8Array(SALT_CONTRIBUTION_BYTES).fill(0xa1);
const THEIRS = new Uint8Array(SALT_CONTRIBUTION_BYTES).fill(0xb2);
const AGREED = deriveSessionSalt(OURS, THEIRS);

describe("Decision #8: two fresh sides converge on one salt", () => {
  it("★ a peer contribution makes us derive, and the salt is the one the primitive defines", () => {
    const action = onPeerSaltFrame({ ownSalt: null, ownContribution: OURS, frame: { contribution: THEIRS } });
    expect(action.action).toBe("derive_and_announce");
    expect(action.action === "derive_and_announce" && Buffer.from(action.salt).toString("hex"))
      .toBe(Buffer.from(AGREED).toString("hex"));
  });

  it("★ BOTH SIDES REACH THE SAME BYTES — the test the whole exchange exists to make true", () => {
    /**
     * Run the machine from each side's point of view, with the roles swapped. This is the property
     * a per-side test cannot see: `deriveSessionSalt` sorts its inputs, so a side-agnostic
     * derivation is exactly what makes "who sent first" irrelevant. If the machine ever passed its
     * own contribution and the peer's in a role-dependent order, one of these two would move.
     */
    const us = onPeerSaltFrame({ ownSalt: null, ownContribution: OURS, frame: { contribution: THEIRS } });
    const them = onPeerSaltFrame({ ownSalt: null, ownContribution: THEIRS, frame: { contribution: OURS } });
    expect(us.action === "derive_and_announce" && Buffer.from(us.salt).toString("hex"))
      .toBe(them.action === "derive_and_announce" ? Buffer.from(them.salt).toString("hex") : "different");
  });

  it("★ the announcement carries the FINGERPRINT, never the salt — and the salt's bytes are absent", () => {
    /**
     * Decision #10 says compare a fingerprint, never the salt. The frame goes out over a stream a
     * relay forwards, so this is not stylistic: publishing the salt would hand the correlation
     * attack back to exactly the party the salt is defending against.
     */
    const action = onPeerSaltFrame({ ownSalt: null, ownContribution: OURS, frame: { contribution: THEIRS } });
    if (action.action !== "derive_and_announce") throw new Error("expected derive_and_announce");
    expect(Buffer.from(action.fingerprint).toString("hex")).toBe(Buffer.from(saltFingerprint(AGREED)).toString("hex"));
    // The announcement frame itself must not contain the salt anywhere in it.
    const frame = ownSaltFrame({ ownSalt: action.salt, ownContribution: OURS });
    expect(frame.contribution, "a side that HOLDS a salt must not re-offer a contribution").toBeUndefined();
    expect(Buffer.from(JSON.stringify(Array.from(frame.fingerprint ?? []))).includes(Buffer.from(AGREED)))
      .toBe(false);
    expect(frame.fingerprint!.length).toBeLessThan(AGREED.length);
  });
});

describe("Decision #10: a fingerprint that disagrees stops the session", () => {
  it("★ matching fingerprints confirm, and nothing further is sent", () => {
    const action = onPeerSaltFrame({ ownSalt: AGREED, ownContribution: OURS, frame: { fingerprint: saltFingerprint(AGREED) } });
    expect(action.action).toBe("confirmed");
  });

  it("★ a DIFFERING fingerprint freezes with a named reason", () => {
    const otherSalt = deriveSessionSalt(OURS, new Uint8Array(SALT_CONTRIBUTION_BYTES).fill(0xc3));
    const action = onPeerSaltFrame({ ownSalt: AGREED, ownContribution: OURS, frame: { fingerprint: saltFingerprint(otherSalt) } });
    expect(action.action).toBe("freeze");
    expect(action.action === "freeze" && action.reason).toBe(SALT_FREEZE_REASONS.FINGERPRINT_MISMATCH);
  });

  it("★ a fingerprint of the WRONG LENGTH is a disagreement, not something to pad or truncate", () => {
    // The shape a version skew takes: a peer computing a different-width digest. Comparing a
    // prefix would let two sides that agree on 8 of 16 bytes call it a match.
    const action = onPeerSaltFrame({
      ownSalt: AGREED, ownContribution: OURS,
      frame: { fingerprint: saltFingerprint(AGREED).slice(0, 4) },
    });
    expect(action.action).toBe("freeze");
    expect(action.action === "freeze" && action.reason).toBe(SALT_FREEZE_REASONS.FINGERPRINT_MISMATCH);
  });
});

describe("Decision #8: the two states that cannot converge say so", () => {
  it("★ we hold a salt and the peer offers a contribution — unrecoverable, and refused", () => {
    /**
     * The restart case, from the side whose record SURVIVED. The peer is starting the agreement
     * over, which means their salt is gone; ours cannot be re-derived for them, because the salt is
     * a one-way function of two contributions and neither of us keeps the inputs.
     *
     * Answering with our fingerprint would be worse than refusing: they would compare it against a
     * salt they do not have, and the session would sit in a half-agreed state whose only symptom is
     * discarded messages.
     */
    const action = onPeerSaltFrame({ ownSalt: AGREED, ownContribution: OURS, frame: { contribution: THEIRS } });
    expect(action.action).toBe("freeze");
    expect(action.action === "freeze" && action.reason).toBe(SALT_FREEZE_REASONS.STATE_DIVERGENT);
  });

  it("★ we hold NO salt and the peer announces a fingerprint — the same divergence, other side", () => {
    const action = onPeerSaltFrame({ ownSalt: null, ownContribution: OURS, frame: { fingerprint: saltFingerprint(AGREED) } });
    expect(action.action).toBe("freeze");
    expect(action.action === "freeze" && action.reason).toBe(SALT_FREEZE_REASONS.STATE_DIVERGENT);
  });

  it("★ BOTH SIDES REACH THE SAME VERDICT on a divergence — neither one limps on", () => {
    // A refusal only one side makes leaves the other sending into a session that is gone. Both
    // halves of the divergent pair must freeze, or the loud failure is only half loud.
    const survivor = onPeerSaltFrame({ ownSalt: AGREED, ownContribution: OURS, frame: { contribution: THEIRS } });
    const restarted = onPeerSaltFrame({ ownSalt: null, ownContribution: THEIRS, frame: { fingerprint: saltFingerprint(AGREED) } });
    expect(survivor.action).toBe("freeze");
    expect(restarted.action).toBe("freeze");
  });
});

describe("Decision #8: a degenerate peer contribution is refused, not absorbed", () => {
  it("★ an all-zero contribution freezes rather than deriving a salt one side chose", () => {
    const action = onPeerSaltFrame({
      ownSalt: null, ownContribution: OURS,
      frame: { contribution: new Uint8Array(SALT_CONTRIBUTION_BYTES) },
    });
    expect(action.action).toBe("freeze");
    expect(action.action === "freeze" && action.reason).toBe(SALT_FREEZE_REASONS.CONTRIBUTION_DEGENERATE);
  });

  it("★ a short contribution freezes — a padded one is a salt we did not really help choose", () => {
    const action = onPeerSaltFrame({
      ownSalt: null, ownContribution: OURS,
      frame: { contribution: new Uint8Array(8).fill(0x7f) },
    });
    expect(action.action).toBe("freeze");
    expect(action.action === "freeze" && action.reason).toBe(SALT_FREEZE_REASONS.CONTRIBUTION_DEGENERATE);
  });

  it("★ a REFLECTED contribution freezes — the peer echoing our own half is not an exchange", () => {
    const action = onPeerSaltFrame({ ownSalt: null, ownContribution: OURS, frame: { contribution: OURS } });
    expect(action.action).toBe("freeze");
    expect(action.action === "freeze" && action.reason).toBe(SALT_FREEZE_REASONS.CONTRIBUTION_DEGENERATE);
  });

  it("★ the refusal's DETAIL carries the primitive's own sentence, not a substituted one", () => {
    /**
     * Invariant 2, error substitution. The primitive refuses with a paragraph explaining what a
     * zero contribution means for both parties; a state machine that catches the throw and replaces
     * it with "invalid contribution" destroys the only explanation that exists.
     */
    const action = onPeerSaltFrame({
      ownSalt: null, ownContribution: OURS,
      frame: { contribution: new Uint8Array(SALT_CONTRIBUTION_BYTES) },
    });
    expect(action.action === "freeze" && action.detail).toMatch(/all zeros/);
  });
});

describe("the frame we send announces our state and nothing else", () => {
  it("★ no salt yet → we offer our contribution, and it is the SAME one every time", () => {
    /**
     * The subtle break: minting a fresh contribution per reconnect. Both sides would keep deriving
     * against a moving value and the fingerprints would never settle — a reconnect loop that looks
     * like a network problem.
     */
    const first = ownSaltFrame({ ownSalt: null, ownContribution: OURS });
    const second = ownSaltFrame({ ownSalt: null, ownContribution: OURS });
    expect(Buffer.from(first.contribution!).toString("hex")).toBe(Buffer.from(OURS).toString("hex"));
    expect(Buffer.from(second.contribution!).toString("hex")).toBe(Buffer.from(first.contribution!).toString("hex"));
    expect(first.fingerprint).toBeUndefined();
  });

  it("★ salt held → we announce the fingerprint and STOP offering a contribution", () => {
    const frame = ownSaltFrame({ ownSalt: AGREED, ownContribution: OURS });
    expect(frame.contribution).toBeUndefined();
    expect(Buffer.from(frame.fingerprint!).toString("hex")).toBe(Buffer.from(saltFingerprint(AGREED)).toString("hex"));
  });
});

describe("a malformed frame is refused by shape, not routed by guesswork", () => {
  it("★ a frame carrying NEITHER field is refused", () => {
    const action = onPeerSaltFrame({ ownSalt: null, ownContribution: OURS, frame: {} });
    expect(action.action).toBe("freeze");
    expect(action.action === "freeze" && action.reason).toBe(SALT_FREEZE_REASONS.FRAME_MALFORMED);
  });

  it("★ a frame carrying BOTH fields is refused — the two states are exclusive", () => {
    /**
     * Not pedantry. A peer that sends both is claiming to hold a salt AND to be starting fresh, and
     * whichever field this machine chose to read first would decide the outcome. A sender that can
     * pick the branch is a sender that can steer the agreement.
     */
    const action = onPeerSaltFrame({
      ownSalt: null, ownContribution: OURS,
      frame: { contribution: THEIRS, fingerprint: saltFingerprint(AGREED) },
    });
    expect(action.action).toBe("freeze");
    expect(action.action === "freeze" && action.reason).toBe(SALT_FREEZE_REASONS.FRAME_MALFORMED);
  });
});

describe("every reason an operator can be shown has something for them to DO", () => {
  it("★ the guidance map is TOTAL over the reasons — a reason without guidance is a bare code", () => {
    for (const reason of Object.values(SALT_FREEZE_REASONS)) {
      expect(SALT_FREEZE_GUIDANCE[reason], `no guidance for ${reason}`).toBeTruthy();
      expect(SALT_FREEZE_GUIDANCE[reason].length).toBeGreaterThan(80);
    }
  });

  it("★ the guidance never tells the reader to retry the thing that cannot work", () => {
    // The lesson refusal-reasons.ts already paid for: an affordance that resolves to nothing is
    // worse than none, because they will try to follow it. A frozen session is not retryable —
    // only a NEW session is.
    for (const reason of Object.values(SALT_FREEZE_REASONS)) {
      expect(SALT_FREEZE_GUIDANCE[reason], `${reason} tells them to retry`).not.toMatch(/retry this session/i);
    }
  });
});
