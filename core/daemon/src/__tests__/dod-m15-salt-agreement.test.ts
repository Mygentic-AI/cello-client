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
 * That makes the four combinations exhaustive. **Two of them REPAIR** — a side that holds a salt and
 * a side that does not DO converge, because the holder still keeps its own half and
 * `deriveSessionSalt` sorts its arguments, so re-sending that half lands the peer on byte-identical
 * bytes.
 *
 * ⚠️ THIS HEADER USED TO SAY THE OPPOSITE, and it was the false sentence that produced a
 * session-killing defect (review F1, then F17 for this file). It claimed the two cells "cannot be
 * repaired… the holder no longer keeps" the inputs. We do keep ours. Freezing on that reasoning
 * meant one dropped frame destroyed a healthy session, to defend a value nothing consumes yet.
 * It is corrected here rather than deleted, because a reader who re-derives the old claim would
 * re-derive the old behaviour with it — and this is the sentence they would use to argue the repair
 * back out.
 *
 * Exactly ONE state cannot converge: we hold a salt read back from the row and the half it was
 * built from is gone. Loudness is still the whole point there — the alternative is the
 * silent-discard loop `wire-content-hash.ts` already cost two daemons.
 */

import { describe, it, expect } from "vitest";
import {
  onPeerSaltFrame,
  ownSaltFrame,
  SALT_ADOPTION_LABELS,
  SALT_FREEZE_REASONS,
  SALT_FREEZE_GUIDANCE,
  type SaltAgreementAction,
  type SaltAgreementFrame,
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

  it("★ BOTH SIDES REACH THE SAME BYTES — run from each side, against an INDEPENDENT derivation", () => {
    /**
     * The first version of this test compared the two sides against EACH OTHER and claimed that a
     * role-dependent argument order would move one of them. That claim was false — review F12 —
     * because `deriveSessionSalt` sorts its inputs, so both orders return the same bytes and the
     * comparison was a tautology. The arg-swap mutant it was supposed to catch is caught by the
     * blame-direction test instead.
     *
     * What is left worth asserting is the real property: each side reaches the value an outside
     * observer computes from the two halves, so neither side's result depends on it having been the
     * one that "went first".
     */
    const independent = Buffer.from(deriveSessionSalt(OURS, THEIRS)).toString("hex");
    const us = onPeerSaltFrame({ ownSalt: null, ownContribution: OURS, frame: { contribution: THEIRS } });
    const them = onPeerSaltFrame({ ownSalt: null, ownContribution: THEIRS, frame: { contribution: OURS } });
    expect(us.action === "derive_and_announce" && Buffer.from(us.salt).toString("hex")).toBe(independent);
    expect(them.action === "derive_and_announce" && Buffer.from(them.salt).toString("hex")).toBe(independent);
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

describe("Decision #8: two sides out of step REPAIR rather than die — review F1", () => {
  /**
   * These three replace three tests that asserted the opposite, and the tests were wrong because
   * the code was.
   *
   * The off-diagonal cells used to freeze the session, justified by a claim in the module header
   * that turned out to be false: *"neither party keeps the inputs once it has the output."* We keep
   * ours — for the life of the session node — and `deriveSessionSalt` sorts its arguments, so a
   * side holding a salt can re-send its half and the peer lands on byte-identical bytes.
   *
   * That mattered because reaching the off-diagonal takes nothing exotic: one side's announce
   * failing while the other's lands does it. So **one dropped frame destroyed a live session**, to
   * defend a value that nothing consumes yet.
   */
  it("★ we hold a salt and the peer offers a contribution — we re-offer OUR HALF, not a refusal", () => {
    const action = onPeerSaltFrame({ ownSalt: AGREED, ownContribution: OURS, frame: { contribution: THEIRS } });
    expect(action.action).toBe("repair");
    expect(
      action.action === "repair" && Buffer.from(action.frame.contribution!).toString("hex"),
      "the repair must send the half our salt was built from, or the peer lands on a different salt",
    ).toBe(Buffer.from(OURS).toString("hex"));
    expect(action.action === "repair" && action.frame.fingerprint, "one field, never both").toBeUndefined();
  });

  it("★ THE REPAIR ACTUALLY CONVERGES — the peer derives the salt we already hold", () => {
    /**
     * The assertion that makes the repair worth having rather than merely non-fatal. Run the peer's
     * side of it: they receive our half and derive. If the result were not our stored salt, we would
     * have "repaired" them onto a different value — the silent disagreement that is worse than the
     * freeze this replaced.
     */
    const ourRepair = onPeerSaltFrame({ ownSalt: AGREED, ownContribution: OURS, frame: { contribution: THEIRS } });
    if (ourRepair.action !== "repair") throw new Error("expected repair");
    const peerSide = onPeerSaltFrame({
      ownSalt: null, ownContribution: THEIRS, frame: { contribution: ourRepair.frame.contribution! },
    });
    expect(peerSide.action).toBe("derive_and_announce");
    expect(peerSide.action === "derive_and_announce" && Buffer.from(peerSide.salt).toString("hex"))
      .toBe(Buffer.from(AGREED).toString("hex"));
  });

  it("★ we hold NO salt and the peer announces a fingerprint — we re-offer our half, which asks for theirs", () => {
    const action = onPeerSaltFrame({ ownSalt: null, ownContribution: OURS, frame: { fingerprint: saltFingerprint(AGREED) } });
    expect(action.action).toBe("repair");
    expect(action.action === "repair" && Buffer.from(action.frame.contribution!).toString("hex"))
      .toBe(Buffer.from(OURS).toString("hex"));
  });

  it("★ the ONE state that truly cannot converge: we hold a salt and our half is GONE", () => {
    /**
     * A restart after the salt was stored but before both sides confirmed. `null` here is not "we
     * didn't look" — the caller never mints a fresh half for a session that already has a salt,
     * precisely so this state stays distinguishable. Minting one would let us repair the peer onto
     * a DIFFERENT salt with both sides believing they had agreed, which is the outcome worse than
     * refusing.
     */
    const action = onPeerSaltFrame({ ownSalt: AGREED, ownContribution: null, frame: { contribution: THEIRS } });
    expect(action.action).toBe("freeze");
    expect(action.action === "freeze" && action.reason).toBe(SALT_FREEZE_REASONS.STATE_DIVERGENT);
    expect(action.action === "freeze" && action.detail).toMatch(/no longer hold the half/);
  });

  it("★ a genuine MISMATCH still tells the peer before stopping — Decision #10 wants both sides to refuse", () => {
    /**
     * The peer holds everything needed to run this identical comparison and has simply not been
     * given our side of it. Without the notice the session just stops answering: our operator gets
     * a full explanation and theirs gets silence.
     */
    const otherSalt = deriveSessionSalt(OURS, new Uint8Array(SALT_CONTRIBUTION_BYTES).fill(0xc3));
    const action = onPeerSaltFrame({ ownSalt: AGREED, ownContribution: OURS, frame: { fingerprint: saltFingerprint(otherSalt) } });
    if (action.action !== "freeze") throw new Error("expected freeze");
    expect(action.notifyPeer?.fingerprint, "the peer must be handed our digest before we go").toBeDefined();
    expect(Buffer.from(action.notifyPeer!.fingerprint!).toString("hex"))
      .toBe(Buffer.from(saltFingerprint(AGREED)).toString("hex"));
    // And that notice must drive the peer to the SAME verdict, or the symmetry is decorative.
    const peerVerdict = onPeerSaltFrame({
      ownSalt: otherSalt, ownContribution: OURS, frame: { fingerprint: action.notifyPeer!.fingerprint! },
    });
    expect(peerVerdict.action).toBe("freeze");
    expect(peerVerdict.action === "freeze" && peerVerdict.reason).toBe(SALT_FREEZE_REASONS.FINGERPRINT_MISMATCH);
  });

  it("★ the mismatch DETAIL prints both digests in hex, not their lengths", () => {
    /**
     * Review F5. It printed only lengths, so the ordinary case — two 8-byte digests that differ —
     * told the operator *"ours is 8 bytes, theirs was 8"*, which reads as an equality on the one
     * failure Decision #10 exists to make debuggable. Both values are one-way and both already
     * crossed the wire in the clear.
     */
    const otherSalt = deriveSessionSalt(OURS, new Uint8Array(SALT_CONTRIBUTION_BYTES).fill(0xc3));
    const action = onPeerSaltFrame({ ownSalt: AGREED, ownContribution: OURS, frame: { fingerprint: saltFingerprint(otherSalt) } });
    if (action.action !== "freeze") throw new Error("expected freeze");
    expect(action.detail).toContain(Buffer.from(saltFingerprint(AGREED)).toString("hex"));
    expect(action.detail).toContain(Buffer.from(saltFingerprint(otherSalt)).toString("hex"));
  });
});

describe("Decision #8: a LOCAL defect is never reported as the counterparty's — review F3", () => {
  /**
   * `deriveSessionSalt` throws for FOUR conditions and two of them are local: our own wrong length
   * and our own all-zero. `session-salt.ts` added the second one specifically so the operator whose
   * machine is broken is not told their counterparty did it — and a single catch mapping all four
   * to one peer-blaming reason handed that accusation straight back at the guidance layer.
   *
   * It was also a surviving mutant: swapping the two arguments in the derive call left every reason
   * code and every message-regex passing while every degenerate refusal blamed the wrong party.
   */
  it("★ OUR OWN all-zero half is its own reason, and its guidance says the machine is ours", () => {
    const action = onPeerSaltFrame({
      ownSalt: null, ownContribution: new Uint8Array(SALT_CONTRIBUTION_BYTES), frame: { contribution: THEIRS },
    });
    expect(action.action).toBe("freeze");
    expect(action.action === "freeze" && action.reason).toBe(SALT_FREEZE_REASONS.OWN_CONTRIBUTION_DEGENERATE);
    expect(SALT_FREEZE_GUIDANCE[SALT_FREEZE_REASONS.OWN_CONTRIBUTION_DEGENERATE]).toMatch(/THIS MACHINE/);
    expect(
      SALT_FREEZE_GUIDANCE[SALT_FREEZE_REASONS.OWN_CONTRIBUTION_DEGENERATE],
      "it must tell them NOT to raise it with their counterparty",
    ).toMatch(/not your counterparty|they did nothing/i);
  });

  it("★ our own WRONG-LENGTH half is local too", () => {
    const action = onPeerSaltFrame({ ownSalt: null, ownContribution: new Uint8Array(8), frame: { contribution: THEIRS } });
    expect(action.action === "freeze" && action.reason).toBe(SALT_FREEZE_REASONS.OWN_CONTRIBUTION_DEGENERATE);
  });

  it("★ THE BLAME DIRECTION IS PINNED — the arg-swap mutant dies here", () => {
    /**
     * Swap the arguments in the derive call and this pair inverts: a degenerate PEER half would
     * report `OWN_CONTRIBUTION_DEGENERATE` and vice versa. Asserting both directions in one test is
     * what makes the swap detectable — either alone still passes, because both messages contain
     * "all zeros".
     */
    const peerBad = onPeerSaltFrame({
      ownSalt: null, ownContribution: OURS, frame: { contribution: new Uint8Array(SALT_CONTRIBUTION_BYTES) },
    });
    const ownBad = onPeerSaltFrame({
      ownSalt: null, ownContribution: new Uint8Array(SALT_CONTRIBUTION_BYTES), frame: { contribution: THEIRS },
    });
    expect(peerBad.action === "freeze" && peerBad.reason).toBe(SALT_FREEZE_REASONS.CONTRIBUTION_DEGENERATE);
    expect(ownBad.action === "freeze" && ownBad.reason).toBe(SALT_FREEZE_REASONS.OWN_CONTRIBUTION_DEGENERATE);
    // And the operator-facing text points opposite ways, which is the part that actually matters.
    expect(SALT_FREEZE_GUIDANCE[SALT_FREEZE_REASONS.CONTRIBUTION_DEGENERATE]).toMatch(/OUT OF BAND/);
    expect(SALT_FREEZE_GUIDANCE[SALT_FREEZE_REASONS.OWN_CONTRIBUTION_DEGENERATE]).not.toMatch(/OUT OF BAND/);
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
    /**
     * The lesson `refusal-reasons.ts` already paid for: an affordance that resolves to nothing is
     * worse than none, because they will try to follow it. A frozen session is not retryable — only
     * a NEW session is.
     *
     * Review F11: this matched the single literal "retry this session", so "try again",
     * "reconnect and it will resolve" and "wait for them to come back" all sailed through. The
     * pattern now covers the phrasings someone would actually write.
     */
    for (const reason of Object.values(SALT_FREEZE_REASONS)) {
      expect(
        SALT_FREEZE_GUIDANCE[reason], `${reason} points the operator at something that cannot work`,
      ).not.toMatch(/try again|retry|reconnect|wait for them|wait for the/i);
      // The move that DOES work has to be named, or the refusal is a dead end.
      expect(SALT_FREEZE_GUIDANCE[reason], `${reason} names no way forward`).toMatch(/new session|another session/i);
    }
  });
});

describe("the exchange TERMINATES from every reachable state — 006-CRYPTO finding 1", () => {
  /**
   * F14 closed ONE fixed point and opened its mirror, and its comment asserts the safety it lost:
   *
   *   *"a fingerprint drives the peer to `confirmed` or `FINGERPRINT_MISMATCH` — both terminal — so
   *   the cycle cannot re-enter."*
   *
   * That holds only for a peer that HOLDS a salt. A peer holding NONE answers a fingerprint with the
   * mirror repair — its contribution — and the salt-holder, latched by F14, answers with its
   * fingerprint again. Neither side is faulty and neither can stop.
   *
   * ─── How two healthy daemons reach it, with no adversary ─────────────────────────────────────
   *
   * 1. Both offer contributions. B derives, persists, announces `fingerprint(S)`.
   * 2. A derives the same salt and its `#persistSessionSalt` FAILS — a named, designed-for outcome
   *    (`session.salt.persist.failed`). A holds no salt, but keeps its half: it is minted once per
   *    session, which is what makes the repair converge in the first place.
   * 3. A reconnect re-announces both sides (correctly — A still holds nothing). B answers A's half
   *    with a repair and LATCHES it in `#saltRepairedAgainst`.
   * 4. From here the two states are fixed: A only ever receives fingerprints, so it never derives;
   *    B is latched, so it only ever answers with its fingerprint.
   *
   * The test starts at step 4 by pre-seeding B's latch, because that is the state the caller reaches
   * — not because the state is contrived.
   *
   * Cost per iteration in production: one `entry.node.newStream(...)` per side against libp2p's
   * per-protocol stream cap, plus one INFO `session.salt.repair` line per side, for the life of the
   * session. The conversation looks healthy while it does it.
   */
  const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

  /** Drive the two sides against each other, latching exactly as `#handleSaltFrame` does. */
  function runExchange(maxSteps: number) {
    const aAnsweredFingerprints = new Set<string>();
    // B has already answered our half once — step 3 above. This is the caller's `#saltRepairedAgainst`.
    const bAnsweredHalves = new Set<string>([hex(OURS)]);

    let turn: "A" | "B" = "A";
    let inbound: SaltAgreementFrame = { fingerprint: saltFingerprint(AGREED) };
    const trace: string[] = [];
    let terminal: SaltAgreementAction | null = null;

    for (let step = 0; step < maxSteps && !terminal; step++) {
      const action = turn === "A"
        ? onPeerSaltFrame({
            // A never gains a salt: its persist keeps failing.
            ownSalt: null,
            ownContribution: OURS,
            alreadyRepairedAgainstPeerFingerprint:
              inbound.fingerprint !== undefined && aAnsweredFingerprints.has(hex(inbound.fingerprint)),
            frame: inbound,
          })
        : onPeerSaltFrame({
            ownSalt: AGREED,
            ownContribution: THEIRS,
            alreadyRepairedAgainstPeerHalf:
              inbound.contribution !== undefined && bAnsweredHalves.has(hex(inbound.contribution)),
            frame: inbound,
          });

      trace.push(`${turn}:${action.action}`);

      if (action.action === "repair") {
        if (turn === "A" && inbound.fingerprint) aAnsweredFingerprints.add(hex(inbound.fingerprint));
        if (turn === "B" && inbound.contribution) bAnsweredHalves.add(hex(inbound.contribution));
        inbound = action.frame;
        turn = turn === "A" ? "B" : "A";
      } else {
        terminal = action;
      }
    }
    return { terminal, trace };
  }

  it("★ a salt-holder and a saltless side do NOT trade frames forever", () => {
    const { terminal, trace } = runExchange(12);

    /**
     * Asserting the OUTCOME, not its shadow. "It terminated" would also pass if the exchange ended
     * by freezing a healthy session, which is the wrong answer here: nothing has been hashed under
     * the salt, no sender salts exist yet, and F1's own lesson is that a refusal which breaks
     * availability to defend an unconsumed value is the defect. Decision #8's terminal state for
     * "one side cannot adopt" is that BOTH sides stay unsalted and both KNOW — exactly as verifiable
     * as every session shipped before the salt existed.
     */
    expect(terminal?.action, `the exchange never terminated: ${trace.join(" -> ")}`).toBe("adoption_closed");
    expect(
      terminal?.action === "adoption_closed" && terminal.announce?.adoptionClosed,
      "the peer must be TOLD, or it keeps a salt we can never reach and discards every message we send",
    ).toBe(SALT_ADOPTION_LABELS.EXCHANGE_STALLED);
  });

  it("★ it terminates within ONE round trip of the repeat, not eventually", () => {
    /**
     * A bound, because "terminates" is satisfied by a fix that gives up after fifty round trips and
     * that is still a flood. The first repair is legitimate — it is F1's convergence — so the shape
     * is: A repairs once, B answers, A sees the SAME fingerprint a second time and stops.
     */
    const { trace } = runExchange(12);
    expect(trace.join(" -> ")).toBe("A:repair -> B:repair -> A:adoption_closed");
  });

  it("★ the FIRST repair still happens — F1's convergence is not what this removes", () => {
    /**
     * The latch must fire on a REPEAT, never on the first sight of a fingerprint. If it fired
     * immediately, a saltless side would refuse to ask for the peer's half at all and every session
     * where one side persisted first would go unsalted.
     */
    const action = onPeerSaltFrame({
      ownSalt: null,
      ownContribution: OURS,
      alreadyRepairedAgainstPeerFingerprint: false,
      frame: { fingerprint: saltFingerprint(AGREED) },
    });
    expect(action.action).toBe("repair");
    expect(action.action === "repair" && action.frame.contribution && hex(action.frame.contribution)).toBe(hex(OURS));
  });
});
