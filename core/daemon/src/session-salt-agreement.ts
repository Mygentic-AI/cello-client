/**
 * THE SALT AGREEMENT STATE MACHINE — `DOD-M15-SEALWIRE-1` bullet 6, part A.
 * Decisions Carried #8 (both sides contribute, one salt per session, persisted) and #10 (a mismatch
 * must be loud).
 *
 * ⚠️ PART A OF THE SALT WORK, AND THE SPLIT IS DELIBERATE. This module and its caller AGREE a salt
 * and store it.
 *
 * **NO SENDER SALTS YET**, which is what makes an unanswered agreement free: a peer on an older
 * build that never replies costs nothing today. (An earlier revision of this line said
 * `wire-content-hash.ts` is untouched — that is no longer true. Part B1 shipped the RECEIVE half:
 * it reads a `content_hash_alg` off the frame and can verify a salted hash. The outbound half, part
 * B2, is what moves the send sites onto `saltedContentHash` and holds the first send until the salt
 * is agreed — and from that moment an unanswered agreement IS a session that cannot send.)
 *
 * ─── The frame, and why exactly one field is present ───────────────────────────────────────────
 *
 * One frame type carries the whole agreement, and WHICH FIELD IS PRESENT IS THE SENDER'S STATE:
 *
 *   `contribution` (32 bytes) → "I hold no salt for this session. Here is my half."
 *   `fingerprint`  (8 bytes)  → "I already hold a salt. Here is a one-way digest of it."
 *
 * Never both, never neither. That is not tidiness: a peer that sends both is claiming to be in two
 * states at once, and whichever field this machine read first would decide the outcome — a sender
 * that can pick the branch is a sender that can steer the agreement. Both malformed shapes are
 * refused rather than resolved.
 *
 * ─── The four combinations ─────────────────────────────────────────────────────────────────────
 *
 *                          peer sent CONTRIBUTION            peer sent FINGERPRINT
 *   we hold NO salt        derive, persist, announce ours    REPAIR: re-offer our half
 *   we HOLD a salt         REPAIR: re-offer our half         compare → confirmed | ✗ MISMATCH
 *                          (✗ DIVERGENT if our half is gone)
 *
 * ⚠️ THE OFF-DIAGONAL CELLS USED TO FREEZE THE SESSION, AND THAT WAS WRONG — review F1, and the
 * justification written here for it was **false**.
 *
 * It said the salt "cannot be repaired by retrying… neither party keeps the inputs once it has the
 * output." We DO keep our input: `#saltContributions` holds our half for the life of the session
 * node, and `deriveSessionSalt` sorts its two arguments — so a side that holds a salt can simply
 * re-send its own half and the peer derives **byte-identical** bytes.
 *
 * That mattered because the off-diagonal is not the exotic state the old text described. It is
 * reached by ANY of:
 *   - one side's connect-time announce failing (`#sendSaltFrame` logs and gives up until the next
 *     connect) while the other's lands;
 *   - one side's persist failing, so it re-offers a contribution while the other has stored one;
 *   - a teardown between the two derives.
 * **A single dropped frame therefore destroyed a live session** — a refusal that breaks availability
 * to defend a value nothing has consumed yet. Repairing costs one frame and always converges.
 *
 * The cell is genuinely unrepairable in exactly one case, and the code now CHECKS it rather than
 * assuming it: we hold a salt read back from the row, and our half is **gone** — evicted by a
 * teardown, or never in this process at all after a restart. `ownContribution` is `null` there, and
 * only there, because the caller never mints a fresh half for a session that already has a salt.
 * Minting one would be worse than freezing: the peer would derive a DIFFERENT salt from it and both
 * sides would believe they had agreed.
 *
 * ─── Why a refusal, and why it has to be loud ──────────────────────────────────────────────────
 *
 * Decision #10 exists because a salt disagreement is the least debuggable failure this system can
 * produce, and `wire-content-hash.ts`'s own header says why: the send SUCCEEDS, the sender's log
 * says the frame left, and the receiver discards before anything about it is logged. It cost two
 * live daemons to find once. Every branch here therefore ends in a decision — converge or stop —
 * and never in "keep going and see".
 *
 * ─── Where the named reasons live, and why NOT in `refusal-reasons.ts` ─────────────────────────
 *
 * An earlier acceptance criterion of mine said to add these to `REFUSAL_REASONS`. That was wrong,
 * and following it would have put them somewhere no caller could raise them: `recordRefusal`
 * refuses an inbound session REQUEST — the decision made *before* a session exists, whose audience
 * is `cello_inbox` and whose guidance is written for someone deciding whether to accept a stranger.
 * A salt disagreement happens on an ESTABLISHED session, mid-flight, and its response is to tear
 * that session down. Different moment, different reader, different verb.
 *
 * The shape is copied on purpose, because the shape is the part that was right: a CLOSED set of
 * reasons plus a TOTAL guidance map, so a reason cannot be added without something for the operator
 * to do. `refusal-reasons.ts` records what a free-form `reason: string` permitted — a new code
 * slipping past every test in the milestone's own guard file — and this file inherits that lesson
 * without inheriting its union.
 */

import { deriveSessionSalt, saltFingerprint, SALT_CONTRIBUTION_BYTES } from "@cello-protocol/crypto";

function isAllZero(b: Uint8Array): boolean {
  let acc = 0;
  for (const x of b) acc |= x;
  return acc === 0;
}

/**
 * The salt-agreement frame, as it rides `/cello/content/1.0.0`.
 *
 * 🚨 CHANNEL RULE, and it is unrepairable if broken — Decision #8 and `session-salt.ts`'s header.
 * This frame travels the PEER-TO-PEER content stream, which carries its own Noise session inside
 * circuit-relay-v2, so a forwarding relay sees ciphertext. It must NEVER be added to
 * `session_offer` / `session_offer_accept` or anything else a DIRECTORY brokers — and that is the
 * trap, because the only round trip at session open today runs on the directory's signaling stream.
 * A session that shipped the contribution there cannot be fixed afterwards: the relay would already
 * hold the salt and every hash it protects.
 */
export interface SaltAgreementFrame {
  /** Present iff the sender holds NO salt for this session. */
  contribution?: Uint8Array;
  /** Present iff the sender HOLDS a salt. Never the salt itself (Decision #10). */
  fingerprint?: Uint8Array;
  /**
   * Present iff the sender has CLOSED adoption — it has already hashed content under the unsalted
   * rule, so it can never adopt a salt for this session (Decision #8).
   *
   * ⚠️ THIS FIELD EXISTS BECAUSE ADOPTION IS BILATERAL AND THE LEAF COUNT IS LOCAL — review B2b-2 F2.
   * The two sides reach their frontier at different instants: the very first message of a session is
   * a leaf on the RECEIVER before it is one on the sender, who is still inside its own `await`. So
   * one side can adopt while the other refuses, **both correctly**, and nothing on the wire or in
   * either row records the disagreement. Once salting is on that is not a weaker hash — it is a
   * one-way dead conversation, every frame from the salted side refused as
   * `content_hash_salt_unavailable` and never shown.
   *
   * It also restores TERMINATION (review F1). `derive_and_announce` is the only transition that lets
   * a saltless side finish, and the adoption guard removes it — so without this the two sides trade
   * `repair` frames forever, one new stream each per round trip against libp2p's per-protocol cap.
   *
   * The value is a short reason, not a boolean, so the peer's log can say WHY the other side closed.
   */
  adoptionClosed?: string;
}

/**
 * The state a peer announced that ends the agreement without a salt — Decision #8, review F1/F2.
 *
 * NOT a freeze. Both sides simply stay unsalted, which is exactly as verifiable as every session
 * shipped before the salt existed. The point is that they agree on it.
 */
export const SALT_ADOPTION_CLOSED = "adoption_closed" as const;

/** The CLOSED set of reasons a salt disagreement stops a session. */
export const SALT_FREEZE_REASONS = {
  /** Both sides hold a salt and the digests differ. */
  FINGERPRINT_MISMATCH: "salt_fingerprint_mismatch",
  /** We hold a salt and our own half is gone, so the peer cannot be brought back to it. */
  STATE_DIVERGENT: "salt_state_divergent",
  /** The peer's contribution was all-zero, the wrong length, or our own echoed back. */
  CONTRIBUTION_DEGENERATE: "salt_contribution_degenerate",
  /**
   * OUR OWN half is degenerate — a broken or patched random source on THIS machine.
   *
   * Separate from `CONTRIBUTION_DEGENERATE` because the two send the operator to different places,
   * and collapsing them undid a fix one layer down (review F3). `session-salt.ts` deliberately
   * refuses our own all-zero half with *"this is a LOCAL defect… not something the peer did"*,
   * precisely so the operator whose machine is broken is not told their counterparty did it — and
   * mapping both throws to one peer-blaming reason handed that accusation straight back.
   */
  OWN_CONTRIBUTION_DEGENERATE: "salt_own_contribution_degenerate",
  /** The frame carried both fields or neither, so the sender's state is unreadable. */
  FRAME_MALFORMED: "salt_frame_malformed",
} as const;

export type SaltFreezeReason = (typeof SALT_FREEZE_REASONS)[keyof typeof SALT_FREEZE_REASONS];

/**
 * What the operator should DO, per reason. Typed as a TOTAL map, so a reason added without guidance
 * fails to compile.
 *
 * ⚠️ EVERY VERB HERE MUST BE ONE THE READER CAN PERFORM. A frozen session is not retryable — that
 * is what freezing means — so none of these may say "try again on this session". The move is always
 * a NEW session, and for the divergent cases it is worth saying plainly that nothing is broken and
 * nobody did anything wrong: one side's record simply did not survive.
 */
export const SALT_FREEZE_GUIDANCE: Record<SaltFreezeReason, string> = {
  [SALT_FREEZE_REASONS.FINGERPRINT_MISMATCH]:
    "STOPPED ON PURPOSE. You and your counterparty ended up with different values for this " +
    "session's content salt, so from here every message either of you sent would be discarded by " +
    "the other with nothing said about it. Nothing was lost and nothing was tampered with. Two " +
    "things cause it: one of you is running an older build, or one side restarted midway through " +
    "opening the session and came back without the half it had already sent. Check the log for " +
    "session.salt.persist.failed or session.salt.announce.failed on either machine — if you see " +
    "one, it was the restart and there is nothing to fix. Otherwise compare versions. Either way, " +
    "start a new session.",
  [SALT_FREEZE_REASONS.STATE_DIVERGENT]:
    "STOPPED ON PURPOSE. This side holds the session's content salt but no longer holds the random " +
    "half it was built from, so your counterparty — who is starting the agreement over — cannot be " +
    "brought back to the same value. This happens when a daemon restarts after the salt was stored " +
    "but before both sides had confirmed it. Nothing is broken and neither of you did anything " +
    "wrong. Start a new session; the transcript of this one is unaffected and still readable.",
  [SALT_FREEZE_REASONS.OWN_CONTRIBUTION_DEGENERATE]:
    "STOPPED ON PURPOSE, AND THE PROBLEM IS ON THIS MACHINE — not your counterparty's. The random " +
    "half this side generated for the session's content salt came out empty or the wrong size, " +
    "which means the random source this daemon is using is broken or has been modified. Do not " +
    "raise this with your counterparty; they did nothing. Check this machine's CELLO build and its " +
    "system random source before opening another session, because every session it opens has the " +
    "same defect.",
  [SALT_FREEZE_REASONS.CONTRIBUTION_DEGENERATE]:
    "STOPPED ON PURPOSE. Your counterparty's half of this session's content salt was empty, the " +
    "wrong size, or a copy of your own. Accepting it would have meant one side alone deciding a " +
    "value whose entire purpose is that neither side can — and the effect would be that anyone " +
    "relaying your messages could confirm guesses at what short ones said. This can be a broken or " +
    "modified build on their side, so raise it with them OUT OF BAND before opening a new session.",
  [SALT_FREEZE_REASONS.FRAME_MALFORMED]:
    "STOPPED ON PURPOSE. Your counterparty's salt-agreement message did not say which state they " +
    "were in — it claimed both at once, or neither — so there was no way to answer it that was not " +
    "a guess. Nothing was accepted. A build mismatch is the ordinary cause; confirm what they are " +
    "running, then start a new session.",
};

/**
 * The outcome of one inbound salt frame. Every variant is terminal for the agreement: it either
 * settles it or stops the session. There is deliberately no "wait and see" — see the header.
 */
export type SaltAgreementAction =
  /** We derived the salt. The caller persists it and sends the returned fingerprint. */
  | { action: "derive_and_announce"; salt: Uint8Array; fingerprint: Uint8Array }
  /**
   * Neither side will hold a salt for this session, and BOTH now know it. Terminal, and deliberately
   * not a freeze: the session keeps working with the unsalted hash every build has always used.
   * `announce` is a frame to send iff the peer has not already told us — so the exchange ends rather
   * than echoing.
   */
  | { action: "adoption_closed"; detail: string; announce?: SaltAgreementFrame }
  /** The peer's digest matches ours. Agreed; nothing more to send. */
  | { action: "confirmed" }
  /**
   * The two sides are out of step but CAN converge: re-send the exact frame given. Review F1 —
   * this replaces two freezes that a single dropped frame could trigger.
   */
  | { action: "repair"; frame: SaltAgreementFrame; detail: string }
  /**
   * Stop the session, with a reason the operator can act on.
   *
   * `notifyPeer`, when present, is a frame to put on the wire BEFORE tearing down, so the
   * counterparty reaches the same verdict instead of discovering the session by its absence. Only
   * the fingerprint mismatch carries one: it is the sole refusal where the peer holds everything it
   * needs to run the identical comparison and has simply not been given our side of it.
   */
  | { action: "freeze"; reason: SaltFreezeReason; detail: string; notifyPeer?: SaltAgreementFrame };

function digestsEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  return Buffer.from(a).equals(Buffer.from(b));
}

/**
 * The frame this side should send, given its own state. Called on every counterparty connect, so it
 * must be a pure function of the state and NOT mint anything.
 *
 * ⚠️ `ownContribution` IS MINTED ONCE PER SESSION BY THE CALLER, and this is where that requirement
 * is visible. A fresh contribution per reconnect would have both sides re-deriving against a moving
 * value, the fingerprints would never settle, and the symptom — a session that reconnects and still
 * disagrees — reads as a network fault rather than a bug here.
 */
export function ownSaltFrame(
  state: { ownSalt: Uint8Array | null; ownContribution: Uint8Array | null },
): SaltAgreementFrame | null {
  if (state.ownSalt) return { fingerprint: saltFingerprint(state.ownSalt) };
  /**
   * `null` — nothing to announce, and the caller must say so rather than invent a half.
   *
   * Review F15: `ownContribution` was typed non-null here, so the daemon satisfied it by calling
   * the MINTING accessor — which minted for a session that already held a salt, on the one state
   * `null` exists to name. Taking the nullable type is what forces the caller to pass `#saltState`
   * and makes minting a decision rather than a side effect of a parameter list.
   *
   * Reaching here at all means we hold neither a salt nor a half, which `#saltState` does not
   * produce; it is a real defect if seen, not a state to paper over with a fresh contribution.
   */
  if (!state.ownContribution) return null;
  return { contribution: state.ownContribution };
}

/**
 * `isTimingSafeEqual` was the name; constant time is NOT required here and never was.
 *
 * Review F13: nothing pinned the constant-time property and nothing needs it — both operands are
 * 8-byte one-way digests that the two sides have already exchanged in the clear, so there is no
 * secret for a timing signal to leak. A name asserting a property nothing checks is the same defect
 * as a comment asserting one, so the name says what the function does instead.
 *
 * The LENGTH check is the load-bearing half and is pinned by a test: a differing width IS a
 * disagreement, and comparing a common prefix would let two sides that agree on half their digest
 * call it a match.
 */

/**
 * OUR OWN half, checked before it is used — review F3.
 *
 * `deriveSessionSalt` refuses four conditions and TWO OF THEM ARE LOCAL: our own wrong length and
 * our own all-zero. A single `catch` around it mapped all four to one peer-blaming reason, which
 * handed the operator an out-of-band accusation of their counterparty for a broken RNG on their own
 * machine — undoing, at the guidance layer, the exact fix `session-salt.ts` added for it.
 *
 * Checking here means the primitive's throw can only ever be about the PEER's half by the time it
 * is caught. It also kills a mutant the tests could not see: swapping the two arguments in the
 * derive call left every reason code and every message-regex passing while every degenerate refusal
 * blamed the wrong party.
 */
function ownHalfDefect(ownContribution: Uint8Array): string | null {
  if (ownContribution.length !== SALT_CONTRIBUTION_BYTES) {
    return `our own salt contribution is ${ownContribution.length} bytes rather than ${SALT_CONTRIBUTION_BYTES}. This is a LOCAL defect, not something the peer did.`;
  }
  if (isAllZero(ownContribution)) {
    return "our own salt contribution is all zeros, so this side contributed nothing. This is a LOCAL defect — a broken or patched random source — not something the peer did.";
  }
  return null;
}

/**
 * Decide what an inbound salt frame means. See the four-cell table in the header.
 *
 * `ownContribution` is `null` ONLY in the one state that cannot be repaired: we hold a salt read
 * back from the row and the half it was built from is gone. The caller never mints a fresh half for
 * a session that already has a salt — minting one would let us "repair" the peer onto a DIFFERENT
 * salt, with both sides believing they had agreed.
 */
export function onPeerSaltFrame(state: {
  ownSalt: Uint8Array | null;
  ownContribution: Uint8Array | null;
  /**
   * THIS side can no longer adopt a salt — it has already hashed content unsalted (Decision #8).
   *
   * Passed in rather than inferred, because it is the caller that can count a frontier. When true,
   * every branch that would have derived instead announces `adoption_closed`: that is what stops the
   * two sides silently disagreeing (F2) and what restores a terminal state for a saltless side (F1).
   */
  ownAdoptionClosed?: boolean;
  /**
   * TERMINATION — review F14, and the repair did not have it.
   *
   * `(hold a salt) + (peer contribution) → emit a contribution, state unchanged` is a FIXED POINT
   * that emits on every receipt. Two daemons both in it exchange contributions at round-trip speed
   * forever, one new stream and one INFO line each per iteration — and they reach it while holding
   * the SAME salt, so the whole exchange is waste.
   *
   * One reconnect during the exchange is enough: both sides re-announce (correctly — neither holds
   * a salt yet), each ends up with a second copy of the other's half queued, and after both derive,
   * that second copy lands on a side that now holds a salt.
   *
   * This flag breaks it. A contribution we have ALREADY answered gets our fingerprint instead, and a
   * fingerprint drives the peer to `confirmed` or `FINGERPRINT_MISMATCH` — both terminal — so the
   * cycle cannot re-enter. The FIRST repair against any given half still happens, so F1's
   * convergence property is untouched.
   */
  alreadyRepairedAgainstPeerHalf?: boolean;
  frame: SaltAgreementFrame;
}): SaltAgreementAction {
  const hasContribution = state.frame.contribution instanceof Uint8Array;
  const hasFingerprint = state.frame.fingerprint instanceof Uint8Array;

  const hasClosed = typeof state.frame.adoptionClosed === "string";

  /**
   * THE PEER HAS CLOSED ADOPTION — terminal for both, and it takes precedence over every other
   * branch, including the malformed-shape check below. A peer that can never adopt is not offering a
   * contribution and not comparing a fingerprint; there is nothing left to agree.
   *
   * We answer once IFF we have not already closed ourselves, so the exchange ends rather than
   * echoing. Both sides then hold no salt and both KNOW it, which is the whole point — the failure
   * this replaces was two sides reaching opposite verdicts with nothing on the wire saying so.
   */
  if (hasClosed) {
    return {
      action: "adoption_closed",
      detail: `the counterparty has already hashed content in this session and cannot adopt a salt (${state.frame.adoptionClosed}); neither side will use one`,
      ...(state.ownAdoptionClosed ? {} : { announce: { adoptionClosed: "peer_closed_first" } }),
    };
  }

  /**
   * WE have closed adoption. Say so instead of deriving, whatever the peer sent — otherwise we
   * refuse silently, they adopt, and every message they send afterwards is unverifiable here.
   */
  if (state.ownAdoptionClosed) {
    return {
      action: "adoption_closed",
      detail: "this side has already hashed content in this session, so no salt can be adopted; telling the peer so they do not adopt one either",
      announce: { adoptionClosed: "already_hashing" },
    };
  }

  if (hasContribution === hasFingerprint) {
    return {
      action: "freeze",
      reason: SALT_FREEZE_REASONS.FRAME_MALFORMED,
      detail: hasContribution
        ? "the peer's salt frame carried BOTH a contribution and a fingerprint, so it claims to hold a salt and to be starting fresh at the same time; whichever field we read first would decide the outcome"
        : "the peer's salt frame carried neither a contribution nor a fingerprint, so it says nothing about which state the peer is in",
    };
  }

  if (state.ownSalt) {
    if (hasContribution) {
      // THE REPAIR (review F1). The peer is starting over; ours is a one-way function of two halves
      // and `deriveSessionSalt` SORTS them, so re-sending our half lands them on byte-identical
      // bytes. Freezing here destroyed live sessions over a single dropped frame.
      if (!state.ownContribution) {
        return {
          action: "freeze",
          reason: SALT_FREEZE_REASONS.STATE_DIVERGENT,
          detail:
            "we hold this session's salt but no longer hold the half it was built from — a teardown or a restart evicted it — so the peer, who is starting over, cannot be brought back to the same value. " +
            "Offering a freshly minted half instead would put them on a DIFFERENT salt with both sides believing they had agreed.",
        };
      }
      if (state.alreadyRepairedAgainstPeerHalf) {
        // TERMINATION (review F14). We have already sent our half in answer to this exact one; the
        // peer is not short of it. Answering with our fingerprint instead makes their next step
        // terminal — `confirmed` or `FINGERPRINT_MISMATCH` — instead of another contribution.
        return {
          action: "repair",
          frame: { fingerprint: saltFingerprint(state.ownSalt) },
          detail: "we have already answered this exact peer half with ours, so a second identical repair would loop; sending our fingerprint instead moves the peer to a terminal answer",
        };
      }
      return {
        action: "repair",
        frame: { contribution: state.ownContribution },
        detail: "the peer is starting the agreement over; re-sending our half lands them on the salt we already hold",
      };
    }
    if (digestsEqual(saltFingerprint(state.ownSalt), state.frame.fingerprint!)) {
      return { action: "confirmed" };
    }
    return {
      action: "freeze",
      reason: SALT_FREEZE_REASONS.FINGERPRINT_MISMATCH,
      // BOTH DIGESTS IN HEX (review F5). This printed only lengths, so in the ordinary case — two
      // 8-byte digests that differ — the operator was told "ours is 8 bytes, theirs was 8", which
      // reads as an equality. Both values are one-way, public, and already crossed the wire.
      detail:
        `the peer's salt fingerprint does not match ours: ours ${Buffer.from(saltFingerprint(state.ownSalt)).toString("hex")}, ` +
        `theirs ${Buffer.from(state.frame.fingerprint!).toString("hex")}. Every message from here would be discarded unread by one side or the other.`,
      // The peer holds everything needed to run this same comparison and has not been given our
      // side of it. Without this it learns nothing — the session simply stops answering.
      notifyPeer: { fingerprint: saltFingerprint(state.ownSalt) },
    };
  }

  // From here we hold no salt, so we are going to use our own half — check it before the primitive
  // does, so a local defect cannot be reported as the peer's (review F3).
  if (!state.ownContribution) {
    return {
      action: "freeze",
      reason: SALT_FREEZE_REASONS.OWN_CONTRIBUTION_DEGENERATE,
      detail: "this side holds neither a salt nor a contribution for the session, so it has nothing to agree with",
    };
  }
  const localDefect = ownHalfDefect(state.ownContribution);
  if (localDefect) {
    return { action: "freeze", reason: SALT_FREEZE_REASONS.OWN_CONTRIBUTION_DEGENERATE, detail: localDefect };
  }

  if (hasFingerprint) {
    // THE MIRROR REPAIR. They hold a salt, we do not. Re-offering our half is what prompts them to
    // send theirs back, and then we derive the value they already have.
    return {
      action: "repair",
      frame: { contribution: state.ownContribution },
      detail: "the peer already holds a salt and we do not; re-offering our half is what asks them for theirs",
    };
  }

  try {
    // The primitive owns every rule about the PEER's half — length, all-zero, reflection — and owns
    // the WORDING too. Its refusals explain what a zero contribution means for both parties;
    // replacing that with a code of our own would be exit-point substitution (Invariant 2),
    // destroying the only explanation that exists at the only moment anyone will read it. Our own
    // half was cleared above, so anything thrown here is about theirs.
    const salt = deriveSessionSalt(state.ownContribution, state.frame.contribution!);
    return { action: "derive_and_announce", salt, fingerprint: saltFingerprint(salt) };
  } catch (err: unknown) {
    return {
      action: "freeze",
      reason: SALT_FREEZE_REASONS.CONTRIBUTION_DEGENERATE,
      detail: err instanceof Error ? err.message : String(err),
    };
  }
}
