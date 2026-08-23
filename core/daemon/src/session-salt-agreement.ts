/**
 * THE SALT AGREEMENT STATE MACHINE — `DOD-M15-SEALWIRE-1` bullet 6, part A.
 * Decisions Carried #8 (both sides contribute, one salt per session, persisted) and #10 (a mismatch
 * must be loud).
 *
 * ⚠️ PART A OF TWO, AND THE SPLIT IS DELIBERATE. This module and its caller AGREE a salt and store
 * it. **Nothing hashes with it yet** — `wire-content-hash.ts` is untouched, so a peer running an
 * older build that never answers a salt frame costs exactly nothing today. Part B moves
 * `wireContentHash` onto `saltedContentHash`, adds the wire version discriminator, and holds the
 * first send until the salt is agreed; from that moment an unanswered agreement is a session that
 * cannot send, which is why it is not this unit.
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
 * ─── The four combinations, all of them terminal ───────────────────────────────────────────────
 *
 *                          peer sent CONTRIBUTION            peer sent FINGERPRINT
 *   we hold NO salt        derive, persist, announce ours    ✗ STATE_DIVERGENT
 *   we HOLD a salt         ✗ STATE_DIVERGENT                 compare → confirmed | ✗ MISMATCH
 *
 * The two divergent cells are the restart case seen from each side, and they **cannot be repaired
 * by retrying**. The salt is a one-way function of two contributions and neither party keeps the
 * inputs once it has the output — so a side whose record survived cannot re-derive it for a side
 * whose record is gone, and cannot accept theirs either. Answering with our fingerprint would be
 * strictly worse than refusing: they would compare it against a salt they do not have, and the
 * session would sit half-agreed with no symptom but discarded messages.
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

import { deriveSessionSalt, saltFingerprint, SALT_FINGERPRINT_BYTES } from "@cello-protocol/crypto";

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
}

/** The CLOSED set of reasons a salt disagreement stops a session. */
export const SALT_FREEZE_REASONS = {
  /** Both sides hold a salt and the digests differ. */
  FINGERPRINT_MISMATCH: "salt_fingerprint_mismatch",
  /** One side holds a salt and the other does not — no retry converges. */
  STATE_DIVERGENT: "salt_state_divergent",
  /** The peer's contribution was all-zero, the wrong length, or our own echoed back. */
  CONTRIBUTION_DEGENERATE: "salt_contribution_degenerate",
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
    "STOPPED ON PURPOSE. You and your counterparty agreed different values for this session's " +
    "content salt, so from here every message either of you sent would be discarded by the other " +
    "with nothing said about it. Nothing was lost and nothing was tampered with — the two sides " +
    "simply did not end up with the same value, which usually means one of you is running an older " +
    "build. Compare versions with them, then start a new session.",
  [SALT_FREEZE_REASONS.STATE_DIVERGENT]:
    "STOPPED ON PURPOSE. One side of this session still holds its content salt and the other has " +
    "started over without one, which happens when a daemon comes back without its database. The " +
    "two cannot be brought back into agreement: the salt is derived from two random halves that " +
    "neither side keeps once it has the result. Nothing is broken and neither of you did anything " +
    "wrong. Start a new session; the transcript of this one is unaffected and still readable.",
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
  /** The peer's digest matches ours. Agreed; nothing more to send. */
  | { action: "confirmed" }
  /** Stop the session, with a reason the operator can act on. */
  | { action: "freeze"; reason: SaltFreezeReason; detail: string };

function isTimingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  // Length first — a differing length IS a disagreement (see the wrong-width case below), and
  // comparing a common prefix would let two sides that agree on half their digest call it a match.
  if (a.length !== b.length) return false;
  let acc = 0;
  for (let i = 0; i < a.length; i++) acc |= a[i]! ^ b[i]!;
  return acc === 0;
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
export function ownSaltFrame(state: { ownSalt: Uint8Array | null; ownContribution: Uint8Array }): SaltAgreementFrame {
  if (state.ownSalt) return { fingerprint: saltFingerprint(state.ownSalt) };
  return { contribution: state.ownContribution };
}

/** Decide what an inbound salt frame means. See the four-cell table in the header. */
export function onPeerSaltFrame(state: {
  ownSalt: Uint8Array | null;
  ownContribution: Uint8Array;
  frame: SaltAgreementFrame;
}): SaltAgreementAction {
  const hasContribution = state.frame.contribution instanceof Uint8Array;
  const hasFingerprint = state.frame.fingerprint instanceof Uint8Array;

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
      return {
        action: "freeze",
        reason: SALT_FREEZE_REASONS.STATE_DIVERGENT,
        detail:
          "we hold this session's salt and the peer is offering a fresh contribution, which means theirs is gone. " +
          "It cannot be re-derived for them — the salt is a one-way function of two contributions and neither side keeps the inputs.",
      };
    }
    if (isTimingSafeEqual(saltFingerprint(state.ownSalt), state.frame.fingerprint!)) {
      return { action: "confirmed" };
    }
    return {
      action: "freeze",
      reason: SALT_FREEZE_REASONS.FINGERPRINT_MISMATCH,
      detail:
        `the peer's salt fingerprint does not match ours (ours is ${SALT_FINGERPRINT_BYTES} bytes, ` +
        `theirs was ${state.frame.fingerprint!.length}); every message from here would be discarded unread by one side or the other`,
    };
  }

  if (hasFingerprint) {
    return {
      action: "freeze",
      reason: SALT_FREEZE_REASONS.STATE_DIVERGENT,
      detail:
        "the peer already holds this session's salt and we do not, so we cannot reproduce it: the contributions it was derived from are gone on both sides. " +
        "Announcing anything back would leave the session half-agreed, whose only symptom is discarded messages.",
    };
  }

  try {
    // The primitive owns every degeneracy rule — length, all-zero, reflection — and owns the
    // WORDING too. Its refusals explain what a zero contribution means for both parties; replacing
    // that with a code of our own would be exit-point substitution (Invariant 2), destroying the
    // only explanation that exists at the only moment anyone will read it.
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
