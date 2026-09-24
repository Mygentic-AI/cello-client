/**
 * DOD-AWAY-MUTUAL-SEAL-1 — recognising this daemon's own away auto-replies.
 *
 * ── WHY THIS EXISTS ──────────────────────────────────────────────────────────────────────────────
 *
 * When two agents contact each other while BOTH are unattended, each side's away responder answers
 * the other's away responder. The second such arrival looks exactly like "a caller who ignored the
 * leave-a-message instruction", which is what `DOD-INBOX-ONESHOT-1` exists to handle — so both sides
 * send a `[[WRAP]]` rejection and initiate a seal. Two distinct-sender SEAL ctrl leaves is precisely
 * what triggers notarization.
 *
 * Measured on the relay's own log 2026-08-09: a session **sealed three seconds after it opened**,
 * its entire content being two machines telling each other nobody was home. Neither daemon learned
 * (the seal completion is pushed with no pull twin), so both kept showing `active`; the operators
 * came back, talked into a closed room for 68 minutes, and found out only at close.
 *
 * The one-shot rule is right about a human who keeps typing. It is wrong about another away
 * responder, which is not a caller ignoring anything.
 *
 * ── DOD-M12B-AWAY-MARK-1 (2026-08-17): A MARKER, PLUS THE EXACT MATCHING ────────────────────────
 *
 * A token at the front of the message TEXT, the same class of thing as `[[OVER]]` and `[[WRAP]]`,
 * which already ride in the body and which the receive path already parses.
 *
 * The marker exists because of a defect the mutual-seal fix does not touch. This daemon's away
 * responder answers when nobody is attending, and the reply goes out as an ordinary `msg` leaf at a
 * real sequence with nothing on it to say a machine wrote it. To the initiator that is positive
 * evidence a person is there. Measured 2026-08-17: two agents spent a morning exchanging each
 * other's away responders while both operators believed a conversation was happening.
 *
 * PREFIX, never suffix. `[[WRAP]]` detection is end-anchored on purpose (`DOD-WRAP-SUBSTRING-1`)
 * and the one-shot rejection ends with `[[WRAP]]`; a marker appended at the end would take that
 * position and silently break the counterparty's close detection.
 *
 * The marker LABELS, it never SUPPRESSES. An in-band token is spoofable — a human can type it — so
 * it must never be able to make a real message vanish. It changes what the reader is told, never
 * whether the reader is told.
 *
 * The texts live HERE and are read by both the sender and the detector. A second hardcoded copy is
 * how a reworded away message stops being recognised and the loop quietly returns. The marker is
 * applied at the single send choke point in `sendAwayResponse`, so a configured away message carries
 * it exactly like a default one does.
 *
 * A broader rule was tried and reverted: "never notarize a session on which this agent has only sent
 * away traffic". It disabled `DOD-INBOX-ONESHOT-1`'s designed behaviour — a REAL caller who ignores
 * the leave-one-message instruction should still get the inbox closed on them — and five tests
 * correctly caught it. The narrow rule is not a weaker version of the broad one; it is the correct
 * one, because the thing to suppress is a machine answering a machine, not an away agent sealing.
 */

/**
 * The in-band mark on every message this daemon generates without a human in the loop.
 *
 * DOD-M12B-AWAY-MARK-1. Prefixed, for the end-anchoring reason in the header. Deliberately shaped
 * like the existing `[[…]]` signal tokens: the receive path already parses that family, and a
 * human reading the transcript can see it.
 */
export const AWAY_AUTO_REPLY_MARKER = "[[AUTO-REPLY]]";

/** The offer text after the agent name. */
const OFFER_SUFFIX = " is currently away. Leave a message (send with signal: wrap to close) and it will be read when they return.";

/**
 * Prefix `text` with the auto-reply marker. IDEMPOTENT — the single send choke point in
 * `sendAwayResponse` marks whatever `resolveAwayMessage` returns, which for a system default is
 * already marked, and double-marking would put a stray token in front of every operator's greeting.
 */
export function markAsAutoReply(text: string): string {
  if (isAutoReplyMarked(text)) return text;
  return `${AWAY_AUTO_REPLY_MARKER} ${text}`;
}

/**
 * True when `text` carries the marker AT THE FRONT.
 *
 * Anchored, not a substring search: a message that merely mentions the marker is a person talking
 * about it, and labelling that as machine traffic teaches the reader to discount a human.
 */
export function isAutoReplyMarked(text: string): boolean {
  return text.startsWith(AWAY_AUTO_REPLY_MARKER);
}

/** The exact strings this daemon sends as away auto-replies. Marked at the source. */
export const AWAY_AUTO_REPLY_TEXTS = {
  /** The session-offer answer, which names the away agent — so it is built, not fixed. */
  offerFor(agentName: string): string {
    return `${AWAY_AUTO_REPLY_MARKER} ${agentName}${OFFER_SUFFIX}`;
  },

  /**
   * M8C-CONTACT-1: "unknown senders learn only 'dispatched' by default" — deliberately minimal.
   *
   * It stays bare after DOD-M15-AWAYSCOPE-1. Andre's principle 3 draws the line at ACCEPTED
   * sessions: a counterparty who accepted is entitled to know what happened to the session, and a
   * STRANGER knocking is not. Lives here beside its siblings for the reason the marker does: one
   * definition, so a reword cannot desynchronise the detector.
   */
  stranger: `${AWAY_AUTO_REPLY_MARKER} Dispatched.`,
} as const;

/**
 * The system default away text for an inbound session REQUEST, per whether the caller is known.
 * MOVED HERE from `attendance-wiring.ts` (DOD-M15-AWAYLEAF-1) so the selection sits beside the
 * strings it selects.
 *
 * The record that travelled with it:
 * - DOD-AWAY-WRAP-1 AC1: the request text is a leave-a-message greeting, and it names the specific
 *   away agent — which is why it is built rather than fixed.
 * - ONE definition, shared with the detector in this file. A second copy elsewhere is how a reworded
 *   away message stops being recognised as machine traffic and the mutual-seal loop
 *   (DOD-AWAY-MUTUAL-SEAL-1) quietly comes back.
 *
 * ⚠️ DOD-M15-AWAYSCOPE-1 TOOK THE SECOND KIND AWAY, and with it the reason this function took a
 * `kind` at all. There used to be a second arm for a message arriving on an ALREADY-ACCEPTED
 * session — the one-shot acknowledgement, `DOD-AWAY-ACK-ONESHOT-TEXT-1` — and sending it was the
 * defect: it typed a status announcement into a live conversation and took a chain leaf doing it.
 */
export function systemAwayText(agentName: string, isKnown: boolean): string {
  if (!isKnown) return AWAY_AUTO_REPLY_TEXTS.stranger;
  return AWAY_AUTO_REPLY_TEXTS.offerFor(agentName);
}
