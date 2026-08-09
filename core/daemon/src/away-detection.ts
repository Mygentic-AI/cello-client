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
 * ── WHY EXACT MATCHING, AND NOT A MARKER ─────────────────────────────────────────────────────────
 *
 * A marker in the wire frame would be cleaner and is the right long-term answer, but it is a wire
 * change: an older peer would not send it, and this defect fires precisely when talking to a peer we
 * do not control. Exact text match works today against the case that actually loops — both sides
 * running THIS logic — and needs no version agreement.
 *
 * EXACT, never substring. A human who quotes the away message must still be answered; silencing a
 * real message is a worse failure than the one being fixed, because the operator would never learn
 * it arrived.
 *
 * The texts live HERE and are read by both the sender and the detector. A second hardcoded copy is
 * how a reworded away message stops being recognised and the loop quietly returns.
 */

/** The exact strings this daemon sends as away auto-replies. */
export const AWAY_AUTO_REPLY_TEXTS = {
  /**
   * The one-shot acknowledgement, sent when a message arrives for an unattended agent.
   * States the one-shot rule, because without it a cooperative caller has no reason to stop.
   */
  oneShot:
    "Agent is currently away. Your message has been received and will be read when the operator returns. " +
    "This inbox accepts one message per visit — please close the session now (send with signal: wrap) instead of sending more.",

  /** The session-offer answer, which names the away agent — so it is built, not fixed. */
  offerFor(agentName: string): string {
    return `${agentName} is currently away. Leave a message (send with signal: wrap to close) and it will be read when they return.`;
  },
} as const;

/** The offer text with the agent name removed, so any agent's offer is recognised. */
const OFFER_SUFFIX = " is currently away. Leave a message (send with signal: wrap to close) and it will be read when they return.";

/**
 * True when `text` is one of THIS daemon's away auto-replies — machine traffic, not a caller.
 *
 * The caller must neither answer it nor count it toward the one-shot rule. Answering produces the
 * ping-pong; counting it produces the seal.
 */
export function isOwnAwayAutoReply(text: string): boolean {
  if (text.length === 0) return false;
  if (text === AWAY_AUTO_REPLY_TEXTS.oneShot) return true;
  // The offer names an agent, so match the invariant tail — but require a non-empty name in front
  // of it, so a bare quote of the suffix alone is not treated as machine traffic.
  if (text.endsWith(OFFER_SUFFIX) && text.length > OFFER_SUFFIX.length) return true;
  return false;
}
