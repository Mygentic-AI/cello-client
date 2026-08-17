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
 * This file used to argue against a marker, on the grounds that it is a WIRE change an older peer
 * would not send. That argument holds for a marker in the wire FRAME, and `AWAY_AUTO_REPLY_MARKER`
 * is not one — it is a token at the front of the message TEXT, the same class of thing as
 * `[[OVER]]` and `[[WRAP]]`, which already ride in the body and which the receive path already
 * parses. An older peer just sends text without it. So the exact matching below did not go away; it
 * became the LEGACY branch, and it is still the only thing that recognises an un-upgraded peer.
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
 * ── WHY EXACT MATCHING IS STILL HERE ────────────────────────────────────────────────────────────
 *
 * EXACT, never substring. A human who quotes the away message must still be answered; silencing a
 * real message is a worse failure than the one being fixed, because the operator would never learn
 * it arrived.
 *
 * The texts live HERE and are read by both the sender and the detector. A second hardcoded copy is
 * how a reworded away message stops being recognised and the loop quietly returns.
 *
 * ── WHY A CUSTOM AWAY MESSAGE ON THE FAR SIDE DOES NOT DEFEAT THIS ───────────────────────────────
 *
 * An operator can set their own away wording (`resolveAwayMessage`). Against a marker-aware peer
 * that is now solved outright — the marker is applied at the single send choke point in
 * `sendAwayResponse`, so a configured message carries it exactly like a default one does, and this
 * is the gap exact matching could not close by construction.
 *
 * Against an un-upgraded peer with custom wording, the original reasoning still applies and is
 * unchanged: **notarization requires TWO ctrl leaves from DISTINCT senders.** Declining on one side
 * is enough to break it: their one-shot posts one ctrl leaf, ours does not post the second, and no
 * certificate is minted. The session simply stays unsealed, which is the correct end for an
 * exchange nobody had.
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
 * like the existing `[[…]]` signal tokens: the receive path already parses that family, an older
 * peer reads it as plain text rather than choking, and a human reading the transcript can see it.
 */
export const AWAY_AUTO_REPLY_MARKER = "[[AUTO-REPLY]]";

/** The unmarked bodies. Kept separate so the legacy detector below matches an un-upgraded peer. */
const ONESHOT_BODY =
  "Agent is currently away. Your message has been received and will be read when the operator returns. " +
  "This inbox accepts one message per visit — please close the session now (send with signal: wrap) instead of sending more.";

/** The offer text with the agent name removed, so any agent's offer is recognised. */
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
  /**
   * The one-shot acknowledgement, sent when a message arrives for an unattended agent.
   * States the one-shot rule, because without it a cooperative caller has no reason to stop.
   */
  oneShot: `${AWAY_AUTO_REPLY_MARKER} ${ONESHOT_BODY}`,

  /** The session-offer answer, which names the away agent — so it is built, not fixed. */
  offerFor(agentName: string): string {
    return `${AWAY_AUTO_REPLY_MARKER} ${agentName}${OFFER_SUFFIX}`;
  },
} as const;

/**
 * True when `text` is away auto-reply traffic — a machine, not a caller.
 *
 * The caller must neither answer it nor count it toward the one-shot rule. Answering produces the
 * ping-pong; counting it produces the seal.
 *
 * Two branches, and both are needed. The MARKER branch covers any marker-aware peer including one
 * running a configured away message, which exact matching could never reach. The LEGACY branch
 * covers a peer on the pre-marker build sending this daemon's old default wording — remove it and
 * two away agents on mixed versions notarize a session nobody had, which is the whole of
 * DOD-AWAY-MUTUAL-SEAL-1.
 */
export function isOwnAwayAutoReply(text: string): boolean {
  if (text.length === 0) return false;
  if (isAutoReplyMarked(text)) return true;
  if (text === ONESHOT_BODY) return true;
  // The offer names an agent, so match the invariant tail — but require a non-empty name in front
  // of it, so a bare quote of the suffix alone is not treated as machine traffic.
  if (text.endsWith(OFFER_SUFFIX) && text.length > OFFER_SUFFIX.length) return true;
  return false;
}
