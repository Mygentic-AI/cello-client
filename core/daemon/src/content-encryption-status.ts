/**
 * WHY A SESSION HAS NO AGREED CONTENT KEY — `DOD-M15-EPHEMERAL-AUTH-1` (007-CRYPTO).
 *
 * ─── The rule, and it is deliberately absolute ─────────────────────────────────────────────────
 *
 * **A live message body is encrypted under the agreed session key, or it is not sent.** There is no
 * degraded mode, no "unencrypted but visibly so", and no negotiation.
 *
 * That is not strictness for its own sake — it is what removes an entire class of defect. A
 * fallback to plaintext is a thing an attacker steers a session into: strip the key frame, and a
 * system that "carries on, visibly degraded" hands over exactly the plaintext the attacker wanted,
 * while the operator sees a warning they have learned to scroll past. The salt can degrade because
 * a missing salt costs a correlation property; a missing KEY costs the message.
 *
 * ⚠️ AND THERE IS NO COMPATIBILITY CASE TO SERVE. CELLO is pre-launch with no external installs, so
 * "the counterparty is on a build that predates this" is not a state anything is in. Every reason
 * below is a FAULT — local, transient, or a counterparty that did not complete an exchange it is
 * running the code for. None of them is an accepted steady state, and none of them may be described
 * to an operator as one.
 *
 * ─── Not the same question as the salt ─────────────────────────────────────────────────────────
 *
 * `content_hashes_salted` is about a relay CONFIRMING a guess at a stored hash. This is about a
 * relay READING the message. A session can be salted and unencrypted; it cannot send while
 * unencrypted.
 *
 * ─── Why a closed set and a total map ──────────────────────────────────────────────────────────
 *
 * Copied from `refusal-reasons.ts`, which exists because a free-form `reason: string` let a new code
 * slip past every test in its own guard file. A `Record` over the union means a reason cannot be
 * added without something for the reader to do about it.
 */

/**
 * The `content_encryption` marker on a `content_frame`, naming the scheme its body is under.
 *
 * On the WIRE rather than inferred, so a receiver never has to guess a layout from a length — and
 * ABSENT is refused rather than read as plaintext. There is no unencrypted sender to accommodate, so
 * a missing marker is not "an old peer", it is a frame something rewrote.
 */
export const SESSION_CONTENT_ENCRYPTION_V1 = "session-aes-256-gcm-v1";

export const CONTENT_ENCRYPTION_REASONS = {
  /**
   * The exchange has not finished yet. Transient, and the ordinary state for the instant between a
   * session opening and its first connect completing.
   */
  NOT_YET_AGREED: "not_yet_agreed",
  /**
   * THIS machine has no identity key to sign its half with, so it cannot take part at all.
   *
   * Local setup fault — a signing-only or threshold provider, or an agent loaded without one. Named
   * apart from the peer cases because "we could not sign" and "they did not answer" send the
   * operator to opposite machines.
   */
  NO_LOCAL_IDENTITY: "no_local_identity",
  /** THIS side's half never left the machine. Local and transient; the next connect re-announces. */
  OUR_ANNOUNCE_FAILED: "our_announce_failed",
  /**
   * TERMINAL. The peer's key could not be tied to them and the session was stopped.
   *
   * ⚠️ THIS MUST SURVIVE THE TEARDOWN THAT FOLLOWS IT — review F2. The freeze destroys the session's
   * key material, and clearing the reason with it left the listing recomputing `NOT_YET_AGREED`, so
   * the one detection in this unit that means *someone may be substituting keys on your connection*
   * reached the agent as "still agreeing, please wait". A security refusal that reads as a
   * reassurance is worse than silence.
   */
  KEY_REFUSED: "key_refused",
  /**
   * The counterparty never sent their half.
   *
   * NOT "they are on an old build" — they are running this code. Something between the two of you
   * dropped the frame, or their daemon is not answering.
   */
  PEER_SILENT: "peer_silent",
} as const;

export type ContentEncryptionReason =
  (typeof CONTENT_ENCRYPTION_REASONS)[keyof typeof CONTENT_ENCRYPTION_REASONS];

/**
 * What the operator should DO. TOTAL over the union by construction.
 *
 * ⚠️ EVERY ENTRY NAMES A VERB THE READER CAN PERFORM, and none of them says "this is expected" —
 * because none of these is. An affordance that resolves to nothing is worse than none, and a
 * reassurance attached to a fault is worse than both.
 */
export const CONTENT_ENCRYPTION_GUIDANCE: Record<ContentEncryptionReason, string> = {
  [CONTENT_ENCRYPTION_REASONS.NOT_YET_AGREED]:
    "This session has not finished agreeing its encryption key with your counterparty, which happens " +
    "as soon as you are both connected. A message sent before it completes is NOT held and is NOT " +
    "sent in the open: it goes to your counterparty's relay mailbox instead, encrypted to their " +
    "long-term key, and they receive it when they next collect. It arrives — it just takes the slow " +
    "route, and that copy does not have the forward secrecy the direct path gives you. If this " +
    "persists, your counterparty is not reachable right now.",
  [CONTENT_ENCRYPTION_REASONS.NO_LOCAL_IDENTITY]:
    "THIS machine has no identity key available for this agent, so it cannot sign its half of the " +
    "session encryption key — and every session it opens has the same problem. Your counterparty did " +
    "nothing and does not need to change anything. Check that this agent was loaded with its identity " +
    "key, then start a new session.",
  [CONTENT_ENCRYPTION_REASONS.OUR_ANNOUNCE_FAILED]:
    "THIS side could not send its half of the session encryption key — the frame never left this " +
    "machine, so your counterparty was never asked. Do not raise it with them. Look for " +
    "session.key.announce.failed immediately above this line for the connection error; most often the " +
    "direct link dropped between connecting and sending. It re-announces on the next connect.",
  [CONTENT_ENCRYPTION_REASONS.KEY_REFUSED]:
    "STOPPED ON PURPOSE. The session encryption key your counterparty sent could not be tied to " +
    "them, so this session was stopped rather than carried on in the open. The ordinary cause is a " +
    "build mismatch. The one that matters is something between you substituting its own key so it " +
    "can read what you send — which is exactly what this check exists to catch. Confirm with your " +
    "counterparty OUT OF BAND, not over CELLO, before opening another session with them.",
  [CONTENT_ENCRYPTION_REASONS.PEER_SILENT]:
    "Your counterparty never sent their half of the session encryption key. They are running the same " +
    "protocol, so this is not a version difference — either the frame was dropped between you, or " +
    "their daemon is not answering. Check they are online, then start a new session. Nothing was sent " +
    "in the open in the meantime.",
};

/**
 * ⚠️ **THE SAME REASONS, TOLD TO THE OTHER DIRECTION** — `029c` review F6.
 *
 * `CONTENT_ENCRYPTION_GUIDANCE` above is written for the SEND path: it explains what became of a
 * message THIS operator tried to send. The inbound refusal (`no_session_key`) was reusing it
 * verbatim, so an operator who could not open an INCOMING message read advice about their own
 * outbound mail — *"A message sent before it completes … goes to your counterparty's relay
 * mailbox"* — two directions and two mailboxes in one paragraph.
 *
 * The CAUSE is identical, so the reason set is shared; only the consequence differs, so only the
 * prose is. Total over the union for the same reason the other map is: a new reason cannot be added
 * without deciding what it means to the receiving side.
 */
export const CONTENT_ENCRYPTION_INBOUND_GUIDANCE: Record<ContentEncryptionReason, string> = {
  [CONTENT_ENCRYPTION_REASONS.NOT_YET_AGREED]:
    "This conversation had not finished agreeing its encryption key when their message arrived, " +
    "which normally completes within a second of you both being connected. Nothing is wrong with " +
    "their message or their build. If it keeps happening, one of you is not staying connected long " +
    "enough for the exchange to finish.",
  [CONTENT_ENCRYPTION_REASONS.NO_LOCAL_IDENTITY]:
    "THIS machine has no identity key available for this agent, so it cannot take part in the " +
    "encryption exchange at all — and every conversation it opens has the same problem. Your " +
    "counterparty did nothing and does not need to change anything. Check that this agent was " +
    "loaded with its identity key, then start a new conversation.",
  [CONTENT_ENCRYPTION_REASONS.OUR_ANNOUNCE_FAILED]:
    "THIS side never sent its half of the encryption key, so your counterparty could not finish the " +
    "exchange and you cannot open what they sent. The fault is local — do not raise it with them. " +
    "Look for session.key.announce.failed for the connection error; it re-announces on the next " +
    "connect, so a new conversation usually clears it.",
  [CONTENT_ENCRYPTION_REASONS.KEY_REFUSED]:
    "STOPPED ON PURPOSE. The encryption key your counterparty sent could not be tied to them, so " +
    "this conversation was stopped rather than carried on in the open — which is why their message " +
    "cannot be opened now. The ordinary cause is a build mismatch. The one that matters is " +
    "something between you substituting its own key so it can read what you exchange. Confirm with " +
    "them OUT OF BAND, not over CELLO, before opening another conversation.",
  [CONTENT_ENCRYPTION_REASONS.PEER_SILENT]:
    "Your counterparty never sent their half of the encryption key, so there is nothing here to " +
    "open their message with. They are running the same protocol, so this is not a version " +
    "difference — either the frame was dropped between you, or their daemon is not answering. " +
    "Check they are online, then start a new conversation.",
};

/**
 * Render a reason for an agent.
 *
 * ⚠️ NO UNKNOWN-REASON FALLBACK, deliberately. The value is produced and consumed in one process
 * from the closed set above — there is no column it is read back from and no other build writing
 * one, so a "reason this version does not recognise" is a state nothing can be in. An earlier cut
 * carried that branch anyway and described the value as coming off a database row, which was simply
 * untrue. Unreachable defensive code that states a false provenance is worse than no code: it reads
 * as a considered case and it is scaffolding for a world that does not exist.
 *
 * The map is TOTAL over the union, so the type is the check.
 */
export function contentEncryptionGuidanceFor(reason: ContentEncryptionReason): string {
  return CONTENT_ENCRYPTION_GUIDANCE[reason];
}
