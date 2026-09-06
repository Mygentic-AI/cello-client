/**
 * Refusal reason codes shared between the site that RECORDS a refusal and the site that EXPLAINS it.
 *
 * DOD-M15-OFFER-SIGNED-1 review N8. These strings were duplicated literals across
 * `inbound-sessions.ts` (which calls `recordRefusal`) and `notification-handlers.ts` (which looks
 * the reason up to attach guidance), with nothing binding them. Rename or mistype either side and
 * the lookup silently misses: the operator gets a bare reason code again, which is exactly the
 * defect the guidance was added to fix — reintroduced by a typo, with every test still green.
 *
 * A shared constant makes that a compile error instead. `REFUSAL_REASONS` is the single source; the
 * guidance table below is keyed by its values, so a reason without guidance cannot be added silently.
 */

/**
 * DOD-M15-NO-SILENT-REFUSAL-1 — WHAT KIND of thing happened to the message.
 *
 * ⚠️ **THE HEADER OVER A LIST OF REFUSALS CANNOT BE ONE SENTENCE, and review F4 measured why.**
 * The `refused` sentence below was written for three hash-verification reasons and every clause
 * of it was true of them: received, not verified, not ingested, not shown, sender never told. Carry
 * that sentence verbatim onto the nine other reasons and each clause breaks somewhere —
 *
 *  - a SCREENER block was verified and IS in the hash chain, and the sender WAS acknowledged;
 *  - a transcript write failure was verified and committed, and the sender IS told;
 *  - `delivery_impaired` is not an inbound message at all — it is this side's own send failing, so
 *    the sentence names the wrong direction of travel and sends the operator to the counterparty
 *    about a fault on their own machine.
 *
 * So the notice carries its kind and the door composes the header from the kinds actually present.
 * The `refused` sentence is unchanged, for the set it was written for.
 */
export const REFUSAL_KINDS = {
  /** Received, could not be accepted. Not ingested, not shown, and the sender was not told. */
  REFUSED: "refused",
  /** Received, verified, RECORDED in the chain and ACKNOWLEDGED — deliberately not shown. */
  BLOCKED: "blocked",
  /** Received; nothing recorded, nothing acknowledged. The sender's daemon redelivers on its own. */
  DEFERRED: "deferred",
  /** Received and committed to the chain, then LOST to a local storage failure. Unrecoverable. */
  LOST: "lost",
  /** Nothing was received. This side's own send or acknowledgement failed to reach them. */
  OUTBOUND: "outbound",
} as const;

export type RefusalKind = (typeof REFUSAL_KINDS)[keyof typeof REFUSAL_KINDS];

/**
 * The header for each kind — total over `RefusalKind`, so a new kind cannot be added without one.
 *
 * ⚠️ IT TRAVELS WITH THE NOTICES, NEVER SEPARATELY. When only one exit carried a header, a catch-up
 * read drained the refusals into a payload with no advice at all, and the operator's next blocking
 * read then said "call again and keep waiting" — the notice was already gone. Every door returns the
 * two together for that reason.
 */
/**
 * DOD-M15-REFUSALTERMINAL-1 — what the counts on a refusal notice mean, for EVERY door that shows
 * one.
 *
 * ⚠️ **ONE constant because there are TWO doors.** `cello_inbox` and `cello_receive` both surface
 * refusals, and review F4 caught the receive door shipping the new field names with no sentence
 * explaining them — the misreading this line exists to end, moved rather than fixed. A second copy
 * is a second thing to keep true.
 *
 * The defect being described: on 2026-09-04 an operator read `times: 58` for a refusal that had
 * fired tens of thousands of times over two and a half days, and concluded it was minor. The
 * counter was accurate; the word `times` was the lie.
 */
export const REFUSAL_COUNT_GUIDANCE =
  "THE TWO COUNTS MEAN DIFFERENT THINGS. `times_since_dismissed` counts only the refusals since " +
  "the operator last ran cello_dismiss on that conversation — dismissing clears the notice, never " +
  "the cause — so it can be small while the real figure is enormous. Judge severity by the " +
  "lifetime one instead, which arrives as ONE of these two: `times_total` is an exact count from " +
  "the first refusal; `times_total_at_least` is a FLOOR, for a conversation whose tally began when " +
  "this daemon was upgraded, and the true figure may be far higher. If NEITHER is present, this " +
  "notice could not be written to disk (see session.refusal.persist.failed) and its scale is " +
  "unknown — in that case do not read the smaller number as the total.";

export const REFUSAL_KIND_GUIDANCE: Record<RefusalKind, string> = {
  /**
   * VERBATIM, and deliberately so: this is the sentence the previous unit wrote for exactly this
   * set, it is the one that makes the notice actionable, and a note in the tree records that a
   * catch-up door destroyed it once already.
   */
  [REFUSAL_KINDS.REFUSED]:
    /**
     * ⚠️ **"THEY WERE NOT VERIFIED" WAS DROPPED, and it is the F4 defect one level further down.**
     *
     * That clause was true of the three hash failures this header was written for, and of an
     * unattributable sender. It is FALSE of a message refused because the conversation had already
     * closed, and false of one that hit the sender's size limit — those messages may be perfectly
     * valid and fully verified, and were refused for arriving too late or being too large. A header
     * that tells the operator their counterparty sent something unverifiable, when the counterparty
     * did nothing wrong, is an accusation.
     */
    "Message(s) from this counterparty were received and refused, so they were not delivered. " +
    /**
     * ⚠️ "WAITING HERE WILL NOT HELP" IS LOAD-BEARING and an existing test guards it: the exit this
     * header rides on is a receive that timed out, and without this sentence the operator is handed
     * a reason next to an instruction to keep waiting.
     *
     * Worded "waiting HERE", not the original "waiting will not help" — which is false for one of
     * these. The salt branch has a cause that repairs itself on the next reconnect, and its own
     * guidance says to wait for exactly that. What is universally true is that sitting on this call
     * fixes nothing; the reason below is where the fix is.
     */
    "Waiting here will not help — the reason below says what will. See " +
    "`refusals` for it. The counterparty has no way to know: from their " +
    "side the message was sent. DO NOT REACH FOR A RESEND BY DEFAULT — the reason below says what to " +
    "do, and two of them are already being redelivered on a loop while one cannot be fixed for this " +
    "conversation at all.",
  [REFUSAL_KINDS.BLOCKED]:
    "Message(s) aimed at this agent were BLOCKED by its screener. They were verified and they ARE " +
    "recorded in the conversation's hash chain, and the sender WAS acknowledged — so they do not " +
    "know, they will not resend, and nothing is waiting on you. They were never shown to the agent, " +
    "and that is the protection working. Do not go looking for the blocked text and do not turn " +
    "screening off to read it.",
  [REFUSAL_KINDS.DEFERRED]:
    "Message(s) from this counterparty could not be checked and were not accepted. Nothing was " +
    "recorded and nothing was acknowledged, so the message is still on their side and their agent " +
    "will send it again by itself once the cause clears. DO NOT READ THE SILENCE AS DELIVERY, and do " +
    "not ask them to resend — a resend would take a second place in the record. Fix the cause named " +
    "below.",
  [REFUSAL_KINDS.LOST]:
    "Message(s) reached this agent and were committed to the conversation's record, and then could " +
    "not be written to local storage, so they can never be delivered. THIS IS A FAULT ON THIS " +
    "MACHINE, not a quiet counterparty. Waiting cannot recover them; the text is gone and only its " +
    "hash remains. Fix the local fault named below, then ask them to resend.",
  [REFUSAL_KINDS.OUTBOUND]:
    "NOTHING WAS REFUSED BY THIS AGENT — this is the other direction. A message YOU sent did not get " +
    "through, and could not be saved to send later, so it is gone. Do not go to the counterparty " +
    "about it: they never saw it and there is nothing for them to do. Send it again.",
};

export const REFUSAL_REASONS = {
  /** The session_offer and the session_assignment named different dialers for one session. */
  OFFER_ASSIGNMENT_DIALER_MISMATCH: "offer_assignment_dialer_mismatch",
  /** The directory named a different threshold group key for an already-known counterparty. */
  COUNTERPARTY_PRIMARY_KEY_CHANGED: "counterparty_primary_key_changed",
  /** The inbound assignment failed verification (signature, signer, or shape). */
  INBOUND_ASSIGNMENT_INVALID: "inbound_assignment_invalid",
  /**
   * 038-KEYBIND — the caller's assignment carried no proof that its threshold key is theirs, or
   * carried one that does not hold.
   *
   * ⚠️ ITS OWN REASON, not folded into INBOUND_ASSIGNMENT_INVALID, because the remedy is different
   * and the other one's remedy is actively wrong here. "The assignment did not verify" tells the
   * caller their frame was damaged and to start a new session; a retry cannot produce a binding
   * that was never minted. What this actually means is that the caller registered against a
   * directory that predates the proof, and the fix is on their side and is a re-registration.
   */
  INBOUND_ASSIGNMENT_KEY_BINDING: "inbound_assignment_key_binding",
  /**
   * `DOD-M15-SELFCHAIN-1` — a session was offered with NO directory assignment to anchor it.
   *
   * ⚠️ TREATED AS SUSPICIOUS, NOT AS A MISSING OPTIONAL. Every real session is brokered: the
   * directory FROST-signs an establishment record and each side verifies it before the session
   * begins. That record carries the conversation's STARTING POINT — the value every first message
   * chains to — so a session without one is a conversation whose order could never be proven.
   *
   * Nothing legitimate produces it. A counterparty that offers one is either running software that
   * cannot participate in the record, or trying to open a conversation that leaves none.
   */
  SESSION_WITHOUT_ASSIGNMENT: "session_without_assignment",
  /**
   * A session offer whose directory assignment IS there and cannot be read — its session id or one
   * of its two participants is missing or malformed.
   *
   * ⚠️ SEPARATE FROM `SESSION_WITHOUT_ASSIGNMENT`, AND THE SPLIT IS THE POINT. Both came out of the
   * same `null` return, so a wire or version fault was reaching the operator under a notice reading
   * "NOTHING LEGITIMATE PRODUCES THIS. TREAT IT AS SUSPICIOUS." One exit point standing in for two
   * causes, and the wrong one of the two was the loud one — which teaches an operator to scroll
   * past the notice that matters.
   */
  ASSIGNMENT_UNREADABLE: "assignment_unreadable",
} as const;

export type RefusalReason = (typeof REFUSAL_REASONS)[keyof typeof REFUSAL_REASONS];

/**
 * The CAPACITY refusals — bounds, not security findings.
 *
 * These deliberately carry no guidance: their codes say what happened, and the cap path already
 * sends the sender their own numbers over the wire. They are declared here anyway so that
 * `recordRefusal` can take a CLOSED union.
 *
 * ⚠️ BYTE-IDENTICAL BY DESIGN. A BLOCKED sender and an over-cap UNKNOWN one must be
 * indistinguishable, or the refusal tells someone they are blocked. Do not add a reason that
 * separates them.
 */
export const CAPACITY_REASONS = {
  ABUSE_BOUND_SESSIONS_PER_SENDER: "abuse_bound_sessions_per_sender",
  ABUSE_BOUND_UNKNOWN_SESSIONS_GLOBAL: "abuse_bound_unknown_sessions_global",
} as const;

export type CapacityReason = (typeof CAPACITY_REASONS)[keyof typeof CAPACITY_REASONS];

/**
 * Every reason a session may be refused with — the CLOSED set.
 *
 * ─── Why this is a union and not `string` ──────────────────────────────────────────────────────
 *
 * `recordRefusal` used to take `reason: string`, because capacity bounds legitimately pass their own
 * codes. A review measured what that permitted: **add a new security refusal recording a free-form
 * `"assignment_epoch_replayed"` and the entire gate stays green** — the guard fires, the operator
 * gets a bare code with no guidance, and nothing notices, because every test enumerates
 * `REFUSAL_REASONS` and the new code was never in it.
 *
 * That is the guard-nobody-hears pattern in its FORWARD direction: not the four occurrences already
 * fixed, but the next one. A test cannot see a code that does not exist yet. A type can.
 *
 * So the set is closed. Adding a refusal now means adding a member here, and a security member
 * without guidance fails to compile against `REFUSAL_GUIDANCE`'s total map. `DOD-M15-GUARD-HEARD-1`.
 */
export type AnyRefusalReason = RefusalReason | CapacityReason;

/**
 * What the operator should DO, per reason.
 *
 * A bare reason code is not an affordance. These are the SECURITY refusals from the inbound
 * assignment path — the ones where the operator needs to know something was refused on purpose,
 * what it means, and (for the identity change) that the next step happens OUTSIDE CELLO.
 *
 * Typed as a total map over `RefusalReason`, so adding a reason without guidance fails to compile.
 *
 * ⚠️ THE READER IS THE RESPONDER'S OPERATOR, and every verb here must be one THEY can perform.
 * Two of these said "Retry" — which is the INITIATOR's move. The person reading this did not start
 * the session and has nothing to retry; telling them to is an affordance that resolves to nothing,
 * which is worse than no advice because they will try to follow it. The retry advice belongs in the
 * `session_refused` frame, which goes to the side that can act on it.
 */
export const REFUSAL_GUIDANCE: Record<RefusalReason, string> = {
  /**
   * ⛔ THE REPORTING LINE IS OWED AND IS DELIBERATELY ABSENT — `CELLO_Reporting` DOES NOT EXIST YET.
   *
   * Andre asked (2026-09-06) for this notice to tell the operator to report the attempt to
   * `CELLO_Reporting`, which he expected to be in every address book. It is designed and not
   * provisioned — `orphan-triage.ts` carries the same standing trigger, and
   * `dod-m15-no-silent-refusal-1.test.ts` asserts that no guidance names it.
   *
   * Naming it now would be an affordance that resolves to nothing: the reader would go looking for
   * a contact they do not have, which is worse than no advice because they will try to follow it.
   *
   * ⚠️ AND IT IS THE ADVICE A STRANGER ACTUALLY NEEDS. The notice below gives ONE instruction, for
   * a counterparty the operator recognises: reach them out of band. You cannot do that with an
   * unknown agent — there is no channel and no one to ask.
   *
   * ⚠️ AND THE STRANGER CASE IS SAID BY SAYING NOTHING, deliberately. A draft ended with "if you do
   * not know them, do not accept a session from them" — which restates the header: it was ALREADY
   * refused, and the reader is not being offered a choice. Advice that repeats the outcome spends
   * the reader's attention and gives them nothing to do with it.
   *
   * Reporting is the only action that would work for the stranger, and it is precisely the one that
   * does not exist yet. That is what makes provisioning it worth doing rather than a nicety: today
   * the notice has nothing at all to offer that reader.
   *
   * ⛔ TRIGGER: when `CELLO_Reporting` is provisioned and its pubkey published, add a sentence here
   * telling the operator to report the attempt to it, and drop the assertion in that test.
   */
  [REFUSAL_REASONS.SESSION_WITHOUT_ASSIGNMENT]:
    "REFUSED ON PURPOSE, AND TREAT IT AS SUSPICIOUS. Somebody tried to open a conversation with " +
    "you without the directory record that every real session carries. That record is what fixes " +
    "the conversation's starting point, and every message chains to it — so a session without one " +
    "is a conversation whose order could never be proven afterwards, by you or by anyone. NOTHING " +
    "LEGITIMATE PRODUCES THIS. IF THEY LOOK LIKE SOMEONE YOU KNOW, reach them OUT OF BAND — send " +
    "an email or a direct message, some channel that is not this one — and tell them their agent " +
    "cannot hold a provable conversation with anyone while it is in this state.",
  [REFUSAL_REASONS.ASSIGNMENT_UNREADABLE]:
    // "REFUSED ON PURPOSE" is a cross-cutting invariant (`DOD-M15-GUARD-HEARD-1`): every refusal
    // guidance says the refusal was deliberate, so an operator never reads one as a malfunction.
    "REFUSED ON PURPOSE, AND PROBABLY NOT AN ATTACK. Somebody tried to open a conversation with " +
    "you and the directory record they brought could not be read — a field it must carry is " +
    "missing or the wrong shape. That is what a version difference between their agent and yours " +
    "looks like, and it is by far the likeliest explanation. Ask them OUT OF BAND — a channel that " +
    "is not this one — which version they are running; if you are both current, ask them to try " +
    "again, because a record damaged in transit produces exactly this too.",
  [REFUSAL_REASONS.COUNTERPARTY_PRIMARY_KEY_CHANGED]:
    "REFUSED ON PURPOSE. The directory named a different signing identity for a contact you have " +
    "completed sessions with before. Either they genuinely re-registered — confirm that with them " +
    "OUT OF BAND (a channel that is not this one), then run cello_contact_remove for them, which " +
    "clears the pinned identity so the next session re-pins — or a directory is substituting an " +
    "identity. Do not accept a session from them until you know which.",
  [REFUSAL_REASONS.OFFER_ASSIGNMENT_DIALER_MISMATCH]:
    "REFUSED ON PURPOSE. The directory's session offer named one dialer and the session assignment " +
    "named another, so the two frames for one session disagree. A stale or replayed offer produces " +
    "this too, so one occurrence is not proof of a hostile directory. Nothing was accepted, and " +
    "nothing is wrong on your side — the other party has been told to start a new session. If the " +
    "SAME counterparty keeps failing this way, stop treating it as noise: confirm out of band that " +
    "they are the one dialling you, and until they answer, do not accept a session from them.",
  [REFUSAL_REASONS.INBOUND_ASSIGNMENT_INVALID]:
    "REFUSED ON PURPOSE. The session assignment did not verify, so this agent would have been " +
    "opening its receiver to a peer named by a document it could not check. Nothing was accepted. " +
    "There is nothing for you to retry — the other party holds the session and has been told to " +
    "start a new one. If it repeats for the SAME counterparty, do not accept anything from them " +
    "until you have confirmed out of band that they still control the identity you know them by.",
  [REFUSAL_REASONS.INBOUND_ASSIGNMENT_KEY_BINDING]:
    "REFUSED ON PURPOSE. Your session record did not carry the proof that the threshold signing key " +
    "on it is yours — the signature your own identity key makes over it at registration. Without " +
    "that, they would be taking a directory's word for which key is yours, and recording it as your " +
    "identity for every future conversation. Retrying will not produce it. Run cello_status: if your " +
    "agent registered before this proof existed, re-register it and the proof is minted and " +
    "published; if it is current, the directory node that brokered this is dropping the field, and " +
    "another node will serve it.",
};

/**
 * 033-ACKEMIT — what the operator is told when the RELAY refuses to witness a message because the
 * acknowledgement this daemon signed contradicts the relay's own record.
 *
 * ⚠️ **A PURE FUNCTION, AND THAT IS THE POINT.** The two sentences it returns lived inline at the
 * one call site, which sits behind a real relay answering a real `hash_submit_error` — so nothing in
 * the suite could reach them, and the guard's own comment invoked the "a refusal nobody hears"
 * pattern while being, itself, untestable. Review F6 then found the `relay_fault` remedy naming a
 * move that does not exist ("sending again usually picks a healthy one" — a session keeps the relay
 * its assignment names, and there is no handover anywhere). Pulling the text out is what lets a test
 * hold it.
 *
 * `relayFault` is `ack_hash_unverifiable`: the relay's counter reached a position its own leaf log
 * did not, which is a fault on the relay and NOT something either participant did. It is separate
 * from a mismatch for that reason — sending an operator to ask their counterparty about a problem
 * the witness caused spends their attention on the wrong party.
 */
export function relayAckHashRefusalNotice(relayFault: boolean, mailboxRouteAvailable: boolean): {
  impact: string;
  guidance: string;
} {
  const impact = relayFault
    ? "the relay could not check what this agent said it had received, so it did not witness this message. The message was still sent; it has no place in the notarized record."
    : "the relay REFUSED to witness this message: what this agent signed as the last thing it received from your counterparty does not match what the relay recorded at that position. The message was still sent, and it has no place in the notarized record. Your copy of this conversation and the witness's copy have stopped agreeing.";
  const guidance = relayFault
    ? "Nothing to change on your machine — the fault is on the relay this session is bound to, and it cannot be moved: a session keeps the relay its assignment names. Your messages still reach your counterparty; what stops is the notarized record growing. Close the session (cello_close_session) while its record is still worth notarizing, and open a new one, which will be assigned a relay afresh."
    : "Do NOT rely on a receipt for this conversation until this stops. Send one more message: if it is witnessed, this was a one-off. If it repeats, the two records genuinely disagree — confirm what your counterparty actually sent you OUT OF BAND, then close this session and open a new one." +
      (mailboxRouteAvailable ? "" : "");
  return { impact, guidance };
}
