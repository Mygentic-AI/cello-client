/**
 * CELLO Daemon — WHY A PARKED MESSAGE NEVER LEFT THE RELAY MAILBOX, said to the OPERATOR.
 *
 * `041-PARKSTUCK`. Every refusal the park drain can produce already had a `reason`, an `impact` and
 * a `guidance` — written for a person, at ERROR, in `daemon.log`. None of them called
 * `noteContentRefusal`, so no person ever received one. What the operator saw instead was the
 * INGEST reason (`session_committed`), which says where the message was turned away on arrival and
 * says nothing about why it will not leave: error substitution, in the one place there is no
 * upstream for the reader to chase, because `daemon.log` is not an operator affordance.
 *
 * ⚠️ **A CLOSED SET WITH A TOTAL NOTICE MAP, for the reason `refusal-reasons.ts` gives.** The park
 * drain pushed bare string literals into its refusal list, so a new branch could ship a reason the
 * operator surface had never heard of and every test would stay green — a test cannot enumerate a
 * code that does not exist yet, and a type can. Adding a member here without a notice below is a
 * compile error.
 *
 * ⚠️ **THE GUIDANCE IS A FUNCTION OF THE SESSION'S STATUS, and that is the defect it exists to
 * fix.** The salt branch's log line told operators *"this message will keep being re-pulled and
 * re-refused until the session is closed, so close it and start a new one"* — for a session that
 * had been closed three days earlier, which is what made the refusal permanent in the first place.
 * Advice naming an action the reader already took is worse than silence: it spends the trust they
 * would otherwise bring to the next notice.
 */
import { REFUSAL_KINDS, type RefusalKind } from "./refusal-reasons.js";

/**
 * Every reason the park drain can decline to file a parked message with.
 *
 * These are the ANNEX reasons — why the entry is STUCK — and they are deliberately distinct from
 * the ingest reason that sits beside them on the same message. Both reach the inbox; the ingest one
 * says the conversation is closed, this one says why the message cannot leave the mailbox.
 */
export const PARK_REFUSAL_REASONS = {
  /** The sender named a salted algorithm and this side holds no usable salt for the session. */
  ANNEX_SALT_UNAVAILABLE: "annex_salt_unavailable",
  /** The sender named a content-hash algorithm this build cannot compute. */
  ANNEX_ALG_UNKNOWN: "annex_alg_unknown",
  /** The content does not match the hash the sender signed over. */
  ANNEX_HASH_MISMATCH: "annex_hash_mismatch",
  /** The park envelope could not be decoded. */
  ANNEX_DECODE_FAILED: "annex_decode_failed",
  /** The inbound screener was unreachable. TRANSIENT — the relay copy is kept and re-screened. */
  ANNEX_SCREEN_UNAVAILABLE: "annex_screen_unavailable",
  /** The annex write itself ran and failed. */
  ANNEX_WRITE_FAILED: "annex_write_failed",
  /**
   * The inbound screener TERMINALLY blocked the content. Retained as quarantined evidence and
   * deleted from the relay — the only park branch that destroys the remote copy on purpose.
   *
   * ⚠️ IT HAD NO OPERATOR SURFACE AT ALL — review M9. It is the branch with the strongest claim on
   * an operator's attention (hostile bytes aimed at a conversation that is already closed) and the
   * only one that deletes the relay's copy in silence, and its `impact` field was addressed to
   * nobody. Unit 2's scope is every `content.recover.*` refusal, not only the one that loops.
   */
  ANNEX_SCREENED_OUT: "annex_screened_out",
} as const;

export type ParkRefusalReason = (typeof PARK_REFUSAL_REASONS)[keyof typeof PARK_REFUSAL_REASONS];

/** What the notice writer knows about the message it is refusing. */
export interface ParkRefusalContext {
  /**
   * The session's status as THIS daemon holds it, or `null` when the record could not be read.
   *
   * `null` is not "not terminal" — it is "we do not know", and the two must not collapse: the
   * release in `content-park.ts` is gated on proven terminality, so an unreadable record keeps the
   * relay copy rather than deleting it on an assumption.
   */
  readonly sessionStatus: string | null;
  /**
   * Has the relay copy been DELETED as a result of this refusal? Only the permanently-unverifiable
   * exit sets it, and the sentence the operator reads changes completely on it.
   */
  readonly released: boolean;
  /** The algorithm name the sender put in the envelope, or `(absent)`. */
  readonly declaredAlg: string;
  /**
   * WHY there is no salt, for the salt branch only.
   *
   * `none` — no salt was ever agreed for this session. `unreadable` — a salt row EXISTS on this
   * machine and could not be used (wrong width, or the read threw), which is local damage and sends
   * the operator somewhere completely different. `null` for every other reason.
   */
  readonly saltReason: "none" | "unreadable" | null;
  /**
   * The thrown message, for the two reasons that come from a `catch`.
   *
   * Review M4: the upstream cause must survive downstream (Invariant 3). A notice that says "it
   * threw" without saying what it said sends the operator back to the log for the one fact that
   * would have told them whether this is their disk, their build, or the sender.
   */
  readonly errorDetail: string | null;
}

/**
 * The two session statuses from which nothing can change back.
 *
 * `seal_interrupted_pending` is deliberately NOT here — `types.ts` documents it as explicitly
 * non-terminal, and a session still moving toward a notarization is not a session whose inputs are
 * immutable. Excluding it costs a few more drains on a rare state and keeps the release honest.
 */
export const TERMINAL_SESSION_STATUSES: ReadonlySet<string> = new Set(["sealed", "abandoned"]);

/** The one sentence every reader of a park refusal needs before the reason: nobody did anything wrong. */
const NOT_THEIR_FAULT =
  "The sender's signature on this message VERIFIED, so nothing here says they did anything wrong " +
  "and there is no version of theirs to ask about.";

/**
 * A closed conversation cannot be reopened, so "close it" is never the advice for one — but the
 * reader still needs a next step, and for a released message the honest one is that there is none
 * inside CELLO.
 */
function saltGuidance(ctx: ParkRefusalContext): string {
  /**
   * ⚠️ THE TWO CAUSES SEND THE OPERATOR TO OPPOSITE PLACES — one to the conversation, one to their
   * own disk — and only the first can ever be released. A message is dropped from the relay solely
   * on `none`; `unreadable` keeps its copy, because the read that failed may succeed next drain.
   * So the `unreadable` text below never appears beside "there is nothing to retry", and review H2
   * measured the pair contradicting each other when it could.
   */
  const cause =
    ctx.saltReason === "unreadable"
      ? "A salt row for this conversation EXISTS on this machine and could not be used — the read " +
        "failed, or the stored value is the wrong shape. That is a fault on YOUR side, not anything " +
        "the sender did, and it may simply be a database that was busy. Look for " +
        "session.salt.read.failed in the daemon log; if it does not repeat, the next attempt will " +
        "check this message normally."
      : "No salt was ever agreed for this conversation, so there is nothing here to check the " +
        "message against. Look for session.salt.persist.failed or session.salt.announce.failed in " +
        "the daemon log for which half never completed.";
  if (ctx.released) {
    /**
     * ⚠️ **IT NAMES WHERE THE BYTES STILL ARE — review M7, and the affordance was missing.**
     *
     * The reader is told a message existed, was never shown to them, and is gone from the relay.
     * Without the next sentence that is a dead end, and the log line for the same event already
     * said `cello_quarantined` — so the person who needed it was the only one not told.
     *
     * Safe to promise only because the release is now gated on the retention having SUCCEEDED
     * (review H1). Before that gate this sentence would have been a lie on exactly the daemons
     * where it mattered most.
     */
    return (
      `${cause} THERE IS NOTHING TO REPAIR AND NOTHING TO RETRY. This conversation is closed ` +
      `("${ctx.sessionStatus}"), so no salt can ever be agreed for it and this message could never ` +
      `have been checked on any future attempt. The relay's copy has now been dropped, which is what ` +
      `stops it being pulled and refused every few minutes forever. THE MESSAGE ITSELF IS STILL HERE: ` +
      `this agent kept the bytes it could not check, and cello_quarantined shows them — treat what ` +
      `you read there as unverified, because the whole reason it is in there is that nothing could ` +
      `confirm it arrived unaltered. If it matters, ask the sender OUT OF BAND — a channel that is ` +
      `not this one — to say it again in a NEW conversation.`
    );
  }
  /**
   * ⚠️ **IT DOES NOT ASK THE READER TO WORK OUT SOMETHING IT ALREADY KNOWS — review L10.**
   *
   * This read *"if the conversation is still open, staying connected is what fixes it; if it is
   * already closed, nothing will"* — a hedge over a status this function is handed. In production
   * the branch is reachable only when ingest returned `session_committed`, so the status is
   * `seal_interrupted_pending` or a record that could not be read; the hedge is right for the
   * second and lazy for the first.
   */
  if (ctx.sessionStatus === null) {
    return (
      `${cause} The relay still holds this message and it is pulled again on every drain. This ` +
      `agent could not read its own record of the conversation, so it cannot tell you whether the ` +
      `conversation is still open — and that unreadable record is itself worth looking at. If the ` +
      `conversation IS still open, being connected at the same time as your counterparty is what ` +
      `agrees a salt and clears this.`
    );
  }
  return (
    `${cause} The relay still holds this message and it is pulled again on every drain. A salt is ` +
    `agreed while both sides are connected, so being online at the same time as your counterparty ` +
    `is what clears this — the message is then checked and delivered on a later drain. This ` +
    `conversation is "${ctx.sessionStatus}", so if it never reopens, ask the sender OUT OF BAND to ` +
    `say it again in a NEW conversation.`
  );
}

/**
 * The operator-facing notice for each park refusal — TOTAL over the reason set.
 *
 * A function per reason rather than a string, because two of them must know whether the session is
 * closed before they can say anything true about what to do next.
 */
export const PARK_REFUSAL_NOTICE: Record<
  ParkRefusalReason,
  (ctx: ParkRefusalContext) => { kind: RefusalKind; impact: string; guidance: string }
> = {
  [PARK_REFUSAL_REASONS.ANNEX_SALT_UNAVAILABLE]: (ctx) => ({
    // REFUSED, never DEFERRED: nothing was recorded and nothing acknowledged, and — released or not
    // — the sender's daemon is not going to fix this by resending.
    kind: REFUSAL_KINDS.REFUSED,
    impact:
      `A message you were sent could NOT BE CHECKED — not that it failed a check. ${NOT_THEIR_FAULT} ` +
      `This side cannot recompute the fingerprint they committed to, because the shared secret that ` +
      `fingerprint is built from does not exist here. ` +
      (ctx.released
        ? "It was never shown to you and it is now gone from the relay, so this conversation will stop reporting it."
        : "It was never shown to you, and the relay still holds its copy."),
    guidance: saltGuidance(ctx),
  }),
  [PARK_REFUSAL_REASONS.ANNEX_ALG_UNKNOWN]: (ctx) => ({
    kind: REFUSAL_KINDS.DEFERRED,
    impact:
      `A message you were sent was fingerprinted with a method this build cannot compute ` +
      `("${ctx.declaredAlg}"), so it could not be checked and was not shown to you. ` +
      `${NOT_THEIR_FAULT} The relay still holds it.`,
    guidance:
      "Their CELLO build is NEWER than this one. Upgrade this agent's client; the message stays on " +
      "the relay and is delivered on the next drain once this daemon can compute that method. " +
      "Nothing to ask the sender for and nothing to resend.",
  }),
  [PARK_REFUSAL_REASONS.ANNEX_HASH_MISMATCH]: () => ({
    kind: REFUSAL_KINDS.REFUSED,
    impact:
      "A message you were sent does NOT match the fingerprint its sender signed over, so the bytes " +
      "that arrived are not the bytes they committed to. It was not shown to you. This is the one " +
      "park refusal that is evidence of tampering rather than of a version or storage difference — " +
      "the party best placed to have done it is the relay that stored it.",
    guidance:
      "Do not ask the sender to resend into this conversation. Confirm OUT OF BAND — a channel that " +
      "is not this one — what they actually sent, and read the retained copy with cello_quarantined " +
      "to compare. If it repeats with the same counterparty, stop using this conversation.",
  }),
  [PARK_REFUSAL_REASONS.ANNEX_DECODE_FAILED]: (ctx) => ({
    kind: REFUSAL_KINDS.DEFERRED,
    impact:
      "A parked message could not be decoded at all, so nothing about it could be checked and it " +
      "was not shown to you. The relay still holds it. This is a wire or version difference, not a " +
      "claim about the sender." + errorClause(ctx),
    guidance:
      "If the sender is on a newer build, upgrading this client is the fix; the relay keeps the " +
      "message meanwhile, and it is decoded on a later drain. Nothing to ask the sender for.",
  }),
  [PARK_REFUSAL_REASONS.ANNEX_SCREEN_UNAVAILABLE]: () => ({
    // The one TRANSIENT reason in the set. A screener that is down comes back, and the message is
    // re-screened on the next drain with nothing lost — so the operator must not be told to act.
    kind: REFUSAL_KINDS.DEFERRED,
    impact:
      "A parked message could not be screened because this agent's screener did not answer, so it " +
      "was not stored and not shown to you. Nothing was lost: the relay keeps its copy and the " +
      "message is screened again on the next drain.",
    guidance:
      "Nothing to do unless it keeps happening. If it does, the screener on THIS machine is not " +
      "running — look for content.recover.annex.screen_unavailable in the daemon log. Do not ask " +
      "the sender for anything; they cannot see this and there is nothing for them to resend.",
  }),
  [PARK_REFUSAL_REASONS.ANNEX_SCREENED_OUT]: (ctx) => ({
    // BLOCKED, not REFUSED: it was checked, it IS retained, and the operator is not being asked to
    // do anything about it. The kind is what carries "this is the protection working".
    kind: REFUSAL_KINDS.BLOCKED,
    impact:
      "A message that arrived for this closed conversation was BLOCKED by this agent's screener — " +
      "its content was rejected outright, not merely unrecognised. It was never shown to the agent " +
      "and never added to the conversation's record. It is KEPT as evidence, and the relay's copy " +
      "has been dropped so it stops arriving." +
      (ctx.released ? "" : " The relay copy could not be dropped, so it may arrive again."),
    guidance:
      "This is the protection working, and there is nothing to repair. Do not turn screening off " +
      "to read it and do not ask the sender about it — if the content was hostile, telling them " +
      "what was caught tells whoever sent it what to change. cello_quarantined shows it if you " +
      "need to produce it.",
  }),
  [PARK_REFUSAL_REASONS.ANNEX_WRITE_FAILED]: (ctx) => ({
    kind: REFUSAL_KINDS.DEFERRED,
    impact:
      "A parked message decoded and then a later step failed on THIS machine — screening it, " +
      "keeping it, or writing it into the record — so it was not shown to you. THIS IS A FAULT ON " +
      "THIS MACHINE, not something the sender did. The relay keeps its copy, so nothing is lost " +
      "yet." + errorClause(ctx),
    guidance:
      "Check that this machine has disk space and that ~/.cello is writable, then wait for the next " +
      "drain — the message is still on the relay and is retried. Do not ask the sender to resend.",
  }),
};

/**
 * ⚠️ **HOW OFTEN, NOT JUST HOW MANY — `041-PARKSTUCK` Unit 2, property 2.**
 *
 * A count with no cadence beside it reads as that many separate events. On the machine this was
 * written for, ONE message had been refused 731 times in 64 hours and the notice said `731`, which
 * an operator reads as 731 messages going wrong rather than one going wrong every five minutes.
 *
 * Says only what the stored row proves: the number of refusals of this reason on this conversation,
 * and the average gap across the span they cover. It does NOT claim one message — a reason can fire
 * for several — because the row cannot tell them apart.
 *
 * `null` below three refusals or across a zero span: two points are not a cadence, and dividing by a
 * zero span would print an interval that is an artifact of the clock rather than of the behaviour.
 */
export function refusalRecurrence(
  total: number,
  firstAt: number,
  lastAt: number,
  /**
   * Is `total` an exact count or a FLOOR? — review M5.
   *
   * A row seeded at upgrade takes its total from a notice's `count`, which resets on dismissal, so
   * both the count and the span are lower bounds. The drain five lines away already reports a
   * seeded row as `timesTotalAtLeast` for exactly this reason, and this sentence was asserting the
   * same number as a figure right beside it — *"the original lie with the new name on it"*, which
   * is the phrase `DOD-M15-REFUSALTERMINAL-1` used about the defect it removed.
   *
   * On the daemon this unit was written for the row IS seeded: the inbox reported
   * `times_total_at_least: 731`, so the very first thing an unqualified sentence would have shipped
   * is "it has fired 731 times" next to a field saying "at least".
   */
  seeded: boolean,
): string | null {
  if (!Number.isFinite(total) || total < 3) return null;
  const span = lastAt - firstAt;
  if (!Number.isFinite(span) || span <= 0) return null;
  const everyMs = span / (total - 1);
  /**
   * ⚠️ **IT SAYS ONLY WHAT THE ROW PROVES — review M6, and the first version made two claims it
   * could not.**
   *
   * Dropped: *"THIS REFUSAL IS A LOOP, NOT N SEPARATE EVENTS"*. This function serves EVERY reason
   * in the drain, not only park ones, and a counterparty who keeps writing into a closed
   * conversation generates N genuinely separate `session_committed` refusals — the notice would
   * have told the operator they were not separate, beside guidance saying the sender "may not
   * realise it ended". Its own doc comment already said a reason can fire for several messages.
   *
   * Dropped: *"It will keep firing at that rate until the cause is dealt with"*. Notices are
   * durable and re-drained for every new consumer, so that prints long after a cause is resolved —
   * including, immediately after this unit lands, on the released message whose impact in the SAME
   * row says it is gone and will stop being reported.
   *
   * What is left is arithmetic over two stored timestamps and a count, which is all the row has.
   */
  const count = seeded ? `at least ${total} times` : `${total} times`;
  return (
    `RECORDED ${count.toUpperCase()} on this conversation, about once every ` +
    `${humanizeInterval(everyMs)} across ${humanizeInterval(span)} — so read the number as ONE ` +
    `recurring refusal being counted, not as that many separate problems to work through` +
    (seeded
      ? ". The count began when this daemon was upgraded and dismissals are not counted, so the true figure may be far higher."
      : ".")
  );
}

/**
 * The upstream error's own words, appended rather than replacing anything — Invariant 3.
 *
 * Empty when there was no throw, so a notice never carries a dangling "it said:" with nothing after.
 */
function errorClause(ctx: ParkRefusalContext): string {
  return ctx.errorDetail === null || ctx.errorDetail === "" ? "" : ` The failure said: ${ctx.errorDetail}.`;
}

/** A duration a person reads without converting it. Whole units, because a cadence is an estimate. */
function humanizeInterval(ms: number): string {
  const s = Math.round(ms / 1000);
  if (s < 60) return `${Math.max(1, s)} second${s === 1 ? "" : "s"}`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m} minute${m === 1 ? "" : "s"}`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h} hour${h === 1 ? "" : "s"}`;
  const d = Math.round(h / 24);
  return `${d} days`;
}
