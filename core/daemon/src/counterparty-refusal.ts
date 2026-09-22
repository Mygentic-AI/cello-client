/**
 * `DOD-M15-NOTACCEPTING-1` — WHAT THE CALLER IS TOLD WHEN THE OTHER SIDE REFUSES THEIR SESSION.
 *
 * ─── The defect this exists to close, measured live 2026-09-22 ────────────────────────────────
 *
 * The responder refuses and sends `session_refused`. It arrives about a MILLISECOND after the
 * caller's `cello_initiate_session` has already returned `ok: true` — because the directory answers
 * the caller before the responder has even seen the offer — and the caller's daemon unregisters its
 * frame listener the instant the assignment lands. So the refusal was dropped on the floor, every
 * time, and the caller was left holding a session the other side never opened. Their next send
 * answered *"Sent… sealed, witnessed and on its way… No action is needed"* and their next read
 * answered *"Nothing arrived… THIS IS A FAULT ON THIS MACHINE — the connection is fine and your
 * counterparty is not involved."* Two confident sentences, both false, and the second blames them.
 *
 * ─── ⚠️ THE WIRE CARRIES A CODE. THE SENTENCE IS WRITTEN HERE ─────────────────────────────────
 *
 * The frame also carries a `guidance` string, and surfacing it would be handing an arbitrary
 * counterparty a paragraph of prose that lands in front of the operator's agent — an injection
 * surface reachable by anyone who can refuse a session, which is everyone. So the counterparty's
 * prose is NEVER stored and NEVER shown. Only a reason CODE crosses, it must match a strict
 * pattern, and the words below are ours.
 *
 * It also means every caller sees the same sentence for the same posture no matter whose daemon
 * refused them — a counterparty running modified software cannot make their refusal read
 * differently, kinder, or more alarming than anyone else's.
 */

import { NOT_ACCEPTING_CALLER_GUIDANCE, REFUSAL_REASONS, CAPACITY_REASONS } from "./refusal-reasons.js";

/** A reason code we will accept off the wire at all: lower-snake, bounded, nothing else. */
export const WIRE_REASON_RE = /^[a-z][a-z0-9_]{0,39}$/;

/**
 * The sentence the CALLER reads, per reason code.
 *
 * Deliberately not a total map over `AnyRefusalReason`: the set that can arrive here is whatever
 * the counterparty's build sends, which may be older or newer than ours. An unknown-but-well-formed
 * code gets the fallback below, which names the code and says plainly that this build has no
 * explanation for it — rather than inventing one.
 */
const CALLER_TEXT: Record<string, string> = {
  [REFUSAL_REASONS.NOT_ACCEPTING_CONNECTIONS]: NOT_ACCEPTING_CALLER_GUIDANCE,
  [CAPACITY_REASONS.ABUSE_BOUND_SESSIONS_PER_SENDER]:
    "They refused this session: you already have as many conversations open with them as their limit " +
    "allows. Close one with cello_close_session and try again. A session that was interrupted still " +
    "counts until it is sealed or abandoned.",
  [CAPACITY_REASONS.ABUSE_BOUND_UNKNOWN_SESSIONS_GLOBAL]:
    "They refused this session: they are already holding as many conversations with agents they do " +
    "not know as they allow at once. This one clears on its own as those end — try again later.",
};

/** What to tell the caller for a reason code that arrived off the wire. */
export function callerTextForRefusal(reason: string): string {
  return (
    CALLER_TEXT[reason] ??
    // Names the code without dressing it up. An operator can quote it to the counterparty, which is
    // the only next step that exists when our build has never heard of it.
    `They refused this session, with a reason this build does not recognise (${reason}). Nothing was sent. ` +
    `Their software may be newer than yours; ask them what it means, or try a different counterparty.`
  );
}
