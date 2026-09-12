/**
 * `DOD-M15-CARRIEDSEAL-1` — WHEN THE RELAY GAVE NO ANSWER, as opposed to giving a bad one.
 *
 * The seal writes its own closing leaf only when there was nobody to ask. That is a narrower
 * condition than "the submit failed", and the difference is load-bearing: a relay that REFUSED a
 * leaf has ruled on it, and routing around a ruling is exactly the behaviour a trust layer must not
 * have. A relay that never answered has ruled on nothing.
 *
 * ⚠️ **THE LIST IS AN ALLOW-SET, AND THE DEFAULT IS THE OLD BEHAVIOUR.** A reason that is not here
 * does not unlock the local terminus — the close fails as it does today. That asymmetry is the whole
 * design: a new relay refusal reason added next year cannot silently widen this, because widening
 * requires someone to come here and add it. The reverse default — "fall back unless the reason is
 * one of these known refusals" — would have let every future refusal become a bypass.
 *
 * Every reason below is produced by THIS daemon, in `session-relay-client.ts` or
 * `session-seal.ts`'s transport resolution, at a point where no `hash_submit_ack` came back.
 *
 * Three that are deliberately NOT here, and why each one is an answer rather than a silence:
 *   - `relay_assignment_rejected` — the relay considered the session and declined it.
 *   - `relay_ack_unverified` / `relay_ack_malformed` — the relay ANSWERED and the answer did not
 *     check out. That is a relay to distrust, and letting distrust promote us onto a path with
 *     weaker evidence is the wrong direction entirely.
 *   - `standing_receiver_unavailable` — this agent is not started. Local, fixable, and the existing
 *     guidance ("start the agent and retry") is the correct thing to tell someone.
 */

/**
 * ⚠️ THE ALLOW-SET IS NOT SUFFICIENT ON ITS OWN, AND THIS IS THE HALF THAT MAKES IT SOUND.
 *
 * The submit boundary COLLAPSES almost every relay refusal into `relay_unavailable`. Only three
 * token faults survive under their own names (`DOD-M15-TOKENSTALE-1` split those out); everything
 * else the relay actually said — rate limited, over its slot cap, this agent's token rejected as
 * invalid, and by that code's own documented default every future relay-side reason — arrives at
 * this file wearing the label for an outage.
 *
 * So the reason string alone cannot tell "nobody was there" from "they authenticated me and said
 * no". A relay exercising judgement about this agent would have been read as silence and sealed
 * around, which is the one thing this whole design says must never happen.
 *
 * The standing refusal is the signal the boundary drops, and the client still holds it. Ask for it
 * directly rather than trying to infer it from a label that was never going to carry it.
 *
 * **A ruling is anything the relay answered with.** Not a list of known-bad reasons: a set like that
 * defaults to "silence" for anything unfamiliar, which is the wrong direction here — a reason added
 * next year would quietly become a bypass. Present means refused.
 */
export function relayRefusedUs(refusal: { reason: string } | null | undefined): boolean {
  return refusal != null;
}

/** The relay never ruled. See the header — this is an allow-set and the default is to fail as before. */
export const RELAY_GAVE_NO_ANSWER: ReadonlySet<string> = new Set([
  // No relay client, no stream, or the session is gone from the relay's side.
  "relay_unavailable",
  "relay_client_unavailable",
  "relay_client_closed",
  "relay_stream_closed",
  "relay_session_gone",
  // The frame never left, or left and was never answered.
  "relay_submit_send_failed",
  "relay_submit_timeout",
  // This daemon has no endpoint to dial any more — the relay is gone as far as it can tell.
  "no_persisted_relay_endpoint",
]);
