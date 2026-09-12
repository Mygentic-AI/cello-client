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
