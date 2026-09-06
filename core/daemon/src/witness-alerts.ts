/**
 * CELLO Daemon — WHAT A RELAY SAID IT SAW, AND WHETHER IT AGREES WITH US
 *
 * Split out of `session-node-manager.ts` by 037-SESSIONCORE. A relay witnesses message order; when
 * what it reports does not reconcile with this side's record, that is an alert an operator has to be
 * able to read.
 *
 * Moved verbatim, comments included.
 *
 * ⚠️ THE LIST IS BOUNDED AND IT IS FED BY A REMOTE PARTY, which is why it is capped and why the cap
 * reports its own truncation rather than silently dropping the tail. An alert list that quietly
 * stopped growing would understate exactly the situation it exists to report.
 */
import type { Logger } from "./types.js";
import type { WitnessAlertNotice } from "./session-node-types.js";
import type { RelayWitnessAlert } from "./session-relay-client.js";

/** What the witness-alert record needs from the manager. */
export interface WitnessAlertContext {
  readonly logger: Logger;
}

const WITNESS_ALERT_CAP = 20;

export class WitnessAlerts {
  readonly #ctx: WitnessAlertContext;

  constructor(ctx: WitnessAlertContext) {
    this.#ctx = ctx;
  }

  /**
   * DOD-M15-CORROBORATE-1: witness alerts this agent's relays have reported, oldest first, capped.
   *
   * ⚠️ **IN MEMORY, AND A DAEMON RESTART LOSES THEM** — review F4. This comment used to say a relay
   * that still holds the observation re-delivers it on the next connection. It does not:
   * `drainWitnessAlerts` splices, so once an alert has been delivered the relay no longer holds it.
   * Nothing here is a durable record of anything; the relay operator's own log is, and so is the
   * signature on the alert, which the operator can keep. Said plainly rather than left as an implied
   * guarantee.
   *
   * Nothing clears the list before that restart, and that is deliberate: an alert an operator can
   * silence is one an attacker can wait out.
   */
  readonly #witnessAlerts = new Map<string, WitnessAlertNotice[]>();
  /**
   * Agents whose alert list hit the cap — fallback-finder LOW 2. Without this the inbox renders a
   * full list that looks complete, and "twenty alerts" is indistinguishable from "twenty of some
   * larger number". A marker the operator can see costs one boolean.
   */
  readonly #witnessTruncated = new Set<string>();
  /**
   * ⚠️ **THE CAP KEEPS THE FIRST, NOT THE LAST** — review F1, and the direction is the whole point.
   *
   * The relay's own queue drops the NEWEST when full, precisely so a flood cannot push the first
   * real observation out. This list did the opposite (`slice(-20)`), which handed the mute button
   * straight back one layer up: at the relay's 120-submits-per-minute limit, about ten seconds of
   * fabricated alerts evicted the genuine one before any operator read it. Repeats of one event also
   * collapse — see the dedupe in `recordRelayWitnessAlert` — so a flood cannot even fill it.
   */
  /**
   * Record what one relay says it saw on one of this agent's sessions, for the operator to read.
   *
   * ⚠️ **IT DOES NOT FREEZE THE SESSION, AND THAT IS THE DESIGN.** A client freezing on its OWN
   * verification is safe: it limits only what that client trusts. Freezing on a REMOTE party's
   * say-so hands any single relay the power to end any conversation it carries, and to write an
   * accusatory record about a counterparty who did nothing. The identity freeze stays where it is —
   * on this daemon's own check of an inbound frame — and this surfaces a second, independent
   * observation next to it. One witness reports; it does not rule.
   */
  recordRelayWitnessAlert(agentName: string, alert: RelayWitnessAlert): void {
    const list = this.#witnessAlerts.get(agentName) ?? [];
    /**
     * ONE ROW PER (WITNESS, SESSION) — review F1's second half. A relay reports every refused
     * submission, and a determined submitter can produce a great many; twenty rows saying the same
     * thing is not twenty facts, it is one fact and nineteen ways to push another one off the list.
     * The repeat updates the count and the last-seen time and leaves the row where it is.
     */
    /**
     * Keyed on the relay's PEER ID, not on `relayId` — fallback-finder LOW 1. `relayId` is absent
     * for any relay that could not sign, so two DIFFERENT such relays reporting on one session
     * collapsed into a single row and the operator read one witness where there were two. The peer
     * id is the transport identity this client is actually talking to and is always known.
     */
    const key = `${alert.witnessPeerId}::${alert.sessionIdHex}`;
    const existing = list.find((n) => n.key === key);
    if (existing) {
      existing.occurrences += 1;
      existing.lastObservedAt = alert.observedAt;
      // A later repeat that IS verifiable upgrades the row: the operator should end up holding the
      // strongest form of the claim they were sent, never the weakest one that arrived first.
      existing.alert = alert.verifiable ? alert : existing.alert;
      // `firstObservedAt` is deliberately untouched — see its note on the type.
    } else if (list.length >= WITNESS_ALERT_CAP) {
      // Keep the first. See the cap's own note for why this direction is load-bearing.
      this.#witnessTruncated.add(agentName);
      this.#ctx.logger.warn("session.witness.alert.list_full", {
        agentName, held: list.length,
        impact: "this alert was not recorded; the earlier ones are kept and still shown, and the " +
          "inbox now says the list is incomplete rather than looking whole",
      });
      return;
    } else {
      list.push({ key, alert, occurrences: 1, firstObservedAt: alert.observedAt, lastObservedAt: alert.observedAt });
    }
    this.#witnessAlerts.set(agentName, list);
    this.#ctx.logger.error("session.witness.alert.recorded", {
      agentName,
      sessionId: alert.sessionIdHex,
      relayId: alert.relayId ?? "(unnamed)",
      submitterIsCounterparty: alert.submitterIsCounterparty,
      verifiable: alert.verifiable,
      impact: "surfaced to the operator on the next cello_inbox; the session is NOT frozen by it",
    });
  }
  /** The witness alerts an agent has been told about, oldest first, one row per witness+session. */
  getWitnessAlerts(agentName: string): ReadonlyArray<WitnessAlertNotice> {
    return this.#witnessAlerts.get(agentName) ?? [];
  }
  /** Whether this agent's alert list hit its cap, so the inbox can say the list is incomplete. */
  witnessAlertsTruncated(agentName: string): boolean {
    return this.#witnessTruncated.has(agentName);
  }
}
