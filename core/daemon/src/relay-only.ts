/**
 * CELLO Daemon — relay-only routing (`DOD-M15-RELAYONLY-1`).
 *
 * The feature half of the IP disclosure. A direct session reveals the operator's IP permanently;
 * relay routing is the mitigation, and until now it was a footnote in an architecture document
 * rather than something an operator could switch on.
 *
 * ─── ⚠️ WHY THIS IS NOT A `transport_mode` SETTING ─────────────────────────────────────────────
 *
 * `transport_mode` DOES NOT CONTROL WHETHER A DIRECT CONNECTION HAPPENS, and a setting that wrote it
 * would be a privacy control that does not protect privacy:
 *
 *   - The directory already defaults the label to relay (`requestedTransportMode ?? "relay"`), so in
 *     the ordinary case the label ALREADY reads "relay".
 *   - And the client dials directly anyway — the gate is `counterparty_session_addrs.length > 0`,
 *     *"regardless of the transport_mode LABEL"*, in `initiate-session-handler.ts`'s own words.
 *
 * So the IP is exposed today on a path whose label already claims otherwise, and an operator who set
 * a label-only flag would be told they were protected while they were not.
 *
 * ─── The two halves, and why the second is the one that makes it a control ────────────────────
 *
 * A direct connection leaks the IP in BOTH directions:
 *
 *   1. **We must not dial them** — `shouldDialCounterparty`. Dialing hands our address to the peer.
 *   2. **We must not publish our own session addrs** — `publishableEndpoint`. With nothing to dial,
 *      the operator is protected **even against a counterparty who ignores the flag entirely**.
 *
 * The second is load-bearing: *a control that depends on the other side honouring it is not a
 * control.* The first alone would leave us reachable by anyone who kept our address.
 *
 * `publishableEndpoint` is applied INSIDE `getStandingReceiverInfo` — the single method both publish
 * paths draw from — rather than at its call sites. Suppressing at call sites would be a hand-kept
 * list, and a fourth publish path added later would leak while every test stayed green. At the choke
 * point a new caller inherits the protection instead of having to be told about it.
 */

/** The per-agent settings key. Lower-snake, dotted namespace, per `agent-settings-keys.ts`. */
export const RELAY_ONLY_KEY = "transport.relay_only";

/**
 * Is relay-only routing ON for this agent?
 *
 * ⚠️ THE FAILURE DIRECTION IS CHOSEN, not incidental. **Only the exact string `"true"` is ON.**
 * Unset reads OFF because the daemon must run correctly on defaults alone; a corrupt or unparseable
 * value also reads OFF, because reading a value nobody validated as ON would silently break every
 * ordinary direct session.
 *
 * That leaves one hazard — a typo'd value that the operator believes turned the control on — and it
 * is closed at the WRITE boundary instead: `validateSettingValue` refuses anything but `"true"` and
 * `"false"`, loudly, so a mistyped value can never be stored to be misread here.
 */
export function isRelayOnly(getSetting: (key: string) => string | null): boolean {
  return getSetting(RELAY_ONLY_KEY) === "true";
}

/** A session-transport endpoint as published to a counterparty. */
export interface PublishableEndpoint {
  peerId: string;
  addrs: string[];
}

/**
 * The endpoint as it may leave this machine.
 *
 * Under relay-only the addresses are dropped and **the peer id is KEPT** — it is the identity a
 * relay circuit is addressed to, and stripping it would break the very routing this setting forces
 * everything onto. This suppresses *addresses*, not reachability.
 *
 * A null endpoint stays null: "no standing receiver" and "a receiver at no address" are different
 * facts, and collapsing them would let a caller advertise an endpoint that does not exist.
 */
export function publishableEndpoint<T extends PublishableEndpoint>(
  endpoint: T | null,
  relayOnly: boolean,
): T | PublishableEndpoint | null {
  if (endpoint === null) return null;
  if (!relayOnly) return endpoint;
  return { peerId: endpoint.peerId, addrs: [] };
}

/**
 * May we dial the counterparty's advertised session addresses?
 *
 * The ordinary rule is unchanged — dial iff they advertised somewhere to dial. Relay-only refuses
 * regardless of how dialable they are, because the counterparty may not be relay-only themselves:
 * they will still publish addresses, and dialing them would hand over our IP with our own setting
 * switched on.
 */
export function shouldDialCounterparty(addrs: readonly string[], relayOnly: boolean): boolean {
  if (relayOnly) return false;
  return addrs.length > 0;
}
