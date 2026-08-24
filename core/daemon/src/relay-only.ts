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
 * A relay-CIRCUIT multiaddr — the address that discloses nothing about the operator.
 *
 * ⚠️ THIS IS THE DISTINCTION THE WHOLE UNIT TURNS ON, and getting it wrong the first time took the
 * operator OFF THE NETWORK rather than making them private. A `/p2p-circuit` address names the
 * **RELAY's** address and our peer id. It terminates at the relay. Publishing one tells a
 * counterparty how to reach us *through* the relay and tells them nothing about where we are;
 * dialing one reveals us to the relay we already chose, not to them.
 *
 * So relay-only is not "no addresses". It is "circuit addresses only".
 */
export function isCircuitAddr(addr: string): boolean {
  return addr.includes("/p2p-circuit");
}

/**
 * The endpoint as it may leave this machine.
 *
 * ⚠️ **AN EMPTY ADDRESS ARRAY IS NOT A PRIVATE FRAME, IT IS A MALFORMED ONE.** The first build of
 * this published `addrs: []` and the directory refuses exactly that on both sides — a
 * `session_request` whose `initiator_session_addrs` is empty is rejected outright, and a
 * `session_offer_accept` is only folded in `if (counterparty_session_addrs.length > 0)`, **with no
 * `else`**, so the accept was silently dropped and the offer waiter never resolved. The operator
 * switched on a privacy control and was told their counterparty was offline.
 *
 * So we publish the **circuit-only subset**: enough for the directory to build a real assignment and
 * for the counterparty to reach us over the relay, and nothing that points at the operator.
 *
 * A genuinely empty result is meaningful and is NOT silently published — see `relayOnlyReachable`.
 * A null endpoint stays null: "no standing receiver" and "a receiver at no address" are different
 * facts, and collapsing them would let a caller advertise an endpoint that does not exist.
 */
export function publishableEndpoint<T extends PublishableEndpoint>(
  endpoint: T | null,
  relayOnly: boolean,
): T | PublishableEndpoint | null {
  if (endpoint === null) return null;
  if (!relayOnly) return endpoint;
  return { peerId: endpoint.peerId, addrs: endpoint.addrs.filter(isCircuitAddr) };
}

/**
 * Can a relay-only agent actually be reached with what it is about to publish?
 *
 * FALSE means it holds **no relay reservation yet**, so the circuit-only subset is empty. That must
 * become a LOUD LOCAL REFUSAL rather than an empty publish: an empty publish is refused by the
 * directory as malformed and surfaces to the operator as "the counterparty is offline", which is a
 * lie about someone else's state caused by a setting on this machine.
 */
export function relayOnlyReachable(endpoint: PublishableEndpoint | null, relayOnly: boolean): boolean {
  if (!relayOnly) return true;
  if (endpoint === null) return false;
  return endpoint.addrs.some(isCircuitAddr);
}

/**
 * Which of the counterparty's advertised addresses may we dial?
 *
 * ⚠️ Returns the FILTERED LIST, not a boolean, because "relay-only" does not mean "do not connect" —
 * it means "connect only over the circuit". The first build refused every address including the
 * `/p2p-circuit` one, which is the relay route this setting exists to force everything onto, so it
 * dropped every session onto the store-and-forward backstop.
 *
 * The counterparty may not be relay-only themselves, so they will still advertise direct addresses:
 * those are dropped, because dialing one hands them our IP with our own setting switched on.
 */
export function dialableAddrs(addrs: readonly string[], relayOnly: boolean): string[] {
  if (!relayOnly) return [...addrs];
  return addrs.filter(isCircuitAddr);
}
