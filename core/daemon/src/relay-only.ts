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
 *   1. **We dial only their CIRCUIT** — `dialableAddrs`. Dialling their direct address hands them
 *      ours; dialling the circuit terminates at the relay and reveals nothing.
 *   2. **We publish only our own CIRCUIT** — `publishableEndpoint`. The only route they hold points
 *      at the relay, which protects the operator **even against a counterparty who ignores the flag**.
 *
 * The second is load-bearing: *a control that depends on the other side honouring it is not a
 * control.* The first alone would leave us reachable by anyone who kept our address.
 *
 * ⚠️ **AND NEITHER HALF IS SUFFICIENT WHILE libp2p CAN SPEAK FOR US.** These functions filter what
 * the DIRECTORY is told. `identify` hands a peer our listen addresses on the first relayed
 * connection, and `dcutr` actively hole-punches a relayed connection into a direct one — the inbound
 * side starts that upgrade, and a relay-only responder IS the inbound side. Both bypass everything
 * here, peer-to-peer. `createNode`'s `holePunch: { enabled: false }` closes the second; the announce
 * filter closes the first. **Without those, this file filters the paperwork and leaves the wire
 * open** — see `DOD-M15-RELAYONLY-1`.
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

/**
 * The setting's state when the read itself may fail — `"on" | "off" | "unknown"`.
 *
 * ⚠️ **"THE DATABASE IS GONE" IS NOT A VALUE, AND TREATING IT AS ONE FAILS TOWARD DISCLOSURE.**
 * `getSetting` returns `null` both for *unset* and for *no database*, and `isRelayOnly` reads both
 * as OFF. Unset-means-off is right; **db-gone-means-off is not** — the standing receiver outlives
 * the database during shutdown, so an offer arriving in that window would publish the operator's
 * real addresses with relay-only switched on.
 *
 * A read that THROWS is also `"unknown"` rather than an escaping exception: this sits on a ceremony
 * path with no catch, where a throw becomes an unhandled rejection and the offer vanishes with no
 * local log — the initiator then sees `counterparty_did_not_accept` and blames its own subsystem.
 *
 * The caller decides what `"unknown"` costs. For publishing, it must cost a refusal, never a guess.
 */
export function relayOnlyState(
  getSetting: (key: string) => string | null,
  readable: boolean,
): "on" | "off" | "unknown" {
  if (!readable) return "unknown";
  try {
    return getSetting(RELAY_ONLY_KEY) === "true" ? "on" : "off";
  } catch {
    return "unknown";
  }
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
  // ⚠️ PARSED, never substring-matched. `addr.includes("/p2p-circuit")` was defeatable by the
  // COUNTERPARTY, who controls these strings — the directory copies them verbatim and the FROST
  // signature attests that the quorum agreed on the assignment, NOT that its contents are circuits.
  //
  //     /dns4/p2p-circuit.attacker.example/tcp/443/p2p/12D3KooWTheirs
  //
  // contains the literal text, resolves through the DNS transport, and would have been dialled
  // directly — handing over the operator's IP with relay-only switched ON, while the suppression log
  // reported `suppressed: 0`. A control a peer can defeat by naming a host is precisely what this
  // line rules out.
  //
  // EXACT SEGMENT match on the multiaddr's own `/`-delimited components. `p2p-circuit` is a
  // standalone protocol with no value, so it appears as a whole segment; a hostname that merely
  // CONTAINS the text appears as `p2p-circuit.attacker.example`, which is a different segment and is
  // correctly rejected.
  //
  // Deliberately NOT `multiaddr().protoNames()`, which would be the stricter parse: that lives in
  // `@multiformats/multiaddr`, a dependency `core/daemon` does not have. Reaching for it here would
  // add a package to the daemon to make one boolean stricter, and this client is installed on
  // operators' machines where install weight is a user-facing cost. The exact-segment test defeats
  // the demonstrated bypass with no new dependency.
  //
  // ⚠️ RESIDUAL, stated rather than left implied: this proves the address CLAIMS a circuit hop, not
  // that the circuit runs through a relay we chose. A peer could name a relay we hold no reservation
  // with. Binding the embedded relay peer id to our own reservations is the stronger check and is
  // NOT done here.
  return addr.split("/").includes("p2p-circuit");
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
