/**
 * DOD-M15-RELAYONLY-1 — relay-only routing is an operator setting that ACTUALLY SUPPRESSES THE DIAL.
 *
 * ─── The defect this line exists to avoid SHIPPING, which is not the same as the one it opened with ─
 *
 * The line asks to promote relay routing from a footnote to a setting. The trap, recorded in the DoD
 * before a line was written: **`transport_mode` does not control whether a direct connection
 * happens.** Two facts, both read out of the source rather than assumed:
 *
 *   1. **The directory already defaults the label to relay** — `const transportMode =
 *      requestedTransportMode ?? "relay"`. So in the ordinary case the label ALREADY says "relay".
 *   2. **And the client dials directly anyway.** `initiate-session-handler.ts` says so in its own
 *      comment: *"attempt the dial whenever the assignment carries counterparty session addrs,
 *      **regardless of the transport_mode LABEL**"*. The gate is `counterpartyAddrs.length > 0`.
 *
 * **So the operator's IP is exposed TODAY on a path whose label already claims relay**, and a
 * setting that merely set that label would tell an operator they were protected while they were not.
 * That is the tier-that-grants-nothing defect in the one domain where the promise IS the product.
 *
 * ─── Why suppressing the DIAL is not enough on its own ─────────────────────────────────────────
 *
 * A direct connection leaks the IP in BOTH directions: we reveal ours by dialing them, and we reveal
 * ours by publishing addresses they can dial. So the control has two halves, and the second is the
 * one that matters most:
 *
 *   - **Dial only the CIRCUIT** — a circuit addr terminates at the relay, so it reveals nothing;
 *     their direct addr is dropped, because dialling it hands them our IP.
 *   - **Publish only the CIRCUIT** — so the only route they hold points at the relay. This half
 *     protects the operator **even against a counterparty who ignores the flag**, and that is the
 *     whole point: *a control that depends on the other side honouring it is not a control.*
 *
 * ⚠️ **BOTH HALVES SAY "ONLY THE CIRCUIT", NOT "NOTHING", AND THE FIRST BUILD SAID NOTHING.** That
 * version did not make the operator private — **it took them off the network.** An empty address
 * array is a MALFORMED frame to the directory, which rejects a `session_request` carrying no
 * initiator addrs and folds an offer accept only `if (counterparty_session_addrs.length > 0)`, with
 * no `else`. The operator switched on a privacy control and was told their counterparty was
 * offline. Review caught it; these tests now pin the difference.
 *
 * ─── The choke point, and why the guard test below exists ─────────────────────────────────────
 *
 * Our own session addrs leave this machine at exactly TWO sites — `initiator_session_addrs` when we
 * initiate (`outbound-sessions.ts`) and `counterparty_session_addrs` when we answer an offer
 * (`session-ceremony.ts`) — and **both draw from `getStandingReceiverInfo`**, which has three
 * consumers, every one a publish path. Nothing else in the tree reads it.
 *
 * Suppression therefore lives INSIDE that method, not at its call sites. Call-site gating would be a
 * hand-kept list — and a fourth publish path added later would leak the operator's IP while every
 * test here stayed green. This milestone has been bitten by a hand-kept list four separate times, so
 * the choke point is the version where a new caller **inherits** the protection instead of having to
 * be told about it.
 *
 * ⚠️ That makes the guard tests below guard a DIFFERENT failure than an un-wrapped caller, which is
 * no longer possible. They guard a **bypass**: a new reader that goes around the method for raw
 * `listenAddresses()` and publishes those instead. That reader would look entirely correct and would
 * leak on every relay-only session.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  RELAY_ONLY_KEY,
  isRelayOnly,
  publishableEndpoint,
  relayOnlyReachable,
  relayOnlyState,
  isCircuitAddr,
  dialableAddrs,
} from "../relay-only.js";
import { isValidSettingKey, validateSettingValue } from "../agent-settings-keys.js";
import { registerInitiateSessionHandler } from "../initiate-session-handler.js";
import type { IpcHandler } from "../ipc-server.js";
import type { Logger } from "../types.js";
import type { SessionNegotiator } from "../transport-selector.js";
import type { IAutoNatService } from "@cello-protocol/transport";

/** The operator's own address — the thing that must never leave this machine under relay-only. */
const DIRECT = "/ip4/203.0.113.7/tcp/4001";
/** A circuit address: it names the RELAY and our peer id, and discloses nothing about the operator. */
const CIRCUIT = "/ip4/198.51.100.4/tcp/4001/p2p/12D3KooWRelay/p2p-circuit/p2p/12D3KooWStandingReceiver";
const SR = { peerId: "12D3KooWStandingReceiver", addrs: [DIRECT, CIRCUIT] };

describe("DOD-M15-RELAYONLY-1 — the setting", () => {
  it("★ is a REAL settings key, so the handler stores it instead of refusing it", () => {
    /**
     * The handler refuses an unknown key outright — deliberately, so a typo cannot persist as a
     * setting that never takes effect. A privacy control that the handler rejects is not a control.
     */
    expect(isValidSettingKey(RELAY_ONLY_KEY), `${RELAY_ONLY_KEY} must be a known settings key`).toBe(true);
  });

  it("★ ACCEPTS ONLY true/false — the away-text fallback would otherwise swallow anything", () => {
    /**
     * ⚠️ THE SILENT-FALLBACK TRAP IN THIS FILE, and the reason this test exists rather than being
     * assumed. `validateSettingValue` branches on `isBoundKey` and **falls through to away-TEXT
     * validation for every other key** — which accepts any non-empty string under 2048 chars.
     *
     * So adding the key to the registry WITHOUT a validation branch would let
     * `transport.relay_only = "yes"` — or `"flase"` — store successfully and read as
     * not-the-string-"true" forever. The operator would have set the privacy control, been told it
     * was stored, and have no protection. Refusing at the boundary is the only place this is
     * catchable.
     */
    for (const good of ["true", "false"]) {
      expect(validateSettingValue(RELAY_ONLY_KEY, good), `${good} must be accepted`).toEqual({ ok: true });
    }
    for (const bad of ["yes", "no", "flase", "1", "0", "TRUE", "", "  ", "relay"]) {
      const res = validateSettingValue(RELAY_ONLY_KEY, bad);
      expect(res.ok, `${JSON.stringify(bad)} must be REFUSED — a value that stores but never reads as on is a privacy control that silently does nothing`).toBe(false);
    }
  });

  it("★ is OFF unless explicitly set to true — an unreadable or unset value never means 'protected'", () => {
    /**
     * Direction matters. A missing setting must mean OFF (the daemon runs correctly on defaults),
     * but the failure direction has to be chosen deliberately: reading an unset key as ON would
     * silently break every ordinary direct session, and reading a corrupt value as ON would do the
     * same. Both read as OFF; the operator's protection comes from an explicit act, and the LOUD
     * refusal above is what stops a typo becoming a false sense of safety.
     */
    expect(isRelayOnly(() => null), "unset = off").toBe(false);
    expect(isRelayOnly(() => "false"), "explicit false = off").toBe(false);
    expect(isRelayOnly(() => "true"), "explicit true = ON").toBe(true);
    expect(isRelayOnly(() => "yes"), "a value that never passed validation is not ON").toBe(false);
  });

  it("★★ A GONE DATABASE IS 'unknown', NOT 'off' — the difference is a disclosure", () => {
    /**
     * ⚠️ THE SILENT FALLBACK REVIEW FOUND, and it failed in the dangerous direction. `getSetting`
     * answers `null` for BOTH "unset" and "there is no database", and reading them the same way
     * means a shutdown window — where the standing receiver outlives the DB — publishes the
     * operator's real addresses with relay-only switched on.
     *
     * Unset-means-off is correct. Db-gone-means-off is a leak. They must be different answers.
     */
    expect(relayOnlyState(() => "true", true), "readable and on").toBe("on");
    expect(relayOnlyState(() => null, true), "readable and unset = off, as before").toBe("off");
    expect(
      relayOnlyState(() => null, false),
      "NOT readable = unknown. Reading this as 'off' is what publishes a real address during shutdown.",
    ).toBe("unknown");
    expect(
      relayOnlyState(() => { throw new Error("retired agent"); }, true),
      "and a THROW is unknown rather than an escaping exception — this sits on a ceremony path with " +
        "no catch, where it would become an unhandled rejection and the offer would vanish silently",
    ).toBe("unknown");
  });
});

describe("DOD-M15-RELAYONLY-1 — the two halves of the control", () => {
  it("★★ RELAY-ONLY PUBLISHES THE CIRCUIT ADDRESS AND ONLY THAT — not nothing, and not the operator's", () => {
    /**
     * ⚠️ THE ASSERTION THAT WAS WRONG IN THE FIRST BUILD, and it is worth stating plainly because
     * the test header itself carried the false claim: *"the peer id is KEPT… stripping it would
     * break relay routing"*. **Keeping the peer id does not give a counterparty a route.** In this
     * codebase the circuit address travels in the very field the first build emptied.
     *
     * **An empty address array is not a private frame, it is a MALFORMED one.** The directory
     * rejects a `session_request` with no initiator addrs, and folds an offer accept only
     * `if (counterparty_session_addrs.length > 0)` with no `else`. So relay-only-as-shipped did not
     * make the operator private — it took them OFF THE NETWORK, and told them their counterparty
     * was offline.
     *
     * A circuit multiaddr names the RELAY and our peer id. It is what makes this a routing control
     * rather than a disconnection.
     */
    const out = publishableEndpoint(SR, true);
    expect(out, "the endpoint still exists — this suppresses addresses, not reachability").not.toBeNull();
    expect(out!.addrs, "the circuit address must SURVIVE — it is the route, and it names the relay, not us").toEqual([CIRCUIT]);
    expect(out!.addrs, "and the operator's own address must NOT").not.toContain(DIRECT);
    expect(out!.addrs.length, "publishing an EMPTY array is what the directory refuses as malformed").toBeGreaterThan(0);
    expect(out!.peerId, "the peer id rides along, as before").toBe(SR.peerId);
  });

  it("★★ NO RESERVATION YET is a REFUSAL, never a silent empty publish", () => {
    /**
     * The case the first build could not distinguish. An agent with no relay reservation has no
     * circuit address, so the filtered set is legitimately empty — and publishing that empty set is
     * exactly the malformed frame above. It must become a loud local refusal instead, because the
     * alternative surfaces to the operator as "the counterparty is offline": a lie about someone
     * else's state, caused by a setting on this machine.
     */
    const noReservation = { peerId: SR.peerId, addrs: [DIRECT] };
    expect(relayOnlyReachable(noReservation, true), "no circuit addr = not reachable, and we must SAY so").toBe(false);
    expect(relayOnlyReachable(SR, true), "with a reservation, reachable").toBe(true);
    expect(relayOnlyReachable(noReservation, false), "and with the setting off this question does not apply").toBe(true);
    expect(relayOnlyReachable(null, true), "no standing receiver at all is likewise not reachable").toBe(false);
  });

  it("★ and with the setting OFF, the endpoint is untouched — the default path cannot regress", () => {
    expect(publishableEndpoint(SR, false), "off = byte-identical to what the caller had").toEqual(SR);
  });

  it("★ a null endpoint stays null under both — no receiver is not an empty receiver", () => {
    expect(publishableEndpoint(null, true)).toBeNull();
    expect(publishableEndpoint(null, false)).toBeNull();
  });

  it("★★★ A HOSTILE COUNTERPARTY CANNOT DEFEAT THE FILTER BY NAMING A HOST", () => {
    /**
     * ⚠️ THE BYPASS REVIEW FOUND, and it turned the control off from the OTHER side of the wire.
     * The first version tested `addr.includes("/p2p-circuit")` — and the COUNTERPARTY controls these
     * strings. The directory copies them verbatim, and the FROST signature attests that the quorum
     * agreed on the assignment, **not that its contents are circuits**.
     *
     * So a peer offering `/dns4/p2p-circuit.attacker.example/...` got dialled DIRECTLY, handing over
     * the operator's IP with relay-only switched ON — and the suppression log reported
     * `suppressed: 0`, so nothing looked wrong. **A control a peer can defeat by naming a host is
     * exactly what this line rules out.**
     */
    const attack = "/dns4/p2p-circuit.attacker.example/tcp/443/p2p/12D3KooWTheirs";
    expect(isCircuitAddr(attack), "a HOSTNAME containing the text is not a circuit hop").toBe(false);
    expect(
      dialableAddrs([attack], true),
      "and it must not be dialled — this is the operator's IP, handed to whoever picked the hostname",
    ).toEqual([]);
    expect(isCircuitAddr(CIRCUIT), "while a real circuit address still passes").toBe(true);
    expect(isCircuitAddr(DIRECT), "and a plain direct address still does not").toBe(false);
    expect(isCircuitAddr("not-a-multiaddr"), "unparseable is not a circuit — the safe answer for both callers").toBe(false);
  });

  it("★★ RELAY-ONLY DIALS THE CIRCUIT AND DROPS THE DIRECT — 'only over the relay', not 'never'", () => {
    /**
     * THE OTHER HALF, and the first build got it wrong in the same direction: it refused EVERY
     * address, including the `/p2p-circuit` one — which is the relay route this setting exists to
     * force everything onto — and so dropped every session onto the store-and-forward backstop.
     *
     * Dialing a circuit addr reveals nothing to the counterparty: it terminates at the relay we
     * already chose. Dialing their DIRECT addr is what hands them our IP, and that is what must be
     * refused — the counterparty may not be relay-only themselves, so they will keep advertising one.
     */
    const theirs = [DIRECT, CIRCUIT];
    expect(dialableAddrs(theirs, true), "the circuit survives; the direct one does not").toEqual([CIRCUIT]);
    expect(dialableAddrs(theirs, false), "and the ordinary path is untouched").toEqual(theirs);
    expect(dialableAddrs([DIRECT], true), "a counterparty offering only a direct addr is not dialled at all").toEqual([]);
    expect(dialableAddrs([], false), "no addrs is still no dial, as before").toEqual([]);
  });
});

describe("DOD-M15-RELAYONLY-1 — the DIAL, driven through the real handler", () => {
  /**
   * ⚠️ THIS BLOCK EXISTS BECAUSE REVIEW FOUND THE DIAL HALF FAILED THE REVERT TEST. Reverting the
   * gate in `initiate-session-handler.ts` left every other test in this file GREEN — the pure
   * functions were pinned and the *behaviour* was not, which is the hollow-test shape this milestone
   * keeps finding. These drive `openSessionAs` and read what the daemon actually tried to dial.
   */
  function opener(relayOnly: string | null, counterpartyAddrs: string[]) {
    const dialled: string[][] = [];
    /**
     * ⚠️ THE PARTICIPANTS AND THE TIMESTAMP ARE NOT DECORATION — `DOD-M15-SELFCHAIN-1`.
     *
     * They were absent, because nothing in this file read them. The handler now derives the
     * session's chain starting point from exactly these four values and records it, so an
     * assignment without them is a shape production never produces: the negotiator verifies the
     * directory's threshold signature over a to-be-signed structure built from them, and an
     * assignment missing one could not have got past that check. This fixture stubs the negotiator,
     * which is what let an impossible shape reach the handler.
     */
    const assignment = {
      session_id: new Uint8Array(32).fill(0xab),
      participant_a: { pubkey: new Uint8Array(32).fill(0xa1) },
      participant_b: { pubkey: new Uint8Array(32).fill(0xb2) },
      session_timestamp: 1_750_000_000_000,
      counterparty_session_peer_id: "12D3KooWTheirs",
      counterparty_session_addrs: counterpartyAddrs,
      counterparty_pubkey: "cd".repeat(32),
      transport_mode: "relay",
    };
    const sessionNodeManager = {
      getSetting: (_a: string, key: string) => (key === RELAY_ONLY_KEY ? relayOnly : null),
      // The dial half reads the TRI-STATE, so the stub must answer whether the store is readable.
      // `true` here means "readable", so `relayOnly: null` is a genuine OFF rather than an unknown —
      // which is what the off-path test below needs in order to be testing what it claims.
      hasDatabase: () => true,
      // 038-KEYBIND: the initiator pins the responder group key the negotiation proved, and
      // compares it against any key recorded for that counterparty before — no pin here, so the
      // comparison passes and this suite stays about the DIAL.
      recordCounterpartyPrimary: () => {},
      getPinnedCounterpartyPrimary: () => null,
      createSessionNode: async () => ({ ok: true }),
      // The handler records the session's chain starting point right after the node is created.
      recordSessionGenesis: () => {},
      connectToCounterparty: async (_a: string, _s: string, addrs: string[]) => {
        dialled.push(addrs);
        return { ok: true };
      },
      addContact: () => {},
    };
    const { openSessionAs } = registerInitiateSessionHandler({
      handlers: new Map<string, IpcHandler>(),
      logger: { debug() {}, info() {}, warn() {}, error() {} } as unknown as Logger,
      sessionNodeManager: sessionNodeManager as never,
      getConnState: () => undefined,
      resolveCurrentAgent: (_c, explicit) => explicit ?? null,
      NO_CURRENT_AGENT_RESPONSE: { ok: false, reason: "no_current_agent" },
      resolvedSessionNegotiator: {
        negotiate: async () => ({ ok: true as const, assignment, counterpartyPrimaryHex: "11".repeat(32) }),
      } as unknown as SessionNegotiator,
      transportSelector: { dial: async () => ({ ok: true, mode: "relay" }) } as never,
      autoNatService: { getDialability: () => ({ dialable: false }) } as unknown as IAutoNatService,
      buildRelayConnectParams: async () => undefined,
      getRelayCircuitAddress: () => "",
    });
    return { openSessionAs, dialled };
  }

  it("★★★ RELAY-ONLY ON: the daemon dials the CIRCUIT and never the operator-revealing address", async () => {
    const { openSessionAs, dialled } = opener("true", [DIRECT, CIRCUIT]);
    await openSessionAs("alice", { target_pubkey: "cd".repeat(32) });
    expect(dialled.length, "it must still connect — relay-only is a routing control, not a disconnection").toBe(1);
    expect(
      dialled[0],
      "ONLY the circuit may be dialled. Dialling their direct address is what hands them our IP, " +
        "with the operator's own privacy setting switched on.",
    ).toEqual([CIRCUIT]);
  });

  it("★★★ RELAY-ONLY OFF: the ordinary path is untouched — both addresses are dialled", async () => {
    /** The regression half. A privacy control that changes the default path is a bug in itself. */
    const { openSessionAs, dialled } = opener(null, [DIRECT, CIRCUIT]);
    await openSessionAs("alice", { target_pubkey: "cd".repeat(32) });
    expect(dialled[0], "unchanged when the setting is off").toEqual([DIRECT, CIRCUIT]);
  });

  it("★★ RELAY-ONLY with only a DIRECT address offered: no dial at all", async () => {
    /**
     * The counterparty is not relay-only, so they advertise a direct address and nothing else.
     * Refusing to dial is correct — the session falls back to the relay-park path rather than
     * revealing this node. **This is the case that must not silently become a direct dial.**
     */
    const { openSessionAs, dialled } = opener("true", [DIRECT]);
    await openSessionAs("alice", { target_pubkey: "cd".repeat(32) });
    expect(dialled, "nothing dialable without revealing ourselves, so nothing is dialled").toEqual([]);
  });
});

describe("DOD-M15-RELAYONLY-1 — the leak cannot come back in through a BYPASS", () => {
  /**
   * ⚠️ THE CHOKE POINT MOVED, AND THIS GUARD FOLLOWS THE CODE RATHER THAN THE FILENAME.
   *
   * 037-SESSIONCORE split the standing receiver out of `session-node-manager.ts` into
   * `standing-receivers.ts`. `getStandingReceiverInfo` — the single method every publish path leaves
   * through — went with it, along with `publishableEndpoint` and the factory call.
   *
   * Pointing this at the new file is the whole change. Leaving it on the manager would have scanned
   * a one-line DELEGATOR: `publishableEndpoint` absent, the `!== null` sentinel absent, and the
   * factory never called — so this guard would have gone red for the wrong reason, and a later
   * reader "fixing" it by relaxing the assertions would have disarmed the leak protection entirely.
   * It DID go red, including its own vacuity precondition, which is the design working.
   */
  const SNM_PATH = join(import.meta.dirname, "..", "standing-receivers.ts");
  const MANAGER_PATH = join(import.meta.dirname, "..", "session-node-manager.ts");

  it("★★ the suppression is IN the choke point, not at its call sites", () => {
    /**
     * Suppression lives inside `getStandingReceiverInfo` so that a fourth publish path inherits the
     * protection rather than having to be told about it. Call-site gating would be a hand-kept list,
     * and this milestone has been bitten by one four separate times — the claim scanner's single
     * hard-coded non-markdown file, the 27-file typecheck allowlist, the guidance trees that
     * enumerated four causes when a fifth existed, and the leaf-kind default.
     *
     * **Revert test, RUN:** delete the `publishableEndpoint(...)` wrapper from the method and this
     * fails — which is the point, because every behavioural test above would still pass. They
     * exercise the pure functions; only this one pins that the daemon actually calls them.
     */
    /**
     * ⚠️ Reads the method's ACTUAL BODY — from its signature to its closing brace — rather than a
     * fixed number of characters. The first version sliced 1200 chars and went red the moment the
     * method grew, which is a guard that fails for a reason unrelated to what it guards. A test that
     * cries wolf on formatting gets weakened or deleted, and then it protects nothing.
     */
    const src = readFileSync(SNM_PATH, "utf8");
    const start = src.indexOf("getStandingReceiverInfo(agentName: string)");
    expect(start, "precondition: the method must be found at all — a rename makes this guard vacuous").toBeGreaterThan(0);
    const end = src.indexOf("\n  }", start);
    expect(end, "precondition: the method's closing brace must be locatable").toBeGreaterThan(start);
    expect(
      src.slice(start, end),
      "getStandingReceiverInfo must pass its endpoint through publishableEndpoint — without it, " +
        "relay-only publishes the operator's real addresses and the setting is a placebo",
    ).toContain("publishableEndpoint");
  });

  it("★★★ THE SENTINEL IS `!== null` — `!== undefined` made the whole fix DEAD CODE", () => {
    /**
     * ⚠️ THE BUG REVIEW FOUND IN MY OWN FIX, pinned at the exact character that was wrong.
     *
     * `#db` is declared `DaemonDatabase | null` and is only ever assigned on open or set to `null`
     * on close — **it is never `undefined` at any point in its lifetime.** So `this.#db !== undefined`
     * was a compile-time-constant `true`, TypeScript had nothing to object to, and the entire
     * `"unknown"` branch was unreachable. In the exact window it was written for — shutting down,
     * `#db` null, standing receiver still alive — it returned `off` and published the operator's real
     * addresses, while the DoD recorded the window as closed.
     *
     * The pure-function test above could never have caught this: it passes the boolean in literally.
     * **The defect was at the CALL SITE, in how that boolean is computed**, which is why this asserts
     * on the call site rather than the function.
     */
    const src = readFileSync(SNM_PATH, "utf8");
    const start = src.indexOf("getStandingReceiverInfo(agentName: string)");
    const body = src.slice(start, src.indexOf("\n  }", start));
    expect(
      body,
      "the readable argument must test against null. `!== undefined` is always true for this field, " +
        "which silently disables the entire unknown branch and fails toward disclosure.",
    ).toContain("this.#db !== null");
    expect(
      body,
      "and it must NOT test undefined — that sentinel cannot occur, so it is a guard that never fires",
    ).not.toContain("this.#db !== undefined");
  });

  it("★★★ EVERY return path leaves through the choke point — not just one that mentions it", () => {
    /**
     * ⚠️ THE GUARD'S OWN WEAKNESS, found by review. The earlier version asserted the string
     * `publishableEndpoint` appears SOMEWHERE in the method — so inserting `return endpoint;` at the
     * top would have left it green while the control was completely dead. It also went briefly false
     * in fact: the `unknown` branch used to build its own filtered object inline, so a second filter
     * existed inside the one method whose stated design is that there is exactly one.
     *
     * Now every `return` in the body must be either the null case or a call through the choke point.
     */
    const src = readFileSync(SNM_PATH, "utf8");
    const start = src.indexOf("getStandingReceiverInfo(agentName: string)");
    const body = src.slice(start, src.indexOf("\n  }", start));
    const returns = body.split("\n").map((l) => l.trim()).filter((l) => l.startsWith("return "));
    expect(returns.length, "precondition: the method must have return statements to police").toBeGreaterThan(0);
    const offenders = returns.filter((r) => r !== "return null;" && !r.includes("publishableEndpoint"));
    expect(
      offenders,
      "a return path leaves getStandingReceiverInfo without passing through publishableEndpoint — " +
        "that path publishes whatever it was handed, which under relay-only is the operator's real address",
    ).toEqual([]);
  });

  it("★★★ EVERY node is built through the agent-aware factory — a raw one hole-punches", () => {
    /**
     * ⚠️ THE SECOND CHOKE POINT, and it guards a leak the address filters cannot reach. dcutr
     * UPGRADES a relayed connection into a direct one, and the inbound side starts the upgrade —
     * which is exactly a standing receiver. So a node built without the agent's privacy posture
     * routes over the relay precisely as asked and then hole-punches to a direct connection anyway.
     * **Every test stays green, because the leak happens inside libp2p after the assertions.**
     *
     * Five sites build nodes. Passing the flag at each would be a hand-kept list, and the SIXTH
     * would leak. So the only permitted direct use of the raw factory is inside the wrapper itself.
     */
    const src = readFileSync(SNM_PATH, "utf8");
    const raw = src.split("\n")
      .map((line, i) => ({ line: line.trim(), n: i + 1 }))
      // Matches `#factory.createNode(` and `#ctx.factory.createNode(` alike: 037-SESSIONCORE moved
      // the wrapper into a collaborator that reaches the factory through its context, and a pattern
      // pinned to the old spelling would have found zero calls — which this guard's own precondition
      // correctly reports as vacuous rather than passing.
      .filter((r) => /factory\.createNode\(/.test(r.line));
    expect(raw.length, "precondition: the factory must still be called somewhere, or this guard is vacuous")
      .toBeGreaterThan(0);
    const offenders = raw.filter((r) => !r.line.includes("...config, relayOnly"));
    expect(
      offenders.map((r) => `session-node-manager.ts:${r.n}`),
      "a node is built straight off the factory instead of through #createAgentNode, so it does not " +
        "carry this agent's relay-only posture — that node will hole-punch to a direct connection " +
        "and disclose the address the setting exists to hide",
    ).toEqual([]);
  });

  it("★★ NOBODY reads a standing receiver's raw addresses around the choke point", () => {
    /**
     * ⚠️ THE BYPASS GUARD, and the shape that survives a refactor. Once suppression is at the choke
     * point, the way it comes undone is not an un-wrapped caller — it is a NEW READER that goes
     * around the method for raw addresses (`sr.node.listenAddresses()`) and publishes those instead.
     * That reader would be perfectly correct-looking and would leak on every relay-only session.
     *
     * There is exactly ONE such read today, inside the guarded method. A second is not necessarily
     * wrong, but it must be looked at by a human against this line, which is what failing here buys.
     */
    /**
     * ⚠️ **THIS ONE SCANS BOTH FILES, and narrowing it to one was a coverage regression.**
     *
     * The three checks above are about ONE METHOD, so pointing them at the file that method now
     * lives in is exactly right. This check is different in kind: it is a scan for a DANGEROUS SHAPE
     * anywhere — a non-predicate read of a standing receiver's raw addresses. 037-SESSIONCORE moved
     * the choke point out, but `session-node-manager.ts` still holds 22 reads of `#standingReceivers`
     * and the reservation watchdog's own `listenAddresses()` call. Scanning only the new file would
     * have left the manager — the file the split explicitly says the watchdog and relay paths stayed
     * in — invisible to the guard that exists to police it.
     */
    const scanned = [SNM_PATH, MANAGER_PATH];
    const lines = scanned.flatMap((f) => {
      const name = f.split("/").pop()!;
      return readFileSync(f, "utf8").split("\n").map((line, i) => ({ line, where: `${name}:${i + 1}` }));
    });
    const src = readFileSync(SNM_PATH, "utf8");
    const chokeLines = src.split("\n");
    const chokeStart = chokeLines.findIndex((l) => l.includes("getStandingReceiverInfo(agentName: string)"));
    expect(chokeStart, "precondition: the choke point must be locatable").toBeGreaterThan(0);
    const chokeEnd = chokeStart + chokeLines.slice(chokeStart).findIndex((l, i) => i > 0 && l === "  }");
    const chokeText = new Set(chokeLines.slice(chokeStart, chokeEnd + 1));

    const leaks: string[] = [];
    lines.forEach(({ line, where }) => {
      if (!line.includes(".node.listenAddresses()")) return;
      // Inside the choke point: this is the guarded read, and the only one that publishes.
      if (chokeText.has(line)) return;
      // ⚠️ NOT a blanket exemption for "any other read". The two reads outside the choke point today
      // are PREDICATES — `.some((a) => a.includes("/p2p-circuit"))`, asking whether a relay
      // reservation exists. A predicate inspects addresses; it does not hand them to anyone. A read
      // that is NOT a predicate is one that could be building an endpoint, and that is the shape
      // that must be looked at against this line.
      if (line.includes(".some(")) return;
      leaks.push(where);
    });

    expect(
      leaks,
      "a raw read of a standing receiver's listen addresses appeared outside the choke point and " +
        "outside a predicate. If it publishes those addresses, relay-only leaks the operator's IP " +
        "through it — route it via publishableEndpoint.",
    ).toEqual([]);
  });

  it("★ the guard is NOT VACUOUS — it can see the file and the pattern it polices", () => {
    /**
     * The positive control, and it is not ceremony. A count of 1 is also what a broken read returns
     * on the way to a false pass, and in this milestone a `grep` that classified a file as binary
     * over one stray NUL byte already produced a confident false claim. So prove the file was read
     * and the pattern is real before trusting either number above.
     */
    const src = readFileSync(SNM_PATH, "utf8");
    expect(src.length, "the file must actually have been read").toBeGreaterThan(10_000);
    expect(src, "and the method under guard must exist under that exact name").toContain("getStandingReceiverInfo");
  });
});
