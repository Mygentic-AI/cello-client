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
 *   - **Do not dial** — otherwise we hand our IP to the counterparty ourselves.
 *   - **Do not PUBLISH our session addrs** — so there is nothing for them to dial. This half
 *     protects the operator **even against a counterparty who ignores the flag**, and that is the
 *     whole point: *a control that depends on the other side honouring it is not a control.*
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
  shouldDialCounterparty,
} from "../relay-only.js";
import { isValidSettingKey, validateSettingValue } from "../agent-settings-keys.js";

const SR = { peerId: "12D3KooWStandingReceiver", addrs: ["/ip4/203.0.113.7/tcp/4001", "/ip4/127.0.0.1/tcp/4001"] };

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
});

describe("DOD-M15-RELAYONLY-1 — the two halves of the control", () => {
  it("★★ RELAY-ONLY PUBLISHES NO ADDRESSES — there is nothing left to dial", () => {
    /**
     * THE HALF THAT MAKES IT A CONTROL. With no addrs in the assignment, a counterparty who ignores
     * the flag entirely still has nowhere to connect. The peer id is KEPT: it is the identity the
     * relay circuit is addressed to, and stripping it would break relay routing — which is the very
     * path this setting forces everything onto.
     */
    const out = publishableEndpoint(SR, true);
    expect(out, "the endpoint still exists — this suppresses addresses, not reachability").not.toBeNull();
    expect(out!.addrs, "NO addresses may be published under relay-only").toEqual([]);
    expect(out!.peerId, "the peer id must survive — the relay circuit is addressed to it").toBe(SR.peerId);
  });

  it("★ and with the setting OFF, the endpoint is untouched — the default path cannot regress", () => {
    expect(publishableEndpoint(SR, false), "off = byte-identical to what the caller had").toEqual(SR);
  });

  it("★ a null endpoint stays null under both — no receiver is not an empty receiver", () => {
    expect(publishableEndpoint(null, true)).toBeNull();
    expect(publishableEndpoint(null, false)).toBeNull();
  });

  it("★★ RELAY-ONLY DOES NOT DIAL, even when the assignment carries dialable addresses", () => {
    /**
     * THE OTHER HALF, and the one the shipped code gets wrong today: the dial is gated on
     * `counterpartyAddrs.length > 0` and on nothing else. A counterparty that publishes addresses —
     * because THEY are not relay-only — would otherwise have us dial them and hand over our IP,
     * with our own setting on and the operator believing otherwise.
     */
    const addrs = ["/ip4/198.51.100.9/tcp/4001"];
    expect(shouldDialCounterparty(addrs, true), "relay-only must never dial, however dialable they are").toBe(false);
    expect(shouldDialCounterparty(addrs, false), "and the ordinary path is unchanged").toBe(true);
    expect(shouldDialCounterparty([], false), "no addrs is still no dial, as before").toBe(false);
  });
});

describe("DOD-M15-RELAYONLY-1 — the leak cannot come back in through a BYPASS", () => {
  const SNM_PATH = join(import.meta.dirname, "..", "session-node-manager.ts");

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
    const src = readFileSync(SNM_PATH, "utf8");
    const method = src.slice(src.indexOf("getStandingReceiverInfo(agentName: string)"));
    expect(method.length, "precondition: the method must be found at all — a rename makes this guard vacuous").toBeGreaterThan(0);
    expect(
      method.slice(0, 1200),
      "getStandingReceiverInfo must pass its endpoint through publishableEndpoint — without it, " +
        "relay-only publishes the operator's real addresses and the setting is a placebo",
    ).toContain("publishableEndpoint");
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
    const src = readFileSync(SNM_PATH, "utf8");
    const lines = src.split("\n");
    const chokeStart = lines.findIndex((l) => l.includes("getStandingReceiverInfo(agentName: string)"));
    expect(chokeStart, "precondition: the choke point must be locatable").toBeGreaterThan(0);
    const chokeEnd = chokeStart + lines.slice(chokeStart).findIndex((l, i) => i > 0 && l === "  }");

    const leaks: string[] = [];
    lines.forEach((line, i) => {
      if (!line.includes(".node.listenAddresses()")) return;
      // Inside the choke point: this is the guarded read, and the only one that publishes.
      if (i >= chokeStart && i <= chokeEnd) return;
      // ⚠️ NOT a blanket exemption for "any other read". The two reads outside the choke point today
      // are PREDICATES — `.some((a) => a.includes("/p2p-circuit"))`, asking whether a relay
      // reservation exists. A predicate inspects addresses; it does not hand them to anyone. A read
      // that is NOT a predicate is one that could be building an endpoint, and that is the shape
      // that must be looked at against this line.
      if (line.includes(".some(")) return;
      leaks.push(`session-node-manager.ts:${i + 1}`);
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
