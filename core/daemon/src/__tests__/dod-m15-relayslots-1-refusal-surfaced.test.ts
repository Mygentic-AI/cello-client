/**
 * DOD-M15-RELAYSLOTS-1 — a relay's refusal reaches the OPERATOR, with something to do about it.
 *
 * ─── The failure this is written against ──────────────────────────────────────────────────────
 *
 * The relay now refuses to let an agent hold a reservation slot for several distinct reasons, and
 * they mean genuinely different things: no directory has issued a token yet; the token expired; this
 * relay is misconfigured and refusing everyone; you already hold too many slots here. Each has a
 * different next step. Every one of them is worth nothing if it stops at a `logger.warn` on the
 * relay, or even at a `logger.warn` on the client — from where the person is sitting, their agent
 * came up, reported itself online, and is reachable by nobody.
 *
 * ⚠️ **THESE ARE UNIT TESTS OF THE CLASSIFIER, AND THEY ARE NOT THE EVIDENCE FOR CLAUSE 7.** They
 * were, and review measured that they could not be: every assertion below still passed with the
 * whole operator surface deleted — the capture in the relay client, the map in the manager, and
 * both `standing_receiver_refusal` blocks in the daemon. A pure function asserted in isolation says
 * nothing about what reaches a person.
 *
 * The clause-7 and clause-9 evidence lives in `dod-m15-relayslots-1-online-token-carried.test.ts`,
 * which drives a relay that really refuses and reads `getStandingReceiverRefusal` — the same value
 * `cello_status` puts in front of an operator. What remains here is worth keeping on its own terms:
 * it pins the wording and the failover classification per reason, which that test exercises for
 * only two of them.
 *
 * ─── And the second consumer is the daemon ────────────────────────────────────────────────────
 *
 * We run several relays, so "try the next one" is always available — which is exactly why it needs
 * a rule rather than a reflex. A token problem reproduces identically on every relay in the fleet,
 * so walking the fleet turns one client-side fault into what looks like a fleet-wide outage and
 * sends the operator hunting a broken relay. That decision has to branch on a code, not on prose,
 * which is why the reason is machine-readable as well as human-readable.
 */
import { describe, it, expect } from "vitest";
import { classifyRelayAuthRefusal } from "../session-relay-client.js";

describe("DOD-M15-RELAYSLOTS-1: every relay refusal carries a cause AND an affordance", () => {
  const ALL_REASONS = [
    "online_token_required",
    "online_token_expired",
    "online_token_malformed",
    "online_token_signature_invalid",
    "online_token_lifetime_too_long",
    "online_token_pubkey_mismatch",
    "online_token_no_directory_key",
    "slot_cap_exceeded",
    "session_tuple_cap_exceeded",
    "rate_limited",
  ];

  it("★★★ every reason the relay can give names an ACTION, not just a state", () => {
    for (const reason of ALL_REASONS) {
      const refusal = classifyRelayAuthRefusal(reason);
      expect(refusal.reason, "the relay's own code survives unmodified — the daemon branches on it").toBe(reason);
      expect(
        refusal.advice.length,
        `${reason} must come with what to DO about it. A bare code reads as the product being broken.`,
      ).toBeGreaterThan(40);
    }
  });

  it("reasons with different NEXT STEPS get different advice — it is not one sentence wearing nine hats", () => {
    /**
     * Grouped ON PURPOSE, and the grouping is the interesting half. `signature_invalid`,
     * `malformed` and `lifetime_too_long` are three ways for a relay to say "I would not accept the
     * token you were issued", and the person reading it does the same thing in all three cases:
     * check which directories that relay trusts. Giving them three near-identical sentences would
     * be noise pretending to be precision. The distinct CODES survive for the daemon regardless.
     */
    const sameNextStep = ["online_token_signature_invalid", "online_token_malformed", "online_token_lifetime_too_long"];
    const grouped = new Set(sameNextStep.map((r) => classifyRelayAuthRefusal(r).advice));
    expect(grouped.size, "one next step, one message").toBe(1);

    const distinctNextSteps = [
      "online_token_required",
      "online_token_expired",
      "online_token_signature_invalid",
      "online_token_pubkey_mismatch",
      "online_token_no_directory_key",
      "slot_cap_exceeded",
      "session_tuple_cap_exceeded",
      "rate_limited",
    ];
    const advice = new Set(distinctNextSteps.map((r) => classifyRelayAuthRefusal(r).advice));
    expect(
      advice.size,
      "collapsing THESE into one message is the same defect as collapsing the codes: 'no token yet' " +
        "clears itself, 'too many sessions' needs you to close some, and 'this relay has no " +
        "directory key' is somebody else's machine to fix.",
    ).toBe(distinctNextSteps.length);
  });

  it("★★★ the slot-cap refusal says HOW MANY, because nobody knows what sessions they have open", () => {
    const withCounts = classifyRelayAuthRefusal("slot_cap_exceeded", { slotsHeld: 32, slotCap: 32 });
    expect(withCounts.advice).toContain("32");
    expect(withCounts.slotsHeld).toBe(32);
    expect(withCounts.slotCap).toBe(32);

    // And it still says something useful when the relay did not send the numbers.
    const bare = classifyRelayAuthRefusal("slot_cap_exceeded");
    expect(bare.advice.length).toBeGreaterThan(40);
    expect(bare.slotsHeld).toBeUndefined();
  });

  it("the throttle refusal says when to come back, in seconds a person can read", () => {
    expect(classifyRelayAuthRefusal("rate_limited", { retryAfterMs: 4_500 }).advice).toContain("5s");
  });

  it("★★★ only a RELAY-side fault justifies trying another relay", () => {
    expect(
      classifyRelayAuthRefusal("online_token_no_directory_key").tryAnotherRelay,
      "this relay can verify nothing and is refusing everyone. That is its misconfiguration, not " +
        "ours, and having several relays is precisely for this.",
    ).toBe(true);

    for (const clientSide of [
      "online_token_required",
      "online_token_expired",
      "online_token_malformed",
      "online_token_signature_invalid",
      "online_token_lifetime_too_long",
      "online_token_pubkey_mismatch",
      "rate_limited",
    ]) {
      expect(
        classifyRelayAuthRefusal(clientSide).tryAnotherRelay,
        `${clientSide} reproduces identically on every relay in the fleet. Walking the fleet spends ` +
          "real time turning a client fault into an apparent outage, and sends whoever is looking " +
          "after a broken relay that is working fine.",
      ).toBe(false);
    }
  });

  it("★★★ a slot cap does NOT fail over, even though another relay would grant it", () => {
    const refusal = classifyRelayAuthRefusal("slot_cap_exceeded", { slotsHeld: 32, slotCap: 32 });
    expect(
      refusal.tryAnotherRelay,
      "another relay WOULD grant this, which is exactly the trap. Spreading papers over sessions " +
        "that leaked, and the same wall arrives on the next relay with the cause one hop further " +
        "away. Surface it instead.",
    ).toBe(false);
    expect(refusal.advice).toContain("same wall");
  });

  it("an unrecognised reason still gets a cause and an affordance rather than being dropped", () => {
    const refusal = classifyRelayAuthRefusal("something_added_later_on_the_relay");
    expect(refusal.reason).toBe("something_added_later_on_the_relay");
    expect(refusal.advice.length).toBeGreaterThan(40);
    expect(
      refusal.tryAnotherRelay,
      "the default has to be 'do not spread'. A reason nobody has classified yet is far more likely " +
        "to be ours than to be one relay's.",
    ).toBe(false);
  });
});
