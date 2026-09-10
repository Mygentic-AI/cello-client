/**
 * DOD-M15-TOKENSTALE-1, unit 1 — an expired credential must not wear a relay outage's clothes.
 *
 * ─── What was measured, and why the label is the defect ────────────────────────────────────────
 *
 * Found live 2026-09-10 on the Hermes box. Its agent had been up for days, `cello status` read
 * `directory_signaling: connected`, and every send returned `ok:true, delivered:true`. Not one was
 * witnessed. The relay had refused it thirteen times with `online_token_expired` — the online token
 * is issued once in the directory handshake and lasts ONE HOUR, and nothing refreshes it while a
 * signalling connection stays up.
 *
 * The send path never saw that reason. `#ensureConnected` returns a BOOLEAN, so every auth refusal
 * collapses to `false`, and `#doSubmitOnce` substitutes `relay_unavailable`:
 *
 *     if (!(await this.#ensureConnected(node))) return { ok: false, reason: "relay_unavailable" };
 *
 * `relay_unavailable` means "the relay is unreachable" — transient, someone else's fault, and the
 * documented reason the send degrades to an unwitnessed leaf and reports success. Our own dead
 * credential is none of those: it is local, permanent until refreshed, and every send after it is
 * unwitnessed. **Two facts with opposite remedies leaving through one exit** is this milestone's
 * named defect class, and here it costs the receipt on every conversation the agent holds.
 *
 * ⚠️ THIS UNIT DOES NOT REFRESH THE TOKEN. Refreshing needs a directory frame that does not exist —
 * the directory issues only at `signaling_auth_ok` and `register_success`, and a repeat auth on an
 * open stream is ignored because the read loop skips that branch once `authed` is true. That is a
 * two-repo change and a deploy. **This unit makes the failure LOUD**, which is worth having on its
 * own: today the condition is invisible, and a silent unwitnessable agent is strictly worse than a
 * noisy one.
 */
import { describe, it, expect } from "vitest";
import { generateKeypair } from "@cello-protocol/crypto";
import { AgentRelayClient, classifyRelayAuthRefusal, RELAY_AUTH_REFUSAL_IS_LOCAL } from "../session-relay-client.js";
import { makeFakeRelay, noopLogger, tick } from "./relay-client-fake.js";

describe("DOD-M15-TOKENSTALE-1: an auth refusal is not a relay outage", () => {
  it("★ an expired token is classified as a LOCAL fault, not a relay one", () => {
    /**
     * The distinction the submit boundary needs in order to stop substituting. `tryAnotherRelay`
     * already says "do not fail over" — but it says that for a slot cap too, which IS satisfiable
     * elsewhere and IS the relay's answer. So it cannot be reused to mean "this is our fault":
     * it answers a different question and would be right for the wrong reason.
     */
    expect(RELAY_AUTH_REFUSAL_IS_LOCAL("online_token_expired"), "our credential died — nothing about the relay is wrong").toBe(true);
    expect(RELAY_AUTH_REFUSAL_IS_LOCAL("online_token_required"), "we never had one; also ours").toBe(true);
    expect(RELAY_AUTH_REFUSAL_IS_LOCAL("online_token_pubkey_mismatch"), "an identity mix-up on this machine").toBe(true);
  });

  it("★ a relay-side fault is NOT local — otherwise the flag means nothing", () => {
    /**
     * The teeth. A predicate that returned true for everything would pass the test above and make
     * every relay outage report as a local credential problem, which is the same substitution
     * running the other way.
     */
    expect(RELAY_AUTH_REFUSAL_IS_LOCAL("online_token_no_directory_key"), "this relay is misconfigured; another one works").toBe(false);
    expect(RELAY_AUTH_REFUSAL_IS_LOCAL("slot_cap_exceeded"), "the relay's own answer about its own slots").toBe(false);
    expect(RELAY_AUTH_REFUSAL_IS_LOCAL("throttled"), "the relay asking us to come back later").toBe(false);
  });

  it("★ an unknown reason is NOT assumed local", () => {
    /**
     * Which way to fail is a real choice. Defaulting to "local" would let a future relay-side reason
     * silently start telling operators their own machine is broken — and a wrong accusation about
     * the reader's own setup costs more than a vague one about someone else's.
     */
    expect(RELAY_AUTH_REFUSAL_IS_LOCAL("some_future_relay_reason")).toBe(false);
  });

  it("★ the expired-token advice no longer promises a refresh that cannot happen", () => {
    /**
     * The shipped sentence was *"refreshed on the next directory connection"*. It is true and it is
     * useless: the refresh happens on the next CONNECTION, and a healthy agent does not make one.
     * The Hermes box went from 2026-09-08 09:06 to 2026-09-10 13:40 without a token.
     *
     * ⚠️ Asserts what the reader must be able to DO. A test that only banned the old sentence would
     * pass on empty advice.
     */
    const advice = classifyRelayAuthRefusal("online_token_expired").advice;
    expect(advice, "the operator needs the one action that actually works today").toMatch(/cello (logout|login)|restart/i);
    expect(advice, "and must not be promised an automatic refresh that never comes")
      .not.toMatch(/refreshed on the next directory connection/i);
  });

  it("★ it says the CONSEQUENCE, because the whole defect is that nothing looked wrong", () => {
    // An operator reading this has been told their sends succeeded. The advice has to overturn that,
    // or it is a sentence about a token to someone who has no reason to care about tokens.
    const advice = classifyRelayAuthRefusal("online_token_expired").advice;
    expect(advice).toMatch(/witness|receipt/i);
  });
});

describe("DOD-M15-TOKENSTALE-1: the submit boundary stops substituting", () => {
  /**
   * Drive a REAL `AgentRelayClient` against a relay that refuses authentication, then submit.
   *
   * ⚠️ The relay's refusal is the seam that is faked, and the thing under test is what the CLIENT
   * does with it. Faking the submit result instead would assert the value this test exists to prove
   * is computed.
   */
  async function submitAgainstRefusingRelay(reason: string): Promise<{ ok: boolean; reason?: string }> {
    const relay = makeFakeRelay();
    const kp = generateKeypair();
    const client = new AgentRelayClient({
      relayPeerId: "12D3KooWFakeRelayForTokenStaleTestOnly0000000000000000",
      relayAddrs: [],
      keyProvider: kp,
      senderPubkey: await kp.getPublicKey(),
      logger: noopLogger,
      onlineToken: () => new Uint8Array(104).fill(0x11),
    });
    /**
     * The shared fake node has no `getConnections` — the client calls it only on the stream-failure
     * log path, which no existing test reaches. Wrapped here rather than widened in
     * `relay-client-fake.ts`: an empty list is the honest answer for a node that never connected,
     * and giving the shared fake one would let a future test assert against a value it invented.
     */
    const node = Object.assign(Object.create(Object.getPrototypeOf(relay.node) as object), relay.node, {
      getConnections: () => [],
    }) as never;
    const submitted = client.submitMessageHash(
      node,
      new Uint8Array(16).fill(0xab),
      new Uint8Array(32).fill(0xcd),
      0x01,
    ) as Promise<{ ok: boolean; reason?: string }>;
    // The client sends `relay_auth_response`; answer the way a relay with a dead token does.
    await tick();
    relay.push({ type: "relay_auth_challenge", nonce: new Uint8Array(32).fill(0x01) });
    await tick();
    relay.push({ type: "relay_auth_failed", reason });
    await tick();
    return await submitted;
  }

  it("★★ an expired token is REPORTED as an expired token, not as an unreachable relay", async () => {
    /**
     * THE LINE. `relay_unavailable` is the documented relay-degraded path: transient, someone
     * else's, and the reason a send may append an unwitnessed leaf and report success. Answering it
     * for our own dead credential is what let an agent go two days telling its operator everything
     * was fine while nothing it said could ever be proven.
     */
    const res = await submitAgainstRefusingRelay("online_token_expired");
    expect(res.ok).toBe(false);
    expect(res.reason, "the cause, not the exit point").toBe("online_token_expired");
    expect(res.reason, "relay_unavailable is a claim about the RELAY and it is false here")
      .not.toBe("relay_unavailable");
  }, 20_000);

  it("★★ a RELAY-side refusal still reports relay_unavailable — this is a split, not a rename", async () => {
    /**
     * The teeth, and the half that stops the fix being "return the reason for everything". A relay
     * holding no directory key genuinely IS a relay fault: the caller should keep treating it as the
     * transient remote condition it is, and failing over is the right move.
     */
    const res = await submitAgainstRefusingRelay("online_token_no_directory_key");
    expect(res.ok).toBe(false);
    expect(res.reason, "a relay fault must not be re-labelled as our credential").toBe("relay_unavailable");
  }, 20_000);
});
