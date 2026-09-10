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
import { AgentRelayClient, classifyRelayAuthRefusal, isLocalCredentialRefusal } from "../session-relay-client.js";
import { makeFakeRelay, noopLogger, tick } from "./relay-client-fake.js";
import { localCredentialRefusalNotice } from "../refusal-reasons.js";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

describe("DOD-M15-TOKENSTALE-1: an auth refusal is not a relay outage", () => {
  it("★ an expired token is classified as a LOCAL fault, not a relay one", () => {
    /**
     * The distinction the submit boundary needs in order to stop substituting. `tryAnotherRelay`
     * already says "do not fail over" — but it says that for a slot cap too, which IS satisfiable
     * elsewhere and IS the relay's answer. So it cannot be reused to mean "this is our fault":
     * it answers a different question and would be right for the wrong reason.
     */
    expect(isLocalCredentialRefusal("online_token_expired"), "our credential died — nothing about the relay is wrong").toBe(true);
    expect(isLocalCredentialRefusal("online_token_required"), "we never had one; also ours").toBe(true);
    expect(isLocalCredentialRefusal("online_token_pubkey_mismatch"), "an identity mix-up on this machine").toBe(true);
  });

  it("★ a relay-side fault is NOT local — otherwise the flag means nothing", () => {
    /**
     * The teeth. A predicate that returned true for everything would pass the test above and make
     * every relay outage report as a local credential problem, which is the same substitution
     * running the other way.
     */
    expect(isLocalCredentialRefusal("online_token_no_directory_key"), "this relay is misconfigured; another one works").toBe(false);
    expect(isLocalCredentialRefusal("slot_cap_exceeded"), "the relay's own answer about its own slots").toBe(false);
    expect(isLocalCredentialRefusal("throttled"), "the relay asking us to come back later").toBe(false);
  });

  it("★ an unknown reason is NOT assumed local", () => {
    /**
     * Which way to fail is a real choice. Defaulting to "local" would let a future relay-side reason
     * silently start telling operators their own machine is broken — and a wrong accusation about
     * the reader's own setup costs more than a vague one about someone else's.
     */
    expect(isLocalCredentialRefusal("some_future_relay_reason")).toBe(false);
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

describe("DOD-M15-TOKENSTALE-1: the operator is told without having to ask", () => {
  const notice = () =>
    localCredentialRefusalNotice("online_token_expired", classifyRelayAuthRefusal("online_token_expired").advice);

  it("★★ the impact leads with what is LOST, not with the credential", () => {
    /**
     * The reader arrives here having just been told their message was delivered. A sentence about a
     * token reads as housekeeping and gets skipped; the fact that has to land is that nothing they
     * say is being recorded as proof.
     */
    const { impact } = notice();
    expect(impact, "the receipt is the thing at stake").toMatch(/receipt/i);
    expect(impact, "and it must say the messages DO still arrive, or it reads as an outage").toMatch(/still arriv/i);
    // ⚠️ BOTH INDICES ASSERTED PRESENT FIRST — review: `indexOf` returns -1 for a missing needle, so
    // the ordering comparison alone passes vacuously when the word it is ordering is not there.
    const lossAt = impact.indexOf("witness");
    const mechanismAt = impact.indexOf("pass from the directory");
    expect(lossAt, "the loss must be stated at all").toBeGreaterThanOrEqual(0);
    expect(mechanismAt, "and so must the mechanism").toBeGreaterThanOrEqual(0);
    expect(lossAt, "the loss comes before the mechanism").toBeLessThan(mechanismAt);
  });

  it("★★ it says this is OURS and permanent — the two facts the old label denied", () => {
    const { impact } = notice();
    expect(impact, "not the relay being unreachable").toMatch(/not the relay being unreachable/i);
    expect(impact, "and it will not clear on its own").toMatch(/does not clear on its own/i);
  });

  it("★★ the inbox and cello status cannot give two different remedies", () => {
    /**
     * The guidance is the SAME string `classifyRelayAuthRefusal` produces, by construction rather
     * than by two authors agreeing. One condition with two remedies is how an operator learns to
     * trust neither.
     */
    expect(notice().guidance).toBe(classifyRelayAuthRefusal("online_token_expired").advice);
  });

  it("★ it scopes the damage to the AGENT, not to one conversation", () => {
    // A dead credential is not per-session: every conversation this agent holds is unwitnessed. An
    // operator told only about this session would close it and open another into the same wall.
    expect(notice().impact).toMatch(/any other one this agent holds|every conversation/i);
  });
});

describe("DOD-M15-TOKENSTALE-1: the split did not strip the fallbacks that exist for exactly this state", () => {
  /**
   * ⚠️ THE TESTS THAT WERE MISSING, AND THEIR ABSENCE IS THE REVIEW FINDING — F1, F2, F3.
   *
   * Every other test in this file stops at the submit boundary's return value. `relay_unavailable`
   * had FOUR consumers that branched on the exact string, and promoting the real reason silently
   * took all four away — from the one condition they were built for, because an agent whose
   * credential is dead has by definition no relay witness. A 3,554-test gate went green over it.
   *
   * These read the SOURCE rather than driving each flow, and that is a deliberate trade stated
   * plainly: driving a close, a restart-resolver sweep and an away auto-seal each needs a live
   * multi-process rig, and a test that cannot be written does not get written — which is how this
   * gap opened. A source assertion is weaker than an execution, and it is strictly stronger than
   * nothing; it fails the moment someone re-narrows a branch back to the bare string.
   */
  const SRC = join(dirname(fileURLToPath(import.meta.url)), "..");
  const read = (f: string): string => readFileSync(join(SRC, f), "utf8");

  it("★★ the close path still falls back to the directory-mediated seal (F1)", () => {
    const src = read("close-session-handler.ts");
    expect(
      src,
      "an expired credential means NO relay witness — the exact state this fallback is for. Keyed on " +
      "the bare string it stops being taken, and the operator is told to retry once the relay is " +
      "reachable about a relay that was never the problem.",
    ).toMatch(/submit\.reason === "relay_unavailable" \|\| isLocalCredentialRefusal\(submit\.reason\)/);
  });

  it("★★ a seal that may already be durable is still checked (F1, second hit)", () => {
    // Same line, different set: the stored certificate is the answer either way and consulting it is
    // cheap. Dropping out of this set revives the M12-P15 regression its own comment describes.
    const src = read("close-session-handler.ts");
    const set = src.slice(src.indexOf("SEAL_MAY_ALREADY_BE_DURABLE"), src.indexOf("const localCert"));
    for (const reason of ["online_token_expired", "online_token_required", "online_token_pubkey_mismatch"]) {
      expect(set, `${reason} must still reach the stored-certificate check`).toContain(reason);
    }
  });

  it("★★ the restart-seal resolver does not spend its budget on a credential that clears on relogin (F2)", () => {
    /**
     * The sharpest of the three. Outside this set the reason consumes attempts and then writes a
     * DURABLE give-up, removing sessions that hold signed commitments from the only queue that would
     * ever enumerate them again — the 28-session outcome that set was written to prevent.
     */
    const src = read("restart-seal-resolver.ts");
    const set = src.slice(src.indexOf("LOCAL_PRECONDITION_REFUSALS"), src.indexOf("TERMINAL_SEAL_REFUSALS"));
    expect(set, "an expired token is a local precondition: it passes after a relogin").toContain("online_token_expired");
    expect(src.slice(src.indexOf("TERMINAL_SEAL_REFUSALS")), "and it is NEVER terminal — that would forfeit the receipt")
      .not.toContain("online_token_expired");
  });

  it("★★ the away auto-seal still falls back, where nobody is watching (F3)", () => {
    // By construction there is no operator on this path, so the loss would be silent.
    expect(read("attendance-wiring.ts")).toMatch(/submit\.reason === "relay_unavailable" \|\| isLocalCredentialRefusal\(submit\.reason\)/);
  });

  it("★★ a stale verdict cannot relabel a genuine relay outage as our credential (F4)", () => {
    /**
     * `#lastAuthRefusal` is cleared only on auth SUCCESS. `#connect`'s dial and stream failures never
     * reach a verdict, so without a clear at entry they return carrying an earlier attempt's refusal
     * — and the promotion would then blame this machine for somebody else's outage AND strip the
     * fallbacks above from the case they exist for.
     */
    const src = read("session-relay-client.ts");
    const connect = src.slice(src.indexOf("async #connect(node: CelloNode)"), src.indexOf("async #authenticate"));
    expect(connect, "the verdict must be dropped before an attempt that may never reach one").toContain("this.#clearAuthRefusal();");
  });
});
