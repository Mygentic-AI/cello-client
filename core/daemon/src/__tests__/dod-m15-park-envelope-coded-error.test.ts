/**
 * A PARK FAULT THAT IS NOT THE RELAY MUST NOT SAY IT IS — `DOD-M15-SEALWIRE-1` bullet 6, part
 * B2b-2, constraint 6. Inherited from B2a's two review passes.
 *
 * ─── What the operator lives through today ─────────────────────────────────────────────────────
 *
 * 1. They send a message. Direct delivery is not available, so it takes the park route.
 * 2. `encodeParkEnvelope` refuses to seal it, because the entry names a content-hash algorithm this
 *    build cannot itself reproduce — a real refusal, and the right one.
 * 3. The throw is caught. Nothing is lost: the message goes into the durable queue.
 * 4. **And they are told: _"Direct delivery failed and the relay refused the hand-off, so the
 *    message is queued and will be re-sent automatically when the relay link is back."_**
 *
 * Step 4 is false twice over, and both halves send them somewhere useless:
 *
 *   - **The relay refused nothing.** It was never asked. An operator reading that goes to look at
 *     relay health, or asks their counterparty about the relay, for a fault that is entirely local
 *     to the sending build.
 *   - **It will NOT be re-sent when the link is back.** Every drain re-parks the same entry and
 *     throws in exactly the same place. The message sits in the queue forever while the operator
 *     waits for a recovery that cannot happen.
 *
 * ─── Why a coded error rather than better prose ────────────────────────────────────────────────
 *
 * The prose is already good — it is a clear paragraph naming the exact problem. The defect is WHERE
 * IT LANDS: `cause`, which this file's own callers document as *the machine-readable half*, added
 * (M12-P13) precisely so nobody would have to substring-match English to decide what to do. Putting
 * a paragraph in it means the branch that should distinguish this fault cannot, so the fault falls
 * into the generic relay branch and inherits its guidance.
 *
 * So: a code the caller can switch on, and the paragraph kept where prose belongs.
 */

import { describe, it, expect, afterEach } from "vitest";
import { startTwoConnectionFixture, FakeNode, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import type { CelloNode } from "@cello-protocol/transport";
import { encodeParkEnvelope, sealParkEnvelope, ParkEnvelopeError, PARK_ENVELOPE_REASONS, RELAY_PARK_REFUSALS, parkRefusalGuidance } from "../park-envelope.js";
import { generateKeypair } from "@cello-protocol/crypto";
import { readFileSync } from "node:fs";
import { LEAF_KIND_MSG } from "../session-relay-client.js";

const SID = "5e".repeat(32);
const PEER = "12D3KooWQYV9dGMFoRzNStwpXztXaBUjtPqi6aMghfATmPnRAENn";
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

function envelopeArgs(alg: string) {
  return {
    contentHashHex: "ab".repeat(32),
    ciphertext: new Uint8Array([1, 2, 3]),
    senderPubkey: "cd".repeat(32),
    signature: new Uint8Array(64).fill(7),
    contentHashAlg: alg,
  };
}

/**
 * ⚠️ THE ERROR IS NOT FABRICATED — this calls the REAL producer.
 *
 * The production hook (`daemon.ts`) reaches `sealParkEnvelope` only after a live standing receiver
 * exists, which needs a real relay reservation this fixture's fake node cannot grant. So the hook is
 * replaced by one that calls **the same production function with the same arguments**, and throws
 * whatever it throws. Nothing about the failure is invented here; what is skipped is the receiver
 * lookup that happens before it.
 *
 * The gap that leaves — production wrapping its own `sealParkEnvelope` call in a `try` and swallowing
 * the throw — is closed by the source assertion in the last test rather than left to trust.
 */
const realSealHook = async (args: {
  sessionId: string;
  contentHash?: Uint8Array;
  content: Uint8Array;
  contentHashHex: string;
  contentHashAlg: string | undefined;
  structure1Cbor?: Uint8Array;
  structure2Cbor?: Uint8Array;
}): Promise<{ ok: true } | { ok: false; reason: string }> => {
  const kp = generateKeypair();
  await sealParkEnvelope({
    signer: kp,
    sessionIdHex: args.sessionId,
    recipientPubkey: Buffer.from("cd".repeat(32), "hex"),
    contentHash: Buffer.from(args.contentHashHex, "hex"),
    content: args.content,
    contentHashAlg: args.contentHashAlg,
    ...(args.structure1Cbor ? { structure1Cbor: args.structure1Cbor } : {}),
    ...(args.structure2Cbor ? { structure2Cbor: args.structure2Cbor } : {}),
  });
  return { ok: true };
};

describe("DOD-M15-SEALWIRE-1 B2b-2 constraint 6: the park refusal is CODED, not a paragraph", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  it("★ refusing an unreadable algorithm throws a TYPED error carrying a stable code", () => {
    let thrown: unknown;
    try { encodeParkEnvelope(envelopeArgs("sha3-512-someday")); } catch (err) { thrown = err; }

    expect(thrown, "the refusal itself must survive — this guard is what stops a silent mail loop").toBeInstanceOf(ParkEnvelopeError);
    expect(
      (thrown as ParkEnvelopeError).reason,
      "the code is what a caller branches on; without it the fault can only be identified by matching English",
    ).toBe(PARK_ENVELOPE_REASONS.ALG_UNREADABLE);
  });

  it("★ the code is MACHINE-readable and the prose is kept — not one at the cost of the other", () => {
    /**
     * The trap in "throw a coded error" is throwing away the paragraph, which is the part that tells
     * a human what actually happened. Both, in their own fields: the code carries no spaces so it
     * cannot be mistaken for a sentence, and the message still names the algorithm.
     */
    let thrown: ParkEnvelopeError | null = null;
    try { encodeParkEnvelope(envelopeArgs("sha3-512-someday")); } catch (err) { thrown = err as ParkEnvelopeError; }

    expect(thrown!.reason, "a code with a space in it is a sentence wearing a code's name").not.toMatch(/\s/);
    expect(
      thrown!.message,
      "the human half must still say WHICH algorithm, or the operator cannot tell which build to look at",
    ).toContain("sha3-512-someday");
    expect(
      thrown!.detail,
      "and the detail must be the offending value alone, so a caller can log it without re-parsing the sentence",
    ).toBe("sha3-512-someday");
  });

  it("★ a KNOWN algorithm still seals — the guard must not have become a wall", () => {
    expect(() => encodeParkEnvelope(envelopeArgs("sha256")), "the default algorithm").not.toThrow();
    expect(() => encodeParkEnvelope(envelopeArgs("hmac-sha256-salt-v1")), "the salted algorithm B2b-2 turns on").not.toThrow();
  });

  it("★ the park refusal reaches the caller as the CODE, not as the paragraph", async () => {
    /**
     * The whole point of the unit. `cause` is documented as the machine-readable half and is handed
     * to callers that branch on it; a paragraph there is unbranchable, so this fault has been
     * falling into the generic relay branch.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-park-coded-", node: new FakeNode({ newStreamFails: true }) as unknown as CelloNode });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER, { relay: true });
    fx.snm.setContentParkHook(realSealHook);

    const body = new TextEncoder().encode("a message whose algorithm this build cannot reproduce");
    const res = await fx.snm.sendContent("alice", SID, body, "ef".repeat(32), "corr-park", LEAF_KIND_MSG, "sha3-512-someday");
    await wait(200);

    expect(res.ok, "precondition: the send must actually fail, or nothing below is being tested").toBe(false);
    expect(
      (res as { cause?: string }).cause,
      "a caller that has to distinguish 'the relay is down' from 'this build cannot seal it' can only do so from a code",
    ).toBe(PARK_ENVELOPE_REASONS.ALG_UNREADABLE);
  }, 60_000);

  it("★ and the operator is NOT told the relay refused it, nor that it will re-send itself", async () => {
    /**
     * ⚠️ THE ASSERTION THIS UNIT EXISTS FOR, and it is about what the person reading the error does
     * next — not about a field's contents.
     *
     * Both halves of the inherited guidance are false here, and each sends them somewhere that
     * cannot help: to the relay, and to waiting. The message IS durably queued, so it is not lost —
     * but it will never drain, because every re-park throws in the same place. Saying "it will be
     * re-sent when the relay link is back" is the difference between an operator who fixes this in
     * ten minutes and one who waits out an afternoon.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-park-guidance-", node: new FakeNode({ newStreamFails: true }) as unknown as CelloNode });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER, { relay: true });
    fx.snm.setContentParkHook(realSealHook);

    const body = new TextEncoder().encode("and the guidance must not lie about it");
    const res = await fx.snm.sendContent("alice", SID, body, "ef".repeat(32), "corr-guide", LEAF_KIND_MSG, "sha3-512-someday");
    await wait(200);

    const guidance = String((res as { guidance?: string }).guidance ?? "");
    expect(guidance, "there must BE guidance — an unexplained failure is the thing this milestone keeps finding").not.toBe("");
    /**
     * ⚠️ FORBIDDING THE WORD "relay" WAS WRONG, and the first version of this test did it.
     *
     * Saying *"the relay is NOT involved"* is the single most useful sentence here — it is what stops
     * an operator opening a relay dashboard. What must not appear is the CLAIM that the relay refused
     * this or is down, so that is what is asserted.
     */
    expect(
      guidance,
      "the relay was never asked, so claiming it refused the hand-off sends the operator to the wrong subsystem",
    ).not.toMatch(/relay refused|relay is down|relay link/i);
    expect(
      guidance,
      "and it should say plainly that the relay is not the problem, since that is where an operator's first guess goes",
    ).toMatch(/relay is NOT involved/i);
    expect(
      guidance,
      "every re-park throws in the same place, so promising an automatic recovery costs the operator the time they spend waiting for it",
    ).not.toMatch(/when the relay link is back|re-sent automatically/i);
    expect(
      guidance,
      "and it must say what is actually true: this build cannot seal that algorithm, and a re-send changes nothing",
    ).toMatch(/upgrade|build|version/i);
  }, 60_000);

  it("★ production does not SWALLOW the throw — the one thing the hook substitution cannot observe", () => {
    /**
     * The two tests above call the real producer through a substituted hook, because the production
     * hook only reaches `sealParkEnvelope` after a live standing receiver exists — a real relay
     * reservation this fixture cannot grant. That substitution is faithful about the error and blind
     * about exactly one thing: whether production lets the throw out.
     *
     * If someone wraps that call in a `try` and returns `{ok: false, reason: "..."}` instead, every
     * assertion above still passes and the operator is back to a generic refusal — the defect
     * reintroduced with a green suite. So the shape is asserted directly, and the assertion pins the
     * ANCHOR first: a check that silently matches nothing is not a check.
     */
    const src = readFileSync(new URL("../daemon.ts", import.meta.url), "utf8");
    const calls = [...src.matchAll(/await sealParkEnvelope\(\{/g)];
    expect(calls.length, "anchor — if the call moved or was renamed, this test is checking nothing and must fail loudly").toBe(2);

    for (const call of calls) {
      // The 400 characters before the call: any enclosing `try {` opened for it would be in here.
      const before = src.slice(Math.max(0, call.index - 400), call.index);
      const lastTry = before.lastIndexOf("try {");
      const lastClose = before.lastIndexOf("}");
      expect(
        lastTry > lastClose,
        "sealParkEnvelope's refusal must reach #parkContent's catch — a try here turns a coded, actionable fault back into a generic refused deposit",
      ).toBe(false);
    }
  });
});

describe("DOD-M15-RELAYABUSE-1 — a THROTTLING relay is not an OUTAGE, and the guidance must not confuse them", () => {
  /**
   * ⚠️ THE SENTENCE WAS WRITTEN WHEN A REFUSED PARK COULD ONLY MEAN THE LINK WAS DOWN. Rate limiting
   * made a second, opposite cause reachable: the relay answered, promptly, and said no on purpose.
   *
   * *"will be re-sent automatically when the relay link is back"* then fails twice over. It sends the
   * operator to inspect a link that is fine — a wrong diagnosis is worse than none, because it tells
   * them where NOT to look — and it promises a trigger that will never fire, since the client retries
   * a deferred park only on events (boot, agent start, drain hook, signaling reconnect) and no
   * link-restored event is coming.
   */
  it("★★ rate_limited says the relay is HEALTHY, gives the real clearing time, and never blames the link", () => {
    const guidance = parkRefusalGuidance(RELAY_PARK_REFUSALS.RATE_LIMITED, true);

    expect(
      guidance,
      "blaming the link sends the operator to a dashboard that will show everything green, which is " +
        "the most expensive possible answer",
    ).not.toMatch(/relay link is back|relay is down|link is down/i);
    expect(
      guidance,
      "and it must say the relay is fine, because that is where the first guess goes",
    ).toMatch(/healthy|nothing is wrong/i);
    expect(
      guidance,
      "it must say the limit clears by itself, and roughly when — that is the fact that decides " +
        "whether they wait or start debugging",
    ).toMatch(/clears/i);
    expect(
      guidance,
      "and it must still say not to re-send: re-sending is precisely what the limit exists to slow",
    ).toMatch(/do not re-send/i);
  });

  it("★★ a FULL RECIPIENT mailbox is distinguished from a full relay — they need opposite actions", () => {
    /**
     * These read alike and are not alike. "This counterparty's mailbox is full" is about the other
     * party and another relay would refuse it identically; "the relay's store is full" is about
     * infrastructure and its operator needs to know. Collapsing them into one message loses the only
     * thing that decides what the reader does next.
     */
    const recipient = parkRefusalGuidance(RELAY_PARK_REFUSALS.RECIPIENT_FULL, true);
    const store = parkRefusalGuidance(RELAY_PARK_REFUSALS.STORE_FULL, true);

    expect(recipient, "the recipient case must point at the counterparty, not the infrastructure").toMatch(
      /counterparty|their mailbox|come online/i,
    );
    expect(
      recipient,
      "and must say another relay would not help — otherwise the obvious next move is to try one",
    ).toMatch(/another relay/i);
    expect(store, "the store case must point at the relay operator").toMatch(/relay operator|store is full/i);
    expect(recipient, "and the two must not be the same paragraph").not.toBe(store);
  });

  it("★ the ORIGINAL outage wording still exists for the case it was written for", () => {
    /** The regression half: an actual link failure must still get the sentence that is true for it. */
    const generic = parkRefusalGuidance("relay_unreachable", true);
    expect(generic, "an unknown/link failure keeps the original guidance").toMatch(/when the relay link is back/i);
  });
});

describe("DOD-M15-RELAYABUSE-1 — the guidance cannot promise a queue that does not exist", () => {
  /**
   * ⚠️ THE DEFECT REVIEW FOUND IN MY OWN FIX, and it is the lie this whole family of work exists to
   * kill, reintroduced one layer up.
   *
   * The first version of the three new branches returned a complete paragraph per cause and NEVER
   * consulted `durable`. So all three ended *"The message is queued and re-sent automatically. Do
   * not re-send it."* — including when the durable enqueue had been refused as a duplicate, or the
   * retry hook was unwired. The daemon logs at ERROR that the content is not retained, and the
   * operator was simultaneously told it was safe and instructed not to re-send it. **Nothing held
   * the message.**
   *
   * Diagnosis and action are now composed, so the action half is produced in one place and cannot be
   * reached without reading the flag.
   */
  for (const cause of [
    RELAY_PARK_REFUSALS.RATE_LIMITED,
    RELAY_PARK_REFUSALS.RECIPIENT_FULL,
    RELAY_PARK_REFUSALS.STORE_FULL,
  ]) {
    it(`${cause}: durable=false says LOST, and never says queued`, () => {
      const g = parkRefusalGuidance(cause, false);
      expect(g, "a message that was not queued must be described as lost").toMatch(/lost|send it again/i);
      expect(
        g,
        "and it must NOT tell the operator it is queued and to sit tight — that is the exact lie " +
          "this family of work exists to remove",
      ).not.toMatch(/queued and re-sent automatically/i);
      expect(g, "nor tell them not to re-send the only copy that exists").not.toMatch(/do not re-send/i);
    });

    it(`${cause}: durable=true keeps the diagnosis AND says it is queued`, () => {
      const g = parkRefusalGuidance(cause, true);
      expect(g, "the queued case still says so").toMatch(/queued and re-sent automatically/i);
      expect(g, "and still carries the cause-specific diagnosis rather than a generic sentence").not.toBe(
        parkRefusalGuidance("something_else_entirely", true),
      );
    });
  }
});


describe("DOD-M15-RELAYABUSE-1 — the guidance quotes the RELAY's window, or says nothing", () => {
  /**
   * ⚠️ "in about a minute" was a HARDCODED GUESS about the other side's configuration. The relay's
   * window is configurable; run it at ten minutes and that sentence becomes a wrong promise — and a
   * wrong number is worse than no number, because the reader plans around it.
   *
   * The real value was two frames away and died at `ParkAttempt`, which is the value-with-no-reader
   * defect one layer further out from where it had just been fixed twice.
   */
  it("quotes the relay's own delay when it gave one", () => {
    const g = parkRefusalGuidance(RELAY_PARK_REFUSALS.RATE_LIMITED, true, 45_000);
    expect(g, "45s is quoted in seconds, not rounded into a guess").toMatch(/about 45 seconds/i);
    expect(g, "and the old hardcoded guess is gone").not.toMatch(/about a minute/i);
  });

  it("renders a long window in minutes rather than 600 seconds", () => {
    const g = parkRefusalGuidance(RELAY_PARK_REFUSALS.RATE_LIMITED, true, 10 * 60_000);
    expect(g, "a ten-minute window must read as minutes — this is the case the guess got wrong").toMatch(/about 10 minutes/i);
  });

  it("says NOTHING about timing when the relay did not say", () => {
    /** Silence beats invention: an older relay sends no delay, and a made-up one is a wrong promise. */
    const g = parkRefusalGuidance(RELAY_PARK_REFUSALS.RATE_LIMITED, true, undefined);
    expect(g, "no delay, no claim about when").not.toMatch(/in about/i);
    expect(g, "but the diagnosis still stands").toMatch(/rate-limiting/i);
  });

  it("ignores a nonsense delay rather than rendering it", () => {
    for (const bad of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(parkRefusalGuidance(RELAY_PARK_REFUSALS.RATE_LIMITED, true, bad), `${String(bad)} must not be rendered`).not.toMatch(/in about/i);
    }
  });
});
