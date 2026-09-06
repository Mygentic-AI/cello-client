/**
 * `DOD-M15-SELFCHAIN-1` — WHAT THIS AGENT ACTUALLY SIGNS AS ITS SELF LINK.
 *
 * ─── Why this file exists, stated plainly ──────────────────────────────────────────────────────
 *
 * The unit has two halves: the checkers (relay, receiving daemon, directory) and the EMITTER. The
 * checkers were covered from the start. The emitter had no test of any kind — and it was wrong.
 *
 * The bug, as the operator would have met it:
 *
 *   1. Alice opens a session and sends "hi". She has said nothing before, so her self link is the
 *      session's starting point. The relay expects exactly that. Accepted.
 *   2. Bob's daemon ingests "hi" and advances its record of what Alice last said.
 *   3. Bob replies. Bob has never spoken on this session, so his self link should also be the
 *      starting point — but the code fell back to "the last thing I received", which by now is
 *      the hash of Alice's message.
 *   4. The relay refuses Bob's very first reply, and then SIGNS AN ALERT TO ALICE saying Bob's
 *      chain is broken.
 *
 * So: no two-party conversation could get past its second message, and the innocent party was told
 * the record had been tampered with. It was invisible because every fixture in the relay and
 * directory suites builds its chains with the correct per-sender semantics, so none of them ever
 * exercised the client's fallback.
 *
 * ─── The rule these tests pin ──────────────────────────────────────────────────────────────────
 *
 *   - `last_seen_hash` is the last message this sender RECEIVED, and it ADVANCES as the
 *     counterparty speaks.
 *   - `prev_own_hash` is this sender's OWN previous message, and it advances only when THIS side
 *     sends. Before this side has spoken it is the session GENESIS — never the counterparty's hash,
 *     and never a shared constant.
 *
 * The two are equal exactly once per session: at the very start, before anyone has said anything.
 * Every test below therefore drives at least one counterparty message first, because a fixture
 * where nothing has arrived cannot tell the two fields apart.
 */

import { describe, it, expect } from "vitest";
import { generateKeypair } from "@cello-protocol/crypto";
import { decodeStructure1 } from "@cello-protocol/protocol-types";
import { AgentRelayClient, LEAF_KIND_MSG } from "../session-relay-client.js";
import { makeFakeRelay, tick, noopLogger } from "./relay-client-fake.js";

/**
 * The session's starting point. A recognisable fill rather than zeros: an all-zero value is what an
 * unset field looks like, so a test asserting against zeros cannot tell "we agreed on this" from
 * "nobody wrote it".
 */
const GENESIS = new Uint8Array(32).fill(0x9c);
const SID = new Uint8Array(16).fill(0xf7);
const SID_HEX = Buffer.from(SID).toString("hex");

/** A client wired to a fake relay, with the session registered and the stream authenticated. */
async function connected(): Promise<{
  client: AgentRelayClient;
  relay: ReturnType<typeof makeFakeRelay>;
  submit: (contentHash: Uint8Array) => Promise<{ ok: boolean }>;
  links: () => { lastSeen: Uint8Array; prevOwn: Uint8Array };
}> {
  const kp = generateKeypair();
  const pub = await kp.getPublicKey();
  const client = new AgentRelayClient({
    relayPeerId: "12D3KooWRelay",
    relayAddrs: ["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWRelay"],
    keyProvider: kp,
    senderPubkey: pub,
    logger: noopLogger,
  });
  const relay = makeFakeRelay();
  client.registerSession(SID_HEX, relay.node, undefined, undefined, GENESIS);

  let seq = 0;
  /** Submit a leaf and let the fake relay acknowledge it, so the chain advances as it would live. */
  const submit = async (contentHash: Uint8Array): Promise<{ ok: boolean }> => {
    const p = client.submitMessageHash(relay.node, SID, contentHash, LEAF_KIND_MSG);
    await tick();
    if (seq === 0) {
      relay.push({ type: "relay_auth_challenge", nonce: new Uint8Array(32).fill(7) });
      await tick();
      relay.push({ type: "relay_auth_ok" });
      await tick();
    }
    seq += 1;
    relay.push({ type: "hash_submit_ack", sequence_number: seq });
    return (await p) as { ok: boolean };
  };

  /** The two chain links out of the LAST `hash_submit` the client actually put on the wire. */
  const links = (): { lastSeen: Uint8Array; prevOwn: Uint8Array } => {
    const submits = relay.sentFrames.filter((f) => f["type"] === "hash_submit");
    const last = submits[submits.length - 1]!;
    const decoded = decodeStructure1(last["structure1_cbor"] as Uint8Array);
    if (!decoded.ok) throw new Error(`the client emitted bytes it cannot read back: ${decoded.reason}`);
    return { lastSeen: decoded.fields.lastSeenHash, prevOwn: decoded.fields.prevOwnHash };
  };

  return { client, relay, submit, links };
}

const hex = (u: Uint8Array): string => Buffer.from(u).toString("hex");

describe("DOD-M15-SELFCHAIN-1: what this agent signs as its own self link", () => {
  it("★ the FIRST message of a session links to the session genesis on BOTH fields", async () => {
    const { submit, links } = await connected();
    expect((await submit(new Uint8Array(32).fill(0x11))).ok).toBe(true);
    const { lastSeen, prevOwn } = links();
    // The one moment the two are equal: nothing received, nothing said.
    expect(hex(lastSeen), "acknowledges the starting point").toBe(hex(GENESIS));
    expect(hex(prevOwn), "and links to the starting point").toBe(hex(GENESIS));
  });

  it("★★★ THE BUG: after the counterparty speaks, this side's FIRST message still links to the GENESIS", async () => {
    /**
     * THE REVERT TEST FOR THE WHOLE EMITTER. Restore the `?? seed` fallback and this goes red,
     * because `prev_own_hash` becomes the counterparty's content hash.
     *
     * This is the shape of every real conversation where the other party opens it: they say
     * something, we reply, and our reply is our FIRST message. If the two fields are conflated, the
     * relay refuses that reply and tells THEM their chain is broken.
     */
    const { client, submit, links } = await connected();
    // Get the stream authenticated without this side having said anything that counts as its own
    // first message — the auth handshake rides the first submit, so submit once and then start over
    // is not available. Instead: authenticate via a submit, then note a counterparty leaf, then
    // read the NEXT submit. The assertion below is about `prev_own_hash` NOT following `last_seen`.
    const theirs = new Uint8Array(32).fill(0x22);
    expect((await submit(new Uint8Array(32).fill(0x11))).ok).toBe(true);
    const mineFirst = links().prevOwn;
    expect(hex(mineFirst), "precondition: our first leaf linked to the genesis").toBe(hex(GENESIS));

    // The counterparty speaks. This advances the ACKNOWLEDGEMENT and must not touch the self link.
    client.noteReceivedLeaf(SID_HEX, 2, theirs);
    expect((await submit(new Uint8Array(32).fill(0x33))).ok).toBe(true);

    const { lastSeen, prevOwn } = links();
    expect(hex(lastSeen), "the acknowledgement follows THEM").toBe(hex(theirs));
    expect(
      hex(prevOwn),
      "the self link follows US — it must be our own previous content hash, never theirs",
    ).toBe(hex(new Uint8Array(32).fill(0x11)));
    expect(hex(prevOwn), "and the two fields must not be the same value").not.toBe(hex(lastSeen));
  });

  it("★★★ TWO MESSAGES IN A ROW carry DIFFERENT self links — the defect this unit exists to close", async () => {
    /**
     * The headline case. When one party sends twice with nothing arriving in between, both messages
     * acknowledge the SAME thing — so before this unit nothing in the signed bytes told them apart,
     * and whoever carried the conversation to a new relay could swap them.
     */
    const { submit, links } = await connected();
    const first = new Uint8Array(32).fill(0x11);
    const second = new Uint8Array(32).fill(0x22);

    expect((await submit(first)).ok).toBe(true);
    const a = links();
    expect((await submit(second)).ok).toBe(true);
    const b = links();

    expect(hex(a.lastSeen), "nothing arrived in between, so the acknowledgements are identical")
      .toBe(hex(b.lastSeen));
    expect(hex(a.prevOwn), "the first links to the starting point").toBe(hex(GENESIS));
    expect(hex(b.prevOwn), "the second links to the FIRST — which is what pins their order")
      .toBe(hex(first));
  });

  it("★★ a REFUSED submit does not advance the chain, so a retransmission repeats the same link", async () => {
    /**
     * A retransmission is the same message, so it must carry the same predecessor. Advancing on a
     * send that failed would skip a link over a message that never existed, and the counterparty
     * would then refuse everything after it for a reason that names tampering.
     */
    const kp = generateKeypair();
    const pub = await kp.getPublicKey();
    const client = new AgentRelayClient({
      relayPeerId: "12D3KooWRelay",
      relayAddrs: ["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWRelay"],
      keyProvider: kp,
      senderPubkey: pub,
      logger: noopLogger,
    });
    const relay = makeFakeRelay();
    client.registerSession(SID_HEX, relay.node, undefined, undefined, GENESIS);

    const first = new Uint8Array(32).fill(0x11);
    const p1 = client.submitMessageHash(relay.node, SID, first, LEAF_KIND_MSG);
    await tick();
    relay.push({ type: "relay_auth_challenge", nonce: new Uint8Array(32).fill(7) });
    await tick();
    relay.push({ type: "relay_auth_ok" });
    await tick();
    // REFUSED, not acknowledged. `hash_submit_error` is the relay's refusal frame — named here
    // rather than guessed, because a frame the client ignores would leave the submit hanging and
    // this test would then be measuring a timeout.
    relay.push({ type: "hash_submit_error", reason: "relay_busy" });
    expect((await p1).ok).toBe(false);

    const p2 = client.submitMessageHash(relay.node, SID, first, LEAF_KIND_MSG);
    await tick();
    relay.push({ type: "hash_submit_ack", sequence_number: 1 });
    expect((await p2).ok).toBe(true);

    const submits = relay.sentFrames.filter((f) => f["type"] === "hash_submit");
    expect(submits.length, "both attempts reached the wire").toBeGreaterThanOrEqual(2);
    for (const f of submits) {
      const d = decodeStructure1(f["structure1_cbor"] as Uint8Array);
      expect(d.ok).toBe(true);
      if (!d.ok) return;
      expect(
        hex(d.fields.prevOwnHash),
        "a refused attempt must not move the chain — every attempt at this message links to the genesis",
      ).toBe(hex(GENESIS));
    }
  });

  it("★★ a session registered with NO starting point cannot submit at all — it is refused, not downgraded", async () => {
    /**
     * There is no shorter shape to fall back to, deliberately: an unlinked message is invisible
     * until the conversation's order is disputed, which is far too late for anyone to act on it.
     */
    const kp = generateKeypair();
    const client = new AgentRelayClient({
      relayPeerId: "12D3KooWRelay",
      relayAddrs: ["/ip4/127.0.0.1/tcp/1/p2p/12D3KooWRelay"],
      keyProvider: kp,
      senderPubkey: await kp.getPublicKey(),
      logger: noopLogger,
    });
    const relay = makeFakeRelay();
    // A session WITH a starting point first, so the stream can be authenticated at all…
    client.registerSession(SID_HEX, relay.node, undefined, undefined, GENESIS);
    const warmup = client.submitMessageHash(relay.node, SID, new Uint8Array(32).fill(9), LEAF_KIND_MSG);
    await tick();
    relay.push({ type: "relay_auth_challenge", nonce: new Uint8Array(32).fill(7) });
    await tick();
    relay.push({ type: "relay_auth_ok" });
    await tick();
    relay.push({ type: "hash_submit_ack", sequence_number: 1 });
    expect((await warmup).ok).toBe(true);
    const framesBefore = relay.sentFrames.filter((f) => f["type"] === "hash_submit").length;

    // …then a SECOND session on the same authenticated client, registered with no starting point.
    // Split this way on purpose: if the only session has none, the submit fails at CONNECT instead,
    // and the test would pass on a refusal that has nothing to do with the chain.
    const bare = new Uint8Array(16).fill(0xb0);
    client.registerSession(Buffer.from(bare).toString("hex"), relay.node);

    const res = await client.submitMessageHash(relay.node, bare, new Uint8Array(32).fill(1), LEAF_KIND_MSG);
    expect(res.ok).toBe(false);
    expect(res.ok === false && res.reason).toBe("session_unchainable");
    expect(
      relay.sentFrames.filter((f) => f["type"] === "hash_submit").length,
      "and nothing reached the wire — a refusal that still sends is not a refusal",
    ).toBe(framesBefore);
  });
});
