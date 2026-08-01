/**
 * DOD-FRONTIER-STRAND-1 AC2 (M8C line, worked to lift M8D's Tier-1 fence) — the refusal must
 * report the ACTUAL mismatch.
 *
 * A leaf appended on one side and never recorded on the other strands the session as permanently
 * unsealable: the frontiers disagree, each side refuses to co-sign the other, and force-abandon —
 * which forfeits the receipt — is the only exit. Session `dbb93dfc…` sat that way for a week.
 *
 * What made it a WEEK rather than an afternoon is the diagnosis. The refusal said:
 *
 *   "The counterparty rejected the seal-interrupted request. This may indicate their session state
 *    is inconsistent. Ask the counterparty to check their interrupted sessions via cello status on
 *    their end."
 *
 * Both ends were the SAME DAEMON. There was no counterparty to ask, no second machine to check, and
 * the message never said what disagreed or by how much — so it pointed at the one action that could
 * not be taken and withheld the one fact that would have solved it in a minute.
 *
 * This clause fixes the message, not the strand. The producer-side fix (position-keyed dedup, per
 * the root-cause correction of 2026-07-31) is AC1 and is a separate unit — a strand can still be
 * created; it can no longer be undiagnosable.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import { createInboundSealRequestHandler } from "../inbound-seal-request.js";

const SID = "ef".repeat(32);

describe("DOD-FRONTIER-STRAND-1 AC2: a frontier mismatch names both frontiers", () => {
  let fx: TwoConnectionFixture;

  beforeEach(async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-m8c-frontier-" });
  });

  afterEach(async () => {
    await fx.cleanup();
  });

  it("F1: the responder's rejection carries BOTH leaf counts, not a bare reason string", async () => {
    // The responder is the side that can SEE the disagreement: it holds its own tree and receives
    // the initiator's claimed leafCount in the request. Today it discards that comparison and sends
    // the word "leaf_count_mismatch" alone, so the only party who ever knew the two numbers throws
    // them away.
    await fx.createSession(SID, "alice");
    fx.seedReceived("alice", SID, "one");
    fx.seedReceived("alice", SID, "two"); // alice's frontier: 2 leaves

    const sent: Array<Record<string, unknown>> = [];
    const { handleInboundSealInterruptedRequest } = createInboundSealRequestHandler({
      logger: { debug() {}, info() {}, warn() {}, error() {} },
      sessionNodeManager: fx.snm,
      agents: [{ name: "alice", state: "online", pubkey: "alicepubkeyhex" }],
      getKeyProvider: () => undefined,
      sendOver: async (_agent: string, frame: Record<string, unknown>) => {
        sent.push(frame);
        return { ok: true };
      },
    });
    await handleInboundSealInterruptedRequest({
      type: "seal_interrupted_request",
      sessionId: SID,
      initiatorPubkey: "bobpubkeyhex",
      counterpartyPubkey: "alicepubkeyhex",
      leafCountAtInterruption: 1, // bob thinks there is ONE leaf; alice holds TWO — the strand, staged
      merkleRootAtInterruption: "00".repeat(32),
      nonce: "n-f1",
    });

    const rejection = sent.find((f) => f.type === "seal_interrupted_rejection");
    expect(rejection, "the responder must reject a frontier mismatch").toBeDefined();
    expect(rejection!.reason).toBe("leaf_count_mismatch");
    // THE FIX: the two numbers travel with the refusal, so the initiator can render them.
    expect(rejection!.responder_leaf_count).toBe(2);
    expect(rejection!.initiator_leaf_count).toBe(1);
    // ...and the first index where they diverge, which is what an operator actually needs to look at.
    expect(rejection!.diverging_leaf_index).toBe(1);
  });

  it("F2: the mismatch is logged at WARN with both frontiers — findable without a close attempt", async () => {
    await fx.createSession(SID, "alice");
    fx.seedReceived("alice", SID, "one");
    fx.seedReceived("alice", SID, "two");

    const { handleInboundSealInterruptedRequest } = createInboundSealRequestHandler({
      logger: {
        debug() {}, info() {}, error() {},
        warn(event: string, ctx?: Record<string, unknown>) { warns.push({ event, ctx: ctx ?? {} }); },
      },
      sessionNodeManager: fx.snm,
      agents: [{ name: "alice", state: "online", pubkey: "alicepubkeyhex" }],
      getKeyProvider: () => undefined,
      sendOver: async () => ({ ok: true }),
    } as never);
    const warns: Array<{ event: string; ctx: Record<string, unknown> }> = [];

    await handleInboundSealInterruptedRequest({
      type: "seal_interrupted_request", sessionId: SID,
      initiatorPubkey: "bobpubkeyhex", counterpartyPubkey: "alicepubkeyhex",
      leafCountAtInterruption: 1, merkleRootAtInterruption: "00".repeat(32), nonce: "n-f2",
    });

    // The strand went a week unnoticed because nothing named it. This is the grep handle.
    const mismatch = warns.filter((w) => w.event === "session.frontier.mismatch");
    expect(mismatch).toHaveLength(1);
    expect(mismatch[0].ctx).toMatchObject({
      sessionId: SID, agentName: "alice",
      responderLeafCount: 2, initiatorLeafCount: 1, divergingLeafIndex: 1,
    });
  });

  it("F3: the diverging index is the SHORTER side, whichever side that is", async () => {
    // Either side can be the longer one, depending on which failed to record. Hardcoding "the
    // responder is ahead" would misreport the index exactly half the time — and the index is the
    // one thing the operator is told to go read.
    await fx.createSession(SID, "alice");
    fx.seedReceived("alice", SID, "only one"); // alice holds 1; the initiator claims 4

    const sent: Array<Record<string, unknown>> = [];
    const { handleInboundSealInterruptedRequest } = createInboundSealRequestHandler({
      logger: { debug() {}, info() {}, warn() {}, error() {} },
      sessionNodeManager: fx.snm,
      agents: [{ name: "alice", state: "online", pubkey: "alicepubkeyhex" }],
      getKeyProvider: () => undefined,
      sendOver: async (_a: string, frame: Record<string, unknown>) => { sent.push(frame); return { ok: true }; },
    } as never);

    await handleInboundSealInterruptedRequest({
      type: "seal_interrupted_request", sessionId: SID,
      initiatorPubkey: "bobpubkeyhex", counterpartyPubkey: "alicepubkeyhex",
      leafCountAtInterruption: 4, merkleRootAtInterruption: "00".repeat(32), nonce: "n-f3",
    });

    const rejection = sent.find((f) => f.type === "seal_interrupted_rejection")!;
    expect(rejection.responder_leaf_count).toBe(1);
    expect(rejection.initiator_leaf_count).toBe(4);
    expect(rejection.diverging_leaf_index).toBe(1); // min(1, 4) — the shorter side stops here
  });
});
