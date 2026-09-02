/**
 * A DIRECTORY REFUSAL MUST NOT COST AN HONEST PARTY ITS RECEIPT —
 * `DOD-M15-SEALPARTIES-1` clause 5, review finding F1.
 *
 * ─── The regression this pins, as an operator would meet it ────────────────────────────────────
 *
 * You and your counterparty both close. Something between you drops one field — a relay that dropped
 * a leaf, a relay that stripped a payload, or the two of you genuinely closing on different message
 * sets. The directory refuses to certify.
 *
 * **Before this unit:** nobody answered, the close waited out its window, and it escalated to a solo
 * seal over your own carried chain. Slow, and you got a receipt.
 *
 * **After clause 6 gave that refusal a listener:** the answer came back in seconds and the close
 * ENDED. Faster, and no receipt — in a case where one used to arrive. That is the trap the order
 * names ("must not become a new way to lose a receipt"), reached through the refusal listener rather
 * than through the approval requirement, and it applied to every directory refusal reason, not only
 * the new ones. `seal_leaves_invalid` was the sharpest: the relay tampered, and a solo seal over your
 * own chain is exactly the remedy.
 *
 * ─── Why the discriminator is WHO refused, not WHY ─────────────────────────────────────────────
 *
 * The terminal branch was written for one producer — this daemon refusing a certificate whose root
 * does not describe its own conversation — where ending the close is right, because there is nothing
 * further to ask for. `source` separates that from a directory refusal, where there is: the solo
 * path. Whether a PRESENT counterparty may be sealed around is the directory's call on its own
 * unilateral gate, so this side asks rather than deciding not to.
 */
import { describe, it, expect, vi } from "vitest";

const AGENT = "agent-a";
const SESSION = "cd".repeat(16);

type Handler = (p: Record<string, unknown>, c: string) => Promise<unknown>;

/**
 * An ACTIVE close whose bilateral wait this test resolves by hand.
 *
 * Extends the shape `dod-m15-closewait-1.test.ts` established for driving the real handler; the
 * additions are a recording `sendOver` (so an escalation attempt is observable) and a captured
 * `pendingSealWaiters` map (so the refusal can be injected at the exact moment the close is waiting).
 */
async function harness() {
  const { registerCloseSessionHandler } = await import("../close-session-handler.js");
  const handlers = new Map<string, Handler>();
  const sent: Array<Record<string, unknown>> = [];
  const events: Array<{ event: string; ctx: Record<string, unknown> }> = [];
  const recorded: Array<{ sessionId: string; reason: string }> = [];
  const rec = (event: string, ctx?: Record<string, unknown>) => { events.push({ event, ctx: ctx ?? {} }); };
  const pendingSealWaiters = new Map<string, (c: unknown) => void>();
  const backgroundSeals: Array<Promise<unknown>> = [];

  registerCloseSessionHandler({
    handlers,
    logger: { info: rec, warn: rec, error: rec, debug: () => {} },
    sealFailures: { record: (_a: string, s: string, r: string) => { recorded.push({ sessionId: s, reason: r }); }, clear: () => {} },
    registerBackgroundSeal: (p: Promise<unknown>) => { backgroundSeals.push(p); },
    sessionNodeManager: {
      getSessionRecord: () => ({ agent_name: AGENT, agent_id: "aid", session_id: SESSION, status: "active" }),
      submitSealLeaf: async () => ({ ok: true as const, sequenceNumber: 1, reportedRootHex: "aa".repeat(32) }),
      getSealCarry: () => [],
      getSealCertificate: () => null,
      resolveAgentId: () => "aid",
      setSessionName: () => {},
      sealReadiness: () => ({ ready: true, treeSize: 1, highWaterSeq: 0, heldCount: 0, missingLeaves: 0, heldOwn: 0, heldReceived: 0, diverged: false }),
    },
    getConnState: () => ({ currentAgent: AGENT }),
    resolveCurrentAgent: () => AGENT,
    NO_CURRENT_AGENT_RESPONSE: { ok: false, reason: "no_current_agent" },
    getKeyProvider: () => ({ getPublicKey: async () => new Uint8Array(32) }),
    signalingFor: () => ({ status: "connected" }),
    sendOver: async (_m: unknown, frame: Record<string, unknown>) => { sent.push(frame); return { ok: true }; },
    waitForSignalingConnected: async () => true,
    openVisitingConnection: () => ({ mgr: {}, stop: vi.fn(async () => {}) }),
    crossNodeBrokerBySession: new Map<string, string>(),
    sealKey: (a: string, s: string) => `${a}\x1f${s}`,
    sealInterruptedInProgress: new Set<string>(),
    pendingSealWaiters,
    pendingUnilateralWaiters: new Map(),
    resolveConsortiumRoster: async () => [],
    unilateralTimeoutMs: 10,
    bilateralTimeoutMs: 20_000,
    handleSealInterruptedFlow: async () => ({ ok: false, reason: "unused" }),
    handleActiveSealFlow: async () => ({ ok: false, reason: "unused" }),
  } as never);

  return { close: handlers.get("cello_close_session")!, sent, events, recorded, pendingSealWaiters, backgroundSeals };
}

/** Resolve the close's bilateral waiter as soon as it is armed. */
async function refuseOnceWaiting(
  pendingSealWaiters: Map<string, (c: unknown) => void>,
  completion: Record<string, unknown>,
): Promise<void> {
  const key = `${AGENT}\x1f${SESSION}`;
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    const waiter = pendingSealWaiters.get(key);
    if (waiter) { waiter(completion); return; }
    await new Promise((r) => setTimeout(r, 5));
  }
  throw new Error("the close never registered a bilateral seal waiter — the harness is not exercising the wait");
}

describe("DOD-M15-SEALPARTIES-1 clause 5: a directory refusal falls through to the solo seal", () => {
  it("★★★ a DIRECTORY refusal reaches the escalation instead of ending the close", async () => {
    const { close, events, pendingSealWaiters, backgroundSeals } = await harness();
    /**
     * ⚠️ THE CLOSE ANSWERS AT COMMITMENT AND NOTARIZES IN THE BACKGROUND (`DOD-M15-CLOSEWAIT-1`), so
     * the tail is where the receipt is won or lost and the tail is what this asserts on. Reading the
     * immediate response instead would report `ok: true` for both behaviours and prove nothing.
     */
    const committed = (await close({ session_id: SESSION }, "corr-1")) as Record<string, unknown>;
    expect(committed["seal_status"]).toBe("committed");
    expect(backgroundSeals, "the notarization tail must be registered, or there is nothing to test").toHaveLength(1);
    const closing = backgroundSeals[0]!;
    await refuseOnceWaiting(pendingSealWaiters, {
      refused: true,
      reason: "seal_approval_missing",
      detail: "only one participant's signed root was carried",
      ownRootHex: null,
      guidance: "…",
      source: "directory",
    });
    const result = (await closing) as Record<string, unknown>;

    expect(
      events.some((e) => e.event === "session.seal.refused.escalating"),
      "the close must announce that it is taking the solo path — otherwise the fall-through is a " +
        "behaviour nobody can see in a log",
    ).toBe(true);
    expect(
      result["seal_status"],
      "ending here as `refused` is the regression: it takes a receipt away from a party who used to " +
        "get one after the wait",
    ).not.toBe("refused");
    /**
     * ⚠️ THE UPSTREAM CAUSE SURVIVES THE DOWNSTREAM ANSWER — Invariant 3. The solo seal has nothing
     * to carry in this harness and fails on its own terms; the operator must still learn that a
     * BILATERAL seal was refused first, or the two answers point at different subsystems and only
     * one of them is printed.
     */
    expect(result["bilateral_refused_reason"]).toBe("seal_approval_missing");
    expect(String(result["guidance"] ?? "")).toMatch(/solo seal was then attempted/i);
  }, 30_000);

  it("★★ a LOCAL refusal is still terminal — this daemon refusing its own certificate has nothing left to ask", async () => {
    const { close, events, pendingSealWaiters, backgroundSeals } = await harness();
    await close({ session_id: SESSION }, "corr-2");
    const closing = backgroundSeals[0]!;
    await refuseOnceWaiting(pendingSealWaiters, {
      refused: true,
      reason: "seal_root_mismatch",
      detail: "the certified root is not this conversation",
      ownRootHex: "bb".repeat(32),
      source: "local",
    });
    const result = (await closing) as Record<string, unknown>;

    expect(result["seal_status"]).toBe("refused");
    expect(result["reason"]).toBe("seal_root_mismatch");
    expect(result["own_root"]).toBe("bb".repeat(32));
    expect(
      events.some((e) => e.event === "session.seal.refused.escalating"),
      "the local refusal must NOT escalate — the certificate was valid and simply describes another " +
        "conversation, so a solo seal over this side's chain answers a question nobody asked",
    ).toBe(false);
  }, 30_000);

  it("★ an absent `source` reads as local, so the pre-existing producer keeps its behaviour", async () => {
    const { close, pendingSealWaiters, backgroundSeals } = await harness();
    await close({ session_id: SESSION }, "corr-3");
    const closing = backgroundSeals[0]!;
    await refuseOnceWaiting(pendingSealWaiters, {
      refused: true,
      reason: "seal_root_mismatch",
      detail: "no source field, as the original producer wrote it",
      ownRootHex: null,
    });
    expect(((await closing) as Record<string, unknown>)["seal_status"]).toBe("refused");
  }, 30_000);
});
