/**
 * M12-P15 — a side must not pick its closing ceremony from a flag that records only its own crash.
 *
 * Measured 2026-08-05, session `dcd0aadc…`:
 *   09:39:42  A's daemon goes down. Shutdown runs one blanket statement —
 *             `UPDATE sessions SET status='interrupted' WHERE status='active'` — so `interrupted`
 *             means "MY process stopped", nothing about the counterparty.
 *   09:45:59  B closes, six minutes later, with no idea A is gone. It picks the NORMAL bilateral
 *             seal (`node.destroyed reason="sealing"`) and waits for A's co-signature. It never
 *             escalates to a unilateral root, so there is no R1 for the existing upgrade path.
 *   12:14:52  A returns, reads its OWN `interrupted` flag, infers "the counterparty must be gone",
 *             and sends seal_interrupted_request. B refuses — correctly, it is mid-seal.
 *             Deadlock: A cannot seal-interrupted, B cannot finish without A. force:true, no receipt.
 *
 * The leaves AGREE throughout. Only the beliefs about which ceremony is running diverge, which is
 * why M12-P14's readiness gate reports ready and walks straight into the refusal.
 *
 * The refusal already carries the answer once the responder names the state (e3da3b4). The initiator
 * must ROUTE on it rather than dead-end.
 */
import { describe, it, expect, vi } from "vitest";
import { createSealFlows } from "../seal-flows.js";

const AGENT = "alice";
const SID = "dc".repeat(32);

function harness(rejectionReason: string) {
  const events: Array<{ event: string; context: Record<string, unknown> }> = [];
  const submitSealLeaf = vi.fn(async () => ({ ok: true as const, sequenceNumber: 3 }));

  const sessionNodeManager = {
    getSessionTree: () => ({ size: () => 2 }),
    getSessionTreeRootHex: () => "aa".repeat(32),
    submitSealLeaf,
    persistSealInterruptedCommitment: () => true,
    retireSessionNode: async () => {},
    getSealCertificate: () => null,
  };

  const flows = createSealFlows({
    logger: {
      debug() {}, info(e, c) { events.push({ event: e, context: c ?? {} }); },
      warn(e, c) { events.push({ event: e, context: c ?? {} }); },
      error(e, c) { events.push({ event: e, context: c ?? {} }); },
    },
    sessionNodeManager: sessionNodeManager as never,
    agents: [{ name: AGENT, state: "online", pubkey: "alicepub" }],
    getKeyProvider: () => ({ sign: async () => new Uint8Array(64), getPublicKey: async () => new Uint8Array(32) }) as never,
    // The counterparty answers every request with the rejection under test.
    signalingFor: () => ({
      status: "connected",
      registerInboundHandler: (h: (f: Record<string, unknown>) => void) => {
        setTimeout(() => h({ type: "seal_interrupted_rejection", sessionId: SID, reason: rejectionReason }), 1);
        return () => {};
      },
    }) as never,
    sendOver: async () => ({ ok: true }),
    recordFrontierMismatch: () => {},
    clearFrontierMismatch: () => {},
  });

  return { flows, events, submitSealLeaf };
}

const RECORD = {
  agent_name: AGENT, agent_id: "aid", session_id: SID,
  counterparty_pubkey: "bobpub", status: "interrupted", message_count: 2,
} as never;

describe("M12-P15: the initiator routes on the counterparty's actual state", () => {
  it("session_seal_already_pending → submit our own seal leaf instead of dead-ending", async () => {
    // The dcd0aadc case. B has recorded its half and is waiting for ours; the completing action is
    // to give it, not to re-ask for a different ceremony. Dead-ending here is what left the operator
    // with force:true and no receipt.
    const h = harness("session_seal_already_pending");
    const res = await h.flows.handleSealInterruptedFlow(SID, RECORD, "corr", "") as Record<string, unknown>;

    expect(h.submitSealLeaf, "the peer is waiting on OUR half — send it").toHaveBeenCalled();
    expect(res.reason).not.toBe("seal_interrupted_rejected_by_counterparty");
  });

  it("session_already_sealed → do NOT re-request; the receipt exists", async () => {
    // Re-requesting a ceremony against a session the peer already sealed cannot succeed, and
    // submitting a seal leaf into a completed seal is worse than doing nothing.
    const h = harness("session_already_sealed");
    const res = await h.flows.handleSealInterruptedFlow(SID, RECORD, "corr", "") as Record<string, unknown>;

    expect(h.submitSealLeaf, "a sealed session must not receive another leaf").not.toHaveBeenCalled();
    expect(String(res.guidance)).toMatch(/receipt/i);
  });

  it("leaf_count_mismatch still dead-ends — routing must not paper over a genuine divergence", async () => {
    // The control, and the one that must NOT be routed. A short chain is M12-P14's case: there is no
    // ceremony to complete, because the two sides do not hold the same conversation. Submitting a
    // seal leaf here would attest a transcript we know disagrees.
    const h = harness("leaf_count_mismatch");
    const res = await h.flows.handleSealInterruptedFlow(SID, RECORD, "corr", "") as Record<string, unknown>;

    expect(h.submitSealLeaf).not.toHaveBeenCalled();
    expect(res.ok).toBe(false);
    expect(res.reason).toBe("seal_interrupted_rejected_by_counterparty");
  });
});
