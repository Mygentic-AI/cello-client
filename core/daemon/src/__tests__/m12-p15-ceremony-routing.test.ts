/**
 * M12-P15 — route on the counterparty's CEREMONY, never on our own crash flag.
 *
 * `interrupted` is set by one blanket statement at daemon shutdown, so it records that OUR OWN
 * process stopped and says nothing about the counterparty. Choosing seal-interrupted from it is the
 * inference "I crashed, therefore they are gone" — false in the measured case (`dcd0aadc…`): the
 * peer was healthy and had been waiting on our co-signature for two and a half hours.
 *
 * Review HIGH-2 on the first attempt: `session_seal_already_pending` names ONE wire string for TWO
 * peer ceremonies that demand OPPOSITE actions.
 *   - peer ran the relay bilateral seal and submitted a SEAL ctrl leaf  → our leaf completes it
 *   - peer ran the seal-interrupted ceremony and persisted a commitment → it has NO relay ctrl leaf
 *     and never will; our leaf is one leaf into a log that can never have a second distinct sender,
 *     so `#maybeProcessSeal` never fires and we would report ok:true for a session that can never
 *     seal. A permanent false success is worse than the dead end.
 * So the responder names the ceremony and the initiator routes ONLY on the one it can complete.
 * An absent field (older peer) means DO NOT SUBMIT.
 */
import { describe, it, expect, vi } from "vitest";
import { createSealFlows } from "../seal-flows.js";

const AGENT = "alice";
const SID = "dc".repeat(32);

function harness(reason: string, pendingCeremony?: string, submitResult: unknown = { ok: true, sequenceNumber: 3, reportedRootHex: "bb".repeat(32) }) {
  const events: Array<{ event: string; context: Record<string, unknown> }> = [];
  const submitSealLeaf = vi.fn(async () => submitResult);
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
    signalingFor: () => ({
      status: "connected",
      registerInboundHandler: (h: (f: Record<string, unknown>) => void) => {
        setTimeout(() => h({
          type: "seal_interrupted_rejection", sessionId: SID, reason,
          ...(pendingCeremony !== undefined ? { pending_ceremony: pendingCeremony } : {}),
        }), 1);
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

const close = (h: ReturnType<typeof harness>) =>
  h.flows.handleSealInterruptedFlow(SID, RECORD, "corr", "") as Promise<Record<string, unknown>>;

describe("M12-P15: the initiator routes on the counterparty's ceremony", () => {
  it("relay_bilateral → submit our half; that is the ceremony our leaf can complete", async () => {
    const h = harness("session_seal_already_pending", "relay_bilateral");
    const res = await close(h);
    expect(h.submitSealLeaf, "the peer is waiting on OUR half — send it").toHaveBeenCalled();
    expect(res.ok).toBe(true);
    expect(h.events.find((e) => e.event === "session.seal.ceremony.realigned")).toBeDefined();
  });

  it("seal_interrupted → submit NOTHING; our leaf could never complete that ceremony", async () => {
    // The review's HIGH-2. Submitting here buys a permanent false success: one leaf into a log that
    // will never have a second distinct sender, reported to the operator as ok.
    const h = harness("session_seal_already_pending", "seal_interrupted");
    const res = await close(h);
    expect(h.submitSealLeaf, "a seal-interrupted commitment has no relay ctrl leaf to join").not.toHaveBeenCalled();
    expect(res.ok).toBe(false);
  });

  it("ABSENT ceremony field (older peer) → submit NOTHING — never guess which one it is", async () => {
    const h = harness("session_seal_already_pending", undefined);
    const res = await close(h);
    expect(h.submitSealLeaf).not.toHaveBeenCalled();
    expect(res.ok).toBe(false);
  });

  it("responder_seal_already_submitted from OUR submit is SUCCESS — our half is already in", async () => {
    // Review HIGH-3: the active seal path already treats this as success ("keep the waiter
    // registered"). Reporting it as failure told the operator to retry forever — every retry hits
    // the same synchronous idempotency mark — while forbidding force:true, the only real exit.
    const h = harness("session_seal_already_pending", "relay_bilateral",
      { ok: false, reason: "responder_seal_already_submitted", reportedRootHex: "cc".repeat(32), sequenceNumber: 4 });
    const res = await close(h);
    expect(res.ok, "our leaf is in the relay log — that is not a failure").toBe(true);
  });

  it("a REAL submit failure stays a failure, and does not blame the relay for a missing node", async () => {
    const h = harness("session_seal_already_pending", "relay_bilateral",
      { ok: false, reason: "no_persisted_relay_endpoint" });
    const res = await close(h);
    expect(res.ok).toBe(false);
    expect(String(res.guidance)).toContain("no_persisted_relay_endpoint");
    expect(String(res.guidance), "do not forbid the only exit on an unrecoverable failure").not.toMatch(/Do NOT use force/);
  });

  it("leaf_count_mismatch still dead-ends — routing must not paper over genuine divergence", async () => {
    const h = harness("leaf_count_mismatch");
    const res = await close(h);
    expect(h.submitSealLeaf).not.toHaveBeenCalled();
    expect(res.reason).toBe("seal_interrupted_rejected_by_counterparty");
  });
});
