/**
 * DOD-M15-CLOSEWAIT-1 — a close answers the caller before eleven minutes elapse.
 *
 * ─── What an operator lives through today ──────────────────────────────────────────────────────
 *
 * They run `cello_close_session`. The command freezes. Measured 2026-08-17: seal leaf submitted at
 * 16:48:55, ceremony completed at 17:00:01 — **11 minutes 6 seconds of a dead terminal.**
 *
 * It is working the whole time. It has submitted its SEAL leaf, and it is waiting for the
 * counterparty to close too; if they never do, it escalates to a unilateral seal and produces a real
 * notarized receipt. But nobody watching a frozen command believes that. One operator concluded it
 * was broken and force-abandoned **seventeen sessions** — and force-abandon forfeits the exact
 * receipt the wait was earning.
 *
 * `DOD-M12B-CLOSE-SILENT-WAIT-1` already fixed the half that could be fixed without touching the
 * contract: the wait now announces itself in the log. This is the other half.
 *
 * ─── The contract, decided before the code (Decisions Carried #4) ──────────────────────────────
 *
 * **ANSWER ON COMMITMENT, NOT ON NOTARIZATION.** The close returns as soon as the SEAL leaf is
 * durably submitted. The bilateral wait and the unilateral escalation continue in the background;
 * the receipt is collected with `cello_get_sealed_receipt`.
 *
 * Nothing about WHAT is signed, by whom, or in what order changes — the same escalation produces the
 * same receipt from the same leaf. Only the IPC response stops waiting for it.
 *
 * ─── The counterbalance, named before the code ─────────────────────────────────────────────────
 *
 * Answering early must not let an operator believe a COMMITTED session is a SEALED one. That is the
 * failure this change could introduce, and it would be worse than the wait: an operator who thinks
 * they hold a receipt and does not is in a worse position than one who is merely kept waiting. So
 * the response says committed-not-notarized, names the verb that fetches the receipt, and the
 * session keeps reading as sealing until it genuinely is not.
 *
 * ─── Why this is plumbing and not a rebuild ────────────────────────────────────────────────────
 *
 * Both safety nets already existed, which is what made this the least-reversing option:
 *   - `cello_get_sealed_receipt` already returns the same certificate.
 *   - `RestartSealResolver` (`DOD-M12B-RESTART-SEAL-1`) already resolves `seal_interrupted_pending`
 *     on boot — a seal commitment nobody asked the directory to notarize — so a daemon that dies
 *     during the background wait finishes on its next start rather than orphaning the session.
 */

import { describe, it, expect, vi } from "vitest";
import { CLOSE_COMMITTED_GUIDANCE, describeSealCommitted } from "../close-commitment.js";

describe("DOD-M15-CLOSEWAIT-1: the committed answer cannot be mistaken for a sealed one", () => {
  it("★ it does NOT report ok-with-a-root — there is no root yet", () => {
    /**
     * The counterbalance, first. The tempting shape is `{ ok: true }` with the session gone from the
     * list, because that is what a close "looks like" — and it would be a lie that costs an operator
     * their receipt, since they would never call `cello_get_sealed_receipt`.
     */
    const r = describeSealCommitted({ sessionId: "abc123", deadlineMs: 660_000 });
    expect(r["sealed_root"], "there is no notarized root at commitment time, so there must be no field claiming one").toBeUndefined();
    expect(r["sealed"], "and nothing may report the session as sealed").toBeUndefined();
  });

  it("★ it states the status as COMMITTED, in a word that is not 'closed'", () => {
    const r = describeSealCommitted({ sessionId: "abc123", deadlineMs: 660_000 });
    expect(r["ok"]).toBe(true);
    expect(r["seal_status"]).toBe("committed");
  });

  it("★ the guidance names the verb that fetches the receipt", () => {
    /**
     * Invariant 4 — an agent-facing response carries the affordance. Without the verb, "committed"
     * is a status an agent can do nothing with, and the receipt is never collected.
     */
    const r = describeSealCommitted({ sessionId: "abc123", deadlineMs: 660_000 });
    expect(String(r["guidance"])).toContain("cello_sealed_receipt");
    expect(
      String(r["guidance"]),
      "and it must NOT name the internal IPC method — the handler is registered as " +
        "cello_get_sealed_receipt, but the TOOL an agent can call is cello_sealed_receipt, and " +
        "prose naming the wrong one hands the operator a dead command (the vocabulary audit caught " +
        "exactly this here)",
    ).not.toMatch(/cello_get_sealed_receipt/);
  });

  it("★ it says the receipt is NOT yet available, and roughly when to look", () => {
    const g = String(describeSealCommitted({ sessionId: "abc", deadlineMs: 660_000 })["guidance"]);
    expect(g, "an agent that polls immediately and finds nothing must not read that as failure").toMatch(/not yet/i);
    expect(g, "and the outer bound has to be a NUMBER, not 'shortly'").toMatch(/11 minutes/);
  });

  it("★ it warns against force-abandon, which is what the 11-minute freeze actually caused", () => {
    /**
     * Seventeen sessions were lost that way. The wait no longer blocks, so the panic that produced
     * those force-abandons should not recur — but an operator who does not see an immediate receipt
     * may still reach for `force: true`, and that still forfeits it.
     */
    const g = String(describeSealCommitted({ sessionId: "abc", deadlineMs: 660_000 })["guidance"]);
    expect(g).toMatch(/force/i);
    expect(g, "and it must say what forcing COSTS, not merely that it exists").toMatch(/forfeit|lose|destroy/i);
  });

  it("the deadline is rendered from the actual configured timeout, not hardcoded prose", () => {
    // An operator who shortened CELLO_SEAL_BILATERAL_TIMEOUT_MS must not be told "11 minutes".
    const g = String(describeSealCommitted({ sessionId: "abc", deadlineMs: 120_000 })["guidance"]);
    expect(g).toMatch(/2 minutes/);
    expect(g).not.toMatch(/11 minutes/);
  });

  it("the session id is echoed, so the receipt can actually be fetched", () => {
    const r = describeSealCommitted({ sessionId: "deadbeef", deadlineMs: 660_000 });
    expect(r["session_id"]).toBe("deadbeef");
    expect(String(r["guidance"]), "and the id appears in the instruction itself").toContain("deadbeef");
  });

  it("CLOSE_COMMITTED_GUIDANCE is one definition, not a second copy", () => {
    /**
     * The shape this milestone keeps finding: a string duplicated at two call sites, one of which is
     * later reworded, and the two surfaces quietly disagree. One exported builder, used everywhere.
     */
    expect(typeof CLOSE_COMMITTED_GUIDANCE).toBe("function");
    expect(CLOSE_COMMITTED_GUIDANCE({ sessionId: "x", deadlineMs: 660_000 })).toBe(
      String(describeSealCommitted({ sessionId: "x", deadlineMs: 660_000 })["guidance"]),
    );
  });
});

/**
 * THE ORDERING GUARD — the most dangerous part of this unit, and the revert test found it untested.
 *
 * Deleting the `handedOff` check from the enclosing `finally` left every test green. That check is
 * the only thing stopping the close from releasing the broker's seal connection while the background
 * ceremony is still using it — which would not merely report the seal differently, it would break it
 * mid-flight. A guard nobody hears is not a guard.
 */
describe("DOD-M15-CLOSEWAIT-1: the broker connection outlives the response", () => {
  const AGENT = "agent-a";
  const SESSION = "ab".repeat(16);

  /** Builds a cross-node ACTIVE close whose seal never resolves, so the tail stays in flight. */
  async function harness() {
    const { registerCloseSessionHandler } = await import("../close-session-handler.js");
    const handlers = new Map<string, (p: Record<string, unknown>, c: string) => Promise<unknown>>();
    const stop = vi.fn(async () => {});
    const crossNodeBrokerBySession = new Map<string, string>([[`${AGENT}:${SESSION}`, "gcp-usc1"]]);

    registerCloseSessionHandler({
      handlers,
      logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
      sessionNodeManager: {
        getSessionRecord: () => ({ agent_name: AGENT, agent_id: "aid", session_id: SESSION, status: "active" }),
        // A successful submit is what puts the flow into the bilateral wait — the tail under test.
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
      sendOver: async () => ({ ok: true }),
      waitForSignalingConnected: async () => true,
      openVisitingConnection: () => ({ mgr: {}, stop }),
      crossNodeBrokerBySession,
      sealKey: (a: string, s: string) => `${a}\x1f${s}`,
      sealInterruptedInProgress: new Set<string>(),
      pendingSealWaiters: new Map(),
      pendingUnilateralWaiters: new Map(),
      resolveConsortiumRoster: async () => [{ nodeId: "gcp-usc1", peerId: "12D3KooWBroker", multiaddr: "/ip4/10.10.1.25/tcp/4000" }],
      unilateralTimeoutMs: 10,
      handleSealInterruptedFlow: async () => ({ ok: false, reason: "unused" }),
      handleActiveSealFlow: async () => ({ ok: false, reason: "unused" }),
    } as never);

    return { close: handlers.get("cello_close_session")!, stop };
  }

  it("★ the close returns WITHOUT releasing the broker connection the background seal still needs", async () => {
    /**
     * The failure this pins: the enclosing `finally` runs when the close returns, and with the
     * `handedOff` guard removed it calls `stop("seal-complete")` on a connection the background
     * ceremony is still holding. The seal loses its transport mid-flight — a corrupted seal, not a
     * differently-reported one.
     *
     * The seal is never resolved here, so the tail is still in flight when the assertion runs, which
     * is exactly the window that matters.
     */
    const { close, stop } = await harness();
    const bilateral = process.env["CELLO_SEAL_BILATERAL_TIMEOUT_MS"];
    process.env["CELLO_SEAL_BILATERAL_TIMEOUT_MS"] = "600000"; // long, so the tail cannot finish
    try {
      const res = (await close({ session_id: SESSION }, "conn-1")) as Record<string, unknown>;
      expect(res["seal_status"], "PRECONDITION: this must be the committed (handed-off) path").toBe("committed");
      expect(
        stop,
        "the close released the broker's seal connection on its way out, while the background " +
          "ceremony was still using it — the seal loses its transport mid-flight",
      ).not.toHaveBeenCalled();
    } finally {
      if (bilateral === undefined) delete process.env["CELLO_SEAL_BILATERAL_TIMEOUT_MS"];
      else process.env["CELLO_SEAL_BILATERAL_TIMEOUT_MS"] = bilateral;
    }
  }, 30_000);

  it("★ and the background owner DOES release it once the ceremony finishes", async () => {
    /**
     * The other half of the ownership move, and the revert test found it missing: deleting the
     * release from the background tail left everything green, because the "not released early" test
     * asserts an absence and the blocking test is served by the enclosing finally.
     *
     * So nothing proved the handed-off path ever releases at all — a connection leak per close, on
     * the DEFAULT path, invisible until a long-running daemon runs out of them.
     */
    const { close, stop } = await harness();
    const bilateral = process.env["CELLO_SEAL_BILATERAL_TIMEOUT_MS"];
    process.env["CELLO_SEAL_BILATERAL_TIMEOUT_MS"] = "10"; // let the tail finish on its own
    try {
      const res = (await close({ session_id: SESSION }, "conn-1")) as Record<string, unknown>;
      expect(res["seal_status"], "PRECONDITION: the handed-off path").toBe("committed");
      // Give the detached tail room to finish. It has a 10 ms bilateral wait and a 10 ms unilateral.
      for (let i = 0; i < 100 && stop.mock.calls.length === 0; i++) {
        await new Promise((r) => setTimeout(r, 20));
      }
      expect(
        stop,
        "the background ceremony finished and never released the broker connection — one leaked " +
          "connection per close, on the default path",
      ).toHaveBeenCalled();
    } finally {
      if (bilateral === undefined) delete process.env["CELLO_SEAL_BILATERAL_TIMEOUT_MS"];
      else process.env["CELLO_SEAL_BILATERAL_TIMEOUT_MS"] = bilateral;
    }
  }, 30_000);

  it("★ but the BLOCKING form still releases it, because there is no background owner", async () => {
    /**
     * The counterexample, and what stops the fix from becoming a connection leak: when the caller
     * waits, the tail finishes inline and must release the connection exactly as before. Asserting
     * only the first half would pass an implementation that never releases at all.
     */
    const { close, stop } = await harness();
    const bilateral = process.env["CELLO_SEAL_BILATERAL_TIMEOUT_MS"];
    process.env["CELLO_SEAL_BILATERAL_TIMEOUT_MS"] = "10"; // resolve fast, then escalate and finish
    try {
      await close({ session_id: SESSION, wait_for_seal: true }, "conn-1");
      expect(
        stop,
        "the blocking path finished the ceremony inline and never released the broker connection — " +
          "the ownership move turned into a leak",
      ).toHaveBeenCalled();
    } finally {
      if (bilateral === undefined) delete process.env["CELLO_SEAL_BILATERAL_TIMEOUT_MS"];
      else process.env["CELLO_SEAL_BILATERAL_TIMEOUT_MS"] = bilateral;
    }
  }, 30_000);
});
