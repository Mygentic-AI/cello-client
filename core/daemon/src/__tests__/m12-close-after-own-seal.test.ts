/**
 * M12 — a close that lands AFTER its own seal returns the root, not "relay unreachable".
 *
 * ─── Why this test did not exist, and why that mattered ─────────────────────────────────────────
 * `registerCloseSessionHandler` had no test anywhere in the repo, so the fix it carries failed THE
 * REVERT TEST vacuously: remove the branch and all 1121 tests still passed. This builds the harness.
 *
 * The bug: both parties closing at once is the ORDINARY case — each operator ends the conversation —
 * and whichever call arrives second can find the in-memory session node already gone. `submitSealLeaf`
 * then cannot submit, and the handler surfaced that verbatim with guidance blaming
 * relay reachability. The relay was fine and the seal was notarized and durable; the operator who asked
 * to close was told it failed and got no root, which is the entire point of closing.
 *
 * ─── The two halves that have to hold together ──────────────────────────────────────────────────
 * Returning a stored root is only safe if it is SCOPED. The first version fired on every submit
 * failure while justifying itself for one reason, so a future tree-mismatch or signing failure would
 * have been absorbed into `ok: true` with a stale root and never surfaced. Both the positive and the
 * negative are asserted here; the negative is the one that pins the scope.
 *
 * M12-P15 (review HIGH-3): these used to stub `session_node_unavailable`, which `submitSealLeaf` can
 * no longer produce — once it learned to fall back to a detached transport, the recovery branch went
 * dead and this suite kept passing against an impossible value. That is a hollow test by drift: the
 * stub outlived the contract. They now use `relay_session_gone`, a reason the real object emits on
 * this path, and the handler keys on the SET of reasons that mean "we could not submit; the seal may
 * already be durable" rather than on one string.
 */

import { describe, it, expect, vi } from "vitest";
import { registerCloseSessionHandler } from "../close-session-handler.js";
import type { Logger } from "@cello-protocol/interfaces";

const silent: Logger = { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} } as unknown as Logger;

const AGENT = "agent-a";
const SESSION = "ab".repeat(16);
const ROOT = "cd".repeat(32);

/**
 * The smallest dependency set that reaches `submitSealLeaf`. `crossNodeBrokerBySession` is empty on
 * purpose: with no recorded broker the handler skips the visiting-connection dial (and its 10s wait)
 * and goes straight to the submit, which is the code under test.
 */
function harness(opts: {
  submitReason: string;
  cert: { sealed_root: string; legibility: unknown } | null;
}) {
  const handlers = new Map<string, (p: Record<string, unknown>, c: string) => Promise<unknown>>();
  const submitSealLeaf = vi.fn(async () => ({ ok: false as const, reason: opts.submitReason }));
  const getSealCertificate = vi.fn(() => opts.cert);

  const sessionNodeManager = {
    getSessionRecord: () => ({ agent_name: AGENT, agent_id: "aid", session_id: SESSION, status: "active" }),
    submitSealLeaf,
    getSealCertificate,
    resolveAgentId: () => "aid",
    setSessionName: () => {},
    // M12-P14: this suite is about what a close returns AFTER its own seal landed, so the chain is
    // complete by construction — report ready and leave the seal path under test unchanged. The
    // incomplete case has its own tests (m12-p14-seal-readiness).
    sealReadiness: () => ({ ready: true, treeSize: 0, highWaterSeq: -1, heldCount: 0, missingLeaves: 0 }),
  };

  registerCloseSessionHandler({
    handlers,
    logger: silent,
    sessionNodeManager,
    getConnState: () => ({ currentAgent: AGENT }),
    resolveCurrentAgent: () => AGENT,
    NO_CURRENT_AGENT_RESPONSE: { ok: false, reason: "no_current_agent" },
    getKeyProvider: () => undefined,
    signalingFor: () => ({ status: "connected" }),
    sendOver: async () => ({ ok: true }),
    waitForSignalingConnected: async () => true,
    openVisitingConnection: () => ({ mgr: {}, stop: async () => {} }),
    crossNodeBrokerBySession: new Map<string, string>(),
    sealKey: (a: string, s: string) => `${a}\x1f${s}`, // production shape (seal-coordinator.ts)
    sealInterruptedInProgress: new Set<string>(),
    pendingSealWaiters: new Map(),
    pendingUnilateralWaiters: new Map(),
    resolveConsortiumRoster: async () => null,
    handleSealInterruptedFlow: async () => ({ ok: false, reason: "unused" }),
    handleActiveSealFlow: async () => ({ ok: false, reason: "unused" }),
  } as never);

  const close = handlers.get("cello_close_session")!;
  return { close, submitSealLeaf, getSealCertificate };
}

describe("a close that lands after its own seal", () => {
  it("returns the stored root instead of the submit's exit-point reason", async () => {
    const { close, getSealCertificate } = harness({
      submitReason: "relay_session_gone",
      cert: { sealed_root: ROOT, legibility: { attests: "receipt" } },
    });

    const res = (await close({ session_id: SESSION }, "conn-1")) as {
      ok: boolean; sealed_root?: string; legibility?: unknown; reason?: string;
    };

    expect(res.ok, `expected the seal to be reported, got reason=${res.reason}`).toBe(true);
    expect(res.sealed_root).toBe(ROOT);
    // The legibility travels too — the operator's receipt is the root AND what it attests.
    expect(res.legibility).toEqual({ attests: "receipt" });
    expect(getSealCertificate).toHaveBeenCalledWith(AGENT, SESSION);
  });

  it("still surfaces the failure when there is NO stored root", async () => {
    // The negative half. Without it, "return ok when a cert exists" is indistinguishable from
    // "return ok", and a genuine unsealable session would be reported as sealed with no root.
    const { close } = harness({ submitReason: "relay_session_gone", cert: null });

    const res = (await close({ session_id: SESSION }, "conn-1")) as { ok: boolean; reason?: string };

    expect(res.ok).toBe(false);
    expect(res.reason).toBe("relay_session_gone");
  });

  it("does NOT consult the local cert for an unrelated submit failure", async () => {
    // THE SCOPE ASSERTION. The branch first fired on every `!submit.ok` while justifying itself for
    // one reason — so a future tree-mismatch or signing failure would have been absorbed into
    // `ok: true` carrying a stale root, and the real fault would never have surfaced. A stored cert is
    // evidence that the session sealed; it is NOT evidence that THIS failure is benign.
    const { close, getSealCertificate } = harness({
      submitReason: "merkle_tree_mismatch",
      cert: { sealed_root: ROOT, legibility: {} },
    });

    const res = (await close({ session_id: SESSION }, "conn-1")) as { ok: boolean; reason?: string };

    expect(res.ok, "an unrelated failure must not be masked by a stored root").toBe(false);
    expect(res.reason).toBe("merkle_tree_mismatch");
    expect(getSealCertificate, "the cert must not even be consulted").not.toHaveBeenCalled();
  });
});
