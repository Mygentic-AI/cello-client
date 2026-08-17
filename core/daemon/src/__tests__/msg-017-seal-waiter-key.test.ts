/**
 * DOD-M12B-SEAL-WAITER-KEY-1 — two agents on one daemon clobbered each other's seal waiter.
 *
 * `sealInterruptedInProgress` is keyed `agent \x1f session`. `pendingUnilateralWaiters` was keyed by
 * **session id alone**, and it has three registrants: the close handler's escalation, the away-path
 * one-shot, and the coordinator that resolves them.
 *
 * Two agents on one daemon is a supported topology and the one the operator actually runs. When both
 * escalate the same session id — the loopback case, or an away-path one-shot overlapping a manual
 * close — whichever registered second **overwrote** the first's resolver. The loser then waited out
 * the full 30 seconds and reported `seal_unilateral_timeout`: the operator is told the directory
 * could not verify their root, for a session that is **notarized and whose certificate is already on
 * disk**. That is this milestone's founding error-fidelity defect — a label naming our own wait for
 * the one thing that was working.
 *
 * Revert test: key the map by `sessionId` again and the first case fails — resolving one agent's
 * waiter answers the other agent's close, or nobody's.
 */
import { describe, it, expect, vi } from "vitest";
import { registerCloseSessionHandler } from "../close-session-handler.js";
import type { Logger } from "../types.js";

const SESSION = "8c".repeat(32);
const ROOT = "ab".repeat(32);
const SEALED = "ef".repeat(32);
const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };

const CARRY = [1, 2, 3].map((n) => ({
  sequenceNumber: n,
  leafKind: n === 3 ? 0x02 : 0x00,
  senderPubkeyHex: "11".repeat(32),
  structure2Cbor: new Uint8Array([n]),
  structure1Cbor: new Uint8Array([n, n]),
  relayId: "relay-1",
  relayTimestamp: 1_700_000_000_000 + n,
  relaySignatureHex: "cc".repeat(64),
}));

/** The production key. Mirrors `sealKey` in seal-coordinator.ts. */
const key = (agent: string, session: string): string => `${agent}\x1f${session}`;

/** One shared waiter map, two agents — the daemon's real shape. */
function twoAgentHarness() {
  const pendingUnilateralWaiters = new Map<string, (r: unknown) => void>();
  const closes = new Map<string, (p: Record<string, unknown>, c: string) => Promise<unknown>>();

  for (const agent of ["alice", "bob"]) {
    const handlers = new Map<string, (p: Record<string, unknown>, c: string) => Promise<unknown>>();
    registerCloseSessionHandler({
      handlers,
      logger: silent,
      sessionNodeManager: {
        getSessionRecord: () => ({ agent_name: agent, agent_id: `id-${agent}`, session_id: SESSION, status: "interrupted" }),
        submitSealLeaf: async () => ({ ok: true as const, sequenceNumber: 4, reportedRootHex: ROOT }),
        getSealCarry: () => CARRY,
        getSealCertificate: () => null,
        resolveAgentId: () => `id-${agent}`,
        setSessionName: () => {},
        sealReadiness: () => ({ ready: true, treeSize: 1, highWaterSeq: 0, heldCount: 0, missingLeaves: 0 }),
      },
      getConnState: () => ({ currentAgent: agent }),
      resolveCurrentAgent: () => agent,
      NO_CURRENT_AGENT_RESPONSE: { ok: false, reason: "no_current_agent" },
      getKeyProvider: () => ({ getPublicKey: async () => new Uint8Array(32).fill(0x11) }),
      signalingFor: () => ({ status: "connected" }),
      sendOver: vi.fn(async () => ({ ok: true })),
      waitForSignalingConnected: async () => true,
      openVisitingConnection: () => ({ mgr: {}, stop: async () => {} }),
      crossNodeBrokerBySession: new Map<string, string>(),
      sealKey: (a: string, s: string) => `${a}\x1f${s}`,
      sealInterruptedInProgress: new Set<string>(),
      pendingSealWaiters: new Map(),
      pendingUnilateralWaiters,
      resolveConsortiumRoster: async () => [],
      unilateralTimeoutMs: 400,
      handleSealInterruptedFlow: async () => ({ ok: true, sessionId: SESSION, status: "seal_interrupted_pending" }),
      handleActiveSealFlow: async () => ({ ok: false, reason: "unused" }),
    } as never);
    closes.set(agent, handlers.get("cello_close_session")!);
  }
  return { closes, pendingUnilateralWaiters };
}

describe("DOD-M12B-SEAL-WAITER-KEY-1: two agents on one daemon do not clobber each other", () => {
  it("both waiters coexist, and resolving ONE answers only that agent's close", async () => {
    const h = twoAgentHarness();

    const aliceP = h.closes.get("alice")!({ session_id: SESSION }, "conn-a");
    const bobP = h.closes.get("bob")!({ session_id: SESSION }, "conn-b");
    // Let both register before either is answered.
    await new Promise((r) => setTimeout(r, 60));

    expect(
      h.pendingUnilateralWaiters.size,
      "keyed by session id alone, the second registration overwrote the first and this is 1",
    ).toBe(2);

    // The directory answers ALICE. Bob's ceremony is a different one and is still outstanding.
    h.pendingUnilateralWaiters.get(key("alice", SESSION))!({ ok: true, sealedRootHex: SEALED });

    const alice = (await aliceP) as { ok: boolean; sealed_root?: string };
    expect(alice.sealed_root, "the agent whose seal completed must get the receipt").toBe(SEALED);

    const bob = (await bobP) as { ok: boolean; seal_pending_reason?: string };
    expect(bob.ok, "and the other agent's close is untouched — it simply has not been answered").toBe(true);
    expect(bob.seal_pending_reason).toBe("seal_unilateral_timeout");
  }, 30_000);

  it("each agent's waiter is removed on its OWN completion, never the other's", async () => {
    const h = twoAgentHarness();
    const aliceP = h.closes.get("alice")!({ session_id: SESSION }, "conn-a");
    const bobP = h.closes.get("bob")!({ session_id: SESSION }, "conn-b");
    await new Promise((r) => setTimeout(r, 60));

    h.pendingUnilateralWaiters.get(key("alice", SESSION))!({ ok: true, sealedRootHex: SEALED });
    await aliceP;

    expect(
      h.pendingUnilateralWaiters.has(key("bob", SESSION)),
      "alice's cleanup must not delete bob's outstanding ceremony",
    ).toBe(true);
    await bobP;
  }, 30_000);
});
