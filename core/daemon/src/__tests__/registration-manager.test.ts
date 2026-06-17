/**
 * CELLO-M7-REGISTRATION — ported RegistrationManager seam paths (step c part 2)
 *
 * Exercises the daemon adaptations of register() WITHOUT a live DKG (the full
 * 3-round ceremony is covered by the morning live two-agent test):
 *   1. already-registered short-circuit
 *   2. signaling not connected → directory_unreachable
 *   3. register_request send failure → surfaces the send reason
 *   4. getNode() null at the DKG stage → directory_unreachable (the new null-check)
 *   5. already_registered reply at the dkg_ready stage → persists + returns state
 *
 * Uses a fake RegistrationContext that captures the pending resolvers so the test
 * can deliver inbound frames deterministically.
 */

import { describe, it, expect, vi } from "vitest";
import { RegistrationManager, type RegistrationContext, type SignalingSendResult } from "../registration-manager.js";
import type { DaemonRegistrationPersistence } from "../registration-persistence.js";
import type { Logger } from "../types.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { KeyProvider } from "@cello-protocol/crypto";

const noopLogger: Logger = { debug() {}, info() {}, warn() {}, error() {} };
const stubKeyProvider = { async getPublicKey() { return new Uint8Array(32); } } as unknown as KeyProvider;
const stubNode = {} as unknown as CelloNode;

function makeRecordingPersistence() {
  const calls = { mlDsa: [] as unknown[], reg: [] as unknown[], frost: [] as unknown[] };
  const persistence: DaemonRegistrationPersistence = {
    async persistMlDsaKeypair(o) { calls.mlDsa.push(o); },
    async persistRegistrationState(o) { calls.reg.push(o); },
    async persistFrostKeyShare(o) { calls.frost.push(o); },
    async loadRegistrationState() { return null; },
    async loadMlDsaKeypair() { return null; },
    async loadActiveFrostKeyShare() { return null; },
  };
  return { persistence, calls };
}

function makeFakeCtx(opts: Partial<{
  persistence: DaemonRegistrationPersistence | null;
  getNode: () => CelloNode | null;
  getDirectoryEndpoint: () => { peer_id: string; multiaddrs: string[] } | null;
  isSignalingConnected: () => boolean;
  sendSignalingFrame: (frame: Record<string, unknown>) => Promise<SignalingSendResult>;
}> = {}) {
  let pendingDkg: ((f: Record<string, unknown>) => void) | null = null;
  let pendingReg: ((f: Record<string, unknown>) => void) | null = null;
  let pubkeyHex: string | null = "ab".repeat(32);

  const ctx: RegistrationContext = {
    keyProvider: stubKeyProvider,
    logger: noopLogger,
    persistence: opts.persistence ?? null,
    mlDsaKeyFile: undefined,
    getNode: opts.getNode ?? (() => stubNode),
    getMyPubkeyHex: () => pubkeyHex,
    setMyPubkeyHex: (h) => { pubkeyHex = h; },
    getDirectoryEndpoint: opts.getDirectoryEndpoint ?? (() => ({ peer_id: "dir", multiaddrs: ["/ip4/1.2.3.4/tcp/1/p2p/dir"] })),
    getThresholdSigner: () => undefined,
    setThresholdSigner: () => {},
    getMyPrimaryPubkey: () => null,
    setMyPrimaryPubkey: () => {},
    isSignalingConnected: opts.isSignalingConnected ?? (() => true),
    sendSignalingFrame: opts.sendSignalingFrame ?? (async () => ({ ok: true })),
    setPendingDkgReadyResolve: (r) => { pendingDkg = r; },
    setPendingRegisterResolve: (r) => { pendingReg = r; },
  };

  return {
    ctx,
    deliverDkg: (f: Record<string, unknown>) => pendingDkg?.(f),
    deliverReg: (f: Record<string, unknown>) => pendingReg?.(f),
    getPendingDkg: () => pendingDkg,
  };
}

describe("RegistrationManager (daemon port) — seam paths", () => {
  it("short-circuits when already registered", async () => {
    const { ctx } = makeFakeCtx();
    const mgr = new RegistrationManager(ctx);
    mgr.setRegistrationState({
      agent_id: "x", primary_pubkey: "p", ml_dsa_pubkey: "m", registered_at: 1, status: "active",
    });
    expect(await mgr.register("", "token")).toEqual({ error: "already_registered" });
  });

  it("returns directory_unreachable when signaling is not connected", async () => {
    const { ctx } = makeFakeCtx({ isSignalingConnected: () => false });
    const mgr = new RegistrationManager(ctx);
    expect(await mgr.register("", "token")).toEqual({ error: "directory_unreachable" });
  });

  it("surfaces the send failure reason when register_request cannot be sent", async () => {
    const { ctx } = makeFakeCtx({
      sendSignalingFrame: async () => ({ ok: false, reason: "signaling_lost" }),
    });
    const mgr = new RegistrationManager(ctx);
    expect(await mgr.register("", "token")).toEqual({ error: "signaling_lost" });
  });

  it("returns directory_unreachable when getNode() is null at the DKG stage", async () => {
    const h = makeFakeCtx({ getNode: () => null });
    const mgr = new RegistrationManager(h.ctx);
    const promise = mgr.register("", "token");
    await vi.waitFor(() => expect(h.getPendingDkg()).not.toBeNull());
    h.deliverDkg({ type: "dkg_ready", epochId: "e1", participants: 1, threshold: 2 });
    expect(await promise).toEqual({ error: "directory_unreachable" });
  });

  it("persists and returns state on an already_registered reply at the dkg_ready stage", async () => {
    const { persistence, calls } = makeRecordingPersistence();
    const h = makeFakeCtx({ persistence });
    const mgr = new RegistrationManager(h.ctx);
    const promise = mgr.register("", "token");
    await vi.waitFor(() => expect(h.getPendingDkg()).not.toBeNull());
    h.deliverDkg({
      type: "register_error",
      reason: "already_registered",
      agent_id: "agent-77",
      primary_pubkey: "cc".repeat(32),
      ml_dsa_pubkey: "dd".repeat(32),
    });
    const result = await promise;
    expect(result).toMatchObject({ agent_id: "agent-77", status: "active" });
    // persistence path (mlDsaKeyFile=undefined) → both writes happened
    expect(calls.mlDsa).toHaveLength(1);
    expect(calls.reg).toHaveLength(1);
    expect(calls.reg[0]).toMatchObject({ agentId: "agent-77" });
  });
});
