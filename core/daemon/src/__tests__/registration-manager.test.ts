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
import type { ConsortiumEndpoint } from "../directory-bootstrap.js";
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
  getConsortiumEndpoints: () => ConsortiumEndpoint[];
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
    getConsortiumEndpoints: opts.getConsortiumEndpoints ?? (() => []),
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

  // PERSIST-002 Unit 3 (AC-005/AC-012/SI-003): the identity persist is AWAITED, not fire-and-forget.
  // A persist failure must FAIL the registration with identity_persist_failed — never report success
  // with an uncommitted identity (the can't-sign-zombie failure mode).
  it("fails the registration with identity_persist_failed when a persist rejects (not fire-and-forget)", async () => {
    const rejectingPersistence: DaemonRegistrationPersistence = {
      async persistMlDsaKeypair() { throw new Error("disk full"); },
      async persistRegistrationState() { /* unreached */ },
      async persistFrostKeyShare() { /* unreached */ },
      async loadRegistrationState() { return null; },
      async loadMlDsaKeypair() { return null; },
      async loadActiveFrostKeyShare() { return null; },
    };
    const h = makeFakeCtx({ persistence: rejectingPersistence });
    const mgr = new RegistrationManager(h.ctx);
    const promise = mgr.register("", "token");
    await vi.waitFor(() => expect(h.getPendingDkg()).not.toBeNull());
    h.deliverDkg({
      type: "register_error",
      reason: "already_registered",
      agent_id: "agent-88",
      primary_pubkey: "cc".repeat(32),
      ml_dsa_pubkey: "dd".repeat(32),
    });
    // Must surface the persist failure as a registration failure — NOT return the state.
    expect(await promise).toEqual({ error: "identity_persist_failed" });
  });

  // DOD-DKG-1 — the threshold-REFUSAL gate. FROST DKG needs ALL N declared nodes present (a
  // node absent during DKG receives no share, yielding a smaller/divergent consortium). When the
  // client's resolved roster is below the directory's declared N (here 2 < 3), register MUST
  // refuse with dkg_below_threshold rather than silently DKG a partial consortium — and must NOT
  // reach runNetworkDkg. (Deterministic in-process — the live multi-node DKG is in J-TOFN-DKG.)
  it("refuses with dkg_below_threshold when the resolved roster is below the directory's N", async () => {
    const roster: ConsortiumEndpoint[] = [
      { nodeId: "n0", pubkey: "00".repeat(32), peerId: "p0", multiaddr: "/ip4/127.0.0.1/tcp/1/p2p/p0" },
      { nodeId: "n1", pubkey: "11".repeat(32), peerId: "p1", multiaddr: "/ip4/127.0.0.1/tcp/2/p2p/p1" },
    ];
    const h = makeFakeCtx({ getConsortiumEndpoints: () => roster });
    const mgr = new RegistrationManager(h.ctx);
    const promise = mgr.register("", "token");
    await vi.waitFor(() => expect(h.getPendingDkg()).not.toBeNull());
    // Directory advertises a 3-node consortium; the client only resolved 2.
    h.deliverDkg({ type: "dkg_ready", epochId: "e1", participants: 3, threshold: 3 });
    expect(await promise).toEqual({ error: "dkg_below_threshold" });
  });

  // DOD-DKG-1 B1 (code-reviewer / fallback-finder, BLOCKING) — an EMPTY roster while a consortium
  // manifest IS configured (the whole consortium momentarily unreachable) must REFUSE, NOT silently
  // downgrade to a 2-of-2 DKG against an unverified directory. The null-vs-empty distinction makes
  // the gate (0 !== N) fire here. (getNode is a real stub so we reach the roster branch.)
  it("refuses (dkg_below_threshold) when a manifest is configured but the roster resolves EMPTY", async () => {
    const h = makeFakeCtx({ getConsortiumEndpoints: () => [] });
    const mgr = new RegistrationManager(h.ctx);
    const promise = mgr.register("", "token");
    await vi.waitFor(() => expect(h.getPendingDkg()).not.toBeNull());
    h.deliverDkg({ type: "dkg_ready", epochId: "e1", participants: 3, threshold: 3 });
    expect(await promise).toEqual({ error: "dkg_below_threshold" });
  });

  // DOD-DKG-1 (cello-test-attacker note) — the gate fires in BOTH directions: a roster LARGER than
  // the directory's declared N (a divergent/forward-skewed manifest) is also refused.
  it("refuses (dkg_below_threshold) when the resolved roster EXCEEDS the directory's N", async () => {
    const roster: ConsortiumEndpoint[] = [0, 1, 2, 3].map((i) => ({
      nodeId: `n${i}`,
      pubkey: String(i).repeat(64).slice(0, 64),
      peerId: `p${i}`,
      multiaddr: `/ip4/127.0.0.1/tcp/${i + 1}/p2p/p${i}`,
    }));
    const h = makeFakeCtx({ getConsortiumEndpoints: () => roster });
    const mgr = new RegistrationManager(h.ctx);
    const promise = mgr.register("", "token");
    await vi.waitFor(() => expect(h.getPendingDkg()).not.toBeNull());
    h.deliverDkg({ type: "dkg_ready", epochId: "e1", participants: 3, threshold: 3 });
    expect(await promise).toEqual({ error: "dkg_below_threshold" });
  });

  // Single-node back-compat: NULL roster (no consortium manifest configured) takes the single-node
  // path — it does NOT refuse with dkg_below_threshold. Proven by reaching runNetworkDkg against the
  // single primary endpoint (the stub node makes the live ceremony throw → dkg_failed, which only
  // happens PAST the gate on the single-node branch — distinct from the below_threshold refusal).
  it("null roster (no manifest) → single-node path, NOT a below-threshold refusal", async () => {
    const h = makeFakeCtx({ getConsortiumEndpoints: () => null });
    const mgr = new RegistrationManager(h.ctx);
    const promise = mgr.register("", "token");
    await vi.waitFor(() => expect(h.getPendingDkg()).not.toBeNull());
    h.deliverDkg({ type: "dkg_ready", epochId: "e1", participants: 1, threshold: 2 });
    expect(await promise).toEqual({ error: "dkg_failed" });
  });
});
