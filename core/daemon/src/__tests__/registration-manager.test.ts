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
import { generateKeypair, verifyKeyBinding } from "@cello-protocol/crypto";
import type { Logger } from "../types.js";
import type { CelloNode } from "@cello-protocol/transport";

const noopLogger: Logger = { debug() {}, info() {}, warn() {}, error() {} };
// 038-KEYBIND: registration now SIGNS the key binding with K_local, so the stub must sign.
const stubKeyProvider = generateKeypair();
const stubKeyProviderPubkeyHex = stubKeyProvider.toJSON()["publicKey"]!;
const stubNode = {} as unknown as CelloNode;

/**
 * 038-KEYBIND review F4: `sharePrimaryHex` is the group key this machine's own FROST share belongs
 * to. The `already_registered` paths run no ceremony, so it is the ONLY thing they can check a
 * directory-supplied `primary_pubkey` against before K_local signs a statement about it. `null`
 * models a machine holding no share, which is now a refusal rather than a licence to sign.
 */
function makeRecordingPersistence(sharePrimaryHex: string | null = "cc".repeat(32)) {
  const calls = { mlDsa: [] as unknown[], reg: [] as unknown[], frost: [] as unknown[] };
  const persistence: DaemonRegistrationPersistence = {
    async persistMlDsaKeypair(o) { calls.mlDsa.push(o); },
    async persistRegistrationState(o) { calls.reg.push(o); },
    async persistFrostKeyShare(o) { calls.frost.push(o); },
    async loadRegistrationState() { return null; },
    async loadMlDsaKeypair() { return null; },
    async loadActiveFrostKeyShare() {
      return sharePrimaryHex === null
        ? null
        : ({ primaryPubkey: sharePrimaryHex } as unknown as Awaited<
            ReturnType<DaemonRegistrationPersistence["loadActiveFrostKeyShare"]>
          >);
    },
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
  /**
   * 038-KEYBIND: the stub's REAL pubkey, not an invented "ab"…. `register()` reads this rather than
   * calling `getPublicKey()`, so an invented value would have K_local sign a binding naming a key
   * it does not own — the binding would fail its own verifier and no test could assert on it.
   */
  let pubkeyHex: string | null = stubKeyProviderPubkeyHex;

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

  it("names the LOCAL cause when getNode() is null at the DKG stage — not the network", async () => {
    /**
     * DOD-M15-SURFACE-1 review F6. This asserted `directory_unreachable`, and in doing so pinned a
     * network verdict for a purely local fact: the daemon's OWN transport node is briefly null while
     * a signaling stream dies and is rebuilt. The directory may be perfectly reachable, and the
     * production comment at the call site already said as much.
     *
     * The old name sent an operator — or whoever is debugging for them — at the network, at the
     * consortium, at their connection. It is the same one-string-for-the-wrong-subsystem shape M15
     * is closing elsewhere, and a test asserting it made it required behaviour.
     */
    const h = makeFakeCtx({ getNode: () => null });
    const mgr = new RegistrationManager(h.ctx);
    const promise = mgr.register("", "token");
    await vi.waitFor(() => expect(h.getPendingDkg()).not.toBeNull());
    h.deliverDkg({ type: "dkg_ready", epochId: "e1", participants: 1, threshold: 2 });

    const result = await promise as { error: string; detail?: string };
    expect(result.error).toBe("transport_node_unavailable");
    expect(result.error, "must not blame the directory for a local lifecycle state").not.toBe("directory_unreachable");
    // Invariant 4: the answer carries what to do about it, and says the directory is not implicated.
    expect(result.detail).toMatch(/local/i);
    expect(result.detail).toMatch(/retry/i);
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
      // 038-KEYBIND: a share that agrees with the directory's answer, so this test still reaches
      // the persist it is about rather than stopping at the binding corroboration.
      async loadActiveFrostKeyShare() {
        return { primaryPubkey: "cc".repeat(32) } as unknown as Awaited<
          ReturnType<DaemonRegistrationPersistence["loadActiveFrostKeyShare"]>
        >;
      },
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
    // The wire code stays the closed protocol union; `detail` carries the underlying cause so the
    // operator-facing guidance can name it instead of asserting "verify the preAuthToken" — which is
    // wrong for a colliding NODE_ID, a commitment mismatch, or an unreachable node.
    const outcome = (await promise) as { error: string; detail?: string };
    expect(outcome.error).toBe("dkg_failed");
    expect(outcome.detail, "the cause must travel with the code, not be discarded").toBeTruthy();
  });
});

/**
 * 038-KEYBIND — THE MINT HALF, which had no test at all until review found it (F4 / test teeth).
 *
 * Everything downstream verifies a binding; nothing verified the one this daemon PRODUCES. A
 * `#mintKeyBinding` that signed over the group key alone, or under the wrong context, or returned
 * 64 zero bytes, left every test in BOTH repos green — the directory fixtures re-implement the
 * framing locally, so they cannot catch a producer that drifts from it either.
 *
 * The `already_registered` path is the one this harness can drive end to end, and it is also the
 * path that matters most: no ceremony runs, so the group key arrives in a directory's reply with
 * nothing in the frame to check it against.
 */
describe("038-KEYBIND: the binding this daemon MINTS", () => {
  const GROUP = "cc".repeat(32);

  async function registerAgainstAlreadyRegistered(
    persistence: DaemonRegistrationPersistence,
    answeredPrimary = GROUP,
  ): Promise<unknown> {
    const h = makeFakeCtx({ persistence });
    const mgr = new RegistrationManager(h.ctx);
    const promise = mgr.register("", "token");
    await vi.waitFor(() => expect(h.getPendingDkg()).not.toBeNull());
    h.deliverDkg({
      type: "register_error",
      reason: "already_registered",
      agent_id: "agent-mint",
      primary_pubkey: answeredPrimary,
      ml_dsa_pubkey: "dd".repeat(32),
    });
    return promise;
  }

  it("★ signs a binding the PRODUCTION verifier accepts, over (K_local, the group key)", async () => {
    const { persistence, calls } = makeRecordingPersistence(GROUP);
    await registerAgainstAlreadyRegistered(persistence);

    const persisted = calls.reg[0] as { keyBinding: string; primaryPubkey: string };
    // The VALUE, run through `verifyKeyBinding` — not "a 128-char string was stored". A binding over
    // the group key alone, or under a reused context, or over the wrong identity, fails here.
    expect(
      verifyKeyBinding(
        new Uint8Array(Buffer.from(persisted.keyBinding, "hex")),
        new Uint8Array(Buffer.from(stubKeyProviderPubkeyHex, "hex")),
        new Uint8Array(Buffer.from(GROUP, "hex")),
      ),
      "the binding this daemon mints must verify under its own K_local, over its own group key",
    ).toBe(true);
    expect(persisted.primaryPubkey).toBe(GROUP);
  });

  it("REFUSES when the directory names a group key this machine's share does not belong to", async () => {
    // The share says one key; the directory answers another. Signing over the answer would have
    // K_local vouch for a key this agent cannot sign with — chosen by the party the binding exists
    // to take out of the trust path.
    const { persistence, calls } = makeRecordingPersistence("11".repeat(32));
    const result = await registerAgainstAlreadyRegistered(persistence, GROUP);

    expect(result).toMatchObject({ error: "registration_primary_pubkey_mismatch" });
    expect(calls.reg, "nothing may be persisted when the key could not be corroborated").toHaveLength(0);
  });

  it("REFUSES when this machine holds NO share — absence is not a licence to sign", async () => {
    const { persistence, calls } = makeRecordingPersistence(null);
    const result = await registerAgainstAlreadyRegistered(persistence, GROUP);

    // A DIFFERENT reason from the mismatch: one says the directory disagrees with this machine, the
    // other says this machine has nothing to disagree with, and the remedies are not the same.
    expect(result).toMatchObject({ error: "registration_share_missing" });
    expect((result as { detail?: string }).detail, "a refusal carries its next step").toBeTruthy();
    expect(calls.reg).toHaveLength(0);
  });
});
