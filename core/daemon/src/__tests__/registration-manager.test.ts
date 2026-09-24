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

/**
 * M16 004-IDENTITY-WIRE: the `register_success` echo check sits AFTER the FROST DKG, and a real
 * ceremony cannot complete against this harness's stub node. So `runNetworkDkg` delegates to the
 * REAL implementation by default — every pre-existing test here still reaches the real ceremony and
 * fails in it — and only the channel tests below hand it one ceremony result, so they can reach
 * the frame the unit exists to check. Nothing about the ceremony is asserted through this seam.
 */
const dkgSeam = vi.hoisted(() => ({ nextResult: null as unknown }));
vi.mock("../network-directory-node.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../network-directory-node.js")>();
  return {
    ...actual,
    runNetworkDkg: async (...args: Parameters<typeof actual.runNetworkDkg>) => {
      if (dkgSeam.nextResult !== null) {
        const r = dkgSeam.nextResult;
        dkgSeam.nextResult = null;
        return r as Awaited<ReturnType<typeof actual.runNetworkDkg>>;
      }
      return actual.runNetworkDkg(...args);
    },
  };
});

import { RegistrationManager, type RegistrationContext, type SignalingSendResult } from "../registration-manager.js";
import type { ConsortiumEndpoint } from "../directory-bootstrap.js";
import type { DaemonRegistrationPersistence, PqIdentityRecord, StoredPqIdentity } from "../registration-persistence.js";
import { generateKeypair, verifyKeyBinding, mlDsaGenerateSeed } from "@cello-protocol/crypto";
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
function makeRecordingPersistence(
  sharePrimaryHex: string | null = "cc".repeat(32),
  opts: { stored?: StoredPqIdentity; failPq?: "ml_dsa" | "ml_kem" } = {},
) {
  const calls = { pq: [] as PqIdentityRecord[], reg: [] as unknown[], frost: [] as unknown[] };
  // M9D 002-PQKEYS: the row's post-quantum identity, as stored — persisted seeds are what a later
  // registration attempt on the same row reads back.
  let stored: StoredPqIdentity = opts.stored ?? { mlDsaSeed: null, mlDsaPubkey: null, mlKemSeed: null, mlKemPubkey: null };
  const persistence: DaemonRegistrationPersistence = {
    async persistPqIdentity(r) {
      if (opts.failPq) throw new Error(`${opts.failPq}_persist_failed: disk full`);
      calls.pq.push(r);
      stored = { mlDsaSeed: r.mlDsaSeed, mlDsaPubkey: r.mlDsaPubkey, mlKemSeed: r.mlKemSeed, mlKemPubkey: r.mlKemPubkey };
    },
    async persistRegistrationState(o) { calls.reg.push(o); },
    async persistFrostKeyShare(o) { calls.frost.push(o); },
    async loadRegistrationState() { return null; },
    async loadPqIdentity() { return stored; },
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
  logger: Logger;
  persistence: DaemonRegistrationPersistence;
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
  // Every frame sent, in order — the register_request's PQ keys are what an honest directory echoes.
  const frames: Array<Record<string, unknown>> = [];

  const ctx: RegistrationContext = {
    keyProvider: stubKeyProvider,
    logger: opts.logger ?? noopLogger,
    persistence: opts.persistence ?? makeRecordingPersistence().persistence,
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
    sendSignalingFrame: async (f) => {
      frames.push(f);
      return opts.sendSignalingFrame ? opts.sendSignalingFrame(f) : { ok: true };
    },
    setPendingDkgReadyResolve: (r) => { pendingDkg = r; },
    setPendingRegisterResolve: (r) => { pendingReg = r; },
  };

  return {
    ctx,
    frames,
    /** The PQ keys this registration sent — what an honest directory's `already_registered` echoes. */
    echoKeys: () => {
      const req = frames.find((f) => f["type"] === "register_request");
      if (!req) throw new Error("echoKeys: no register_request was sent");
      return { ml_dsa_pubkey: req["ml_dsa_pubkey"], ml_kem_pubkey: req["ml_kem_pubkey"] };
    },
    deliverDkg: (f: Record<string, unknown>) => pendingDkg?.(f),
    deliverReg: (f: Record<string, unknown>) => pendingReg?.(f),
    getPendingDkg: () => pendingDkg,
    getPendingReg: () => pendingReg,
  };
}

describe("RegistrationManager (daemon port) — seam paths", () => {
  it("short-circuits when already registered", async () => {
    const { ctx } = makeFakeCtx();
    const mgr = new RegistrationManager(ctx);
    mgr.setRegistrationState({
      agent_id: "x", primary_pubkey: "p", ml_dsa_pubkey: "m", ml_kem_pubkey: "k", registered_at: 1, status: "active",
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
      ...h.echoKeys(),
    });
    const result = await promise;
    expect(result).toMatchObject({ agent_id: "agent-77", status: "active" });
    // The PQ identity was persisted (32-byte ML-DSA seed, 64-byte ML-KEM seed), then the state.
    expect(calls.pq).toHaveLength(1);
    expect(calls.pq[0]!.mlDsaSeed.length).toBe(32);
    expect(calls.pq[0]!.mlKemSeed.length).toBe(64);
    expect(calls.reg).toHaveLength(1);
    expect(calls.reg[0]).toMatchObject({ agentId: "agent-77" });
  });

  // PERSIST-002 Unit 3 (AC-005/AC-012/SI-003): the identity persist is AWAITED, not fire-and-forget.
  // A persist failure must FAIL the registration with identity_persist_failed — never report success
  // with an uncommitted identity (the can't-sign-zombie failure mode).
  it("fails the registration with identity_persist_failed when a persist rejects (not fire-and-forget)", async () => {
    const rejectingPersistence: DaemonRegistrationPersistence = {
      ...makeRecordingPersistence().persistence,
      async persistRegistrationState() { throw new Error("disk full"); },
      async persistFrostKeyShare() { /* unreached */ },
      async loadRegistrationState() { return null; },
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
      ...h.echoKeys(),
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
      ...h.echoKeys(),
    });
    return promise;
  }

  it("★ signs a v2 binding the PRODUCTION verifier accepts — both halves, over all four keys", async () => {
    const { persistence, calls } = makeRecordingPersistence(GROUP);
    await registerAgainstAlreadyRegistered(persistence);

    const persisted = calls.reg[0] as { keyBinding: string; keyBindingPq: string; primaryPubkey: string };
    const hex = (h: string) => new Uint8Array(Buffer.from(h, "hex"));
    // The VALUE, run through `verifyKeyBinding` — not "a 128-char string was stored". A binding over
    // fewer keys, under a reused context, over the wrong identity, or with either half missing or
    // signed by the wrong key, fails here.
    expect(
      await verifyKeyBinding({
        keys: {
          kLocal: hex(stubKeyProviderPubkeyHex),
          group: hex(GROUP),
          mlDsa: hex(calls.pq[0]!.mlDsaPubkey),
          mlKem: hex(calls.pq[0]!.mlKemPubkey),
        },
        signature: hex(persisted.keyBinding),
        signaturePq: hex(persisted.keyBindingPq),
      }),
      "the binding this daemon mints must verify under its own K_local AND its own ML-DSA key",
    ).toEqual({ ok: true });
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

/**
 * M16 004-IDENTITY-WIRE — a broadcast channel is a registered identity marked `channel` + the admin's
 * pubkey. Until the directory stores those (order 005), a directory ignores them, and a channel that
 * silently registered as a plain agent would be a corrupt identity nobody notices. So the client
 * REQUIRES the directory to echo `channel: true`, and fails the registration without it.
 */
describe("M16 004-IDENTITY-WIRE: channel registration (client side)", () => {
  const GROUP = "cc".repeat(32);
  const ADMIN = generateKeypair().toJSON()["publicKey"]!;
  // M16 024-CREATE: a channel presents no token — the admin's Ed25519 signature over the channel's
  // pubkey rides the round-1 DKG frame instead. The manager forwards it verbatim (the DIRECTORY
  // verifies it), so any well-formed hex stands in here.
  const ADMIN_SIG = "ab".repeat(64);

  function makeCapturingCtx(persistence: DaemonRegistrationPersistence = makeRecordingPersistence(GROUP).persistence) {
    const errors: Array<{ event: string; ctx: Record<string, unknown> }> = [];
    const logger: Logger = {
      debug() {}, info() {}, warn() {},
      error(event, ctx) { errors.push({ event, ctx: (ctx ?? {}) as Record<string, unknown> }); },
    };
    const h = makeFakeCtx({
      logger,
      persistence,
      getConsortiumEndpoints: () => null,
    });
    return { ...h, errors };
  }

  /** Drive register() through a completed ceremony to the register_success frame. */
  async function driveToRegisterSuccess(
    h: ReturnType<typeof makeCapturingCtx>,
    promise: Promise<unknown>,
    success: Record<string, unknown> | (() => Record<string, unknown>),
  ): Promise<unknown> {
    await vi.waitFor(() => expect(h.getPendingDkg()).not.toBeNull());
    dkgSeam.nextResult = {
      signer: {},
      primaryPubkey: new Uint8Array(Buffer.from(GROUP, "hex")),
      signingShare: new Uint8Array([1, 2, 3]),
      identifier: "client:test",
      commitments: [],
      verifyingShares: {},
      threshold: 2,
      participants: 1,
    };
    h.deliverDkg({ type: "dkg_ready", epochId: "e1", participants: 1, threshold: 2 });
    await vi.waitFor(() => expect(h.getPendingReg()).not.toBeNull());
    h.deliverReg({ type: "register_success", agent_id: "agent-ch", primary_pubkey: GROUP, ...(typeof success === "function" ? success() : success) });
    return promise;
  }

  it("channel registration sends channel and admin_pubkey in register_request", async () => {
    const h = makeCapturingCtx();
    const mgr = new RegistrationManager(h.ctx);
    void mgr.register("", "token", { channel: true, adminPubkeyHex: ADMIN, adminSignature: ADMIN_SIG });
    await vi.waitFor(() => expect(h.frames.length).toBeGreaterThan(0));
    const frame = h.frames[0]!;
    expect(frame["type"]).toBe("register_request");
    expect(frame["channel"]).toBe(true);
    expect(frame["admin_pubkey"]).toBe(ADMIN);
  });

  it("ordinary registration frame carries neither key", async () => {
    const h = makeCapturingCtx();
    const mgr = new RegistrationManager(h.ctx);
    void mgr.register("", "token");
    await vi.waitFor(() => expect(h.frames.length).toBeGreaterThan(0));
    const frame = h.frames[0]!;
    expect(frame["type"]).toBe("register_request");
    expect("channel" in frame).toBe(false);
    expect("admin_pubkey" in frame).toBe(false);
  });

  it("self-administered channel is refused before sending", async () => {
    const h = makeCapturingCtx();
    const mgr = new RegistrationManager(h.ctx);
    const result = await mgr.register("", "token", { channel: true, adminPubkeyHex: stubKeyProviderPubkeyHex, adminSignature: ADMIN_SIG });
    expect(result).toMatchObject({ error: "invalid_channel_registration" });
    expect(h.frames).toHaveLength(0);
  });

  it("malformed admin pubkey is refused before sending", async () => {
    for (const bad of [ADMIN.slice(0, 63), "A" + ADMIN.slice(1)]) {
      const h = makeCapturingCtx();
      const mgr = new RegistrationManager(h.ctx);
      const result = await mgr.register("", "token", { channel: true, adminPubkeyHex: bad, adminSignature: ADMIN_SIG });
      expect(result, bad).toMatchObject({ error: "invalid_channel_registration" });
      expect(h.frames, bad).toHaveLength(0);
    }
  });

  it("register_success WITH the echo persists channel fields", async () => {
    const { persistence, calls } = makeRecordingPersistence(GROUP);
    const h = makeCapturingCtx(persistence);
    const mgr = new RegistrationManager(h.ctx);
    const promise = mgr.register("", "token", { channel: true, adminPubkeyHex: ADMIN, adminSignature: ADMIN_SIG });
    const result = await driveToRegisterSuccess(h, promise, { channel: true });
    expect(result).toMatchObject({ agent_id: "agent-ch", status: "active" });
    expect(calls.reg).toHaveLength(1);
    expect(calls.reg[0]).toMatchObject({ agentId: "agent-ch", channel: true, adminPubkey: ADMIN });
  });

  it("register_success carries the directory's two relays back to the caller (M16 024-CREATE)", async () => {
    // Nobody typed a relay: the directory picks two from its pool and echoes them here. register()
    // returns exactly those so cello_channel_create can record them.
    const RELAY_A = "/dns4/relay-a.example/tcp/443/tls/ws";
    const RELAY_B = "/dns4/relay-b.example/tcp/443/tls/ws";
    const { persistence } = makeRecordingPersistence(GROUP);
    const h = makeCapturingCtx(persistence);
    const mgr = new RegistrationManager(h.ctx);
    const promise = mgr.register("", "token", { channel: true, adminPubkeyHex: ADMIN, adminSignature: ADMIN_SIG });
    const result = await driveToRegisterSuccess(h, promise, { channel: true, relays: [RELAY_A, RELAY_B] });
    expect(result).toMatchObject({ agent_id: "agent-ch", relays: [RELAY_A, RELAY_B] });
  });

  it("register_success WITHOUT the echo fails the registration", async () => {
    const { persistence, calls } = makeRecordingPersistence(GROUP);
    const h = makeCapturingCtx(persistence);
    const mgr = new RegistrationManager(h.ctx);
    const promise = mgr.register("", "token", { channel: true, adminPubkeyHex: ADMIN, adminSignature: ADMIN_SIG });
    const result = await driveToRegisterSuccess(h, promise, {});
    expect(result).toMatchObject({ error: "directory_missing_channel_support" });
    expect(calls.reg, "a channel the directory did not record must not be persisted as registered").toHaveLength(0);
    expect(mgr.getRegistrationState(), "nor cached as registered in memory").toBeNull();
    const logged = h.errors.find((e) => e.event === "registration.channel.echo_missing");
    expect(logged, "the operator must see why the registration failed").toBeDefined();
    expect(logged!.ctx["k_local_pubkey"]).toBe(stubKeyProviderPubkeyHex);
    expect(typeof logged!.ctx["correlationId"]).toBe("string");
  });

  it("an already_registered reply WITHOUT the echo also fails a channel registration", async () => {
    // The other way a registration "succeeds": no ceremony, the directory hands back an existing
    // profile. Persisting channel = true over a profile the directory holds as a plain agent is the
    // same silent downgrade reached by a different frame.
    const { persistence, calls } = makeRecordingPersistence(GROUP);
    const h = makeCapturingCtx(persistence);
    const mgr = new RegistrationManager(h.ctx);
    const promise = mgr.register("", "token", { channel: true, adminPubkeyHex: ADMIN, adminSignature: ADMIN_SIG });
    await vi.waitFor(() => expect(h.getPendingDkg()).not.toBeNull());
    h.deliverDkg({
      type: "register_error", reason: "already_registered",
      agent_id: "agent-old", primary_pubkey: GROUP, ...h.echoKeys(),
    });
    expect(await promise).toMatchObject({ error: "directory_missing_channel_support" });
    expect(calls.reg).toHaveLength(0);
  });

  it("an already_registered reply at the FINAL stage without the echo also fails", async () => {
    // Review: the second already_registered branch (after the ceremony) had no test of its own.
    const { persistence, calls } = makeRecordingPersistence(GROUP);
    const h = makeCapturingCtx(persistence);
    const mgr = new RegistrationManager(h.ctx);
    const promise = mgr.register("", "token", { channel: true, adminPubkeyHex: ADMIN, adminSignature: ADMIN_SIG });
    // Lazy: the echo can only name the keys once register_request has actually been sent.
    const result = await driveToRegisterSuccess(h, promise, () => ({
      type: "register_error", reason: "already_registered", ...h.echoKeys(),
    }));
    expect(result).toMatchObject({ error: "directory_missing_channel_support" });
    expect(calls.reg).toHaveLength(0);
  });

  it("a truthy-but-not-true echo is not an echo", async () => {
    const { persistence, calls } = makeRecordingPersistence(GROUP);
    const h = makeCapturingCtx(persistence);
    const mgr = new RegistrationManager(h.ctx);
    const promise = mgr.register("", "token", { channel: true, adminPubkeyHex: ADMIN, adminSignature: ADMIN_SIG });
    const result = await driveToRegisterSuccess(h, promise, { channel: "true" });
    expect(result).toMatchObject({ error: "directory_missing_channel_support" });
    expect(calls.reg).toHaveLength(0);
  });

  it("a failed echo after the ceremony says the identity is now an ordinary agent, not 'retry'", async () => {
    // Review F2: by the time register_success arrives, the directory has stored the profile. A
    // retry gets already_registered with no echo, forever, so "retry" is advice that cannot work.
    const h = makeCapturingCtx(makeRecordingPersistence(GROUP).persistence);
    const mgr = new RegistrationManager(h.ctx);
    const promise = mgr.register("", "token", { channel: true, adminPubkeyHex: ADMIN, adminSignature: ADMIN_SIG });
    const result = (await driveToRegisterSuccess(h, promise, {})) as { error: string; detail?: string };
    expect(result.error).toBe("directory_missing_channel_support");
    expect(result.detail).toMatch(/ordinary agent/);
    expect(result.detail).toMatch(/new identity/);
    expect(result.detail).not.toMatch(/retry/i);
  });

  it("re-registering a directory-recorded channel WITHOUT channel params is refused", async () => {
    // Review F1: the directory says this identity is a channel. Registering it as an ordinary agent
    // would overwrite the local channel flag with false.
    const { persistence, calls } = makeRecordingPersistence(GROUP);
    const h = makeCapturingCtx(persistence);
    const mgr = new RegistrationManager(h.ctx);
    const promise = mgr.register("", "token");
    await vi.waitFor(() => expect(h.getPendingDkg()).not.toBeNull());
    h.deliverDkg({
      type: "register_error", reason: "already_registered", channel: true,
      agent_id: "agent-news", primary_pubkey: GROUP, ...h.echoKeys(),
    });
    expect(await promise).toMatchObject({ error: "channel_fields_immutable" });
    expect(calls.reg).toHaveLength(0);
  });
});

/**
 * M9D 002-PQKEYS — the post-quantum identity is persisted BEFORE anything is sent, reused on retry,
 * and never half-minted.
 */
describe("002-PQKEYS: the PQ identity is persisted first", () => {
  it("test 8: persistPqIdentity throws → pq_keys_not_persisted, and NO frame was sent", async () => {
    const { persistence } = makeRecordingPersistence(undefined, { failPq: "ml_kem" });
    // Recorder starts UNDEFINED and is only ever set by a send — a default would pass on no send.
    let firstFrame: Record<string, unknown> | undefined = undefined;
    const errors: Array<{ event: string; ctx: Record<string, unknown> }> = [];
    const logger: Logger = {
      debug() {}, info() {}, warn() {},
      error(event, ctx) { errors.push({ event, ctx: (ctx ?? {}) as Record<string, unknown> }); },
    };
    const h = makeFakeCtx({ persistence, logger, sendSignalingFrame: async (f) => { firstFrame ??= f; return { ok: true }; } });
    const result = await new RegistrationManager(h.ctx).register("", "token") as { error: string; detail?: string };

    expect(result.error).toBe("pq_keys_not_persisted");
    expect(result.detail).toMatch(/not attempted/);
    expect(firstFrame, "nothing may reach the directory when the seeds did not persist").toBeUndefined();
    const refused = errors.find((e) => e.event === "registration.pq_keys.refused");
    expect(refused?.ctx["reason"]).toBe("ml_kem_persist_failed");
    expect(typeof refused?.ctx["correlationId"]).toBe("string");
  });

  it("test 9: a retried registration reuses the persisted seeds — the second register_request carries the same keys", async () => {
    const { persistence, calls } = makeRecordingPersistence();
    // First attempt persists, then fails to send.
    const first = makeFakeCtx({ persistence, sendSignalingFrame: async () => ({ ok: false, reason: "signaling_lost" }) });
    expect(await new RegistrationManager(first.ctx).register("", "token")).toEqual({ error: "signaling_lost" });
    const firstKeys = first.echoKeys();

    const second = makeFakeCtx({ persistence, sendSignalingFrame: async () => ({ ok: false, reason: "signaling_lost" }) });
    await new RegistrationManager(second.ctx).register("", "token");
    expect(second.echoKeys()).toEqual(firstKeys);
    expect(calls.pq, "the seeds are minted and persisted exactly once").toHaveLength(1);
  });

  it("test 10: a row holding an ML-DSA seed and no ML-KEM seed fails loud — nothing minted, nothing sent", async () => {
    const { persistence, calls } = makeRecordingPersistence(undefined, {
      stored: { mlDsaSeed: mlDsaGenerateSeed(), mlDsaPubkey: "aa", mlKemSeed: null, mlKemPubkey: null },
    });
    const h = makeFakeCtx({ persistence });
    const result = await new RegistrationManager(h.ctx).register("", "token") as { error: string; detail?: string };
    expect(result.error).toBe("pq_keys_not_persisted");
    expect(result.detail).toMatch(/ML-DSA seed but no ML-KEM seed/);
    expect(calls.pq, "the missing half must not be minted").toHaveLength(0);
    expect(h.frames).toHaveLength(0);
  });

  it("an already_registered answer naming OTHER post-quantum keys is refused, and nothing is persisted", async () => {
    const { persistence, calls } = makeRecordingPersistence();
    const h = makeFakeCtx({ persistence });
    const promise = new RegistrationManager(h.ctx).register("", "token");
    await vi.waitFor(() => expect(h.getPendingDkg()).not.toBeNull());
    h.deliverDkg({
      type: "register_error", reason: "already_registered", agent_id: "agent-x",
      primary_pubkey: "cc".repeat(32), ml_dsa_pubkey: h.echoKeys().ml_dsa_pubkey, ml_kem_pubkey: "ee".repeat(1184),
    });
    expect(await promise).toMatchObject({ error: "registration_pq_keys_mismatch" });
    expect(calls.reg).toHaveLength(0);
  });
});
