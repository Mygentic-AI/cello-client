/**
 * RegistrationManager — REG-001, ML-DSA keygen, DKG (daemon port).
 *
 * Ported from cello-client's RegistrationManager. Owns registration domain
 * state (#registrationState, #mlDsaProvider). The only adaptation vs the client
 * is the signaling seam: the client wrote directly to a raw persistent libp2p
 * Stream, whereas the daemon's directory signaling lives behind SignalingManager.
 * So RegistrationContext exposes `sendSignalingFrame` (→ SignalingManager.sendRaw,
 * which CBOR/length-prefix-encodes internally) and `isSignalingConnected`, and a
 * single daemon-owned inbound handler drives the pending dkg_ready/register
 * resolvers (see DaemonRegistrationContext). The register() control flow is
 * otherwise unchanged.
 */

import { encodeCbor } from "@cello-protocol/protocol-types";
import { mlDsaKeygen, mlDsaKeygenWithBytes, FileMlDsaKeyProvider, buildKeyBindingTbs } from "@cello-protocol/crypto";
import type { IThresholdSigner, MlDsaKeyProvider } from "@cello-protocol/crypto";
import type { RegistrationState } from "@cello-protocol/protocol-types";
import { NetworkDirectoryNode, runNetworkDkg } from "./network-directory-node.js";
import type { ConsortiumEndpoint } from "./directory-bootstrap.js";

import type { DaemonRegistrationPersistence } from "./registration-persistence.js";
import type { Logger } from "./types.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { KeyProvider } from "@cello-protocol/crypto";

/** Result of attempting to send a frame over the daemon's directory signaling stream. */
export interface SignalingSendResult {
  ok: boolean;
  reason?: string;
  /** DOD-SENDRAW-1 review F2: the transport's OperationResult carries the SPECIFIC cause here
   *  (e.g. `Send failed: <exception text>`) while `reason` is the generic label — failure logs
   *  must thread it through or the operator gets the label, not the cause. */
  guidance?: string;
}

/**
 * Narrow interface exposing only what RegistrationManager needs from the daemon.
 * This avoids importing daemon internals and prevents circular dependencies.
 */
export interface RegistrationContext {
  readonly keyProvider: KeyProvider;
  readonly logger: Logger;
  readonly persistence: DaemonRegistrationPersistence | null;
  readonly mlDsaKeyFile: string | undefined;
  /**
   * The live directory-facing libp2p node FROST DKG opens streams on. May be
   * null even when signaling reads connected (brief stream-death window) — the
   * caller MUST null-check before constructing a NetworkDirectoryNode.
   */
  getNode(): CelloNode | null;
  getMyPubkeyHex(): string | null;
  setMyPubkeyHex(hex: string): void;
  getDirectoryEndpoint(): { peer_id: string; multiaddrs: string[] } | null;
  /**
   * DOD-MANIFEST-1/DKG-1: the consortium directory-node roster resolved from the verified
   * manifest (one entry per resolved node), or NULL when NO consortium manifest is configured.
   * `null` ⇒ single-node DKG against getDirectoryEndpoint() (M6/M7 back-compat). A non-null
   * array ⇒ a consortium IS configured and the DKG must fan across exactly these nodes
   * (T-of-N); an EMPTY array (manifest configured but the whole consortium unresolved) is NOT
   * a fallback to single-node — it must REFUSE (the threshold gate). This null-vs-empty
   * distinction is load-bearing (code-reviewer B1 / fallback-finder).
   */
  getConsortiumEndpoints(): ConsortiumEndpoint[] | null;
  getThresholdSigner(): IThresholdSigner | undefined;
  setThresholdSigner(signer: IThresholdSigner): void;
  getMyPrimaryPubkey(): Uint8Array | null;
  setMyPrimaryPubkey(pubkey: Uint8Array): void;
  /** True when the directory signaling stream is connected and a send can be attempted. */
  isSignalingConnected(): boolean;
  /** Send a frame object over directory signaling (SignalingManager encodes it). */
  sendSignalingFrame(frame: Record<string, unknown>): Promise<SignalingSendResult>;
  setPendingDkgReadyResolve(resolve: ((frame: Record<string, unknown>) => void) | null): void;
  setPendingRegisterResolve(resolve: ((frame: Record<string, unknown>) => void) | null): void;
}

export class RegistrationManager {
  readonly #ctx: RegistrationContext;

  // Registration state owned by this manager
  #registrationState: RegistrationState | null = null;
  #mlDsaProvider: MlDsaKeyProvider | null = null;

  constructor(ctx: RegistrationContext) {
    this.#ctx = ctx;
  }

  // ─── Public state accessors ──────────────────────────────────────────────────

  getRegistrationState(): RegistrationState | null {
    return this.#registrationState;
  }

  setRegistrationState(state: RegistrationState | null): void {
    this.#registrationState = state;
  }

  getMlDsaProvider(): MlDsaKeyProvider | null {
    return this.#mlDsaProvider;
  }

  setMlDsaProvider(provider: MlDsaKeyProvider | null): void {
    this.#mlDsaProvider = provider;
  }

  /**
   * PERSIST-002 (SI-003/AC-005/AC-012): AWAIT every identity persist (was fire-and-forget) and
   * report whether all succeeded. A failure is logged as persist.identity.persist.failed and turns
   * the registration into an identity_persist_failed error — registration never reports success with
   * an uncommitted identity. SI-001: the error message carries no secret (the persist methods never
   * receive the secret in a loggable form here).
   */
  async #persistAll(ops: Array<() => Promise<void>>): Promise<boolean> {
    try {
      for (const op of ops) await op();
      return true;
    } catch (err: unknown) {
      this.#ctx.logger.error("persist.identity.persist.failed", {
        error: err instanceof Error ? err.message : String(err),
      });
      return false;
    }
  }

  /**
   * The awaited identity-persist operations for a successful registration: the ML-DSA keypair (only
   * when its secret blob is available) and ALWAYS the registration state. Registration state is never
   * gated on the ml-dsa blob — so an agent is never left durably-unregistered when the blob is absent.
   * Requires `this.#ctx.persistence` to be present (callers check).
   */
  #identityPersistOps(
    state: RegistrationState,
    mlDsaPubkeyHex: string,
    mlDsaSecretKeyBlob: Uint8Array | null,
    keyBinding: string,
  ): Array<() => Promise<void>> {
    const persistence = this.#ctx.persistence!;
    const ops: Array<() => Promise<void>> = [];
    if (mlDsaSecretKeyBlob) {
      ops.push(() => persistence.persistMlDsaKeypair({ mlDsaPubkey: mlDsaPubkeyHex, secretKeyBlob: mlDsaSecretKeyBlob }));
    }
    ops.push(() => persistence.persistRegistrationState({
      agentId: state.agent_id,
      primaryPubkey: state.primary_pubkey,
      mlDsaPubkey: state.ml_dsa_pubkey,
      registeredAt: state.registered_at,
      keyBinding,
    }));
    return ops;
  }

  /**
   * 038-KEYBIND — sign the statement "this FROST group key is mine" with K_local.
   *
   * ⚠️ NEVER A RE-DKG. An agent that already exists holds both keys and can produce this on
   * demand: K_local is on this machine and the group key is either just out of the DKG or handed
   * back by the directory on `already_registered`. Key refresh preserves the group key
   * (`session-ceremony.ts` aborts if the primary changes), so the binding is signed once for the
   * life of the agent — which is why every path that learns a `primary_pubkey` mints one, rather
   * than only the path that ran a ceremony.
   *
   * The signer is a key NO DIRECTORY HOLDS. That is the whole property: the directory carries this
   * value to the counterparty and cannot forge it, cannot swap it, and cannot lift it onto another
   * identity — the signed bytes name the K_local it belongs to as well as the group key.
   */
  async #mintKeyBinding(kLocalPubkeyHex: string, primaryPubkeyHex: string): Promise<string> {
    const tbs = buildKeyBindingTbs(
      new Uint8Array(Buffer.from(kLocalPubkeyHex, "hex")),
      new Uint8Array(Buffer.from(primaryPubkeyHex, "hex")),
    );
    return Buffer.from(await this.#ctx.keyProvider.sign(tbs)).toString("hex");
  }

  /**
   * Register this agent with the directory.
   * REG-001: ML-DSA keygen → signaling stream → register_request → DKG → register_success.
   */
  async register(phoneStub: string = "", preAuthToken?: string): Promise<RegistrationState | { error: string; detail?: string }> {
    // Step 1: already registered
    if (this.#registrationState) {
      return { error: "already_registered" };
    }

    // Step 2: generate or load ML-DSA-44 keypair
    let mlDsaProvider: MlDsaKeyProvider;
    let mlDsaSecretKeyBlob: Uint8Array | null = null;
    if (this.#ctx.mlDsaKeyFile) {
      mlDsaProvider = await FileMlDsaKeyProvider.load(this.#ctx.mlDsaKeyFile);
    } else if (this.#ctx.persistence) {
      const { provider, secretKeyBlob } = await mlDsaKeygenWithBytes();
      mlDsaProvider = provider;
      mlDsaSecretKeyBlob = secretKeyBlob;
    } else {
      mlDsaProvider = await mlDsaKeygen();
    }
    const mlDsaPubkey = await mlDsaProvider.getPublicKey();
    const mlDsaPubkeyHex = Buffer.from(mlDsaPubkey).toString("hex");

    // Step 3: require the directory signaling stream to be connected.
    // (The daemon keeps it connected via SignalingManager; we don't open it here.)
    if (!this.#ctx.isSignalingConnected()) {
      return { error: "directory_unreachable" };
    }

    // Step 4: get K_local pubkey hex
    if (!this.#ctx.getMyPubkeyHex()) {
      const pubkey = await this.#ctx.keyProvider.getPublicKey();
      this.#ctx.setMyPubkeyHex(Buffer.from(pubkey).toString("hex"));
    }
    const kLocalPubkeyHex = this.#ctx.getMyPubkeyHex()!;

    // Step 5: send register_request (SignalingManager CBOR/lp-encodes the frame)
    // M8B quorum: include the nodeIds we can reach right now (our resolved roster) so the directory can
    // pick the DKG quorum Q = these ∩ its manifest, |Q| ≥ T=majority(N). getConsortiumEndpoints() is
    // null on the single-node back-compat path (no consortium manifest) → omit the field.
    const reachableRoster = this.#ctx.getConsortiumEndpoints();
    const reachableNodeIds = reachableRoster?.map((e) => e.nodeId);
    const regSent = await this.#ctx.sendSignalingFrame({
      type: "register_request",
      phone_stub: phoneStub,
      k_local_pubkey: kLocalPubkeyHex,
      ml_dsa_pubkey: mlDsaPubkeyHex,
      ...(reachableNodeIds ? { reachable_node_ids: reachableNodeIds } : {}),
    });
    if (!regSent.ok) {
      return { error: regSent.reason ?? "directory_unreachable" };
    }

    // Step 5a: await dkg_ready
    const DKG_READY_TIMEOUT_MS = 15_000;
    let dkgReadyTimeoutHandle: ReturnType<typeof setTimeout> | undefined;
    const dkgReadyFrame = await Promise.race<Record<string, unknown>>([
      new Promise<Record<string, unknown>>((resolve) => {
        this.#ctx.setPendingDkgReadyResolve(resolve);
      }),
      new Promise<Record<string, unknown>>((resolve) => {
        dkgReadyTimeoutHandle = setTimeout(() => {
          this.#ctx.setPendingDkgReadyResolve(null);
          resolve({ type: "register_error", reason: "timeout" });
        }, DKG_READY_TIMEOUT_MS);
      }),
    ]);
    clearTimeout(dkgReadyTimeoutHandle);

    if (dkgReadyFrame["type"] !== "dkg_ready") {
      const reason = (dkgReadyFrame["reason"] as string | undefined) ?? "unknown";
      if (
        reason === "already_registered" &&
        dkgReadyFrame["agent_id"] &&
        dkgReadyFrame["primary_pubkey"]
      ) {
        const state: RegistrationState = {
          agent_id: dkgReadyFrame["agent_id"] as string,
          primary_pubkey: dkgReadyFrame["primary_pubkey"] as string,
          ml_dsa_pubkey: (dkgReadyFrame["ml_dsa_pubkey"] as string | undefined) ?? mlDsaPubkeyHex,
          registered_at: Date.now(),
          status: "active",
        };
        // SI-003: persist BEFORE caching the in-memory registered state, so a persist failure does
        // not leave a phantom "registered" manager (which would short-circuit a retry). Registration
        // state is persisted whenever persistence is present — NOT gated on the ml-dsa blob (so an
        // already_registered agent is never left durably-unregistered when the blob is absent).
        if (this.#ctx.persistence) {
          // 038-KEYBIND: this agent is already registered, so no ceremony runs — but both keys are
          // here (K_local locally, the group key in the frame), which is all the binding needs.
          const keyBinding = await this.#mintKeyBinding(kLocalPubkeyHex, state.primary_pubkey);
          const ok = await this.#persistAll(this.#identityPersistOps(state, mlDsaPubkeyHex, mlDsaSecretKeyBlob, keyBinding));
          if (!ok) return { error: "identity_persist_failed" };
        }
        this.#registrationState = state;
        this.#mlDsaProvider = mlDsaProvider;
        return state;
      }
      return { error: reason };
    }

    // Step 5b: run real FROST DKG
    const epochId = dkgReadyFrame["epochId"] as string;
    const participants = dkgReadyFrame["participants"] as number;
    const threshold = dkgReadyFrame["threshold"] as number;
    // getNode() may be null even when signaling reads connected (brief
    // stream-death window) — null-check before FROST DKG opens streams on it.
    const dkgNode = this.#ctx.getNode();
    if (!dkgNode) {
      /**
       * NAMES THE LOCAL STATE, not the network. This returned `directory_unreachable` — a network
       * verdict for a purely local lifecycle fact, and the comment two lines above already says so:
       * the daemon's own node reference is briefly null while a stream dies and is rebuilt. The
       * directory may be perfectly reachable.
       *
       * Found by the `DOD-M15-SURFACE-1` review as `[pre-existing]`; fixed under the standing rule
       * that an error naming the wrong subsystem gets corrected when it is found. It is also the
       * exact shape M15 is closing elsewhere — one string sending an investigation at the network
       * when the cause is local — so leaving it while fixing its siblings would be inconsistent.
       */
      this.#ctx.logger.warn("registration.dkg.node_unavailable", {
        impact: "the daemon's own transport node was momentarily absent while a signaling stream was rebuilt; registration was not attempted and nothing about the directory's reachability was established",
      });
      // `detail` is the shape this return type carries — the affordance rides there rather than in
      // a `guidance` key the caller would drop on the floor.
      return {
        error: "transport_node_unavailable",
        detail:
          "The daemon's transport node was briefly unavailable while its directory connection was rebuilding. This is local and usually clears within seconds; it says nothing about whether the directory is reachable. Retry registration, and if it repeats check the directory connection state with cello status.",
      };
    }
    // DOD-DKG-1: build the directory-node set the DKG fans across. With a verified consortium
    // manifest the client resolved the full N-node roster (getConsortiumEndpoints) and the DKG
    // runs across ALL of them (the generated key is T-of-N). Without a manifest the roster is
    // empty → the single primary endpoint (single-node DKG, M6/M7 back-compat).
    // getConsortiumEndpoints() returns the resolved roster when a consortium manifest IS
    // configured, or NULL when none is (the M6/M7 single-node back-compat path). Branching on
    // "manifest configured" (roster !== null) — NOT "roster non-empty" — is the load-bearing
    // distinction (code-reviewer B1 / cello-fallback-finder HIGH): an EMPTY roster with a
    // manifest configured (the whole consortium momentarily unreachable) must REFUSE, never
    // silently fall back to a 2-of-2 DKG against an unverified single directory.
    const roster = this.#ctx.getConsortiumEndpoints();
    let directoryNodes: NetworkDirectoryNode[];
    if (roster !== null) {
      // M8B quorum: the directory set `participants` = |Q| = |R ∩ manifest| from the reachable_node_ids
      // we reported. Our resolved roster IS Q (Q = R ∩ manifest, and R = our roster), so we fan the DKG
      // to it directly. The count must still agree: roster.length !== participants ⇒ a node we reported
      // is now unreachable, or a manifest version skew ⇒ REFUSE rather than DKG a divergent set.
      // (Replaces the old all-N check — `participants` is now the quorum size, not the full manifest N.)
      if (roster.length !== participants) {
        this.#ctx.logger.warn("registration.dkg.quorum_mismatch", {
          resolvedRoster: roster.length,
          declaredParticipants: participants,
        });
        return { error: "dkg_below_threshold" };
      }
      directoryNodes = roster.map(
        (ep) =>
          new NetworkDirectoryNode({
            id: ep.peerId,
            node: dkgNode,
            directoryPeerId: ep.peerId,
            directoryMultiaddrs: [ep.multiaddr],
            logger: this.#ctx.logger,
          }),
      );
    } else {
      // No consortium manifest configured → single-node DKG (M6/M7 back-compat).
      const directoryEndpoint = this.#ctx.getDirectoryEndpoint();
      if (!directoryEndpoint) {
        return { error: "directory_unreachable" };
      }
      directoryNodes = [
        new NetworkDirectoryNode({
          id: directoryEndpoint.peer_id,
          node: dkgNode,
          directoryPeerId: directoryEndpoint.peer_id,
          directoryMultiaddrs: directoryEndpoint.multiaddrs,
          logger: this.#ctx.logger,
        }),
      ];
    }
    void epochId;
    const kLocalPubkeyBytes = Buffer.from(kLocalPubkeyHex, "hex");
    let dkgPrimaryPubkeyHex: string;
    // The share to persist, captured inside the DKG try (a DKG error → dkg_failed) but persisted
    // AFTER it, so a persist failure surfaces as identity_persist_failed, not dkg_failed.
    let shareToPersist: Parameters<DaemonRegistrationPersistence["persistFrostKeyShare"]>[0] | null = null;
    try {
      const dkgResult = await runNetworkDkg(kLocalPubkeyBytes, {
        threshold,
        participants,
        directoryNodes,
        preAuthToken,
        signAuth: (h) => this.#ctx.keyProvider.sign(h), // SEC-2
      });
      dkgPrimaryPubkeyHex = Buffer.from(dkgResult.primaryPubkey).toString("hex");
      this.#ctx.setThresholdSigner(dkgResult.signer);
      this.#ctx.setMyPrimaryPubkey(new Uint8Array(dkgResult.primaryPubkey));
      if (this.#ctx.persistence) {
        shareToPersist = {
          epochId,
          primaryPubkey: dkgPrimaryPubkeyHex,
          identifier: dkgResult.identifier,
          signingShare: dkgResult.signingShare,
          threshold: dkgResult.threshold,
          participants: dkgResult.participants,
          commitmentsCbor: encodeCbor(dkgResult.commitments) as Uint8Array,
          verifyingSharesCbor: encodeCbor(dkgResult.verifyingShares) as Uint8Array,
          dkgMethod: "network_dkg",
          // M8B quorum: persist the quorum Q (nodeIds the DKG ran among) so a restored signer targets the
          // actual share-holders, not the full live roster. null on the single-node back-compat path.
          directoryNodeIds: roster ? roster.map((e) => e.nodeId) : undefined,
        };
      }
    } catch (err: unknown) {
      // NOT a bare catch. Everything runNetworkDkg can throw was being discarded here, and this is
      // the client's own log — where the operator actually is. The messages destroyed included the
      // only diagnosis of a colliding FROST identifier (`Duplicate id=5375…`, thrown by
      // @noble/curves DKG.round2 when two nodes derive the same identifier) and the
      // commitment-vs-primary_pubkey mismatch, plus every stream/transport failure from
      // dkgRound1WithNode / dkgRound2WithNode. All of them reached the operator as `dkg_failed` —
      // one exit-point label standing in for a dozen unrelated causes, sending them to debug FROST
      // when the cause was a duplicate nodeId in a manifest or an unreachable node.
      this.#ctx.logger.error("registration.dkg.failed", {
        reason: err instanceof Error ? err.message : String(err),
        // WHICH registration and WHICH nodes. `reason` alone cannot be acted on: on a multi-agent
        // daemon the operator cannot tell which agent failed, and a nested
        // "dkgRound2: no response received" does not say from whom. These are also what let this line
        // be correlated with the registration.dkg.quorum_mismatch warning that may precede it.
        agentPubkey: kLocalPubkeyHex,
        directoryNodeIds: roster ? roster.map((e) => e.nodeId) : undefined,
        // The stack, not just the message — a wrapped throw from two frames down otherwise loses the
        // frame that names the node.
        stack: err instanceof Error ? err.stack : undefined,
      });
      // The cause travels WITH the code. `dkg_failed` is the closed protocol union the wire needs;
      // `detail` is what lets the operator-facing guidance say which failure it actually was.
      return { error: "dkg_failed", detail: err instanceof Error ? err.message : String(err) };
    }
    // SI-003/AC-005: AWAIT the share persist (was fire-and-forget) before register reports success —
    // so a register-success guarantees the share is durably committed (no can't-sign zombie).
    if (shareToPersist && this.#ctx.persistence) {
      const persistence = this.#ctx.persistence;
      const share = shareToPersist;
      const ok = await this.#persistAll([() => persistence.persistFrostKeyShare(share)]);
      if (!ok) return { error: "identity_persist_failed" };
    }

    /**
     * ─── 038-KEYBIND: MINT THE BINDING, THEN HAND IT OVER WITH THE GROUP KEY ────────────────────
     *
     * THE TAIL OF REGISTRATION IS THE ONLY MOMENT THIS CAN HAPPEN. At agent creation the group key
     * does not exist — a FROST DKG's group key is the sum of every participant's commitment, so by
     * construction it is nobody's existing key. After this frame the ceremony is over. Right here
     * is the one point where K_local's private half and the finished group key are both on this
     * machine.
     *
     * It rides on `dkg_complete` rather than in a frame of its own so the directory can never hold
     * a group key it has no binding for: one frame, both values, or neither.
     */
    const keyBinding = await this.#mintKeyBinding(kLocalPubkeyHex, dkgPrimaryPubkeyHex);

    // Step 5c: send dkg_complete (SignalingManager CBOR/lp-encodes the frame)
    const dkgSent = await this.#ctx.sendSignalingFrame({
      type: "dkg_complete",
      primary_pubkey: dkgPrimaryPubkeyHex,
      key_binding: keyBinding,
    });
    if (!dkgSent.ok) {
      return { error: dkgSent.reason ?? "directory_unreachable" };
    }

    // Step 6: await register_success or register_error
    const REGISTER_TIMEOUT_MS = 15_000;
    let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
    const responseWithTimeout = await Promise.race<Record<string, unknown>>([
      new Promise<Record<string, unknown>>((resolve) => {
        this.#ctx.setPendingRegisterResolve(resolve);
      }),
      new Promise<Record<string, unknown>>((resolve) => {
        timeoutHandle = setTimeout(() => {
          this.#ctx.setPendingRegisterResolve(null);
          resolve({ type: "register_error", reason: "timeout" });
        }, REGISTER_TIMEOUT_MS);
      }),
    ]);
    clearTimeout(timeoutHandle);

    if (responseWithTimeout["type"] !== "register_success") {
      const reason = (responseWithTimeout["reason"] as string | undefined) ?? "unknown";
      if (
        reason === "already_registered" &&
        responseWithTimeout["agent_id"] &&
        responseWithTimeout["primary_pubkey"]
      ) {
        const state: RegistrationState = {
          agent_id: responseWithTimeout["agent_id"] as string,
          primary_pubkey: responseWithTimeout["primary_pubkey"] as string,
          ml_dsa_pubkey: (responseWithTimeout["ml_dsa_pubkey"] as string | undefined) ?? mlDsaPubkeyHex,
          registered_at: Date.now(),
          status: "active",
        };
        // SI-003: persist before caching the registered state (see the dkg_ready branch).
        if (this.#ctx.persistence) {
          // 038-KEYBIND: the DKG ran but the directory already had a profile, so the group key it
          // returns is the authoritative one — bind THAT, not the one this run derived.
          const rebinding = await this.#mintKeyBinding(kLocalPubkeyHex, state.primary_pubkey);
          const ok = await this.#persistAll(this.#identityPersistOps(state, mlDsaPubkeyHex, mlDsaSecretKeyBlob, rebinding));
          if (!ok) return { error: "identity_persist_failed" };
        }
        this.#registrationState = state;
        this.#mlDsaProvider = mlDsaProvider;
        return state;
      }
      return { error: reason };
    }

    // Step 7: build RegistrationState and cache
    const agentId = responseWithTimeout["agent_id"] as string;
    const primaryPubkey = responseWithTimeout["primary_pubkey"] as string;

    const state: RegistrationState = {
      agent_id: agentId,
      primary_pubkey: primaryPubkey,
      ml_dsa_pubkey: mlDsaPubkeyHex,
      registered_at: Date.now(),
      status: "active",
    };
    // SI-003: AWAIT the final identity persists before reporting success, and cache the registered
    // state only after they commit — a register-success guarantees a durable identity row.
    if (this.#ctx.persistence) {
      /**
       * 038-KEYBIND — RE-MINT AGAINST THE DIRECTORY'S ANSWER, do not reuse the value sent above.
       *
       * `register_success` carries the primary_pubkey the directory considers canonical. It is the
       * same key on every healthy registration, and reusing `keyBinding` would be right in exactly
       * that case — but if the two ever differ, the stored binding would name a group key this
       * agent is not actually registered under, and it would verify perfectly while pointing at the
       * wrong key. Binding what was ANSWERED costs one signature and cannot drift.
       */
      const ok = await this.#persistAll(this.#identityPersistOps(
        state, mlDsaPubkeyHex, mlDsaSecretKeyBlob,
        primaryPubkey === dkgPrimaryPubkeyHex ? keyBinding : await this.#mintKeyBinding(kLocalPubkeyHex, primaryPubkey),
      ));
      if (!ok) return { error: "identity_persist_failed" };
    }
    this.#registrationState = state;
    this.#mlDsaProvider = mlDsaProvider;
    return state;
  }
}
