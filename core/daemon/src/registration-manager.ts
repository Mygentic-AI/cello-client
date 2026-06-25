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

import { Encoder } from "cbor-x";
import { mlDsaKeygen, mlDsaKeygenWithBytes, FileMlDsaKeyProvider } from "@cello-protocol/crypto";
import type { IThresholdSigner, MlDsaKeyProvider } from "@cello-protocol/crypto";
import type { RegistrationState } from "@cello-protocol/protocol-types";
import { NetworkDirectoryNode, runNetworkDkg } from "./network-directory-node.js";

// CBOR encoder for serializing FROST commitments/verifyingShares before
// persistence (not signaling frames — those go through SignalingManager).
const CBOR_ENC = new Encoder({ tagUint8Array: false });
import type { DaemonRegistrationPersistence } from "./registration-persistence.js";
import type { Logger } from "./types.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { KeyProvider } from "@cello-protocol/crypto";

/** Result of attempting to send a frame over the daemon's directory signaling stream. */
export interface SignalingSendResult {
  ok: boolean;
  reason?: string;
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
    }));
    return ops;
  }

  /**
   * Register this agent with the directory.
   * REG-001: ML-DSA keygen → signaling stream → register_request → DKG → register_success.
   */
  async register(phoneStub: string = "", preAuthToken?: string): Promise<RegistrationState | { error: string }> {
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
    const regSent = await this.#ctx.sendSignalingFrame({
      type: "register_request",
      phone_stub: phoneStub,
      k_local_pubkey: kLocalPubkeyHex,
      ml_dsa_pubkey: mlDsaPubkeyHex,
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
          const ok = await this.#persistAll(this.#identityPersistOps(state, mlDsaPubkeyHex, mlDsaSecretKeyBlob));
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
    const directoryEndpoint = this.#ctx.getDirectoryEndpoint();
    if (!directoryEndpoint) {
      return { error: "directory_unreachable" };
    }
    // getNode() may be null even when signaling reads connected (brief
    // stream-death window) — null-check before FROST DKG opens streams on it.
    const dkgNode = this.#ctx.getNode();
    if (!dkgNode) {
      return { error: "directory_unreachable" };
    }
    const dirNode = new NetworkDirectoryNode({
      id: directoryEndpoint.peer_id,
      node: dkgNode,
      directoryPeerId: directoryEndpoint.peer_id,
      directoryMultiaddrs: directoryEndpoint.multiaddrs,
      logger: this.#ctx.logger,
    });
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
        directoryNodes: [dirNode],
        preAuthToken,
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
          commitmentsCbor: CBOR_ENC.encode(dkgResult.commitments) as Uint8Array,
          verifyingSharesCbor: CBOR_ENC.encode(dkgResult.verifyingShares) as Uint8Array,
          dkgMethod: "network_dkg",
        };
      }
    } catch {
      return { error: "dkg_failed" };
    }
    // SI-003/AC-005: AWAIT the share persist (was fire-and-forget) before register reports success —
    // so a register-success guarantees the share is durably committed (no can't-sign zombie).
    if (shareToPersist && this.#ctx.persistence) {
      const persistence = this.#ctx.persistence;
      const share = shareToPersist;
      const ok = await this.#persistAll([() => persistence.persistFrostKeyShare(share)]);
      if (!ok) return { error: "identity_persist_failed" };
    }

    // Step 5c: send dkg_complete (SignalingManager CBOR/lp-encodes the frame)
    const dkgSent = await this.#ctx.sendSignalingFrame({
      type: "dkg_complete",
      primary_pubkey: dkgPrimaryPubkeyHex,
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
          const ok = await this.#persistAll(this.#identityPersistOps(state, mlDsaPubkeyHex, mlDsaSecretKeyBlob));
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
      const ok = await this.#persistAll(this.#identityPersistOps(state, mlDsaPubkeyHex, mlDsaSecretKeyBlob));
      if (!ok) return { error: "identity_persist_failed" };
    }
    this.#registrationState = state;
    this.#mlDsaProvider = mlDsaProvider;
    return state;
  }
}
