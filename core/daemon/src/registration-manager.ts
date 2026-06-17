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
        this.#registrationState = state;
        this.#mlDsaProvider = mlDsaProvider;
        if (this.#ctx.persistence && mlDsaSecretKeyBlob) {
          void this.#ctx.persistence.persistMlDsaKeypair({
            mlDsaPubkey: mlDsaPubkeyHex,
            secretKeyBlob: mlDsaSecretKeyBlob,
          });
          void this.#ctx.persistence.persistRegistrationState({
            agentId: state.agent_id,
            primaryPubkey: state.primary_pubkey,
            mlDsaPubkey: state.ml_dsa_pubkey,
            registeredAt: state.registered_at,
          });
        }
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
        const commitmentsCbor = CBOR_ENC.encode(dkgResult.commitments) as Uint8Array;
        const verifyingSharesCbor = CBOR_ENC.encode(dkgResult.verifyingShares) as Uint8Array;
        void this.#ctx.persistence.persistFrostKeyShare({
          epochId,
          primaryPubkey: dkgPrimaryPubkeyHex,
          identifier: dkgResult.identifier,
          signingShare: dkgResult.signingShare,
          threshold: dkgResult.threshold,
          participants: dkgResult.participants,
          commitmentsCbor,
          verifyingSharesCbor,
          dkgMethod: "network_dkg",
        });
      }
    } catch {
      return { error: "dkg_failed" };
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
        this.#registrationState = state;
        this.#mlDsaProvider = mlDsaProvider;
        if (this.#ctx.persistence && mlDsaSecretKeyBlob) {
          void this.#ctx.persistence.persistMlDsaKeypair({
            mlDsaPubkey: mlDsaPubkeyHex,
            secretKeyBlob: mlDsaSecretKeyBlob,
          });
          void this.#ctx.persistence.persistRegistrationState({
            agentId: state.agent_id,
            primaryPubkey: state.primary_pubkey,
            mlDsaPubkey: state.ml_dsa_pubkey,
            registeredAt: state.registered_at,
          });
        }
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
    this.#registrationState = state;
    this.#mlDsaProvider = mlDsaProvider;
    if (this.#ctx.persistence && mlDsaSecretKeyBlob) {
      void this.#ctx.persistence.persistMlDsaKeypair({
        mlDsaPubkey: mlDsaPubkeyHex,
        secretKeyBlob: mlDsaSecretKeyBlob,
      });
    }
    if (this.#ctx.persistence) {
      void this.#ctx.persistence.persistRegistrationState({
        agentId: state.agent_id,
        primaryPubkey: state.primary_pubkey,
        mlDsaPubkey: state.ml_dsa_pubkey,
        registeredAt: state.registered_at,
      });
    }
    return state;
  }
}
