/**
 * RegistrationManager — REG-001, ML-DSA keygen, DKG
 *
 * Extracted from CelloClientImpl. Methods operate on the shared internal state
 * passed via the `ctx` parameter (typed as InternalClientAccess).
 */

import { Encoder } from "cbor-x";
import * as lp from "it-length-prefixed";
import { mlDsaKeygen, mlDsaKeygenWithBytes, FileMlDsaKeyProvider } from "@cello-protocol/crypto";
import type { IThresholdSigner } from "@cello-protocol/crypto";
import type { RegistrationState } from "@cello-protocol/protocol-types";
import type { Stream } from "@libp2p/interface";
import { NetworkDirectoryNode, runNetworkDkg } from "./network-directory-node.js";
import type { ClientStatePersistence } from "./client-state-persistence.js";
import type { Logger } from "@cello-protocol/interfaces";
import type { CelloNode } from "@cello-protocol/transport";
import type { KeyProvider } from "@cello-protocol/crypto";

const CBOR_ENC = new Encoder({ tagUint8Array: false });

/**
 * Narrow interface exposing only what RegistrationManager needs from CelloClientImpl.
 * This avoids importing the full class and prevents circular dependencies.
 */
export interface RegistrationContext {
  readonly node: CelloNode;
  readonly keyProvider: KeyProvider;
  readonly logger: Logger;
  readonly persistence: ClientStatePersistence | null;
  readonly mlDsaKeyFile: string | undefined;
  getMyPubkeyHex(): string | null;
  setMyPubkeyHex(hex: string): void;
  getDirectoryEndpoint(): { peer_id: string; multiaddrs: string[] } | null;
  getThresholdSigner(): IThresholdSigner | undefined;
  setThresholdSigner(signer: IThresholdSigner): void;
  getRegistrationState(): RegistrationState | null;
  setRegistrationState(state: RegistrationState | null): void;
  getMlDsaProvider(): import("@cello-protocol/crypto").MlDsaKeyProvider | null;
  setMlDsaProvider(provider: import("@cello-protocol/crypto").MlDsaKeyProvider | null): void;
  getMyPrimaryPubkey(): Uint8Array | null;
  setMyPrimaryPubkey(pubkey: Uint8Array): void;
  getPersistentSignalingStream(): Stream | null;
  openPersistentSignalingStream(): Promise<boolean>;
  setPendingDkgReadyResolve(resolve: ((frame: Record<string, unknown>) => void) | null): void;
  setPendingRegisterResolve(resolve: ((frame: Record<string, unknown>) => void) | null): void;
}

export class RegistrationManager {
  readonly #ctx: RegistrationContext;

  constructor(ctx: RegistrationContext) {
    this.#ctx = ctx;
  }

  /**
   * Register this agent with the directory.
   * REG-001: ML-DSA keygen → signaling stream → register_request → DKG → register_success.
   */
  async register(phoneStub: string = "", preAuthToken?: string): Promise<RegistrationState | { error: string }> {
    // Step 1: already registered
    if (this.#ctx.getRegistrationState()) {
      return { error: "already_registered" };
    }

    // Step 2: generate or load ML-DSA-44 keypair
    let mlDsaProvider: import("@cello-protocol/crypto").MlDsaKeyProvider;
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

    // Step 3: open persistent signaling stream
    const opened = await this.#ctx.openPersistentSignalingStream();
    if (!opened || !this.#ctx.getPersistentSignalingStream()) {
      return { error: "directory_unreachable" };
    }

    // Step 4: get K_local pubkey hex
    if (!this.#ctx.getMyPubkeyHex()) {
      const pubkey = await this.#ctx.keyProvider.getPublicKey();
      this.#ctx.setMyPubkeyHex(Buffer.from(pubkey).toString("hex"));
    }
    const kLocalPubkeyHex = this.#ctx.getMyPubkeyHex()!;

    // Step 5: send register_request
    const regRequestFrame = CBOR_ENC.encode({
      type: "register_request",
      phone_stub: phoneStub,
      k_local_pubkey: kLocalPubkeyHex,
      ml_dsa_pubkey: mlDsaPubkeyHex,
    }) as Uint8Array;
    this.#ctx.getPersistentSignalingStream()!.send(lp.encode.single(regRequestFrame));

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
        this.#ctx.setRegistrationState(state);
        this.#ctx.setMlDsaProvider(mlDsaProvider);
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
    const dirNode = new NetworkDirectoryNode({
      id: directoryEndpoint.peer_id,
      node: this.#ctx.node,
      directoryPeerId: directoryEndpoint.peer_id,
      directoryMultiaddrs: directoryEndpoint.multiaddrs,
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

    // Step 5c: send dkg_complete
    const dkgCompleteFrame = CBOR_ENC.encode({
      type: "dkg_complete",
      primary_pubkey: dkgPrimaryPubkeyHex,
    }) as Uint8Array;
    this.#ctx.getPersistentSignalingStream()!.send(lp.encode.single(dkgCompleteFrame));

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
        this.#ctx.setRegistrationState(state);
        this.#ctx.setMlDsaProvider(mlDsaProvider);
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
    this.#ctx.setRegistrationState(state);
    this.#ctx.setMlDsaProvider(mlDsaProvider);
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
