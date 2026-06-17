/**
 * DaemonRegistrationContext — CELLO-M7-REGISTRATION (Action 2, step c part 2).
 *
 * Implements the RegistrationManager's RegistrationContext seam against daemon
 * internals. The one non-trivial piece is the signaling bridge: the client wrote
 * directly to a raw persistent libp2p Stream and ran its own read loop; the
 * daemon's directory signaling lives behind SignalingManager. So this context:
 *   - sends frames via SignalingManager.sendRaw (which CBOR/length-prefix-encodes),
 *   - registers ONE inbound handler that routes the registration reply frames
 *     (dkg_ready / register_success / register_error) to whichever pending
 *     resolver RegistrationManager.register() has currently armed.
 *
 * register() drives the two stages strictly sequentially (await dkg_ready, then
 * await register_success), so at most one resolver is armed at any moment — which
 * is why a bare register_error can be routed to "whichever stage is waiting".
 */

import type { CelloNode } from "@cello-protocol/transport";
import type { IThresholdSigner, KeyProvider } from "@cello-protocol/crypto";
import type { Logger } from "./types.js";
import type { DaemonRegistrationPersistence } from "./registration-persistence.js";
import type { RegistrationContext, SignalingSendResult } from "./registration-manager.js";

/**
 * Structural slice of SignalingManager this context needs. The real
 * SignalingManager satisfies this (status getter; sendRaw → OperationResult,
 * assignable to SignalingSendResult; registerInboundHandler → unregister fn),
 * and a fake satisfies it in tests.
 */
export interface SignalingSeam {
  readonly status: string;
  sendRaw(frame: unknown): Promise<SignalingSendResult>;
  registerInboundHandler(handler: (frame: Record<string, unknown>) => void): () => void;
}

const REGISTRATION_REPLY_TYPES = new Set(["dkg_ready", "register_success", "register_error"]);

export class DaemonRegistrationContext implements RegistrationContext {
  readonly keyProvider: KeyProvider;
  readonly logger: Logger;
  readonly persistence: DaemonRegistrationPersistence | null;
  readonly mlDsaKeyFile: string | undefined;

  readonly #signaling: SignalingSeam;
  readonly #getDirectoryNode: () => CelloNode | null;
  readonly #getDirectoryEndpoint: () => { peer_id: string; multiaddrs: string[] } | null;
  readonly #unregisterInbound: () => void;

  #myPubkeyHex: string | null = null;
  #thresholdSigner: IThresholdSigner | undefined = undefined;
  #myPrimaryPubkey: Uint8Array | null = null;
  #pendingDkgReady: ((frame: Record<string, unknown>) => void) | null = null;
  #pendingRegister: ((frame: Record<string, unknown>) => void) | null = null;

  constructor(opts: {
    signaling: SignalingSeam;
    getDirectoryNode: () => CelloNode | null;
    getDirectoryEndpoint: () => { peer_id: string; multiaddrs: string[] } | null;
    keyProvider: KeyProvider;
    persistence: DaemonRegistrationPersistence | null;
    logger: Logger;
    mlDsaKeyFile?: string | undefined;
  }) {
    this.#signaling = opts.signaling;
    this.#getDirectoryNode = opts.getDirectoryNode;
    this.#getDirectoryEndpoint = opts.getDirectoryEndpoint;
    this.keyProvider = opts.keyProvider;
    this.persistence = opts.persistence;
    this.logger = opts.logger;
    this.mlDsaKeyFile = opts.mlDsaKeyFile;
    this.#unregisterInbound = this.#signaling.registerInboundHandler((frame) => this.#onInbound(frame));
  }

  // ─── Node + identity ────────────────────────────────────────────────────────

  getNode(): CelloNode | null {
    return this.#getDirectoryNode();
  }

  getMyPubkeyHex(): string | null {
    return this.#myPubkeyHex;
  }

  setMyPubkeyHex(hex: string): void {
    this.#myPubkeyHex = hex;
  }

  getDirectoryEndpoint(): { peer_id: string; multiaddrs: string[] } | null {
    return this.#getDirectoryEndpoint();
  }

  getThresholdSigner(): IThresholdSigner | undefined {
    return this.#thresholdSigner;
  }

  setThresholdSigner(signer: IThresholdSigner): void {
    this.#thresholdSigner = signer;
  }

  getMyPrimaryPubkey(): Uint8Array | null {
    return this.#myPrimaryPubkey;
  }

  setMyPrimaryPubkey(pubkey: Uint8Array): void {
    this.#myPrimaryPubkey = pubkey;
  }

  // ─── Signaling seam ──────────────────────────────────────────────────────────

  isSignalingConnected(): boolean {
    return this.#signaling.status === "connected";
  }

  async sendSignalingFrame(frame: Record<string, unknown>): Promise<SignalingSendResult> {
    return this.#signaling.sendRaw(frame);
  }

  setPendingDkgReadyResolve(resolve: ((frame: Record<string, unknown>) => void) | null): void {
    this.#pendingDkgReady = resolve;
  }

  setPendingRegisterResolve(resolve: ((frame: Record<string, unknown>) => void) | null): void {
    this.#pendingRegister = resolve;
  }

  /** Stop routing inbound frames (call when the owning agent is torn down). */
  dispose(): void {
    this.#unregisterInbound();
    this.#pendingDkgReady = null;
    this.#pendingRegister = null;
  }

  // ─── Inbound routing ──────────────────────────────────────────────────────────

  #onInbound(frame: Record<string, unknown>): void {
    const type = frame["type"];
    if (typeof type !== "string" || !REGISTRATION_REPLY_TYPES.has(type)) {
      return; // not a registration reply — leave it for other inbound handlers
    }

    if (type === "dkg_ready") {
      const resolve = this.#pendingDkgReady;
      this.#pendingDkgReady = null;
      resolve?.(frame);
      return;
    }
    if (type === "register_success") {
      const resolve = this.#pendingRegister;
      this.#pendingRegister = null;
      resolve?.(frame);
      return;
    }

    // register_error → deliver to whichever stage is currently waiting.
    // Stages are sequential, so at most one resolver is armed.
    if (this.#pendingDkgReady) {
      const resolve = this.#pendingDkgReady;
      this.#pendingDkgReady = null;
      resolve(frame);
    } else if (this.#pendingRegister) {
      const resolve = this.#pendingRegister;
      this.#pendingRegister = null;
      resolve(frame);
    }
  }
}
