/**
 * M7-MANIFEST-002 — SignalingManager: step-6 directory challenge verifier and
 * background manifest poll dispatcher.
 *
 * Responsibilities:
 * 1. Process the step-5 signaling_auth_ok frame (directory→client):
 *    - Extract nodeId, signature, timestamp
 *    - Build the TBS (to-be-signed) bytes from stored nonce + agent pubkey + timestamp
 *    - Verify the Ed25519 signature via IDirectoryChallengeVerifier
 *    - Emit directory.auth.challenge.verified (INFO) or directory.auth.challenge.failed (ERROR)
 * 2. Handle manifest_poll_response frames — validate and update in-memory manifest
 * 3. Dispatch manifest_poll_request frames on schedule via IManifestPollScheduler
 *
 * Step-5 TBS definition (authoritative):
 *   UTF-8('cello-directory-auth-challenge-v1\n') +
 *   UTF-8(nodeId) + UTF-8('\n') +
 *   UTF-8(agentPubkeyHex) + UTF-8('\n') +
 *   UTF-8(nonceHex) + UTF-8('\n') +
 *   UTF-8(isoTimestamp)
 *
 * Crypto reference: RFC 8032 (Ed25519 signature and verification).
 */

import type { ConsortiumManifest } from "@cello-protocol/protocol-types";
import { verifyManifest, type ConsortiumManifestInput } from "@cello-protocol/crypto";
import type {
  IDirectoryChallengeVerifier,
  IManifestPollScheduler,
  IManifestVersionStore,
  IManifestProvider,
} from "./manifest-interfaces.js";
export type { ChallengeVerifyResult } from "./manifest-interfaces.js";

// ─── Logger interface ─────────────────────────────────────────────────────────

export interface SignalingLogger {
  info(event: string, context: Record<string, unknown>): void;
  warn(event: string, context: Record<string, unknown>): void;
  error(event: string, context: Record<string, unknown>): void;
}

// ─── ISignalingOutboundQueue ──────────────────────────────────────────────────

/**
 * Outbound queue for signaling stream frames.
 *
 * SIGNAL-001: stub — real queue wired when SIGNAL-001 lands.
 *
 * The SignalingManager calls enqueue() to send frames over the established
 * signaling stream. SIGNAL-001 will implement the actual queue-to-stream
 * wiring with back-pressure and reconnect behaviour.
 */
export interface ISignalingOutboundQueue {
  /** Enqueue a frame for delivery over the signaling stream. */
  enqueue(frame: Record<string, unknown>): void;
}

/**
 * InMemorySignalingOutboundQueue — stub for SIGNAL-001.
 *
 * // SIGNAL-001: stub — real queue wired when SIGNAL-001 lands
 */
export class InMemorySignalingOutboundQueue implements ISignalingOutboundQueue {
  readonly #frames: Array<Record<string, unknown>> = [];

  enqueue(frame: Record<string, unknown>): void {
    this.#frames.push(frame);
  }

  getFrames(): ReadonlyArray<Record<string, unknown>> {
    return this.#frames;
  }

  drain(): Array<Record<string, unknown>> {
    return this.#frames.splice(0);
  }
}

// ─── Frame types ──────────────────────────────────────────────────────────────

/**
 * Augmented signaling_auth_ok frame with step-5 directory identity proof.
 * The nodeId, signature, and timestamp fields are optional for backward
 * compatibility — pre-MANIFEST-002 directories send auth_ok without them.
 */
export interface SignalingAuthOkFrame {
  type: "signaling_auth_ok";
  nodeId?: string;
  signature?: string;
  timestamp?: string;
}

export interface ManifestPollResponseFrame {
  type: "manifest_poll_response";
  manifest: ConsortiumManifest;
}

// ─── SignalingManager config ──────────────────────────────────────────────────

export interface SignalingManagerConfig {
  challengeVerifier: IDirectoryChallengeVerifier;
  pollScheduler: IManifestPollScheduler;
  manifestVersionStore: IManifestVersionStore;
  manifestProvider: IManifestProvider;
  outboundQueue: ISignalingOutboundQueue;
  logger: SignalingLogger;
  correlationId: string;
  /** Officer root keys for threshold signature verification of polled manifests (RFC 8032). */
  rootKeys: readonly string[];
  /** Officer threshold — minimum valid signatures required. */
  threshold: number;
}

// ─── SignalingManager ─────────────────────────────────────────────────────────

/**
 * SignalingManager processes inbound signaling frames for steps 5–6 of the
 * 7-step mutual challenge-response and manages background manifest polling.
 */
export class SignalingManager {
  readonly #challengeVerifier: IDirectoryChallengeVerifier;
  readonly #pollScheduler: IManifestPollScheduler;
  readonly #manifestVersionStore: IManifestVersionStore;
  readonly #manifestProvider: IManifestProvider;
  readonly #outboundQueue: ISignalingOutboundQueue;
  readonly #logger: SignalingLogger;
  readonly #correlationId: string;
  readonly #rootKeys: readonly string[];
  readonly #threshold: number;

  #pendingNonce: string | null = null;
  #agentPubkeyHex: string | null = null;

  constructor(config: SignalingManagerConfig) {
    this.#challengeVerifier = config.challengeVerifier;
    this.#pollScheduler = config.pollScheduler;
    this.#manifestVersionStore = config.manifestVersionStore;
    this.#manifestProvider = config.manifestProvider;
    this.#outboundQueue = config.outboundQueue;
    this.#logger = config.logger;
    this.#correlationId = config.correlationId;
    this.#rootKeys = config.rootKeys;
    this.#threshold = config.threshold;
  }

  /**
   * Store the nonce and agent pubkey from handshake steps 2–3.
   * Must be called before processStep5Frame().
   */
  setHandshakeContext(nonceHex: string, agentPubkeyHex: string): void {
    this.#pendingNonce = nonceHex;
    this.#agentPubkeyHex = agentPubkeyHex;
  }

  /**
   * Process a signaling_auth_ok frame (step 6 of the 7-step handshake).
   *
   * Pseudocode (RFC 8032 — Ed25519 verify):
   *   1. If frame has no nodeId/signature/timestamp: log warn, return no_identity_proof.
   *   2. Validate handshake context was set.
   *   3. Build TBS bytes.
   *   4. Call challengeVerifier.verifyChallenge(nodeId, tbsBytes, signature).
   *   5. Log directory.auth.challenge.verified (INFO) or directory.auth.challenge.failed (ERROR).
   */
  processStep5Frame(frame: SignalingAuthOkFrame): ProcessStep5Result {
    const { nodeId, signature, timestamp } = frame;

    if (!nodeId || !signature || !timestamp) {
      this.#logger.warn("directory.auth.challenge.skipped", {
        correlationId: this.#correlationId,
        reason: "no_identity_proof",
        hasNodeId: !!nodeId,
        hasSignature: !!signature,
        hasTimestamp: !!timestamp,
      });
      return { verified: false, reason: "no_identity_proof" };
    }

    if (this.#pendingNonce === null || this.#agentPubkeyHex === null) {
      this.#logger.error("directory.auth.challenge.failed", {
        correlationId: this.#correlationId,
        nodeId,
        reason: "handshake_context_missing",
      });
      return { verified: false, reason: "handshake_context_missing" };
    }

    const tbsBytes = buildStep5Tbs({
      nodeId,
      agentPubkeyHex: this.#agentPubkeyHex,
      nonceHex: this.#pendingNonce,
      isoTimestamp: timestamp,
    });

    const result = this.#challengeVerifier.verifyChallenge(nodeId, tbsBytes, signature);

    if (result.valid) {
      this.#logger.info("directory.auth.challenge.verified", {
        correlationId: this.#correlationId,
        nodeId,
      });
      return { verified: true };
    } else {
      this.#logger.error("directory.auth.challenge.failed", {
        correlationId: this.#correlationId,
        nodeId,
        reason: result.reason,
      });
      return { verified: false, reason: result.reason };
    }
  }

  /**
   * Handle a manifest_poll_response frame from the directory.
   *
   * Pseudocode:
   *   1. Verify threshold signatures (RFC 8032) via verifyManifest().
   *   2. Check not_before <= now < expires (validity window).
   *   3. Check version monotonicity via IManifestVersionStore.
   *   4. If rollback: log warn (poll-time rollback is non-blocking), schedule next poll.
   *   5. If version unchanged (up-to-date): schedule next poll silently.
   *   6. If valid and newer: update in-memory manifest via IManifestProvider.updateManifest(),
   *      persist version, log directory.auth.manifest.poll.success, schedule next poll.
   */
  async handleManifestPollResponse(manifest: ConsortiumManifest): Promise<void> {
    // Step 1: Threshold signature verification (RFC 8032)
    const verifyResult = verifyManifest(
      manifest as unknown as ConsortiumManifestInput,
      this.#rootKeys,
      this.#threshold,
    );
    if (!verifyResult.ok) {
      this.#logger.error("directory.auth.manifest.signature.invalid", {
        correlationId: this.#correlationId,
        manifestVersion: manifest.version,
        reason: verifyResult.reason,
        detail: verifyResult.detail,
      });
      this.#schedulePoll();
      return;
    }

    // Step 2: Validity window — not_before <= now < expires
    const now = new Date();
    const notBefore = new Date(manifest.not_before);
    if (now < notBefore) {
      this.#logger.warn("directory.auth.manifest.not.yet.valid", {
        correlationId: this.#correlationId,
        manifestVersion: manifest.version,
        notBefore: manifest.not_before,
      });
      this.#schedulePoll();
      return;
    }

    const expiresAt = new Date(manifest.expires);
    if (expiresAt <= now) {
      this.#logger.error("directory.auth.manifest.expired", {
        correlationId: this.#correlationId,
        manifestVersion: manifest.version,
        expiresAt: manifest.expires,
      });
      this.#schedulePoll();
      return;
    }

    // Step 3: Version monotonicity
    const lastSeen = await this.#manifestVersionStore.getLastSeenVersion();

    if (lastSeen !== null && manifest.version < lastSeen) {
      // Poll-time rollback: log at WARN (non-blocking per DB-002) — daemon continues on existing manifest
      this.#logger.warn("directory.auth.manifest.version.rollback", {
        correlationId: this.#correlationId,
        manifestVersion: manifest.version,
        lastSeenVersion: lastSeen,
      });
      this.#schedulePoll();
      return;
    }

    if (lastSeen !== null && manifest.version === lastSeen) {
      // Up-to-date — no change needed, no event emitted (per story observability notes)
      this.#schedulePoll();
      return;
    }

    // Step 5: New version — update in-memory manifest and persist
    const oldVersion = this.#manifestProvider.getCurrentManifest()?.version ?? null;
    this.#manifestProvider.updateManifest(manifest);
    await this.#manifestVersionStore.persistVersion(manifest.version);

    this.#logger.info("directory.auth.manifest.poll.success", {
      correlationId: this.#correlationId,
      oldVersion,
      newVersion: manifest.version,
    });

    this.#schedulePoll();
  }

  /** Dispatch a manifest_poll_request frame over the signaling stream. */
  dispatchManifestPoll(): void {
    this.#outboundQueue.enqueue({ type: "manifest_poll_request" });
    this.#logger.info("directory.auth.manifest.poll.dispatched", {
      correlationId: this.#correlationId,
    });
  }

  /** Start background polling after step-6 authentication completes. */
  startPolling(): void {
    this.#schedulePoll();
  }

  /** Cancel pending poll timer (called on disconnect). */
  stopPolling(): void {
    this.#pollScheduler.cancel();
  }

  #schedulePoll(): void {
    this.#pollScheduler.scheduleNext(async () => {
      this.dispatchManifestPoll();
    });
  }
}

// ─── Step-5 TBS builder ───────────────────────────────────────────────────────

const TBS_LABEL = "cello-directory-auth-challenge-v1\n";

/**
 * Build the TBS (to-be-signed) bytes for step-5 directory identity verification.
 *
 * Authoritative format:
 *   UTF-8('cello-directory-auth-challenge-v1\n') +
 *   UTF-8(nodeId) + '\n' + UTF-8(agentPubkeyHex) + '\n' +
 *   UTF-8(nonceHex) + '\n' + UTF-8(isoTimestamp)
 *
 * Crypto reference: RFC 8032 (the signing input is these bytes verbatim).
 */
export function buildStep5Tbs(opts: {
  nodeId: string;
  agentPubkeyHex: string;
  nonceHex: string;
  isoTimestamp: string;
}): Uint8Array {
  const enc = new TextEncoder();
  const str = TBS_LABEL + opts.nodeId + "\n" + opts.agentPubkeyHex + "\n" + opts.nonceHex + "\n" + opts.isoTimestamp;
  return enc.encode(str);
}

// ─── Result type ──────────────────────────────────────────────────────────────

export type ProcessStep5Result =
  | { verified: true }
  | { verified: false; reason: string };
