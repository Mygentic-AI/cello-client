/**
 * CELLO SignalingManager — directory signaling stream lifecycle + step-6 auth + manifest polling.
 *
 * Owns:
 * - Heartbeat keepalive (ping every N seconds, pong timeout N seconds)
 * - Exponential backoff reconnect (1s → maxBackoffMs cap, max N attempts)
 * - directory_signaling status observable: 'connected' | 'reconnecting' | 'lost'
 * - Outbound operation queue during reconnect (bounded FIFO)
 * - Step-6 directory challenge verification (MANIFEST-002, RFC 8032)
 * - Background manifest polling
 *
 * Connection lifecycle pseudocode:
 * 1. constructor(opts):
 *    a. Store config (heartbeat/backoff/queue params)
 *    b. Set status = 'reconnecting'
 *    c. Begin connection loop immediately (no pre-attempt state)
 *
 * 2. connectionLoop():
 *    a. Call connect() (injectable — full 7-step handshake in prod)
 *    b. On success: set status = 'connected', log directory.signaling.connected,
 *       drain outbound queue, then start heartbeat loop
 *    c. On failure: log directory.signaling.reconnecting with attempt/backoffMs,
 *       wait backoffMs, increment attempt. If attempt > max, transition to 'lost'.
 *
 * 3. heartbeatLoop():
 *    a. Every heartbeatIntervalMs, send { type: 'ping', ts: counter++ }
 *    b. Start pong timeout timer (heartbeatTimeoutMs)
 *    c. On pong received: reset timeout timer
 *    d. On timeout: declare stream dead, transition to 'reconnecting'
 *    e. On send error: declare stream dead immediately
 *
 * 4. submitMcpOperation():
 *    a. If 'connected': return { ok: true }
 *    b. If 'reconnecting': return { ok: false, reason: 'signaling_reconnecting', guidance }
 *    c. If 'lost': return { ok: false, reason: 'signaling_lost', guidance }
 *
 * 5. submitInternalOperation(execute):
 *    a. If 'connected': execute immediately, return result
 *    b. If 'reconnecting' + queue not full: queue, return pending promise
 *    c. If 'reconnecting' + queue full: return { ok: false, reason: 'signaling_queue_full' }
 *    d. If 'lost': return { ok: false, reason: 'signaling_lost', guidance }
 *
 * 6. drainQueue():
 *    a. For each queued op in FIFO order: call execute(), resolve/reject caller promise
 *    b. On execute() failure: reject that op, continue with next
 *
 * 7. flushQueue(reason):
 *    a. Reject all pending ops with the given error response
 *    b. Clear queue
 *
 * 8. stop():
 *    a. Set stopped = true
 *    b. Cancel backoff wait (if in progress)
 *    c. Cancel heartbeat timers
 *    d. Close current stream (if any)
 *    e. Flush queue with shutdown error
 *    f. Do NOT transition to 'lost'
 *
 * Step-6 directory challenge verification (RFC 8032):
 *   processStep5Frame() is called inside production connect() after auth_ok.
 *   TBS format (authoritative):
 *     UTF-8('cello-directory-auth-challenge-v1\n') +
 *     UTF-8(nodeId) + '\n' + UTF-8(agentPubkeyHex) + '\n' +
 *     UTF-8(nonceHex) + '\n' + UTF-8(isoTimestamp)
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

// Subset of daemon's Logger (daemon also has debug). Defined locally because transport
// must not depend on daemon. TypeScript structural typing ensures compatibility —
// a daemon Logger satisfies this interface.
export interface Logger {
  info(event: string, context: Record<string, unknown>): void;
  warn(event: string, context: Record<string, unknown>): void;
  error(event: string, context: Record<string, unknown>): void;
}

// Keep the named alias used by MANIFEST-002 tests
export type SignalingLogger = Logger;

// ─── ISignalingOutboundQueue ──────────────────────────────────────────────────

export interface ISignalingOutboundQueue {
  enqueue(frame: Record<string, unknown>): void;
}

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
 * nodeId/signature/timestamp are optional — pre-MANIFEST-002 directories omit them.
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

// ─── SignalingStream interface (what connect() returns) ───────────────────────

export interface SignalingStream {
  send(frame: unknown): Promise<void>;
  onMessage(handler: (frame: unknown) => void): void;
  close(): void;
}

// ─── Connect result ───────────────────────────────────────────────────────────

export interface ConnectResult {
  stream: SignalingStream;
  directoryNodeId: string;
  manifestVersion: number;
}

// ─── Operation result types ───────────────────────────────────────────────────

export interface OperationSuccess {
  ok: true;
}

export type SignalingFailureReason =
  | "signaling_reconnecting"
  | "signaling_lost"
  | "signaling_queue_full"
  | "signaling_shutdown";

export interface OperationFailure {
  ok: false;
  reason: SignalingFailureReason;
  guidance: string;
}

export type OperationResult = OperationSuccess | OperationFailure;

// ─── Step-5 result type ───────────────────────────────────────────────────────

export type ProcessStep5Result =
  | { verified: true }
  | { verified: false; reason: string };

// ─── Pending operation in the queue ──────────────────────────────────────────

interface PendingOperation {
  execute: () => Promise<unknown>;
  resolve: (result: unknown) => void;
  reject: (error: unknown) => void;
}

// ─── Configuration ────────────────────────────────────────────────────────────

export interface SignalingManagerOptions {
  connect?: () => Promise<ConnectResult>;
  logger: Logger;
  heartbeatIntervalMs?: number;
  heartbeatTimeoutMs?: number;
  maxReconnectAttempts?: number;
  initialBackoffMs?: number;
  maxBackoffMs?: number;
  outboundQueueCap?: number;
  // Step-6 directory challenge verification (optional — skipped when absent)
  challengeVerifier?: IDirectoryChallengeVerifier;
  // Manifest polling (optional — skipped when absent)
  pollScheduler?: IManifestPollScheduler;
  manifestVersionStore?: IManifestVersionStore;
  manifestProvider?: IManifestProvider;
  outboundQueue?: ISignalingOutboundQueue;
  correlationId?: string;
  rootKeys?: readonly string[];
  threshold?: number;
}

// Keep the named config type used by MANIFEST-002 tests
export type SignalingManagerConfig = SignalingManagerOptions;

// ─── Guidance strings ─────────────────────────────────────────────────────────

const GUIDANCE_RECONNECTING =
  "The directory signaling stream is reconnecting. The daemon reconnects automatically — wait for directory_signaling to show connected in cello status before retrying this operation.";

const GUIDANCE_LOST =
  "The daemon has lost its connection to the directory and automatic reconnection has failed. Check network connectivity, then run cello logout followed by cello login to restart the directory connection.";

const GUIDANCE_QUEUE_FULL =
  "The internal operation queue is at capacity (64 operations pending). The daemon is reconnecting — wait for directory_signaling to show connected in cello status.";

const GUIDANCE_SHUTDOWN =
  "The daemon is shutting down. All pending operations have been cancelled.";

// ─── SignalingManager ─────────────────────────────────────────────────────────

type SignalingStatus = "connected" | "reconnecting" | "lost";

export class SignalingManager {
  private _status: SignalingStatus = "reconnecting";
  private _stopped = false;
  private _currentStream: SignalingStream | null = null;
  private _currentDirectoryNodeId: string | null = null;
  private _queue: PendingOperation[] = [];
  private _pingCounter = 0;
  private _heartbeatInterval: ReturnType<typeof setInterval> | null = null;
  private _heartbeatTimeout: ReturnType<typeof setTimeout> | null = null;
  private _backoffTimeout: ReturnType<typeof setTimeout> | null = null;
  private _backoffResolve: (() => void) | null = null;
  private _draining = false;

  // Connection lifecycle config
  private readonly _connect: () => Promise<ConnectResult>;
  private readonly _logger: Logger;
  private readonly _heartbeatIntervalMs: number;
  private readonly _heartbeatTimeoutMs: number;
  private readonly _maxReconnectAttempts: number;
  private readonly _initialBackoffMs: number;
  private readonly _maxBackoffMs: number;
  private readonly _outboundQueueCap: number;

  // Step-6 challenge verification state (MANIFEST-002)
  private readonly _challengeVerifier: IDirectoryChallengeVerifier | undefined;
  private _pendingNonce: string | null = null;
  private _agentPubkeyHex: string | null = null;

  // M7-SESSION-001: registered inbound message handlers.
  // Handlers are called for every inbound frame not consumed by built-in logic.
  private _inboundHandlers: Array<(frame: Record<string, unknown>) => void> = [];

  // Manifest polling state (MANIFEST-002)
  private readonly _pollScheduler: IManifestPollScheduler | undefined;
  private readonly _manifestVersionStore: IManifestVersionStore | undefined;
  private readonly _manifestProvider: IManifestProvider | undefined;
  private readonly _outboundQueue: ISignalingOutboundQueue | undefined;
  private readonly _correlationId: string;
  private readonly _rootKeys: readonly string[];
  private readonly _threshold: number;

  constructor(opts: SignalingManagerOptions) {
    this._connect = opts.connect ?? (() => Promise.reject(new Error("no_connect_configured")));
    this._logger = opts.logger;
    this._heartbeatIntervalMs = opts.heartbeatIntervalMs ?? 15_000;
    this._heartbeatTimeoutMs = opts.heartbeatTimeoutMs ?? 15_000;
    this._maxReconnectAttempts = opts.maxReconnectAttempts ?? 10;
    this._initialBackoffMs = opts.initialBackoffMs ?? 1_000;
    this._maxBackoffMs = opts.maxBackoffMs ?? 60_000;
    this._outboundQueueCap = opts.outboundQueueCap ?? 64;

    // MANIFEST-002 optional fields
    this._challengeVerifier = opts.challengeVerifier;
    this._pollScheduler = opts.pollScheduler;
    this._manifestVersionStore = opts.manifestVersionStore;
    this._manifestProvider = opts.manifestProvider;
    this._outboundQueue = opts.outboundQueue;
    this._correlationId = opts.correlationId ?? "";
    this._rootKeys = opts.rootKeys ?? [];
    this._threshold = opts.threshold ?? 0;

    // Begin connection immediately — status starts as 'reconnecting'
    void this.reconnectLoop();
  }

  // ─── Public API — connection status ─────────────────────────────────────────

  get status(): SignalingStatus {
    return this._status;
  }

  get queueDepth(): number {
    return this._queue.length;
  }

  /**
   * M7-SESSION-001: Send a frame directly on the active signaling stream.
   * Returns ok:true when connected and send succeeded.
   * Returns ok:false with reason when not connected or send failed.
   */
  async sendRaw(frame: unknown): Promise<OperationResult> {
    if (this._status !== "connected" || !this._currentStream) {
      if (this._status === "reconnecting") {
        return { ok: false, reason: "signaling_reconnecting", guidance: GUIDANCE_RECONNECTING };
      }
      return { ok: false, reason: "signaling_lost", guidance: GUIDANCE_LOST };
    }
    try {
      await this._currentStream.send(frame);
      return { ok: true };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return { ok: false, reason: "signaling_lost", guidance: `Send failed: ${msg}` };
    }
  }

  /**
   * M7-SESSION-001: Register a handler for inbound signaling frames.
   * Called for every frame not consumed by the built-in heartbeat/manifest logic.
   * Returns an unregister function.
   */
  registerInboundHandler(handler: (frame: Record<string, unknown>) => void): () => void {
    this._inboundHandlers.push(handler);
    return () => {
      const idx = this._inboundHandlers.indexOf(handler);
      if (idx !== -1) this._inboundHandlers.splice(idx, 1);
    };
  }

  /**
   * Submit an MCP tool call operation.
   * When connected: returns { ok: true }.
   * When reconnecting/lost: returns immediately with rejection + guidance.
   * NEVER queued.
   */
  async submitMcpOperation(): Promise<OperationResult> {
    if (this._status === "connected") {
      return { ok: true };
    }
    if (this._status === "reconnecting") {
      return { ok: false, reason: "signaling_reconnecting", guidance: GUIDANCE_RECONNECTING };
    }
    return { ok: false, reason: "signaling_lost", guidance: GUIDANCE_LOST };
  }

  /**
   * Submit an internal protocol operation (FROST ceremony, manifest poll).
   * When connected: executes immediately, returns result.
   * When reconnecting: queues if capacity allows, returns pending promise.
   * When lost: rejects immediately.
   * When queue full: rejects immediately with signaling_queue_full.
   */
  submitInternalOperation<T>(execute: () => Promise<T>): Promise<T | OperationFailure> {
    if (this._status === "connected" && !this._draining) {
      return execute();
    }

    if (this._status === "lost") {
      return Promise.resolve({ ok: false as const, reason: "signaling_lost", guidance: GUIDANCE_LOST });
    }

    if (this._status === "reconnecting" || this._draining) {
      if (this._queue.length >= this._outboundQueueCap) {
        return Promise.resolve({ ok: false as const, reason: "signaling_queue_full", guidance: GUIDANCE_QUEUE_FULL });
      }

      return new Promise<T | OperationFailure>((resolve, reject) => {
        this._queue.push({
          execute: execute as () => Promise<unknown>,
          resolve: resolve as (result: unknown) => void,
          reject,
        });
      });
    }

    return Promise.resolve({ ok: false as const, reason: "signaling_lost", guidance: GUIDANCE_LOST });
  }

  /**
   * Graceful shutdown. Cancels reconnect loop, flushes queue with shutdown error.
   * Does NOT transition to 'lost'.
   */
  async stop(): Promise<void> {
    this._stopped = true;
    this.cancelHeartbeat();
    this.cancelBackoffWait();

    if (this._currentStream) {
      this._currentStream.close();
      this._currentStream = null;
    }

    if (this._streamDeathResolve) {
      this._streamDeathResolve();
      this._streamDeathResolve = null;
    }

    if (this._pollScheduler) {
      this._pollScheduler.cancel();
    }

    this.flushQueue("signaling_shutdown", GUIDANCE_SHUTDOWN);
  }

  // ─── Public API — step-6 challenge verification (MANIFEST-002) ───────────────

  /**
   * Store the nonce and agent pubkey from handshake steps 2–3.
   * Must be called before processStep5Frame().
   */
  setHandshakeContext(nonceHex: string, agentPubkeyHex: string): void {
    this._pendingNonce = nonceHex;
    this._agentPubkeyHex = agentPubkeyHex;
  }

  /**
   * Process a signaling_auth_ok frame (step 6 of the 7-step handshake).
   * Called inside production connect() after receiving auth_ok.
   *
   * Pseudocode (RFC 8032 — Ed25519 verify):
   *   1. If frame has no nodeId/signature/timestamp: log warn, return no_identity_proof.
   *   2. Validate handshake context was set.
   *   3. Build TBS bytes.
   *   4. Call challengeVerifier.verifyChallenge(nodeId, tbsBytes, signature).
   *   5. Log directory.auth.challenge.verified (INFO) or directory.auth.challenge.failed (ERROR).
   */
  processStep5Frame(frame: SignalingAuthOkFrame): ProcessStep5Result {
    if (!this._challengeVerifier) {
      return { verified: false, reason: "no_challenge_verifier" };
    }

    const { nodeId, signature, timestamp } = frame;

    if (!nodeId || !signature || !timestamp) {
      this._logger.warn("directory.auth.challenge.skipped", {
        correlationId: this._correlationId,
        reason: "no_identity_proof",
        hasNodeId: !!nodeId,
        hasSignature: !!signature,
        hasTimestamp: !!timestamp,
      });
      return { verified: false, reason: "no_identity_proof" };
    }

    // Consume nonce and pubkey immediately — nonces are single-use.
    // Clearing before verification prevents stale-nonce reuse across reconnects (SI-003).
    const pendingNonce = this._pendingNonce;
    const agentPubkeyHex = this._agentPubkeyHex;
    this._pendingNonce = null;
    this._agentPubkeyHex = null;

    if (pendingNonce === null || agentPubkeyHex === null) {
      this._logger.error("directory.auth.challenge.failed", {
        correlationId: this._correlationId,
        nodeId,
        reason: "handshake_context_missing",
      });
      return { verified: false, reason: "handshake_context_missing" };
    }

    const tbsBytes = buildStep5Tbs({
      nodeId,
      agentPubkeyHex,
      nonceHex: pendingNonce,
      isoTimestamp: timestamp,
    });

    const result = this._challengeVerifier.verifyChallenge(nodeId, tbsBytes, signature);

    if (result.valid) {
      this._logger.info("directory.auth.challenge.verified", {
        correlationId: this._correlationId,
        nodeId,
      });
      return { verified: true };
    } else {
      this._logger.error("directory.auth.challenge.failed", {
        correlationId: this._correlationId,
        nodeId,
        reason: result.reason,
      });
      return { verified: false, reason: result.reason };
    }
  }

  // ─── Public API — manifest polling (MANIFEST-002) ────────────────────────────

  /**
   * Handle a manifest_poll_response frame from the directory.
   */
  async handleManifestPollResponse(manifest: ConsortiumManifest): Promise<void> {
    if (!this._manifestProvider || !this._manifestVersionStore) return;

    const verifyResult = verifyManifest(
      manifest as unknown as ConsortiumManifestInput,
      this._rootKeys,
      this._threshold,
    );
    if (!verifyResult.ok) {
      this._logger.error("directory.auth.manifest.signature.invalid", {
        correlationId: this._correlationId,
        manifestVersion: manifest.version,
        reason: verifyResult.reason,
        detail: verifyResult.detail,
      });
      this.#schedulePoll();
      return;
    }

    const now = new Date();
    const notBefore = new Date(manifest.not_before);
    if (now < notBefore) {
      this._logger.warn("directory.auth.manifest.not.yet.valid", {
        correlationId: this._correlationId,
        manifestVersion: manifest.version,
        notBefore: manifest.not_before,
      });
      this.#schedulePoll();
      return;
    }

    const expiresAt = new Date(manifest.expires);
    if (expiresAt <= now) {
      this._logger.error("directory.auth.manifest.expired", {
        correlationId: this._correlationId,
        manifestVersion: manifest.version,
        expiresAt: manifest.expires,
      });
      this.#schedulePoll();
      return;
    }

    const lastSeen = await this._manifestVersionStore.getLastSeenVersion();

    if (lastSeen !== null && manifest.version < lastSeen) {
      this._logger.warn("directory.auth.manifest.version.rollback", {
        correlationId: this._correlationId,
        manifestVersion: manifest.version,
        lastSeenVersion: lastSeen,
      });
      this.#schedulePoll();
      return;
    }

    if (lastSeen !== null && manifest.version === lastSeen) {
      this.#schedulePoll();
      return;
    }

    const oldVersion = this._manifestProvider.getCurrentManifest()?.version ?? null;
    this._manifestProvider.updateManifest(manifest);
    await this._manifestVersionStore.persistVersion(manifest.version);

    this._logger.info("directory.auth.manifest.poll.success", {
      correlationId: this._correlationId,
      oldVersion,
      newVersion: manifest.version,
    });

    this.#schedulePoll();
  }

  /** Dispatch a manifest_poll_request frame over the signaling stream. */
  dispatchManifestPoll(): void {
    if (!this._outboundQueue) return;
    this._outboundQueue.enqueue({ type: "manifest_poll_request" });
    this._logger.info("directory.auth.manifest.poll.dispatched", {
      correlationId: this._correlationId,
    });
  }

  /** Start background polling after step-6 authentication completes. */
  startPolling(): void {
    this.#schedulePoll();
  }

  /** Cancel pending poll timer (called on disconnect). */
  stopPolling(): void {
    this._pollScheduler?.cancel();
  }

  #schedulePoll(): void {
    if (!this._pollScheduler) return;
    this._pollScheduler.scheduleNext(async () => {
      this.dispatchManifestPoll();
    });
  }

  // ─── Private: Connection Loop ─────────────────────────────────────────────────

  private async reconnectLoop(): Promise<void> {
    const initialResult = await this.attemptConnect();
    if (!initialResult) return; // stopped

    if (initialResult.success) {
      await this.runConnectedPhase(initialResult.result!);
      if (this._stopped) return;
    }

    await this.runReconnectCycle(initialResult.success ? this._lastDisconnectReason : initialResult.error!);
  }

  private async runReconnectCycle(initialError?: string): Promise<void> {
    let lastError = initialError ?? "";

    for (let attempt = 1; attempt <= this._maxReconnectAttempts; attempt++) {
      if (this._stopped) return;

      const backoffMs = Math.min(
        this._initialBackoffMs * (2 ** (attempt - 1)),
        this._maxBackoffMs,
      );

      this._logger.info("directory.signaling.reconnecting", {
        attempt,
        backoffMs,
        directoryNodeId: this._currentDirectoryNodeId ?? "unknown",
      });

      const cancelled = await this.backoffWait(backoffMs);
      if (cancelled) return;
      if (this._stopped) return;

      const connectResult = await this.attemptConnect();
      if (!connectResult) return;

      if (connectResult.success) {
        await this.runConnectedPhase(connectResult.result!);
        if (this._stopped) return;
        return this.runReconnectCycle();
      }

      lastError = connectResult.error!;
    }

    if (this._stopped) return;

    this._logger.error("directory.signaling.reconnect.failed", {
      attempt: this._maxReconnectAttempts,
      maxAttempts: this._maxReconnectAttempts,
      lastError,
    });
    this._status = "lost";
    this.flushQueue("signaling_lost", GUIDANCE_LOST);
  }

  private async attemptConnect(): Promise<
    | { success: true; result: ConnectResult; error?: undefined }
    | { success: false; result?: undefined; error: string }
    | null
  > {
    try {
      const result = await this._connect();
      if (this._stopped) {
        result.stream.close();
        return null;
      }
      return { success: true, result };
    } catch (err: unknown) {
      if (this._stopped) return null;
      const errorMessage = err instanceof Error ? err.message : String(err);
      return { success: false, error: errorMessage };
    }
  }

  private async runConnectedPhase(result: ConnectResult): Promise<void> {
    this._currentStream = result.stream;
    this._currentDirectoryNodeId = result.directoryNodeId;
    this._status = "connected";

    this._logger.info("directory.signaling.connected", {
      directoryNodeId: result.directoryNodeId,
      manifestVersion: result.manifestVersion,
    });

    result.stream.onMessage((frame: unknown) => {
      this.handleMessage(frame);
    });

    // Drain queue before starting heartbeat. Starting heartbeat first creates a
    // race: if the heartbeat interval fires during a slow drain, declareStreamDead
    // may be called before waitForStreamDeath() has set _streamDeathResolve.
    await this.drainQueue();

    if (this._stopped) return;

    this.startHeartbeat();

    await this.waitForStreamDeath();

    if (this._stopped) return;

    this.stopPolling();
    this._status = "reconnecting";
  }

  // ─── Private: Heartbeat ───────────────────────────────────────────────────────

  private startHeartbeat(): void {
    this._heartbeatInterval = setInterval(() => {
      this.sendPing();
    }, this._heartbeatIntervalMs);
  }

  private async sendPing(): Promise<void> {
    if (!this._currentStream || this._stopped) return;

    this._pingCounter++;
    const frame = { type: "ping", ts: this._pingCounter };

    try {
      await this._currentStream.send(frame);
      if (!this._heartbeatTimeout) {
        this._heartbeatTimeout = setTimeout(() => {
          this._heartbeatTimeout = null;
          this.declareStreamDead("heartbeat_timeout");
        }, this._heartbeatTimeoutMs);
      }
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      this.declareStreamDead(errorMessage);
    }
  }

  private handleMessage(frame: unknown): void {
    if (typeof frame !== "object" || frame === null) return;
    const f = frame as Record<string, unknown>;

    if (f.type === "pong") {
      if (this._heartbeatTimeout) {
        clearTimeout(this._heartbeatTimeout);
        this._heartbeatTimeout = null;
      }
      return;
    }

    if (f.type === "manifest_poll_response" && f.manifest) {
      void this.handleManifestPollResponse(f.manifest as ConsortiumManifest);
      return;
    }

    // M7-SESSION-001: dispatch to registered inbound handlers (e.g. seal_interrupted_ack/rejection)
    if (this._inboundHandlers.length > 0) {
      for (const handler of this._inboundHandlers) {
        try {
          handler(f);
        } catch (err: unknown) {
          this._logger.error("signaling.inbound.handler.error", {
            frameType: typeof f.type === "string" ? f.type : "unknown",
            error: err instanceof Error ? err.message : String(err),
          });
        }
      }
    }
  }

  private cancelHeartbeat(): void {
    if (this._heartbeatInterval) {
      clearInterval(this._heartbeatInterval);
      this._heartbeatInterval = null;
    }
    if (this._heartbeatTimeout) {
      clearTimeout(this._heartbeatTimeout);
      this._heartbeatTimeout = null;
    }
  }

  // ─── Private: Stream death ────────────────────────────────────────────────────

  private _streamDeathResolve: (() => void) | null = null;
  private _lastDisconnectReason = "";

  private waitForStreamDeath(): Promise<void> {
    return new Promise((resolve) => {
      this._streamDeathResolve = resolve;
    });
  }

  private declareStreamDead(reason: string): void {
    if (this._status !== "connected") return;

    this._lastDisconnectReason = reason;
    this.cancelHeartbeat();

    this._logger.warn("directory.signaling.disconnected", {
      directoryNodeId: this._currentDirectoryNodeId ?? "unknown",
      reason,
    });

    if (this._currentStream) {
      this._currentStream.close();
      this._currentStream = null;
    }

    if (this._streamDeathResolve) {
      this._streamDeathResolve();
      this._streamDeathResolve = null;
    }
  }

  // ─── Private: Backoff ─────────────────────────────────────────────────────────

  private backoffWait(ms: number): Promise<boolean> {
    return new Promise((resolve) => {
      this._backoffResolve = () => resolve(true);
      this._backoffTimeout = setTimeout(() => {
        this._backoffResolve = null;
        this._backoffTimeout = null;
        resolve(false);
      }, ms);
    });
  }

  private cancelBackoffWait(): void {
    if (this._backoffTimeout) {
      clearTimeout(this._backoffTimeout);
      this._backoffTimeout = null;
    }
    if (this._backoffResolve) {
      this._backoffResolve();
      this._backoffResolve = null;
    }
  }

  // ─── Private: Queue ───────────────────────────────────────────────────────────

  private async drainQueue(): Promise<void> {
    this._draining = true;
    while (this._queue.length > 0) {
      const op = this._queue.shift()!;
      try {
        const result = await op.execute();
        op.resolve(result);
      } catch (err: unknown) {
        op.reject(err);
      }
    }
    this._draining = false;
  }

  private flushQueue(reason: SignalingFailureReason, guidance: string): void {
    const response: OperationFailure = { ok: false, reason, guidance };
    for (const op of this._queue) {
      op.resolve(response);
    }
    this._queue = [];
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
