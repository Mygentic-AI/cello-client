/**
 * ConnectionManager — CONNREQ-002, CONNREQ-003
 *
 * Extracted from CelloClientImpl. Handles connection establishment,
 * inbound connection requests, disclosure rounds, and connection state.
 */

import { Encoder } from "cbor-x";
import * as lp from "it-length-prefixed";
import {
  decodeConnectionPackage, validateConnectionPackage,
} from "@cello-protocol/protocol-types";
import { mlDsaVerify } from "@cello-protocol/crypto";
import type { Stream } from "@libp2p/interface";
import type { Logger } from "@cello-protocol/interfaces";
import type { ClientStatePersistence } from "./client-state-persistence.js";

const CBOR_ENC = new Encoder({ tagUint8Array: false });

type ConnectionReport = import("./connection-policy.js").ConnectionReport;
type SignalRequirementPolicy = import("./connection-policy.js").SignalRequirementPolicy;
type ClientConnectionRecord = import("@cello-protocol/protocol-types").ClientConnectionRecord;
type ConnectionRequestInbound = import("@cello-protocol/protocol-types").ConnectionRequestInbound;
type ConnectionEstablished = import("@cello-protocol/protocol-types").ConnectionEstablished;
type DisclosureRequestInbound = import("@cello-protocol/protocol-types").DisclosureRequestInbound;

type PendingInboundRequest = {
  connection_request_id: string;
  from_pubkey: string;
  package_cbor: Uint8Array;
  round: number;
};

export type ReviewQueueItem = {
  connection_request_id: string;
  from_pubkey: string;
  report: Extract<ConnectionReport, { verdict: "pending_agent_review" }>;
  package_cbor: Uint8Array;
  sender_registered_at: number;
  sender_is_provisional: boolean;
};

type AwaitItem = {
  connection_request_id: string;
  from_pubkey: string;
  report: Extract<ConnectionReport, { verdict: "pending_agent_review" }>;
};

/**
 * Narrow interface exposing only what ConnectionManager needs from CelloClientImpl.
 */
export interface ConnectionContext {
  readonly logger: Logger;
  readonly persistence: ClientStatePersistence | null;
  readonly connectionTimeoutMs: number;
  readonly round2TimeoutMs: number;
  readonly trackEvaluateCount: boolean;
  readonly whitelist: string[];
  readonly crossCheckDirectoryOnInbound: boolean;
  readonly connectionPolicy: SignalRequirementPolicy | undefined;
  readonly onConnectionPendingReview: ((event: ConnectionRequestInbound) => void) | undefined;
  readonly onConnectionEstablishedHandler: ((event: ConnectionEstablished) => void) | undefined;
  readonly onDisclosureRequestedHandler: ((event: DisclosureRequestInbound) => void) | undefined;
  getPersistentSignalingStream(): Stream | null;
  openPersistentSignalingStream(): Promise<boolean>;
  getConnectionsByPeer(): Map<string, string>;
  getConnections(): Map<string, ClientConnectionRecord>;
  getProfileUncheckedPeers(): Set<string>;
  incrementEvaluateCallCount(): void;
}

export class ConnectionManager {
  readonly #ctx: ConnectionContext;

  // Connection state (owned by this manager)
  readonly #pendingConnectionRequestResolvers = new Map<string, (frame: Record<string, unknown>) => void>();
  readonly #pendingAwaitConnectionRequestResolvers: Array<(item: AwaitItem) => void> = [];
  readonly #pendingDisclosureResolvers = new Map<string, (result: Record<string, unknown>) => void>();
  readonly #pendingInboundRequests = new Map<string, PendingInboundRequest>();
  readonly #pendingReviewQueue: ReviewQueueItem[] = [];
  readonly #decidedRequests = new Set<string>();

  constructor(ctx: ConnectionContext) {
    this.#ctx = ctx;
  }

  get pendingConnectionRequestResolverCount(): number {
    return this.#pendingConnectionRequestResolvers.size;
  }

  // ─── Public API methods ─────────────────────────────────────────────────────

  async acceptConnection(connectionRequestId: string): Promise<
    | { accepted: true; connection_id: string }
    | { error: { reason: "no_pending_request" | "already_decided" } }
  > {
    const pending = this.#pendingInboundRequests.get(connectionRequestId);
    if (!pending) {
      if (this.#decidedRequests.has(connectionRequestId)) {
        return { error: { reason: "already_decided" } };
      }
      return { error: { reason: "no_pending_request" } };
    }
    if (this.#decidedRequests.has(connectionRequestId)) {
      return { error: { reason: "already_decided" } };
    }

    // Mark as decided before sending to prevent races
    this.#decidedRequests.add(connectionRequestId);
    this.#pendingInboundRequests.delete(connectionRequestId);
    // CRIT-2: persist decision
    if (this.#ctx.persistence) {
      void this.#ctx.persistence.decidePendingConnectionRequest(connectionRequestId, "accepted");
    }

    const stream = this.#ctx.getPersistentSignalingStream();
    if (!stream) {
      // Stream gone — still mark as decided
      return { error: { reason: "no_pending_request" } };
    }

    const responseFrame = CBOR_ENC.encode({
      type: "connection_response",
      connection_request_id: connectionRequestId,
      verdict: "accept",
    }) as Uint8Array;

    try {
      stream.send(lp.encode.single(responseFrame));
    } catch {
      return { error: { reason: "no_pending_request" } };
    }

    // Wait for connection_established to arrive via the signaling reader loop.
    const deadline = Date.now() + this.#ctx.connectionTimeoutMs;
    while (Date.now() < deadline) {
      const connectionId = this.#ctx.getConnectionsByPeer().get(pending.from_pubkey);
      if (connectionId) {
        return { accepted: true, connection_id: connectionId };
      }
      const remaining = deadline - Date.now();
      if (remaining <= 0) break;
      await new Promise<void>((resolve) => setTimeout(resolve, Math.min(20, remaining)));
    }

    return { error: { reason: "no_pending_request" } };
  }

  async rejectConnection(connectionRequestId: string, reason?: string): Promise<
    | { rejected: true }
    | { error: { reason: "no_pending_request" | "already_decided" } }
  > {
    const pending = this.#pendingInboundRequests.get(connectionRequestId);
    if (!pending) {
      if (this.#decidedRequests.has(connectionRequestId)) {
        return { error: { reason: "already_decided" } };
      }
      return { error: { reason: "no_pending_request" } };
    }
    if (this.#decidedRequests.has(connectionRequestId)) {
      return { error: { reason: "already_decided" } };
    }

    // Mark as decided
    this.#decidedRequests.add(connectionRequestId);
    this.#pendingInboundRequests.delete(connectionRequestId);
    // CRIT-2: persist decision
    if (this.#ctx.persistence) {
      void this.#ctx.persistence.decidePendingConnectionRequest(connectionRequestId, "rejected");
    }

    const stream = this.#ctx.getPersistentSignalingStream();
    if (!stream) {
      return { rejected: true };
    }

    const payload: Record<string, unknown> = {
      type: "connection_response",
      connection_request_id: connectionRequestId,
      verdict: "reject",
    };
    if (reason !== undefined) payload["reason"] = reason;

    const responseFrame = CBOR_ENC.encode(payload) as Uint8Array;
    try {
      stream.send(lp.encode.single(responseFrame));
    } catch { /* stream closed */ }

    return { rejected: true };
  }

  async requestMoreDisclosure(connectionRequestId: string, requestedItems: unknown[]): Promise<
    | { request_sent: true }
    | { error: { reason: "no_pending_request" | "already_decided" | "max_rounds_reached" } }
  > {
    const pending = this.#pendingInboundRequests.get(connectionRequestId);
    if (!pending) {
      if (this.#decidedRequests.has(connectionRequestId)) {
        return { error: { reason: "already_decided" } };
      }
      return { error: { reason: "no_pending_request" } };
    }
    if (this.#decidedRequests.has(connectionRequestId)) {
      return { error: { reason: "already_decided" } };
    }
    if (pending.round >= 2) {
      return { error: { reason: "max_rounds_reached" } };
    }

    // Advance to Round 2
    pending.round = 2;
    // CRIT-2: persist disclosure decision
    if (this.#ctx.persistence) {
      void this.#ctx.persistence.decidePendingConnectionRequest(connectionRequestId, "more_disclosure");
    }

    const stream = this.#ctx.getPersistentSignalingStream();
    if (!stream) {
      return { error: { reason: "no_pending_request" } };
    }

    const disclosureFrame = CBOR_ENC.encode({
      type: "disclosure_request",
      connection_request_id: connectionRequestId,
      requested_items: requestedItems,
    }) as Uint8Array;

    try {
      stream.send(lp.encode.single(disclosureFrame));
    } catch {
      return { error: { reason: "no_pending_request" } };
    }

    return { request_sent: true };
  }

  async awaitConnectionRequest(timeoutMs = 30_000): Promise<
    | {
        type: "pending_review";
        connection_request_id: string;
        from_pubkey: string;
        report: Extract<ConnectionReport, { verdict: "pending_agent_review" }>;
      }
    | { type: "timeout" }
  > {
    // Fast path: if items already queued, return immediately (no Promise overhead)
    if (this.#pendingReviewQueue.length > 0) {
      const item = this.#pendingReviewQueue.shift()!;
      return {
        type: "pending_review",
        connection_request_id: item.connection_request_id,
        from_pubkey: item.from_pubkey,
        report: item.report,
      };
    }

    // CONNREQ-003: multi-slot await via Promise queue.
    let resolveItem!: (item: AwaitItem) => void;
    const itemPromise = new Promise<AwaitItem>((resolve) => {
      resolveItem = resolve;
    });
    this.#pendingAwaitConnectionRequestResolvers.push(resolveItem);

    const result: { item: AwaitItem | null } = { item: null };
    let timedOut = false;
    await Promise.race([
      itemPromise.then((i) => { result.item = i; }),
      new Promise<void>((resolve) => setTimeout(() => { timedOut = true; resolve(); }, timeoutMs)),
    ]);

    // On timeout: remove our resolver from the queue if it hasn't been consumed yet
    if (timedOut) {
      const idx = this.#pendingAwaitConnectionRequestResolvers.indexOf(resolveItem);
      if (idx !== -1) {
        this.#pendingAwaitConnectionRequestResolvers.splice(idx, 1);
      }
      return { type: "timeout" };
    }

    const item = result.item;
    if (!item) {
      return { type: "timeout" };
    }

    return {
      type: "pending_review",
      connection_request_id: item.connection_request_id,
      from_pubkey: item.from_pubkey,
      report: item.report,
    };
  }

  async cello_request_connection(opts: {
    target_pubkey: string;
    package_cbor: Uint8Array;
    dialTimeoutMs?: number;
    sendTimeoutMs?: number;
    waitTimeoutMs?: number;
  }): Promise<
    | { result: "established"; connection_id: string }
    | { result: "rejected"; reason: string }
    | { result: "insufficient"; unmet_requirements: unknown[] }
    | { result: "disclosure_requested"; connection_request_id: string; requested_items: unknown[] }
    | { result: "timeout"; stage: "dial" | "send" | "wait" }
    | { result: "error"; reason: string }
  > {
    const targetPubkeyHex = opts.target_pubkey;

    // CONNREQ-003 AC-002: reject duplicate concurrent requests to same target immediately.
    if (this.#pendingConnectionRequestResolvers.has(targetPubkeyHex)) {
      this.#ctx.logger.warn("connection.request.duplicate", { targetPubkeyHex });
      return { result: "error", reason: "connection_request_in_flight" };
    }

    // CONNREQ-003: Reserve this target's slot in the map BEFORE any async work.
    let resolveOutcome!: (result: Record<string, unknown>) => void;
    const outcomePromise = new Promise<Record<string, unknown>>((resolve) => {
      resolveOutcome = resolve;
    });
    this.#pendingConnectionRequestResolvers.set(targetPubkeyHex, resolveOutcome);

    // AC-008 (DX-001): per-stage timeouts.
    const dialTimeoutMs = opts.dialTimeoutMs ?? this.#ctx.connectionTimeoutMs;
    const sendTimeoutMs = opts.sendTimeoutMs ?? this.#ctx.connectionTimeoutMs;
    const waitTimeoutMs = opts.waitTimeoutMs ?? this.#ctx.connectionTimeoutMs;

    // Stage 1 — dial: Ensure the persistent signaling stream is open within dialTimeoutMs.
    if (!this.#ctx.getPersistentSignalingStream()) {
      let dialTimedOut = false;
      let opened = false;
      await Promise.race([
        this.#ctx.openPersistentSignalingStream().then((result) => { opened = result; }),
        new Promise<void>((resolve) => setTimeout(() => { dialTimedOut = true; resolve(); }, dialTimeoutMs)),
      ]);
      if (dialTimedOut || !opened) {
        this.#pendingConnectionRequestResolvers.delete(targetPubkeyHex);
        this.#ctx.logger.warn("client.connection.request.stage.timeout", { stage: "dial", timeoutMs: dialTimeoutMs, targetPubkeyOrAgentId: targetPubkeyHex });
        return { result: "timeout", stage: "dial" };
      }
    }

    // Mint a correlationId for this outbound connection request flow.
    const correlationId = `connreq-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`;

    this.#ctx.logger.info("connection.request.sent", { targetPubkeyHex, correlationId });

    // Build the frame
    const frameBytes = CBOR_ENC.encode({
      type: "connection_request",
      target_pubkey: targetPubkeyHex,
      package_cbor: opts.package_cbor,
    }) as Uint8Array;

    // Stage 2 — send: Deliver the frame within sendTimeoutMs.
    let sendTimedOut = false;
    let sendError = false;
    await Promise.race([
      new Promise<void>((resolve) => {
        try {
          this.#ctx.getPersistentSignalingStream()!.send(lp.encode.single(frameBytes));
        } catch {
          sendError = true;
        }
        resolve();
      }),
      new Promise<void>((resolve) => setTimeout(() => { sendTimedOut = true; resolve(); }, sendTimeoutMs)),
    ]);
    if (sendTimedOut) {
      this.#pendingConnectionRequestResolvers.delete(targetPubkeyHex);
      this.#ctx.logger.warn("client.connection.request.stage.timeout", { stage: "send", timeoutMs: sendTimeoutMs, targetPubkeyOrAgentId: targetPubkeyHex });
      return { result: "timeout", stage: "send" };
    }
    if (sendError) {
      this.#pendingConnectionRequestResolvers.delete(targetPubkeyHex);
      return { result: "error", reason: "directory_unreachable" };
    }

    // Stage 3 — wait: Race outcome vs waitTimeoutMs.
    let frame: Record<string, unknown> | null = null;
    let timedOut = false;
    await Promise.race([
      outcomePromise.then((f) => { frame = f; }),
      new Promise<void>((resolve) => setTimeout(() => { timedOut = true; resolve(); }, waitTimeoutMs)),
    ]);

    // Clean up this target's resolver slot on timeout
    if (this.#pendingConnectionRequestResolvers.get(targetPubkeyHex) === resolveOutcome) {
      this.#pendingConnectionRequestResolvers.delete(targetPubkeyHex);
    }

    if (timedOut || !frame) {
      this.#ctx.logger.warn("client.connection.request.stage.timeout", { stage: "wait", timeoutMs: waitTimeoutMs, targetPubkeyOrAgentId: targetPubkeyHex });
      return { result: "timeout", stage: "wait" };
    }

    const type = frame["type"] as string;

    if (type === "connection_established") {
      const connectionId = frame["connection_id"] as string;
      const counterpartyPubkey = frame["counterparty_pubkey"] as string;
      // Store connection record locally
      const record: ClientConnectionRecord = {
        connection_id: connectionId,
        counterparty_pubkey: counterpartyPubkey,
        counterparty_primary_pubkey: "",
        counterparty_ml_dsa_pubkey: "",
        established_at: Date.now(),
        status: "active",
      };
      this.#ctx.getConnections().set(connectionId, record);
      this.#ctx.getConnectionsByPeer().set(counterpartyPubkey, connectionId);
      // PERSIST-024: persist connection to DB
      if (this.#ctx.persistence) {
        void this.#ctx.persistence.persistConnection({
          connectionId,
          counterpartyPubkey,
          establishedAt: record.established_at,
        });
      }
      this.#ctx.logger.info("connection.established", {
        connectionId,
        counterpartyPubkeyHex: counterpartyPubkey,
        correlationId,
      });
      return { result: "established", connection_id: connectionId };
    }

    if (type === "connection_rejected") {
      return { result: "rejected", reason: (frame["reason"] as string) ?? "rejected" };
    }

    if (type === "connection_insufficient") {
      return { result: "insufficient", unmet_requirements: (frame["unmet_requirements"] as unknown[]) ?? [] };
    }

    if (type === "connection_request_error") {
      const reason = (frame["reason"] as string) ?? "unknown";
      // already_connected: hydrate the existing connection so the caller can proceed.
      if (reason === "already_connected" && frame["connection_id"]) {
        const connectionId = frame["connection_id"] as string;
        if (!this.#ctx.getConnections().has(connectionId)) {
          const record: ClientConnectionRecord = {
            connection_id: connectionId,
            counterparty_pubkey: targetPubkeyHex,
            counterparty_primary_pubkey: "",
            counterparty_ml_dsa_pubkey: "",
            established_at: Date.now(),
            status: "active",
          };
          this.#ctx.getConnections().set(connectionId, record);
          this.#ctx.getConnectionsByPeer().set(targetPubkeyHex, connectionId);
          // PERSIST-024: persist connection to DB
          if (this.#ctx.persistence) {
            void this.#ctx.persistence.persistConnection({
              connectionId,
              counterpartyPubkey: targetPubkeyHex,
              establishedAt: record.established_at,
            });
          }
        }
        this.#ctx.logger.info("connection.established", {
          connectionId,
          counterpartyPubkeyHex: targetPubkeyHex,
          correlationId,
        });
        return { result: "established", connection_id: connectionId };
      }
      this.#ctx.logger.error("connection.request.failed", { targetPubkeyHex, reason, correlationId });
      return { result: "error", reason };
    }

    if (type === "disclosure_request_inbound") {
      return {
        result: "disclosure_requested",
        connection_request_id: frame["connection_request_id"] as string,
        requested_items: (frame["requested_items"] as unknown[]) ?? [],
      };
    }

    return { result: "error", reason: "unknown" };
  }

  async cello_respond_to_disclosure_request(opts: {
    connection_request_id: string;
    package_cbor: Uint8Array;
  }): Promise<
    | { result: "established"; connection_id: string }
    | { result: "rejected"; reason: string }
    | { result: "insufficient"; unmet_requirements: unknown[] }
    | { result: "timeout" }
    | { result: "error"; reason: string }
  > {
    const stream = this.#ctx.getPersistentSignalingStream();
    if (!stream) {
      return { result: "error", reason: "directory_unreachable" };
    }

    const frameBytes = CBOR_ENC.encode({
      type: "disclosure_response",
      connection_request_id: opts.connection_request_id,
      package_cbor: opts.package_cbor,
    }) as Uint8Array;

    let resolveOutcome!: (result: Record<string, unknown>) => void;
    const outcomePromise = new Promise<Record<string, unknown>>((resolve) => {
      resolveOutcome = resolve;
    });
    this.#pendingDisclosureResolvers.set(opts.connection_request_id, resolveOutcome);

    try {
      stream.send(lp.encode.single(frameBytes));
    } catch {
      this.#pendingDisclosureResolvers.delete(opts.connection_request_id);
      return { result: "error", reason: "directory_unreachable" };
    }

    let frame: Record<string, unknown> | null = null;
    let timedOut = false;
    await Promise.race([
      outcomePromise.then((f) => { frame = f; }),
      new Promise<void>((resolve) => setTimeout(() => { timedOut = true; resolve(); }, this.#ctx.connectionTimeoutMs)),
    ]);

    this.#pendingDisclosureResolvers.delete(opts.connection_request_id);

    if (timedOut || !frame) {
      return { result: "timeout" };
    }

    const type = frame["type"] as string;

    if (type === "connection_established") {
      const connectionId = frame["connection_id"] as string;
      const counterpartyPubkey = frame["counterparty_pubkey"] as string;
      const establishedAt = Date.now();
      const record: ClientConnectionRecord = {
        connection_id: connectionId,
        counterparty_pubkey: counterpartyPubkey,
        counterparty_primary_pubkey: "",
        counterparty_ml_dsa_pubkey: "",
        established_at: establishedAt,
        status: "active",
      };
      this.#ctx.getConnections().set(connectionId, record);
      this.#ctx.getConnectionsByPeer().set(counterpartyPubkey, connectionId);
      if (this.#ctx.persistence) {
        void this.#ctx.persistence.persistConnection({
          connectionId,
          counterpartyPubkey,
          establishedAt,
        });
      }
      return { result: "established", connection_id: connectionId };
    }

    if (type === "connection_rejected") {
      return { result: "rejected", reason: (frame["reason"] as string) ?? "rejected" };
    }

    if (type === "connection_insufficient") {
      return { result: "insufficient", unmet_requirements: (frame["unmet_requirements"] as unknown[]) ?? [] };
    }

    return { result: "error", reason: "unknown" };
  }

  async cello_request_more_disclosure(opts: {
    connection_request_id: string;
    requested_items: unknown[];
  }): Promise<{ error: "max_rounds_reached" } | { ok: true }> {
    const pending = this.#pendingInboundRequests.get(opts.connection_request_id);
    if (!pending) {
      return { error: "max_rounds_reached" }; // no such request or already completed
    }
    if (pending.round >= 2) {
      return { error: "max_rounds_reached" };
    }

    // Advance to Round 2 state
    pending.round = 2;

    const stream = this.#ctx.getPersistentSignalingStream();
    if (!stream) {
      return { error: "max_rounds_reached" }; // stream gone
    }

    const frameBytes = CBOR_ENC.encode({
      type: "disclosure_request",
      connection_request_id: opts.connection_request_id,
      requested_items: opts.requested_items,
    }) as Uint8Array;

    try {
      stream.send(lp.encode.single(frameBytes));
    } catch {
      return { error: "max_rounds_reached" };
    }

    return { ok: true };
  }

  // ─── State restoration (called by loadPersistedState) ────────────────────────

  /**
   * Restore a decided request ID from persisted state.
   * Called during loadPersistedState to restore the #decidedRequests set.
   */
  restoreDecidedRequest(requestId: string): void {
    this.#decidedRequests.add(requestId);
  }

  /**
   * Restore a pending inbound request from persisted state.
   * Called during loadPersistedState to restore the #pendingInboundRequests map.
   */
  restorePendingInboundRequest(opts: {
    connection_request_id: string;
    from_pubkey: string;
    package_cbor: Uint8Array;
    round: number;
  }): void {
    this.#pendingInboundRequests.set(opts.connection_request_id, {
      connection_request_id: opts.connection_request_id,
      from_pubkey: opts.from_pubkey,
      package_cbor: opts.package_cbor,
      round: opts.round,
    });
  }

  /**
   * Restore a review queue item from persisted state.
   * Called during loadPersistedState to restore the #pendingReviewQueue.
   */
  restoreReviewQueueItem(item: ReviewQueueItem): void {
    this.#pendingReviewQueue.push(item);
  }

  // ─── TEST-ONLY escape hatches ───────────────────────────────────────────────

  _injectPendingConnectionRequest(opts: {
    connection_request_id: string;
    from_pubkey: string;
    package_cbor: Uint8Array;
    round: number;
  }): void {
    this.#pendingInboundRequests.set(opts.connection_request_id, {
      connection_request_id: opts.connection_request_id,
      from_pubkey: opts.from_pubkey,
      package_cbor: opts.package_cbor,
      round: opts.round,
    });
  }

  _injectConnectionFrame(frame: Record<string, unknown>): void {
    const type = frame["type"] as string;
    if (type === "connection_established") {
      const counterpartyPubkey = frame["counterparty_pubkey"] as string;
      const resolve = this.#pendingConnectionRequestResolvers.get(counterpartyPubkey);
      if (resolve) {
        this.#pendingConnectionRequestResolvers.delete(counterpartyPubkey);
        resolve(frame);
      }
    } else if (type === "disclosure_request_inbound") {
      const targetPubkeyForDisclosure = frame["from_pubkey"] as string;
      const resolve = this.#pendingConnectionRequestResolvers.get(targetPubkeyForDisclosure);
      if (resolve) {
        this.#pendingConnectionRequestResolvers.delete(targetPubkeyForDisclosure);
        resolve(frame);
      }
    } else {
      // connection_rejected, connection_insufficient, connection_request_error
      const targetPubkeyForError = frame["target_pubkey"] as string | undefined;
      if (targetPubkeyForError && this.#pendingConnectionRequestResolvers.has(targetPubkeyForError)) {
        const resolve = this.#pendingConnectionRequestResolvers.get(targetPubkeyForError)!;
        this.#pendingConnectionRequestResolvers.delete(targetPubkeyForError);
        resolve(frame);
      } else if (this.#pendingConnectionRequestResolvers.size === 1) {
        const [singleKey, singleResolve] = this.#pendingConnectionRequestResolvers.entries().next().value as [string, (frame: Record<string, unknown>) => void];
        this.#pendingConnectionRequestResolvers.delete(singleKey);
        singleResolve(frame);
      }
    }
  }

  // ─── Signaling reader routing (called by CelloClientImpl signaling reader) ──

  /**
   * Route connection outcome frames from the signaling reader.
   * Called by CelloClientImpl#runPersistentSignalingReader when a connection-related frame arrives.
   */
  routeConnectionFrame(frame: Record<string, unknown>): void {
    const type = frame["type"] as string;

    if (type === "connection_established") {
      // Store connection record locally (applies to both sender A and target B)
      const connectionId = frame["connection_id"] as string;
      const counterpartyPubkey = frame["counterparty_pubkey"] as string;
      if (connectionId && counterpartyPubkey) {
        if (!this.#ctx.getConnections().has(connectionId)) {
          const record: ClientConnectionRecord = {
            connection_id: connectionId,
            counterparty_pubkey: counterpartyPubkey,
            counterparty_primary_pubkey: "",
            counterparty_ml_dsa_pubkey: "",
            established_at: Date.now(),
            status: "active",
          };
          const profileUncheckedPeers = this.#ctx.getProfileUncheckedPeers();
          if (profileUncheckedPeers.has(counterpartyPubkey)) {
            record.profile_unchecked = true;
            profileUncheckedPeers.delete(counterpartyPubkey);
          }
          this.#ctx.getConnections().set(connectionId, record);
          this.#ctx.getConnectionsByPeer().set(counterpartyPubkey, connectionId);
          // PERSIST-024: persist connection to DB
          if (this.#ctx.persistence) {
            void this.#ctx.persistence.persistConnection({
              connectionId,
              counterpartyPubkey,
              establishedAt: record.established_at,
              profileUnchecked: record.profile_unchecked,
            });
          }
        }
        // Fire onConnectionEstablished handler (both A and B)
        const handler = this.#ctx.onConnectionEstablishedHandler;
        if (handler) {
          handler({ type: "connection_established", counterparty_pubkey: counterpartyPubkey, connection_id: connectionId });
        }
      }
      // CONNREQ-003: Route to the resolver for this specific target (keyed by counterparty pubkey).
      const resolve = this.#pendingConnectionRequestResolvers.get(counterpartyPubkey);
      if (resolve) {
        this.#pendingConnectionRequestResolvers.delete(counterpartyPubkey);
        resolve(frame);
      } else {
        // Round 2: route to disclosure resolver if pending (no in-flight connection_request)
        for (const [id, disclosureResolve] of this.#pendingDisclosureResolvers) {
          this.#pendingDisclosureResolvers.delete(id);
          disclosureResolve(frame);
          break;
        }
      }
    } else if (type === "disclosure_request_inbound") {
      // CONNREQ-002 Round 2: target requests more disclosure → fire onDisclosureRequested
      const disclosureHandler = this.#ctx.onDisclosureRequestedHandler;
      if (disclosureHandler) {
        disclosureHandler({
          type: "disclosure_request_inbound",
          from_pubkey: frame["from_pubkey"] as string,
          connection_request_id: frame["connection_request_id"] as string,
          requested_items: (frame["requested_items"] as import("@cello-protocol/protocol-types").DisclosureRequestItem[]) ?? [],
        });
      }
      // CONNREQ-003: disclosure_request_inbound carries from_pubkey (= target).
      const targetPubkeyForDisclosure = frame["from_pubkey"] as string;
      const resolve = this.#pendingConnectionRequestResolvers.get(targetPubkeyForDisclosure);
      if (resolve) {
        this.#pendingConnectionRequestResolvers.delete(targetPubkeyForDisclosure);
        resolve(frame);
      }
    } else {
      // connection_rejected, connection_insufficient, connection_request_error
      const targetPubkeyForError = frame["target_pubkey"] as string | undefined;
      if (targetPubkeyForError && this.#pendingConnectionRequestResolvers.has(targetPubkeyForError)) {
        const resolve = this.#pendingConnectionRequestResolvers.get(targetPubkeyForError)!;
        this.#pendingConnectionRequestResolvers.delete(targetPubkeyForError);
        resolve(frame);
      } else if (this.#pendingConnectionRequestResolvers.size === 1) {
        // Fallback: if exactly one request is in flight and frame has no target_pubkey,
        // route to that single resolver (backward-compatible with pre-CONNREQ-003 directory).
        const [singleKey, singleResolve] = this.#pendingConnectionRequestResolvers.entries().next().value as [string, (frame: Record<string, unknown>) => void];
        this.#pendingConnectionRequestResolvers.delete(singleKey);
        singleResolve(frame);
      } else {
        // Round 2: route to disclosure resolver if pending
        for (const [id, disclosureResolve] of this.#pendingDisclosureResolvers) {
          this.#pendingDisclosureResolvers.delete(id);
          disclosureResolve(frame);
          break;
        }
      }
    }
  }

  /**
   * Unblock all pending connection request resolvers when the signaling stream closes.
   * CONNREQ-003 AC-005.
   */
  unblockAllOnStreamClose(): void {
    for (const [targetPubkey, pendingResolve] of this.#pendingConnectionRequestResolvers) {
      this.#pendingConnectionRequestResolvers.delete(targetPubkey);
      pendingResolve({ type: "connection_request_error", reason: "directory_unreachable", target_pubkey: targetPubkey });
    }
  }

  // ─── Inbound connection request handling ────────────────────────────────────

  async handleInboundConnectionRequest(frame: Record<string, unknown>): Promise<void> {
    const stream = this.#ctx.getPersistentSignalingStream();
    if (!stream) return;

    const connectionRequestId = frame["connection_request_id"] as string;
    const fromPubkey = frame["from_pubkey"] as string;
    const packageCborRaw = frame["package_cbor"];
    const packageCbor = packageCborRaw instanceof Uint8Array ? packageCborRaw
      : Buffer.isBuffer(packageCborRaw) ? new Uint8Array(packageCborRaw as Buffer) : null;

    if (!connectionRequestId || !fromPubkey || !packageCbor) return;

    const senderRegisteredAt = typeof frame["sender_registered_at"] === "number"
      ? frame["sender_registered_at"] : 0;
    const senderIsProvisional = frame["sender_is_provisional"] === true;

    let verdict: "accept" | "reject" | "insufficient" = "reject";
    let rejectReason: string | undefined;
    let unmetRequirements: unknown[] | undefined;

    const isWhitelisted = this.#ctx.whitelist.includes(fromPubkey);

    if (isWhitelisted) {
      verdict = "accept";
    } else if (!this.#ctx.connectionPolicy) {
      // No policy configured — default to accept
      verdict = "accept";
    } else {
      // Decode and validate the package
      let pkg;
      try {
        pkg = decodeConnectionPackage(packageCbor);
      } catch {
        verdict = "reject";
        rejectReason = "package_decode_failed";
        pkg = null;
      }

      if (pkg !== null) {
        const fromPubkeyBytes = Buffer.from(fromPubkey, "hex");
        const validatedPackage = validateConnectionPackage(
          pkg,
          fromPubkeyBytes,
          Date.now(),
          mlDsaVerify,
        );

        if (!validatedPackage.valid) {
          verdict = "reject";
          rejectReason = validatedPackage.reason;
        } else {
        const context: import("@cello-protocol/protocol-types").DirectoryContext = {
          registered_at: senderRegisteredAt,
          is_provisional: senderIsProvisional,
          conversation_count: 0,
          clean_close_rate: 0,
        };

        if (this.#ctx.trackEvaluateCount) {
          this.#ctx.incrementEvaluateCallCount();
        }

        const { evaluateConnectionPackage } = await import("./connection-policy.js");
        const report = evaluateConnectionPackage(
          validatedPackage,
          this.#ctx.connectionPolicy,
          context,
          Date.now(),
        );

        if (report.verdict === "auto_accept") {
          verdict = "accept";
        } else if (report.verdict === "auto_reject") {
          verdict = "reject";
          rejectReason = report.reason;
        } else if (report.verdict === "auto_insufficient") {
          if (this.#ctx.round2TimeoutMs > 0) {
            // Round 2 enabled: send disclosure_request to ask for more
            this.#pendingInboundRequests.set(connectionRequestId, {
              connection_request_id: connectionRequestId,
              from_pubkey: fromPubkey,
              package_cbor: packageCbor,
              round: 1,
            });
            const disclosureFrame = CBOR_ENC.encode({
              type: "disclosure_request",
              connection_request_id: connectionRequestId,
              requested_items: report.unmet_requirements.map((u) => ({
                type: u.signal_type,
                condition: u.condition,
              })),
            }) as Uint8Array;
            try {
              stream.send(lp.encode.single(disclosureFrame));
            } catch { /* stream closed */ }
            setTimeout(() => {
              const stillPending = this.#pendingInboundRequests.get(connectionRequestId);
              if (stillPending) {
                this.#pendingInboundRequests.delete(connectionRequestId);
                const currentStream = this.#ctx.getPersistentSignalingStream();
                if (currentStream) {
                  const timeoutFrame = CBOR_ENC.encode({
                    type: "connection_response",
                    connection_request_id: connectionRequestId,
                    verdict: "reject",
                    reason: "disclosure_timeout",
                  }) as Uint8Array;
                  try {
                    currentStream.send(lp.encode.single(timeoutFrame));
                  } catch { /* stream closed */ }
                }
              }
            }, this.#ctx.round2TimeoutMs);
            return;
          }
          verdict = "insufficient";
          unmetRequirements = report.unmet_requirements;
        } else {
          // pending_agent_review: store for agent review and fire callback
          this.#pendingInboundRequests.set(connectionRequestId, {
            connection_request_id: connectionRequestId,
            from_pubkey: fromPubkey,
            package_cbor: packageCbor,
            round: 1,
          });

          const reviewItem: ReviewQueueItem = {
            connection_request_id: connectionRequestId,
            from_pubkey: fromPubkey,
            report,
            package_cbor: packageCbor,
            sender_registered_at: senderRegisteredAt,
            sender_is_provisional: senderIsProvisional,
          };

          // CONNREQ-003: Deliver to the first waiting awaitConnectionRequest() caller (FIFO),
          // or enqueue in #pendingReviewQueue if no callers are waiting.
          const awaitResolver = this.#pendingAwaitConnectionRequestResolvers.shift();
          if (awaitResolver) {
            awaitResolver({
              connection_request_id: connectionRequestId,
              from_pubkey: fromPubkey,
              report,
            });
          } else {
            this.#pendingReviewQueue.push(reviewItem);
          }

          // CRIT-2: persist pending connection request
          if (this.#ctx.persistence) {
            void this.#ctx.persistence.persistPendingConnectionRequest({
              requestId: connectionRequestId,
              fromPubkey,
              packageCbor,
              round: 1,
            });
          }

          if (this.#ctx.onConnectionPendingReview) {
            this.#ctx.onConnectionPendingReview({
              type: "connection_request_inbound",
              from_pubkey: fromPubkey,
              connection_request_id: connectionRequestId,
              package_cbor: packageCbor,
              sender_registered_at: senderRegisteredAt,
              sender_is_provisional: senderIsProvisional,
            });
          }

          // Start round2TimeoutMs auto-reject timer
          if (this.#ctx.round2TimeoutMs > 0) {
            setTimeout(() => {
              const stillPending = this.#pendingInboundRequests.get(connectionRequestId);
              if (stillPending) {
                this.#pendingInboundRequests.delete(connectionRequestId);
                const currentStream = this.#ctx.getPersistentSignalingStream();
                if (currentStream) {
                  const responseFrame = CBOR_ENC.encode({
                    type: "connection_response",
                    connection_request_id: connectionRequestId,
                    verdict: "reject",
                    reason: "disclosure_timeout",
                  }) as Uint8Array;
                  try {
                    currentStream.send(lp.encode.single(responseFrame));
                  } catch { /* stream closed */ }
                }
              }
            }, this.#ctx.round2TimeoutMs);
          }
          return; // do not send a connection_response yet
        }
        } // end of validatedPackage.valid else-branch
      } else {
        // pkg was null (decode failed) — verdict/rejectReason already set above
      }
    }

    // DB-003: cross-check logic — mark as unchecked when enabled
    if (verdict === "accept" && this.#ctx.crossCheckDirectoryOnInbound) {
      this.#ctx.getProfileUncheckedPeers().add(fromPubkey);
    }

    // Send connection_response to directory
    const responsePayload: Record<string, unknown> = {
      type: "connection_response",
      connection_request_id: connectionRequestId,
      verdict,
    };
    if (rejectReason !== undefined) responsePayload["reason"] = rejectReason;
    if (unmetRequirements !== undefined) responsePayload["unmet_requirements"] = unmetRequirements;

    const responseFrame = CBOR_ENC.encode(responsePayload) as Uint8Array;
    try {
      stream.send(lp.encode.single(responseFrame));
    } catch { /* stream closed — response lost */ }
  }

  /**
   * Handle a disclosure_response_inbound frame (B's side, Round 2).
   * Re-evaluates the updated package and sends final connection_response.
   */
  async handleDisclosureResponse(frame: Record<string, unknown>): Promise<void> {
    const stream = this.#ctx.getPersistentSignalingStream();
    if (!stream) return;

    const connectionRequestId = frame["connection_request_id"] as string;
    const packageCborRaw = frame["package_cbor"];
    const packageCbor = packageCborRaw instanceof Uint8Array ? packageCborRaw
      : Buffer.isBuffer(packageCborRaw) ? new Uint8Array(packageCborRaw as Buffer) : null;

    if (!connectionRequestId || !packageCbor) return;

    const pending = this.#pendingInboundRequests.get(connectionRequestId);
    if (!pending) return; // stale — already handled or timed out

    this.#pendingInboundRequests.delete(connectionRequestId);

    const fromPubkey = pending.from_pubkey;

    let verdict: "accept" | "reject" | "insufficient" = "reject";
    let rejectReason: string | undefined;
    let unmetRequirements: unknown[] | undefined;

    if (!this.#ctx.connectionPolicy) {
      verdict = "accept";
    } else {
      let pkg;
      try {
        pkg = decodeConnectionPackage(packageCbor);
      } catch {
        verdict = "reject";
        rejectReason = "package_decode_failed";
        pkg = null;
      }

      if (pkg !== null) {
        const fromPubkeyBytes = Buffer.from(fromPubkey, "hex");
        const validatedPackage = validateConnectionPackage(
          pkg,
          fromPubkeyBytes,
          Date.now(),
          mlDsaVerify,
        );

        if (!validatedPackage.valid) {
          verdict = "reject";
          rejectReason = validatedPackage.reason;
        } else {
          const context: import("@cello-protocol/protocol-types").DirectoryContext = {
            registered_at: 0,
            is_provisional: false,
            conversation_count: 0,
            clean_close_rate: 0,
          };

          if (this.#ctx.trackEvaluateCount) {
            this.#ctx.incrementEvaluateCallCount();
          }

          const { evaluateConnectionPackage } = await import("./connection-policy.js");
          const report = evaluateConnectionPackage(
            validatedPackage,
            this.#ctx.connectionPolicy,
            context,
            Date.now(),
          );

          if (report.verdict === "auto_accept") {
            verdict = "accept";
          } else if (report.verdict === "auto_reject") {
            verdict = "reject";
            rejectReason = report.reason;
          } else if (report.verdict === "auto_insufficient") {
            verdict = "insufficient";
            unmetRequirements = report.unmet_requirements;
          } else {
            // pending_agent_review in Round 2 (inference mode) — surface for agent review with is_round_2: true.
            const round2Report = { ...report, is_round_2: true };
            this.#pendingInboundRequests.set(connectionRequestId, {
              connection_request_id: connectionRequestId,
              from_pubkey: fromPubkey,
              package_cbor: packageCbor,
              round: 2,
            });
            if (this.#ctx.persistence) {
              void this.#ctx.persistence.persistPendingConnectionRequest({
                requestId: connectionRequestId,
                fromPubkey,
                packageCbor,
                round: 2,
              });
            }
            const round2ReviewItem: ReviewQueueItem = {
              connection_request_id: connectionRequestId,
              from_pubkey: fromPubkey,
              report: round2Report,
              package_cbor: packageCbor,
              sender_registered_at: 0,
              sender_is_provisional: false,
            };
            const awaitResolver = this.#pendingAwaitConnectionRequestResolvers.shift();
            if (awaitResolver) {
              awaitResolver({
                connection_request_id: connectionRequestId,
                from_pubkey: fromPubkey,
                report: round2Report,
              });
            } else {
              this.#pendingReviewQueue.push(round2ReviewItem);
            }
            // No response yet — wait for agent to call accept/reject.
            return;
          }
        }
      } else {
        // pkg was null (decode failed) — verdict already set
      }
    }

    const responsePayload: Record<string, unknown> = {
      type: "connection_response",
      connection_request_id: connectionRequestId,
      verdict,
    };
    if (rejectReason !== undefined) responsePayload["reason"] = rejectReason;
    if (unmetRequirements !== undefined) responsePayload["unmet_requirements"] = unmetRequirements;

    const responseFrame = CBOR_ENC.encode(responsePayload) as Uint8Array;
    try {
      stream.send(lp.encode.single(responseFrame));
    } catch { /* stream closed */ }
  }
}
