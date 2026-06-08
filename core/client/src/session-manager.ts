/**
 * SessionManager — SESSION-002, MSG-004, SESSION-007
 *
 * Extracted from CelloClientImpl. Owns the complete session lifecycle:
 *   - Session assignment acceptance (receiveSessionAssignment)
 *   - Outbound message sending (sendMessage, #sendMessageLocked)
 *   - Content delivery (sendContentFrame, waitForOwnEcho)
 *   - Inbound message queuing (receiveMessage, receiveAnyMessage)
 *   - Async blocking receive (receiveSessionMessageAsync, receiveMessageAsync)
 *   - Session sealed event routing (#enqueueSessionSealedEvent)
 *   - Session listing (listSessions)
 */

import { createHash } from "node:crypto";
import { Encoder } from "cbor-x";
import * as lp from "it-length-prefixed";
import {
  computeGenesisPrevRoot, buildSessionEstablishmentTbs,
} from "@cello-protocol/protocol-types";
import { verifyFrostSignature, CONTEXT_SESSION_ESTABLISHMENT } from "@cello-protocol/crypto";
import type { IThresholdSigner, KeyProvider } from "@cello-protocol/crypto";
import { CELLO_CONTENT_PROTOCOL_ID } from "@cello-protocol/transport";
import type { CelloNode } from "@cello-protocol/transport";
import type { Stream } from "@libp2p/interface";
import type { SessionAssignment } from "@cello-protocol/protocol-types";
import type {
  SessionRecord, ReceivedMessage, SendMessageResult, SessionAssignmentEvent,
  ReceiveAssignmentResult,
} from "./types.js";
import type { Logger } from "@cello-protocol/interfaces";
import type { ClientStatePersistence } from "./client-state-persistence.js";

const CBOR_ENC = new Encoder({ tagUint8Array: false });
const RELAY_PROTOCOL_ID = "/cello/relay/1.0.0";

/**
 * Narrow interface exposing only what SessionManager needs from CelloClientImpl.
 */
export interface SessionContext {
  readonly logger: Logger;
  readonly persistence: ClientStatePersistence | null;
  readonly keyProvider: KeyProvider;
  readonly node: CelloNode;
  getMyPubkeyHex(): string | null;
  setMyPubkeyHex(hex: string): void;
  getThresholdSigner(): IThresholdSigner | undefined;
  getSession(sessionIdHex: string): SessionRecord | undefined;
  getSessions(): Map<string, SessionRecord>;
  setSession(sessionIdHex: string, record: SessionRecord): void;
  getRelayStream(sessionIdHex: string): Stream | undefined;
  setRelayStream(sessionIdHex: string, stream: Stream): void;
  getRelayRecvSeq(sessionIdHex: string): number | undefined;
  setRelayRecvSeq(sessionIdHex: string, seq: number): void;
  setReadyQueue(sessionIdHex: string, queue: Map<number, unknown>): void;
  setPendingS2(sessionIdHex: string, map: Map<string, unknown>): void;
  setPendingContent(sessionIdHex: string, map: Map<string, unknown>): void;
  setOwnPendingContent(sessionIdHex: string, map: Map<string, { content_bytes: Uint8Array; arrived_at: number }>): void;
  getOwnPendingContent(sessionIdHex: string): Map<string, { content_bytes: Uint8Array; arrived_at: number }> | undefined;
  setTamperedContentClaims(sessionIdHex: string, set: Set<string>): void;
  setOwnEchoResolvers(sessionIdHex: string, map: Map<number, () => void>): void;
  getOwnEchoResolvers(sessionIdHex: string): Map<number, () => void> | undefined;
  setSessionMessageQueue(sessionIdHex: string, queue: ReceivedMessage[]): void;
  getSessionMessageQueue(sessionIdHex: string): ReceivedMessage[] | undefined;
  deleteSessionMessageQueue(sessionIdHex: string): void;
  getAnyMessageQueue(): Array<{ sessionIdHex: string; message: ReceivedMessage }>;
  getReceiveWaiters(sessionIdHex: string): Set<() => void> | undefined;
  setReceiveWaiters(sessionIdHex: string, set: Set<() => void>): void;
  getReceiveAnyWaiters(): Set<() => void>;
  getOutboundQueue(sessionIdHex: string): Promise<void> | undefined;
  setOutboundQueue(sessionIdHex: string, queue: Promise<void>): void;
  getPendingAckResolver(sessionIdHex: string): ((ack: { ok: true; sequence_number: number } | { ok: false; reason: string }) => void) | undefined;
  setPendingAckResolver(sessionIdHex: string, resolve: (ack: { ok: true; sequence_number: number } | { ok: false; reason: string }) => void): void;
  deletePendingAckResolver(sessionIdHex: string): void;
  getPersistentSignalingStream(): Stream | null;
  getContentHandlerRegistered(): boolean;
  setContentHandlerRegistered(value: boolean): void;
  getOnSessionAssignmentHandler(): ((event: SessionAssignmentEvent) => void) | undefined;
  // Callbacks into other managers
  runRelayStreamReader(sessionIdHex: string, stream: Stream, myPubkeyHex: string, iter: AsyncIterator<Uint8Array>): void;
  performRelayAuth(stream: Stream, myPubkey: Uint8Array): Promise<{ ok: true; iter: AsyncIterator<Uint8Array> } | { ok: false; reason: "relay_auth_failed" | "relay_auth_error" }>;
  handleContentStream(stream: Stream): void;
  connectDirectorySignalingStream(sessionIdHex: string, assignment: SessionAssignment, myPubkey: Uint8Array): Promise<void>;
}

export class SessionManager {
  readonly #ctx: SessionContext;

  constructor(ctx: SessionContext) {
    this.#ctx = ctx;
  }

  // ─── SESSION-002 ─────────────────────────────────────────────────────────────

  /**
   * Process a SessionAssignment pushed by the directory.
   * SESSION-002 AC-002, AC-003, AC-004, AC-005, SI-003.
   *
   * Crypto refs:
   *   Ed25519 verification: RFC 8032
   *   SHA-256: FIPS 180-4
   */
  async receiveSessionAssignment(
    assignment: SessionAssignment,
    myPubkey: Uint8Array,
  ): Promise<ReceiveAssignmentResult> {
    const { session_id, session_timestamp } = assignment;
    const pubA = assignment.participant_a.pubkey;
    const pubB = assignment.participant_b.pubkey;

    // SESSION-004 Step 1: Check signature_type (SI-003, AC-003)
    // M1 'single' frames are hard-refused in M2 — even if the single-key sig verifies.
    if (assignment.signature_type === "single") {
      return { ok: false, reason: "unsupported_signature_type" };
    }

    // SESSION-004 Step 2: Determine role and verification key (AC-007)
    const myPubkeyHex = Buffer.from(myPubkey).toString("hex");
    const pubAHex = Buffer.from(pubA).toString("hex");
    const isInitiator = myPubkeyHex === pubAHex;

    let verifyKey: Uint8Array;
    if (isInitiator) {
      // CRITICAL-1: initiator MUST have a thresholdSigner injected.
      // Falling back to assignment.signer_pubkey (frame-provided) would be attacker-controlled.
      const thresholdSigner = this.#ctx.getThresholdSigner();
      if (!thresholdSigner) {
        return { ok: false, reason: "frost_signer_not_configured" };
      }
      verifyKey = thresholdSigner.getPrimaryPubkey();
    } else {
      // Counterparty (B): use signer_pubkey from the frame (A's primary_pubkey).
      // TypeScript discriminated union guarantees signer_pubkey is present for 'frost' frames.
      verifyKey = assignment.signer_pubkey;
    }

    // SESSION-004 Step 3: Build TBS and verify FROST signature (AC-002, SI-001)
    // TBS = canonical CBOR([session_id, pubA, pubB, genesis_prev_root, session_timestamp])
    // buildSessionEstablishmentTbs imported from protocol-types (HIGH-5: single source of truth)
    const genesis_prev_root_for_tbs = computeGenesisPrevRoot(pubA, pubB, session_id, session_timestamp);
    const tbs = buildSessionEstablishmentTbs(session_id, pubA, pubB, genesis_prev_root_for_tbs, session_timestamp);

    // Verify FROST signature with domain separation (context\0tbs framing)
    if (!verifyFrostSignature(assignment.directory_signature, tbs, CONTEXT_SESSION_ESTABLISHMENT, verifyKey)) {
      return { ok: false, reason: "frost_signature_invalid" };
    }

    // Step 4: Determine counterparty
    const counterparty = isInitiator ? assignment.participant_b : assignment.participant_a;

    // genesis_prev_root was already computed above for TBS — reuse it
    const genesis_prev_root = genesis_prev_root_for_tbs;

    // Step 4: Register content protocol handler on this node (if not already registered).
    // Set the flag before awaiting handle() to prevent concurrent calls from both registering.
    if (!this.#ctx.getContentHandlerRegistered()) {
      this.#ctx.setContentHandlerRegistered(true);
      try {
        await this.#ctx.node.handle(CELLO_CONTENT_PROTOCOL_ID, (stream) => {
          this.#ctx.handleContentStream(stream);
        });
      } catch {
        // Already registered by a concurrent call — safe to ignore.
      }
    }

    // Step 5: Dial relay on /cello/relay/1.0.0 and complete challenge-response auth (AC-003)
    const relayPeerId = assignment.relay_endpoint.peer_id;
    const relayMultiaddr = assignment.relay_endpoint.multiaddrs[0];

    if (relayMultiaddr) {
      try {
        await this.#ctx.node.dial(relayMultiaddr);
      } catch {
        // Connection may already exist — proceed
      }
    }

    let relayStream: Stream;
    try {
      relayStream = await this.#ctx.node.newStream(relayPeerId, RELAY_PROTOCOL_ID);
    } catch {
      return { ok: false, reason: "relay_auth_error" };
    }

    // Auth challenge-response
    let relayIter: AsyncIterator<Uint8Array>;
    try {
      const authResult = await this.#ctx.performRelayAuth(relayStream, myPubkey);
      if (!authResult.ok) {
        return { ok: false, reason: authResult.reason };
      }
      relayIter = authResult.iter;
    } catch {
      return { ok: false, reason: "relay_auth_error" };
    }

    // Step 6: Dial counterparty on /cello/content/1.0.0 (AC-004)
    try {
      const counterpartyMultiaddr = counterparty.multiaddrs[0];
      if (counterpartyMultiaddr) {
        try {
          await this.#ctx.node.dial(counterpartyMultiaddr);
        } catch {
          // Already connected or not yet reachable — proceed
        }
      }
      const contentStream = await this.#ctx.node.newStream(counterparty.peer_id, CELLO_CONTENT_PROTOCOL_ID);
      // Close gracefully — content stream will be re-established per message in M1
      contentStream.close().catch(() => {});
    } catch {
      // Counterparty not yet listening — store session as active anyway.
    }

    // Step 7: Store session record (AC-004)
    const sessionIdHex = Buffer.from(session_id).toString("hex");
    const record: SessionRecord = {
      session_id,
      counterparty_pubkey: counterparty.pubkey,
      counterparty_peer_id: counterparty.peer_id,
      counterparty_multiaddrs: counterparty.multiaddrs,
      relay_endpoint: {
        peer_id: assignment.relay_endpoint.peer_id,
        multiaddrs: assignment.relay_endpoint.multiaddrs,
      },
      directory_endpoint: {
        peer_id: assignment.directory_endpoint.peer_id,
        multiaddrs: assignment.directory_endpoint.multiaddrs,
      },
      directory_pubkey: assignment.directory_pubkey,
      genesis_prev_root,
      last_seen_seq: 0,
      last_sent_seq: 0,
      status: "active",
      local_tree_leaves: [],
      next_expected_seq: 1,
      desynchronized: false,
    };
    this.#ctx.setSession(sessionIdHex, record);
    // PERSIST-024: persist session to DB
    if (this.#ctx.persistence) {
      void this.#ctx.persistence.persistSession(sessionIdHex, record);
    }

    // Store the relay stream and start the persistent reader loop (MSG-004)
    this.#ctx.setRelayStream(sessionIdHex, relayStream);
    this.#ctx.setRelayRecvSeq(sessionIdHex, 0);
    this.#ctx.setReadyQueue(sessionIdHex, new Map());
    this.#ctx.setPendingS2(sessionIdHex, new Map());
    this.#ctx.setPendingContent(sessionIdHex, new Map());
    this.#ctx.setOwnPendingContent(sessionIdHex, new Map());
    this.#ctx.setTamperedContentClaims(sessionIdHex, new Set());
    this.#ctx.setOwnEchoResolvers(sessionIdHex, new Map());
    this.#ctx.setSessionMessageQueue(sessionIdHex, []);

    // Cache myPubkeyHex for the stream reader (same key across all sessions on this client)
    if (!this.#ctx.getMyPubkeyHex()) this.#ctx.setMyPubkeyHex(myPubkeyHex);

    this.#ctx.runRelayStreamReader(sessionIdHex, relayStream, myPubkeyHex, relayIter);

    // Fire inbound session handler if this client is participant B.
    if (myPubkeyHex !== pubAHex) {
      const handler = this.#ctx.getOnSessionAssignmentHandler();
      if (handler) {
        handler({
          sessionIdHex,
          counterpartyPubkeyHex: Buffer.from(counterparty.pubkey).toString("hex"),
          genesisPrevRootHex: Buffer.from(genesis_prev_root).toString("hex"),
        });
      }
    }

    // ADAPTER-003: if the persistent signaling stream is already open, it handles
    // session_sealed/seal_rejected events for all sessions.
    // Only open a per-session stream when the persistent stream is not available.
    if (!this.#ctx.getPersistentSignalingStream()) {
      void this.#ctx.connectDirectorySignalingStream(sessionIdHex, assignment, myPubkey);
    }

    return { ok: true, sessionId: session_id };
  }

  listSessions(): SessionRecord[] {
    return Array.from(this.#ctx.getSessions().values());
  }

  // ─── MSG-004 implementation ──────────────────────────────────────────────────

  async sendMessage(sessionIdHex: string, content: Uint8Array): Promise<SendMessageResult> {
    // Per-session outbound serialization queue: next send not started until echo received
    const prev = this.#ctx.getOutboundQueue(sessionIdHex) ?? Promise.resolve();
    let release!: () => void;
    const next = new Promise<void>((r) => { release = r; });
    this.#ctx.setOutboundQueue(sessionIdHex, prev.then(() => next));
    await prev;
    try {
      return await this.#sendMessageLocked(sessionIdHex, content);
    } finally {
      release();
    }
  }

  async #sendMessageLocked(sessionIdHex: string, content: Uint8Array): Promise<SendMessageResult> {
    const session = this.#ctx.getSession(sessionIdHex);
    if (!session) return { ok: false, reason: "session_not_found" };
    if (session.desynchronized) return { ok: false, reason: "session_desynchronized" };
    if (session.status === "sealing" || session.status === "sealed" || session.status === "seal_deferred" || session.status === "seal_rejected") return { ok: false, reason: "session_sealed" };
    // SESSION-006 AC-001/AC-003: transport_lost means relay stream is gone or being reconnected
    if (session.status === "transport_lost") return { ok: false, reason: "transport_unavailable" };

    const relayStream = this.#ctx.getRelayStream(sessionIdHex);
    if (!relayStream || relayStream.status !== "open") {
      return { ok: false, reason: "transport_unavailable" };
    }

    // content_hash = SHA-256(0x00 || content) per MERKLE-001
    const contentHash = new Uint8Array(
      createHash("sha256").update(new Uint8Array([0x00])).update(content).digest()
    );

    // Build Structure 1 TBS: [1, content_hash, myPubkey, session_id, last_seen_seq, timestamp]
    const myPubkeyHex = this.#ctx.getMyPubkeyHex()!;
    const myPubkeyBytes = Buffer.from(myPubkeyHex, "hex");
    const tbs = CBOR_ENC.encode([
      1,
      contentHash,
      myPubkeyBytes,
      session.session_id,
      session.last_seen_seq,
      Date.now(),
    ]) as Uint8Array;
    const signature = await this.#ctx.keyProvider.sign(tbs);

    // Submit hash_submit to relay on the persistent relay stream
    const hashSubmitFrame = CBOR_ENC.encode({
      type: "hash_submit",
      session_id: session.session_id,
      leaf_kind: 0x00,
      structure1_cbor: tbs,
      sender_signature: signature,
    }) as Uint8Array;

    const contentHashHex = Buffer.from(contentHash).toString("hex");
    this.#ctx.getOwnPendingContent(sessionIdHex)?.set(contentHashHex, {
      content_bytes: content,
      arrived_at: Date.now(),
    });

    // PERSIST-024 AC-008: Persist pending hash BEFORE relay submission.
    const enqueuedAt = Date.now();
    if (this.#ctx.persistence) {
      void this.#ctx.persistence.persistPendingHash({ sessionId: sessionIdHex, hashHex: contentHashHex, enqueuedAt });
    }

    // Set up ack resolver before sending to avoid race with fast relay.
    if (this.#ctx.getPendingAckResolver(sessionIdHex)) {
      throw new Error(`[cello-client] ack resolver already set for session ${sessionIdHex}; outbound queue invariant violated`);
    }
    let ackResolve!: (v: { ok: true; sequence_number: number } | { ok: false; reason: string }) => void;
    const ackPromise = new Promise<{ ok: true; sequence_number: number } | { ok: false; reason: string }>(
      (r) => { ackResolve = r; }
    );
    this.#ctx.setPendingAckResolver(sessionIdHex, ackResolve);

    try {
      relayStream.send(lp.encode.single(hashSubmitFrame));
    } catch {
      this.#ctx.deletePendingAckResolver(sessionIdHex);
      this.#ctx.getOwnPendingContent(sessionIdHex)?.delete(contentHashHex);
      if (this.#ctx.persistence) {
        void this.#ctx.persistence.removePendingHash(sessionIdHex, contentHashHex);
      }
      return { ok: false, reason: "transport_unavailable" };
    }

    const ack = await ackPromise;
    if (!ack.ok) {
      if (this.#ctx.persistence) {
        void this.#ctx.persistence.removePendingHash(sessionIdHex, contentHashHex);
      }
      return { ok: false, reason: "relay_rejected" };
    }
    const mySeq = ack.sequence_number;

    // PERSIST-024 AC-008: Relay ACKed — remove from pending_hashes.
    if (this.#ctx.persistence) {
      void this.#ctx.persistence.removePendingHash(sessionIdHex, contentHashHex);
    }

    // Send content to counterparty on /cello/content/1.0.0
    const sess2 = this.#ctx.getSession(sessionIdHex);
    if (sess2 && !sess2.desynchronized) {
      void this.sendContentFrame(sess2, content, contentHash);
    }

    // Wait for our own echoed leaf_deliver
    await this.waitForOwnEcho(sessionIdHex, mySeq);

    const sess3 = this.#ctx.getSession(sessionIdHex);
    if (!sess3 || sess3.desynchronized) return { ok: false, reason: "session_desynchronized" };

    return { ok: true };
  }

  async sendContentFrame(session: SessionRecord, content: Uint8Array, contentHash: Uint8Array): Promise<void> {
    const counterpartyPeerId = session.counterparty_peer_id;
    try {
      // Dial counterparty if not connected
      const multiaddr = session.counterparty_multiaddrs[0];
      if (multiaddr) {
        try { await this.#ctx.node.dial(multiaddr); } catch { /* already connected */ }
      }
      const contentStream = await this.#ctx.node.newStream(counterpartyPeerId, CELLO_CONTENT_PROTOCOL_ID);
      const frame = CBOR_ENC.encode({
        type: "content_frame",
        session_id: session.session_id,
        content_hash: contentHash,
        content_bytes: content,
      }) as Uint8Array;
      contentStream.send(lp.encode.single(frame));
      await contentStream.close();
    } catch {
      // Content path failure is silent; 30s grace timer fires if receiver doesn't get content
    }
  }

  async waitForOwnEcho(sessionIdHex: string, seqNum: number): Promise<void> {
    return new Promise<void>((resolve) => {
      const resolvers = this.#ctx.getOwnEchoResolvers(sessionIdHex);
      if (resolvers) {
        resolvers.set(seqNum, resolve);
      } else {
        resolve(); // session was closed
      }
    });
  }

  receiveMessage(sessionIdHex: string): ReceivedMessage | null {
    const queue = this.#ctx.getSessionMessageQueue(sessionIdHex);
    if (!queue || queue.length === 0) return null;
    return queue.shift()!;
  }

  receiveAnyMessage(): { sessionIdHex: string; message: ReceivedMessage } | null {
    return this.#ctx.getAnyMessageQueue().shift() ?? null;
  }

  // ─── SESSION-007: async blocking receive ─────────────────────────────────────

  #computeOtherSessionsPending(excludeSessionIdHex: string): string[] {
    const pending: string[] = [];
    for (const [sid, queue] of this.#ctx.getSessions().entries()) {
      void queue;
      const msgQueue = this.#ctx.getSessionMessageQueue(sid);
      if (sid !== excludeSessionIdHex && msgQueue && msgQueue.length > 0) {
        pending.push(sid);
      }
    }
    return pending;
  }

  wakeReceiveWaiters(sessionIdHex: string): void {
    // Wake per-session waiters
    const sessionWaiters = this.#ctx.getReceiveWaiters(sessionIdHex);
    if (sessionWaiters) {
      for (const resolve of sessionWaiters) resolve();
      sessionWaiters.clear();
    }
    // Wake any-session waiters
    for (const resolve of this.#ctx.getReceiveAnyWaiters()) resolve();
    this.#ctx.getReceiveAnyWaiters().clear();
  }

  async receiveSessionMessageAsync(sessionIdHex: string, timeoutMs: number): Promise<ReceivedMessage | null> {
    const deadline = Date.now() + timeoutMs;

    while (true) {
      // Check queue first (fast path: already has messages)
      const queue = this.#ctx.getSessionMessageQueue(sessionIdHex);
      if (queue && queue.length > 0) {
        const item = queue.shift()!;
        // Remove from anyMessageQueue as well to keep in sync
        const anyQueue = this.#ctx.getAnyMessageQueue();
        const idx = anyQueue.findIndex(
          (e) => e.sessionIdHex === sessionIdHex && e.message === item
        );
        if (idx !== -1) anyQueue.splice(idx, 1);
        // Attach otherSessionsPending
        const pending = this.#computeOtherSessionsPending(sessionIdHex);
        const result = pending.length > 0 ? { ...item, otherSessionsPending: pending } : item;
        if (pending.length > 0) {
          this.#ctx.logger.info("session.receive.pending_hint", {
            currentSessionId: sessionIdHex,
            pendingSessionCount: pending.length,
            correlationId: sessionIdHex,
          });
        }
        return result;
      }

      const remaining = deadline - Date.now();
      if (remaining <= 0) return null;

      // Register wake resolver and race against timeout
      await new Promise<void>((resolve) => {
        let set = this.#ctx.getReceiveWaiters(sessionIdHex);
        if (!set) {
          set = new Set();
          this.#ctx.setReceiveWaiters(sessionIdHex, set);
        }
        set.add(resolve);
        setTimeout(() => {
          this.#ctx.getReceiveWaiters(sessionIdHex)?.delete(resolve);
          resolve();
        }, remaining);
      });
    }
  }

  async receiveMessageAsync(timeoutMs: number): Promise<
    | (ReceivedMessage & { sessionIdHex: string })
    | { type: "timeout" }
  > {
    const deadline = Date.now() + timeoutMs;

    while (true) {
      // Check any-session queue first (fast path)
      const anyQueue = this.#ctx.getAnyMessageQueue();
      if (anyQueue.length > 0) {
        const entry = anyQueue.shift()!;
        // Remove from per-session queue as well
        const perSession = this.#ctx.getSessionMessageQueue(entry.sessionIdHex);
        if (perSession) {
          const idx = perSession.indexOf(entry.message);
          if (idx !== -1) perSession.splice(idx, 1);
        }
        // Attach otherSessionsPending
        const pending = this.#computeOtherSessionsPending(entry.sessionIdHex);
        const result = pending.length > 0
          ? { ...entry.message, sessionIdHex: entry.sessionIdHex, otherSessionsPending: pending }
          : { ...entry.message, sessionIdHex: entry.sessionIdHex };
        if (pending.length > 0) {
          this.#ctx.logger.info("session.receive.pending_hint", {
            currentSessionId: entry.sessionIdHex,
            pendingSessionCount: pending.length,
            correlationId: entry.sessionIdHex,
          });
        }
        return result;
      }

      const remaining = deadline - Date.now();
      if (remaining <= 0) return { type: "timeout" };

      // Register wake resolver and race against timeout
      await new Promise<void>((resolve) => {
        this.#ctx.getReceiveAnyWaiters().add(resolve);
        setTimeout(() => {
          this.#ctx.getReceiveAnyWaiters().delete(resolve);
          resolve();
        }, remaining);
      });
    }
  }

  enqueueSessionSealedEvent(
    sessionIdHex: string,
    sealedRoot: Uint8Array,
    closeTimestamp: number,
  ): void {
    const correlationId = sessionIdHex;
    this.#ctx.logger.info("session.sealed.received", {
      sessionId: sessionIdHex,
      sealedRoot: Buffer.from(sealedRoot).toString("hex"),
      closeTimestamp,
      checkpointStatus: "pending",
      correlationId,
    });
    const lifecycleEvent: ReceivedMessage = {
      type: "session_sealed",
      sessionIdHex,
      sealedRoot: new Uint8Array(sealedRoot),
      closeTimestamp,
      checkpointStatus: "pending",
    };
    let queue = this.#ctx.getSessionMessageQueue(sessionIdHex);
    if (!queue) {
      queue = [];
      this.#ctx.setSessionMessageQueue(sessionIdHex, queue);
    }
    queue.push(lifecycleEvent);
    this.#ctx.getAnyMessageQueue().push({ sessionIdHex, message: lifecycleEvent });
    this.wakeReceiveWaiters(sessionIdHex);
  }
}
