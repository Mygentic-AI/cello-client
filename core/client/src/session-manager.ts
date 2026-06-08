/**
 * SessionManager — SESSION-002, MSG-004, SESSION-007
 *
 * Extracted from CelloClientImpl. Owns the complete session lifecycle:
 *   - Session assignment acceptance (receiveSessionAssignment)
 *   - Outbound message sending (sendMessage, #sendMessageLocked)
 *   - Content delivery (sendContentFrame, waitForOwnEcho)
 *   - Inbound message queuing (enqueueReceivedMessage, enqueueSessionSealedEvent)
 *   - Async blocking receive (receiveSessionMessageAsync, receiveMessageAsync)
 *   - Session listing (listSessions)
 *
 * State owned here (not in facade):
 *   - #sessions: SessionRecord map
 *   - #sessionMessageQueues + #anyMessageQueue: inbound message queues
 *   - #receiveWaiters + #receiveAnyWaiters: async-receive wake resolvers
 *   - #outboundQueues: per-session send serialization chains
 *   - #pendingAckResolvers: in-flight ack resolvers
 *   - #ownEchoResolvers: echo wait resolvers (set by relay reader, resolved here)
 *   - #ownPendingContent: pre-buffered own sends (keyed by content_hash_hex)
 *   - #contentHandlerRegistered: content stream protocol guard
 *   - #onSessionAssignmentHandler: inbound session callback
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
 * Narrow interface exposing only what SessionManager needs from the facade
 * and from other managers.
 */
export interface SessionContext {
  readonly logger: Logger;
  readonly persistence: ClientStatePersistence | null;
  readonly keyProvider: KeyProvider;
  readonly node: CelloNode;
  getMyPubkeyHex(): string | null;
  setMyPubkeyHex(hex: string): void;
  getThresholdSigner(): IThresholdSigner | undefined;
  getPersistentSignalingStream(): Stream | null;
  // RelayStreamManager callbacks (lazy — safe since managers are wired before any method is called)
  initRelaySession(sessionIdHex: string): void;
  runRelayStreamReader(sessionIdHex: string, stream: Stream, myPubkeyHex: string, iter: AsyncIterator<Uint8Array>): void;
  performRelayAuth(stream: Stream, myPubkey: Uint8Array): Promise<{ ok: true; iter: AsyncIterator<Uint8Array> } | { ok: false; reason: "relay_auth_failed" | "relay_auth_error" }>;
  handleContentStream(stream: Stream): void;
  connectDirectorySignalingStream(sessionIdHex: string, assignment: SessionAssignment, myPubkey: Uint8Array): Promise<void>;
  // RelayStreamManager state accessor (needed by #sendMessageLocked)
  getRelayStream(sessionIdHex: string): Stream | undefined;
}

export class SessionManager {
  readonly #ctx: SessionContext;

  // ─── Owned state ─────────────────────────────────────────────────────────────

  // session_id_hex → SessionRecord (SESSION-002)
  readonly #sessions = new Map<string, SessionRecord>();

  // track whether content handler has been registered on this node
  #contentHandlerRegistered = false;

  // Callback for inbound session assignments (participant B role). MCP-002.
  #onSessionAssignmentHandler: ((event: SessionAssignmentEvent) => void) | undefined;

  // session_id_hex → Promise<void> chain for outbound serialization
  readonly #outboundQueues = new Map<string, Promise<void>>();

  // session_id_hex → pending ack resolver (sequence_number → ack data)
  readonly #pendingAckResolvers = new Map<string, (ack: { ok: true; sequence_number: number } | { ok: false; reason: string }) => void>();

  // session_id_hex → own_echo_resolvers (sequence_number → resolve fn)
  // Populated from relay stream reader via notifyOwnEcho(); resolved when echo arrives.
  readonly #ownEchoResolvers = new Map<string, Map<number, () => void>>();

  // session_id_hex → own-send pre-buffered content keyed by content_hash_hex
  readonly #ownPendingContent = new Map<string, Map<string, { content_bytes: Uint8Array; arrived_at: number }>>();

  // session_id_hex → FIFO queue of ReceivedMessage (for receiveMessage)
  readonly #sessionMessageQueues = new Map<string, ReceivedMessage[]>();

  // FIFO arrival order across all sessions: { sessionIdHex, message }
  readonly #anyMessageQueue: Array<{ sessionIdHex: string; message: ReceivedMessage }> = [];

  // SESSION-007: wake resolvers for receiveSessionMessageAsync (per-session) and receiveMessageAsync (any-session)
  readonly #receiveWaiters = new Map<string, Set<() => void>>();
  readonly #receiveAnyWaiters = new Set<() => void>();

  constructor(ctx: SessionContext) {
    this.#ctx = ctx;
  }

  // ─── State accessors (called by RelayStreamManager, SealManager, facade) ─────

  getSession(sessionIdHex: string): SessionRecord | undefined {
    return this.#sessions.get(sessionIdHex);
  }

  getSessions(): Map<string, SessionRecord> {
    return this.#sessions;
  }

  setSession(sessionIdHex: string, record: SessionRecord): void {
    this.#sessions.set(sessionIdHex, record);
  }

  deleteSession(sessionIdHex: string): void {
    this.#sessions.delete(sessionIdHex);
  }

  getOutboundQueue(sessionIdHex: string): Promise<void> | undefined {
    return this.#outboundQueues.get(sessionIdHex);
  }

  setOutboundQueue(sessionIdHex: string, queue: Promise<void>): void {
    this.#outboundQueues.set(sessionIdHex, queue);
  }

  deleteOutboundQueue(sessionIdHex: string): void {
    this.#outboundQueues.delete(sessionIdHex);
  }

  getPendingAckResolver(sessionIdHex: string): ((ack: { ok: true; sequence_number: number } | { ok: false; reason: string }) => void) | undefined {
    return this.#pendingAckResolvers.get(sessionIdHex);
  }

  setPendingAckResolver(sessionIdHex: string, resolve: (ack: { ok: true; sequence_number: number } | { ok: false; reason: string }) => void): void {
    this.#pendingAckResolvers.set(sessionIdHex, resolve);
  }

  deletePendingAckResolver(sessionIdHex: string): void {
    this.#pendingAckResolvers.delete(sessionIdHex);
  }

  getOwnEchoResolvers(sessionIdHex: string): Map<number, () => void> | undefined {
    return this.#ownEchoResolvers.get(sessionIdHex);
  }

  initOwnEchoResolvers(sessionIdHex: string): void {
    this.#ownEchoResolvers.set(sessionIdHex, new Map());
  }

  deleteOwnEchoResolvers(sessionIdHex: string): void {
    this.#ownEchoResolvers.delete(sessionIdHex);
  }

  getOwnPendingContent(sessionIdHex: string): Map<string, { content_bytes: Uint8Array; arrived_at: number }> | undefined {
    return this.#ownPendingContent.get(sessionIdHex);
  }

  initOwnPendingContent(sessionIdHex: string): void {
    this.#ownPendingContent.set(sessionIdHex, new Map());
  }

  deleteOwnPendingContent(sessionIdHex: string): void {
    this.#ownPendingContent.delete(sessionIdHex);
  }

  getSessionMessageQueue(sessionIdHex: string): ReceivedMessage[] | undefined {
    return this.#sessionMessageQueues.get(sessionIdHex);
  }

  deleteSessionMessageQueue(sessionIdHex: string): void {
    this.#sessionMessageQueues.delete(sessionIdHex);
  }

  /** Initialize the message queue for a session (called from loadPersistedState). */
  initSessionMessageQueue(sessionIdHex: string): void {
    if (!this.#sessionMessageQueues.has(sessionIdHex)) {
      this.#sessionMessageQueues.set(sessionIdHex, []);
    }
  }

  getAnyMessageQueue(): Array<{ sessionIdHex: string; message: ReceivedMessage }> {
    return this.#anyMessageQueue;
  }

  setOnSessionAssignmentHandler(handler: (event: SessionAssignmentEvent) => void): void {
    this.#onSessionAssignmentHandler = handler;
  }

  /**
   * Clean up all per-session state owned by SessionManager.
   * Called by facade.closeSession — companion to RelayStreamManager.closeSession and SealManager.closeSession.
   */
  closeSession(sessionIdHex: string): void {
    this.#sessions.delete(sessionIdHex);
    this.#outboundQueues.delete(sessionIdHex);
    this.#ownEchoResolvers.delete(sessionIdHex);
    this.#ownPendingContent.delete(sessionIdHex);
    this.#sessionMessageQueues.delete(sessionIdHex);
    // Clear pending ack resolver (already unblocked by facade before calling closeSession)
    this.#pendingAckResolvers.delete(sessionIdHex);
    // Clear receive waiters for this session
    this.#receiveWaiters.delete(sessionIdHex);
  }

  // ─── Called by RelayStreamManager after relay receives a message ─────────────

  enqueueReceivedMessage(sessionIdHex: string, message: ReceivedMessage): void {
    let queue = this.#sessionMessageQueues.get(sessionIdHex);
    if (!queue) {
      queue = [];
      this.#sessionMessageQueues.set(sessionIdHex, queue);
    }
    queue.push(message);
    this.#anyMessageQueue.push({ sessionIdHex, message });
    this.wakeReceiveWaiters(sessionIdHex);
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
    if (!this.#contentHandlerRegistered) {
      this.#contentHandlerRegistered = true;
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
    this.#sessions.set(sessionIdHex, record);
    // PERSIST-024: persist session to DB
    if (this.#ctx.persistence) {
      void this.#ctx.persistence.persistSession(sessionIdHex, record);
    }

    // Initialize per-session state in this manager and RelayStreamManager
    this.#outboundQueues.set(sessionIdHex, Promise.resolve());
    this.#ownEchoResolvers.set(sessionIdHex, new Map());
    this.#ownPendingContent.set(sessionIdHex, new Map());
    this.#sessionMessageQueues.set(sessionIdHex, []);
    this.#ctx.initRelaySession(sessionIdHex);

    // Cache myPubkeyHex for the stream reader (same key across all sessions on this client)
    if (!this.#ctx.getMyPubkeyHex()) this.#ctx.setMyPubkeyHex(myPubkeyHex);

    this.#ctx.runRelayStreamReader(sessionIdHex, relayStream, myPubkeyHex, relayIter);

    // Fire inbound session handler if this client is participant B.
    if (myPubkeyHex !== pubAHex) {
      const handler = this.#onSessionAssignmentHandler;
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
    return Array.from(this.#sessions.values());
  }

  // ─── MSG-004 implementation ──────────────────────────────────────────────────

  async sendMessage(sessionIdHex: string, content: Uint8Array): Promise<SendMessageResult> {
    // Per-session outbound serialization queue: next send not started until echo received
    const prev = this.#outboundQueues.get(sessionIdHex) ?? Promise.resolve();
    let release!: () => void;
    const next = new Promise<void>((r) => { release = r; });
    this.#outboundQueues.set(sessionIdHex, prev.then(() => next));
    await prev;
    try {
      return await this.#sendMessageLocked(sessionIdHex, content);
    } finally {
      release();
    }
  }

  async #sendMessageLocked(sessionIdHex: string, content: Uint8Array): Promise<SendMessageResult> {
    const session = this.#sessions.get(sessionIdHex);
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
    this.#ownPendingContent.get(sessionIdHex)?.set(contentHashHex, {
      content_bytes: content,
      arrived_at: Date.now(),
    });

    // PERSIST-024 AC-008: Persist pending hash BEFORE relay submission.
    const enqueuedAt = Date.now();
    if (this.#ctx.persistence) {
      void this.#ctx.persistence.persistPendingHash({ sessionId: sessionIdHex, hashHex: contentHashHex, enqueuedAt });
    }

    // Set up ack resolver before sending to avoid race with fast relay.
    if (this.#pendingAckResolvers.has(sessionIdHex)) {
      throw new Error(`[cello-client] ack resolver already set for session ${sessionIdHex}; outbound queue invariant violated`);
    }
    let ackResolve!: (v: { ok: true; sequence_number: number } | { ok: false; reason: string }) => void;
    const ackPromise = new Promise<{ ok: true; sequence_number: number } | { ok: false; reason: string }>(
      (r) => { ackResolve = r; }
    );
    this.#pendingAckResolvers.set(sessionIdHex, ackResolve);

    try {
      relayStream.send(lp.encode.single(hashSubmitFrame));
    } catch {
      this.#pendingAckResolvers.delete(sessionIdHex);
      this.#ownPendingContent.get(sessionIdHex)?.delete(contentHashHex);
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
    const sess2 = this.#sessions.get(sessionIdHex);
    if (sess2 && !sess2.desynchronized) {
      void this.sendContentFrame(sess2, content, contentHash);
    }

    // Wait for our own echoed leaf_deliver
    await this.waitForOwnEcho(sessionIdHex, mySeq);

    const sess3 = this.#sessions.get(sessionIdHex);
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
      const resolvers = this.#ownEchoResolvers.get(sessionIdHex);
      if (resolvers) {
        resolvers.set(seqNum, resolve);
      } else {
        resolve(); // session was closed
      }
    });
  }

  receiveMessage(sessionIdHex: string): ReceivedMessage | null {
    const queue = this.#sessionMessageQueues.get(sessionIdHex);
    if (!queue || queue.length === 0) return null;
    return queue.shift()!;
  }

  receiveAnyMessage(): { sessionIdHex: string; message: ReceivedMessage } | null {
    return this.#anyMessageQueue.shift() ?? null;
  }

  // ─── SESSION-007: async blocking receive ─────────────────────────────────────

  #computeOtherSessionsPending(excludeSessionIdHex: string): string[] {
    const pending: string[] = [];
    for (const [sid, queue] of this.#sessionMessageQueues.entries()) {
      if (sid !== excludeSessionIdHex && queue.length > 0) {
        pending.push(sid);
      }
    }
    return pending;
  }

  wakeReceiveWaiters(sessionIdHex: string): void {
    // Wake per-session waiters
    const sessionWaiters = this.#receiveWaiters.get(sessionIdHex);
    if (sessionWaiters) {
      for (const resolve of sessionWaiters) resolve();
      sessionWaiters.clear();
    }
    // Wake any-session waiters
    for (const resolve of this.#receiveAnyWaiters) resolve();
    this.#receiveAnyWaiters.clear();
  }

  async receiveSessionMessageAsync(sessionIdHex: string, timeoutMs: number): Promise<ReceivedMessage | null> {
    const deadline = Date.now() + timeoutMs;

    while (true) {
      // Check queue first (fast path: already has messages)
      const queue = this.#sessionMessageQueues.get(sessionIdHex);
      if (queue && queue.length > 0) {
        const item = queue.shift()!;
        // Remove from #anyMessageQueue as well to keep in sync
        const idx = this.#anyMessageQueue.findIndex(
          (e) => e.sessionIdHex === sessionIdHex && e.message === item
        );
        if (idx !== -1) this.#anyMessageQueue.splice(idx, 1);
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
        let set = this.#receiveWaiters.get(sessionIdHex);
        if (!set) {
          set = new Set();
          this.#receiveWaiters.set(sessionIdHex, set);
        }
        set.add(resolve);
        setTimeout(() => {
          // Remove resolver if timeout fires before wake
          this.#receiveWaiters.get(sessionIdHex)?.delete(resolve);
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
      if (this.#anyMessageQueue.length > 0) {
        const entry = this.#anyMessageQueue.shift()!;
        // Remove from per-session queue as well
        const perSession = this.#sessionMessageQueues.get(entry.sessionIdHex);
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
        this.#receiveAnyWaiters.add(resolve);
        setTimeout(() => {
          this.#receiveAnyWaiters.delete(resolve);
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
    // Use sessionIdHex as correlationId — minted at session initiation, unique per session flow.
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
    let queue = this.#sessionMessageQueues.get(sessionIdHex);
    if (!queue) {
      queue = [];
      this.#sessionMessageQueues.set(sessionIdHex, queue);
    }
    queue.push(lifecycleEvent);
    this.#anyMessageQueue.push({ sessionIdHex, message: lifecycleEvent });
    this.wakeReceiveWaiters(sessionIdHex);
  }
}
