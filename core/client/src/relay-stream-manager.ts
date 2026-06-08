/**
 * RelayStreamManager — relay reader loop, reconnect logic, cross-check, content frame handling.
 *
 * Extracted from CelloClientImpl. Handles MSG-004 relay stream lifecycle:
 * - #runRelayStreamReader: reads leaf_deliver, hash_submit_ack/error, gap_fill frames
 * - #reconnectRelayStream: SESSION-006 exponential backoff reconnect
 * - #handleInboundLeafDeliver: S2 decode, sequence/signature checks, cross-check pairing
 * - #handleContentStream: content path receiver, cross-check trigger
 * - #crossCheckDelivery / #drainReadyQueue: in-order delivery with prevRoot check
 * - #desync: session desynchronization
 * - #performRelayAuth: challenge-response auth
 * - #performGapFillReconciliation: PERSIST-014 gap fill
 * - #handleGapFillResponse
 *
 * State owned here (not in facade):
 *   - #relayStreams, #relayRecvSeq, #reconnectInProgress
 *   - #readyQueue, #pendingS2, #pendingContent
 *   - #tamperedContentClaims, #pendingGapFillResolvers
 *   - #directoryStreams
 */

import { createHash } from "node:crypto";
import { Encoder, decode } from "cbor-x";
import * as lp from "it-length-prefixed";
import { verify, buildMerkleTree, merkleRoot } from "@cello-protocol/crypto";
import type { LeafInput } from "@cello-protocol/crypto";
import type { CelloNode } from "@cello-protocol/transport";
import type { Stream } from "@libp2p/interface";
import type { Structure2 } from "@cello-protocol/protocol-types";
import type { Logger } from "@cello-protocol/interfaces";
import type { KeyProvider } from "@cello-protocol/crypto";
import type { ClientStatePersistence } from "./client-state-persistence.js";
import type { SessionRecord, ReceivedMessage } from "./types.js";
import type { AgentHashQueue } from "./agent-hash-queue.js";

const CBOR_ENC = new Encoder({ tagUint8Array: false });
const RELAY_PROTOCOL_ID = "/cello/relay/1.0.0";
const AUTH_DOMAIN = "CELLO-RELAY-AUTH-v1";
const RELAY_AUTH_TIMEOUT_MS = 5_000;
const DEFAULT_RECONNECT_TIMEOUT_MS = 60_000;
const RECONNECT_INITIAL_BACKOFF_MS = 200;
const RECONNECT_MAX_BACKOFF_MS = 5_000;
const PENDING_CONTENT_BOUND = 256;

function toU8(v: unknown): Uint8Array {
  if (v instanceof Uint8Array) return v;
  if (Buffer.isBuffer(v)) return new Uint8Array(v as Buffer);
  if (typeof (v as { slice?: unknown }).slice === "function") {
    return (v as { slice(): Uint8Array }).slice();
  }
  throw new Error(`expected bytes, got ${typeof v}`);
}

function toU8Safe(v: unknown): Uint8Array | null {
  if (v instanceof Uint8Array) return v;
  if (Buffer.isBuffer(v)) return new Uint8Array(v as Buffer);
  return null;
}

async function nextWithTimeout<T>(
  iter: AsyncIterator<T>,
  timeoutMs: number,
): Promise<IteratorResult<T>> {
  return Promise.race([
    iter.next(),
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error("auth_timeout")), timeoutMs),
    ),
  ]);
}

interface Structure1Fields {
  last_seen_seq: number;
  timestamp: number | bigint;
}

interface PendingS2Entry {
  s2: Structure2;
  s2_cbor: Uint8Array;
  s1_fields: Structure1Fields;
  leaf_kind: number;
  sequence_number: number;
  content_hash: Uint8Array;
  is_own_send: boolean;
  arrived_at: number;
  timer_handle: ReturnType<typeof setTimeout>;
  echo_resolve?: () => void;
}

interface PendingContentEntry {
  content_bytes: Uint8Array;
  arrived_at: number;
}

interface ReadyEntry {
  s2: Structure2;
  s2_cbor: Uint8Array;
  s1_fields: Structure1Fields;
  leaf_kind: number;
  content_bytes: Uint8Array;
  is_own_send: boolean;
  echo_resolve?: () => void;
}

/**
 * Narrow interface exposing only what RelayStreamManager needs from external managers.
 * State owned by RelayStreamManager is no longer in this interface.
 */
export interface RelayStreamContext {
  readonly node: CelloNode;
  readonly keyProvider: KeyProvider;
  readonly logger: Logger;
  readonly persistence: ClientStatePersistence | null;
  readonly contentGraceMs: number;
  readonly reconnectTimeoutMs: number;
  readonly hashQueue: AgentHashQueue | null;
  getMyPubkeyHex(): string | null;
  // From SessionManager (session records and send-side state)
  getSession(sessionIdHex: string): SessionRecord | undefined;
  getSessions(): Map<string, SessionRecord>;
  getPendingAckResolver(sessionIdHex: string): ((v: { ok: true; sequence_number: number } | { ok: false; reason: string }) => void) | undefined;
  setPendingAckResolver(sessionIdHex: string, resolve: (v: { ok: true; sequence_number: number } | { ok: false; reason: string }) => void): void;
  deletePendingAckResolver(sessionIdHex: string): void;
  getOwnPendingContent(sessionIdHex: string): Map<string, { content_bytes: Uint8Array; arrived_at: number }> | undefined;
  getOwnEchoResolvers(sessionIdHex: string): Map<number, () => void> | undefined;
  getOutboundQueue(sessionIdHex: string): Promise<void> | undefined;
  // Delivery callbacks into SessionManager
  enqueueReceivedMessage(sessionIdHex: string, message: ReceivedMessage): void;
  wakeReceiveWaiters(sessionIdHex: string): void;
  enqueueSessionSealedEvent(sessionIdHex: string, sealedRoot: Uint8Array, closeTimestamp: number): void;
  // Seal callbacks
  handleSealVerified(sessionIdHex: string, frame: Record<string, unknown>): void;
  handleSessionFrostSealed(sessionIdHex: string, frame: Record<string, unknown>): void;
  handleSealRejectedTreeMismatch(sessionIdHex: string, frame: Record<string, unknown>): void;
  handleSealUnilateralConfirmed(sessionIdHex: string, frame: Record<string, unknown>): void;
  handleSealUnilateralNotification(sessionIdHex: string, frame: Record<string, unknown>): void;
  handleDirectorySessionSealed(sessionIdHex: string, frame: Record<string, unknown>, directoryPubkey: Uint8Array): void;
  handleDirectorySessionSealRejected(sessionIdHex: string, frame: Record<string, unknown>): void;
  // Reconnect callback
  onRelayDisconnected(sessionIdHex: string, myPubkeyHex: string): void;
}

export type { ReadyEntry, PendingS2Entry, PendingContentEntry, Structure1Fields };

export class RelayStreamManager {
  readonly #ctx: RelayStreamContext;

  // ─── Owned state ──────────────────────────────────────────────────────────────

  // session_id_hex → persistent relay stream
  readonly #relayStreams = new Map<string, Stream>();

  // session_id_hex → directory signaling stream (SESSION-003)
  readonly #directoryStreams = new Map<string, Stream>();

  // session_id_hex → highest seq# received from relay
  readonly #relayRecvSeq = new Map<string, number>();

  // SESSION-006: track whether a reconnect loop is already running per session
  readonly #reconnectInProgress = new Set<string>();

  // session_id_hex → fully-ready cross-checks keyed by seqNum, awaiting in-order processing
  readonly #readyQueue = new Map<string, Map<number, ReadyEntry>>();

  // session_id_hex → pending S2 entries keyed by content_hash_hex
  readonly #pendingS2 = new Map<string, Map<string, PendingS2Entry>>();

  // session_id_hex → pending content entries keyed by content_hash_hex
  readonly #pendingContent = new Map<string, Map<string, PendingContentEntry>>();

  // session_id_hex → set of content_hash_hex values from tampered frames
  readonly #tamperedContentClaims = new Map<string, Set<string>>();

  // session_id_hex → pending gap fill resolver
  readonly #pendingGapFillResolvers = new Map<string, (result: { ok: true; leaves: unknown[] } | { ok: false; reason: string }) => void>();

  constructor(ctx: RelayStreamContext) {
    this.#ctx = ctx;
  }

  // ─── State accessors (called by SessionManager, SealManager, facade) ──────────

  getRelayStream(sessionIdHex: string): Stream | undefined {
    return this.#relayStreams.get(sessionIdHex);
  }

  setRelayStream(sessionIdHex: string, stream: Stream): void {
    this.#relayStreams.set(sessionIdHex, stream);
  }

  deleteRelayStream(sessionIdHex: string): void {
    this.#relayStreams.delete(sessionIdHex);
  }

  getDirectoryStream(sessionIdHex: string): Stream | undefined {
    return this.#directoryStreams.get(sessionIdHex);
  }

  setDirectoryStream(sessionIdHex: string, stream: Stream): void {
    this.#directoryStreams.set(sessionIdHex, stream);
  }

  deleteDirectoryStream(sessionIdHex: string): void {
    this.#directoryStreams.delete(sessionIdHex);
  }

  /** Called by SessionManager.receiveSessionAssignment to initialize per-session relay state. */
  initSession(sessionIdHex: string): void {
    this.#relayRecvSeq.set(sessionIdHex, 0);
    this.#readyQueue.set(sessionIdHex, new Map());
    this.#pendingS2.set(sessionIdHex, new Map());
    this.#pendingContent.set(sessionIdHex, new Map());
    this.#tamperedContentClaims.set(sessionIdHex, new Set());
  }

  /** Called by facade.closeSession to tear down per-session relay state. */
  closeSession(sessionIdHex: string): void {
    // Clear pending S2 timers to avoid memory leaks
    const ps2 = this.#pendingS2.get(sessionIdHex);
    if (ps2) {
      for (const entry of ps2.values()) clearTimeout(entry.timer_handle);
    }
    this.#relayRecvSeq.delete(sessionIdHex);
    this.#readyQueue.delete(sessionIdHex);
    this.#pendingS2.delete(sessionIdHex);
    this.#pendingContent.delete(sessionIdHex);
    this.#tamperedContentClaims.delete(sessionIdHex);
    this.#pendingGapFillResolvers.delete(sessionIdHex);
    const stream = this.#relayStreams.get(sessionIdHex);
    if (stream) {
      this.#relayStreams.delete(sessionIdHex);
      stream.abort(new Error("session_closed"));
    }
    const dirStream = this.#directoryStreams.get(sessionIdHex);
    if (dirStream) {
      this.#directoryStreams.delete(sessionIdHex);
      dirStream.abort(new Error("session_closed"));
    }
    this.#reconnectInProgress.delete(sessionIdHex);
  }

  // ─── Public API: TEST-ONLY escape hatches ────────────────────────────────────

  injectLeafDeliver(sessionIdHex: string, frame: Record<string, unknown>): void {
    const myPubkeyHex = this.#ctx.getMyPubkeyHex();
    if (!myPubkeyHex) throw new Error("injectLeafDeliver: client not yet authenticated (no session registered)");
    this.#handleInboundLeafDeliver(sessionIdHex, frame, myPubkeyHex);
  }

  injectRelayDisconnect(sessionIdHex: string): void {
    const stream = this.#relayStreams.get(sessionIdHex);
    const myPubkeyHex = this.#ctx.getMyPubkeyHex();
    if (!myPubkeyHex) return;
    if (stream) {
      this.#relayStreams.delete(sessionIdHex);
      try { stream.abort(new Error("test_inject_disconnect")); } catch { /* ignore */ }
    }
    this.#ctx.onRelayDisconnected(sessionIdHex, myPubkeyHex);
  }

  // ─── Relay stream reader (MSG-004) ─────────────────────────────────────────

  runRelayStreamReader(
    sessionIdHex: string,
    stream: Stream,
    myPubkeyHex: string,
    iter?: AsyncIterator<Uint8Array>,
  ): void {
    void this.#doRunRelayStreamReader(sessionIdHex, stream, myPubkeyHex, iter);
  }

  async #doRunRelayStreamReader(
    sessionIdHex: string,
    stream: Stream,
    myPubkeyHex: string,
    iter?: AsyncIterator<Uint8Array>,
  ): Promise<void> {
    const source: AsyncIterator<Uint8Array> = iter ?? (
      (lp.decode(stream) as AsyncIterable<unknown>)[Symbol.asyncIterator]() as AsyncIterator<Uint8Array>
    );
    try {
      while (true) {
        let result: IteratorResult<Uint8Array>;
        try {
          result = await source.next();
        } catch { break; }
        if (result.done || result.value === undefined) break;

        const bytes = toU8(result.value as unknown);
        let frame: Record<string, unknown>;
        try {
          frame = decode(bytes) as Record<string, unknown>;
        } catch { continue; }

        if (frame["type"] === "hash_submit_ack") {
          const resolve = this.#ctx.getPendingAckResolver(sessionIdHex);
          if (resolve) {
            this.#ctx.deletePendingAckResolver(sessionIdHex);
            const seqNum = typeof frame["sequence_number"] === "number" ? frame["sequence_number"] : 0;
            resolve({ ok: true, sequence_number: seqNum });
          }
        } else if (frame["type"] === "hash_submit_error") {
          const resolve = this.#ctx.getPendingAckResolver(sessionIdHex);
          if (resolve) {
            this.#ctx.deletePendingAckResolver(sessionIdHex);
            resolve({ ok: false, reason: String(frame["reason"] ?? "unknown") });
          }
        } else if (frame["type"] === "leaf_deliver") {
          const deliverSessionIdRaw = frame["session_id"];
          const deliverSessionId = deliverSessionIdRaw instanceof Uint8Array ? deliverSessionIdRaw
            : Buffer.isBuffer(deliverSessionIdRaw) ? new Uint8Array(deliverSessionIdRaw as Buffer) : null;
          const targetSessionHex = deliverSessionId
            ? Buffer.from(deliverSessionId).toString("hex")
            : sessionIdHex;
          this.#handleInboundLeafDeliver(targetSessionHex, frame, myPubkeyHex);
        } else if (frame["type"] === "gap_fill_response") {
          this.#handleGapFillResponse(sessionIdHex, frame);
        } else if (frame["type"] === "gap_fill_error") {
          const reason = typeof frame["reason"] === "string" ? frame["reason"] : "unknown";
          const pendingReconciliation = this.#pendingGapFillResolvers.get(sessionIdHex);
          if (pendingReconciliation) {
            this.#pendingGapFillResolvers.delete(sessionIdHex);
            pendingReconciliation({ ok: false, reason });
          }
        }
      }
    } catch { /* stream closed */ }

    if (this.#relayStreams.get(sessionIdHex) === stream) {
      this.#relayStreams.delete(sessionIdHex);
    }
    this.#ctx.onRelayDisconnected(sessionIdHex, myPubkeyHex);
  }

  // ─── SESSION-006 reconnect ──────────────────────────────────────────────────

  async reconnectRelayStream(sessionIdHex: string, myPubkeyHex: string): Promise<void> {
    if (this.#reconnectInProgress.has(sessionIdHex)) return;
    this.#reconnectInProgress.add(sessionIdHex);

    const reconnectTimeoutMs = this.#ctx.reconnectTimeoutMs;
    const deadline = Date.now() + reconnectTimeoutMs;
    let backoff = RECONNECT_INITIAL_BACKOFF_MS;

    try {
      while (Date.now() < deadline) {
        const session = this.#ctx.getSession(sessionIdHex);
        if (!session || session.desynchronized) return;
        if (session.status !== "transport_lost") return;

        try {
          const relayPeerId = session.relay_endpoint.peer_id;
          const relayMultiaddr = session.relay_endpoint.multiaddrs[0];

          if (relayMultiaddr) {
            try { await this.#ctx.node.dial(relayMultiaddr); } catch { /* non-fatal */ }
          }

          let newStream: Stream;
          try {
            newStream = await this.#ctx.node.newStream(relayPeerId, RELAY_PROTOCOL_ID);
          } catch {
            throw new Error("relay_unreachable");
          }

          const myPubkey = Buffer.from(myPubkeyHex, "hex");
          const authResult = await this.#performRelayAuth(newStream, myPubkey);
          if (!authResult.ok) {
            newStream.abort(new Error("auth_failed"));
            throw new Error("relay_auth_failed");
          }

          const sessionAfterAuth = this.#ctx.getSession(sessionIdHex);
          if (!sessionAfterAuth || sessionAfterAuth.desynchronized) {
            newStream.abort(new Error("session_gone"));
            return;
          }

          this.#relayStreams.set(sessionIdHex, newStream);
          sessionAfterAuth.status = "active";
          void this.#ctx.persistence?.persistSession(sessionIdHex, sessionAfterAuth);

          if (this.#ctx.hashQueue) {
            const pendingEntries = await this.#ctx.hashQueue.getPending(sessionIdHex);
            if (pendingEntries.length > 0) {
              this.#ctx.logger.info("client.hashqueue.resubmit.pending", {
                agentId: myPubkeyHex,
                sessionId: sessionIdHex,
                pendingCount: pendingEntries.length,
              });
            }
          }

          this.runRelayStreamReader(sessionIdHex, newStream, myPubkeyHex, authResult.iter);
          return;
        } catch {
          const remaining = deadline - Date.now();
          if (remaining <= 0) break;
          const waitMs = Math.min(backoff, remaining);
          await new Promise<void>((r) => setTimeout(r, waitMs));
          backoff = Math.min(backoff * 2, RECONNECT_MAX_BACKOFF_MS);
        }
      }
    } finally {
      this.#reconnectInProgress.delete(sessionIdHex);
    }
  }

  // ─── Content frame handler (MSG-004) ─────────────────────────────────────────

  async handleContentStream(stream: Stream): Promise<void> {
    let payload: Uint8Array | undefined;
    try {
      for await (const chunk of lp.decode(stream)) {
        payload = toU8(chunk as unknown);
        break;
      }
    } catch {
      stream.abort(new Error("content_stream_error"));
      return;
    }

    if (!payload) { stream.close().catch(() => {}); return; }

    let frame: Record<string, unknown>;
    try {
      frame = decode(payload) as Record<string, unknown>;
    } catch {
      stream.close().catch(() => {});
      return;
    }

    if (frame["type"] !== "content_frame") { stream.close().catch(() => {}); return; }

    const sessionIdRaw = frame["session_id"];
    const sessionIdBytes = sessionIdRaw instanceof Uint8Array ? sessionIdRaw
      : Buffer.isBuffer(sessionIdRaw) ? new Uint8Array(sessionIdRaw as Buffer) : null;
    if (!sessionIdBytes) { stream.close().catch(() => {}); return; }

    const sessionIdHex = Buffer.from(sessionIdBytes).toString("hex");
    const session = this.#ctx.getSession(sessionIdHex);
    if (!session || session.desynchronized) { stream.close().catch(() => {}); return; }

    const contentBytesRaw = frame["content_bytes"];
    const contentBytes = contentBytesRaw instanceof Uint8Array ? contentBytesRaw
      : Buffer.isBuffer(contentBytesRaw) ? new Uint8Array(contentBytesRaw as Buffer) : null;
    if (!contentBytes) { stream.close().catch(() => {}); return; }

    const declaredHashRaw = frame["content_hash"];
    const declaredHash = declaredHashRaw instanceof Uint8Array ? declaredHashRaw
      : Buffer.isBuffer(declaredHashRaw) ? new Uint8Array(declaredHashRaw as Buffer) : null;
    if (!declaredHash || declaredHash.length !== 32) { stream.close().catch(() => {}); return; }

    const declaredHashHex = Buffer.from(declaredHash).toString("hex");

    const ps2MapEarly = this.#pendingS2.get(sessionIdHex);
    const s2EntryEarly = ps2MapEarly?.get(declaredHashHex);

    if (s2EntryEarly) {
      const recomputed = new Uint8Array(
        createHash("sha256").update(new Uint8Array([s2EntryEarly.leaf_kind])).update(contentBytes).digest()
      );
      if (Buffer.compare(Buffer.from(recomputed), Buffer.from(declaredHash)) !== 0) {
        clearTimeout(s2EntryEarly.timer_handle);
        ps2MapEarly!.delete(declaredHashHex);
        this.#desync(sessionIdHex, "content_hash_mismatch");
        stream.close().catch(() => {});
        return;
      }
    } else {
      const msgHash = new Uint8Array(
        createHash("sha256").update(new Uint8Array([0x00])).update(contentBytes).digest()
      );
      const ctrlHash = new Uint8Array(
        createHash("sha256").update(new Uint8Array([0x02])).update(contentBytes).digest()
      );
      const matchesMsg = Buffer.compare(Buffer.from(msgHash), Buffer.from(declaredHash)) === 0;
      const matchesCtrl = Buffer.compare(Buffer.from(ctrlHash), Buffer.from(declaredHash)) === 0;
      if (!matchesMsg && !matchesCtrl) {
        this.#tamperedContentClaims.get(sessionIdHex)?.add(declaredHashHex);
        stream.close().catch(() => {});
        return;
      }
    }

    const contentHashHex = declaredHashHex;
    const ps2Map = this.#pendingS2.get(sessionIdHex);
    const s2Entry = ps2Map?.get(contentHashHex);

    if (s2Entry) {
      ps2Map!.delete(contentHashHex);
      clearTimeout(s2Entry.timer_handle);
      this.#crossCheckDelivery(
        sessionIdHex,
        s2Entry.s2,
        s2Entry.s2_cbor,
        s2Entry.s1_fields,
        s2Entry.leaf_kind,
        contentBytes,
        s2Entry.is_own_send,
        s2Entry.echo_resolve,
      );
    } else {
      const pending = this.#pendingContent.get(sessionIdHex);
      if (pending) {
        if (pending.size >= PENDING_CONTENT_BOUND) {
          const firstKey = pending.keys().next().value;
          if (firstKey !== undefined) pending.delete(firstKey);
        }
        pending.set(contentHashHex, { content_bytes: contentBytes, arrived_at: Date.now() });
        console.debug(`[cello-client] content_without_hash: session=${sessionIdHex} hash=${contentHashHex}`);
      }
    }

    stream.close().catch(() => {});
  }

  // ─── Relay auth ──────────────────────────────────────────────────────────────

  async performRelayAuth(
    stream: Stream,
    myPubkey: Uint8Array,
  ): Promise<{ ok: true; iter: AsyncIterator<Uint8Array> } | { ok: false; reason: "relay_auth_failed" | "relay_auth_error" }> {
    return this.#performRelayAuth(stream, myPubkey);
  }

  async #performRelayAuth(
    stream: Stream,
    myPubkey: Uint8Array,
  ): Promise<{ ok: true; iter: AsyncIterator<Uint8Array> } | { ok: false; reason: "relay_auth_failed" | "relay_auth_error" }> {
    const iter = (lp.decode(stream) as AsyncIterable<unknown>)[Symbol.asyncIterator]() as AsyncIterator<Uint8Array>;

    const { value: challengeRaw, done } = await nextWithTimeout(iter, RELAY_AUTH_TIMEOUT_MS);
    if (done || challengeRaw === undefined) return { ok: false, reason: "relay_auth_error" };

    const challengeBytes = toU8(challengeRaw);
    let challenge: Record<string, unknown>;
    try {
      challenge = decode(challengeBytes) as Record<string, unknown>;
    } catch {
      return { ok: false, reason: "relay_auth_error" };
    }

    if (challenge["type"] !== "relay_auth_challenge") return { ok: false, reason: "relay_auth_error" };

    const nonce = toU8(challenge["nonce"]);
    if (nonce.length !== 32) return { ok: false, reason: "relay_auth_error" };

    const domain = Buffer.from(AUTH_DOMAIN, "utf8");
    const authMsg = new Uint8Array(Buffer.concat([domain, nonce, myPubkey]));
    const msgHash = new Uint8Array(createHash("sha256").update(authMsg).digest());
    const signature = await this.#ctx.keyProvider.sign(msgHash);

    const responseFrame = CBOR_ENC.encode({
      type: "relay_auth_response",
      pubkey: myPubkey,
      signature,
    }) as Uint8Array;
    stream.send(lp.encode.single(responseFrame));

    const { value: ackRaw, done: ackDone } = await nextWithTimeout(iter, RELAY_AUTH_TIMEOUT_MS);
    if (ackDone || ackRaw === undefined) return { ok: false, reason: "relay_auth_error" };

    let ackFrame: Record<string, unknown>;
    try {
      ackFrame = decode(toU8(ackRaw)) as Record<string, unknown>;
    } catch {
      return { ok: false, reason: "relay_auth_error" };
    }

    if (ackFrame["type"] === "relay_auth_failed") return { ok: false, reason: "relay_auth_failed" };
    if (ackFrame["type"] !== "relay_auth_ok") return { ok: false, reason: "relay_auth_error" };

    return { ok: true, iter };
  }

  // ─── Inbound leaf deliver ────────────────────────────────────────────────────

  #handleInboundLeafDeliver(
    sessionIdHex: string,
    frame: Record<string, unknown>,
    myPubkeyHex: string,
  ): void {
    const session = this.#ctx.getSession(sessionIdHex);
    if (!session || session.desynchronized) return;

    const s2CborRaw = frame["structure2_cbor"];
    const s2Cbor = s2CborRaw instanceof Uint8Array ? s2CborRaw
      : Buffer.isBuffer(s2CborRaw) ? new Uint8Array(s2CborRaw as Buffer) : null;
    if (!s2Cbor) { this.#desync(sessionIdHex, "structure2_malformed"); return; }

    let s2Arr: unknown[];
    try {
      const decoded = decode(s2Cbor);
      if (!Array.isArray(decoded) || decoded.length !== 6) {
        this.#desync(sessionIdHex, "structure2_malformed"); return;
      }
      s2Arr = decoded;
    } catch {
      this.#desync(sessionIdHex, "structure2_malformed"); return;
    }

    const seqNum = typeof s2Arr[0] === "number" ? s2Arr[0] : null;
    if (seqNum === null) { this.#desync(sessionIdHex, "structure2_fields_invalid"); return; }

    const senderPubkey = toU8Safe(s2Arr[1]);
    const contentHash = toU8Safe(s2Arr[2]);
    const senderSig = toU8Safe(s2Arr[3]);
    const prevRoot = toU8Safe(s2Arr[5]);

    if (!senderPubkey || senderPubkey.length !== 32) { this.#desync(sessionIdHex, "structure2_fields_invalid"); return; }
    if (!contentHash || contentHash.length !== 32) { this.#desync(sessionIdHex, "structure2_fields_invalid"); return; }
    if (!senderSig || senderSig.length !== 64) { this.#desync(sessionIdHex, "structure2_fields_invalid"); return; }
    if (!prevRoot || prevRoot.length !== 32) { this.#desync(sessionIdHex, "structure2_fields_invalid"); return; }

    const s2: Structure2 = {
      sequence_number: seqNum,
      sender_pubkey: senderPubkey,
      content_hash: contentHash,
      sender_signature: senderSig,
      scan_result: { score: null, verdict: "unscanned", model_hash: new Uint8Array(32) },
      prev_root: prevRoot,
    };

    const relayRecvSeq = this.#relayRecvSeq.get(sessionIdHex) ?? 0;
    if (seqNum <= relayRecvSeq) { this.#desync(sessionIdHex, "sequence_replay"); return; }
    if (seqNum > relayRecvSeq + 1) { this.#desync(sessionIdHex, "sequence_gap"); return; }
    this.#relayRecvSeq.set(sessionIdHex, seqNum);

    const s1CborRaw = frame["structure1_cbor"];
    const s1Cbor = s1CborRaw instanceof Uint8Array ? s1CborRaw
      : Buffer.isBuffer(s1CborRaw) ? new Uint8Array(s1CborRaw as Buffer) : null;
    if (!s1Cbor) { this.#desync(sessionIdHex, "structure1_malformed"); return; }

    let s1Fields: Structure1Fields | null = null;
    try {
      const s1Decoded = decode(s1Cbor);
      if (Array.isArray(s1Decoded) && s1Decoded.length === 6) {
        const lss = s1Decoded[4];
        const ts = s1Decoded[5];
        if (typeof lss === "number" && (typeof ts === "number" || typeof ts === "bigint")) {
          s1Fields = { last_seen_seq: lss, timestamp: ts };
        }
      }
    } catch { /* fall through */ }

    if (!s1Fields) { this.#desync(sessionIdHex, "structure1_malformed"); return; }

    if (!verify(senderPubkey, s1Cbor, s2.sender_signature)) {
      this.#desync(sessionIdHex, "signature_verification_failed"); return;
    }

    const senderHex = Buffer.from(senderPubkey).toString("hex");
    const isOwnSend = senderHex === myPubkeyHex;

    const contentHashHex = Buffer.from(contentHash).toString("hex");
    const leafKind = typeof frame["leaf_kind"] === "number" ? frame["leaf_kind"] : 0x00;

    const tamperedClaims = this.#tamperedContentClaims.get(sessionIdHex);
    if (tamperedClaims?.has(contentHashHex)) {
      tamperedClaims.delete(contentHashHex);
      this.#desync(sessionIdHex, "content_hash_mismatch"); return;
    }

    const ownPendingContent = isOwnSend ? this.#ctx.getOwnPendingContent(sessionIdHex) : undefined;
    const pendingContent = this.#pendingContent.get(sessionIdHex);
    const contentEntry = isOwnSend
      ? ownPendingContent?.get(contentHashHex)
      : pendingContent?.get(contentHashHex);

    let echoResolve: (() => void) | undefined;
    if (isOwnSend) {
      const resolvers = this.#ctx.getOwnEchoResolvers(sessionIdHex);
      echoResolve = resolvers?.get(seqNum);
      resolvers?.delete(seqNum);
    }

    if (contentEntry) {
      if (isOwnSend) { ownPendingContent!.delete(contentHashHex); }
      else { pendingContent!.delete(contentHashHex); }
      this.#crossCheckDelivery(sessionIdHex, s2, s2Cbor, s1Fields, leafKind, contentEntry.content_bytes, isOwnSend, echoResolve);
    } else {
      const timerHandle = setTimeout(() => {
        const ps2Map = this.#pendingS2.get(sessionIdHex);
        if (ps2Map?.has(contentHashHex)) {
          ps2Map.delete(contentHashHex);
          this.#desync(sessionIdHex, "content_missing");
        }
      }, this.#ctx.contentGraceMs);

      const entry: PendingS2Entry = {
        s2,
        s2_cbor: s2Cbor,
        s1_fields: s1Fields,
        leaf_kind: leafKind,
        sequence_number: seqNum,
        content_hash: contentHash,
        is_own_send: isOwnSend,
        arrived_at: Date.now(),
        timer_handle: timerHandle,
        echo_resolve: echoResolve,
      };
      this.#pendingS2.get(sessionIdHex)?.set(contentHashHex, entry);
    }
  }

  #crossCheckDelivery(
    sessionIdHex: string,
    s2: Structure2,
    s2Cbor: Uint8Array,
    s1Fields: Structure1Fields,
    leafKind: number,
    contentBytes: Uint8Array,
    isOwnSend: boolean,
    echoResolve?: () => void,
  ): void {
    const session = this.#ctx.getSession(sessionIdHex);
    if (!session || session.desynchronized) return;

    const readyQ = this.#readyQueue.get(sessionIdHex);
    if (!readyQ) return;

    readyQ.set(s2.sequence_number, { s2, s2_cbor: s2Cbor, s1_fields: s1Fields, leaf_kind: leafKind, content_bytes: contentBytes, is_own_send: isOwnSend, echo_resolve: echoResolve });
    this.#drainReadyQueue(sessionIdHex);
  }

  #drainReadyQueue(sessionIdHex: string): void {
    const session = this.#ctx.getSession(sessionIdHex);
    const readyQ = this.#readyQueue.get(sessionIdHex);
    if (!session || !readyQ || session.desynchronized) return;

    while (true) {
      const nextSeq = session.next_expected_seq;
      const entry = readyQ.get(nextSeq);
      if (!entry) break;
      readyQ.delete(nextSeq);

      const { s2, s2_cbor, s1_fields, leaf_kind, content_bytes, is_own_send, echo_resolve } = entry;

      const expectedPrevRoot = session.local_tree_leaves.length === 0
        ? session.genesis_prev_root
        : (() => {
            const inputs: LeafInput[] = session.local_tree_leaves.map(l => ({
              kind: l.kind,
              data: l.s2_cbor,
            }));
            return merkleRoot(buildMerkleTree(inputs));
          })();

      if (Buffer.compare(Buffer.from(s2.prev_root), Buffer.from(expectedPrevRoot)) !== 0) {
        this.#desync(sessionIdHex, "prev_root_mismatch"); return;
      }

      if (!is_own_send && s1_fields.last_seen_seq > session.last_sent_seq) {
        this.#desync(sessionIdHex, "sequence_causal_inconsistency"); return;
      }

      const kind: "msg" | "ctrl" = leaf_kind === 0x02 ? "ctrl" : "msg";
      const leafIndex = session.local_tree_leaves.length;
      session.local_tree_leaves.push({ kind, s2_cbor });
      session.next_expected_seq += 1;

      if (this.#ctx.persistence) {
        void this.#ctx.persistence.persistSessionTreeLeaf({
          sessionIdHex,
          leafIndex,
          leafKind: kind,
          s2Cbor: s2_cbor,
          sequenceNumber: s2.sequence_number,
        });
      }

      const leafHash = new Uint8Array(
        createHash("sha256").update(new Uint8Array([leaf_kind])).update(s2_cbor).digest()
      );

      if (is_own_send) {
        session.last_sent_seq = s2.sequence_number;
        void this.#ctx.persistence?.persistSession(sessionIdHex, session);
        echo_resolve?.();
      } else {
        session.last_seen_seq = s2.sequence_number;
        if (kind === "ctrl" && session.status === "active") {
          session.status = "sealing";
          void this.#ctx.persistence?.persistSession(sessionIdHex, session);
          void (async () => {
            // Notify the seal manager that responder received SEAL leaf
            this.#ctx.handleSealVerified(sessionIdHex, {
              type: "_responder_seal_trigger",
              sessionIdHex,
            });
          })();
        } else {
          void this.#ctx.persistence?.persistSession(sessionIdHex, session);
          const msg: ReceivedMessage = {
            type: "message",
            content: content_bytes,
            senderPubkey: s2.sender_pubkey,
            sequenceNumber: s2.sequence_number,
            leafHash,
          };
          this.#ctx.enqueueReceivedMessage(sessionIdHex, msg);
        }
      }
    }
  }

  #desync(sessionIdHex: string, reason: string): void {
    const session = this.#ctx.getSession(sessionIdHex);
    if (!session) return;

    session.desynchronized = true;
    void this.#ctx.persistence?.persistSession(sessionIdHex, session);

    const ps2 = this.#pendingS2.get(sessionIdHex);
    if (ps2) {
      for (const entry of ps2.values()) {
        clearTimeout(entry.timer_handle);
        entry.echo_resolve?.();
      }
      ps2.clear();
    }

    const resolvers = this.#ctx.getOwnEchoResolvers(sessionIdHex);
    if (resolvers) {
      for (const resolve of resolvers.values()) resolve();
      resolvers.clear();
    }

    this.#pendingContent.get(sessionIdHex)?.clear();
    this.#ctx.getOwnPendingContent(sessionIdHex)?.clear();
    this.#relayRecvSeq.delete(sessionIdHex);
    this.#readyQueue.get(sessionIdHex)?.clear();

    const ackResolve = this.#ctx.getPendingAckResolver(sessionIdHex);
    if (ackResolve) {
      this.#ctx.deletePendingAckResolver(sessionIdHex);
      ackResolve({ ok: false, reason });
    }

    console.warn(`[cello-client] session_desynchronized: ${sessionIdHex} reason=${reason}`);
  }

  // ─── Gap fill (PERSIST-014) ──────────────────────────────────────────────────

  async performGapFillReconciliation(
    sessionIdHex: string,
    fromSeq: number,
    toSeq: number,
    correlationId: string,
  ): Promise<void> {
    const session = this.#ctx.getSession(sessionIdHex);
    if (!session) return;

    const startMs = Date.now();
    const gapSize = toSeq - fromSeq;

    const relayStream = this.#relayStreams.get(sessionIdHex);
    if (!relayStream || relayStream.status !== "open") {
      this.#ctx.logger.error("session.gap.fill.failed", {
        sessionId: sessionIdHex,
        reason: "relay_stream_unavailable",
        correlationId,
      });
      return;
    }

    const gapFillRequestFrame = CBOR_ENC.encode({
      type: "gap_fill_request",
      session_id: session.session_id,
      from_seq: fromSeq,
      to_seq: toSeq,
    }) as Uint8Array;

    const responsePromise = new Promise<{ ok: true; leaves: unknown[] } | { ok: false; reason: string }>((resolve) => {
      this.#pendingGapFillResolvers.set(sessionIdHex, resolve);
    });

    try {
      relayStream.send(lp.encode.single(gapFillRequestFrame));
    } catch {
      this.#pendingGapFillResolvers.delete(sessionIdHex);
      this.#ctx.logger.error("session.gap.fill.failed", {
        sessionId: sessionIdHex,
        reason: "relay_send_failed",
        correlationId,
      });
      return;
    }

    const responseResult = await responsePromise;

    if (!responseResult.ok) {
      this.#ctx.logger.error("session.gap.fill.failed", {
        sessionId: sessionIdHex,
        reason: responseResult.reason,
        correlationId,
      });
      return;
    }

    const gapLeaves = responseResult.leaves as Array<Record<string, unknown>>;
    for (let i = 0; i < gapLeaves.length; i++) {
      const leaf = gapLeaves[i]!;
      const senderPubkey = leaf["sender_pubkey"] instanceof Uint8Array ? leaf["sender_pubkey"]
        : Buffer.isBuffer(leaf["sender_pubkey"]) ? new Uint8Array(leaf["sender_pubkey"] as Buffer) : null;
      const structure1Cbor = leaf["structure1_cbor"] instanceof Uint8Array ? leaf["structure1_cbor"]
        : Buffer.isBuffer(leaf["structure1_cbor"]) ? new Uint8Array(leaf["structure1_cbor"] as Buffer) : null;
      const senderSignature = leaf["sender_signature"] instanceof Uint8Array ? leaf["sender_signature"]
        : Buffer.isBuffer(leaf["sender_signature"]) ? new Uint8Array(leaf["sender_signature"] as Buffer) : null;

      if (!senderPubkey || !structure1Cbor || !senderSignature) {
        this.#ctx.logger.warn("session.gap.fill.leaf.invalid", {
          sessionId: sessionIdHex,
          leafIndex: i,
          reason: "missing_fields",
          correlationId,
        });
        return;
      }

      if (!verify(senderPubkey, structure1Cbor, senderSignature)) {
        this.#ctx.logger.warn("session.gap.fill.leaf.invalid", {
          sessionId: sessionIdHex,
          leafIndex: i,
          reason: "signature_invalid",
          correlationId,
        });
        return;
      }
    }

    const latestSeq = gapLeaves.reduce((max, l) => {
      const seq = typeof l["sequence_number"] === "number" ? l["sequence_number"] : max;
      return Math.max(max, seq);
    }, session.next_expected_seq - 1);
    session.next_expected_seq = latestSeq + 1;

    this.#ctx.logger.info("session.reconciliation.completed", {
      sessionId: sessionIdHex,
      gapSize,
      durationMs: Date.now() - startMs,
      correlationId,
    });

    const localRoot = this.#computeLocalRoot(session);
    const dirStream = this.#directoryStreams.get(sessionIdHex);
    if (localRoot && dirStream && dirStream.status === "open") {
      const sealAttemptFrame = CBOR_ENC.encode({
        type: "seal_attempt",
        session_id: session.session_id,
        reported_root: localRoot,
        reported_seq: session.next_expected_seq - 1,
      }) as Uint8Array;
      try {
        dirStream.send(lp.encode.single(sealAttemptFrame));
      } catch {
        this.#ctx.logger.error("session.gap.fill.failed", {
          sessionId: sessionIdHex,
          reason: "seal_retry_send_failed",
          correlationId,
        });
      }
    }
  }

  #handleGapFillResponse(sessionIdHex: string, frame: Record<string, unknown>): void {
    const resolver = this.#pendingGapFillResolvers.get(sessionIdHex);
    if (!resolver) return;
    this.#pendingGapFillResolvers.delete(sessionIdHex);
    const leavesRaw = Array.isArray(frame["leaves"]) ? frame["leaves"] as unknown[] : [];
    resolver({ ok: true, leaves: leavesRaw });
  }

  #computeLocalRoot(session: SessionRecord): Uint8Array | null {
    if (!session.local_tree_leaves || session.local_tree_leaves.length === 0) return null;
    const leafInputs: LeafInput[] = session.local_tree_leaves.map((l) => ({
      kind: l.kind,
      data: l.s2_cbor,
    }));
    const tree = buildMerkleTree(leafInputs);
    return merkleRoot(tree);
  }
}

export { DEFAULT_RECONNECT_TIMEOUT_MS };
