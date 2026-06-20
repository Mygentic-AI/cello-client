/**
 * M7 DOD-SPINE-6 / MSG-001-3b — daemon-side relay witness client (PER AGENT).
 *
 * In CELLO the relay is the ordering/witness authority (Structure 2): it never sees
 * plaintext (content is peer↔peer), only the SIGNED content-hash leaves. It assigns
 * the canonical `sequence_number` and forwards each witnessed leaf to the counterparty
 * (`leaf_deliver`). A `cello_send` whose hash the relay never witnessed has no canonical
 * sequence and is not a complete CELLO message — so the session submits the message leaf
 * hash here, in parallel with the direct content delivery.
 *
 * ONE stream per AGENT, not per session. The relay authenticates a stream by the agent's
 * K_local pubkey and keys its delivery/queue maps by that pubkey (relay-node
 * #handleRelayStream / #processHashSubmit), so a second stream for the same pubkey would
 * OVERWRITE the first's delivery stream and steal its queued `leaf_deliver`s. The protocol
 * is designed for one relay connection per agent identity multiplexing all that agent's
 * sessions — every wire frame carries `session_id`. So this client is shared across an
 * agent's sessions: submits are globally FIFO-serialized on the stream (a `hash_submit_ack`
 * carries NO session_id, so at most one submit may be outstanding at a time and acks match
 * the queue head in order), while inbound `leaf_deliver` (which DOES carry `session_id`) is
 * routed to the owning session's handler.
 *
 * The stream is (re)dialed from whatever live session node is current at submit time, so it
 * survives individual session teardown (the relay treats a same-pubkey reconnect as a
 * reconnect, re-auths, and re-drains). Reuses only proven wire shapes:
 *   - auth: mirror of the retired client's relay challenge-response (proven against this relay)
 *   - Structure 1 + hash_submit: mirror of the retired client's seal-leaf submit path
 *   - server contract: `packages/relay/src/relay-node.ts`
 *
 * Crypto: Ed25519 RFC 8032. Relay auth domain: "CELLO-RELAY-AUTH-v1".
 */
import { createHash } from "node:crypto";
import * as lp from "it-length-prefixed";
import { Encoder, decode } from "cbor-x";
import type { Stream } from "@libp2p/interface";
import type { CelloNode } from "@cello-protocol/transport";
import type { KeyProvider } from "@cello-protocol/crypto";
import type { Logger } from "./types.js";

const CBOR_ENC = new Encoder({ tagUint8Array: false });

export const RELAY_PROTOCOL_ID = "/cello/relay/1.0.0";
export const RELAY_AUTH_DOMAIN = "CELLO-RELAY-AUTH-v1";
/** Structure 1 leaf kind: 0x00 = message, 0x02 = control (matches the relay). */
export const LEAF_KIND_MSG = 0x00;
/** Control leaf (SEAL etc.) — two distinct-sender ctrl leaves trigger directory notarization. */
export const LEAF_KIND_CTRL = 0x02;

const RELAY_AUTH_TIMEOUT_MS = 5_000;
const HASH_SUBMIT_TIMEOUT_MS = 10_000;

/**
 * The Ed25519-signed payload that proves K_local ownership to the relay:
 * SHA-256("CELLO-RELAY-AUTH-v1" || nonce || pubkey). The relay verifies the
 * signature against exactly this hash (relay-node #handleRelayStream).
 */
export function buildRelayAuthPayload(nonce: Uint8Array, pubkey: Uint8Array): Uint8Array {
  const domain = Buffer.from(RELAY_AUTH_DOMAIN, "utf8");
  const authMsg = Buffer.concat([domain, nonce, pubkey]);
  return new Uint8Array(createHash("sha256").update(authMsg).digest());
}

/**
 * Canonical Structure 1 CBOR the sender signs and the relay re-verifies byte-for-byte:
 * [1, content_hash(32), sender_pubkey(32), session_id(16), last_seen_seq, timestamp].
 * The relay decodes this (decodeStructure1) AND verifies Ed25519 over these EXACT bytes,
 * so the encoded bytes — not a re-encoding — are what gets signed and sent.
 */
export function encodeStructure1(
  contentHash: Uint8Array,
  senderPubkey: Uint8Array,
  sessionId: Uint8Array,
  lastSeenSeq: number,
  timestamp: number,
): Uint8Array {
  return CBOR_ENC.encode([1, contentHash, senderPubkey, sessionId, lastSeenSeq, timestamp]) as Uint8Array;
}

export interface LeafDeliverFrame {
  sequence_number: number;
  leaf_kind: number;
  structure1_cbor: Uint8Array;
  structure2_cbor: Uint8Array;
}

/** Result of a single relay hash submission. */
export type SubmitResult = { ok: true; sequence_number: number } | { ok: false; reason: string };
type AckResolver = (r: SubmitResult) => void;

export interface AgentRelayClientOpts {
  relayPeerId: string;
  relayAddrs: string[];
  /** The agent's K_local signing key (relay auth + leaf signatures). */
  keyProvider: KeyProvider;
  /** The agent's K_local public key (32 bytes) — relay routes delivery by this. */
  senderPubkey: Uint8Array;
  logger: Logger;
}

/**
 * Extract a real message from a thrown value. libp2p / cross-package errors are not
 * always `instanceof Error` in this realm (multi-version split), so fall back to a
 * `message` property or JSON — never the useless "[object Object]".
 */
export function extractErrorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (err && typeof err === "object" && typeof (err as { message?: unknown }).message === "string") {
    return (err as { message: string }).message;
  }
  try {
    return JSON.stringify(err);
  } catch {
    return String(err);
  }
}

function toU8(v: unknown): Uint8Array {
  if (v instanceof Uint8Array) return v;
  if (Buffer.isBuffer(v)) return new Uint8Array(v as Buffer);
  if (v && typeof (v as { subarray?: unknown }).subarray === "function") {
    return (v as { subarray(): Uint8Array }).subarray();
  }
  if (v && typeof (v as { slice?: unknown }).slice === "function") {
    return (v as { slice(): Uint8Array }).slice();
  }
  return new Uint8Array();
}

async function nextWithTimeout(
  iter: AsyncIterator<Uint8Array>,
  ms: number,
): Promise<{ value: Uint8Array | undefined; done: boolean }> {
  let timer!: ReturnType<typeof setTimeout>;
  const timeout = new Promise<{ value: undefined; done: true }>((resolve) => {
    timer = setTimeout(() => resolve({ value: undefined, done: true }), ms);
  });
  try {
    const result = (await Promise.race([iter.next(), timeout])) as IteratorResult<Uint8Array>;
    return { value: result.value, done: !!result.done };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Per-AGENT relay witness client. Shared across all of an agent's sessions; one
 * authenticated stream at a time (the relay keys by agent pubkey). Submits are FIFO and
 * single-in-flight on the stream; `leaf_deliver` is routed by session_id.
 */
export class AgentRelayClient {
  readonly #relayPeerId: string;
  readonly #relayAddrs: string[];
  readonly #keyProvider: KeyProvider;
  readonly #senderPubkey: Uint8Array;
  readonly #logger: Logger;

  #stream: Stream | null = null;
  #connecting: Promise<boolean> | null = null;
  #closed = false;
  /**
   * PER-SESSION highest relay-assigned sequence (session_id hex → seq). The relay's
   * `seq_counter` is per session, and it rejects `last_seen_seq > seq_counter`, so each
   * session's submit MUST carry that session's own high-water mark — NOT an agent-global
   * one (which would make a newer session's first submit look ahead and get rejected).
   */
  readonly #lastSeen = new Map<string, number>();
  /** The one outstanding submit's resolver (global FIFO — ack carries no session_id). */
  #pendingAck: AckResolver | null = null;
  /** The session_id hex of the in-flight submit, so its ack updates the right #lastSeen. */
  #pendingAckSessionHex: string | null = null;
  /** Serializes submits so only one is in flight at a time across all sessions. */
  #submitChain: Promise<unknown> = Promise.resolve();
  /** session_id hex → { the live node to (re)dial from, inbound leaf handler }. */
  readonly #sessions = new Map<string, { node: CelloNode; onLeafDeliver: (frame: LeafDeliverFrame) => void }>();

  constructor(opts: AgentRelayClientOpts) {
    this.#relayPeerId = opts.relayPeerId;
    this.#relayAddrs = opts.relayAddrs;
    this.#keyProvider = opts.keyProvider;
    this.#senderPubkey = opts.senderPubkey;
    this.#logger = opts.logger;
  }

  /**
   * Register a session's inbound leaf handler + a live node to (re)dial the relay from
   * (idempotent). Storing the node per session lets a pure-receiver session re-establish
   * the shared stream if the node that originally dialed is torn down (L5).
   */
  registerSession(sessionIdHex: string, node: CelloNode, onLeafDeliver?: (frame: LeafDeliverFrame) => void): void {
    this.#sessions.set(sessionIdHex, { node, onLeafDeliver: onLeafDeliver ?? (() => {}) });
  }

  /** Remove a session; caller closes the client when no sessions remain. */
  unregisterSession(sessionIdHex: string): void {
    this.#sessions.delete(sessionIdHex);
    this.#lastSeen.delete(sessionIdHex);
  }

  hasSessions(): boolean {
    return this.#sessions.size > 0;
  }

  /** Settle the one outstanding submit (if any) exactly once. */
  #settlePending(r: SubmitResult): void {
    const resolve: AckResolver | null = this.#pendingAck;
    this.#pendingAck = null;
    this.#pendingAckSessionHex = null;
    if (resolve) resolve(r);
  }

  /**
   * Tear down the current stream (drops it so the next submit re-dials). Used on a submit
   * timeout: because `hash_submit_ack` carries no session_id, ack↔submit matching is purely
   * FIFO, so a LATE ack from a timed-out submit would settle the NEXT submit's resolver and
   * shift every subsequent ack by one. Resetting the stream prevents that desync (the relay
   * re-auths + re-drains on the reconnect).
   */
  #resetStream(): void {
    const stream = this.#stream;
    this.#stream = null;
    if (stream) {
      try { void stream.close(); } catch { /* best-effort */ }
    }
  }

  #bumpLastSeen(sessionIdHex: string, seq: number): void {
    if (seq < 0) return;
    const prev = this.#lastSeen.get(sessionIdHex) ?? 0;
    if (seq > prev) this.#lastSeen.set(sessionIdHex, seq);
  }

  /** True if this Structure-1 leaf was authored by US (sender_pubkey === our K_local). */
  #isOwnLeaf(structure1Cbor: Uint8Array): boolean {
    try {
      const arr = decode(structure1Cbor) as unknown[];
      // Structure 1 = [1, content_hash, sender_pubkey, session_id, last_seen_seq, ts].
      const senderPubkey = toU8(arr[2]);
      return Buffer.from(senderPubkey).equals(Buffer.from(this.#senderPubkey));
    } catch {
      // Undecodable → treat as NOT ours (conservative: don't suppress a real counterparty leaf).
      return false;
    }
  }

  #dispatch(frame: Record<string, unknown>): void {
    const type = frame["type"];
    if (type === "hash_submit_ack") {
      const seq = typeof frame["sequence_number"] === "number" ? frame["sequence_number"] : -1;
      // DO NOT advance #lastSeen here: the ack is for OUR OWN leaf. last_seen_seq must track
      // the highest COUNTERPARTY sequence we've observed (the directory's causal check —
      // SESSION-003 SI-003 — rejects a leaf whose last_seen_seq exceeds the max sequence of
      // OTHER-sender leaves before it). Advancing on our own ack would inflate it and trip
      // causal_chain_violated on a subsequent submit (e.g. the SEAL leaf after a sent message).
      this.#settlePending(seq >= 0 ? { ok: true, sequence_number: seq } : { ok: false, reason: "relay_ack_malformed" });
    } else if (type === "hash_submit_error") {
      const reason = typeof frame["reason"] === "string" ? frame["reason"] : "relay_rejected";
      this.#settlePending({ ok: false, reason });
    } else if (type === "leaf_deliver") {
      const seq = typeof frame["sequence_number"] === "number" ? frame["sequence_number"] : -1;
      const sidHex = Buffer.from(toU8(frame["session_id"])).toString("hex");
      const s1 = toU8(frame["structure1_cbor"]);
      // Advance last_seen_seq ONLY for a COUNTERPARTY leaf. The relay also echoes our OWN
      // leaf back as a leaf_deliver — that must NOT advance it (same reason as the ack above).
      if (seq >= 0 && !this.#isOwnLeaf(s1)) this.#bumpLastSeen(sidHex, seq);
      const session = this.#sessions.get(sidHex);
      if (session && seq >= 0) {
        session.onLeafDeliver({
          sequence_number: seq,
          leaf_kind: typeof frame["leaf_kind"] === "number" ? frame["leaf_kind"] : LEAF_KIND_MSG,
          structure1_cbor: s1,
          structure2_cbor: toU8(frame["structure2_cbor"]),
        });
      }
    }
    // session_interrupted / content_park_notify are out of scope here — session interruption
    // is handled by the session node manager's dedicated relay-stream watcher.
  }

  /**
   * Proactively establish the authenticated stream from `node`. The RECEIVER must connect
   * before the counterparty submits, so the relay has its stream to deliver `leaf_deliver`
   * to (otherwise the relay queues until the recipient connects). Best-effort.
   */
  async connect(node: CelloNode): Promise<boolean> {
    return this.#ensureConnected(node);
  }

  /** Ensure an authenticated stream exists, (re)dialing from `node` if needed. */
  async #ensureConnected(node: CelloNode): Promise<boolean> {
    if (this.#closed) return false;
    if (this.#stream) return true;
    if (this.#connecting) return this.#connecting;
    this.#connecting = this.#connect(node).finally(() => { this.#connecting = null; });
    return this.#connecting;
  }

  async #connect(node: CelloNode): Promise<boolean> {
    // Best-effort dial: newStream auto-dials a known peer, but the relay's addrs may not
    // be in the peerstore yet, so dial each addr first. One success is enough.
    let dialed = false;
    let lastDialError = "";
    for (const addr of this.#relayAddrs) {
      try {
        await node.dial(addr);
        dialed = true;
        break;
      } catch (err: unknown) {
        lastDialError = extractErrorMessage(err);
      }
    }
    if (!dialed && this.#relayAddrs.length > 0) {
      this.#logger.warn("session.relay.dial.failed", {
        relayPeerId: this.#relayPeerId,
        relayAddrs: this.#relayAddrs,
        error: lastDialError,
      });
      return false;
    }

    let stream: Stream;
    try {
      stream = await node.newStream(this.#relayPeerId, RELAY_PROTOCOL_ID);
    } catch (err: unknown) {
      this.#logger.warn("session.relay.stream.failed", { relayPeerId: this.#relayPeerId, error: extractErrorMessage(err) });
      return false;
    }

    // ONE shared lp.decode iterator for the whole stream lifetime — splitting it signals
    // EOF to the relay's single-iterator reader and breaks subsequent reads.
    const iter = (lp.decode(stream as unknown as AsyncIterable<Uint8Array>) as AsyncIterable<unknown>)[
      Symbol.asyncIterator
    ]() as AsyncIterator<Uint8Array>;

    if (!(await this.#authenticate(stream, iter))) return false;

    this.#stream = stream;
    this.#logger.info("session.relay.connected", { relayPeerId: this.#relayPeerId });
    this.#startReader(stream, iter);
    return true;
  }

  async #authenticate(stream: Stream, iter: AsyncIterator<Uint8Array>): Promise<boolean> {
    const challengeRes = await nextWithTimeout(iter, RELAY_AUTH_TIMEOUT_MS);
    if (challengeRes.done || challengeRes.value === undefined) {
      this.#logger.warn("session.relay.auth.failed", { relayPeerId: this.#relayPeerId, reason: "no_challenge" });
      return false;
    }
    let challenge: Record<string, unknown>;
    try {
      challenge = decode(toU8(challengeRes.value)) as Record<string, unknown>;
    } catch {
      this.#logger.warn("session.relay.auth.failed", { relayPeerId: this.#relayPeerId, reason: "challenge_decode" });
      return false;
    }
    if (challenge["type"] !== "relay_auth_challenge") {
      this.#logger.warn("session.relay.auth.failed", { relayPeerId: this.#relayPeerId, reason: "not_challenge" });
      return false;
    }
    const nonce = toU8(challenge["nonce"]);
    if (nonce.length !== 32) {
      this.#logger.warn("session.relay.auth.failed", { relayPeerId: this.#relayPeerId, reason: "bad_nonce" });
      return false;
    }
    const authSig = await this.#keyProvider.sign(buildRelayAuthPayload(nonce, this.#senderPubkey));
    try {
      stream.send(lp.encode.single(CBOR_ENC.encode({ type: "relay_auth_response", pubkey: this.#senderPubkey, signature: authSig }) as Uint8Array));
    } catch (err: unknown) {
      this.#logger.warn("session.relay.auth.failed", { relayPeerId: this.#relayPeerId, reason: "response_send", error: extractErrorMessage(err) });
      return false;
    }
    const ackRes = await nextWithTimeout(iter, RELAY_AUTH_TIMEOUT_MS);
    if (ackRes.done || ackRes.value === undefined) {
      this.#logger.warn("session.relay.auth.failed", { relayPeerId: this.#relayPeerId, reason: "no_auth_ok" });
      return false;
    }
    let ackFrame: Record<string, unknown>;
    try {
      ackFrame = decode(toU8(ackRes.value)) as Record<string, unknown>;
    } catch {
      this.#logger.warn("session.relay.auth.failed", { relayPeerId: this.#relayPeerId, reason: "auth_ok_decode" });
      return false;
    }
    if (ackFrame["type"] !== "relay_auth_ok") {
      this.#logger.warn("session.relay.auth.failed", {
        relayPeerId: this.#relayPeerId,
        reason: ackFrame["type"] === "relay_auth_failed" ? "auth_rejected" : "unexpected_frame",
      });
      return false;
    }
    return true;
  }

  #startReader(stream: Stream, iter: AsyncIterator<Uint8Array>): void {
    void (async () => {
      try {
        while (!this.#closed && this.#stream === stream) {
          const res = await iter.next();
          if (res.done || res.value === undefined) break;
          // The await above can suspend across a #resetStream() (timeout) that supersedes this
          // stream. Re-check identity before dispatching so a late frame from a stale stream
          // (e.g. a buffered ack for a timed-out submit) can't bump/settle the wrong session.
          if (this.#stream !== stream) break;
          let frame: Record<string, unknown>;
          try {
            frame = decode(toU8(res.value)) as Record<string, unknown>;
          } catch {
            continue;
          }
          this.#dispatch(frame);
        }
      } catch (err: unknown) {
        this.#logger.debug?.("session.relay.reader.ended", { relayPeerId: this.#relayPeerId, error: extractErrorMessage(err) });
      } finally {
        // Stream gone — clear it so the next submit re-dials, and fail any in-flight submit.
        if (this.#stream === stream) this.#stream = null;
        this.#settlePending({ ok: false, reason: "relay_stream_closed" });
        // L5: a pure-receiver session issues no submit, so it would never trigger a re-dial
        // after the node that owned the stream is torn down. If sessions remain, proactively
        // re-establish from any still-live registered session node so queued leaf_delivers
        // are drained (the relay queues by pubkey and re-delivers on reconnect).
        if (!this.#closed && this.#sessions.size > 0) {
          void this.#reconnectFromAnySession();
        }
      }
    })();
  }

  /** Re-establish the shared stream from any registered session's node (first that dials). */
  async #reconnectFromAnySession(): Promise<void> {
    if (this.#closed || this.#stream) return;
    for (const { node } of this.#sessions.values()) {
      if (await this.#ensureConnected(node)) return;
    }
  }

  /**
   * Submit a session's MESSAGE-leaf (0x00) hash to the relay. Connects/re-connects from
   * `node` if needed. Globally FIFO across the agent's sessions (the ack has no session_id).
   */
  async submitMessageHash(node: CelloNode, sessionId: Uint8Array, contentHash: Uint8Array): Promise<SubmitResult> {
    return this.submitLeaf(node, sessionId, contentHash, LEAF_KIND_MSG);
  }

  /**
   * Submit a leaf hash of a given kind (0x00 message / 0x02 control) to the relay. The SEAL
   * ctrl leaf (DOD-SPINE-7) rides this path: two distinct-sender ctrl leaves in the relay's
   * log trigger the directory's FROST notarization (relay `#maybeProcessSeal`).
   */
  async submitLeaf(node: CelloNode, sessionId: Uint8Array, contentHash: Uint8Array, leafKind: number): Promise<SubmitResult> {
    // Chain on the prior submit so only one is outstanding at a time (FIFO). The ack
    // carries no session_id, so concurrent submits on one stream would be ambiguous.
    const run = this.#submitChain.then(() => this.#doSubmit(node, sessionId, contentHash, leafKind));
    // Keep the chain alive regardless of this submit's outcome.
    this.#submitChain = run.then(() => undefined, () => undefined);
    return run;
  }

  async #doSubmit(node: CelloNode, sessionId: Uint8Array, contentHash: Uint8Array, leafKind: number): Promise<SubmitResult> {
    if (this.#closed) return { ok: false, reason: "relay_client_closed" };
    if (!(await this.#ensureConnected(node))) return { ok: false, reason: "relay_unavailable" };
    const stream = this.#stream;
    if (!stream) return { ok: false, reason: "relay_unavailable" };

    const sessionIdHex = Buffer.from(sessionId).toString("hex");
    // This session's OWN high-water mark (NOT an agent-global one) — the relay's seq_counter
    // is per session and rejects last_seen_seq > seq_counter.
    const lastSeenForSession = this.#lastSeen.get(sessionIdHex) ?? 0;
    const structure1 = encodeStructure1(contentHash, this.#senderPubkey, sessionId, lastSeenForSession, Date.now());
    const signature = await this.#keyProvider.sign(structure1);
    const frame = CBOR_ENC.encode({
      type: "hash_submit",
      session_id: sessionId,
      leaf_kind: leafKind,
      structure1_cbor: structure1,
      sender_signature: signature,
    }) as Uint8Array;

    // Set the resolver synchronously (no await between the in-flight check and the set):
    // the submit chain guarantees no other submit runs concurrently, so #pendingAck is null.
    let resolveAck!: AckResolver;
    const ackPromise = new Promise<SubmitResult>((r) => { resolveAck = r; });
    this.#pendingAck = resolveAck;
    this.#pendingAckSessionHex = sessionIdHex;
    try {
      stream.send(lp.encode.single(frame));
    } catch (err: unknown) {
      if (this.#pendingAck === resolveAck) { this.#pendingAck = null; this.#pendingAckSessionHex = null; }
      this.#logger.warn("session.relay.submit.send.failed", { relayPeerId: this.#relayPeerId, error: extractErrorMessage(err) });
      return { ok: false, reason: "relay_submit_send_failed" };
    }
    let timer!: ReturnType<typeof setTimeout>;
    const timeout = new Promise<SubmitResult>((r) => {
      timer = setTimeout(() => r({ ok: false, reason: "relay_submit_timeout" }), HASH_SUBMIT_TIMEOUT_MS);
    });
    try {
      const result = await Promise.race([ackPromise, timeout]);
      // On timeout, reset the stream so a late ack can't settle a LATER submit (FIFO desync).
      if (!result.ok && result.reason === "relay_submit_timeout") this.#resetStream();
      return result;
    } finally {
      clearTimeout(timer);
      if (this.#pendingAck === resolveAck) { this.#pendingAck = null; this.#pendingAckSessionHex = null; }
    }
  }

  /** The highest relay-assigned sequence observed for a given session (ack or deliver). */
  lastSeenSeq(sessionIdHex: string): number {
    return this.#lastSeen.get(sessionIdHex) ?? 0;
  }

  close(): void {
    this.#closed = true;
    this.#settlePending({ ok: false, reason: "relay_client_closed" });
    const stream = this.#stream;
    this.#stream = null;
    if (stream) {
      try { void stream.close(); } catch { /* best-effort */ }
    }
  }
}
