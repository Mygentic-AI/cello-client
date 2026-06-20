/**
 * M7 DOD-SPINE-6 / MSG-001-3b — daemon-side relay witness client.
 *
 * In CELLO the relay is the ordering/witness authority (Structure 2): it never sees
 * plaintext (content is peer↔peer), only the SIGNED content-hash leaves. It assigns
 * the canonical `sequence_number` and forwards each witnessed leaf to the counterparty
 * (`leaf_deliver`). A `cello_send` whose hash the relay never witnessed has no canonical
 * sequence and is not a complete CELLO message — so the session node submits the message
 * leaf hash here, in parallel with the direct content delivery.
 *
 * This is a FOCUSED client (connect + auth + submit + reader), NOT a port of the dead
 * `core/client/relay-stream-manager.ts` (that carries the retired client's session model).
 * It reuses only the proven wire shapes:
 *   - auth: mirror of `relay-stream-manager.#performRelayAuth` (proven against this relay)
 *   - Structure 1 + hash_submit: mirror of the retired client's seal-leaf submit path
 *   - server contract: `packages/relay/src/relay-node.ts` (#handleRelayStream / #processHashSubmit)
 *
 * The SESSION node opens the relay stream, so the relay sees the SESSION peer id
 * (satisfying "hash_submit from A's session Peer ID"); the stream is AUTHENTICATED with
 * the agent's K_local identity, so the relay routes `leaf_deliver` to the right agent.
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
type SubmitResult = { ok: true; sequence_number: number } | { ok: false; reason: string };
/** Resolver for the in-flight submission, settled by the reader on ack/error/close. */
type AckResolver = (r: SubmitResult) => void;

export interface RelaySessionClient {
  /**
   * Submit a message leaf hash to the relay. The relay validates the signature,
   * assigns the canonical sequence, witnesses the leaf, and delivers it to the
   * counterparty. Returns the assigned sequence or a named failure.
   */
  submitMessageHash(
    contentHash: Uint8Array,
  ): Promise<{ ok: true; sequence_number: number } | { ok: false; reason: string }>;
  /** The highest relay-assigned sequence this client has observed (ack or deliver). */
  lastSeenSeq(): number;
  close(): void;
}

export interface ConnectSessionRelayOpts {
  /** The SESSION node (N_A / N_B) — opens the relay stream so the relay sees its peer id. */
  node: CelloNode;
  relayPeerId: string;
  relayAddrs: string[];
  /** The agent's K_local signing key (relay auth + leaf signatures). */
  keyProvider: KeyProvider;
  /** The agent's K_local public key (32 bytes) — relay routes delivery by this. */
  senderPubkey: Uint8Array;
  /** The 16-byte session id from the FROST-signed assignment. */
  sessionId: Uint8Array;
  logger: Logger;
  correlationId: string;
  /** Called for each counterparty leaf the relay forwards (canonical-sequenced). */
  onLeafDeliver?: (frame: LeafDeliverFrame) => void;
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
 * Dial + authenticate the relay over /cello/relay/1.0.0 and start the reader.
 * Returns a client for submitting leaves, or null if connect/auth failed (the
 * caller treats a null relay client as "no witness yet" — the direct content path
 * still works; the session is not destroyed).
 */
export async function connectSessionRelay(opts: ConnectSessionRelayOpts): Promise<RelaySessionClient | null> {
  const { node, relayPeerId, relayAddrs, keyProvider, senderPubkey, sessionId, logger, correlationId } = opts;
  const sessionIdHex = Buffer.from(sessionId).toString("hex");

  // Best-effort dial: newStream auto-dials a known peer, but the relay's addrs may not
  // be in the peerstore yet, so dial each addr first. One success is enough.
  let dialed = false;
  let lastDialError = "";
  for (const addr of relayAddrs) {
    try {
      await node.dial(addr);
      dialed = true;
      break;
    } catch (err: unknown) {
      lastDialError = err instanceof Error ? err.message : String(err);
    }
  }
  if (!dialed && relayAddrs.length > 0) {
    logger.warn("session.relay.dial.failed", { sessionId: sessionIdHex, error: lastDialError, correlationId });
    return null;
  }

  let stream: Stream;
  try {
    stream = await node.newStream(relayPeerId, RELAY_PROTOCOL_ID);
  } catch (err: unknown) {
    logger.warn("session.relay.stream.failed", {
      sessionId: sessionIdHex,
      error: err instanceof Error ? err.message : String(err),
      correlationId,
    });
    return null;
  }

  // ONE shared lp.decode iterator for the whole stream lifetime — splitting it signals
  // EOF to the relay's single-iterator reader and breaks subsequent reads.
  const iter = (lp.decode(stream as unknown as AsyncIterable<Uint8Array>) as AsyncIterable<unknown>)[
    Symbol.asyncIterator
  ]() as AsyncIterator<Uint8Array>;

  // ── Challenge-response auth (mirror of relay-stream-manager.#performRelayAuth) ──
  const challengeRes = await nextWithTimeout(iter, RELAY_AUTH_TIMEOUT_MS);
  if (challengeRes.done || challengeRes.value === undefined) {
    logger.warn("session.relay.auth.failed", { sessionId: sessionIdHex, reason: "no_challenge", correlationId });
    return null;
  }
  let challenge: Record<string, unknown>;
  try {
    challenge = decode(toU8(challengeRes.value)) as Record<string, unknown>;
  } catch {
    logger.warn("session.relay.auth.failed", { sessionId: sessionIdHex, reason: "challenge_decode", correlationId });
    return null;
  }
  if (challenge["type"] !== "relay_auth_challenge") {
    logger.warn("session.relay.auth.failed", { sessionId: sessionIdHex, reason: "not_challenge", correlationId });
    return null;
  }
  const nonce = toU8(challenge["nonce"]);
  if (nonce.length !== 32) {
    logger.warn("session.relay.auth.failed", { sessionId: sessionIdHex, reason: "bad_nonce", correlationId });
    return null;
  }
  const authSig = await keyProvider.sign(buildRelayAuthPayload(nonce, senderPubkey));
  try {
    stream.send(lp.encode.single(CBOR_ENC.encode({ type: "relay_auth_response", pubkey: senderPubkey, signature: authSig }) as Uint8Array));
  } catch (err: unknown) {
    logger.warn("session.relay.auth.failed", {
      sessionId: sessionIdHex,
      reason: "response_send",
      error: err instanceof Error ? err.message : String(err),
      correlationId,
    });
    return null;
  }
  const ackRes = await nextWithTimeout(iter, RELAY_AUTH_TIMEOUT_MS);
  if (ackRes.done || ackRes.value === undefined) {
    logger.warn("session.relay.auth.failed", { sessionId: sessionIdHex, reason: "no_auth_ok", correlationId });
    return null;
  }
  let ackFrame: Record<string, unknown>;
  try {
    ackFrame = decode(toU8(ackRes.value)) as Record<string, unknown>;
  } catch {
    logger.warn("session.relay.auth.failed", { sessionId: sessionIdHex, reason: "auth_ok_decode", correlationId });
    return null;
  }
  if (ackFrame["type"] !== "relay_auth_ok") {
    logger.warn("session.relay.auth.failed", {
      sessionId: sessionIdHex,
      reason: ackFrame["type"] === "relay_auth_failed" ? "auth_rejected" : "unexpected_frame",
      correlationId,
    });
    return null;
  }

  logger.info("session.relay.connected", { sessionId: sessionIdHex, relayPeerId, correlationId });

  // ── Client state: single in-flight submit (FIFO per session); own last_seen_seq ──
  let lastSeen = 0;
  let pendingAck: AckResolver | null = null;
  let closed = false;

  // Settle the in-flight submit (if any) exactly once. The explicit AckResolver|null
  // annotation defeats TS narrowing the captured `pendingAck` to `null` inside these
  // closures (the non-null assignment lives lexically later, in submitMessageHash).
  const settlePending = (r: SubmitResult): void => {
    const resolve: AckResolver | null = pendingAck;
    pendingAck = null;
    if (resolve) resolve(r);
  };

  const dispatch = (frame: Record<string, unknown>): void => {
    const type = frame["type"];
    if (type === "hash_submit_ack") {
      const seq = typeof frame["sequence_number"] === "number" ? frame["sequence_number"] : -1;
      if (seq > lastSeen) lastSeen = seq;
      settlePending(seq >= 0 ? { ok: true, sequence_number: seq } : { ok: false, reason: "relay_ack_malformed" });
    } else if (type === "hash_submit_error") {
      const reason = typeof frame["reason"] === "string" ? frame["reason"] : "relay_rejected";
      settlePending({ ok: false, reason });
    } else if (type === "leaf_deliver") {
      const seq = typeof frame["sequence_number"] === "number" ? frame["sequence_number"] : -1;
      if (seq > lastSeen) lastSeen = seq;
      if (opts.onLeafDeliver && seq >= 0) {
        opts.onLeafDeliver({
          sequence_number: seq,
          leaf_kind: typeof frame["leaf_kind"] === "number" ? frame["leaf_kind"] : LEAF_KIND_MSG,
          structure1_cbor: toU8(frame["structure1_cbor"]),
          structure2_cbor: toU8(frame["structure2_cbor"]),
        });
      }
    }
    // Other frames (session_interrupted, content_park_notify, …) are out of scope here —
    // session interruption is handled by registerRelayStream's dedicated watcher.
  };

  // Background reader — runs for the stream lifetime on the SAME iterator.
  void (async () => {
    try {
      while (!closed) {
        const res = await iter.next();
        if (res.done || res.value === undefined) break;
        let frame: Record<string, unknown>;
        try {
          frame = decode(toU8(res.value)) as Record<string, unknown>;
        } catch {
          continue;
        }
        dispatch(frame);
      }
    } catch {
      // Stream error == relay gone; fall through to reader exit.
    } finally {
      // A closing stream must not leave a submit hanging forever.
      settlePending({ ok: false, reason: "relay_stream_closed" });
    }
  })();

  return {
    lastSeenSeq: () => lastSeen,
    async submitMessageHash(contentHash: Uint8Array) {
      if (closed) return { ok: false, reason: "relay_client_closed" };
      if (pendingAck) return { ok: false, reason: "relay_submit_in_flight" };
      const structure1 = encodeStructure1(contentHash, senderPubkey, sessionId, lastSeen, Date.now());
      const signature = await keyProvider.sign(structure1);
      const frame = CBOR_ENC.encode({
        type: "hash_submit",
        session_id: sessionId,
        leaf_kind: LEAF_KIND_MSG,
        structure1_cbor: structure1,
        sender_signature: signature,
      }) as Uint8Array;

      let resolveAck!: AckResolver;
      const ackPromise = new Promise<SubmitResult>((r) => { resolveAck = r; });
      pendingAck = resolveAck;
      try {
        stream.send(lp.encode.single(frame));
      } catch {
        pendingAck = null;
        return { ok: false, reason: "relay_submit_send_failed" };
      }
      let timer!: ReturnType<typeof setTimeout>;
      const timeout = new Promise<SubmitResult>((r) => {
        timer = setTimeout(() => r({ ok: false, reason: "relay_submit_timeout" }), HASH_SUBMIT_TIMEOUT_MS);
      });
      try {
        return await Promise.race([ackPromise, timeout]);
      } finally {
        clearTimeout(timer);
        if (pendingAck === resolveAck) pendingAck = null;
      }
    },
    close() {
      closed = true;
      try {
        void stream.close();
      } catch {
        /* best-effort */
      }
    },
  };
}
