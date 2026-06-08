/**
 * SignalingManager — persistent signaling stream, frame router, per-session directory streams.
 *
 * Extracted from CelloClientImpl. Methods operate on the shared internal state
 * passed via the `ctx` parameter (typed as SignalingContext).
 */

import { createHash } from "node:crypto";
import { Encoder, decode } from "cbor-x";
import * as lp from "it-length-prefixed";
import type { Stream } from "@libp2p/interface";
import type { Logger } from "@cello-protocol/interfaces";
import type { CelloNode } from "@cello-protocol/transport";
import type { KeyProvider } from "@cello-protocol/crypto";
import type { SessionAssignment } from "@cello-protocol/protocol-types";

const SIGNALING_PROTOCOL_ID = "/cello/signaling/1.0.0";
const AUTH_DOMAIN_DIR = "CELLO-DIR-AUTH-v1";
const RELAY_AUTH_TIMEOUT_MS = 5_000;
const CBOR_ENC = new Encoder({ tagUint8Array: false });

function toU8(v: unknown): Uint8Array {
  if (v instanceof Uint8Array) return v;
  if (Buffer.isBuffer(v)) return new Uint8Array(v as Buffer);
  if (typeof (v as { slice?: unknown }).slice === "function") {
    return (v as { slice(): Uint8Array }).slice();
  }
  throw new Error(`expected bytes, got ${typeof v}`);
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

/**
 * Narrow interface exposing only what SignalingManager needs from CelloClientImpl.
 */
export interface SignalingContext {
  readonly node: CelloNode;
  readonly keyProvider: KeyProvider;
  readonly logger: Logger;
  getMyPubkeyHex(): string | null;
  setMyPubkeyHex(hex: string): void;
  getDirectoryEndpoint(): { peer_id: string; multiaddrs: string[] } | null;
  getPersistentSignalingStream(): Stream | null;
  setPersistentSignalingStream(stream: Stream | null): void;
  setPersistentSignalingIter(iter: AsyncIterator<Uint8Array> | null): void;
  getOpeningSignalingStream(): Promise<boolean> | null;
  setOpeningSignalingStream(p: Promise<boolean> | null): void;
  getDirectoryStreams(): Map<string, Stream>;
  // Pending-state accessors for AC-007 signaling.stream.closed log
  hasPendingSessionRequest(): boolean;
  hasPendingRegister(): boolean;
  hasPendingDkgReady(): boolean;
  getPendingConnectionResolverCount(): number;
  // Frame dispatch
  dispatchSignalingFrame(stream: Stream, frame: Record<string, unknown>): void;
  onSignalingStreamClosed(stream: Stream): void;
}

export class SignalingManager {
  readonly #ctx: SignalingContext;

  constructor(ctx: SignalingContext) {
    this.#ctx = ctx;
  }

  /**
   * Open and authenticate the persistent directory signaling stream.
   * Serializes concurrent calls.
   */
  openPersistentSignalingStream(directoryPeerId?: string, directoryMultiaddr?: string): Promise<boolean> {
    if (this.#ctx.getPersistentSignalingStream()) return Promise.resolve(true);
    const existing = this.#ctx.getOpeningSignalingStream();
    if (existing) return existing;

    const p = this.#doOpen(directoryPeerId, directoryMultiaddr).finally(() => {
      if (this.#ctx.getOpeningSignalingStream() === p) {
        this.#ctx.setOpeningSignalingStream(null);
      }
    });
    this.#ctx.setOpeningSignalingStream(p);
    return p;
  }

  /**
   * Reconnect the persistent signaling stream.
   */
  async reconnectDirectory(): Promise<boolean> {
    const stream = this.#ctx.getPersistentSignalingStream();
    if (stream) {
      try { stream.abort(new Error("reconnect")); } catch {}
      this.#ctx.setPersistentSignalingStream(null);
      this.#ctx.setPersistentSignalingIter(null);
    }
    return this.openPersistentSignalingStream();
  }

  /**
   * Open per-session directory signaling stream (SESSION-003).
   */
  async connectDirectorySignalingStream(
    sessionIdHex: string,
    assignment: SessionAssignment,
    myPubkey: Uint8Array,
  ): Promise<void> {
    const dirPeerId = assignment.directory_endpoint.peer_id;
    const dirMultiaddr = assignment.directory_endpoint.multiaddrs[0];

    if (!dirPeerId) return;

    try {
      if (dirMultiaddr) {
        try { await this.#ctx.node.dial(dirMultiaddr); } catch { /* already connected */ }
      }
      let dirStream: Stream;
      try {
        dirStream = await this.#ctx.node.newStream(dirPeerId, SIGNALING_PROTOCOL_ID);
      } catch {
        return;
      }

      this.#ctx.getDirectoryStreams().set(sessionIdHex, dirStream);

      const iter = (lp.decode(dirStream) as AsyncIterable<unknown>)[Symbol.asyncIterator]() as AsyncIterator<Uint8Array>;
      const { value: challengeRaw, done } = await iter.next();
      if (done || challengeRaw === undefined) { dirStream.abort(new Error("dir_auth_error")); return; }

      let challengeFrame: Record<string, unknown>;
      try {
        challengeFrame = decode(toU8(challengeRaw)) as Record<string, unknown>;
      } catch { dirStream.abort(new Error("dir_auth_error")); return; }

      if (challengeFrame["type"] !== "signaling_auth_challenge") { dirStream.abort(new Error("dir_auth_error")); return; }

      const nonce = toU8(challengeFrame["nonce"]);
      const domain = Buffer.from(AUTH_DOMAIN_DIR, "utf8");
      const authMsg = new Uint8Array(Buffer.concat([domain, nonce, myPubkey]));
      const msgHash = new Uint8Array(createHash("sha256").update(authMsg).digest());
      const sig = await this.#ctx.keyProvider.sign(msgHash);

      const authResponseFrame = CBOR_ENC.encode({
        type: "signaling_auth_response",
        pubkey: myPubkey,
        signature: sig,
      }) as Uint8Array;
      dirStream.send(lp.encode.single(authResponseFrame));

      const { value: ackRaw2, done: ackDone2 } = await nextWithTimeout(iter, RELAY_AUTH_TIMEOUT_MS);
      if (ackDone2 || ackRaw2 === undefined) { dirStream.abort(new Error("dir_auth_error")); return; }
      let ackFrame2: Record<string, unknown>;
      try {
        ackFrame2 = decode(toU8(ackRaw2)) as Record<string, unknown>;
      } catch { dirStream.abort(new Error("dir_auth_error")); return; }
      if (ackFrame2["type"] !== "signaling_auth_ok") {
        dirStream.abort(new Error("dir_auth_error")); return;
      }

      void this.#runDirectoryStreamReader(sessionIdHex, dirStream, assignment.directory_pubkey, iter);
    } catch {
      // Directory connection failure — session still active
    }
  }

  /**
   * FEDERATION-003 AC-004: Look up a relay's registered public key from the directory.
   */
  async getRelayPublicKey(relayId: string): Promise<string | undefined> {
    const directoryEndpoint = this.#ctx.getDirectoryEndpoint();
    if (!directoryEndpoint) return undefined;

    const dirPeerId = directoryEndpoint.peer_id;
    const dirMultiaddr = directoryEndpoint.multiaddrs[0];

    try {
      if (dirMultiaddr) {
        try { await this.#ctx.node.dial(dirMultiaddr); } catch { /* already connected */ }
      }

      let sigStream: Stream;
      try {
        sigStream = await this.#ctx.node.newStream(dirPeerId, SIGNALING_PROTOCOL_ID);
      } catch (err: unknown) {
        this.#ctx.logger.warn("relay.pubkey.lookup.failed", { relayId, reason: err instanceof Error ? err.message : "stream_open_failed" });
        return undefined;
      }

      const iter = (lp.decode(sigStream) as AsyncIterable<unknown>)[Symbol.asyncIterator]() as AsyncIterator<Uint8Array>;

      const { value: challengeRaw, done } = await nextWithTimeout(iter, RELAY_AUTH_TIMEOUT_MS);
      if (done || challengeRaw === undefined) { sigStream.abort(new Error("dir_auth_error")); this.#ctx.logger.warn("relay.pubkey.lookup.failed", { relayId, reason: "no_auth_challenge" }); return undefined; }

      let challengeFrame: Record<string, unknown>;
      try {
        challengeFrame = decode(toU8(challengeRaw)) as Record<string, unknown>;
      } catch { sigStream.abort(new Error("dir_auth_error")); this.#ctx.logger.warn("relay.pubkey.lookup.failed", { relayId, reason: "decode_failed" }); return undefined; }

      if (challengeFrame["type"] !== "signaling_auth_challenge") {
        sigStream.abort(new Error("dir_auth_error")); this.#ctx.logger.warn("relay.pubkey.lookup.failed", { relayId, reason: "unexpected_frame" }); return undefined;
      }

      const nonce = toU8(challengeFrame["nonce"]);

      if (!this.#ctx.getMyPubkeyHex()) {
        const pubkey = await this.#ctx.keyProvider.getPublicKey();
        this.#ctx.setMyPubkeyHex(Buffer.from(pubkey).toString("hex"));
      }
      const myPubkey = Buffer.from(this.#ctx.getMyPubkeyHex()!, "hex");

      const domain = Buffer.from(AUTH_DOMAIN_DIR, "utf8");
      const authMsg = new Uint8Array(Buffer.concat([domain, nonce, myPubkey]));
      const msgHash = new Uint8Array(createHash("sha256").update(authMsg).digest());
      const sig = await this.#ctx.keyProvider.sign(msgHash);

      sigStream.send(lp.encode.single(CBOR_ENC.encode({
        type: "signaling_auth_response",
        pubkey: myPubkey,
        signature: sig,
      }) as Uint8Array));

      const { value: ackRaw, done: ackDone } = await nextWithTimeout(iter, RELAY_AUTH_TIMEOUT_MS);
      if (ackDone || ackRaw === undefined) { sigStream.abort(new Error("dir_auth_error")); this.#ctx.logger.warn("relay.pubkey.lookup.failed", { relayId, reason: "no_auth_ack" }); return undefined; }
      let ackFrame: Record<string, unknown>;
      try {
        ackFrame = decode(toU8(ackRaw)) as Record<string, unknown>;
      } catch { sigStream.abort(new Error("dir_auth_error")); this.#ctx.logger.warn("relay.pubkey.lookup.failed", { relayId, reason: "decode_failed" }); return undefined; }
      if (ackFrame["type"] !== "signaling_auth_ok") {
        sigStream.abort(new Error("dir_auth_error")); this.#ctx.logger.warn("relay.pubkey.lookup.failed", { relayId, reason: "auth_failed" }); return undefined;
      }

      sigStream.send(lp.encode.single(CBOR_ENC.encode({
        type: "relay_pubkey_request",
        relay_id: relayId,
      }) as Uint8Array));

      const { value: respRaw, done: respDone } = await nextWithTimeout(iter, RELAY_AUTH_TIMEOUT_MS);
      if (respDone || respRaw === undefined) {
        sigStream.abort(new Error("no_response"));
        this.#ctx.logger.warn("relay.pubkey.lookup.failed", { relayId, reason: "no_response" });
        return undefined;
      }

      let respFrame: Record<string, unknown>;
      try {
        respFrame = decode(toU8(respRaw)) as Record<string, unknown>;
      } catch {
        sigStream.abort(new Error("decode_failed"));
        this.#ctx.logger.warn("relay.pubkey.lookup.failed", { relayId, reason: "decode_failed" });
        return undefined;
      }

      sigStream.close().catch(() => {});

      if (respFrame["type"] === "relay_pubkey_response") {
        return respFrame["public_key_hex"] as string | undefined;
      }

      const errorReason = (respFrame["reason"] as string | undefined) ?? "not_found";
      if (errorReason !== "not_found") {
        this.#ctx.logger.warn("relay.pubkey.lookup.failed", { relayId, reason: errorReason });
      }
      return undefined;
    } catch (err: unknown) {
      this.#ctx.logger.warn("relay.pubkey.lookup.failed", { relayId, reason: err instanceof Error ? err.message : "unknown" });
      return undefined;
    }
  }

  // ─── Persistent signaling reader ──────────────────────────────────────────────

  runPersistentSignalingReader(
    stream: Stream,
    iter: AsyncIterator<Uint8Array>,
  ): void {
    void this.#doRunPersistentSignalingReader(stream, iter);
  }

  async #doRunPersistentSignalingReader(
    stream: Stream,
    iter: AsyncIterator<Uint8Array>,
  ): Promise<void> {
    this.#ctx.logger.debug("signaling.stream.frame.received", { frameType: "reader_started" });
    try {
      while (true) {
        let result: IteratorResult<Uint8Array>;
        try {
          result = await iter.next();
        } catch (iterErr) {
          this.#ctx.logger.debug("signaling.stream.iter.error", { error: iterErr instanceof Error ? iterErr.message : String(iterErr) });
          break;
        }
        if (result.done || result.value === undefined) {
          this.#ctx.logger.debug("signaling.stream.closed", {
            pendingSessionRequest: this.#ctx.hasPendingSessionRequest(),
            pendingRegister: this.#ctx.hasPendingRegister(),
            pendingDkgReady: this.#ctx.hasPendingDkgReady(),
            pendingConnectionResolvers: this.#ctx.getPendingConnectionResolverCount(),
          });
          break;
        }

        let frame: Record<string, unknown>;
        try {
          frame = decode(toU8(result.value as unknown)) as Record<string, unknown>;
        } catch (decErr) {
          this.#ctx.logger.debug("signaling.stream.decode.error", { error: decErr instanceof Error ? decErr.message : String(decErr) });
          continue;
        }

        this.#ctx.logger.debug("signaling.stream.frame.received", { frameType: String(frame["type"]) });

        // Dispatch all frames to the facade which routes them to the appropriate manager
        this.#ctx.dispatchSignalingFrame(stream, frame);
      }
    } catch (outerErr) {
      this.#ctx.logger.debug("signaling.stream.iter.error", { error: outerErr instanceof Error ? outerErr.message : String(outerErr) });
    }

    // Notify facade that stream is closed
    this.#ctx.onSignalingStreamClosed(stream);
  }

  // ─── Per-session directory stream reader ───────────────────────────────────────

  async #runDirectoryStreamReader(
    sessionIdHex: string,
    stream: Stream,
    directoryPubkey: Uint8Array,
    iter: AsyncIterator<Uint8Array>,
  ): Promise<void> {
    try {
      while (true) {
        let result: IteratorResult<Uint8Array>;
        try {
          result = await iter.next();
        } catch { break; }
        if (result.done || result.value === undefined) break;

        let frame: Record<string, unknown>;
        try {
          frame = decode(toU8(result.value as unknown)) as Record<string, unknown>;
        } catch { continue; }

        // Wrap frame with session context and dispatch
        (frame as Record<string, unknown>)["__session_id_hex"] = sessionIdHex;
        (frame as Record<string, unknown>)["__directory_pubkey"] = directoryPubkey;
        this.#ctx.dispatchSignalingFrame(stream, frame);
      }
    } catch { /* stream closed */ }

    const directoryStreams = this.#ctx.getDirectoryStreams();
    if (directoryStreams.get(sessionIdHex) === stream) {
      directoryStreams.delete(sessionIdHex);
    }
  }

  // ─── Private: open implementation ──────────────────────────────────────────────

  async #doOpen(directoryPeerId?: string, directoryMultiaddr?: string): Promise<boolean> {
    const directoryEndpoint = this.#ctx.getDirectoryEndpoint();
    if (!directoryEndpoint && !directoryPeerId) return false;
    if (this.#ctx.getPersistentSignalingStream()) return true;

    const dirPeerId = directoryPeerId ?? directoryEndpoint!.peer_id;
    const dirMultiaddr = directoryMultiaddr ?? directoryEndpoint?.multiaddrs[0];

    try {
      if (dirMultiaddr) {
        try { await this.#ctx.node.dial(dirMultiaddr); } catch { /* non-fatal */ }
      }

      let sigStream: Stream;
      try {
        sigStream = await this.#ctx.node.newStream(dirPeerId, SIGNALING_PROTOCOL_ID);
      } catch {
        return false;
      }

      const iter = (lp.decode(sigStream) as AsyncIterable<unknown>)[Symbol.asyncIterator]() as AsyncIterator<Uint8Array>;

      const { value: challengeRaw, done } = await nextWithTimeout(iter, RELAY_AUTH_TIMEOUT_MS);
      if (done || challengeRaw === undefined) { sigStream.abort(new Error("dir_auth_error")); return false; }

      let challengeFrame: Record<string, unknown>;
      try {
        challengeFrame = decode(toU8(challengeRaw)) as Record<string, unknown>;
      } catch { sigStream.abort(new Error("dir_auth_error")); return false; }

      if (challengeFrame["type"] !== "signaling_auth_challenge") {
        sigStream.abort(new Error("dir_auth_error")); return false;
      }

      const nonce = toU8(challengeFrame["nonce"]);
      if (nonce.length !== 32) { sigStream.abort(new Error("dir_auth_error")); return false; }

      if (!this.#ctx.getMyPubkeyHex()) {
        const pubkey = await this.#ctx.keyProvider.getPublicKey();
        this.#ctx.setMyPubkeyHex(Buffer.from(pubkey).toString("hex"));
      }
      const myPubkey = Buffer.from(this.#ctx.getMyPubkeyHex()!, "hex");

      const domain = Buffer.from(AUTH_DOMAIN_DIR, "utf8");
      const authMsg = new Uint8Array(Buffer.concat([domain, nonce, myPubkey]));
      const msgHash = new Uint8Array(createHash("sha256").update(authMsg).digest());
      const sig = await this.#ctx.keyProvider.sign(msgHash);

      const authResponseFrame = CBOR_ENC.encode({
        type: "signaling_auth_response",
        pubkey: myPubkey,
        signature: sig,
      }) as Uint8Array;
      sigStream.send(lp.encode.single(authResponseFrame));

      const { value: ackRaw, done: ackDone } = await nextWithTimeout(iter, RELAY_AUTH_TIMEOUT_MS);
      if (ackDone || ackRaw === undefined) { sigStream.abort(new Error("dir_auth_error")); return false; }
      let ackFrame: Record<string, unknown>;
      try {
        ackFrame = decode(toU8(ackRaw)) as Record<string, unknown>;
      } catch { sigStream.abort(new Error("dir_auth_error")); return false; }
      if (ackFrame["type"] !== "signaling_auth_ok") {
        sigStream.abort(new Error("dir_auth_error")); return false;
      }

      const peerInfoFrame = CBOR_ENC.encode({
        type: "peer_info_announce",
        peer_id: this.#ctx.node.getPeerId(),
        multiaddrs: this.#ctx.node.listenAddresses(),
      }) as Uint8Array;
      sigStream.send(lp.encode.single(peerInfoFrame));

      this.#ctx.setPersistentSignalingStream(sigStream);
      this.#ctx.setPersistentSignalingIter(iter);

      this.runPersistentSignalingReader(sigStream, iter);
      return true;
    } catch {
      return false;
    }
  }
}
