/**
 * M7 MSG-001-3b — daemon-side content-park CLIENT (deposit + pull).
 *
 * The relay runs a store-and-forward "mailbox" so a message survives the recipient being
 * OFFLINE: the sender DEPOSITS ciphertext keyed to the recipient's pubkey; when the
 * recipient comes online it PULLS its parked entries. The relay holds CIPHERTEXT only
 * (sealed to the recipient — INV-3); it is a hash custodian, not a data custodian.
 *
 * This is the daemon counterpart to `packages/relay/src/content-park.ts` (the relay handler).
 * It speaks the same protocol (`/cello/content-park/1.0.0`, CBOR frames, length-prefixed) over
 * a libp2p stream, exactly mirroring the dial/stream/framing of `session-relay-client.ts` (the
 * hash-witness client) — only the protocol ID and the frames differ.
 *
 * Wire contract (relay is authoritative — packages/relay/src/content-park.ts):
 *   deposit:  → content_park_deposit { recipient_pubkey, content_hash, session_id, ciphertext }
 *             ← content_park_deposit_ack { content_hash, ok, reason? }
 *   pull:     → content_park_pull_request { recipient_pubkey, content_hash? }
 *             ← content_park_auth_challenge { nonce(32) }          (I1: prove recipient identity)
 *             → content_park_auth_response { signature(64) }       Ed25519(buildContentParkAuthMsg)
 *             ← content_park_pull_count { count }
 *             ← count × content_park_pull_response { found, content_hash, session_id?, ciphertext? }
 *
 * Crypto: Ed25519 (RFC 8032). The pull auth binds the caller to the recipient identity key so a
 * stranger cannot drain another recipient's mailbox (the recipient pubkey is public).
 */
import * as lp from "it-length-prefixed";
import { decode } from "cbor-x";
import { encodeCbor } from "@cello-protocol/protocol-types";
import type { Stream } from "@libp2p/interface";
import type { CelloNode } from "@cello-protocol/transport";
import type { KeyProvider } from "@cello-protocol/crypto";
import { CONTENT_PARK_PROTOCOL_ID, buildContentParkAuthMsg } from "@cello-protocol/protocol-types";
import type { Logger } from "./types.js";

const FRAME_TIMEOUT_MS = 8_000;

function toU8(chunk: unknown): Uint8Array {
  if (chunk instanceof Uint8Array) return chunk;
  const c = chunk as { subarray?: () => Uint8Array };
  if (typeof c?.subarray === "function") return c.subarray();
  return new Uint8Array(chunk as ArrayBufferLike);
}

function asBytes(v: unknown): Uint8Array | null {
  if (v instanceof Uint8Array) return v;
  if (typeof Buffer !== "undefined" && Buffer.isBuffer(v)) return new Uint8Array(v as Buffer);
  return null;
}

/** A single parked entry returned by pull(). */
export interface ParkedEntry {
  contentHashHex: string;
  sessionIdHex: string;
  ciphertext: Uint8Array;
}

export interface ContentParkClientOptions {
  /** Relay libp2p peer id (12D3Koo…) — from the session assignment's relay endpoint. */
  relayPeerId: string;
  /** Relay multiaddrs to dial. */
  relayAddrs: string[];
  logger: Logger;
}

export class ContentParkClient {
  readonly #relayPeerId: string;
  readonly #relayAddrs: string[];
  readonly #logger: Logger;

  constructor(opts: ContentParkClientOptions) {
    this.#relayPeerId = opts.relayPeerId;
    this.#relayAddrs = opts.relayAddrs;
    this.#logger = opts.logger;
  }

  /**
   * Deposit ciphertext into the recipient's relay mailbox (sender side). Deposit is OPEN by
   * design — the blob is E2E-encrypted to the recipient, so an unauthenticated deposit cannot
   * leak plaintext.
   */
  async deposit(
    node: CelloNode,
    args: { recipientPubkey: Uint8Array; contentHash: Uint8Array; sessionId: Uint8Array; ciphertext: Uint8Array },
  ): Promise<{ ok: boolean; reason?: string }> {
    const stream = await this.#open(node);
    try {
      const iter = this.#iter(stream);
      stream.send(
        lp.encode.single(
          encodeCbor({
            type: "content_park_deposit",
            recipient_pubkey: args.recipientPubkey,
            content_hash: args.contentHash,
            session_id: args.sessionId,
            ciphertext: args.ciphertext,
          }) as Uint8Array,
        ),
      );
      const ack = await this.#read(iter);
      if (!ack || ack["type"] !== "content_park_deposit_ack") {
        return { ok: false, reason: "no_deposit_ack" };
      }
      const ok = ack["ok"] === true;
      this.#logger.info("content.park.deposit.result", {
        relayPeerId: this.#relayPeerId,
        ok,
        reason: typeof ack["reason"] === "string" ? ack["reason"] : undefined,
      });
      return { ok, reason: typeof ack["reason"] === "string" ? (ack["reason"] as string) : undefined };
    } finally {
      await stream.close().catch(() => {});
    }
  }

  /**
   * Pull the recipient's parked entries (recipient side). Runs the relay's auth challenge:
   * sign buildContentParkAuthMsg(nonce, recipientPubkey) with the recipient's K_local to prove
   * ownership before the relay releases anything.
   */
  async pull(node: CelloNode, recipientPubkey: Uint8Array, signer: KeyProvider): Promise<ParkedEntry[]> {
    const stream = await this.#open(node);
    try {
      const iter = this.#iter(stream);
      stream.send(
        lp.encode.single(
          encodeCbor({ type: "content_park_pull_request", recipient_pubkey: recipientPubkey }) as Uint8Array,
        ),
      );

      // I1 auth challenge → response.
      const challenge = await this.#read(iter);
      if (!challenge || challenge["type"] !== "content_park_auth_challenge") {
        this.#logger.warn("content.park.pull.failed", { relayPeerId: this.#relayPeerId, reason: "no_auth_challenge" });
        return [];
      }
      const nonce = asBytes(challenge["nonce"]);
      if (!nonce) return [];
      const signature = await signer.sign(buildContentParkAuthMsg(nonce, recipientPubkey));
      stream.send(
        lp.encode.single(encodeCbor({ type: "content_park_auth_response", signature }) as Uint8Array),
      );

      // Count header, then N responses.
      const countFrame = await this.#read(iter);
      if (!countFrame || countFrame["type"] !== "content_park_pull_count") {
        this.#logger.warn("content.park.pull.failed", { relayPeerId: this.#relayPeerId, reason: "no_pull_count" });
        return [];
      }
      const count = typeof countFrame["count"] === "number" ? (countFrame["count"] as number) : 0;
      const entries: ParkedEntry[] = [];
      for (let i = 0; i < count; i++) {
        const r = await this.#read(iter);
        if (!r || r["type"] !== "content_park_pull_response") break;
        if (r["found"] !== true) continue;
        const contentHash = asBytes(r["content_hash"]);
        const sessionId = asBytes(r["session_id"]);
        const ciphertext = asBytes(r["ciphertext"]);
        if (!contentHash || !ciphertext) continue;
        entries.push({
          contentHashHex: Buffer.from(contentHash).toString("hex"),
          sessionIdHex: sessionId ? Buffer.from(sessionId).toString("hex") : "",
          ciphertext,
        });
      }
      this.#logger.info("content.park.pull.result", { relayPeerId: this.#relayPeerId, count: entries.length });
      return entries;
    } finally {
      await stream.close().catch(() => {});
    }
  }

  /**
   * Confirm-delete one parked entry (recipient side). The relay is delete-on-CONFIRM, not
   * delete-on-pull, so without this the mailbox never drains and every reconnect re-pulls the whole
   * history. Mirrors pull's I1 auth (sign buildContentParkAuthMsg(nonce, recipientPubkey)). Called
   * after a parked entry is durably ingested. Best-effort: a failed confirm leaves the entry (it will
   * be re-pulled + deduped next time, and the relay TTL eventually evicts it) — never loses content.
   */
  async confirm(node: CelloNode, recipientPubkey: Uint8Array, contentHash: Uint8Array, signer: KeyProvider): Promise<boolean> {
    const stream = await this.#open(node);
    try {
      const iter = this.#iter(stream);
      stream.send(
        lp.encode.single(
          encodeCbor({ type: "content_park_confirm", recipient_pubkey: recipientPubkey, content_hash: contentHash }) as Uint8Array,
        ),
      );
      const challenge = await this.#read(iter);
      if (!challenge || challenge["type"] !== "content_park_auth_challenge") {
        this.#logger.warn("content.park.confirm.failed", { relayPeerId: this.#relayPeerId, reason: "no_auth_challenge" });
        return false;
      }
      const nonce = asBytes(challenge["nonce"]);
      if (!nonce) return false;
      const signature = await signer.sign(buildContentParkAuthMsg(nonce, recipientPubkey));
      stream.send(
        lp.encode.single(encodeCbor({ type: "content_park_auth_response", signature }) as Uint8Array),
      );
      const ack = await this.#read(iter);
      const ok = !!ack && ack["type"] === "content_park_confirm_ack" && ack["ok"] === true;
      if (!ok) this.#logger.warn("content.park.confirm.failed", { relayPeerId: this.#relayPeerId, reason: "no_confirm_ack" });
      return ok;
    } finally {
      await stream.close().catch(() => {});
    }
  }

  /** Dial the relay (best-effort per addr) and open a content-park stream. */
  async #open(node: CelloNode): Promise<Stream> {
    for (const addr of this.#relayAddrs) {
      try {
        await node.dial(addr);
        break;
      } catch {
        /* try the next addr; newStream below may still succeed from the peerstore */
      }
    }
    return node.newStream(this.#relayPeerId, CONTENT_PARK_PROTOCOL_ID);
  }

  #iter(stream: Stream): AsyncIterator<unknown> {
    return (lp.decode(stream as unknown as AsyncIterable<Uint8Array>) as AsyncIterable<unknown>)[
      Symbol.asyncIterator
    ]() as AsyncIterator<unknown>;
  }

  async #read(iter: AsyncIterator<unknown>): Promise<Record<string, unknown> | null> {
    const timeout = new Promise<IteratorResult<unknown>>((_, reject) =>
      setTimeout(() => reject(new Error("content_park_frame_timeout")), FRAME_TIMEOUT_MS),
    );
    const res = (await Promise.race([iter.next(), timeout])) as IteratorResult<unknown>;
    if (res.done || res.value === undefined) return null;
    return decode(toU8(res.value)) as Record<string, unknown>;
  }
}
