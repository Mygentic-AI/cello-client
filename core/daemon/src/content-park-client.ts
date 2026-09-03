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
import { extractErrorMessage } from "./error-message.js";

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

/**
 * DOD-M15-RELAYAUTH-1 review HIGH-3: the relay REFUSED to release parked content, as distinct from
 * having none. Thrown rather than returned so it cannot be mistaken for an empty result — the whole
 * defect was a refusal flattening into `[]`, which reads to an operator as "nothing was waiting".
 */
export class ContentParkRefusedError extends Error {
  readonly reason: string;
  constructor(reason: string) {
    super(`the relay refused to release parked content: ${reason}`);
    this.name = "ContentParkRefusedError";
    this.reason = reason;
  }
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
  ): Promise<{ ok: boolean; reason?: string; retryAfterMs?: number }> {
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
      /**
       * DOD-M15-RELAYABUSE-1 — **CARRY THE RELAY'S OWN ANSWER TO "WHEN?".**
       *
       * The relay computes exactly when a throttle clears and now puts `retry_after_ms` on the ack.
       * Dropping it here would make it a value with no reader — the defect this milestone keeps
       * finding — and it is the one number that decides whether a queued message waits sixty seconds
       * or waits for an unrelated reconnect that may be minutes away.
       */
      const rawRetry = ack["retry_after_ms"];
      const retryAfterMs = typeof rawRetry === "number" && Number.isFinite(rawRetry) && rawRetry > 0 ? rawRetry : undefined;
      this.#logger.info("content.park.deposit.result", {
        relayPeerId: this.#relayPeerId,
        ok,
        reason: typeof ack["reason"] === "string" ? ack["reason"] : undefined,
        ...(retryAfterMs !== undefined ? { retryAfterMs } : {}),
      });
      return {
        ok,
        reason: typeof ack["reason"] === "string" ? (ack["reason"] as string) : undefined,
        ...(retryAfterMs !== undefined ? { retryAfterMs } : {}),
      };
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
      /**
       * DOD-M15-RELAYAUTH-1 review HIGH-3 — **A REFUSAL MUST NOT READ AS AN EMPTY MAILBOX.**
       *
       * The relay refuses a pull from a key it has never seen named by a directory-signed
       * assignment, and it names the cause: `content_park_pull_refused { reason }`. Without this
       * branch that frame simply is not `content_park_pull_count`, so the operator was told
       * `no_pull_count` — a wire-shape complaint about the RIGHT answer — and the caller got `[]`,
       * which the recover flow reports as `pulled: 0`: *nothing was waiting for you*. The relay was
       * honest and the client threw the reason away one layer up.
       *
       * This is reachable on the ordinary path, not just under attack: the relay's vouched set is
       * in-process, so every relay restart empties it, and a client does not re-present its
       * assignment on reconnect.
       */
      if (countFrame && countFrame["type"] === "content_park_pull_refused") {
        const reason = typeof countFrame["reason"] === "string" ? (countFrame["reason"] as string) : "refused";
        // Review L2: named `..._by_relay`, not `content.park.pull.refused` — that name is already
        // emitted by the relay itself, and an operator grepping one aggregated log for it would get
        // two events from opposite sides of a trust boundary under a single name.
        this.#logger.warn("content.park.pull.refused_by_relay", {
          relayPeerId: this.#relayPeerId,
          reason,
          impact:
            "this relay refused to release parked content for this key — it is NOT an empty mailbox. " +
            "Content may still be waiting. If the reason is not_a_participant the relay has no record " +
            "of a session naming this agent (it restarts empty), and a new session on this relay re-vouches it.",
        });
        throw new ContentParkRefusedError(reason);
      }
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
      if (!ok) {
        /**
         * Review M3 — the same error substitution HIGH-3 fixed on the pull path, left standing one
         * function above in this same file.
         *
         * A refused confirm is not a missing ack. The relay answers with a perfectly well-formed
         * `content_park_confirm_ack { ok: false, reason }`, and reporting `no_confirm_ack` is a
         * complaint about the wire shape of the RIGHT answer — it sends the operator to look at the
         * transport when the relay has already said exactly what is wrong.
         *
         * What it costs: confirm is delete-on-pickup. If it is refused, the entry is never deleted,
         * so the recipient is re-notified about a message it has already read, every time it
         * reconnects, forever — while the log blames the connection.
         */
        const reason = typeof ack?.["reason"] === "string"
          ? (ack["reason"] as string)
          : ack
            ? "unexpected_frame"
            : "no_confirm_ack";
        this.#logger.warn("content.park.confirm.failed", {
          relayPeerId: this.#relayPeerId,
          reason,
          impact:
            "pickup was not confirmed, so the relay keeps the entry and will keep announcing it as " +
            "unread on every reconnect. If the reason is not_a_participant this relay has no record " +
            "of a session naming this agent; a new session on it re-vouches the key.",
        });
      }
      return ok;
    } finally {
      await stream.close().catch(() => {});
    }
  }

  /** Dial the relay (best-effort per addr) and open a content-park stream. */
  /**
   * Open a content-park stream, dialling the relay first.
   *
   * WHY THE DIAL ERRORS ARE KEPT. `newStream` does not dial — it requires an already-open
   * connection and otherwise throws `no_connection`, naming only the peer. So when every dial
   * here fails, the caller sees "No open connection to peer 12D3Koo…" and the reason the dial
   * failed is gone. That is the exit point reported as the cause, and it is what made an
   * intermittent deposit failure undiagnosable: the one fact needed to explain it was discarded
   * by an empty catch one line earlier.
   *
   * Proceeding to `newStream` after a failed dial is still correct — a connection opened by
   * another part of the daemon may already exist, and the peerstore may hold a route this
   * address list does not. What is not correct is doing so silently. `session-relay-client.ts`
   * has kept `lastDialError` and logged `session.relay.dial.failed` for exactly this reason;
   * this is the same pattern, applied to the path that lacked it.
   */
  async #open(node: CelloNode): Promise<Stream> {
    let dialed = false;
    let lastDialError: string | undefined;
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
      // WARN, not error: the stream may still open on a pre-existing connection, and this is only
      // fatal if `newStream` then throws. It is logged before that attempt so the reason survives
      // even when it does.
      this.#logger.warn("content.park.dial.failed", {
        relayPeerId: this.#relayPeerId,
        relayAddrs: this.#relayAddrs,
        error: lastDialError,
      });
    }
    try {
      return await node.newStream(this.#relayPeerId, CONTENT_PARK_PROTOCOL_ID);
    } catch (err: unknown) {
      /**
       * The caller gets `no_connection`, which names the peer and nothing else. Carry the dial
       * failure with it so whoever reads this knows WHY there was no connection — that is the
       * difference between "the relay is unreachable from here" and "we never tried".
       */
      this.#logger.warn("content.park.stream.failed", {
        relayPeerId: this.#relayPeerId,
        error: extractErrorMessage(err),
        dialAttempted: this.#relayAddrs.length > 0,
        dialSucceeded: dialed,
        ...(lastDialError !== undefined ? { dialError: lastDialError } : {}),
      });
      throw err;
    }
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
