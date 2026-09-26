/**
 * ChannelInboxStore — the posts a SUBSCRIBER has collected and verified (M16 018-PUBCOLLECT).
 *
 * Distinct from `channel-log-store.ts`, which is the PUBLISHER's copy of what it sent. This is the
 * reader's side: what arrived, from which relay, and — when two relays disagree — both versions.
 *
 * ⚠️ **A FORK IS STORED, NOT RESOLVED.** Two different posts at one number means the channel signed
 * both, which is the one thing a channel key cannot take back. Keeping only the first seen would
 * make whichever relay answered first the arbiter of what the channel said, and would destroy the
 * evidence that it said two things. So both rows survive, and the position stops below them.
 *
 * Keyed on `agent_id`, never `agent_name`.
 */
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";
import {
  broadcastPostHash,
  decodeBroadcastArtifact,
  encodeBroadcastArtifact,
  decodeRelayPostReceipt,
  type BroadcastArtifact,
} from "@cello-protocol/protocol-types";

export const CHANNEL_INBOX_CREATE_SQL = `
  CREATE TABLE IF NOT EXISTS channel_inbox (
    agent_id        TEXT    NOT NULL,
    channel_pubkey  TEXT    NOT NULL,
    seq             INTEGER NOT NULL,
    -- The post's own hash is part of the key, which is what lets a FORK keep both rows rather than
    -- one overwriting the other. A (agent, channel, seq) key would silently drop the evidence.
    post_hash       TEXT    NOT NULL,
    post_cbor       BLOB    NOT NULL,
    receipt_cbor    BLOB,
    from_relay      TEXT    NOT NULL,
    collected_at    INTEGER NOT NULL,
    PRIMARY KEY (agent_id, channel_pubkey, seq, post_hash)
  );
`;

export type ChannelInboxErrorCode = "post_invalid" | "inbox_row_corrupt";

export class ChannelInboxError extends Error {
  readonly code: ChannelInboxErrorCode;
  constructor(code: ChannelInboxErrorCode, message: string) {
    super(`${code}: ${message}`);
    this.name = "ChannelInboxError";
    this.code = code;
  }
}

export class ChannelInboxStore {
  readonly #db: DaemonDatabase;
  readonly #logger: Logger;

  constructor(db: DaemonDatabase, logger: Logger) {
    this.#db = db;
    this.#logger = logger;
    this.#db.exec(CHANNEL_INBOX_CREATE_SQL);
  }

  /**
   * Store one verified post. Idempotent on (agent, channel, seq, hash): the same post arriving from
   * the second relay is the ordinary case, not a conflict.
   */
  store(agentId: string, channelHex: string, post: BroadcastArtifact, opts: {
    receiptCbor?: Uint8Array; fromRelay: string; collectedAt: number;
  }): { stored: boolean } {
    const cbor = encodeBroadcastArtifact(post);
    const hashHex = Buffer.from(broadcastPostHash(post)).toString("hex");
    const inserted = this.#db
      .prepare(
        `INSERT OR IGNORE INTO channel_inbox
           (agent_id, channel_pubkey, seq, post_hash, post_cbor, receipt_cbor, from_relay, collected_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        agentId, channelHex.toLowerCase(), post.seq, hashHex, Buffer.from(cbor),
        opts.receiptCbor ? Buffer.from(opts.receiptCbor) : null, opts.fromRelay, opts.collectedAt,
      );
    return { stored: Number(inserted.changes) > 0 };
  }

  /** Posts in [fromSeq, toSeq], seq order. A forked number contributes every version it holds. */
  range(agentId: string, channelHex: string, fromSeq: number, toSeq: number): BroadcastArtifact[] {
    const rows = this.#db
      .prepare(
        `SELECT seq, post_cbor FROM channel_inbox
          WHERE agent_id = ? AND channel_pubkey = ? AND seq BETWEEN ? AND ?
          ORDER BY seq ASC, post_hash ASC`,
      )
      .all(agentId, channelHex.toLowerCase(), fromSeq, toSeq) as Array<{ seq: number | bigint; post_cbor: Uint8Array }>;
    return rows.map((r) => this.#decode(Number(r.seq), new Uint8Array(r.post_cbor)));
  }

  /**
   * 043-POSTERS: posts in [fromSeq, toSeq] with the time the relay RECEIVED each — its signed
   * receipt's `received_at`, or `collected_at` when the post came without a receipt. This is what a
   * read merges several lanes by.
   */
  rangeTimed(agentId: string, channelHex: string, fromSeq: number, toSeq: number): Array<{ post: BroadcastArtifact; received_at: number }> {
    const rows = this.#db
      .prepare(
        `SELECT seq, post_cbor, receipt_cbor, collected_at FROM channel_inbox
          WHERE agent_id = ? AND channel_pubkey = ? AND seq BETWEEN ? AND ?
          ORDER BY seq ASC, post_hash ASC`,
      )
      .all(agentId, channelHex.toLowerCase(), fromSeq, toSeq) as Array<{
        seq: number | bigint; post_cbor: Uint8Array; receipt_cbor: Uint8Array | null; collected_at: number | bigint;
      }>;
    return rows.map((r) => {
      const receipt = r.receipt_cbor ? decodeRelayPostReceipt(new Uint8Array(r.receipt_cbor)) : null;
      return {
        post: this.#decode(Number(r.seq), new Uint8Array(r.post_cbor)),
        received_at: receipt?.ok ? receipt.receipt.received_at : Number(r.collected_at),
      };
    });
  }

  /** Every version held at one number. Length > 1 is a fork. */
  forksFor(agentId: string, channelHex: string, seq: number): BroadcastArtifact[] {
    return this.range(agentId, channelHex, seq, seq);
  }

  /** The post numbers this subscriber holds, ascending and deduplicated. */
  heldSeqs(agentId: string, channelHex: string): number[] {
    const rows = this.#db
      .prepare(
        `SELECT DISTINCT seq FROM channel_inbox
          WHERE agent_id = ? AND channel_pubkey = ? ORDER BY seq ASC`,
      )
      .all(agentId, channelHex.toLowerCase()) as Array<{ seq: number | bigint }>;
    return rows.map((r) => Number(r.seq));
  }

  /** The numbers at which this subscriber holds more than one distinct post. */
  forkedSeqs(agentId: string, channelHex: string): number[] {
    const rows = this.#db
      .prepare(
        `SELECT seq FROM channel_inbox
          WHERE agent_id = ? AND channel_pubkey = ?
          GROUP BY seq HAVING COUNT(DISTINCT post_hash) > 1 ORDER BY seq ASC`,
      )
      .all(agentId, channelHex.toLowerCase()) as Array<{ seq: number | bigint }>;
    return rows.map((r) => Number(r.seq));
  }

  #decode(seq: number, cbor: Uint8Array): BroadcastArtifact {
    const decoded = decodeBroadcastArtifact(cbor);
    if (!decoded.ok) {
      // A stored row that no longer decodes is corruption, never something to skip past: the caller
      // is about to show these to an agent.
      this.#logger.error("channel.inbox.row_corrupt", { seq, reason: decoded.reason });
      throw new ChannelInboxError("inbox_row_corrupt", `stored seq ${String(seq)} does not decode: ${decoded.reason}`);
    }
    return decoded.artifact;
  }
}
