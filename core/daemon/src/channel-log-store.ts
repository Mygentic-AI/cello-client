/**
 * ChannelLogStore — M16 016-CLIENTREWORK.
 *
 * A broadcast channel publishes a signed post once and it is delivered many times. The publisher
 * keeps ONE append-only log of everything it published, not one per subscriber, and that log is the
 * durable copy: when a relay loses content, it is refilled from here. Beside each post sit the
 * relays' signed receipts — the publisher's proof of what it sent and when each relay took it. So:
 *
 *   - ROWS ARE IMMUTABLE. Nothing rewrites a published post. The only deletion is `pruneThrough`,
 *     and it only ever removes from the OLDEST end, because a hole in the middle is indistinguishable
 *     to a subscriber from a post it has not received yet.
 *   - THE STORE NEVER DECIDES A POSITION. The number is inside both signatures, so `nextPosition`
 *     reports what the next append must carry, the publisher signs that, and `append` checks it. A
 *     wrong position throws its own code; nothing is auto-corrected.
 *   - A RECEIPT IS VERIFIED BEFORE IT IS STORED, against the post it names as this log holds it. An
 *     unverified receipt is worthless as proof, and storing one would only be discovered at the
 *     moment it was needed.
 *
 * Keyed on the channel's pubkey — the daemon's own channel identity — never on an agent name.
 */
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";
import { extractErrorMessage } from "./error-message.js";
import {
  encodeBroadcastArtifact,
  decodeBroadcastArtifact,
  verifyBroadcastArtifact,
  encodeRelayPostReceipt,
  decodeRelayPostReceipt,
  verifyRelayPostReceipt,
} from "@cello-protocol/protocol-types";
import type { BroadcastArtifact, RelayPostReceipt } from "@cello-protocol/protocol-types";

export const CHANNEL_LOG_CREATE_SQL = `
  CREATE TABLE IF NOT EXISTS channel_log (
    channel_pubkey   TEXT    NOT NULL,
    seq              INTEGER NOT NULL,
    published_at     INTEGER NOT NULL,
    title            TEXT    NOT NULL,
    post_cbor        BLOB    NOT NULL,
    PRIMARY KEY (channel_pubkey, seq)
  );
  CREATE TABLE IF NOT EXISTS channel_log_receipts (
    channel_pubkey   TEXT    NOT NULL,
    seq              INTEGER NOT NULL,
    relay_pubkey     TEXT    NOT NULL,
    received_at      INTEGER NOT NULL,
    receipt_cbor     BLOB    NOT NULL,
    PRIMARY KEY (channel_pubkey, seq, relay_pubkey)
  );
  CREATE TABLE IF NOT EXISTS channel_state (
    channel_pubkey   TEXT    NOT NULL PRIMARY KEY,
    next_seq         INTEGER NOT NULL,
    pruned_through   INTEGER NOT NULL DEFAULT 0
  );
`;

export type ChannelLogErrorCode =
  | "channel_unknown" | "seq_not_next" | "position_taken" | "post_invalid"
  // recordReceipt: the receipt does not verify against the post this log holds at that number, or
  // there is no such post.
  | "receipt_invalid"
  // pruneThrough: asked to prune below what has already been pruned.
  | "prune_regression"
  // readRange: a stored row no longer decodes, or no longer carries valid signatures.
  | "log_row_corrupt";

export class ChannelLogError extends Error {
  readonly code: ChannelLogErrorCode;
  constructor(code: ChannelLogErrorCode, message: string) {
    super(`${code}: ${message}`);
    this.name = "ChannelLogError";
    this.code = code;
  }
}

interface StateRow {
  next_seq: number | bigint;
  pruned_through: number | bigint;
}

export interface ChannelHead {
  /** Oldest post still held, or null when the log holds none. */
  first_seq: number | null;
  /** Newest post held, or null when the log holds none. */
  last_seq: number | null;
  /** Everything at or below this number was pruned. NOT the same as `first_seq`. */
  pruned_through: number;
}

const hexOf = (b: Uint8Array): string => Buffer.from(b).toString("hex");

export class ChannelLogStore {
  readonly #db: DaemonDatabase;
  readonly #logger: Logger;

  constructor(db: DaemonDatabase, logger: Logger) {
    this.#db = db;
    this.#logger = logger;
    this.#db.exec(CHANNEL_LOG_CREATE_SQL);
  }

  /** Idempotent: creates the state row {next_seq 1, pruned_through 0}. */
  ensureChannel(channelPubkeyHex: string): void {
    this.#db
      .prepare(`INSERT OR IGNORE INTO channel_state (channel_pubkey, next_seq, pruned_through) VALUES (?, 1, 0)`)
      .run(channelPubkeyHex);
  }

  /** What the NEXT append will be assigned — the publisher signs with this before appending. */
  nextPosition(channelPubkeyHex: string): { seq: number } {
    return { seq: Number(this.#state(channelPubkeyHex).next_seq) };
  }

  /** Append an already-signed post. Throws ChannelLogError — never silently skips. */
  append(channelPubkeyHex: string, post: BroadcastArtifact, correlationId?: string): { seq: number } {
    this.#state(channelPubkeyHex);

    this.#db.exec("BEGIN IMMEDIATE");
    try {
      // The position check runs UNDER the write lock: a second daemon on this DB could otherwise
      // append between the read and the insert, and both posts would claim one number.
      const nextSeq = Number(this.#state(channelPubkeyHex).next_seq);
      if (post.seq !== nextSeq) {
        throw new ChannelLogError("seq_not_next", `post seq ${post.seq}, next is ${nextSeq}`);
      }
      // Never trust the in-memory object: it must survive its own wire encoding, and it must carry
      // both valid signatures — an unsigned post in the log is one a subscriber would reject.
      let cbor: Uint8Array;
      try {
        cbor = encodeBroadcastArtifact(post);
      } catch (err) {
        throw new ChannelLogError("post_invalid", extractErrorMessage(err));
      }
      const decoded = decodeBroadcastArtifact(cbor);
      if (!decoded.ok) {
        throw new ChannelLogError("post_invalid", `${decoded.reason}: ${decoded.detail}`);
      }
      const verdict = verifyBroadcastArtifact(decoded.artifact);
      if (!verdict.ok) {
        throw new ChannelLogError("post_invalid", verdict.reason);
      }
      const inserted = this.#db
        .prepare(
          `INSERT OR IGNORE INTO channel_log (channel_pubkey, seq, published_at, title, post_cbor)
           VALUES (?, ?, ?, ?, ?)`,
        )
        .run(channelPubkeyHex, post.seq, post.published_at, post.title, Buffer.from(cbor));
      if (Number(inserted.changes) === 0) {
        throw new ChannelLogError("position_taken", `seq ${post.seq} is already in this channel's log`);
      }
      this.#db.prepare(`UPDATE channel_state SET next_seq = ? WHERE channel_pubkey = ?`).run(nextSeq + 1, channelPubkeyHex);
      this.#db.exec("COMMIT");
    } catch (err) {
      this.#rollback(channelPubkeyHex, err);
      throw err;
    }

    this.#logger.info("channel.post.appended", {
      ...(correlationId !== undefined ? { correlationId } : {}),
      channel_pubkey: channelPubkeyHex,
      seq: post.seq,
      published_at: post.published_at,
    });
    return { seq: post.seq };
  }

  /**
   * Store one relay's receipt for a post this log holds. VERIFIES FIRST, against the stored post —
   * not against whatever the caller passed alongside it — so a receipt for a different post at the
   * same number is refused rather than filed as proof.
   */
  recordReceipt(channelPubkeyHex: string, receipt: RelayPostReceipt, correlationId?: string): void {
    this.#state(channelPubkeyHex);
    const post = this.#postAt(channelPubkeyHex, receipt.seq);
    if (!post) {
      throw new ChannelLogError("receipt_invalid", `no post at seq ${receipt.seq} in this channel's log`);
    }
    if (!verifyRelayPostReceipt(receipt, post)) {
      throw new ChannelLogError("receipt_invalid", `the receipt does not verify against the post at seq ${receipt.seq}`);
    }
    this.#db
      .prepare(
        `INSERT OR IGNORE INTO channel_log_receipts (channel_pubkey, seq, relay_pubkey, received_at, receipt_cbor)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .run(
        channelPubkeyHex,
        receipt.seq,
        hexOf(receipt.relay_pubkey),
        receipt.received_at,
        Buffer.from(encodeRelayPostReceipt(receipt)),
      );
    this.#logger.info("channel.receipt.stored", {
      ...(correlationId !== undefined ? { correlationId } : {}),
      channel_pubkey: channelPubkeyHex,
      seq: receipt.seq,
      relay_pubkey: hexOf(receipt.relay_pubkey),
      received_at: receipt.received_at,
    });
  }

  /** Every relay's receipt for one post, in relay order. Empty when none were stored. */
  receiptsFor(channelPubkeyHex: string, seq: number): RelayPostReceipt[] {
    this.#state(channelPubkeyHex);
    const rows = this.#db
      .prepare(`SELECT receipt_cbor FROM channel_log_receipts WHERE channel_pubkey = ? AND seq = ? ORDER BY relay_pubkey ASC`)
      .all(channelPubkeyHex, seq) as Array<{ receipt_cbor: Uint8Array }>;
    return rows.map((r) => {
      const d = decodeRelayPostReceipt(new Uint8Array(r.receipt_cbor));
      if (!d.ok) {
        throw new ChannelLogError("log_row_corrupt", `a stored receipt for seq ${seq} does not decode: ${d.reason}`);
      }
      return d.receipt;
    });
  }

  /** Range read, for refilling a relay and for verification. Inclusive, seq order. */
  readRange(channelPubkeyHex: string, fromSeq: number, toSeq: number): BroadcastArtifact[] {
    this.#state(channelPubkeyHex);
    const rows = this.#db
      .prepare(`SELECT seq, post_cbor FROM channel_log WHERE channel_pubkey = ? AND seq BETWEEN ? AND ? ORDER BY seq ASC`)
      .all(channelPubkeyHex, fromSeq, toSeq) as Array<{ seq: number | bigint; post_cbor: Uint8Array }>;
    return rows.map((r) => this.#decodeRow(Number(r.seq), new Uint8Array(r.post_cbor)));
  }

  /**
   * Delete every post at or below `throughSeq`, with its receipts. The OLDEST END ONLY: a prune
   * below what is already pruned is refused rather than silently ignored, because a caller that
   * believes it pruned something it did not would keep re-sending it.
   */
  pruneThrough(channelPubkeyHex: string, throughSeq: number): { pruned: number } {
    const state = this.#state(channelPubkeyHex);
    const prunedThrough = Number(state.pruned_through);
    if (!Number.isSafeInteger(throughSeq) || throughSeq < 0) {
      throw new ChannelLogError("prune_regression", "throughSeq must be a safe integer >= 0");
    }
    if (throughSeq < prunedThrough) {
      throw new ChannelLogError(
        "prune_regression",
        `asked to prune through ${throughSeq}, but ${prunedThrough} is already pruned`,
      );
    }

    this.#db.exec("BEGIN IMMEDIATE");
    let pruned: number;
    try {
      pruned = Number(
        this.#db.prepare(`DELETE FROM channel_log WHERE channel_pubkey = ? AND seq <= ?`).run(channelPubkeyHex, throughSeq).changes,
      );
      // The receipts go with the posts: they are proof about bytes that no longer exist here.
      this.#db.prepare(`DELETE FROM channel_log_receipts WHERE channel_pubkey = ? AND seq <= ?`).run(channelPubkeyHex, throughSeq);
      this.#db.prepare(`UPDATE channel_state SET pruned_through = ? WHERE channel_pubkey = ?`).run(throughSeq, channelPubkeyHex);
      this.#db.exec("COMMIT");
    } catch (err) {
      this.#rollback(channelPubkeyHex, err);
      throw err;
    }

    this.#logger.info("channel.log.pruned", {
      channel_pubkey: channelPubkeyHex,
      pruned_through: throughSeq,
      posts_removed: pruned,
    });
    return { pruned };
  }

  /**
   * What this log holds. `pruned_through` is NOT `first_seq`: posts can also be absent because the
   * log is empty, and a caller that conflated them would report gaps that are not gaps.
   */
  head(channelPubkeyHex: string): ChannelHead {
    const state = this.#state(channelPubkeyHex);
    const row = this.#db
      .prepare(`SELECT MIN(seq) AS first_seq, MAX(seq) AS last_seq FROM channel_log WHERE channel_pubkey = ?`)
      .get(channelPubkeyHex) as { first_seq: number | bigint | null; last_seq: number | bigint | null };
    return {
      first_seq: row.first_seq === null ? null : Number(row.first_seq),
      last_seq: row.last_seq === null ? null : Number(row.last_seq),
      pruned_through: Number(state.pruned_through),
    };
  }

  #postAt(channelPubkeyHex: string, seq: number): BroadcastArtifact | null {
    const row = this.#db
      .prepare(`SELECT post_cbor FROM channel_log WHERE channel_pubkey = ? AND seq = ?`)
      .get(channelPubkeyHex, seq) as { post_cbor: Uint8Array } | undefined;
    if (!row) return null;
    return this.#decodeRow(seq, new Uint8Array(row.post_cbor));
  }

  /**
   * A stored row that no longer decodes, or no longer carries both valid signatures, is corruption —
   * never something to skip past or hand to a relay being refilled.
   */
  #decodeRow(seq: number, cbor: Uint8Array): BroadcastArtifact {
    const d = decodeBroadcastArtifact(cbor);
    if (!d.ok) {
      throw new ChannelLogError("log_row_corrupt", `stored seq ${seq} does not decode: ${d.reason}`);
    }
    const verdict = verifyBroadcastArtifact(d.artifact);
    if (!verdict.ok) {
      throw new ChannelLogError("log_row_corrupt", `stored seq ${seq} no longer verifies: ${verdict.reason}`);
    }
    return d.artifact;
  }

  #rollback(channelPubkeyHex: string, original: unknown): void {
    try {
      this.#db.exec("ROLLBACK");
    } catch (rollbackErr) {
      // Usually harmless: the failing statement already ended the transaction. If it did not, the
      // handle is still inside one, and the next write fails naming the wrong cause — so say so.
      this.#logger.warn("channel.log.rollback_failed", {
        channel_pubkey: channelPubkeyHex,
        error: extractErrorMessage(rollbackErr),
        original_error: extractErrorMessage(original),
      });
    }
  }

  #state(channelPubkeyHex: string): StateRow {
    const row = this.#db
      .prepare(`SELECT next_seq, pruned_through FROM channel_state WHERE channel_pubkey = ?`)
      .get(channelPubkeyHex) as StateRow | undefined;
    if (!row) throw new ChannelLogError("channel_unknown", `no channel log for ${channelPubkeyHex.slice(0, 16)}; call ensureChannel first`);
    return row;
  }
}
