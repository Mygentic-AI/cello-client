/**
 * ChannelLogStore — M16 007-PUBLOG.
 *
 * A broadcast channel publishes a signed artifact once and it is delivered many times. The publisher
 * keeps ONE append-only log of everything it published, not one per subscriber, and that log is the
 * durable copy: when a relay loses content, subscribers repair from it. So:
 *
 *   - ROWS ARE IMMUTABLE. INSERT OR IGNORE at (channel_pubkey, seq); nothing rewrites a published
 *     artifact. A log that could be edited would make a consistency proof over it worthless.
 *   - THE STORE NEVER DECIDES A POSITION. The seq and epoch are inside the artifact's signature, so
 *     `nextPosition` reports what the next append must carry, the publisher signs that, and `append`
 *     checks it. A wrong position throws its own code; nothing is auto-corrected.
 *   - THE LOG ROW AND THE EPOCH STATE CHANGE IN ONE TRANSACTION, or `next_seq` could drift from the
 *     rows forever after a crash.
 *
 * Keyed on the channel's pubkey — the daemon's own channel identity — never on an agent name.
 */
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";
import { extractErrorMessage } from "./error-message.js";
import { buildMerkleTree, merkleRoot } from "@cello-protocol/crypto";
import { encodeBroadcastArtifact, decodeBroadcastArtifact, broadcastArtifactLeafHash } from "@cello-protocol/protocol-types";
import type { BroadcastArtifact } from "@cello-protocol/protocol-types";

export const CHANNEL_LOG_CREATE_SQL = `
  CREATE TABLE IF NOT EXISTS channel_log (
    channel_pubkey   TEXT    NOT NULL,
    seq              INTEGER NOT NULL,
    epoch_index      INTEGER NOT NULL,
    leaf_hash        BLOB    NOT NULL,
    artifact_cbor    BLOB    NOT NULL,
    title            TEXT    NOT NULL,
    published_at     INTEGER NOT NULL,
    PRIMARY KEY (channel_pubkey, seq)
  );
  CREATE TABLE IF NOT EXISTS channel_epoch_state (
    channel_pubkey        TEXT    NOT NULL PRIMARY KEY,
    open_epoch_index      INTEGER NOT NULL,
    open_epoch_first_seq  INTEGER NOT NULL,
    open_epoch_opened_at  INTEGER NOT NULL,
    prev_epoch_root       BLOB,
    next_seq              INTEGER NOT NULL
  );
`;

export interface AppendResult {
  seq: number;
  epoch_index: number;
  leaf_index: number;
  epoch_root: Uint8Array;
  leaf_count: number;
}

export type ChannelLogErrorCode =
  | "channel_unknown" | "seq_not_next" | "epoch_mismatch" | "prev_root_mismatch"
  | "position_taken" | "artifact_invalid";

export class ChannelLogError extends Error {
  readonly code: ChannelLogErrorCode;
  constructor(code: ChannelLogErrorCode, message: string) {
    super(`${code}: ${message}`);
    this.name = "ChannelLogError";
    this.code = code;
  }
}

interface StateRow {
  open_epoch_index: number | bigint;
  open_epoch_first_seq: number | bigint;
  open_epoch_opened_at: number | bigint;
  prev_epoch_root: Uint8Array | null;
  next_seq: number | bigint;
}

const toBytes = (v: unknown): Uint8Array | null =>
  v === null || v === undefined ? null : new Uint8Array(v as Uint8Array);

function bytesEqual(a: Uint8Array | null, b: Uint8Array | null): boolean {
  if (a === null || b === null) return a === b;
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export class ChannelLogStore {
  readonly #db: DaemonDatabase;
  readonly #logger: Logger;

  constructor(db: DaemonDatabase, logger: Logger) {
    this.#db = db;
    this.#logger = logger;
    this.#db.exec(CHANNEL_LOG_CREATE_SQL);
  }

  /** Idempotent: creates the state row {epoch 0, first_seq 0, opened_at 0, prev NULL, next_seq 1}. */
  ensureChannel(channelPubkeyHex: string): void {
    this.#db
      .prepare(
        `INSERT OR IGNORE INTO channel_epoch_state
           (channel_pubkey, open_epoch_index, open_epoch_first_seq, open_epoch_opened_at, prev_epoch_root, next_seq)
         VALUES (?, 0, 0, 0, NULL, 1)`,
      )
      .run(channelPubkeyHex);
  }

  /** What the NEXT append will be assigned — the publisher signs with these before appending. */
  nextPosition(channelPubkeyHex: string): {
    seq: number; epoch_index: number; prev_epoch_root: Uint8Array | null; first_in_epoch: boolean;
  } {
    const s = this.#state(channelPubkeyHex);
    return {
      seq: Number(s.next_seq),
      epoch_index: Number(s.open_epoch_index),
      prev_epoch_root: toBytes(s.prev_epoch_root),
      first_in_epoch: Number(s.open_epoch_first_seq) === 0,
    };
  }

  /** Append an already-signed artifact. Throws ChannelLogError — never silently skips. */
  append(channelPubkeyHex: string, artifact: BroadcastArtifact, publishedAtMs: number, correlationId?: string): AppendResult {
    const s = this.#state(channelPubkeyHex);
    const nextSeq = Number(s.next_seq);
    const openEpoch = Number(s.open_epoch_index);
    const firstInEpoch = Number(s.open_epoch_first_seq) === 0;

    if (artifact.seq !== nextSeq) {
      throw new ChannelLogError("seq_not_next", `artifact seq ${artifact.seq}, next is ${nextSeq}`);
    }
    if (artifact.epoch_index !== openEpoch) {
      throw new ChannelLogError("epoch_mismatch", `artifact epoch ${artifact.epoch_index}, open epoch is ${openEpoch}`);
    }
    if (firstInEpoch) {
      if (!bytesEqual(artifact.prev_epoch_root, toBytes(s.prev_epoch_root))) {
        throw new ChannelLogError("prev_root_mismatch", "the first artifact of an epoch must carry the previous epoch's sealed root");
      }
    } else if (artifact.prev_epoch_root !== null) {
      throw new ChannelLogError("prev_root_mismatch", "only the first artifact of an epoch carries prev_epoch_root");
    }

    // Never trust the in-memory object: it must survive its own wire encoding.
    let cbor: Uint8Array;
    try {
      cbor = encodeBroadcastArtifact(artifact);
    } catch (err) {
      throw new ChannelLogError("artifact_invalid", extractErrorMessage(err));
    }
    const decoded = decodeBroadcastArtifact(cbor);
    if (!decoded.ok) {
      throw new ChannelLogError("artifact_invalid", `${decoded.reason}: ${decoded.detail}`);
    }
    const leafHash = broadcastArtifactLeafHash(decoded.artifact);

    this.#db.exec("BEGIN IMMEDIATE");
    try {
      const inserted = this.#db
        .prepare(
          `INSERT OR IGNORE INTO channel_log
             (channel_pubkey, seq, epoch_index, leaf_hash, artifact_cbor, title, published_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(channelPubkeyHex, artifact.seq, artifact.epoch_index, Buffer.from(leafHash), Buffer.from(cbor), artifact.title, publishedAtMs);
      if (Number(inserted.changes) === 0) {
        throw new ChannelLogError("position_taken", `seq ${artifact.seq} is already in this channel's log`);
      }
      this.#db
        .prepare(
          firstInEpoch
            ? `UPDATE channel_epoch_state SET next_seq = ?, open_epoch_first_seq = ?, open_epoch_opened_at = ? WHERE channel_pubkey = ?`
            : `UPDATE channel_epoch_state SET next_seq = ? WHERE channel_pubkey = ?`,
        )
        .run(...(firstInEpoch
          ? [nextSeq + 1, artifact.seq, publishedAtMs, channelPubkeyHex]
          : [nextSeq + 1, channelPubkeyHex]));
      this.#db.exec("COMMIT");
    } catch (err) {
      try { this.#db.exec("ROLLBACK"); } catch { /* the failing statement may have ended the transaction */ }
      throw err;
    }

    const { root, leaf_count } = this.openEpochRoot(channelPubkeyHex);
    this.#logger.info("channel.artifact.appended", {
      ...(correlationId !== undefined ? { correlationId } : {}),
      channel_pubkey: channelPubkeyHex,
      seq: artifact.seq,
      epoch_index: artifact.epoch_index,
      leaf_count,
    });
    return { seq: artifact.seq, epoch_index: artifact.epoch_index, leaf_index: leaf_count - 1, epoch_root: root, leaf_count };
  }

  /** Leaf hashes of the open epoch in seq order; [] when the epoch has no leaves. */
  openEpochLeafHashes(channelPubkeyHex: string): Uint8Array[] {
    const s = this.#state(channelPubkeyHex);
    const rows = this.#db
      .prepare(`SELECT leaf_hash FROM channel_log WHERE channel_pubkey = ? AND epoch_index = ? ORDER BY seq ASC`)
      .all(channelPubkeyHex, Number(s.open_epoch_index)) as Array<{ leaf_hash: Uint8Array }>;
    return rows.map((r) => new Uint8Array(r.leaf_hash));
  }

  /** Merkle root over openEpochLeafHashes. `leaf_count` 0 means an empty epoch — never seal it. */
  openEpochRoot(channelPubkeyHex: string): { root: Uint8Array; leaf_count: number; first_seq: number; opened_at: number } {
    const s = this.#state(channelPubkeyHex);
    const leaves = this.openEpochLeafHashes(channelPubkeyHex);
    return {
      root: merkleRoot(buildMerkleTree(leaves.map((data) => ({ kind: "hash" as const, data })))),
      leaf_count: leaves.length,
      first_seq: Number(s.open_epoch_first_seq),
      opened_at: Number(s.open_epoch_opened_at),
    };
  }

  /** Range read for repair and for verification. Inclusive, seq order. */
  readRange(channelPubkeyHex: string, fromSeq: number, toSeq: number): BroadcastArtifact[] {
    const rows = this.#db
      .prepare(`SELECT seq, artifact_cbor FROM channel_log WHERE channel_pubkey = ? AND seq BETWEEN ? AND ? ORDER BY seq ASC`)
      .all(channelPubkeyHex, fromSeq, toSeq) as Array<{ seq: number | bigint; artifact_cbor: Uint8Array }>;
    return rows.map((r) => {
      const d = decodeBroadcastArtifact(new Uint8Array(r.artifact_cbor));
      if (!d.ok) {
        // A stored row that no longer decodes is corruption, not something to skip past quietly.
        throw new ChannelLogError("artifact_invalid", `stored seq ${Number(r.seq)} does not decode: ${d.reason}`);
      }
      return d.artifact;
    });
  }

  /** Called by the epoch sealer after a seal: advances to epoch+1 with prev_epoch_root = sealedRoot. */
  closeEpoch(channelPubkeyHex: string, sealedRoot: Uint8Array): void {
    this.#state(channelPubkeyHex);
    this.#db
      .prepare(
        `UPDATE channel_epoch_state
            SET open_epoch_index = open_epoch_index + 1, open_epoch_first_seq = 0, open_epoch_opened_at = 0, prev_epoch_root = ?
          WHERE channel_pubkey = ?`,
      )
      .run(Buffer.from(sealedRoot), channelPubkeyHex);
  }

  #state(channelPubkeyHex: string): StateRow {
    const row = this.#db
      .prepare(`SELECT open_epoch_index, open_epoch_first_seq, open_epoch_opened_at, prev_epoch_root, next_seq FROM channel_epoch_state WHERE channel_pubkey = ?`)
      .get(channelPubkeyHex) as StateRow | undefined;
    if (!row) throw new ChannelLogError("channel_unknown", `no channel log for ${channelPubkeyHex.slice(0, 16)}; call ensureChannel first`);
    return row;
  }
}
