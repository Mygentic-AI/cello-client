/**
 * ChannelEpochSealStore — M16 008-EPOCH.
 *
 * The publisher-signed seal over each closed epoch of a channel. Same shape as the channel log
 * (007): DDL in the constructor, INSERT OR IGNORE at (channel_pubkey, epoch_index), so a seal can
 * never be replaced by a second one for the same epoch.
 *
 * ONE mutation is permitted, and only one: `markNotarized` swaps in the version of the SAME seal
 * whose notarization slot the directory filled (order 009) and sets `notarized`. Nothing else
 * updates a row.
 *
 * `transaction` exists because recording a seal and closing its epoch in the log must be one
 * atomic step — a seal recorded without the epoch closing, or the reverse, is the corruption the
 * sealer is built to make impossible. Both stores share this daemon's one DB handle.
 */
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";
import { decodeChannelEpochSeal, encodeChannelEpochSeal, type ChannelEpochSeal } from "@cello-protocol/protocol-types";
import { extractErrorMessage } from "./error-message.js";

export const CHANNEL_EPOCH_SEALS_CREATE_SQL = `
  CREATE TABLE IF NOT EXISTS channel_epoch_seals (
    channel_pubkey TEXT    NOT NULL,
    epoch_index    INTEGER NOT NULL,
    epoch_root     BLOB    NOT NULL,
    seal_cbor      BLOB    NOT NULL,
    notarized      INTEGER NOT NULL DEFAULT 0,
    sealed_at      INTEGER NOT NULL,
    PRIMARY KEY (channel_pubkey, epoch_index)
  );
`;

export type ChannelEpochSealStoreErrorCode = "seal_position_taken" | "seal_not_found" | "seal_already_notarized" | "seal_mismatch";

export class ChannelEpochSealStoreError extends Error {
  readonly code: ChannelEpochSealStoreErrorCode;
  constructor(code: ChannelEpochSealStoreErrorCode, message: string) {
    super(`${code}: ${message}`);
    this.name = "ChannelEpochSealStoreError";
    this.code = code;
  }
}

export interface StoredEpochSeal {
  epoch_index: number;
  epoch_root: Uint8Array;
  seal_cbor: Uint8Array;
  notarized: boolean;
  sealed_at: number;
}

interface Row {
  epoch_index: number | bigint;
  epoch_root: Uint8Array;
  seal_cbor: Uint8Array;
  notarized: number | bigint;
  sealed_at: number | bigint;
}

const toStored = (r: Row): StoredEpochSeal => ({
  epoch_index: Number(r.epoch_index),
  epoch_root: new Uint8Array(r.epoch_root),
  seal_cbor: new Uint8Array(r.seal_cbor),
  notarized: Number(r.notarized) === 1,
  sealed_at: Number(r.sealed_at),
});

export class ChannelEpochSealStore {
  readonly #db: DaemonDatabase;
  readonly #logger: Logger;

  constructor(db: DaemonDatabase, logger: Logger) {
    this.#db = db;
    this.#logger = logger;
    this.#db.exec(CHANNEL_EPOCH_SEALS_CREATE_SQL);
  }

  /** Record a publisher-signed seal. Throws seal_position_taken if this epoch already has one. */
  record(channelPubkeyHex: string, seal: ChannelEpochSeal): void {
    const info = this.#db
      .prepare(
        `INSERT OR IGNORE INTO channel_epoch_seals (channel_pubkey, epoch_index, epoch_root, seal_cbor, notarized, sealed_at)
         VALUES (?, ?, ?, ?, 0, ?)`,
      )
      .run(channelPubkeyHex, seal.epoch_index, Buffer.from(seal.epoch_root), Buffer.from(encodeChannelEpochSeal(seal)), seal.sealed_at);
    if (Number(info.changes) === 0) {
      throw new ChannelEpochSealStoreError("seal_position_taken", `epoch ${seal.epoch_index} of this channel is already sealed`);
    }
  }

  get(channelPubkeyHex: string, epochIndex: number): StoredEpochSeal | null {
    const row = this.#db
      .prepare(`SELECT epoch_index, epoch_root, seal_cbor, notarized, sealed_at FROM channel_epoch_seals WHERE channel_pubkey = ? AND epoch_index = ?`)
      .get(channelPubkeyHex, epochIndex) as Row | undefined;
    return row ? toStored(row) : null;
  }

  latest(channelPubkeyHex: string): StoredEpochSeal | null {
    const row = this.#db
      .prepare(`SELECT epoch_index, epoch_root, seal_cbor, notarized, sealed_at FROM channel_epoch_seals WHERE channel_pubkey = ? ORDER BY epoch_index DESC LIMIT 1`)
      .get(channelPubkeyHex) as Row | undefined;
    return row ? toStored(row) : null;
  }

  /**
   * The ONLY update this table permits: the notarized version of the same seal (order 009), once.
   * Everything but the notarization slot must re-encode byte-identically to the stored seal, or a
   * wiring slip could overwrite the publisher's commitment with another seal and still read notarized.
   */
  markNotarized(channelPubkeyHex: string, epochIndex: number, notarizedSealCbor: Uint8Array): void {
    const stored = this.get(channelPubkeyHex, epochIndex);
    if (!stored) {
      throw new ChannelEpochSealStoreError("seal_not_found", `no seal recorded for epoch ${epochIndex} of this channel`);
    }
    if (stored.notarized) {
      throw new ChannelEpochSealStoreError("seal_already_notarized", `epoch ${epochIndex} of this channel is already notarized`);
    }
    const incoming = decodeChannelEpochSeal(notarizedSealCbor);
    if (!incoming.ok) {
      throw new ChannelEpochSealStoreError("seal_mismatch", `the notarized seal does not decode: ${incoming.reason}`);
    }
    if (incoming.seal.notarization === null) {
      throw new ChannelEpochSealStoreError("seal_mismatch", "the notarized seal's notarization slot is empty");
    }
    const withoutSlot = encodeChannelEpochSeal({ ...incoming.seal, notarization: null });
    if (!Buffer.from(withoutSlot).equals(Buffer.from(stored.seal_cbor))) {
      throw new ChannelEpochSealStoreError("seal_mismatch", "the notarized seal differs from the recorded seal outside the notarization slot");
    }
    const info = this.#db
      .prepare(`UPDATE channel_epoch_seals SET seal_cbor = ?, notarized = 1 WHERE channel_pubkey = ? AND epoch_index = ? AND notarized = 0`)
      .run(Buffer.from(notarizedSealCbor), channelPubkeyHex, epochIndex);
    if (Number(info.changes) === 0) {
      throw new ChannelEpochSealStoreError("seal_already_notarized", `epoch ${epochIndex} of this channel was notarized concurrently`);
    }
  }

  /** Run `fn` in one write transaction on this daemon's DB; roll back and rethrow on any throw. */
  transaction<T>(fn: () => T): T {
    this.#db.exec("BEGIN IMMEDIATE");
    try {
      const result = fn();
      this.#db.exec("COMMIT");
      return result;
    } catch (err) {
      try {
        this.#db.exec("ROLLBACK");
      } catch (rollbackErr) {
        this.#logger.warn("channel.epoch.rollback_failed", { error: extractErrorMessage(rollbackErr), original_error: extractErrorMessage(err) });
      }
      throw err;
    }
  }
}
