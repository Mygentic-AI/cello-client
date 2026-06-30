/**
 * CELLO Daemon — RelayReceiptStore (M8B DOD-RELAYSIG-1)
 *
 * The relay is the ordering/witness authority: it assigns a canonical sequence number to each submitted
 * content-hash leaf and signs an ACK over it (PERSIST-012, relay-node `buildRelayAckTbs`). This store is the
 * client's IMMUTABLE record of those signed attestations — durable evidence that the relay assigned a
 * specific sequence to a specific hash at a specific time. The receipt is what lets the client later prove
 * (or dispute) the relay's ordering, and is the building block the client carries to the directory at seal
 * time (OPTIONB-SEAL-1) instead of the directory dialing the relay.
 *
 * Ported from the pre-REPOSPLIT dead `core/client/src/agent-hash-queue.ts` (+ its `relay_ack_receipts`
 * schema) into the LIVE daemon. The verification is the same Ed25519 check the relay's signer mirrors.
 *
 * IMMUTABILITY (SI-003): a receipt for a given (hash, agent) is written at most ONCE. A second ACK for the
 * same hash — including a relay trying to re-attest a DIFFERENT sequence — does NOT overwrite the first.
 *
 * Crypto: Ed25519 (RFC 8032), SHA-256 (FIPS 180-4). TBS = SHA-256(hash_bytes || seq_BE4 || ts_BE8).
 */
import { verify, buildRelayAckTbs } from "@cello-protocol/crypto";
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";

/** A relay's signed ACK for a submitted content hash, stored as an immutable receipt. */
export interface RelayReceipt {
  /** Hex of the 32-byte content hash the relay witnessed + sequenced. */
  hashHex: string;
  /** Hex of the agent (K_local pubkey) this receipt belongs to. */
  agentPubkeyHex: string;
  /** Session this hash belonged to (hex), if known. */
  sessionIdHex: string | null;
  /** Stable relay identifier (relay-node sets relayId = hex of its ACK-signing pubkey). */
  relayId: string;
  /** Hex of the 32-byte Ed25519 pubkey that signed this ACK (the trusted, directory-confirmed relay key). */
  relayPubkeyHex: string;
  /** Relay-assigned canonical sequence number. */
  sequenceNumber: number;
  /** Unix ms timestamp embedded in the ACK TBS. */
  timestamp: number;
  /** Hex of the 64-byte Ed25519 signature over the ACK TBS. */
  signatureHex: string;
}

/**
 * Verify a relay ACK signature against the (trusted) relay pubkey. Returns true iff the signature is
 * exactly 64 bytes and Ed25519-verifies over TBS = SHA-256(hash_bytes || seq_BE4 || ts_BE8) — the same TBS
 * the relay signs (`buildRelayAckTbs`). A forged sequence number changes the TBS, so its signature fails.
 */
export function verifyRelayAck(
  contentHash: Uint8Array,
  sequenceNumber: number,
  timestamp: number,
  signature: Uint8Array,
  relayPubkey: Uint8Array,
): boolean {
  if (signature.length !== 64) return false;
  const tbs = buildRelayAckTbs(contentHash, sequenceNumber, timestamp);
  return verify(relayPubkey, tbs, signature);
}

const CREATE_RELAY_RECEIPTS_SQL = `
  CREATE TABLE IF NOT EXISTS relay_ack_receipts (
    hash_hex         TEXT    NOT NULL,
    agent_pubkey     TEXT    NOT NULL,
    session_id       TEXT,
    relay_id         TEXT    NOT NULL,
    relay_pubkey_hex TEXT    NOT NULL,
    sequence_number  INTEGER NOT NULL,
    relay_timestamp  INTEGER NOT NULL,
    signature_hex    TEXT    NOT NULL,
    stored_at        INTEGER NOT NULL,
    PRIMARY KEY (hash_hex, agent_pubkey)
  );
`;

export class RelayReceiptStore {
  readonly #db: DaemonDatabase;
  readonly #logger: Logger;

  constructor(db: DaemonDatabase, logger: Logger) {
    this.#db = db;
    this.#logger = logger;
    this.#db.exec(CREATE_RELAY_RECEIPTS_SQL);
  }

  /**
   * Persist a VERIFIED receipt. IMMUTABLE: if a receipt for (hashHex, agentPubkeyHex) already exists it is
   * NOT overwritten — `INSERT OR IGNORE` — so a relay cannot retroactively re-attest a different sequence
   * for a hash the client already recorded. Returns true if a new row was written, false if one existed.
   */
  store(receipt: RelayReceipt, storedAtMs: number): boolean {
    const info = this.#db
      .prepare(
        `INSERT OR IGNORE INTO relay_ack_receipts
           (hash_hex, agent_pubkey, session_id, relay_id, relay_pubkey_hex, sequence_number, relay_timestamp, signature_hex, stored_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        receipt.hashHex,
        receipt.agentPubkeyHex,
        receipt.sessionIdHex,
        receipt.relayId,
        receipt.relayPubkeyHex,
        receipt.sequenceNumber,
        receipt.timestamp,
        receipt.signatureHex,
        storedAtMs,
      );
    const wrote = info.changes > 0;
    if (!wrote) {
      this.#logger.debug("relay.receipt.duplicate_ignored", { hashShort: receipt.hashHex.slice(0, 16), agentShort: receipt.agentPubkeyHex.slice(0, 16) });
    }
    return wrote;
  }

  /** The stored receipt for a content hash (this agent), or undefined. */
  get(hashHex: string, agentPubkeyHex: string): RelayReceipt | undefined {
    const row = this.#db
      .prepare(
        `SELECT hash_hex, agent_pubkey, session_id, relay_id, relay_pubkey_hex, sequence_number, relay_timestamp, signature_hex
           FROM relay_ack_receipts WHERE hash_hex = ? AND agent_pubkey = ?`,
      )
      .get(hashHex, agentPubkeyHex) as Record<string, unknown> | undefined;
    return row ? this.#rowToReceipt(row) : undefined;
  }

  /** All receipts for an agent (optionally a single session), newest sequence first. */
  getAll(agentPubkeyHex: string, sessionIdHex?: string): RelayReceipt[] {
    const rows = sessionIdHex
      ? this.#db
          .prepare(
            `SELECT hash_hex, agent_pubkey, session_id, relay_id, relay_pubkey_hex, sequence_number, relay_timestamp, signature_hex
               FROM relay_ack_receipts WHERE agent_pubkey = ? AND session_id = ? ORDER BY sequence_number DESC`,
          )
          .all(agentPubkeyHex, sessionIdHex)
      : this.#db
          .prepare(
            `SELECT hash_hex, agent_pubkey, session_id, relay_id, relay_pubkey_hex, sequence_number, relay_timestamp, signature_hex
               FROM relay_ack_receipts WHERE agent_pubkey = ? ORDER BY sequence_number DESC`,
          )
          .all(agentPubkeyHex);
    return (rows as Array<Record<string, unknown>>).map((r) => this.#rowToReceipt(r));
  }

  #rowToReceipt(row: Record<string, unknown>): RelayReceipt {
    return {
      hashHex: row.hash_hex as string,
      agentPubkeyHex: row.agent_pubkey as string,
      sessionIdHex: (row.session_id as string | null) ?? null,
      relayId: row.relay_id as string,
      relayPubkeyHex: row.relay_pubkey_hex as string,
      sequenceNumber: row.sequence_number as number,
      timestamp: row.relay_timestamp as number,
      signatureHex: row.signature_hex as string,
    };
  }
}
