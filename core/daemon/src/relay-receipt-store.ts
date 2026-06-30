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
 * IMMUTABILITY (SI-003): the unique unit of a relay attestation is a POSITION — (agent, session, sequence)
 * — not a content hash. The same plaintext ("ok") legitimately produces the same content hash at DIFFERENT
 * sequences (per-session relay counter; repeated content within a session), so the table is keyed on the
 * position with the hash as payload. `INSERT OR IGNORE` then defends the real threat — a relay rewriting the
 * hash it recorded for an already-assigned (session, sequence) — while never dropping a legitimate
 * attestation for repeated content (code review HIGH).
 *
 * Crypto: Ed25519 (RFC 8032), SHA-256 (FIPS 180-4). TBS = SHA-256(hash_bytes || seq_BE4 || ts_BE8).
 */
import { verify, buildRelayAckTbs } from "@cello-protocol/crypto";
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";

/** A relay's signed ACK for a submitted content hash, stored as an immutable receipt. */
export interface RelayReceipt {
  /** Hex of the 32-byte content hash the relay witnessed + sequenced (payload, NOT the unique key). */
  hashHex: string;
  /** Hex of the agent (K_local pubkey) this receipt belongs to. */
  agentPubkeyHex: string;
  /** Session this hash belonged to (hex) — part of the unique attestation position. */
  sessionIdHex: string;
  /** Stable relay identifier (relay-node sets relayId = hex of its ACK-signing pubkey). */
  relayId: string;
  /** Hex of the 32-byte Ed25519 pubkey that signed this ACK (= relayId; the directory confirms it at seal). */
  relayPubkeyHex: string;
  /** Relay-assigned canonical sequence number — part of the unique attestation position. */
  sequenceNumber: number;
  /** Unix ms timestamp embedded in the ACK TBS. */
  timestamp: number;
  /** Hex of the 64-byte Ed25519 signature over the ACK TBS. */
  signatureHex: string;
}

/**
 * Verify a relay ACK signature against the (relayId-derived) relay pubkey. Returns true iff the signature
 * is exactly 64 bytes and Ed25519-verifies over TBS = SHA-256(hash_bytes || seq_BE4 || ts_BE8) — the same
 * TBS the relay signs (`buildRelayAckTbs`). A forged sequence number changes the TBS, so its signature fails.
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

/** The decision for one `hash_submit_ack` — pure + directly unit-testable (the verify-gates-store wiring). */
export type AckEvaluation =
  | { kind: "store"; receipt: RelayReceipt }
  /** The ACK carried no relay_id/signature/timestamp (a keyless/legacy relay) — nothing to attest. */
  | { kind: "unsigned" }
  /** relay_id is not a 64-hex Ed25519 pubkey. */
  | { kind: "bad_relay_id" }
  /** The signature does NOT bind (content_hash, sequence, timestamp) — a forged/corrupt ACK. REJECT. */
  | { kind: "invalid_signature" };

/**
 * Evaluate a relay ACK: decide whether it yields a storable, signature-verified receipt. This is the
 * verify-gates-store decision in isolation (so it is unit-testable without the relay stream) — a forged
 * signature returns `invalid_signature` and MUST NOT be stored (DoD: "a forged sequence is rejected").
 */
export function evaluateRelayAck(params: {
  contentHash: Uint8Array;
  sessionIdHex: string;
  agentPubkeyHex: string;
  relayId: string | undefined;
  relaySignature: Uint8Array | undefined;
  timestamp: number | undefined;
  sequenceNumber: number;
}): AckEvaluation {
  const { contentHash, sessionIdHex, agentPubkeyHex, relayId, relaySignature, timestamp, sequenceNumber } = params;
  if (!relayId || !relaySignature || timestamp === undefined) return { kind: "unsigned" };
  if (!/^[0-9a-fA-F]{64}$/.test(relayId)) return { kind: "bad_relay_id" };
  const relayPubkey = new Uint8Array(Buffer.from(relayId, "hex"));
  if (!verifyRelayAck(contentHash, sequenceNumber, timestamp, relaySignature, relayPubkey)) {
    return { kind: "invalid_signature" };
  }
  return {
    kind: "store",
    receipt: {
      hashHex: Buffer.from(contentHash).toString("hex"),
      agentPubkeyHex,
      sessionIdHex,
      relayId,
      relayPubkeyHex: relayId,
      sequenceNumber,
      timestamp,
      signatureHex: Buffer.from(relaySignature).toString("hex"),
    },
  };
}

const CREATE_RELAY_RECEIPTS_SQL = `
  CREATE TABLE IF NOT EXISTS relay_ack_receipts (
    agent_pubkey     TEXT    NOT NULL,
    session_id       TEXT    NOT NULL,
    sequence_number  INTEGER NOT NULL,
    hash_hex         TEXT    NOT NULL,
    relay_id         TEXT    NOT NULL,
    relay_pubkey_hex TEXT    NOT NULL,
    relay_timestamp  INTEGER NOT NULL,
    signature_hex    TEXT    NOT NULL,
    stored_at        INTEGER NOT NULL,
    PRIMARY KEY (agent_pubkey, session_id, sequence_number)
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
   * Persist a VERIFIED receipt. IMMUTABLE: keyed on the attestation POSITION (agent, session, sequence) —
   * `INSERT OR IGNORE` keeps the FIRST hash recorded for a position, so a relay cannot rewrite the hash it
   * already attested at that (session, sequence). Returns true if a new row was written, false if the
   * position was already recorded (logged distinctly when the existing hash DIFFERS — a relay equivocation).
   */
  store(receipt: RelayReceipt, storedAtMs: number): boolean {
    const existing = this.get(receipt.agentPubkeyHex, receipt.sessionIdHex, receipt.sequenceNumber);
    const info = this.#db
      .prepare(
        `INSERT OR IGNORE INTO relay_ack_receipts
           (agent_pubkey, session_id, sequence_number, hash_hex, relay_id, relay_pubkey_hex, relay_timestamp, signature_hex, stored_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        receipt.agentPubkeyHex,
        receipt.sessionIdHex,
        receipt.sequenceNumber,
        receipt.hashHex,
        receipt.relayId,
        receipt.relayPubkeyHex,
        receipt.timestamp,
        receipt.signatureHex,
        storedAtMs,
      );
    const wrote = Number(info.changes) > 0;
    if (!wrote && existing && existing.hashHex !== receipt.hashHex) {
      // EQUIVOCATION: a relay re-attesting a DIFFERENT hash at an already-recorded position. The first
      // verified receipt stands; surface the conflict loudly (it is an attack/misbehavior signal).
      this.#logger.warn("relay.receipt.equivocation", {
        agentShort: receipt.agentPubkeyHex.slice(0, 16),
        sessionShort: receipt.sessionIdHex.slice(0, 16),
        seq: receipt.sequenceNumber,
        recordedHashShort: existing.hashHex.slice(0, 16),
        conflictingHashShort: receipt.hashHex.slice(0, 16),
      });
    }
    return wrote;
  }

  /** The stored receipt at an attestation position (agent, session, sequence), or undefined. */
  get(agentPubkeyHex: string, sessionIdHex: string, sequenceNumber: number): RelayReceipt | undefined {
    const row = this.#db
      .prepare(
        `SELECT agent_pubkey, session_id, sequence_number, hash_hex, relay_id, relay_pubkey_hex, relay_timestamp, signature_hex
           FROM relay_ack_receipts WHERE agent_pubkey = ? AND session_id = ? AND sequence_number = ?`,
      )
      .get(agentPubkeyHex, sessionIdHex, sequenceNumber) as Record<string, unknown> | undefined;
    return row ? this.#rowToReceipt(row) : undefined;
  }

  /** All receipts for an agent (optionally a single session), in canonical sequence order (ascending). */
  getAll(agentPubkeyHex: string, sessionIdHex?: string): RelayReceipt[] {
    const rows = sessionIdHex
      ? this.#db
          .prepare(
            `SELECT agent_pubkey, session_id, sequence_number, hash_hex, relay_id, relay_pubkey_hex, relay_timestamp, signature_hex
               FROM relay_ack_receipts WHERE agent_pubkey = ? AND session_id = ? ORDER BY sequence_number ASC`,
          )
          .all(agentPubkeyHex, sessionIdHex)
      : this.#db
          .prepare(
            `SELECT agent_pubkey, session_id, sequence_number, hash_hex, relay_id, relay_pubkey_hex, relay_timestamp, signature_hex
               FROM relay_ack_receipts WHERE agent_pubkey = ? ORDER BY session_id, sequence_number ASC`,
          )
          .all(agentPubkeyHex);
    return (rows as Array<Record<string, unknown>>).map((r) => this.#rowToReceipt(r));
  }

  #rowToReceipt(row: Record<string, unknown>): RelayReceipt {
    return {
      hashHex: row.hash_hex as string,
      agentPubkeyHex: row.agent_pubkey as string,
      sessionIdHex: row.session_id as string,
      relayId: row.relay_id as string,
      relayPubkeyHex: row.relay_pubkey_hex as string,
      sequenceNumber: row.sequence_number as number,
      timestamp: row.relay_timestamp as number,
      signatureHex: row.signature_hex as string,
    };
  }
}
