/**
 * SessionSealLeafStore — FED-OPTIONB-SEAL-001.
 *
 * The per-session leaf log a UNILATERAL seal CARRIES to the directory so the directory rebuilds + verifies
 * the Merkle tree OFFLINE (no directory→relay getSealLeaves dial). It holds BOTH parties' leaves, because a
 * unilateral seal's reported_root spans the whole conversation:
 *   - PRESENT-party (own) leaves: captured from this agent's own hash_submit_ack — they carry the relay's
 *     signed RECEIPT (relay_id + timestamp + signature over buildRelayAckTbs(content_hash, seq, ts)). That
 *     signature is the teeth that pins each own leaf to its canonical sequence (Structure1 does NOT bind
 *     seq/prev_root, so without it a supplier could reorder its own leaves).
 *   - COUNTERPARTY leaves: captured from leaf_deliver — they carry structure1/structure2 but NO relay
 *     receipt (the relay does not ack-sign a delivery to the recipient). They are pinned by the absent
 *     party's sender_signature (unforgeable) + the prev_root chain + the signed last_seen_seq causal check +
 *     sequence contiguity against the receipt-pinned own leaves.
 *
 * Immutable at a position (agent, session, sequence): INSERT OR IGNORE keeps the first record for a seq.
 */
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";

/** A carried leaf for the unilateral-seal offline rebuild. Relay-receipt fields present only for own leaves. */
export interface SealCarryLeaf {
  sequenceNumber: number;
  /** 0x00 message / 0x02 control (SEAL). */
  leafKind: number;
  /** Hex of the leaf author's 32-byte pubkey (present party for own leaves, counterparty for received). */
  senderPubkeyHex: string;
  /** The relay's committed Structure2 (CBOR) for this leaf. */
  structure2Cbor: Uint8Array;
  /** The sender-signed Structure1 (CBOR) for this leaf. */
  structure1Cbor: Uint8Array;
  /** Relay ack-signing pubkey hex (own leaves only). */
  relayId?: string;
  /** Unix ms embedded in the relay ACK TBS (own leaves only). */
  relayTimestamp?: number;
  /** Hex of the 64-byte relay ACK signature (own leaves only). */
  relaySignatureHex?: string;
}

const CREATE_SQL = `
  CREATE TABLE IF NOT EXISTS session_seal_leaves (
    agent_pubkey      TEXT    NOT NULL,
    session_id        TEXT    NOT NULL,
    sequence_number   INTEGER NOT NULL,
    leaf_kind         INTEGER NOT NULL,
    sender_pubkey_hex TEXT    NOT NULL,
    structure2_cbor   BLOB    NOT NULL,
    structure1_cbor   BLOB    NOT NULL,
    relay_id          TEXT,
    relay_timestamp   INTEGER,
    relay_signature   TEXT,
    stored_at         INTEGER NOT NULL,
    PRIMARY KEY (agent_pubkey, session_id, sequence_number)
  );
`;

export class SessionSealLeafStore {
  readonly #db: DaemonDatabase;
  readonly #logger: Logger;

  constructor(db: DaemonDatabase, logger: Logger) {
    this.#db = db;
    this.#logger = logger;
    this.#db.exec(CREATE_SQL);
  }

  /**
   * Persist a leaf at its canonical position. IMMUTABLE: INSERT OR IGNORE keeps the FIRST record for an
   * (agent, session, sequence) — a later record for the same position (e.g. a re-delivery, or a relay
   * equivocation) cannot overwrite it. Returns true iff a new row was written.
   */
  store(agentPubkeyHex: string, sessionIdHex: string, leaf: SealCarryLeaf, storedAtMs: number): boolean {
    const info = this.#db
      .prepare(
        `INSERT OR IGNORE INTO session_seal_leaves
           (agent_pubkey, session_id, sequence_number, leaf_kind, sender_pubkey_hex, structure2_cbor, structure1_cbor, relay_id, relay_timestamp, relay_signature, stored_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        agentPubkeyHex,
        sessionIdHex,
        leaf.sequenceNumber,
        leaf.leafKind,
        leaf.senderPubkeyHex,
        Buffer.from(leaf.structure2Cbor),
        Buffer.from(leaf.structure1Cbor),
        leaf.relayId ?? null,
        leaf.relayTimestamp ?? null,
        leaf.relaySignatureHex ?? null,
        storedAtMs,
      );
    return Number(info.changes) > 0;
  }

  /**
   * The complete carried leaf chain for a session's UNILATERAL seal, ordered by canonical sequence. The
   * directory rebuilds + verifies this tree OFFLINE. Returns ALL recorded leaves (both parties); the caller
   * carries them verbatim and the directory enforces contiguity + the per-leaf relay-receipt teeth.
   */
  getCarry(agentPubkeyHex: string, sessionIdHex: string): SealCarryLeaf[] {
    const rows = this.#db
      .prepare(
        `SELECT sequence_number, leaf_kind, sender_pubkey_hex, structure2_cbor, structure1_cbor, relay_id, relay_timestamp, relay_signature
           FROM session_seal_leaves WHERE agent_pubkey = ? AND session_id = ? ORDER BY sequence_number ASC`,
      )
      .all(agentPubkeyHex, sessionIdHex) as Array<Record<string, unknown>>;
    return rows.map((r) => ({
      sequenceNumber: r.sequence_number as number,
      leafKind: r.leaf_kind as number,
      senderPubkeyHex: r.sender_pubkey_hex as string,
      structure2Cbor: toU8(r.structure2_cbor),
      structure1Cbor: toU8(r.structure1_cbor),
      relayId: (r.relay_id as string | null) ?? undefined,
      relayTimestamp: (r.relay_timestamp as number | null) ?? undefined,
      relaySignatureHex: (r.relay_signature as string | null) ?? undefined,
    }));
  }
}

/** Normalize a SQLite BLOB (Buffer/Uint8Array/ArrayBuffer) to a Uint8Array. */
function toU8(v: unknown): Uint8Array {
  if (v instanceof Uint8Array) return v;
  if (Buffer.isBuffer(v)) return new Uint8Array(v as Buffer);
  if (v instanceof ArrayBuffer) return new Uint8Array(v);
  return new Uint8Array();
}
