/**
 * CELLO Daemon — RelayReceiptStore (DOD-M15-ORDERPROOF-1, was M8B DOD-RELAYSIG-1)
 *
 * The relay is the ordering/witness authority: it assigns a canonical sequence number to each submitted
 * content-hash leaf and signs an ATTESTATION over it (relay-node `buildRelayAckTbs`). This store is the
 * client's IMMUTABLE record of those signed attestations — durable evidence that the relay assigned a
 * specific sequence to a specific hash at a specific time. The receipt is what lets the client later prove
 * (or dispute) the relay's ordering, and is the building block the client carries to the directory at seal
 * time (OPTIONB-SEAL-1) instead of the directory dialing the relay.
 *
 * Verification is an Ed25519 check that MUST stay byte-compatible with the relay's signer.
 *
 * ⚠️ **THE KEY IT IS CHECKED AGAINST IS THE POINT — 069-ORDERPROOF.** This module used to verify the
 * signature against `relay_id`, a key carried inside the very frame being checked, and its own comment
 * called that "SELF-CONSISTENCY". It is not a check: anyone who can write the frame can mint a key, sign
 * any ordering they like with it, and put the key in the field we verify against. The key now comes from
 * `relay_id` on the **directory-signed `SessionAssignment`**, which is inside the FROST-signed TBS the
 * client already verifies — something neither the relay nor either participant can rewrite.
 *
 * ⚠️ **AND ABSENT IS NOT FINE.** Missing, malformed and mismatched are ONE outcome (`refused`), because
 * a party holding no attestation for a message is in exactly the state a corrupted one leaves them in.
 * Whoever can cause the absence must not get a softer answer than whoever can cause the corruption — and
 * the party who can cause the absence is the relay, the party the check exists to constrain.
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
import { decodeStructure1 } from "@cello-protocol/protocol-types";
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
  /**
   * 069-ORDERPROOF — hex of the 32-byte running root of this session's tree AFTER this leaf was
   * appended, as the relay signed it. The position alone says where a leaf sits in a COUNTER; the
   * root says where it sits in a CHAIN, which is what lets a party prove a prefix once the relay is
   * gone. Optional on the TYPE only so rows written before this order still read; every row this
   * build writes has one.
   */
  runningRootHex?: string;
  /** Hex of the 64-byte Ed25519 signature over the ACK TBS. */
  signatureHex: string;
  // FED-OPTIONB-SEAL-001 — the per-leaf bytes a UNILATERAL seal carries so the directory rebuilds the
  // tree OFFLINE (no directory→relay getSealLeaves dial). Optional: pre-OPTIONB-SEAL receipts (and rows
  // written before the migration) have none; getSealLeaves omits those. When present, structure2Cbor is
  // the relay's committed Structure2 (from the DOD-MSG-4 ack), structure1Cbor the sender-signed leaf, and
  // leafKind the leaf kind (0x00 msg / 0x02 ctrl).
  /** The relay's committed Structure2 (CBOR) for this leaf (DOD-MSG-4 hash_submit_ack). */
  structure2Cbor?: Uint8Array;
  /** The sender-signed Structure1 (CBOR) for this leaf. */
  structure1Cbor?: Uint8Array;
  /** Leaf kind: 0x00 message, 0x02 control (SEAL). */
  leafKind?: number;
}

/**
 * FED-OPTIONB-SEAL-001: a fully-carried leaf for the unilateral-seal offline rebuild — a receipt that has
 * its Structure2/Structure1 carry bytes. `getSealLeaves` returns these (the chain the directory can rebuild
 * + verify offline), narrowing the optional carry fields to required.
 */
export interface SealLeaf extends RelayReceipt {
  structure2Cbor: Uint8Array;
  structure1Cbor: Uint8Array;
  leafKind: number;
}

/**
 * Verify a relay ordering attestation against a relay pubkey the CALLER supplies — and the caller
 * must have got it from the directory-signed assignment, never from the frame.
 *
 * Returns true iff every field is well-formed and the 64-byte Ed25519 signature verifies over
 * TBS = SHA-256(DOMAIN ‖ session_id ‖ content_hash ‖ seq_BE4 ‖ running_root ‖ ts_BE8) — the same
 * statement the relay signs. A forged sequence, a swapped session or a rewritten prefix all change
 * the TBS, so each fails.
 *
 * A wrong-length field returns FALSE rather than throwing: these bytes come off a wire the relay
 * controls, and a malformed length must refuse this attestation, not take down the frame handler.
 */
export function verifyRelayAck(
  sessionId: Uint8Array,
  contentHash: Uint8Array,
  sequenceNumber: number,
  runningRoot: Uint8Array,
  timestamp: number,
  signature: Uint8Array,
  relayPubkey: Uint8Array,
): boolean {
  if (signature.length !== 64) return false;
  if (sessionId.length !== 16 || contentHash.length !== 32 || runningRoot.length !== 32) return false;
  const tbs = buildRelayAckTbs(sessionId, contentHash, sequenceNumber, runningRoot, timestamp);
  return verify(relayPubkey, tbs, signature);
}

/** Why an attestation was refused. For the LOG — the protocol outcome is identical for all of them. */
export type AckRefusalCause =
  /** This session has no directory-named relay key recorded, so nothing can anchor the check. */
  | "no_anchor"
  /** The frame named a relay other than the one the directory assigned to this session. */
  | "relay_not_assigned"
  /** `relay_id` was present but is not a 64-hex Ed25519 pubkey. */
  | "bad_relay_id"
  /** No signature, no timestamp, or no running root — the relay attested nothing. */
  | "attestation_absent"
  /** The signature does not bind (session, hash, sequence, root, timestamp) under the assigned key. */
  | "signature_invalid";

/** The decision for one `hash_submit_ack` — pure + directly unit-testable (the verify-gates-store wiring). */
export type AckEvaluation =
  | { kind: "store"; receipt: RelayReceipt }
  /**
   * REFUSED. One outcome for missing, malformed and mismatched — the caller must treat all three
   * identically, and `cause` exists so the LOG can still name which one it was. A caller that
   * branches on `cause` to soften any of them reintroduces exactly the hole this closes.
   */
  | { kind: "refused"; cause: AckRefusalCause };

/**
 * Read back the leaf we just submitted, so the relay's attestation has something to be checked
 * against — the step BEFORE `evaluateRelayAck`, and the one that decides whether the check can run
 * at all.
 *
 * ⚠️ "COULD NOT RUN THE CHECK" IS NOT "THE CHECK PASSED" — 069-ORDERPROOF.
 *
 * Both failures here used to be waved through by the caller, which settled the send `ok` having
 * verified nothing: the absent-versus-verified collapse this unit exists to remove, reproduced at
 * the one point where nothing was left to verify with. These are our OWN just-signed bytes, so a
 * hostile relay cannot steer into either — unreachable in practice, which is a different claim from
 * safe to wave through, and the distinction is the one that decays under later edits.
 *
 * `"none"` is the honest third answer: no submit was made, so no attestation is owed and none is
 * missing. It is the only one of the three that does not reject.
 */
export function readSubmittedLeaf(
  structure1Cbor: Uint8Array | undefined,
  seq: number,
): { kind: "none" } | { kind: "unreadable"; event: string; reason?: string } | { kind: "ok"; contentHash: Uint8Array; sessionId: Uint8Array } {
  if (seq < 0) return { kind: "none" };
  if (!structure1Cbor) return { kind: "unreadable", event: "relay.receipt.leaf_absent" };
  // Structure 1 = [version, content_hash(32), sender_pubkey(32), session_id(16), last_seen_seq, ts],
  // plus last_seen_hash(32) at index 6 on a v2 claim (020-ACKHASH). content_hash is index 1 and
  // session_id index 3 in both.
  const s1 = decodeStructure1(structure1Cbor);
  // The reason is carried because "we cannot read what we just wrote" and "we wrote a layout we
  // cannot name" are different faults with the same symptom.
  if (!s1.ok) return { kind: "unreadable", event: "relay.receipt.undecodable_leaf", reason: s1.reason };
  return { kind: "ok", contentHash: s1.fields.contentHash, sessionId: s1.fields.sessionId };
}

/**
 * Evaluate a relay ordering attestation: decide whether it yields a storable, signature-verified
 * receipt. This is the verify-gates-store decision in isolation, so it is unit-testable without the
 * relay stream.
 *
 * `expectedRelayPubkeyHex` is the anchor and it is REQUIRED in substance: `undefined` refuses. It
 * must come from `relay_id` on an assignment whose FROST signature has been verified.
 */
export function evaluateRelayAck(params: {
  sessionId: Uint8Array;
  contentHash: Uint8Array;
  runningRoot: Uint8Array | undefined;
  sessionIdHex: string;
  agentPubkeyHex: string;
  /** The relay the DIRECTORY assigned to this session, hex. Absent ⇒ nothing to anchor to ⇒ refuse. */
  expectedRelayPubkeyHex: string | undefined;
  relayId: string | undefined;
  relaySignature: Uint8Array | undefined;
  timestamp: number | undefined;
  sequenceNumber: number;
}): AckEvaluation {
  const {
    sessionId, contentHash, runningRoot, sessionIdHex, agentPubkeyHex,
    expectedRelayPubkeyHex, relayId, relaySignature, timestamp, sequenceNumber,
  } = params;

  if (!expectedRelayPubkeyHex || !/^[0-9a-fA-F]{64}$/.test(expectedRelayPubkeyHex)) {
    return { kind: "refused", cause: "no_anchor" };
  }
  /**
   * THE FRAME'S OWN CLAIM IS COMPARED, NEVER TRUSTED. The signature below is verified against the
   * directory's key regardless, so this comparison adds no security on its own — what it adds is a
   * NAMED cause. A relay that has been replaced mid-session produces a valid signature under a key
   * the directory never named, and "this is not the relay you were assigned" is the sentence an
   * operator can act on. `undefined` is not a mismatch: a relay omitting the field does not get to
   * skip the check, it simply gets checked against the anchor with no label.
   */
  if (relayId !== undefined) {
    if (!/^[0-9a-fA-F]{64}$/.test(relayId)) return { kind: "refused", cause: "bad_relay_id" };
    if (relayId.toLowerCase() !== expectedRelayPubkeyHex.toLowerCase()) {
      return { kind: "refused", cause: "relay_not_assigned" };
    }
  }

  if (!relaySignature || timestamp === undefined || !runningRoot) {
    return { kind: "refused", cause: "attestation_absent" };
  }

  const relayPubkey = new Uint8Array(Buffer.from(expectedRelayPubkeyHex, "hex"));
  if (!verifyRelayAck(sessionId, contentHash, sequenceNumber, runningRoot, timestamp, relaySignature, relayPubkey)) {
    return { kind: "refused", cause: "signature_invalid" };
  }

  return {
    kind: "store",
    receipt: {
      hashHex: Buffer.from(contentHash).toString("hex"),
      agentPubkeyHex,
      sessionIdHex,
      relayId: expectedRelayPubkeyHex,
      relayPubkeyHex: expectedRelayPubkeyHex,
      sequenceNumber,
      timestamp,
      signatureHex: Buffer.from(relaySignature).toString("hex"),
      runningRootHex: Buffer.from(runningRoot).toString("hex"),
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
    -- 069-ORDERPROOF: the running root the relay signed alongside the position (nullable — rows
    -- written before this order have none, and they stay readable and sealable exactly as they are).
    running_root_hex TEXT,
    -- FED-OPTIONB-SEAL-001: per-leaf carry bytes for the unilateral-seal offline rebuild (nullable).
    structure2_cbor  BLOB,
    structure1_cbor  BLOB,
    leaf_kind        INTEGER,
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
    this.#migrateSealCarryColumns();
  }

  /**
   * FED-OPTIONB-SEAL-001: add the per-leaf carry columns to a relay_ack_receipts table created before the
   * seal-carry feature (CREATE TABLE IF NOT EXISTS leaves an existing table untouched). Idempotent + safe:
   * each column is added only if absent (checked via PRAGMA table_info), and all three are NULLABLE so the
   * ALTER never rewrites or invalidates existing rows. Pre-migration receipts simply have no carry bytes
   * (getSealLeaves omits them). No data is read/destroyed — pure additive schema evolution.
   */
  #migrateSealCarryColumns(): void {
    const cols = new Set(
      (this.#db.prepare(`PRAGMA table_info(relay_ack_receipts)`).all() as Array<{ name: string }>).map((c) => c.name),
    );
    for (const [name, decl] of [
      ["structure2_cbor", "BLOB"],
      ["structure1_cbor", "BLOB"],
      ["leaf_kind", "INTEGER"],
      // 069-ORDERPROOF. NULLABLE, like the three above: a session that predates this order keeps
      // every receipt it already holds, opens, reads and seals unchanged, and simply has no root
      // recorded for those positions.
      ["running_root_hex", "TEXT"],
    ] as const) {
      if (!cols.has(name)) {
        this.#db.exec(`ALTER TABLE relay_ack_receipts ADD COLUMN ${name} ${decl}`);
      }
    }
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
           (agent_pubkey, session_id, sequence_number, hash_hex, relay_id, relay_pubkey_hex, relay_timestamp, signature_hex, stored_at, structure2_cbor, structure1_cbor, leaf_kind, running_root_hex)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
        // FED-OPTIONB-SEAL-001: carry bytes (null when absent — receipt-only rows).
        receipt.structure2Cbor ? Buffer.from(receipt.structure2Cbor) : null,
        receipt.structure1Cbor ? Buffer.from(receipt.structure1Cbor) : null,
        receipt.leafKind ?? null,
        receipt.runningRootHex ?? null,
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
        `SELECT agent_pubkey, session_id, sequence_number, hash_hex, relay_id, relay_pubkey_hex, relay_timestamp, signature_hex, running_root_hex
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
            `SELECT agent_pubkey, session_id, sequence_number, hash_hex, relay_id, relay_pubkey_hex, relay_timestamp, signature_hex, running_root_hex
               FROM relay_ack_receipts WHERE agent_pubkey = ? AND session_id = ? ORDER BY sequence_number ASC`,
          )
          .all(agentPubkeyHex, sessionIdHex)
      : this.#db
          .prepare(
            `SELECT agent_pubkey, session_id, sequence_number, hash_hex, relay_id, relay_pubkey_hex, relay_timestamp, signature_hex, running_root_hex
               FROM relay_ack_receipts WHERE agent_pubkey = ? ORDER BY session_id, sequence_number ASC`,
          )
          .all(agentPubkeyHex);
    return (rows as Array<Record<string, unknown>>).map((r) => this.#rowToReceipt(r));
  }

  /**
   * FED-OPTIONB-SEAL-001: the complete carried leaf chain for a session's UNILATERAL seal — every receipt
   * that has its Structure2/Structure1 carry bytes, ordered by canonical sequence. The directory rebuilds +
   * verifies this tree OFFLINE (no directory→relay getSealLeaves dial). Rows without carry bytes
   * (pre-migration / receipt-only) are omitted: the caller carries only what the directory can rebuild.
   */
  getSealLeaves(agentPubkeyHex: string, sessionIdHex: string): SealLeaf[] {
    const rows = this.#db
      .prepare(
        `SELECT agent_pubkey, session_id, sequence_number, hash_hex, relay_id, relay_pubkey_hex, relay_timestamp, signature_hex, running_root_hex, structure2_cbor, structure1_cbor, leaf_kind
           FROM relay_ack_receipts
          WHERE agent_pubkey = ? AND session_id = ? AND structure2_cbor IS NOT NULL AND structure1_cbor IS NOT NULL AND leaf_kind IS NOT NULL
          ORDER BY sequence_number ASC`,
      )
      .all(agentPubkeyHex, sessionIdHex) as Array<Record<string, unknown>>;
    return rows.map((r) => ({
      ...this.#rowToReceipt(r),
      structure2Cbor: toU8(r.structure2_cbor),
      structure1Cbor: toU8(r.structure1_cbor),
      leafKind: r.leaf_kind as number,
    }));
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
      ...(typeof row.running_root_hex === "string" ? { runningRootHex: row.running_root_hex } : {}),
    };
  }
}

/** Normalize a SQLite BLOB column (Buffer/Uint8Array/ArrayBuffer) to a Uint8Array. */
function toU8(v: unknown): Uint8Array {
  if (v instanceof Uint8Array) return v;
  if (Buffer.isBuffer(v)) return new Uint8Array(v as Buffer);
  if (v instanceof ArrayBuffer) return new Uint8Array(v);
  return new Uint8Array();
}
