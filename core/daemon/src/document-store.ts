/**
 * DOD-DOC-STORE-1 — the daemon's three document tables (§16.7-12).
 *
 * TWO LAYERS, NOT ONE (§14). Storing only a merged Yjs binary would discard the signed envelope
 * chain that makes a seal verifiable, so both are kept:
 *
 *   `document_envelopes`  — the IMMUTABLE log: signatures, provenance, the per-document chain.
 *                           This is the truth.
 *   `document_snapshots`  — a MATERIALIZATION for fast start. Disposable by construction:
 *                           delete it and it rebuilds from the log, byte-identical.
 *
 * The distinction is load-bearing rather than stylistic. Live Yjs state deliberately does NOT
 * survive a daemon restart — CELLO's invariant is daemon-up-is-CELLO-on — and that is only safe
 * because the log makes rebuilding a lookup rather than an archaeology exercise.
 *
 * THIS MODULE PERSISTS; IT DOES NOT APPLY. Replay is INJECTED (`rebuildSnapshot`), so the store
 * owns *what to replay and in what order* while the engine (DOD-DOC-ENGINE-1) owns *how to
 * apply*. That keeps `yjs` out of this file's imports entirely and keeps the P0/P1 boundary
 * honest — a store that quietly grew a Y.Doc would be the engine wearing a store's name.
 *
 * WHAT IS NEVER STORED HERE: a Yjs clientID. §14's one-line rule is "let Yjs mint its own per
 * live Y.Doc; never derive it from agent identity, never persist and restore one." DOD-DOC-FUZZ-1
 * measured the cost of getting this wrong — two live docs sharing a clientID means the colliding
 * writer silently wins, the honest client's update is accepted-and-dropped, and the result is a
 * splice of two authors with an EMPTY pending set and no error on any path. So the snapshot
 * stores a binary and a state vector, and nothing that could be restored into a live document as
 * an identity.
 *
 * KEYED ON STABLE IDS ONLY. `agent_id` and `document_id`, never `agent_name` — it is a mutable
 * display label and reusable after retirement. The M7 session tables join on `agent_name`; that
 * is a known defect (`DOD-AGENT-ID-JOINKEY-1`), not a precedent to copy.
 */

import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";

/** Lifecycle states a document can hold (§3.5). `stalled` is DOD-DOC-REJECT-1's terminal state. */
export type DocumentStatus = "active" | "closed" | "killed" | "stalled";

/**
 * What an envelope IS, as opposed to what it says. A withdrawal or a rejection is a NEW ROW that
 * references an earlier envelope — never an edit to it. The log is append-only, so the only way
 * to say "that one no longer counts" is to add a record saying so.
 */
export type DocumentEnvelopeKind = "update" | "withdrawal" | "rejection";

export interface DocumentProperties {
  /** V1 accepts only `authenticated` — the Tier-2 seam (§16.1). */
  assurance_tier?: string;
  /** V1 accepts only `false` — the Tier-2 seam (§16.1). */
  schema_enforcement?: boolean;
  append_only?: boolean;
  [key: string]: unknown;
}

export interface DocumentRow {
  documentId: string;
  ownerAgentId: string;
  peerAgentId: string;
  documentType: string;
  properties: DocumentProperties;
  status: DocumentStatus;
  createdAtMs: number;
}

export interface DocumentEnvelopeRow {
  /** Content hash of the envelope — the stable identity, and the log's primary key. */
  envelopeHash: string;
  documentId: string;
  /** WHO authored it. The chain is per-sender, so this is what partitions it. */
  senderAgentId: string;
  /** The sender's previous envelope for this document, or null at genesis (§9.1). */
  docPrevHash: string | null;
  /** Constant 0 in V1 and NEVER omitted — after a compaction an update that does not state its
   *  epoch cannot be verified unambiguously (§14, §16.1 seam). */
  epochId: number;
  signature: Uint8Array;
  /** The sender's Yjs state vector at publish time (§7). */
  stateVector: Uint8Array;
  /** NULLABLE — a purged envelope keeps its hash and signature, proving it existed (§16.7-12). */
  payload: Uint8Array | null;
  kind: DocumentEnvelopeKind;
  /** For a withdrawal or rejection: the envelope it concerns. */
  referencesEnvelopeHash?: string | null;
  createdAtMs: number;
}

export interface DocumentSnapshot {
  binary: Uint8Array;
  stateVector: Uint8Array;
  /**
   * Position in the envelope log this snapshot reflects. §14 is explicit about why this is
   * stored rather than derived: with it, "where does the snapshot sit relative to the log" is a
   * lookup; without it, every rebuild and verification works it out from scratch.
   */
  lastAppliedIndex: number;
}

export type ChainVerdict =
  | { ok: true }
  | { ok: false; reason: "document_chain_broken" | "document_chain_forked"; detail: string };

/** Injected by the engine: fold an ordered payload list into a materialized state. */
export type ReplayFn = (payloads: Uint8Array[]) => { binary: Uint8Array; stateVector: Uint8Array };

const CREATE_DOCUMENTS_SQL = `
  CREATE TABLE IF NOT EXISTS documents (
    owner_agent_id  TEXT    NOT NULL,
    document_id     TEXT    NOT NULL,
    peer_agent_id   TEXT    NOT NULL,
    document_type   TEXT    NOT NULL,
    properties      TEXT    NOT NULL,
    status          TEXT    NOT NULL,
    created_at      INTEGER NOT NULL,
    PRIMARY KEY (owner_agent_id, document_id)
  );
`;

const CREATE_ENVELOPES_SQL = `
  CREATE TABLE IF NOT EXISTS document_envelopes (
    owner_agent_id  TEXT    NOT NULL,
    document_id     TEXT    NOT NULL,
    envelope_hash   TEXT    NOT NULL,
    sender_agent_id TEXT    NOT NULL,
    doc_prev_hash   TEXT,
    epoch_id        INTEGER NOT NULL,
    signature       BLOB    NOT NULL,
    state_vector    BLOB    NOT NULL,
    payload         BLOB,
    kind            TEXT    NOT NULL,
    references_hash TEXT,
    created_at      INTEGER NOT NULL,
    log_index       INTEGER NOT NULL,
    PRIMARY KEY (owner_agent_id, document_id, envelope_hash)
  );
`;

const CREATE_SNAPSHOTS_SQL = `
  CREATE TABLE IF NOT EXISTS document_snapshots (
    owner_agent_id      TEXT    NOT NULL,
    document_id         TEXT    NOT NULL,
    binary              BLOB    NOT NULL,
    state_vector        BLOB    NOT NULL,
    last_applied_index  INTEGER NOT NULL,
    PRIMARY KEY (owner_agent_id, document_id)
  );
`;

export class DocumentStore {
  readonly #db: DaemonDatabase;
  readonly #logger: Logger;

  constructor(db: DaemonDatabase, logger: Logger) {
    this.#db = db;
    this.#logger = logger;
    this.#db.exec(CREATE_DOCUMENTS_SQL);
    this.#db.exec(CREATE_ENVELOPES_SQL);
    this.#db.exec(CREATE_SNAPSHOTS_SQL);
    // Reading the log in arrival order is the only access pattern that matters.
    this.#db.exec(
      "CREATE INDEX IF NOT EXISTS idx_document_envelopes_order ON document_envelopes (owner_agent_id, document_id, log_index)",
    );
  }

  // ─── documents ────────────────────────────────────────────────────────────

  createDocument(row: DocumentRow): void {
    this.#db
      .prepare(
        `INSERT OR IGNORE INTO documents
           (owner_agent_id, document_id, peer_agent_id, document_type, properties, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        row.ownerAgentId,
        row.documentId,
        row.peerAgentId,
        row.documentType,
        JSON.stringify(row.properties),
        row.status,
        row.createdAtMs,
      );
  }

  getDocument(ownerAgentId: string, documentId: string): DocumentRow | null {
    const r = this.#db
      .prepare("SELECT * FROM documents WHERE owner_agent_id = ? AND document_id = ?")
      .get(ownerAgentId, documentId) as Record<string, unknown> | undefined;
    return r ? toDocumentRow(r) : null;
  }

  listDocuments(ownerAgentId: string): DocumentRow[] {
    const rows = this.#db
      .prepare("SELECT * FROM documents WHERE owner_agent_id = ? ORDER BY created_at ASC")
      .all(ownerAgentId) as Array<Record<string, unknown>>;
    return rows.map(toDocumentRow);
  }

  setDocumentStatus(ownerAgentId: string, documentId: string, status: DocumentStatus): void {
    this.#db
      .prepare("UPDATE documents SET status = ? WHERE owner_agent_id = ? AND document_id = ?")
      .run(status, ownerAgentId, documentId);
  }

  // ─── the append-only envelope log ─────────────────────────────────────────

  /**
   * Append an envelope at the next log position.
   *
   * IMMUTABLE AT A HASH: `INSERT OR IGNORE` keeps the FIRST record for an envelope hash, so a
   * re-delivery — or a peer replaying the same hash with different bytes — cannot overwrite what
   * was recorded. Returns whether a new row was written, so the caller can tell a genuine append
   * from a duplicate rather than inferring it.
   */
  appendEnvelope(ownerAgentId: string, envelope: DocumentEnvelopeRow): boolean {
    const nextIndex = this.#nextLogIndex(ownerAgentId, envelope.documentId);
    const info = this.#db
      .prepare(
        `INSERT OR IGNORE INTO document_envelopes
           (owner_agent_id, document_id, envelope_hash, sender_agent_id, doc_prev_hash, epoch_id,
            signature, state_vector, payload, kind, references_hash, created_at, log_index)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        ownerAgentId,
        envelope.documentId,
        envelope.envelopeHash,
        envelope.senderAgentId,
        envelope.docPrevHash,
        envelope.epochId,
        Buffer.from(envelope.signature),
        Buffer.from(envelope.stateVector),
        envelope.payload === null ? null : Buffer.from(envelope.payload),
        envelope.kind,
        envelope.referencesEnvelopeHash ?? null,
        envelope.createdAtMs,
        nextIndex,
      );
    return Number(info.changes) > 0;
  }

  getEnvelopeLog(ownerAgentId: string, documentId: string): DocumentEnvelopeRow[] {
    const rows = this.#db
      .prepare(
        `SELECT * FROM document_envelopes
          WHERE owner_agent_id = ? AND document_id = ? ORDER BY log_index ASC`,
      )
      .all(ownerAgentId, documentId) as Array<Record<string, unknown>>;
    return rows.map(toEnvelopeRow);
  }

  /**
   * Verify each sender's `doc_prev_hash` chain independently.
   *
   * The log interleaves both parties' envelopes, so there is no single total order to check —
   * §16.7-5 defines replay set-based per epoch for exactly this reason. What must hold is that
   * every sender's own links form one unbroken chain from a single genesis.
   *
   * A break REFUSES and names the sender and the missing predecessor. Skipping the leaf and
   * carrying on would leave a document that reads as complete while missing operations, which is
   * the silent-divergence failure the chain exists to prevent.
   */
  verifyChain(ownerAgentId: string, documentId: string): ChainVerdict {
    const log = this.getEnvelopeLog(ownerAgentId, documentId);
    const bySender = new Map<string, DocumentEnvelopeRow[]>();
    for (const e of log) {
      const list = bySender.get(e.senderAgentId);
      if (list) list.push(e);
      else bySender.set(e.senderAgentId, [e]);
    }

    for (const [sender, envelopes] of bySender) {
      const present = new Set(envelopes.map((e) => e.envelopeHash));
      const genesis = envelopes.filter((e) => e.docPrevHash === null);
      if (genesis.length > 1) {
        return {
          ok: false,
          reason: "document_chain_forked",
          detail:
            `sender ${sender.slice(0, 16)}… has ${genesis.length} genesis envelopes for document ` +
            `${documentId.slice(0, 16)}… — a chain has exactly one`,
        };
      }
      for (const e of envelopes) {
        if (e.docPrevHash !== null && !present.has(e.docPrevHash)) {
          return {
            ok: false,
            reason: "document_chain_broken",
            detail:
              `sender ${sender.slice(0, 16)}… envelope ${e.envelopeHash.slice(0, 16)}… links to ` +
              `${e.docPrevHash.slice(0, 16)}…, which is absent from the log`,
          };
        }
      }
    }
    return { ok: true };
  }

  // ─── the snapshot (disposable) ────────────────────────────────────────────

  getSnapshot(ownerAgentId: string, documentId: string): DocumentSnapshot | null {
    const r = this.#db
      .prepare("SELECT * FROM document_snapshots WHERE owner_agent_id = ? AND document_id = ?")
      .get(ownerAgentId, documentId) as Record<string, unknown> | undefined;
    if (!r) return null;
    return {
      binary: toU8(r["binary"]),
      stateVector: toU8(r["state_vector"]),
      lastAppliedIndex: r["last_applied_index"] as number,
    };
  }

  /** REPLACES — a snapshot is a cache of the log, not a second log. */
  putSnapshot(ownerAgentId: string, documentId: string, snapshot: DocumentSnapshot): void {
    this.#db
      .prepare(
        `INSERT OR REPLACE INTO document_snapshots
           (owner_agent_id, document_id, binary, state_vector, last_applied_index)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .run(
        ownerAgentId,
        documentId,
        Buffer.from(snapshot.binary),
        Buffer.from(snapshot.stateVector),
        snapshot.lastAppliedIndex,
      );
  }

  deleteSnapshot(ownerAgentId: string, documentId: string): void {
    this.#db
      .prepare("DELETE FROM document_snapshots WHERE owner_agent_id = ? AND document_id = ?")
      .run(ownerAgentId, documentId);
  }

  /**
   * Rebuild a snapshot from the envelope log alone, using the caller's replay function.
   *
   * Payload-stripped envelopes (purged, or withdrawal/rejection records that carry none)
   * contribute nothing to replay but STILL COUNT toward `lastAppliedIndex` — otherwise the next
   * incremental rebuild would start behind them and replay them forever.
   */
  rebuildSnapshot(ownerAgentId: string, documentId: string, replay: ReplayFn): DocumentSnapshot {
    const log = this.getEnvelopeLog(ownerAgentId, documentId);
    const payloads: Uint8Array[] = [];
    for (const e of log) {
      if (e.payload !== null) payloads.push(e.payload);
    }
    const { binary, stateVector } = replay(payloads);
    this.#logger.info("document.snapshot.rebuilt", {
      documentId,
      envelopes: log.length,
      replayed: payloads.length,
    });
    return { binary, stateVector, lastAppliedIndex: log.length - 1 };
  }

  // ─── internals ────────────────────────────────────────────────────────────

  #nextLogIndex(ownerAgentId: string, documentId: string): number {
    const r = this.#db
      .prepare(
        "SELECT MAX(log_index) AS max_index FROM document_envelopes WHERE owner_agent_id = ? AND document_id = ?",
      )
      .get(ownerAgentId, documentId) as { max_index: number | null } | undefined;
    const current = r?.max_index;
    return current === null || current === undefined ? 0 : current + 1;
  }
}

function toDocumentRow(r: Record<string, unknown>): DocumentRow {
  return {
    documentId: r["document_id"] as string,
    ownerAgentId: r["owner_agent_id"] as string,
    peerAgentId: r["peer_agent_id"] as string,
    documentType: r["document_type"] as string,
    properties: JSON.parse(r["properties"] as string) as DocumentProperties,
    status: r["status"] as DocumentStatus,
    createdAtMs: r["created_at"] as number,
  };
}

function toEnvelopeRow(r: Record<string, unknown>): DocumentEnvelopeRow {
  const payload = r["payload"];
  return {
    envelopeHash: r["envelope_hash"] as string,
    documentId: r["document_id"] as string,
    senderAgentId: r["sender_agent_id"] as string,
    docPrevHash: (r["doc_prev_hash"] as string | null) ?? null,
    epochId: r["epoch_id"] as number,
    signature: toU8(r["signature"]),
    stateVector: toU8(r["state_vector"]),
    payload: payload === null || payload === undefined ? null : toU8(payload),
    kind: r["kind"] as DocumentEnvelopeKind,
    referencesEnvelopeHash: (r["references_hash"] as string | null) ?? null,
    createdAtMs: r["created_at"] as number,
  };
}

/** Normalize a SQLite BLOB (Buffer / Uint8Array / ArrayBuffer) to a Uint8Array. */
function toU8(v: unknown): Uint8Array {
  if (v instanceof Uint8Array) return v;
  if (Buffer.isBuffer(v)) return new Uint8Array(v);
  if (v instanceof ArrayBuffer) return new Uint8Array(v);
  return new Uint8Array();
}
