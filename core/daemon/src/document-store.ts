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
import { addColumnIfMissing } from "./column-birth.js";
import { DOCUMENT_AMENDMENTS_CREATE_SQL, walkMembership } from "./document-amendment-store.js";

/** Lifecycle states a document can hold (§3.5). `stalled` is DOD-DOC-REJECT-1's terminal state. */
export type DocumentStatus = "active" | "closed" | "killed" | "stalled";

/**
 * What an envelope IS, as opposed to what it says. A withdrawal or a rejection is a NEW ROW that
 * references an earlier envelope — never an edit to it. The log is append-only, so the only way
 * to say "that one no longer counts" is to add a record saying so.
 */
export type DocumentEnvelopeKind = "update" | "withdrawal" | "rejection";

/**
 * RE-EXPORTED, not redefined.
 *
 * This was a second, structurally-similar interface declared here, and that is a drift risk with
 * teeth: `properties` is inside the proposal's SIGNED preimage and `seamViolation` reads it, so two
 * definitions of what a property is means two answers to what is admissible — one enforced at the
 * signature and one at the store. They agreed by coincidence, and the first field added to one of
 * them would have ended that quietly.
 */
export type { DocumentProperties } from "@cello-protocol/protocol-types";
import type { DocumentProperties } from "@cello-protocol/protocol-types";
import { decodeDocumentAmendment } from "@cello-protocol/protocol-types";

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
  /** The Yjs clientID this sender signed for — the gate's authorship binding. */
  senderClientId?: number | null;
  /** Position in this document's log. Assigned on append; absent until then. */
  logIndex?: number;
  /** DELIVERY bookkeeping, read back from the log. Absent on a row being appended. */
  deliveredAtMs?: number | null;
  ackedAtMs?: number | null;
  attempts?: number;
  nextAttemptAtMs?: number | null;
}

export interface QuarantineRow {
  documentId: string;
  /** The 0x05 leaf this row belongs to — the PK. One leaf, one row; see the table comment. */
  rejectionEnvelopeHash: string;
  rejectedEnvelopeHash: string;
  /** The refused envelope's own author and chain link, so the chain verifier can bridge it. */
  rejectedSenderAgentId: string;
  rejectedDocPrevHash: string | null;
  payload: Uint8Array;
  reason: string;
  detail?: string;
  /** Which pluggable rule refused, when one did — the gate produces this and it must not be lost. */
  rule?: string;
  limitName?: string;
  limitValue?: number;
  limitActual?: number;
  createdAtMs: number;
}

export interface DocumentSnapshot {
  binary: Uint8Array;
  stateVector: Uint8Array;
  /**
   * The `log_index` of the last envelope this snapshot reflects. §14 is explicit about why it is
   * stored rather than derived: with it, "where does the snapshot sit relative to the log" is a
   * lookup; without it, every rebuild works it out from scratch.
   *
   * **-1 means nothing has been applied.** The resume point is ALWAYS `lastAppliedIndex + 1`,
   * so an empty log yields 0 and `getEnvelopesSince(0)` reads the whole log — the sentinel and
   * the convention are chosen to agree.
   */
  lastAppliedIndex: number;
}

/** Thrown when a read path refuses to materialize over a chain that does not verify. */
export class DocumentChainError extends Error {
  readonly reason: "document_chain_broken" | "document_chain_forked";
  readonly detail: string;
  constructor(reason: "document_chain_broken" | "document_chain_forked", detail: string) {
    super(`${reason}: ${detail}`);
    this.name = "DocumentChainError";
    this.reason = reason;
    this.detail = detail;
  }
}

export type ChainVerdict =
  | { ok: true }
  | { ok: false; reason: "document_chain_broken" | "document_chain_forked"; detail: string };

/**
 * Injected by the engine: fold an ordered envelope list into a materialized state.
 *
 * Takes ROWS, not bare payloads. The engine has to distinguish an update from a withdrawal or a
 * rejection to fold correctly — a withdrawn envelope's payload must not be applied — and it
 * cannot do that from `Uint8Array[]`. The store supplies the WHOLE log in order — withdrawal and
 * rejection records included, payload-free though they are; deciding what counts is the engine's
 * call, not the store's.
 */
export type ReplayFn = (envelopes: DocumentEnvelopeRow[]) => {
  binary: Uint8Array;
  stateVector: Uint8Array;
};

const CREATE_DOCUMENTS_SQL = `
  CREATE TABLE IF NOT EXISTS documents (
    owner_agent_id  TEXT    NOT NULL,
    document_id     TEXT    NOT NULL,
    peer_agent_id   TEXT    NOT NULL,
    document_type   TEXT    NOT NULL,
    properties      TEXT    NOT NULL,
    status          TEXT    NOT NULL CHECK (status IN ('active', 'closed', 'killed', 'stalled')),
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
    kind            TEXT    NOT NULL CHECK (kind IN ('update', 'withdrawal', 'rejection')),
    -- The Yjs clientID the sender SIGNED for (ENVELOPE-1 puts it inside the TBS). Recorded so the
    -- gate's authorship rule has a binding derived from authenticated data rather than from a seam
    -- somebody has to remember to implement. §14 forbids persisting a clientID for REUSE — this is
    -- the opposite: a record of which ones a peer has actually signed for.
    sender_client_id INTEGER,
    references_hash TEXT,
    created_at      INTEGER NOT NULL,
    log_index       INTEGER NOT NULL,
    -- DELIVERY-1. Pending outbound is DERIVED from these columns rather than held in a queue:
    -- a queue in memory does not survive a restart, and a queue in its own table is a second
    -- source of truth that can disagree with the log about what was sent. "Unacknowledged
    -- envelopes I authored" is the whole definition, and it is a WHERE clause.
    -- TWO facts, and they are genuinely different: delivered_at is when the envelope LEFT (or was
    -- parked for an offline peer), acked_at is when the peer's daemon said it admitted or rejected
    -- it. An earlier version had delivered_at with no real writer — its only assignment was a
    -- COALESCE inside the ack, so it always equalled acked_at and the distinction was one the
    -- schema could not express. It has a writer now (markDelivered), so the distinction is real:
    -- "sent, awaiting confirmation" is exactly the state a store-and-forward transport leaves an
    -- envelope in, and an operator asking why something has not landed needs to tell it from
    -- "never sent".
    delivered_at    INTEGER,
    acked_at        INTEGER,
    -- A THIRD fact, and it is not either of the two above. abandoned_at is when WE STOPPED TRYING
    -- (the unacked ceiling) — a local decision, and NOT a claim about the peer.
    --
    -- It exists because the ceiling first stopped delivery by calling markAcked, and acked_at means
    -- "the peer's daemon said it admitted or rejected it". Overloading it made withdraw tell the
    -- operator "your peer holds it, so it cannot be withdrawn" about an envelope the peer may never
    -- have seen. Same class as any other false claim of confirmation, and a column is cheaper.
    abandoned_at    INTEGER,
    -- How many times delivery has been attempted, and when the next attempt is due. On the row,
    -- because a backoff that resets on restart is not a backoff — a daemon restarting in a
    -- reconnect loop would hammer an unreachable peer at full rate forever.
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER,
    PRIMARY KEY (owner_agent_id, document_id, envelope_hash),
    -- A duplicate index would make ORDER BY log_index non-deterministic, and this log's entire
    -- value is deterministic replay. Two daemons on one DB file (the orphan-process case this
    -- repo has been bitten by) would otherwise each compute the same next index and both insert.
    UNIQUE (owner_agent_id, document_id, log_index),
    -- An audit record carries no content, and replay SKIPS payload-free non-update rows on that
    -- basis. Enforce it here rather than relying on the convention: if a withdrawal ever carried
    -- a payload and were later purged, replay would skip it and rebuild SHORT — the exact
    -- divergence the purged-update refusal exists to prevent.
    CHECK (kind = 'update' OR payload IS NULL),
    -- Rows cannot exist for a document that was never created. The reference store makes the
    -- same call in writing: an unscoped row must be impossible to write, not merely discouraged
    -- by a query convention every future caller has to remember.
    FOREIGN KEY (owner_agent_id, document_id) REFERENCES documents (owner_agent_id, document_id)
  );
`;

/**
 * Quarantined updates (DOD-DOC-REJECT-1). A separate table, deliberately:
 *
 * `document_envelopes` cannot hold them — its CHECK forbids a payload on a non-update row — and
 * putting the refused bytes in as an `update` row would be worse, because `replay` applies every
 * payload in order and does not honour references. The refused content would come back on every
 * rebuild, which is the opposite of quarantine.
 *
 * So the log stays clean and replay is untouched, while the bytes a `0x05` leaf references
 * actually survive a restart — which is the whole point of "held, never discarded" (§3.2).
 */
const CREATE_QUARANTINE_SQL = `
  CREATE TABLE IF NOT EXISTS document_quarantine (
    owner_agent_id        TEXT    NOT NULL,
    document_id           TEXT    NOT NULL,
    rejected_envelope_hash TEXT   NOT NULL,
    -- The 0x05 leaf THIS row belongs to. It is the PK because one refused envelope can be refused
    -- MORE THAN ONCE, for different reasons, across retry rounds — the rejection protocol's normal
    -- path. Keyed on the REFUSED envelope instead, the second round's bytes, reason, rule and limit
    -- were dropped by ON CONFLICT DO NOTHING with no log line, and the stall message then told the
    -- operator "the most recent reason was" and printed the OLDEST. One 0x05 leaf, one row.
    rejection_envelope_hash TEXT  NOT NULL,
    -- The refused envelope's OWN chain link and author, so verifyChainLinkage can bridge across
    -- it. The refused payload is deliberately never written to the log (see the header), which
    -- would otherwise leave the peer's supersession chaining onto a hash that is nowhere.
    rejected_sender_agent_id TEXT NOT NULL,
    rejected_doc_prev_hash TEXT,
    payload               BLOB    NOT NULL,
    reason                TEXT    NOT NULL,
    detail                TEXT,
    rule                  TEXT,
    limit_name            TEXT,
    limit_value           INTEGER,
    limit_actual          INTEGER,
    created_at            INTEGER NOT NULL,
    PRIMARY KEY (owner_agent_id, document_id, rejection_envelope_hash),
    FOREIGN KEY (owner_agent_id, document_id) REFERENCES documents (owner_agent_id, document_id)
  );
`;

/**
 * Rejections we RECEIVED (§3.2 "both sides"). A separate table from `document_quarantine` because
 * the two hold different facts: quarantine holds bytes WE refused, this holds the peer's refusal of
 * bytes we authored — we hold no payload of theirs to quarantine.
 *
 * It is durable rather than a log line because everything an operator needs on the publishing side
 * depends on it surviving a restart: why their work was refused, and how many rounds remain before
 * the document stalls. Without a row, the sending side counted its OWN rejections — which on a pure
 * publisher is zero forever — so the retry bound existed only on the side that never loops.
 */
const CREATE_REJECTIONS_RECEIVED_SQL = `
  CREATE TABLE IF NOT EXISTS document_rejections_received (
    owner_agent_id         TEXT    NOT NULL,
    document_id            TEXT    NOT NULL,
    rejection_envelope_hash TEXT   NOT NULL,
    rejected_envelope_hash TEXT    NOT NULL,
    from_agent_id          TEXT    NOT NULL,
    reason                 TEXT    NOT NULL,
    detail                 TEXT,
    created_at             INTEGER NOT NULL,
    PRIMARY KEY (owner_agent_id, document_id, rejection_envelope_hash),
    FOREIGN KEY (owner_agent_id, document_id) REFERENCES documents (owner_agent_id, document_id)
  );
`;

/** Mirrors `DocumentLifecycle`'s definition exactly — see the note at the exec site. */
const CREATE_WITHDRAWALS_SQL = `
  CREATE TABLE IF NOT EXISTS document_withdrawals (
    owner_agent_id TEXT    NOT NULL,
    document_id    TEXT    NOT NULL,
    envelope_hash  TEXT    NOT NULL,
    created_at     INTEGER NOT NULL,
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
    PRIMARY KEY (owner_agent_id, document_id),
    FOREIGN KEY (owner_agent_id, document_id) REFERENCES documents (owner_agent_id, document_id)
  );
`;

export class DocumentStore {
  readonly #db: DaemonDatabase;
  readonly #logger: Logger;

  /**
   * The underlying handle, for modules that own their OWN tables alongside this one
   * (DocumentLifecycle). Deliberately not a licence to query this store's tables from outside —
   * every one of them has a method here, and a second query path is a second set of rules about
   * scoping that nobody remembers to keep in step.
   */
  get rawDb(): DaemonDatabase {
    return this.#db;
  }

  constructor(db: DaemonDatabase, logger: Logger) {
    this.#db = db;
    this.#logger = logger;
    this.#db.exec(CREATE_DOCUMENTS_SQL);
    // M14B / DOD-MP-AMEND-1 — the amendments table this store READS (currentDocumentEpoch);
    // DocumentAmendmentStore owns writes. Shared definition, whichever constructs first wins.
    this.#db.exec(DOCUMENT_AMENDMENTS_CREATE_SQL);
    // M14B / DOD-MP-FANOUT-1 — per-(envelope, holder) delivery state. The envelope row's
    // bilateral ack columns cannot carry N answers; this table can, and it is DERIVED
    // bookkeeping over the log — the envelope is the truth, a row here is one holder's
    // outstanding confirmation. Restart-survivable by construction.
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS document_deliveries (
        owner_agent_id  TEXT    NOT NULL,
        document_id     TEXT    NOT NULL,
        envelope_hash   TEXT    NOT NULL,
        holder_agent_id TEXT    NOT NULL,
        delivered_at    INTEGER,
        acked_at        INTEGER,
        abandoned_at    INTEGER,
        attempts        INTEGER NOT NULL DEFAULT 0,
        next_attempt_at INTEGER,
        created_at      INTEGER NOT NULL,
        PRIMARY KEY (owner_agent_id, document_id, envelope_hash, holder_agent_id)
      );
    `);
    this.#db.exec(CREATE_ENVELOPES_SQL);
    this.#db.exec(CREATE_QUARANTINE_SQL);
    this.#db.exec(CREATE_REJECTIONS_RECEIVED_SQL);
    // Owned by DocumentLifecycle, created HERE too because `pendingDeliveries` references it and a
    // store used without the lifecycle module is a legitimate configuration. Both statements are
    // CREATE TABLE IF NOT EXISTS over the same definition, so whichever runs first wins and the
    // other is a no-op — the alternative is a query that throws on a missing table and takes an
    // entire delivery pass down with it.
    this.#db.exec(CREATE_WITHDRAWALS_SQL);
    this.#db.exec(CREATE_SNAPSHOTS_SQL);
    // COLUMN BIRTH. A daemon that already holds an envelope log must gain the column without
    // losing the log. `ALTER TABLE ... ADD COLUMN` throws when it is already there, which is the
    // guard — the same pattern `document-handshake.ts` uses, rather than a version number nobody
    // maintains.
    addColumnIfMissing(this.#db, this.#logger, {
      table: "document_envelopes",
      column: "abandoned_at",
      sql: "ALTER TABLE document_envelopes ADD COLUMN abandoned_at INTEGER",
    });
    // Reading the log in arrival order is the only access pattern that matters.
    this.#db.exec(
      "CREATE INDEX IF NOT EXISTS idx_document_envelopes_order ON document_envelopes (owner_agent_id, document_id, log_index)",
    );
  }

  // ─── documents ────────────────────────────────────────────────────────────

  createDocument(row: DocumentRow): void {
    this.#db
      .prepare(
        // Scoped to the identity conflict only — a bare OR IGNORE would also swallow the status
        // CHECK, leaving the caller believing a document exists that was never stored, and the
        // failure would surface later as a foreign-key error on the first append.
        `INSERT INTO documents
           (owner_agent_id, document_id, peer_agent_id, document_type, properties, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (owner_agent_id, document_id) DO NOTHING`,
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

  /**
   * Does this daemon hold ANY document, under any owner?
   *
   * Deliberately unscoped, and that is the point: it is the only question that can tell a delivery
   * sweep visiting zero agents apart from a daemon that simply has no documents. Without it the two
   * look identical in the log, which is what let an owner-key mismatch hide.
   */
  anyDocumentExists(): boolean {
    return this.#db.prepare("SELECT 1 FROM documents LIMIT 1").get() !== undefined;
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
   * IMMUTABLE AT A HASH: the conflict clause is scoped to the envelope hash ALONE, so a
   * re-delivery — or a peer replaying the same hash with different bytes — cannot overwrite what
   * was recorded. Returns whether a new row was written, so the caller can tell a genuine append
   * from a duplicate rather than inferring it.
   *
   * Scoped deliberately, not written as a bare `OR IGNORE`: that form suppresses CHECK, UNIQUE
   * and NOT NULL as well, which on an append-only log means a malformed `kind` or a colliding
   * `log_index` would be DROPPED and reported to the caller as an already-seen duplicate. Every
   * constraint except the hash conflict must throw, or `false` means three different things the
   * caller cannot tell apart.
   */
  appendEnvelope(ownerAgentId: string, envelope: DocumentEnvelopeRow): boolean {
    // The log index is computed INSIDE the insert, not read first and passed in. A read-then-write
    // is safe within one process (this API is synchronous throughout), but two daemons on one DB
    // file — the orphan-process case this repo has hit before — would each read the same MAX and
    // each insert it. A duplicate index makes ORDER BY log_index non-deterministic, and
    // deterministic replay is this log's entire purpose. The UNIQUE constraint is the backstop.
    let info;
    try {
      info = this.#db
      .prepare(
        `INSERT INTO document_envelopes
           (owner_agent_id, document_id, envelope_hash, sender_agent_id, doc_prev_hash, epoch_id,
            signature, state_vector, payload, kind, references_hash, sender_client_id,
            created_at, log_index)
         SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                COALESCE((SELECT MAX(log_index) + 1 FROM document_envelopes
                           WHERE owner_agent_id = ? AND document_id = ?), 0)
         ON CONFLICT (owner_agent_id, document_id, envelope_hash) DO NOTHING`,
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
        envelope.senderClientId ?? null,
        envelope.createdAtMs,
        ownerAgentId,
        envelope.documentId,
      );
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      // SQLite says "FOREIGN KEY constraint failed" and nothing else — not which document, not
      // which owner, not that a `documents` row is missing. That is the message an operator meets
      // when an envelope arrives before its document exists, so it has to name its own cause.
      if (message.includes("FOREIGN KEY")) {
        throw new Error(
          `document_envelope_unscoped: no document ${envelope.documentId.slice(0, 16)}… exists for ` +
            `owner ${ownerAgentId.slice(0, 16)}… — create the document before appending to its log`,
        );
      }
      throw err;
    }
    return Number(info.changes) > 0;
  }

  /**
   * Envelopes at or after `fromIndex`, in log order. This is what makes `lastAppliedIndex` the
   * lookup §14 asks for: resume an incremental rebuild at `lastAppliedIndex + 1` without reading
   * the whole log.
   */
  getEnvelopesSince(ownerAgentId: string, documentId: string, fromIndex: number): DocumentEnvelopeRow[] {
    const rows = this.#db
      .prepare(
        `SELECT * FROM document_envelopes
          WHERE owner_agent_id = ? AND document_id = ? AND log_index >= ?
          ORDER BY log_index ASC`,
      )
      .all(ownerAgentId, documentId, fromIndex) as Array<Record<string, unknown>>;
    return rows.map(toEnvelopeRow);
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
   *
   * LINKAGE ONLY — the name says so deliberately. This verifies no signature and does not check
   * that `envelope_hash` hashes the content; neither is possible here (no key, no encoder). A
   * caller must not read `ok: true` as authenticity — that belongs to the engine.
   */
  verifyChainLinkage(ownerAgentId: string, documentId: string): ChainVerdict {
    const log = this.getEnvelopeLog(ownerAgentId, documentId);

    // BRIDGE THE REFUSED ENVELOPES. A refused update's payload is never written to the log — that
    // is what makes the refusal real across a restart — but the peer does not know it was refused
    // when it authors the next envelope, so its supersession chains onto a hash the log does not
    // contain. Without the bridge that reads as `document_chain_broken`, the document refuses to
    // rebuild, and the operator is sent to debug the chain layer for a rejection-protocol event.
    //
    // These stubs exist ONLY for verification. They carry no payload and are never returned by
    // `getEnvelopeLog`, so replay cannot see them and the refused content cannot come back.
    const stubs: DocumentEnvelopeRow[] = this.listQuarantined(ownerAgentId, documentId).map((q) => ({
      envelopeHash: q.rejectedEnvelopeHash,
      documentId: q.documentId,
      senderAgentId: q.rejectedSenderAgentId,
      docPrevHash: q.rejectedDocPrevHash,
      // EXEMPT from current-epoch stamping (M14B Entry 5): a stub is a SYNTHETIC verification
      // node — never on the wire, never replayed — and the chain walk checks hash linkage only.
      epochId: 0,
      signature: new Uint8Array(0),
      stateVector: new Uint8Array(0),
      payload: null,
      kind: "rejection",
      referencesEnvelopeHash: null,
      createdAtMs: q.createdAtMs,
    }));
    // One refused envelope can carry several quarantine rows (one per retry round), and the chain
    // has exactly one node for it.
    const seenStub = new Set<string>();
    const bySender = new Map<string, DocumentEnvelopeRow[]>();
    for (const stub of stubs) {
      if (seenStub.has(stub.envelopeHash)) continue;
      seenStub.add(stub.envelopeHash);
      const list = bySender.get(stub.senderAgentId);
      if (list) list.push(stub);
      else bySender.set(stub.senderAgentId, [stub]);
    }
    for (const e of log) {
      const list = bySender.get(e.senderAgentId);
      if (list) list.push(e);
      else bySender.set(e.senderAgentId, [e]);
    }

    for (const [sender, envelopes] of bySender) {
      const present = new Set(envelopes.map((e) => e.envelopeHash));
      const genesis = envelopes.filter((e) => e.docPrevHash === null);
      if (genesis.length !== 1) {
        return {
          ok: false,
          reason: "document_chain_forked",
          detail:
            `sender ${sender.slice(0, 16)}… has ${genesis.length} genesis envelopes for document ` +
            `${documentId.slice(0, 16)}… — a chain has exactly one`,
        };
      }
      // Every link must resolve. Checked first so a missing predecessor reports as BROKEN rather
      // than as the unreachability it would also cause.
      for (const e of envelopes) {
        if (e.docPrevHash !== null && !present.has(e.docPrevHash)) {
          return {
            ok: false,
            reason: "document_chain_broken",
            detail:
              `sender ${sender.slice(0, 16)}… envelope ${e.envelopeHash.slice(0, 16)}… links to ` +
              `${e.docPrevHash.slice(0, 16)}…, which is absent from the log and is not among this ` +
              `document's refused envelopes either — so this is a gap in the chain itself, not a ` +
              `rejection`,
          };
        }
      }

      // REACHABILITY, not structural heuristics. Walk forward from the one genesis and require
      // the walk to cover every envelope this sender authored. That single check subsumes the
      // duplicate-genesis case, the duplicate-predecessor fork, AND every cycle shape — including
      // a disjoint cycle sitting alongside a perfectly good genesis chain, which counting roots
      // and predecessors cannot see. `doc_prev_hash` is peer-controlled, so this is a hostile
      // input path and the verifier is the only thing between a crafted log and a persisted
      // snapshot.
      const childOf = new Map<string, DocumentEnvelopeRow[]>();
      for (const e of envelopes) {
        if (e.docPrevHash === null) continue;
        const siblings = childOf.get(e.docPrevHash);
        if (siblings) siblings.push(e);
        else childOf.set(e.docPrevHash, [e]);
      }
      const reached = new Set<string>();
      let cursor: DocumentEnvelopeRow | undefined = genesis[0]!;
      while (cursor) {
        if (reached.has(cursor.envelopeHash)) break; // defensive; a cycle cannot include genesis
        reached.add(cursor.envelopeHash);
        const children: DocumentEnvelopeRow[] = childOf.get(cursor.envelopeHash) ?? [];
        if (children.length > 1) {
          return {
            ok: false,
            reason: "document_chain_forked",
            detail:
              `sender ${sender.slice(0, 16)}… has ${children.length} envelopes claiming predecessor ` +
              `${cursor.envelopeHash.slice(0, 16)}… — a chain branches nowhere`,
          };
        }
        cursor = children[0];
      }
      if (reached.size !== envelopes.length) {
        return {
          ok: false,
          reason: "document_chain_forked",
          detail:
            `sender ${sender.slice(0, 16)}… has ${envelopes.length - reached.size} envelopes ` +
            `unreachable from its genesis for document ${documentId.slice(0, 16)}… — a detached ` +
            `cycle or branch, not a chain`,
        };
      }
    }
    return { ok: true };
  }

  // ─── quarantine (held, never discarded) ───────────────────────────────────

  /**
   * Hold a refused update's bytes. Idempotent per REJECTION (per 0x05 leaf), not per refused
   * envelope — one envelope may be refused across several retry rounds and each round's reason,
   * rule and limit are distinct facts an operator needs.
   *
   * Returns whether a row was written, so a caller never has to infer it. The previous signature
   * returned void and the conflict clause silently dropped every round after the first.
   */
  holdQuarantined(ownerAgentId: string, row: QuarantineRow): boolean {
    const info = this.#db
      .prepare(
        `INSERT INTO document_quarantine
           (owner_agent_id, document_id, rejection_envelope_hash, rejected_envelope_hash,
            rejected_sender_agent_id, rejected_doc_prev_hash, payload, reason, detail,
            rule, limit_name, limit_value, limit_actual, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (owner_agent_id, document_id, rejection_envelope_hash) DO NOTHING`,
      )
      .run(
        ownerAgentId,
        row.documentId,
        row.rejectionEnvelopeHash,
        row.rejectedEnvelopeHash,
        row.rejectedSenderAgentId,
        row.rejectedDocPrevHash,
        Buffer.from(row.payload),
        row.reason,
        row.detail ?? null,
        row.rule ?? null,
        row.limitName ?? null,
        row.limitValue ?? null,
        row.limitActual ?? null,
        row.createdAtMs,
      );
    return Number(info.changes) > 0;
  }

  listQuarantined(ownerAgentId: string, documentId: string): QuarantineRow[] {
    const rows = this.#db
      .prepare(
        // rowid breaks the tie. Several rounds can land inside one millisecond, and `created_at`
        // alone then leaves the order to SQLite — which is what an operator is shown as "the most
        // recent reason". Insertion order is the real answer and rowid is it.
        `SELECT * FROM document_quarantine
          WHERE owner_agent_id = ? AND document_id = ?
          ORDER BY created_at ASC, rowid ASC`,
      )
      .all(ownerAgentId, documentId) as Array<Record<string, unknown>>;
    return rows.map((r) => ({
      documentId: r["document_id"] as string,
      rejectionEnvelopeHash: r["rejection_envelope_hash"] as string,
      rejectedEnvelopeHash: r["rejected_envelope_hash"] as string,
      rejectedSenderAgentId: r["rejected_sender_agent_id"] as string,
      rejectedDocPrevHash: (r["rejected_doc_prev_hash"] as string | null) ?? null,
      payload: toU8(r["payload"]),
      reason: r["reason"] as string,
      detail: (r["detail"] as string | null) ?? undefined,
      rule: (r["rule"] as string | null) ?? undefined,
      limitName: (r["limit_name"] as string | null) ?? undefined,
      limitValue: (r["limit_value"] as number | null) ?? undefined,
      limitActual: (r["limit_actual"] as number | null) ?? undefined,
      createdAtMs: r["created_at"] as number,
    }));
  }

  /**
   * Release every entry for a refused envelope once its superseding update has been admitted.
   * Returns whether anything was released. Keyed by the REFUSED envelope rather than the rejection
   * leaf, because admitting the supersession resolves all of that envelope's rounds at once.
   */
  releaseQuarantined(ownerAgentId: string, documentId: string, rejectedEnvelopeHash: string): boolean {
    const info = this.#db
      .prepare(
        `DELETE FROM document_quarantine
          WHERE owner_agent_id = ? AND document_id = ? AND rejected_envelope_hash = ?`,
      )
      .run(ownerAgentId, documentId, rejectedEnvelopeHash);
    return Number(info.changes) > 0;
  }

  /**
   * Every envelope hash we hold from one sender. Hash-only on purpose: the caller needs a set for a
   * membership test, and `getEnvelopeLog` selects `*` — including every payload BLOB — so building
   * that set from it materialized the whole document's content on every inbound update.
   */
  knownEnvelopeHashesBySender(
    ownerAgentId: string,
    documentId: string,
    senderAgentId: string,
  ): Set<string> {
    const rows = this.#db
      .prepare(
        // THE QUARANTINE COUNTS AS KNOWN, and it has to.
        //
        // A refused envelope is deliberately never written to `document_envelopes` — that is the
        // point of refusing it. But the sender's chain does not rewind: their next envelope links
        // to the one we refused. Without the second half of this union that link resolves to
        // nothing and the supersession is rejected as `document_chain_broken` — so ONE gate refusal
        // permanently broke the document, and the supersede-then-converge protocol §3.2 describes
        // could never run at all. Measured live.
        //
        // The bridge was already designed for exactly this: the quarantine records the refused
        // envelope's own author and prev-hash so a later link can span it. It had only ever been
        // applied to `verifyChainLinkage`, the LOCAL replay check — never to inbound admission,
        // which is the path a peer's supersession actually arrives on.
        //
        // Scoped by the refused envelope's own sender, so one peer's quarantine can never make
        // another peer's broken chain resolve.
        `SELECT envelope_hash FROM document_envelopes
          WHERE owner_agent_id = ? AND document_id = ? AND sender_agent_id = ?
         UNION ALL
         SELECT rejected_envelope_hash AS envelope_hash FROM document_quarantine
          WHERE owner_agent_id = ? AND document_id = ? AND rejected_sender_agent_id = ?`,
      )
      .all(ownerAgentId, documentId, senderAgentId, ownerAgentId, documentId, senderAgentId) as Array<{
        envelope_hash: string;
      }>;
    return new Set(rows.map((r) => r.envelope_hash));
  }

  /** The clientIDs one sender has signed for on this document. Also hash-free — see above. */
  senderClientIdsFor(ownerAgentId: string, documentId: string, senderAgentId: string): number[] {
    const rows = this.#db
      .prepare(
        `SELECT DISTINCT sender_client_id FROM document_envelopes
          WHERE owner_agent_id = ? AND document_id = ? AND sender_agent_id = ?
            AND sender_client_id IS NOT NULL`,
      )
      .all(ownerAgentId, documentId, senderAgentId) as Array<{ sender_client_id: number }>;
    return rows.map((r) => r.sender_client_id);
  }

  /**
   * The state vector the PEER last told us they had — from their most recent envelope.
   *
   * This is what a publish diffs against (§3.2 step 3, §7): an update computed against what they
   * have already seen carries exactly the operations they lack. Diffing against OUR OWN snapshot
   * instead publishes what we have not yet snapshotted, which is a different question with an
   * answer that happens to look plausible.
   */
  peerStateVector(ownerAgentId: string, documentId: string, peerAgentId: string): Uint8Array | null {
    const r = this.#db
      .prepare(
        `SELECT state_vector FROM document_envelopes
          WHERE owner_agent_id = ? AND document_id = ? AND sender_agent_id = ? AND kind = 'update'
          ORDER BY log_index DESC LIMIT 1`,
      )
      .get(ownerAgentId, documentId, peerAgentId) as { state_vector?: unknown } | undefined;
    return r?.state_vector === undefined ? null : toU8(r.state_vector);
  }

  /**
   * The state vector OUR last published envelope carried — what we had when we last spoke.
   *
   * Distinct from `peerStateVector`, and the distinction is the point: that one answers "what does
   * the peer lack" (what to send), this one answers "has anything changed since I last published"
   * (whether to send at all). Conflating them meant a republish with no edits still produced a
   * non-empty update, because before the peer has ever published the diff is the whole document.
   */
  lastPublishedStateVector(
    ownerAgentId: string,
    documentId: string,
    senderAgentId: string,
  ): Uint8Array | null {
    const r = this.#db
      .prepare(
        `SELECT state_vector FROM document_envelopes
          WHERE owner_agent_id = ? AND document_id = ? AND sender_agent_id = ? AND kind = 'update'
          ORDER BY log_index DESC LIMIT 1`,
      )
      .get(ownerAgentId, documentId, senderAgentId) as { state_vector?: unknown } | undefined;
    return r?.state_vector === undefined ? null : toU8(r.state_vector);
  }

  /** The rejecting agent's most recent envelope for this document, for chain linkage. */
  /**
   * The head of a sender's chain AS WE SEE IT — including envelopes we REFUSED.
   *
   * A refused envelope is never written to `document_envelopes`, but the sender's chain does not
   * rewind: their supersession links to the envelope we just refused. Taking the head from the log
   * alone meant that link never matched, so the supersession was refused as `document_chain_broken`
   * — and so was everything after it, forever. Measured against two real daemons: the gate fired
   * ONCE and the next three envelopes never reached it, so the retry round stuck at 1 and the
   * document could never reach the stall the protocol defines.
   *
   * That is the bridge the quarantine was built for — it stores the refused envelope's own author
   * and prev-hash saying exactly this — and it had only ever been applied to `verifyChainLinkage`,
   * the local replay check. An earlier attempt added the quarantine to the KNOWN-hash set, which
   * was not enough and is worth recording: `known` answers "have I seen this before" (duplicate
   * detection), while the forward link is checked against the HEAD. Bridging the wrong one looks
   * right and changes nothing.
   *
   * `log_index` and the quarantine's `created_at` are different clocks, so they are not merged into
   * one ORDER BY. Whichever is newer by arrival is the head: a refusal always happens after the
   * envelope it refuses, so a quarantine row newer than the last admitted envelope IS the head.
   */
  lastEnvelopeHashBySender(ownerAgentId: string, documentId: string, senderAgentId: string): string | null {
    const admitted = this.#db
      .prepare(
        `SELECT envelope_hash, created_at FROM document_envelopes
          WHERE owner_agent_id = ? AND document_id = ? AND sender_agent_id = ?
          ORDER BY log_index DESC LIMIT 1`,
      )
      .get(ownerAgentId, documentId, senderAgentId) as
      | { envelope_hash?: string; created_at?: number }
      | undefined;
    const refused = this.#db
      .prepare(
        `SELECT rejected_envelope_hash AS envelope_hash, created_at FROM document_quarantine
          WHERE owner_agent_id = ? AND document_id = ? AND rejected_sender_agent_id = ?
          ORDER BY created_at DESC LIMIT 1`,
      )
      .get(ownerAgentId, documentId, senderAgentId) as
      | { envelope_hash?: string; created_at?: number }
      | undefined;

    if (!refused?.envelope_hash) return admitted?.envelope_hash ?? null;
    if (!admitted?.envelope_hash) return refused.envelope_hash;
    return (refused.created_at ?? 0) >= (admitted.created_at ?? 0)
      ? refused.envelope_hash
      : admitted.envelope_hash;
  }

  // ─── delivery (DELIVERY-1) ────────────────────────────────────────────────

  /**
   * Envelopes this agent authored that the peer has not acknowledged, and whose next attempt is
   * due. DERIVED — there is no queue. Survives a restart because the log does.
   *
   * Scoped to `senderAgentId = ownerAgentId`: an envelope we RECEIVED is not ours to deliver, and
   * without the scope a receiver would helpfully re-send the sender's own updates back at it.
   */
  /**
   * The document's CURRENT epoch: the head of its recorded amendment chain, 0 at genesis.
   * Trustworthy for stamping because every append site validates (deriveArrangement) before
   * recording — a row in document_amendments is post-validation by invariant (M14B Entry 5).
   */
  /**
   * DOD-MP-REMOVE-1 — was THIS OWNER written out of the arrangement? DERIVED from the recorded
   * chain, never stored: a status column would need a CHECK-constraint rebuild on every operator
   * DB, and a stored flag can drift from the chain that actually governs. Forward-only by
   * construction — nothing here touches content.
   */
  removedFromArrangement(
    ownerAgentId: string,
    documentId: string,
  ): { removed: boolean; epochId: number | null } {
    return this.memberRemoved(ownerAgentId, documentId, ownerAgentId);
  }

  /** The same walk for ANY agent — the delivery worker asks it about the TARGET (F1). */
  memberRemoved(
    ownerAgentId: string,
    documentId: string,
    agentId: string,
  ): { removed: boolean; epochId: number | null } {
    const rows = this.#db
      .prepare(
        `SELECT received_bytes FROM document_amendments
          WHERE owner_agent_id = ? AND document_id = ?
          ORDER BY epoch_id ASC`,
      )
      .all(ownerAgentId, documentId) as Array<{ received_bytes: Uint8Array }>;
    const verdict = walkMembership(
      rows.map((r) => decodeDocumentAmendment(new Uint8Array(r.received_bytes))),
      agentId,
    );
    return { removed: verdict.state === "removed", epochId: verdict.epochId };
  }

  currentDocumentEpoch(ownerAgentId: string, documentId: string): number {
    const r = this.#db
      .prepare(
        `SELECT MAX(epoch_id) AS max_epoch FROM document_amendments
          WHERE owner_agent_id = ? AND document_id = ?`,
      )
      .get(ownerAgentId, documentId) as { max_epoch?: number | null } | undefined;
    return r?.max_epoch ?? 0;
  }

  /** DOD-MP-FANOUT-1 — one pending row per CURRENT holder for a freshly published envelope. */
  seedDeliveries(
    ownerAgentId: string,
    documentId: string,
    envelopeHash: string,
    holderAgentIds: readonly string[],
    nowMs: number,
  ): void {
    const insert = this.#db.prepare(
      `INSERT INTO document_deliveries
         (owner_agent_id, document_id, envelope_hash, holder_agent_id, created_at)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT (owner_agent_id, document_id, envelope_hash, holder_agent_id) DO NOTHING`,
    );
    for (const holder of holderAgentIds) {
      insert.run(ownerAgentId, documentId, envelopeHash, holder, nowMs);
    }
  }

  /**
   * Everything due for delivery, PER HOLDER, joined to its envelope. The window is bounded PER
   * HOLDER (`ROW_NUMBER` over holder partitions) — one holder's backlog must never evict
   * another's rows from the pass, which is the no_peer starvation shape multiplied by N.
   */
  pendingHolderDeliveries(
    ownerAgentId: string,
    nowMs: number,
    opts: { perHolderLimit?: number } = {},
  ): Array<{ holderAgentId: string; documentId: string; attempts: number; envelope: DocumentEnvelopeRow }> {
    const limit = opts.perHolderLimit ?? 50;
    const rows = this.#db
      .prepare(
        // holder_attempts ALIASED: e.* carries the envelope row's LEGACY bilateral attempts
        // column, which would silently shadow the per-holder count in the result map.
        `SELECT d.holder_agent_id, d.attempts AS holder_attempts, d.document_id AS delivery_document_id, e.*
           FROM (
             SELECT *, ROW_NUMBER() OVER (
               PARTITION BY holder_agent_id
               ORDER BY created_at ASC, envelope_hash ASC
             ) AS rn
             FROM document_deliveries
             WHERE owner_agent_id = ?
               AND acked_at IS NULL AND abandoned_at IS NULL
               AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
           ) d
           JOIN document_envelopes e
             ON e.owner_agent_id = d.owner_agent_id
            AND e.document_id = d.document_id
            AND e.envelope_hash = d.envelope_hash
          WHERE d.rn <= ?
          ORDER BY d.holder_agent_id ASC, d.created_at ASC`,
      )
      .all(ownerAgentId, nowMs, limit) as Array<Record<string, unknown>>;
    return rows.map((r) => ({
      holderAgentId: r["holder_agent_id"] as string,
      documentId: r["delivery_document_id"] as string,
      attempts: (r["holder_attempts"] as number) ?? 0,
      envelope: toEnvelopeRow(r),
    }));
  }

  /** Record one holder's attempt; returns THEIR attempt count. */
  recordHolderAttempt(
    ownerAgentId: string,
    documentId: string,
    envelopeHash: string,
    holderAgentId: string,
    nextAttemptAtMs: number,
  ): number {
    this.#db
      .prepare(
        `UPDATE document_deliveries
            SET attempts = attempts + 1, next_attempt_at = ?
          WHERE owner_agent_id = ? AND document_id = ? AND envelope_hash = ? AND holder_agent_id = ?`,
      )
      .run(nextAttemptAtMs, ownerAgentId, documentId, envelopeHash, holderAgentId);
    const r = this.#db
      .prepare(
        `SELECT attempts FROM document_deliveries
          WHERE owner_agent_id = ? AND document_id = ? AND envelope_hash = ? AND holder_agent_id = ?`,
      )
      .get(ownerAgentId, documentId, envelopeHash, holderAgentId) as { attempts?: number } | undefined;
    return r?.attempts ?? 0;
  }

  /** Settle one holder's confirmation. True exactly when THIS call settled it. */
  ackHolderDelivery(
    ownerAgentId: string,
    documentId: string,
    envelopeHash: string,
    holderAgentId: string,
    nowMs: number,
  ): boolean {
    const r = this.#db
      .prepare(
        `UPDATE document_deliveries
            SET acked_at = ?, delivered_at = COALESCE(delivered_at, ?)
          WHERE owner_agent_id = ? AND document_id = ? AND envelope_hash = ? AND holder_agent_id = ?
            AND acked_at IS NULL`,
      )
      .run(nowMs, nowMs, ownerAgentId, documentId, envelopeHash, holderAgentId);
    return (r.changes ?? 0) > 0;
  }

  /** Retire EVERY outstanding row for one holder — our decision, announced by the caller. */
  abandonHolderDeliveries(
    ownerAgentId: string,
    documentId: string,
    holderAgentId: string,
    nowMs: number,
  ): number {
    const r = this.#db
      .prepare(
        `UPDATE document_deliveries
            SET abandoned_at = ?
          WHERE owner_agent_id = ? AND document_id = ? AND holder_agent_id = ?
            AND acked_at IS NULL AND abandoned_at IS NULL`,
      )
      .run(nowMs, ownerAgentId, documentId, holderAgentId);
    return Number(r.changes ?? 0);
  }

  /** Does this holder still owe any confirmation on this document? */
  holderHasPending(ownerAgentId: string, documentId: string, holderAgentId: string): boolean {
    const r = this.#db
      .prepare(
        `SELECT 1 FROM document_deliveries
          WHERE owner_agent_id = ? AND document_id = ? AND holder_agent_id = ?
            AND acked_at IS NULL AND abandoned_at IS NULL
          LIMIT 1`,
      )
      .get(ownerAgentId, documentId, holderAgentId);
    return r !== undefined;
  }

  pendingDeliveries(
    ownerAgentId: string,
    nowMs: number,
    /**
     * OUR OWN sender id on the wire — the author's pubkey hex (M14-D5).
     *
     * Kept as a separate parameter, and separately named, even though the daemon now scopes the
     * store by that same pubkey hex so the two coincide. They are different FACTS: the owner key
     * says whose local store this row is in, the sender id says who signed the envelope. An
     * earlier version of the daemon scoped by agent name, and the mismatch returned nothing
     * pending — every published update sitting in the log undelivered, with no error anywhere.
     * Collapsing them into one argument makes that class of bug unrepresentable in the call and
     * invisible in the query.
     */
    senderAgentId: string = ownerAgentId,
    limit = 100,
  ): DocumentEnvelopeRow[] {
    const rows = this.#db
      .prepare(
        `SELECT * FROM document_envelopes
          WHERE owner_agent_id = ? AND sender_agent_id = ? AND acked_at IS NULL
            -- ABANDONED rows are not pending. This is what actually stops the worker at the
            -- unacked ceiling: the selection reads no document STATUS, so setting the document
            -- stalled changed what the surface said and nothing about what the worker did, and one
            -- envelope went out 74 times against a cap of 5.
            AND abandoned_at IS NULL
            -- UPDATES only. A withdrawal record is local audit — the update it concerns was never
            -- delivered, so there is nothing for the peer to act on — and a rejection reaches the
            -- peer through the rejection protocol, not this worker. Without the scope the worker
            -- would ship both, and the withdrawal would arrive as a reference to an envelope the
            -- peer has never seen.
            AND kind = 'update'
            -- An ENDED document does not deliver. A killed or closed document that kept shipping
            -- would contradict the verb the operator just used, and the peer would receive updates
            -- on a collaboration they were told had stopped.
            AND EXISTS (
              SELECT 1 FROM documents d
               WHERE d.owner_agent_id = document_envelopes.owner_agent_id
                 AND d.document_id = document_envelopes.document_id
                 AND d.status NOT IN ('killed', 'closed')
            )
            AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
            -- A WITHDRAWN update is not pending. Derived from the withdrawal record rather than a
            -- flag on the row, so there is one fact in one place: without this the delivery worker
            -- ships the very update the operator just withdrew.
            --
            -- The table is created by DocumentLifecycle, which may not have run — a store used
            -- without it is a legitimate configuration — so the reference is guarded rather than
            -- assumed. A missing table would otherwise throw here and take the whole delivery pass
            -- down with it.
            AND NOT EXISTS (
              SELECT 1 FROM document_withdrawals w
               WHERE w.owner_agent_id = document_envelopes.owner_agent_id
                 AND w.document_id = document_envelopes.document_id
                 AND w.envelope_hash = document_envelopes.envelope_hash
            )
          -- log_index is PER DOCUMENT, so it alone is not a total order across documents and the
          -- bounded window could be filled by one document's backlog forever. The tiebreaks make
          -- the window deterministic; the no-peer branch scheduling its rows is what stops one
          -- document monopolising it.
          ORDER BY log_index ASC, document_id ASC, envelope_hash ASC LIMIT ?`,
      )
      .all(ownerAgentId, senderAgentId, nowMs, limit) as Array<Record<string, unknown>>;
    return rows.map(toEnvelopeRow);
  }

  /** Mark an attempt: bumps the counter and schedules the next one. Returns the new count. */
  recordDeliveryAttempt(
    ownerAgentId: string,
    documentId: string,
    envelopeHash: string,
    nextAttemptAtMs: number,
  ): number {
    this.#db
      .prepare(
        `UPDATE document_envelopes
            SET attempts = attempts + 1, next_attempt_at = ?
          WHERE owner_agent_id = ? AND document_id = ? AND envelope_hash = ?`,
      )
      .run(nextAttemptAtMs, ownerAgentId, documentId, envelopeHash);
    const r = this.#db
      .prepare(
        `SELECT attempts FROM document_envelopes
          WHERE owner_agent_id = ? AND document_id = ? AND envelope_hash = ?`,
      )
      .get(ownerAgentId, documentId, envelopeHash) as { attempts?: number } | undefined;
    return r?.attempts ?? 0;
  }

  /** Record that the envelope left. Not an ack — the peer has not answered yet. */
  markDelivered(
    ownerAgentId: string,
    documentId: string,
    envelopeHash: string,
    nowMs: number,
  ): boolean {
    const info = this.#db
      .prepare(
        `UPDATE document_envelopes SET delivered_at = COALESCE(delivered_at, ?)
          WHERE owner_agent_id = ? AND document_id = ? AND envelope_hash = ?`,
      )
      .run(nowMs, ownerAgentId, documentId, envelopeHash);
    return Number(info.changes) > 0;
  }

  /** Record that the peer acknowledged. Idempotent — a redelivered ack must not move the clock. */
  /**
   * How many of our envelopes for this document were ABANDONED — the unacked ceiling fired and they
   * will never be retried.
   *
   * Surfaced because an abandoned envelope leaves every pending counter, so a document that
   * permanently dropped an update is otherwise indistinguishable from one that delivered everything.
   */
  abandonedCount(ownerAgentId: string, documentId: string): number {
    const row = this.#db
      .prepare(
        `SELECT COUNT(*) AS n FROM document_envelopes
          WHERE owner_agent_id = ? AND document_id = ? AND sender_agent_id = ? AND abandoned_at IS NOT NULL`,
      )
      .get(ownerAgentId, documentId, ownerAgentId) as { n?: number } | undefined;
    return row?.n ?? 0;
  }

  /**
   * Is this envelope SETTLED — the peer answered it, admitted or rejected?
   *
   * Keyed by envelope hash ALONE, without the document, because the caller waiting on it is the
   * delivery transport, which holds a session open and knows the envelope it sent but has no reason
   * to carry the document id through the wait. The hash is a sha256 over the envelope's own
   * preimage, so it identifies one envelope across every document this owner holds.
   */
  isEnvelopeAcked(ownerAgentId: string, envelopeHash: string): boolean {
    return this.envelopeSettlement(ownerAgentId, envelopeHash) !== null;
  }

  /**
   * HOW an envelope was settled, or null if the peer has not answered it.
   *
   * `admitted` is derived from whether a rejection was RECEIVED for it, because `acked_at` records
   * only that the peer answered — a rejection is an ack for delivery purposes, so the two states
   * share that column deliberately (see `DocumentAckInbound`). Reading the answer, not just its
   * existence, is what lets the delivery worker report `delivered` and `rejected` truthfully rather
   * than counting every answered envelope as still in flight.
   */
  envelopeSettlement(ownerAgentId: string, envelopeHash: string): { admitted: boolean } | null {
    const row = this.#db
      .prepare(
        `SELECT document_id FROM document_envelopes
          WHERE owner_agent_id = ? AND envelope_hash = ? AND acked_at IS NOT NULL LIMIT 1`,
      )
      .get(ownerAgentId, envelopeHash) as { document_id?: string } | undefined;
    if (row?.document_id === undefined) return null;
    return { admitted: !this.rejectionReceivedFor(ownerAgentId, row.document_id, envelopeHash) };
  }

  /**
   * WE GAVE UP — the unacked ceiling. Deliberately not `markAcked`: this records a decision of
   * ours, and says nothing about whether the peer holds the envelope, because we do not know.
   */
  markAbandoned(
    ownerAgentId: string,
    documentId: string,
    envelopeHash: string,
    nowMs: number,
  ): boolean {
    const info = this.#db
      .prepare(
        `UPDATE document_envelopes SET abandoned_at = ?
          WHERE owner_agent_id = ? AND document_id = ? AND envelope_hash = ?
            AND acked_at IS NULL AND abandoned_at IS NULL`,
      )
      .run(nowMs, ownerAgentId, documentId, envelopeHash);
    return Number(info.changes) > 0;
  }

  markAcked(
    ownerAgentId: string,
    documentId: string,
    envelopeHash: string,
    nowMs: number,
  ): boolean {
    const info = this.#db
      .prepare(
        `UPDATE document_envelopes SET acked_at = ?, delivered_at = COALESCE(delivered_at, ?)
          WHERE owner_agent_id = ? AND document_id = ? AND envelope_hash = ? AND acked_at IS NULL`,
      )
      .run(nowMs, nowMs, ownerAgentId, documentId, envelopeHash);
    return Number(info.changes) > 0;
  }

  /** Record a rejection the PEER sent us. Returns whether a row was written (idempotent by leaf). */
  recordRejectionReceived(
    ownerAgentId: string,
    row: {
      documentId: string;
      rejectionEnvelopeHash: string;
      rejectedEnvelopeHash: string;
      fromAgentId: string;
      reason: string;
      detail?: string;
      createdAtMs: number;
    },
  ): boolean {
    const info = this.#db
      .prepare(
        `INSERT INTO document_rejections_received
           (owner_agent_id, document_id, rejection_envelope_hash, rejected_envelope_hash,
            from_agent_id, reason, detail, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (owner_agent_id, document_id, rejection_envelope_hash) DO NOTHING`,
      )
      .run(
        ownerAgentId,
        row.documentId,
        row.rejectionEnvelopeHash,
        row.rejectedEnvelopeHash,
        row.fromAgentId,
        row.reason,
        row.detail ?? null,
        row.createdAtMs,
      );
    return Number(info.changes) > 0;
  }

  /** How many rejections this document has RECEIVED — the publishing side's retry round. */
  /**
   * DOD-DOC-SCREEN-1 (§16.7-16) — SENDER ADOPTS THE RECEIVER'S RULE.
   *
   * The codepoints this peer has actually refused for this document, learned from their own signed
   * refusals rather than assumed. Rules compose toward STRICT: once they have said no to a
   * character, we stop emitting it, so the same refusal cannot be spent twice — and three refusals
   * stall the document, which makes every avoidable one expensive.
   *
   * Scoped to (owner, document), never global. A rule adopted for one document must not silently
   * narrow what an operator may write everywhere else — the peer refused it HERE, under the profile
   * agreed HERE, and another peer may accept it happily.
   *
   * Stored as the refusal's own machine-readable codepoints, which is why the refusal was made
   * machine-readable in the first place: prose cannot be adopted.
   */
  adoptedRefusedCodepoints(ownerAgentId: string, documentId: string): Set<string> {
    const rows = this.#db
      .prepare(
        `SELECT detail FROM document_rejections_received
          WHERE owner_agent_id = ? AND document_id = ? AND detail IS NOT NULL`,
      )
      .all(ownerAgentId, documentId) as Array<{ detail?: string }>;
    const out = new Set<string>();
    for (const r of rows) {
      if (typeof r.detail !== "string") continue;
      try {
        const parsed = JSON.parse(r.detail) as { codepoints?: unknown };
        // ONLY the structured form. A refusal whose detail is prose carries no rule to adopt, and
        // guessing one out of English is how a sender ends up refusing text nobody objected to.
        if (Array.isArray(parsed.codepoints)) {
          for (const c of parsed.codepoints) if (typeof c === "string") out.add(c);
        }
      } catch {
        /* prose detail — nothing to adopt, and that is not an error */
      }
    }
    return out;
  }

  /**
   * How many ROUNDS this document has been through — DISTINCT refused envelopes, not rows.
   *
   * ONE REFUSED ENVELOPE IS ONE ROUND, however many times the refusal is announced. A peer's refusal
   * arrives TWICE by design: once as the signed `document_rejection` frame, and once as the ack that
   * settles the delivery (`admitted: false`). Both are recorded — correctly, they are two real
   * events — but the table is keyed on the ANNOUNCEMENT's hash, so the two land as separate rows.
   *
   * Counting rows therefore advanced the round by two per refusal, and `MAX_REJECTED_ROUNDS` is 3 —
   * so a document stalled after TWO refusals instead of three, cutting the supersede-and-retry
   * budget the protocol grants an operator by a third. Measured: the stall enforcer's sender was
   * refused at attempt 2 with `document_stalled`.
   *
   * Counted rather than deduplicated on write, deliberately. Both announcements genuinely happened
   * and the audit record should say so; what was wrong is the arithmetic built on top of it. And a
   * UNIQUE index on the refused hash would fail to create on any database that already holds the
   * duplicate rows this fix is about.
   *
   * Same principle as `ackRecordHash` one layer down — that one collapsed repeated ACKS of one
   * envelope; this collapses the two KINDS of announcement of one refusal.
   */
  countRejectionsReceived(ownerAgentId: string, documentId: string): number {
    const r = this.#db
      .prepare(
        `SELECT COUNT(DISTINCT rejected_envelope_hash) AS n FROM document_rejections_received
          WHERE owner_agent_id = ? AND document_id = ?`,
      )
      .get(ownerAgentId, documentId) as { n?: number } | undefined;
    return r?.n ?? 0;
  }

  /**
   * Was a rejection received for THIS envelope? Envelope-scoped on purpose: the document-scoped
   * reader below answers a different question, and using it to decide whether one envelope was
   * refused makes a rejection of any OTHER envelope in the document look like a rejection of this
   * one.
   */
  rejectionReceivedFor(ownerAgentId: string, documentId: string, envelopeHash: string): boolean {
    const r = this.#db
      .prepare(
        `SELECT 1 AS present FROM document_rejections_received
          WHERE owner_agent_id = ? AND document_id = ? AND rejected_envelope_hash = ? LIMIT 1`,
      )
      .get(ownerAgentId, documentId, envelopeHash) as { present?: number } | undefined;
    return r?.present === 1;
  }

  /** The most recently received rejection, for the reason an operator is shown on a stall. */
  latestRejectionReceived(
    ownerAgentId: string,
    documentId: string,
  ): { reason: string; detail?: string; fromAgentId: string } | null {
    const r = this.#db
      .prepare(
        `SELECT reason, detail, from_agent_id FROM document_rejections_received
          WHERE owner_agent_id = ? AND document_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 1`,
      )
      .get(ownerAgentId, documentId) as Record<string, unknown> | undefined;
    if (!r) return null;
    return {
      reason: r["reason"] as string,
      detail: (r["detail"] as string | null) ?? undefined,
      fromAgentId: r["from_agent_id"] as string,
    };
  }

  /**
   * How many rejection records this document carries, PER REJECTING AGENT — the retry round.
   *
   * Scoped by author, because a mutual exchange puts both directions' 0x05 leaves in one document
   * log. Counting across senders conflated them, so two peers each rejecting once read as round 2
   * and the document stalled at half the intended rounds.
   */
  countRejections(ownerAgentId: string, documentId: string, rejectingAgentId: string): number {
    const r = this.#db
      .prepare(
        `SELECT COUNT(*) AS n FROM document_envelopes
          WHERE owner_agent_id = ? AND document_id = ? AND kind = 'rejection'
            AND sender_agent_id = ?`,
      )
      .get(ownerAgentId, documentId, rejectingAgentId) as { n?: number } | undefined;
    return r?.n ?? 0;
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
    // VERIFY BEFORE REPLAY. Rebuilding over an unverified chain is the exact silent divergence
    // the chain exists to prevent: a log with a missing predecessor folds into a state that is
    // quietly short of operations, and putSnapshot would then persist it as authoritative.
    // Refusing is loud; a short document is not.
    const verdict = this.verifyChainLinkage(ownerAgentId, documentId);
    if (!verdict.ok) {
      this.#logger.warn("document.chain.broken", {
        documentId,
        reason: verdict.reason,
        detail: verdict.detail,
      });
      throw new DocumentChainError(verdict.reason, verdict.detail);
    }

    const log = this.getEnvelopeLog(ownerAgentId, documentId);
    // The WHOLE log, in order — including withdrawal and rejection records, which carry no
    // payload. The engine needs those rows to tell an expected payload-free AUDIT record from a
    // PURGED update whose bytes are gone; filtering here would hide that distinction and make the
    // row-shaped signature pointless. The store decides ORDER; the engine decides WHAT COUNTS.
    const { binary, stateVector } = replay(log);
    this.#logger.info("document.snapshot.rebuilt", {
      documentId,
      envelopes: log.length,
      withPayload: log.filter((e) => e.payload !== null).length,
    });
    // The LAST ROW'S log_index, not the array length. They coincide only while indices are dense,
    // which is an accident of how they are assigned rather than a guarantee.
    return { binary, stateVector, lastAppliedIndex: log.at(-1)?.logIndex ?? -1 };
  }

  // ─── internals ────────────────────────────────────────────────────────────

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
    senderClientId: (r["sender_client_id"] as number | null) ?? null,
    referencesEnvelopeHash: (r["references_hash"] as string | null) ?? null,
    createdAtMs: r["created_at"] as number,
    logIndex: r["log_index"] as number,
    deliveredAtMs: (r["delivered_at"] as number | null) ?? null,
    ackedAtMs: (r["acked_at"] as number | null) ?? null,
    attempts: (r["attempts"] as number | null) ?? 0,
    nextAttemptAtMs: (r["next_attempt_at"] as number | null) ?? null,
  };
}

/**
 * Normalize a SQLite BLOB (Buffer / Uint8Array / ArrayBuffer) to a Uint8Array.
 *
 * REFUSES anything else rather than substituting an empty array. This is the read path for
 * `signature`, `state_vector` and `payload`: returning `new Uint8Array()` for an unexpected type
 * would hand back a ZERO-LENGTH SIGNATURE as if it were the stored one, and the failure would
 * surface downstream as "signature invalid" — sending an operator to the crypto layer for what
 * is a storage-read defect. Nothing legitimate reaches this branch; `null` is handled by callers.
 */
function toU8(v: unknown): Uint8Array {
  if (v instanceof Uint8Array) return v;
  if (Buffer.isBuffer(v)) return new Uint8Array(v);
  if (v instanceof ArrayBuffer) return new Uint8Array(v);
  throw new Error(
    `document_store_blob_decode_failed: expected a BLOB, got ${v === null ? "null" : typeof v}`,
  );
}
