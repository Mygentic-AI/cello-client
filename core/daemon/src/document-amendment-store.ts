/**
 * SYNC-P1 (daemon half) — the fork-tolerant entry store.
 *
 * One row per ENTRY (keyed by entry hash — never by an epoch slot), holding the entry AS
 * RECEIVED — the wire bytes, never a re-encode. The bytes are the truth: `chain` decodes them on
 * read, so what the fold consumes is exactly what was signed, and a codec asymmetry can never
 * silently rewrite an agreed record (the class of defect TRACE-1 found in the proposal codec).
 *
 * The store owns persistence and ANCESTRY CLOSURE:
 * - **Held until whole (R14)** — an entry lands in `document_entries` only when every parent has
 *   landed. Otherwise it waits in `document_entries_pending`: recorded, never applied, never in a
 *   watermark, promoted the moment its ancestry completes — cascade included. The invariant this
 *   buys: everything in `document_entries` has its FULL ancestry there too.
 * - **Fork tolerance** — two entries claiming the same epoch or the same author seq are BOTH
 *   stored. Ruling on conflicts is the causal fold's job (`deriveDocumentState`), not the
 *   store's; the old chain-gap and epoch-conflict refusals are gone WITH the epoch spine.
 * - **Idempotent redelivery** — the same bytes again is `recorded: false`, not an error and not
 *   a second row.
 * - **Watermarks** — per author, the highest CONTIGUOUS seq with its head hash(es). Two heads at
 *   one seq is an equivocation made visible for the exchange to resolve, never silently picked.
 *
 * What the store does NOT judge: signatures, policy, subject semantics. The fold rules on those
 * at every consumption, and the inbound path rules BEFORE appending. A row in these tables is a
 * claim to be folded, not an admitted fact.
 */

import {
  decodeDocumentAmendment,
  documentAmendmentHash,
  type DocumentAmendmentEnvelope,
} from "@cello-protocol/protocol-types";
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";

/**
 * The PRE-PIVOT table, epoch-keyed. Still created because `DocumentStore` execs this too and the
 * pre-pivot readers live until P4 deletes them (SYNC-D2); the entry store neither reads nor
 * writes it. Rows predating the pivot stay untouched — old-shape bytes are not decodable by the
 * v2 codec and are not migrated (no compatibility owed; essentially no documents exist).
 */
export const DOCUMENT_AMENDMENTS_CREATE_SQL = `
  CREATE TABLE IF NOT EXISTS document_amendments (
    owner_agent_id  TEXT    NOT NULL,
    document_id     TEXT    NOT NULL,
    epoch_id        INTEGER NOT NULL,
    amendment_hash  TEXT    NOT NULL,
    received_bytes  BLOB    NOT NULL,
    recorded_at     INTEGER NOT NULL,
    PRIMARY KEY (owner_agent_id, document_id, epoch_id)
  );
`;

/**
 * Shared with `DocumentStore` (the :352 shared-definition precedent): its membership walk and
 * epoch read consume `document_entries`, so the tables must exist whichever module constructs
 * first. Keep both consumers on THIS string.
 */
/**
 * D7 — the epoch spine is deleted. A database born before that carries a NOT NULL `epoch_id`
 * with no default, which would refuse every insert from this build. Dropped in place (SQLite
 * ≥3.35 / SQLCipher 4.5); a fresh database never has it.
 */
export function dropLegacyEpochColumn(db: { exec(sql: string): void; prepare(sql: string): { all(...a: unknown[]): unknown[] } }, table: string): void {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name?: string }>;
  if (cols.some((c) => c.name === "epoch_id")) {
    db.exec(`ALTER TABLE ${table} DROP COLUMN epoch_id`);
  }
}

export const DOCUMENT_ENTRIES_CREATE_SQL = `
  CREATE TABLE IF NOT EXISTS document_entries (
    owner_agent_id  TEXT    NOT NULL,
    document_id     TEXT    NOT NULL,
    entry_hash      TEXT    NOT NULL,
    author_agent_id TEXT    NOT NULL,
    author_seq      INTEGER NOT NULL,
    received_bytes  BLOB    NOT NULL,
    recorded_at     INTEGER NOT NULL,
    PRIMARY KEY (owner_agent_id, document_id, entry_hash)
  );
  CREATE INDEX IF NOT EXISTS idx_document_entries_author
    ON document_entries (owner_agent_id, document_id, author_agent_id, author_seq);
  CREATE TABLE IF NOT EXISTS document_entries_pending (
    owner_agent_id  TEXT    NOT NULL,
    document_id     TEXT    NOT NULL,
    entry_hash      TEXT    NOT NULL,
    author_agent_id TEXT    NOT NULL,
    received_bytes  BLOB    NOT NULL,
    recorded_at     INTEGER NOT NULL,
    PRIMARY KEY (owner_agent_id, document_id, entry_hash)
  );
`;

export interface AmendmentAppendResult {
  /** False on an idempotent redelivery — the entry (or its pending row) already existed. */
  recorded: boolean;
  /** True when the entry is waiting on missing parents (R14) — recorded but not yet applied. */
  held: boolean;
  /** Hex of the entry's TBS hash. */
  entryHash: string;
  /** Previously-held entries this arrival completed, now applied — envelopes included, so the
   *  caller can run the same post-apply surfacing it runs for a direct arrival (review F2: the
   *  held path silently dropped removal notices and lifecycle completion). */
  promoted: PromotedEntry[];
}

export interface PromotedEntry {
  entryHash: string;
  envelope: DocumentAmendmentEnvelope;
}

export interface PendingEntry {
  entryHash: string;
  /** The parents not yet held — the exchange asks for exactly these. */
  missingParents: string[];
  recordedAtMs: number;
}

/**
 * Ceiling on HELD entries per (document, author). An honest author's pending set is a short gap
 * awaiting one delivery; a hostile known author fabricating parents could otherwise grow the
 * pending table without bound (review F4).
 */
export const MAX_PENDING_PER_AUTHOR = 64;

export interface AuthorWatermark {
  /** Highest CONTIGUOUS seq held from this author. */
  seq: number;
  /** Entry hash(es) at that seq — more than one is an equivocation, visible by design. */
  headHashes: string[];
}

export class DocumentAmendmentStore {
  readonly #db: DaemonDatabase;
  readonly #logger: Logger;

  constructor(db: DaemonDatabase, logger: Logger) {
    this.#db = db;
    this.#logger = logger;
    this.#db.exec(DOCUMENT_AMENDMENTS_CREATE_SQL);
    this.#db.exec(DOCUMENT_ENTRIES_CREATE_SQL);
    dropLegacyEpochColumn(this.#db, "document_entries");
  }

  /**
   * Append one entry from its wire bytes. Decodes first — malformed bytes refuse with the
   * decoder's named reason and nothing is stored. An entry with missing parents is HELD; an
   * arrival that completes held ancestry promotes the whole cascade.
   */
  append(
    ownerAgentId: string,
    documentId: string,
    receivedBytes: Uint8Array,
    nowMs: number,
  ): AmendmentAppendResult {
    const env = decodeDocumentAmendment(receivedBytes);
    if (env.body.document_id !== documentId) {
      throw new Error(
        `document_amendment_wrong_document: the bytes name ${env.body.document_id}, appending ` +
          `under ${documentId}`,
      );
    }
    const hash = Buffer.from(documentAmendmentHash(env.body)).toString("hex");

    if (this.#hasEntry(ownerAgentId, documentId, hash)) {
      return { recorded: false, held: false, entryHash: hash, promoted: [] };
    }
    if (this.#hasPending(ownerAgentId, documentId, hash)) {
      return { recorded: false, held: true, entryHash: hash, promoted: [] };
    }

    const missing = env.body.parents.filter(
      (p) => !this.#hasEntry(ownerAgentId, documentId, p),
    );
    if (missing.length > 0) {
      const author = env.body.author_agent_id;
      const backlog = this.#db
        .prepare(
          `SELECT COUNT(*) AS n FROM document_entries_pending
            WHERE owner_agent_id = ? AND document_id = ? AND author_agent_id = ?`,
        )
        .get(ownerAgentId, documentId, author) as { n: number };
      if (backlog.n >= MAX_PENDING_PER_AUTHOR) {
        throw new Error(
          `document_pending_cap: ${author} already has ${backlog.n} entries held awaiting ` +
            `parents — the ceiling is ${MAX_PENDING_PER_AUTHOR}, and an honest gap is never ` +
            `this deep; deliver the missing ancestry first`,
        );
      }
      this.#db
        .prepare(
          `INSERT INTO document_entries_pending
             (owner_agent_id, document_id, entry_hash, author_agent_id, received_bytes, recorded_at)
           VALUES (?, ?, ?, ?, ?, ?)`,
        )
        .run(ownerAgentId, documentId, hash, author, Buffer.from(receivedBytes), nowMs);
      this.#logger.info("document.entry.held", {
        documentId,
        entryHash: hash,
        author: env.body.author_agent_id,
        authorSeq: env.body.author_seq,
        kind: env.body.kind,
        missingParents: missing,
      });
      return { recorded: true, held: true, entryHash: hash, promoted: [] };
    }

    this.#insertEntry(ownerAgentId, documentId, hash, env, receivedBytes, nowMs);
    const promoted = this.#promoteReady(ownerAgentId, documentId, nowMs);
    return { recorded: true, held: false, entryHash: hash, promoted };
  }

  /** Every applied entry, decoded from the stored received bytes. The set is ancestry-closed. */
  chain(ownerAgentId: string, documentId: string): DocumentAmendmentEnvelope[] {
    const rows = this.#db
      .prepare(
        `SELECT received_bytes FROM document_entries
          WHERE owner_agent_id = ? AND document_id = ?
          ORDER BY author_seq ASC, entry_hash ASC`,
      )
      .all(ownerAgentId, documentId) as Array<{ received_bytes: Uint8Array }>;
    return rows.map((r) => decodeDocumentAmendment(new Uint8Array(r.received_bytes)));
  }

  /** Held entries and exactly which parents they still wait on (R37's receiver-side record). */
  pending(ownerAgentId: string, documentId: string): PendingEntry[] {
    const rows = this.#db
      .prepare(
        `SELECT entry_hash, received_bytes, recorded_at FROM document_entries_pending
          WHERE owner_agent_id = ? AND document_id = ?
          ORDER BY recorded_at ASC, entry_hash ASC`,
      )
      .all(ownerAgentId, documentId) as Array<{
      entry_hash: string;
      received_bytes: Uint8Array;
      recorded_at: number;
    }>;
    return rows.map((r) => {
      const env = decodeDocumentAmendment(new Uint8Array(r.received_bytes));
      return {
        entryHash: r.entry_hash,
        missingParents: env.body.parents.filter(
          (p) => !this.#hasEntry(ownerAgentId, documentId, p),
        ),
        recordedAtMs: r.recorded_at,
      };
    });
  }

  /**
   * This author's applied entries with seq strictly beyond `afterSeq`, as WIRE BYTES in seq
   * order — what a reconcile reply carries to a peer whose watermark for this author is behind
   * ours (R10 step 2/3). Forked seqs both ship: the peer's fold rules on them like ours did.
   */
  entriesByAuthorAfter(
    ownerAgentId: string,
    documentId: string,
    authorAgentId: string,
    afterSeq: number,
  ): Uint8Array[] {
    const rows = this.#db
      .prepare(
        `SELECT received_bytes FROM document_entries
          WHERE owner_agent_id = ? AND document_id = ? AND author_agent_id = ? AND author_seq > ?
          ORDER BY author_seq ASC, entry_hash ASC`,
      )
      .all(ownerAgentId, documentId, authorAgentId, afterSeq) as Array<{
      received_bytes: Uint8Array;
    }>;
    return rows.map((r) => new Uint8Array(r.received_bytes));
  }

  /**
   * Per-author position: the highest CONTIGUOUS seq held and the head hash(es) at it. A held
   * (pending) entry is not counted — a gap ends the walk (R13: report contiguous, never highest
   * received).
   */
  watermarks(ownerAgentId: string, documentId: string): Map<string, AuthorWatermark> {
    const rows = this.#db
      .prepare(
        `SELECT author_agent_id, author_seq, entry_hash FROM document_entries
          WHERE owner_agent_id = ? AND document_id = ?
          ORDER BY author_agent_id ASC, author_seq ASC, entry_hash ASC`,
      )
      .all(ownerAgentId, documentId) as Array<{
      author_agent_id: string;
      author_seq: number;
      entry_hash: string;
    }>;
    const byAuthor = new Map<string, Map<number, string[]>>();
    for (const r of rows) {
      let seqs = byAuthor.get(r.author_agent_id);
      if (!seqs) {
        seqs = new Map();
        byAuthor.set(r.author_agent_id, seqs);
      }
      const at = seqs.get(r.author_seq);
      if (at) at.push(r.entry_hash);
      else seqs.set(r.author_seq, [r.entry_hash]);
    }
    const out = new Map<string, AuthorWatermark>();
    for (const [author, seqs] of byAuthor) {
      let seq = 0;
      while (seqs.has(seq + 1)) seq++;
      if (seq === 0) continue;
      out.set(author, { seq, headHashes: seqs.get(seq)! });
    }
    return out;
  }

  #hasEntry(ownerAgentId: string, documentId: string, hash: string): boolean {
    return (
      this.#db
        .prepare(
          `SELECT 1 FROM document_entries
            WHERE owner_agent_id = ? AND document_id = ? AND entry_hash = ?`,
        )
        .get(ownerAgentId, documentId, hash) !== undefined
    );
  }

  #hasPending(ownerAgentId: string, documentId: string, hash: string): boolean {
    return (
      this.#db
        .prepare(
          `SELECT 1 FROM document_entries_pending
            WHERE owner_agent_id = ? AND document_id = ? AND entry_hash = ?`,
        )
        .get(ownerAgentId, documentId, hash) !== undefined
    );
  }

  #insertEntry(
    ownerAgentId: string,
    documentId: string,
    hash: string,
    env: DocumentAmendmentEnvelope,
    bytes: Uint8Array,
    nowMs: number,
  ): void {
    this.#db
      .prepare(
        `INSERT INTO document_entries
           (owner_agent_id, document_id, entry_hash, author_agent_id, author_seq,
            received_bytes, recorded_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        ownerAgentId,
        documentId,
        hash,
        env.body.author_agent_id,
        env.body.author_seq,
        // Copied — the caller may reuse or zero its buffer after we return.
        Buffer.from(bytes),
        nowMs,
      );
    this.#logger.info("document.entry.recorded", {
      documentId,
      entryHash: hash,
      author: env.body.author_agent_id,
      authorSeq: env.body.author_seq,
      kind: env.body.kind,
    });
  }

  /** Move every pending entry whose ancestry is now complete — repeated until a pass moves none. */
  #promoteReady(ownerAgentId: string, documentId: string, nowMs: number): PromotedEntry[] {
    const promoted: PromotedEntry[] = [];
    for (;;) {
      const rows = this.#db
        .prepare(
          `SELECT entry_hash, received_bytes FROM document_entries_pending
            WHERE owner_agent_id = ? AND document_id = ?`,
        )
        .all(ownerAgentId, documentId) as Array<{
        entry_hash: string;
        received_bytes: Uint8Array;
      }>;
      let movedThisPass = false;
      for (const row of rows) {
        const env = decodeDocumentAmendment(new Uint8Array(row.received_bytes));
        const ready = env.body.parents.every((p) =>
          this.#hasEntry(ownerAgentId, documentId, p),
        );
        if (!ready) continue;
        this.#insertEntry(
          ownerAgentId,
          documentId,
          row.entry_hash,
          env,
          new Uint8Array(row.received_bytes),
          nowMs,
        );
        this.#db
          .prepare(
            `DELETE FROM document_entries_pending
              WHERE owner_agent_id = ? AND document_id = ? AND entry_hash = ?`,
          )
          .run(ownerAgentId, documentId, row.entry_hash);
        this.#logger.info("document.entry.promoted", {
          documentId,
          entryHash: row.entry_hash,
        });
        promoted.push({ entryHash: row.entry_hash, envelope: env });
        movedThisPass = true;
      }
      if (!movedThisPass) return promoted;
    }
  }
}
