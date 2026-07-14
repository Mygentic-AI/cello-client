/**
 * M10 / DOD-STORE-CLIENT-1 — the daemon's two trust-signal tables.
 *
 * TWO tables, never one with a role flag (M10-D4). They answer different questions and obey
 * different scoping rules, and a single table with a `role` column is how one set of rules ends up
 * applied to the other's rows.
 *
 *   `wallet_trust_signals`  — signals ABOUT this daemon's agents, held so they can be PRESENTED.
 *   `contact_trust_signals` — signals OTHER agents PRESENTED TO one of my agents.
 *
 * THE WALLET CARRIES NO AGENT ASSOCIATION (M10-D14). PK = `signal_hash`; one row per signal per
 * daemon, and nothing more. It is the envelope's own HASHED `subject_kind`/`subject` that decides
 * who may present it, evaluated at presentation time — not a local attribution decided at delivery
 * time. That is the whole point: an account-subject signal (phone, email) serves every agent under
 * the account, so **adding an agent to an existing daemon is ZERO signal work** — no assignment
 * sweep, no re-attribution at renewal, no copies to keep in step at expiry. A per-agent column
 * would quietly reintroduce every one of those chores.
 *
 * THE RECEIVED STORE IS PER-AGENT, AND THE DATABASE ENFORCES IT (INV-AGENT-SCOPED). Consent is
 * genuinely per-agent here: a signal Bob showed to my agent `alice` must be invisible to my agent
 * `bob` on the same daemon. `agent_id` is NOT NULL and the row hangs off a contact row by composite
 * FK, so an unscoped row cannot be written at all — as opposed to being merely discouraged by a
 * query convention that every future caller must remember. (This requires `PRAGMA foreign_keys = ON`,
 * set at open in sqlcipher-db.ts — M10-D19. Without it the FK is decorative.) This is where the M8
 * scaffold's `agent_id = null` defect dies.
 *
 * EVIDENCE, NOT AN INPUT (M10-D4 / INV-STATELESS-RECIPIENT). Received rows are re-checkable evidence
 * of what was presented and when we verified it. They are NEVER an input to policy evaluation, which
 * consumes only the currently-presented set, and they are never trusted for freshness (that is
 * re-checked on use). This module therefore exposes no "is this contact trusted?" read — the absence
 * is deliberate and structural. Do not add one.
 *
 * OPAQUE THROUGHOUT (INV-ZERO-BUMP / INV-TYPE-CARRY). `type` is a TEXT column with no CHECK, no
 * enum, and no index predicated on a type value; `payload` is a BLOB that is never parsed and whose
 * fields are never hoisted into columns. A type string this code has never seen stores, reads, and
 * presents exactly like a known one. Adding a signal type must require no change to this file.
 */

import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";

/** Status lives OUTSIDE the hash — it is mutable after minting, which is exactly why it is not in
 *  the preimage. If it were hashed, revoking a signal would change its hash and the directory could
 *  never find it again. */
export type SignalStatus = "active" | "revoked" | "superseded";

/** The envelope, as this store takes and returns it. Mirrors `TrustSignalEnvelope` in
 *  protocol-types, plus the two non-hashed local columns. */
export interface WalletSignalInput {
  signalHash: string;
  subjectKind: "account" | "agent";
  subject: string;
  issuerKind: "portal" | "agent";
  issuerPubkey: string;
  /** OPAQUE. Never gated on, never enumerated. */
  type: string;
  schemaVersion: number;
  /** OPAQUE bytes. Never parsed. */
  payload: Uint8Array;
  issuedAt: number;
  expiresAt: number | null;
  supersedesHash: string | null;
  status: SignalStatus | string;
}

export interface WalletSignalRow extends WalletSignalInput {
  receivedAt: number;
}

export interface ReceivedSignalInput extends WalletSignalInput {
  agentId: string;
  contactPubkey: string;
  verifiedAt: number;
}

export interface ReceivedSignalRow extends ReceivedSignalInput {
  receivedAt: number;
}

/**
 * ⚠️ TWO TIME UNITS LIVE IN THESE TABLES, AND MIXING THEM SILENTLY PRESENTS EXPIRED SIGNALS.
 *
 *   issued_at / expires_at  — epoch **SECONDS**. These are ENVELOPE fields: they are HASHED, so the
 *                             protocol fixed the unit and we do not get to choose it.
 *   received_at / verified_at — epoch **MILLISECONDS** (`Date.now()`). Local bookkeeping only, never
 *                             hashed, and matching the house convention of every other daemon table
 *                             (`contacts.added_at`, `sessions.updated_at`).
 *
 * A factor-of-1000 error between them does not throw. Compared against a 1970 timestamp, every
 * expiry is still in the future — so the failure mode is an expired signal being cheerfully
 * presented. Anything that compares against `expires_at` must be in SECONDS; see `listPresentable`.
 */
const ENVELOPE_COLUMNS = `
    signal_hash     TEXT NOT NULL,
    subject_kind    TEXT NOT NULL,
    subject         TEXT NOT NULL,
    issuer_kind     TEXT NOT NULL,
    issuer_pubkey   TEXT NOT NULL,
    type            TEXT NOT NULL,
    schema_version  INTEGER NOT NULL,
    payload         BLOB NOT NULL,
    issued_at       INTEGER NOT NULL,
    expires_at      INTEGER,
    supersedes_hash TEXT,
    status          TEXT NOT NULL`;

/** Content-addressed: the row IS its hash (spec §14.11 — this is what makes wallet rows portable
 *  between a user's daemons, and duplicate delivery a no-op). */
const CREATE_WALLET_SQL = `
  CREATE TABLE IF NOT EXISTS wallet_trust_signals (
    ${ENVELOPE_COLUMNS},
    received_at     INTEGER NOT NULL,
    PRIMARY KEY (signal_hash)
  );
`;

const CREATE_RECEIVED_SQL = `
  CREATE TABLE IF NOT EXISTS contact_trust_signals (
    agent_id        TEXT NOT NULL,
    contact_pubkey  TEXT NOT NULL,
    ${ENVELOPE_COLUMNS},
    verified_at     INTEGER NOT NULL,
    received_at     INTEGER NOT NULL,
    PRIMARY KEY (agent_id, contact_pubkey, signal_hash),
    FOREIGN KEY (agent_id, contact_pubkey) REFERENCES contacts(agent_id, pubkey) ON DELETE CASCADE
  );
`;

/**
 * Idempotent schema. Must run AFTER `contacts` exists — the composite FK's parent. SQLite resolves
 * an FK's parent at DML time, not at DDL time, so creating this first would not fail here; it would
 * fail later, on the first insert, which is a far worse place to find out.
 */
export function ensureTrustSignalSchema(db: DaemonDatabase, _logger: Logger): void {
  db.exec(CREATE_WALLET_SQL);
  db.exec(CREATE_RECEIVED_SQL);
  // Presentation reads by subject; nothing reads by `type`, and nothing may (INV-ZERO-BUMP — an
  // index predicated on a type VALUE is a per-type construct in the schema).
  db.exec("CREATE INDEX IF NOT EXISTS idx_wallet_signals_subject ON wallet_trust_signals (subject_kind, subject)");
}

const toBuf = (b: Uint8Array): Buffer => Buffer.from(b);
const toBytes = (v: unknown): Uint8Array =>
  v instanceof Uint8Array ? new Uint8Array(v) : Buffer.isBuffer(v) ? new Uint8Array(v) : new Uint8Array(0);

interface EnvelopeDbRow {
  signal_hash: string;
  subject_kind: string;
  subject: string;
  issuer_kind: string;
  issuer_pubkey: string;
  type: string;
  schema_version: number;
  payload: unknown;
  issued_at: number;
  expires_at: number | null;
  supersedes_hash: string | null;
  status: string;
  received_at: number;
  verified_at?: number;
}

function toWalletRow(r: EnvelopeDbRow): WalletSignalRow {
  return {
    signalHash: r.signal_hash,
    subjectKind: r.subject_kind as "account" | "agent",
    subject: r.subject,
    issuerKind: r.issuer_kind as "portal" | "agent",
    issuerPubkey: r.issuer_pubkey,
    type: r.type,
    schemaVersion: r.schema_version,
    payload: toBytes(r.payload),
    issuedAt: r.issued_at,
    expiresAt: r.expires_at,
    supersedesHash: r.supersedes_hash,
    status: r.status,
    receivedAt: r.received_at,
  };
}

export class TrustSignalStore {
  readonly #db: DaemonDatabase;
  readonly #logger: Logger;

  constructor(db: DaemonDatabase, logger: Logger) {
    this.#db = db;
    this.#logger = logger;
    ensureTrustSignalSchema(db, logger);
  }

  /**
   * Store a signal this daemon holds about one of its agents.
   *
   * `INSERT OR IGNORE`, and that is a correctness property, not a convenience: the row is keyed by
   * its own content hash, so a second delivery of the same hash is by definition the same signal.
   * If the bytes really differed, the hash would differ. A differing payload under an identical hash
   * is therefore a liar, and it must not overwrite the truth. This is also what makes duplicate
   * delivery a no-op and wallet rows safely mergeable across a user's daemons (spec §14.11).
   */
  putWalletSignal(s: WalletSignalInput): void {
    const res = this.#db
      .prepare(
        `INSERT OR IGNORE INTO wallet_trust_signals
           (signal_hash, subject_kind, subject, issuer_kind, issuer_pubkey, type, schema_version,
            payload, issued_at, expires_at, supersedes_hash, status, received_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        s.signalHash, s.subjectKind, s.subject, s.issuerKind, s.issuerPubkey, s.type, s.schemaVersion,
        toBuf(s.payload), s.issuedAt, s.expiresAt, s.supersedesHash, s.status, Date.now(),
      );
    if (res.changes > 0) {
      this.#logger.info("signal.wallet.stored", {
        signalHash: s.signalHash, type: s.type, subjectKind: s.subjectKind, issuerKind: s.issuerKind,
      });
    }
  }

  getWalletSignal(signalHash: string): WalletSignalRow | null {
    const row = this.#db
      .prepare("SELECT * FROM wallet_trust_signals WHERE signal_hash = ?")
      .get(signalHash) as EnvelopeDbRow | undefined;
    return row ? toWalletRow(row) : null;
  }

  /** Status is the ONE mutable field — it lives outside the hash precisely so this is possible. */
  setWalletStatus(signalHash: string, status: SignalStatus): void {
    const res = this.#db
      .prepare("UPDATE wallet_trust_signals SET status = ? WHERE signal_hash = ?")
      .run(status, signalHash);
    if (res.changes > 0) this.#logger.info("signal.wallet.status.changed", { signalHash, status });
  }

  /**
   * The signals `agentId` may present, resolved from the ENVELOPE, not from a stored attribution:
   * an `account`-subject row is presentable by every agent under `accountId`; an `agent`-subject row
   * only by its own subject (M10-D5/M10-D14).
   *
   * Excludes expired and non-active rows. Selective disclosure (all / some / none) is the CALLER's
   * choice on top of this — DOD-PRESENT-1; this returns what is *eligible*, never what to send.
   */
  listPresentable(opts: { agentId: string; accountId: string; nowSec?: number }): WalletSignalRow[] {
    // `nowSec` is epoch SECONDS, and it is named for its unit deliberately. The envelope's
    // `issued_at`/`expires_at` are seconds (they are HASHED, and the protocol fixed the unit);
    // `Date.now()` is milliseconds. An unnamed `now` here invites a caller to pass one where the
    // other is meant, and a factor-of-1000 error in an expiry check does not throw — it silently
    // presents an EXPIRED signal (compared against a 1970 timestamp, every expiry is still in the
    // future). The first version of this method took `now` and its own test passed seconds into a
    // parameter that was divided by 1000; it only went green because the fixture's expiry was 1.
    const nowSec = opts.nowSec ?? Math.floor(Date.now() / 1000);
    const rows = this.#db
      .prepare(
        `SELECT * FROM wallet_trust_signals
          WHERE status = 'active'
            AND (expires_at IS NULL OR expires_at > ?)
            AND ( (subject_kind = 'account' AND subject = ?)
               OR (subject_kind = 'agent'   AND subject = ?) )`,
      )
      .all(nowSec, opts.accountId, opts.agentId) as unknown as EnvelopeDbRow[];
    return rows.map(toWalletRow);
  }

  /**
   * Store a signal a contact PRESENTED to one of my agents, after it was verified.
   *
   * The FK refuses a row for a contact that does not exist — an unscoped received signal is not
   * merely discouraged, it is unwritable. `verified_at` is RE-STAMPED on re-presentation: it records
   * when WE last re-verified, and a stale value that looked fresh would be worse than no value at
   * all (freshness is re-checked on use — M10-D4).
   */
  putReceivedSignal(s: ReceivedSignalInput): void {
    this.#db
      .prepare(
        `INSERT INTO contact_trust_signals
           (agent_id, contact_pubkey, signal_hash, subject_kind, subject, issuer_kind, issuer_pubkey,
            type, schema_version, payload, issued_at, expires_at, supersedes_hash, status,
            verified_at, received_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (agent_id, contact_pubkey, signal_hash)
           DO UPDATE SET verified_at = excluded.verified_at, status = excluded.status`,
      )
      .run(
        s.agentId, s.contactPubkey, s.signalHash, s.subjectKind, s.subject, s.issuerKind,
        s.issuerPubkey, s.type, s.schemaVersion, toBuf(s.payload), s.issuedAt, s.expiresAt,
        s.supersedesHash, s.status, s.verifiedAt, Date.now(),
      );
    this.#logger.info("signal.received.stored", {
      agentId: s.agentId, signalHash: s.signalHash, type: s.type, issuerKind: s.issuerKind,
    });
  }

  /** Evidence only. Never an input to policy — see the header. */
  listReceived(opts: { agentId: string; contactPubkey: string }): ReceivedSignalRow[] {
    const rows = this.#db
      .prepare(
        `SELECT * FROM contact_trust_signals WHERE agent_id = ? AND contact_pubkey = ?`,
      )
      .all(opts.agentId, opts.contactPubkey) as unknown as EnvelopeDbRow[];
    return rows.map((r) => ({
      ...toWalletRow(r),
      agentId: opts.agentId,
      contactPubkey: opts.contactPubkey,
      verifiedAt: r.verified_at ?? 0,
    }));
  }
}
