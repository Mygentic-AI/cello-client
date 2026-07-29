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

import { verifyTrustSignalHash, type TrustSignalEnvelope } from "@cello-protocol/protocol-types";
import type { DaemonDatabase } from "./sqlcipher-db.js";
import { migrateWalletAddConsentState, CONSENT_ACCEPTED, type ConsentState } from "./consent-migration.js";
import type { Logger } from "./types.js";

/** Status lives OUTSIDE the hash — it is mutable after minting, which is exactly why it is not in
 *  the preimage. If it were hashed, revoking a signal would change its hash and the directory could
 *  never find it again. */
export type SignalStatus = "active" | "revoked" | "superseded";

/**
 * A delivery the holder REFUSED at its own chokepoint. A TYPED error so the delivery consumer (the M8
 * retirement's `inbound-sessions` re-point) can branch on it: a refused delivery must NEVER be ACKed
 * — the directory should re-deliver, or the operator investigate. A plain `Error` swallowed by a
 * best-effort `catch { return }` could accidentally fall through to an ACK; this cannot.
 */
export type SignalDeliveryRejection = "claimed_hash_malformed" | "hash_mismatch";
export class SignalDeliveryRejected extends Error {
  constructor(readonly reason: SignalDeliveryRejection, detail: string) {
    super(`signal_delivery_${reason}: ${detail}`);
    this.name = "SignalDeliveryRejected";
  }
}

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
  /** Whether this signal is included in the default presentation bundle. When absent, derived from type suffix. */
  defaultPresent?: boolean;
}

export interface WalletSignalRow extends WalletSignalInput {
  receivedAt: number;
  /** M10B-D14r2 — may this be presented at all. Distinct from `defaultPresent`, which answers the
   *  different question of whether to include it BY DEFAULT once it may be presented.
   *
   *  NULLABLE, because the COLUMN is (SQLite cannot ADD COLUMN NOT NULL without a default). Declaring
   *  it non-null would be a type that lies to every future consumer — and the consumer who then
   *  writes `!== "refused"` ships a NULL straight through as presentable. The predicate tests for
   *  exactly `accepted`, so NULL fails closed; the type must say so too. */
  consentState: ConsentState | null;
  /** True = included in the default presentation bundle. _id signals default false; everything else true. */
  defaultPresent: boolean;
}

/**
 * A signal a contact PRESENTED to one of my agents, as it is stored after verification.
 *
 * ⚠️ NOTE WHAT IS ABSENT: there is no `status` field, and this type deliberately does NOT extend
 * `WalletSignalInput`.
 *
 * `status` is outside the hash preimage — that is what makes it mutable, and it also means it is
 * **NOT AUTHENTICATED BY THE SIGNAL HASH**. A presenter can claim any status they like. If this type
 * simply extended the wallet's, the peer's claimed `status` would ride in the same struct as the
 * envelope fields and the natural call site would pass it straight through to the database.
 *
 * The attack that permits: Bob presents signal H; we verify it, find it REVOKED at the directory,
 * and store that as evidence. Next session Bob re-presents the same hash claiming `status: active`.
 * An upsert on the peer's value overwrites the one durable record that says we caught it — the party
 * a revocation indicts gets to erase the indictment. Evidence an adversary can rewrite is not
 * evidence.
 *
 * So the stored status is OUR verification verdict (`verdict`), produced by the verification seam
 * (DOD-VERIFY-1) from what the DIRECTORY said — never a field the peer controls. Removing `status`
 * from the input type makes that structural: there is no pass-through to forget to block.
 */
export interface ReceivedSignalInput extends Omit<WalletSignalInput, "status"> {
  agentId: string;
  contactPubkey: string;
  verifiedAt: number;
  /** OUR verdict from re-checking the directory — never the presenter's claim. */
  verdict: SignalStatus;
}

export interface ReceivedSignalRow extends ReceivedSignalInput {
  receivedAt: number;
}

/**
 * ⚠️ TWO TIME UNITS LIVE IN THESE TABLES, AND MIXING THEM SILENTLY PRESENTS EXPIRED SIGNALS.
 *
 *   issued_at / expires_at  — epoch **SECONDS**. These are ENVELOPE fields: they are HASHED, so the
 *                             protocol fixed the unit and we do not get to choose it.
 *   received_at / verified_at / consent_notified_at
 *                           — epoch **MILLISECONDS** (`Date.now()`). Local bookkeeping only, never
 *                             hashed, and matching the house convention of every other daemon table
 *                             (`contacts.added_at`, `sessions.updated_at`). A review read
 *                             `consent_notified_at` as an outlier among "seconds" siblings and
 *                             proposed converting it; that is backwards — it is not hashed and not
 *                             compared against `expires_at`, so it belongs with this group. Named
 *                             here so the next reader does not have to re-derive it.
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
    default_present INTEGER NOT NULL DEFAULT 1,
    -- M10B-D14r2 — NULLABLE, and that is forced rather than chosen: SQLite cannot ADD COLUMN with
    -- NOT NULL and no DEFAULT, so a MIGRATED database can only ever have a nullable column. Making
    -- the fresh DDL stricter would give fresh installs a different schema from migrated ones, and
    -- the divergence would surface only on fresh installs — i.e. on every new operator, which is the
    -- worst possible audience for it. The repo's "fresh == migrated" convention wins.
    --
    -- Nullability costs nothing here because presentability is enforced by the PREDICATE, which tests
    -- for exactly 'accepted' rather than for the absence of a bad value. NULL, '', 'ACCEPTED' and any
    -- future state all fail closed by construction (§5a), so the column constraint was never what was
    -- protecting the invariant.
    consent_state   TEXT,
    -- DOD-END-PENDING-1 — when the operator was TOLD about this pending decision. NULL = not yet
    -- told. Separate from consent_state because the item and the notification have different
    -- lifetimes: the decision persists until made, the nag stops once seen.
    consent_notified_at INTEGER,
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
  // Additive migration: add default_present if the table already exists without it.
  try {
    db.exec("ALTER TABLE wallet_trust_signals ADD COLUMN default_present INTEGER NOT NULL DEFAULT 1");
  } catch {
    // Column already exists — safe to ignore.
  }
  // M10B-D14r2 — DELIBERATELY OUTSIDE the try/catch above. That swallow is safe for an idempotent
  // ALTER whose only expected failure is "already exists"; it is NOT safe for a migration with a
  // one-time backfill, where a swallowed failure leaves the daemon running against a schema it
  // believes gates consent and does not. This one is birth-gated and rethrows.
  migrateWalletAddConsentState(db, _logger);
}

const toBuf = (b: Uint8Array): Buffer => Buffer.from(b);

/**
 * The payload column is `BLOB NOT NULL`, so an unrecognized shape coming back from the driver means
 * something is wrong — NOT that the payload is empty.
 *
 * Returning `new Uint8Array(0)` here (the previous behavior) is the silent-fallback pattern: a signal
 * whose payload failed to materialise would flow on to presentation and verification looking like a
 * perfectly valid signal that simply has no content. Its hash would then not match, and the operator
 * would be sent to hunt a canonicalization bug that does not exist. ABSENT IS NOT FINE — refuse, and
 * name the actual cause.
 */
const toBytes = (v: unknown): Uint8Array => {
  if (v instanceof Uint8Array) return new Uint8Array(v);
  if (Buffer.isBuffer(v)) return new Uint8Array(v);
  throw new Error(
    `signal_payload_not_bytes: the payload column returned ${v === null ? "null" : typeof v}` +
    `${v && typeof v === "object" ? ` (${v.constructor?.name})` : ""}, but the column is BLOB NOT NULL. ` +
    "This is a storage-layer fault, not an empty payload — an empty payload would be a zero-length BLOB.",
  );
};

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
  default_present?: number;
}

/** The received table's row. `verified_at` is `NOT NULL` in the schema, so it is REQUIRED here — an
 *  optional type would only invite a `?? 0` default, and "verified at the epoch" is indistinguishable
 *  from a real, absurd timestamp. */
interface ReceivedDbRow extends EnvelopeDbRow {
  verified_at: number;
}

/**
 * Refuse anything that is not a 32-byte K_local pubkey as lowercase hex.
 *
 * SHARED, because it was written once for `listAllActive` and then DROPPED by three methods that
 * copied its SQL predicate without it (review F3). The predicate alone fails closed, but silently:
 * a device-local `agent_id` UUID — the natural thing to have in hand in an IPC handler — matches
 * zero rows, which is indistinguishable from "this operator has nothing pending". For the consent
 * queue that silence IS the bug the queue exists to prevent, and `markConsentNotified` would still
 * match account rows and log success, so the surface would look like it was working.
 */
function requireAgentPubkeyHex(value: string | undefined, caller: string): void {
  if (!/^[0-9a-f]{64}$/.test(value ?? "")) {
    throw new Error(
      `${caller} requires the agent's 32-byte K_local pubkey as lowercase hex — ` +
        `refusing rather than returning an empty result that reads as "nothing to show"`,
    );
  }
}

function toWalletRow(r: EnvelopeDbRow): WalletSignalRow {
  return {
    signalHash: r.signal_hash,
    consentState: (r as unknown as { consent_state: string }).consent_state as ConsentState,
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
    // Rows written before this column existed have null here; treat as true (default-on).
    defaultPresent: r.default_present !== 0,
  };
}

export class TrustSignalStore {
  readonly #db: DaemonDatabase;
  readonly #logger: Logger;

  /**
   * Does NOT create the schema. `SessionNodeManager.initialize()` owns it, and must — the received
   * table's FK parent is `contacts`, which that init creates. A store that created its own schema
   * would happily build `contact_trust_signals` on any handle lacking `contacts`, producing a
   * dangling FK that then fails on the first INSERT with `no such table: main.contacts` — an error
   * that names the wrong subsystem, at the wrong time, far from the cause.
   */
  constructor(db: DaemonDatabase, logger: Logger) {
    this.#db = db;
    this.#logger = logger;
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
  /** Returns true iff a NEW row was inserted (false = the content-addressed row already existed, a
   *  benign duplicate). */
  putWalletSignal(s: WalletSignalInput): boolean {
    // _id suffix signals default to excluded; everything else defaults to included.
    const defaultPresent = s.defaultPresent !== undefined ? s.defaultPresent : !s.type.endsWith("_id");
    const res = this.#db
      .prepare(
        `INSERT OR IGNORE INTO wallet_trust_signals
           (signal_hash, subject_kind, subject, issuer_kind, issuer_pubkey, type, schema_version,
            payload, issued_at, expires_at, supersedes_hash, status, received_at, default_present,
            consent_state)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        s.signalHash, s.subjectKind, s.subject, s.issuerKind, s.issuerPubkey, s.type, s.schemaVersion,
        toBuf(s.payload), s.issuedAt, s.expiresAt, s.supersedesHash, s.status, Date.now(),
        defaultPresent ? 1 : 0,
        // M10B-D14r2 / INV-CONSENT. Keys on ISSUER_KIND, never on the type string, so every future
        // client-sourced type inherits consent for free (M10B-D1). An `agent`-issued signal was
        // authored by somebody else ABOUT the operator and is unpresentable until they say so; a
        // `portal`-issued one was minted for them, at their own action, and has no third party to
        // wait for. Written at the one insert path, and the SQL predicate fails closed regardless.
        s.issuerKind === "agent" ? "pending" : CONSENT_ACCEPTED,
      );
    if (res.changes > 0) {
      this.#logger.info("signal.wallet.stored", {
        signalHash: s.signalHash, type: s.type, subjectKind: s.subjectKind, issuerKind: s.issuerKind,
      });
      if (s.issuerKind === "agent") {
        // DOD-END-PENDING-1 named event. Emitted where the decision is CREATED, so the log shows a
        // decision being owed even if the operator never selects the agent again.
        this.#logger.info("signal.consent.pending", {
          signalHash: s.signalHash, subject: s.subject.slice(0, 16), issuerPubkey: s.issuerPubkey.slice(0, 16),
        });
      }
    }
    return res.changes > 0;
  }

  /**
   * Accept a trust-signal envelope delivered to this holder: RE-VERIFY its hash, then store it.
   *
   * This is the holder's own chokepoint (INV-CANONICAL / M10-D4): the daemon does not trust the
   * `claimedHash` the delivery frame carried — it re-derives the hash from the envelope with the SAME
   * canonical component every party uses, and REFUSES a mismatch. A delivered envelope whose bytes do
   * not hash to the claim is a corrupted or tampered delivery; storing it would let the wallet present
   * a signal the directory never notarized.
   *
   * Storage is idempotent (content-addressed PK) — a re-delivery is a no-op (§14.11). Returns whether
   * a new row was stored, so the caller can ACK only a genuinely-accepted delivery.
   */
  deliverWalletSignal(envelope: TrustSignalEnvelope, claimedHash: string): { stored: boolean } {
    // A malformed claim STRING and a genuine byte-tamper are two different causes — name them apart
    // (a directory version-skew emitting uppercase hex must not read as universal tamper and send the
    // operator to the wrong subsystem). Both refuse-and-don't-store; only the message differs.
    if (!/^[0-9a-f]{64}$/.test(claimedHash)) {
      this.#logger.warn("signal.delivery.claimed_hash_malformed", { claimedHash, type: envelope.type });
      throw new SignalDeliveryRejected("claimed_hash_malformed", `claimed hash is not 64-char lowercase hex: ${claimedHash}`);
    }
    if (!verifyTrustSignalHash(envelope, new Uint8Array(Buffer.from(claimedHash, "hex")))) {
      this.#logger.warn("signal.delivery.hash_mismatch", {
        claimedHash, type: envelope.type, subjectKind: envelope.subject_kind,
      });
      throw new SignalDeliveryRejected("hash_mismatch", `delivered envelope does not hash to the claimed ${claimedHash}`);
    }
    const supersedesHash = envelope.supersedes_hash === null ? null : Buffer.from(envelope.supersedes_hash).toString("hex");
    // putWalletSignal is idempotent (content-addressed PK) and reports whether it inserted — use that
    // directly rather than a second SELECT (no read-then-write, no theoretical race).
    const inserted = this.putWalletSignal({
      signalHash: claimedHash,
      subjectKind: envelope.subject_kind,
      subject: envelope.subject,
      issuerKind: envelope.issuer_kind,
      issuerPubkey: envelope.issuer_pubkey,
      type: envelope.type,
      schemaVersion: envelope.schema_version,
      payload: envelope.payload,
      issuedAt: envelope.issued_at,
      expiresAt: envelope.expires_at,
      supersedesHash,
      status: "active",
    });
    if (inserted) {
      // ⚠️ SUPERSESSION IS A DESTRUCTIVE WRITE BY A THIRD PARTY, so it is gated twice.
      //
      // GATE 1 — CONSENT (M10B / DOD-END-ACCEPT-1 review F1). An `issuer_kind: agent` delivery lands
      // `pending` and is unpresentable, which stops a rogue endorsement being DISPLAYED. It does not
      // stop it ERASING: without this gate the rogue's insert superseded the subject's own ACCEPTED
      // endorsement of the same type, and Alice presented NOTHING. Consent that blocks display but
      // not deletion closes half the threat Andre named. An unconsented signal supersedes nothing;
      // `setConsentState` re-runs these effects if and when the subject accepts it.
      //
      // GATE 2 — AUTHORITY (review F2, pre-existing since M10). `supersedes_hash` was honoured
      // without asking whether the new issuer is entitled to supersede the target, so any third
      // party who could get one signal delivered could knock out ANY row in the wallet — including
      // phone and email — just by naming its hash. Supersession now requires the SAME ISSUER: for an
      // agent the key IS the identity, and for the portal it is the one logical issuer. This mirrors
      // what the directory does in V54, where an unauthorised write must not change what a third
      // party can present.
      const consented = this.getWalletSignal(claimedHash)?.consentState === CONSENT_ACCEPTED;
      if (consented) {
        this.#applySupersession(envelope, claimedHash, supersedesHash);
      } else {
        this.#logger.info("signal.supersede.deferred", {
          signalHash: claimedHash,
          issuerKind: envelope.issuer_kind,
          reason: "not consented — supersession is re-evaluated on acceptance",
        });
      }
    }
    return { stored: inserted };
  }

  /**
   * Apply a newly-consented signal's supersession effects, with the ISSUER-AUTHORITY check.
   *
   * Extracted so acceptance can re-run it: a signal that arrived `pending` supersedes nothing until
   * the subject accepts it, and at that moment the same rules must apply as if it had arrived
   * accepted. One implementation, so the two entry points cannot drift.
   */
  #applySupersession(
    envelope: { subject_kind: string; subject: string; type: string; issuer_kind: string; issuer_pubkey: string },
    claimedHash: string,
    supersedesHash: string | null,
  ): void {
    if (supersedesHash) {
      const target = this.getWalletSignal(supersedesHash);
      // SAME ISSUER, or refuse. A missing target is NOT an invitation to proceed (§5a): if we cannot
      // see what is being superseded we cannot judge the authority, so we do not act.
      const authorized = target !== null && target.issuerPubkey === envelope.issuer_pubkey;
      if (authorized) {
        this.setWalletStatus(supersedesHash, "superseded");
      } else {
        this.#logger.warn("signal.supersede.refused", {
          signalHash: claimedHash,
          supersedesHash,
          reason: target === null ? "target_not_held" : "issuer_mismatch",
          newIssuer: envelope.issuer_pubkey.slice(0, 16),
          targetIssuer: target === null ? null : target.issuerPubkey.slice(0, 16),
        });
      }
    }
    // Type-dedup: another active signal of the same (subject_kind, subject, type) is superseded by
    // the new one — duplicates delivered without supersedes_hash (e.g. a type re-minted on a fresh
    // portal login with no prior-hash lookup). SCOPED TO THE SAME ISSUER for the same reason: a
    // stranger's endorsement is not a newer version of yours just because it shares a type string.
    this.#db
      .prepare(
        `UPDATE wallet_trust_signals
            SET status = 'superseded'
          WHERE subject_kind = ? AND subject = ? AND type = ?
            AND signal_hash != ?
            AND issuer_pubkey = ?
            AND status = 'active'`,
      )
      .run(envelope.subject_kind, envelope.subject, envelope.type, claimedHash, envelope.issuer_pubkey);
  }

  getWalletSignal(signalHash: string): WalletSignalRow | null {
    const row = this.#db
      .prepare("SELECT * FROM wallet_trust_signals WHERE signal_hash = ?")
      .get(signalHash) as EnvelopeDbRow | undefined;
    return row ? toWalletRow(row) : null;
  }

  /**
   * Status is the ONE mutable field — it lives outside the hash precisely so this is possible.
   *
   * REVOCATION IS TERMINAL. A revoked signal can never go back to `active`. Without that guard this
   * is a blind UPDATE, and a stale or replayed directory read reporting `active` for a hash we
   * already revoked would resurrect it — and `listPresentable` would start offering it again. The
   * directory is the authority on revocation, but a LATE answer from it is not a NEW answer; the
   * monotonic rule makes out-of-order responses harmless instead of dangerous.
   *
   * `superseded` may still be overtaken by `revoked` (a superseded signal can also be revoked), but
   * never the reverse, and never back to `active`.
   */
  setWalletStatus(signalHash: string, status: SignalStatus): void {
    const res = this.#db
      .prepare(
        `UPDATE wallet_trust_signals SET status = ?
          WHERE signal_hash = ?
            AND status != 'revoked'
            AND NOT (status = 'superseded' AND ? = 'active')`,
      )
      .run(status, signalHash, status);
    if (res.changes > 0) {
      this.#logger.info("signal.wallet.status.changed", { signalHash, status });
      return;
    }
    // No change is not necessarily an error (the row may already hold this status), but a REFUSED
    // downgrade is worth surfacing — it means something tried to resurrect a dead signal.
    const current = this.#db
      .prepare("SELECT status FROM wallet_trust_signals WHERE signal_hash = ?")
      .get(signalHash) as { status: string } | undefined;
    if (current && current.status !== status) {
      this.#logger.warn("signal.wallet.status.change_refused", {
        signalHash, current: current.status, attempted: status,
        reason: "revocation is terminal — a revoked or superseded signal is never returned to active",
      });
    }
  }

  /**
   * The signals an agent may present, resolved from the ENVELOPE, not from a stored attribution:
   * an `account`-subject row is presentable by every agent under `accountId`; an `agent`-subject row
   * only by its own subject (M10-D5/M10-D14).
   *
   * **`agentPubkeyHex` is the K_local pubkey hex, NOT the daemon's device-local `agent_id`.** An
   * agent-subject envelope's `subject` holds the pubkey — that is the value the directory joins on
   * (`ap.k_local_pubkey = sr.subject`) — and a UUID compared against it matches nothing at all.
   *
   * NOTE (`DOD-END-SCOPE-FIX-1`): this method has no production callers; the live wire path is
   * `listAllActive`, which now carries the agent-subject half of this scoping. Kept because it is
   * the only implementation of the ACCOUNT-subject half, which is deferred behind a named
   * prerequisite — the daemon holds no `accountId` anywhere in production code.
   *
   * Excludes expired and non-active rows. Selective disclosure (all / some / none) is the CALLER's
   * choice on top of this — DOD-PRESENT-1; this returns what is *eligible*, never what to send.
   */
  listPresentable(opts: { agentPubkeyHex: string; accountId: string; nowSec?: number }): WalletSignalRow[] {
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
               OR (subject_kind = 'agent'   AND subject = ?) )
            AND consent_state = '${CONSENT_ACCEPTED}'`,
      )
      .all(nowSec, opts.accountId, opts.agentPubkeyHex) as unknown as EnvelopeDbRow[];
    return rows.map(toWalletRow);
  }

  /**
   * All wallet signals regardless of status — for operator inspection via `cello trust-signals list`.
   * Ordered by issued_at DESC so the most recent signal of each type appears first.
   */
  listAllWalletSignals(): WalletSignalRow[] {
    const rows = this.#db
      .prepare("SELECT * FROM wallet_trust_signals ORDER BY issued_at DESC, received_at DESC")
      .all() as unknown as EnvelopeDbRow[];
    return rows.map(toWalletRow);
  }

  /**
   * Look up a wallet signal by hash prefix (minimum 8 chars). Returns the unique matching signal,
   * or null if no match, or throws if the prefix is ambiguous (multiple matches).
   */
  getWalletSignalByPrefix(prefix: string): WalletSignalRow | null {
    if (prefix.length < 8) {
      throw new Error("hash prefix too short — supply at least 8 characters");
    }
    const rows = this.#db
      .prepare("SELECT * FROM wallet_trust_signals WHERE signal_hash LIKE ?")
      .all(prefix + "%") as unknown as EnvelopeDbRow[];
    if (rows.length === 0) return null;
    if (rows.length > 1) throw new Error(`ambiguous hash prefix '${prefix}' matches ${rows.length} signals — supply more characters`);
    return toWalletRow(rows[0]);
  }

  /**
   * Hard-delete a wallet signal by hash (GDPR removal). Returns true if a row was deleted.
   *
   * This is a permanent DELETE, not a status transition. Revocation is directory-driven and leaves
   * the row for audit; this is the operator exercising their own right to remove a signal from their
   * own device with no directory involvement.
   */
  removeWalletSignal(signalHash: string): boolean {
    const res = this.#db
      .prepare("DELETE FROM wallet_trust_signals WHERE signal_hash = ?")
      .run(signalHash);
    if (Number(res.changes) > 0) {
      this.#logger.info("signal.wallet.removed", { signalHash });
      return true;
    }
    return false;
  }

  /**
   * Active, non-expired wallet signals THIS agent is eligible to present — the live wire path
   * (`outbound-sessions.ts`).
   *
   * `presentingAgentPubkeyHex` is the presenting agent's K_local pubkey hex, and it is REQUIRED.
   * An `agent`-subject row is presentable only by its own subject (M10-D5/M10-D14); the wallet is
   * daemon-wide and shared by every agent on the device, so without this predicate each agent
   * offers every co-resident agent's agent-subject signals to its own counterparties —
   * `INV-AGENT-SCOPED`, which is what `DOD-END-SCOPE-FIX-1` closes. The scoping is in the SQL, not
   * a JS filter, because `include` already routes around `default_present` and a JS branch would
   * route around this the same way.
   *
   * **`lower(subject)`, because hex has a case and this comparison is byte-exact.** SQLite `TEXT`
   * uses BINARY collation, so `AABB…` and `aabb…` — the same key — do not match, and the row would
   * be silently un-presented with no error. The daemon's own `k_local_pubkey` is always lowercase
   * (`agent-loader.ts` derives it with `.toString("hex")`), so only the STORED side can vary, and it
   * can: `putWalletSignal` already names "a directory version-skew emitting uppercase hex" as a real
   * condition. Comparing case-insensitively is the correct equality for hex, not a fallback that
   * papers over a mismatch.
   *
   * Note the residual, because it is NOT closed here: the directory's
   * `JOIN agent_profiles ap ON ap.k_local_pubkey = sr.subject` is case-sensitive too, so an
   * uppercase-hex subject that ever got minted would still be invisible THERE. Closing that means
   * constraining the value where it is produced (the portal's mint) — which spans three components
   * and is its own decision, not something to smuggle into a presentation-scoping unit.
   *
   * **ACCOUNT-subject rows are deliberately NOT scoped here, and that half is deferred, not done.**
   * `listPresentable` scopes them on `accountId` — but the daemon holds no `accountId` anywhere in
   * production code, so there is nothing to compare against and inventing one is a separate
   * decision (M10B fourth review F5). Today's behavior for account rows is therefore unchanged:
   * every agent on the daemon may present them, which is also what M10-D5 says for agents under the
   * same account. It becomes wrong only when one daemon holds agents of two different accounts.
   *
   * Default behavior: returns only signals where `default_present = 1`.
   * `include` overrides the default — only the listed types are returned regardless of `default_present`.
   * `exclude` removes types from the default set.
   * Both `include` and `exclude` are type strings. Unknown types cause a validation error at the
   * IPC layer (the caller must pre-validate against listAllWalletSignals before calling this).
   */
  listAllActive(opts: {
    presentingAgentPubkeyHex: string;
    nowSec?: number;
    include?: string[];
    exclude?: string[];
  }): WalletSignalRow[] {
    // ABSENT IS NOT FINE (§5a), AND SO IS MALFORMED. A caller that cannot say who is presenting gets
    // a refusal, never the whole wallet: the fail-open direction here IS the defect this method was
    // fixed for, and it would hand a counterparty another agent's signals with no error and no log.
    //
    // The SHAPE check is the half that is easy to omit and expensive to omit. An empty string is
    // caught by any guard; a device-local `agent_id` UUID, an agent NAME, or uppercase hex all sail
    // through a truthiness check and then match zero rows — which is indistinguishable, to every
    // caller, from "this operator holds no signals". That silence is precisely the trap
    // `DOD-END-SCOPE-FIX-1` exists to close, so it is closed by construction here rather than by
    // remembering to pass the right thing. 32-byte Ed25519 key, lowercase hex, as `agent-loader.ts`
    // produces it.
    requireAgentPubkeyHex(opts.presentingAgentPubkeyHex, "listAllActive");
    const nowSec = opts.nowSec ?? Math.floor(Date.now() / 1000);
    const rows = this.#db
      .prepare(
        `SELECT * FROM wallet_trust_signals
          WHERE status = 'active'
            AND (expires_at IS NULL OR expires_at > ?)
            AND (subject_kind <> 'agent' OR lower(subject) = ?)
            AND consent_state = '${CONSENT_ACCEPTED}'`,
      )
      .all(nowSec, opts.presentingAgentPubkeyHex) as unknown as EnvelopeDbRow[];
    const all = rows.map(toWalletRow);
    if (opts.include) {
      const set = new Set(opts.include);
      return all.filter((s) => set.has(s.type));
    }
    const excluded = new Set(opts.exclude ?? []);
    return all.filter((s) => s.defaultPresent && !excluded.has(s.type));
  }

  /**
   * The distinct signal TYPES this agent could present — active, unexpired, and scoped to the
   * presenting agent exactly as `listAllActive` scopes rows.
   *
   * Deliberately ignores `default_present`, because this answers "may this type be named in a
   * filter", and `include` exists precisely to override the default. Validating a filter against
   * `listAllActive`'s output would reject a type the operator holds but has defaulted off — the
   * filter rejecting the thing it was built to select.
   *
   * The scoping is the point: the wallet is daemon-wide, so validating a filter against the whole
   * wallet accepts a type only a CO-RESIDENT agent holds, and the session then presents nothing with
   * no error (review MEDIUM-4).
   */
  listPresentableTypes(presentingAgentPubkeyHex: string, nowSec?: number): string[] {
    const now = nowSec ?? Math.floor(Date.now() / 1000);
    const rows = this.#db
      .prepare(
        `SELECT DISTINCT type FROM wallet_trust_signals
          WHERE status = 'active'
            AND (expires_at IS NULL OR expires_at > ?)
            AND (subject_kind <> 'agent' OR lower(subject) = ?)
            AND consent_state = '${CONSENT_ACCEPTED}'`,
      )
      .all(now, presentingAgentPubkeyHex) as Array<{ type: string }>;
    return rows.map((r) => r.type);
  }

  /**
   * Record the subject's consent decision (D-23). The ONLY writer of this column after insert.
   *
   * `refused` is terminal in spirit but not enforced as one-way here: `M10B-D4` allows Bob to issue a
   * CORRECTED endorsement after a refusal, and that is a NEW signal with its own hash — it does not
   * reuse this row. What must never happen is a refusal being silently undone, which is why the
   * migration is birth-gated rather than NULL-driven.
   */
  setConsentState(signalHash: string, state: ConsentState): boolean {
    const res = this.#db
      .prepare("UPDATE wallet_trust_signals SET consent_state = ? WHERE signal_hash = ?")
      .run(state, signalHash);
    if (Number(res.changes) === 0) return false;
    this.#logger.info("signal.consent.changed", { signalHash, consentState: state });

    // ACCEPTANCE IS WHEN SUPERSESSION BECOMES LEGITIMATE (review F1). Delivery deliberately defers
    // it — an unconsented signal must not erase a consented one — so the effects are applied here
    // instead, through the SAME authority-checked path, at the moment the subject says yes. Without
    // this an accepted re-issue would sit alongside the endorsement it replaces rather than
    // superseding it, and the operator would present both.
    if (state === CONSENT_ACCEPTED) {
      const row = this.getWalletSignal(signalHash);
      if (row) {
        this.#applySupersession(
          {
            subject_kind: row.subjectKind,
            subject: row.subject,
            type: row.type,
            issuer_kind: row.issuerKind,
            issuer_pubkey: row.issuerPubkey,
          },
          signalHash,
          row.supersedesHash,
        );
      }
    }
    return true;
  }

  /**
   * DOD-END-PENDING-1 — the decisions this agent still owes (`M10B-D5`).
   *
   * Its OWN surface, deliberately not the transcript inbox: an inbox item is cleared by reading or
   * dismissing a transcript, and an endorsement awaiting consent has no transcript, so it would be an
   * item the operator could never clear the normal way.
   *
   * Keyed by CONSENT STATE, never by type — that is what makes a whole new queue legal under
   * INV-ZEROBUMP, and it is why a future client-sourced type appears here with no code change.
   *
   * SCOPING, STATED HONESTLY. Agent-subject items are scoped to their subject, on the same axis as
   * presentation (DOD-END-SCOPE-FIX-1). ACCOUNT-subject items are visible to every agent on the
   * daemon — the same deferred residual `listAllActive` carries, because the daemon holds no
   * `accountId` anywhere in production code and per M10-D5 account signals serve every agent under
   * the account.
   *
   * ⚠️ BUT THE RESIDUAL CHANGES CHARACTER HERE, and that is worth naming rather than inheriting
   * silently: in `listAllActive` the consequence is SHOWING the wrong signal; here it is DECIDING.
   * Any agent on the daemon can accept an account-subject endorsement on another's behalf, and
   * acceptance runs a destructive supersession. Nobody has ruled on whether account-subject consent
   * should be per-agent or per-account — M10B-D9 says acceptance is recorded once per account-subject
   * SIGNAL, which points at "any agent may decide", but it was written about the operator surface,
   * not about authority. Recorded as an open question on `DOD-END-SURFACE-1` rather than settled by
   * whichever predicate got copied first.
   */
  listPendingConsent(agentPubkeyHex: string): WalletSignalRow[] {
    requireAgentPubkeyHex(agentPubkeyHex, "listPendingConsent");
    const rows = this.#db
      .prepare(
        `SELECT * FROM wallet_trust_signals
          WHERE consent_state = 'pending'
            AND status = 'active'
            AND (expires_at IS NULL OR expires_at > ?)
            AND (subject_kind <> 'agent' OR lower(subject) = ?)
          ORDER BY received_at ASC`,
      )
      .all(Math.floor(Date.now() / 1000), agentPubkeyHex) as unknown as EnvelopeDbRow[];
    return rows.map(toWalletRow);
  }

  /**
   * How many pending decisions this agent has NOT yet been told about.
   *
   * Asked on every agent selection, so it must go quiet once the operator has been told — while the
   * ITEM stays in `listPendingConsent` until they actually decide. A new arrival raises it again,
   * because the silence is per-item and not a permanent "already notified" flag on the agent.
   */
  countUnnotifiedConsent(agentPubkeyHex: string): number {
    requireAgentPubkeyHex(agentPubkeyHex, "countUnnotifiedConsent");
    const row = this.#db
      .prepare(
        `SELECT COUNT(*) AS n FROM wallet_trust_signals
          WHERE consent_state = 'pending'
            AND consent_notified_at IS NULL
            AND status = 'active'
            AND (expires_at IS NULL OR expires_at > ?)
            AND (subject_kind <> 'agent' OR lower(subject) = ?)`,
      )
      .get(Math.floor(Date.now() / 1000), agentPubkeyHex) as { n: number };
    return Number(row.n);
  }

  /** Record that the operator has been told about this agent's currently-pending decisions. */
  markConsentNotified(agentPubkeyHex: string): number {
    requireAgentPubkeyHex(agentPubkeyHex, "markConsentNotified");
    const res = this.#db
      .prepare(
        // The predicate MUST match countUnnotifiedConsent's exactly. It did not: this omitted the
        // status and expiry clauses, so it marked rows the counter never counted — the mark and the
        // count drifting apart is precisely how an item goes quiet without ever being shown.
        `UPDATE wallet_trust_signals
            SET consent_notified_at = ?
          WHERE consent_state = 'pending'
            AND consent_notified_at IS NULL
            AND status = 'active'
            AND (expires_at IS NULL OR expires_at > ?)
            AND (subject_kind <> 'agent' OR lower(subject) = ?)`,
      )
      .run(Date.now(), Math.floor(Date.now() / 1000), agentPubkeyHex);
    const n = Number(res.changes);
    if (n > 0) this.#logger.info("signal.consent.notified", { agentPubkey: agentPubkeyHex.slice(0, 16), count: n });
    return n;
  }

  /** Set the persistent default-presentation flag for a wallet signal. */
  setDefaultPresent(signalHash: string, value: boolean): boolean {
    const res = this.#db
      .prepare("UPDATE wallet_trust_signals SET default_present = ? WHERE signal_hash = ?")
      .run(value ? 1 : 0, signalHash);
    if (Number(res.changes) > 0) {
      this.#logger.info("signal.wallet.default_present.changed", { signalHash, defaultPresent: value });
      return true;
    }
    return false;
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
           DO UPDATE SET
             verified_at = excluded.verified_at,
             -- OUR verdict may only ever get WORSE, never better. A re-presentation cannot launder a
             -- signal we already caught as revoked/superseded back to active: the party a revocation
             -- indicts does not get to erase the indictment. (The envelope fields are not updated at
             -- all — they are hashed, so an identical signal_hash means identical envelope bytes; a
             -- differing value under the same hash is a liar and must not win.)
             status = CASE WHEN contact_trust_signals.status = 'active' THEN excluded.status
                           ELSE contact_trust_signals.status END`,
      )
      .run(
        s.agentId, s.contactPubkey, s.signalHash, s.subjectKind, s.subject, s.issuerKind,
        s.issuerPubkey, s.type, s.schemaVersion, toBuf(s.payload), s.issuedAt, s.expiresAt,
        s.supersedesHash, s.verdict, s.verifiedAt, Date.now(),
      );
    this.#logger.info("signal.received.stored", {
      agentId: s.agentId, signalHash: s.signalHash, type: s.type, issuerKind: s.issuerKind,
      verdict: s.verdict,
    });
  }

  /**
   * Mark a received signal as superseded. Same monotonic rules as setWalletStatus: revoked wins,
   * and a superseded signal never goes back to active.
   */
  setReceivedStatus(opts: { agentId: string; contactPubkey: string; signalHash: string; status: SignalStatus }): void {
    const res = this.#db
      .prepare(
        `UPDATE contact_trust_signals SET status = ?
          WHERE agent_id = ? AND contact_pubkey = ? AND signal_hash = ?
            AND status != 'revoked'
            AND NOT (status = 'superseded' AND ? = 'active')`,
      )
      .run(opts.status, opts.agentId, opts.contactPubkey, opts.signalHash, opts.status);
    if (res.changes > 0) {
      this.#logger.info("signal.received.status.changed", {
        agentId: opts.agentId, signalHash: opts.signalHash, status: opts.status,
      });
    }
  }

  /** Evidence only. Never an input to policy — see the header. */
  listReceived(opts: { agentId: string; contactPubkey: string }): ReceivedSignalRow[] {
    const rows = this.#db
      .prepare(
        `SELECT * FROM contact_trust_signals WHERE agent_id = ? AND contact_pubkey = ?`,
      )
      .all(opts.agentId, opts.contactPubkey) as unknown as ReceivedDbRow[];
    return rows.map((r) => {
      const { status, ...envelope } = toWalletRow(r);
      return {
        ...envelope,
        agentId: opts.agentId,
        contactPubkey: opts.contactPubkey,
        verifiedAt: r.verified_at,
        verdict: status as SignalStatus,
      };
    });
  }
}
