/**
 * M10B / DOD-END-ACCEPT-1 — the `consent_state` column on `wallet_trust_signals` (`M10B-D14r2`).
 *
 * WHY THIS IS ITS OWN FILE AND NOT A LINE IN `ensureTrustSignalSchema`. That function runs on EVERY
 * `startDaemon` and ends in a bare `catch {}` ("Column already exists — safe to ignore"). A consent
 * migration written as a sibling `ALTER`/`UPDATE` in there would have its failures swallowed AND its
 * backfill run unconditionally — so an operator who REFUSES an endorsement would have it flipped
 * back to `accepted` on the next restart, silently, and it would become presentable again. The
 * client DB has no migration versioning to catch that.
 *
 * So this follows the pattern the repo already proved for exactly this hazard
 * (`contacts-tier-migration.ts`):
 *   - a `PRAGMA table_info` COLUMN-BIRTH gate, so the one-time step is tied to the column being
 *     created rather than to a NULL that could reappear later;
 *   - NO column DEFAULT, so the backfill has a real discriminator — with a DEFAULT every existing
 *     row gets a value the instant the column exists and the backfill matches nothing;
 *   - the ALTER and the backfill in ONE transaction, so a crash between them cannot leave the
 *     column present and the rows un-backfilled, which would skip the one-time step FOREVER;
 *   - a RETHROW, because a migration that fails silently is a schema nobody can trust.
 *
 * DIRECTION OF THE BACKFILL — ENFORCED BY THE SQL, NOT BY AN ARGUMENT ABOUT THE PAST.
 * Portal-issued rows become `accepted`: they were minted about the operator, for the operator, at
 * their own action, so there was never a third party whose decision was pending, and making them
 * `pending` would silently render every phone/email signal already in every wallet unpresentable —
 * a data-loss-shaped bug that raises no error. Agent-issued rows become `pending`, because somebody
 * else authored them.
 *
 * An earlier version backfilled everything to `accepted` on the reasoning that nothing agent-issued
 * could exist yet. That was true only by RELEASE TIMING — the daemon has accepted
 * `issuer_kind: agent` since M10 — so a dev or staging wallet that picked one up during M10B
 * integration testing would have had it backfilled to presentable at boot, which is exactly the
 * D-23 violation this file exists to prevent. Two WHERE clauses make it a property of the code.
 *
 * NEW rows are handled at the write path on the same axis: `putWalletSignal` inserts `pending` for
 * `issuer_kind: agent` and `accepted` otherwise.
 */

import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";

/**
 * The consent states. Anything not in this set — including NULL and including a value with stray
 * whitespace or case — is UNPRESENTABLE (§5a: absent is not fine). The presentability predicate
 * tests for exactly `accepted` rather than testing for the absence of a bad state, so an
 * unrecognised value fails closed by construction.
 */
export type ConsentState = "pending" | "accepted" | "refused";

/** Present-tense truth for the reader: this is what gates presentation. */
export const CONSENT_ACCEPTED = "accepted";

export function migrateWalletAddConsentState(db: DaemonDatabase, logger: Logger): void {
  const columns = new Set(
    (db.prepare("PRAGMA table_info(wallet_trust_signals)").all() as Array<{ name: string }>).map((c) => c.name),
  );

  // BIRTH GATE. Idempotent, and deliberately NOT "backfill wherever the value is NULL": a NULL that
  // appears later is not a legacy row, and promoting it would be the clobber this file prevents.
  if (columns.has("consent_state")) return;

  // BEGIN IMMEDIATE, not DEFERRED: a deferred transaction takes no write lock, so two daemons on one
  // DB — a named real condition in this project — can both pass the gate above and the loser dies at
  // boot on `duplicate column name`. It does not clobber, but it is a baffling crash. The lock also
  // makes the re-read below meaningful.
  db.exec("BEGIN IMMEDIATE");
  try {
    // Re-read the gate under the lock: the PRAGMA above is a check-then-act outside any transaction.
    const underLock = new Set(
      (db.prepare("PRAGMA table_info(wallet_trust_signals)").all() as Array<{ name: string }>).map((c) => c.name),
    );
    // EACH COLUMN IS GATED INDEPENDENTLY. An earlier version added both under one gate keyed on
    // `consent_state`, so a database holding one but not the other hit `duplicate column name`, the
    // migration rethrew, and the daemon refused to start — a self-inflicted boot failure on a
    // recoverable state. Caught by the legacy-backfill test, which constructs exactly that shape.
    const needsConsent = !underLock.has("consent_state");
    const needsNotified = !underLock.has("consent_notified_at");
    if (!needsConsent && !needsNotified) { db.exec("COMMIT"); return; }

    // No DEFAULT — see the header. The rows are given their value by the explicit backfill below.
    if (needsConsent) db.exec("ALTER TABLE wallet_trust_signals ADD COLUMN consent_state TEXT");
    // DOD-END-PENDING-1 / M10B-D5 — the NOTIFICATION's lifetime, which is NOT the item's. The item
    // persists until accepted or refused; the notification is raised once and stops once seen. One
    // flag cannot carry both: a single seen-bit would either dismiss the pending decision (losing it)
    // or re-fire on every agent selection (nagging). Two facts, two columns.
    if (needsNotified) db.exec("ALTER TABLE wallet_trust_signals ADD COLUMN consent_notified_at INTEGER");

    if (!needsConsent) {
      // The backfill belongs to consent_state's BIRTH. If only the notification column was missing,
      // the rows already carry their consent and must not be re-judged — that is the clobber this
      // file exists to prevent, and it would arrive by the back door of a partially-migrated schema.
      db.exec("COMMIT");
      logger.info("signal.consent.migrated", { backfilled: 0, added: "consent_notified_at" });
      return;
    }
    // THE DIRECTION IS ENFORCED, NOT ARGUED (review F5). The header's reasoning — "everything
    // predating this column is portal-issued" — is true TODAY only by release timing: the daemon has
    // accepted `issuer_kind: agent` since M10, and a dev or staging wallet that picked one up during
    // M10B integration testing would be backfilled straight to `accepted` and presentable, which is
    // the D-23 violation this unit exists to prevent, silently, at boot. Two WHERE clauses make the
    // claim a property of the code instead of a property of the calendar.
    const acceptedRes = db
      .prepare(`UPDATE wallet_trust_signals SET consent_state = '${CONSENT_ACCEPTED}' WHERE issuer_kind <> 'agent'`)
      .run();
    const pendingRes = db
      .prepare("UPDATE wallet_trust_signals SET consent_state = 'pending' WHERE issuer_kind = 'agent'")
      .run();
    const res = { changes: Number(acceptedRes.changes) + Number(pendingRes.changes) };
    db.exec("COMMIT");
    logger.info("signal.consent.migrated", {
      backfilled: res.changes,
      accepted: Number(acceptedRes.changes),
      pending: Number(pendingRes.changes),
      reason: "portal-issued rows were minted for the operator at their own action; agent-issued rows need consent",
    });
  } catch (err: unknown) {
    // A FAILING ROLLBACK MUST NOT MASK THE REAL ERROR (review F6, and the pattern this file claims to
    // follow guards it — `contacts-tier-migration.ts` — I copied the shape minus its most important
    // two lines). SQLite auto-aborts the transaction on SQLITE_FULL/SQLITE_IOERR, so a bare ROLLBACK
    // then throws "cannot rollback - no transaction is active" — BEFORE the log and BEFORE the
    // rethrow. The operator gets a transaction-layer message for a full disk, and
    // `signal.consent.migration_failed` never fires at all.
    try { db.exec("ROLLBACK"); } catch { /* the failing statement may already have aborted the txn */ }
    // RETHROW. A swallowed failure here leaves the daemon running against a schema it believes has
    // consent and does not — which presents unconsented endorsements while every test passes.
    logger.error("signal.consent.migration_failed", {
      reason: err instanceof Error ? err.message : String(err),
    });
    throw err;
  }
}
