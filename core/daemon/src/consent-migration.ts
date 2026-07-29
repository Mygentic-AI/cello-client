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
 * DIRECTION OF THE BACKFILL. Existing rows become `accepted`, and that is correct rather than
 * lenient: every row that predates this column is portal-issued, minted about the operator, for the
 * operator, at their own action — there was never a third party whose decision was pending. Making
 * them `pending` would silently render every phone/email signal already in every wallet
 * unpresentable, which is a data-loss-shaped bug that raises no error.
 *
 * NEW rows are a different question and are handled at the write path: an `issuer_kind: agent`
 * signal is inserted `pending`, because it is exactly the case where somebody else authored an
 * object about you.
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

  db.exec("BEGIN");
  try {
    // No DEFAULT — see the header. The rows are given their value by the explicit backfill below.
    db.exec("ALTER TABLE wallet_trust_signals ADD COLUMN consent_state TEXT");
    const res = db
      .prepare(`UPDATE wallet_trust_signals SET consent_state = '${CONSENT_ACCEPTED}'`)
      .run();
    db.exec("COMMIT");
    logger.info("signal.consent.migrated", {
      backfilled: Number(res.changes),
      to: CONSENT_ACCEPTED,
      reason: "rows predating consent are portal-issued — minted for the operator, at their own action",
    });
  } catch (err: unknown) {
    db.exec("ROLLBACK");
    // RETHROW. A swallowed failure here leaves the daemon running against a schema it believes has
    // consent and does not — which presents unconsented endorsements while every test passes.
    logger.error("signal.consent.migration_failed", {
      reason: err instanceof Error ? err.message : String(err),
    });
    throw err;
  }
}
