/**
 * A PUBLIC KEY IS BYTES. ITS HEX CASE IS NOT PART OF ITS IDENTITY.
 *
 * ─── The defect, from the operator's chair ─────────────────────────────────────────────────────
 *
 * You paste a counterparty's public key with any uppercase in it — which is what half the tools in
 * the world hand you — and CELLO stores that string verbatim. From then on the address book holds a
 * contact you can SEE in `cello_contacts` and that every behavioural read treats as a stranger:
 *
 *  - `getTier` returns UNKNOWN, so the tighter inbound bounds apply and they are never auto-accepted;
 *  - `isKnown` is false, so they get the stranger wording;
 *  - a per-contact away message, a pet name, a trust-signal disclosure choice — all set against one
 *    spelling and read against the other, so none of them ever apply;
 *  - and **a key you BLOCKED in one spelling is unblocked in the other**, which is the direction
 *    that matters.
 *
 * Nothing errors, nothing logs, and the row is right there on screen. Found by review while ruling
 * on `024-ORPHANTRIAGE`, which had worked around it locally with its own `lower(pubkey)` lookup
 * rather than changing a predicate several callers depend on.
 *
 * ─── The fix is BOTH halves, and either alone leaves the bug ───────────────────────────────────
 *
 * 1. **Normalize at the accessor**, so a caller may pass either spelling and always reach one row —
 *    and so two spellings can never create two rows through the `(agent_id, pubkey)` primary key.
 * 2. **Fold the rows that already exist**, because normalizing reads alone strands every mixed-case
 *    row already on an operator's disk: it becomes unreachable rather than merely wrong.
 *
 * ⚠️ **THE WIRE BOUNDARY STILL ACCEPTS EITHER SPELLING, DELIBERATELY.** `invalidPubkey` validates
 * `[0-9a-fA-F]{64}`, and tightening it to lowercase would reject a key the operator pasted correctly
 * from a tool that happens to upper-case. The answer is to accept what they paste and store one form,
 * not to argue with them about capitals.
 */

import type { Logger } from "./types.js";

/** Minimal surface: what these two functions need from a SQLCipher handle. */
interface MigrationDb {
  exec(sql: string): unknown;
  prepare(sql: string): { run(...params: unknown[]): { changes: number | bigint } };
}

/**
 * The one spelling every contact-keyed table stores and every accessor compares against.
 *
 * Hex, so lowercase is the conventional form and the one `Buffer.toString("hex")` produces — which
 * matters, because keys arriving from the wire come through that call and keys arriving from an
 * operator's paste do not.
 */
export function normalizeContactPubkey(pubkey: string): string {
  return pubkey.toLowerCase();
}

/**
 * Fold every mixed-case contact row to one spelling. Idempotent; a no-op on a clean database.
 *
 * ⚠️ **ON A COLLISION THE MOST RESTRICTIVE SETTING WINS, and that is the whole reason this is not a
 * two-line UPDATE.** When both spellings exist they are two halves of one relationship, and merging
 * them by taking either one at random can silently UNBLOCK a key the operator blocked, or disclose a
 * trust signal they withheld. `MIN` over the tier and over the disclosure flag makes the merge fail
 * in the safe direction every time: BLOCKED(0) beats anything, withheld(0) beats presented(1).
 *
 * The operator can always loosen a setting afterwards; they cannot recover from a permission they
 * did not know had been widened.
 */
export function foldContactPubkeyCase(db: MigrationDb, logger: Logger): void {
  db.exec("BEGIN");
  try {
    // ── contacts ──────────────────────────────────────────────────────────────────────────────
    //
    // Step 1 must run BEFORE the delete: once the duplicate is gone there is nothing left to take
    // the restrictive value from.
    const tightened = Number(db.prepare(
      `UPDATE contacts SET tier = (
         SELECT MIN(COALESCE(c2.tier, 1)) FROM contacts c2
          WHERE c2.agent_id = contacts.agent_id AND lower(c2.pubkey) = contacts.pubkey)
       WHERE pubkey = lower(pubkey)
         AND EXISTS (SELECT 1 FROM contacts c3
                      WHERE c3.agent_id = contacts.agent_id
                        AND lower(c3.pubkey) = contacts.pubkey
                        AND c3.pubkey <> contacts.pubkey)`,
    ).run().changes);
    const droppedContacts = Number(db.prepare(
      `DELETE FROM contacts WHERE pubkey <> lower(pubkey)
         AND EXISTS (SELECT 1 FROM contacts c2
                      WHERE c2.agent_id = contacts.agent_id AND c2.pubkey = lower(contacts.pubkey))`,
    ).run().changes);
    const foldedContacts = Number(db.prepare(
      "UPDATE contacts SET pubkey = lower(pubkey) WHERE pubkey <> lower(pubkey)",
    ).run().changes);

    // ── contact_signal_prefs ──────────────────────────────────────────────────────────────────
    //
    // `present` is a disclosure choice, so 0 (withhold) is the restrictive value and wins the merge.
    const tightenedPrefs = Number(db.prepare(
      `UPDATE contact_signal_prefs SET present = (
         SELECT MIN(p2.present) FROM contact_signal_prefs p2
          WHERE p2.agent_id = contact_signal_prefs.agent_id
            AND lower(p2.contact_pubkey) = contact_signal_prefs.contact_pubkey
            AND p2.signal_hash = contact_signal_prefs.signal_hash)
       WHERE contact_pubkey = lower(contact_pubkey)
         AND EXISTS (SELECT 1 FROM contact_signal_prefs p3
                      WHERE p3.agent_id = contact_signal_prefs.agent_id
                        AND lower(p3.contact_pubkey) = contact_signal_prefs.contact_pubkey
                        AND p3.signal_hash = contact_signal_prefs.signal_hash
                        AND p3.contact_pubkey <> contact_signal_prefs.contact_pubkey)`,
    ).run().changes);
    db.prepare(
      `DELETE FROM contact_signal_prefs WHERE contact_pubkey <> lower(contact_pubkey)
         AND EXISTS (SELECT 1 FROM contact_signal_prefs p2
                      WHERE p2.agent_id = contact_signal_prefs.agent_id
                        AND p2.contact_pubkey = lower(contact_signal_prefs.contact_pubkey)
                        AND p2.signal_hash = contact_signal_prefs.signal_hash)`,
    ).run();
    const foldedPrefs = Number(db.prepare(
      "UPDATE contact_signal_prefs SET contact_pubkey = lower(contact_pubkey) WHERE contact_pubkey <> lower(contact_pubkey)",
    ).run().changes);

    // ── contact_rename_notices ────────────────────────────────────────────────────────────────
    //
    // A queued display notice, with nothing to merge: the lowercase row is kept and the duplicate
    // dropped. Worst case the operator is offered a name once instead of twice.
    db.prepare(
      `DELETE FROM contact_rename_notices WHERE pubkey <> lower(pubkey)
         AND EXISTS (SELECT 1 FROM contact_rename_notices n2
                      WHERE n2.agent_id = contact_rename_notices.agent_id
                        AND n2.pubkey = lower(contact_rename_notices.pubkey))`,
    ).run();
    const foldedNotices = Number(db.prepare(
      "UPDATE contact_rename_notices SET pubkey = lower(pubkey) WHERE pubkey <> lower(pubkey)",
    ).run().changes);

    db.exec("COMMIT");

    // Silent on a clean database — this runs at every open, and a line per boot saying "nothing to
    // do" is how a log stops being read.
    if (foldedContacts + droppedContacts + foldedPrefs + foldedNotices > 0) {
      logger.info("contacts.pubkey.case.folded", {
        contacts: foldedContacts,
        duplicatesMerged: droppedContacts,
        tiersTightened: tightened,
        signalPrefs: foldedPrefs,
        signalPrefsTightened: tightenedPrefs,
        renameNotices: foldedNotices,
        impact:
          "contacts stored under a mixed-case public key were unreachable to every behavioural read — " +
          "tier, away message, pet name and disclosure choice — and are now one row. Where both " +
          "spellings existed, the more restrictive setting was kept.",
      });
    }
  } catch (err: unknown) {
    // SQLite may have already aborted the transaction; a failing ROLLBACK must not mask the cause.
    try { db.exec("ROLLBACK"); } catch { /* the failing statement may have aborted it already */ }
    logger.error("contacts.pubkey.case.fold.failed", {
      reason: err instanceof Error ? err.message : String(err),
      impact:
        "contacts stored under a mixed-case public key stay split across two rows, so a tier, block " +
        "or away message set against one spelling does not apply to the other. Reads are still " +
        "normalized, so a mixed-case row is now unreachable rather than merely wrong.",
    });
    throw err;
  }
}
