/**
 * CELLO Daemon — contacts tier metadata (DOD-TIER-1, address-book Step 1).
 *
 * `contacts` was re-keyed to the stable `agent_id` in daemon@0.0.45 (DOD-AGENT-ID-JOINKEY-1). This
 * module lands the address-book's per-contact metadata ON that key: a reachability `tier`, the
 * `provenance` of the relationship, the last self-declared name a peer offered (for Option-C rename
 * detection, Step 3), and a per-contact `away_message` (Step 4). All four are pure ADD COLUMN — no
 * table rebuild, no PK change — so, unlike the join-key migration, this one is simple and idempotent
 * and never has to appear in that migration's pinned DDL. It runs AFTER `migrateSessionTablesToAgentId`.
 *
 * Design source: docs/planning/user-stories/m8c/2026-07-10_contact-address-book-design.md (§1).
 */

import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";

/**
 * The five reachability tiers, ordered so `>=` is meaningful (blocked < unknown < known < whitelisted
 * < vip). Stored as the INTEGER `contacts.tier`. This const map is the SINGLE source of the numbers;
 * no bare tier integer may appear at a call site (DOD-TIER-1 AC2).
 *
 * BLOCKED is a real, meaningful ZERO — see `normalizeTier` for why that matters.
 */
export const TIER = Object.freeze({
  BLOCKED: 0,
  UNKNOWN: 1,
  KNOWN: 2,
  WHITELISTED: 3,
  VIP: 4,
} as const);

export type TierName = keyof typeof TIER;
export type TierValue = (typeof TIER)[TierName];

const TIER_VALUES: readonly number[] = Object.freeze(Object.values(TIER));

/** True iff `n` is exactly one of the five defined tier integers (0..4). The validation gate for
 *  `cello_contact_set_tier` (Step 3) — an unknown value is refused, never coerced. */
export function isKnownTierValue(n: number): boolean {
  return Number.isInteger(n) && TIER_VALUES.includes(n);
}

/**
 * The read-side default, and the single most safety-critical function in this unit.
 *
 * A contact's effective tier is UNKNOWN when there is NO row (undefined) OR when the row's `tier`
 * column is NULL (a row that predates a tier being set, or a stray never-stamped row). Both collapse
 * to UNKNOWN — the tighter default: a caller must never accidentally treat an unresolved contact as
 * reachable.
 *
 * It is written with EXPLICIT null/undefined checks, never `tier || UNKNOWN`, for two reasons that
 * are both live bugs otherwise:
 *   - `0 || 1 === 1`: a `|| UNKNOWN` would swallow BLOCKED(0) and silently un-block a blocked contact.
 *   - `null >= 0 === true`: a NULL reaching a `>=` bound check reads as "not blocked", and a NULL
 *     reaching a `grid[tier]` lookup is `grid[null]` → undefined → crash. Normalizing NULL→UNKNOWN
 *     here keeps every downstream comparison and lookup total.
 */
export function normalizeTier(tier: number | null | undefined): number {
  if (tier === null || tier === undefined) return TIER.UNKNOWN;
  // TOTAL over ALL inputs: a stored value that is not one of the five defined tiers (a corrupt or
  // future-version row) also collapses to UNKNOWN, so `getTier` is guaranteed to return a value in
  // 0..4 and every downstream `grid[tier]` lookup / `>=` comparison is total. Without this, a corrupt
  // `tier = 99` would sail through and become the `grid[99] → undefined` crash the bound grid fears.
  if (!isKnownTierValue(tier)) return TIER.UNKNOWN;
  return tier;
}

interface TierColumn {
  readonly name: string;
  /** Column DDL WITHOUT a default — see `migrateContactsAddTierMetadata` for why no default. */
  readonly ddl: string;
}

const TIER_METADATA_COLUMNS: readonly TierColumn[] = [
  { name: "tier", ddl: "tier INTEGER" },
  { name: "provenance", ddl: "provenance TEXT" },
  { name: "last_offered_moniker", ddl: "last_offered_moniker TEXT" },
  { name: "away_message", ddl: "away_message TEXT" },
];

/**
 * Idempotently add the tier-metadata columns to `contacts` and grandfather existing contacts.
 *
 * SQLite has no `ADD COLUMN IF NOT EXISTS`, so each ALTER is PRAGMA-guarded. Crucially the columns
 * are added with NO DEFAULT: a `DEFAULT` would give every existing row a value the instant the column
 * is created, so the grandfather backfill (`UPDATE … WHERE tier IS NULL`) would then match NOTHING —
 * every auto-accepting contact would silently drop to UNKNOWN. No default → existing rows read NULL →
 * the explicit backfill promotes them to WHITELISTED, preserving today's binary-whitelist behaviour
 * (design §1). Silently revoking access people already rely on is a worse failure than grandfathering
 * a permissive default for a handful of contacts they can list and demote at leisure.
 *
 * The grandfather is ONE-TIME: it runs only in the invocation that first adds the `tier` column. A
 * NULL that appears later (a stray un-stamped row) is NOT promoted — it is read as UNKNOWN by
 * `normalizeTier`, the tighter default. The promotion is tied to the column's birth, not to NULL-ness.
 */
export function migrateContactsAddTierMetadata(db: DaemonDatabase, logger: Logger): void {
  const existing = new Set(
    (db.prepare("PRAGMA table_info(contacts)").all() as Array<{ name: string }>).map((c) => c.name),
  );

  const toAdd = TIER_METADATA_COLUMNS.filter((c) => !existing.has(c.name));
  if (toAdd.length === 0) return; // idempotent: every column already present → nothing to do

  // The ADD COLUMNs and the grandfather backfill MUST commit atomically, in ONE transaction (SQLite
  // DDL is transactional — the same reason the join-key migration uses one BEGIN…COMMIT). If a crash
  // landed between the `tier` ALTER committing and the backfill, the next init would see the column
  // exists, skip the one-time grandfather FOREVER, and silently demote every legacy contact to
  // UNKNOWN — the exact "silently revoking access people already rely on" failure this file exists to
  // avoid, with no log and no error. Wrapping both makes "column added" and "existing rows
  // grandfathered" inseparable: a crash rolls back BOTH, and the clean re-run does the whole thing —
  // which is what makes column-existence a VALID durability marker for the one-time gate.
  const addsTier = toAdd.some((c) => c.name === "tier");
  let grandfathered = 0;
  db.exec("BEGIN");
  try {
    for (const col of toAdd) db.exec(`ALTER TABLE contacts ADD COLUMN ${col.ddl}`);
    // Grandfather EXISTING contacts to WHITELISTED — but ONLY on the migration that first adds `tier`
    // (a one-time, column-birth event). A NULL written AFTER the column exists is never promoted here;
    // it is a read-time UNKNOWN via normalizeTier, the tighter default.
    if (addsTier) {
      grandfathered = Number(db.prepare("UPDATE contacts SET tier = ? WHERE tier IS NULL").run(TIER.WHITELISTED).changes);
    }
    db.exec("COMMIT");
  } catch (err) {
    // SQLite may have already aborted the transaction; a failing ROLLBACK must not mask the real error.
    try {
      db.exec("ROLLBACK");
    } catch {
      /* the failing statement may have already aborted the txn */
    }
    logger.error("contacts.tier.migration.failed", {
      columns: toAdd.map((c) => c.name),
      reason: err instanceof Error ? err.message : String(err),
    });
    throw err;
  }

  logger.info("contacts.tier.columns.added", { columns: toAdd.map((c) => c.name) });
  if (grandfathered > 0) {
    logger.info("contacts.tier.grandfathered", { count: grandfathered, tier: TIER.WHITELISTED });
  }
}
