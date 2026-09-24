/**
 * CELLO Daemon — contact reachability tiers (DOD-TIER-1, address-book Step 1).
 *
 * The tier values and their abuse bounds. The columns (`tier`, `provenance`,
 * `last_offered_moniker`, `away_message`) are on `contacts` in `session-schema.ts`.
 *
 * Design source: docs/planning/user-stories/m8c/2026-07-10_contact-address-book-design.md (§1).
 */

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
 * column is NULL (a row whose tier was never stamped). Both collapse
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

/** DOD-TIER-2: the abuse bounds for one tier. INV-TIER-BOUND — every field is FINITE (no tier is
 *  unbounded; `vip` is a large but real number, never Infinity). Step 4 lets settings OVERRIDE these
 *  defaults, but a setting may only raise/lower within finite bounds, never remove one. */
export interface TierBound {
  /** Max concurrent (active|interrupted) sessions this agent will hold from ONE sender at this tier. */
  readonly maxSessionsPerSender: number;
  /** Max cumulative RECEIVED bytes for a single session at this tier (anti-drip-feed). */
  readonly maxBytesPerSession: number;
}

/**
 * The hardcoded default bounds grid (DOD-TIER-2). One named map — the SINGLE source; call sites
 * reference it via `tierBoundsFor`, never inline a number. Step 4 (DOD-TIER-BOUNDS-SETTINGS) makes
 * these overridable per agent; until then they are the policy.
 *
 * INV-TIER-BOUND: a HIGHER tier only RAISES a bound — no tier removes one. `vip` is 50 sessions / 2 GiB,
 * deliberately finite. `blocked` is 0/0, which is what makes DOD-TIER-3 fall out for free: a 0 session
 * cap refuses a blocked sender through the SAME per-sender-cap path an over-cap unknown takes, with no
 * separate branch and therefore no distinguishing oracle.
 */
export const DEFAULT_TIER_BOUNDS: Readonly<Record<number, TierBound>> = Object.freeze({
  [TIER.BLOCKED]: { maxSessionsPerSender: 0, maxBytesPerSession: 0 },
  [TIER.UNKNOWN]: { maxSessionsPerSender: 3, maxBytesPerSession: 25 * 1024 * 1024 },
  [TIER.KNOWN]: { maxSessionsPerSender: 5, maxBytesPerSession: 100 * 1024 * 1024 },
  [TIER.WHITELISTED]: { maxSessionsPerSender: 20, maxBytesPerSession: 500 * 1024 * 1024 },
  [TIER.VIP]: { maxSessionsPerSender: 50, maxBytesPerSession: 2 * 1024 * 1024 * 1024 },
});

/** The bounds for a tier, TOTAL: any input is normalized to a defined tier first, so the return is
 *  always a real `TierBound` — a corrupt/out-of-range tier gets UNKNOWN's bounds, never `undefined`
 *  (the `grid[99]` crash the whole tier design guards against). */
export function tierBoundsFor(tier: number | null | undefined): TierBound {
  return DEFAULT_TIER_BOUNDS[normalizeTier(tier)];
}
