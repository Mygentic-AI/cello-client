/**
 * CELLO Daemon — the agent_settings key namespace (DOD-SETTINGS-1).
 *
 * A single source for every valid per-agent reachability-policy setting key, so the handler (which
 * REFUSES an unknown key) and the consumers (TIER-BOUNDS-SETTINGS reads the bound overrides,
 * AWAY-TIER-1 reads the away texts) can never drift. Keys are lower-snake, dotted namespaces:
 *
 *   bounds.<tier>.max_sessions   bounds.<tier>.max_bytes    — per-tier bound overrides
 *   away.default                                            — the agent's default away text
 *   away.tier.<tier>                                        — a per-tier away text
 *
 * `<tier>` is a tier NAME (not the integer), for legibility in the store. BLOCKED is deliberately NOT
 * settable — 0/0 is fixed (you cannot "raise" a block), and it has no away text (a blocked sender is
 * refused before any reply). So the settable tiers are unknown / known / whitelisted / vip.
 */

import { TIER } from "./contacts-tier-migration.js";

/** The tiers whose bounds and away texts are settable (BLOCKED is fixed, never overridable). */
export const SETTABLE_TIER_NAMES = Object.freeze(["unknown", "known", "whitelisted", "vip"] as const);
export type SettableTierName = (typeof SETTABLE_TIER_NAMES)[number];

/** The tier NAME for a tier integer, or null for an unknown/unsettable value (e.g. BLOCKED=0).
 *  Keyed off the TIER constants (review F3) so a renumbering in contacts-tier-migration can never
 *  silently desync the settings namespace from the grid. */
export function settableTierName(tier: number): SettableTierName | null {
  switch (tier) {
    case TIER.UNKNOWN: return "unknown";
    case TIER.KNOWN: return "known";
    case TIER.WHITELISTED: return "whitelisted";
    case TIER.VIP: return "vip";
    default: return null; // BLOCKED or out-of-range — not settable
  }
}

export type BoundField = "max_sessions" | "max_bytes";

/** The setting key for a per-tier bound override. */
export function boundSettingKey(tier: SettableTierName, field: BoundField): string {
  return `bounds.${tier}.${field}`;
}

/** The setting key for a per-tier away text. */
export function awayTierSettingKey(tier: SettableTierName): string {
  return `away.tier.${tier}`;
}

/** The setting key for the agent's default away text (the fallback below any per-tier text). */
export const AWAY_DEFAULT_KEY = "away.default";

const BOUND_FIELDS: readonly BoundField[] = Object.freeze(["max_sessions", "max_bytes"]);

/** Every valid setting key, precomputed. The handler validates a `set` against this exact set. */
const VALID_KEYS: ReadonlySet<string> = new Set<string>([
  AWAY_DEFAULT_KEY,
  ...SETTABLE_TIER_NAMES.flatMap((t) => [
    ...BOUND_FIELDS.map((f) => boundSettingKey(t, f)),
    awayTierSettingKey(t),
  ]),
]);

/** True iff `key` is a known, settable reachability-policy key. An unknown key is REFUSED by the
 *  handler (never silently stored — a typo'd key that persisted would be a setting that never takes
 *  effect, invisible to the operator). */
export function isValidSettingKey(key: string): boolean {
  return VALID_KEYS.has(key);
}

/** The full list of valid keys (for surfacing in a settings-list / help). */
export function allSettingKeys(): string[] {
  return [...VALID_KEYS];
}

/** True iff the key is a per-tier BOUND override (its value must be a positive integer). */
export function isBoundKey(key: string): boolean {
  return key.startsWith("bounds.");
}

/**
 * Validate a setting's VALUE for its key (DOD-TIER-BOUNDS-SETTINGS AC2). A bound override may only be
 * a FINITE POSITIVE INTEGER — INV-TIER-BOUND: a setting can RAISE or lower a bound within finite
 * limits, never REMOVE one. So `Infinity`, negatives, zero, non-integers, and non-numeric strings are
 * refused (an unbounded tier is exactly what the grid forbids). Away-text values are free-form strings.
 */
export function validateSettingValue(key: string, value: string): { ok: true } | { ok: false; reason: string } {
  if (isBoundKey(key)) {
    // `^[1-9][0-9]*$` — a positive integer with no sign, decimal, or `Infinity`/`NaN` spelling.
    if (!/^[1-9][0-9]*$/.test(value)) {
      return { ok: false, reason: "a bound must be a finite positive integer (no 0, negative, decimal, or Infinity)" };
    }
    // Number.MAX_SAFE_INTEGER guard — a value past it loses precision and is meaningless as a cap.
    if (Number(value) > Number.MAX_SAFE_INTEGER) {
      return { ok: false, reason: "a bound must be <= Number.MAX_SAFE_INTEGER" };
    }
  }
  return { ok: true };
}
