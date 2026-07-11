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

/** The tiers whose bounds and away texts are settable (BLOCKED is fixed, never overridable). */
export const SETTABLE_TIER_NAMES = Object.freeze(["unknown", "known", "whitelisted", "vip"] as const);
export type SettableTierName = (typeof SETTABLE_TIER_NAMES)[number];

/** The tier NAME for a tier integer, or null for an unknown/unsettable value (e.g. BLOCKED=0). */
export function settableTierName(tier: number): SettableTierName | null {
  switch (tier) {
    case 1: return "unknown";
    case 2: return "known";
    case 3: return "whitelisted";
    case 4: return "vip";
    default: return null; // BLOCKED(0) or out-of-range — not settable
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
