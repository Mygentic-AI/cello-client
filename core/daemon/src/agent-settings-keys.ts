/**
 * CELLO Daemon — the agent_settings key namespace (DOD-SETTINGS-1).
 *
 * A single source for every valid per-agent reachability-policy setting key, so the handler (which
 * REFUSES an unknown key) and the consumers (TIER-BOUNDS-SETTINGS reads the bound overrides,
 * AWAY-TIER-1 reads the away texts) can never drift. Keys are lower-snake, dotted namespaces:
 *
 *   bounds.<tier>.max_sessions   bounds.<tier>.max_bytes    — per-tier bound overrides
 *   bounds.<tier>.not_accepting                             — shut the tier (DOD-M15-NOTACCEPTING-1)
 *   away.default                                            — the agent's default away text
 *   away.tier.<tier>                                        — a per-tier away text
 *
 * `<tier>` is a tier NAME (not the integer), for legibility in the store. BLOCKED is deliberately NOT
 * settable — 0/0 is fixed (you cannot "raise" a block), and it has no away text (a blocked sender is
 * refused before any reply). So the settable tiers are unknown / known / whitelisted / vip.
 */

import { TIER } from "./contact-tier.js";
import { RELAY_ONLY_KEY } from "./relay-only.js";

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

/**
 * DOD-M15-NOTACCEPTING-1 — the key that SHUTS a tier. `"true"` means not accepting.
 *
 * ⚠️ THE POLARITY IS THE OPERATOR'S, NOT THE CODE'S. The first draft called this `accepting`, where
 * `false` shut the tier — the double negative someone shuts the WRONG tier with. The word typed is
 * the word intended: *this tier is not accepting*.
 *
 * Setting it is the ONLY way a bound of 0 is ever written (see `validateSettingValue`): the handler
 * writes the mark and both zeros in one transaction, so a zero exists in the store only where the
 * intent was declared, and a half-shut tier cannot be produced by one operator gesture.
 */
export function notAcceptingSettingKey(tier: SettableTierName): string {
  return `bounds.${tier}.${NOT_ACCEPTING_FIELD}`;
}

/** The trailing segment of the mark's key — shared with `isBoundKey`, which must NOT match it. */
export const NOT_ACCEPTING_FIELD = "not_accepting";

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
  // DOD-M15-RELAYONLY-1: relay-only routing. A BOOLEAN key, and the first one here — see
  // `validateSettingValue`, where it needs its own branch or the away-text fallback swallows it.
  RELAY_ONLY_KEY,
  ...SETTABLE_TIER_NAMES.flatMap((t) => [
    ...BOUND_FIELDS.map((f) => boundSettingKey(t, f)),
    // DOD-M15-NOTACCEPTING-1: a BOOLEAN key under the `bounds.` namespace — see `isBoundKey`.
    notAcceptingSettingKey(t),
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

/**
 * True iff the key is a per-tier BOUND override (its value must be a positive integer).
 *
 * ⚠️ IT MATCHES ON THE FIELD, NOT ON THE `bounds.` PREFIX, and that is load-bearing.
 * `bounds.<tier>.not_accepting` lives in the same namespace and is a BOOLEAN. A prefix test would
 * hand it to the integer branch below, where `"true"` and `"false"` are both refused — so the
 * control could not be switched on OR off, and the tier could never be shut at all.
 */
export function isBoundKey(key: string): boolean {
  return BOUND_FIELDS.some((f) => key.startsWith("bounds.") && key.endsWith(`.${f}`));
}

/**
 * The tier a `bounds.<tier>.<field>` key names, or null if the key is not one (or names a tier that
 * is not settable). Parsed rather than pattern-matched per call site, so the handler and the store
 * cannot disagree about which tier a key is about.
 */
export function boundsKeyTier(key: string): SettableTierName | null {
  const parts = key.split(".");
  if (parts.length !== 3 || parts[0] !== "bounds") return null;
  const name = parts[1] as SettableTierName;
  return SETTABLE_TIER_NAMES.includes(name) ? name : null;
}

/** The tier INTEGER for a settable tier name — the inverse of `settableTierName`. */
export function tierIndexForName(name: SettableTierName): number {
  switch (name) {
    case "unknown": return TIER.UNKNOWN;
    case "known": return TIER.KNOWN;
    case "whitelisted": return TIER.WHITELISTED;
    case "vip": return TIER.VIP;
  }
}

/** True iff the key is the per-tier NOT-ACCEPTING mark (a boolean). */
export function isNotAcceptingKey(key: string): boolean {
  return key.startsWith("bounds.") && key.endsWith(`.${NOT_ACCEPTING_FIELD}`);
}

/**
 * Validate a setting's VALUE for its key (DOD-TIER-BOUNDS-SETTINGS AC2).
 *
 * A bound override may only be a FINITE POSITIVE INTEGER — INV-TIER-BOUND: a setting can RAISE or
 * lower a bound within finite limits, never REMOVE one. `Infinity`, negatives, non-integers and
 * non-numeric strings are refused (an unbounded tier is exactly what the grid forbids).
 *
 * ⚠️ ZERO IS REFUSED HERE AND WRITTEN BY THE MARK — DOD-M15-NOTACCEPTING-1, and the refusal carries
 * the remedy rather than just a verdict. A bare `max_bytes 0` used to be the tempting way to shut a
 * tier and it does not shut anything: the caller is ADMITTED and then every message they send is
 * starved, which is a session that carries nothing. So zero stops being an operator gesture and
 * becomes a consequence of `bounds.<tier>.not_accepting true`, which writes both fields together.
 *
 * Away-text values are free-form strings.
 */
export function validateSettingValue(key: string, value: string): { ok: true } | { ok: false; reason: string } {
  // DOD-M15-NOTACCEPTING-1: the BOOLEAN mark, checked BEFORE the bound branch (its key is under the
  // same `bounds.` namespace) and before the away-text fallback further down. Same hazard, same
  // remedy as RELAY_ONLY_KEY: without its own branch `"flase"` stores successfully and reads as
  // not-"true" forever — the operator shuts the tier, is told it was saved, and is still reachable.
  if (isNotAcceptingKey(key)) {
    if (value !== "true" && value !== "false") {
      return { ok: false, reason: `${key} must be exactly "true" (shut this tier) or "false" (re-open it)` };
    }
    return { ok: true };
  }
  if (isBoundKey(key)) {
    // `^[1-9][0-9]*$` — a positive integer with no sign, decimal, or `Infinity`/`NaN` spelling.
    // Zero is excluded deliberately and the reason names what to do instead: see the note above.
    if (!/^[1-9][0-9]*$/.test(value)) {
      const tier = key.split(".")[1] ?? "<tier>";
      return {
        ok: false,
        reason:
          `a bound must be a positive integer (no negative, decimal, or Infinity). To SHUT this tier, ` +
          `set bounds.${tier}.not_accepting to true — that writes both of its bounds to 0 for you, and ` +
          `every caller it refuses is told the agent is not accepting connections.`,
      };
    }
    // Number.MAX_SAFE_INTEGER guard — a value past it loses precision and is meaningless as a cap.
    if (Number(value) > Number.MAX_SAFE_INTEGER) {
      return { ok: false, reason: "a bound must be <= Number.MAX_SAFE_INTEGER" };
    }
    return { ok: true };
  }
  // DOD-M15-RELAYONLY-1: a BOOLEAN key, and it must be caught BEFORE the away-text fallback below.
  //
  // ⚠️ THE FALLBACK IS THE HAZARD, not an edge case. Everything that is not a bound key falls
  // through to away-text validation, which accepts any non-empty string under 2048 characters. So
  // without this branch `transport.relay_only = "yes"` — or `"flase"` — would STORE successfully and
  // then read as not-"true" forever: the operator sets the privacy control, is told it was saved,
  // and has no protection. `isRelayOnly` deliberately treats anything but "true" as OFF, which is
  // only safe because a bad value cannot get past here to be misread later.
  if (key === RELAY_ONLY_KEY) {
    if (value !== "true" && value !== "false") {
      return { ok: false, reason: `${RELAY_ONLY_KEY} must be exactly "true" or "false"` };
    }
    return { ok: true };
  }
  // Away-text (review F2/F3): an EMPTY / whitespace-only away text is refused — to CLEAR, use null
  // (cello_contact_set_away) or omit the key; storing "" would silently blank every away reply,
  // including the minimal stranger disclosure. Bounded to a sane length (an answering-machine line,
  // not a document).
  if (value.trim().length === 0) {
    return { ok: false, reason: "an away message cannot be empty or whitespace-only (omit the key or pass null to clear)" };
  }
  if (value.length > AWAY_MESSAGE_MAX_LEN) {
    return { ok: false, reason: `an away message must be <= ${AWAY_MESSAGE_MAX_LEN} characters` };
  }
  return { ok: true };
}

/** Max length of an away message (per-contact or per-tier/agent-default) — an answering-machine line. */
export const AWAY_MESSAGE_MAX_LEN = 2048;
