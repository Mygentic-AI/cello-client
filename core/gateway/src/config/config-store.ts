/**
 * M9-CFG-001 — the gateway's own versioned config store (INV-4).
 *
 * The gateway owns its configuration; the daemon never does. This store lives in the gateway's own
 * local DB file (node:sqlite — the same library the daemon uses, a separate file), is append-only and
 * versioned, and enforces the §7 governance asymmetry:
 *
 *   - TIGHTENING a guard (making the gateway MORE restrictive) is free — no confirmation.
 *   - LOOSENING a guard (making it LESS restrictive — enabling autonomous override, adding a value to
 *     the PII whitelist, raising/removing the rate cap, allowing another language) requires an explicit
 *     `confirmed` flag. Without it the change is REJECTED and not versioned. (The human confirmation —
 *     WebAuthn in the portal — is the front-end's job; this store is the enforcement point.)
 *
 * Every applied change appends a row whose `fingerprint` is hash-chained to the previous version, so
 * the change history is tamper-evident and ready to attest to the directory in Phase 2 (M9-ATTEST-001).
 *
 * Encryption-at-rest: the daemon opens node:sqlite without a cipher key today, so this store matches
 * that (a separate FILE, per INV-4); SQLCipher-style key encryption is a cross-cutting gap shared with
 * the daemon's DB, not a CFG-001-local concern.
 */
import { DatabaseSync } from "node:sqlite";
import { createHash } from "node:crypto";

/** Whether a config change makes the gateway more restrictive (tighten), less (loosen), or neither. */
export type ConfigDirection = "tighten" | "loosen" | "neutral";

export type SetResult =
  | { ok: true; version: number; direction: ConfigDirection; fingerprint: string }
  | { ok: false; reason: "needs_confirmation"; direction: "loosen" };

export interface ConfigVersionRow {
  version: number;
  value: unknown;
  direction: ConfigDirection;
  confirmed: boolean;
  fingerprint: string;
}

/** Classify a change for one key. `prev` is the current value (never undefined — the first set is
 *  always neutral, handled by the store before this runs). */
type Classifier = (prev: unknown, next: unknown) => ConfigDirection;

const asArray = (v: unknown): string[] => (Array.isArray(v) ? (v as string[]) : []);
/** Set-membership delta: more members = looser, fewer = tighter (for allowlists/whitelists). */
function membershipDirection(prev: unknown, next: unknown): ConfigDirection {
  const p = new Set(asArray(prev));
  const n = new Set(asArray(next));
  const added = [...n].some((v) => !p.has(v));
  const removed = [...p].some((v) => !n.has(v));
  if (added) return "loosen"; // a strictly-added member widens what is permitted
  if (removed) return "tighten";
  return "neutral";
}

/** The known config keys + how a change to each is classified. An unknown key is rejected outright. */
const CLASSIFIERS: Record<string, Classifier> = {
  // false → true loosens (the agent may now self-authorize); true → false tightens.
  autonomous_override: (prev, next) => (!prev && next ? "loosen" : prev && !next ? "tighten" : "neutral"),
  // More whitelisted PII values = more that passes silently = looser.
  pii_whitelist: membershipDirection,
  // More allowed languages = looser.
  language_allow: membershipDirection,
  // 0 = no cap = loosest; a higher cap = looser. Lowering the cap tightens.
  rate_max_per_window: (prev, next) => {
    const looseness = (v: unknown): number => { const n = Number(v) || 0; return n === 0 ? Infinity : n; };
    const p = looseness(prev), q = looseness(next);
    return q > p ? "loosen" : q < p ? "tighten" : "neutral";
  },
  // The rate window pairs with the cap; a longer window over the same cap is looser (slower refill is
  // tighter). Treat purely as neutral unless it changes — windowing nuance is not a guard on its own.
  rate_window_ms: () => "neutral",
};

const DDL = `
CREATE TABLE IF NOT EXISTS config_versions (
  key              TEXT    NOT NULL,
  version          INTEGER NOT NULL,
  value_json       TEXT    NOT NULL,
  direction        TEXT    NOT NULL,
  confirmed        INTEGER NOT NULL,
  fingerprint      TEXT    NOT NULL,
  prev_fingerprint TEXT    NOT NULL,
  changed_at       INTEGER NOT NULL,
  PRIMARY KEY (key, version)
);
`;

export class GatewayConfigStore {
  readonly #db: DatabaseSync;
  #closed = false;

  constructor(dbPath: string) {
    this.#db = new DatabaseSync(dbPath);
    this.#db.exec(DDL);
  }

  /** Set `key` to `value`. Loosening requires `opts.confirmed`; tightening/first-set/neutral is free. */
  set(key: string, value: unknown, opts: { confirmed?: boolean } = {}): SetResult {
    const classify = CLASSIFIERS[key];
    if (!classify) throw new Error(`unknown config key: ${key}`);

    const latest = this.#latestRow(key);
    const prevValue = latest ? (JSON.parse(latest.value_json) as unknown) : undefined;
    // The first value for a key is neutral (there is no prior guard to loosen). After that, classify.
    const direction: ConfigDirection = latest ? classify(prevValue, value) : "neutral";

    if (direction === "loosen" && !opts.confirmed) {
      return { ok: false, reason: "needs_confirmation", direction: "loosen" };
    }

    const version = (latest?.version ?? 0) + 1;
    const valueJson = JSON.stringify(value);
    const prevFingerprint = latest?.fingerprint ?? "";
    const fingerprint = createHash("sha256")
      .update(`${key}|${version}|${valueJson}|${prevFingerprint}`)
      .digest("hex");

    this.#db
      .prepare(
        `INSERT INTO config_versions
           (key, version, value_json, direction, confirmed, fingerprint, prev_fingerprint, changed_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(key, version, valueJson, direction, opts.confirmed ? 1 : 0, fingerprint, prevFingerprint, Date.now());

    return { ok: true, version, direction, fingerprint };
  }

  /** The current (latest-version) value for `key`, or undefined if never set. */
  get(key: string): unknown {
    const row = this.#latestRow(key);
    return row ? (JSON.parse(row.value_json) as unknown) : undefined;
  }

  /** The full append-only version history for `key`, oldest first. */
  history(key: string): ConfigVersionRow[] {
    const rows = this.#db
      .prepare(`SELECT version, value_json, direction, confirmed, fingerprint FROM config_versions WHERE key = ? ORDER BY version ASC`)
      .all(key) as Array<{ version: number; value_json: string; direction: string; confirmed: number; fingerprint: string }>;
    return rows.map((r) => ({
      version: r.version,
      value: JSON.parse(r.value_json) as unknown,
      direction: r.direction as ConfigDirection,
      confirmed: r.confirmed === 1,
      fingerprint: r.fingerprint,
    }));
  }

  /** Recompute the hash chain for `key` and confirm every stored fingerprint matches (tamper check). */
  verifyChain(key: string): boolean {
    const rows = this.#db
      .prepare(`SELECT version, value_json, fingerprint, prev_fingerprint FROM config_versions WHERE key = ? ORDER BY version ASC`)
      .all(key) as Array<{ version: number; value_json: string; fingerprint: string; prev_fingerprint: string }>;
    let prevFingerprint = "";
    for (const r of rows) {
      if (r.prev_fingerprint !== prevFingerprint) return false;
      const expected = createHash("sha256")
        .update(`${key}|${r.version}|${r.value_json}|${prevFingerprint}`)
        .digest("hex");
      if (expected !== r.fingerprint) return false;
      prevFingerprint = r.fingerprint;
    }
    return true;
  }

  close(): void {
    if (this.#closed) return; // idempotent — a double close (e.g. test teardown after an explicit close) is a no-op
    this.#closed = true;
    this.#db.close();
  }

  #latestRow(key: string): { version: number; value_json: string; fingerprint: string } | undefined {
    return this.#db
      .prepare(`SELECT version, value_json, fingerprint FROM config_versions WHERE key = ? ORDER BY version DESC LIMIT 1`)
      .get(key) as { version: number; value_json: string; fingerprint: string } | undefined;
  }
}
