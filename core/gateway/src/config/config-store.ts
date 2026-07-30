/**
 * M9-CFG-001 — the gateway's versioned config store (INV-4 as amended by M9B-D2).
 *
 * The store is append-only and versioned, and enforces the §7 governance asymmetry:
 *
 *   - TIGHTENING a guard (making the gateway MORE restrictive) is free — no confirmation.
 *   - LOOSENING a guard (making it LESS restrictive — enabling autonomous override, adding a value to
 *     the PII whitelist, raising/removing the rate cap, allowing another language) requires an explicit
 *     `confirmed` flag. Without it the change is REJECTED and not versioned. (The human confirmation
 *     is the CLI prompt — the portal passkey later; this store is the enforcement point.)
 *
 * Every applied change appends a row whose `fingerprint` is hash-chained to the previous version, so
 * the change history is tamper-evident and ready to attest to the directory in Phase 2 (M9-ATTEST-001).
 *
 * Encryption-at-rest (DOD-M9B-STORE-1): the store lives in the gateway's SQLCipher file, opened with
 * the daemon's key via a key FILE path — fail-closed, no plaintext fallback (see store/encrypted-db.ts).
 */
import { openEncryptedStoreDb, type StoreDb, type StoreEventSink } from "../store/encrypted-db.js";
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
  /** WHEN it changed. Stored all along; `history()` used to drop it, so the surface could not show
   *  provenance (review F9 of the earlier pass). */
  changedAt: number;
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
  // The window pairs with the cap: a SHORTER window refills faster → strictly more throughput → looser
  // (code-review H2 — shrinking the window must be gated like raising the cap). A longer window tightens.
  rate_window_ms: (prev, next) => {
    const p = Number(prev) || 0, q = Number(next) || 0;
    return q < p ? "loosen" : q > p ? "tighten" : "neutral";
  },
};

/**
 * The TIGHTEST default for every guard (code-review B1). The §7 contract defines a baseline: each guard
 * defaults to its most restrictive value, and LOOSENING from that default requires confirmation. The
 * store ships empty, so the FIRST set of a key must be classified against THIS baseline — not treated as
 * a free "neutral" — otherwise first-enabling autonomous_override (or seeding a whitelist) would be free,
 * inverting the security model.
 */
const BASELINE: Record<string, unknown> = {
  autonomous_override: false,      // the agent cannot self-authorize
  pii_whitelist: [] as string[],   // nothing passes silently
  language_allow: ["latin"],       // English only (the product default; allowing MORE languages loosens)
  rate_max_per_window: 0,          // 0 = no cap is the loosest; SETTING a cap tightens (so it is free)
  rate_window_ms: 60_000,          // a shorter window loosens; first-set of a shorter one is gated
};

/** Per-key value-type guard (code-review M2): a type-confused value must not silently disable a guard. */
const VALIDATORS: Record<string, (v: unknown) => boolean> = {
  autonomous_override: (v) => typeof v === "boolean",
  pii_whitelist: (v) => Array.isArray(v) && v.every((x) => typeof x === "string"),
  language_allow: (v) => Array.isArray(v) && v.every((x) => typeof x === "string"),
  rate_max_per_window: (v) => typeof v === "number" && Number.isFinite(v) && v >= 0,
  rate_window_ms: (v) => typeof v === "number" && Number.isFinite(v) && v > 0,
};

/** The hash-chain fingerprint over a version's fields (incl. direction + confirmed, H1) + the prior fp. */
function fingerprintOf(
  key: string,
  version: number,
  valueJson: string,
  direction: string,
  confirmed: number,
  prevFingerprint: string,
): string {
  return createHash("sha256")
    .update(`${key}|${version}|${valueJson}|${direction}|${confirmed}|${prevFingerprint}`)
    .digest("hex");
}

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
  readonly #db: StoreDb;
  #closed = false;

  /** Opens (creating if absent) the encrypted store at `dbPath`, keyed by the raw 32-byte key in
   *  `keyFilePath` — the daemon's own key file (M9B-D8/D9). Throws GatewayStoreError fail-closed. */
  constructor(dbPath: string, keyFilePath: string, onEvent?: StoreEventSink) {
    this.#db = openEncryptedStoreDb(dbPath, keyFilePath, onEvent);
    try {
      this.#db.exec(DDL);
    } catch (err) {
      // Review F8: the connection is already open at this point. A DDL throw — SQLITE_BUSY past the
      // busy_timeout is reachable on a file shared with the sidecar — used to leak the native handle
      // and cache nothing, so every retry opened another one. An fd leak against a lock-sensitive
      // file is a slow way to make the whole store unopenable.
      try { this.#db.close(); } catch { /* the throw below is the real error */ }
      throw err;
    }
  }

  /** Set `key` to `value`. Loosening requires `opts.confirmed`; tightening/neutral is free. The FIRST
   *  set of a key is classified against the per-key TIGHTEST baseline, not treated as free (B1). */
  set(key: string, value: unknown, opts: { confirmed?: boolean } = {}): SetResult {
    const classify = CLASSIFIERS[key];
    if (!classify) throw new Error(`unknown config key: ${key}`);
    if (!VALIDATORS[key](value)) throw new Error(`invalid value for config key '${key}': ${JSON.stringify(value)}`);

    const latest = this.#latestRow(key);
    // First set → compare against the tightest BASELINE so initial loosening is gated like any other (B1).
    const prevValue = latest ? (JSON.parse(latest.value_json) as unknown) : BASELINE[key];
    const direction: ConfigDirection = classify(prevValue, value);

    if (direction === "loosen" && !opts.confirmed) {
      return { ok: false, reason: "needs_confirmation", direction: "loosen" };
    }

    const version = (latest?.version ?? 0) + 1;
    const valueJson = JSON.stringify(value);
    const confirmed = opts.confirmed ? 1 : 0;
    const prevFingerprint = latest?.fingerprint ?? "";
    // The fingerprint binds direction + confirmed too (code-review H1): the whole point of attesting the
    // chain is to prove a loosening WAS confirmed by a human — so those fields must be inside the hash, or
    // an editor could flip confirmed 0→1 / relabel a loosen as neutral and still pass verifyChain.
    const fingerprint = fingerprintOf(key, version, valueJson, direction, confirmed, prevFingerprint);

    // Read-modify-write as one transaction so two processes on the same file cannot both write the same
    // version and collide on the PRIMARY KEY (code-review L1).
    this.#db.exec("BEGIN IMMEDIATE");
    try {
      this.#db
        .prepare(
          `INSERT INTO config_versions
             (key, version, value_json, direction, confirmed, fingerprint, prev_fingerprint, changed_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(key, version, valueJson, direction, confirmed, fingerprint, prevFingerprint, Date.now());
      this.#db.exec("COMMIT");
    } catch (err) {
      this.#db.exec("ROLLBACK");
      throw err;
    }

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
      .prepare(`SELECT version, value_json, direction, confirmed, fingerprint, changed_at FROM config_versions WHERE key = ? ORDER BY version ASC`)
      .all(key) as Array<{ version: number; value_json: string; direction: string; confirmed: number; fingerprint: string; changed_at: number }>;
    return rows.map((r) => ({
      version: r.version,
      value: JSON.parse(r.value_json) as unknown,
      direction: r.direction as ConfigDirection,
      confirmed: r.confirmed === 1,
      fingerprint: r.fingerprint,
      changedAt: r.changed_at,
    }));
  }

  /**
   * Recompute the hash chain for `key` and confirm every stored fingerprint + prev-link matches
   * (catches an edited value, a flipped `confirmed`, a relabelled `direction`, a deleted/reordered row).
   * NOT resistant to a full consistent rewrite or tail truncation by an actor with DB write access +
   * the (unkeyed) hash — that needs the Phase-2 attested head on the directory (M9-ATTEST-001); this is
   * the local half (code-review M3, recorded).
   */
  verifyChain(key: string): boolean {
    const rows = this.#db
      .prepare(`SELECT version, value_json, direction, confirmed, fingerprint, prev_fingerprint FROM config_versions WHERE key = ? ORDER BY version ASC`)
      .all(key) as Array<{ version: number; value_json: string; direction: string; confirmed: number; fingerprint: string; prev_fingerprint: string }>;
    let prevFingerprint = "";
    for (const r of rows) {
      if (r.prev_fingerprint !== prevFingerprint) return false;
      const expected = fingerprintOf(key, r.version, r.value_json, r.direction, r.confirmed, prevFingerprint);
      if (expected !== r.fingerprint) return false;
      prevFingerprint = r.fingerprint;
    }
    return true;
  }

  /**
   * Fold the WAL back into the main file WITHOUT closing (review F1/F2). Closing unlinks
   * `-wal`/`-shm` for every process sharing the file, including the daemon's long-lived handles.
   */
  checkpoint(): void {
    this.#db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
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
