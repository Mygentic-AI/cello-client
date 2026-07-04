/**
 * CELLO-M7-PERSIST-002 — DB-backed identity store (the `agents` table).
 *
 * Every piece of an agent's persisted identity — the K_local Ed25519 seed, the ML-DSA keypair, the
 * FROST signing share, the registration record, and the agent↔user link — lives as ONE row of the
 * `agents` table in the SQLCipher-encrypted daemon DB. This replaces the per-agent plaintext flat
 * files (`agents/<name>/key`, `frost-share.json`, `ml-dsa-keypair.json`, `registration-state.json`,
 * `agent-user-link.json`).
 *
 * `DbRegistrationPersistence` implements the SAME `DaemonRegistrationPersistence` interface the
 * daemon's RegistrationManager and the ceremony/seal signer-reconstruction already consume — so the
 * call sites change only their construction (a DB handle + agent name instead of an `agentDir`), not
 * their behaviour. Writes are AWAITED single-row UPSERTs (SI-003: a register-success implies a
 * durably committed row — fixing the old fire-and-forget at registration-manager.ts:229).
 *
 * The K_local seed and FROST/ML-DSA secrets are stored as BLOB columns inside the encrypted DB; they
 * are NEVER written to a flat file and NEVER logged (SI-001). The row is the only home.
 */

import { randomUUID } from "node:crypto";
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";
import type {
  DaemonRegistrationPersistence,
  RegistrationStateRecord,
  MlDsaKeypairRecord,
  FrostKeyShareRecord,
  AgentUserLinkRecord,
} from "./registration-persistence.js";

const ML_DSA_ALGORITHM = "ML-DSA-44";

/**
 * The `agents` schema (CELLO-M7-REMOVE-001 DOD-REMOVE-1). The store is keyed by a STABLE `agent_id`,
 * not by `agent_name` — guardrail #1: durable identity hangs off agent_id; the human name and the
 * pubkey are mutable ATTRIBUTES. A partial unique index makes `agent_name` unique only among
 * NON-retired rows, so removal (state='retired') frees the name for reuse while the retired identity
 * survives for accountability (SI-002). `state`: 'created' | 'registered' | 'retired'.
 */
const CREATE_AGENTS_SQL = `
  CREATE TABLE IF NOT EXISTS agents (
    agent_id               TEXT PRIMARY KEY,
    agent_name             TEXT NOT NULL,
    -- K_local Ed25519 identity (PERSIST-002: seed moves from agents/<name>/key into this BLOB).
    k_local_seed           BLOB NOT NULL,
    k_local_pubkey         TEXT NOT NULL,
    -- lifecycle: 'created' (K_local exists, not yet registered) | 'registered' | 'retired' (REMOVE-001).
    state                  TEXT NOT NULL DEFAULT 'created',
    -- ML-DSA keypair (was ml-dsa-keypair.json).
    ml_dsa_pubkey          TEXT,
    ml_dsa_secret          BLOB,
    ml_dsa_algorithm       TEXT,
    -- FROST signing share (was frost-share.json).
    frost_epoch_id         TEXT,
    frost_primary_pubkey   TEXT,
    frost_identifier       TEXT,
    frost_signing_share    BLOB,
    frost_threshold        INTEGER,
    frost_participants     INTEGER,
    frost_commitments      BLOB,
    frost_verifying_shares BLOB,
    frost_dkg_method       TEXT,
    -- M8B quorum: JSON array of the directory nodeIds (Q) the DKG ran among, so a restored signer
    -- targets the actual share-holders (not the full live roster). NULL for pre-quorum agents.
    frost_directory_node_ids TEXT,
    -- registration record (was registration-state.json).
    reg_agent_id           TEXT,
    reg_primary_pubkey     TEXT,
    reg_ml_dsa_pubkey      TEXT,
    reg_registered_at      INTEGER,
    reg_status             TEXT,
    -- agent↔user link captured at registration (was agent-user-link.json).
    link_agent_id          TEXT,
    link_pre_auth_token    TEXT,
    link_linked_at         INTEGER,
    created_at             INTEGER NOT NULL,
    updated_at             INTEGER NOT NULL
  )
`;

// A name is unique only among NON-retired agents — the DB-level backstop for "free the name on removal".
const CREATE_ACTIVE_NAME_INDEX_SQL =
  "CREATE UNIQUE INDEX IF NOT EXISTS agents_active_name ON agents(agent_name) WHERE state != 'retired'";

// The columns of the PRE-REMOVE-001 `agents` table (agent_name PK, no agent_id), in order. Used to
// copy rows verbatim during the one-time re-key rebuild.
const PRE_REKEY_COLUMNS = [
  "agent_name",
  "k_local_seed",
  "k_local_pubkey",
  "state",
  "ml_dsa_pubkey",
  "ml_dsa_secret",
  "ml_dsa_algorithm",
  "frost_epoch_id",
  "frost_primary_pubkey",
  "frost_identifier",
  "frost_signing_share",
  "frost_threshold",
  "frost_participants",
  "frost_commitments",
  "frost_verifying_shares",
  "frost_dkg_method",
  "reg_agent_id",
  "reg_primary_pubkey",
  "reg_ml_dsa_pubkey",
  "reg_registered_at",
  "reg_status",
  "link_agent_id",
  "link_pre_auth_token",
  "link_linked_at",
  "created_at",
  "updated_at",
] as const;

/**
 * One-time re-key of a PRE-REMOVE-001 `agents` table (PRIMARY KEY agent_name, no agent_id) to the new
 * stable-agent_id shape. Rebuilds the table, backfilling a fresh agent_id per existing row. Runs at
 * most once — `ensureIdentitySchema` guards it behind a column-presence check — and is wrapped in a
 * transaction so a crash mid-rebuild leaves the original table intact. Works on node:sqlite (in-memory
 * test handles) and SQLCipher alike.
 */
function rebuildAgentsToAgentIdPk(db: DaemonDatabase): void {
  const cols = PRE_REKEY_COLUMNS.join(", ");
  db.exec("BEGIN");
  try {
    db.exec("ALTER TABLE agents RENAME TO agents_pre_rekey");
    db.exec(CREATE_AGENTS_SQL);
    db.exec(
      `INSERT INTO agents (agent_id, ${cols})
       SELECT lower(hex(randomblob(16))), ${cols} FROM agents_pre_rekey`,
    );
    db.exec("DROP TABLE agents_pre_rekey");
    db.exec("COMMIT");
  } catch (err) {
    try { db.exec("ROLLBACK"); } catch { /* the failing statement may have already aborted the txn */ }
    throw err;
  }
}

/**
 * Idempotent schema for the identity store. Called once at daemon init AND defensively by each
 * DbRegistrationPersistence constructor, so the store works whether or not the composition root has
 * run its own ensure. Creates the table on a fresh DB, re-keys a pre-REMOVE-001 table to the
 * stable-agent_id shape once, and (always) ensures the active-name partial unique index.
 */
export function ensureIdentitySchema(db: DaemonDatabase): void {
  const cols = db.prepare("PRAGMA table_info(agents)").all() as Array<{ name: string }>;
  if (cols.length === 0) {
    db.exec(CREATE_AGENTS_SQL);
  } else if (!cols.some((c) => c.name === "agent_id")) {
    // A pre-REMOVE-001 table exists (agent_name PK). Re-key it once to the stable-agent_id shape.
    rebuildAgentsToAgentIdPk(db);
  } else if (!cols.some((c) => c.name === "frost_directory_node_ids")) {
    // M8B quorum: additive column on an existing agent_id table (fresh/rebuilt tables already have it
    // via CREATE_AGENTS_SQL). Nullable → pre-quorum agents keep the full-roster fallback; no data touched.
    db.exec("ALTER TABLE agents ADD COLUMN frost_directory_node_ids TEXT");
  }
  db.exec(CREATE_ACTIVE_NAME_INDEX_SQL);
  db.exec(CREATE_TRUST_SIGNALS_SQL);
}

/**
 * CELLO-M8-TRUST-001: received trust signals — the daemon's local copy of a signal it pulled from the
 * directory pickup queue, opened (k_local), and HASH-VERIFIED against the directory anchor. Keyed by
 * signal_hash (the verification anchor) → storing the same signal twice is idempotent. The payload is
 * the recovered plaintext JSON — the ONLY plaintext copy of the signal (the server side holds only
 * the hash). In the encrypted SQLCipher DB.
 */
const CREATE_TRUST_SIGNALS_SQL = `
  CREATE TABLE IF NOT EXISTS trust_signals (
    signal_hash   TEXT PRIMARY KEY,
    agent_id      TEXT,
    signal_kind   TEXT NOT NULL,
    payload       BLOB NOT NULL,
    received_at   INTEGER NOT NULL
  );
`;

const toBuf = (b: Uint8Array): Buffer => Buffer.from(b);
const toBytes = (v: unknown): Uint8Array =>
  v instanceof Uint8Array ? new Uint8Array(v) : Buffer.isBuffer(v) ? new Uint8Array(v) : new Uint8Array(0);

/**
 * Row CRUD for the K_local identity — used by the agent-creation path (AC-004) and the DB-backed
 * agent loader (AC-007). Separate from the registration-persistence seam because it owns the
 * seed/lifecycle, not the registration material.
 */
export interface AgentRow {
  agentId: string;
  agentName: string;
  kLocalSeed: Uint8Array;
  kLocalPubkey: string;
  state: string;
}

export class DbIdentityStore {
  readonly #db: DaemonDatabase;
  readonly #logger: Logger;

  constructor(db: DaemonDatabase, logger: Logger) {
    this.#db = db;
    this.#logger = logger;
    ensureIdentitySchema(db);
  }

  /**
   * CELLO-M8-TRUST-001: store a received + verified trust signal. Idempotent on signal_hash (the same
   * signal delivered/pulled twice stores once). `payload` is the recovered plaintext JSON.
   */
  storeTrustSignal(args: { signalHash: string; agentId: string | null; signalKind: string; payload: Uint8Array }): void {
    this.#db
      .prepare(
        `INSERT OR IGNORE INTO trust_signals (signal_hash, agent_id, signal_kind, payload, received_at)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .run(args.signalHash, args.agentId, args.signalKind, toBuf(args.payload), Date.now());
  }

  /** Read a stored trust signal back by its hash anchor (TRUST-001 — proves local storage). */
  getTrustSignal(signalHash: string): { signalKind: string; payload: Uint8Array } | null {
    const row = this.#db
      .prepare("SELECT signal_kind, payload FROM trust_signals WHERE signal_hash = ?")
      .get(signalHash) as { signal_kind: string; payload: unknown } | undefined;
    return row ? { signalKind: row.signal_kind, payload: toBytes(row.payload) } : null;
  }

  /** True if an ACTIVE (non-retired) agent row with this name exists — the create-collision check. */
  hasActiveAgent(agentName: string): boolean {
    const row = this.#db
      .prepare("SELECT 1 AS one FROM agents WHERE agent_name = ? AND state != 'retired'")
      .get(agentName) as { one: number } | undefined;
    return row !== undefined;
  }

  /**
   * Create a new agent row holding a fresh K_local seed (AC-004), keyed by a freshly-minted stable
   * agent_id (REMOVE-001 DOD-REMOVE-1; guardrail #1). Explicit only — callers generate the seed
   * (crypto) and pass it in. Throws if an ACTIVE agent already holds the name (no silent overwrite); a
   * RETIRED row with the same name does NOT block — the name has been freed. Returns the new agent_id.
   */
  createAgent(agentName: string, kLocalSeed: Uint8Array, kLocalPubkeyHex: string): string {
    if (this.hasActiveAgent(agentName)) {
      throw new Error(`agent '${agentName}' already exists`);
    }
    const agentId = randomUUID();
    const now = Date.now();
    this.#db
      .prepare(
        `INSERT INTO agents (agent_id, agent_name, k_local_seed, k_local_pubkey, state, created_at, updated_at)
         VALUES (?, ?, ?, ?, 'created', ?, ?)`,
      )
      .run(agentId, agentName, toBuf(kLocalSeed), kLocalPubkeyHex, now, now);
    // SI-001: the seed is NEVER logged — only the agent name, the agent_id, and the PUBLIC key.
    this.#logger.info("persist.identity.created", { agentName, agentId, agentPubkey: kLocalPubkeyHex });
    return agentId;
  }

  /**
   * Retire (REMOVE-001 DOD-REMOVE-1): flip the ACTIVE row for `agentName` to state='retired' WITHOUT
   * deleting the row, its keys, or its history (SI-002 — accountability survives). One-way. The name
   * is freed (the partial unique index excludes retired rows). Returns the retired agent_id, or null if
   * there was no active agent with that name (fail-loud at the caller).
   */
  retireAgent(agentName: string): string | null {
    const active = this.#db
      .prepare("SELECT agent_id FROM agents WHERE agent_name = ? AND state != 'retired'")
      .get(agentName) as { agent_id: string } | undefined;
    if (!active) return null;
    const res = this.#db
      .prepare("UPDATE agents SET state = 'retired', updated_at = ? WHERE agent_id = ?")
      .run(Date.now(), active.agent_id);
    if (Number(res.changes) === 0) return null;
    return active.agent_id;
  }

  /**
   * Read the row to act on for a removal / directory-revocation re-push (REMOVE-001 DOD-REMOVE-2): the
   * ACTIVE row for the name if one exists (a fresh removal), else the MOST-RECENTLY-retired row (a
   * re-push of an already-retired agent whose directory revocation did not land — DB-001). Includes the
   * K_local seed (to re-sign the revocation) and the DIRECTORY-known reg_agent_id (what the directory is
   * asked to revoke; null if the agent was never registered). Returns null if no row with this name
   * exists at all.
   */
  getAgentForRevocation(
    agentName: string,
  ): { localAgentId: string; regAgentId: string | null; kLocalSeed: Uint8Array; state: string } | null {
    const r = this.#db
      .prepare(
        `SELECT agent_id, reg_agent_id, k_local_seed, state FROM agents WHERE agent_name = ?
         ORDER BY (state != 'retired') DESC, updated_at DESC LIMIT 1`,
      )
      .get(agentName) as { agent_id: string; reg_agent_id: string | null; k_local_seed: unknown; state: string } | undefined;
    if (!r) return null;
    return {
      localAgentId: r.agent_id,
      regAgentId: r.reg_agent_id ?? null,
      kLocalSeed: toBytes(r.k_local_seed),
      state: r.state,
    };
  }

  /**
   * Enumerate ACTIVE agents (agent_id + name + seed + pubkey + state) for the daemon's startup loader.
   * Retired rows are EXCLUDED — they must never be resurrected into the runtime — but remain in the DB
   * and are readable directly for accountability (SI-002).
   */
  listAgents(): AgentRow[] {
    const rows = this.#db
      .prepare(
        "SELECT agent_id, agent_name, k_local_seed, k_local_pubkey, state FROM agents WHERE state != 'retired' ORDER BY agent_name ASC",
      )
      .all() as Array<{ agent_id: string; agent_name: string; k_local_seed: unknown; k_local_pubkey: string; state: string }>;
    return rows.map((r) => ({
      agentId: r.agent_id,
      agentName: r.agent_name,
      kLocalSeed: toBytes(r.k_local_seed),
      kLocalPubkey: r.k_local_pubkey,
      state: r.state,
    }));
  }
}

/**
 * DB-backed `DaemonRegistrationPersistence`. Scoped to a single agent's row. All persist operations
 * are single-row UPSERTs that update the named agent's row; a register-success therefore implies the
 * material is durably committed (SI-003). A persist against a non-existent agent throws — the row is
 * created by the agent-creation path (AC-004) before registration runs.
 */
export class DbRegistrationPersistence implements DaemonRegistrationPersistence {
  readonly #db: DaemonDatabase;
  readonly #agentName: string;
  readonly #logger: Logger;

  constructor(opts: { db: DaemonDatabase; agentName: string; logger: Logger }) {
    this.#db = opts.db;
    this.#agentName = opts.agentName;
    this.#logger = opts.logger;
    ensureIdentitySchema(opts.db);
  }

  #updateRow(setClause: string, params: unknown[]): void {
    const now = Date.now();
    // REMOVE-001: target the ACTIVE row for this name. After name reuse a retired row and a new active
    // row can share a name; the partial unique index guarantees at most one active row, so this is
    // unambiguous. A retired identity's registration material is never mutated.
    const res = this.#db
      .prepare(`UPDATE agents SET ${setClause}, updated_at = ? WHERE agent_name = ? AND state != 'retired'`)
      .run(...params, now, this.#agentName);
    if (Number(res.changes) === 0) {
      // The agent row must exist (created by the agent-creation path before registration). A missing
      // row is a real fault, not something to paper over — fail loud so registration fails (AC-012).
      throw new Error(`identity_persist_failed: no agent row for '${this.#agentName}'`);
    }
  }

  async persistMlDsaKeypair(opts: { mlDsaPubkey: string; secretKeyBlob: Uint8Array }): Promise<void> {
    // SI-001: secretKeyBlob is written to the encrypted DB only — never logged.
    this.#updateRow("ml_dsa_pubkey = ?, ml_dsa_secret = ?, ml_dsa_algorithm = ?", [
      opts.mlDsaPubkey,
      toBuf(opts.secretKeyBlob),
      ML_DSA_ALGORITHM,
    ]);
    this.#logger.info("registration.mldsa.persisted", { mlDsaPubkey: opts.mlDsaPubkey });
  }

  async persistRegistrationState(opts: {
    agentId: string;
    primaryPubkey: string;
    mlDsaPubkey: string;
    registeredAt: number;
  }): Promise<void> {
    this.#updateRow(
      "reg_agent_id = ?, reg_primary_pubkey = ?, reg_ml_dsa_pubkey = ?, reg_registered_at = ?, reg_status = 'active', state = 'registered'",
      [opts.agentId, opts.primaryPubkey, opts.mlDsaPubkey, opts.registeredAt],
    );
    this.#logger.info("registration.state.persisted", {
      agentId: opts.agentId,
      primaryPubkey: opts.primaryPubkey,
    });
  }

  async persistFrostKeyShare(opts: {
    epochId: string;
    primaryPubkey: string;
    identifier: string;
    signingShare: Uint8Array;
    threshold: number;
    participants: number;
    commitmentsCbor: Uint8Array;
    verifyingSharesCbor: Uint8Array;
    dkgMethod: "trusted_dealer" | "network_dkg";
    /** M8B quorum: the directory nodeIds (Q) the DKG ran among; a restored signer targets these. */
    directoryNodeIds?: string[];
  }): Promise<void> {
    // SI-001: signingShare is written to the encrypted DB only — never logged.
    this.#updateRow(
      `frost_epoch_id = ?, frost_primary_pubkey = ?, frost_identifier = ?, frost_signing_share = ?,
       frost_threshold = ?, frost_participants = ?, frost_commitments = ?, frost_verifying_shares = ?,
       frost_dkg_method = ?, frost_directory_node_ids = ?`,
      [
        opts.epochId,
        opts.primaryPubkey,
        opts.identifier,
        toBuf(opts.signingShare),
        opts.threshold,
        opts.participants,
        toBuf(opts.commitmentsCbor),
        toBuf(opts.verifyingSharesCbor),
        opts.dkgMethod,
        opts.directoryNodeIds ? JSON.stringify(opts.directoryNodeIds) : null,
      ],
    );
    this.#logger.info("registration.frost.share.persisted", {
      epochId: opts.epochId,
      threshold: opts.threshold,
      participants: opts.participants,
      dkgMethod: opts.dkgMethod,
    });
  }

  async persistAgentUserLink(opts: { agentId: string; preAuthToken: string; linkedAt: number }): Promise<void> {
    // SI: the preAuthToken is a bearer ticket — written to the encrypted DB only, never logged.
    this.#updateRow("link_agent_id = ?, link_pre_auth_token = ?, link_linked_at = ?", [
      opts.agentId,
      opts.preAuthToken,
      opts.linkedAt,
    ]);
    this.#logger.info("registration.user_link.persisted", { agentId: opts.agentId });
  }

  // ─── Load (restart rehydration) ──────────────────────────────────────────────

  #row(): Record<string, unknown> | undefined {
    // REMOVE-001: load the ACTIVE row for this name (never a retired tombstone).
    return this.#db.prepare("SELECT * FROM agents WHERE agent_name = ? AND state != 'retired'").get(this.#agentName) as
      | Record<string, unknown>
      | undefined;
  }

  async loadRegistrationState(): Promise<RegistrationStateRecord | null> {
    const r = this.#row();
    if (!r || r["reg_agent_id"] == null) return null;
    return {
      agentId: String(r["reg_agent_id"]),
      primaryPubkey: String(r["reg_primary_pubkey"]),
      mlDsaPubkey: String(r["reg_ml_dsa_pubkey"]),
      registeredAt: Number(r["reg_registered_at"]),
      status: String(r["reg_status"]),
    };
  }

  async loadMlDsaKeypair(): Promise<MlDsaKeypairRecord | null> {
    const r = this.#row();
    if (!r || r["ml_dsa_secret"] == null) return null;
    return {
      mlDsaPubkey: String(r["ml_dsa_pubkey"]),
      secretKeyBlob: toBytes(r["ml_dsa_secret"]),
      algorithm: String(r["ml_dsa_algorithm"]),
    };
  }

  async loadActiveFrostKeyShare(): Promise<FrostKeyShareRecord | null> {
    const r = this.#row();
    if (!r || r["frost_signing_share"] == null) return null;
    // M8B quorum: the DKG's quorum Q (nodeIds). NULL for pre-quorum agents → undefined → seal falls
    // back to the full roster. Defensive parse: malformed data must not break share loading.
    let directoryNodeIds: string[] | undefined;
    const rawIds = r["frost_directory_node_ids"];
    if (rawIds != null) {
      try {
        const parsed = JSON.parse(String(rawIds)) as unknown;
        if (Array.isArray(parsed) && parsed.every((x) => typeof x === "string")) {
          directoryNodeIds = parsed as string[];
        }
      } catch { /* malformed → full-roster fallback */ }
    }
    return {
      epochId: String(r["frost_epoch_id"]),
      primaryPubkey: String(r["frost_primary_pubkey"]),
      identifier: String(r["frost_identifier"]),
      signingShare: toBytes(r["frost_signing_share"]),
      threshold: Number(r["frost_threshold"]),
      participants: Number(r["frost_participants"]),
      commitmentsCbor: toBytes(r["frost_commitments"]),
      verifyingSharesCbor: toBytes(r["frost_verifying_shares"]),
      dkgMethod: String(r["frost_dkg_method"]),
      directoryNodeIds,
    };
  }

  async loadAgentUserLink(): Promise<AgentUserLinkRecord | null> {
    const r = this.#row();
    if (!r || r["link_agent_id"] == null) return null;
    return {
      agentId: String(r["link_agent_id"]),
      preAuthToken: String(r["link_pre_auth_token"]),
      linkedAt: Number(r["link_linked_at"]),
    };
  }
}
