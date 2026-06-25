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
 * Idempotent schema for the identity store. Called once at daemon init AND defensively by each
 * DbRegistrationPersistence constructor (CREATE TABLE IF NOT EXISTS is idempotent), so the store
 * works whether or not the composition root has run its own ensure.
 */
export function ensureIdentitySchema(db: DaemonDatabase): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS agents (
      agent_name             TEXT PRIMARY KEY,
      -- K_local Ed25519 identity (PERSIST-002: seed moves from agents/<name>/key into this BLOB).
      k_local_seed           BLOB NOT NULL,
      k_local_pubkey         TEXT NOT NULL,
      -- lifecycle: 'created' (K_local exists, not yet registered) | 'registered'.
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
  `);
}

const toBuf = (b: Uint8Array): Buffer => Buffer.from(b);
const toBytes = (v: unknown): Uint8Array =>
  v instanceof Uint8Array ? new Uint8Array(v) : Buffer.isBuffer(v) ? new Uint8Array(v) : new Uint8Array(0);

/**
 * Row CRUD for the K_local identity — used by the agent-creation path (AC-004) and the DB-backed
 * agent loader (AC-007). Separate from the registration-persistence seam because it owns the
 * seed/lifecycle, not the registration material.
 */
export interface AgentRow {
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

  /** True if an agent row with this name already exists. */
  hasAgent(agentName: string): boolean {
    const row = this.#db.prepare("SELECT 1 AS one FROM agents WHERE agent_name = ?").get(agentName) as
      | { one: number }
      | undefined;
    return row !== undefined;
  }

  /**
   * Create a new agent row holding a fresh K_local seed (AC-004). Explicit only — callers generate
   * the seed (crypto) and pass it in. Throws if the name already exists (no silent overwrite of an
   * identity).
   */
  createAgent(agentName: string, kLocalSeed: Uint8Array, kLocalPubkeyHex: string): void {
    if (this.hasAgent(agentName)) {
      throw new Error(`agent '${agentName}' already exists`);
    }
    const now = Date.now();
    this.#db
      .prepare(
        `INSERT INTO agents (agent_name, k_local_seed, k_local_pubkey, state, created_at, updated_at)
         VALUES (?, ?, ?, 'created', ?, ?)`,
      )
      .run(agentName, toBuf(kLocalSeed), kLocalPubkeyHex, now, now);
    // SI-001: the seed is NEVER logged — only the agent name and PUBLIC key.
    this.#logger.info("persist.identity.created", { agentName, agentPubkey: kLocalPubkeyHex });
  }

  /** Enumerate all agents (name + seed + pubkey + state) for the daemon's startup loader. */
  listAgents(): AgentRow[] {
    const rows = this.#db
      .prepare("SELECT agent_name, k_local_seed, k_local_pubkey, state FROM agents ORDER BY agent_name ASC")
      .all() as Array<{ agent_name: string; k_local_seed: unknown; k_local_pubkey: string; state: string }>;
    return rows.map((r) => ({
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
    const res = this.#db
      .prepare(`UPDATE agents SET ${setClause}, updated_at = ? WHERE agent_name = ?`)
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
  }): Promise<void> {
    // SI-001: signingShare is written to the encrypted DB only — never logged.
    this.#updateRow(
      `frost_epoch_id = ?, frost_primary_pubkey = ?, frost_identifier = ?, frost_signing_share = ?,
       frost_threshold = ?, frost_participants = ?, frost_commitments = ?, frost_verifying_shares = ?,
       frost_dkg_method = ?`,
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
    return this.#db.prepare("SELECT * FROM agents WHERE agent_name = ?").get(this.#agentName) as
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
