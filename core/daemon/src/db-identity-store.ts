/**
 * DB-backed identity store (the `agents` table).
 *
 * Every piece of an agent's persisted identity — the K_local Ed25519 seed, the ML-DSA keypair, the
 * FROST signing share, the registration record, and the agent↔user link — lives as ONE row of the
 * `agents` table in the SQLCipher-encrypted daemon DB. There is no flat-file home for any of it.
 *
 * `DbRegistrationPersistence` implements the `DaemonRegistrationPersistence` interface the daemon's
 * RegistrationManager and the ceremony/seal signer-reconstruction consume. Writes are AWAITED
 * single-row UPSERTs — never fire-and-forget — so a register-success implies a durably committed row.
 *
 * The K_local seed and FROST/ML-DSA secrets are stored as BLOB columns inside the encrypted DB; they
 * are NEVER written to a flat file and NEVER logged. The row is the only home.
 */

import { randomUUID } from "node:crypto";
import { MONIKER_RE, validateMoniker } from "@cello-protocol/protocol-types";
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
 * The `agents` schema. The store is keyed by a STABLE `agent_id`, never by `agent_name` — durable
 * identity hangs off agent_id; the human name and the pubkey are mutable ATTRIBUTES. A partial unique
 * index makes `agent_name` unique only among NON-retired rows, so removal (state='retired') frees the
 * name for reuse while the retired identity survives for accountability.
 * `state`: 'created' | 'registered' | 'retired'.
 */
const CREATE_AGENTS_SQL = `
  CREATE TABLE IF NOT EXISTS agents (
    agent_id               TEXT PRIMARY KEY,
    agent_name             TEXT NOT NULL,
    -- K_local Ed25519 identity: the seed lives ONLY in this BLOB, never on the filesystem.
    k_local_seed           BLOB NOT NULL,
    k_local_pubkey         TEXT NOT NULL,
    -- lifecycle: 'created' (K_local exists, not yet registered) | 'registered' | 'retired'.
    state                  TEXT NOT NULL DEFAULT 'created',
    -- ML-DSA keypair.
    ml_dsa_pubkey          TEXT,
    ml_dsa_secret          BLOB,
    ml_dsa_algorithm       TEXT,
    -- FROST signing share.
    frost_epoch_id         TEXT,
    frost_primary_pubkey   TEXT,
    frost_identifier       TEXT,
    frost_signing_share    BLOB,
    frost_threshold        INTEGER,
    frost_participants     INTEGER,
    frost_commitments      BLOB,
    frost_verifying_shares BLOB,
    frost_dkg_method       TEXT,
    -- JSON array of the directory nodeIds (Q) the DKG ran among, so a restored signer targets the
    -- actual share-holders, not the full live roster. NULL for agents registered before quorum DKG.
    frost_directory_node_ids TEXT,
    -- Optional outbound-name override. The outbound name defaults to agent_name; this column only
    -- holds an explicit override. Local-only — never sent to the directory.
    moniker                TEXT,
    -- registration record.
    reg_agent_id           TEXT,
    reg_primary_pubkey     TEXT,
    reg_ml_dsa_pubkey      TEXT,
    reg_registered_at      INTEGER,
    reg_status             TEXT,
    -- 038-KEYBIND: hex 64-byte Ed25519 signature by k_local_seed's public half over
    -- (k_local_pubkey, reg_primary_pubkey). Minted once at the tail of registration — the only
    -- moment both keys are on this machine together — and never re-derived by a second DKG.
    reg_key_binding        TEXT,
    -- agent↔user link captured at registration.
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

// The columns of the legacy `agents` table (agent_name PK, no agent_id), in order. Used to copy rows
// verbatim during the one-time re-key rebuild.
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
 * One-time re-key of a legacy `agents` table (PRIMARY KEY agent_name, no agent_id) to the stable
 * agent_id shape. Rebuilds the table, backfilling a fresh agent_id per existing row. Runs at most once
 * — `ensureIdentitySchema` guards it behind a column-presence check — and is wrapped in a transaction
 * so a crash mid-rebuild leaves the original table intact. Works on node:sqlite (in-memory test
 * handles) and SQLCipher alike.
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
 * run its own ensure. Creates the table on a fresh DB, re-keys a legacy table to the stable agent_id
 * shape once, and (always) ensures the active-name partial unique index.
 */
export function ensureIdentitySchema(db: DaemonDatabase): void {
  const cols = db.prepare("PRAGMA table_info(agents)").all() as Array<{ name: string }>;
  if (cols.length === 0) {
    db.exec(CREATE_AGENTS_SQL);
  } else if (!cols.some((c) => c.name === "agent_id")) {
    // A legacy table exists (agent_name PK). Re-key it once to the stable agent_id shape.
    rebuildAgentsToAgentIdPk(db);
  } else {
    // Additive columns on an existing agent_id table (fresh/rebuilt tables already have them via
    // CREATE_AGENTS_SQL). SQLite has no ADD COLUMN IF NOT EXISTS, so each is PRAGMA-guarded — and
    // each guard is an INDEPENDENT `if`: a table missing several must receive every ALTER.
    if (!cols.some((c) => c.name === "frost_directory_node_ids")) {
      // Nullable → agents predating quorum DKG keep the full-roster fallback; no data touched.
      db.exec("ALTER TABLE agents ADD COLUMN frost_directory_node_ids TEXT");
    }
    if (!cols.some((c) => c.name === "moniker")) {
      // Outbound-name override. Nullable → existing agents keep the agent-name default.
      db.exec("ALTER TABLE agents ADD COLUMN moniker TEXT");
    }
    if (!cols.some((c) => c.name === "reg_key_binding")) {
      // 038-KEYBIND. Nullable, because an operator's existing row cannot grow a signature by a
      // migration — the value is minted by the daemon holding the seed, on the next registration.
      // A null here is not tolerated at the protocol boundary: the directory refuses to serve an
      // assignment without a binding, so an agent with a null column re-registers to get one.
      db.exec("ALTER TABLE agents ADD COLUMN reg_key_binding TEXT");
    }
  }
  db.exec(CREATE_ACTIVE_NAME_INDEX_SQL);
  // M10-D18: DROP the M8 `trust_signals` scaffold. It held canonical-JSON records keyed by a RAW hash;
  // M10 wallet signals are canonical CBOR envelopes in `wallet_trust_signals` (TrustSignalStore),
  // re-derived via deliverWalletSignal. The M8 shape can't migrate (different hash + format) and is
  // re-mintable (D1), so the scaffold is dropped, not converted. IF EXISTS + no FK children → safe and
  // idempotent on both fresh and existing operator DBs. This is the forcing-function drop that MINT-
  // INTERNAL-1 owes; a test asserts the table is GONE.
  db.exec("DROP TABLE IF EXISTS trust_signals");
}

const toBuf = (b: Uint8Array): Buffer => Buffer.from(b);
const toBytes = (v: unknown): Uint8Array =>
  v instanceof Uint8Array ? new Uint8Array(v) : Buffer.isBuffer(v) ? new Uint8Array(v) : new Uint8Array(0);

/**
 * Row CRUD for the K_local identity — used by the agent-creation path and the DB-backed agent loader.
 * Separate from the registration-persistence seam because it owns the seed/lifecycle, not the
 * registration material.
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

  // M10-D18: `storeTrustSignal` / `getTrustSignal` (the M8 `trust_signals` writer + reader) are RETIRED.
  // A received wallet signal is now a canonical CBOR envelope, re-verified and stored in
  // `wallet_trust_signals` by `TrustSignalStore.deliverWalletSignal` (inbound-sessions). The M8 table is
  // dropped in `ensureIdentitySchema` above.

  /** True if an ACTIVE (non-retired) agent row with this name exists — the create-collision check. */
  hasActiveAgent(agentName: string): boolean {
    const row = this.#db
      .prepare("SELECT 1 AS one FROM agents WHERE agent_name = ? AND state != 'retired'")
      .get(agentName) as { one: number } | undefined;
    return row !== undefined;
  }

  /**
   * Create a new agent row holding a fresh K_local seed, keyed by a freshly-minted stable agent_id.
   * Explicit only — callers generate the seed (crypto) and pass it in. Throws if an ACTIVE agent
   * already holds the name (no silent overwrite); a RETIRED row with the same name does NOT block —
   * the name has been freed. Returns the new agent_id.
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
    // The seed is NEVER logged — only the agent name, the agent_id, and the PUBLIC key.
    this.#logger.info("persist.identity.created", { agentName, agentId, agentPubkey: kLocalPubkeyHex });
    return agentId;
  }

  /**
   * Retire: flip the ACTIVE row for `agentName` to state='retired' WITHOUT deleting the row, its keys,
   * or its history — accountability must survive a removal. One-way. The name is freed (the partial
   * unique index excludes retired rows). Returns the retired agent_id, or null if there was no active
   * agent with that name (fail-loud at the caller).
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
   * Read the row to act on for a removal / directory-revocation re-push: the ACTIVE row for the name if
   * one exists (a fresh removal), else the MOST-RECENTLY-retired row (a re-push of an already-retired
   * agent whose directory revocation did not land). Includes the
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
   * and are readable directly for accountability.
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

  /**
   * Set (or clear, via null) the outbound-name override on the ACTIVE row.
   * Returns false when no active agent holds the name (fail-loud at the caller — never a silent
   * no-op success). THROWS on an invalid moniker: callers validate first for a friendly error;
   * this is the backstop that makes "an invalid value can never be stored" true at the lowest layer.
   */
  setMoniker(agentName: string, moniker: string | null): boolean {
    if (moniker !== null && validateMoniker(moniker) === null) {
      throw new Error(`invalid moniker for agent '${agentName}': must match ${MONIKER_RE.source}`);
    }
    const res = this.#db
      .prepare("UPDATE agents SET moniker = ?, updated_at = ? WHERE agent_name = ? AND state != 'retired'")
      .run(moniker, Date.now(), agentName);
    return Number(res.changes) > 0;
  }

  /** The stored override for the ACTIVE agent, or null (no override / no such agent). */
  getMoniker(agentName: string): string | null {
    const row = this.#db
      .prepare("SELECT moniker FROM agents WHERE agent_name = ? AND state != 'retired'")
      .get(agentName) as { moniker: string | null } | undefined;
    return row?.moniker ?? null;
  }

  /**
   * The agent's outbound name — the override when set, else the agent name itself.
   * There is no separate "self-moniker" concept; the default is valid by construction (the agent
   * name already satisfies MONIKER_RE at creation). Null only when no active agent holds the name.
   */
  getOutboundName(agentName: string): string | null {
    const row = this.#db
      .prepare("SELECT agent_name, moniker FROM agents WHERE agent_name = ? AND state != 'retired'")
      .get(agentName) as { agent_name: string; moniker: string | null } | undefined;
    if (!row) return null;
    return row.moniker ?? row.agent_name;
  }
}

/**
 * DB-backed `DaemonRegistrationPersistence`. Scoped to a single agent's row. All persist operations
 * are single-row UPSERTs that update the named agent's row; a register-success therefore implies the
 * material is durably committed. A persist against a non-existent agent throws — the row is created by
 * the agent-creation path before registration runs.
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
    // Target the ACTIVE row for this name. After name reuse a retired row and a new active
    // row can share a name; the partial unique index guarantees at most one active row, so this is
    // unambiguous. A retired identity's registration material is never mutated.
    const res = this.#db
      .prepare(`UPDATE agents SET ${setClause}, updated_at = ? WHERE agent_name = ? AND state != 'retired'`)
      .run(...params, now, this.#agentName);
    if (Number(res.changes) === 0) {
      // The agent row must exist (created by the agent-creation path before registration). A missing
      // row is a real fault, not something to paper over — FAIL LOUD so registration fails.
      throw new Error(`identity_persist_failed: no agent row for '${this.#agentName}'`);
    }
  }

  async persistMlDsaKeypair(opts: { mlDsaPubkey: string; secretKeyBlob: Uint8Array }): Promise<void> {
    // secretKeyBlob is written to the encrypted DB only — never logged.
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
    keyBinding: string;
  }): Promise<void> {
    this.#updateRow(
      "reg_agent_id = ?, reg_primary_pubkey = ?, reg_ml_dsa_pubkey = ?, reg_registered_at = ?, reg_key_binding = ?, reg_status = 'active', state = 'registered'",
      [opts.agentId, opts.primaryPubkey, opts.mlDsaPubkey, opts.registeredAt, opts.keyBinding],
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
    /** The directory nodeIds (Q) the DKG ran among; a restored signer targets these. */
    directoryNodeIds?: string[];
  }): Promise<void> {
    // signingShare is written to the encrypted DB only — never logged.
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
    // The preAuthToken is a bearer ticket — written to the encrypted DB only, never logged.
    this.#updateRow("link_agent_id = ?, link_pre_auth_token = ?, link_linked_at = ?", [
      opts.agentId,
      opts.preAuthToken,
      opts.linkedAt,
    ]);
    this.#logger.info("registration.user_link.persisted", { agentId: opts.agentId });
  }

  // ─── Load (restart rehydration) ──────────────────────────────────────────────

  #row(): Record<string, unknown> | undefined {
    // Load the ACTIVE row for this name (never a retired tombstone).
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
      // 038-KEYBIND: null for a row written before this column existed. `String(null)` would hand
      // callers the four characters "null" as if they were a signature, which is why this is a
      // typeof check and not the String() every field above uses.
      keyBinding: typeof r["reg_key_binding"] === "string" ? r["reg_key_binding"] : null,
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
    // The DKG's quorum Q (nodeIds). NULL → undefined → the seal falls back to the full roster.
    // Defensive parse: malformed data must not break share loading.
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
