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
import { ML_DSA_ALGORITHM_LABEL } from "@cello-protocol/crypto";
import { MONIKER_RE, validateMoniker } from "@cello-protocol/protocol-types";
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";
import { checkChannelFacts } from "./registration-persistence.js";
import { extractErrorMessage } from "./error-message.js";
import type {
  DaemonRegistrationPersistence,
  RegistrationStateRecord,
  PqIdentityRecord,
  StoredPqIdentity,
  FrostKeyShareRecord,
  AgentUserLinkRecord,
} from "./registration-persistence.js";

const ML_DSA_ALGORITHM = ML_DSA_ALGORITHM_LABEL;

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
    -- ML-DSA-44 identity. ml_dsa_secret holds the 32-byte FIPS 204 SEED (M9D 002-PQKEYS), never the
    -- 2,560-byte expanded key. Written before register_request is sent; never regenerated.
    ml_dsa_pubkey          TEXT,
    ml_dsa_secret          BLOB,
    ml_dsa_algorithm       TEXT,
    -- M9D 002-PQKEYS: ML-KEM-768 identity — the 64-byte FIPS 203 seed and its public key. Same rules.
    ml_kem_seed            BLOB,
    ml_kem_pubkey          TEXT,
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
    -- actual share-holders, not the full live roster. NULL on the local single-node path.
    frost_directory_node_ids TEXT,
    -- Optional outbound-name override. The outbound name defaults to agent_name; this column only
    -- holds an explicit override. Local-only — never sent to the directory.
    moniker                TEXT,
    -- registration record.
    reg_agent_id           TEXT,
    reg_primary_pubkey     TEXT,
    reg_ml_dsa_pubkey      TEXT,
    -- M9D 002-PQKEYS: the ML-KEM public key the directory registered.
    reg_ml_kem_pubkey      TEXT,
    reg_registered_at      INTEGER,
    reg_status             TEXT,
    -- 038-KEYBIND: hex 64-byte Ed25519 signature by k_local_seed's public half over the v2 binding
    -- TBS naming all four keys (M9D 002-PQKEYS). Minted once at the tail of registration — the only
    -- moment both keys are on this machine together — and never re-derived by a second DKG.
    reg_key_binding        TEXT,
    -- M9D 002-PQKEYS: the ML-DSA half of the v2 binding (hex 2420 bytes), over the same TBS.
    reg_key_binding_pq     TEXT,
    -- M16: 1 when this identity is a broadcast channel (publish-only, never converses), with the
    -- hex pubkey of the agent that administers it. Written once, from the directory's echo at
    -- registration; nothing updates either column afterwards.
    channel                INTEGER NOT NULL DEFAULT 0,
    admin_pubkey           TEXT NOT NULL DEFAULT '',
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

/**
 * Schema for the identity store. Called once at daemon init AND defensively by each
 * DbRegistrationPersistence constructor, so the store works whether or not the composition root has
 * run its own ensure.
 */
export function ensureIdentitySchema(db: DaemonDatabase): void {
  db.exec(CREATE_AGENTS_SQL);
  db.exec(CREATE_ACTIVE_NAME_INDEX_SQL);
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
  /** M16: true when this identity is a broadcast channel. */
  channel: boolean;
  /** M16: hex pubkey of the administering agent; "" when `channel` is false. */
  adminPubkey: string;
  /** 'active' once registration completed; null for a created-but-unregistered agent. */
  regStatus: string | null;
  /** M9D 002-PQKEYS: the stored 32-byte ML-DSA seed, AS STORED (the loader judges its width). */
  mlDsaSeed: Uint8Array | null;
  /** M9D 002-PQKEYS: the stored 64-byte ML-KEM seed, AS STORED. */
  mlKemSeed: Uint8Array | null;
}

export class DbIdentityStore {
  readonly #db: DaemonDatabase;
  readonly #logger: Logger;

  constructor(db: DaemonDatabase, logger: Logger) {
    this.#db = db;
    this.#logger = logger;
    ensureIdentitySchema(db);
  }

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
        "SELECT agent_id, agent_name, k_local_seed, k_local_pubkey, state, channel, admin_pubkey, reg_status, ml_dsa_secret, ml_kem_seed FROM agents WHERE state != 'retired' ORDER BY agent_name ASC",
      )
      .all() as Array<{
        agent_id: string; agent_name: string; k_local_seed: unknown; k_local_pubkey: string; state: string;
        channel: number | bigint; admin_pubkey: string;
        reg_status: string | null; ml_dsa_secret: unknown; ml_kem_seed: unknown;
      }>;
    return rows.map((r) => ({
      agentId: r.agent_id,
      agentName: r.agent_name,
      kLocalSeed: toBytes(r.k_local_seed),
      kLocalPubkey: r.k_local_pubkey,
      state: r.state,
      channel: Number(r.channel) === 1,
      adminPubkey: r.admin_pubkey,
      regStatus: typeof r.reg_status === "string" ? r.reg_status : null,
      mlDsaSeed: r.ml_dsa_secret == null ? null : toBytes(r.ml_dsa_secret),
      mlKemSeed: r.ml_kem_seed == null ? null : toBytes(r.ml_kem_seed),
    }));
  }

  /**
   * M16: is the ACTIVE agent with this name a broadcast channel? False for an unknown agent: an
   * unknown agent is not a channel, and it is refused by the gates that require an agent at all.
   */
  isChannelAgent(agentName: string): boolean {
    const row = this.#db
      .prepare("SELECT channel FROM agents WHERE agent_name = ? AND state != 'retired'")
      .get(agentName) as { channel: number | bigint } | undefined;
    return row !== undefined && Number(row.channel) === 1;
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
 * M16: the "is this local agent a broadcast channel?" accessor, bound to the daemon's DB, for the
 * session openers and the inbound-assignment path. Each call reads the agent's row, so a channel
 * registered after startup is covered without a restart. Lives here rather than in the composition
 * root so `daemon.ts` does not grow.
 */
export function channelAgentLookup(
  sessionNodeManager: { getDb(): DaemonDatabase },
  logger: Logger,
): (agentName: string) => boolean {
  return (agentName) => new DbIdentityStore(sessionNodeManager.getDb(), logger).isChannelAgent(agentName);
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

  async persistPqIdentity(r: PqIdentityRecord): Promise<void> {
    // The seeds are written to the encrypted DB only — never logged. Two writes, ML-DSA first, so a
    // failure names the half that did not land.
    try {
      this.#updateRow("ml_dsa_pubkey = ?, ml_dsa_secret = ?, ml_dsa_algorithm = ?", [
        r.mlDsaPubkey, toBuf(r.mlDsaSeed), ML_DSA_ALGORITHM,
      ]);
    } catch (err: unknown) {
      throw new Error(`ml_dsa_persist_failed: ${extractErrorMessage(err)}`);
    }
    try {
      this.#updateRow("ml_kem_pubkey = ?, ml_kem_seed = ?", [r.mlKemPubkey, toBuf(r.mlKemSeed)]);
    } catch (err: unknown) {
      throw new Error(`ml_kem_persist_failed: ${extractErrorMessage(err)}`);
    }
    this.#logger.info("registration.pq_keys.persisted", {
      mlDsaPubkeyPrefix: r.mlDsaPubkey.slice(0, 16),
      mlKemPubkeyPrefix: r.mlKemPubkey.slice(0, 16),
    });
  }

  async persistRegistrationState(opts: {
    agentId: string;
    primaryPubkey: string;
    mlDsaPubkey: string;
    mlKemPubkey: string;
    registeredAt: number;
    keyBinding: string;
    keyBindingPq: string;
    channel?: boolean;
    adminPubkey?: string;
  }): Promise<void> {
    const { channel, adminPubkey } = checkChannelFacts(opts, await this.loadRegistrationState());
    this.#updateRow(
      "reg_agent_id = ?, reg_primary_pubkey = ?, reg_ml_dsa_pubkey = ?, reg_ml_kem_pubkey = ?, reg_registered_at = ?, reg_key_binding = ?, reg_key_binding_pq = ?, channel = ?, admin_pubkey = ?, reg_status = 'active', state = 'registered'",
      [
        opts.agentId, opts.primaryPubkey, opts.mlDsaPubkey, opts.mlKemPubkey, opts.registeredAt,
        opts.keyBinding, opts.keyBindingPq, channel ? 1 : 0, adminPubkey,
      ],
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
      mlKemPubkey: typeof r["reg_ml_kem_pubkey"] === "string" ? r["reg_ml_kem_pubkey"] : "",
      registeredAt: Number(r["reg_registered_at"]),
      status: String(r["reg_status"]),
      // 038-KEYBIND: registration always writes both; a missing value is a corrupt row, and
      // `String(null)` would hand callers the four characters "null" as if they were a signature.
      keyBinding: typeof r["reg_key_binding"] === "string" ? r["reg_key_binding"] : null,
      keyBindingPq: typeof r["reg_key_binding_pq"] === "string" ? r["reg_key_binding_pq"] : null,
      channel: Number(r["channel"]) === 1,
      adminPubkey: typeof r["admin_pubkey"] === "string" ? r["admin_pubkey"] : "",
    };
  }

  async loadPqIdentity(): Promise<StoredPqIdentity> {
    const r = this.#row();
    const str = (v: unknown): string | null => (typeof v === "string" ? v : null);
    return {
      mlDsaSeed: r && r["ml_dsa_secret"] != null ? toBytes(r["ml_dsa_secret"]) : null,
      mlDsaPubkey: r ? str(r["ml_dsa_pubkey"]) : null,
      mlKemSeed: r && r["ml_kem_seed"] != null ? toBytes(r["ml_kem_seed"]) : null,
      mlKemPubkey: r ? str(r["ml_kem_pubkey"]) : null,
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
