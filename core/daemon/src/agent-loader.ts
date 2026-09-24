/**
 * Agent identity loader for the CELLO daemon.
 *
 * Agents are enumerated from the encrypted `agents` table — ONE loading path. There is no flat-file
 * fallback: on-disk key files are imported into the `agents` table by the one-time migration
 * (identity-migration.ts) before this loader runs.
 *
 * Each agent's K_local Ed25519 seed is stored as a BLOB column; the loader builds a sign-only
 * InMemoryKeyProvider from it (the private scalar never leaves the provider — only signatures and
 * content-seal opens are emitted).
 */

import { InMemoryKeyProvider, mlDsaProviderFromSeed, ML_DSA_SEED_BYTES, ML_KEM_SEED_BYTES } from "@cello-protocol/crypto";
import type { KeyProvider, MlDsaKeyProvider } from "@cello-protocol/crypto";
import { DbIdentityStore } from "./db-identity-store.js";
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";
import { extractErrorMessage } from "./error-message.js";
import type { PqIdentity } from "./registration-manager.js";

export interface LoadedAgent {
  name: string;
  pubkey: string;
  /**
   * The agent's K_local signing key, retained so the daemon can produce K_local-signed control
   * leaves (e.g. the SEAL-INTERRUPTED leaf). The private scalar never leaves this provider.
   */
  keyProvider: KeyProvider;
  /**
   * M9D 002-PQKEYS: the agent's ML-DSA-44 key, loaded from its persisted 32-byte seed. Null ONLY for
   * an agent that has not registered yet — registration mints it. A REGISTERED agent without one is
   * never loaded (see `loadAgents`).
   */
  mlDsaProvider: MlDsaKeyProvider | null;
  /** M9D 002-PQKEYS: the agent's 64-byte ML-KEM-768 seed. Null only for an unregistered agent. */
  mlKemSeed: Uint8Array | null;
}

export interface FailedAgent {
  name: string;
  error: string;
  /** What the operator can do about it, when there is something to say. */
  remedy?: string;
}

/**
 * M9D 002-PQKEYS. Why a REGISTERED agent's post-quantum identity could not be loaded. The daemon never
 * generates a replacement: the directory holds this agent's public keys fixed for life, so a new seed
 * would be a key nobody else will ever accept.
 */
export type PqLoadRefusal = "ml_dsa_seed_missing" | "ml_dsa_seed_invalid" | "ml_kem_seed_missing" | "ml_kem_seed_invalid";

export const PQ_LOAD_REMEDY =
  "this identity cannot sign or decrypt post-quantum; register a new agent";

/** Judge a registered row's seeds. Returns the refusal, or null when both are the right width. */
function pqSeedsRefusal(mlDsaSeed: Uint8Array | null, mlKemSeed: Uint8Array | null): PqLoadRefusal | null {
  if (mlDsaSeed === null) return "ml_dsa_seed_missing";
  if (mlDsaSeed.length !== ML_DSA_SEED_BYTES) return "ml_dsa_seed_invalid";
  if (mlKemSeed === null) return "ml_kem_seed_missing";
  if (mlKemSeed.length !== ML_KEM_SEED_BYTES) return "ml_kem_seed_invalid";
  return null;
}

export interface AgentLoadResult {
  loaded: LoadedAgent[];
  failed: FailedAgent[];
}

/**
 * Load every agent from the encrypted `agents` table. A row whose seed is unusable (corrupt/wrong
 * length) is reported as a failed agent and skipped — never silently dropped.
 *
 * M9D 002-PQKEYS: a REGISTERED row (`reg_status = 'active'`) must also hold a 32-byte ML-DSA seed and a
 * 64-byte ML-KEM seed. One that does not is reported as failed, with the reason and remedy — never
 * loaded half-working, and no key is generated. An unregistered row is unaffected: registration
 * mints its keys.
 */
export async function loadAgents(db: DaemonDatabase, logger: Logger): Promise<AgentLoadResult> {
  const store = new DbIdentityStore(db, logger);
  const loaded: LoadedAgent[] = [];
  const failed: FailedAgent[] = [];

  for (const row of store.listAgents()) {
    try {
      const keyProvider = new InMemoryKeyProvider(row.kLocalSeed);
      const pubkey = Buffer.from(await keyProvider.getPublicKey()).toString("hex");
      if (row.regStatus !== "active") {
        loaded.push({ name: row.agentName, pubkey, keyProvider, mlDsaProvider: null, mlKemSeed: null });
        continue;
      }
      const refusal = pqSeedsRefusal(row.mlDsaSeed, row.mlKemSeed);
      if (refusal !== null) {
        logger.error("agent.load.failed", { agentName: row.agentName, error: refusal, remedy: PQ_LOAD_REMEDY });
        failed.push({ name: row.agentName, error: refusal, remedy: PQ_LOAD_REMEDY });
        continue;
      }
      const mlDsaProvider = await mlDsaProviderFromSeed(row.mlDsaSeed!);
      loaded.push({ name: row.agentName, pubkey, keyProvider, mlDsaProvider, mlKemSeed: row.mlKemSeed! });
    } catch (err: unknown) {
      const error = extractErrorMessage(err);
      logger.error("agent.load.failed", { agentName: row.agentName, error });
      failed.push({ name: row.agentName, error });
    }
  }

  return { loaded, failed };
}

/**
 * M9D 002-PQKEYS — each REGISTERED agent's post-quantum identity, keyed by agent name. A registered
 * agent without both seeds never reaches `loaded` (see `loadAgents`), so every registered agent is
 * here; an unregistered one is not until it registers. Later orders sign and decapsulate through this
 * map, and a registration in this run adds to it (register-handler.ts).
 */
export function buildPqIdentities(loaded: LoadedAgent[]): Map<string, PqIdentity> {
  const out = new Map<string, PqIdentity>();
  for (const a of loaded) {
    if (a.mlDsaProvider && a.mlKemSeed) out.set(a.name, { mlDsaProvider: a.mlDsaProvider, mlKemSeed: a.mlKemSeed });
  }
  return out;
}
