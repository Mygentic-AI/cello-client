/**
 * Agent identity loader for the CELLO daemon.
 *
 * CELLO-M7-PERSIST-002 (AC-007): agents are enumerated from the encrypted `agents` table — ONE
 * loading path. The legacy flat-file paths (`~/.cello/agents/<name>/key` and the single-file
 * `~/.cello/key` "default" fallback) are gone; any pre-story key files are imported into the
 * `agents` table by the one-time migration (identity-migration.ts) before this loader runs.
 *
 * Each agent's K_local Ed25519 seed is stored as a BLOB column; the loader builds a sign-only
 * InMemoryKeyProvider from it (the private scalar never leaves the provider — only signatures and
 * content-seal opens are emitted).
 */

import { InMemoryKeyProvider } from "@cello-protocol/crypto";
import type { KeyProvider } from "@cello-protocol/crypto";
import { DbIdentityStore } from "./db-identity-store.js";
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";

export interface LoadedAgent {
  name: string;
  pubkey: string;
  /**
   * The agent's K_local signing key, retained so the daemon can produce K_local-signed control
   * leaves (e.g. the SEAL-INTERRUPTED leaf). The private scalar never leaves this provider.
   */
  keyProvider: KeyProvider;
}

export interface FailedAgent {
  name: string;
  error: string;
}

export interface AgentLoadResult {
  loaded: LoadedAgent[];
  failed: FailedAgent[];
}

/**
 * Load every agent from the encrypted `agents` table. A row whose seed is unusable (corrupt/wrong
 * length) is reported as a failed agent and skipped — never silently dropped.
 */
export async function loadAgents(db: DaemonDatabase, logger: Logger): Promise<AgentLoadResult> {
  const store = new DbIdentityStore(db, logger);
  const loaded: LoadedAgent[] = [];
  const failed: FailedAgent[] = [];

  for (const row of store.listAgents()) {
    try {
      const keyProvider = new InMemoryKeyProvider(row.kLocalSeed);
      const pubkey = Buffer.from(await keyProvider.getPublicKey()).toString("hex");
      loaded.push({ name: row.agentName, pubkey, keyProvider });
    } catch (err: unknown) {
      const error = err instanceof Error ? err.message : String(err);
      logger.error("agent.load.failed", { agentName: row.agentName, error });
      failed.push({ name: row.agentName, error });
    }
  }

  return { loaded, failed };
}
