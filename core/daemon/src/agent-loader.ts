/**
 * Agent identity loader for the CELLO daemon.
 *
 * Pseudocode:
 * 1. loadAgents(celloDir, logger):
 *    a. Check if ~/.cello/agents/ exists
 *    b. If not, check if ~/.cello/key exists (legacy single-agent mode)
 *       - If legacy key exists, load it as agent 'default'
 *    c. If agents/ exists, enumerate subdirectories
 *       - For each subdir, check if a 'key' file exists
 *       - If yes, attempt to load it via FileKeyProvider.load()
 *       - If load fails (corrupt), log agent.load.failed and skip
 *       - Subdirectories without a 'key' file are silently skipped
 *    d. Return array of {name, pubkey} for successfully loaded agents
 *
 * Key file format: CELLO binary format (magic bytes + version + 32-byte Ed25519 seed)
 * See core/crypto/src/ed25519.ts FileKeyProvider.load() for the canonical parser.
 */

import { readdir, stat, access } from "node:fs/promises";
import { join } from "node:path";
import { FileKeyProvider } from "@cello-protocol/crypto";
import type { KeyProvider } from "@cello-protocol/crypto";
import type { Logger } from "./types.js";

export interface LoadedAgent {
  name: string;
  pubkey: string;
  /**
   * The agent's K_local signing key, retained so the daemon can produce
   * K_local-signed control leaves (e.g. the SEAL-INTERRUPTED leaf in the
   * seal-interrupted bilateral flow). The private scalar never leaves this
   * provider — only signatures are emitted.
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

export async function loadAgents(celloDir: string, logger: Logger): Promise<AgentLoadResult> {
  const agentsDir = join(celloDir, "agents");
  const loaded: LoadedAgent[] = [];
  const failed: FailedAgent[] = [];

  const agentsDirExists = await directoryExists(agentsDir);

  if (!agentsDirExists) {
    // Legacy backwards compat: if ~/.cello/key exists and ~/.cello/agents/ doesn't
    const legacyKeyPath = join(celloDir, "key");
    if (await fileExists(legacyKeyPath)) {
      const result = await loadSingleAgent("default", legacyKeyPath, logger);
      if (result.ok) {
        loaded.push(result.agent);
      } else {
        failed.push({ name: "default", error: result.error });
      }
    }
    return { loaded, failed };
  }

  // Enumerate subdirectories of agents/
  const entries = await readdir(agentsDir, { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;

    const keyPath = join(agentsDir, entry.name, "key");
    if (!(await fileExists(keyPath))) {
      continue;
    }

    const result = await loadSingleAgent(entry.name, keyPath, logger);
    if (result.ok) {
      loaded.push(result.agent);
    } else {
      failed.push({ name: entry.name, error: result.error });
    }
  }

  return { loaded, failed };
}

type LoadResult =
  | { ok: true; agent: LoadedAgent }
  | { ok: false; error: string };

async function loadSingleAgent(
  name: string,
  keyPath: string,
  logger: Logger,
): Promise<LoadResult> {
  try {
    const keyProvider = await FileKeyProvider.load(keyPath);
    const pubkeyBytes = await keyProvider.getPublicKey();
    const pubkey = Buffer.from(pubkeyBytes).toString("hex");
    return { ok: true, agent: { name, pubkey, keyProvider } };
  } catch (err: unknown) {
    const errorMsg = err instanceof Error ? err.message : String(err);
    logger.error("agent.load.failed", {
      agentName: name,
      error: errorMsg,
    });
    return { ok: false, error: errorMsg };
  }
}

async function directoryExists(path: string): Promise<boolean> {
  try {
    const s = await stat(path);
    return s.isDirectory();
  } catch {
    return false;
  }
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}
