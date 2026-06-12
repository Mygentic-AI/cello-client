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
import type { Logger } from "./types.js";

export interface LoadedAgent {
  name: string;
  pubkey: string;
}

export async function loadAgents(celloDir: string, logger: Logger): Promise<LoadedAgent[]> {
  const agentsDir = join(celloDir, "agents");
  const agents: LoadedAgent[] = [];

  const agentsDirExists = await directoryExists(agentsDir);

  if (!agentsDirExists) {
    // Legacy backwards compat: if ~/.cello/key exists and ~/.cello/agents/ doesn't
    const legacyKeyPath = join(celloDir, "key");
    if (await fileExists(legacyKeyPath)) {
      const agent = await loadSingleAgent("default", legacyKeyPath, logger);
      if (agent) {
        agents.push(agent);
      }
    }
    return agents;
  }

  // Enumerate subdirectories of agents/
  const entries = await readdir(agentsDir, { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;

    const keyPath = join(agentsDir, entry.name, "key");
    if (!(await fileExists(keyPath))) {
      // Silently skip directories without a key file
      continue;
    }

    const agent = await loadSingleAgent(entry.name, keyPath, logger);
    if (agent) {
      agents.push(agent);
    }
  }

  return agents;
}

async function loadSingleAgent(
  name: string,
  keyPath: string,
  logger: Logger,
): Promise<LoadedAgent | null> {
  try {
    const keyProvider = await FileKeyProvider.load(keyPath);
    const pubkeyBytes = await keyProvider.getPublicKey();
    const pubkey = Buffer.from(pubkeyBytes).toString("hex");
    return { name, pubkey };
  } catch (err: unknown) {
    logger.error("agent.load.failed", {
      agentName: name,
      error: err instanceof Error ? err.message : String(err),
    });
    return null;
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
