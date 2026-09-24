/**
 * TEST-ONLY exports. Reachable as `@cello-protocol/daemon/testing`, deliberately NOT from the
 * package barrel (DOD-M9B-WIRE-1).
 *
 * `DaemonConfig.securityGateway` is REQUIRED (INV-9), so every caller needs a way to satisfy it —
 * including a test that deliberately does not screen. That test says so by importing from here.
 * The daemon's own barrel stays free of an always-allow client.
 */
import { join } from "node:path";
import { mkdirSync } from "node:fs";
import { InMemoryKeyProvider, generateKLocalSeed } from "@cello-protocol/crypto";
import { openEncryptedDatabase, resolveDbKey, dbKeyPathFor } from "./sqlcipher-db.js";
import { DbIdentityStore } from "./db-identity-store.js";
import type { Logger } from "./types.js";

export { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };

/**
 * Create a LOCAL agent identity in the daemon database under `celloDir`, BEFORE the daemon starts —
 * the same row `cello create-agent` writes against a running daemon. The daemon loads it at boot.
 *
 * Idempotent: an agent that already exists is returned as it is, so a test can re-provision before
 * restarting the daemon on the same directory. Returns the agent's K_local key provider, for a test
 * that signs as the agent.
 */
export async function provisionAgentIdentity(celloDir: string, name: string): Promise<InMemoryKeyProvider> {
  mkdirSync(celloDir, { recursive: true });
  const dbPath = join(celloDir, "sessions.db");
  const db = openEncryptedDatabase(dbPath, resolveDbKey(dbPath, dbKeyPathFor(dbPath)));
  try {
    const store = new DbIdentityStore(db, silent);
    const existing = store.listAgents().find((a) => a.agentName === name);
    if (existing) return new InMemoryKeyProvider(existing.kLocalSeed);
    const seed = generateKLocalSeed();
    const keyProvider = new InMemoryKeyProvider(seed);
    const pubkeyHex = Buffer.from(await keyProvider.getPublicKey()).toString("hex");
    store.createAgent(name, seed, pubkeyHex);
    return keyProvider;
  } finally {
    db.close();
  }
}
