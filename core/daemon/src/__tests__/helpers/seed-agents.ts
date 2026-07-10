/**
 * DOD-AGENT-ID-JOINKEY-1 — test helper: give a SessionNodeManager's database the `agents` rows that
 * production always has.
 *
 * The seven session tables are keyed by the STABLE `agent_id`, and `SessionNodeManager` resolves an
 * agent NAME to that id against the `agents` table on every scoped query. In production the row is
 * always there: the daemon creates the agent (`cello_create_agent`) long before any session exists.
 *
 * Many unit tests predate that invariant and drove the manager with a bare name — `createSessionNode
 * ("alice", …)` against a database in which "alice" does not exist. That was never a reachable state;
 * the tests were relying on `WHERE agent_name = 'alice'` matching a string rather than an identity.
 * Seeding real agent rows makes them MORE production-faithful, not less: a manager scoped to an agent
 * that does not exist is exactly the condition `#requireAgentId` now refuses to silently absorb.
 *
 * The seed uses the real `DbIdentityStore.createAgent`, so each agent gets a genuine stable id and a
 * distinct K_local pubkey — never a hand-rolled INSERT that could drift from the production shape.
 */

import { randomBytes } from "node:crypto";
import { InMemoryKeyProvider } from "@cello-protocol/crypto";
import { DbIdentityStore, ensureIdentitySchema } from "../../db-identity-store.js";
import type { DaemonDatabase } from "../../sqlcipher-db.js";
import type { Logger } from "../../types.js";

const silentLogger: Logger = { debug() {}, info() {}, warn() {}, error() {} };

/**
 * Create one `agents` row per name, returning `name → agent_id`. Idempotent per name: an agent that
 * already exists (active) is left alone and its existing id returned.
 *
 * The stored `k_local_pubkey` is DERIVED from the stored seed, never invented. The daemon's agent
 * loader reads the seed and re-derives the key, so a row whose pubkey column disagrees with its seed
 * is not a shortcut — it is a corrupt identity that would surface as a baffling failure much later.
 */
export async function seedAgents(
  db: DaemonDatabase,
  names: readonly string[],
  logger: Logger = silentLogger,
): Promise<Map<string, string>> {
  ensureIdentitySchema(db);
  const store = new DbIdentityStore(db, logger);
  const ids = new Map<string, string>();
  for (const name of names) {
    const existing = db
      .prepare("SELECT agent_id FROM agents WHERE agent_name = ? AND state != 'retired'")
      .get(name) as { agent_id: string } | undefined;
    if (existing) {
      ids.set(name, existing.agent_id);
      continue;
    }
    // A real seed per agent — two agents must never share identity material — and the pubkey that
    // seed actually produces.
    const seed = new Uint8Array(randomBytes(32));
    const pubkeyHex = Buffer.from(await new InMemoryKeyProvider(seed).getPublicKey()).toString("hex");
    ids.set(name, store.createAgent(name, seed, pubkeyHex));
  }
  return ids;
}
