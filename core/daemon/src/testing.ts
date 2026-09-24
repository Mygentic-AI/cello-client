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
import { createHash } from "node:crypto";
import { InMemoryKeyProvider, generateKLocalSeed, mlDsaProviderFromSeed, mlKemKeypairFromSeed, type MlDsaKeyProvider } from "@cello-protocol/crypto";
import { openEncryptedDatabase, resolveDbKey, dbKeyPathFor, type DaemonDatabase } from "./sqlcipher-db.js";
import { DbIdentityStore, DbRegistrationPersistence } from "./db-identity-store.js";
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
export async function provisionAgentIdentity(
  celloDir: string,
  name: string,
  /**
   * `true` (the default): the agent is REGISTERED with its fixture PQ keys, for a test that builds its
   * sessions from signed-assignment fixtures. `false`: a plain agent row, exactly what `cello
   * create-agent` writes, for a test that then registers it for real against a directory.
   */
  opts: { registered?: boolean } = {},
): Promise<InMemoryKeyProvider> {
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
    // M9D 003-PQSESSION: registered, with its fixture PQ keys — a session announce needs the ML-DSA key.
    if (opts.registered ?? true) await giveFixturePqIdentity(db, name, pubkeyHex);
    return keyProvider;
  } finally {
    db.close();
  }
}

/**
 * M9D — the deterministic post-quantum keys a TEST agent holds, derived from its K_local pubkey.
 *
 * Deterministic so a fixture that builds a signed assignment for an agent binds the very keys the
 * agent's daemon loads and signs with. Test-only: a real agent mints random seeds at registration.
 */
export async function fixturePqKeys(pubkeyHex: string): Promise<{
  mlDsaSeed: Uint8Array;
  mlDsaProvider: MlDsaKeyProvider;
  mlDsaPubkey: Uint8Array;
  mlKemSeed: Uint8Array;
  mlKemPubkey: Uint8Array;
}> {
  const hex = pubkeyHex.toLowerCase();
  const mlDsaSeed = new Uint8Array(createHash("sha256").update(`fixture-mldsa:${hex}`).digest());
  const mlKemSeed = new Uint8Array(createHash("sha512").update(`fixture-mlkem:${hex}`).digest());
  const mlDsaProvider = await mlDsaProviderFromSeed(mlDsaSeed);
  return {
    mlDsaSeed,
    mlDsaProvider,
    mlDsaPubkey: await mlDsaProvider.getPublicKey(),
    mlKemSeed,
    mlKemPubkey: (await mlKemKeypairFromSeed(mlKemSeed)).publicKey,
  };
}

/**
 * Make an agent row a REGISTERED one holding its fixture PQ keys, as registration leaves it — the
 * loader then hands out its ML-DSA provider, which signs every session announce.
 */
export async function giveFixturePqIdentity(db: DaemonDatabase, name: string, pubkeyHex: string): Promise<void> {
  const pq = await fixturePqKeys(pubkeyHex);
  await new DbRegistrationPersistence({ db, agentName: name, logger: silent }).persistPqIdentity({
    mlDsaSeed: pq.mlDsaSeed, mlDsaPubkey: Buffer.from(pq.mlDsaPubkey).toString("hex"),
    mlKemSeed: pq.mlKemSeed, mlKemPubkey: Buffer.from(pq.mlKemPubkey).toString("hex"),
  });
  db.prepare("UPDATE agents SET reg_status = 'active' WHERE agent_name = ? AND state != 'retired'").run(name);
}

/**
 * The counterparty keys a stub session negotiator reports for a TEST agent — the fixture keys that
 * agent really holds, so the ML-DSA signature on its session announce verifies (M9D 003-PQSESSION).
 */
export async function fixtureCounterpartyKeysHex(pubkeyHex: string): Promise<{ counterpartyPrimaryHex: string; counterpartyMlDsaHex: string; counterpartyMlKemHex: string }> {
  const pq = await fixturePqKeys(pubkeyHex);
  return {
    counterpartyPrimaryHex: "11".repeat(32),
    counterpartyMlDsaHex: Buffer.from(pq.mlDsaPubkey).toString("hex"),
    counterpartyMlKemHex: Buffer.from(pq.mlKemPubkey).toString("hex"),
  };
}
