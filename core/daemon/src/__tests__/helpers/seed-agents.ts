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
import type { KeyProvider, MlDsaKeyProvider } from "@cello-protocol/crypto";
import { loadAgents } from "../../agent-loader.js";
import { DbIdentityStore, ensureIdentitySchema } from "../../db-identity-store.js";
import { fixturePqKeys, registerFixturePqIdentity } from "../../testing.js";
import type { DaemonDatabase } from "../../sqlcipher-db.js";
import type { Logger } from "../../types.js";

const silentLogger: Logger = { debug() {}, info() {}, warn() {}, error() {} };

/** The two identities a seeded agent has, and they are NOT interchangeable — see `seedAgentKeys`. */
export interface SeededAgent {
  /** Device-local `randomUUID()`. Keys the session tables. NEVER appears in a hashed envelope. */
  agentId: string;
  /** The K_local Ed25519 public key, hex. This is what a trust-signal envelope's `subject` holds. */
  pubkeyHex: string;
}

/**
 * Create one `agents` row per name, returning `name → {agentId, pubkeyHex}`. Idempotent per name: an
 * agent that already exists (active) is left alone and its existing identities returned.
 *
 * The stored `k_local_pubkey` is DERIVED from the stored seed, never invented. The daemon's agent
 * loader reads the seed and re-derives the key, so a row whose pubkey column disagrees with its seed
 * is not a shortcut — it is a corrupt identity that would surface as a baffling failure much later.
 *
 * **Use `pubkeyHex` — not `agentId` — anywhere a trust-signal envelope's `subject` is being seeded**
 * (`DOD-END-SCOPE-FIX-1`). The two are different values with different lifetimes, and `agentId` is
 * device-local: the directory joins an agent-subject signal with
 * `JOIN agent_profiles ap ON ap.k_local_pubkey = sr.subject`, so a fixture that puts a UUID in
 * `subject` describes a row production never writes. A scoping predicate written against that
 * fixture goes green and matches ZERO production rows — silently un-presenting every agent-subject
 * signal. That trap was live in this file's consumers until 2026-07-29.
 */
export async function seedAgentKeys(
  db: DaemonDatabase,
  names: readonly string[],
  logger: Logger = silentLogger,
): Promise<Map<string, SeededAgent>> {
  ensureIdentitySchema(db);
  const store = new DbIdentityStore(db, logger);
  const agents = new Map<string, SeededAgent>();
  for (const name of names) {
    const existing = db
      .prepare("SELECT agent_id, k_local_pubkey FROM agents WHERE agent_name = ? AND state != 'retired'")
      .get(name) as { agent_id: string; k_local_pubkey: string } | undefined;
    if (existing) {
      agents.set(name, { agentId: existing.agent_id, pubkeyHex: existing.k_local_pubkey });
      continue;
    }
    // A real seed per agent — two agents must never share identity material — and the pubkey that
    // seed actually produces.
    const seed = new Uint8Array(randomBytes(32));
    const pubkeyHex = Buffer.from(await new InMemoryKeyProvider(seed).getPublicKey()).toString("hex");
    agents.set(name, { agentId: store.createAgent(name, seed, pubkeyHex), pubkeyHex });
    /**
     * M9D 003-PQSESSION: a session announce is signed by the agent's REGISTERED ML-DSA key, so a
     * seeded agent is a registered one: it holds the fixture PQ seeds — the same deterministic keys
     * `makeSignedAssignmentFrame` binds for this pubkey, so the counterparty's recorded key matches
     * the key that signs — and the loader hands out its ML-DSA provider.
     */
    await registerFixturePqIdentity(db, name, pubkeyHex);
  }
  return agents;
}

/**
 * `name → agent_id`, for the session-table callers that only ever need the stable id.
 *
 * A projection of `seedAgentKeys`, never a second implementation — one seeding path means the two
 * helpers cannot drift into disagreeing about an agent's identity.
 */
export async function seedAgents(
  db: DaemonDatabase,
  names: readonly string[],
  logger: Logger = silentLogger,
): Promise<Map<string, string>> {
  const agents = await seedAgentKeys(db, names, logger);
  return new Map([...agents].map(([name, a]) => [name, a.agentId]));
}

/**
 * Give a bare `SessionNodeManager` the key providers `startDaemon` always gives it.
 *
 * `DOD-M15-AUTHORSHIP-ABSENT-1` made this a precondition for SENDING: every content frame now
 * carries the sender's signature over its own Structure 1, so a manager with no way to sign cannot
 * put one on the wire and refuses the send by name. `startDaemon` wires this unconditionally
 * (`setKeyProviderResolver`, right after `loadAgents`), so a manager without it is a state
 * production never reaches — and a test in that state was silently exercising a refusal path.
 *
 * It calls the REAL `loadAgents`, from the REAL `agents` rows, so the key that signs in a test is
 * the key the daemon would have used. A hand-made provider here would let a fixture pass with a
 * signature by a key no counterparty could ever match.
 */
export async function wireAgentKeyProviders(
  mgr: {
    setKeyProviderResolver(resolve: (agentName: string) => KeyProvider | undefined): void;
    setMlDsaProviderResolver?(resolve: (agentName: string) => MlDsaKeyProvider | undefined): void;
  },
  db: DaemonDatabase,
  logger: Logger = silentLogger,
): Promise<void> {
  const { loaded } = await loadAgents(db, logger);
  const byName = new Map(loaded.map((a) => [a.name, a.keyProvider]));
  mgr.setKeyProviderResolver((agentName: string) => byName.get(agentName));
  // M9D 003-PQSESSION: the announce is signed by the agent's ML-DSA key too, as `boot-agents` wires it.
  const pqByName = new Map(loaded.map((a) => [a.name, a.mlDsaProvider ?? undefined]));
  mgr.setMlDsaProviderResolver?.((agentName: string) => pqByName.get(agentName));
}

/**
 * M9D 003-PQSESSION — record each side's counterparty PQ keys on a session a test built by hand.
 *
 * Production records them from the directory-signed assignment after verifying the v2 key binding.
 * A test that opens a session with `createSessionNode` / `acceptSession` never sees an assignment, so
 * without this every announce is refused `ephemeral_pq_peer_keys_unknown`. The keys are the fixture
 * keys the seeded agents actually hold (see `seedAgentKeys`).
 */
export async function recordFixtureCounterpartyKeys(
  sessionId: string,
  sides: Array<{ mgr: { recordCounterpartyKeys(a: string, sid: string, k: { primaryHex: string; mlDsaHex: string; mlKemHex: string }): void }; agentName: string; pubkeyHex: string }>,
): Promise<void> {
  const [a, b] = sides;
  if (!a || !b) throw new Error("recordFixtureCounterpartyKeys needs two sides");
  for (const [self, peer] of [[a, b], [b, a]] as const) {
    const pq = await fixturePqKeys(peer.pubkeyHex);
    self.mgr.recordCounterpartyKeys(self.agentName, sessionId, {
      primaryHex: "00".repeat(32),
      mlDsaHex: Buffer.from(pq.mlDsaPubkey).toString("hex"),
      mlKemHex: Buffer.from(pq.mlKemPubkey).toString("hex"),
    });
  }
}

interface EphemeralCarrier {
  signOwnEphemeralForTest(agentName: string, sessionId: string): Promise<import("@cello-protocol/crypto").SessionKeyAgreementFields | null>;
  handleEphemeralFrameForTest(agentName: string, sessionId: string, frame: import("@cello-protocol/crypto").SessionKeyAgreementFields, correlationId?: string): Promise<void>;
  contentEncryptionStateForTest(agentName: string, sessionId: string): { key: Uint8Array | null };
}

/**
 * M9D 003-PQSESSION — carry each side's signed announce to the other by hand until BOTH hold the
 * agreed key, for harnesses whose link carries no announce on its own.
 *
 * Needs up to three hops, not one: both halves cross once, then the encapsulator (whichever side's
 * X25519 key sorts lower — random per run) re-announces WITH its ciphertext, and only then can the
 * other side derive. Carrying one half one way agreed a key only when the draw happened to favour it.
 * Every hop runs the REAL verification and derivation.
 */
export async function carryEphemeralsUntilAgreed(
  sessionId: string,
  a: { mgr: EphemeralCarrier; agentName: string },
  b: { mgr: EphemeralCarrier; agentName: string },
): Promise<void> {
  for (let hop = 0; hop < 3; hop++) {
    for (const [from, to] of [[a, b], [b, a]] as const) {
      const half = await from.mgr.signOwnEphemeralForTest(from.agentName, sessionId);
      if (!half) throw new Error(`carryEphemeralsUntilAgreed: ${from.agentName} could not sign its half`);
      await to.mgr.handleEphemeralFrameForTest(to.agentName, sessionId, half);
    }
    if (a.mgr.contentEncryptionStateForTest(a.agentName, sessionId).key && b.mgr.contentEncryptionStateForTest(b.agentName, sessionId).key) return;
  }
  throw new Error("carryEphemeralsUntilAgreed: the two sides did not agree a key");
}

/**
 * One side of `recordFixtureCounterpartyKeys`: record, on `agentName`'s session, the fixture PQ keys
 * the counterparty `peerPubkeyHex` holds. Call it right after `createSessionNode` / `acceptSession`,
 * which is where production records them from the verified assignment.
 */
export async function recordFixtureKeysFor(
  mgr: { recordCounterpartyKeys(a: string, sid: string, k: { primaryHex: string; mlDsaHex: string; mlKemHex: string }): void },
  agentName: string,
  sessionId: string,
  peerPubkeyHex: string,
): Promise<void> {
  const pq = await fixturePqKeys(peerPubkeyHex);
  mgr.recordCounterpartyKeys(agentName, sessionId, {
    primaryHex: "00".repeat(32),
    mlDsaHex: Buffer.from(pq.mlDsaPubkey).toString("hex"),
    mlKemHex: Buffer.from(pq.mlKemPubkey).toString("hex"),
  });
}
