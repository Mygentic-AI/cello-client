/**
 * DOD-M12B-SESSION-SEED-1 — a session node that is torn down must come back at the SAME peer id.
 *
 * WHY THE SESSION CANNOT COME BACK TODAY (traced 2026-08-17, and it is not what §5 first assumed):
 * `markInterruptedWithDetails` and `destroySessionNode` stop the node and delete it from
 * `#activeNodes`, and **nothing anywhere recreates one**. A rebuilt node would get a fresh random
 * keypair, so we could dial the counterparty but they could never dial us — the peer id they were
 * handed at establishment would be dead. That is the actual reason a laptop-close session is stuck,
 * and it is why the seed has to be per-session rather than per-agent.
 *
 * ANDRE'S TENET, 2026-08-18 — the constraint this unit is built against:
 *   *"No peer ID should be used for more than one session. If a session needs to be revived… it
 *   should be possible to revive that session on those peer IDs. But after that, those peer IDs and
 *   that peer connection needs to be shut down."*
 *
 * The recorded rationale for ephemeral ids is PRIVACY — `2026-04-11_1400_libp2p-dht-and-peer-
 * connectivity.md`: *"A passive observer… sees different Peer IDs for each session and cannot
 * correlate 'Agent X's session on Monday' with 'Agent X's session on Tuesday'."* A per-session seed
 * preserves that exactly: the id is stable WITHIN one session (which an observer already correlates
 * by watching the connection) and unlinkable ACROSS sessions.
 *
 * WHERE THE SEED COMES FROM, and why it is not minted at session creation. The responder's session
 * node is not created — the standing receiver is PROMOTED into it, and a fresh receiver is built
 * behind it. So the id the counterparty holds is the receiver's. The seed is therefore minted WITH
 * each standing receiver and becomes session-scoped at the moment of handoff; the replacement
 * receiver mints its own. No agent-wide identifier is ever created.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SessionNodeManager, type ISessionNodeFactory, type SessionNodeConfig } from "../session-node-manager.js";
import { FakeNode } from "./helpers/two-connection-fixture.js";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { seedAgents } from "./helpers/seed-agents.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { Logger } from "../types.js";

const silent: Logger = { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} };

/** Records the seed handed to every node it builds, in creation order. */
class RecordingFactory implements ISessionNodeFactory {
  readonly seeds: Array<Uint8Array | undefined> = [];
  readonly configs: SessionNodeConfig[] = [];
  async createNode(config: SessionNodeConfig): Promise<CelloNode> {
    this.configs.push(config);
    this.seeds.push(config.transportPrivateKey);
    return new FakeNode() as unknown as CelloNode;
  }
}

let tempDir: string;
let mgr: SessionNodeManager | undefined;
let factory: RecordingFactory;

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "cello-msg021-"));
  factory = new RecordingFactory();
  mgr = new SessionNodeManager({
    securityGateway: new PassthroughGatewayClient(),
    factory,
    logger: silent,
    dbPath: join(tempDir, "sessions.db"),
  });
  await mgr.initialize();
  await seedAgents(mgr.getDb(), ["alice"]);
});

afterEach(async () => {
  await mgr?.gracefulShutdown();
  mgr = undefined;
  await rm(tempDir, { recursive: true, force: true });
});


/** Create a session node the way the outbound path does, reusing the agent's standing receiver so
 *  the promotion (and therefore the seed handoff) is the thing under test. */
async function seedSession(m: SessionNodeManager, sessionId: string): Promise<void> {
  const res = await m.createSessionNode(
    sessionId,
    "alice",
    "bb".repeat(32),
    "12D3KooWFakeCounterpartyPeerIdForTestingOnly000000000000",
    "corr-session",
    true,
  );
  if (!res.ok) throw new Error(`createSessionNode failed: ${JSON.stringify(res)}`);
}

describe("DOD-M12B-SESSION-SEED-1: a session keeps its peer id across a teardown", () => {
  it("every standing receiver is built from a 32-byte seed we hold", async () => {
    // Without this the node's key is generated inside libp2p and is unrecoverable, so a rebuild can
    // never reproduce the id the counterparty was given.
    await mgr!.ensureStandingReceiverForAgent("alice");

    expect(factory.seeds.length, "the receiver was built").toBeGreaterThan(0);
    const seed = factory.seeds[0];
    expect(seed, "a node built with no seed has an id we cannot reproduce").toBeInstanceOf(Uint8Array);
    expect(seed!.length, "Ed25519 seed").toBe(32);
  });

  it("ONE PEER ID, ONE SESSION: a real PROMOTION releases the receiver and the replacement is fresh", async () => {
    // REWRITTEN after review. The first version never went through a promotion at all — it called
    // removeStandingReceiverForAgent + ensure, which is a different transition. Its bypass was
    // concrete: delete `this.#standingReceivers.delete(agentName)` from the promotion and the
    // receiver's seed stays in the map, so the NEXT session on that agent gets the SAME peer id —
    // AC1 broken outright — and the old test stayed green because it never touched that path.
    await mgr!.ensureStandingReceiverForAgent("alice");
    const promotedSeed = mgr!.getStandingReceiverSeedForTest("alice")!;
    expect(promotedSeed, "a receiver exists to be promoted").toBeInstanceOf(Uint8Array);

    await seedSession(mgr!, "31".repeat(32));

    // The promotion must have RELEASED the receiver, or the agent is still advertising the identity
    // it just gave away.
    expect(
      mgr!.getStandingReceiverSeedForTest("alice"),
      "the promoted receiver was not released — the next session would reuse this peer id",
    ).not.toEqual(promotedSeed);

    await mgr!.ensureStandingReceiverForAgent("alice");
    expect(
      mgr!.getStandingReceiverSeedForTest("alice"),
      "the replacement must mint its own identity",
    ).not.toEqual(promotedSeed);
  });

  it("ONE PEER ID, ONE SESSION: two consecutive sessions on one agent never share an identity", async () => {
    // The property AC1 actually states, asserted end to end rather than via the receiver slot.
    await mgr!.ensureStandingReceiverForAgent("alice");
    await seedSession(mgr!, "32".repeat(32));
    await mgr!.ensureStandingReceiverForAgent("alice");
    await seedSession(mgr!, "33".repeat(32));

    const seeds = factory.seeds.filter((x): x is Uint8Array => x !== undefined);
    const distinct = new Set(seeds.map((b) => Buffer.from(b).toString("hex")));
    expect(distinct.size, "every node built in this test must have its own identity").toBe(seeds.length);
  });

  it("AC2: the seed SURVIVES an interruption — that is the whole point of holding it", async () => {
    // The trap this pins: the obvious home for the seed is `ActiveSessionEntry`, and that entry is
    // deleted the instant a session is interrupted. Storing it there destroys the identity at
    // exactly the moment revival needs it, and every test that only checks a live session passes.
    await mgr!.ensureStandingReceiverForAgent("alice");
    const sid = "11".repeat(32);
    await seedSession(mgr!, sid);

    expect(mgr!.hasSessionSeedForTest("alice", sid), "held while active").toBe(true);
    await mgr!.markInterruptedWithDetails("alice", sid, 1, "stream_close");
    expect(
      mgr!.hasSessionSeedForTest("alice", sid),
      "an interrupted session that lost its identity can never be revived — it can only be sealed",
    ).toBe(true);
  });

  it("AC2: the seed DIES with the session, in the same step that writes the terminal status", async () => {
    // Andre 2026-08-18: revive if it must, "but after that, those peer IDs and that peer connection
    // needs to be shut down." Not on a later sweep — there must be no window where the row says the
    // session is over and the process can still bring its peer id back.
    await mgr!.ensureStandingReceiverForAgent("alice");
    const sid = "12".repeat(32);
    await seedSession(mgr!, sid);

    await mgr!.abandonSession("alice", sid);
    expect(
      mgr!.hasSessionSeedForTest("alice", sid),
      "a terminal session that can still be revived is the thing the tenet forbids",
    ).toBe(false);
  });

  it("AC2: the seed bytes are ZEROED, not merely dereferenced", async () => {
    // The threat model is a daemon reprogrammed on the operator's own machine, so "unreachable by
    // our code" is not the bar — anything in this process can read a live buffer. Dropping the map
    // entry leaves the bytes readable until GC decides otherwise.
    await mgr!.ensureStandingReceiverForAgent("alice");
    const sid = "13".repeat(32);
    await seedSession(mgr!, sid);
    const held = factory.seeds[0]!;
    expect(held.some((b) => b !== 0), "a seed of all zeros would make this test vacuous").toBe(true);

    await mgr!.abandonSession("alice", sid);
    expect(held.every((b) => b === 0), "the buffer we handed libp2p must not still hold key material").toBe(true);
  });

  it("F2: a RETIRED agent's session still loses its identity, even though the status write throws", async () => {
    // The first build destroyed the seed only after the UPDATE landed. `#requireAgentId` throws for
    // a retired agent, so every terminal write for a revoked agent fell into the catch and the seed
    // was held for the life of the process — an identity whose agent was just revoked in the
    // directory, with nothing reporting it, and REVIVAL-BOUND-1's sweep skips retired agents so
    // nothing else closed it either. Coupling a security teardown to a DB write is backwards: the
    // write can fail, and that is exactly when a live key must not be left lying around.
    await mgr!.ensureStandingReceiverForAgent("alice");
    const sid = "34".repeat(32);
    await seedSession(mgr!, sid);
    expect(mgr!.hasSessionSeedForTest("alice", sid)).toBe(true);

    mgr!.getDb().prepare("UPDATE agents SET state = 'retired' WHERE agent_name = 'alice'").run();
    // The teardown genuinely throws for a retired agent — that IS the condition under test. What
    // must not depend on it is the identity being destroyed.
    await mgr!.abandonSession("alice", sid).catch(() => { /* expected: agent_id_unresolved */ });

    expect(
      mgr!.hasSessionSeedForTest("alice", sid),
      "the status write cannot land for a retired agent — the identity must go regardless",
    ).toBe(false);
  });

  it("F3: seal_interrupted_pending destroys the identity — it is unrevivable AND unswept", async () => {
    // The first build grouped this status with `interrupted` as "a state revival exists for". It is
    // not: `ingestReceivedContent` refuses it, and BOTH sweeps that could close a session filter
    // `status = 'interrupted'`. So its identity was held until the process exited — and Entry 42's
    // measurement is that 59% of seals that start never finish, making this the common path.
    await mgr!.ensureStandingReceiverForAgent("alice");
    const sid = "35".repeat(32);
    await seedSession(mgr!, sid);

    const marked = mgr!.persistSealInterruptedCommitment({
      agentName: "alice",
      sessionId: sid,
      role: "initiator",
      ownLeaf: { kind: "seal" },
      counterpartyLeaf: { kind: "seal" },
      merkleRoot: "cc".repeat(32),
      nonce: "dd".repeat(16),
    });
    expect(marked, "the status write landed").toBe(true);

    expect(
      mgr!.hasSessionSeedForTest("alice", sid),
      "a session nothing can revive and nothing will sweep must not keep a live identity",
    ).toBe(false);
  });

  it("F5: shutdown zeroes every held identity — session and standing receiver alike", async () => {
    // `gracefulShutdown` clears `#trees` and `#receivedContent` because plaintext must not survive
    // shutdown in memory. Key material belongs in the same sentence — and shutdown marks active rows
    // interrupted by direct SQL, so no per-session destroy fires for them.
    await mgr!.ensureStandingReceiverForAgent("alice");
    const sid = "36".repeat(32);
    await seedSession(mgr!, sid);
    const sessionSeed = factory.seeds.find((x) => x !== undefined)!;
    await mgr!.ensureStandingReceiverForAgent("alice");
    const receiverSeed = mgr!.getStandingReceiverSeedForTest("alice")!;
    expect(receiverSeed.some((b) => b !== 0), "not vacuous").toBe(true);

    await mgr!.gracefulShutdown();
    mgr = undefined; // afterEach must not shut down twice

    expect(sessionSeed.every((b) => b === 0), "the session's identity survived shutdown in memory").toBe(true);
    expect(receiverSeed.every((b) => b === 0), "the receiver's identity survived shutdown in memory").toBe(true);
  });
});
