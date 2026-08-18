/**
 * DOD-M12B-SESSION-SEED-1 — the revival's relay-reservation race, which had NO coverage at all.
 *
 * Every other test in this family leaves `#reservationCircuitAddrs` empty, so only the plain-node
 * floor of `#buildRevivedNode` ever executed. The candidate loop — the entire subject of the commit
 * that introduced it — was untested, and that is precisely why review HIGH-3 was invisible: the
 * timed-out candidate's teardown was a no-op and nothing could see it.
 *
 * WHY THE LOOP EXISTS, measured live 2026-08-18 with two real agents:
 *   handed 2 relay addrs at once, no deadline:  start() NEVER completes (10,002ms and counting)
 *   handed none:                                start() in 1ms, but the node holds no circuit
 *                                               address and the counterparty cannot dial it
 *   one at a time, each raced against 3s:       granted in 2.5s with 5 circuit addresses
 *
 * A relay that has a slot answers well inside the deadline; one that does not never answers at all.
 * So the bound is not a performance tweak — it is the difference between a session that comes back
 * and one that hangs forever.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { SessionNodeManager, type ISessionNodeFactory, type SessionNodeConfig } from "../session-node-manager.js";
import { FakeNode } from "./helpers/two-connection-fixture.js";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { seedAgents } from "./helpers/seed-agents.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { Logger } from "../types.js";

const COUNTERPARTY_PEER = "12D3KooWFakeCounterpartyPeerIdForTestingOnly000000000000";
const RELAY_A = "12D3KooWRelayAAAA0000000000000000000000000000";
const RELAY_B = "12D3KooWRelayBBBB0000000000000000000000000000";
const CIRCUIT_A = `/ip4/10.0.0.1/tcp/4001/p2p/${RELAY_A}/p2p-circuit`;

interface Behaviour {
  /** ms until start() resolves, or "never" to model a relay that simply does not answer. */
  startAfterMs: number | "never";
  /** whether the node ends up advertising a circuit address — i.e. the relay actually granted. */
  grants: boolean;
}

/** A node whose start() timing and reservation outcome are scripted per relay. */
class ScriptedNode extends FakeNode {
  stopped = false;
  started = false;
  readonly #id: string;
  constructor(seed: Uint8Array | undefined, private readonly b: Behaviour, private readonly circuit: string | undefined) {
    super();
    this.#id = seed ? `12D3KooW${createHash("sha256").update(seed).digest("hex").slice(0, 40)}` : "random";
  }
  override getPeerId(): string { return this.#id; }
  override async start(): Promise<void> {
    if (this.b.startAfterMs === "never") {
      // A relay that never answers. The point of the deadline is that this promise never settles;
      // an unref'd handle keeps it from holding the process open.
      await new Promise<void>(() => { /* never */ });
      return;
    }
    await new Promise<void>((res) => { setTimeout(res, this.b.startAfterMs as number).unref?.(); });
    this.started = true;
  }
  /**
   * MODELS libp2p 3.3.2, which is the whole point of this fake.
   *
   *   `async stop() { if (this.status !== 'started') return; … }`
   *
   * A `stop()` issued while the node is still starting returns immediately and stops NOTHING. A fake
   * that always honours stop() cannot see review HIGH-3 at all — it reports the defect fixed whether
   * it is or not, which is how the first version of this test passed against the broken code.
   */
  override async stop(): Promise<void> {
    if (!this.started) return;
    this.stopped = true;
  }
  override listenAddresses(): string[] {
    return this.started && this.b.grants && this.circuit ? [this.circuit, "/ip4/127.0.0.1/tcp/1"] : ["/ip4/127.0.0.1/tcp/1"];
  }
}

class ScriptedFactory implements ISessionNodeFactory {
  readonly built: ScriptedNode[] = [];
  /** Every createNode call, tagged with its role — a standing-receiver rebuild can run in the same
   *  window as a revival and asks for circuit addresses too, so a raw count folds the two together. */
  readonly asks: Array<{ circuits: string[]; nodeType: string | undefined }> = [];
  constructor(private readonly script: (circuit: string | undefined) => Behaviour) {}
  async createNode(config: SessionNodeConfig): Promise<CelloNode> {
    const circuit = config.circuitRelayListenAddrs?.[0];
    this.asks.push({ circuits: config.circuitRelayListenAddrs ?? [], nodeType: config.nodeType });
    const node = new ScriptedNode(config.transportPrivateKey, this.script(circuit), circuit);
    this.built.push(node);
    return node as unknown as CelloNode;
  }
}

const silent: Logger = { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} };
let tempDir: string;
let mgr: SessionNodeManager | undefined;

async function makeManager(factory: ISessionNodeFactory): Promise<SessionNodeManager> {
  const m = new SessionNodeManager({
    securityGateway: new PassthroughGatewayClient(),
    factory,
    logger: silent,
    dbPath: join(tempDir, "sessions.db"),
  });
  await m.initialize();
  await seedAgents(m.getDb(), ["alice"]);
  m.setDirectoryRelayEndpoints("alice", [
    { relayPeerId: RELAY_A, relayAddrs: [`/ip4/10.0.0.1/tcp/4001/p2p/${RELAY_A}`] },
    { relayPeerId: RELAY_B, relayAddrs: [`/ip4/10.0.0.2/tcp/4001/p2p/${RELAY_B}`] },
  ]);
  return m;
}

async function openThenInterrupt(m: SessionNodeManager, sessionId: string): Promise<void> {
  await m.ensureStandingReceiverForAgent("alice");
  const res = await m.createSessionNode(sessionId, "alice", "bb".repeat(32), COUNTERPARTY_PEER, "corr", true);
  if (!res.ok) throw new Error(JSON.stringify(res));
  await m.destroySessionNode("alice", sessionId, "interrupted");
}

beforeEach(async () => { tempDir = await mkdtemp(join(tmpdir(), "cello-msg027-")); });
afterEach(async () => {
  await mgr?.gracefulShutdown();
  mgr = undefined;
  await rm(tempDir, { recursive: true, force: true });
});

describe("DOD-M12B-SESSION-SEED-1: the revival reservation race", () => {
  it("the FIRST relay that grants wins, and the second is never asked", async () => {
    const factory = new ScriptedFactory(() => ({ startAfterMs: 5, grants: true }));
    mgr = await makeManager(factory);
    const sid = "91".repeat(32);
    await openThenInterrupt(mgr, sid);
    const builtBefore = factory.built.length;

    const revived = await mgr.reviveSessionNode("alice", sid);

    expect(revived.ok, JSON.stringify(revived)).toBe(true);
    const duringRevival = factory.built.slice(builtBefore);
    expect(duringRevival.length, "a granting first candidate must end the loop — asking a second " +
      "relay burns a scarce reservation the first already gave us").toBe(1);
    expect(duringRevival[0]!.listenAddresses().some((a) => a.includes("/p2p-circuit"))).toBe(true);
  }, 30_000);

  it("a relay that NEVER answers does not hang the revival — it moves on and the session comes back", async () => {
    // The measured production failure: 10,002ms and still waiting. Without the per-candidate
    // deadline the revival never returns and every send on that session is refused forever.
    const factory = new ScriptedFactory((circuit) =>
      circuit === CIRCUIT_A ? { startAfterMs: "never", grants: false } : { startAfterMs: 5, grants: true });
    mgr = await makeManager(factory);
    const sid = "92".repeat(32);
    await openThenInterrupt(mgr, sid);

    const revived = await mgr.reviveSessionNode("alice", sid);

    expect(revived.ok, "a dead relay must not be able to hold a session down").toBe(true);
  }, 30_000);

  it("when NO relay grants, the session still comes back on the plain floor", async () => {
    // A session usable over the relay park route beats no session. This is the floor that stops a
    // bad relay day from making every interrupted session permanent.
    const factory = new ScriptedFactory(() => ({ startAfterMs: 2, grants: false }));
    mgr = await makeManager(factory);
    const sid = "93".repeat(32);
    await openThenInterrupt(mgr, sid);
    const builtBefore = factory.built.length;

    const askedBefore = factory.asks.length;
    const revived = await mgr.reviveSessionNode("alice", sid);

    expect(revived.ok).toBe(true);
    // Count what the LOOP asked for, not how many nodes exist — a standing-receiver rebuild can
    // build its own nodes in the same window, and a raw count folds the two together.
    const askedDuring = factory.asks.slice(askedBefore).filter((a) => a.nodeType === "session");
    const withCircuit = askedDuring.filter((a) => a.circuits.length > 0);
    expect(
      withCircuit.length,
      "the candidate cap is what stops a revival walking every relay it has ever seen and burning a " +
      "scarce reservation attempt on each",
    ).toBeLessThanOrEqual(2);
    expect(
      askedDuring.at(-1)?.circuits,
      "the last thing built is the plain floor — no circuit address, which is the honest degraded state",
    ).toEqual([]);
    const duringRevival = factory.built.slice(builtBefore);
    expect(
      duringRevival.at(-1)!.listenAddresses().some((a) => a.includes("/p2p-circuit")),
      "the floor advertises no circuit address",
    ).toBe(false);
  }, 30_000);

  it("REVIEW HIGH-3: a candidate that times out is STOPPED once its own start settles", async () => {
    /**
     * `libp2p.stop()` opens with `if (this.status !== 'started') return`, and through the whole
     * timeout window the status is `'starting'` — so the first build's `await candidate.stop()`
     * stopped nothing and waited for nothing. The abandoned `start()` stayed in flight, and a relay
     * answering late would bring that node LIVE on this session's own peer id, sharing the gater
     * (so it admits the counterparty) with no content handler and no reference left to stop it.
     *
     * That is the "open connection a malicious agent can farm for" the tenet forbids, arrived at by
     * accident. The teardown is now chained onto the candidate's own start promise.
     */
    const factory = new ScriptedFactory((circuit) =>
      // A grants LATE — after the 3s deadline has already moved us on.
      circuit === CIRCUIT_A ? { startAfterMs: 3_400, grants: true } : { startAfterMs: 5, grants: true });
    mgr = await makeManager(factory);
    const sid = "94".repeat(32);
    await openThenInterrupt(mgr, sid);
    const builtBefore = factory.built.length;

    const revived = await mgr.reviveSessionNode("alice", sid);
    expect(revived.ok).toBe(true);

    const lateCandidate = factory.built.slice(builtBefore)[0]!;
    // Give its start promise time to settle, which is when the teardown is chained to run.
    await new Promise((r) => setTimeout(r, 900));

    expect(
      lateCandidate.stopped,
      "a late-granting candidate that nobody holds a reference to is a live node on this session's " +
      "advertised peer id, with no content handler — an open endpoint we did not mean to leave",
    ).toBe(true);
  }, 30_000);
});
