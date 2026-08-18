/**
 * DOD-M12B-SESSION-SEED-1 (second half) — rebuild the node, and take the session back to `active`.
 *
 * The first half made the identity RECOVERABLE. Nothing recovers it yet: `markInterruptedWithDetails`
 * and `destroySessionNode` stop the node and delete it from `#activeNodes`, and **no code path
 * anywhere recreates one**. So a laptop-close session stays stuck even though both parties are
 * healthy and both peer ids are still valid — which is the actual finding of the 2026-08-17 trace.
 *
 * TWO EDGES, and today neither exists:
 *   1. `session_node_unavailable` — the node is gone; rebuild it from the held seed.
 *   2. `session_not_active` — the STATUS is `interrupted`; nothing has ever moved a session back to
 *      `active`. A transport event can take a session out of `active`, and there is no reverse.
 *
 * ANDRE'S CONSTRAINTS (2026-08-18 tenet + the REDIAL-1 discipline):
 *   - **Demand-driven, never a timer.** Nothing may re-open on its own; the operator sending is what
 *     revives a session. A background rebuilder is precisely the "open connection a malicious agent
 *     can farm for" that the tenet forbids.
 *   - **Terminal is terminal.** A sealed or abandoned session has no seed and must never come back,
 *     however it is asked.
 *   - **Same peer id, or the rebuild is pointless** — the counterparty holds the old one, and
 *     libp2p connections are bidirectional only if both ids still resolve.
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

const silent: Logger = { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} };
const COUNTERPARTY_PEER = "12D3KooWFakeCounterpartyPeerIdForTestingOnly000000000000";

/**
 * A node whose peer id is DERIVED FROM ITS SEED, modelling the real transport.
 *
 * `msg-021-seed-determinism` proves the real `createNode` behaves this way against libp2p; this is
 * the cheap stand-in that lets the manager's rebuild logic be tested without standing up libp2p.
 * A FakeNode with a random id would make "came back at the same peer id" untestable — and passing
 * for the wrong reason is the failure mode this whole file exists to rule out.
 */
class SeededNode extends FakeNode {
  readonly #id: string;
  constructor(seed: Uint8Array | undefined) {
    super();
    this.#id = seed
      ? `12D3KooW${createHash("sha256").update(seed).digest("hex").slice(0, 40)}`
      : `random-${Math.random().toString(36).slice(2)}`;
  }
  override getPeerId(): string { return this.#id; }
}

class SeedDerivedFactory implements ISessionNodeFactory {
  readonly built: Array<{ config: SessionNodeConfig; node: SeededNode }> = [];
  async createNode(config: SessionNodeConfig): Promise<CelloNode> {
    const node = new SeededNode(config.transportPrivateKey);
    this.built.push({ config, node });
    return node as unknown as CelloNode;
  }
}

let tempDir: string;
let mgr: SessionNodeManager | undefined;
let factory: SeedDerivedFactory;

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "cello-msg022-"));
  factory = new SeedDerivedFactory();
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

async function openSession(sessionId: string): Promise<string> {
  await mgr!.ensureStandingReceiverForAgent("alice");
  const res = await mgr!.createSessionNode(sessionId, "alice", "bb".repeat(32), COUNTERPARTY_PEER, "corr", true);
  if (!res.ok) throw new Error(`createSessionNode failed: ${JSON.stringify(res)}`);
  return mgr!.getSessionNodePeerId("alice", sessionId)!;
}

function statusOf(sessionId: string): string {
  const row = mgr!.getDb().prepare("SELECT status FROM sessions WHERE session_id = ?").get(sessionId) as { status: string };
  return row.status;
}

describe("DOD-M12B-SESSION-SEED-1: an interrupted session can be revived on its own peer id", () => {
  it("rebuilds the torn-down node at the SAME peer id the counterparty holds", async () => {
    const sid = "21".repeat(32);
    const originalPeerId = await openSession(sid);
    await mgr!.markInterruptedWithDetails("alice", sid, 1, "stream_close");
    expect(mgr!.getSessionNodePeerId("alice", sid), "the node really is gone").toBeNull();

    const revived = await mgr!.reviveSessionNode("alice", sid);

    expect(revived.ok, JSON.stringify(revived)).toBe(true);
    expect(
      mgr!.getSessionNodePeerId("alice", sid),
      "a rebuilt node with a fresh key can dial them, but they can never dial back — the id they " +
      "were handed at establishment would be dead",
    ).toBe(originalPeerId);
  });

  it("THE REVERSE EDGE: the session goes interrupted → active", async () => {
    // A transport event can take a session out of `active`, and today there is no path back. Without
    // this the node is rebuilt and every send still refuses with `session_not_active`.
    const sid = "22".repeat(32);
    await openSession(sid);
    await mgr!.markInterruptedWithDetails("alice", sid, 1, "stream_close");
    expect(statusOf(sid)).toBe("interrupted");

    await mgr!.reviveSessionNode("alice", sid);

    expect(statusOf(sid), "a rebuilt node behind an interrupted row is still a stuck session").toBe("active");
  });

  it("a TERMINAL session is never revived — its identity was destroyed with it", async () => {
    // Andre's tenet: revive if it must, then shut down. `abandonSession` zeroes the seed in the same
    // step that writes the status, so there is nothing to come back on — and the refusal must say so
    // rather than silently minting a NEW identity, which would hand the session a second peer id.
    const sid = "23".repeat(32);
    await openSession(sid);
    await mgr!.abandonSession("alice", sid);

    const revived = await mgr!.reviveSessionNode("alice", sid);

    expect(revived.ok).toBe(false);
    expect(revived.ok === false && revived.reason).toBe("session_terminal");
    expect(statusOf(sid), "the revival attempt must not resurrect the row either").toBe("abandoned");
  });

  it("ONE PEER ID, ONE SESSION survives a revival — no second identity is ever minted", async () => {
    // The tenet allows revival ON THE EXISTING ids and forbids anything beyond it. A revive that
    // quietly minted a fresh seed would satisfy "the session works again" while breaking the rule.
    const sid = "24".repeat(32);
    const originalPeerId = await openSession(sid);
    const seedsBefore = factory.built.filter((b) => b.config.transportPrivateKey !== undefined).length;

    await mgr!.markInterruptedWithDetails("alice", sid, 1, "stream_close");
    await mgr!.reviveSessionNode("alice", sid);
    await mgr!.markInterruptedWithDetails("alice", sid, 1, "stream_close");
    await mgr!.reviveSessionNode("alice", sid);

    expect(mgr!.getSessionNodePeerId("alice", sid), "twice revived, still the one identity").toBe(originalPeerId);
    const distinctSeeds = new Set(
      factory.built
        .filter((b) => b.config.transportPrivateKey !== undefined)
        .map((b) => Buffer.from(b.config.transportPrivateKey!).toString("hex")),
    );
    // The receiver's seed, plus its replacement's. Two revivals must add NOTHING to that set.
    expect(distinctSeeds.size, `built ${factory.built.length}, seeded ${seedsBefore} before revival`).toBe(2);
  });

  it("DEMAND-DRIVEN: an interrupted session is not revived by the passage of time alone", async () => {
    // The REDIAL-1 discipline, and the tenet's core: nothing may re-open on its own. A background
    // rebuilder would hold a dialable endpoint open for a session nobody is using — exactly the
    // "open connection a malicious agent can farm for".
    const sid = "25".repeat(32);
    await openSession(sid);
    await mgr!.markInterruptedWithDetails("alice", sid, 1, "stream_close");
    const builtAtInterrupt = factory.built.length;

    await new Promise((r) => setTimeout(r, 250));

    expect(factory.built.length, "something rebuilt a node with nobody asking").toBe(builtAtInterrupt);
    expect(statusOf(sid), "and nothing moved the status on its own either").toBe("interrupted");
  });

  it("MEASURED LIVE: a revived session keeps the addresses it needs to DIAL the counterparty", async () => {
    /**
     * 2026-08-18, live, with two real agents. The rebuild succeeded in 1ms and the very next send
     * failed and was LOST — not parked, lost:
     *
     *   09:02:17.448  session.revived
     *   09:02:17.449  session.content.direct.send.failed   error: "[object Object]"
     *   09:02:17.449  session.content.send.failed          reason: session_stream_unavailable
     *
     * `#evictSessionCaches` clears `#counterpartyAddrs` on every teardown — including the
     * interruption a revival exists to undo. So the node came back, went `active`, and had nowhere
     * to send: the re-dial's own guard says it plainly, *"this side holds no address for the
     * counterparty."* A session that is active and cannot speak is worse than one that admits it is
     * broken, because the operator's message is accepted and then discarded.
     *
     * The addresses now ride in the revival record, which has exactly the right lifetime: it dies
     * when the session reaches a terminal status.
     */
    const sid = "26".repeat(32);
    await openSession(sid);
    const addrs = ["/ip4/10.0.0.7/tcp/4001/p2p/12D3KooWCounterpartyAddressForTest0000000000"];
    mgr!.setCounterpartyAddrsForTest("alice", sid, addrs);

    // `destroySessionNode` is the path that runs `#evictSessionCaches`, which is where the addresses
    // were being dropped. Driving the interruption through it is what makes this test the live case
    // rather than a nearby one.
    await mgr!.destroySessionNode("alice", sid, "interrupted");
    await mgr!.reviveSessionNode("alice", sid);

    expect(
      mgr!.getCounterpartyAddrsForTest("alice", sid),
      "revived with no way to dial them: the next send fails on a connection that was never made, " +
      "and it is discarded rather than parked",
    ).toEqual(addrs);
  }, 60_000);

  it("MEASURED LIVE x5: a revived session can still PARK — otherwise every failed send is 'lost'", async () => {
    /**
     * THE DEFECT BEHIND FIVE IDENTICAL LIVE FAILURES, 2026-08-18. After an offline/online cycle the
     * counterparty's reply came back:
     *
     *   {"ok":false,"reason":"session_stream_unavailable",
     *    "guidance":"Direct delivery failed and the message could NOT be queued for retry — it is
     *                lost. Send it again."}
     *
     * `#parkContent` opens with
     *   `if (!hook || !entry || !entry.relayPeerId || !entry.relayAddrs) return "unconfigured"`
     * and the revived entry carried no relay — so the park was skipped and the send fell through to
     * the lost path. The relay was on the session ROW the whole time, and store-and-forward
     * delivered the other side's messages through it in the same minute.
     *
     * The operator's reply was accepted, discarded, and they were told to retype it. That is how a
     * transcript gets duplicates of a message that was never lost.
     *
     * Revert test (RUN): drop the `persistedRelay` spread from the revived entry and this fails.
     */
    const sid = "27".repeat(32);
    await openSession(sid);
    // What the relay assignment writes, and what every send afterwards depends on.
    mgr!.getDb().prepare("UPDATE sessions SET relay_peer_id = ?, relay_addrs = ? WHERE session_id = ?")
      .run("12D3KooWRelayForTest00000000000000000000000000", JSON.stringify(["/ip4/1.2.3.4/tcp/4001"]), sid);

    await mgr!.destroySessionNode("alice", sid, "interrupted");
    await mgr!.reviveSessionNode("alice", sid);

    expect(
      mgr!.getSessionRelayForTest("alice", sid),
      "revived with no relay: the park is skipped and the operator is told their message is lost, " +
      "while the relay that would have delivered it sits recorded on the row",
    ).toEqual({ relayPeerId: "12D3KooWRelayForTest00000000000000000000000000", relayAddrs: ["/ip4/1.2.3.4/tcp/4001"] });
  }, 60_000);

  /**
   * DOD-M12B-REVIVE-RELAY-1 — THE PRINCIPLE: a revived session must be indistinguishable from a
   * fresh one.
   *
   * Every symptom chased separately over six live rounds on 2026-08-18 — doorbells not firing, a
   * three-minute delivery against seconds, sends that could not park — was one consequence of
   * revival doing four of establishment's five steps.
   *
   * REWRITTEN AFTER REVIEW. The first version matched five hardcoded strings against revival's own
   * source and claimed *"if establishment gains a sixth step, this fails until revival takes it
   * too."* That was false: it never read establishment at all. It also passed while the fifth step
   * — `client.connect(node)` — was still missing, which is the exact defect the commit was named
   * after.
   *
   * This derives the step list from ESTABLISHMENT instead, so it cannot go stale, and requires each
   * step to appear in revival unless it is on a written exemption list with a reason.
   */
  it("PARITY: every call establishment makes, revival makes too", async () => {
    const { readFileSync } = await import("node:fs");
    const src = readFileSync(join(import.meta.dirname, "..", "session-node-manager.ts"), "utf-8");
    const code = src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");

    const region = (from: string, to: string): string => {
      const a = code.indexOf(from);
      const b = code.indexOf(to, a);
      expect(a, `region start not found: ${from}`).toBeGreaterThan(-1);
      expect(b, `region end not found: ${to}`).toBeGreaterThan(a);
      return code.slice(a, b);
    };

    // The RESPONDER's establishment path — the closest analogue to a revival, since it too adopts an
    // existing node rather than dialling out to create one.
    // BOUNDED AT THE NEXT METHOD, not at some later one — the first version ran to
    // `#registerContentHandler` and swept `destroySessionNode`'s teardown calls in with it, then
    // reported them as steps revival was skipping. A region that is too wide invents findings.
    const establish = region("async acceptSession(", "async destroySessionNode(");
    const revive = region("async reviveSessionNode(", "async reviveIfNeededForSend(");

    /**
     * Steps establishment takes that a revival legitimately does not, each with the reason. Anything
     * NOT on this list must appear in both.
     */
    /** Establishment's step → revival's equivalent, where the same job has a different name. */
    const EQUIVALENT = new Map<string, string>([
      ["#connectSessionRelay", "#reconnectRevivedSessionRelay"],
    ]);

    const EXEMPT = new Map<string, string>([
      ["#insertSessionRow", "the row already exists — a revival updates its status instead"],
      ["#ensureStandingReceiver", "no receiver is consumed, so none needs replacing"],
      ["#rememberSessionSeed", "the identity is what a revival RESTORES; it was recorded at establishment"],
      ["#recordRelayAssignment", "the relay already recorded this session at first establishment"],
      ["#maybeAutoAcknowledgeSeal", "reached from the relay leaf handler, which both paths register"],
      // The inbound ACCEPTANCE accounting (D18): these decide whether to admit a NEW session from
      // this sender. A revival admits nothing new — the session was already accepted — so repeating
      // them would charge the counterparty a second time for one conversation.
      ["#getUnreadReceivedCount", "acceptance accounting for a NEW inbound session; a revival admits nothing new"],
      ["#getReceivedBytesTotal", "acceptance accounting for a NEW inbound session; a revival admits nothing new"],
    ]);

    const calls = new Set(
      [...establish.matchAll(/this\.(#?[A-Za-z][A-Za-z0-9_]*)\(/g)].map((m) => `#${m[1]!.replace(/^#/, "")}`),
    );

    const takenByRevival = (c: string): boolean => {
      const names = [c, ...(EQUIVALENT.has(c) ? [EQUIVALENT.get(c)!] : [])];
      return names.some((n) => revive.includes(`${n.replace(/^#/, "this.#")}(`) || revive.includes(`${n.slice(1)}(`));
    };
    const missing = [...calls].filter((c) => !EXEMPT.has(c) && !takenByRevival(c));

    expect(
      missing,
      "a revived session that skips any of these is not a session: it reports active while some " +
      "part of it — inbound delivery, liveness, the content handler — was never wired. That is the " +
      "defect class this whole file exists for, and it shipped past a green suite for two days.",
    ).toEqual([]);
  }, 60_000);

  it("PARITY: the relay witness is CONNECTED, not merely registered", async () => {
    // Review HIGH-2. `registerSession` files a handler in a Map — it opens no stream, no auth, no
    // reader loop. Establishment ends with `await client.connect(node)`; the first revival did not,
    // so it logged "live inbound path back" over a client whose stream was null and delivery fell
    // straight back to the five-minute mailbox poll.
    const { readFileSync } = await import("node:fs");
    const code = readFileSync(join(import.meta.dirname, "..", "session-node-manager.ts"), "utf-8")
      .replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
    // BOUNDED BY THE NEXT METHOD. The first version used `indexOf("\n  }\n")`, which does not match
    // this file's formatting — it returned -1, so `slice(a, -1)` scanned almost the whole file and
    // found `client.connect(` in `#connectSessionRelay`. The test passed with the call reverted,
    // which is the same hollowness it was written to fix.
    const a = code.indexOf("async #reconnectRevivedSessionRelay(");
    const b = code.indexOf("async reviveSessionNode(", a);
    expect(a, "method not found").toBeGreaterThan(-1);
    expect(b, "region end not found").toBeGreaterThan(a);
    const body = code.slice(a, b);

    expect(body.includes("registerSession("), "the handler must still be registered").toBe(true);
    expect(
      body.includes("client.connect("),
      "registering without connecting is a session that reports a live inbound path and has none",
    ).toBe(true);
  }, 60_000);
});
