/**
 * DOD-M15-DIVERGE-DURABLE-1 — divergence survives a daemon restart.
 *
 * ─── What divergence is, and why forgetting it is not a small thing ────────────────────────────
 *
 * A session diverges when the relay hands this side a canonical position BEHIND its own tree
 * frontier. That proves the two can no longer agree on a Merkle root, so the session can never seal
 * bilaterally. The seal gate reads it and refuses, which is correct: a bilateral seal that cannot
 * succeed should be refused with a reason, not attempted forever.
 *
 * `#diverged` was a `Set` in memory. `DOD-M15-DIVERGE-1` closed the in-process hole — it is no
 * longer dropped on node teardown, only at a terminal status — but a restart emptied it, and **the
 * read site cannot tell "not diverged" from "forgotten": both are `false`, and both read READY.**
 *
 * So: your conversation provably diverged, the daemon restarts, and the session comes back looking
 * perfectly healthy. The close is attempted, and the thing the flag existed to prevent happens.
 *
 * ─── Why this is not the trade `frontier-mismatch.ts` makes on purpose ─────────────────────────
 *
 * A frontier mismatch is also in memory, deliberately, because it is **re-detected by the very next
 * close** — losing it costs one recomputation. Divergence is re-detected only by the next send that
 * gets an ack behind the frontier, which on a session that is already finished never happens. A
 * restart therefore costs a WRONG ANSWER, not a re-detection. The DoD line says exactly that, and it
 * is the reason this one needs a column and that one does not.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { openTestDb } from "./helpers/encrypted-db.js";
import { seedAgents } from "./helpers/seed-agents.js";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { SessionNodeManager, type ISessionNodeFactory, type SessionNodeConfig } from "../session-node-manager.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { Logger } from "../types.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };

class StubNodeFactory implements ISessionNodeFactory {
  async createNode(_c: SessionNodeConfig): Promise<CelloNode> {
    return {
      getPeerId: () => "stub", listenAddresses: () => ["/ip4/127.0.0.1/tcp/0"],
      async start() {}, async stop() {}, async dial() { return { peerId: "remote" }; },
      async handle() {}, getProtocols: () => [], getConnections: () => [],
      onPeerConnect() {}, onPeerDisconnect() {},
      getDialability: () => ({ dialable: false, publicAddr: null }),
      onDialabilityChange: () => () => {},
      async newStream() { return { send() {}, async close() {}, abort() {}, status: "open" }; },
    } as unknown as CelloNode;
  }
}

const AGENT = "alice";
const SESSION = "ab".repeat(16);
const COUNTERPARTY = "cc".repeat(32);

describe("DOD-M15-DIVERGE-DURABLE-1: a restart does not turn diverged into healthy", () => {
  let dir: string;
  let dbPath: string;
  let agentId: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "m15-diverge-"));
    dbPath = join(dir, "sessions.db");
    const seed = openTestDb(dbPath);
    agentId = (await seedAgents(seed, [AGENT])).get(AGENT)!;
    seed.close();
  });
  afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

  /** A manager over the SAME database file — a restart is a second one of these. */
  async function boot(): Promise<SessionNodeManager> {
    const mgr = new SessionNodeManager({
      securityGateway: new PassthroughGatewayClient(),
      factory: new StubNodeFactory(),
      logger: silent,
      dbPath,
    });
    await mgr.initialize();
    return mgr;
  }

  function seedSession(mgr: SessionNodeManager): void {
    mgr.getDb().prepare(
      `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at,
                             message_count, interrupted_at)
       VALUES (?, ?, ?, 'active', 1000, 1000, 0, NULL)`,
    ).run(SESSION, agentId, COUNTERPARTY);
  }

  it("★ divergence recorded before a restart is still true after it", async () => {
    /**
     * THE DEFECT. Before this, the second manager's `#diverged` set was empty, `diverged` read
     * false, and the seal gate saw a session it was happy to close bilaterally — the exact outcome
     * the flag exists to prevent.
     */
    let mgr = await boot();
    seedSession(mgr);
    mgr.markSessionDiverged(AGENT, SESSION);
    expect(mgr.isSessionDiverged(AGENT, SESSION), "the flag must hold before the restart").toBe(true);
    await mgr.stop?.();

    // The restart.
    mgr = await boot();
    expect(
      mgr.isSessionDiverged(AGENT, SESSION),
      "After a restart this session reads as NOT diverged. The read site cannot tell that from " +
        "'never diverged' — both are false, both read ready — so the close the flag existed to " +
        "refuse is attempted, on a session that provably cannot seal bilaterally.",
    ).toBe(true);
    await mgr.stop?.();
  });

  it("a session that never diverged still reads false after a restart", async () => {
    // The counterexample. A durable flag that defaulted to true would refuse every close on every
    // restarted daemon — worse than the defect, and it would look like the protocol had broken.
    let mgr = await boot();
    seedSession(mgr);
    await mgr.stop?.();

    mgr = await boot();
    expect(mgr.isSessionDiverged(AGENT, SESSION)).toBe(false);
    await mgr.stop?.();
  });

  it("marking is idempotent and does not disturb the rest of the row", async () => {
    // It is written on a path that can fire more than once for one session, and it must not become
    // a way to bump `updated_at` — that column drives the inbox's last-spoke ordering.
    const mgr = await boot();
    seedSession(mgr);
    mgr.markSessionDiverged(AGENT, SESSION);
    mgr.markSessionDiverged(AGENT, SESSION);
    const row = mgr.getDb()
      .prepare("SELECT status, updated_at FROM sessions WHERE session_id = ?")
      .get(SESSION) as { status: string; updated_at: number };
    expect(row.status).toBe("active");
    expect(row.updated_at, "marking divergence is not activity — it must not move last-spoke").toBe(1000);
    await mgr.stop?.();
  });

  it("a TERMINAL status clears it, and the clear is durable too", async () => {
    /**
     * `DOD-M15-DIVERGE-1` established that divergence stops being true at a terminal status and
     * only there — at that point no future close can be refused, so the flag has nothing left to
     * protect. That reasoning has to survive a restart as well, or a sealed session comes back
     * carrying a refusal for a close that can no longer happen.
     */
    let mgr = await boot();
    seedSession(mgr);
    mgr.markSessionDiverged(AGENT, SESSION);
    mgr.markSealed(AGENT, SESSION);
    expect(mgr.isSessionDiverged(AGENT, SESSION)).toBe(false);
    await mgr.stop?.();

    mgr = await boot();
    expect(mgr.isSessionDiverged(AGENT, SESSION), "the clear must be durable, not just in memory").toBe(false);
    await mgr.stop?.();
  });

  it("★ TWO AGENTS SHARING ONE session_id — one side's divergence is not the other's", async () => {
    /**
     * THE LOOPBACK CASE, and the one the first version of this test missed.
     *
     * It used two sessions of the SAME agent, which an unkeyed `WHERE session_id = ?` handles
     * correctly by accident — so it passed while the real defect sat underneath. The schema's own
     * comment says why this shape exists: the PK is composite because **two of one operator's
     * agents can hold both ends of the same session_id on ONE daemon**. That is Andre's daily
     * setup, not an edge case.
     *
     * Unkeyed, marking side A diverged marked BOTH rows, and side B sealing cleared BOTH — so A's
     * divergence was erased by B's success, and after a restart A read healthy and signed a close
     * that could only be refused. Review F3.
     */
    const shared = "ee".repeat(16);
    // Seeded through the real helper, not a hand-rolled INSERT: `agents` has NOT NULL columns
    // (k_local_seed among them) that a partial insert violates, and reproducing its shape here
    // would be a second copy of the schema free to drift from the first.
    const seed = openTestDb(dbPath);
    const bobId = (await seedAgents(seed, ["bob"])).get("bob")!;
    seed.close();

    let mgr = await boot();
    for (const [aid] of [[agentId], [bobId]] as const) {
      mgr.getDb().prepare(
        `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at,
                               message_count, interrupted_at)
         VALUES (?, ?, ?, 'active', 1000, 1000, 0, NULL)`,
      ).run(shared, aid, COUNTERPARTY);
    }

    mgr.markSessionDiverged(AGENT, shared);
    expect(mgr.isSessionDiverged(AGENT, shared), "alice's side diverged").toBe(true);
    expect(mgr.isSessionDiverged("bob", shared), "bob's side did NOT").toBe(false);

    // Bob seals HIS half. Alice's divergence must survive it.
    mgr.markSealed("bob", shared);
    await mgr.stop?.();

    mgr = await boot();
    expect(
      mgr.isSessionDiverged(AGENT, shared),
      "Bob sealing his half cleared Alice's divergence. Both ends share the session_id on this " +
        "daemon, so an unkeyed UPDATE writes and wipes BOTH rows — and after a restart Alice's " +
        "seal gate reads healthy on a session that provably cannot seal.",
    ).toBe(true);
    await mgr.stop?.();
  });

  it("divergence is scoped to ITS session — one diverged conversation does not condemn another", async () => {
    const other = "dd".repeat(16);
    let mgr = await boot();
    seedSession(mgr);
    mgr.getDb().prepare(
      `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at,
                             message_count, interrupted_at)
       VALUES (?, ?, ?, 'active', 1000, 1000, 0, NULL)`,
    ).run(other, agentId, COUNTERPARTY);
    mgr.markSessionDiverged(AGENT, SESSION);
    await mgr.stop?.();

    mgr = await boot();
    expect(mgr.isSessionDiverged(AGENT, SESSION)).toBe(true);
    expect(mgr.isSessionDiverged(AGENT, other), "a second session must be unaffected").toBe(false);
    await mgr.stop?.();
  });
});
