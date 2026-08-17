/**
 * DOD-CAP-SELF-HEAL-1 — the acceptance cap must count LIVE sessions, not everything that ever was.
 *
 * Found 2026-08-17 by running a real end-to-end test between two of Andre's own agents on one
 * machine: `session.inbound.accept.failed reason=abuse_bound_sessions_per_sender`. The receiving
 * agent held FIVE finished conversations with the caller — `interrupted`, 22 to 90 messages each —
 * against a stranger cap of three.
 *
 * They were never reaped, and correctly so: the reaper only takes 0-received ghosts, because D18's
 * disconnect-evasion attacker always has received content. So the bound was ALL-TIME rather than
 * concurrent. **Every pair of agents that had talked three times could never talk again, and every
 * restart made it worse** — a restart flips every active session to `interrupted` and nothing ever
 * resolves them.
 *
 * The caller was told nothing. Its send returned `ok` with "dispatched to relay", and the receiving
 * side then swept the parked message as `counterparty_unknown` and deleted it: a success message
 * for a conversation that never existed.
 *
 * WHAT MUST NOT BREAK — D18. A counterparty can flip a session to `interrupted` for free by
 * disconnecting, then open a fresh one, repeatedly. Those interruptions are THEIRS and must keep
 * counting. The ones a restart causes are OURS and must not be charged to them. The cause is
 * knowable at the source — `markInterruptedWithDetails` is the counterparty's stream closing; the
 * boot and shutdown sweeps are ours — it simply was not recorded.
 *
 * Revert test: count `interrupted` unconditionally again and the first case fails — a peer that has
 * survived three restarts can no longer be reached.
 */
import { describe, it, expect, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { startTwoConnectionFixture, FakeNode, FixedFactory, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import { SessionNodeManager, ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER } from "../session-node-manager.js";
import { seedAgents } from "./helpers/seed-agents.js";
import type { Logger } from "../types.js";
import type { CelloNode } from "@cello-protocol/transport";

const PEER = "5e".repeat(32);
const sid = (n: number): string => n.toString(16).padStart(2, "0").repeat(32);

describe("DOD-CAP-SELF-HEAL-1: the per-sender cap counts live sessions, not history", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  /** Seed a session in the shape a RESTART leaves behind: interrupted, with real content. */
  function seedRestartInterrupted(f: TwoConnectionFixture, id: string): void {
    f.snm.getDb().prepare(
      `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at, message_count, interrupted_at)
       VALUES (?, (SELECT agent_id FROM agents WHERE agent_name = 'alice'), ?, 'interrupted', ?, ?, 40, ?)`,
    ).run(id, PEER, Date.now() - 3_600_000, Date.now() - 3_600_000, new Date().toISOString());
  }

  it("finished conversations left behind by restarts do not lock the counterparty out", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg010-" });
    const { snm } = fx;

    // More past conversations than the cap allows, every one of them ours to explain: this is what
    // a daemon restart leaves behind, and Andre's own two agents had five.
    for (let i = 0; i < ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER + 2; i++) seedRestartInterrupted(fx, sid(i));
    snm.markSessionsInterruptedByLocalShutdownForTest();

    const bound = snm.checkUnknownSenderAcceptanceBound("alice", PEER);
    expect(
      bound.ok,
      `a peer with ${ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER + 2} finished conversations must still be able to reach us`,
    ).toBe(true);
  }, 60_000);

  it("THE REAL SHUTDOWN labels its own sessions — not a seam that writes the label for it", async () => {
    // Every other case here writes `interrupted_by` through a test seam, so deleting the label from
    // the production sweeps would leave them all green while the measured bug returned in full.
    // This drives the real gracefulShutdown and then reads the rows back from a SECOND process on
    // the same database — the shutdown closes its own handle, which is exactly why the assertion
    // has to happen from outside it.
    const dir = await mkdtemp(join(tmpdir(), "cello-msg010e-"));
    const dbPath = join(dir, "s.db");
    try {
      const logger: Logger = { debug() {}, info() {}, warn() {}, error() {} };
      const first = new SessionNodeManager({
        securityGateway: new PassthroughGatewayClient(), factory: new FixedFactory(new FakeNode() as unknown as CelloNode), logger, dbPath,
      });
      await first.initialize();
      await seedAgents(first.getDb(), ["alice"]);
      for (let i = 0; i < 2; i++) await first.createSessionNode(sid(i), "alice", PEER, "peer-id", "corr");
      await first.gracefulShutdown();

      const second = new SessionNodeManager({
        securityGateway: new PassthroughGatewayClient(), factory: new FixedFactory(new FakeNode() as unknown as CelloNode), logger, dbPath,
      });
      await second.initialize();
      const rows = second.getDb()
        .prepare("SELECT status, interrupted_by FROM sessions WHERE counterparty_pubkey = ?")
        .all(PEER) as Array<{ status: string; interrupted_by: string | null }>;
      expect(rows.length).toBe(2);
      for (const r of rows) {
        expect(r.status).toBe("interrupted");
        expect(r.interrupted_by, "our own shutdown must say it was ours").toBe("local");
      }
      // And the whole point: that peer is not locked out by our own stop.
      expect(second.checkUnknownSenderAcceptanceBound("alice", PEER).ok).toBe(true);
      await second.gracefulShutdown();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }, 60_000);

  it("an UNLABELLED row counts — the safe default for an anti-abuse bound is to count", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg010f-" });
    const { snm } = fx;
    // Every row on every database that predates this column is NULL. Reading those as excused would
    // open D18 wide on exactly the rows that motivated the change, so the default has to be theirs.
    for (let i = 0; i < ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER; i++) seedRestartInterrupted(fx, sid(i));
    const nulls = snm.getDb()
      .prepare("SELECT COUNT(*) AS n FROM sessions WHERE counterparty_pubkey = ? AND interrupted_by IS NULL")
      .get(PEER) as { n: number };
    expect(nulls.n, "the fixture must actually leave them unlabelled").toBe(ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER);

    const bound = snm.checkUnknownSenderAcceptanceBound("alice", PEER);
    expect(bound.ok, "an unattributable interruption must count, not be excused").toBe(false);
  }, 60_000);

  it("the operator's own kill switch is not charged to the counterparty", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg010g-" });
    const { snm } = fx;
    // cello_set_agent_offline tears sessions down with destroySessionNode. That is the operator
    // pressing their own stop button — the most obviously local act there is — and it was being
    // billed to the peer, who had done nothing.
    for (let i = 0; i < ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER + 1; i++) {
      await fx.createSession(sid(i), "alice", PEER);
      await snm.destroySessionNode("alice", sid(i), "interrupted");
    }
    const bound = snm.checkUnknownSenderAcceptanceBound("alice", PEER);
    expect(bound.ok, "using your own kill switch must not lock out the person you were talking to").toBe(true);
  }, 60_000);

  it("D18 still holds — a counterparty that disconnects and reopens is still bounded", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg010b-" });
    const { snm } = fx;

    // The disconnect-evasion attack: flip a session to `interrupted` for free by dropping the
    // stream, open a fresh one, repeat. Those interruptions are the COUNTERPARTY's doing and must
    // keep counting, or the bound is worth nothing.
    for (let i = 0; i < ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER; i++) {
      seedRestartInterrupted(fx, sid(i));
      snm.markInterruptedByCounterpartyForTest("alice", sid(i));
    }

    const bound = snm.checkUnknownSenderAcceptanceBound("alice", PEER);
    expect(bound.ok, "a peer churning its own disconnects must still hit the bound").toBe(false);
    expect(!bound.ok && bound.reason).toBe("abuse_bound_sessions_per_sender");
  }, 60_000);

  it("a LIVE session always counts, however it got there", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg010c-" });
    const { snm } = fx;
    for (let i = 0; i < ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER; i++) {
      await fx.createSession(sid(i), "alice", PEER);
    }
    const bound = snm.checkUnknownSenderAcceptanceBound("alice", PEER);
    expect(bound.ok, "concurrent live sessions are exactly what this bound is for").toBe(false);
  }, 60_000);

});
