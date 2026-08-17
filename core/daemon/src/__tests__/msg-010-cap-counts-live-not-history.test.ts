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
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import { ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER } from "../session-node-manager.js";

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
    snm.markSessionsInterruptedByLocalShutdown();

    const bound = snm.checkUnknownSenderAcceptanceBound("alice", PEER);
    expect(
      bound.ok,
      `a peer with ${ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER + 2} finished conversations must still be able to reach us`,
    ).toBe(true);
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

  it("the operator is told when their OWN cap refuses someone — they are the only one who can clear it", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg010d-" });
    const { snm } = fx;
    for (let i = 0; i < ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER; i++) {
      seedRestartInterrupted(fx, sid(i));
      snm.markInterruptedByCounterpartyForTest("alice", sid(i));
    }

    const bound = snm.checkUnknownSenderAcceptanceBound("alice", PEER);
    expect(bound.ok).toBe(false);

    // OUTWARD silence stays — a refused peer must not learn whether it is blocked or merely
    // over-cap. INWARD silence is the defect: an agent cannot self-heal against a limit it is
    // never told it hit, and the operator is the only party who can clear it.
    const alarm = fx.eventsNamed("session.inbound.cap.reached");
    expect(alarm.length, "the operator's own cap firing must be visible to them").toBe(1);
    expect(alarm[0]!.ctx["counterpartyPubkey"]).toBe(PEER);
    expect(alarm[0]!.ctx["cap"]).toBe(ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER);
    expect(alarm[0]!.ctx["counted"]).toBe(ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER);
    // And it must say what to DO — the whole point is that only they can act.
    expect(String(alarm[0]!.ctx["impact"])).toMatch(/close/i);
  }, 60_000);
});
