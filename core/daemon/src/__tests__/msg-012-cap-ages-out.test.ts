/**
 * DOD-CAP-SELF-HEAL-1 (second half) — a stale interrupted session stops counting, whoever ended it.
 *
 * The first half recorded WHO caused each interruption and excused our own. That was correct and it
 * did not fix the case it was written for. Two reasons, both found by asking whether the measured
 * five rows would actually have been cleared:
 *
 *  1. **Attribution only works forward.** Every row written before the column existed is unlabelled,
 *     and an unlabelled row counts — deliberately, since the safe default for an anti-abuse bound is
 *     to count. So the operator's existing backlog was untouched.
 *  2. **It can never clear history**, and history is what filled the cap. Five finished
 *     conversations, 22 to 90 messages each, none of them live, all of them blocking.
 *
 * AGE is what clears a backlog. An interrupted session nobody has touched for hours is debris, not
 * a live obligation — and it is the same answer whether our restart or their disconnect produced it.
 *
 * D18 SURVIVES because the attack is a RATE. The disconnect-evasion peer must drop and reopen
 * faster than the window to gain anything, so every session it churns is recent and every one still
 * counts. What ages out is the thing that was never an attack: a conversation that finished.
 *
 * Revert test: drop the age term and the first case fails — a peer you finished talking to this
 * morning still cannot reach you.
 */
import { describe, it, expect, afterEach } from "vitest";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import { ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER, CAP_INTERRUPTED_TTL_MS } from "../session-node-manager.js";

const PEER = "6e".repeat(32);
const sid = (n: number): string => n.toString(16).padStart(2, "0").repeat(32);

describe("DOD-CAP-SELF-HEAL-1: a stale interrupted session stops counting", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  /** An interrupted session `ageMs` old, with content, and — like every row that predates the
   *  labelling — NO `interrupted_by`. This is the exact shape that filled the measured cap. */
  function seed(f: TwoConnectionFixture, id: string, ageMs: number): void {
    const t = Date.now() - ageMs;
    f.snm.getDb().prepare(
      `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at, message_count, interrupted_at)
       VALUES (?, (SELECT agent_id FROM agents WHERE agent_name = 'alice'), ?, 'interrupted', ?, ?, 40, ?)`,
    ).run(id, PEER, t, t, new Date(t).toISOString());
  }

  it("UNLABELLED and old — the exact rows that locked the operator out — no longer count", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg012-" });
    const { snm } = fx;

    // Five finished conversations, hours old, no label, against a cap of three. This is the
    // measured case, reproduced: it is what two of one operator's own agents were holding when
    // they could not open a session, and attribution alone left every one of them counting.
    for (let i = 0; i < ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER + 2; i++) {
      seed(fx, sid(i), CAP_INTERRUPTED_TTL_MS + 60_000);
    }
    const nulls = snm.getDb()
      .prepare("SELECT COUNT(*) AS n FROM sessions WHERE counterparty_pubkey = ? AND interrupted_by IS NULL")
      .get(PEER) as { n: number };
    expect(nulls.n, "the fixture must reproduce the unlabelled shape, not a labelled one").toBe(ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER + 2);

    expect(
      snm.checkUnknownSenderAcceptanceBound("alice", PEER).ok,
      "a peer you finished talking to hours ago must be able to reach you again",
    ).toBe(true);
  }, 60_000);

  it("D18 holds — a peer churning disconnects NOW is still bounded", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg012b-" });
    const { snm } = fx;
    // The attack is a rate: to gain a slot the attacker must outlast the window, so everything it
    // churns is recent. Recent interruptions count exactly as before.
    for (let i = 0; i < ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER; i++) {
      seed(fx, sid(i), 5_000);
      snm.markInterruptedByCounterpartyForTest("alice", sid(i));
    }
    expect(snm.checkUnknownSenderAcceptanceBound("alice", PEER).ok, "a live churn must still be refused").toBe(false);
  }, 60_000);

  it("age alone is not enough — a session still OPEN counts however old it is", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg012c-" });
    const { snm } = fx;
    // The bound is about concurrency. An old session that is still active is still concurrent, and
    // ageing it out would let a peer hold unlimited live sessions by simply keeping them quiet.
    for (let i = 0; i < ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER; i++) {
      await fx.createSession(sid(i), "alice", PEER);
      snm.getDb().prepare("UPDATE sessions SET updated_at = ? WHERE session_id = ?")
        .run(Date.now() - CAP_INTERRUPTED_TTL_MS * 10, sid(i));
    }
    expect(snm.checkUnknownSenderAcceptanceBound("alice", PEER).ok, "an open session always counts").toBe(false);
  }, 60_000);

  it("a recent interruption we caused ourselves does not count either — both rules apply", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg012d-" });
    const { snm } = fx;
    // Age clears a backlog; attribution clears the case age cannot reach — you restart your daemon
    // and immediately try to talk to the same peer. Neither rule alone covers both.
    for (let i = 0; i < ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER + 1; i++) {
      seed(fx, sid(i), 5_000);
    }
    snm.markSessionsInterruptedByLocalShutdownForTest();
    expect(
      snm.checkUnknownSenderAcceptanceBound("alice", PEER).ok,
      "restarting and immediately reconnecting must work",
    ).toBe(true);
  }, 60_000);
});
