/**
 * DOD-M12B-PENDING-RESOLVE-1 — `seal_interrupted_pending` has an exit, and nobody takes it.
 *
 * MEASURED on Andre's live store, 2026-08-18: **28 sessions** in this status, aged 0.3 to 12.8 days,
 * one of them 14 messages long, 26 holding relay-witnessed seal leaves — and **not one with a sealed
 * root**. Real conversations, no receipt. The count grows: it was 26 two days ago.
 *
 * **HALF ARE NOT BILATERAL** — the first draft of this header said they were, and review caught it.
 * Measured split: 14 initiator rows carrying the counterparty's signed leaf, and 14 responder rows
 * with `counterparty_leaf = NULL`. `inbound-seal-request.ts` writes a responder row from an UNSIGNED
 * request frame, BEFORE its ack is sent, so an ordinary send failure produces a one-sided row.
 *
 * `DOD-M12B-PENDING-EXIT-1` built the exit and it works — but only when an operator runs
 * `cello_close_session` on that session by hand, having somehow worked out that they should. Nothing
 * enumerates them. `listRestartOrphanedSessions` filters `status = 'interrupted'`, and so does
 * `listExpiredUnrevivableSessions`, so this status is invisible to both sweeps. An exit nobody is
 * told about is not an exit.
 *
 * WHY AUTO-RESOLVING THIS IS SAFE, AND SI-001 IS NOT VIOLATED — on TWO branches, not one. SI-001
 * forbids sealing on a live `session_interrupted` receipt because *"a daemon that sealed on its own
 * would notarize a conversation nobody chose to end."* Every row here was chosen to be ended by one
 * side: an initiator row carries the counterparty's signed leaf, and a responder row exists because
 * the counterparty SENT a request to seal. What makes the outcome verifiable is neither — the
 * directory rebuilds the tree from relay-witnessed leaves and checks their signatures, never
 * consulting the commitment. The commitment is what makes it legitimate to ASK.
 *
 * `interrupted_by` is deliberately NOT consulted here: it answers "did WE cause this", which is the
 * wrong question once a seal has been requested or signed.
 */
import { describe, it, expect, afterEach } from "vitest";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import { RestartSealResolver, type RestartOrphan, type SealOutcome } from "../restart-seal-resolver.js";
import type { Logger } from "../types.js";

const PEER = "aa".repeat(32);
let fx: TwoConnectionFixture | undefined;
afterEach(async () => { await fx?.cleanup(); fx = undefined; });

/**
 * Seed a session the way production leaves one behind.
 *
 * `seal_interrupted_pending` gets a commitment artifact by default, because production cannot
 * produce that status without one — `persistSealInterruptedCommitment` writes both. `role` defaults
 * to `responder` with a NULL `counterparty_leaf`, which is the HALF of the live population the first
 * draft of this file wrongly described as bilateral; testing against the weaker of the two shapes is
 * the point. Pass `{ artifact: false }` for the one case that asserts the structural check.
 */
function seed(
  f: TwoConnectionFixture,
  sessionId: string,
  status: string,
  opts: { messages?: number; gaveUp?: number | null; interruptedBy?: string | null; artifact?: boolean; role?: "initiator" | "responder" } = {},
): void {
  const db = f.snm.getDb();
  db.prepare(
    `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at,
                           message_count, interrupted_by, restart_seal_gave_up_at)
     VALUES (?, (SELECT agent_id FROM agents WHERE agent_name = 'alice'), ?, ?, 1, 1, ?, ?, ?)`,
  ).run(sessionId, PEER, status, opts.messages ?? 3, opts.interruptedBy ?? null, opts.gaveUp ?? null);

  const wantArtifact = opts.artifact ?? (status === "seal_interrupted_pending");
  if (wantArtifact) {
    const role = opts.role ?? "responder";
    db.prepare(
      `INSERT INTO seal_interrupted_artifacts (agent_id, session_id, role, own_leaf, counterparty_leaf, merkle_root, nonce, created_at)
       VALUES ((SELECT agent_id FROM agents WHERE agent_name = 'alice'), ?, ?, '{}', ?, 'ab', 'cd', 1)`,
    // NOT SQL NULL — the column is NOT NULL, and a responder row stores the JSON string "null".
    // Measured on the live store: 14 responder rows, all with the literal text, which is why the
    // "counterparty_leaf IS NULL" reading of that data needed correcting too.
    ).run(sessionId, role, role === "initiator" ? "{}" : "null");
  }
}

describe("DOD-M12B-PENDING-RESOLVE-1: a bilateral commitment is not left unnotarized forever", () => {
  it("a seal_interrupted_pending session is enumerated for resolution", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg025a-" });
    seed(fx, "61".repeat(32), "seal_interrupted_pending");

    expect(
      fx.snm.listRestartOrphanedSessions().map((o) => o.sessionId),
      "28 real conversations on the live store have sat here for up to 12.8 days because nothing " +
      "ever looks at this status",
    ).toEqual(["61".repeat(32)]);
  }, 60_000);

  it("interrupted_by is NOT required for it — both parties already signed", async () => {
    // The `interrupted_by = 'local'` guard answers "may we describe how this ended". Once both
    // parties have committed to seal, that question is settled by their signatures, not by ours.
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg025b-" });
    seed(fx, "62".repeat(32), "seal_interrupted_pending", { interruptedBy: null });

    expect(fx.snm.listRestartOrphanedSessions().map((o) => o.sessionId)).toEqual(["62".repeat(32)]);
  }, 60_000);

  // REGRESSION PIN on unchanged behaviour — this one is expected to survive a revert of the diff.
  it("REGRESSION PIN: an INTERRUPTED session still requires interrupted_by='local' — SI-001 untouched", async () => {
    // The safety argument differs per status and must not be flattened. An interrupted session with
    // an unknown cause has no signatures behind it and must still be refused.
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg025c-" });
    seed(fx, "63".repeat(32), "interrupted", { interruptedBy: null });

    expect(
      fx.snm.listRestartOrphanedSessions(),
      "widening this status too would notarize a conversation nobody chose to end",
    ).toEqual([]);
  }, 60_000);

  it("a pending session already given up on is not retried, while an eligible one still is", async () => {
    // TWO ROWS, after review. The first version seeded only the excluded row and asserted `[]` — so
    // it stayed green with the whole `OR` clause reverted, because the STATUS filter excluded it
    // before the gate under test was ever reached. It proved nothing about `restart_seal_gave_up_at`.
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg025d-" });
    seed(fx, "64".repeat(32), "seal_interrupted_pending", { gaveUp: Date.now() });
    seed(fx, "6a".repeat(32), "seal_interrupted_pending");

    expect(
      fx.snm.listRestartOrphanedSessions().map((o) => o.sessionId),
      "exact set: a revert makes the eligible row vanish, a broken gate makes the given-up one appear",
    ).toEqual(["6a".repeat(32)]);
  }, 60_000);

  it("a zero-message pending session is skipped, while a messaged one is taken", async () => {
    // Same two-row correction, same reason.
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg025e-" });
    seed(fx, "65".repeat(32), "seal_interrupted_pending", { messages: 0 });
    seed(fx, "6b".repeat(32), "seal_interrupted_pending", { messages: 2 });

    expect(fx.snm.listRestartOrphanedSessions().map((o) => o.sessionId)).toEqual(["6b".repeat(32)]);
  }, 60_000);

  it("review F5: a pending row with NO commitment artifact is not enqueued", async () => {
    // The header's licence is "a seal was requested or signed". A status check alone asserts that in
    // prose while the query checks something else — and today status implies an artifact row only by
    // construction, which holds until someone adds a fourth writer of this status.
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg025f-" });
    seed(fx, "6c".repeat(32), "seal_interrupted_pending", { artifact: false });
    seed(fx, "6d".repeat(32), "seal_interrupted_pending", { role: "responder" });

    expect(
      fx.snm.listRestartOrphanedSessions().map((o) => o.sessionId),
      "the eligible row is a RESPONDER row with a NULL counterparty_leaf — the licence is that a " +
      "seal was requested, not that both sides signed",
    ).toEqual(["6d".repeat(32)]);
  }, 60_000);

  it("the enumerated row carries its STATUS, so a give-up can say something true about it", async () => {
    // force-abandon is the right advice for an interrupted session and destructive for a pending
    // one — it forfeits a commitment that is one request away from a receipt.
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg025g-" });
    seed(fx, "6e".repeat(32), "seal_interrupted_pending");

    expect(fx.snm.listRestartOrphanedSessions()[0]?.status).toBe("seal_interrupted_pending");
  }, 60_000);
});

/**
 * REVIEW F2 — the test that would have caught the defect that made this unit worse than doing
 * nothing.
 *
 * Walk what would have happened on the operator's own machine. The daemon boots and enqueues all 28
 * pending sessions. The standing receiver does not exist yet — it is created only when
 * `cello_start_agent` reaches the daemon, so on a boot where no client has attached it is absent for
 * every agent, and every attempt returns `standing_receiver_unavailable`. That is not in
 * `TERMINAL_SEAL_REFUSALS`, so it is retried: 30 s, 60 s, 120 s, 240 s, 480 s. **Attempt five
 * exhausts the budget and writes `restart_seal_gave_up_at` — durably.** ~15 minutes after boot all
 * 28 rows fail the `restart_seal_gave_up_at IS NULL` clause, and no future boot ever enumerates them
 * again. The give-up reaches no operator surface: it is a warn line in `daemon.log`.
 *
 * The close handler names this condition itself: *"`standing_receiver_unavailable` is simply 'the
 * agent is not started yet', which a freshly booted daemon reports for every session."* A freshly
 * booted daemon is the ONLY time this resolver runs.
 */
describe("DOD-M12B-PENDING-RESOLVE-1 (review F2): a local precondition is not a verdict", () => {
  const silent: Logger = { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} };

  function harness(seal: () => Promise<SealOutcome>, orphan: RestartOrphan) {
    let t = 0;
    const timers: Array<{ at: number; fn: () => void }> = [];
    const gaveUp: string[] = [];
    let attempts = 0;
    const resolver = new RestartSealResolver({
      logger: silent,
      markGaveUp: (_a, sessionId) => { gaveUp.push(sessionId); },
      listRestartOrphans: () => [orphan],
      sealSession: async () => { attempts += 1; return seal(); },
      now: () => t,
      schedule: (fn, ms) => { const e = { at: t + ms, fn }; timers.push(e); return { cancel: () => { const i = timers.indexOf(e); if (i >= 0) timers.splice(i, 1); } }; },
      initialDelayMs: 0,
      staggerMs: 0,
    });
    const advance = async (ms: number): Promise<void> => {
      const end = t + ms;
      for (;;) {
        const due = timers.filter((x) => x.at <= end).sort((a, b) => a.at - b.at)[0];
        if (!due) break;
        timers.splice(timers.indexOf(due), 1);
        t = due.at;
        due.fn();
        await Promise.resolve(); await Promise.resolve(); await Promise.resolve();
      }
      t = end;
    };
    return { resolver, advance, gaveUp, attemptCount: () => attempts };
  }

  const pending: RestartOrphan = {
    agentName: "alice", sessionId: "71".repeat(32), messageCount: 4, status: "seal_interrupted_pending",
  };

  it("standing_receiver_unavailable NEVER causes a permanent give-up, however often it repeats", async () => {
    const h = harness(async () => ({ ok: false, reason: "standing_receiver_unavailable" }), pending);
    h.resolver.start();
    await h.advance(60 * 60 * 1000); // an hour of the agent never starting

    expect(
      h.gaveUp,
      "a durable give-up here removes the session from the ONLY queue that would look at it again — " +
      "for a row holding a signed commitment and relay-witnessed leaves ready to notarize",
    ).toEqual([]);
    expect(h.attemptCount(), "and it keeps trying, so the receipt is still reachable").toBeGreaterThan(3);
    await h.resolver.stop();
  });

  it("a refusal that IS about the session still exhausts the budget", async () => {
    // The bound has to survive: this must not become "retry everything forever".
    const h = harness(async () => ({ ok: false, reason: "seal_unilateral_failed" }), pending);
    h.resolver.start();
    await h.advance(60 * 60 * 1000);

    expect(h.gaveUp, "a session-level failure is a verdict, and the budget must still bound it").toEqual([pending.sessionId]);
    await h.resolver.stop();
  });
});
