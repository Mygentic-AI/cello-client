/**
 * DOD-M12B-INTERRUPTED-ESCALATE-1 — the RECEIPT LANDING AND THE ROW NOT MOVING.
 *
 * The DoD line carried one explicit proof obligation: *prove a `seal_interrupted_pending` row can
 * reach `sealed`*. It could not, and the first build of the escalation shipped without noticing —
 * the seal succeeded, the notarized root and the certificate were stored, and the session still
 * said `interrupted`.
 *
 * WHY. Every seal-completion path ends with `destroySessionNode(agent, session, "sealed")` and
 * trusts it to flip the status. Its third line is `if (!entry) return`, and the status write lives
 * 26 lines BELOW that guard — so it flips the status only for a session that still has an
 * `#activeNodes` entry. An interrupted session has none *by construction*: the file says so itself,
 * *"EVERY producer of that status deletes the entry."* And a unilateral seal is exactly what an
 * interrupted session escalates to, so on that path the guard fires every single time.
 *
 * What it cost, in order: `cello_sessions` still shows the session stuck; `cello_close_session`
 * still refuses it by name; the restart-seal resolver re-selects it on the next boot and runs the
 * whole ceremony again against a session that already holds a receipt — then tells the operator to
 * force-abandon it. And `#updateSessionStatus`'s terminal hooks never run, so held content is never
 * annexed.
 *
 * Revert tests, both RUN: remove `markSealed`'s body and the first case fails; drop the two new
 * WHERE clauses from `listRestartOrphanedSessions` and two more fail. The CALL SITES are pinned
 * separately, by source order, in the last case — deleting `markSealed(...)` from any seal-completion
 * path leaves every behavioural test above green, which is exactly how this defect shipped.
 */
import { describe, it, expect, afterEach } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";

const SID = "9a".repeat(32);
const PEER = "9b".repeat(32);

describe("DOD-M12B-INTERRUPTED-ESCALATE-1: a sealed session's ROW says sealed", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  /** The exact shape a restart leaves: a row with no in-memory node behind it. */
  function seedNodelessInterrupted(f: TwoConnectionFixture, status = "interrupted"): void {
    f.snm.getDb().prepare(
      `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at, message_count, interrupted_by)
       VALUES (?, (SELECT agent_id FROM agents WHERE agent_name = 'alice'), ?, ?, ?, ?, 6, 'local')`,
    ).run(SID, PEER, status, Date.now(), Date.now());
  }

  function statusOf(f: TwoConnectionFixture): string {
    return (f.snm.getDb().prepare("SELECT status FROM sessions WHERE session_id = ?").get(SID) as { status: string }).status;
  }

  it("markSealed flips a session that has NO live node — the case every seal path actually hits", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg016-" });
    seedNodelessInterrupted(fx);

    expect(fx.snm.markSealed("alice", SID), "the write must report that it landed, not merely not throw").toBe(true);
    expect(statusOf(fx), "the receipt exists; the row has to agree").toBe("sealed");
  }, 60_000);

  it("destroySessionNode ALONE does not — this is the defect, pinned so it cannot come back", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg016b-" });
    seedNodelessInterrupted(fx);

    // The call every seal-completion site used to make on its own.
    await fx.snm.destroySessionNode("alice", SID, "sealed");

    expect(
      statusOf(fx),
      "if this ever reads 'sealed', destroySessionNode has grown a no-node path and markSealed can be reconsidered — until then, removing markSealed silently loses every unilateral seal",
    ).toBe("interrupted");
  }, 60_000);

  it("a seal_interrupted_pending row reaches sealed — the DoD's own proof obligation", async () => {
    // The 26 measured stuck sessions are in this status. Nothing had ever moved one forward.
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg016c-" });
    seedNodelessInterrupted(fx, "seal_interrupted_pending");

    expect(fx.snm.markSealed("alice", SID)).toBe(true);
    expect(statusOf(fx)).toBe("sealed");
  }, 60_000);

  it("a NEVER-MESSAGED session is not offered for sealing — a dead handshake is not a conversation", async () => {
    // `classifySession` deliberately hides a 0-message interrupted session in the "failed" bucket so
    // it does not clutter status. Sealing one spends a directory ceremony to notarize nothing, and
    // then moves it into the operator's CLOSED list — making the clutter visible. The justification
    // for this whole line is "3,576 messages produced nothing"; zero messages is nothing to produce.
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg016e-" });
    const db = fx.snm.getDb();
    const ins = db.prepare(
      `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at, message_count, interrupted_by)
       VALUES (?, (SELECT agent_id FROM agents WHERE agent_name = 'alice'), ?, 'interrupted', ?, ?, ?, 'local')`,
    );
    ins.run(SID, PEER, Date.now(), Date.now(), 6);
    ins.run("9c".repeat(32), PEER, Date.now(), Date.now(), 0);

    expect(
      fx.snm.listRestartOrphanedSessions().map((o) => o.sessionId),
      "exact set — a negative containment check passes for reasons that are not the guard",
    ).toEqual([SID]);
  }, 60_000);

  it("a session already GIVEN UP on is not re-offered — the budget must not reset every boot", async () => {
    // The resolver's attempt budget is in memory. Without the durable mark, a machine restarting
    // ~6 times a day re-runs five directory ceremonies against a hopeless session, forever.
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg016f-" });
    seedNodelessInterrupted(fx);
    expect(fx.snm.listRestartOrphanedSessions().length).toBe(1);

    fx.snm.markRestartSealGaveUp("alice", SID, "seal_interrupted_rejected_by_counterparty");

    expect(fx.snm.listRestartOrphanedSessions(), "withdrawn from AUTOMATIC retries").toEqual([]);
    // But NOT a dead end for the operator: the row is still `interrupted`, so a manual
    // cello_close_session still works on it and still escalates.
    expect(statusOf(fx)).toBe("interrupted");
  }, 60_000);

  it("a sealed session stops being a restart orphan — otherwise it is re-sealed every boot", async () => {
    // The compounding cost of the defect: the resolver re-selects a session whose receipt it
    // already obtained, spends five ceremonies on it, and then advises a force-abandon.
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg016d-" });
    seedNodelessInterrupted(fx);
    expect(fx.snm.listRestartOrphanedSessions().map((o) => o.sessionId)).toEqual([SID]);

    fx.snm.markSealed("alice", SID);
    expect(
      fx.snm.listRestartOrphanedSessions(),
      "a session holding a receipt must never be offered for automatic sealing again",
    ).toEqual([]);
  }, 60_000);
});

/**
 * THE CALL SITES, pinned by source.
 *
 * A behavioural test for these would need a live directory pushing a verified FROST certificate
 * over a signaling stream, and the property being asserted is an ORDERING one — status flip before
 * teardown — which is a property of the source. `startup-ordering.test.ts` makes the same argument
 * for the same reason: assert it where it lives, honestly, rather than build a rig that pins it by
 * accident. This is deliberately crude and it has teeth: delete a `markSealed` call and it goes red.
 */
describe("every seal-completion path flips the status itself", () => {
  const FILES = ["seal-coordinator.ts", "seal-certificate-pull.ts"];

  for (const file of FILES) {
    it(`${file}: each destroySessionNode(..., "sealed") is preceded by markSealed`, () => {
      const src = readFileSync(join(import.meta.dirname, "..", file), "utf-8");
      const lines = src.split("\n");
      const sealTeardowns = lines
        .map((l, i) => ({ l, i }))
        .filter(({ l }) => l.includes('destroySessionNode(') && l.includes('"sealed"'));

      expect(sealTeardowns.length, `${file} must still contain the seal teardown this pins`).toBeGreaterThan(0);

      for (const { i } of sealTeardowns) {
        // A CALL, not a mention. `.toContain("markSealed")` would be satisfied by a comment saying
        // "markSealed was removed on purpose" — which is precisely the change this is here to stop.
        // Comment lines are stripped before the check for the same reason.
        const window = lines
          .slice(Math.max(0, i - 6), i)
          .filter((l) => !l.trim().startsWith("//") && !l.trim().startsWith("*"))
          .join("\n");
        expect(
          window,
          `${file}:${i + 1} tears the node down as sealed without flipping the status first. ` +
          `destroySessionNode returns early at 'if (!entry) return' and writes the status below that ` +
          `guard, so for a session with no live node — every interrupted one — the receipt lands and ` +
          `the row never moves.`,
        ).toContain(".markSealed(");
      }
    });
  }
});
