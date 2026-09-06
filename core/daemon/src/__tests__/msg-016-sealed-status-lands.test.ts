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
import { readFileSync, readdirSync } from "node:fs";
import { encode } from "cbor-x";
import { join } from "node:path";
import { encodeStructure1 } from "@cello-protocol/protocol-types";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import { TEST_SESSION_GENESIS } from "./helpers/session-genesis.js";

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

  it("a force-ABANDONED session is not resurrected as sealed — that was the operator's decision", async () => {
    // `#updateSessionStatus` has no status guard, so markSealed has to carry one. A certificate
    // arriving after a force-abandon must not silently overturn the choice to give up the receipt.
    // The certificate is still stored and retrievable; the row keeps saying what the operator did.
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg016g-" });
    seedNodelessInterrupted(fx, "abandoned");

    expect(fx.snm.markSealed("alice", SID), "it must report that it did NOT write").toBe(false);
    expect(statusOf(fx)).toBe("abandoned");
  }, 60_000);

  it("an already-sealed session is not re-written — a no-op must not report that it landed", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg016h-" });
    seedNodelessInterrupted(fx, "sealed");

    expect(fx.snm.markSealed("alice", SID)).toBe(false);
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
  // SCANNED, NOT LISTED. A hand-maintained list is the anti-pattern this pin exists to avoid: a
  // fifth seal site can be added in a file nobody remembers to add here, and the suite stays green.
  // Every daemon source file is checked; anything genuinely exempt goes in EXEMPT with a reason.
  const SRC_DIR = join(import.meta.dirname, "..");
  const EXEMPT: Record<string, string> = {
    // The teardown itself. It is the function whose early return causes the defect — it cannot
    // call the wrapper that exists to work around it.
    "session-node-manager.ts": "writes the status inline, below the #activeNodes guard this pins around",
  };
  /**
   * A CALL on ONE line, which is the same rule the per-site scan below uses.
   *
   * It used to be `/destroySessionNode\([^)]*"sealed"/` over the whole file, and `[^)]*` crosses
   * newlines — so the moment the content path was split out and something DECLARED the method,
   * a four-line type signature with `reason: "sealed" | "interrupted" | "error"` matched. That
   * file has no teardown in it at all, so the scan then demanded a `markSealed` next to a call
   * that does not exist and failed on a file that could not possibly be wrong. A declaration is
   * not a call, and the two filters agreeing is what keeps this scan pointed at real sites.
   */
  const isSealTeardownCall = (line: string): boolean =>
    line.includes("destroySessionNode(") && line.includes('"sealed"');
  const FILES = readdirSync(SRC_DIR)
    .filter((f) => f.endsWith(".ts"))
    .filter((f) => !(f in EXEMPT))
    .filter((f) => readFileSync(join(SRC_DIR, f), "utf-8").split("\n").some(isSealTeardownCall));

  it("the scan finds the seal-completion files at all — an empty list would pin nothing", () => {
    expect(FILES.length).toBeGreaterThan(0);
  });

  for (const file of FILES) {
    it(`${file}: each destroySessionNode(..., "sealed") is preceded by markSealed`, () => {
      const src = readFileSync(join(SRC_DIR, file), "utf-8");
      const lines = src.split("\n");
      const sealTeardowns = lines.map((l, i) => ({ l, i })).filter(({ l }) => isSealTeardownCall(l));

      expect(sealTeardowns.length, `${file} must still contain the seal teardown this pins`).toBeGreaterThan(0);

      for (const { i } of sealTeardowns) {
        // A CALL, not a mention. `.toContain("markSealed")` would be satisfied by a comment saying
        // "markSealed was removed on purpose" — which is precisely the change this is here to stop.
        // Comment lines are stripped before the check for the same reason.
        const window = lines
          .slice(Math.max(0, i - 14), i)
          .filter((l) => !l.trim().startsWith("//") && !l.trim().startsWith("*"))
          .join("\n");
        /**
         * TWO ways to flip it, and both are the property — review of the content-path split.
         *
         * The wrapper `markSealed` is one. The other is the inline `updateSessionStatus(…,
         * "sealed")`, which is what the send path does and has always done; it simply used to live
         * in the one file this scan exempts, so the scan never had to know about it. When the
         * content path moved to its own file the site became visible and the check called a
         * correct, deliberate, commented flip a defect.
         *
         * What is being pinned is "the row is flipped before the teardown", not "one named
         * function was called". Accepting both keeps the teeth: delete EITHER and this goes red,
         * because what is gone is the flip.
         */
        // PER LINE, for the reason the file filter above is per line: `[^)]*` crosses newlines, so
        // over a 14-line joined window it would happily match an `updateSessionStatus(` on one line
        // against a `"sealed"` on another that has nothing to do with it. Nothing in this window
        // declares that signature today, so it is not reachable — it is the identical trap sitting
        // one refactor away, and it costs one `.some()` to close now rather than after it fires.
        const flipped = window.split("\n").some((l) =>
          l.includes(".markSealed(") || (l.includes("updateSessionStatus(") && l.includes('"sealed"')));
        expect(
          flipped,
          `${file}:${i + 1} tears the node down as sealed without flipping the status first. ` +
          `destroySessionNode returns early at 'if (!entry) return' and writes the status below that ` +
          `guard, so for a session with no live node — every interrupted one — the receipt lands and ` +
          `the row never moves.`,
        ).toBe(true);
      }
    });
  }
});

/**
 * DOD-M12B-INTERRUPTED-ESCALATE-1 — the durable ctrl-leaf recovery, which is the DoD's own
 * "prove this first" and had no test anywhere.
 *
 * `#responderSealSubmitted` is in memory. A session whose close was in flight when the daemon
 * stopped already has our SEAL ctrl leaf in the relay log — and on the next boot the mark is empty.
 * Without the durable recovery, the restart-seal resolver's automatic close posts a SECOND, the
 * directory then refuses `ctrlLeaves.length !== 1` forever, and the receipt is gone permanently.
 *
 * Revert test: make `#recoverOwnSealCtrlLeaf` return "none" unconditionally and the RECOVERY case
 * fails — a leaf that is on disk is reported absent, and the caller posts a second.
 */
describe("DOD-M12B-INTERRUPTED-ESCALATE-1: a ctrl leaf posted before the restart is recovered, not reposted", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  async function ownPubkeyHex(f: TwoConnectionFixture): Promise<string> {
    return (f.snm.getDb().prepare("SELECT k_local_pubkey FROM agents WHERE agent_name = 'alice'").get() as { k_local_pubkey: string }).k_local_pubkey;
  }

  function seed(f: TwoConnectionFixture): void {
    f.snm.getDb().prepare(
      `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at, message_count, interrupted_by)
       VALUES (?, (SELECT agent_id FROM agents WHERE agent_name = 'alice'), ?, 'interrupted', ?, ?, 6, 'local')`,
    ).run(SID, PEER, Date.now(), Date.now());
  }

  it("RECOVERS the root and sequence from a ctrl leaf a previous run posted — the answer that saves the receipt", async () => {
    // The third answer, and the only one whose failure is permanent: if this returns "none" for a
    // session that DOES hold our ctrl leaf, the caller posts a second, the directory then refuses
    // `ctrlLeaves.length !== 1` forever, and the receipt is gone. It had no test at any level.
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg016k-" });
    seed(fx);
    const own = await ownPubkeyHex(fx);
    // The leaf store is created lazily; this call is what makes its table exist.
    fx.snm.getSealCarry(own, SID);
    // The content hash at index 1 is what the root is rebuilt from, and it cannot be recomputed
    // because the seal payload embeds a close_timestamp. Built with the REAL encoder rather than a
    // hand-rolled array: this fixture kept emitting the old six-field layout after both chain links
    // became required, so the leaf it planted no longer decoded and the recovery correctly reported
    // "I cannot read this" — a test about finding a leaf, failing because it wrote an unreadable one.
    const contentHash = new Uint8Array(32).fill(0xa7);
    fx.snm.getDb().prepare(
      `INSERT INTO session_seal_leaves (agent_pubkey, session_id, sequence_number, leaf_kind, sender_pubkey_hex, structure2_cbor, structure1_cbor, stored_at)
       VALUES (?, ?, 7, 2, ?, ?, ?, 0)`,
    ).run(own, SID, own, Buffer.from(encode([7])), Buffer.from(encodeStructure1({
      contentHash,
      senderPubkey: new Uint8Array(32),
      sessionId: new Uint8Array(16),
      lastSeenSeq: 0,
      timestamp: 0,
      lastSeenHash: TEST_SESSION_GENESIS,
      prevOwnHash: TEST_SESSION_GENESIS,
    })));

    const got = fx.snm.recoverOwnSealCtrlLeafForTest("alice", SID);
    expect(got, "a ctrl leaf we posted before the restart must be FOUND, not reported absent").not.toBe("none");
    expect(got).not.toBe("unknown");
    const rec = got as { reportedRootHex: string; sequenceNumber: number };
    expect(rec.sequenceNumber, "the relay-assigned position comes back with it").toBe(7);
    expect(
      rec.reportedRootHex,
      "and the root is the tree WITH that leaf appended — the value the escalation reports",
    ).toBe(fx.snm.getSessionTree("alice", SID).rootWithAppendedHex(Buffer.from(contentHash).toString("hex")));
  }, 60_000);

  it("a session with no OWN ctrl leaf reports none — the ordinary first close", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg016i-" });
    seed(fx);
    expect(
      fx.snm.recoverOwnSealCtrlLeafForTest("alice", SID),
      "nothing posted yet, and 'none' must be distinguishable from 'I could not tell'",
    ).toBe("none");
  }, 60_000);

  it("an unreadable identity reports UNKNOWN, never 'none' — the distinction that saves the receipt", async () => {
    // The blocking finding from the second review: three paths meaning "I cannot determine whether
    // a ctrl leaf exists" all returned the same value as "there is none", and the caller reads that
    // as permission to post one. A second leaf is permanent.
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg016j-" });
    seed(fx);
    expect(
      fx.snm.recoverOwnSealCtrlLeafForTest("nobody-by-that-name", SID),
      "an unresolvable agent must not be reported as 'no leaf posted'",
    ).toBe("unknown");
  }, 60_000);
});
