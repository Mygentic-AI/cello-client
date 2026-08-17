/**
 * DOD-M12B-SEAL-STUCK-1 — a session that can never seal must not be invisible.
 *
 * The seal gate refuses correctly: a chain with a gap cannot be co-signed, and signing a short one
 * gets `leaf_count_mismatch` back, which is terminal and costs the notarized receipt for good. That
 * refusal is right and this unit does not touch it.
 *
 * What is missing is that you cannot SEE the condition. A stuck session sits in `cello status` as
 * an ordinary active session; the only way to learn it will never close is to attempt a close on
 * each one and read the refusal. Measured 2026-08-17: **25 sessions opened by the document worker,
 * 25 seals blocked, 0 closed** — and each one holds a slot against the per-sender cap, so a spine
 * defect turns straight into "this agent stops accepting sessions" with nothing on any surface
 * saying why.
 *
 * The three states are the point, and each is pinned below. `ready` and `blocked` are the obvious
 * two; `unknown` exists because the witness state that reveals a never-arrived position is
 * memory-only, so after a restart a genuinely stranded session would otherwise report itself
 * healthy — the same lie, on the surface built to end it.
 *
 * Driven through the real IPC `status` call, not `getStatus()` directly, because an unrendered
 * field is an invisible one and the CLI path is what the operator actually runs.
 */
import { describe, it, expect, afterEach } from "vitest";
import { startTwoConnectionFixture, msgLeafHash, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import type { SealReadinessView, DaemonStatusResponse } from "../types.js";

describe("DOD-M12B-SEAL-STUCK-1: a session that cannot seal is visible without probing it", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  const STUCK = "7a".repeat(32);
  const HEALTHY = "7b".repeat(32);

  async function statusOf(f: TwoConnectionFixture): Promise<DaemonStatusResponse> {
    const client = await f.connect();
    return (await client.send("status", {})) as unknown as DaemonStatusResponse;
  }

  it("status distinguishes stuck from healthy, and reports the two counters as the different things they are", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg005-" });
    const { snm } = fx;
    await fx.createSession(STUCK, "alice");
    await fx.createSession(HEALTHY, "alice");

    // The stuck session, built so the two counters MUST differ — otherwise an implementation that
    // swapped them, or reported one twice, would pass.
    //   position 1 and 2: received, verified, held behind the gap at 0  → heldBehindGap = 2
    //   position 3:       witnessed by the relay, never arrived         → awaitingArrival = 1
    const held1 = new TextEncoder().encode("held at 1");
    const held2 = new TextEncoder().encode("held at 2");
    const never = new TextEncoder().encode("never arrived");
    snm.recordWitnessedSequence("alice", STUCK, Buffer.from(msgLeafHash(held1)).toString("hex"), 1);
    snm.recordWitnessedSequence("alice", STUCK, Buffer.from(msgLeafHash(held2)).toString("hex"), 2);
    snm.recordWitnessedSequence("alice", STUCK, Buffer.from(msgLeafHash(never)).toString("hex"), 3);
    await snm.ingestReceivedContent("alice", STUCK, held1, msgLeafHash(held1), "corr");
    await snm.ingestReceivedContent("alice", STUCK, held2, msgLeafHash(held2), "corr");
    expect(snm.sealReadiness("alice", STUCK).ready, "the fixture must actually be stuck").toBe(false);

    // The healthy session: an ordinary in-order message, witnessed and appended.
    const ok = new TextEncoder().encode("ordinary");
    snm.recordWitnessedSequence("alice", HEALTHY, Buffer.from(msgLeafHash(ok)).toString("hex"), 0);
    await snm.ingestReceivedContent("alice", HEALTHY, ok, msgLeafHash(ok), "corr");
    expect(snm.sealReadiness("alice", HEALTHY).ready).toBe(true);

    const rows = (await statusOf(fx)).active_sessions;
    const stuck = rows.find((r) => r.sessionId === STUCK);
    const healthy = rows.find((r) => r.sessionId === HEALTHY);
    expect(stuck, "the stuck session must be listed at all").toBeDefined();
    expect(healthy).toBeDefined();

    // toEqual on the whole object, with the two numbers different — the assertion a swap fails.
    expect(stuck!.sealReadiness).toEqual({
      state: "blocked",
      awaitingArrival: 1,
      heldBehindGap: 2,
      oldestHeldMs: expect.any(Number) as unknown as number,
    });
    // The age is what separates "stuck since this morning" from "in flight 40 ms ago". A blocked
    // session holding content must always be able to say how long it has been waiting.
    const blocked = stuck!.sealReadiness as Extract<SealReadinessView, { state: "blocked" }>;
    expect(blocked.oldestHeldMs).not.toBeNull();

    // A warning on everything is a warning on nothing.
    expect(healthy!.sealReadiness).toEqual({ state: "ready" });
  }, 60_000);

  it("an INTERRUPTED session carries the same answer — it can seal, so it can be blocked from sealing", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg005b-" });
    const { snm } = fx;
    await fx.createSession(STUCK, "alice");

    const held = new TextEncoder().encode("held behind a gap");
    snm.recordWitnessedSequence("alice", STUCK, Buffer.from(msgLeafHash(held)).toString("hex"), 1);
    await snm.ingestReceivedContent("alice", STUCK, held, msgLeafHash(held), "corr");
    // Give it a message so it survives the resumable-only filter, then interrupt it.
    snm.getDb()
      .prepare("UPDATE sessions SET status = 'interrupted', message_count = 1 WHERE session_id = ?")
      .run(STUCK);

    const rows = (await statusOf(fx)).interrupted_sessions;
    const row = rows.find((r) => r.sessionId === STUCK);
    expect(row, "an interrupted session must still be listed").toBeDefined();
    expect(row!.sealReadiness).toEqual({
      state: "blocked",
      awaitingArrival: 0,
      heldBehindGap: 1,
      oldestHeldMs: expect.any(Number) as unknown as number,
    });
  }, 60_000);

  it("a session whose ordering this process never watched reports UNKNOWN, never ready", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg005c-" });
    const { snm } = fx;
    await fx.createSession(STUCK, "alice");

    // Leaves this process did not watch arrive — the shape of every session after a daemon restart.
    // `#witnessedSeq` is memory-only, so a position the relay witnessed for content that never
    // arrived leaves no trace at all: the counters read clean and the session looks closable.
    // Closing it gets `leaf_count_mismatch`, which is terminal and costs the receipt for good.
    fx.seedReceived("alice", STUCK, "from a previous process");
    expect(snm.sealReadiness("alice", STUCK).ready, "the raw counters DO read clean — that is the trap").toBe(true);

    const rows = (await statusOf(fx)).active_sessions;
    const row = rows.find((r) => r.sessionId === STUCK);
    expect(row!.sealReadiness).toEqual({
      state: "unknown",
      reason: "witness_state_predates_daemon_start",
    });
  }, 60_000);

  it("reading status does NOT deliver messages — a diagnostic must not advance the chain", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg005d-" });
    const { snm } = fx;
    await fx.createSession(STUCK, "alice");

    const held = new TextEncoder().encode("waiting its turn");
    snm.recordWitnessedSequence("alice", STUCK, Buffer.from(msgLeafHash(held)).toString("hex"), 1);
    await snm.ingestReceivedContent("alice", STUCK, held, msgLeafHash(held), "corr");
    const before = snm.getSessionTree("alice", STUCK).size();

    await statusOf(fx);

    // The status path hydrates durable holds so its count is right, and stops there. If it also
    // released, `cello status` would append leaves, advance the session root, write transcript rows
    // and ring the doorbell — making the operator's diagnostic command the thing that delivers
    // messages, and making whether they ran it change the leaf count a later close signs over.
    expect(snm.getSessionTree("alice", STUCK).size(), "a read must not grow the tree").toBe(before);
    expect(fx.eventsNamed("session.content.released"), "a read must not release held content").toEqual([]);
  }, 60_000);

  // A GUARD test, not a change test: it passes before this unit because DOD-M12B-STRAND-1 already
  // made holds durable and moves them to the annex when a session goes terminal. It is here so that
  // the property force-abandon now depends on — "the escape hatch costs the receipt, not the
  // messages" — cannot be removed without something going red.
  it("held content survives a force-abandon (guard on the annex hand-off the escape hatch relies on)", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg005e-" });
    const { snm } = fx;
    await fx.createSession(STUCK, "alice");

    const held = new TextEncoder().encode("received, verified, never delivered");
    snm.recordWitnessedSequence("alice", STUCK, Buffer.from(msgLeafHash(held)).toString("hex"), 1);
    await snm.ingestReceivedContent("alice", STUCK, held, msgLeafHash(held), "corr");

    await snm.abandonSession("alice", STUCK);

    // The content moved, it did not vanish. Once a session is terminal nothing can ever release a
    // held frame into its chain again, so leaving the row in `held_content` would be durable
    // storage nothing can read.
    const stillHeld = snm.getDb()
      .prepare("SELECT COUNT(*) AS n FROM held_content WHERE session_id = ?")
      .get(STUCK) as { n: number };
    expect(stillHeld.n, "an unreachable held row is not preservation — it must be moved, not kept").toBe(0);

    const annexed = snm.getDb()
      .prepare("SELECT content FROM sealed_session_annex WHERE session_id = ?")
      .get(STUCK) as { content: Buffer } | undefined;
    expect(annexed, "abandoning a session must not destroy content it already received and verified").toBeDefined();
    expect(Buffer.from(annexed!.content).toString()).toBe("received, verified, never delivered");
  }, 60_000);
});
