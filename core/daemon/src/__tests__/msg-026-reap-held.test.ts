/**
 * DOD-M12B-REAP-HELD-1 — the half-open reaper destroyed a 36-message conversation's receipt.
 *
 * OBSERVED LIVE on Andre's daemon, 2026-08-18, minutes after the restart-seal path first ran. The
 * resolver had enqueued session `d28db475…` for a receipt. Four minutes later:
 *
 *   07:57:24  session.seal.blocked_incomplete  treeSize=20 highWaterSeq=35 heldCount=16
 *                                              heldOwn=6 heldReceived=10 missingLeaves=1
 *   07:57:56  session.half_open.reaped         priorStatus=interrupted ageMs=2750768
 *   07:57:56  session.content.held.annexed     status=abandoned annexed=16
 *   07:59:24  session.restart_seal.gave_up     reason=session_abandoned
 *
 * **The reaper abandoned a session the resolver was actively trying to seal**, and the receipt was
 * forfeited. Twenty leaves in the chain, sixteen more messages verified and held — ten of them from
 * the counterparty — and the whole thing ended with no notarized record.
 *
 * WHY THE REAPER THOUGHT IT WAS A DEAD HANDSHAKE. Its guard is exactly right in intent:
 * *"counterparty never established (liveness != 'alive' AND 0 RECEIVED messages)"*, and it is
 * careful to say `message_count` alone is not the signal because that counts our own ack. But it
 * asks the question of the TRANSCRIPT — `countReceivedMessages` is
 * `SELECT COUNT(*) FROM transcript WHERE direction = 'received'` — and **held content never reaches
 * the transcript**. It sits in `held_content` until it can join the chain.
 *
 * So the very condition that holds content — an interrupted session — is the condition that makes
 * the counterparty's messages invisible to this test. Ten received messages read as zero, and a
 * fully-established conversation is indistinguishable from an offer nobody ever answered.
 *
 * This is not a corner case; it is the interaction of two normal paths. Every session the
 * interrupted-session work exists to rescue accumulates held content by design.
 */
import { describe, it, expect, afterEach } from "vitest";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import { join } from "node:path";

const PEER = "aa".repeat(32);
let fx: TwoConnectionFixture | undefined;
afterEach(async () => { await fx?.cleanup(); fx = undefined; });

function seedSession(f: TwoConnectionFixture, sessionId: string): void {
  f.snm.getDb().prepare(
    `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at, message_count)
     VALUES (?, (SELECT agent_id FROM agents WHERE agent_name = 'alice'), ?, 'interrupted', 1, 1, 20)`,
  ).run(sessionId, PEER);
}

/** A frame the counterparty sent that arrived and verified but could not join the chain. */
function seedHeld(f: TwoConnectionFixture, sessionId: string, seq: number, origin: "received" | "sent"): void {
  f.snm.getDb().prepare(
    `INSERT INTO held_content (agent_id, session_id, canonical_seq, content_blob, content_hash_hex, held_at, origin)
     VALUES ((SELECT agent_id FROM agents WHERE agent_name = 'alice'), ?, ?, X'01', ?, 1, ?)`,
  ).run(sessionId, seq, `${seq}`.padStart(64, "0"), origin);
}

describe("DOD-M12B-REAP-HELD-1: held content proves the counterparty established", () => {
  it("a session with HELD received content is not a dead half-open", async () => {
    // The live case: ten received frames verified and held. The reaper asks the transcript, finds
    // nothing, and concludes the counterparty never showed up.
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg026a-" });
    const sid = "81".repeat(32);
    seedSession(fx, sid);
    for (let i = 1; i <= 10; i += 1) seedHeld(fx, sid, i, "received");

    expect(
      fx.snm.countEstablishedReceived("alice", sid),
      "ten messages from the counterparty read as zero, so a real conversation is reaped as an " +
      "unanswered offer and its receipt is forfeited",
    ).toBe(10);
  }, 60_000);

  it("held content of OUR OWN does not count — it proves nothing about them", async () => {
    // The reaper's question is "did the COUNTERPARTY establish?". Our own held frames are our own
    // words; counting them would make every session we ever spoke into un-reapable, which is the
    // clutter the reaper exists to remove.
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg026b-" });
    const sid = "82".repeat(32);
    seedSession(fx, sid);
    for (let i = 1; i <= 6; i += 1) seedHeld(fx, sid, i, "sent");

    expect(
      fx.snm.countEstablishedReceived("alice", sid),
      "our own held frames must not be evidence that they answered",
    ).toBe(0);
  }, 60_000);

  it("a genuinely dead half-open still reads zero — the reaper must keep working", async () => {
    // D18 depends on this: reaping only 0-RECEIVED ghosts is what keeps a stranger whose first
    // handshakes died from being locked out forever by the acceptance bound.
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg026c-" });
    const sid = "83".repeat(32);
    seedSession(fx, sid);

    expect(fx.snm.countEstablishedReceived("alice", sid)).toBe(0);
  }, 60_000);

  it("transcript and held are ADDED, not either/or", async () => {
    // A session interrupted mid-conversation has both: earlier messages that made it into the
    // transcript, and later ones still held. Either source alone under-counts.
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg026d-" });
    const sid = "84".repeat(32);
    seedSession(fx, sid);
    fx.seedReceived("alice", sid, "one that landed");
    for (let i = 1; i <= 3; i += 1) seedHeld(fx, sid, i, "received");

    expect(fx.snm.countEstablishedReceived("alice", sid)).toBe(4);
  }, 60_000);

  /**
   * THE WIRING. Every case above drives the counter directly, so the reaper in `daemon.ts` could
   * keep calling the transcript-only count and all four would stay green — which is exactly how the
   * live session was lost while a full suite passed.
   *
   * Revert test (RUN): put `countReceivedMessages` back in the reaper and this fails.
   */
  it("WIRING: the reaper asks the counter that includes held content", async () => {
    const { readFileSync } = await import("node:fs");
    const code = readFileSync(join(import.meta.dirname, "..", "daemon.ts"), "utf-8")
      .replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
    // The DEFINITION, not the first mention — earlier call sites made the window land elsewhere.
    const idx = code.indexOf("function reapDeadHalfOpenSessions");
    const body = code.slice(idx, idx + 2000);

    expect(
      body.includes("countEstablishedReceived("),
      "the reaper is back on the transcript-only count — an interrupted conversation with held " +
      "messages will be abandoned as a dead handshake and its receipt forfeited",
    ).toBe(true);
    expect(
      body.includes("countReceivedMessages("),
      "the transcript-only count must not remain in this guard",
    ).toBe(false);
  });
});
