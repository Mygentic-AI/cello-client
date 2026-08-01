/**
 * DOD-COATTEND-CATCHUP-1 — catch-up means everything since my bookmark, whoever wrote it (§3b).
 *
 * `cello_receive` only ever returns the COUNTERPARTY's messages: both its branches filter
 * `direction === "received"`. So a sibling session's reply is in the record and is never delivered
 * through that path, and a connection sitting behind one cannot clear its cursor by receiving —
 * `safeCursorAdvance` walks a contiguous run and the sibling's sent leaf is the gap it stops at.
 *
 * A rule satisfiable only through a door the caller is not pointed at is the same shape as the bug
 * that stopped command-line sessions replying at all.
 *
 * ── M8D-D3: THE DOOR IS `cello_get_transcript`. Decided, per AC1 ("pick ONE and say so"). ────────
 *
 * REJECTED: extending `since_seq` / the plain receive to both directions. Post-Tier-1 the blocking
 * receive reads the durable record filtered to received; widening it would make `cello_receive`
 * return THE AGENT'S OWN SENT MESSAGES — a different verb wearing the same name, and every existing
 * caller would have to learn the difference.
 *
 * CHOSEN: `cello_get_transcript`, which already IS the both-directions door — it advances the
 * connection cursor AND the persisted watermark through `safeCursorAdvance` / `safeWatermarkAdvance`
 * (`session-read-handlers.ts:130-146`), and its own comment names the sibling-send case as its
 * purpose. The send gate's refusal already points there, and so does the new
 * `session_moved_under_send` refusal (SENDWINDOW-1) — so "point every caller at it" costs nothing,
 * which is the strongest argument for this door over the other.
 *
 * These clauses prove the door WORKS and the dead end is REAL, because a door nobody has walked
 * through is a claim, not a door.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";

const SID = "7c".repeat(32);

/**
 * The connection cursor is in-memory and has no read surface — so it is observed where production
 * observes it: `session.send.blocked` logs `lastReadSeq` on every refusal (M8C-CURSOR-1 made both
 * authorities visible for exactly this reason). Forcing a refusal and reading the number is the
 * honest way to see the cursor; adding an accessor just for a test would be a hole in the daemon.
 */
/**
 * Attach FIRST, then seed.
 *
 * Ingesting into an UNATTENDED agent fires the M8C-AWAY-1 auto-reply, which appends its own "sent"
 * leaf — so the frontier these clauses reason about picks up a third message that has nothing to do
 * with catch-up, and the expected cursor silently becomes a number about the away path. Measured,
 * not guessed: the first version of K1 expected 1 and got 2, and the transcript dump showed
 * `{sequence: 2, direction: "sent", text: "Dispatched."}` sitting between them.
 */
function lastBlockedCursor(fx: TwoConnectionFixture): number {
  const blocked = fx.eventsNamed("session.send.blocked").filter((e) => e.ctx.lastReadSeq !== undefined);
  expect(blocked.length, "expected a gate refusal to read the cursor from").toBeGreaterThan(0);
  return blocked[blocked.length - 1].ctx.lastReadSeq as number;
}

describe("DOD-COATTEND-CATCHUP-1: a session behind a SIBLING'S SEND has a door, and it is not receive", () => {
  let fx: TwoConnectionFixture;

  beforeEach(async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-m8d-catchup-" });
  });
  afterEach(async () => { await fx.cleanup(); });

  it("K1 (AC2/AC4, THE LINE): cello_transcript clears a cursor stuck behind a sibling's sent leaf", async () => {
    await fx.createSession(SID, "alice");
    const connB = await fx.connectAs("alice"); // attended BEFORE any arrival — no away auto-reply
    fx.seedSent("alice", SID, "A's reply, which B never saw");   // leaf 0 — the sibling's send
    await fx.ingestReceived("alice", SID, "counterparty follow-up"); // leaf 1 — unread by the agent

    // The bar is real: B is refused, and the refusal reports a cursor of -1 — B has read nothing.
    const refused = (await connB.send("cello_send", { session_id: SID, content: "B's reply" })) as Record<string, unknown>;
    expect(refused.ok, "B must be gated while unread counterparty content exists").toBe(false);
    expect(lastBlockedCursor(fx), "B has read nothing").toBe(-1);

    // THE DOOR. Both directions, so the sibling's sent leaf at 0 is IN the delivered set and the
    // contiguous walk crosses it.
    const t = (await connB.send("cello_get_transcript", { session_id: SID })) as Record<string, unknown>;
    expect(t.ok).toBe(true);

    // Force one more refusal to read the cursor again. If the door worked, B's cursor now sits at
    // the sibling's send AND the counterparty message — past the gap that receive could not cross.
    await fx.ingestReceived("alice", SID, "another one"); // leaf 2, unread → the gate bites again
    const refusedAgain = (await connB.send("cello_send", { session_id: SID, content: "B's reply" })) as Record<string, unknown>;
    expect(refusedAgain.ok).toBe(false);
    expect(lastBlockedCursor(fx), "the transcript door moved the cursor ACROSS the sibling's sent leaf").toBe(1);
  });

  it("K2 (§3b): cello_receive alone does NOT clear it — the dead end this line exists to name", async () => {
    // The contrast that makes K1 mean something. Same setup, same bar, the OTHER door — and the
    // cursor does not move, because receive delivers only `direction === "received"` and
    // safeCursorAdvance stops at the sibling's sent leaf at 0. Without this clause, K1 would pass on
    // a build where BOTH paths worked and would prove nothing about the choice.
    await fx.createSession(SID, "alice");
    const connB = await fx.connectAs("alice");
    fx.seedSent("alice", SID, "A's reply, which B never saw");   // leaf 0
    await fx.ingestReceived("alice", SID, "counterparty follow-up"); // leaf 1

    expect(((await connB.send("cello_send", { session_id: SID, content: "x" })) as Record<string, unknown>).ok).toBe(false);
    expect(lastBlockedCursor(fx)).toBe(-1);

    const got = (await connB.send("cello_receive", { session_id: SID, timeout_ms: 2_000 })) as Record<string, unknown>;
    expect(got.content, "receive DOES deliver the counterparty's message").toBe("counterparty follow-up");

    await fx.ingestReceived("alice", SID, "another one");
    expect(((await connB.send("cello_send", { session_id: SID, content: "x" })) as Record<string, unknown>).ok).toBe(false);
    expect(
      lastBlockedCursor(fx),
      "receive delivered the content but could NOT move the cursor past the sibling's sent leaf",
    ).toBe(-1);
  });

  it("K3 (AC3): the door still refuses to skip an unread leaf — catch-up is not a bypass", async () => {
    // safeCursorAdvance's gap-safety is the read-before-write guarantee itself. If the transcript
    // door vaulted the cursor to the newest leaf it happened to see, catch-up would become a way to
    // clear the bar WITHOUT reading — the exact thing the gate exists to prevent, reachable by
    // calling the tool the refusal recommends.
    await fx.createSession(SID, "alice");
    const connB = await fx.connectAs("alice");
    fx.seedLeafWithoutTranscriptRow("alice", SID);                   // leaf 0 — a permanent hole
    await fx.ingestReceived("alice", SID, "counterparty follow-up"); // leaf 1
    expect(((await connB.send("cello_send", { session_id: SID, content: "x" })) as Record<string, unknown>).ok).toBe(false);

    await connB.send("cello_get_transcript", { session_id: SID });

    await fx.ingestReceived("alice", SID, "another one");
    expect(((await connB.send("cello_send", { session_id: SID, content: "x" })) as Record<string, unknown>).ok).toBe(false);
    expect(
      lastBlockedCursor(fx),
      "a leaf with no transcript row is UNREAD — the cursor must stop below it, not vault past",
    ).toBe(-1);
  });
});
