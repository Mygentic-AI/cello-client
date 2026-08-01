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

  // NOTE ON ALL THREE CLAUSES (review F5): these are CHARACTERIZATION tests. This line shipped no
  // production change — the door already existed — so none of them goes red when the unit's only
  // code change is reverted, and AC4's "red before green" was not and could not be satisfied. They
  // pin a door that already worked so a later edit cannot quietly remove it. Said here, in the
  // names, rather than only in the commit body: a clause called "THE LINE" that cannot fail reads
  // as proof of a change to anyone skimming.

  it("K1 (AC2/AC4, CHARACTERIZATION): cello_transcript clears the bar for a session behind a sibling's send", async () => {
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
    // AC4 says the door must let B CLEAR THE BAR — so assert the SEND, not a number scraped off a
    // refusal (review F4). The first version asserted `lastBlockedCursor === 1`, which is a field
    // of a refusal: it proved B was still refused and merely inspected how. Any implementation that
    // advanced the cursor and kept refusing would have passed it unchanged.
    const after = (await connB.send("cello_send", { session_id: SID, content: "B's reply" })) as Record<string, unknown>;
    expect(after.ok, "after walking through the door, the send must go through").toBe(true);
  });

  it("K2 (§3b, CHARACTERIZATION): cello_receive cannot move the CURSOR past a sibling's sent leaf", async () => {
    // The contrast that makes K1 mean something: the cursor does not move, because receive delivers
    // only `direction === "received"` and safeCursorAdvance stops at the sibling's sent leaf at 0.
    // It would go red if `cello_receive` were widened to both directions, which is the design this
    // line rejected.
    //
    // SCOPED PRECISELY (review F2 on CATCHUP): this is about the CURSOR, not the GATE. Receive does
    // clear the *gate*, because it advances the agent-scoped watermark and the second authority
    // then passes. So there is no dead end at the gate today — the DoD's own correction says the
    // requirement stands in weakened form, and this clause is the weakened form, not the original
    // "stuck forever" claim. Asserting a gate dead end here would assert something untrue.
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

  it("K3 (AC3, CHARACTERIZATION): the door still refuses to skip an unread leaf — catch-up is not a bypass", async () => {
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
