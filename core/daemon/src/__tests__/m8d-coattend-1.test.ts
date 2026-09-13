/**
 * DOD-COATTEND-1 (M8D Tier 1) — per-session delivery: a message can no longer be taken by the
 * wrong session.
 *
 * THE DEFECT (spec §2), three individually-reasonable mechanisms colliding:
 *   1. attachment is unrestricted and uncounted,
 *   2. the doorbell is MULTICAST — one message, N wake-ups,
 *   3. the content queue is DESTRUCTIVE and single-consumer — `#receivedContent` is keyed
 *      `(agentName, sessionId)`, NOT by connection, and `takeReceivedContent` is `buf.shift()`.
 *
 * Both sessions are woken; both enter the 20 ms poll; whichever hits the next tick first gets the
 * message and REMOVES it. Tier 0 (`DOD-COATTEND-VISIBLE-1`) made that visible. This line makes it
 * stop happening: delivery reads a DURABLE RECORD. (Since 2026-09-13 the bookmark is per AGENT,
 * not per connection — see receive-all-unread.test.ts.)
 *
 * Only mechanism 3 changes. The doorbell STAYS multicast — AC 2 says so, and it was never the
 * defect. No attach is refused: exclusivity is rejected permanently (§3).
 *
 * Note what these clauses do NOT do: they never call `readTranscript` or the cursor helpers
 * directly. Every assertion goes through `cello_receive` on two real IPC connections, because three
 * separate units in this milestone shipped with the fix fully deletable and the suite green. The
 * revert test is the acceptance criterion, not the assertion count.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";

const SID = "cd".repeat(32);
const contents = (r: Record<string, unknown>) => ((r.messages ?? []) as Array<{ content: string }>).map((m) => m.content);

describe("DOD-COATTEND-1: two attached sessions BOTH receive the message", () => {
  let fx: TwoConnectionFixture;

  beforeEach(async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-m8d-coattend1-" });
  });

  afterEach(async () => {
    await fx.cleanup();
  });

  // DELIVERY IS NOW ONE BOOKMARK PER AGENT (2026-09-13). Per-connection delivery re-served old
  // messages on every reconnect, so T2–T4 (each session re-reads what a sibling read) are deleted.
  it("T1 (rewritten): one message, two attached sessions — the first read takes it for the AGENT, the second gets nothing", async () => {
    await fx.createSession(SID, "alice");
    const connA = await fx.connectAs("alice");
    const connB = await fx.connectAs("alice");

    await fx.ingestReceived("alice", SID, "from bob");

    const a = (await connA.send("cello_receive", { session_id: SID, timeout_ms: 2_000 })) as Record<string, unknown>;
    expect(contents(a), "the first session receives it").toEqual(["from bob"]);

    // One bookmark per (agent, session): B is the same agent, so the message is already read.
    const b = (await connB.send("cello_receive", { session_id: SID, timeout_ms: 300 })) as Record<string, unknown>;
    expect(b.messages).toBeUndefined();
    expect(b.content).toBeNull();

    // Reading did not duplicate the record.
    expect(fx.snm.getSessionTree("alice", SID).size(), "delivery must not append").toBe(1);
  });

  it("T5 (AC3, CONTENT LOSS): a connection dying with the message unread loses NOTHING", async () => {
    // The queue could drop a message on a dead connection — an in-flight `shift()` removed it from
    // everyone's view and the dying reader never delivered it. The durable record cannot: a
    // reconnecting session resumes from its bookmark. This is the clause that makes the record
    // strictly better than the buffer rather than merely different.
    await fx.createSession(SID, "alice");
    const doomed = await fx.connectAs("alice");
    await fx.ingestReceived("alice", SID, "must survive");

    doomed.close();
    await new Promise((r) => setTimeout(r, 150));

    const fresh = await fx.connectAs("alice");
    const got = (await fresh.send("cello_receive", { session_id: SID, timeout_ms: 2_000 })) as Record<string, unknown>;
    expect(contents(got), "content must survive the death of the connection that was going to read it").toEqual(["must survive"]);
  });

  // ─── F1 (review, BLOCKING): the bookmark must not be the GATE's cursor ────────────────────────
  //
  // Tier 1 delivered against `safeCursorAdvance`, which by design refuses to walk past a gap. That
  // is correct for the SEND GATE — "has this connection seen every leaf?" must never skip an unseen
  // one. It is fatal for DELIVERY — "what have I already handed this connection?" — because the
  // answer is pinned below the gap forever, so the same message is served on every call and the
  // next one is never reached. One question needs gap-safety; the other is destroyed by it.
  //
  // The gap is produced by the most ordinary thing in the protocol: a message this agent SENT from
  // another connection. Leaf indices are contiguous across both directions, so every sibling send
  // is a hole in a co-attending connection's received-only view.

  it("T7 (AC1/AC6, F1): a sibling's SENT leaf must not pin a co-attending session to one message", async () => {
    await fx.createSession(SID, "alice");
    fx.seedSent("alice", SID, "hello bob"); // leaf 0 — authored on some other connection
    const connB = await fx.connectAs("alice"); // cursor -1, and leaf 0 is a gap it will never read

    await fx.ingestReceived("alice", SID, "reply one");
    const first = (await connB.send("cello_receive", { session_id: SID, timeout_ms: 2_000 })) as Record<string, unknown>;
    expect(contents(first)).toEqual(["reply one"]);

    await fx.ingestReceived("alice", SID, "reply two");
    const second = (await connB.send("cello_receive", { session_id: SID, timeout_ms: 2_000 })) as Record<string, unknown>;
    // Before the fix this was "reply one" again — and again, and again, unboundedly. Worse than the
    // theft this milestone exists to fix: the session is not merely missing a message, it is stuck
    // replying to the same one while the conversation moves on without it.
    expect(contents(second), "the NEXT message must be delivered, not the same one again").toEqual(["reply two"]);
  });

  it("T8 (AC1, F1 second shape): a screened-out leaf leaves a PERMANENT hole — delivery must cross it", async () => {
    // The security gateway terminal-blocks an inbound message: the leaf is committed, no transcript
    // row is ever written. That index can never be filled, so a gap-stopping bookmark stops there
    // for the life of the session — one block would permanently break cello_receive for EVERY
    // connection, which is a far larger blast radius than co-attendance.
    await fx.createSession(SID, "alice");
    fx.seedLeafWithoutTranscriptRow("alice", SID); // leaf 0 — no row, forever
    const conn = await fx.connectAs("alice");

    await fx.ingestReceived("alice", SID, "one");
    expect(contents((await conn.send("cello_receive", { session_id: SID, timeout_ms: 2_000 })) as Record<string, unknown>)).toEqual(["one"]);
    await fx.ingestReceived("alice", SID, "two");
    const second = (await conn.send("cello_receive", { session_id: SID, timeout_ms: 2_000 })) as Record<string, unknown>;
    expect(contents(second), "a permanent transcript hole must not stop delivery forever").toEqual(["two"]);
  });

  // WHY THERE IS NO "AND THE SEND IS STILL REFUSED" CLAUSE HERE.
  //
  // The fix's other half is that it must not WEAKEN the gate: M8C-CURSOR-1's read-before-write
  // guarantee lives on the gate's cursor, and if the new bookmark were reused as the gate then
  // delivering a received message would vault a connection past an unread SENT leaf and let it
  // reply having never seen what its sibling said. So the fix adds a SEPARATE map and leaves
  // safeCursorAdvance and every gate call site untouched.
  //
  // That half is not assertable through IPC today — measured, not assumed. Written as
  // `expect(send.ok).toBe(false)` the clause failed with `ok: true` BEFORE the bookmark existed:
  // the gate reads `connectionCursor >= currentSeq || unreadReceived === 0`, and the second
  // authority passes as soon as ANY connection has read. That is DOD-COATTEND-SENDWINDOW-1's
  // defect (journal Entry 17) and it is that line's to fix; the refusal becomes assertable there.
  // A clause asserting it here would pin behavior this unit does not ship, and a clause asserting
  // only what already passes would survive the revert test — which is the failure mode this
  // milestone keeps hitting. So it is stated, not staged.

  it("T6 (AC2 + AC4): the doorbell STAYS multicast and carries no content", async () => {
    // AC2 is a do-not-change clause: the multicast wake-up is correct and only the queue was wrong.
    // A 'fix' that made the doorbell single-cast would pass T1 (one reader still gets it) while
    // silently breaking every other attached session's liveness, so it is pinned here.
    await fx.createSession(SID, "alice");
    const connA = await fx.connectAs("alice");
    const connB = await fx.connectAs("alice");

    const rung: Array<Record<string, unknown>> = [];
    for (const c of [connA, connB]) {
      c.onNotification((n) => { if (n.notification === "cello_message") rung.push((n.data ?? {}) as Record<string, unknown>); });
    }
    await fx.ingestReceived("alice", SID, "secret words");
    await new Promise((r) => setTimeout(r, 200));

    expect(rung.length, "BOTH attached sessions must be woken — the doorbell is multicast").toBe(2);
    expect(JSON.stringify(rung), "DOD-INV-CONTENTFREE: no content on any push").not.toMatch(/secret words/);
  });
});
