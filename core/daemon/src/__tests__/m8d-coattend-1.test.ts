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
 * stop happening: delivery reads a DURABLE RECORD against a PER-CONNECTION BOOKMARK.
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

describe("DOD-COATTEND-1: two attached sessions BOTH receive the message", () => {
  let fx: TwoConnectionFixture;

  beforeEach(async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-m8d-coattend1-" });
  });

  afterEach(async () => {
    await fx.cleanup();
  });

  it("T1 (AC1, THE LINE): one message, two attached sessions, BOTH get it — neither removes it", async () => {
    await fx.createSession(SID, "alice");
    const connA = await fx.connectAs("alice");
    const connB = await fx.connectAs("alice");

    await fx.ingestReceived("alice", SID, "from bob");

    const a = (await connA.send("cello_receive", { session_id: SID, timeout_ms: 2_000 })) as Record<string, unknown>;
    expect(a.content, "the first session receives it").toBe("from bob");

    // Before this line, B's poll found an empty buffer — A's read had REMOVED the message — and B
    // was told nothing arrived, word for word what a quiet counterparty produces.
    const b = (await connB.send("cello_receive", { session_id: SID, timeout_ms: 2_000 })) as Record<string, unknown>;
    expect(b.content, "the SECOND session must receive the SAME message, not silence").toBe("from bob");
    expect(b.sequence_number).toBe(a.sequence_number);

    // ...and reading twice did not duplicate the record. One message is one leaf, however many
    // sessions read it — the tree is the agent's, not the connection's.
    expect(fx.snm.getSessionTree("alice", SID).size(), "delivery must not append").toBe(1);
  });

  it("T2 (AC1): each session's own bookmark advances independently — a re-read is not a re-delivery", async () => {
    await fx.createSession(SID, "alice");
    const connA = await fx.connectAs("alice");
    const connB = await fx.connectAs("alice");

    // A SENT leaf first (review: this clause previously ran at cursor -1 against seq 0 — the one
    // arrangement where a gap-safe walk happens to work, so it passed one leaf short of the defect
    // it exists to guard). A conversation has both directions in it; that is what makes it one.
    fx.seedSent("alice", SID, "something a sibling connection sent");
    await fx.ingestReceived("alice", SID, "first");
    expect(((await connA.send("cello_receive", { session_id: SID, timeout_ms: 2_000 })) as Record<string, unknown>).content).toBe("first");

    // A has read it, so A's next poll must NOT hand it back — otherwise a caught-up session loops
    // on the same message forever. B has still never seen it and must still get it.
    const aAgain = (await connA.send("cello_receive", { session_id: SID, timeout_ms: 300 })) as Record<string, unknown>;
    expect(aAgain.content, "a session must not be re-served a message it already read").toBeNull();

    const b = (await connB.send("cello_receive", { session_id: SID, timeout_ms: 2_000 })) as Record<string, unknown>;
    expect(b.content, "B's bookmark is its own — A reading did not move it").toBe("first");
  });

  it("T3 (AC5, LISTENER MODE): THREE sessions all see the conversation — the property exclusivity would have cost", async () => {
    // Asserted with three connections deliberately: two proves the bug is gone, three proves the
    // capability co-attendance was chosen FOR (§3 — exclusivity forecloses listener mode, and
    // co-attendance gets it free). A design that special-cases "the other one" passes at two.
    await fx.createSession(SID, "alice");
    const conns = [await fx.connectAs("alice"), await fx.connectAs("alice"), await fx.connectAs("alice")];

    await fx.ingestReceived("alice", SID, "broadcast");

    for (const [i, c] of conns.entries()) {
      const r = (await c.send("cello_receive", { session_id: SID, timeout_ms: 2_000 })) as Record<string, unknown>;
      expect(r.content, `session ${i} must see the conversation`).toBe("broadcast");
    }
  });

  it("T4 (AC6): a session attaching MID-CONVERSATION catches up from its own bookmark", async () => {
    await fx.createSession(SID, "alice");
    const connA = await fx.connectAs("alice");

    // "Mid-conversation" must MEAN mid-conversation (review): the first version of this clause
    // seeded only received messages, so the late connection's cursor had no gap ahead of it and
    // any gap-stopping implementation passed. A real conversation has this agent's own replies in
    // it, and every one of them is a leaf the late connection never read.
    fx.seedSent("alice", SID, "our earlier reply");
    await fx.ingestReceived("alice", SID, "before you joined");
    expect(((await connA.send("cello_receive", { session_id: SID, timeout_ms: 2_000 })) as Record<string, unknown>).content).toBe("before you joined");

    // A THIRD party joins after the fact. Its bookmark starts behind, so the message it never saw
    // is still deliverable to it — the record is the source of truth, not a drained buffer.
    const late = await fx.connectAs("alice");
    const caught = (await late.send("cello_receive", { session_id: SID, timeout_ms: 2_000 })) as Record<string, unknown>;
    expect(caught.content, "a late session catches up from its own bookmark").toBe("before you joined");

    // ...and KEEPS catching up. Stopping at the first message it finds is what made the original
    // version of this clause hollow: a bookmark that never advances past the sent leaf at seq 0
    // still returns "before you joined" here, so the assertion above passes on the broken build.
    // Catching up means reaching the present, not receiving once.
    await fx.ingestReceived("alice", SID, "and this came after");
    const next = (await late.send("cello_receive", { session_id: SID, timeout_ms: 2_000 })) as Record<string, unknown>;
    expect(next.content, "catching up means reaching the NEXT message too").toBe("and this came after");
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
    expect(got.content, "content must survive the death of the connection that was going to read it").toBe("must survive");
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
    expect(first.content).toBe("reply one");

    await fx.ingestReceived("alice", SID, "reply two");
    const second = (await connB.send("cello_receive", { session_id: SID, timeout_ms: 2_000 })) as Record<string, unknown>;
    // Before the fix this was "reply one" again — and again, and again, unboundedly. Worse than the
    // theft this milestone exists to fix: the session is not merely missing a message, it is stuck
    // replying to the same one while the conversation moves on without it.
    expect(second.content, "the NEXT message must be delivered, not the same one again").toBe("reply two");
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
    expect(((await conn.send("cello_receive", { session_id: SID, timeout_ms: 2_000 })) as Record<string, unknown>).content).toBe("one");
    await fx.ingestReceived("alice", SID, "two");
    const second = (await conn.send("cello_receive", { session_id: SID, timeout_ms: 2_000 })) as Record<string, unknown>;
    expect(second.content, "a permanent transcript hole must not stop delivery forever").toBe("two");
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
