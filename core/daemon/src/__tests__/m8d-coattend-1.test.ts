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

    await fx.ingestReceived("alice", SID, "before you joined");
    expect(((await connA.send("cello_receive", { session_id: SID, timeout_ms: 2_000 })) as Record<string, unknown>).content).toBe("before you joined");

    // A THIRD party joins after the fact. Its bookmark starts behind, so the message it never saw
    // is still deliverable to it — the record is the source of truth, not a drained buffer.
    const late = await fx.connectAs("alice");
    const caught = (await late.send("cello_receive", { session_id: SID, timeout_ms: 2_000 })) as Record<string, unknown>;
    expect(caught.content, "a late session catches up from its own bookmark").toBe("before you joined");
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
