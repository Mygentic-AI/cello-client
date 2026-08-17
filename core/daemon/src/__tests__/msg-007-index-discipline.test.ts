/**
 * DOD-M12B-INDEX-1 — a message lands where the relay says it lands.
 *
 * The whole ordering design rests on one property, which `session-node-manager.ts` names outright
 * as "the leaf-index === sequence invariant": a party's leaf index for a piece of content IS its
 * relay-assigned canonical position. The receiver enforces it — content witnessed ahead of the next
 * expected leaf is HELD, not appended out of order. **The sender does not.**
 *
 * The send path has the position in hand — `session.relay.hash.submitted` fires about 4 ms before
 * `session.tree.appended` — and calls `appendLeafHash`, which is push-only and appends at the tail
 * regardless. While the sender's tree has no gap the tail happens to equal the assigned position
 * and nothing shows. The moment it has a gap — one held message, one park, one restart — its own
 * leaf goes in at the wrong index, its root parts from the counterparty's, and the next seal gets
 * `leaf_count_mismatch`, which is terminal.
 *
 * Delivery is NOT deferred by this. The bytes still go on the wire at once; only the leaf waits for
 * its slot, exactly as a received message does. That is affordable now because holds are durable
 * (DOD-M12B-STRAND-1) — before that, holding our own send would have risked losing it.
 *
 * Revert test: have `placeOwnLeaf` call `appendSessionLeaf` unconditionally and the first case
 * fails — our leaf lands at index 0 wearing the counterparty's position.
 */
import { describe, it, expect, afterEach } from "vitest";
import { startTwoConnectionFixture, msgLeafHash, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";

const SID = "8a".repeat(32);
const AGENT = "alice";
const hx = (b: Uint8Array) => Buffer.from(b).toString("hex");

describe("DOD-M12B-INDEX-1: the sender's own leaf takes its relay-assigned position", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  it("a send made while this side has a gap is held at its own position, not appended at the tail", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg007-" });
    const { snm } = fx;
    await fx.createSession(SID, AGENT);

    // Their message at position 1 arrives first, so this tree has a gap at 0 and stays empty.
    const theirs1 = new TextEncoder().encode("theirs at 1");
    snm.recordWitnessedSequence(AGENT, SID, hx(msgLeafHash(theirs1)), 1);
    await snm.ingestReceivedContent(AGENT, SID, theirs1, msgLeafHash(theirs1), "corr");
    expect(snm.getSessionTree(AGENT, SID).size(), "the gap at 0 keeps the tree empty").toBe(0);

    // Now WE send. The relay assigns position 2. Appending at the tail would put our own message at
    // index 0 — wearing the position that belongs to a message of theirs we have not seen yet.
    const ours = new TextEncoder().encode("ours at 2");
    const placed = snm.placeOwnLeaf(AGENT, SID, hx(msgLeafHash(ours)), ours, 2, "corr-send");
    expect(placed.placed, "our leaf must not be committed at the wrong index").toBe(false);
    expect(snm.getSessionTree(AGENT, SID).size(), "nothing may be appended while the gap is open").toBe(0);

    // Their message at 0 arrives. Everything drains in canonical order, ours included.
    const theirs0 = new TextEncoder().encode("theirs at 0");
    snm.recordWitnessedSequence(AGENT, SID, hx(msgLeafHash(theirs0)), 0);
    await snm.ingestReceivedContent(AGENT, SID, theirs0, msgLeafHash(theirs0), "corr");

    expect(snm.getSessionTree(AGENT, SID).size()).toBe(3);
    expect(
      snm.getSessionTree(AGENT, SID).leaves().map((l) => l.hashHex),
      "leaf index must equal the relay's position for every leaf, ours included",
    ).toEqual([hx(msgLeafHash(theirs0)), hx(msgLeafHash(theirs1)), hx(msgLeafHash(ours))]);
  }, 60_000);

  it("our released message is recorded as SENT, not as something the counterparty said", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg007b-" });
    const { snm } = fx;
    await fx.createSession(SID, AGENT);

    const theirs = new TextEncoder().encode("theirs at 1");
    snm.recordWitnessedSequence(AGENT, SID, hx(msgLeafHash(theirs)), 1);
    await snm.ingestReceivedContent(AGENT, SID, theirs, msgLeafHash(theirs), "corr");

    const ours = new TextEncoder().encode("something we said");
    snm.placeOwnLeaf(AGENT, SID, hx(msgLeafHash(ours)), ours, 2, "corr-send");

    const theirs0 = new TextEncoder().encode("theirs at 0");
    snm.recordWitnessedSequence(AGENT, SID, hx(msgLeafHash(theirs0)), 0);
    await snm.ingestReceivedContent(AGENT, SID, theirs0, msgLeafHash(theirs0), "corr");

    // Direction is what the transcript is read by. Releasing our own message down the RECEIVED path
    // would put our words in the counterparty's mouth in the sealed record, and hand them back to
    // our own agent through cello_receive as though they had just arrived.
    const rows = snm.getDb()
      .prepare("SELECT sequence, direction FROM transcript WHERE session_id = ? ORDER BY sequence ASC")
      .all(SID) as Array<{ sequence: number; direction: string }>;
    expect(rows).toEqual([
      { sequence: 0, direction: "received" },
      { sequence: 1, direction: "received" },
      { sequence: 2, direction: "sent" },
    ]);
    // And it must NOT be delivered to our own agent as inbound content.
    const inbound: string[] = [];
    for (;;) {
      const next = snm.takeReceivedContent(AGENT, SID);
      if (!next) break;
      inbound.push(Buffer.from(next.contentHex, "hex").toString());
    }
    expect(inbound, "our own message must never come back to us as inbound").toEqual(["theirs at 0", "theirs at 1"]);
  }, 60_000);

  it("with the position in hand and the tree already there, the leaf is committed immediately", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg007c-" });
    const { snm } = fx;
    await fx.createSession(SID, AGENT);

    // The ordinary case, and the one that must not regress: no gap, so the assigned position IS the
    // tail and the send commits at once. A fix that held everything would break every conversation.
    const ours = new TextEncoder().encode("first thing said");
    const placed = snm.placeOwnLeaf(AGENT, SID, hx(msgLeafHash(ours)), ours, 0, "corr-send");
    expect(placed.placed).toBe(true);
    expect(placed.placed && placed.leafIndex).toBe(0);
    expect(snm.getSessionTree(AGENT, SID).size()).toBe(1);
  }, 60_000);

  it("with NO relay position — the relay-degraded path — it appends at the tail as before", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg007d-" });
    const { snm } = fx;
    await fx.createSession(SID, AGENT);

    // No ordering authority is reachable, so there is no position to obey and no gap to detect.
    // Arrival order is the documented degradation, and this unit must not convert it into a refusal
    // — that would take messaging down whenever the relay is unreachable.
    const ours = new TextEncoder().encode("relay is down");
    const placed = snm.placeOwnLeaf(AGENT, SID, hx(msgLeafHash(ours)), ours, undefined, "corr-send");
    expect(placed.placed).toBe(true);
    expect(snm.getSessionTree(AGENT, SID).size()).toBe(1);
  }, 60_000);

  it("a position BEHIND the tree is refused loudly, never written over a committed leaf", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg007e-" });
    const { snm } = fx;
    await fx.createSession(SID, AGENT);
    fx.seedReceived(AGENT, SID, "already committed at 0");
    fx.seedReceived(AGENT, SID, "already committed at 1");

    // The relay handing back a position this tree has already passed is not something that should
    // happen for a message we just submitted. Appending anyway would commit our leaf at the wrong
    // index; overwriting would rewrite a leaf a root has already been computed over. Neither.
    const ours = new TextEncoder().encode("impossible position");
    const placed = snm.placeOwnLeaf(AGENT, SID, hx(msgLeafHash(ours)), ours, 0, "corr-send");
    expect(placed.placed).toBe(false);
    expect(snm.getSessionTree(AGENT, SID).size(), "a committed leaf must not be disturbed").toBe(2);
    const complaint = fx.eventsNamed("session.tree.position_behind_frontier");
    expect(complaint.length, "an impossible position must be named, not absorbed").toBe(1);
  }, 60_000);
});
