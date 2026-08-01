/**
 * DOD-FRONTIER-STRAND-1 AC1 — dedup keys on the relay-assigned POSITION, not the content hash.
 *
 * THE STRAND, from the live log (session `dbb93dfc…`, stranded a week). The away autoresponder
 * fired twice with byte-identical text. The sender appended both. The receiver hashed the second,
 * found that hash already at position 0, concluded "redelivery", and did not append. One side three
 * leaves, the other two — diverged permanently, every later message at a different index on each
 * side, and the session could never produce a receipt. Force-abandon was the only exit and it
 * forfeits the seal.
 *
 * The rule it broke is stated as design intent: *"a content_hash satisfies AT MOST ONE Merkle leaf,
 * exactly once."* That is false whenever two genuinely distinct messages match byte-for-byte — and
 * two instances of the same model, same incoming message, similar context, make that FAR likelier
 * than the human baseline. The wrap/over convention encourages exactly the terse turns most likely
 * to collide. It gets likelier precisely as same-model agent-to-agent grows, which is the wedge.
 *
 * THE DISCRIMINATOR ALREADY EXISTS: the relay assigns every submission a unique position. A
 * redelivery carries the SAME position; a genuinely new identical message carries a NEW one. So the
 * rule becomes: a duplicate is the same hash AT THE SAME POSITION.
 *
 * Why this could not be a one-line change (journal Entry 7): `ingestReceivedContent` took no
 * position at all, and the canonical position was recovered from `#witnessedSeq` — a map KEYED BY
 * CONTENT HASH, so two identical messages collapsed in it before dedup was ever consulted. The
 * position had to be threaded from the ordering record into ingest first.
 *
 * BOTH failure directions are silent and both destroy a receipt, so both are pinned here:
 *   too permissive → a real redelivery double-appends, inflating this side's tree (D3)
 *   too strict     → a genuine message is dropped, which IS the strand (D2)
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { startTwoConnectionFixture, msgLeafHash, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";

const SID = "ab".repeat(32);

describe("DOD-FRONTIER-STRAND-1 AC1: identical messages at different relay positions both land", () => {
  let fx: TwoConnectionFixture;

  beforeEach(async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-m8c-dedup-" });
    // ATTEND FIRST. An unattended agent trips M8C-AWAY-1's auto-ack, which appends its own SENT
    // leaf asynchronously — so a bare leaf COUNT races the away reply and this file's assertions
    // would pass or fail on timing rather than on dedup. (Caught by tracing the tree: the third
    // leaf carried a different hash entirely.) Attending suppresses the away path, exactly as
    // m8c-cursor-1 does for the same reason.
    await fx.connectAs("alice");
  });

  afterEach(async () => {
    await fx.cleanup();
  });

  /** The away-autoresponder text that actually stranded dbb93dfc… — identical on both firings. */
  const AWAY = new TextEncoder().encode("I'm away right now — leave a message and I'll get back to you.");

  it("D1 (control): a REDELIVERY — same hash, same position — still dedups to ONE leaf", async () => {
    await fx.createSession(SID, "alice");

    const first = await fx.snm.ingestReceivedContent("alice", SID, AWAY, msgLeafHash(AWAY), "corr-1", 0);
    expect(first).toMatchObject({ ok: true, leafIndex: 0 });
    expect(fx.snm.getSessionTree("alice", SID).size()).toBe(1);

    // The SAME message arriving again at the SAME relay position — direct delivery plus the
    // park backstop, or a replay. This must NOT become a second leaf.
    const again = await fx.snm.ingestReceivedContent("alice", SID, AWAY, msgLeafHash(AWAY), "corr-1b", 0);
    expect(again).toMatchObject({ ok: true, leafIndex: 0, appendedCount: 0 });
    expect(fx.snm.getSessionTree("alice", SID).size(), "a redelivery must not inflate the tree").toBe(1);
  });

  it("D2 (THE STRAND): two DISTINCT messages that happen to be identical BOTH append", async () => {
    await fx.createSession(SID, "alice");

    // The away responder fires once...
    const one = await fx.snm.ingestReceivedContent("alice", SID, AWAY, msgLeafHash(AWAY), "corr-a", 0);
    expect(one).toMatchObject({ ok: true, leafIndex: 0 });

    // ...and again, byte-for-byte identical, but the relay gave it its OWN position. Under the
    // content-hash rule this was silently dropped, the counterparty appended it, and the two
    // frontiers disagreed forever.
    const two = await fx.snm.ingestReceivedContent("alice", SID, AWAY, msgLeafHash(AWAY), "corr-b", 1);
    expect(two).toMatchObject({ ok: true, leafIndex: 1 });
    expect((two as { appendedCount?: number }).appendedCount ?? 1).toBeGreaterThan(0);

    expect(
      fx.snm.getSessionTree("alice", SID).size(),
      "two distinct messages must be two leaves, however identical their bytes",
    ).toBe(2);
  });

  it("D3: a redelivery of the SECOND one still dedups — position, not arrival order", async () => {
    await fx.createSession(SID, "alice");
    await fx.snm.ingestReceivedContent("alice", SID, AWAY, msgLeafHash(AWAY), "corr-a", 0);
    await fx.snm.ingestReceivedContent("alice", SID, AWAY, msgLeafHash(AWAY), "corr-b", 1);
    expect(fx.snm.getSessionTree("alice", SID).size()).toBe(2);

    // Position 1 arriving twice is a redelivery of THAT message, even though an identical leaf also
    // sits at position 0. Keying on the hash alone cannot tell these apart; keying on the position
    // can, and this is the clause that proves the fix is not just "append everything".
    const dup = await fx.snm.ingestReceivedContent("alice", SID, AWAY, msgLeafHash(AWAY), "corr-b2", 1);
    expect(dup).toMatchObject({ ok: true, leafIndex: 1, appendedCount: 0 });
    expect(fx.snm.getSessionTree("alice", SID).size()).toBe(2);
  });

  it("D4 (relay-degraded): with NO position, hash-dedup still applies — and does NOT cry wolf", async () => {
    // A session with no relay witness has no discriminator, so the pre-existing content-hash rule is
    // all there is. It keeps today's protection against real redelivery and today's blind spot for
    // identical messages — the strand can still form on this path. §5a permits proceeding rather
    // than refusing (losing content is worse than mis-ordering it).
    //
    // But it must NOT warn here. A session with NO RELAY ATTACHED has no witness BY DESIGN, so a
    // warn would fire on every deduped message of a perfectly normal no-relay session and bury the
    // case that means something — the same rule its sibling `session.content.unwitnessed` already
    // follows. A signal that fires on the normal case is not a signal. (Review F4: the first version
    // of this clause asserted the opposite, and was wrong.)
    await fx.createSession(SID, "alice"); // createSessionNode attaches NO relay client

    await fx.snm.ingestReceivedContent("alice", SID, AWAY, msgLeafHash(AWAY), "corr-x");
    const second = await fx.snm.ingestReceivedContent("alice", SID, AWAY, msgLeafHash(AWAY), "corr-y");
    expect(second).toMatchObject({ ok: true, appendedCount: 0 });
    expect(fx.snm.getSessionTree("alice", SID).size()).toBe(1);

    expect(
      fx.eventsNamed("session.content.dedup.unwitnessed"),
      "a no-relay session must not warn about a witness it was never going to get",
    ).toHaveLength(0);
  });

  // NOT COVERED HERE, deliberately, and for the same reason m8c-cursor-1 records for
  // `session.content.unwitnessed`: the case the warn EXISTS for is a session with a relay ATTACHED
  // whose content frame carried no ordering record. Reaching it means attaching a live relay client
  // (`#activeNodes` is private, and a seam added purely for the test would test the seam). It
  // belongs in the live spine, against a real relay.

  it("D5 (review F2 — the regression this fix first INTRODUCED): under position DRIFT a true redelivery still dedups", async () => {
    // Drift is a documented live condition (§7a): a first message whose relay submit failed is
    // appended locally and never counted by the relay, so the local tree runs permanently one ahead
    // and LEAF INDEX IS NO LONGER THE RELAY POSITION.
    //
    // The first version of AC1 used the position as an index into the tree, which under drift made a
    // TRUE REDELIVERY append a second leaf — measured at tree size 3 where the pre-fix code gave 2.
    // That is the "too permissive" direction: it inflates this side's tree against the
    // counterparty's, which is the strand from the other end. Both directions destroy a receipt, so
    // both get a clause.
    await fx.createSession(SID, "alice");

    // Leaf 0: an UNWITNESSED message (its relay submit failed) — the drift producer.
    const first = new TextEncoder().encode("first message, relay submit failed");
    await fx.snm.ingestReceivedContent("alice", SID, first, msgLeafHash(first), "corr-d1");
    expect(fx.snm.getSessionTree("alice", SID).size()).toBe(1);

    // Leaf 1: a WITNESSED message which the relay numbered 0 — the tree is now one ahead.
    const second = new TextEncoder().encode("second message, witnessed at relay position 0");
    await fx.snm.ingestReceivedContent("alice", SID, second, msgLeafHash(second), "corr-d2", 0);
    expect(fx.snm.getSessionTree("alice", SID).size()).toBe(2);

    // ...and now the SAME message is redelivered (direct delivery plus the park backstop both
    // landing is a designed path). It carries the same relay position, 0.
    const redelivered = await fx.snm.ingestReceivedContent("alice", SID, second, msgLeafHash(second), "corr-d3", 0);
    expect(redelivered).toMatchObject({ ok: true, appendedCount: 0 });
    expect(
      fx.snm.getSessionTree("alice", SID).size(),
      "a redelivery must not append a second leaf just because the tree has drifted",
    ).toBe(2);

    // The ambiguity is ANNOUNCED — under drift the position is unusable as an index, so dedup falls
    // back to the weaker content-hash rule and says so rather than pretending it is still exact.
    // Exactly ONE — it fires where the fallback DECIDED (the redelivery), not on the earlier
    // message that merely appended under drift. sequence_behind_tree already reports that.
    const drifted = fx.eventsNamed("session.content.dedup.position_drifted");
    expect(drifted).toHaveLength(1);
    expect(drifted[0].ctx).toMatchObject({ sessionId: SID, canonicalSeq: 0, treeSize: 2, dedupedAt: 1 });
  });
});
