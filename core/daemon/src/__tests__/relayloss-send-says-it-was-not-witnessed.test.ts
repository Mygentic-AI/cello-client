/**
 * A SEND THAT WAS NOT WITNESSED SAYS SO IN THE RESPONSE — `016-RELAYLOSS`, Part 3.
 *
 * ─── The measurement this exists to pin ────────────────────────────────────────────────────────
 *
 * `j-relayloss.spine.test.ts` black-holed a real relay in the middle of a real conversation between
 * two real daemons. The send stalled for the ten-second submit timeout and came back:
 *
 *     {"ok":true,"sequence_number":1,"delivered":true,"modified":false}
 *
 * The witnessed send that preceded it came back with the same shape and the same fields. The daemon
 * logged `session.tree.own_leaf_unwitnessed` at ERROR — correct, detailed, and addressed to a file
 * the agent cannot read. So the operator's message arrived, they were told it succeeded, and the
 * ordering authority has no copy of it. The consequence surfaces one or more sends later, when the
 * two trees can no longer agree on a root and the session cannot be sealed bilaterally.
 *
 * ─── What this file pins, and what it deliberately leaves to the journey ───────────────────────
 *
 * Here: the UNWITNESSED branch — `witnessed: false` and a `guidance` that names the condition. The
 * fixture has no relay, so an unwitnessed send is its natural state and this half is cheap.
 *
 * **The witnessed branch is pinned in the SPINE journey, not here, and that split is deliberate.**
 * A test that can only ever produce `false` is satisfied by a hardcoded `false`, which is the
 * hollow-test shape this milestone keeps finding. The journey asserts `witnessed: true` against a
 * real relay that really witnessed, so between the two files both values are held by something that
 * could observe the other.
 */
import { describe, it, expect, afterEach } from "vitest";
import { startTwoConnectionFixture, FakeNode, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import type { CelloNode } from "@cello-protocol/transport";

const SID = "5c".repeat(32);
const PEER = "12D3KooWQYV9dGMFoRzNStwpXztXaBUjtPqi6aMghfATmPnRAENn";

describe("016-RELAYLOSS — an unwitnessed send is not reported as an ordinary success", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  it("★ says witnessed:false and names what it means, instead of a response identical to a witnessed send", async () => {
    fx = await startTwoConnectionFixture({
      dirPrefix: "cello-relayloss-unwitnessed-",
      node: new FakeNode() as unknown as CelloNode,
    });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);
    const conn = await fx.connectAs("alice");

    const res = (await conn.send("cello_send", { session_id: SID, content: "no relay is witnessing this" })) as
      Record<string, unknown>;

    // PRECONDITION, stated rather than assumed: this is the SUCCESS path. If the send had failed
    // outright the assertions below would be about a different branch entirely, and would pass for
    // a reason that has nothing to do with witnessing.
    expect(res["ok"], `the send must succeed for this to be about witnessing: ${JSON.stringify(res)}`).toBe(true);

    // And the daemon agreed it was unwitnessed — read from its own event, not inferred from the
    // fixture's shape, so this test cannot drift away from the branch it means to cover.
    expect(
      fx.eventsNamed("session.tree.own_leaf_unwitnessed").length,
      "PRECONDITION: the daemon must consider this leaf unwitnessed",
    ).toBe(1);

    expect(
      res["witnessed"],
      `the operator's only readable surface must carry the fact: ${JSON.stringify(res)}`,
    ).toBe(false);

    /**
     * NAME THE VALUE, not its shadow. `expect(guidance).toBeDefined()` would stay green for a
     * guidance string about something else entirely — and a wrong remedy costs the reader more than
     * no remedy, because it spends their trust as well as their time.
     */
    const guidance = String(res["guidance"] ?? "");
    expect(guidance, `guidance must say the relay did not witness it: ${JSON.stringify(res)}`)
      .toMatch(/did not witness/i);
    expect(guidance, "and must tell them NOT to resend — a resend takes a second position in the record")
      .toMatch(/not resend|do not resend/i);
  }, 60_000);
});
