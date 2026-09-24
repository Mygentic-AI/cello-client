/**
 * NO AGREEMENT, NO SALT — `DOD-M15-SEALWIRE-1` bullet 6, part B2b-2.
 *
 * A session salts only once both sides' contributions have produced an agreed salt. A counterparty
 * that never answers the agreement leaves the session unsalted, and the unknown frame on the far
 * side is reported rather than swallowed.
 */

import { describe, it, expect, afterEach } from "vitest";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import { encodeCbor } from "@cello-protocol/protocol-types";
import * as lp from "it-length-prefixed";

const SID = "3d".repeat(32);
const PEER = "12D3KooWQYV9dGMFoRzNStwpXztXaBUjtPqi6aMghfATmPnRAENn";
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** A frame type no build knows. */
function unknownFrame(): Uint8Array {
  return lp.encode.single(encodeCbor({
    type: "session_salt_agreement_v9_from_the_future", session_id: SID,
  }) as Uint8Array).subarray();
}

function storedSalt(fx: TwoConnectionFixture): Uint8Array | null {
  const agentId = (fx.snm.getDb().prepare("SELECT agent_id FROM agents WHERE agent_name = ?").get("alice") as { agent_id: string }).agent_id;
  const row = fx.snm.getDb()
    .prepare("SELECT content_salt FROM sessions WHERE agent_id = ? AND session_id = ?")
    .get(agentId, SID) as { content_salt: Uint8Array | null } | undefined;
  return row?.content_salt ? new Uint8Array(row.content_salt) : null;
}

describe("DOD-M15-SEALWIRE-1 B2b-2: no agreement, no salt", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  it("★ a peer that does not speak the agreement leaves the session UNSALTED — no agreement, no salt", async () => {
    /**
     * The case that will actually happen: every published build predates both features. Verified
     * against the last release tag — an unrecognised frame type on the content stream is logged and
     * returned from, never an error and never a stream close — so a salt frame reaching an old peer
     * costs them one WARN line and produces no reply at all.
     *
     * This side must therefore stay unsalted, which is exactly what makes "they agreed" a usable
     * signal: silence is a NO, not a maybe. Driven with a frame type no build knows, which is what
     * this side's own frames look like to a peer that predates them.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-cap-old-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    await fx.snm.handleContentFrameForTest("alice", SID, unknownFrame(), PEER);
    await wait(200);

    expect(
      storedSalt(fx),
      "an unanswered agreement must not produce a salt — a side that salts alone sends messages its counterparty can never verify",
    ).toBeNull();
    expect(
      fx.eventsNamed("session.salt.agreed").length,
      "and it must not BELIEVE it agreed one either",
    ).toBe(0);
  }, 60_000);

  it("★ and the unknown frame is REPORTED, not swallowed — the old peer's side of the same exchange", async () => {
    /**
     * This is what the counterparty's log will show, and it is the only trace either operator gets
     * of a version mismatch. A silent drop here would make "my counterparty is on an old build" and
     * "the message never arrived" indistinguishable — and those have completely different fixes.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-cap-report-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", PEER);

    await fx.snm.handleContentFrameForTest("alice", SID, unknownFrame(), PEER);
    await wait(200);

    const seen = fx.eventsNamed("session.content.frame_unknown_type");
    expect(seen.length, "a frame we do not understand must leave a trace").toBe(1);
    expect(
      String(seen[0]!.ctx!["type"]),
      "and must name WHICH frame, or the operator cannot tell which feature their peer is missing",
    ).toBe("session_salt_agreement_v9_from_the_future");
  }, 60_000);
});
