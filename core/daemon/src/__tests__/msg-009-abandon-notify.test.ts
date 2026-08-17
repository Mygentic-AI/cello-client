/**
 * DOD-M12B-ABANDON-NOTIFY-1 — tell the far side you have hung up.
 *
 * `cello_close_session { force: true }` marks the session terminal on THIS side and does nothing
 * else. The counterparty keeps its half live, keeps retrying delivery into it, and keeps trying to
 * re-establish the connection — forever, because nothing will ever answer.
 *
 * That is what produced the 2026-08-17 "notification storm": after several force-abandons, the
 * surviving halves called continuously and the operator saw connection requests from agents nobody
 * was driving. The existing guidance warns that the receipt is forfeited; it never said the other
 * side would keep calling.
 *
 * BEST-EFFORT BY CONSTRUCTION, and the guidance says so. A peer that is offline cannot be told, so
 * the notice is an improvement on silence, not a guarantee — and it must never delay or fail the
 * abandon itself, which is the operator's escape hatch from a session that can never seal.
 *
 * Authentication is the same rail the delivery acknowledgement rides: the stream is Noise-
 * authenticated to this session's peer and the handler already refuses a frame that names a
 * different session. Only the counterparty can abandon their own half, and doing so is their right
 * — the alternative on offer is that they simply stop answering, which is worse for us.
 *
 * Revert test: drop the notice from the force branch and the first case fails — B stays active and
 * goes on being a live session with nobody behind it.
 */
import { describe, it, expect, afterEach } from "vitest";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";

const SID = "ab".repeat(32);

describe("DOD-M12B-ABANDON-NOTIFY-1: a force-abandon reaches the counterparty", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  it("the surviving half retires itself when it is told, instead of calling forever", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg009-" });
    const { snm } = fx;
    await fx.createSession(SID, "alice");
    fx.seedReceived("alice", SID, "a conversation that happened");

    expect(snm.getSessionRecord("alice", SID)!.status).toBe("active");

    // The frame the counterparty sends when they force-abandon. It arrives on the session's own
    // authenticated content stream, exactly as a delivery acknowledgement does.
    const retired = snm.retireOnCounterpartyAbandon("alice", SID, "corr");
    expect(retired, "a live session told its counterparty has gone must retire").toBe(true);
    expect(snm.getSessionRecord("alice", SID)!.status).toBe("abandoned");

    const notice = fx.eventsNamed("session.counterparty.abandoned");
    expect(notice.length, "the operator must be able to see why their session ended").toBe(1);
  }, 60_000);

  it("the transcript survives — retiring is not deleting", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg009b-" });
    const { snm } = fx;
    await fx.createSession(SID, "alice");
    fx.seedReceived("alice", SID, "worth keeping");

    snm.retireOnCounterpartyAbandon("alice", SID, "corr");

    // The counterparty walking away forfeits the notarized receipt. It must not also cost the
    // operator the record of what was actually said — that is theirs, and it is the whole product.
    const rows = snm.getDb()
      .prepare("SELECT COUNT(*) AS n FROM transcript WHERE session_id = ?")
      .get(SID) as { n: number };
    expect(rows.n, "an abandoned session keeps everything it received").toBe(1);
    expect(snm.getSessionTree("alice", SID).size()).toBe(1);
  }, 60_000);

  it("a session that already ended is not disturbed, and says nothing twice", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg009c-" });
    const { snm } = fx;
    await fx.createSession(SID, "alice");
    snm.getDb().prepare("UPDATE sessions SET status = 'sealed' WHERE session_id = ?").run(SID);

    // A late or duplicated notice must not reopen, re-terminate, or re-announce anything — and it
    // must certainly not turn a SEALED session, which has a notarized receipt, into an abandoned
    // one. That would destroy the artifact the protocol exists to produce.
    const retired = snm.retireOnCounterpartyAbandon("alice", SID, "corr");
    expect(retired).toBe(false);
    expect(snm.getSessionRecord("alice", SID)!.status, "a sealed session must stay sealed").toBe("sealed");
    expect(fx.eventsNamed("session.counterparty.abandoned")).toEqual([]);
  }, 60_000);

  it("an unknown session is refused, not created", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg009d-" });
    const { snm } = fx;
    // A notice naming a session this agent does not have must not bring one into existence, however
    // authenticated the stream is.
    expect(snm.retireOnCounterpartyAbandon("alice", "cc".repeat(32), "corr")).toBe(false);
    expect(snm.getSessionRecord("alice", "cc".repeat(32))).toBeNull();
  }, 60_000);
});
