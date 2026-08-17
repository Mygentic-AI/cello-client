/**
 * DOD-M12B-CLOSE-SILENT-WAIT-1 — an eleven-minute wait must not look like a dead daemon.
 *
 * `cello_close_session` with no `force`, on a session the counterparty never joined, returns
 * NOTHING for eleven minutes and then succeeds with a real notarized unilateral receipt. It is not
 * a hang: `CELLO_SEAL_BILATERAL_TIMEOUT_MS` defaults to 660,000 ms, and the close waits it out
 * before escalating. Measured 2026-08-17 on daemon 0.0.170 — seal leaf submitted 16:48:55.137,
 * ceremony completed 17:00:01.508, a gap of 11m 06s.
 *
 * The wait is correct: it is what earns the receipt. THE SILENCE IS THE DEFECT. Nothing tells
 * anyone it is happening, so an operator watching a frozen command concludes it is broken and
 * reaches for `force: true` — which forfeits the exact receipt the wait was about to produce. That
 * is not hypothetical: seventeen sessions were force-closed that day because the first normal close
 * looked dead.
 *
 * This unit does NOT change the ceremony or when the caller is answered. It makes the wait
 * observable from another window, which is the half that can be shipped without touching what the
 * seal signs. Answering the caller early is a change to the close contract and is parked as a
 * decision, not taken here.
 *
 * Revert test: drop `sealing` from the status row and the first case fails — a session mid-seal
 * becomes indistinguishable from an idle one again.
 */
import { describe, it, expect, afterEach } from "vitest";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import type { DaemonStatusResponse } from "../types.js";

const SID = "5a".repeat(32);
const IDLE = "5b".repeat(32);

describe("DOD-M12B-CLOSE-SILENT-WAIT-1: a seal in flight is visible while it runs", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  async function status(f: TwoConnectionFixture): Promise<DaemonStatusResponse> {
    const client = await f.connect();
    return (await client.send("status", {})) as unknown as DaemonStatusResponse;
  }

  it("a session waiting on its counterparty's seal says so; an idle one does not", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg011-" });
    await fx.createSession(SID, "alice");
    await fx.createSession(IDLE, "alice");

    // The state a close enters and then sits in for eleven minutes.
    fx.markSealInFlightForTest("alice", SID);

    const rows = (await status(fx)).active_sessions;
    const sealing = rows.find((r) => r.sessionId === SID);
    const idle = rows.find((r) => r.sessionId === IDLE);

    expect(sealing!.sealing, "an operator whose close looks frozen must be able to see it working").toBe(true);
    // A flag on everything is a flag on nothing — the neighbouring session must stay unmarked.
    expect(idle!.sealing).toBe(false);
  }, 60_000);

  it("the wait announces itself when it STARTS, with the deadline and the cost of forcing", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-msg011b-" });
    await fx.createSession(SID, "alice");
    fx.markSealInFlightForTest("alice", SID);

    // The log is what a second window reads while the first is blocked. It has to carry the two
    // facts that stop the operator reaching for force: how long this can legitimately take, and
    // that forcing destroys the receipt being earned.
    const ev = fx.eventsNamed("session.seal.awaiting_counterparty");
    expect(ev.length, "the wait must announce itself at the start, not only at the end").toBe(1);
    expect(ev[0]!.ctx["deadlineMs"], "name the deadline — 11 minutes of silence is otherwise indistinguishable from a hang").toBe(660_000);
    expect(String(ev[0]!.ctx["impact"]), "and say what forcing costs").toMatch(/receipt/i);
  }, 60_000);
});
