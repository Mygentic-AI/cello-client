/**
 * A TEARDOWN MUST SETTLE A PENDING SALT AGREEMENT, NEVER DROP IT — 037-SESSIONCORE.
 *
 * ─── The regression this pins, and what a user lived through ─────────────────────────────────
 *
 * `#saltPending` holds a PROMISE that an outbound send is awaiting: `contentHashForSession` asks
 * "am I salted?", and if an agreement is in flight it waits for the answer before hashing. Every
 * outbound message goes through it.
 *
 * Session teardown has always ended that wait by SETTLING the promise with `"closed"`, which is what
 * lets the waiting send return `session_torn_down` and carry on unsalted. 037-SESSIONCORE moved the
 * salt maps into `SessionSalts` and, for tidiness, added `#saltPending` to its `evictSession` —
 * eleven deletes where the manager had only ever hand-deleted ten.
 *
 * Because `evictSession` runs FIRST, the settle on the next line then found nothing and returned.
 * The promise was never resolved. Its five-second timer fired into the same empty map and also
 * returned. **Nothing ever resolved it**, so `cello_send` hung forever — no error, no log, no
 * timeout — for any message in flight when its session was closed, retired or reaped.
 *
 * ─── Why the suite did not catch it, which is the point of this file ─────────────────────────
 *
 * 4,963 tests were green with the bug in. Nothing anywhere asserted `session_torn_down`, and nothing
 * exercised `settled === "closed"`. A branch with no test is not covered by a large suite; it is
 * only surrounded by one.
 */
import { describe, it, expect, afterEach } from "vitest";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import { UNSALTED_REASONS } from "../session-node-types.js";

const SID = "b1b2b3b4b5b6b7b8b9b0c1c2c3c4c5c6";
const BODY = new TextEncoder().encode("a message in flight when the session went away");

describe("037-SESSIONCORE: a torn-down session settles its pending salt agreement", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { await fx?.cleanup(); fx = null; });

  it("★★ a send awaiting the agreement RETURNS when the session is torn down — it does not hang", async () => {
    fx = await startTwoConnectionFixture();
    await fx.createSession(SID, "alice");

    // Arm an agreement that will never be answered: this is the state every outbound send waits in
    // between announcing its half and hearing the peer's.
    fx.snm.markSaltPendingForTest("alice", SID);

    // The send starts waiting. It must not be awaited yet — the whole defect is that it never
    // settles, so awaiting here would hang the test rather than fail it.
    const inFlight = fx.snm.contentHashForSession("alice", SID, BODY);

    // Tear the session down underneath it, exactly as close / retire / reap do.
    await fx.snm.destroySessionNode("alice", SID);

    /**
     * ⚠️ THE BOUND IS THE ASSERTION. Without it a regression does not fail this test, it HANGS it —
     * and a hanging test reads as an infrastructure problem rather than as the bug it is. The five
     * seconds is the agreement's own timeout: if the promise is settled correctly this resolves
     * immediately, and if it is dropped we outlive even the timer that was supposed to save us.
     */
    const settled = await Promise.race([
      inFlight.then((r) => ({ ok: true as const, r })),
      new Promise<{ ok: false }>((resolve) => setTimeout(() => resolve({ ok: false }), 5_000)),
    ]);

    expect(
      settled.ok,
      "the send never returned: a pending salt agreement was DELETED by the teardown instead of " +
        "being settled, so nothing resolves the promise the send is awaiting and cello_send hangs " +
        "with no error, no log and no timeout",
    ).toBe(true);
  }, 20_000);

  it("★ and it is told the SESSION went away, not that its counterparty refused", async () => {
    fx = await startTwoConnectionFixture();
    await fx.createSession(SID, "alice");
    fx.snm.markSaltPendingForTest("alice", SID);

    const inFlight = fx.snm.saltForHashingForTest("alice", SID);
    await fx.snm.destroySessionNode("alice", SID);
    const outcome = await inFlight;

    /**
     * `closed` is reached by TWO routes and they mean opposite things to an operator: the peer
     * saying "I cannot adopt" is a settled bilateral outcome on a healthy session, while a teardown
     * means there is no session left at all. The live node is what distinguishes them, so a test
     * that only asserted "it returned" would pass with the two collapsed into one.
     */
    expect(outcome.salt).toBeNull();
    expect(
      outcome.reason,
      "a teardown must not be reported as the counterparty closing adoption — that sends the " +
        "operator to ask their counterparty about a session that no longer exists on this side",
    ).toBe(UNSALTED_REASONS.SESSION_TORN_DOWN);
  }, 20_000);
});
