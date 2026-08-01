/**
 * DOD-COATTEND-1 (review F2, BLOCKING) — a durable-write failure must not wear the quiet-
 * counterparty label.
 *
 * `recordTranscriptMessage` catches a write failure, logs it, and returns normally. That was
 * survivable before Tier 1, and the code's own comment said exactly why: "cello_receive still
 * delivers it live from the in-memory buffer (masking the loss)."
 *
 * Tier 1 deleted that mitigation. Delivery now reads the transcript, so a swallowed received-row
 * write is TOTAL content loss: the message is verified, leafed, hash-chained, the doorbell rings,
 * every attached session wakes — and every one of them finds nothing and times out with
 *
 *     "No content arrived within timeout_ms — the counterparty has not sent anything."
 *
 * A local SQLCipher failure, reported as the counterparty being quiet. The operator debugs the
 * wrong machine. That is textbook error substitution, and it is the failure mode this project's
 * debugging discipline names first: the error message describes where it surfaced, not what broke.
 *
 * This unit does NOT make the write succeed — a failing disk is a failing disk. It makes the
 * failure REACH THE CALLER, which is the part that was missing.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";

const SID = "ab".repeat(32);

describe("DOD-COATTEND-1 F2: a swallowed transcript write is reported as itself", () => {
  let fx: TwoConnectionFixture;

  beforeEach(async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-m8d-writefail-" });
  });
  afterEach(async () => { await fx.cleanup(); });

  /**
   * Break the write at the SQL layer, the way a full/locked/corrupt disk does.
   *
   * NOT by stubbing `recordTranscriptMessage` — the first version of this file did exactly that and
   * both clauses passed against the BROKEN build, because replacing the method also replaces the
   * `try/catch` that swallows, so the throw under test was the stub's own. The defect lives INSIDE
   * that catch, so the failure has to originate under it.
   */
  function breakTranscriptWrites(): void {
    const db = fx.snm.getDb() as unknown as { prepare: (sql: string) => unknown };
    const realPrepare = db.prepare.bind(db);
    db.prepare = (sql: string) => {
      if (/INSERT OR IGNORE INTO transcript/i.test(sql)) throw new Error("SQLITE_FULL: database or disk is full");
      return realPrepare(sql);
    };
  }

  it("W1: the ingest FAILS instead of reporting success on a message it could not durably record", async () => {
    await fx.createSession(SID, "alice");
    breakTranscriptWrites();

    // Before the fix this was an ordinary success — `{ok: true, leafIndex: 0, ...}`: the leaf was
    // committed, the doorbell rang, and nothing anywhere said the plaintext had not landed.
    //
    // It reports `ok: false`, not a throw. The ingest contract already has a failure arm
    // (`{ok: false, reason}`) and every caller handles it, so a durable-write failure travels the
    // path that exists rather than introducing an exception the relay and park callers would have
    // to learn. (This clause originally asserted `.rejects` — that was the test being written
    // against an imagined contract instead of the real one.)
    const r = (await fx.ingestReceived("alice", SID, "the message that never landed")) as Record<string, unknown>;
    expect(r.ok, "a message that cannot be durably recorded must not be reported as ingested").toBe(false);
    expect(r.reason).toBe("transcript_write_failed");
  });

  it("W2: cello_receive does not blame the counterparty for a local write failure", async () => {
    await fx.createSession(SID, "alice");
    const conn = await fx.connectAs("alice");
    breakTranscriptWrites();

    await fx.ingestReceived("alice", SID, "lost to the disk").catch(() => { /* W1 covers the throw */ });

    const r = (await conn.send("cello_receive", { session_id: SID, timeout_ms: 400 })) as Record<string, unknown>;
    // Measured, not assumed — the pre-fix answer, verbatim:
    //   "No content arrived within timeout_ms. Call cello receive again to keep waiting — do not
    //    resend your last message. Or read cello transcript for the full session history."
    // Every clause of that is wrong here. Waiting cannot help; the transcript does not contain it;
    // and "do not resend" is advice to the one party who could still fix this. It is the answer for
    // a quiet counterparty, handed to an operator whose disk is full.
    expect(r.reason, "the local failure must be named, not inferred").toBe("content_undeliverable");
    expect(String(r.guidance)).toMatch(/could not be (written|recorded)|durabl|disk/i);
    expect(String(r.guidance), "must not send them back to wait on a counterparty who already sent")
      .not.toMatch(/keep waiting/);
  });
});
