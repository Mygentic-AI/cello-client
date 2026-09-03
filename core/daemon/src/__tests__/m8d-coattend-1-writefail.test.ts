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

  /**
   * DOD-M15-NO-SILENT-REFUSAL-1 review F2 — the two LOST reasons had no notice test.
   *
   * W1 and W2 assert the ingest's return and the receive exit's `reason`. Neither touches the
   * durable notice, so deleting either `noteContentRefusal` call left the whole gate green — the
   * same hollow shape a mutant already exposed on the inbox door, present here twice.
   *
   * Why it matters that these are DURABLE: `#undeliverableSeqs` is in memory, so the receive exit
   * stops being able to say this after a restart while the hole in the transcript is permanent. And
   * the exit only runs if somebody is attending, which is the case the whole line exists for.
   */
  it("W3: a lost message leaves a DURABLE notice, in both halves — the ingest's and the append's", async () => {
    await fx.createSession(SID, "alice");
    breakTranscriptWrites();
    await fx.ingestReceived("alice", SID, "lost to the disk");

    const notices = fx.snm.takeContentRefusals("alice", SID, "op");
    const reasons = notices.map((n) => n.reason).sort();
    expect(
      reasons,
      "both producers must file: the APPEND records that the text is gone, and the INGEST records " +
      "that the sender was told the ingest failed and is now retrying into a leaf whose plaintext " +
      "is not there. A reader fixing the disk needs both facts.",
    ).toEqual(["content_undeliverable", "transcript_write_failed"]);
    for (const n of notices) {
      expect(n.kind, "these are LOST, not refused — the message was verified and committed").toBe("lost");
      // Read across BOTH fields: one of these two notices puts the local-fault sentence in its
      // impact and the other in its guidance, and pinning which would be pinning prose rather than
      // the property. What must hold is that the operator is not sent to the counterparty.
      expect(
        `${n.impact} ${n.guidance}`,
        "it must name THIS machine — a quiet counterparty is the wrong place to look",
      ).toMatch(/THIS machine/);
      expect(`${n.impact} ${n.guidance}`).toMatch(/disk space/);
      /**
       * The reader is usually already in a coding agent, so the guidance sends them to LOOK rather
       * than listing symptoms — and support is the EXIT, not the first step. An operator sent
       * straight to support for a full disk has been wasted.
       */
      expect(n.guidance, "it tells them to go and find the cause").toMatch(/coding agent/);
      expect(n.guidance, "and names support only as the last resort").toMatch(/If you genuinely cannot work out the cause, reach out to CELLO_Support/);
    }
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
