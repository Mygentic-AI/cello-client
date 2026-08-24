/**
 * DOD-M15-SEALWIRE-1 bullet 5 — THE WIRING, EXECUTED.
 *
 * ─── Why this file exists, and it is the review finding rather than a nicety ────────────────────
 *
 * Both lanes shipped the sent half with **zero execution of the path**. The three tests in
 * `dod-m15-sealwire-1-authorship.test.ts` call `recordTranscriptMessage` directly with hand-built
 * bytes (`fill(0x7e)`, `fill(0x5a)`), so they prove the STORE accepts a pubkey and a signature and
 * say nothing about whether anything ever hands it one.
 *
 * **The concrete bypass:** delete `authorship` from `sendContent`'s return, delete all five
 * call-site arguments, and that entire suite stays green.
 *
 * And it was not theoretical — review found **two of the five call sites were dead by
 * construction**, sitting inside `if (!sendResult.ok)` while the helper read `r.ok ? … : undefined`.
 * They typechecked. They looked wired. They could never fire. That is invisible to any test that
 * does not drive a real send.
 *
 * ─── What this drives ──────────────────────────────────────────────────────────────────────────
 *
 * `cello_send` over IPC, through the real handler, against the fixture's relay — so the path runs
 * end to end: submit → signature captured → `SubmitResult` → `sentAuthorship()` → the transcript
 * write. Then it reads the row back out of SQLite and looks at the stored bytes.
 */

import { describe, it, expect, afterEach } from "vitest";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";

const SID = "cc".repeat(32);

interface Row {
  direction: string;
  attribution: string;
  sender_pubkey: string | null;
  sender_sig: Uint8Array | null;
}

describe("DOD-M15-SEALWIRE-1 bullet 5 — a real send stores a real proof", () => {
  let fx: TwoConnectionFixture | null = null;
  afterEach(async () => { if (fx) await fx.cleanup(); fx = null; });

  function sentRows(agent: string, sessionId: string): Row[] {
    const db = fx!.snm.getDb()!;
    const agentId = (db
      .prepare("SELECT agent_id FROM agents WHERE agent_name = ? AND state != 'retired'")
      .get(agent) as { agent_id: string }).agent_id;
    return db
      .prepare(
        `SELECT direction, attribution, sender_pubkey, sender_sig
           FROM transcript WHERE agent_id = ? AND session_id = ? AND direction = 'sent'
          ORDER BY sequence ASC`,
      )
      .all(agentId, sessionId) as unknown as Row[];
  }

  it("★ THE WIRING RUNS: a sent row written by the real send path carries a stored signature", async () => {
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-sentproof-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex", undefined, { relay: true });

    const client = await fx.connectAs("alice");
    const res = (await client.send("cello_send", {
      session_id: SID, content: "the message whose authorship must be provable",
    })) as { ok?: boolean; reason?: string };

    const rows = sentRows("alice", SID);
    expect(
      rows.length,
      `the send must have produced a sent transcript row — got ${JSON.stringify(res)}`,
    ).toBeGreaterThan(0);

    const row = rows[0]!;
    expect(
      row.attribution,
      "a message we wrote is self_authored, whatever proof it carries — we produced that signature, " +
        "we did not verify a counterparty's key",
    ).toBe("self_authored");

    /**
     * THE ASSERTION THE UNIT WAS MISSING. Everything above would pass with `authorship` deleted from
     * the return type and every call site; this is the line that does not.
     */
    expect(
      row.sender_sig,
      "the relay witnessed and signed this send, so the row must carry the proof — if this is null " +
        "the wiring from the submit result to the transcript write is not connected, which is " +
        "exactly what shipped and typechecked",
    ).not.toBeNull();
    expect(row.sender_sig!.length, "a 64-byte Ed25519 signature").toBe(64);
    expect(row.sender_pubkey, "and the key it verifies against, as hex").toMatch(/^[0-9a-f]{64}$/);
  });

  it("★ an UNWITNESSED send stores no proof, and does not fabricate one", async () => {
    /**
     * The pair, and the one that keeps the fix honest. Without a relay there is no submit, so no
     * Structure 1 goes on the wire and there is nothing signed to store. The row must record
     * `self_authored` with NO signature — the truthful answer — rather than a placeholder that
     * would make an unprovable row look provable.
     *
     * This is also the discriminator the schema comment now names: `self_authored` covers both, and
     * `sender_sig IS NOT NULL` is what separates them.
     */
    fx = await startTwoConnectionFixture({ dirPrefix: "cello-sentproof-bare-" });
    await fx.createSession(SID, "alice", "bobpubkeyhex");

    const client = await fx.connectAs("alice");
    await client.send("cello_send", { session_id: SID, content: "no relay witnessed this" });

    const rows = sentRows("alice", SID);
    if (rows.length === 0) return; // no leaf committed at all — nothing to assert about a row
    expect(rows[0]!.attribution).toBe("self_authored");
    expect(
      rows[0]!.sender_sig,
      "nothing was signed, so nothing is stored — never a placeholder that implies a proof",
    ).toBeNull();
  });
});
