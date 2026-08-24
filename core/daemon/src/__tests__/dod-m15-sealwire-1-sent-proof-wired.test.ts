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
 * ─── ⚠️ WHAT THIS DOES AND DOES NOT COVER — corrected after the first version asserted more ────
 *
 * My first version drove `cello_send` over IPC and asserted the stored row carries a signature. **It
 * failed, and the code was not the reason.** `two-connection-fixture`'s relay points at
 * `/ip4/127.0.0.1/tcp/1` — a dead address — so nothing is ever witnessed through it, no submit
 * happens, and there is legitimately nothing signed to store. **I asserted a precondition the
 * fixture never establishes**, which is the same mistake as the rest of this bullet wearing
 * different clothes.
 *
 * So what is covered here:
 *   1. **The dead-wiring defect itself**, at the seam it lived in — `sentAuthorship` must read the
 *      proof off the FAILURE shape as well as the success one. That is the assertion that was false
 *      in shipped code, and it is unit-exact rather than incidental.
 *   2. **The honest negative** — an unwitnessed send stores no signature and fabricates none.
 *
 * **STILL NOT COVERED, and named so it is not mistaken for done:** a WITNESSED send driven end to
 * end, asserting the stored row carries the proof. That needs a relay that actually acks;
 * `m8c-away-1.test.ts` has one (`makeFakeRelayServerOneshot` plus its node subclass), and promoting
 * it into a shared helper is the way in. **Carried, not silently skipped.**
 */

import { describe, it, expect, afterEach } from "vitest";
import { startTwoConnectionFixture, type TwoConnectionFixture } from "./helpers/two-connection-fixture.js";
import { sentAuthorship } from "../session-content-handlers.js";

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

  it("★ THE DEAD-WIRING BUG, pinned: the helper must read the proof off BOTH result shapes", () => {
    /**
     * ⚠️ THE EXACT DEFECT REVIEW FOUND, and the one an end-to-end test would have caught only by
     * accident.
     *
     * `sentAuthorship` read `r.ok ? r.authorship : undefined`. Two of the five call sites live
     * inside `if (!sendResult.ok)` — so at those two it was **unconditionally undefined**. It
     * typechecked. It looked wired. It could never fire, and the consequence was that every
     * durably-queued send (witnessed, SIGNED, only the direct hand-off failed) wrote a row with no
     * proof while the proof sat in the result object.
     *
     * A failure-shaped result carrying `authorship` is not a contrivance: `sendContent`'s failure
     * member carries `sequenceNumber` for exactly the same reason, and has since long before this
     * bullet — *"a DURABLY QUEUED message still owns the position the relay witnessed for it."*
     */
    const proof = { senderPubkey: new Uint8Array(32).fill(0x11), senderSig: new Uint8Array(64).fill(0x22) };

    expect(
      sentAuthorship({ ok: true, delivered: true, sequenceNumber: 3, authorship: proof } as never),
      "the delivered path carries it",
    ).toBe(proof);

    expect(
      sentAuthorship({
        ok: false, reason: "session_stream_unavailable", error: "x", durable: true,
        sequenceNumber: 3, authorship: proof,
      } as never),
      "and so does the DURABLY QUEUED path — this is the assertion that was false in shipped code, " +
        "and the two call sites that read it are unreachable on any ok-gated read",
    ).toBe(proof);

    expect(
      sentAuthorship({ ok: false, reason: "no_node", error: "x", durable: false } as never),
      "a result with no proof yields none — never a placeholder",
    ).toBeUndefined();
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
    // NOTE: this fixture's relay (when enabled) points at /ip4/127.0.0.1/tcp/1 — a dead address, so
    // nothing is ever witnessed through it. That is why the WITNESSED half of this bullet is not
    // asserted here: see the header.

    const client = await fx.connectAs("alice");
    await client.send("cello_send", { session_id: SID, content: "no relay witnessed this" });

    const rows = sentRows("alice", SID);
    // ASSERTED, not skipped: an early return here would let this pass while proving nothing, which
    // is the shape the whole bullet keeps producing.
    expect(rows.length, "the send must still commit a leaf and write its row").toBeGreaterThan(0);
    expect(rows[0]!.attribution).toBe("self_authored");
    expect(
      rows[0]!.sender_sig,
      "nothing was signed, so nothing is stored — never a placeholder that implies a proof",
    ).toBeNull();
  });
});
