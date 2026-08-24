/**
 * DOD-M15-SEALWIRE-1 bullet 5 — a transcript row proves authorship, or says it cannot.
 *
 * ─── What the row used to be, and why that is not enough ───────────────────────────────────────
 *
 * `(agent_id, session_id, sequence, direction, blob, created_at)`. Attribution came entirely from
 * local session state: *this arrived on the socket I believed was Bob's*. That is fine while a
 * transcript is only ever read by its owner, and worthless the moment it is shown to anyone else —
 * which is the whole reason a notarized record exists.
 *
 * The daemon ALREADY had the proof. `#recordFrameOrdering` verifies the Structure-2 signature
 * against the pubkey inside the sender's own signed bytes, then matches that signer to this
 * session's counterparty. It made the strongest statement it ever makes about who wrote a message,
 * used it to choose a sequence number, and discarded it.
 *
 * ─── The assertion that matters is the DISTINCTION, not the value ──────────────────────────────
 *
 * A test that only checks "a verified row has a signature" would pass against a schema that writes
 * a signature into every row regardless — including rows whose author was never proven. That is the
 * defect this bullet exists to close, not a lesser version of it.
 *
 * So both halves are asserted here: a proven row says `verified_signature` and carries the bytes,
 * and an unproven row says `local_session_state` and carries NOTHING. The soft path is real —
 * `session.content.ordering.decode_failed` falls back to hash-dedup and ingests without a verified
 * record — so rows without proof legitimately exist, and the column's job is to make them
 * distinguishable rather than to pretend they do not.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { startDaemon, type DaemonHandle } from "../daemon.js";
import { FileKeyProvider } from "@cello-protocol/crypto";
import type { Logger } from "../types.js";

interface TranscriptRow {
  direction: string;
  sender_pubkey: string | null;
  sender_sig: Uint8Array | null;
  attribution: string;
}

describe("DOD-M15-SEALWIRE-1 bullet 5 — the transcript records HOW a message is attributed", () => {
  let tempDir: string;
  let handle: DaemonHandle | null;
  let logger: Logger;

  beforeEach(async () => {
    process.env["CELLO_ENV"] = "test";
    tempDir = await mkdtemp(join(tmpdir(), "cello-authorship-"));
    logger = { debug() {}, info() {}, warn() {}, error() {} };
    handle = null;
  });

  afterEach(async () => {
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* stopped */ } }
    await rm(tempDir, { recursive: true, force: true });
    delete process.env["CELLO_ENV"];
  });

  async function startWithAgent(name: string): Promise<DaemonHandle> {
    await mkdir(join(tempDir, "agents", name), { recursive: true });
    await FileKeyProvider.load(join(tempDir, "agents", name, "key"));
    handle = await startDaemon({
      securityGateway: new PassthroughGatewayClient(),
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger,
    });
    return handle;
  }

  function rowsFor(session: string): TranscriptRow[] {
    const db = handle!.getSessionNodeManager().getDb()!;
    return db
      .prepare(
        `SELECT direction, sender_pubkey, sender_sig, attribution
           FROM transcript WHERE session_id = ? ORDER BY sequence ASC`,
      )
      .all(session) as unknown as TranscriptRow[];
  }

  it("a row written WITHOUT verified authorship says so, and carries no signature", async () => {
    /**
     * The soft path. `recordTranscriptMessage` is called with no authorship argument — which is
     * exactly what happens when the ordering record is absent or fails to decode, and the message
     * is still ingested via hash-dedup.
     *
     * The row must not be silent about that. `attribution` is NOT NULL precisely so this case has
     * to name itself: without it, a nullable signature column would leave a proven row and an
     * assumed row structurally identical, which is the defect rather than the fix.
     */
    const h = await startWithAgent("alice");
    const mgr = h.getSessionNodeManager();
    const ok = mgr.recordTranscriptMessage("alice", "s-soft", 0, "received", new TextEncoder().encode("hi"), "t1");
    expect(ok, "the row must be written even without proof — an unproven message is still a message").toBe(true);

    const [row] = rowsFor("s-soft");
    expect(row, "the row exists").toBeDefined();
    expect(
      row!.attribution,
      "a row with no verified signature must SAY it is attributed by local session state, not stay silent",
    ).toBe("local_session_state");
    expect(row!.sender_sig, "no signature was proven, so none is stored — never a placeholder").toBeNull();
    expect(row!.sender_pubkey, "and no sender key is claimed either").toBeNull();
  });

  it("a row written WITH verified authorship carries the signature and says it is verified", async () => {
    const h = await startWithAgent("alice");
    const mgr = h.getSessionNodeManager();
    const senderPubkey = new Uint8Array(32).fill(0xab);
    const senderSig = new Uint8Array(64).fill(0xcd);

    const ok = mgr.recordTranscriptMessage(
      "alice", "s-proven", 0, "received", new TextEncoder().encode("hi"), "t2",
      { senderPubkey, senderSig },
    );
    expect(ok).toBe(true);

    const [row] = rowsFor("s-proven");
    expect(row!.attribution, "a verified row must say so").toBe("verified_signature");
    expect(row!.sender_pubkey, "the pubkey is stored as hex, from INSIDE the sender's signed bytes")
      .toBe("ab".repeat(32));
    expect(
      row!.sender_sig === null ? null : Buffer.from(row!.sender_sig).toString("hex"),
      "the 64-byte Structure-2 signature is stored verbatim — this is the proof itself, not a digest of it",
    ).toBe("cd".repeat(64));
  });

  it("a SENT row says self_authored — not the same thing as an unproven received row", async () => {
    /**
     * Caught by review of the first version of this work, and it is the same defect the column
     * exists to prevent surviving one layer up, in the enum.
     *
     * `local_session_state` originally covered two OPPOSITE rows:
     *   - one this agent AUTHORED — provenance fully known, merely not third-party-provable; and
     *   - one RECEIVED on the soft fallback — provenance unknown, nobody's signature checked.
     *
     * A reader shown the transcript later could not tell "he wrote this himself" from "something
     * arrived on a socket and was trusted". Structurally identical rows with different
     * trustworthiness is precisely what a nullable signature column would have produced, and
     * refusing that at the column level while allowing it at the value level fixes nothing.
     */
    const h = await startWithAgent("alice");
    const mgr = h.getSessionNodeManager();
    const enc = new TextEncoder();

    mgr.recordTranscriptMessage("alice", "s-dir", 0, "sent", enc.encode("mine"), "t5");
    mgr.recordTranscriptMessage("alice", "s-dir", 1, "received", enc.encode("theirs"), "t6");

    const rows = rowsFor("s-dir");
    expect(
      rows.map((r) => r.attribution),
      "an authored row and an unverified received row must NOT share a value — knowing who wrote " +
        "something and having no idea are different facts about the record",
    ).toEqual(["self_authored", "local_session_state"]);
  });

  it("★ A SENT ROW CAN CARRY OUR OWN SIGNATURE — and is still `self_authored`, not `verified`", async () => {
    /**
     * DOD-M15-SEALWIRE-1 bullet 5, SENT half.
     *
     * ─── The asymmetry this closes ───────────────────────────────────────────────────────────────
     *
     * A RECEIVED row carries the counterparty's pubkey and signature, so a third party can check it.
     * A SENT row carried `self_authored` and nothing else — **fine for its owner, who already knows
     * what they wrote, and worth nothing to the auditor this bullet exists for.** Half the transcript
     * was provable. The signature was never missing: the submit path already computes
     * `keyProvider.sign(structure1)` and puts it on the wire; it simply was not handed back.
     *
     * ─── Why `self_authored` MUST survive the signature ─────────────────────────────────────────
     *
     * The obvious move is to reuse `verified_signature` now that a signature is present. **That
     * would be false.** Nobody verified anything here — there was no counterparty in the act, and no
     * key was checked against anything. We PRODUCED this signature. Collapsing "I wrote it" into "I
     * checked someone else's" is the same defect the third enum value was added to prevent, one turn
     * further on: two rows with different provenance wearing one label.
     *
     * So the attribution expression now decides on DIRECTION FIRST, and this test is what holds that
     * ordering in place — swap it back and this reddens while everything else stays green.
     */
    const h = await startWithAgent("alice");
    const mgr = h.getSessionNodeManager();
    const ourPubkey = new Uint8Array(32).fill(0x7e);
    const ourSig = new Uint8Array(64).fill(0x5a);

    mgr.recordTranscriptMessage(
      "alice", "s-sent-signed", 0, "sent", new TextEncoder().encode("I agree to the terms"), "t-sent",
      { senderPubkey: ourPubkey, senderSig: ourSig },
    );

    const [row] = rowsFor("s-sent-signed");
    expect(
      row!.attribution,
      "a message WE wrote is self_authored even when it carries a signature — we produced that " +
        "signature, we did not verify anyone else's, and the two are different facts about the row",
    ).toBe("self_authored");
    expect(
      row!.sender_pubkey,
      "and the proof is stored, so the row is checkable by someone who is not its owner",
    ).toBe("7e".repeat(32));
    expect(
      row!.sender_sig === null ? null : Buffer.from(row!.sender_sig).toString("hex"),
      "the 64-byte signature over the Structure-1 bytes we put on the wire",
    ).toBe("5a".repeat(64));
  });

  it("★ a sent row with NO signature is still self_authored, and still carries nothing", async () => {
    /**
     * The relay-degraded path: no submit happens, so there is nothing to sign and nothing to store.
     * The row must not pretend otherwise — this is the pair to the test above, and without it a
     * change that always stamped a placeholder signature would pass.
     */
    const h = await startWithAgent("alice");
    const mgr = h.getSessionNodeManager();
    mgr.recordTranscriptMessage("alice", "s-sent-bare", 0, "sent", new TextEncoder().encode("hi"), "t-bare");

    const [row] = rowsFor("s-sent-bare");
    expect(row!.attribution).toBe("self_authored");
    expect(row!.sender_sig, "no submit, no signature — never a placeholder").toBeNull();
    expect(row!.sender_pubkey).toBeNull();
  });

  it("THE DISTINCTION: a proven row and an assumed row are told apart by the STORED record alone", async () => {
    /**
     * This is the assertion the bullet is actually about, and the reason the other two are not
     * enough on their own.
     *
     * A reader of this transcript — an auditor, a counterparty, anyone shown it later — has only
     * the rows. Not the session, not the socket, not the daemon's memory of who it believed it was
     * talking to. If both kinds of row look the same to that reader, the record does not prove
     * authorship no matter how carefully the signature was checked at the time.
     */
    const h = await startWithAgent("alice");
    const mgr = h.getSessionNodeManager();
    const enc = new TextEncoder();

    mgr.recordTranscriptMessage("alice", "s-mixed", 0, "received", enc.encode("proven"), "t3", {
      senderPubkey: new Uint8Array(32).fill(0x11),
      senderSig: new Uint8Array(64).fill(0x22),
    });
    mgr.recordTranscriptMessage("alice", "s-mixed", 1, "received", enc.encode("assumed"), "t4");

    const rows = rowsFor("s-mixed");
    expect(rows.length, "both messages are in the transcript").toBe(2);

    const attributions = rows.map((r) => r.attribution);
    expect(
      attributions,
      "the two rows must be DISTINGUISHABLE from the stored record alone — if they are not, the " +
        "transcript claims a uniform level of proof it does not have, which is worse than claiming none",
    ).toEqual(["verified_signature", "local_session_state"]);

    // And the distinction is not merely a label: the proven row carries bytes a third party can
    // check, the assumed row carries nothing that could be mistaken for proof.
    expect(rows[0]!.sender_sig).not.toBeNull();
    expect(rows[1]!.sender_sig).toBeNull();
  });
});
