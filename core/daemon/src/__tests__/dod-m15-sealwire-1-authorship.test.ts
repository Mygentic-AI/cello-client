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
