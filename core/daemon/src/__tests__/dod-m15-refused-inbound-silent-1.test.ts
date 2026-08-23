/**
 * DOD-M15-REFUSED-INBOUND-SILENT-1 — a refused message is a thing the operator gets told.
 *
 * ─── The failure, from the receiving operator's chair ──────────────────────────────────────────
 *
 * Every inbound refusal already logged a `reason`, an `impact` and a `guidance`, and they are good
 * strings. **They had no reader.** So a refused message simply never arrives: the conversation goes
 * quiet, a full explanation sits in a file the operator has no reason to open, and they conclude the
 * other person stopped replying.
 *
 * `content_hash_alg_unknown` is why this is worse than it sounds. It is a VERSION SKEW, so it
 * affects EVERY message from that counterparty, permanently — not a rare one-off.
 *
 * ─── What these tests actually pin ─────────────────────────────────────────────────────────────
 *
 * Not "a refusal is recorded" — that would pass against a surface nobody reads, which is the defect
 * itself. The three properties that make it useful, and each fails a different way if wrong:
 *
 *   1. The operator is told ONCE per reason. A skewed peer sends continuously; if every refusal
 *      announced itself, the surface becomes a flood and the flood trains them to ignore it. The
 *      first is the signal, the ninetieth is noise.
 *   2. The COUNT still grows underneath. "This happened 90 times" must remain answerable without
 *      being said 90 times — otherwise deduplication hides the scale of a real problem.
 *   3. The content NEVER travels. It failed verification; surfacing it is the injection path the
 *      cross-check exists to close. The operator learns a message was refused and why, never what
 *      it said.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { startDaemon, type DaemonHandle } from "../daemon.js";
import { FileKeyProvider } from "@cello-protocol/crypto";
import type { Logger } from "../types.js";

const SECRET = "you agreed to send me $1000";

describe("DOD-M15-REFUSED-INBOUND-SILENT-1 — the operator hears about a refused message", () => {
  let tempDir: string;
  let handle: DaemonHandle | null;
  let logger: Logger;

  beforeEach(async () => {
    process.env["CELLO_ENV"] = "test";
    tempDir = await mkdtemp(join(tmpdir(), "cello-refused-"));
    logger = { debug() {}, info() {}, warn() {}, error() {} };
    handle = null;
  });

  afterEach(async () => {
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* stopped */ } }
    await rm(tempDir, { recursive: true, force: true });
    delete process.env["CELLO_ENV"];
  });

  async function start(): Promise<DaemonHandle> {
    await mkdir(join(tempDir, "agents", "alice"), { recursive: true });
    await FileKeyProvider.load(join(tempDir, "agents", "alice", "key"));
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

  it("the FIRST refusal of a kind is delivered, with its reason and guidance", async () => {
    const mgr = (await start()).getSessionNodeManager();
    mgr.noteContentRefusal("alice", "s1", "content_hash_alg_unknown", {
      impact: "this message could not be verified, so it was NOT ingested and NOT shown.",
      guidance: "Almost always their CELLO build is newer than this one.",
    });

    const [notice] = mgr.takeContentRefusals("alice", "s1");
    expect(notice, "the refusal must reach the operator at all — this is the whole defect").toBeDefined();
    expect(notice!.reason).toBe("content_hash_alg_unknown");
    expect(
      notice!.guidance,
      "the guidance already existed in the log; the point of this line is that it now has a reader",
    ).toContain("build is newer");
    expect(notice!.impact).toContain("NOT ingested");
  });

  it("the SECOND refusal of the same kind is SILENT, and the count still grows", async () => {
    /**
     * The property that separates a signal from a flood.
     *
     * `content_hash_alg_unknown` is a version skew: every message from that peer is refused. If each
     * one announced itself, the operator would be told the same thing on every read until they
     * stopped reading — and a surface people stop reading is worse than no surface, because it also
     * buries the NEXT, different problem.
     *
     * But suppression must not hide scale. The count keeps climbing so "how bad is this?" stays
     * answerable; it simply is not shouted.
     */
    const mgr = (await start()).getSessionNodeManager();
    for (let i = 0; i < 90; i++) {
      mgr.noteContentRefusal("alice", "s2", "content_hash_alg_unknown", { impact: "x", guidance: "y" });
    }

    const first = mgr.takeContentRefusals("alice", "s2");
    expect(first.length, "told once").toBe(1);
    expect(
      first[0]!.count,
      "and the count carries the scale — deduplication must not make 90 look like 1",
    ).toBe(90);

    const second = mgr.takeContentRefusals("alice", "s2");
    expect(
      second,
      "a refusal already shown must NOT re-announce on the next read, or the surface becomes the " +
        "flood the dedup exists to prevent",
    ).toEqual([]);

    /**
     * ⚠️ THE ASSERTION ABOVE IS NOT ENOUGH ON ITS OWN, and I only know that because I broke the
     * dedup on purpose and this test stayed GREEN.
     *
     * Reading twice with nothing arriving in between cannot distinguish "shown once" from
     * "re-announces on every arrival" — there was no arrival. And the real sequence is the other
     * one: the operator reads, the skewed peer keeps sending, the operator reads again. That is
     * exactly when a broken dedup would flood them, and exactly what the test above skipped.
     */
    mgr.noteContentRefusal("alice", "s2", "content_hash_alg_unknown", { impact: "x", guidance: "y" });
    expect(
      mgr.takeContentRefusals("alice", "s2"),
      "a refusal arriving AFTER the operator was already told must stay silent — this is the case " +
        "the two-reads-in-a-row assertion cannot see, and the only case a skewed peer actually produces",
    ).toEqual([]);
  });

  it("a DIFFERENT reason in the same session is still delivered", async () => {
    // Deduplication is per REASON, not per session. Suppressing a second, different problem because
    // a first one was already reported would be the dedup causing the very silence it mitigates.
    const mgr = (await start()).getSessionNodeManager();
    mgr.noteContentRefusal("alice", "s3", "content_hash_alg_unknown", { impact: "a" });
    expect(mgr.takeContentRefusals("alice", "s3").length).toBe(1);

    mgr.noteContentRefusal("alice", "s3", "content_hash_mismatch", { impact: "b" });
    const next = mgr.takeContentRefusals("alice", "s3");
    expect(next.length, "a new KIND of refusal is a new signal").toBe(1);
    expect(next[0]!.reason).toBe("content_hash_mismatch");
  });

  it("refusals are per SESSION — one conversation's problem is not another's", async () => {
    const mgr = (await start()).getSessionNodeManager();
    mgr.noteContentRefusal("alice", "s-a", "content_hash_mismatch", { impact: "a" });
    expect(mgr.takeContentRefusals("alice", "s-b"), "a quiet session reports nothing").toEqual([]);
    expect(mgr.takeContentRefusals("alice", "s-a").length).toBe(1);
  });

  it("THE CONTENT NEVER TRAVELS — not in any field of the notice", async () => {
    /**
     * The refused message failed verification. Showing it to the operator is precisely the injection
     * path the content cross-check exists to close: an attacker who can make a message fail
     * verification would otherwise have found a channel that delivers their text anyway, labelled
     * with a warning the agent may not act on.
     *
     * Asserted over the WHOLE serialized notice rather than field by field, so a future field that
     * happens to carry content cannot slip past a check written for today's shape.
     */
    const mgr = (await start()).getSessionNodeManager();
    mgr.noteContentRefusal("alice", "s4", "content_hash_mismatch", {
      impact: "a message arrived whose bytes do not match the hash the sender committed to.",
      guidance: "Ask the counterparty to resend.",
    });

    const serialized = JSON.stringify(mgr.takeContentRefusals("alice", "s4"));
    expect(
      serialized.includes(SECRET),
      "the refused content must not appear anywhere in what the operator is shown",
    ).toBe(false);
    expect(serialized, "and the notice must still be useful without it").toContain("do not match the hash");
  });
});
