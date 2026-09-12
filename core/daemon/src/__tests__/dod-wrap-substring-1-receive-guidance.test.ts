/**
 * DOD-WRAP-SUBSTRING-1 — `[[WRAP]]` is recognised at the END of a message, never anywhere in it.
 *
 * ── WHY THIS FILE EXISTS AT ALL ──────────────────────────────────────────────────────────────────
 *
 * The rule had exactly two production readers. One was the away responder, which skipped its reply
 * when the arriving message closed the conversation; `DOD-M15-AWAYSCOPE-1` deleted that whole branch
 * and the three tests that covered the rule went with it, because they drove it through a reply that
 * no longer exists. The other reader is still shipping and had no test of its own: the guidance
 * `cello_receive` hands the reading agent, which tells it whether to close, reply, or wait.
 *
 * Deleting the tests without moving the coverage would have left an end-anchored match that
 * everything still depends on and nothing checks. So the property moved here rather than being lost.
 *
 * ── THE RULE, AND THE LIVE DEFECT BEHIND IT ─────────────────────────────────────────────────────
 *
 * `DOD-SIGNAL-TOKEN-1` always APPENDS the real token at the END of the body. A substring match
 * therefore classifies a message that merely mentions `[[WRAP]]` — someone asking what the token
 * means — as a close signal. Measured 2026-07-24 on session `9d6f56d7…`.
 *
 * The cost runs both ways and neither is loud:
 *   - too broad: an agent is told "close now — do not reply" about a message that asked it a
 *     question, and the conversation ends mid-exchange;
 *   - too narrow: a real close is read as an ordinary turn, so the agent replies into a session the
 *     other side has finished with.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { FileKeyProvider } from "@cello-protocol/crypto";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { startDaemon, type DaemonHandle } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import type { Logger } from "../types.js";

const SID64 = (a: string) => a.repeat(64).slice(0, 64);

describe("DOD-WRAP-SUBSTRING-1: the close signal is read at the END, not found anywhere in the body", () => {
  let tempDir: string;
  let logger: Logger;
  let handle: DaemonHandle | null;
  let clients: IpcClient[];

  beforeEach(async () => {
    process.env["CELLO_ENV"] = "test";
    tempDir = await mkdtemp(join(tmpdir(), "cello-wrap-substring-"));
    logger = { debug() {}, info() {}, warn() {}, error() {} };
    handle = null;
    clients = [];
  });

  afterEach(async () => {
    for (const c of clients) { try { c.close(); } catch { /* closed */ } }
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* stopped */ } }
    await rm(tempDir, { recursive: true, force: true });
    delete process.env["CELLO_ENV"];
  });

  /** Seed one received message and read back the guidance `cello_receive` gives for it. */
  async function guidanceFor(sessionSeed: string, text: string): Promise<string | undefined> {
    if (!handle) {
      await mkdir(join(tempDir, "agents", "alice"), { recursive: true });
      await FileKeyProvider.load(join(tempDir, "agents", "alice", "key"));
      handle = await startDaemon({
        securityGateway: new PassthroughGatewayClient(),
        celloDir: tempDir, socketPath: join(tempDir, "daemon.sock"), lockFilePath: join(tempDir, "daemon.lock"),
        maxConnections: 16, version: "0.0.1-test", logger,
      });
      const client = await connectToDaemon(join(tempDir, "daemon.sock"));
      clients.push(client);
      await client.send("ipc.connect", { clientType: "mcp" });
      await client.send("cello_use_agent", { name: "alice" });
    }
    const s = SID64(sessionSeed);
    // A live `sessions` row, so cello_receive takes the LIVE single-message exit. That is the only
    // exit that carries `guidance` — the batch (`since_seq`) exit returns a `messages` array and no
    // guidance at all, so a fixture that reached it would assert nothing.
    const snm = handle.getSessionNodeManager();
    const db = snm.getDb()!;
    const row = db.prepare("SELECT agent_id FROM agents WHERE agent_name = ? AND state != 'retired'").get("alice") as { agent_id: string } | undefined;
    if (!row) throw new Error("test fixture bug: agent 'alice' has no agents row");
    const now = Date.now();
    db.prepare(
      `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at, message_count, interrupted_at)
       VALUES (?, ?, ?, 'active', ?, ?, 0, NULL)`,
    ).run(s, row.agent_id, "cphex", now, now);
    snm.recordTranscriptMessage("alice", s, 0, "received", new TextEncoder().encode(text), "seed");

    const res = (await clients[0]!.send("cello_receive", { session_id: s, timeout_ms: 2000 })) as Record<string, unknown>;
    expect(res["messages"], "this must be the live exit, not the since_seq batch").toBeUndefined();
    expect(res["content"], "the seeded message must come back").toBe(text);
    return res["guidance"] as string | undefined;
  }

  it("★★ a message that MENTIONS [[WRAP]] mid-body is not a close — the reader is not told to stop", async () => {
    // The live defect verbatim: a question ABOUT the token, sent with signal:"over", so the real
    // appended token is [[OVER]]. Pre-fix the substring match read this as a close.
    const guidance = await guidanceFor("a", "can you explain the [[WRAP]] token to me? [[OVER]]");
    expect(guidance, "a question must not be read as a goodbye").not.toMatch(/close|do not reply/i);
    expect(guidance, "and it is still the caller's turn to be answered").toMatch(/reply/i);
  });

  it("★★ a genuine trailing [[WRAP]] IS a close, trailing whitespace and all", async () => {
    // The other half. Naming the outcome rather than asserting "not undefined": a guidance string
    // that merely EXISTS would pass while saying the wrong thing.
    const guidance = await guidanceFor("b", "done here, thanks [[WRAP]]  \n");
    expect(guidance).toMatch(/close/i);
    expect(guidance).toMatch(/do not reply/i);
  });
});
