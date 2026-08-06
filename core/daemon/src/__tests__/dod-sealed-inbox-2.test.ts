/**
 * DOD-SEALED-INBOX-2 — the inbox asserted sessions were SEALED when they were not.
 *
 * THE DEFECT. `getSealedUnread` correctly returns all four TERMINAL statuses — `sealed`,
 * `abandoned`, `interrupted`, `seal_interrupted_pending` — because all four are
 * terminal-with-unread. Only ONE of them is notarized. The inbox then asserted the opposite three
 * times over:
 *
 *   1. the wire field was named `sealed_unread`;
 *   2. every row was stamped `session_state: "sealed"` — hardcoded, not read from the row;
 *   3. the guidance read "These sessions are SEALED".
 *
 * Found live: a session was reported under "sealed with unread messages" while three other
 * surfaces said it was interrupted and had never sealed, and the agent reading the inbox repeated
 * "it's sealed" to the operator as fact. Nothing in the system contradicts the claim unless you go
 * and ask a second surface.
 *
 * For a product whose whole proposition is verifiable trust, this is not a wrong label — it is the
 * product making a FALSE CLAIM ABOUT NOTARIZATION and an agent relaying it onward. A reader cannot
 * tell "this conversation has a cryptographic receipt" from "this conversation died halfway".
 *
 * THE FIX IS ONE PASS, INCLUDING THE RENAME (Andre, 2026-08-04). The name is half the claim: an
 * agent reading the JSON says "sealed" without ever reaching the guidance string. Renaming is a
 * wire change for the shim, the receptionist SKILL and the receptionist AGENT, and pre-launch is
 * the only time that is free — deferring it is the migration trap.
 *
 * The field is `ended_unread`; each row carries its REAL `status` and an explicit `notarized`
 * boolean, which is the only thing a caller should branch on to decide whether a receipt exists.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { FileKeyProvider } from "@cello-protocol/crypto";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { startDaemon } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import type { DaemonConfig } from "../types.js";

/** The four statuses `getEndedUnread` returns. Exactly one of them is notarized. */
const TERMINAL_STATUSES = ["sealed", "abandoned", "interrupted", "seal_interrupted_pending"] as const;

interface EndedRow {
  session_id: string;
  unread_count: number;
  last_seq: number;
  status: string;
  notarized: boolean;
  actionable?: boolean;
}
interface InboxAgent {
  ended_unread?: EndedRow[];
  ended_unread_actionable?: boolean;
  ended_unread_guidance?: string;
  // The dead name, kept in the type ONLY so the test can assert its absence.
  sealed_unread?: unknown;
  sealed_unread_guidance?: unknown;
  sealed_unread_actionable?: unknown;
}

describe("DOD-SEALED-INBOX-2: the inbox must not claim a session is notarized when it is not", () => {
  let tempDir: string;
  let handle: Awaited<ReturnType<typeof startDaemon>> | null;
  let clients: IpcClient[];

  beforeEach(async () => {
    process.env["CELLO_ENV"] = "test";
    tempDir = await mkdtemp(join(tmpdir(), "cello-sealed-inbox-2-"));
    handle = null;
    clients = [];
  });
  afterEach(async () => {
    for (const c of clients) { try { c.close(); } catch { /* closed */ } }
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* stopped */ } }
    await rm(tempDir, { recursive: true, force: true });
    delete process.env["CELLO_ENV"];
  });

  async function makeAgentDir(name: string): Promise<void> {
    const dir = join(tempDir, "agents", name);
    await mkdir(dir, { recursive: true });
    await FileKeyProvider.load(join(dir, "key"));
  }

  async function start(): Promise<Awaited<ReturnType<typeof startDaemon>>> {
    const config: DaemonConfig = {
      securityGateway: new PassthroughGatewayClient(),
      celloDir: tempDir, socketPath: join(tempDir, "daemon.sock"), lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16, version: "0.0.1-test", logger: { debug() {}, info() {}, warn() {}, error() {} },
    };
    const h = await startDaemon(config);
    handle = h;
    return h;
  }

  async function connectAs(agent: string): Promise<IpcClient> {
    const client = await connectToDaemon(join(tempDir, "daemon.sock"));
    clients.push(client);
    await client.send("ipc.connect", { clientType: "test" });
    await client.send("cello_use_agent", { name: agent });
    return client;
  }

  /** Seed one terminal session per status, each with one unread received message. */
  async function seedAllTerminalStatuses(client: IpcClient): Promise<Map<string, string>> {
    const mgr = handle!.getSessionNodeManager();
    const byStatus = new Map<string, string>();
    for (const [i, status] of TERMINAL_STATUSES.entries()) {
      const sessionId = String(10 + i).repeat(16).slice(0, 64);
      await client.send("__test_insert_session_row", {
        agentName: "alice", sessionId, status, counterpartyPubkey: "cphex",
      });
      mgr.recordTranscriptMessage("alice", sessionId, 0, "received",
        new TextEncoder().encode(`a message left in a ${status} session`), "corr");
      byStatus.set(status, sessionId);
    }
    return byStatus;
  }

  async function inboxAgent(client: IpcClient): Promise<InboxAgent> {
    const inbox = (await client.send("cello_check_notifications", { scope: "current" })) as {
      agents: InboxAgent[];
    };
    return inbox.agents[0]!;
  }

  it("reports each ended session's REAL status — three of the four were stamped 'sealed'", async () => {
    await makeAgentDir("alice");
    await start();
    const client = await connectAs("alice");
    const byStatus = await seedAllTerminalStatuses(client);

    const a = await inboxAgent(client);
    expect(a.ended_unread).toBeDefined();

    for (const status of TERMINAL_STATUSES) {
      const row = a.ended_unread!.find((u) => u.session_id === byStatus.get(status));
      expect(row, `a ${status} session with unread must be reported`).toBeDefined();
      // The row's status is READ FROM THE ROW. The old code hardcoded "sealed" here, so this
      // assertion fails three times out of four against it.
      expect(row!.status, `a ${status} session must not be reported as anything else`).toBe(status);
    }
  });

  it("marks ONLY a sealed session as notarized — this is the claim that must never be wrong", async () => {
    await makeAgentDir("alice");
    await start();
    const client = await connectAs("alice");
    const byStatus = await seedAllTerminalStatuses(client);

    const a = await inboxAgent(client);
    for (const status of TERMINAL_STATUSES) {
      const row = a.ended_unread!.find((u) => u.session_id === byStatus.get(status))!;
      // `notarized` is the single field a caller branches on to answer "is there a receipt?".
      // Getting it wrong in the TRUE direction is the failure that loses trust.
      expect(row.notarized, `notarized must be ${status === "sealed"} for a ${status} session`)
        .toBe(status === "sealed");
    }
    // And exactly one of the four, so a blanket `true` (or `false`) cannot pass.
    expect(a.ended_unread!.filter((u) => u.notarized)).toHaveLength(1);
  });

  it("does not emit the dead `sealed_unread` name — the field name was half the false claim", async () => {
    await makeAgentDir("alice");
    await start();
    const client = await connectAs("alice");
    await seedAllTerminalStatuses(client);

    const a = await inboxAgent(client);
    // An agent reading the JSON says "sealed" from the KEY without ever reaching the guidance
    // string, so leaving the old key as an alias would keep the lie alive in the surface that
    // actually gets read.
    expect(a.sealed_unread, "the old key must be GONE, not aliased").toBeUndefined();
    expect(a.sealed_unread_guidance).toBeUndefined();
    expect(a.sealed_unread_actionable).toBeUndefined();
  });

  it("guidance states that only sealed sessions are notarized, and no longer asserts they all are", async () => {
    await makeAgentDir("alice");
    await start();
    const client = await connectAs("alice");
    await seedAllTerminalStatuses(client);

    const a = await inboxAgent(client);
    const g = a.ended_unread_guidance!;
    expect(typeof g).toBe("string");
    // The blanket claim is gone...
    expect(g, "must not assert the whole group is sealed").not.toMatch(/These sessions are SEALED/i);
    // ...replaced by the conditional truth, naming the field to check.
    expect(g).toMatch(/notarized/i);
    expect(g).toMatch(/only|just/i);
    // M12-P17's property must survive this rename: these are history, not a work queue.
    expect(g).toMatch(/CLOSED|ENDED/i);
    expect(g).toMatch(/STALE|must\s+NOT be acted on/i);
    expect(a.ended_unread_actionable).toBe(false);
  });

  it("keeps ended sessions out of `unread` (the DOD-SEALED-INBOX-1 property this rename must not break)", async () => {
    await makeAgentDir("alice");
    await start();
    const client = await connectAs("alice");
    const byStatus = await seedAllTerminalStatuses(client);

    const inbox = (await client.send("cello_check_notifications", { scope: "current" })) as {
      agents: Array<InboxAgent & { unread: Array<{ session_id: string }>; total_unread: number }>;
    };
    const a = inbox.agents[0]!;
    for (const id of byStatus.values()) {
      expect(a.unread.find((u) => u.session_id === id), "a terminal session is not live unread").toBeUndefined();
    }
    expect(a.total_unread).toBe(0);
  });

  // ─── Audit what SHIPS, not only what compiles ───────────────────────────────
  //
  // These two files are shipped in the cello plugin and INSTRUCT AGENTS DIRECTLY. The receptionist
  // agent's wake condition is a jq expression over this exact key: rename the field and forget the
  // agent, and it stops waking for ended sessions — silently, forever, which is worse than the bug
  // being fixed. A grep-level test is the only thing that ties them together.

  const PLUGIN_ROOT = join(import.meta.dirname, "../../../../plugins/cello");

  it("the shipped receptionist AGENT wakes on the new key — a missed rename here sleeps forever", async () => {
    const md = await readFile(join(PLUGIN_ROOT, "agents/cello-receptionist.md"), "utf8");
    expect(md).toContain("ended_unread");
    // Anchored so `ended_unread` cannot satisfy a search for the dead name.
    // Match the STEM, unanchored. `\bsealed_unread\b` looked careful and was worse than useless:
    // the trailing \b cannot match before `_`, so `sealed_unread_guidance` and
    // `sealed_unread_actionable` sailed through green. There is no `sealed_unread` substring inside
    // `ended_unread`, so the loose form cannot false-positive.
    expect(md, "the dead key must not survive in the shipped agent").not.toMatch(/sealed_unread/);
    // ...and the prose form of the same dead vocabulary, which no key-shaped grep would catch.
    expect(md, "the dead WORDING must not survive either").not.toMatch(/sealed unread/i);
  });

  it("the shipped receptionist SKILL names the new key", async () => {
    const md = await readFile(join(PLUGIN_ROOT, "skills/receptionist/SKILL.md"), "utf8");
    expect(md).toContain("ended_unread");
    expect(md, "the dead key must not survive in the shipped skill").not.toMatch(/sealed_unread/);
    expect(md, "the dead WORDING must not survive either").not.toMatch(/sealed unread/i);
  });
});
