/**
 * CELLO-M7-REMOVE-001 — DOD-REMOVE-1 (local re-key + retire-and-keep + name reuse).
 *
 * `cello remove-agent X` RETIRES an agent: it flips the local `agents` row to state='retired' WITHOUT
 * deleting the row, its keys, or its history, and FREES the human name so a NEW agent can reuse it. The
 * store is re-keyed from `agent_name` PK to a stable `agent_id` PK with `agent_name` unique only among
 * non-retired rows — so the retired identity survives (accountability, SI-002) while the name becomes
 * available again, and the recreated agent is a DISTINCT identity (different agent_id + K_local).
 *
 * Fast inner loop: drives the REAL daemon over IPC (create/remove/list/start) and inspects the REAL
 * encrypted DB. The live-binary slice is j-remove.spine.test.ts.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { PassthroughGatewayClient } from "@cello-protocol/gateway";
import { startDaemon, type DaemonHandle, type DaemonConfig } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import { openEncryptedDatabaseAtPath } from "../sqlcipher-db.js";
import { InMemoryKeyProvider } from "@cello-protocol/crypto";
import type { Logger } from "../types.js";

function makeLogger(): Logger {
  return { debug() {}, info() {}, warn() {}, error() {} };
}

let tempDir = "";
let handle: DaemonHandle | null = null;
const clients: IpcClient[] = [];

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "remove001-"));
});
afterEach(async () => {
  for (const c of clients) { try { c.close(); } catch { /* ignore */ } }
  clients.length = 0;
  if (handle) { await handle.stop(); handle = null; }
  await rm(tempDir, { recursive: true, force: true });
});

function makeConfig(): DaemonConfig {
  return {
      securityGateway: new PassthroughGatewayClient(),
      securityGateway: new PassthroughGatewayClient(),
    celloDir: tempDir,
    socketPath: join(tempDir, "daemon.sock"),
    lockFilePath: join(tempDir, "daemon.lock"),
    maxConnections: 16,
    version: "0.0.1-test",
    logger: makeLogger(),
  };
}

async function connect(socketPath: string): Promise<IpcClient> {
  const client = await connectToDaemon(socketPath);
  clients.push(client);
  await client.send("ipc.connect", { clientType: "mcp" });
  return client;
}

type CreateRes = { ok: boolean; name?: string; pubkey?: string; agentId?: string; reason?: string };
type RemoveRes = { ok: boolean; name?: string; agentId?: string; oneWay?: boolean; guidance?: string; reason?: string };

/** Read a row from the encrypted `agents` table by name+state (the accountability read). */
function readRow(dir: string, name: string, state: string): { agent_id: string; agent_name: string; state: string; k_local_seed: Uint8Array } | undefined {
  const db = openEncryptedDatabaseAtPath(join(dir, "sessions.db"));
  try {
    return db
      .prepare("SELECT agent_id, agent_name, state, k_local_seed FROM agents WHERE agent_name = ? AND state = ?")
      .get(name, state) as { agent_id: string; agent_name: string; state: string; k_local_seed: Uint8Array } | undefined;
  } finally {
    db.close();
  }
}

describe("REMOVE-001 DOD-REMOVE-1 — retire-and-keep + name reuse (local)", () => {
  it("retires an agent (row+keys kept, state=retired) and frees the name for a NEW distinct identity", async () => {
    const config = makeConfig();
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    // Create X — capture its stable agent_id + pubkey.
    const created = (await client.send("cello_create_agent", { name: "ada" })) as CreateRes;
    expect(created.ok, JSON.stringify(created)).toBe(true);
    expect(created.agentId, "create-agent must return a stable agent_id").toMatch(/^[0-9a-f-]{8,}$/);
    const id1 = created.agentId!;
    const pub1 = created.pubkey!;

    // Remove X — one-way, with guidance; echoes the retired agent_id.
    const removed = (await client.send("cello_remove_agent", { name: "ada" })) as RemoveRes;
    expect(removed.ok, JSON.stringify(removed)).toBe(true);
    expect(removed.oneWay).toBe(true);
    expect(typeof removed.guidance).toBe("string");
    expect(removed.agentId).toBe(id1);

    // SI-002 (local): the retired row is KEPT — same agent_id, state=retired, K_local seed intact.
    const retired = readRow(tempDir, "ada", "retired");
    expect(retired, "the retired agent row must still exist (accountability survives)").toBeDefined();
    expect(retired!.agent_id).toBe(id1);
    expect(retired!.k_local_seed?.length, "K_local seed must be kept (32-byte Ed25519 seed)").toBe(32);
    // and the kept seed still derives the original pubkey (a real identity, not a tombstone flag).
    const derived = Buffer.from(await new InMemoryKeyProvider(new Uint8Array(retired!.k_local_seed)).getPublicKey()).toString("hex");
    expect(derived).toBe(pub1);

    // The retired agent is gone from the live runtime: list excludes it, start fails.
    const list1 = (await client.send("cello_list_agents")) as { agents: Array<{ name: string }> };
    expect(list1.agents.map((a) => a.name)).not.toContain("ada");
    const startRetired = (await client.send("cello_start_agent", { name: "ada" })) as { ok: boolean; reason?: string };
    expect(startRetired.ok).toBe(false);
    expect(startRetired.reason).toBe("agent_not_found");

    // Name reuse: create-agent ada SUCCEEDS as a NEW identity — different agent_id AND different K_local.
    const recreated = (await client.send("cello_create_agent", { name: "ada" })) as CreateRes;
    expect(recreated.ok, JSON.stringify(recreated)).toBe(true);
    expect(recreated.agentId).not.toBe(id1);
    expect(recreated.pubkey).not.toBe(pub1);

    // Two rows for 'ada' now: the retired id1 + the active id2 (state='created').
    const active = readRow(tempDir, "ada", "created");
    expect(active!.agent_id).toBe(recreated.agentId);
    expect(readRow(tempDir, "ada", "retired")!.agent_id).toBe(id1);

    // The new ada is live and usable.
    const list2 = (await client.send("cello_list_agents")) as { agents: Array<{ name: string }> };
    expect(list2.agents.map((a) => a.name)).toContain("ada");
    expect(((await client.send("cello_start_agent", { name: "ada" })) as { ok: boolean }).ok).toBe(true);
  });

  it("tears down the ONLINE runtime on removal (BEHAVIORAL: receiver gone, can't sign, fresh SR on recreate)", async () => {
    // Teeth for the online-teardown branch (test-attacker). list/use/start all gate on `agents[]`, so a
    // removal that only splices `agents` — leaving keyProviders / onlineAgents / the standing receiver /
    // current-agent intact — passes them all. The notifications below are NECESSARY but not SUFFICIENT
    // (a stub could dispatch them without tearing anything down), so we also assert the BEHAVIORAL state
    // an agents-splice(+dropAgentSignaling+2-dispatch) stub cannot fake:
    //   (1) the retired agent's standing receiver is actually gone (no longer RECEIVES),
    //   (2) its key provider is gone — cello_register can no longer resolve it (no longer SIGNS),
    //   (3) onlineAgents was truly cleared — the RECREATED agent gets a FRESH standing receiver (a stale
    //       onlineAgents entry would make start an idempotent no-op and leave the new agent with no SR).
    const config = makeConfig();
    handle = await startDaemon(config);
    const snm = handle.getSessionNodeManager();
    const client = await connect(config.socketPath);

    await client.send("cello_create_agent", { name: "nora" });
    expect(((await client.send("cello_start_agent", { name: "nora" })) as { ok: boolean }).ok).toBe(true);
    expect(((await client.send("cello_use_agent", { name: "nora" })) as { ok: boolean }).ok).toBe(true);
    // Baseline: an online agent HAS a standing receiver (it comes up asynchronously after start).
    const srUp = async (name: string, want: boolean): Promise<boolean> => {
      for (let i = 0; i < 60; i++) {
        if ((snm.getStandingReceiverInfo(name) !== null) === want) return true;
        await new Promise((r) => setTimeout(r, 100));
      }
      return (snm.getStandingReceiverInfo(name) !== null) === want;
    };
    expect(await srUp("nora", true), "online nora must have a standing receiver before removal").toBe(true);

    const notes: Array<{ notification: string; data: Record<string, unknown> }> = [];
    client.onNotification((n) => notes.push(n as unknown as { notification: string; data: Record<string, unknown> }));

    expect(((await client.send("cello_remove_agent", { name: "nora" })) as RemoveRes).ok).toBe(true);

    // BEHAVIORAL (1): the standing receiver is torn down — the retired identity no longer receives.
    // (The handler awaits removeStandingReceiverForAgent, so it is gone by the time remove returns.)
    expect(snm.getStandingReceiverInfo("nora"), "the retired agent's standing receiver must be torn down").toBeNull();

    // BEHAVIORAL (2): the key provider is gone — cello_register can no longer resolve nora (it checks
    // keyProviders before anything else). A stub that left keyProviders intact would get past this check
    // (to directory_unreachable here), so agent_not_found proves keyProviders.delete actually ran.
    const regGone = (await client.send("cello_register", { agent: "nora", preAuthToken: "DEV-x" })) as { ok: boolean; reason?: string };
    expect(regGone.ok).toBe(false);
    expect(regGone.reason, "the retired identity's signing key must be gone (register can't resolve it)").toBe("agent_not_found");

    // Notifications (necessary, not sufficient): removal is announced + the current agent is reset.
    for (let i = 0; i < 20 && notes.length < 2; i++) await new Promise((r) => setTimeout(r, 50));
    const stateNote = notes.find((n) => n.notification === "agent_state_changed" && n.data["agentName"] === "nora");
    expect(stateNote, `agent_state_changed must fire on removal: ${JSON.stringify(notes)}`).toBeDefined();
    expect(stateNote!.data["reason"]).toBe("removed");
    const currentNote = notes.find((n) => n.notification === "agent_current_changed");
    expect(currentNote, "the connection's current agent must be reset on removal").toBeDefined();
    expect(currentNote!.data["toAgent"]).toBeNull();

    // BEHAVIORAL (3): name reuse + re-election run cleanly AND onlineAgents was truly cleared — the
    // recreated nora gets its OWN fresh standing receiver (not blocked by a stale online entry).
    expect(((await client.send("cello_create_agent", { name: "nora" })) as CreateRes).ok).toBe(true);
    expect(((await client.send("cello_start_agent", { name: "nora" })) as { ok: boolean }).ok).toBe(true);
    expect(((await client.send("cello_use_agent", { name: "nora" })) as { ok: boolean }).ok).toBe(true);
    expect(await srUp("nora", true), "the RECREATED nora must get a fresh standing receiver (onlineAgents was cleared)").toBe(true);
  });

  it("rejects removing a name with no active agent (fail-loud agent_not_found)", async () => {
    const config = makeConfig();
    handle = await startDaemon(config);
    const client = await connect(config.socketPath);

    const ghost = (await client.send("cello_remove_agent", { name: "ghost" })) as RemoveRes;
    expect(ghost.ok).toBe(false);
    expect(ghost.reason).toBe("agent_not_found");
    expect(typeof ghost.guidance).toBe("string");

    // And after retiring the only agent, removing the same name again is agent_not_found (it's retired,
    // not active) — remove is one-way and never re-retires a tombstone.
    await client.send("cello_create_agent", { name: "x" });
    expect(((await client.send("cello_remove_agent", { name: "x" })) as RemoveRes).ok).toBe(true);
    expect(((await client.send("cello_remove_agent", { name: "x" })) as RemoveRes).reason).toBe("agent_not_found");
  });
});

/**
 * DOD-AGENT-ID-JOINKEY-1 — AC4: the retire-reuse history bleed.
 *
 * REMOVE-001 (above) made the name REUSABLE: retire keeps every row and frees the name. It re-keyed the
 * parent `agents` table to a stable `agent_id` and left seven child tables joining on the name it had
 * just turned into a mutable, reusable attribute. So a NEW agent created under a retired agent's name —
 * a different agent_id, a different K_local keypair — inherits the dead identity's rows through every
 * `WHERE agent_name = ?`.
 *
 * That is not stale data. It is one keypair reading another keypair's transcript and contacts, and
 * resuming one of its interrupted sessions would seal with the wrong key.
 *
 * RED-FIRST: this must FAIL on the `agent_name` join and pass on the `agent_id` join.
 */
describe("DOD-AGENT-ID-JOINKEY-1 AC4 — a recreated name inherits NOTHING from the retired identity", () => {
  it("the new agent sees none of the retired agent's contacts, transcript, or watermarks", async () => {
    const config = makeConfig();
    handle = await startDaemon(config);
    const snm = handle.getSessionNodeManager();
    const client = await connect(config.socketPath);

    const SESSION = "aa".repeat(16);
    const STRANGER = "bb".repeat(32);

    // ── The FIRST 'ada' generates history across three of the seven child tables, through the REAL
    //    write paths (IPC for contacts; the manager's public API for transcript + watermarks).
    const first = (await client.send("cello_create_agent", { name: "ada" })) as CreateRes;
    expect(first.ok, JSON.stringify(first)).toBe(true);
    const id1 = first.agentId!;
    const pub1 = first.pubkey!;

    expect(((await client.send("cello_use_agent", { name: "ada" })) as { ok: boolean }).ok).toBe(true);
    expect(((await client.send("cello_contact_add", { pubkey: STRANGER })) as { ok: boolean }).ok).toBe(true);
    snm.recordTranscriptMessage("ada", SESSION, 0, "received", Buffer.from("the dead identity's secret"));
    snm.advanceLastDeliveredSeq("ada", SESSION, 7);

    // Baseline — the history is really there, or the isolation assertions below would pass vacuously.
    expect(snm.listContacts("ada").map((c) => c.pubkey)).toEqual([STRANGER]);
    expect(snm.readTranscript("ada", SESSION).messages).toHaveLength(1);
    expect(snm.getLastDeliveredSeq("ada", SESSION)).toBe(7);

    // ── Retire 'ada'. Rows are KEPT (SI-002 accountability) and the name is FREED.
    expect(((await client.send("cello_remove_agent", { name: "ada" })) as RemoveRes).ok).toBe(true);

    // ── A NEW 'ada' — same name, DIFFERENT identity.
    const second = (await client.send("cello_create_agent", { name: "ada" })) as CreateRes;
    expect(second.ok, JSON.stringify(second)).toBe(true);
    const id2 = second.agentId!;
    const pub2 = second.pubkey!;

    // PRECONDITIONS — assert the two agents are genuinely distinct BEFORE asserting isolation.
    // Without these, a fixture bug (the second create silently no-op'd, or reused the first's id)
    // would make the isolation assertions below pass while proving nothing at all.
    expect(id2, "the recreated agent must have a DIFFERENT stable agent_id").not.toBe(id1);
    expect(pub2, "the recreated agent must have a DIFFERENT K_local pubkey").not.toBe(pub1);
    expect(readRow(tempDir, "ada", "retired")!.agent_id).toBe(id1);
    expect(readRow(tempDir, "ada", "created")!.agent_id).toBe(id2);

    // ── THE BLEED. Every one of these reads `WHERE agent_name = 'ada'` today, so each returns the
    //    RETIRED identity's rows to a brand-new keypair.
    expect(
      snm.listContacts("ada"),
      "the new 'ada' (a different keypair) must not inherit the retired 'ada' contact whitelist — " +
        "an access-control list crossing an identity boundary",
    ).toEqual([]);

    expect(
      snm.readTranscript("ada", SESSION).messages,
      "the new 'ada' must not be able to read the retired 'ada' conversation transcript",
    ).toEqual([]);

    expect(
      snm.getLastDeliveredSeq("ada", SESSION),
      "the new 'ada' must not inherit the retired 'ada' read watermark (-1 = nothing delivered yet, " +
        "so a seq-0 message still reads as unread)",
    ).toBe(-1);

    expect(
      snm.getUnreadSummary("ada"),
      "the new 'ada' must not see the retired 'ada' unread messages",
    ).toEqual([]);

    // ── And the retired identity's history SURVIVES — this migration destroys nothing. It is simply
    //    no longer reachable by name, because the name no longer identifies it.
    const db = openEncryptedDatabaseAtPath(join(tempDir, "sessions.db"));
    try {
      const kept = db.prepare("SELECT COUNT(*) AS n FROM transcript").get() as { n: number };
      expect(kept.n, "the retired identity's transcript row must still exist (accountability, SI-002)").toBe(1);
      const contacts = db.prepare("SELECT COUNT(*) AS n FROM contacts").get() as { n: number };
      expect(contacts.n, "the retired identity's contact row must still exist").toBe(1);
    } finally {
      db.close();
    }
  });
});

/**
 * DOD-AGENT-ID-JOINKEY-1 — cello-unit-reviewer Finding 1 (regression, red-first).
 *
 * Retiring an agent keeps its `sessions` rows (accountability). Those rows are still `active` /
 * `interrupted` — `removeAgent` does not re-status them. The live-status surfaces (`cello_status`)
 * and the half-open reaper iterate every such row, and the reaper resolves the row's agent NAME to a
 * stable id (`countReceivedMessages` → `#requireAgentId`). Post-migration that resolver refuses a
 * RETIRED name and THROWS — synchronously, unguarded, inside the reap loop — so `cello_status` throws
 * for the WHOLE daemon the moment any retired agent still owns a session row. Pre-migration the
 * name-scoped query just returned a count (the bleed), so this is a regression the strict resolver
 * introduced. The AC4 test above never writes a `sessions` row, so it does not enter this path.
 */
describe("DOD-AGENT-ID-JOINKEY-1 — a retired agent's leftover session must not break cello_status", () => {
  it("cello_status succeeds after retiring an agent that still owns an old active session row", async () => {
    const config = makeConfig();
    handle = await startDaemon(config);
    const snm = handle.getSessionNodeManager();
    const client = await connect(config.socketPath);

    // A real agent with a stable id.
    const created = (await client.send("cello_create_agent", { name: "ada" })) as CreateRes;
    expect(created.ok, JSON.stringify(created)).toBe(true);
    const adaId = created.agentId!;

    // Give it an OLD, zero-received active session row — exactly a reap candidate (past the half-open
    // TTL, counterparty never spoke). Written by agent_id, as production does.
    const tenMinAgo = Date.now() - 10 * 60 * 1000;
    snm.getDb()
      .prepare(
        `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at, message_count)
         VALUES (?, ?, ?, 'active', ?, ?, 0)`,
      )
      .run("dd".repeat(16), adaId, "cc".repeat(32), tenMinAgo, tenMinAgo);

    // Baseline via the DB — NOT via cello_status, because status runs the half-open reaper, which
    // would mark this old zero-received row 'abandoned' while ada is still active (correct behaviour)
    // and rob the test of its precondition. Confirm the row is there and 'active'.
    expect(
      (snm.getDb().prepare("SELECT status FROM sessions WHERE agent_id = ?").get(adaId) as { status: string }).status,
    ).toBe("active");

    // Retire ada. Its session row is KEPT (accountability) and still says 'active'.
    expect(((await client.send("cello_remove_agent", { name: "ada" })) as RemoveRes).ok).toBe(true);

    // THE REGRESSION: cello_status must still succeed. Pre-fix, buildActiveSessions →
    // reapDeadHalfOpenSessions → countReceivedMessages('ada', …) → #requireAgentId('ada') threw
    // ("agent_id_unresolved" — ada is retired), and the throw propagated out of the whole handler.
    const after = (await client.send("cello_status")) as
      | { active_sessions: Array<{ sessionId: string; agentName: string }>; interrupted_sessions: unknown[] }
      | { error: string };
    expect("error" in after ? after.error : null, "cello_status must not throw after retiring an agent with a live session row").toBeNull();

    // The retired agent's session is a dead identity's leftover — it must not appear in the LIVE
    // status surface (it is not resumable; ada has no runtime). It survives in the durable archive.
    expect(
      (after as { active_sessions: Array<{ agentName: string }> }).active_sessions.some((s) => s.agentName === "ada"),
      "a retired agent's session must not surface in the live active-session status",
    ).toBe(false);
  });
});
