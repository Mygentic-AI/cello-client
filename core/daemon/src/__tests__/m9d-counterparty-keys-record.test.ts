/**
 * M9D 002-PQKEYS — recording a session counterparty's verified keys either happens or throws.
 *
 * Every later order reads these keys through `counterpartyPqKeys`. The write used to return quietly
 * when there was no database, and an UPDATE matching no session row "succeeded" having changed
 * nothing — either way the session carried on, and the missing keys would surface orders later as
 * "no keys for this session", far from the cause. Real SQLCipher database, no doubles.
 */
import { describe, it, expect, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { SessionNodeManager } from "../session-node-manager.js";
import { seedAgentKeys } from "./helpers/seed-agents.js";
import type { Logger } from "../types.js";

const SID = "cd".repeat(16);
const KEYS = { primaryHex: "11".repeat(32), mlDsaHex: "22".repeat(1312), mlKemHex: "33".repeat(1184) };

let dir: string;
let mgr: SessionNodeManager;
let logged: Array<{ event: string; ctx: Record<string, unknown> }>;
afterEach(async () => { await mgr.gracefulShutdown(); await rm(dir, { recursive: true, force: true }); });

async function manager(withSessionRow: boolean): Promise<SessionNodeManager> {
  logged = [];
  const logger: Logger = { debug() {}, warn() {}, error() {}, info(event: string, ctx?: Record<string, unknown>) { logged.push({ event, ctx: ctx ?? {} }); } };
  dir = await mkdtemp(join(tmpdir(), "m9d-cpkeys-"));
  mgr = new SessionNodeManager({
    securityGateway: new PassthroughGatewayClient(),
    factory: { createNode: async () => { throw new Error("no node"); } },
    logger, dbPath: join(dir, "s.db"),
  });
  await mgr.initialize();
  await seedAgentKeys(mgr.getDb(), ["alice"]);
  if (withSessionRow) {
    mgr.getDb().prepare("INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at) VALUES (?, ?, 'bb', 'active', 0, 0)")
      .run(SID, mgr.resolveAgentId("alice"));
  }
  return mgr;
}

describe("002-PQKEYS: recordCounterpartyKeys writes all three keys, or throws", () => {
  it("records them, reads them back through counterpartyPqKeys, and logs the recording", async () => {
    const m = await manager(true);
    m.recordCounterpartyKeys("alice", SID, KEYS);
    const back = m.counterpartyPqKeys("alice", SID);
    expect(Buffer.from(back!.mlDsa).toString("hex")).toBe(KEYS.mlDsaHex);
    expect(Buffer.from(back!.mlKem).toString("hex")).toBe(KEYS.mlKemHex);
    expect(logged.find((l) => l.event === "session.counterparty_keys.recorded")?.ctx).toMatchObject({ agentName: "alice", sessionId: SID });
  });

  it("THROWS when no session row matches — never a silent no-op", async () => {
    const m = await manager(false);
    expect(() => m.recordCounterpartyKeys("alice", SID, KEYS)).toThrow(/counterparty_keys_not_recorded: no session row/);
    expect(logged.some((l) => l.event === "session.counterparty_keys.recorded")).toBe(false);
  });
});
