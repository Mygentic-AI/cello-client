/**
 * The genesis includes the opening FROST signature, so the chain that runs to the seal starts from
 * the ceremony that established the session.
 */
import { describe, it, expect, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { computeChainAnchor, computeGenesisPrevRoot } from "@cello-protocol/protocol-types";
import { SessionNodeManager } from "../session-node-manager.js";
import { seedAgentKeys } from "./helpers/seed-agents.js";
import type { Logger } from "../types.js";

const logger: Logger = { debug() {}, info() {}, warn() {}, error() {} };
const SID = "ab".repeat(16);
const A = new Uint8Array(32).fill(1);
const B = new Uint8Array(32).fill(2);
const TS = 1_789_000_000_000;

let dir: string;
let mgr: SessionNodeManager;
afterEach(async () => { await mgr.gracefulShutdown(); await rm(dir, { recursive: true, force: true }); });

async function manager(): Promise<SessionNodeManager> {
  dir = await mkdtemp(join(tmpdir(), "genesis-frost-"));
  mgr = new SessionNodeManager({
    securityGateway: new PassthroughGatewayClient(),
    factory: { createNode: async () => { throw new Error("no node"); } },
    logger, dbPath: join(dir, "s.db"),
  });
  await mgr.initialize();
  await seedAgentKeys(mgr.getDb(), ["alice"]);
  mgr.getDb().prepare("INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at) VALUES (?, ?, 'bb', 'active', 0, 0)")
    .run(SID, mgr.resolveAgentId("alice"));
  return mgr;
}

/** The chain start this daemon recorded for the session, read from the session row. */
function recorded(m: SessionNodeManager): Buffer | null {
  const row = m.getDb().prepare("SELECT genesis_prev_root AS g FROM sessions WHERE session_id = ?").get(SID) as { g: Uint8Array | null };
  return row.g ? Buffer.from(row.g) : null;
}

describe("the genesis includes the opening FROST signature", () => {
  it("the recorded chain start is the genesis bound to the session's FROST signature", async () => {
    const m = await manager();
    const sig = new Uint8Array(64).fill(7);
    m.recordSessionGenesis("alice", SID, A, B, TS, sig);
    const expected = computeChainAnchor(computeGenesisPrevRoot(A, B, Buffer.from(SID, "hex"), TS), sig);
    expect(recorded(m)?.equals(Buffer.from(expected))).toBe(true);
  });

  it("a different FROST signature gives a different chain start", async () => {
    const m = await manager();
    m.recordSessionGenesis("alice", SID, A, B, TS, new Uint8Array(64).fill(7));
    const other = computeChainAnchor(computeGenesisPrevRoot(A, B, Buffer.from(SID, "hex"), TS), new Uint8Array(64).fill(8));
    expect(recorded(m)?.equals(Buffer.from(other))).toBe(false);
    expect(recorded(m)).not.toBeNull();
  });

  it("no FROST signature means no chain start — never the bare genesis", async () => {
    const m = await manager();
    m.recordSessionGenesis("alice", SID, A, B, TS, undefined);
    expect(recorded(m)).toBeNull();
  });
});
