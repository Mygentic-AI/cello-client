/**
 * The mailbox pull dialled a relay at an address the fleet closed days earlier.
 *
 * Live 2026-09-15: three messages parked for Mac_Coder_1 at the us-east1 relay were never collected.
 * Every pull dialled `/ip4/34.139.119.165/tcp/4001/ws` — the relay's pre-TLS address, saved on a
 * session row from before the cutover — while the directory had just handed this daemon the current
 * `/dns4/relay-use1…/tcp/443/tls/ws` address for the same relay peer. 1,904 failed opens since
 * 2026-09-11. The pull only ever worked when a live relay connection already existed to reuse,
 * which after a laptop sleep it never does.
 *
 * Driven through `SessionNodeManager.getAgentRelayEndpoints` — the exact call `content-park.ts`
 * makes — against real saved rows, so reverting the manager to read saved rows alone fails here.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { SessionNodeManager } from "../session-node-manager.js";
import { ProductionSessionNodeFactory } from "../daemon.js";
import type { Logger } from "../types.js";
import { seedAgents } from "./helpers/seed-agents.js";

const RELAY = "12D3KooWJXHpnWQhGk3jXBJYdXMmeLxEhRqzwZCYd1bxSUh4pg83";
const DEAD = `/ip4/34.139.119.165/tcp/4001/ws/p2p/${RELAY}`;
const CURRENT = `/dns4/relay-use1.cello.mygentic.ai/tcp/443/tls/ws/p2p/${RELAY}`;
const quiet: Logger = { debug() {}, info() {}, warn() {}, error() {} };

describe("relay endpoints the mailbox pull dials", () => {
  let dir = "";
  let manager: SessionNodeManager;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "cello-relay-endpoints-"));
    manager = new SessionNodeManager({
      securityGateway: new PassthroughGatewayClient(), factory: new ProductionSessionNodeFactory(),
      logger: quiet, dbPath: join(dir, "s.db"),
    });
    await manager.initialize();
  });
  afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

  async function saveRow(addr: string, updatedAt: number): Promise<void> {
    const db = manager.getDb();
    const ids = await seedAgents(db, ["alice"]);
    db.prepare(
      `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at, message_count, relay_peer_id, relay_addrs)
       VALUES (?, ?, ?, 'sealed', ?, ?, 0, ?, ?)`,
    ).run(randomUUID().replaceAll("-", ""), ids.get("alice")!, "cc".repeat(32), updatedAt, updatedAt, RELAY, JSON.stringify([addr]));
  }

  it("★★★ a relay the directory lists is dialled at the directory's address, never a saved one", async () => {
    await saveRow(DEAD, Date.now());
    manager.setDirectoryRelayEndpoints("alice", [{ relayPeerId: RELAY, relayAddrs: [CURRENT] }]);
    expect(
      manager.getAgentRelayEndpoints("alice"),
      "the saved row is from before the TLS cutover; dialling it is how three parked messages sat " +
        "uncollected after a laptop sleep",
    ).toEqual([{ relayPeerId: RELAY, relayAddrs: [CURRENT] }]);
  });

  it("with no directory pool, the NEWEST saved row for a relay wins", async () => {
    // Inserted newest FIRST, so insertion order and recency disagree and only the ORDER BY decides.
    await saveRow(CURRENT, 2_000);
    await saveRow(DEAD, 1_000);
    expect(manager.getAgentRelayEndpoints("alice")).toEqual([{ relayPeerId: RELAY, relayAddrs: [CURRENT] }]);
  });
});
