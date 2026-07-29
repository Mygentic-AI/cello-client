/**
 * DOD-CONTACT-VIEW-1 (address-book Step 3) — the address book is viewable, and tiers are settable.
 *
 *   - setContactTier(agent, pubkey, tier) — the store side of cello_contact_set_tier. Returns false
 *     for an unknown contact (fail-loud at the caller), like setContactMoniker.
 *   - listContacts renders, per contact, tier + provenance + a READ-side JOIN against `sessions`:
 *     how many SEALED sessions were shared, and when they last spoke (MAX updated_at). No new stored
 *     data; a contact with no sessions shows 0 / never (NULL), not an error (SI).
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { openTestDb } from "./helpers/encrypted-db.js";
import { seedAgents } from "./helpers/seed-agents.js";
import { TIER } from "../contacts-tier-migration.js";
import { PassthroughGatewayClient } from "@cello-protocol/gateway";
import { SessionNodeManager, type ISessionNodeFactory, type SessionNodeConfig } from "../session-node-manager.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { Logger } from "../types.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };

class StubNodeFactory implements ISessionNodeFactory {
  async createNode(_c: SessionNodeConfig): Promise<CelloNode> {
    return {
      getPeerId: () => "stub", listenAddresses: () => ["/ip4/127.0.0.1/tcp/0"],
      async start() {}, async stop() {}, async dial() { return { peerId: "remote" }; },
      async handle() {}, getProtocols: () => [], getConnections: () => [],
      onPeerConnect() {}, onPeerDisconnect() {},
      getDialability: () => ({ dialable: false, publicAddr: null }),
      onDialabilityChange: () => () => {},
      async newStream() { return { send() {}, async close() {}, abort() {}, status: "open" }; },
    } as unknown as CelloNode;
  }
}

function insertSession(db: DaemonDatabase, agentId: string, pubkey: string, sid: string, status: string, updatedAt: number): void {
  db.prepare(
    `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at, message_count, interrupted_at)
     VALUES (?, ?, ?, ?, ?, ?, 0, NULL)`,
  ).run(sid, agentId, pubkey, status, updatedAt, updatedAt);
}

describe("DOD-CONTACT-VIEW-1 — set tier + viewable address book", () => {
  let tempDir: string;
  let mgr: SessionNodeManager;
  let db: DaemonDatabase;
  let alice: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "dod-view-1-"));
    const dbPath = join(tempDir, "sessions.db");
    const seed = openTestDb(dbPath);
    alice = (await seedAgents(seed, ["alice"])).get("alice")!;
    seed.close();
    mgr = new SessionNodeManager({ securityGateway: new PassthroughGatewayClient(), factory: new StubNodeFactory(), logger: silent, dbPath });
    await mgr.initialize();
    db = mgr.getDb();
  });
  afterEach(async () => {
    await mgr.stop?.();
    await rm(tempDir, { recursive: true, force: true });
  });

  it("setContactTier sets an existing contact's tier and returns false for an unknown one", () => {
    mgr.addContact("alice", "friend".padStart(64, "0"), undefined, "accepted", TIER.KNOWN);
    expect(mgr.setContactTier("alice", "friend".padStart(64, "0"), TIER.WHITELISTED)).toBe(true);
    expect(mgr.getTier("alice", "friend".padStart(64, "0"))).toBe(TIER.WHITELISTED);
    expect(mgr.setContactTier("alice", "nobody".padStart(64, "0"), TIER.VIP)).toBe(false); // no such contact
  });

  it("listContacts renders tier, provenance, sealed-session count, and last-spoke via a read-side JOIN", () => {
    const friend = "aa".repeat(32);
    mgr.addContact("alice", friend, undefined, "initiated", TIER.KNOWN);
    // Two sealed + one active session; last-spoke is the MAX updated_at across ALL of them.
    insertSession(db, alice, friend, "s1".padStart(32, "0"), "sealed", 1000);
    insertSession(db, alice, friend, "s2".padStart(32, "0"), "sealed", 3000);
    insertSession(db, alice, friend, "s3".padStart(32, "0"), "active", 5000);

    const rows = mgr.listContacts("alice");
    const row = rows.find((r) => r.pubkey === friend)!;
    expect(row.tier).toBe(TIER.KNOWN);
    expect(row.provenance).toBe("initiated");
    expect(row.sealed_count).toBe(2); // only sealed sessions counted
    expect(row.last_spoke).toBe(5000); // MAX updated_at across all sessions
  });

  it("a contact with NO sessions shows zero / never, not an error (SI)", () => {
    const lonely = "bb".repeat(32);
    mgr.addContact("alice", lonely, undefined, null, TIER.KNOWN);
    const row = mgr.listContacts("alice").find((r) => r.pubkey === lonely)!;
    expect(row.sealed_count).toBe(0);
    expect(row.last_spoke).toBeNull();
  });

  it("the JOIN is scoped per agent_id — another agent's sessions with the same pubkey never bleed in", async () => {
    const seed2 = openTestDb(join(tempDir, "sessions.db"));
    const bob = (await seedAgents(seed2, ["bob"])).get("bob")!;
    seed2.close();
    const shared = "cc".repeat(32);
    mgr.addContact("alice", shared, undefined, null, TIER.KNOWN);
    mgr.addContact("bob", shared, undefined, null, TIER.KNOWN);
    insertSession(db, bob, shared, "b1".padStart(32, "0"), "sealed", 9000); // BOB's sealed session
    const aliceRow = mgr.listContacts("alice").find((r) => r.pubkey === shared)!;
    expect(aliceRow.sealed_count).toBe(0); // alice has none — bob's must not bleed in
  });
});
