/**
 * DOD-TIER-4 (address-book Step 3) — split the old binary `isContact` into role-specific checks.
 *
 *   - isAutoAccept(agent, pubkey) = getTier >= WHITELISTED — the POLICY gate (may an inbound session
 *     be auto-accepted when unattended). Its behavioural consumer, the offline relay mailbox
 *     (LEAVEMSG-1), is out of scope for this unit, so it is defined + tested here for the seam.
 *   - isKnown(agent, pubkey)      = getTier >= KNOWN       — the DISPLAY/relationship check (e.g. which
 *     away wording a sender gets).
 *
 * The binary "row exists = trusted" is gone: an UNKNOWN-tier contact (a row at tier 1) is neither known
 * nor auto-accept. Neither check gates a screening call (INV-TIER-SCREEN).
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { openTestDb } from "./helpers/encrypted-db.js";
import { seedAgents } from "./helpers/seed-agents.js";
import { TIER } from "../contacts-tier-migration.js";
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

function setTier(db: DaemonDatabase, agentId: string, pubkey: string, tier: number): void {
  db.prepare("INSERT OR REPLACE INTO contacts (agent_id, pubkey, added_at, tier) VALUES (?, ?, ?, ?)")
    .run(agentId, pubkey, Date.now(), tier);
}

describe("DOD-TIER-4 — isAutoAccept / isKnown role checks", () => {
  let tempDir: string;
  let mgr: SessionNodeManager;
  let db: DaemonDatabase;
  let alice: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "dod-tier-4-"));
    const dbPath = join(tempDir, "sessions.db");
    const seed = openTestDb(dbPath);
    alice = (await seedAgents(seed, ["alice"])).get("alice")!;
    seed.close();
    mgr = new SessionNodeManager({ factory: new StubNodeFactory(), logger: silent, dbPath });
    await mgr.initialize();
    db = mgr.getDb();
  });
  afterEach(async () => {
    await mgr.stop?.();
    await rm(tempDir, { recursive: true, force: true });
  });

  it("isKnown is true only for tier >= KNOWN", () => {
    const cases: Array<[number, boolean]> = [
      [TIER.BLOCKED, false], [TIER.UNKNOWN, false], [TIER.KNOWN, true], [TIER.WHITELISTED, true], [TIER.VIP, true],
    ];
    for (const [tier, expected] of cases) {
      const pk = `k${tier}`.padStart(64, "0");
      setTier(db, alice, pk, tier);
      expect(mgr.isKnown("alice", pk), `tier ${tier}`).toBe(expected);
    }
    expect(mgr.isKnown("alice", "norow".padStart(64, "0")), "no row → UNKNOWN → not known").toBe(false);
  });

  it("isAutoAccept is true only for tier >= WHITELISTED", () => {
    const cases: Array<[number, boolean]> = [
      [TIER.BLOCKED, false], [TIER.UNKNOWN, false], [TIER.KNOWN, false], [TIER.WHITELISTED, true], [TIER.VIP, true],
    ];
    for (const [tier, expected] of cases) {
      const pk = `a${tier}`.padStart(64, "0");
      setTier(db, alice, pk, tier);
      expect(mgr.isAutoAccept("alice", pk), `tier ${tier}`).toBe(expected);
    }
    expect(mgr.isAutoAccept("alice", "norow".padStart(64, "0")), "no row → not auto-accept").toBe(false);
  });

  it("an UNKNOWN-tier CONTACT (row exists) is neither known nor auto-accept — the binary is gone", () => {
    const pk = "cc".repeat(32);
    setTier(db, alice, pk, TIER.UNKNOWN);
    expect(mgr.isContact("alice", pk)).toBe(true); // a row DOES exist
    expect(mgr.isKnown("alice", pk)).toBe(false); // but not known
    expect(mgr.isAutoAccept("alice", pk)).toBe(false); // and not auto-accept
  });

  it("addContact accepts an explicit tier; the default is the least-privilege UNKNOWN floor", () => {
    mgr.addContact("alice", "known1".padStart(64, "0"), undefined, "accepted", TIER.KNOWN);
    mgr.addContact("alice", "default".padStart(64, "0")); // no tier → default
    expect(mgr.getTier("alice", "known1".padStart(64, "0"))).toBe(TIER.KNOWN);
    expect(mgr.getTier("alice", "default".padStart(64, "0"))).toBe(TIER.UNKNOWN);
  });

  it("addContact THROWS on an out-of-range tier — a can-never-be-stored backstop (review F3)", () => {
    expect(() => mgr.addContact("alice", "bad".padStart(64, "0"), undefined, null, 99)).toThrow(/invalid contact tier/);
    expect(() => mgr.addContact("alice", "neg".padStart(64, "0"), undefined, null, -1)).toThrow(/invalid contact tier/);
    // The corrupt row was never written.
    expect(mgr.isContact("alice", "bad".padStart(64, "0"))).toBe(false);
  });
});
