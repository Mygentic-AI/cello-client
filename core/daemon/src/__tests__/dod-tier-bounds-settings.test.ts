/**
 * DOD-TIER-BOUNDS-SETTINGS (address-book Step 4) — the Step-2 bounds grid becomes settings-overridable.
 *
 * With NO settings, behaviour is byte-identical to Step 2 (the daemon runs on defaults alone). A
 * per-agent `bounds.<tier>.<field>` setting takes effect. A setting may only RAISE or lower a bound
 * within finite limits — never REMOVE one (INV-TIER-BOUND): Infinity / negative / 0 / non-integer are
 * refused at SET time.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { openTestDb } from "./helpers/encrypted-db.js";
import { seedAgents } from "./helpers/seed-agents.js";
import { TIER, DEFAULT_TIER_BOUNDS } from "../contacts-tier-migration.js";
import { boundSettingKey, awayTierSettingKey, AWAY_DEFAULT_KEY, validateSettingValue } from "../agent-settings-keys.js";
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

let sidCounter = 0;
function seedSessions(db: DaemonDatabase, agentId: string, pubkey: string, n: number): void {
  const now = Date.now();
  for (let i = 0; i < n; i++) {
    db.prepare(
      `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at, message_count, interrupted_at)
       VALUES (?, ?, ?, 'active', ?, ?, 0, NULL)`,
    ).run((++sidCounter).toString(16).padStart(32, "0"), agentId, pubkey, now, now);
  }
}
function setTier(db: DaemonDatabase, agentId: string, pubkey: string, tier: number): void {
  db.prepare("INSERT OR REPLACE INTO contacts (agent_id, pubkey, added_at, tier) VALUES (?, ?, ?, ?)")
    .run(agentId, pubkey, Date.now(), tier);
}

describe("DOD-TIER-BOUNDS-SETTINGS — value validation (AC2, INV-TIER-BOUND)", () => {
  it("a bound value must be a finite positive integer; Infinity / negative / 0 / decimal are refused", () => {
    const key = boundSettingKey("known", "max_sessions");
    expect(validateSettingValue(key, "8").ok).toBe(true);
    for (const bad of ["Infinity", "-1", "0", "8.5", "abc", "", "1e9", " 8"]) {
      expect(validateSettingValue(key, bad).ok, bad).toBe(false);
    }
  });
  it("away-text values are free-form but non-empty and length-bounded (review F2/F3)", () => {
    expect(validateSettingValue(AWAY_DEFAULT_KEY, "Out for lunch, back at 3").ok).toBe(true);
    expect(validateSettingValue(awayTierSettingKey("vip"), "").ok).toBe(false); // empty → refused (use null to clear)
    expect(validateSettingValue(awayTierSettingKey("vip"), "   ").ok).toBe(false); // whitespace-only → refused
    expect(validateSettingValue(AWAY_DEFAULT_KEY, "x".repeat(3000)).ok).toBe(false); // over the length cap
  });
});

describe("DOD-TIER-BOUNDS-SETTINGS — resolveTierBound + the override in effect (AC1)", () => {
  let tempDir: string;
  let mgr: SessionNodeManager;
  let db: DaemonDatabase;
  let alice: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "dod-tbs-"));
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

  it("with NO setting, resolveTierBound returns the grid default (identical to Step 2)", () => {
    expect(mgr.resolveTierBound("alice", TIER.KNOWN, "max_sessions")).toBe(DEFAULT_TIER_BOUNDS[TIER.KNOWN].maxSessionsPerSender);
    expect(mgr.resolveTierBound("alice", TIER.KNOWN, "max_bytes")).toBe(DEFAULT_TIER_BOUNDS[TIER.KNOWN].maxBytesPerSession);
    // BLOCKED is never settable — always the fixed grid value.
    expect(mgr.resolveTierBound("alice", TIER.BLOCKED, "max_sessions")).toBe(0);
  });

  it("a setting overrides the default; a corrupt stored value falls back to the default (never unbounded)", () => {
    mgr.setSetting("alice", boundSettingKey("known", "max_sessions"), "8");
    expect(mgr.resolveTierBound("alice", TIER.KNOWN, "max_sessions")).toBe(8);
    // Defensive: a value that somehow got stored non-positive falls back, never removes the bound.
    mgr.setSetting("alice", boundSettingKey("known", "max_bytes"), "0"); // (validateSettingValue would reject this at the handler)
    expect(mgr.resolveTierBound("alice", TIER.KNOWN, "max_bytes")).toBe(DEFAULT_TIER_BOUNDS[TIER.KNOWN].maxBytesPerSession);
  });

  it("AC1: with known max_sessions set to 8, the 8th session is accepted and the 9th refused", () => {
    const friend = "bb".repeat(32);
    setTier(db, alice, friend, TIER.KNOWN);
    mgr.setSetting("alice", boundSettingKey("known", "max_sessions"), "8");
    seedSessions(db, alice, friend, 7);
    expect(mgr.checkUnknownSenderAcceptanceBound("alice", friend)).toEqual({ ok: true }); // 7 < 8 → 8th allowed
    seedSessions(db, alice, friend, 1); // now 8
    expect(mgr.checkUnknownSenderAcceptanceBound("alice", friend))
      .toMatchObject({ ok: false, reason: "abuse_bound_sessions_per_sender" }); // 8 >= 8 → 9th refused
    // Default (5) would have refused at the 5th — proving the override is in effect.
    expect(DEFAULT_TIER_BOUNDS[TIER.KNOWN].maxSessionsPerSender).toBe(5);
  });

  it("T1: a max_bytes override takes effect at the byte-cap gate — a KNOWN contact is refused past it", async () => {
    const msgLeafHash = (c: Uint8Array): Uint8Array =>
      new Uint8Array(createHash("sha256").update(new Uint8Array([0x00])).update(c).digest());
    const SID = "dd".repeat(16);
    const known = "ee".repeat(32);
    setTier(db, alice, known, TIER.KNOWN);
    mgr.setSetting("alice", boundSettingKey("known", "max_bytes"), "10"); // tiny override
    await mgr.createSessionNode(SID, "alice", known, "peer", "corr");
    const over = new Uint8Array(20); // 20 > 10 → refused at the OVERRIDE (default 100 MB would accept)
    const res = await mgr.ingestReceivedContent("alice", SID, over, msgLeafHash(over), "c1");
    expect(res).toMatchObject({ ok: false, reason: "session_size_limit_exceeded" });
  });
});
