/**
 * DOD-SETTINGS-1 (address-book Step 4) — the daemon-side per-agent settings store, and its key
 * namespace. A generic key-value store on the stable agent_id; the handler REFUSES an unknown key;
 * an unset key returns null so the CONSUMER falls back to the hardcoded default (the daemon runs
 * correctly on defaults alone — AC3).
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { openTestDb } from "./helpers/encrypted-db.js";
import { seedAgents } from "./helpers/seed-agents.js";
import { isValidSettingKey, boundSettingKey, awayTierSettingKey, AWAY_DEFAULT_KEY, settableTierName } from "../agent-settings-keys.js";
import { SessionNodeManager, type ISessionNodeFactory, type SessionNodeConfig } from "../session-node-manager.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { Logger } from "../types.js";

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

describe("DOD-SETTINGS-1 — the setting key namespace", () => {
  it("accepts every valid bound + away key and rejects unknown ones", () => {
    for (const t of ["unknown", "known", "whitelisted", "vip"] as const) {
      expect(isValidSettingKey(boundSettingKey(t, "max_sessions"))).toBe(true);
      expect(isValidSettingKey(boundSettingKey(t, "max_bytes"))).toBe(true);
      expect(isValidSettingKey(awayTierSettingKey(t))).toBe(true);
    }
    expect(isValidSettingKey(AWAY_DEFAULT_KEY)).toBe(true);
    for (const bad of ["", "bounds.blocked.max_sessions", "bounds.known.max_foo", "away.tier.blocked", "random.key", "bounds.known"]) {
      expect(isValidSettingKey(bad), bad).toBe(false);
    }
  });

  it("settableTierName maps only the settable tiers (BLOCKED is not settable)", () => {
    expect(settableTierName(0)).toBeNull(); // BLOCKED
    expect(settableTierName(1)).toBe("unknown");
    expect(settableTierName(2)).toBe("known");
    expect(settableTierName(3)).toBe("whitelisted");
    expect(settableTierName(4)).toBe("vip");
    expect(settableTierName(99)).toBeNull();
  });
});

describe("DOD-SETTINGS-1 — the per-agent store", () => {
  let tempDir: string;
  let mgr: SessionNodeManager;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "dod-settings-1-"));
    const dbPath = join(tempDir, "sessions.db");
    const seed = openTestDb(dbPath);
    await seedAgents(seed, ["alice", "bob"]);
    seed.close();
    mgr = new SessionNodeManager({ factory: new StubNodeFactory(), logger: silent, dbPath });
    await mgr.initialize();
  });
  afterEach(async () => {
    await mgr.stop?.();
    await rm(tempDir, { recursive: true, force: true });
  });

  it("an UNSET key returns null (so the consumer applies the default — AC3)", () => {
    expect(mgr.getSetting("alice", boundSettingKey("known", "max_sessions"))).toBeNull();
  });

  it("setSetting round-trips and upserts (a second set overwrites, not duplicates)", () => {
    const key = boundSettingKey("known", "max_sessions");
    mgr.setSetting("alice", key, "8");
    expect(mgr.getSetting("alice", key)).toBe("8");
    mgr.setSetting("alice", key, "12"); // upsert
    expect(mgr.getSetting("alice", key)).toBe("12");
    expect(mgr.getAllSettings("alice")).toEqual([{ key, value: "12" }]);
  });

  it("settings are per-agent — alice's setting never leaks into bob's", () => {
    mgr.setSetting("alice", AWAY_DEFAULT_KEY, "Out for lunch");
    expect(mgr.getSetting("bob", AWAY_DEFAULT_KEY)).toBeNull();
    expect(mgr.getAllSettings("bob")).toEqual([]);
  });
});
