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
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
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
    mgr = new SessionNodeManager({ securityGateway: new PassthroughGatewayClient(), factory: new StubNodeFactory(), logger: silent, dbPath });
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

  it("T1: settings are keyed on the STABLE agent_id, never the mutable agent_name", () => {
    const db = mgr.getDb();
    const aliceId = (db.prepare("SELECT agent_id FROM agents WHERE agent_name = 'alice'").get() as { agent_id: string }).agent_id;
    mgr.setSetting("alice", AWAY_DEFAULT_KEY, "hi");
    const row = db.prepare("SELECT agent_id FROM agent_settings WHERE key = ?").get(AWAY_DEFAULT_KEY) as { agent_id: string };
    expect(row.agent_id).toBe(aliceId); // the stable id …
    expect(row.agent_id).not.toBe("alice"); // … never the name (a name-keyed store would orphan on rename)
  });

  it("T2: setSetting fails closed on an uninitialized DB (a silent no-op write would be a lie)", () => {
    const bare = new SessionNodeManager({ securityGateway: new PassthroughGatewayClient(), factory: new StubNodeFactory(), logger: silent, dbPath: "/nonexistent/unused.db" });
    expect(() => bare.setSetting("alice", AWAY_DEFAULT_KEY, "hi")).toThrow(/not initialized/);
  });

  it("F2: setSetting has a store-level backstop — an unknown key can never be persisted", () => {
    expect(() => mgr.setSetting("alice", "bogus.key", "x")).toThrow(/invalid_key/);
  });

  // ─── DOD-SETTINGS-CLEAR-1: a set setting can be UNSET ───
  //
  // Found by testing the away path live. `cello_settings_set` refused an empty away text with the
  // guidance "omit the key or pass null to clear" — while coercing null to undefined and rejecting
  // it as missing_params. So there was no way to unset a setting from any surface, and a caller
  // following that guidance from the CLI stored the literal text "null": the agent then greeted
  // every caller with "null" as its away message.

  it("deleteSetting unsets the key so the built-in default applies again", () => {
    mgr.setSetting("alice", AWAY_DEFAULT_KEY, "Back Monday.");
    expect(mgr.getSetting("alice", AWAY_DEFAULT_KEY)).toBe("Back Monday.");

    expect(mgr.deleteSetting("alice", AWAY_DEFAULT_KEY)).toBe(true);
    expect(mgr.getSetting("alice", AWAY_DEFAULT_KEY)).toBeNull();
  });

  it("deleteSetting reports FALSE when there was nothing to clear", () => {
    // The handler surfaces this as `cleared: false` — clearing an already-unset key must read as the
    // no-op it is, not imply something was removed.
    expect(mgr.deleteSetting("alice", AWAY_DEFAULT_KEY)).toBe(false);
  });

  it("clearing is NOT the same as storing an empty string", () => {
    // The distinction the bug turned on. getSetting returns null for an absent row, but an empty
    // string is a VALUE: it wins the per-contact → per-tier → agent-default → system-default walk
    // and blanks the away reply entirely. Unsetting is the only route back to the default, which is
    // why `set <key> ""` stays refused and `clear` exists instead.
    mgr.setSetting("alice", AWAY_DEFAULT_KEY, "");
    expect(mgr.getSetting("alice", AWAY_DEFAULT_KEY)).toBe(""); // a value, not an absence
    mgr.deleteSetting("alice", AWAY_DEFAULT_KEY);
    expect(mgr.getSetting("alice", AWAY_DEFAULT_KEY)).toBeNull(); // now genuinely absent
  });

  it("deleteSetting has the same store-level key backstop as setSetting", () => {
    expect(() => mgr.deleteSetting("alice", "bogus.key")).toThrow(/invalid_key/);
  });

  it("deleteSetting fails closed on an uninitialized DB", () => {
    const bare = new SessionNodeManager({ securityGateway: new PassthroughGatewayClient(), factory: new StubNodeFactory(), logger: silent, dbPath: "/nonexistent/unused.db" });
    expect(() => bare.deleteSetting("alice", AWAY_DEFAULT_KEY)).toThrow(/not initialized/);
  });
});
