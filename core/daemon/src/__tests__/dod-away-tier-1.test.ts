/**
 * DOD-AWAY-TIER-1 (address-book Step 4) — per-tier and per-contact away messages.
 *
 * resolveAwayMessage returns the most-specific CUSTOM away text, most-specific first: per-contact
 * away_message → per-tier away setting → agent default setting → null (the caller then applies the
 * system default, making the full four-level resolution TOTAL). The local away_message column is set
 * via setContactAwayMessage. (The SI — screening the resolved text on outbound — is exercised in the
 * daemon away-path tests; here we pin the resolution precedence.)
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { openTestDb } from "./helpers/encrypted-db.js";
import { seedAgents } from "./helpers/seed-agents.js";
import { TIER } from "../contacts-tier-migration.js";
import { awayTierSettingKey, AWAY_DEFAULT_KEY } from "../agent-settings-keys.js";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
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

describe("DOD-AWAY-TIER-1 — away message resolution (most-specific-first)", () => {
  let tempDir: string;
  let mgr: SessionNodeManager;
  let db: DaemonDatabase;
  const pk = "aa".repeat(32);

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "dod-away-1-"));
    const dbPath = join(tempDir, "sessions.db");
    const seed = openTestDb(dbPath);
    await seedAgents(seed, ["alice"]);
    seed.close();
    mgr = new SessionNodeManager({ securityGateway: new PassthroughGatewayClient(), factory: new StubNodeFactory(), logger: silent, dbPath });
    await mgr.initialize();
    db = mgr.getDb();
    mgr.addContact("alice", pk, undefined, "accepted", TIER.KNOWN);
  });
  afterEach(async () => {
    await mgr.stop?.();
    await rm(tempDir, { recursive: true, force: true });
  });

  it("returns null when nothing is configured (the caller applies the system default) — total resolution", () => {
    expect(mgr.resolveAwayMessage("alice", pk)).toBeNull();
    expect(mgr.resolveAwayMessage("alice", "norow".padStart(64, "0"))).toBeNull();
  });

  it("agent default applies when set and nothing more specific exists", () => {
    mgr.setSetting("alice", AWAY_DEFAULT_KEY, "Away — back tomorrow");
    expect(mgr.resolveAwayMessage("alice", pk)).toBe("Away — back tomorrow");
  });

  it("a per-tier away text beats the agent default", () => {
    mgr.setSetting("alice", AWAY_DEFAULT_KEY, "generic away");
    mgr.setSetting("alice", awayTierSettingKey("known"), "Hi known contact, I'm away");
    expect(mgr.resolveAwayMessage("alice", pk)).toBe("Hi known contact, I'm away");
  });

  it("a per-CONTACT away message beats everything (most specific)", () => {
    mgr.setSetting("alice", AWAY_DEFAULT_KEY, "generic away");
    mgr.setSetting("alice", awayTierSettingKey("known"), "known away");
    mgr.setContactAwayMessage("alice", pk, "Hey Mum, call me on my cell");
    expect(mgr.resolveAwayMessage("alice", pk)).toBe("Hey Mum, call me on my cell");
  });

  it("the per-tier text is chosen by the contact's OWN tier", () => {
    mgr.setSetting("alice", awayTierSettingKey("vip"), "VIP away");
    mgr.setSetting("alice", awayTierSettingKey("known"), "known away");
    // pk is KNOWN → gets the known text, not the vip one.
    expect(mgr.resolveAwayMessage("alice", pk)).toBe("known away");
  });

  it("setContactAwayMessage sets and clears; returns false for an unknown contact", () => {
    expect(mgr.setContactAwayMessage("alice", pk, "custom")).toBe(true);
    expect(mgr.resolveAwayMessage("alice", pk)).toBe("custom");
    expect(mgr.setContactAwayMessage("alice", pk, null)).toBe(true); // clear
    expect(mgr.resolveAwayMessage("alice", pk)).toBeNull();
    expect(mgr.setContactAwayMessage("alice", "nobody".padStart(64, "0"), "x")).toBe(false);
    void db;
  });
});
