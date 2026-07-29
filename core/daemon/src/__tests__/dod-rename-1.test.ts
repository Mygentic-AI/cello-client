/**
 * DOD-RENAME-1 (address-book Step 3) — Option C: the stored name is sacrosanct; renames are NOTICED,
 * never auto-applied.
 *
 * A peer's self-declared name is recorded as last_offered_moniker when the offer is SEEN. If the peer
 * is a contact the operator has PERSONALLY NAMED and the offered name DIFFERS from the last one seen,
 * a rename NOTICE is queued (surfaced via cello_check_notifications — an INBOX pull, never a push).
 * The local pet name is never overwritten (AC2); a repeat of the same name is idempotent (AC4).
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

describe("DOD-RENAME-1 — Option C rename detection", () => {
  let tempDir: string;
  let mgr: SessionNodeManager;
  let alice: string;
  const pk = "aa".repeat(32);

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "dod-rename-1-"));
    const dbPath = join(tempDir, "sessions.db");
    const seed = openTestDb(dbPath);
    alice = (await seedAgents(seed, ["alice"])).get("alice")!;
    seed.close();
    mgr = new SessionNodeManager({ securityGateway: new PassthroughGatewayClient(), factory: new StubNodeFactory(), logger: silent, dbPath });
    await mgr.initialize();
    void alice;
    mgr.addContact("alice", pk, undefined, "accepted", TIER.KNOWN);
  });
  afterEach(async () => {
    await mgr.stop?.();
    await rm(tempDir, { recursive: true, force: true });
  });

  it("the FIRST offer records a baseline and fires NO notice (nothing to compare against yet)", () => {
    mgr.recordOfferedMoniker("alice", pk, "Alice");
    expect(mgr.getRenameNotices("alice")).toHaveLength(0);
  });

  it("AC3/AC4: offer Alice → name Mum → offer AliceCorp fires ONE notice; offering AliceCorp again is silent", () => {
    mgr.recordOfferedMoniker("alice", pk, "Alice"); // baseline
    mgr.setContactMoniker("alice", pk, "Mum"); // operator personally names them
    mgr.recordOfferedMoniker("alice", pk, "AliceCorp"); // differs + named → NOTICE
    let notices = mgr.getRenameNotices("alice");
    expect(notices).toHaveLength(1);
    expect(notices[0]).toMatchObject({ pubkey: pk, offered_name: "AliceCorp" });

    mgr.recordOfferedMoniker("alice", pk, "AliceCorp"); // same as last seen → idempotent, no new notice
    notices = mgr.getRenameNotices("alice");
    expect(notices).toHaveLength(1);

    // AC2: the local pet name is NEVER overwritten by an offered name.
    expect(mgr.getContactMoniker("alice", pk)).toBe("Mum");
  });

  it("a NEWER differing offer supersedes the pending notice (one notice per contact, latest name)", () => {
    mgr.recordOfferedMoniker("alice", pk, "Alice");
    mgr.setContactMoniker("alice", pk, "Mum");
    mgr.recordOfferedMoniker("alice", pk, "AliceCorp");
    mgr.recordOfferedMoniker("alice", pk, "AliceInc"); // supersede
    const notices = mgr.getRenameNotices("alice");
    expect(notices).toHaveLength(1);
    expect(notices[0].offered_name).toBe("AliceInc");
  });

  it("no notice for a contact the operator has NOT personally named (a bare offered-name change is silent)", () => {
    mgr.recordOfferedMoniker("alice", pk, "Bob"); // baseline, no local moniker
    mgr.recordOfferedMoniker("alice", pk, "Bobby"); // differs, but not personally named → no notice
    expect(mgr.getRenameNotices("alice")).toHaveLength(0);
  });

  it("setting the local moniker (adopting or choosing) clears the pending notice", () => {
    mgr.recordOfferedMoniker("alice", pk, "Alice");
    mgr.setContactMoniker("alice", pk, "Mum");
    mgr.recordOfferedMoniker("alice", pk, "AliceCorp");
    expect(mgr.getRenameNotices("alice")).toHaveLength(1);
    mgr.setContactMoniker("alice", pk, "AliceCorp"); // operator acts
    expect(mgr.getRenameNotices("alice")).toHaveLength(0);
  });

  it("removing the contact clears any pending notice", () => {
    mgr.recordOfferedMoniker("alice", pk, "Alice");
    mgr.setContactMoniker("alice", pk, "Mum");
    mgr.recordOfferedMoniker("alice", pk, "AliceCorp");
    expect(mgr.getRenameNotices("alice")).toHaveLength(1);
    mgr.removeContact("alice", pk);
    expect(mgr.getRenameNotices("alice")).toHaveLength(0);
  });

  it("recordOfferedMoniker on a non-contact (no row) is a no-op — no baseline, no notice", () => {
    const stranger = "bb".repeat(32);
    mgr.recordOfferedMoniker("alice", stranger, "Whoever");
    expect(mgr.getRenameNotices("alice")).toHaveLength(0);
  });

  it("rename notices are per-agent — alice's notice never appears in bob's inbox", async () => {
    const seed = openTestDb(join(tempDir, "sessions.db"));
    await seedAgents(seed, ["bob"]);
    seed.close();
    // Trigger a notice for alice's contact.
    mgr.recordOfferedMoniker("alice", pk, "Alice");
    mgr.setContactMoniker("alice", pk, "Mum");
    mgr.recordOfferedMoniker("alice", pk, "AliceCorp");
    expect(mgr.getRenameNotices("alice")).toHaveLength(1);
    expect(mgr.getRenameNotices("bob")).toHaveLength(0); // scoped by agent_id — no bleed
  });
});
