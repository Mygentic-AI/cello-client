/**
 * DOD-TIER-1 (Step 1) — the tier constant map, the total `normalizeTier`, and the manager helpers.
 *
 * The single most dangerous line in this whole unit is the read-side default. `tier` is an INTEGER
 * where BLOCKED is a REAL, meaningful ZERO. So the resolver may NOT be written `tier || UNKNOWN` —
 * `0 || 1` is `1`, which would silently un-block every blocked contact. And `null >= 0` is `true` in
 * JS (null coerces to 0), so a NULL tier that reached a bound-grid lookup would read as "not blocked"
 * and then crash on `grid[null]`. `normalizeTier` exists precisely to make ABSENT (undefined) and
 * NULL both resolve to UNKNOWN — the tighter default — while preserving an explicit 0 (BLOCKED).
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { openTestDb } from "./helpers/encrypted-db.js";
import { seedAgents } from "./helpers/seed-agents.js";
import { TIER, normalizeTier, isKnownTierValue } from "../contacts-tier-migration.js";
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

describe("DOD-TIER-1 — TIER constant map", () => {
  it("has the five tiers ordered 0..4 so `>=` comparisons are meaningful", () => {
    expect(TIER.BLOCKED).toBe(0);
    expect(TIER.UNKNOWN).toBe(1);
    expect(TIER.KNOWN).toBe(2);
    expect(TIER.WHITELISTED).toBe(3);
    expect(TIER.VIP).toBe(4);
    expect(TIER.BLOCKED < TIER.UNKNOWN).toBe(true);
    expect(TIER.UNKNOWN < TIER.KNOWN).toBe(true);
    expect(TIER.KNOWN < TIER.WHITELISTED).toBe(true);
    expect(TIER.WHITELISTED < TIER.VIP).toBe(true);
  });

  it("isKnownTierValue accepts exactly 0..4 and rejects everything else", () => {
    for (const v of [0, 1, 2, 3, 4]) expect(isKnownTierValue(v)).toBe(true);
    for (const v of [-1, 5, 1.5, NaN, Infinity]) expect(isKnownTierValue(v)).toBe(false);
  });
});

describe("DOD-TIER-1 — normalizeTier totality (the read-side default)", () => {
  it("maps ABSENT (undefined) and NULL to UNKNOWN — the tighter default", () => {
    expect(normalizeTier(undefined)).toBe(TIER.UNKNOWN);
    expect(normalizeTier(null)).toBe(TIER.UNKNOWN);
  });

  it("preserves an explicit BLOCKED (0) — it must NOT be swallowed by a `|| UNKNOWN` falsy trap", () => {
    expect(normalizeTier(0)).toBe(TIER.BLOCKED);
    expect(normalizeTier(TIER.BLOCKED)).toBe(0);
  });

  it("returns every explicit tier unchanged", () => {
    for (const v of [TIER.BLOCKED, TIER.UNKNOWN, TIER.KNOWN, TIER.WHITELISTED, TIER.VIP]) {
      expect(normalizeTier(v)).toBe(v);
    }
  });

  it("is TOTAL: a corrupt / out-of-range stored value also collapses to UNKNOWN (no grid[99] crash)", () => {
    for (const v of [99, -1, 5, 1.5, NaN, Infinity]) {
      expect(normalizeTier(v)).toBe(TIER.UNKNOWN);
    }
  });
});

describe("DOD-TIER-1 — getTier FAILS CLOSED on an unreachable ACL", () => {
  it("throws (never returns UNKNOWN) when the DB is not initialized — a security read must not admit on failure", () => {
    // getTier gates inbound bounds in Step 2. If it degraded to UNKNOWN when it cannot read the ACL,
    // a BLOCKED sender would read as UNKNOWN and be admitted. So a missing DB throws, like addContact.
    const mgr = new SessionNodeManager({ factory: new StubNodeFactory(), logger: silent, dbPath: "/nonexistent/unused.db" });
    // NOT initialized — #db is undefined.
    expect(() => mgr.getTier("ada", "anypubkey")).toThrow(/not initialized/);
  });
});

describe("DOD-TIER-1 — SessionNodeManager.getTier + addContact stamping", () => {
  let tempDir: string;
  let mgr: SessionNodeManager;
  let dbPath: string;
  let ada: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "dod-tier-1-mgr-"));
    dbPath = join(tempDir, "sessions.db");
    const seed = openTestDb(dbPath);
    ada = (await seedAgents(seed, ["ada"])).get("ada")!;
    seed.close();
    mgr = new SessionNodeManager({ factory: new StubNodeFactory(), logger: silent, dbPath });
    await mgr.initialize();
  });
  afterEach(async () => {
    await mgr.stop?.();
    await rm(tempDir, { recursive: true, force: true });
  });

  it("getTier returns UNKNOWN for a pubkey with no contact row (absence = UNKNOWN)", () => {
    expect(mgr.getTier("ada", "neverseenpubkey")).toBe(TIER.UNKNOWN);
  });

  it("getTier returns UNKNOWN for an existing row whose tier is NULL (the null>=0 trap guarded)", () => {
    const db = openTestDb(dbPath);
    db.prepare("INSERT INTO contacts (agent_id, pubkey, added_at, tier) VALUES (?, ?, ?, NULL)")
      .run(ada, "nulltierpubkey", 111);
    db.close();
    expect(mgr.getTier("ada", "nulltierpubkey")).toBe(TIER.UNKNOWN);
  });

  it("getTier returns an explicit tier unchanged, including BLOCKED(0)", () => {
    const db = openTestDb(dbPath);
    db.prepare("INSERT INTO contacts (agent_id, pubkey, added_at, tier) VALUES (?, ?, ?, ?)")
      .run(ada, "vippubkey", 111, TIER.VIP);
    db.prepare("INSERT INTO contacts (agent_id, pubkey, added_at, tier) VALUES (?, ?, ?, ?)")
      .run(ada, "blockedpubkey", 112, TIER.BLOCKED);
    db.close();
    expect(mgr.getTier("ada", "vippubkey")).toBe(TIER.VIP);
    expect(mgr.getTier("ada", "blockedpubkey")).toBe(TIER.BLOCKED);
  });

  it("addContact stamps a new row tier=UNKNOWN (no NULL window) and records provenance", () => {
    mgr.addContact("ada", "accpubkey", undefined, "accepted");
    mgr.addContact("ada", "initpubkey", undefined, "initiated");
    mgr.addContact("ada", "legacypubkey"); // no provenance → null

    expect(mgr.getTier("ada", "accpubkey")).toBe(TIER.UNKNOWN);
    expect(mgr.getTier("ada", "initpubkey")).toBe(TIER.UNKNOWN);

    const db = openTestDb(dbPath);
    const rows = db.prepare("SELECT pubkey, tier, provenance FROM contacts WHERE agent_id = ? ORDER BY added_at ASC")
      .all(ada) as Array<{ pubkey: string; tier: number | null; provenance: string | null }>;
    db.close();
    const byPk = new Map(rows.map((r) => [r.pubkey, r]));
    expect(byPk.get("accpubkey")).toMatchObject({ tier: TIER.UNKNOWN, provenance: "accepted" });
    expect(byPk.get("initpubkey")).toMatchObject({ tier: TIER.UNKNOWN, provenance: "initiated" });
    expect(byPk.get("legacypubkey")).toMatchObject({ tier: TIER.UNKNOWN, provenance: null });
  });

  it("re-adding an existing contact is a no-op — tier and provenance are pinned at first add", () => {
    mgr.addContact("ada", "pinnedpubkey", undefined, "accepted");
    // Raise the tier out-of-band, then re-add: the INSERT OR IGNORE must not reset it.
    const db = openTestDb(dbPath);
    db.prepare("UPDATE contacts SET tier = ? WHERE agent_id = ? AND pubkey = ?").run(TIER.VIP, ada, "pinnedpubkey");
    db.close();

    mgr.addContact("ada", "pinnedpubkey", undefined, "initiated"); // re-add: no-op
    expect(mgr.getTier("ada", "pinnedpubkey")).toBe(TIER.VIP);

    const db2 = openTestDb(dbPath);
    const row = db2.prepare("SELECT provenance FROM contacts WHERE agent_id = ? AND pubkey = ?")
      .get(ada, "pinnedpubkey") as { provenance: string | null };
    db2.close();
    expect(row.provenance).toBe("accepted"); // NOT overwritten to "initiated"
  });
});
