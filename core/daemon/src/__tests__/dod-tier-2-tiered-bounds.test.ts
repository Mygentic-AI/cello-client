/**
 * DOD-TIER-2 / DOD-TIER-3 (address-book Step 2) — abuse bounds become tier-graduated, and a BLOCKED
 * sender is refused indistinguishably.
 *
 * The two invariants under test:
 *   - INV-TIER-BOUND: a higher tier only RAISES a bound; no tier is unbounded. `vip` is finite.
 *   - DOD-TIER-3 (no oracle): `blocked` (session cap 0) is refused through the SAME per-sender-cap
 *     path an over-cap `unknown` takes — byte-identical response, no separate blocked branch.
 *
 * The grid replaces the old binary "known contacts exempt entirely (bounded only by disk)". Since
 * `cello_contact_set_tier` is Step 3, these tests set a contact's tier directly in the DB.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { openTestDb } from "./helpers/encrypted-db.js";
import { seedAgents } from "./helpers/seed-agents.js";
import { TIER, DEFAULT_TIER_BOUNDS, tierBoundsFor } from "../contacts-tier-migration.js";
import {
  SessionNodeManager,
  ABUSE_MAX_SESSION_RECEIVED_BYTES,
  ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER,
  type ISessionNodeFactory,
  type SessionNodeConfig,
} from "../session-node-manager.js";
import type { CelloNode } from "@cello-protocol/transport";
import type { Logger } from "../types.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };
function msgLeafHash(content: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(new Uint8Array([0x00])).update(content).digest());
}

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

/** Set a contact row at an explicit tier (stands in for Step 3's cello_contact_set_tier). */
function setTier(db: DaemonDatabase, agentId: string, pubkey: string, tier: number): void {
  db.prepare("INSERT OR REPLACE INTO contacts (agent_id, pubkey, added_at, tier) VALUES (?, ?, ?, ?)")
    .run(agentId, pubkey, Date.now(), tier);
}

/** Seed N active sessions from one counterparty (fast — no full acceptance flow). A monotonic
 *  counter makes every session_id globally unique across calls (the sessions PK is agent_id+sid). */
let sidCounter = 0;
function seedSessions(db: DaemonDatabase, agentId: string, pubkey: string, n: number): void {
  const now = Date.now();
  for (let i = 0; i < n; i++) {
    const sid = (++sidCounter).toString(16).padStart(32, "0");
    db.prepare(
      `INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at, message_count, interrupted_at)
       VALUES (?, ?, ?, 'active', ?, ?, 0, NULL)`,
    ).run(sid, agentId, pubkey, now, now);
  }
}

describe("DOD-TIER-2 — the bounds grid (INV-TIER-BOUND: no tier unbounded)", () => {
  it("matches the spec table exactly, and every bound is FINITE", () => {
    expect(DEFAULT_TIER_BOUNDS[TIER.BLOCKED]).toEqual({ maxSessionsPerSender: 0, maxBytesPerSession: 0 });
    expect(DEFAULT_TIER_BOUNDS[TIER.UNKNOWN]).toEqual({ maxSessionsPerSender: 3, maxBytesPerSession: 25 * 1024 * 1024 });
    expect(DEFAULT_TIER_BOUNDS[TIER.KNOWN]).toEqual({ maxSessionsPerSender: 5, maxBytesPerSession: 100 * 1024 * 1024 });
    expect(DEFAULT_TIER_BOUNDS[TIER.WHITELISTED]).toEqual({ maxSessionsPerSender: 20, maxBytesPerSession: 500 * 1024 * 1024 });
    expect(DEFAULT_TIER_BOUNDS[TIER.VIP]).toEqual({ maxSessionsPerSender: 50, maxBytesPerSession: 2 * 1024 * 1024 * 1024 });
    for (const t of [TIER.BLOCKED, TIER.UNKNOWN, TIER.KNOWN, TIER.WHITELISTED, TIER.VIP]) {
      const b = DEFAULT_TIER_BOUNDS[t];
      expect(Number.isFinite(b.maxSessionsPerSender), `tier ${t} sessions finite`).toBe(true);
      expect(Number.isFinite(b.maxBytesPerSession), `tier ${t} bytes finite`).toBe(true);
    }
    // VIP is the highest — and explicitly NOT Infinity.
    expect(DEFAULT_TIER_BOUNDS[TIER.VIP].maxSessionsPerSender).not.toBe(Infinity);
    expect(DEFAULT_TIER_BOUNDS[TIER.VIP].maxBytesPerSession).not.toBe(Infinity);
  });

  it("UNKNOWN's caps still equal the legacy constants (unchanged, AC1/AC2)", () => {
    expect(ABUSE_MAX_SESSIONS_PER_UNKNOWN_SENDER).toBe(3);
    expect(ABUSE_MAX_SESSION_RECEIVED_BYTES).toBe(25 * 1024 * 1024);
  });

  it("tierBoundsFor is total — a corrupt/out-of-range tier gets UNKNOWN's bounds, never undefined", () => {
    expect(tierBoundsFor(99)).toEqual(DEFAULT_TIER_BOUNDS[TIER.UNKNOWN]);
    expect(tierBoundsFor(null)).toEqual(DEFAULT_TIER_BOUNDS[TIER.UNKNOWN]);
    expect(tierBoundsFor(TIER.VIP)).toEqual(DEFAULT_TIER_BOUNDS[TIER.VIP]);
  });
});

describe("DOD-TIER-2/3 — tier-graduated acceptance bound", () => {
  let tempDir: string;
  let mgr: SessionNodeManager;
  let db: DaemonDatabase;
  let alice: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "dod-tier-2-"));
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

  it("per-sender session cap is the tier's — KNOWN(5) allows a 5th, refuses a 6th", () => {
    const bob = "bb".repeat(32);
    setTier(db, alice, bob, TIER.KNOWN);
    seedSessions(db, alice, bob, 4);
    expect(mgr.checkUnknownSenderAcceptanceBound("alice", bob)).toEqual({ ok: true }); // 4 < 5
    seedSessions(db, alice, bob, 1); // now 5
    expect(mgr.checkUnknownSenderAcceptanceBound("alice", bob))
      .toMatchObject({ ok: false, reason: "abuse_bound_sessions_per_sender" }); // 5 >= 5
  });

  it("VIP is finite — refused past 50 concurrent sessions (INV-TIER-BOUND)", () => {
    const vip = "cc".repeat(32);
    setTier(db, alice, vip, TIER.VIP);
    seedSessions(db, alice, vip, 49);
    expect(mgr.checkUnknownSenderAcceptanceBound("alice", vip)).toEqual({ ok: true }); // 49 < 50
    seedSessions(db, alice, vip, 1); // now 50
    expect(mgr.checkUnknownSenderAcceptanceBound("alice", vip))
      .toMatchObject({ ok: false, reason: "abuse_bound_sessions_per_sender" }); // 50 >= 50, NOT unbounded
  });

  it("DOD-TIER-3: a BLOCKED sender is refused BYTE-IDENTICALLY to an over-cap UNKNOWN (no oracle)", () => {
    // Over-cap UNKNOWN: a stranger at the per-sender cap.
    const stranger = "dd".repeat(32);
    seedSessions(db, alice, stranger, 3); // UNKNOWN cap is 3
    const overCapUnknown = mgr.checkUnknownSenderAcceptanceBound("alice", stranger);

    // BLOCKED: cap 0 → refused with the SAME reason, through the SAME path, with ZERO sessions.
    const blocked = "ee".repeat(32);
    setTier(db, alice, blocked, TIER.BLOCKED);
    const blockedRes = mgr.checkUnknownSenderAcceptanceBound("alice", blocked);

    expect(blockedRes).toEqual({ ok: false, reason: "abuse_bound_sessions_per_sender" });
    expect(blockedRes).toEqual(overCapUnknown); // byte-identical — the whole point of DOD-TIER-3
  });

  it("the global anti-swarm cap applies to UNKNOWN senders but a KNOWN+ contact is exempt from IT (not from its own cap)", () => {
    // Saturate the global unknown pool with 50 distinct strangers.
    for (let i = 0; i < 50; i++) seedSessions(db, alice, `str${i}`.padStart(64, "0"), 1);
    // A brand-new stranger: own count 0 < 3, but the GLOBAL cap trips.
    const newStranger = "ff".repeat(32);
    expect(mgr.checkUnknownSenderAcceptanceBound("alice", newStranger))
      .toMatchObject({ ok: false, reason: "abuse_bound_unknown_sessions_global" });
    // A KNOWN contact with count 0 is NOT subject to the global unknown cap.
    const friend = "ab".repeat(32);
    setTier(db, alice, friend, TIER.KNOWN);
    expect(mgr.checkUnknownSenderAcceptanceBound("alice", friend)).toEqual({ ok: true });
  });

  it("the pool counts an UNKNOWN-TIER CONTACT's sessions but excludes a KNOWN+ one (tier, not row-existence)", () => {
    // Distinguishes the new `tier >= KNOWN` pool semantics from the old row-existence proxy: BOTH
    // senders below have contact ROWS, so the old query would have exempted BOTH (pool 0). Only the
    // KNOWN one is genuinely trusted; the UNKNOWN-tier contact must still count toward the stranger pool.
    const unknownContact = "1a".repeat(32);
    const knownContact = "2b".repeat(32);
    setTier(db, alice, unknownContact, TIER.UNKNOWN);
    setTier(db, alice, knownContact, TIER.KNOWN);
    seedSessions(db, alice, unknownContact, 4);
    seedSessions(db, alice, knownContact, 7);
    expect(mgr.countActiveSessionsFromUnknownSenders("alice")).toBe(4); // only the UNKNOWN-tier contact
  });

  it("an UNKNOWN-tier CONTACT is refused by the GLOBAL cap when the pool is full (would escape under row-existence)", () => {
    for (let i = 0; i < 50; i++) seedSessions(db, alice, `s${i}`.padStart(64, "0"), 1); // saturate the pool
    const unknownContact = "3c".repeat(32);
    setTier(db, alice, unknownContact, TIER.UNKNOWN); // a contact ROW, but UNKNOWN tier
    // own count 0 < 3, but tier === UNKNOWN → the global check runs → pool 50 >= 50 → refused globally.
    expect(mgr.checkUnknownSenderAcceptanceBound("alice", unknownContact))
      .toMatchObject({ ok: false, reason: "abuse_bound_unknown_sessions_global" });
  });
});

describe("DOD-TIER-2 — per-tier byte cap on received content (AC2)", () => {
  let tempDir: string;
  let mgr: SessionNodeManager;
  let db: DaemonDatabase;
  let alice: string;
  const SID = "aa".repeat(16);

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "dod-tier-2-bytes-"));
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

  it("the byte cap is the TIER's, applied even to a CONTACT — an UNKNOWN-tier contact is capped at 25 MB, a KNOWN one gets 100 MB", async () => {
    // The distinguishing case vs. the old "any contact is exempt entirely" behaviour: BOTH senders
    // below are contacts (rows exist), so the old code would exempt BOTH. Only the tier model caps
    // the UNKNOWN-tier contact — this test is red under the old isContact-exempt gate for that reason.
    // Prior received == exactly the 25 MB cap, so any tip exceeds it for a 25 MB-capped sender.
    const unknownContact = "11".repeat(32);
    setTier(db, alice, unknownContact, TIER.UNKNOWN); // a contact, but only UNKNOWN tier
    await mgr.createSessionNode(SID, "alice", unknownContact, "peer-1", "corr");
    const big = new Uint8Array(ABUSE_MAX_SESSION_RECEIVED_BYTES);
    const { leafIndex } = mgr.appendSessionLeaf("alice", SID, "msg", "aa".repeat(32), "seed");
    mgr.recordTranscriptMessage("alice", SID, leafIndex, "received", big, "seed");
    const tip = new TextEncoder().encode("this tips past 25 MB");
    const unknownRes = await mgr.ingestReceivedContent("alice", SID, tip, msgLeafHash(tip), "corr-2");
    expect(unknownRes).toMatchObject({ ok: false, reason: "session_size_limit_exceeded" });

    // Same 25 MB prior, KNOWN-tier contact: 25 MB + tip is well under KNOWN's 100 MB cap → accepted.
    const SID2 = "bb".repeat(16);
    const knownContact = "22".repeat(32);
    setTier(db, alice, knownContact, TIER.KNOWN);
    await mgr.createSessionNode(SID2, "alice", knownContact, "peer-2", "corr");
    const big2 = new Uint8Array(ABUSE_MAX_SESSION_RECEIVED_BYTES);
    const { leafIndex: li2 } = mgr.appendSessionLeaf("alice", SID2, "msg", "bb".repeat(32), "seed2");
    mgr.recordTranscriptMessage("alice", SID2, li2, "received", big2, "seed2");
    const tip2 = new TextEncoder().encode("still fine for a KNOWN contact");
    const knownRes = await mgr.ingestReceivedContent("alice", SID2, tip2, msgLeafHash(tip2), "corr-3");
    expect(knownRes.ok).toBe(true);
  });

  it("a KNOWN contact's byte cap is FINITE — refused past 100 MB (INV-TIER-BOUND, kills a `tier>=KNOWN?Infinity` bypass)", async () => {
    // Behavioural proof that KNOWN is bounded, not exempt: prior received == exactly the 100 MB cap,
    // so any further byte exceeds it. A cap of Infinity for KNOWN would let this through — this is red
    // under such a bypass.
    const SID3 = "cc".repeat(16);
    const known = "44".repeat(32);
    setTier(db, alice, known, TIER.KNOWN);
    await mgr.createSessionNode(SID3, "alice", known, "peer-3", "corr");
    const huge = new Uint8Array(DEFAULT_TIER_BOUNDS[TIER.KNOWN].maxBytesPerSession); // exactly 100 MB
    const { leafIndex } = mgr.appendSessionLeaf("alice", SID3, "msg", "cc".repeat(32), "seed3");
    mgr.recordTranscriptMessage("alice", SID3, leafIndex, "received", huge, "seed3");
    const tip = new TextEncoder().encode("this pushes past the 100 MB KNOWN cap");
    const res = await mgr.ingestReceivedContent("alice", SID3, tip, msgLeafHash(tip), "corr-4");
    expect(res).toMatchObject({ ok: false, reason: "session_size_limit_exceeded" });
  });
});
