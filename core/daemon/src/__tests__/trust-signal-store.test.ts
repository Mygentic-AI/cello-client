/**
 * DOD-STORE-CLIENT-1 — the two client-side trust-signal tables.
 *
 * TWO tables, never one with a role flag (M10-D4). They answer different questions and obey
 * different scoping rules, and collapsing them behind a `role` column is exactly how one set of
 * rules gets applied to the other's rows:
 *
 *   wallet_trust_signals   — signals ABOUT this daemon's agents, held to be PRESENTED.
 *                            NO agent association at all (M10-D14): PK = signal_hash, one row per
 *                            signal per daemon. The envelope's own HASHED subject_kind/subject
 *                            decides who may present it, at presentation time. Adding an agent to
 *                            an existing daemon is therefore ZERO signal work — no sweep, no
 *                            assignment, no re-attribution at renewal or expiry.
 *
 *   contact_trust_signals  — signals OTHER agents PRESENTED TO one of my agents.
 *                            Consent scoping IS genuinely per-agent here, so agent_id is NOT NULL
 *                            and the row hangs off a contact row by composite FK. This is where the
 *                            M8 scaffold's `agent_id = null` defect (investigation §9) dies.
 *
 * The M8 scaffold table (`trust_signals`) is deliberately still standing — M10-D18: the DROP travels
 * with the BACKFILL (DOD-MINT-INTERNAL-1), so the drop and its replacement land together and no gate
 * is red in between.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { openTestDb } from "./helpers/encrypted-db.js";
import { seedAgents } from "./helpers/seed-agents.js";
import { SessionNodeManager, type ISessionNodeFactory, type SessionNodeConfig } from "../session-node-manager.js";
import { TrustSignalStore, ensureTrustSignalSchema, type WalletSignalInput } from "../trust-signal-store.js";
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

const HASH = (c: string): string => c.repeat(64);

/** A whole envelope, as the store takes it. `type` is an OPAQUE STRING at every layer below. */
function envelope(over: Partial<WalletSignalInput> = {}): WalletSignalInput {
  return {
    signalHash: HASH("a"),
    subjectKind: "agent",
    subject: "agent-1",
    issuerKind: "portal",
    issuerPubkey: "aabb",
    type: "phone",
    schemaVersion: 1,
    payload: new Uint8Array([1, 2, 3]),
    issuedAt: 1_768_000_000,
    expiresAt: null,
    supersedesHash: null,
    status: "active",
    ...over,
  };
}

describe("DOD-STORE-CLIENT-1 — client trust-signal storage", () => {
  let tempDir: string;
  let mgr: SessionNodeManager;
  let db: DaemonDatabase;
  let store: TrustSignalStore;
  let alice: string;
  let bob: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "dod-store-client-1-"));
    const dbPath = join(tempDir, "sessions.db");
    const seed = openTestDb(dbPath);
    const ids = await seedAgents(seed, ["alice", "bob"]);
    alice = ids.get("alice")!;
    bob = ids.get("bob")!;
    seed.close();
    mgr = new SessionNodeManager({ factory: new StubNodeFactory(), logger: silent, dbPath });
    await mgr.initialize();
    db = mgr.getDb();
    store = new TrustSignalStore(db, silent);
  });

  afterEach(async () => {
    await mgr.stop?.();
    await rm(tempDir, { recursive: true, force: true });
  });

  describe("the wallet (M10-D14: no agent association)", () => {
    it("stores and reads back a whole envelope, payload byte-for-byte", () => {
      store.putWalletSignal(envelope({ subject: alice }));
      const got = store.getWalletSignal(HASH("a"));
      expect(got).not.toBeNull();
      expect(got!.type).toBe("phone");
      expect(new Uint8Array(got!.payload)).toEqual(new Uint8Array([1, 2, 3]));
      expect(got!.subjectKind).toBe("agent");
      expect(got!.issuerKind).toBe("portal");
      expect(got!.expiresAt).toBeNull();
      expect(got!.supersedesHash).toBeNull();
    });

    it("has NO agent column at all — the envelope's subject decides who presents it (M10-D14)", () => {
      // Structural, not conventional: with no column there is no per-agent bookkeeping to get wrong
      // at agent-add, at renewal, or at expiry.
      const cols = (db.prepare("PRAGMA table_info(wallet_trust_signals)").all() as Array<{ name: string }>)
        .map((c) => c.name);
      expect(cols).not.toContain("agent_id");
      expect(cols).not.toContain("agent_name");
      expect(cols).toContain("signal_hash");
      expect(cols).toContain("subject_kind");
      expect(cols).toContain("subject");
    });

    it("duplicate delivery is a NO-OP — never an error, never an overwrite (§14.11 sync property)", () => {
      store.putWalletSignal(envelope());
      store.putWalletSignal(envelope({ payload: new Uint8Array([9, 9, 9]) })); // same hash, different bytes
      const got = store.getWalletSignal(HASH("a"));
      // Content-addressed: the row IS its hash. Different bytes under the same hash is a liar — if the
      // bytes really differed, the hash would differ — so the second delivery must not win.
      expect(new Uint8Array(got!.payload)).toEqual(new Uint8Array([1, 2, 3]));
      expect(db.prepare("SELECT COUNT(*) AS n FROM wallet_trust_signals").get()).toMatchObject({ n: 1 });
    });

    it("status is MUTABLE while the hash is not — which is why status is outside the preimage", () => {
      store.putWalletSignal(envelope());
      store.setWalletStatus(HASH("a"), "revoked");
      const got = store.getWalletSignal(HASH("a"))!;
      expect(got.status).toBe("revoked");
      // ...and it is still findable by the SAME hash. If status were hashed, revoking would change
      // the hash and the directory could never find the signal again.
      expect(got.signalHash).toBe(HASH("a"));
    });

    it("an account-subject row is presentable by EVERY agent under that account (M10-D5)", () => {
      store.putWalletSignal(envelope({ signalHash: HASH("1"), subjectKind: "account", subject: "acct-x", type: "email" }));
      store.putWalletSignal(envelope({ signalHash: HASH("2"), subjectKind: "agent", subject: alice, type: "phone" }));
      store.putWalletSignal(envelope({ signalHash: HASH("3"), subjectKind: "agent", subject: bob, type: "phone" }));

      const forAlice = store.listPresentable({ agentId: alice, accountId: "acct-x" }).map((s) => s.signalHash).sort();
      const forBob = store.listPresentable({ agentId: bob, accountId: "acct-x" }).map((s) => s.signalHash).sort();

      expect(forAlice).toEqual([HASH("1"), HASH("2")].sort()); // the account row + her own
      expect(forBob).toEqual([HASH("1"), HASH("3")].sort());   // the account row + his own
      // Alice's agent-subject signal must NOT be presentable by Bob, co-resident or not.
      expect(forBob).not.toContain(HASH("2"));
    });

    it("an agent under a DIFFERENT account cannot present the account signal", () => {
      store.putWalletSignal(envelope({ signalHash: HASH("1"), subjectKind: "account", subject: "acct-x" }));
      expect(store.listPresentable({ agentId: alice, accountId: "acct-OTHER" })).toEqual([]);
    });

    it("does not present an EXPIRED signal", () => {
      store.putWalletSignal(envelope({ signalHash: HASH("2"), subjectKind: "agent", subject: alice, expiresAt: 1 }));
      expect(store.listPresentable({ agentId: alice, accountId: "acct-x", now: 1_768_000_000 })).toEqual([]);
    });

    it("does not present a REVOKED or SUPERSEDED signal", () => {
      store.putWalletSignal(envelope({ signalHash: HASH("2"), subjectKind: "agent", subject: alice }));
      store.setWalletStatus(HASH("2"), "revoked");
      expect(store.listPresentable({ agentId: alice, accountId: "acct-x" })).toEqual([]);
      store.setWalletStatus(HASH("2"), "superseded");
      expect(store.listPresentable({ agentId: alice, accountId: "acct-x" })).toEqual([]);
      store.setWalletStatus(HASH("2"), "active");
      expect(store.listPresentable({ agentId: alice, accountId: "acct-x" })).toHaveLength(1);
    });
  });

  describe("the received store (INV-AGENT-SCOPED)", () => {
    const PEER = HASH("e");

    beforeEach(() => {
      mgr.addContact("alice", PEER, undefined, "accepted");
    });

    it("stores a verified signal against the contact row", () => {
      store.putReceivedSignal({ agentId: alice, contactPubkey: PEER, verifiedAt: 123, ...envelope() });
      const got = store.listReceived({ agentId: alice, contactPubkey: PEER });
      expect(got).toHaveLength(1);
      expect(got[0].type).toBe("phone");
      expect(got[0].verifiedAt).toBe(123);
    });

    it("REFUSES a signal for a contact that does not exist — the FK is REAL, not decorative", () => {
      // This is the test that proves PRAGMA foreign_keys is actually ON. SQLite defaults it OFF, and
      // with it off SQLite silently accepts the orphan row — INV-AGENT-SCOPED would then be enforced
      // by nothing but good intentions, and the schema would LIE about it.
      expect(() =>
        store.putReceivedSignal({ agentId: alice, contactPubkey: HASH("9"), verifiedAt: 1, ...envelope() }),
      ).toThrow(/FOREIGN KEY|constraint/i);
    });

    it("REFUSES a NULL agent_id — the M8 scaffold's defect cannot be reintroduced", () => {
      expect(() =>
        db.prepare(
          `INSERT INTO contact_trust_signals
             (agent_id, contact_pubkey, signal_hash, subject_kind, subject, issuer_kind, issuer_pubkey,
              type, schema_version, payload, issued_at, expires_at, supersedes_hash, status, verified_at, received_at)
           VALUES (NULL, ?, 'h', 'agent', 's', 'portal', 'p', 't', 1, X'00', 1, NULL, NULL, 'active', 1, 1)`,
        ).run(PEER),
      ).toThrow(/NOT NULL|constraint/i);
    });

    it("is INVISIBLE to a co-resident agent — the whole point of INV-AGENT-SCOPED", () => {
      mgr.addContact("bob", PEER, undefined, "accepted"); // Bob has the SAME peer as a contact
      store.putReceivedSignal({ agentId: alice, contactPubkey: PEER, verifiedAt: 1, ...envelope() });

      // Same daemon, same DB, same peer — and Bob still sees nothing.
      expect(store.listReceived({ agentId: bob, contactPubkey: PEER })).toEqual([]);
      expect(store.listReceived({ agentId: alice, contactPubkey: PEER })).toHaveLength(1);
    });

    it("removing a contact takes their signals with it (consent withdrawn ⇒ evidence gone)", () => {
      store.putReceivedSignal({ agentId: alice, contactPubkey: PEER, verifiedAt: 1, ...envelope() });
      mgr.removeContact("alice", PEER);
      expect(store.listReceived({ agentId: alice, contactPubkey: PEER })).toEqual([]);
    });

    it("re-presenting the same signal is idempotent (a peer may present it every session)", () => {
      store.putReceivedSignal({ agentId: alice, contactPubkey: PEER, verifiedAt: 1, ...envelope() });
      store.putReceivedSignal({ agentId: alice, contactPubkey: PEER, verifiedAt: 2, ...envelope() });
      const got = store.listReceived({ agentId: alice, contactPubkey: PEER });
      expect(got).toHaveLength(1);
      // verified_at is re-stamped: it records when WE last re-verified, and freshness is re-checked
      // on use (M10-D4) — a stale verified_at would be worse than useless, it would look fresh.
      expect(got[0].verifiedAt).toBe(2);
    });
  });

  describe("INV-ZERO-BUMP and INV-TYPE-CARRY hold at the storage layer", () => {
    it("accepts a type string this code has never seen — no registry, no release, no migration", () => {
      const weird = "some_type_invented_next_year";
      store.putWalletSignal(envelope({ signalHash: HASH("f"), type: weird }));
      expect(store.getWalletSignal(HASH("f"))!.type).toBe(weird);
    });

    it("has NO per-type construct in the schema — no CHECK, no enum, no type-predicated index", () => {
      // The reviewer's zero-bump lens, mechanised. If someone later adds `CHECK (type IN (...))`, this
      // fails and says why — the only way a schema-level enum gets caught BEFORE it ships and starts
      // rejecting a type the portal invented that morning.
      const sql = (db.prepare(
        "SELECT sql FROM sqlite_master WHERE name IN ('wallet_trust_signals','contact_trust_signals')",
      ).all() as Array<{ sql: string }>).map((r) => r.sql).join("\n");
      expect(sql).not.toMatch(/CHECK\s*\([^)]*\btype\b/i);

      const indexes = (db.prepare(
        `SELECT sql FROM sqlite_master WHERE type='index'
           AND tbl_name IN ('wallet_trust_signals','contact_trust_signals') AND sql IS NOT NULL`,
      ).all() as Array<{ sql: string }>).map((r) => r.sql).join("\n");
      expect(indexes).not.toMatch(/WHERE[^)]*\btype\b\s*=/i); // no partial index on a type VALUE
    });

    it("stores the payload as OPAQUE bytes — no field of it is hoisted into a column", () => {
      const cols = (db.prepare("PRAGMA table_info(wallet_trust_signals)").all() as Array<{ name: string }>)
        .map((c) => c.name);
      // Whatever a payload contains (a phone claim, a GitHub stat), it never becomes a column.
      // Hoisting one is BLOCKING per spec §3 — it is how a generic store quietly becomes per-type.
      for (const forbidden of ["phone", "email", "claim", "value", "count", "rate", "verified"]) {
        expect(cols).not.toContain(forbidden);
      }
      expect(cols).toContain("payload");
    });

    it("round-trips a payload that LOOKS like CBOR without parsing it", () => {
      const payload = new Uint8Array([0xd8, 0x40, 0x00, 0xff, 0x9f, 0xff]);
      store.putWalletSignal(envelope({ signalHash: HASH("b"), payload }));
      expect(new Uint8Array(store.getWalletSignal(HASH("b"))!.payload)).toEqual(payload);
    });
  });

  describe("migration integrity", () => {
    it("is idempotent — running the schema twice changes nothing and throws nothing", () => {
      expect(() => {
        ensureTrustSignalSchema(db, silent);
        ensureTrustSignalSchema(db, silent);
      }).not.toThrow();
      store.putWalletSignal(envelope());
      ensureTrustSignalSchema(db, silent);
      expect(store.getWalletSignal(HASH("a"))).not.toBeNull(); // data survived
    });

    it("fresh schema == migrated schema (the DoD clause)", async () => {
      // The failure this catches: an ALTER path that adds a column the CREATE path forgot, so fresh
      // installs and upgraded installs silently diverge — and only one of them is ever tested.
      const dir2 = await mkdtemp(join(tmpdir(), "dod-store-client-1-fresh-"));
      try {
        const p2 = join(dir2, "sessions.db");
        const mgr2 = new SessionNodeManager({ factory: new StubNodeFactory(), logger: silent, dbPath: p2 });
        await mgr2.initialize();
        const fresh = mgr2.getDb();
        ensureTrustSignalSchema(fresh, silent); // applied again, exactly as an upgrade would

        const shape = (d: DaemonDatabase, t: string): string[] =>
          (d.prepare(`PRAGMA table_info(${t})`).all() as Array<{ name: string; type: string; notnull: number }>)
            .map((c) => `${c.name}:${c.type}:${c.notnull}`);

        for (const t of ["wallet_trust_signals", "contact_trust_signals"]) {
          expect(shape(fresh, t), t).toEqual(shape(db, t));
        }
        await mgr2.stop?.();
      } finally {
        await rm(dir2, { recursive: true, force: true });
      }
    });

    it("the M8 scaffold table is STILL STANDING — the drop travels with the backfill (M10-D18)", () => {
      // Deliberate, and load-bearing. Dropping it here would leave the M8 delivery arm
      // (inbound-sessions.ts:601) writing to columns that no longer exist, and the j-trust spine test
      // red, across four units until MINT-INTERNAL-1 replaced it.
      const row = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='trust_signals'").get();
      expect(row, "M10-D18: drop `trust_signals` in DOD-MINT-INTERNAL-1, together with its replacement").toBeDefined();
    });
  });
});
