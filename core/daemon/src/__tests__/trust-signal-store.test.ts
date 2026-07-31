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
import { seedAgentKeys } from "./helpers/seed-agents.js";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { SessionNodeManager, type ISessionNodeFactory, type SessionNodeConfig } from "../session-node-manager.js";
import { TrustSignalStore, ensureTrustSignalSchema, type WalletSignalInput } from "../trust-signal-store.js";
import { ensureIdentitySchema } from "../db-identity-store.js";
import { withForeignKeysOff } from "../sqlcipher-db.js";
import { hashTrustSignalEnvelope as hashTrustSignalEnvelopeFn } from "@cello-protocol/protocol-types";
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
  /**
   * BOTH identities, deliberately, because they are not interchangeable and this file needs each
   * (`DOD-END-SCOPE-FIX-1`, fourth-review HIGH-4):
   *
   *   `alice`/`bob`             — the device-local `agent_id` UUID. Keys the SESSION tables, so it
   *                               is what `contact_trust_signals.agent_id` and its FK take.
   *   `alicePubkey`/`bobPubkey` — the K_local pubkey hex. This is what an agent-subject ENVELOPE's
   *                               `subject` holds in production; the directory joins it with
   *                               `JOIN agent_profiles ap ON ap.k_local_pubkey = sr.subject`.
   *
   * Until 2026-07-29 this file seeded `subject` with the UUID, so every presentation-scoping
   * assertion was written against a row shape production never produces.
   */
  let alice: string;
  let bob: string;
  let alicePubkey: string;
  let bobPubkey: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "dod-store-client-1-"));
    const dbPath = join(tempDir, "sessions.db");
    const seed = openTestDb(dbPath);
    const agents = await seedAgentKeys(seed, ["alice", "bob"]);
    alice = agents.get("alice")!.agentId;
    bob = agents.get("bob")!.agentId;
    alicePubkey = agents.get("alice")!.pubkeyHex;
    bobPubkey = agents.get("bob")!.pubkeyHex;
    seed.close();
    mgr = new SessionNodeManager({ securityGateway: new PassthroughGatewayClient(), factory: new StubNodeFactory(), logger: silent, dbPath });
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
      store.putWalletSignal(envelope({ subject: alicePubkey }));
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
      store.putWalletSignal(envelope({ signalHash: HASH("2"), subjectKind: "agent", subject: alicePubkey, type: "phone" }));
      store.putWalletSignal(envelope({ signalHash: HASH("3"), subjectKind: "agent", subject: bobPubkey, type: "phone" }));

      const forAlice = store.listPresentable({ agentPubkeyHex: alicePubkey, accountId: "acct-x" }).map((s) => s.signalHash).sort();
      const forBob = store.listPresentable({ agentPubkeyHex: bobPubkey, accountId: "acct-x" }).map((s) => s.signalHash).sort();

      expect(forAlice).toEqual([HASH("1"), HASH("2")].sort()); // the account row + her own
      expect(forBob).toEqual([HASH("1"), HASH("3")].sort());   // the account row + his own
      // Alice's agent-subject signal must NOT be presentable by Bob, co-resident or not.
      expect(forBob).not.toContain(HASH("2"));
    });

    it("an agent under a DIFFERENT account cannot present the account signal", () => {
      store.putWalletSignal(envelope({ signalHash: HASH("1"), subjectKind: "account", subject: "acct-x" }));
      expect(store.listPresentable({ agentPubkeyHex: alicePubkey, accountId: "acct-OTHER" })).toEqual([]);
    });

    it("does not present a signal that expired ONE SECOND ago (the unit bug this caught)", () => {
      // The original test used expires_at = 1 — so small that it was excluded whether the comparison
      // was in seconds or milliseconds. It passed against a `now` parameter that was silently divided
      // by 1000, and would have gone on passing while production presented expired signals. An expiry
      // ONE SECOND in the past is the case that can only pass if the units actually agree.
      const nowSec = 1_768_000_000;
      store.putWalletSignal(envelope({ signalHash: HASH("2"), subjectKind: "agent", subject: alicePubkey, expiresAt: nowSec - 1 }));
      expect(store.listPresentable({ agentPubkeyHex: alicePubkey, accountId: "acct-x", nowSec })).toEqual([]);
    });

    it("DOES present a signal that expires one second from now", () => {
      // The other side of the boundary. Together these two pin the comparison to the right unit: a
      // millisecond/second confusion moves the boundary by a factor of 1000 and breaks one of them.
      const nowSec = 1_768_000_000;
      store.putWalletSignal(envelope({ signalHash: HASH("3"), subjectKind: "agent", subject: alicePubkey, expiresAt: nowSec + 1 }));
      expect(store.listPresentable({ agentPubkeyHex: alicePubkey, accountId: "acct-x", nowSec })).toHaveLength(1);
    });

    it("defaults to the real clock in SECONDS — a signal expired an hour ago is not presented", () => {
      // Guards the DEFAULT path (no nowSec passed), which is where production actually runs and where
      // a stray Date.now() in milliseconds would land.
      const anHourAgo = Math.floor(Date.now() / 1000) - 3600;
      store.putWalletSignal(envelope({ signalHash: HASH("4"), subjectKind: "agent", subject: alicePubkey, expiresAt: anHourAgo }));
      expect(store.listPresentable({ agentPubkeyHex: alicePubkey, accountId: "acct-x" })).toEqual([]);
    });

    it("does not present a REVOKED or SUPERSEDED signal", () => {
      store.putWalletSignal(envelope({ signalHash: HASH("2"), subjectKind: "agent", subject: alicePubkey }));
      store.setWalletStatus(HASH("2"), "superseded");
      expect(store.listPresentable({ agentPubkeyHex: alicePubkey, accountId: "acct-x" })).toEqual([]);

      store.putWalletSignal(envelope({ signalHash: HASH("5"), subjectKind: "agent", subject: alicePubkey }));
      store.setWalletStatus(HASH("5"), "revoked");
      expect(store.listPresentable({ agentPubkeyHex: alicePubkey, accountId: "acct-x" })).toEqual([]);
    });

    it("REVOCATION IS TERMINAL — a revoked signal can never be resurrected to active (F5)", () => {
      // Without this guard setWalletStatus is a blind UPDATE, and a stale or replayed directory read
      // reporting `active` for a hash we already revoked would flip it back — and listPresentable
      // would start offering a revoked signal to counterparties again. The directory is the authority
      // on revocation, but a LATE answer from it is not a NEW answer.
      store.putWalletSignal(envelope({ signalHash: HASH("2"), subjectKind: "agent", subject: alicePubkey }));
      store.setWalletStatus(HASH("2"), "revoked");

      store.setWalletStatus(HASH("2"), "active"); // the stale/replayed read

      expect(store.getWalletSignal(HASH("2"))!.status).toBe("revoked");
      expect(store.listPresentable({ agentPubkeyHex: alicePubkey, accountId: "acct-x" })).toEqual([]);
    });

    it("a SUPERSEDED signal may still be revoked, but never returned to active", () => {
      store.putWalletSignal(envelope({ signalHash: HASH("2"), subjectKind: "agent", subject: alicePubkey }));
      store.setWalletStatus(HASH("2"), "superseded");
      store.setWalletStatus(HASH("2"), "active");
      expect(store.getWalletSignal(HASH("2"))!.status).toBe("superseded"); // not resurrected
      store.setWalletStatus(HASH("2"), "revoked");
      expect(store.getWalletSignal(HASH("2"))!.status).toBe("revoked");    // but may still worsen
    });
  });

  describe("listAllActive (DOD-PRESENT-1 — holder emit)", () => {
    it("offers an account-subject row and the presenting agent's OWN agent-subject row", () => {
      store.putWalletSignal(envelope({ signalHash: HASH("1"), subjectKind: "account", subject: "acct-x", type: "email" }));
      store.putWalletSignal(envelope({ signalHash: HASH("2"), subjectKind: "agent", subject: alicePubkey, type: "phone" }));
      const all = store.listAllActive({ presentingAgentPubkeyHex: alicePubkey });
      expect(all).toHaveLength(2);
      expect(all.map((s) => s.signalHash).sort()).toEqual([HASH("1"), HASH("2")].sort());
    });

    // ─── DOD-END-SCOPE-FIX-1 — INV-AGENT-SCOPED on the LIVE path ────────────────────────────────
    // `listPresentable` implements this scoping and has ZERO production callers. The wire path is
    // `listAllActive` (`outbound-sessions.ts:186`), which took no presenting identity at all — so
    // every agent on a daemon offered every other agent's agent-subject signals to its own
    // counterparties. An M10 defect, live, surfaced by M10B and fixed here.
    it("does NOT offer ANOTHER agent's agent-subject signal — INV-AGENT-SCOPED, live path", () => {
      store.putWalletSignal(envelope({ signalHash: HASH("2"), subjectKind: "agent", subject: alicePubkey, type: "phone" }));
      store.putWalletSignal(envelope({ signalHash: HASH("3"), subjectKind: "agent", subject: bobPubkey, type: "phone" }));

      const forBob = store.listAllActive({ presentingAgentPubkeyHex: bobPubkey });

      // Bob presents his own signal and NOT Alice's. Revert the SQL predicate and this returns both.
      expect(forBob.map((s) => s.signalHash)).toEqual([HASH("3")]);
    });

    it("scopes on the K_local PUBKEY, not the daemon's agent_id — the UUID is REFUSED", () => {
      // The trap this unit exists to close (fourth review HIGH-4): a predicate written against the
      // old fixture convention compares `subject` to a device-local UUID. It goes green on a fixture
      // seeded the same wrong way and matches ZERO production rows — silently un-presenting every
      // agent-subject signal.
      //
      // Returning [] for the UUID would pin that silence. Refusing kills the trap by construction:
      // a caller holding the wrong identity is a BUG, not an operator with an empty wallet, and the
      // two must not be indistinguishable (review MEDIUM-3).
      store.putWalletSignal(envelope({ signalHash: HASH("2"), subjectKind: "agent", subject: alicePubkey, type: "phone" }));
      expect(() => store.listAllActive({ presentingAgentPubkeyHex: alice })).toThrow(/lowercase hex/i);
      expect(store.listAllActive({ presentingAgentPubkeyHex: alicePubkey })).toHaveLength(1);
    });

    it("matches an UPPERCASE-hex stored subject — hex has a case, SQLite TEXT does not fold it", () => {
      // A directory version-skew emitting uppercase hex (a condition putWalletSignal already names)
      // would store `AABB…` for the same key the daemon holds as `aabb…`. Under BINARY collation
      // that row is invisible — never presented, no error. Case-insensitive comparison is the
      // correct equality for hex, not a fallback.
      store.putWalletSignal(envelope({
        signalHash: HASH("2"), subjectKind: "agent", subject: alicePubkey.toUpperCase(), type: "phone",
      }));
      expect(store.listAllActive({ presentingAgentPubkeyHex: alicePubkey })).toHaveLength(1);
      // ...and it is still SCOPED: Bob does not get Alice's row just because the case differs.
      expect(store.listAllActive({ presentingAgentPubkeyHex: bobPubkey })).toEqual([]);
    });

    it("REFUSES an absent, empty, or MALFORMED presenting identity — never presents everything (§5a)", () => {
      // ABSENT IS NOT FINE. If the caller cannot say who is presenting, the answer is refuse, not
      // "offer the lot" — the fail-open direction is precisely the defect being fixed, and it would
      // return silently with a full wallet. Malformed gets the same answer for the same reason: it
      // fails CLOSED either way, but only a refusal is diagnosable.
      store.putWalletSignal(envelope({ signalHash: HASH("2"), subjectKind: "agent", subject: alicePubkey }));
      expect(() => store.listAllActive({ presentingAgentPubkeyHex: "" })).toThrow(/lowercase hex/i);
      expect(() =>
        store.listAllActive({ presentingAgentPubkeyHex: undefined as unknown as string }),
      ).toThrow(/lowercase hex/i);
      // Right length, wrong case — the shape check has to be exact or a mixed-case key silently
      // matches nothing.
      expect(() => store.listAllActive({ presentingAgentPubkeyHex: alicePubkey.toUpperCase() })).toThrow(/lowercase hex/i);
      // An agent NAME: the other value in scope at the call site, and the easiest one to pass by
      // mistake.
      expect(() => store.listAllActive({ presentingAgentPubkeyHex: "alice" })).toThrow(/lowercase hex/i);
    });

    it("excludes expired signals", () => {
      const nowSec = Math.floor(Date.now() / 1000);
      store.putWalletSignal(envelope({ signalHash: HASH("1"), subject: alicePubkey, expiresAt: nowSec - 100 }));
      store.putWalletSignal(envelope({ signalHash: HASH("2"), subject: alicePubkey, expiresAt: nowSec + 100 }));
      const all = store.listAllActive({ presentingAgentPubkeyHex: alicePubkey });
      expect(all).toHaveLength(1);
      expect(all[0].signalHash).toBe(HASH("2"));
    });

    it("excludes revoked and superseded signals", () => {
      store.putWalletSignal(envelope({ signalHash: HASH("1"), subjectKind: "agent", subject: alicePubkey }));
      store.putWalletSignal(envelope({ signalHash: HASH("2"), subjectKind: "agent", subject: alicePubkey }));
      store.putWalletSignal(envelope({ signalHash: HASH("3"), subjectKind: "agent", subject: alicePubkey }));
      store.setWalletStatus(HASH("1"), "revoked");
      store.setWalletStatus(HASH("2"), "superseded");
      const all = store.listAllActive({ presentingAgentPubkeyHex: alicePubkey });
      expect(all).toHaveLength(1);
      expect(all[0].signalHash).toBe(HASH("3"));
    });

    it("returns empty array when wallet is empty", () => {
      expect(store.listAllActive({ presentingAgentPubkeyHex: alicePubkey })).toEqual([]);
    });
  });

  describe("the received store (INV-AGENT-SCOPED)", () => {
    const PEER = HASH("e");

    beforeEach(() => {
      mgr.addContact("alice", PEER, undefined, "accepted");
    });

    it("stores a verified signal against the contact row", () => {
      store.putReceivedSignal({ agentId: alice, contactPubkey: PEER, verifiedAt: 123, verdict: "active", ...envelope() });
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
        store.putReceivedSignal({ agentId: alice, contactPubkey: HASH("9"), verifiedAt: 1, verdict: "active", ...envelope() }),
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
      store.putReceivedSignal({ agentId: alice, contactPubkey: PEER, verifiedAt: 1, verdict: "active", ...envelope() });

      // Same daemon, same DB, same peer — and Bob still sees nothing.
      expect(store.listReceived({ agentId: bob, contactPubkey: PEER })).toEqual([]);
      expect(store.listReceived({ agentId: alice, contactPubkey: PEER })).toHaveLength(1);
    });

    it("removing a contact takes their signals with it (consent withdrawn ⇒ evidence gone)", () => {
      store.putReceivedSignal({ agentId: alice, contactPubkey: PEER, verifiedAt: 1, verdict: "active", ...envelope() });
      mgr.removeContact("alice", PEER);
      expect(store.listReceived({ agentId: alice, contactPubkey: PEER })).toEqual([]);
    });

    it("a peer CANNOT launder our REVOKED verdict back to active by re-presenting (F2)", () => {
      // The attack: `status` is outside the hash preimage — that is what makes it mutable, and it
      // also means it is NOT AUTHENTICATED by the signal hash. A presenter can claim anything.
      //
      // Bob presents signal H. We check the directory, find it REVOKED, and store that as evidence.
      // Next session Bob re-presents the SAME hash while we record a fresh verdict. If a later
      // verdict could overwrite the earlier one unconditionally, the party a revocation indicts
      // would get to erase the indictment. Evidence an adversary can rewrite is not evidence.
      store.putReceivedSignal({ agentId: alice, contactPubkey: PEER, verifiedAt: 1, verdict: "revoked", ...envelope() });
      expect(store.listReceived({ agentId: alice, contactPubkey: PEER })[0].verdict).toBe("revoked");

      store.putReceivedSignal({ agentId: alice, contactPubkey: PEER, verifiedAt: 2, verdict: "active", ...envelope() });

      const got = store.listReceived({ agentId: alice, contactPubkey: PEER })[0];
      expect(got.verdict, "revocation is terminal — a re-presentation must not resurrect it").toBe("revoked");
      expect(got.verifiedAt, "but we DID re-check it, and that is recorded").toBe(2);
    });

    it("the received input type carries no peer-controlled `status` — only OUR verdict", () => {
      // Structural, not a runtime check: ReceivedSignalInput omits `status` and requires `verdict`.
      // There is no pass-through for a call site to forget to block. This test documents the intent
      // so the field is not quietly re-added later "for symmetry with the wallet".
      const input = { agentId: alice, contactPubkey: PEER, verifiedAt: 1, verdict: "active" as const, ...envelope() };
      expect(Object.prototype.hasOwnProperty.call(input, "verdict")).toBe(true);
      store.putReceivedSignal(input);
      expect(store.listReceived({ agentId: alice, contactPubkey: PEER })[0].verdict).toBe("active");
    });

    it("re-presenting the same signal is idempotent (a peer may present it every session)", () => {
      store.putReceivedSignal({ agentId: alice, contactPubkey: PEER, verifiedAt: 1, verdict: "active", ...envelope() });
      store.putReceivedSignal({ agentId: alice, contactPubkey: PEER, verifiedAt: 2, verdict: "active", ...envelope() });
      const got = store.listReceived({ agentId: alice, contactPubkey: PEER });
      expect(got).toHaveLength(1);
      // verified_at is re-stamped: it records when WE last re-verified, and freshness is re-checked
      // on use (M10-D4) — a stale verified_at would be worse than useless, it would look fresh.
      expect(got[0].verifiedAt).toBe(2);
    });
  });

  describe("delivery — the holder re-verifies the hash before storing (M10-D4)", () => {
    // A composed envelope + its true hash, built with the SAME protocol-types the directory uses.
    function deliverable(over: Partial<import("@cello-protocol/protocol-types").TrustSignalEnvelope> = {}) {
      const env = {
        subject_kind: "account" as const, subject: "acct-x", issuer_kind: "portal" as const,
        issuer_pubkey: "aabb", type: "phone", schema_version: 1, payload: new Uint8Array([1, 2, 3]),
        issued_at: 1_768_000_000, expires_at: null, supersedes_hash: null, same_operator: false, ...over,
      };
      return { env, hash: Buffer.from(hashTrustSignalEnvelopeFn(env)).toString("hex") };
    }

    it("accepts a delivery whose bytes hash to the claim, storing it in the wallet", () => {
      const { env, hash } = deliverable();
      const res = store.deliverWalletSignal(env, hash);
      expect(res.stored).toBe(true);
      const got = store.getWalletSignal(hash);
      expect(got).not.toBeNull();
      expect(got!.type).toBe("phone");
      expect(new Uint8Array(got!.payload)).toEqual(new Uint8Array([1, 2, 3]));
    });

    // ── A DELIVERED SIGNAL MUST STILL BE PRESENTABLE ───────────────────────────────────────────────
    // Delivery verifies the hash and stores the FIELDS; presentation RE-ENCODES from those fields and
    // sends the stored hash beside the bytes. So the wallet round-trip has to be byte-exact, and
    // nothing tested that: delivery asserted "stored", presentation asserted "attached", and a field
    // lost in between made the RECIPIENT reject a valid signal one hop away.
    //
    // This is the assertion that closes the gap, and it is parameterized over same_operator because
    // that is the field the round-trip actually dropped — `deliverWalletSignal` did not pass it to
    // `putWalletSignal`, so a co-owned signal was delivered as true and stored as false. Only the
    // TRUE case fails; a suite that tested the default would have passed while the bug shipped.
    for (const sameOperator of [false, true]) {
      it(`round-trips every envelope field through the wallet — same_operator: ${sameOperator}`, () => {
        const { env, hash } = deliverable({ same_operator: sameOperator });
        expect(store.deliverWalletSignal(env, hash).stored).toBe(true);

        const row = store.getWalletSignal(hash);
        expect(row, "the delivered signal is in the wallet").not.toBeNull();

        // Re-encode from the STORED ROW exactly as the presenter does, and re-derive the hash. If any
        // field did not survive, this is not the notarized hash and the signal is unpresentable.
        const rehashed = Buffer.from(hashTrustSignalEnvelopeFn({
          subject_kind: row!.subjectKind,
          subject: row!.subject,
          issuer_kind: row!.issuerKind,
          issuer_pubkey: row!.issuerPubkey,
          type: row!.type,
          schema_version: row!.schemaVersion,
          payload: new Uint8Array(row!.payload),
          issued_at: row!.issuedAt,
          expires_at: row!.expiresAt,
          supersedes_hash: row!.supersedesHash === null ? null : new Uint8Array(Buffer.from(row!.supersedesHash, "hex")),
          same_operator: row!.sameOperator,
        })).toString("hex");
        expect(rehashed, "the wallet row must re-derive the notarized hash").toBe(hash);
        expect(row!.sameOperator, "the delivered flag, not the column default").toBe(sameOperator);
      });
    }

    it("REFUSES a delivery whose envelope does not hash to the claimed hash — never stored", () => {
      // The holder's own chokepoint: a tampered/corrupted delivery must not enter the wallet, or it
      // would present a signal the directory never notarized.
      const { env } = deliverable();
      expect(() => store.deliverWalletSignal(env, "f".repeat(64)))
        .toThrow(expect.objectContaining({ reason: "hash_mismatch" }));
      expect(store.getWalletSignal("f".repeat(64))).toBeNull();
      // ...and the tampered ENVELOPE (right claimed hash, wrong bytes) is also refused.
      const { hash } = deliverable();
      expect(() => store.deliverWalletSignal(deliverable({ type: "email" }).env, hash))
        .toThrow(expect.objectContaining({ reason: "hash_mismatch" }));
    });

    it("REFUSES a MALFORMED claimed hash with a DISTINCT reason (not conflated with byte-tamper)", () => {
      // A malformed hash string (wrong length, or uppercase from a version-skewed directory) is a
      // different cause than a byte-tamper, and must name itself so the operator looks at the right
      // subsystem. Both refuse-and-don't-store.
      const { env } = deliverable();
      expect(() => store.deliverWalletSignal(env, "not-hex"))
        .toThrow(expect.objectContaining({ reason: "claimed_hash_malformed" }));
      expect(() => store.deliverWalletSignal(env, "AABB".repeat(16))) // uppercase
        .toThrow(expect.objectContaining({ reason: "claimed_hash_malformed" }));
    });

    it("re-delivery is idempotent — stored:false the second time, no duplicate", () => {
      const { env, hash } = deliverable({ subject: "acct-redeliver" });
      expect(store.deliverWalletSignal(env, hash).stored).toBe(true);
      expect(store.deliverWalletSignal(env, hash).stored).toBe(false);
      expect(db.prepare("SELECT COUNT(*) AS n FROM wallet_trust_signals WHERE signal_hash = ?").get(hash)).toMatchObject({ n: 1 });
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
        const mgr2 = new SessionNodeManager({ securityGateway: new PassthroughGatewayClient(), factory: new StubNodeFactory(), logger: silent, dbPath: p2 });
        await mgr2.initialize();
        const fresh = mgr2.getDb();
        ensureTrustSignalSchema(fresh, silent); // applied again, exactly as an upgrade would

        // Compare the actual DDL, not just the column list. `PRAGMA table_info` reports names, types
        // and NOT NULL — it says NOTHING about the FOREIGN KEY, the PRIMARY KEY, or the indexes. A
        // migrated database that had lost the FK entirely would have sailed through a table_info
        // comparison, which is precisely the constraint this whole unit is built on.
        const ddl = (d: DaemonDatabase, t: string): string =>
          ((d.prepare("SELECT sql FROM sqlite_master WHERE name = ?").get(t) as { sql: string }).sql)
            .replace(/\s+/g, " ").trim();

        for (const t of ["wallet_trust_signals", "contact_trust_signals"]) {
          expect(ddl(fresh, t), t).toEqual(ddl(db, t));
        }
        // ...and the FK is actually in there, in both.
        expect(ddl(fresh, "contact_trust_signals")).toMatch(/FOREIGN KEY.*REFERENCES contacts/i);
        expect(ddl(db, "contact_trust_signals")).toMatch(/FOREIGN KEY.*REFERENCES contacts/i);
        await mgr2.stop?.();
      } finally {
        await rm(dir2, { recursive: true, force: true });
      }
    });

    it("a `contacts` TABLE REBUILD does not cascade-wipe the received signals (the armed landmine)", () => {
      // THE BUG THIS EXISTS TO PREVENT, and it is a data-loss bug, not a correctness one.
      //
      // With PRAGMA foreign_keys = ON (M10-D19), SQLite treats `DROP TABLE contacts` as an implicit
      // DELETE — which fires ON DELETE CASCADE and SILENTLY empties contact_trust_signals. The
      // rebuild's own row-count guards do not notice: they count `contacts`, not its children. And
      // `contacts` is one of the seven tables agent-id-migration.ts rebuilds with exactly this
      // create-copy-drop-rename recipe.
      //
      // Worse, the intuitive mitigation is a no-op: `PRAGMA foreign_keys = OFF` is SILENTLY IGNORED
      // inside a transaction, and every rebuild here runs inside one BEGIN...COMMIT. So a migration
      // that "disabled" foreign keys would look correct and cascade anyway.
      //
      // This test drives the real recipe through the real helper. If someone rebuilds `contacts`
      // without withForeignKeysOff, every received trust signal on every agent disappears at next
      // boot and nothing logs it — this is the only thing that will catch that.
      mgr.addContact("alice", HASH("e"), undefined, "accepted");
      store.putReceivedSignal({ agentId: alice, contactPubkey: HASH("e"), verifiedAt: 1, verdict: "active", ...envelope() });
      expect(store.listReceived({ agentId: alice, contactPubkey: HASH("e") })).toHaveLength(1);

      withForeignKeysOff(db, silent, () => {
        db.exec("BEGIN");
        db.exec("CREATE TABLE contacts_rebuild (agent_id TEXT NOT NULL, pubkey TEXT NOT NULL, added_at INTEGER NOT NULL, moniker TEXT, PRIMARY KEY (agent_id, pubkey))");
        db.exec("INSERT INTO contacts_rebuild (agent_id, pubkey, added_at, moniker) SELECT agent_id, pubkey, added_at, moniker FROM contacts");
        db.exec("DROP TABLE contacts");
        db.exec("ALTER TABLE contacts_rebuild RENAME TO contacts");
        db.exec("COMMIT");
      });

      // The signal SURVIVED the parent's rebuild.
      expect(store.listReceived({ agentId: alice, contactPubkey: HASH("e") })).toHaveLength(1);
      // ...and the FK still points at a real `contacts`, not at a renamed ghost.
      expect(db.prepare("PRAGMA foreign_key_check").all()).toEqual([]);
    });

    it("withForeignKeysOff REFUSES to run inside a transaction, where the pragma is a silent no-op", () => {
      // The failure is silent by nature, so the helper must verify the toggle took effect rather than
      // assume it. Called inside a BEGIN, `PRAGMA foreign_keys = OFF` is ignored and FKs stay live —
      // so it must refuse loudly rather than proceed and cascade.
      db.exec("BEGIN");
      try {
        expect(() => withForeignKeysOff(db, silent, () => undefined)).toThrow(/NO-OP inside a transaction|did not take effect/i);
      } finally {
        db.exec("ROLLBACK");
      }
    });

    it("the M8 scaffold table is GONE — MINT-INTERNAL-1 dropped it together with its replacement (M10-D18)", () => {
      // THE FORCING FUNCTION. This is DOD-MINT-INTERNAL-1's own test-clause: it was the mirror-image guard
      // that used to assert the scaffold still STOOD (to catch a PREMATURE drop across the four units
      // between STORE-CLIENT-1 and here). Now MINT-INTERNAL-1 has landed — the M8 delivery arm is
      // re-pointed onto TrustSignalStore.deliverWalletSignal (inbound-sessions), the writer + reader are
      // retired, and `ensureIdentitySchema` drops the table — so it must be ABSENT. Its absence proves the
      // drop travelled WITH the replacement, never before it, and the M8 `agent_id = null` defect is gone.
      const row = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='trust_signals'").get();
      expect(row, "M10-D18: the M8 `trust_signals` scaffold must be dropped once its M10 replacement is live").toBeUndefined();
    });

    it("DROPs a POPULATED M8 trust_signals table without error — the real client-migration case (review F1)", () => {
      // The fresh-DB assertion above proves a NEW DB has no table, but the load-bearing claim is that an
      // EXISTING operator DB still holding M8 rows migrates cleanly (client-side, unrecoverable if it
      // throws or corrupts). Reconstruct that DB — the M8 CREATE + a row — then re-run schema-ensure as a
      // daemon restart would, and assert the drop fires without throwing and touches nothing else.
      db.exec(
        `CREATE TABLE IF NOT EXISTS trust_signals (
           signal_hash TEXT PRIMARY KEY, agent_id TEXT, signal_kind TEXT NOT NULL,
           payload BLOB NOT NULL, received_at INTEGER NOT NULL )`,
      );
      db.prepare(
        `INSERT INTO trust_signals (signal_hash, agent_id, signal_kind, payload, received_at) VALUES (?, ?, ?, ?, ?)`,
      ).run("a".repeat(64), null, "webauthn", Buffer.from([1, 2, 3]), 1_700_000_000_000);
      expect(
        db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='trust_signals'").get(),
        "precondition: the populated M8 table exists",
      ).toBeDefined();
      const before = db.prepare("SELECT COUNT(*) AS n FROM agents").get() as { n: number };

      expect(() => ensureIdentitySchema(db)).not.toThrow();

      expect(
        db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='trust_signals'").get(),
        "the populated M8 table is dropped on schema-ensure",
      ).toBeUndefined();
      // The migration is surgical: it drops ONLY the scaffold, leaving every other table intact.
      expect(db.prepare("SELECT COUNT(*) AS n FROM agents").get()).toMatchObject({ n: before.n });
    });
  });

  describe("the same_operator migration verifies rather than assumes (review F4)", () => {
    it("is a silent no-op when the column already exists", () => {
      // Idempotence: ensureTrustSignalSchema runs on every daemon start, so the second call must not
      // throw. This is the case the bare catch was written for, and it still has to hold.
      expect(() => ensureTrustSignalSchema(db, silent)).not.toThrow();
      expect(() => ensureTrustSignalSchema(db, silent)).not.toThrow();
      for (const table of ["wallet_trust_signals", "contact_trust_signals"]) {
        const cols = (db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>).map((c) => c.name);
        expect(cols, `${table} has the column`).toContain("same_operator");
      }
    });

    it("THROWS when the ALTER fails and the column is genuinely absent", () => {
      // The failure the bare swallow hid. Any non-duplicate cause — SQLITE_BUSY from a second daemon
      // on the same DB, READONLY, FULL — used to be swallowed, after which putReceivedSignal throws
      // "no column named same_operator", is caught upstream as a WARN, and the daemon runs with
      // sessions forming normally while NO presented signal is ever stored.
      //
      // Simulated by making the ALTER fail on a table that has no such column: a stand-in table is
      // created, then `prepare` is stubbed so the ALTER path errors and the PRAGMA reports the truth.
      const probe = { ...db } as unknown as typeof db;
      const realPrepare = db.prepare.bind(db);
      let alterAttempted = false;
      (probe as unknown as { exec: (sql: string) => void }).exec = (sql: string) => {
        if (sql.includes("ADD COLUMN same_operator")) {
          alterAttempted = true;
          throw new Error("database is locked");
        }
        db.exec(sql);
      };
      (probe as unknown as { prepare: typeof realPrepare }).prepare = ((sql: string) => {
        if (sql.startsWith("PRAGMA table_info")) {
          // Report the column as absent — i.e. the ALTER really did not take effect.
          return { all: () => [{ name: "signal_hash" }] } as unknown as ReturnType<typeof realPrepare>;
        }
        return realPrepare(sql);
      }) as typeof realPrepare;

      expect(() => ensureTrustSignalSchema(probe, silent)).toThrow(/same_operator/);
      expect(alterAttempted, "the ALTER was actually attempted").toBe(true);
    });
  });

  // ── WHAT I SUBMITTED ABOUT OTHERS (M10B / DOD-END-SURFACE-1, DOD-END-WITHDRAW-1) ────────────────
  // The third table. The wallet holds signals ABOUT me and contact_trust_signals holds signals
  // PRESENTED to me; neither recorded what I SAID about someone else — so withdrawal had nothing to
  // NAME. The id is content-derived and therefore reproducible in principle, but only by re-composing
  // the exact original body, which the operator no longer has once it is sent.
  describe("issued submissions — the handle a withdrawal names", () => {
    const issued = (over: Partial<Parameters<typeof store.recordIssuedSubmission>[0]> = {}) => ({
      agentId: "agent-1", submissionId: HASH("d"), subjectPubkey: HASH("e"),
      op: "submit" as const, intakeKeyId: "intake-1", stored: true, ...over,
    });

    it("records a submission and lists it back for that agent", () => {
      store.recordIssuedSubmission(issued());
      const rows = store.listIssuedSubmissions("agent-1");
      expect(rows).toHaveLength(1);
      expect(rows[0].submissionId).toBe(HASH("d"));
      expect(rows[0].op).toBe("submit");
      expect(rows[0].stored).toBe(true);
      expect(rows[0].submittedAt).toBeGreaterThan(0);
    });

    it("NEVER stores the body — the operator's words about a third party stay sealed", () => {
      // The property this table's shape exists to guarantee. A `body` column would put in the clear,
      // on disk, the one thing the sealed-submission path is for. Asserted on the SCHEMA rather than
      // on a row, so adding the column later fails here even if nothing writes to it yet.
      const cols = (db.prepare("PRAGMA table_info(issued_submissions)").all() as Array<{ name: string }>)
        .map((c) => c.name);
      expect(cols).not.toContain("body");
      expect(cols).not.toContain("statement");
      expect(cols).not.toContain("text");
      expect(cols, "the handle itself must be there").toContain("submission_id");
    });

    it("a re-submit is the SAME row, and a later success updates `stored`", () => {
      // "Re-sending is safe" has to be true at this layer too, or the operator's own list grows a
      // duplicate every time they retry something the directory correctly deduped.
      store.recordIssuedSubmission(issued({ stored: false }));
      store.recordIssuedSubmission(issued({ stored: true }));
      const rows = store.listIssuedSubmissions("agent-1");
      expect(rows, "content-derived id → one row").toHaveLength(1);
      expect(rows[0].stored, "a retry that finally lands must not keep reporting the duplicate answer").toBe(true);
    });

    it("is scoped PER AGENT — two agents on one daemon do not see each other's submissions", () => {
      // Solo multi-agent is the first wedge, so two agents on one daemon is the ordinary case. These
      // are per-agent facts: what agent A said about someone is not agent B's to list or withdraw.
      store.recordIssuedSubmission(issued({ agentId: "agent-1" }));
      store.recordIssuedSubmission(issued({ agentId: "agent-2", submissionId: HASH("f") }));
      expect(store.listIssuedSubmissions("agent-1")).toHaveLength(1);
      expect(store.listIssuedSubmissions("agent-2")).toHaveLength(1);
      expect(store.listIssuedSubmissions("agent-1")[0].submissionId).toBe(HASH("d"));
    });

    it("the same id from a DIFFERENT agent is a separate row, not a conflict", () => {
      // The PK is (agent_id, submission_id). Keying on submission_id alone would let one agent's
      // submission silently overwrite another's when both endorse the same subject identically.
      store.recordIssuedSubmission(issued({ agentId: "agent-1" }));
      store.recordIssuedSubmission(issued({ agentId: "agent-2" }));
      expect(store.listIssuedSubmissions("agent-1")).toHaveLength(1);
      expect(store.listIssuedSubmissions("agent-2")).toHaveLength(1);
    });
  });
});
