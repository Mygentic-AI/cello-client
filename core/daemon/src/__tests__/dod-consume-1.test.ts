/**
 * DOD-CONSUME-1 — verified signals reach the LLM as the JSON projection.
 *
 * 008-POLICY Part A: the projection is `trust_badges` only, one per signal presented this session:
 *   - portal → `verified: true`, summary from the payload's own short line
 *   - agent  → `verified: false`, summary names the author, never quotes the claim
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { openTestDb } from "./helpers/encrypted-db.js";
import { seedAgents } from "./helpers/seed-agents.js";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { SessionNodeManager, type ISessionNodeFactory, type SessionNodeConfig } from "../session-node-manager.js";
import { TrustSignalStore } from "../trust-signal-store.js";
import { evaluateSignalPolicy } from "../signal-requirement-policy.js";
import { encodeCbor, hashTrustSignalEnvelope } from "@cello-protocol/protocol-types";
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

const CONTACT_PUBKEY = "ee".repeat(32);

describe("DOD-CONSUME-1 — trust signal projection to LLM", () => {
  let tempDir: string;
  let mgr: SessionNodeManager;
  let db: DaemonDatabase;
  let store: TrustSignalStore;
  let aliceId: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "dod-consume-1-"));
    const dbPath = join(tempDir, "sessions.db");
    const seed = openTestDb(dbPath);
    const ids = await seedAgents(seed, ["alice"]);
    aliceId = ids.get("alice")!;
    seed.close();
    mgr = new SessionNodeManager({ securityGateway: new PassthroughGatewayClient(), factory: new StubNodeFactory(), logger: silent, dbPath });
    await mgr.initialize();
    db = mgr.getDb();
    store = new TrustSignalStore(db, silent);
    mgr.addContact("alice", CONTACT_PUBKEY, null, "accepted");
  });

  afterEach(async () => {
    await mgr.stop?.();
    await rm(tempDir, { recursive: true, force: true });
  });

  function storeSignal(type: string, issuerKind: "portal" | "agent", claim: unknown, sameOperator = false) {
    const payload = encodeCbor(claim) as Uint8Array;
    const env = {
      subject_kind: "agent" as const,
      subject: "agent-1",
      issuer_kind: issuerKind,
      issuer_pubkey: "aabb",
      type,
      schema_version: 1,
      payload,
      issued_at: 1_768_000_000,
      expires_at: null,
      supersedes_hash: null,
      same_operator: sameOperator,
    };
    const hashHex = Buffer.from(hashTrustSignalEnvelope(env)).toString("hex");
    store.putReceivedSignal({
      agentId: aliceId,
      contactPubkey: CONTACT_PUBKEY,
      signalHash: hashHex,
      subjectKind: "agent",
      subject: "agent-1",
      issuerKind: issuerKind,
      issuerPubkey: "aabb",
      type,
      schemaVersion: 1,
      payload,
      issuedAt: 1_768_000_000,
      expiresAt: null,
      supersedesHash: null,
      sameOperator,
      verifiedAt: 1_768_000_100_000,
      verdict: "active",
    });
    return hashHex;
  }

  it("projects a portal-attested signal as a verified, independent badge (clause 1)", () => {
    const h = storeSignal("phone", "portal", { claim: "has verified phone", phone_stub: "abc123" });
    const out = projectTrustSignals(store.listReceived({ agentId: aliceId, contactPubkey: CONTACT_PUBKEY }), new Set([h]))!;
    expect(out.trust_badges).toEqual([{ type: "phone", summary: "has verified phone", independent: true, verified: true }]);
  });

  it("projects an agent-issued signal as verified:false with its author in the summary (clause 1)", () => {
    const h = storeSignal("endorsement", "agent", { endorsement: "Bob vouches for Alice" });
    const [b] = projectTrustSignals(store.listReceived({ agentId: aliceId, contactPubkey: CONTACT_PUBKEY }), new Set([h]))!.trust_badges;
    expect(b.verified).toBe(false);
    expect(b.summary).toBe("by aabb");
    // The peer's own words never become the summary — the badge is a pointer, not a quotation.
    expect(b.summary).not.toMatch(/vouches/);
  });

  it("the payload's key set is trust_badges ONLY — the old verbose fields are gone (clause 1)", () => {
    const h = storeSignal("endorsement", "agent", { statement: "x" }, true);
    const out = projectTrustSignals(store.listReceived({ agentId: aliceId, contactPubkey: CONTACT_PUBKEY }), new Set([h]))!;
    expect(Object.keys(out)).toEqual(["trust_badges"]);
    expect(Object.keys(out.trust_badges[0]).sort()).toEqual(["independent", "summary", "type", "verified"]);
    const json = JSON.stringify(out);
    for (const gone of ["claim", "framing", "same_operator_framing", "directory_attestation", "currency_checked_this_session"]) {
      expect(json).not.toContain(gone);
    }
    expect(out.trust_badges[0].independent, "same operator → not independent").toBe(false);
  });

  it("carried-over signals are absent — only those presented THIS session are badged (clause 1)", () => {
    const fresh = storeSignal("phone", "portal", { claim: "has verified phone" });
    storeSignal("email", "portal", { claim: "has verified email" });
    const out = projectTrustSignals(store.listReceived({ agentId: aliceId, contactPubkey: CONTACT_PUBKEY }), new Set([fresh]))!;
    expect(out.trust_badges.map((b) => b.type)).toEqual(["phone"]);
    expect(projectTrustSignals(store.listReceived({ agentId: aliceId, contactPubkey: CONTACT_PUBKEY }), new Set())).toBeUndefined();
  });

  it("a malformed payload still yields a badge (never blocks the projection)", () => {
    const badPayload = new Uint8Array([0xff, 0xfe, 0xfd]);
    store.putReceivedSignal({
      agentId: aliceId, contactPubkey: CONTACT_PUBKEY, signalHash: "12".repeat(32), subjectKind: "agent",
      subject: "agent-1", issuerKind: "portal", issuerPubkey: "aabb", type: "broken", schemaVersion: 1,
      payload: badPayload, issuedAt: 1_768_000_000, expiresAt: null, supersedesHash: null,
      verifiedAt: 1_768_000_100_000, verdict: "active",
    });
    const out = projectTrustSignals(store.listReceived({ agentId: aliceId, contactPubkey: CONTACT_PUBKEY }), new Set(["12".repeat(32)]))!;
    expect(out.trust_badges).toEqual([{ type: "broken", summary: "verified", independent: true, verified: true }]);
  });

  // ── DOD-END-COUNT-1 THROUGH THE REAL STORE PATH ─────────────────────────────────────────────────
  // The predicate tests build `ReceivedSignalRow` objects by hand, so they prove the FILTER works and
  // nothing about whether a signal that actually ARRIVED ever carries the flag. It did not:
  // `putReceivedSignal` omitted `same_operator` from its INSERT, the column took its 0 default, and
  // every received endorsement read as not-co-owned. The ten-agents-under-one-operator defence was
  // inert in production while its unit tests were green — a store-level default is exactly the kind of
  // gap hand-built rows cannot see.
  //
  // So these go through putReceivedSignal → listReceived → evaluateSignalPolicy, the real chain.
  describe("the co-ownership flag survives the store, so the count exclusion is not inert", () => {
    it("a co-owned endorsement that ARRIVED through the store is excluded from min_count", () => {
      storeSignal("endorsement", "agent", { statement: "my other agent is great" }, true);
      const received = store.listReceived({ agentId: aliceId, contactPubkey: CONTACT_PUBKEY });
      expect(received, "it is stored and active").toHaveLength(1);
      expect(received[0].sameOperator, "READ BACK as co-owned — this is what the INSERT was dropping").toBe(true);

      const verdict = evaluateSignalPolicy({ min_count: 1 }, received);
      expect(verdict.pass, "one co-owned endorsement must not clear a floor of one").toBe(false);
      expect(verdict.actual_count, "the COUNTABLE total, which is zero").toBe(0);
      expect(verdict.excluded_same_operator, "and the operator is told why").toBe(1);
    });

    it("a third-party endorsement that arrived the same way DOES clear it", () => {
      // The negative control. Without it, a store that returned `sameOperator: true` for everything
      // would satisfy the test above and break every genuine endorsement.
      storeSignal("endorsement", "agent", { statement: "she shipped it clean" }, false);
      const received = store.listReceived({ agentId: aliceId, contactPubkey: CONTACT_PUBKEY });
      expect(received[0].sameOperator).toBe(false);
      expect(evaluateSignalPolicy({ min_count: 1 }, received).pass).toBe(true);
    });

    it("ten co-owned endorsements do not clear a floor of three — the farming shape, end to end", () => {
      for (let i = 0; i < 10; i++) {
        storeSignal("endorsement", "agent", { statement: `agent ${i} vouches` }, true);
      }
      const received = store.listReceived({ agentId: aliceId, contactPubkey: CONTACT_PUBKEY });
      expect(received, "all ten are stored — they are genuine, notarized signals").toHaveLength(10);
      const verdict = evaluateSignalPolicy({ min_count: 3 }, received);
      expect(verdict.pass, "ten of one operator's own agents is not three endorsements").toBe(false);
      expect(verdict.excluded_same_operator).toBe(10);
    });

  });


});

import { projectTrustSignals } from "../inbound-sessions.js";
