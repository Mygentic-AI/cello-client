/**
 * DOD-CONSUME-1 — verified signals reach the LLM as the JSON projection.
 *
 * The projection is framed by issuer_kind:
 *   - portal → "platform-verified" (platform attested this fact)
 *   - agent  → "peer-claimed" (counterparty claims this; not independently verified)
 *
 * Unknown types flow through with generic framing (INV-TYPE-CARRY).
 * The self-describing payload is decoded from CBOR and included as `claim`.
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

  it("projects portal-attested signals as 'platform-verified'", () => {
    storeSignal("phone", "portal", { claim: "has verified phone", phone_stub: "abc123" });

    const received = store.listReceived({ agentId: aliceId, contactPubkey: CONTACT_PUBKEY });
    expect(received).toHaveLength(1);
    expect(received[0].issuerKind).toBe("portal");
    // The projection the LLM sees: issuer framing is "platform-verified"
    const projected = projectSignals(received);
    expect(projected[0].issuer).toBe("platform-verified");
    expect(projected[0].type).toBe("phone");
    expect(projected[0].claim).toEqual({ claim: "has verified phone", phone_stub: "abc123" });
  });

  it("projects agent-issued signals as 'peer-claimed'", () => {
    storeSignal("endorsement", "agent", { endorsement: "Bob vouches for Alice" });

    const received = store.listReceived({ agentId: aliceId, contactPubkey: CONTACT_PUBKEY });
    const projected = projectSignals(received);
    expect(projected[0].issuer).toBe("peer-claimed");
    expect(projected[0].type).toBe("endorsement");
  });

  it("unknown types flow through with generic framing (INV-TYPE-CARRY / INV-ZERO-BUMP)", () => {
    storeSignal("future_type_never_seen", "portal", { arbitrary: "data", nested: [1, 2, 3] });

    const received = store.listReceived({ agentId: aliceId, contactPubkey: CONTACT_PUBKEY });
    const projected = projectSignals(received);
    expect(projected[0].type).toBe("future_type_never_seen");
    expect(projected[0].issuer).toBe("platform-verified");
    expect(projected[0].claim).toEqual({ arbitrary: "data", nested: [1, 2, 3] });
  });

  it("only active-verdict signals are projected (revoked/superseded are excluded)", () => {
    storeSignal("phone", "portal", { claim: "phone" });
    // Store a second signal with revoked verdict
    const payload2 = encodeCbor({ claim: "revoked-thing" }) as Uint8Array;
    const env2 = {
      subject_kind: "agent" as const,
      subject: "agent-2",
      issuer_kind: "portal" as const,
      issuer_pubkey: "aabb",
      type: "email",
      schema_version: 1,
      payload: payload2,
      issued_at: 1_768_000_000,
      expires_at: null,
      supersedes_hash: null,
      same_operator: false,
    };
    const hash2 = Buffer.from(hashTrustSignalEnvelope(env2)).toString("hex");
    store.putReceivedSignal({
      agentId: aliceId,
      contactPubkey: CONTACT_PUBKEY,
      signalHash: hash2,
      subjectKind: "agent",
      subject: "agent-2",
      issuerKind: "portal",
      issuerPubkey: "aabb",
      type: "email",
      schemaVersion: 1,
      payload: payload2,
      issuedAt: 1_768_000_000,
      expiresAt: null,
      supersedesHash: null,
      verifiedAt: 1_768_000_100_000,
      verdict: "revoked",
    });

    const received = store.listReceived({ agentId: aliceId, contactPubkey: CONTACT_PUBKEY });
    const projected = projectSignals(received);
    // Only the active one
    expect(projected).toHaveLength(1);
    expect(projected[0].type).toBe("phone");
  });

  it("a malformed payload decodes as null (never blocks the projection)", () => {
    // Store a signal with invalid CBOR payload directly
    const badPayload = new Uint8Array([0xff, 0xfe, 0xfd]); // not valid CBOR
    const env = {
      subject_kind: "agent" as const,
      subject: "agent-1",
      issuer_kind: "portal" as const,
      issuer_pubkey: "aabb",
      type: "broken",
      schema_version: 1,
      payload: badPayload,
      issued_at: 1_768_000_000,
      expires_at: null,
      supersedes_hash: null,
      same_operator: false,
    };
    const hashHex = Buffer.from(hashTrustSignalEnvelope(env)).toString("hex");
    store.putReceivedSignal({
      agentId: aliceId,
      contactPubkey: CONTACT_PUBKEY,
      signalHash: hashHex,
      subjectKind: "agent",
      subject: "agent-1",
      issuerKind: "portal",
      issuerPubkey: "aabb",
      type: "broken",
      schemaVersion: 1,
      payload: badPayload,
      issuedAt: 1_768_000_000,
      expiresAt: null,
      supersedesHash: null,
      verifiedAt: 1_768_000_100_000,
      verdict: "active",
    });

    const received = store.listReceived({ agentId: aliceId, contactPubkey: CONTACT_PUBKEY });
    const projected = projectSignals(received);
    expect(projected).toHaveLength(1);
    expect(projected[0].claim).toBeNull();
    expect(projected[0].type).toBe("broken");
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

    it("the recipient's PROJECTION surfaces co-ownership with its own framing", () => {
      // DOD-END-JOURNEY-1 case (b) requires the recipient to SEE the fact, not merely have it
      // silently discounted. A consuming model cannot read the statement correctly without it: the
      // same sentence is a stranger's assessment or an operator's claim about their own fleet.
      storeSignal("endorsement", "agent", { statement: "her agent never drops a session" }, true);
      const projected = projectSignals(store.listReceived({ agentId: aliceId, contactPubkey: CONTACT_PUBKEY }));
      const sig = projected[0] as unknown as { same_operator?: boolean; same_operator_framing?: string };
      expect(sig.same_operator, "the flag reaches the LLM-facing JSON").toBe(true);
      expect(String(sig.same_operator_framing), "and says it does not count toward a minimum").toMatch(/does NOT count/i);
    });

    it("a third-party endorsement OMITS the flag entirely rather than sending false", () => {
      // Absent, not `false`: a field present on every signal teaches a reader nothing, and its
      // appearance is what carries the meaning.
      storeSignal("endorsement", "agent", { statement: "she shipped it clean" }, false);
      const projected = projectSignals(store.listReceived({ agentId: aliceId, contactPubkey: CONTACT_PUBKEY }));
      expect(Object.keys(projected[0])).not.toContain("same_operator");
    });
  });


  // ── THE ATTESTATION MUST DESCRIBE BOTH CHECKS, AND CONFLATE NEITHER ─────────────────────────────
  // Two parties check two different things: this daemon re-hashes the envelope (INTEGRITY), and the
  // DIRECTORY checks status against its ledger at session establishment (CURRENCY,
  // `checkPresentedSignals` → `signal_records_effective`). Arrival implies the second ran, because a
  // directory that cannot check forwards no signals at all.
  //
  // The point-in-time assertion is the load-bearing one. I once rewrote this string to claim currency
  // was NOT checked — having grepped only the daemon — and that was false. The correct nuance is
  // narrower and must not drift in either direction: checked at SETUP, not continuously.
  it("states both checks, and that currency is point-in-time at session setup", () => {
    storeSignal("phone", "portal", { claim: "has verified phone" });
    const out = projectTrustSignals(store.listReceived({ agentId: aliceId, contactPubkey: CONTACT_PUBKEY }))!;

    expect(out.directory_attestation, "the local integrity check").toMatch(/re-hashed its canonical CBOR/i);
    expect(out.directory_attestation, "the directory's currency check").toMatch(/notary ledger when this session was established/i);
    expect(out.directory_attestation, "and that non-active signals were stripped").toMatch(/stripped before it reached you/i);
    // NEITHER over- nor under-claiming: it must say point-in-time...
    expect(out.directory_attestation).toMatch(/point-in-time at session setup/i);
    // ...and must NOT claim the agent itself re-queried, which it never does.
    expect(out.directory_attestation, "the daemon does not re-query the ledger").not.toMatch(/this agent (has )?re-?quer/i);
    expect(out.directory_attestation, "never a claim about truth").toMatch(/never of truth/i);
    expect(out.currency_checked_at_session_start).toBe(true);
  });

});

// Test the PRODUCTION projection function, not a local mirror.
import { projectTrustSignals } from "../inbound-sessions.js";
import type { ReceivedSignalRow } from "../trust-signal-store.js";

function projectSignals(received: ReceivedSignalRow[]): Array<{ type: string; issuer: string; signal_hash: string; directory_verified: boolean; claim: unknown }> {
  const result = projectTrustSignals(received);
  return result?.trust_signals ?? [];
}

/**
 * M10B / `M10B-D13` — the framing SPLITS on issuer_kind, and the wrapper matters as much as the
 * payload.
 *
 * The projection previously wrapped every signal in one sentence — "each verified by the CELLO
 * directory… confirmed active" — with `directory_verified: true`, regardless of author. For a
 * portal-issued fact that is accurate. For an agent-issued endorsement it launders authority: the
 * directory checked that the HASH is notarized, and nothing about whether the claim is true.
 *
 * D13 states the trap precisely: the payload split alone does NOT satisfy INV-UNTRUSTED. A live
 * journey asserting only on fields nested inside `claim` would pass while a stranger's sentence
 * reached the model under CELLO's authority.
 */
describe("M10B-D13 — peer-claimed content is framed as peer-claimed", () => {
  const sig = (issuerKind: string, payload: Record<string, unknown>) => ({
    type: "endorsement",
    issuerKind,
    payload: encodeCbor(payload),
    verdict: "active",
    signalHash: "ab".repeat(32),
  });

  it("does NOT tell a model that peer-claimed content was verified by CELLO", () => {
    const out = projectTrustSignals([sig("agent", { claim: "x", statement: "Alice is great" })])!;
    // The attestation must not claim the directory verified the SIGNAL — only its provenance.
    expect(out.directory_attestation).not.toMatch(/each verified by the CELLO directory/i);
    expect(out.directory_attestation).toMatch(/provenance|not of truth/i);
    // And it must warn about the peer-claimed one specifically.
    expect(out.directory_attestation).toMatch(/peer-claimed/i);
  });

  it("marks a peer-claimed signal and tells the model how to treat it", () => {
    const [s] = projectTrustSignals([sig("agent", { statement: "Alice is great" })])!.trust_signals;
    expect(s.issuer).toBe("peer-claimed");
    expect(s.content_is_peer_claimed).toBe(true);
    expect(String(s.framing)).toMatch(/did NOT verify|does not vouch/i);
    expect(String(s.framing)).toMatch(/quote and attribute|never restate/i);
  });

  it("leaves PORTAL-issued facts framed as platform-verified — not 'warn about everything'", () => {
    // The counterpart. Without it, satisfying the above by flagging every signal would pass, and a
    // caveat that fires on the normal case teaches a model to ignore it.
    const [s] = projectTrustSignals([sig("portal", { claim: "verified phone" })])!.trust_signals;
    expect(s.issuer).toBe("platform-verified");
    expect(s.content_is_peer_claimed).toBe(false);
    expect(s.framing, "a portal fact needs no untrusted-content warning").toBeUndefined();
    // And with no peer-claimed signal present, the attestation carries no peer-claimed caveat.
    const out = projectTrustSignals([sig("portal", { claim: "verified phone" })])!;
    expect(out.directory_attestation).not.toMatch(/peer-claimed/i);
  });

  it("still reports the hash as notarized for both — that check IS real", () => {
    // `directory_verified` is hash-level and true either way; what differs is what it means about
    // the CONTENT. Collapsing the two would be the opposite error.
    expect(projectTrustSignals([sig("agent", {})])!.trust_signals[0].directory_verified).toBe(true);
    expect(projectTrustSignals([sig("portal", {})])!.trust_signals[0].directory_verified).toBe(true);
  });
});
