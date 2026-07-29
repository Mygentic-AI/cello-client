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
import { PassthroughGatewayClient } from "@cello-protocol/gateway";
import { SessionNodeManager, type ISessionNodeFactory, type SessionNodeConfig } from "../session-node-manager.js";
import { TrustSignalStore } from "../trust-signal-store.js";
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

  function storeSignal(type: string, issuerKind: "portal" | "agent", claim: unknown) {
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
});

// Test the PRODUCTION projection function, not a local mirror.
import { projectTrustSignals } from "../inbound-sessions.js";
import type { ReceivedSignalRow } from "../trust-signal-store.js";

function projectSignals(received: ReceivedSignalRow[]): Array<{ type: string; issuer: string; signal_hash: string; directory_verified: boolean; claim: unknown }> {
  const result = projectTrustSignals(received);
  return result?.trust_signals ?? [];
}
