/**
 * DOD-VERIFY-1 — recipient verifies presented trust signals.
 *
 * The inbound path decodes the blob, re-derives the hash, compares it to the claimed hash,
 * and stores the verified signal in contact_trust_signals. Tampered or non-canonical blobs
 * are rejected (logged, never stored). The directory's pass-through is trusted for initial
 * freshness (it JUST checked moments ago); TTL re-check on use is a separate concern.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { openTestDb } from "./helpers/encrypted-db.js";
import { seedAgents } from "./helpers/seed-agents.js";
import { SessionNodeManager, type ISessionNodeFactory, type SessionNodeConfig } from "../session-node-manager.js";
import { TrustSignalStore, ensureTrustSignalSchema } from "../trust-signal-store.js";
import {
  encodeTrustSignalEnvelope,
  hashTrustSignalEnvelope,
  decodeTrustSignalEnvelope,
  verifyTrustSignalHash,
  type TrustSignalEnvelope,
} from "@cello-protocol/protocol-types";
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

function makeEnvelope(over: Partial<TrustSignalEnvelope> = {}): TrustSignalEnvelope {
  return {
    subject_kind: "agent",
    subject: "agent-1",
    issuer_kind: "portal",
    issuer_pubkey: "aabb",
    type: "phone",
    schema_version: 1,
    payload: new Uint8Array([1, 2, 3]),
    issued_at: 1_768_000_000,
    expires_at: null,
    supersedes_hash: null,
    ...over,
  };
}

describe("DOD-VERIFY-1 — recipient signal verification", () => {
  let tempDir: string;
  let mgr: SessionNodeManager;
  let db: DaemonDatabase;
  let store: TrustSignalStore;
  let aliceId: string;

  const CONTACT_PUBKEY = "ee".repeat(32);

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "dod-verify-1-"));
    const dbPath = join(tempDir, "sessions.db");
    const seed = openTestDb(dbPath);
    const ids = await seedAgents(seed, ["alice"]);
    aliceId = ids.get("alice")!;
    seed.close();
    mgr = new SessionNodeManager({ factory: new StubNodeFactory(), logger: silent, dbPath });
    await mgr.initialize();
    db = mgr.getDb();
    store = new TrustSignalStore(db, silent);
    mgr.addContact("alice", CONTACT_PUBKEY, null, "signal_presentation");
  });

  afterEach(async () => {
    await mgr.stop?.();
    await rm(tempDir, { recursive: true, force: true });
  });

  it("a valid signal (correct hash + canonical blob) is stored with verdict=active", () => {
    const env = makeEnvelope();
    const blob = encodeTrustSignalEnvelope(env);
    const hashBytes = hashTrustSignalEnvelope(env);
    const hashHex = Buffer.from(hashBytes).toString("hex");

    // Simulate what the inbound path does: decode, verify hash, store
    const decoded = decodeTrustSignalEnvelope(blob);
    expect(verifyTrustSignalHash(decoded, hashBytes)).toBe(true);

    store.putReceivedSignal({
      agentId: aliceId,
      contactPubkey: CONTACT_PUBKEY,
      signalHash: hashHex,
      subjectKind: decoded.subject_kind,
      subject: decoded.subject,
      issuerKind: decoded.issuer_kind,
      issuerPubkey: decoded.issuer_pubkey,
      type: decoded.type,
      schemaVersion: decoded.schema_version,
      payload: decoded.payload,
      issuedAt: decoded.issued_at,
      expiresAt: decoded.expires_at,
      supersedesHash: decoded.supersedes_hash === null ? null : Buffer.from(decoded.supersedes_hash).toString("hex"),
      verifiedAt: 1_768_000_100,
      verdict: "active",
    });

    const rows = store.listReceived({ agentId: aliceId, contactPubkey: CONTACT_PUBKEY });
    expect(rows).toHaveLength(1);
    expect(rows[0].signalHash).toBe(hashHex);
    expect(rows[0].verdict).toBe("active");
    expect(rows[0].verifiedAt).toBe(1_768_000_100);
    expect(rows[0].type).toBe("phone");
  });

  it("a tampered blob (hash mismatch) is rejected — verifyTrustSignalHash returns false", () => {
    const env = makeEnvelope();
    const blob = encodeTrustSignalEnvelope(env);
    const wrongHash = new Uint8Array(32).fill(0xff);

    const decoded = decodeTrustSignalEnvelope(blob);
    expect(verifyTrustSignalHash(decoded, wrongHash)).toBe(false);
  });

  it("a non-canonical blob throws on decode — never silently accepted", () => {
    // A truncated/garbage blob must throw, not return a partial
    const garbage = new Uint8Array([0x83, 0x01, 0x02]); // valid CBOR array of length 3, not 11
    expect(() => decodeTrustSignalEnvelope(garbage)).toThrow();
  });

  it("the full round-trip: encode → hash → decode → verify → store matches end-to-end", () => {
    const env = makeEnvelope({ type: "email", payload: new Uint8Array([4, 5, 6, 7]) });
    const blob = encodeTrustSignalEnvelope(env);
    const hashHex = Buffer.from(hashTrustSignalEnvelope(env)).toString("hex");

    // Recipient side: decode the blob they received
    const decoded = decodeTrustSignalEnvelope(blob);
    // Re-derive the hash from the decoded envelope
    const reHash = hashTrustSignalEnvelope(decoded);
    const reHashHex = Buffer.from(reHash).toString("hex");

    // Must match the original
    expect(reHashHex).toBe(hashHex);
    // Verify function agrees
    expect(verifyTrustSignalHash(decoded, new Uint8Array(Buffer.from(hashHex, "hex")))).toBe(true);
  });

  it("an envelope with a valid blob but wrong claimed hash is rejected", () => {
    const env = makeEnvelope();
    const blob = encodeTrustSignalEnvelope(env);
    const realHashHex = Buffer.from(hashTrustSignalEnvelope(env)).toString("hex");
    const wrongHashHex = "ff".repeat(32);

    const decoded = decodeTrustSignalEnvelope(blob);
    // The claimed hash doesn't match — this is how we catch a liar
    expect(verifyTrustSignalHash(decoded, new Uint8Array(Buffer.from(wrongHashHex, "hex")))).toBe(false);
    // The real hash DOES match
    expect(verifyTrustSignalHash(decoded, new Uint8Array(Buffer.from(realHashHex, "hex")))).toBe(true);
  });

  it("signals from an unknown type verify and store without any type-specific logic (INV-ZERO-BUMP)", () => {
    const env = makeEnvelope({ type: "future_unknown_type_xyz" });
    const blob = encodeTrustSignalEnvelope(env);
    const hashBytes = hashTrustSignalEnvelope(env);
    const hashHex = Buffer.from(hashBytes).toString("hex");

    const decoded = decodeTrustSignalEnvelope(blob);
    expect(verifyTrustSignalHash(decoded, hashBytes)).toBe(true);

    store.putReceivedSignal({
      agentId: aliceId,
      contactPubkey: CONTACT_PUBKEY,
      signalHash: hashHex,
      subjectKind: decoded.subject_kind,
      subject: decoded.subject,
      issuerKind: decoded.issuer_kind,
      issuerPubkey: decoded.issuer_pubkey,
      type: decoded.type,
      schemaVersion: decoded.schema_version,
      payload: decoded.payload,
      issuedAt: decoded.issued_at,
      expiresAt: decoded.expires_at,
      supersedesHash: null,
      verifiedAt: 1_768_000_200,
      verdict: "active",
    });

    const rows = store.listReceived({ agentId: aliceId, contactPubkey: CONTACT_PUBKEY });
    expect(rows).toHaveLength(1);
    expect(rows[0].type).toBe("future_unknown_type_xyz");
  });

  it("re-presentation of the same signal updates verifiedAt but never downgrades verdict", () => {
    const env = makeEnvelope();
    const blob = encodeTrustSignalEnvelope(env);
    const hashHex = Buffer.from(hashTrustSignalEnvelope(env)).toString("hex");
    const decoded = decodeTrustSignalEnvelope(blob);

    store.putReceivedSignal({
      agentId: aliceId,
      contactPubkey: CONTACT_PUBKEY,
      signalHash: hashHex,
      subjectKind: decoded.subject_kind,
      subject: decoded.subject,
      issuerKind: decoded.issuer_kind,
      issuerPubkey: decoded.issuer_pubkey,
      type: decoded.type,
      schemaVersion: decoded.schema_version,
      payload: decoded.payload,
      issuedAt: decoded.issued_at,
      expiresAt: decoded.expires_at,
      supersedesHash: null,
      verifiedAt: 100,
      verdict: "revoked",
    });

    // Re-present claiming active — must NOT overwrite the revoked verdict
    store.putReceivedSignal({
      agentId: aliceId,
      contactPubkey: CONTACT_PUBKEY,
      signalHash: hashHex,
      subjectKind: decoded.subject_kind,
      subject: decoded.subject,
      issuerKind: decoded.issuer_kind,
      issuerPubkey: decoded.issuer_pubkey,
      type: decoded.type,
      schemaVersion: decoded.schema_version,
      payload: decoded.payload,
      issuedAt: decoded.issued_at,
      expiresAt: decoded.expires_at,
      supersedesHash: null,
      verifiedAt: 200,
      verdict: "active",
    });

    const rows = store.listReceived({ agentId: aliceId, contactPubkey: CONTACT_PUBKEY });
    expect(rows).toHaveLength(1);
    expect(rows[0].verdict).toBe("revoked"); // never downgraded
    expect(rows[0].verifiedAt).toBe(200); // timestamp updated
  });
});
