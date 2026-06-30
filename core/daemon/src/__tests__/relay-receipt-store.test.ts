/**
 * RelayReceiptStore + verifyRelayAck + evaluateRelayAck — M8B DOD-RELAYSIG-1 (daemon port).
 *
 * Proves: a genuine relay ACK verifies; a FORGED sequence (or timestamp / wrong key / bad-length sig) is
 * rejected by the predicate AND by evaluateRelayAck (the verify-gates-store DECISION — a forged ACK yields
 * `invalid_signature`, never a stored receipt); the store is keyed on the attestation POSITION
 * (agent, session, sequence) so repeated content is NOT dropped, and is IMMUTABLE at a position (a relay
 * cannot rewrite the hash it already attested at a (session, sequence)).
 */
import { describe, it, expect, beforeEach } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { randomBytes } from "node:crypto";
import { generateKeypair, buildRelayAckTbs } from "@cello-protocol/crypto";
import { RelayReceiptStore, verifyRelayAck, evaluateRelayAck, type RelayReceipt } from "../relay-receipt-store.js";

const NOOP_LOGGER = { debug() {}, info() {}, warn() {}, error() {} } as never;

describe("verifyRelayAck (DOD-RELAYSIG-1) — a forged sequence is rejected", () => {
  it("accepts a genuine relay signature and rejects every tamper", async () => {
    const relay = generateKeypair();
    const relayPubkey = await relay.getPublicKey();
    const contentHash = new Uint8Array(randomBytes(32));
    const seq = 7;
    const ts = 1_719_800_000_000;
    const sig = await relay.sign(buildRelayAckTbs(contentHash, seq, ts));

    expect(verifyRelayAck(contentHash, seq, ts, sig, relayPubkey)).toBe(true);
    expect(verifyRelayAck(contentHash, seq + 1, ts, sig, relayPubkey)).toBe(false);
    expect(verifyRelayAck(contentHash, seq, ts + 1, sig, relayPubkey)).toBe(false);
    expect(verifyRelayAck(new Uint8Array(randomBytes(32)), seq, ts, sig, relayPubkey)).toBe(false);
    const otherPubkey = await generateKeypair().getPublicKey();
    expect(verifyRelayAck(contentHash, seq, ts, sig, otherPubkey)).toBe(false);
    expect(verifyRelayAck(contentHash, seq, ts, new Uint8Array(63), relayPubkey)).toBe(false);
  });
});

describe("evaluateRelayAck (DOD-RELAYSIG-1) — the verify-gates-store DECISION", () => {
  it("a genuine ACK yields a storable receipt; a FORGED sequence yields invalid_signature (never store)", async () => {
    const relay = generateKeypair();
    const relayId = Buffer.from(await relay.getPublicKey()).toString("hex");
    const contentHash = new Uint8Array(randomBytes(32));
    const ts = 1_719_800_000_000;
    const seq = 7;
    const goodSig = await relay.sign(buildRelayAckTbs(contentHash, seq, ts));
    const base = { contentHash, sessionIdHex: "cc".repeat(16), agentPubkeyHex: "aa".repeat(32), timestamp: ts };

    // Genuine ACK → store, with the right receipt fields.
    const good = evaluateRelayAck({ ...base, relayId, relaySignature: goodSig, sequenceNumber: seq });
    expect(good.kind).toBe("store");
    if (good.kind === "store") {
      expect(good.receipt.sequenceNumber).toBe(seq);
      expect(good.receipt.relayId).toBe(relayId);
      expect(good.receipt.hashHex).toBe(Buffer.from(contentHash).toString("hex"));
    }

    // FORGED sequence: the signature is over seq=7 but the frame claims seq=8 → must NOT store.
    expect(evaluateRelayAck({ ...base, relayId, relaySignature: goodSig, sequenceNumber: seq + 1 }).kind).toBe("invalid_signature");
    // Random (non-binding) signature → must NOT store.
    expect(evaluateRelayAck({ ...base, relayId, relaySignature: new Uint8Array(randomBytes(64)), sequenceNumber: seq }).kind).toBe("invalid_signature");
    // Unsigned ACK (no signature) → unsigned, not stored, not rejected.
    expect(evaluateRelayAck({ ...base, relayId, relaySignature: undefined, timestamp: undefined, sequenceNumber: seq }).kind).toBe("unsigned");
    // Malformed relay_id → bad_relay_id.
    expect(evaluateRelayAck({ ...base, relayId: "xyz", relaySignature: goodSig, sequenceNumber: seq }).kind).toBe("bad_relay_id");
  });
});

describe("RelayReceiptStore (DOD-RELAYSIG-1) — durable, positioned, immutable", () => {
  let db: DatabaseSync;
  beforeEach(() => {
    db = new DatabaseSync(":memory:");
  });

  const agent = "aa".repeat(32);
  const mk = (sessionIdHex: string, seq: number, hashHex: string): RelayReceipt => ({
    hashHex,
    agentPubkeyHex: agent,
    sessionIdHex,
    relayId: "dd".repeat(32),
    relayPubkeyHex: "dd".repeat(32),
    sequenceNumber: seq,
    timestamp: seq * 10,
    signatureHex: "ee".repeat(64),
  });

  it("does NOT drop repeated content — the SAME hash at DIFFERENT positions is stored (code-review HIGH)", () => {
    const store = new RelayReceiptStore(db, NOOP_LOGGER);
    const sess = "cc".repeat(16);
    const sameHash = "bb".repeat(32);
    // Identical plaintext ("ok") → identical content hash, but different relay sequences — both legit.
    expect(store.store(mk(sess, 5, sameHash), 1)).toBe(true);
    expect(store.store(mk(sess, 8, sameHash), 1)).toBe(true); // same hash, different position → STORED
    const other = "ab".repeat(16);
    expect(store.store(mk(other, 2, sameHash), 1)).toBe(true); // same hash, different session → STORED
    expect(store.getAll(agent).length).toBe(3);
  });

  it("is IMMUTABLE at a position — a relay re-attesting a DIFFERENT hash at the same (session, seq) is ignored", () => {
    const store = new RelayReceiptStore(db, NOOP_LOGGER);
    const sess = "cc".repeat(16);
    expect(store.store(mk(sess, 5, "11".repeat(32)), 1)).toBe(true);
    // Equivocation: same position, DIFFERENT hash → ignored, the first verified receipt stands.
    expect(store.store(mk(sess, 5, "22".repeat(32)), 2)).toBe(false);
    expect(store.get(agent, sess, 5)?.hashHex).toBe("11".repeat(32));
  });

  it("getAll returns an agent's receipts in canonical sequence order, scoped by session when asked", () => {
    const store = new RelayReceiptStore(db, NOOP_LOGGER);
    const sess = "cc".repeat(16);
    const other = "ab".repeat(16);
    store.store(mk(sess, 3, "33".repeat(32)), 1);
    store.store(mk(sess, 1, "11".repeat(32)), 1);
    store.store(mk(other, 2, "22".repeat(32)), 1);
    expect(store.getAll(agent, sess).map((r) => r.sequenceNumber)).toEqual([1, 3]);
    expect(store.getAll(agent).length).toBe(3);
  });
});

describe("RelayReceiptStore — Option B seal carry (DOD-OPTIONB-SEAL-1)", () => {
  // For a UNILATERAL seal under Option B the client carries the per-leaf Structure2 + Structure1 (so the
  // directory rebuilds the tree OFFLINE) alongside the relay receipt (so the directory verifies the relay
  // witnessed each leaf at its sequence). The store persists those leaf bytes at the same attestation
  // position and getSealLeaves returns the complete ordered chain for a session.
  const agent = "aa".repeat(32);
  const sess = "cc".repeat(16);
  const mkLeaf = (seq: number, hashHex: string, s2: Uint8Array, s1: Uint8Array, kind: number): RelayReceipt => ({
    hashHex,
    agentPubkeyHex: agent,
    sessionIdHex: sess,
    relayId: "dd".repeat(32),
    relayPubkeyHex: "dd".repeat(32),
    sequenceNumber: seq,
    timestamp: seq * 10,
    signatureHex: "ee".repeat(64),
    structure2Cbor: s2,
    structure1Cbor: s1,
    leafKind: kind,
  });

  it("persists + returns per-leaf structure2/structure1/kind ordered by sequence (the unilateral carry)", () => {
    const db = new DatabaseSync(":memory:");
    const store = new RelayReceiptStore(db, NOOP_LOGGER);
    store.store(mkLeaf(2, "22".repeat(32), new Uint8Array([0xa2]), new Uint8Array([0xb2]), 0), 1);
    store.store(mkLeaf(1, "11".repeat(32), new Uint8Array([0xa1]), new Uint8Array([0xb1]), 0), 1);
    store.store(mkLeaf(3, "33".repeat(32), new Uint8Array([0xa3]), new Uint8Array([0xb3]), 2), 1); // ctrl SEAL leaf

    const leaves = store.getSealLeaves(agent, sess);
    expect(leaves.map((l) => l.sequenceNumber)).toEqual([1, 2, 3]);
    expect(leaves[0].leafKind).toBe(0);
    expect(leaves[2].leafKind).toBe(2);
    expect(Buffer.from(leaves[0].structure2Cbor).equals(Buffer.from([0xa1]))).toBe(true);
    expect(Buffer.from(leaves[1].structure1Cbor).equals(Buffer.from([0xb2]))).toBe(true);
    // The relay receipt fields ride along for the directory's per-leaf witness verification.
    expect(leaves[2].hashHex).toBe("33".repeat(32));
    expect(leaves[2].signatureHex).toBe("ee".repeat(64));
    expect(leaves[2].timestamp).toBe(30);
  });

  it("getSealLeaves omits leaves whose carry bytes were never recorded (pre-M8B / receipt-only rows)", () => {
    const db = new DatabaseSync(":memory:");
    const store = new RelayReceiptStore(db, NOOP_LOGGER);
    // A receipt-only row (no structure2/structure1) — e.g. a pre-OPTIONB-SEAL receipt.
    store.store({
      hashHex: "11".repeat(32), agentPubkeyHex: agent, sessionIdHex: sess, relayId: "dd".repeat(32),
      relayPubkeyHex: "dd".repeat(32), sequenceNumber: 1, timestamp: 10, signatureHex: "ee".repeat(64),
    }, 1);
    store.store(mkLeaf(2, "22".repeat(32), new Uint8Array([0xa2]), new Uint8Array([0xb2]), 0), 1);
    // getSealLeaves returns only leaves that have the full carry bytes (the chain it can rebuild offline).
    expect(store.getSealLeaves(agent, sess).map((l) => l.sequenceNumber)).toEqual([2]);
    // getAll still returns ALL receipts (the witness query is unchanged).
    expect(store.getAll(agent, sess).length).toBe(2);
  });
});
