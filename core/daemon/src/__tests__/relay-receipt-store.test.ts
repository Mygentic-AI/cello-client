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
