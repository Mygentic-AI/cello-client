/**
 * RelayReceiptStore + verifyRelayAck — M8B DOD-RELAYSIG-1 (daemon port of the dead core/client receipt
 * logic). Proves: a genuine relay ACK signature verifies; a FORGED sequence (or timestamp / wrong key /
 * bad-length sig) is rejected; and the receipt store is IMMUTABLE (a re-attestation of a different sequence
 * for the same hash does NOT overwrite the first recorded receipt — SI-003).
 */
import { describe, it, expect, beforeEach } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { randomBytes } from "node:crypto";
import { generateKeypair, buildRelayAckTbs } from "@cello-protocol/crypto";
import { RelayReceiptStore, verifyRelayAck, type RelayReceipt } from "../relay-receipt-store.js";

const NOOP_LOGGER = { debug() {}, info() {}, warn() {}, error() {} } as never;

describe("verifyRelayAck (DOD-RELAYSIG-1) — a forged sequence is rejected", () => {
  it("accepts a genuine relay signature and rejects every tamper", async () => {
    const relay = generateKeypair();
    const relayPubkey = await relay.getPublicKey();
    const contentHash = new Uint8Array(randomBytes(32));
    const seq = 7;
    const ts = 1_719_800_000_000;
    const sig = await relay.sign(buildRelayAckTbs(contentHash, seq, ts));

    // Genuine ACK verifies.
    expect(verifyRelayAck(contentHash, seq, ts, sig, relayPubkey)).toBe(true);
    // FORGED sequence → different TBS → signature fails (the DoD's "a forged sequence is rejected").
    expect(verifyRelayAck(contentHash, seq + 1, ts, sig, relayPubkey)).toBe(false);
    // Tampered timestamp / content / wrong pubkey / bad-length sig all rejected.
    expect(verifyRelayAck(contentHash, seq, ts + 1, sig, relayPubkey)).toBe(false);
    expect(verifyRelayAck(new Uint8Array(randomBytes(32)), seq, ts, sig, relayPubkey)).toBe(false);
    const otherPubkey = await generateKeypair().getPublicKey();
    expect(verifyRelayAck(contentHash, seq, ts, sig, otherPubkey)).toBe(false);
    expect(verifyRelayAck(contentHash, seq, ts, new Uint8Array(63), relayPubkey)).toBe(false);
  });
});

describe("RelayReceiptStore (DOD-RELAYSIG-1) — durable + immutable", () => {
  let db: DatabaseSync;
  beforeEach(() => {
    db = new DatabaseSync(":memory:");
  });

  const agent = "aa".repeat(32);
  const mk = (hashHex: string, seq: number, sessionIdHex: string | null): RelayReceipt => ({
    hashHex,
    agentPubkeyHex: agent,
    sessionIdHex,
    relayId: "dd".repeat(32),
    relayPubkeyHex: "dd".repeat(32),
    sequenceNumber: seq,
    timestamp: seq * 10,
    signatureHex: "ee".repeat(64),
  });

  it("stores a receipt and is IMMUTABLE — a second ACK for the same hash does not overwrite", () => {
    const store = new RelayReceiptStore(db, NOOP_LOGGER);
    const hashHex = "bb".repeat(32);
    expect(store.store(mk(hashHex, 5, "cc".repeat(16)), 1000)).toBe(true);
    // A relay re-attesting a DIFFERENT sequence for the same hash must be ignored.
    const reattest: RelayReceipt = { ...mk(hashHex, 99, "cc".repeat(16)), signatureHex: "ff".repeat(64) };
    expect(store.store(reattest, 2000)).toBe(false);
    const got = store.get(hashHex, agent);
    expect(got?.sequenceNumber).toBe(5); // the FIRST receipt survives
    expect(got?.signatureHex).toBe("ee".repeat(64));
  });

  it("getAll returns an agent's receipts (sequence DESC), scoped by session when asked", () => {
    const store = new RelayReceiptStore(db, NOOP_LOGGER);
    const sess = "cc".repeat(16);
    const other = "ab".repeat(16);
    store.store(mk("11".repeat(32), 1, sess), 1);
    store.store(mk("22".repeat(32), 3, sess), 1);
    store.store(mk("33".repeat(32), 2, other), 1);
    expect(store.getAll(agent).map((r) => r.sequenceNumber)).toEqual([3, 2, 1]);
    expect(store.getAll(agent, sess).map((r) => r.sequenceNumber)).toEqual([3, 1]);
  });
});
