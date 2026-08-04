/**
 * SessionSealLeafStore — FED-OPTIONB-SEAL-001. The per-session leaf log a unilateral seal carries to the
 * directory (both parties' leaves; relay receipt only on own leaves). Ordered, immutable at a position.
 */
import { describe, it, expect } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { SessionSealLeafStore, type SealCarryLeaf } from "../session-seal-leaf-store.js";

const NOOP_LOGGER = { debug() {}, info() {}, warn() {}, error() {} } as never;

const agent = "aa".repeat(32);
const sess = "cc".repeat(16);

const own = (seq: number, kind: number): SealCarryLeaf => ({
  sequenceNumber: seq,
  leafKind: kind,
  senderPubkeyHex: agent, // present party authored it
  structure2Cbor: new Uint8Array([0xa0 + seq]),
  structure1Cbor: new Uint8Array([0xb0 + seq]),
  relayId: "dd".repeat(32),
  relayTimestamp: seq * 10,
  relaySignatureHex: "ee".repeat(64),
});

const received = (seq: number, kind: number): SealCarryLeaf => ({
  sequenceNumber: seq,
  leafKind: kind,
  senderPubkeyHex: "bb".repeat(32), // counterparty authored it
  structure2Cbor: new Uint8Array([0xa0 + seq]),
  structure1Cbor: new Uint8Array([0xb0 + seq]),
  // no relay receipt — the relay does not ack-sign a delivery to the recipient
});

describe("SessionSealLeafStore (DOD-OPTIONB-SEAL-1)", () => {
  it("returns the full ordered chain — BOTH parties' leaves, receipts only on own", () => {
    const store = new SessionSealLeafStore(new DatabaseSync(":memory:"), NOOP_LOGGER);
    store.store(agent, sess, received(2, 0), 1); // counterparty msg at seq 2
    store.store(agent, sess, own(1, 0), 1); // own msg at seq 1
    store.store(agent, sess, own(3, 2), 1); // own SEAL ctrl leaf at seq 3 (max)

    const carry = store.getCarry(agent, sess);
    expect(carry.map((l) => l.sequenceNumber)).toEqual([1, 2, 3]);
    // own leaves carry the relay receipt (the seq-pinning teeth)
    expect(carry[0].relaySignatureHex).toBe("ee".repeat(64));
    expect(carry[0].relayId).toBe("dd".repeat(32));
    // the counterparty leaf has NO receipt (pinned by sender-sig + contiguity instead)
    expect(carry[1].senderPubkeyHex).toBe("bb".repeat(32));
    expect(carry[1].relaySignatureHex).toBeUndefined();
    expect(carry[1].relayTimestamp).toBeUndefined();
    // the SEAL ctrl leaf is the present party's, at the max sequence, receipt-pinned
    expect(carry[2].leafKind).toBe(2);
    expect(carry[2].senderPubkeyHex).toBe(agent);
    expect(carry[2].relaySignatureHex).toBe("ee".repeat(64));
    // carry bytes round-trip
    expect(Buffer.from(carry[0].structure2Cbor).equals(Buffer.from([0xa1]))).toBe(true);
    expect(Buffer.from(carry[1].structure1Cbor).equals(Buffer.from([0xb2]))).toBe(true);
  });

  it("is IMMUTABLE at a position — a second record for the same (session, seq) is ignored", () => {
    const store = new SessionSealLeafStore(new DatabaseSync(":memory:"), NOOP_LOGGER);
    expect(store.store(agent, sess, own(1, 0), 1)).toBe(true);
    // A re-delivery / equivocation at seq 1 with different bytes → ignored; the first record stands.
    const conflicting: SealCarryLeaf = { ...received(1, 0), structure2Cbor: new Uint8Array([0xff]) };
    expect(store.store(agent, sess, conflicting, 2)).toBe(false);
    const carry = store.getCarry(agent, sess);
    expect(carry.length).toBe(1);
    expect(carry[0].senderPubkeyHex).toBe(agent); // the FIRST (own) record stands
  });

  it("scopes by (agent, session) — another session's leaves are not returned", () => {
    const store = new SessionSealLeafStore(new DatabaseSync(":memory:"), NOOP_LOGGER);
    store.store(agent, sess, own(1, 0), 1);
    store.store(agent, "ab".repeat(16), own(1, 0), 1);
    expect(store.getCarry(agent, sess).length).toBe(1);
  });

  // DOD-DOC-LEAF-1 (C7): a CHARACTERIZATION test — it constrains behavior that already held
  // rather than proving a fix. The INTEGER leaf_kind column never coerced, so nothing changed
  // here; the pin exists because P2 will write 0x04/0x05 through this store and a later
  // "normalize the kind" edit would otherwise pass unnoticed.
  it("(characterization) leaf_kind INTEGER already round-trips 0x04/0x05 — no coercion to add", () => {
    const store = new SessionSealLeafStore(new DatabaseSync(":memory:"), NOOP_LOGGER);
    store.store(agent, sess, own(1, 0x04), 1);
    store.store(agent, sess, received(2, 0x05), 1);
    store.store(agent, sess, own(3, 0x02), 1);
    const carry = store.getCarry(agent, sess);
    expect(carry.map((l) => l.leafKind)).toEqual([0x04, 0x05, 0x02]);
  });
});
