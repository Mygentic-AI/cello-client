/**
 * RelayReceiptStore + verifyRelayAck + evaluateRelayAck — DOD-M15-ORDERPROOF-1.
 *
 * The relay's ordering attestation, and the two things this order changed about it.
 *
 * **It is verified against the relay key the DIRECTORY named**, from the FROST-signed
 * `SessionAssignment`, never against `relay_id` riding in the frame being checked. Verifying a
 * signature against a key its own signer supplied proves the frame is internally consistent and
 * nothing at all about who ordered anything.
 *
 * **Missing, malformed and mismatched share ONE outcome.** Not three reasons a caller can branch
 * on: an attestation that is absent leaves a party with no ordering evidence for that message,
 * which is exactly what a stripped one leaves them with. Whoever can cause the absence must not
 * get a softer answer than whoever can cause the corruption.
 */
import { describe, it, expect, beforeEach } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { randomBytes } from "node:crypto";
import { generateKeypair, buildRelayAckTbs } from "@cello-protocol/crypto";
import { RelayReceiptStore, verifyRelayAck, evaluateRelayAck, type RelayReceipt } from "../relay-receipt-store.js";

const NOOP_LOGGER = { debug() {}, info() {}, warn() {}, error() {} } as never;

describe("verifyRelayAck (DOD-M15-ORDERPROOF-1) — every bound field is actually bound", () => {
  it("accepts a genuine attestation and rejects every tamper, the session and the root included", async () => {
    const relay = generateKeypair();
    const relayPubkey = await relay.getPublicKey();
    const sessionId = new Uint8Array(randomBytes(16));
    const contentHash = new Uint8Array(randomBytes(32));
    const runningRoot = new Uint8Array(randomBytes(32));
    const seq = 7;
    const ts = 1_719_800_000_000;
    const sig = await relay.sign(buildRelayAckTbs(sessionId, contentHash, seq, runningRoot, ts));

    expect(verifyRelayAck(sessionId, contentHash, seq, runningRoot, ts, sig, relayPubkey)).toBe(true);
    // A DIFFERENT SESSION. Without this field an attestation lifts out of one conversation into
    // another — same hash, same position — and still verifies.
    expect(verifyRelayAck(new Uint8Array(randomBytes(16)), contentHash, seq, runningRoot, ts, sig, relayPubkey)).toBe(false);
    // A DIFFERENT PREFIX. The attestation says this leaf sat at this position of THIS chain.
    expect(verifyRelayAck(sessionId, contentHash, seq, new Uint8Array(randomBytes(32)), ts, sig, relayPubkey)).toBe(false);
    expect(verifyRelayAck(sessionId, contentHash, seq + 1, runningRoot, ts, sig, relayPubkey)).toBe(false);
    expect(verifyRelayAck(sessionId, contentHash, seq, runningRoot, ts + 1, sig, relayPubkey)).toBe(false);
    expect(verifyRelayAck(sessionId, new Uint8Array(randomBytes(32)), seq, runningRoot, ts, sig, relayPubkey)).toBe(false);
    const otherPubkey = await generateKeypair().getPublicKey();
    expect(verifyRelayAck(sessionId, contentHash, seq, runningRoot, ts, sig, otherPubkey)).toBe(false);
    expect(verifyRelayAck(sessionId, contentHash, seq, runningRoot, ts, new Uint8Array(63), relayPubkey)).toBe(false);
  });

  it("a wrong-length field is REFUSED, not hashed — it returns false instead of throwing", async () => {
    // The bytes arrive off a wire a relay controls. A 15-byte session id must not reach the hash,
    // and it must not take down the frame handler either.
    const relay = generateKeypair();
    const relayPubkey = await relay.getPublicKey();
    const sessionId = new Uint8Array(randomBytes(16));
    const contentHash = new Uint8Array(randomBytes(32));
    const runningRoot = new Uint8Array(randomBytes(32));
    const sig = await relay.sign(buildRelayAckTbs(sessionId, contentHash, 1, runningRoot, 10));
    expect(verifyRelayAck(new Uint8Array(15), contentHash, 1, runningRoot, 10, sig, relayPubkey)).toBe(false);
    expect(verifyRelayAck(sessionId, contentHash, 1, new Uint8Array(31), 10, sig, relayPubkey)).toBe(false);
  });
});

describe("evaluateRelayAck (DOD-M15-ORDERPROOF-1) — anchored, and absent is not fine", () => {
  const mk = async () => {
    const relay = generateKeypair();
    const relayId = Buffer.from(await relay.getPublicKey()).toString("hex");
    const sessionId = new Uint8Array(randomBytes(16));
    const contentHash = new Uint8Array(randomBytes(32));
    const runningRoot = new Uint8Array(randomBytes(32));
    const ts = 1_719_800_000_000;
    const seq = 7;
    const sig = await relay.sign(buildRelayAckTbs(sessionId, contentHash, seq, runningRoot, ts));
    return {
      relay, relayId, sessionId, contentHash, runningRoot, ts, seq, sig,
      base: {
        sessionId,
        contentHash,
        runningRoot,
        sessionIdHex: Buffer.from(sessionId).toString("hex"),
        agentPubkeyHex: "aa".repeat(32),
        expectedRelayPubkeyHex: relayId,
        timestamp: ts,
      },
    };
  };

  it("a genuine attestation under the DIRECTORY-NAMED key yields a storable receipt", async () => {
    const t = await mk();
    const ev = evaluateRelayAck({ ...t.base, relayId: t.relayId, relaySignature: t.sig, sequenceNumber: t.seq });
    expect(ev.kind).toBe("store");
    if (ev.kind === "store") {
      expect(ev.receipt.sequenceNumber).toBe(t.seq);
      expect(ev.receipt.relayId).toBe(t.relayId);
      expect(ev.receipt.hashHex).toBe(Buffer.from(t.contentHash).toString("hex"));
      expect(ev.receipt.runningRootHex).toBe(Buffer.from(t.runningRoot).toString("hex"));
    }
  });

  it("a PERFECTLY VALID attestation from a relay the directory did not name is refused", async () => {
    // The defect this closes, in one case: before this order the verification key came from
    // `relay_id` on the frame. Any party able to write the frame minted a key, signed whatever
    // ordering it liked with it, and put the key in the field we checked against.
    const t = await mk();
    const impostor = generateKeypair();
    const impostorId = Buffer.from(await impostor.getPublicKey()).toString("hex");
    const impostorSig = await impostor.sign(
      buildRelayAckTbs(t.sessionId, t.contentHash, t.seq, t.runningRoot, t.ts),
    );
    const ev = evaluateRelayAck({
      ...t.base,
      relayId: impostorId,
      relaySignature: impostorSig,
      sequenceNumber: t.seq,
    });
    expect(ev.kind).toBe("refused");
    if (ev.kind === "refused") expect(ev.cause).toBe("relay_not_assigned");
  });

  it("a signature over the right statement by a relay OMITTING its id is still checked against the anchor", async () => {
    // The relay does not get to opt out of being checked by leaving a field blank.
    const t = await mk();
    const ev = evaluateRelayAck({ ...t.base, relayId: undefined, relaySignature: t.sig, sequenceNumber: t.seq });
    expect(ev.kind).toBe("store");
  });

  it("MISSING, MALFORMED and MISMATCHED produce the SAME refusal — only the logged cause differs", async () => {
    const t = await mk();
    const cases: Array<[string, string, ReturnType<typeof evaluateRelayAck>]> = [
      // The two ABSENCES share one cause on purpose: a signature with no root and a root with no
      // signature are the same fact — the relay attested nothing usable.
      ["missing signature", "attestation_absent", evaluateRelayAck({ ...t.base, relayId: t.relayId, relaySignature: undefined, timestamp: undefined, sequenceNumber: t.seq })],
      ["missing running root", "attestation_absent", evaluateRelayAck({ ...t.base, runningRoot: undefined, relayId: t.relayId, relaySignature: t.sig, sequenceNumber: t.seq })],
      ["malformed signature", "signature_invalid", evaluateRelayAck({ ...t.base, relayId: t.relayId, relaySignature: new Uint8Array(randomBytes(64)), sequenceNumber: t.seq })],
      ["forged sequence", "signature_invalid", evaluateRelayAck({ ...t.base, relayId: t.relayId, relaySignature: t.sig, sequenceNumber: t.seq + 1 })],
      ["malformed relay id", "bad_relay_id", evaluateRelayAck({ ...t.base, relayId: "xyz", relaySignature: t.sig, sequenceNumber: t.seq })],
      ["no anchor recorded", "no_anchor", evaluateRelayAck({ ...t.base, expectedRelayPubkeyHex: undefined, relayId: t.relayId, relaySignature: t.sig, sequenceNumber: t.seq })],
    ];
    for (const [name, expectedCause, ev] of cases) {
      // The OUTCOME is identical for every one of them. That is the clause.
      expect(ev.kind, name).toBe("refused");
      // And the cause is still named, so the log can say which it was. An operator reading "the
      // relay did not sign" must not have to guess whether it meant "it signed wrong".
      if (ev.kind === "refused") expect(ev.cause, name).toBe(expectedCause);
    }
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
    runningRootHex: "ff".repeat(32),
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
    runningRootHex: "ff".repeat(32),
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
      runningRootHex: "ff".repeat(32),
    }, 1);
    store.store(mkLeaf(2, "22".repeat(32), new Uint8Array([0xa2]), new Uint8Array([0xb2]), 0), 1);
    // getSealLeaves returns only leaves that have the full carry bytes (the chain it can rebuild offline).
    expect(store.getSealLeaves(agent, sess).map((l) => l.sequenceNumber)).toEqual([2]);
    // getAll still returns ALL receipts (the witness query is unchanged).
    expect(store.getAll(agent, sess).length).toBe(2);
  });
});
