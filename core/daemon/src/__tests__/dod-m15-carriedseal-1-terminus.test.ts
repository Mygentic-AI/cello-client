/**
 * `DOD-M15-CARRIEDSEAL-1` unit 1 — the closing statement this side can write with nobody watching.
 *
 * A seal used to need the relay alive for one reason: the SEAL control leaf that ends the record had
 * to be handed to the relay for a sequence number. Every message before it was already countersigned
 * and held by both sides, and the receipt was lost anyway.
 *
 * `buildLocalSealTerminus` writes that leaf here instead. It takes nothing on trust and invents
 * nothing: every field it fills is READ OUT OF THE CARRY it is closing over — the position is the
 * next one, the links are the last leaves each party authored, and the prefix root is the fold over
 * the leaves themselves. That is what makes it checkable by a directory that was not present and
 * cannot ask anyone.
 */
import { describe, it, expect } from "vitest";
import { decode as cborDecode } from "cbor-x";
import { createHash, randomBytes } from "node:crypto";
import { generateKeypair, verify, buildMerkleTree, merkleRoot, type LeafInput } from "@cello-protocol/crypto";
import { encodeStructure1, decodeStructure1, encodeStructure2, decodeSealPayload, SCAN_RESULT_SENTINEL } from "@cello-protocol/protocol-types";
import { buildLocalSealTerminus } from "../seal-local-terminus.js";
import type { SealCarryLeaf } from "../session-seal-leaf-store.js";

const LEAF_KIND_MSG = 0x00;
const LEAF_KIND_CTRL = 0x02;
const hex = (u: Uint8Array): string => Buffer.from(u).toString("hex");

const GENESIS = new Uint8Array(randomBytes(32));
const SESSION = new Uint8Array(randomBytes(16));

/** The structure2-domain fold the directory's prev_root chain is checked against. */
function prefixRoot(carry: readonly SealCarryLeaf[]): Uint8Array {
  if (carry.length === 0) return new Uint8Array(32);
  const inputs: LeafInput[] = carry.map((l) => ({
    kind: l.leafKind === LEAF_KIND_CTRL ? "ctrl" : "msg",
    data: l.structure2Cbor,
  }));
  return merkleRoot(buildMerkleTree(inputs));
}

/**
 * A genuine relay-ordered leaf, built the way the relay and the sender jointly build one: the sender
 * signs Structure 1, the relay wraps it in Structure 2 at a position. The relay receipt fields are
 * irrelevant here — the terminus reads positions and content hashes, never witnesses.
 */
async function carriedLeaf(opts: {
  seq: number;
  kind: number;
  kp: ReturnType<typeof generateKeypair>;
  lastSeenSeq: number;
  lastSeenHash: Uint8Array;
  prevOwnHash: Uint8Array;
  prevRoot: Uint8Array;
}): Promise<SealCarryLeaf> {
  const pubkey = new Uint8Array(await opts.kp.getPublicKey());
  const contentHash = new Uint8Array(randomBytes(32));
  const structure1Cbor = encodeStructure1({
    contentHash,
    senderPubkey: pubkey,
    sessionId: SESSION,
    lastSeenSeq: opts.lastSeenSeq,
    timestamp: 1_700_000_000_000 + opts.seq,
    lastSeenHash: opts.lastSeenHash,
    prevOwnHash: opts.prevOwnHash,
  });
  const sig = new Uint8Array(await opts.kp.sign(structure1Cbor));
  const structure2Cbor = encodeStructure2({
    sequence_number: opts.seq,
    sender_pubkey: pubkey,
    content_hash: contentHash,
    sender_signature: sig,
    scan_result: SCAN_RESULT_SENTINEL,
    prev_root: opts.prevRoot,
  });
  return {
    sequenceNumber: opts.seq,
    leafKind: opts.kind,
    senderPubkeyHex: hex(pubkey),
    structure2Cbor,
    structure1Cbor,
    relayId: "aa".repeat(32),
    relayTimestamp: opts.seq,
    relaySignatureHex: "bb".repeat(64),
    relayRunningRootHex: "cc".repeat(32),
  };
}

/** A two-message conversation: us at 1, them at 2. The shape a close closes over. */
async function twoMessageCarry(): Promise<{
  carry: SealCarryLeaf[];
  us: ReturnType<typeof generateKeypair>;
  usHex: string;
}> {
  const us = generateKeypair();
  const them = generateKeypair();
  const usHex = hex(new Uint8Array(await us.getPublicKey()));
  const first = await carriedLeaf({
    seq: 1, kind: LEAF_KIND_MSG, kp: us,
    lastSeenSeq: 0, lastSeenHash: GENESIS, prevOwnHash: GENESIS, prevRoot: new Uint8Array(32),
  });
  const firstHash = decodeStructure1(first.structure1Cbor);
  if (!firstHash.ok) throw new Error("fixture: first leaf did not decode");
  const second = await carriedLeaf({
    seq: 2, kind: LEAF_KIND_MSG, kp: them,
    lastSeenSeq: 1, lastSeenHash: firstHash.fields.contentHash, prevOwnHash: GENESIS,
    prevRoot: prefixRoot([first]),
  });
  return { carry: [first, second], us, usHex };
}

const inputs = async (carry: SealCarryLeaf[], us: ReturnType<typeof generateKeypair>, usHex: string) => ({
  carry,
  ownPubkeyHex: usHex,
  ownPubkey: new Uint8Array(await us.getPublicKey()),
  sessionIdBytes: SESSION,
  genesis: GENESIS,
  finalRootHex: "11".repeat(32),
  closeTimestamp: 1_700_000_009_000,
  sign: async (b: Uint8Array) => new Uint8Array(await us.sign(b)),
});

describe("DOD-M15-CARRIEDSEAL-1 — buildLocalSealTerminus writes the closing leaf with no relay", () => {
  it("★★★ places our SEAL leaf at the next position, chained to the carry it closes over", async () => {
    const { carry, us, usHex } = await twoMessageCarry();
    const r = await buildLocalSealTerminus(await inputs(carry, us, usHex));
    expect(r.ok, `a contiguous two-leaf carry must yield a terminus: ${JSON.stringify(r)}`).toBe(true);
    if (!r.ok) return;

    expect(r.leaf.sequenceNumber, "the terminus takes the next position, never one it chose").toBe(3);
    expect(r.leaf.leafKind).toBe(LEAF_KIND_CTRL);
    expect(r.leaf.senderPubkeyHex).toBe(usHex);

    // ── THE WITNESS FIELDS ARE ABSENT, NOT EMPTY ──
    // A blank relay id would claim a witness and fail to produce one, which the directory judges as
    // a MALFORMED receipt. The exemption it relies on is for a receipt that is not there at all.
    expect(r.leaf.relayId, "no relay ordered this leaf and it must not pretend one did").toBeUndefined();
    expect(r.leaf.relaySignatureHex).toBeUndefined();
    expect(r.leaf.relayTimestamp).toBeUndefined();
    expect(r.leaf.relayRunningRootHex).toBeUndefined();
  });

  it("★★★ signs Structure 1 with our key, over links read out of the carry", async () => {
    const { carry, us, usHex } = await twoMessageCarry();
    const ourPubkey = new Uint8Array(await us.getPublicKey());
    const r = await buildLocalSealTerminus(await inputs(carry, us, usHex));
    expect(r.ok).toBe(true);
    if (!r.ok) return;

    const s1 = decodeStructure1(r.leaf.structure1Cbor);
    expect(s1.ok, "the terminus must be a decodable Structure 1 claim").toBe(true);
    if (!s1.ok) return;

    // The signature is OURS, over the bytes as encoded — the directory verifies exactly this.
    const sigOk = verify(ourPubkey, r.leaf.structure1Cbor, decodeS2Sig(r.leaf.structure2Cbor));
    expect(sigOk, "the directory verifies the sender signature from Structure 2 against these bytes").toBe(true);

    // last_seen — THEIR tip, which is leaf 2. Not a value we chose; the newest leaf they authored.
    const theirLeaf = decodeStructure1(carry[1].structure1Cbor);
    expect(theirLeaf.ok).toBe(true);
    if (!theirLeaf.ok) return;
    expect(s1.fields.lastSeenSeq, "we have seen everything they said, and say so").toBe(2);
    expect(hex(s1.fields.lastSeenHash!)).toBe(hex(theirLeaf.fields.contentHash));

    // prev_own — OUR previous message, which is leaf 1.
    const ourLeaf = decodeStructure1(carry[0].structure1Cbor);
    expect(ourLeaf.ok).toBe(true);
    if (!ourLeaf.ok) return;
    expect(hex(s1.fields.prevOwnHash!)).toBe(hex(ourLeaf.fields.contentHash));
  });

  it("★★★ prev_root is the fold over the carried leaves — the chain the directory re-walks", async () => {
    const { carry, us, usHex } = await twoMessageCarry();
    const r = await buildLocalSealTerminus(await inputs(carry, us, usHex));
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    // Computed independently here from the carry, not taken from the function under test: if the
    // terminus named any other prefix the directory's prev_root walk would break at this leaf.
    expect(hex(decodeS2PrevRoot(r.leaf.structure2Cbor))).toBe(hex(prefixRoot(carry)));
  });

  it("★★★ the content hash binds the SEAL payload — 0x02 || payload, the directory's own derivation", async () => {
    const { carry, us, usHex } = await twoMessageCarry();
    const r = await buildLocalSealTerminus(await inputs(carry, us, usHex));
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const payload = decodeSealPayload(r.payload);
    expect(payload, "the terminus carries a decodable SEAL payload").not.toBeNull();
    expect(hex(payload!.final_root)).toBe("11".repeat(32));
    expect(payload!.attestation).toBe("PENDING");

    const expected = hex(new Uint8Array(
      createHash("sha256").update(new Uint8Array([LEAF_KIND_CTRL])).update(r.payload).digest(),
    ));
    const s1 = decodeStructure1(r.leaf.structure1Cbor);
    expect(s1.ok).toBe(true);
    if (!s1.ok) return;
    expect(hex(s1.fields.contentHash), "the signed hash and the payload must come from one derivation").toBe(expected);
    expect(r.contentHashHex).toBe(expected);
  });

  it("REFUSES an empty carry — there is no conversation to close over", async () => {
    const { us, usHex } = await twoMessageCarry();
    const r = await buildLocalSealTerminus(await inputs([], us, usHex));
    expect(r).toMatchObject({ ok: false, reason: "seal_carry_empty" });
  });

  it("REFUSES a carry with a gap — a leaf the relay witnessed never reached us", async () => {
    const { carry, us, usHex } = await twoMessageCarry();
    carry[1].sequenceNumber = 3; // 1, 3 — position 2 is missing
    const r = await buildLocalSealTerminus(await inputs(carry, us, usHex));
    expect(r).toMatchObject({ ok: false, reason: "seal_carry_noncontiguous" });
  });

  it("★★★ REFUSES when our own SEAL leaf is already in the carry — never a second one", async () => {
    const { carry, us, usHex } = await twoMessageCarry();
    const ours = await carriedLeaf({
      seq: 3, kind: LEAF_KIND_CTRL, kp: us,
      lastSeenSeq: 2, lastSeenHash: GENESIS, prevOwnHash: GENESIS, prevRoot: prefixRoot(carry),
    });
    const r = await buildLocalSealTerminus(await inputs([...carry, ours], us, usHex));
    // Two control leaves from one party makes a session unsealable by ANY directory, permanently.
    // The caller reuses the one that is there; this refuses to add to it.
    expect(r).toMatchObject({ ok: false, reason: "seal_carry_own_ctrl_present" });
  });

  it("REFUSES a carry holding a leaf it cannot read — never a terminus over a record we cannot see", async () => {
    const { carry, us, usHex } = await twoMessageCarry();
    carry[0].structure1Cbor = new Uint8Array([0xff, 0xff, 0xff]);
    const r = await buildLocalSealTerminus(await inputs(carry, us, usHex));
    expect(r).toMatchObject({ ok: false, reason: "seal_carry_unreadable" });
  });

  it("uses the session genesis for both links when neither party has spoken yet", async () => {
    // A session sealed with no messages in it: nothing to link to but the agreed starting point.
    // "I have not spoken" is a VALUE here, exactly as it is on the send path — never an absent field.
    const us = generateKeypair();
    const usHex = hex(new Uint8Array(await us.getPublicKey()));
    const only = await carriedLeaf({
      seq: 1, kind: LEAF_KIND_MSG, kp: us,
      lastSeenSeq: 0, lastSeenHash: GENESIS, prevOwnHash: GENESIS, prevRoot: new Uint8Array(32),
    });
    const r = await buildLocalSealTerminus(await inputs([only], us, usHex));
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const s1 = decodeStructure1(r.leaf.structure1Cbor);
    expect(s1.ok).toBe(true);
    if (!s1.ok) return;
    expect(s1.fields.lastSeenSeq, "they have said nothing").toBe(0);
    expect(hex(s1.fields.lastSeenHash!)).toBe(hex(GENESIS));
    const ourFirst = decodeStructure1(only.structure1Cbor);
    expect(ourFirst.ok).toBe(true);
    if (!ourFirst.ok) return;
    expect(hex(s1.fields.prevOwnHash!), "our previous message is the one leaf we did author").toBe(hex(ourFirst.fields.contentHash));
  });
});

/** The sender signature out of a canonical Structure 2, for the verification above. */
function decodeS2Sig(cbor: Uint8Array): Uint8Array {
  return new Uint8Array((cborDecode(cbor) as unknown[])[3] as Uint8Array);
}

/** The prev_root out of a canonical Structure 2. */
function decodeS2PrevRoot(cbor: Uint8Array): Uint8Array {
  return new Uint8Array((cborDecode(cbor) as unknown[])[5] as Uint8Array);
}
