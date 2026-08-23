/**
 * DOD-M15-SEALWIRE-1 bullet 2 — the client verifies the certified root against its own tree.
 *
 * ─── What the receipt proved before, and what it did not ───────────────────────────────────────
 *
 * The client took the sealed root off the wire, confirmed the directory had signed **those bytes**,
 * stored it, and discarded the root it had computed one step earlier. So the receipt proved *the
 * directory signed something* — never that it signed **your conversation**.
 *
 * The worst moment is co-signing: your key signs a root you never checked.
 *
 * It was not laziness. Until bullet 1 the certified root was the relay/directory INTERNAL root, over
 * `encodeStructure2(s2)`, which carries relay-assigned sequence numbers, prev_roots and relay
 * timestamps. A client never sees those for the counterparty's leaves, so it **could not** rebuild
 * that root. Moving the certified root into the content-hash domain is what makes this a comparison.
 *
 * ─── The counterbalance, named before the code ─────────────────────────────────────────────────
 *
 * A root check that is WRONG makes every session unsealable, and force-abandon — which forfeits the
 * receipt — becomes the only exit. That is worse than the defect being guarded, and this codebase
 * already carries two comments saying exactly that about other gates.
 *
 * So there are THREE verdicts, not two. The carry is this daemon's own view and can be legitimately
 * short at the moment a certificate lands, because the counterparty's SEAL leaf is what TRIGGERS the
 * seal and may not have been witnessed here yet. "I cannot judge" is a different answer from "the
 * roots disagree", and only a provably complete carry is allowed to accuse.
 */

import { describe, it, expect } from "vitest";
import { encodeCbor as encode } from "@cello-protocol/protocol-types";
import { buildMerkleTree, merkleRoot } from "@cello-protocol/crypto";
import { SessionNodeManager } from "../session-node-manager.js";

const AGENT_PUB = "aa".repeat(32);
const SESSION = "bb".repeat(16);

/** Canonical Structure 1 is [version, content_hash, sender_pubkey, session_id, last_seen_seq, timestamp]. */
function structure1(contentHash: Uint8Array): Uint8Array {
  return new Uint8Array(encode([1, contentHash, new Uint8Array(32), new Uint8Array(16), 0, 1]));
}

function contentHash(fill: number): Uint8Array {
  return new Uint8Array(32).fill(fill);
}

const COUNTERPARTY_PUB = "cc".repeat(32);
const LEAF_KIND_MSG = 0x00;
const LEAF_KIND_CTRL = 0x02;

/**
 * A carry in the shape a COMPLETE BILATERAL SEAL actually has — review, hollow-test question 2.
 *
 * The first version of this fixture gave every leaf `leafKind: 0` and one sender, so it contained no
 * SEAL ctrl leaves at all: it modelled a session that had never closed. Every test passed anyway,
 * because the completeness gate at the time asked the CERTIFICATE how many leaves there should be
 * rather than asking the carry what it held. When the gate started deriving completeness from the
 * carry itself, this fixture correctly stopped qualifying — and that is the fixture being wrong, not
 * the code.
 *
 * The real shape: sequences contiguous from 1, the last two leaves being SEAL ctrl leaves from the
 * two DISTINCT parties. That is what makes a carry self-evidently complete.
 */
function completeCarry(msgHashes: Uint8Array[], ownCtrl: Uint8Array, peerCtrl: Uint8Array) {
  const rows = msgHashes.map((h, i) => ({
    sequenceNumber: i + 1, leafKind: LEAF_KIND_MSG, senderPubkeyHex: AGENT_PUB,
    structure1Cbor: structure1(h), structure2Cbor: new Uint8Array(0),
  }));
  rows.push({
    sequenceNumber: rows.length + 1, leafKind: LEAF_KIND_CTRL, senderPubkeyHex: AGENT_PUB,
    structure1Cbor: structure1(ownCtrl), structure2Cbor: new Uint8Array(0),
  });
  rows.push({
    sequenceNumber: rows.length + 1, leafKind: LEAF_KIND_CTRL, senderPubkeyHex: COUNTERPARTY_PUB,
    structure1Cbor: structure1(peerCtrl), structure2Cbor: new Uint8Array(0),
  });
  return rows;
}

/** The leaf hashes such a carry produces, in order — what the directory would certify over. */
function completeHashes(msgHashes: Uint8Array[], ownCtrl: Uint8Array, peerCtrl: Uint8Array): Uint8Array[] {
  return [...msgHashes, ownCtrl, peerCtrl];
}

function managerWith(rows: unknown[]): SessionNodeManager {
  const mgr = Object.create(SessionNodeManager.prototype) as SessionNodeManager;
  (mgr as unknown as { getSealCarry: () => unknown[] }).getSealCarry = () => rows;
  return mgr;
}

/** A complete bilateral carry plus the hash list it corresponds to. */
function managerWithCarry(hashes: Uint8Array[]): { mgr: SessionNodeManager; hashes: Uint8Array[] } {
  const msgs = hashes.slice(0, Math.max(0, hashes.length - 2));
  const own = hashes[hashes.length - 2] ?? contentHash(0xc1);
  const peer = hashes[hashes.length - 1] ?? contentHash(0xc2);
  return { mgr: managerWith(completeCarry(msgs, own, peer)), hashes: completeHashes(msgs, own, peer) };
}

const rootOf = (hashes: Uint8Array[]) =>
  merkleRoot(buildMerkleTree(hashes.map((h) => ({ kind: "hash" as const, data: h }))));

describe("DOD-M15-SEALWIRE-1: the client checks what its key is about to endorse", () => {
  it("★ a root over OUR leaves matches", () => {
    const { mgr, hashes } = managerWithCarry([contentHash(1), contentHash(2), contentHash(3)]);
    expect(mgr.verifyCertifiedRoot(AGENT_PUB, SESSION, rootOf(hashes), hashes.length)).toEqual({ verdict: "match" });
  });

  it("★ a root over a DIFFERENT conversation is caught", () => {
    /**
     * The attack the receipt could not detect: a validly-signed certificate over someone else's
     * leaves. The signature check passes — the directory really did sign it — and before this the
     * client stored it as its own receipt.
     */
    const { mgr, hashes } = managerWithCarry([contentHash(1), contentHash(2), contentHash(3)]);
    const theirs = [contentHash(9), contentHash(8), contentHash(7), contentHash(6), contentHash(5)];
    const v = mgr.verifyCertifiedRoot(AGENT_PUB, SESSION, rootOf(theirs), hashes.length);
    expect(v.verdict).toBe("mismatch");
  });

  it("★ a REORDERED leaf set is caught — order is part of what a transcript means", () => {
    const { mgr, hashes } = managerWithCarry([contentHash(1), contentHash(2), contentHash(3)]);
    const swapped = [hashes[1]!, hashes[0]!, ...hashes.slice(2)];
    expect(mgr.verifyCertifiedRoot(AGENT_PUB, SESSION, rootOf(swapped), hashes.length).verdict).toBe("mismatch");
  });

  it("★ a SUBSTITUTED leaf is caught even with the count unchanged", () => {
    // The shape a dropped-and-replaced message takes: same leaf count, different content.
    const { mgr, hashes } = managerWithCarry([contentHash(1), contentHash(2), contentHash(3)]);
    const tampered = [hashes[0]!, contentHash(0xee), ...hashes.slice(2)];
    expect(mgr.verifyCertifiedRoot(AGENT_PUB, SESSION, rootOf(tampered), hashes.length).verdict).toBe("mismatch");
  });

  it("★ the mismatch carries OUR root, so the two can be compared by a human", () => {
    const { mgr, hashes } = managerWithCarry([contentHash(1)]);
    const v = mgr.verifyCertifiedRoot(AGENT_PUB, SESSION, rootOf([contentHash(2), contentHash(3), contentHash(4)]), hashes.length);
    expect(v.verdict === "mismatch" && v.ownRootHex).toBe(Buffer.from(rootOf(hashes)).toString("hex"));
  });
});

describe("DOD-M15-SEALWIRE-1: 'I cannot judge' is not 'you are lying'", () => {
  it("★ a SHORT carry cannot accuse — the counterparty's SEAL leaf triggers the seal", () => {
    /**
     * The false positive that would make every session unsealable. The certificate covers three
     * leaves; this daemon has witnessed two, because the third is the counterparty's SEAL ctrl leaf
     * which is what caused the certificate to exist. Refusing here would turn a normal timing gap
     * into a permanent refusal, and force-abandon (no receipt) into the only exit.
     */
    // Only ONE ctrl leaf has landed — this side's. The counterparty's is what triggered the seal.
    const rows = completeCarry([contentHash(1)], contentHash(0xc1), contentHash(0xc2)).slice(0, 2);
    const v = managerWith(rows).verifyCertifiedRoot(AGENT_PUB, SESSION, rootOf([contentHash(1)]), 3);
    expect(v.verdict).toBe("cannot_judge");
    expect(v.verdict === "cannot_judge" && v.reason, "and it must say WHICH half is missing").toMatch(/1 of 2 SEAL ctrl/);
  });

  it("★ an EMPTY carry cannot accuse either", () => {
    expect(managerWith([]).verifyCertifiedRoot(AGENT_PUB, SESSION, rootOf([contentHash(1)]), 1).verdict).toBe("cannot_judge");
  });

  it("★ an undecodable leaf cannot accuse — a local defect is not the counterparty's fault", () => {
    // A carry that IS self-evidently complete, but one of whose leaves will not decode. The
    // completeness gate passes; the decode fails; the answer must still be "cannot judge", because a
    // local storage defect is not evidence against the counterparty.
    const rows = completeCarry([contentHash(1)], contentHash(0xc1), contentHash(0xc2));
    (rows[0] as { structure1Cbor: Uint8Array }).structure1Cbor = new Uint8Array([0xff, 0xff]);
    const v = managerWith(rows).verifyCertifiedRoot(AGENT_PUB, SESSION, rootOf([contentHash(1)]), rows.length);
    expect(v.verdict).toBe("cannot_judge");
  });

  it("★ a leaf whose content hash is the wrong SHAPE cannot accuse", () => {
    const rows = completeCarry([contentHash(1)], contentHash(0xc1), contentHash(0xc2));
    (rows[0] as { structure1Cbor: Uint8Array }).structure1Cbor =
      new Uint8Array(encode([1, new Uint8Array(8), new Uint8Array(32), new Uint8Array(16), 0, 1]));
    const v = managerWith(rows).verifyCertifiedRoot(AGENT_PUB, SESSION, rootOf([contentHash(1)]), rows.length);
    expect(v.verdict).toBe("cannot_judge");
    expect(v.verdict === "cannot_judge" && v.reason).toMatch(/content_hash/);
  });
});
