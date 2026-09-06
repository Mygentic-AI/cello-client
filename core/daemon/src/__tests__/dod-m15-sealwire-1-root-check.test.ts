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
import { encodeStructure1 } from "@cello-protocol/protocol-types";
import { buildMerkleTree, merkleRoot } from "@cello-protocol/crypto";
import { SessionNodeManager } from "../session-node-manager.js";

const AGENT_PUB = "aa".repeat(32);
const SESSION = "bb".repeat(16);

/**
 * A Structure 1 leaf, built with the REAL encoder rather than a hand-rolled array.
 *
 * It was hand-rolled, and when `DOD-M15-SELFCHAIN-1` made both chain links required this fixture
 * kept emitting the old six-field shape — so every leaf here became undecodable and nine tests
 * reported "I cannot judge this carry" instead of the verdict they were written to check. A fixture
 * that hand-rolls the layout it is testing against cannot notice that the layout moved.
 *
 * The chain links are filler: these tests compare CONTENT HASHES and read `last_seen_seq`. Nothing
 * here verifies a chain, so the links only have to be the right width.
 */
function structure1(contentHash: Uint8Array): Uint8Array {
  return s1WithLastSeen(contentHash, 0);
}

function contentHash(fill: number): Uint8Array {
  return new Uint8Array(32).fill(fill);
}

/**
 * Structure 1 with a REAL `last_seen_seq` — `DOD-M15-UNILATERAL-1`.
 *
 * `structure1()` above hardcodes 0, which is fine for a root comparison (it reads index 1 only) and
 * useless for the countersigned boundary, which reads index 4. A fixture that always says 0 cannot
 * tell "acknowledged nothing" from "the field is ignored".
 */
function s1WithLastSeen(hash: Uint8Array, lastSeenSeq: number): Uint8Array {
  return encodeStructure1({
    contentHash: hash,
    senderPubkey: new Uint8Array(32),
    sessionId: new Uint8Array(16),
    lastSeenSeq,
    timestamp: 1,
    lastSeenHash: new Uint8Array(32).fill(0x11),
    prevOwnHash: new Uint8Array(32).fill(0x22),
  });
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
    // The CURRENT layout, every field present — only the content hash is 8 bytes instead of 32. If
    // this fixture emitted a stale layout instead, it would be testing "I don't know this shape",
    // which is a different refusal and would pass even if the width check were deleted.
    (rows[0] as { structure1Cbor: Uint8Array }).structure1Cbor = encodeStructure1({
      contentHash: new Uint8Array(8),
      senderPubkey: new Uint8Array(32),
      sessionId: new Uint8Array(16),
      lastSeenSeq: 0,
      timestamp: 1,
      lastSeenHash: new Uint8Array(32).fill(0x11),
      prevOwnHash: new Uint8Array(32).fill(0x22),
    });
    const v = managerWith(rows).verifyCertifiedRoot(AGENT_PUB, SESSION, rootOf([contentHash(1)]), rows.length);
    expect(v.verdict).toBe("cannot_judge");
    expect(v.verdict === "cannot_judge" && v.reason).toMatch(/content_hash/);
  });
});

/**
 * `DOD-M15-UNILATERAL-1` — the completeness predicate above describes a BILATERAL leaf set, and a
 * SOLO seal can never satisfy it.
 */
describe("DOD-M15-UNILATERAL-1: the solo path must be able to co-sign its own seal", () => {
  /** The carry a SOLO close holds: this side's messages and ONE SEAL ctrl leaf — its own. */
  function soloCarry(msgHashes: Uint8Array[], ownCtrl: Uint8Array) {
    const rows = msgHashes.map((h, i) => ({
      sequenceNumber: i + 1, leafKind: LEAF_KIND_MSG, senderPubkeyHex: AGENT_PUB,
      structure1Cbor: structure1(h), structure2Cbor: new Uint8Array(0),
    }));
    rows.push({
      sequenceNumber: rows.length + 1, leafKind: LEAF_KIND_CTRL, senderPubkeyHex: AGENT_PUB,
      structure1Cbor: structure1(ownCtrl), structure2Cbor: new Uint8Array(0),
    });
    return rows;
  }

  it("★★★ A SOLO CARRY CO-SIGNS ITS OWN SEAL — one SEAL ctrl leaf is the shape, not a gap", () => {
    /**
     * The counterparty is gone and never posts a SEAL ctrl leaf, so `ctrlSenders.size === 2` is
     * unreachable here BY CONSTRUCTION. It returned `cannot_judge`, `session-ceremony.ts` refuses to
     * co-sign anything that is not `match`, and the sealing party therefore refused to co-sign its
     * own unilateral seal. The ceremony never reached threshold and the close came back
     * `seal_unilateral_timeout` — the label that names our own wait rather than the cause.
     *
     * Measured against the real binaries before the fix: `j-unilateral` failed here with the
     * directory having already verified the chain and recorded the counterparty ABSENT.
     */
    const hashes = [contentHash(1), contentHash(2), contentHash(0xc1)];
    const mgr = managerWith(soloCarry([contentHash(1), contentHash(2)], contentHash(0xc1)));
    expect(
      mgr.verifyCertifiedRoot(AGENT_PUB, SESSION, rootOf(hashes), hashes.length),
      "the certificate is over exactly the leaves this daemon sent — there is nothing left to judge",
    ).toEqual({ verdict: "match" });
  });

  it("★★★ AND IT STILL CANNOT BE FOOLED — a solo carry whose root disagrees does not co-sign", () => {
    /**
     * The half that makes the fix safe rather than a hole. Agreement is what buys the early match;
     * a certificate over anything else falls through to the completeness logic exactly as before,
     * and a one-ctrl carry cannot accuse — it says it cannot tell.
     */
    const mgr = managerWith(soloCarry([contentHash(1), contentHash(2)], contentHash(0xc1)));
    const theirs = [contentHash(9), contentHash(8), contentHash(7)];
    expect(mgr.verifyCertifiedRoot(AGENT_PUB, SESSION, rootOf(theirs), 3).verdict).not.toBe("match");
  });

  it("★★ a matching root with a DISAGREEING leaf count is not a match — the certificate contradicts itself", () => {
    /**
     * Both values are required for the early match. A count that disagreed while the root matched
     * would be a certificate at odds with itself, and waving that through would hand back the
     * `leaf_count` field as an off-switch: state a count nobody holds and the check is skipped.
     */
    const hashes = [contentHash(1), contentHash(2), contentHash(0xc1)];
    const mgr = managerWith(soloCarry([contentHash(1), contentHash(2)], contentHash(0xc1)));
    expect(mgr.verifyCertifiedRoot(AGENT_PUB, SESSION, rootOf(hashes), 99).verdict).not.toBe("match");
  });

  it("★★★ THE BOUNDARY IS DERIVED FROM THE CARRY, AND IT IS NOT ALWAYS ZERO", () => {
    /**
     * Review T2/F2. The only assertion on this value was a live journey expecting `0`, which
     * `countersigned_through_seq: 0` as the whole implementation would satisfy. And the first
     * implementation derived it from the certificate's own participant list — on the solo path
     * nothing there is bound to the seal signature, so it was arithmetic over somebody else's
     * claim. It is derived from this daemon's own leaves now, where the counterparty's signature
     * covers both inputs.
     *
     * A speaks (1), B replies (2) acknowledging 1, A speaks again (3), A closes (4). B's signature
     * reaches 2: they authored it, and they acknowledged nothing later. So leaves 1–2 are mutually
     * signed and 3–4 are the uncountersigned tail. The expected value is 2 — not 0, and not 4.
     */
    const mgr = managerWith([
      { sequenceNumber: 1, leafKind: LEAF_KIND_MSG, senderPubkeyHex: AGENT_PUB, structure1Cbor: s1WithLastSeen(contentHash(1), 0) },
      { sequenceNumber: 2, leafKind: LEAF_KIND_MSG, senderPubkeyHex: COUNTERPARTY_PUB, structure1Cbor: s1WithLastSeen(contentHash(2), 1) },
      { sequenceNumber: 3, leafKind: LEAF_KIND_MSG, senderPubkeyHex: AGENT_PUB, structure1Cbor: s1WithLastSeen(contentHash(3), 2) },
      { sequenceNumber: 4, leafKind: LEAF_KIND_CTRL, senderPubkeyHex: AGENT_PUB, structure1Cbor: s1WithLastSeen(contentHash(4), 2) },
    ]);
    expect(mgr.countersignedThroughSeqFromCarry(AGENT_PUB, SESSION)).toBe(2);
  });

  it("★★ a party's ACKNOWLEDGEMENT moves the boundary, not just what they authored", () => {
    /**
     * Review T3: every earlier fixture satisfied `min(last_authored_seq)` on its own, so a mutation
     * replacing `max(authored, acknowledged)` with `acknowledged` — or with `authored` — stayed
     * green. A signature reaches what it ACKNOWLEDGES as well as what it authored: B's leaf at 2
     * signs "I have seen 3", so B's commitment reaches 3 even though B authored only 2.
     */
    const mgr = managerWith([
      { sequenceNumber: 1, leafKind: LEAF_KIND_MSG, senderPubkeyHex: AGENT_PUB, structure1Cbor: s1WithLastSeen(contentHash(1), 0) },
      { sequenceNumber: 2, leafKind: LEAF_KIND_MSG, senderPubkeyHex: COUNTERPARTY_PUB, structure1Cbor: s1WithLastSeen(contentHash(2), 3) },
      { sequenceNumber: 3, leafKind: LEAF_KIND_CTRL, senderPubkeyHex: AGENT_PUB, structure1Cbor: s1WithLastSeen(contentHash(3), 2) },
    ]);
    // B authored 2 but acknowledged 3 ⇒ B reaches 3. A authored 3 ⇒ A reaches 3. min = 3.
    expect(mgr.countersignedThroughSeqFromCarry(AGENT_PUB, SESSION)).toBe(3);
  });

  it("★★ ONE author means nothing is countersigned — the receipt may not claim a prefix", () => {
    /**
     * The solo shape: the counterparty only ever received, so no leaf anywhere carries their
     * signature. Deriving `min` over the authors PRESENT would report the whole transcript mutually
     * signed, which is the conflation the field exists to prevent.
     */
    const mgr = managerWith([
      { sequenceNumber: 1, leafKind: LEAF_KIND_MSG, senderPubkeyHex: AGENT_PUB, structure1Cbor: s1WithLastSeen(contentHash(1), 0) },
      { sequenceNumber: 2, leafKind: LEAF_KIND_CTRL, senderPubkeyHex: AGENT_PUB, structure1Cbor: s1WithLastSeen(contentHash(2), 0) },
    ]);
    expect(mgr.countersignedThroughSeqFromCarry(AGENT_PUB, SESSION)).toBe(0);
  });

  it("★★ an unreadable or empty carry yields NO boundary rather than a guessed one", () => {
    // null, not 0. `0` is a derived claim ("nobody countersigned"); absence says this daemon could
    // not establish the boundary at all. Collapsing them would publish a claim it never derived.
    expect(managerWith([]).countersignedThroughSeqFromCarry(AGENT_PUB, SESSION)).toBeNull();
    const junk = managerWith([
      { sequenceNumber: 1, leafKind: LEAF_KIND_MSG, senderPubkeyHex: AGENT_PUB, structure1Cbor: new Uint8Array([0xff, 0xff]) },
    ]);
    expect(junk.countersignedThroughSeqFromCarry(AGENT_PUB, SESSION)).toBeNull();
  });

  it("★★ a SHORT bilateral carry still cannot accuse — the fix did not widen that", () => {
    // The same case the section above pins, re-asserted here because the early match is new code
    // sitting directly in front of it: a two-party conversation whose peer SEAL leaf has not landed
    // produces a different root, falls through, and answers "cannot judge" — never "you are lying".
    const rows = completeCarry([contentHash(1)], contentHash(0xc1), contentHash(0xc2)).slice(0, 2);
    const v = managerWith(rows).verifyCertifiedRoot(
      AGENT_PUB, SESSION, rootOf([contentHash(1), contentHash(0xc1), contentHash(0xc2)]), 3,
    );
    expect(v.verdict).toBe("cannot_judge");
  });
});
