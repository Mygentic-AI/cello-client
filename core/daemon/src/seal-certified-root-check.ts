/**
 * `DOD-M15-SEALWIRE-1` / `DOD-M15-CARRIEDSEAL-1` — DOES THIS CERTIFICATE DESCRIBE WHAT I HOLD?
 *
 * Moved out of `session-seal.ts` whole, with no change to the verdicts, when 070-CARRIEDSEAL needed
 * room under that file's ratchet. It belongs out here on its own terms: everything else in the seal
 * class drives a ceremony, and this only ever ANSWERS A QUESTION about a leaf set — no transport, no
 * lifecycle, no state of its own.
 *
 * Crypto refs: RFC 6962 §2.1 (Merkle hash trees).
 */
import { buildMerkleTree, merkleRoot } from "@cello-protocol/crypto";
import { LEAF_KIND_CTRL } from "./session-relay-client.js";
import { carryContentHashInputs } from "./session-node-types.js";
import type { SealCarryLeaf } from "./session-seal-leaf-store.js";

/**
 * REBUILD THE CERTIFIED ROOT FROM THIS DAEMON'S OWN LEAVES — `DOD-M15-SEALWIRE-1` bullet 2.
 *
 * The receipt used to prove only that the directory signed SOMETHING: the client took the sealed
 * root off the wire, confirmed the directory's signature over those bytes, stored it, and threw
 * away the root it had computed a step earlier. At co-signing time that means **your key signs a
 * root you never checked.**
 *
 * Bullet 1 moved the certified root into the content-hash domain, which is the domain this daemon
 * can actually rebuild — each carry leaf's `content_hash` is the leaf hash (RFC 6962 §2.1 "hash"
 * leaves are used as-is), and the carry is ordered by the relay's canonical `sequence_number`,
 * which is the order the directory rebuilds in.
 *
 * ─── Why this returns "cannot judge" instead of always answering ───────────────────────────
 *
 * A root comparison that is WRONG makes every session unsealable, and force-abandon — no receipt —
 * becomes the only exit. That failure is worse than the one being guarded, and this file already
 * carries two comments saying so about other gates.
 *
 * The carry is this daemon's view, and it is not guaranteed complete at the instant a certificate
 * arrives: the counterparty's SEAL ctrl leaf is what TRIGGERS the seal, so it may not have been
 * witnessed here yet. So completeness is checked FIRST, against the certificate's own leaf count.
 * A short carry means this daemon cannot judge — which is a different answer from "the roots
 * disagree", and conflating them would turn a local timing gap into an accusation.
 */
export function verifyCertifiedRoot(
  getSealCarry: (agentPubkeyHex: string, sessionIdHex: string) => SealCarryLeaf[],
  agentPubkeyHex: string,
  sessionIdHex: string,
  certifiedRoot: Uint8Array,
  certifiedLeafCount: number,
): { verdict: "match" } | { verdict: "mismatch"; ownRootHex: string | null; detail: string } | { verdict: "cannot_judge"; reason: string } {
  const carry = getSealCarry(agentPubkeyHex, sessionIdHex);
  if (carry.length === 0) return { verdict: "cannot_judge", reason: "no_carry" };

  /**
   * COMPLETENESS IS ESTABLISHED FROM THE CARRY'S OWN EVIDENCE, NEVER FROM THE CERTIFICATE.
   *
   * Review F3, and the first cut had this exactly backwards. It gated on
   * `carry.length !== certifiedLeafCount`, where `certifiedLeafCount` is a field the DIRECTORY
   * chooses and signs — so the party being checked controlled whether it was checked. A directory
   * certifying a root over a different conversation had only to state a `leaf_count` that did not
   * match, and the client answered "cannot judge" and accepted. The signature still verified,
   * because the count is signed inside the same TBS.
   *
   * That is the hole §2b names in as many words: *"an attacker who wants to evade a mismatch check
   * simply never supplies a checkable proof. Treating 'we could not tell' as harmless is the
   * hole."* I defended against a false POSITIVE and left the false NEGATIVE one field away.
   *
   * The carry can answer the question by itself. A complete bilateral leaf set is:
   *   - sequences contiguous from 1 — no gap where a leaf this daemon never saw would sit; and
   *   - exactly two SEAL ctrl leaves, from two DISTINCT senders — which is what a bilateral seal
   *     is, and is the condition that says the counterparty's closing leaf has landed here.
   * Both predicates already exist in `seal-escalation.ts`; this reuses their shape rather than
   * inventing a second opinion about the same question.
   *
   * When the carry IS self-evidently complete, a `leaf_count` that disagrees is no longer "I
   * cannot tell" — it is the certificate describing a different leaf set, which is a MISMATCH.
   */
  const sequences = carry.map((l) => l.sequenceNumber).sort((a, b) => a - b);
  const contiguousFromOne = sequences.every((n, i) => n === i + 1);
  const ctrlSenders = new Set(
    carry.filter((l) => l.leafKind === LEAF_KIND_CTRL).map((l) => l.senderPubkeyHex),
  );
  const selfEvidentlyComplete = contiguousFromOne && ctrlSenders.size === 2;

  /**
   * 🚨 THE CERTIFICATE MAY COVER EXACTLY WHAT THIS SIDE HOLDS — ASK THAT FIRST.
   *
   * `DOD-M15-UNILATERAL-1`. The completeness predicate below describes a BILATERAL leaf set: two
   * SEAL ctrl leaves, from two distinct senders. **A solo seal can never satisfy it**, because the
   * counterparty is gone and never posts one — that is the entire premise. So on the solo path
   * this returned `cannot_judge` every time, `session-ceremony.ts` refuses to co-sign on anything
   * that is not `match`, and **the sealing party refused to co-sign its own unilateral seal.** The
   * FROST ceremony never reached threshold, the directory never completed, and the close came back
   * `seal_unilateral_timeout` — the label that names our own wait. Measured against the real
   * binaries: `j-unilateral` failed on exactly this, with the directory having already verified the
   * chain and recorded the counterparty ABSENT.
   *
   * Completeness was only ever needed to tell TWO KINDS OF DISAGREEMENT apart — "the roots differ
   * because my carry is behind" (cannot judge) from "the roots differ because the directory
   * certified something else" (mismatch). It answers nothing when the roots AGREE: a certificate
   * whose root and leaf count are exactly what this daemon holds is, by construction, over this
   * daemon's own leaves. Nothing is taken on trust — both values are recomputed here from the
   * carry, and an adversary who could satisfy them would have to have produced this leaf set.
   *
   * Deliberately BOTH values. A count that disagreed while the root matched would be a certificate
   * contradicting itself, and this is not the place to wave that through.
   */
  const carryInputs = carryContentHashInputs(carry);
  if (
    carryInputs !== null &&
    carry.length === certifiedLeafCount &&
    Buffer.compare(Buffer.from(merkleRoot(buildMerkleTree(carryInputs))), Buffer.from(certifiedRoot)) === 0
  ) {
    return { verdict: "match" };
  }

  if (!selfEvidentlyComplete) {
    return {
      verdict: "cannot_judge",
      reason: contiguousFromOne
        ? `carry_incomplete: ${ctrlSenders.size} of 2 SEAL ctrl leaves witnessed here`
        : `carry_noncontiguous: hold ${carry.length} leaves with a gap in the relay sequence`,
    };
  }
  if (carry.length !== certifiedLeafCount) {
    // The carry proves itself complete and the certificate claims a different size, so the
    // certificate is over a different leaf set. Accusing is correct here.
    return {
      verdict: "mismatch",
      ownRootHex: null, // no root computed — the sets differ in SIZE, which is decisive on its own
      detail: `leaf_count_disagrees: this daemon holds a provably complete ${carry.length}-leaf set, the certificate claims ${certifiedLeafCount}`,
    };
  }
  if (carryInputs === null) {
    // A leaf this daemon cannot decode is a leaf it cannot judge. Never an accusation.
    return { verdict: "cannot_judge", reason: "structure1_content_hash_unreadable" };
  }
  const ownRoot = merkleRoot(buildMerkleTree(carryInputs));
  const ownRootHex = Buffer.from(ownRoot).toString("hex");
  return Buffer.compare(Buffer.from(ownRoot), Buffer.from(certifiedRoot)) === 0
    ? { verdict: "match" }
    : { verdict: "mismatch", ownRootHex, detail: "root_disagrees: same leaf count, different leaves or different order" };
}

