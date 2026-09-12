/**
 * `DOD-M15-CARRIEDSEAL-1` — THE CLOSING LEAF THIS SIDE WRITES WHEN THERE IS NO RELAY LEFT TO ASK.
 *
 * ─── What this exists to fix ───────────────────────────────────────────────────────────────────
 *
 * A seal needed the relay alive, and for exactly one reason. Every message in a conversation is
 * countersigned by the relay when it is ordered and held by BOTH parties from that moment
 * (`069-ORDERPROOF`), so the record itself survives the relay being restarted, rolled or deleted.
 * What did not survive was the last line: the SEAL control leaf that ends the record was handed to
 * the relay for a sequence number like any other leaf, so a relay that was gone at close time cost
 * the conversation its receipt — a record that was fully witnessed, fully held, and unusable.
 *
 * This writes that one leaf here instead.
 *
 * ─── Why nothing is being taken on trust ───────────────────────────────────────────────────────
 *
 * The leaf invents no facts. **Every field is read out of the carry it closes over**, which is the
 * relay's own ordered log as both parties received it:
 *
 *   - **position** — one past the last carried leaf. Contiguity from 1 is checked first, so there is
 *     no position to choose.
 *   - **`prev_root`** — the RFC 6962 fold over the carried leaves in the Structure 2 domain. This is
 *     the value the directory's own chain walk arrives at when it reaches this leaf, so naming any
 *     other one breaks the walk rather than fooling it.
 *   - **`last_seen`** — the counterparty's newest carried leaf, sequence and content hash.
 *   - **`prev_own`** — this side's newest carried leaf.
 *   - **`final_root`** — the content-only root, which is what each party signs and what the
 *     counterparty's copy must agree with.
 *
 * So the only thing this side supplies that is genuinely its own is the CHOICE TO STOP HERE. That is
 * truncation, it is bounded by design, the counterparty refutes it from their own copy, and the work
 * order says in terms not to chase it.
 *
 * ⚠️ **THE RECEIPT FIELDS ARE ABSENT, AND ABSENT IS NOT THE SAME AS EMPTY.** A leaf carrying a blank
 * relay id would be CLAIMING a witness it cannot produce, and the directory judges that as a
 * malformed receipt — correctly, because missing and malformed must not be told apart. The
 * directory's exemption is for a terminal control leaf with no receipt AT ALL, so this writes none.
 *
 * Crypto refs: RFC 8032 (Ed25519, the sender signature), RFC 6962 §2.1 (the Merkle fold).
 */
import { createHash } from "node:crypto";
import { buildMerkleTree, merkleRoot, type LeafInput } from "@cello-protocol/crypto";
import {
  encodeSealPayload, encodeStructure1, encodeStructure2, decodeStructure1, SCAN_RESULT_SENTINEL,
} from "@cello-protocol/protocol-types";
import type { SealCarryLeaf } from "./session-seal-leaf-store.js";

/** The SEAL control leaf's kind byte — the same 0x02 the relay path hashes under. */
const LEAF_KIND_CTRL = 0x02;

export interface LocalSealTerminusInput {
  /** The relay's ordered log as this side holds it, ascending. Both parties' leaves. */
  carry: readonly SealCarryLeaf[];
  /** This agent's K_local pubkey, hex — who the terminus is authored by. */
  ownPubkeyHex: string;
  /** The same key as bytes, for the Structure 1 claim. */
  ownPubkey: Uint8Array;
  /** The RELAY session id the carried leaves are recorded under. */
  sessionIdBytes: Uint8Array;
  /** The session's agreed starting point — what both links fall back to before anyone has spoken. */
  genesis: Uint8Array;
  /** The content-only root this side signs, hex. */
  finalRootHex: string;
  closeTimestamp: number;
  sign: (bytes: Uint8Array) => Promise<Uint8Array>;
}

export type LocalSealTerminusResult =
  | { ok: true; leaf: SealCarryLeaf; payload: Uint8Array; contentHashHex: string }
  | { ok: false; reason: string };

/**
 * Refusals, and each one is a case where writing a leaf anyway would make things worse:
 *
 *   `seal_carry_empty`          nothing was ever witnessed, so there is no record to close.
 *   `seal_carry_noncontiguous`  a witnessed leaf never reached us; a terminus over a record with a
 *                               hole in it would be signing a history we know is not the history.
 *   `seal_carry_own_ctrl_present` we already closed. A SECOND control leaf from one party makes the
 *                               session unsealable by any directory, permanently — the caller must
 *                               reuse the one that is there, never add to it.
 *   `seal_carry_unreadable`     a leaf this daemon cannot decode is one it cannot chain onto.
 */
export async function buildLocalSealTerminus(
  input: LocalSealTerminusInput,
): Promise<LocalSealTerminusResult> {
  const { carry, ownPubkeyHex, sessionIdBytes, genesis, finalRootHex, closeTimestamp, sign } = input;

  if (carry.length === 0) return { ok: false, reason: "seal_carry_empty" };
  // Ascending and exactly 1..N. Sorted rather than assumed: the store returns rows ordered, and a
  // terminus that trusted that ordering would be depending on a detail of a query it does not own.
  const ordered = [...carry].sort((a, b) => a.sequenceNumber - b.sequenceNumber);
  for (let i = 0; i < ordered.length; i++) {
    if (ordered[i]!.sequenceNumber !== i + 1) return { ok: false, reason: "seal_carry_noncontiguous" };
  }
  if (ordered.some((l) => l.leafKind === LEAF_KIND_CTRL && l.senderPubkeyHex === ownPubkeyHex)) {
    return { ok: false, reason: "seal_carry_own_ctrl_present" };
  }

  // ── The links, read out of the leaves each party actually authored ──
  // `ordered` is ascending, so the LAST match in each direction is that party's newest leaf. A
  // decode failure anywhere refuses: this side cannot honestly say what it has seen if it cannot
  // read what it holds.
  let lastSeenSeq = 0;
  let lastSeenHash = genesis;
  let prevOwnHash = genesis;
  for (const leaf of ordered) {
    const s1 = decodeStructure1(leaf.structure1Cbor);
    if (!s1.ok) return { ok: false, reason: "seal_carry_unreadable" };
    if (leaf.senderPubkeyHex === ownPubkeyHex) {
      prevOwnHash = s1.fields.contentHash;
    } else {
      lastSeenSeq = leaf.sequenceNumber;
      lastSeenHash = s1.fields.contentHash;
    }
  }

  /**
   * The prefix root, in the STRUCTURE 2 domain — which is not the domain the certified root lives
   * in, and conflating the two is the easiest mistake available here. `prev_root` is checked by the
   * directory's incremental walk over `leafHashFor(kind, encodeStructure2(s2))`; the certified root
   * is the fold over raw content hashes. Same leaves, different pre-images, different values.
   */
  const prefixInputs: LeafInput[] = ordered.map((l) => ({
    kind: l.leafKind === LEAF_KIND_CTRL ? "ctrl" : "msg",
    data: l.structure2Cbor,
  }));
  const prevRoot = merkleRoot(buildMerkleTree(prefixInputs));

  // The payload and its hash come from ONE derivation, deliberately. When they diverge the directory
  // answers `seal_payload_unbound`, whose guidance accuses the relay of altering bytes — a correct
  // relay named as an attacker for a mismatch made on this machine.
  const payload = encodeSealPayload({
    session_id: sessionIdBytes,
    final_root: new Uint8Array(Buffer.from(finalRootHex, "hex")),
    close_timestamp: closeTimestamp,
    attestation: "PENDING",
  });
  const contentHash = new Uint8Array(
    createHash("sha256").update(new Uint8Array([LEAF_KIND_CTRL])).update(payload).digest(),
  );

  const structure1Cbor = encodeStructure1({
    contentHash,
    senderPubkey: input.ownPubkey,
    sessionId: sessionIdBytes,
    lastSeenSeq,
    timestamp: closeTimestamp,
    lastSeenHash,
    prevOwnHash,
  });
  const senderSignature = await sign(structure1Cbor);

  const sequenceNumber = ordered.length + 1;
  const structure2Cbor = encodeStructure2({
    sequence_number: sequenceNumber,
    sender_pubkey: input.ownPubkey,
    content_hash: contentHash,
    sender_signature: senderSignature,
    scan_result: SCAN_RESULT_SENTINEL,
    prev_root: prevRoot,
  });

  return {
    ok: true,
    payload,
    contentHashHex: Buffer.from(contentHash).toString("hex"),
    // No relay fields. See the header — absent, never blank.
    leaf: {
      sequenceNumber,
      leafKind: LEAF_KIND_CTRL,
      senderPubkeyHex: ownPubkeyHex,
      structure2Cbor,
      structure1Cbor,
    },
  };
}
