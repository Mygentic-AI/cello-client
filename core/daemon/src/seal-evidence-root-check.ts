/**
 * CO-SIGN A ROOT FROM THE DIRECTORY'S EVIDENCE WHEN THIS SIDE'S OWN CARRY IS SHORT — and only when the
 * evidence proves itself.
 *
 * ─── The failure this exists for ───────────────────────────────────────────────────────────────
 *
 * Live 2026-09-16, session `9bcfc168…`. A daemon restarted mid-conversation. Its session identity
 * was gone, so for the rest of the session the relay refused its connection `not_a_participant` — it
 * could still SEND its seal leaf, but it could never RECEIVE the counterparty's. Asked to co-sign, it
 * held 1 of 2 SEAL leaves, `verifyCertifiedRoot` answered `cannot_judge`, and it correctly refused.
 * No co-signature, so no certificate was ever stored — on any directory node — and nobody was told.
 *
 * The leaf it was missing was sitting in the request it was refusing. `seal_verified` carries
 * `frontier_leaves`: the whole ordered leaf set the directory rebuilt the root from, each with its
 * sender's signature. So this side does not need the stream it lost. It needs to check that evidence.
 *
 * ─── What must hold before signing, and why each one ──────────────────────────────────────────
 *
 * The directory is NOT trusted for any of this. Signing puts this agent's key on a durable,
 * non-repudiable claim, so every condition is checked here against something the directory cannot
 * forge:
 *
 *   1. EVERY LEAF THIS SIDE ALREADY HOLDS APPEARS IN THE EVIDENCE, AT THE SAME POSITION, WITH THE SAME
 *      CONTENT HASH. The evidence may FILL gaps; it may never override a leaf this side witnessed. A
 *      contradiction here is an accusation, not a gap — `mismatch`.
 *   2. EVERY EVIDENCE LEAF IS SIGNED BY A PARTICIPANT OF THIS SESSION, FOR THIS SESSION. The
 *      participants come from THIS side's own session record, never from the frame — the frame is the
 *      thing being checked. The signature is verified over the exact Structure 1 bytes, the signer is
 *      the key named inside them, and the session id inside them is this one.
 *   3. THE EVIDENCE HASHES TO THE CERTIFIED ROOT, AND ITS SIZE IS THE CERTIFIED COUNT. Both are
 *      recomputed here.
 *
 * With all three, the root this side signs is over a leaf set that agrees with everything it saw,
 * whose remaining leaves the participants themselves signed, and which the certificate describes.
 *
 * ─── What this deliberately does NOT establish ─────────────────────────────────────────────────
 *
 * The ORDER of leaves this side never held rests on the directory's rebuild, not on this side's own
 * witness. Every leaf this side DID hold is pinned to its position; a gap could in principle be filled
 * in a different order. The participants' own signed approvals — carried on their SEAL leaves and
 * checked by every co-signing directory under DOD-M15-SEALPARTIES-1 — are what bound that, not this
 * file. Saying so rather than implying a stronger property than the code has.
 *
 * Crypto refs: RFC 8032 (Ed25519 signature verification), RFC 6962 §2.1 (Merkle hash trees).
 */
import { buildMerkleTree, merkleRoot, verify } from "@cello-protocol/crypto";
import { decodeStructure1 } from "@cello-protocol/protocol-types";
import type { SealCarryLeaf } from "./session-seal-leaf-store.js";

export interface EvidenceLeaf {
  structure1_cbor: Uint8Array;
  sender_pubkey: Uint8Array;
  sender_signature: Uint8Array;
}

export type EvidenceVerdict =
  | { verdict: "match"; filled: number }
  | { verdict: "mismatch"; detail: string }
  | { verdict: "cannot_judge"; reason: string };

/** Read one `frontier_leaves` entry off the wire, or null if it is not the three byte fields it must be. */
export function parseEvidenceLeaf(raw: unknown): EvidenceLeaf | null {
  if (typeof raw !== "object" || raw === null) return null;
  const o = raw as Record<string, unknown>;
  const bytes = (v: unknown): Uint8Array | null =>
    v instanceof Uint8Array ? v : Array.isArray(v) ? Uint8Array.from(v as number[]) : null;
  const s1 = bytes(o["structure1_cbor"]);
  const pk = bytes(o["sender_pubkey"]);
  const sig = bytes(o["sender_signature"]);
  return s1 && pk && sig ? { structure1_cbor: s1, sender_pubkey: pk, sender_signature: sig } : null;
}

export function verifyCertifiedRootFromEvidence(args: {
  /** This side's own witnessed leaves — the ones the evidence may never contradict. */
  ownCarry: readonly SealCarryLeaf[];
  /** The ordered leaf set from `seal_verified`, raw off the wire. */
  evidence: readonly unknown[];
  sessionIdHex: string;
  /** Both participants' pubkeys, hex, from THIS side's session record. */
  participantsHex: readonly string[];
  certifiedRoot: Uint8Array;
  certifiedLeafCount: number;
}): EvidenceVerdict {
  const { ownCarry, evidence, sessionIdHex, participantsHex, certifiedRoot, certifiedLeafCount } = args;
  if (participantsHex.length !== 2) return { verdict: "cannot_judge", reason: "participants_unknown" };
  if (evidence.length === 0) return { verdict: "cannot_judge", reason: "no_evidence" };
  if (evidence.length !== certifiedLeafCount) {
    return { verdict: "mismatch", detail: `evidence_size_disagrees: ${evidence.length} leaves, certificate claims ${certifiedLeafCount}` };
  }

  const participants = new Set(participantsHex.map((p) => p.toLowerCase()));
  const hashes: Uint8Array[] = [];
  for (let i = 0; i < evidence.length; i++) {
    const leaf = parseEvidenceLeaf(evidence[i]);
    if (!leaf) return { verdict: "cannot_judge", reason: `evidence_leaf_malformed: position ${i + 1}` };
    const senderHex = Buffer.from(leaf.sender_pubkey).toString("hex");
    // 2. A participant of THIS session — named by our own record, not by the frame.
    if (!participants.has(senderHex)) {
      return { verdict: "mismatch", detail: `evidence_sender_not_a_participant: position ${i + 1}` };
    }
    if (!verify(leaf.sender_pubkey, leaf.structure1_cbor, leaf.sender_signature)) {
      return { verdict: "mismatch", detail: `evidence_signature_invalid: position ${i + 1}` };
    }
    const s1 = decodeStructure1(leaf.structure1_cbor);
    if (!s1.ok) return { verdict: "cannot_judge", reason: `evidence_structure1_undecodable: position ${i + 1}` };
    // The key that signed must be the key the claim names, and the claim must be for THIS session. A
    // valid signature over a claim for another conversation authorises nothing here.
    if (Buffer.from(s1.fields.senderPubkey).toString("hex") !== senderHex) {
      return { verdict: "mismatch", detail: `evidence_signer_is_not_the_named_sender: position ${i + 1}` };
    }
    if (Buffer.from(s1.fields.sessionId).toString("hex") !== sessionIdHex.toLowerCase()) {
      return { verdict: "mismatch", detail: `evidence_leaf_is_for_another_session: position ${i + 1}` };
    }
    hashes.push(s1.fields.contentHash);
  }

  // 1. The evidence may fill gaps; it may never override what this side witnessed.
  let held = 0;
  for (const own of ownCarry) {
    const s1 = decodeStructure1(own.structure1Cbor);
    if (!s1.ok) return { verdict: "cannot_judge", reason: `own_leaf_undecodable: sequence ${own.sequenceNumber}` };
    const at = hashes[own.sequenceNumber - 1];
    if (at === undefined || Buffer.compare(Buffer.from(at), Buffer.from(s1.fields.contentHash)) !== 0) {
      return { verdict: "mismatch", detail: `evidence_contradicts_own_leaf: sequence ${own.sequenceNumber}` };
    }
    held += 1;
  }

  // 3. The certificate describes exactly this set.
  const root = merkleRoot(buildMerkleTree(hashes.map((data) => ({ kind: "hash" as const, data }))));
  if (Buffer.compare(Buffer.from(root), Buffer.from(certifiedRoot)) !== 0) {
    return { verdict: "mismatch", detail: "evidence_root_disagrees: the evidence does not hash to the certified root" };
  }
  return { verdict: "match", filled: evidence.length - held };
}

/**
 * The daemon's entry point: consult the evidence for a seal this side's own carry could not judge,
 * reading the participants from THIS side's session row.
 *
 * Lives here rather than in `session-seal.ts` so the whole decision — where the participants come
 * from, what is logged, what each verdict becomes — sits beside the rules it applies.
 */
export function judgeFromEvidence(
  deps: {
    ownCarry: readonly SealCarryLeaf[];
    db: { prepare(sql: string): { get(...params: unknown[]): unknown } } | null;
    logger: { info(event: string, fields: Record<string, unknown>): void };
  },
  a: {
    ownReason: string;
    agentPubkeyHex: string;
    sessionIdHex: string;
    certifiedRoot: Uint8Array;
    certifiedLeafCount: number;
    evidence: readonly unknown[];
  },
): { verdict: "match" } | { verdict: "mismatch"; ownRootHex: string | null; detail: string } | { verdict: "cannot_judge"; reason: string } {
  const checked = verifyCertifiedRootFromEvidence({
    ownCarry: deps.ownCarry, evidence: a.evidence, sessionIdHex: a.sessionIdHex,
    participantsHex: participantsFromRecord(deps.db, a.agentPubkeyHex, a.sessionIdHex),
    certifiedRoot: a.certifiedRoot, certifiedLeafCount: a.certifiedLeafCount,
  });
  if (checked.verdict === "match") {
    deps.logger.info("session.seal.carry.completed_from_evidence", {
      sessionId: a.sessionIdHex, filled: checked.filled, ownVerdict: a.ownReason,
      impact: "this side was missing leaves it never received; the co-sign request's own signed evidence filled them, agreed with every leaf this side held, and hashed to the certified root",
    });
    return { verdict: "match" };
  }
  return checked.verdict === "mismatch"
    ? { verdict: "mismatch", ownRootHex: null, detail: checked.detail }
    : { verdict: "cannot_judge", reason: `${a.ownReason}; evidence: ${checked.reason}` };
}

/**
 * Both participants of a session, from THIS side's own record — never from a frame, because the
 * frame is what is being checked. Empty when the record is missing, which the verifier refuses on.
 */
function participantsFromRecord(
  db: { prepare(sql: string): { get(...params: unknown[]): unknown } } | null,
  agentPubkeyHex: string,
  sessionIdHex: string,
): string[] {
  if (!db) return [];
  const row = db
    .prepare("SELECT s.counterparty_pubkey AS cp FROM sessions s JOIN agents a ON a.agent_id = s.agent_id WHERE a.k_local_pubkey = ? AND s.session_id = ?")
    .get(agentPubkeyHex, sessionIdHex) as { cp: string } | undefined;
  return row ? [agentPubkeyHex.toLowerCase(), row.cp.toLowerCase()] : [];
}
