/**
 * CELLO-M7 — canonical hash of the seal-certificate legibility object, for binding it into
 * the FROST-signed seal TBS (tamper-evidence). MUST stay byte-for-byte identical to the
 * directory's copy (`trustless-cello/packages/directory/src/seal-legibility.ts`
 * canonicalLegibilityHash) — the live bilateral seal SELF-CHECKS agreement: directory and
 * daemon each fold this hash into the signed TBS, and the seal verifies only if they match.
 *
 * Design: an EXPLICIT, fixed byte layout (NOT canonical CBOR) so there is zero dependence on
 * a CBOR library's determinism. Only the TAMPERABLE facts are bound — the per-party frontiers
 * + attestation_mode and the final_message. The constants (attests / implies_assent /
 * disclaimer) are NOT bound: the daemon re-asserts attests/implies_assent as literals on the
 * read surface, so they cannot be meaningfully tampered; the disclaimer is informational.
 *
 * Hash = SHA-256( domain || u32(participantCount) ||
 *   for each participant (in array order): pubkey[32] || u32(content_frontier_seq) ||
 *     u32(last_authored_seq) || modeByte ||
 *   final_message.sender_pubkey[32] || u32(seq) || answeredByte )
 *
 * Participants are hashed in array order, so a MITM that REORDERS the participants array also
 * changes the hash → the seal signature fails. Crypto ref: SHA-256 FIPS 180-4.
 */
import { createHash } from "node:crypto";

/** The legibility shape this hash reads — pubkeys may be Uint8Array or Buffer (CBOR-decoded). */
export interface LegibilityForHash {
  participants: Array<{
    pubkey: unknown;
    content_frontier_seq: unknown;
    last_authored_seq: unknown;
    attestation_mode: unknown;
  }>;
  final_message: {
    sender_pubkey: unknown;
    seq: unknown;
    answered: unknown;
  };
}

const DOMAIN = Buffer.from("CELLO-SEAL-LEGIBILITY-v1", "utf8");

/** Coerce any byte-ish value to a 32-byte Buffer (zero-padded/truncated). Both sides do this. */
function pubkey32(v: unknown): Buffer {
  const out = Buffer.alloc(32);
  if (v instanceof Uint8Array) Buffer.from(v).copy(out, 0, 0, 32);
  else if (Buffer.isBuffer(v)) (v as Buffer).copy(out, 0, 0, 32);
  else if (typeof v === "string" && /^[0-9a-fA-F]{64}$/.test(v)) Buffer.from(v, "hex").copy(out, 0, 0, 32);
  return out;
}

/** Coerce to uint32 the SAME way on both sides (handles bigint/number; >>>0 normalises). */
function u32(v: unknown): Buffer {
  const n = typeof v === "bigint" ? Number(v) : typeof v === "number" ? v : 0;
  const out = Buffer.alloc(4);
  out.writeUInt32BE((n >>> 0), 0);
  return out;
}

function modeByte(v: unknown): Buffer {
  const b = v === "live" ? 1 : v === "recovered" ? 2 : v === "absent" ? 3 : 0;
  return Buffer.from([b]);
}

export function canonicalLegibilityBytes(legibility: LegibilityForHash): Buffer {
  const parts: Buffer[] = [DOMAIN];
  const participants = Array.isArray(legibility.participants) ? legibility.participants : [];
  const count = Buffer.alloc(4);
  count.writeUInt32BE(participants.length >>> 0, 0);
  parts.push(count);
  for (const p of participants) {
    parts.push(pubkey32(p.pubkey), u32(p.content_frontier_seq), u32(p.last_authored_seq), modeByte(p.attestation_mode));
  }
  const fm = legibility.final_message ?? { sender_pubkey: undefined, seq: 0, answered: false };
  parts.push(pubkey32(fm.sender_pubkey), u32(fm.seq), Buffer.from([fm.answered === true ? 1 : 0]));
  return Buffer.concat(parts);
}

/** SHA-256 of the canonical legibility bytes (32 bytes). */
export function canonicalLegibilityHash(legibility: LegibilityForHash): Uint8Array {
  return new Uint8Array(createHash("sha256").update(canonicalLegibilityBytes(legibility)).digest());
}

/**
 * Build the seal TBS bytes WITH the legibility binding: the plain seal TBS concatenated with
 * the 32-byte legibility hash. When `legibility` is absent (the unilateral seal carries none),
 * returns the plain TBS unchanged — so the unilateral path keeps signing/verifying the plain TBS
 * and only the bilateral path (which always carries legibility) is bound.
 */
export function bindLegibilityToTbs(tbs: Uint8Array, legibility: LegibilityForHash | null | undefined): Uint8Array {
  if (!legibility) return tbs;
  const h = canonicalLegibilityHash(legibility);
  const out = new Uint8Array(tbs.length + h.length);
  out.set(tbs, 0);
  out.set(h, tbs.length);
  return out;
}
