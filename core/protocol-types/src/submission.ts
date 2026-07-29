/**
 * M10B / DOD-END-SUBMIT-1 — the sealed submission wire contract (M10B-D2, D-20, D-28, D-31).
 *
 * The client-supplied source's only wire shape. Bob's daemon builds a body, signs the canonical TBS
 * with his agent's K_local, and seals the encoded pair to the portal's intake key; the directory
 * carries the ciphertext without being able to read it; the portal opens it, verifies, and mints.
 *
 * IT LIVES HERE, NOT IN THE DAEMON, AND THAT IS LOAD-BEARING. Three parties rebuild these bytes
 * independently — the daemon signing, the portal verifying, the portal re-deriving `submission_id`
 * to dedupe a retry. A byte-identical local copy on each side is exactly how two implementations
 * drift apart, and the failure it produces is a signature that will not verify, which reads as a bad
 * key rather than as an encoder disagreement (M10B-D28).
 *
 * THE TBS IS AN ARRAY, NOT A MAP. `cbor.ts` is not deterministic for maps — keys follow insertion
 * order and map headers are not minimal-length — so two parties building the same map in a different
 * field order produce different bytes. Every signed structure in CELLO is a fixed-order array for
 * this reason (`buildAgentRevocationTbs`, `buildPrimaryTransferTbs`, `buildSealTbs`).
 *
 * FIELD ORDER IS THE WIRE FORMAT and the field set is CLOSED. Reordering is a breaking signature
 * change, not a refactor; an unknown field is REJECTED rather than ignored, because silently
 * dropping it would let two parties who disagree about the field set still agree on the signature —
 * making the extra field unauthenticated data riding inside a "verified" submission (spec §4).
 *
 * WHAT IS *NOT* HERE: nothing that names a signal TYPE. The discriminator is `op` — a protocol verb
 * the directory already branches on — and `subject_kind`, which is envelope data. A second
 * client-sourced type sends this identical structure (INV-ZEROBUMP).
 *
 * Crypto: Ed25519 → RFC 8032, CBOR → RFC 8949, SHA-256 → FIPS 180-4.
 */

import { hash as sha256 } from "@cello-protocol/crypto";
import { encodeCbor, decodeCbor } from "./cbor.js";
import type { SignalSubjectKind } from "./trust-signal.js";

/** Domain separation, bound as element 0 — the house convention. Distinct from `CELLO-TSIG-v1` (the
 *  envelope preimage) and `CELLO-TSIG-REQ-v1` (the directory's request TBS), so a signature over one
 *  can never be replayed as another. */
export const SUBMISSION_DOMAIN = "CELLO-SUBMIT-v1";

/**
 * What the submitter is ASKING FOR — an operation, never a signal type (M10B-D28).
 *
 * `signal-write.ts` already discriminates its request bodies this way, and the distinction matters
 * for INV-ZEROBUMP: branching on what a signal *means* is forbidden; branching on what the caller is
 * *asking for* is what a protocol verb is. It rides INSIDE the seal, so the directory still cannot
 * tell a withdrawal from an endorsement.
 *
 * `refuse` (M10B-D4) carries the SUBJECT's optional message back to the issuer after she refuses an
 * endorsement about her. It is a third verb rather than a new structure, and widening this union
 * changes no field and no order — so every signature already made over a `submit` or `withdraw`
 * body still verifies. For `refuse` and `withdraw` alike, `subject` is the TARGET SIGNAL HASH: both
 * act on an existing signal instead of asserting a fact about a party.
 */
export type SubmissionOp = "submit" | "withdraw" | "refuse";

/** The number of elements in the TBS array, INCLUDING the domain tag. Bump only with the wire. */
const TBS_ARITY = 8;
/** The encoded submission is the TBS fields plus the detached signature. */
const ENCODED_ARITY = TBS_ARITY + 1;

/**
 * The signed part of a submission. Every field is inside the TBS — a field outside it is
 * unauthenticated data an attacker can edit in flight while the signature still verifies.
 */
export interface SubmissionBody {
  /** Wire version. Signed, so it cannot be downgraded in flight. */
  v: number;
  op: SubmissionOp;
  /** Whose fact this is. The portal resolves an agent subject to an account when it needs one — no
   *  account identifier ever crosses the wire (the directory is hash-only by design). */
  subject_kind: SignalSubjectKind;
  /** For `subject_kind: "agent"`, the subject's K_local pubkey hex — the only identifier a contact
   *  actually holds. For a withdrawal, the target signal hash. */
  subject: string;
  /**
   * The submitter's K_local pubkey hex.
   *
   * **This field is worthless until the signature verifies against it, and it must never be read for
   * any other purpose.** Ed25519 has no key recovery (RFC 8032), so "derive `issuer_pubkey` from the
   * signature" cannot mean literal recovery — it means the pubkey is present but carries no
   * authority on its own. A body claiming P together with a valid signature by P proves possession
   * of P's private key; a body claiming P with any other signature proves nothing and must be
   * refused. Reading it before verification is the INV-ATTRIBUTION defect: anyone could mint an
   * endorsement attributed to anyone, permanently, inside the hash.
   */
  submitter_pubkey: string;
  /** The operator's own words, untrusted and unscanned at this layer. Scanned at intake, BEFORE
   *  hashing (spec §6), and never restated in the portal's attested voice (INV-UNTRUSTED). */
  body: string;
  /** Integer epoch SECONDS. Inside the TBS, so the verifier's clock-skew bound applies — without it
   *  a signature is a permanent bearer capability replayable at every node forever (M10B-D28). */
  issued_at: number;
}

/** A decoded submission: the body as signed, plus the detached signature over its TBS. */
export interface SignedSubmission {
  body: SubmissionBody;
  signature: Uint8Array;
}

/**
 * Canonical to-be-signed bytes. Field order is LOAD-BEARING — the daemon signing and the portal
 * verifying must produce identical bytes, across two repos, forever.
 */
export function buildSubmissionTbs(body: SubmissionBody): Uint8Array {
  return encodeCbor([
    SUBMISSION_DOMAIN,
    body.v,
    body.op,
    body.subject_kind,
    body.subject,
    body.submitter_pubkey,
    body.body,
    body.issued_at,
  ]);
}

/** The sealed plaintext: the TBS fields followed by the detached signature. */
export function encodeSubmission(body: SubmissionBody, signature: Uint8Array): Uint8Array {
  return encodeCbor([
    SUBMISSION_DOMAIN,
    body.v,
    body.op,
    body.subject_kind,
    body.subject,
    body.submitter_pubkey,
    body.body,
    body.issued_at,
    signature,
  ]);
}

function str(v: unknown, field: string): string {
  if (typeof v !== "string") throw new Error(`submission_malformed: ${field} must be a string`);
  return v;
}

function int(v: unknown, field: string): number {
  const n = typeof v === "bigint" ? Number(v) : v;
  if (typeof n !== "number" || !Number.isInteger(n)) {
    throw new Error(`submission_malformed: ${field} must be an integer`);
  }
  return n;
}

/**
 * Decode a sealed submission's plaintext.
 *
 * THROWS on anything it does not fully recognise, and that is the design. A submission that cannot
 * be decoded is POISON — the identity is derived from the signature, so an unparseable body has no
 * known sender and there is nobody to reply to (M10B-D22b). The failure must therefore be loud
 * HERE, not a partly-populated body that flows onward and gets attributed to whatever
 * `submitter_pubkey` happened to decode as.
 */
export function decodeSubmission(bytes: Uint8Array): SignedSubmission {
  let decoded: unknown;
  try {
    decoded = decodeCbor(bytes);
  } catch (err: unknown) {
    throw new Error(`submission_malformed: not valid CBOR: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (!Array.isArray(decoded)) throw new Error("submission_malformed: expected an array");
  if (decoded.length !== ENCODED_ARITY) {
    // Closed field set: a longer array is an unknown field, a shorter one is a missing field, and
    // both must refuse rather than be read positionally into the wrong slots.
    throw new Error(`submission_malformed: expected ${ENCODED_ARITY} elements, got ${decoded.length}`);
  }
  if (decoded[0] !== SUBMISSION_DOMAIN) {
    throw new Error(`submission_malformed: wrong domain tag — refusing to read a foreign structure`);
  }
  const op = str(decoded[2], "op");
  if (op !== "submit" && op !== "withdraw" && op !== "refuse") {
    throw new Error(`submission_malformed: unknown op '${op}'`);
  }
  const subjectKind = str(decoded[3], "subject_kind");
  if (subjectKind !== "agent" && subjectKind !== "account") {
    throw new Error(`submission_malformed: unknown subject_kind '${subjectKind}'`);
  }
  const signature = decoded[8];
  if (!(signature instanceof Uint8Array)) {
    throw new Error("submission_malformed: signature must be bytes");
  }
  // The CBOR decoder hands back a Node `Buffer` (a Uint8Array SUBCLASS). Normalise it, so the
  // declared type is the actual type: a caller that received a Buffer here could come to depend on
  // Buffer-only methods, and the same code would then break in any runtime whose decoder returns a
  // plain view. Copying 64 bytes is not a cost worth trading that for.
  const signatureBytes = new Uint8Array(signature);
  return {
    body: {
      v: int(decoded[1], "v"),
      op,
      subject_kind: subjectKind,
      subject: str(decoded[4], "subject"),
      submitter_pubkey: str(decoded[5], "submitter_pubkey"),
      body: str(decoded[6], "body"),
      issued_at: int(decoded[7], "issued_at"),
    },
    signature: signatureBytes,
  };
}

/**
 * `submission_id` — sha256 over the ENCODED signed submission (M10B-D20), lowercase hex.
 *
 * Content-derived, which is what makes retry-across-nodes safe rather than a duplication mechanism:
 * a daemon that fails over to a second node produces the same id, so the second row is a strict
 * no-op. A legitimate re-issue after a refusal differs, because `issued_at` is inside the signed
 * body — otherwise the portal would dedupe Bob's correction away as a retry and Alice would never
 * see it.
 *
 * **At the directory this id is a ROUTING HINT and nothing more.** The directory cannot open the
 * seal, so it cannot check that the id matches the bytes; the portal re-derives it from the opened
 * body and discards any row whose id disagrees. A daemon writing the same body under two different
 * ids to two nodes would otherwise get two mints and double quota consumption (M10B-D20's
 * second-review correction).
 */
export function submissionId(encodedSubmission: Uint8Array): string {
  return Buffer.from(sha256(encodedSubmission)).toString("hex");
}
