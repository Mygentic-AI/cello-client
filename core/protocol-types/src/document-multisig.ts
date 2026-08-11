/**
 * DOD-MP-SIG-1 — the multi-signature primitive: N Ed25519 signatures over ONE preimage.
 *
 * A collection is COMPLETE only when every signer in the required set has a verifying signature —
 * no more, no fewer, no substitutes. Anything short of that is a partial collection: storable
 * while signatures are being gathered, never valid. Completeness is computed independently by any
 * holder from the collection alone plus a verifier; there is no coordinator whose word settles it.
 *
 * ── GENERIC BY CONSTRUCTION ───────────────────────────────────────────────────────────────────
 *
 * Nothing in this module knows what an amendment is. The subject is carried as
 * `(subject_kind, subject_hash)` — the hash of the subject's OWN to-be-signed structure — so the
 * amendment record (its first consumer) and Tier 2's N-way quiescence agreement (its named second)
 * use the same preimage builder and the same completeness rule. Anything subject-specific growing
 * in here is the drift the M14B Tier-2-readiness lens blocks.
 *
 * ── THE PREIMAGE COMMITS TO WHO MUST SIGN ─────────────────────────────────────────────────────
 *
 * `required_signers` is inside the signed bytes, sorted so the set — not the order it was typed
 * in — is what is committed. Each signer therefore signs knowing exactly which co-signatures the
 * collection needs: a signature given as "the sole required signer" cannot be replayed into a
 * collection claiming a different signer set, because the preimage differs and the signature
 * stops verifying. Replay across chain positions is the SUBJECT's job to prevent (its TBS chains
 * to its predecessor), not this layer's.
 *
 * Signatures are Ed25519 (RFC 8032) over the SHA-256 of the preimage array, matching the sibling
 * envelope builders. Verification is injected — the same seam the proposal path uses — so this
 * module stays pure types + bytes.
 */

import { createHash } from "node:crypto";
import { encodeCbor, decodeCbor } from "./cbor.js";

/** Domain tag in slot 0 of the to-be-signed array. Distinct from every sibling envelope domain. */
export const DOCUMENT_MULTISIG_DOMAIN = "CELLO-DOCUMENT-MULTISIG-v1";

/** The fields the preimage commits to. `signatures` is deliberately NOT part of the TBS. */
export interface MultisigSubject {
  document_id: string;
  /** What kind of thing is being co-signed, e.g. "document_amendment". Open set on purpose. */
  subject_kind: string;
  /** SHA-256 of the subject's own to-be-signed structure. */
  subject_hash: Uint8Array;
  /** Pubkey-hex identities that must ALL sign. Committed as a sorted set. */
  required_signers: readonly string[];
}

export interface MultisigSignature {
  signer_agent_id: string;
  /** Ed25519 (RFC 8032) over `buildDocumentMultisigTbs` of the subject fields. */
  signature: Uint8Array;
}

export interface MultisigCollection extends MultisigSubject {
  required_signers: string[];
  signatures: MultisigSignature[];
}

/**
 * The signer set, validated and canonicalized: non-empty, no duplicates, sorted.
 *
 * Duplicates are REFUSED rather than deduped — a duplicate in a required set is a builder bug,
 * and silently collapsing it would change the preimage under a caller who believes they know
 * what they asked N parties to sign.
 */
function canonicalSigners(signers: readonly string[]): string[] {
  if (signers.length === 0) {
    throw new Error(
      "multisig_empty_signer_set: a collection nobody is required to sign is not a rule — " +
        "the required set must name at least one signer",
    );
  }
  const sorted = [...signers].sort();
  for (let i = 1; i < sorted.length; i++) {
    if (sorted[i] === sorted[i - 1]) {
      throw new Error(
        `multisig_duplicate_signer: ${sorted[i]} appears more than once in the required set`,
      );
    }
  }
  for (const s of sorted) {
    if (typeof s !== "string" || s.length === 0) {
      throw new Error("multisig_signer_type: every required signer must be a non-empty string");
    }
  }
  return sorted;
}

/**
 * The canonical to-be-signed preimage: a fixed-order CBOR ARRAY with the domain in slot 0.
 * SHA-256 pre-hashed by default, matching the sibling builders.
 */
export function buildDocumentMultisigTbs(
  subject: MultisigSubject,
  opts: { preHash?: boolean } = {},
): Uint8Array {
  const preimage = encodeCbor([
    DOCUMENT_MULTISIG_DOMAIN,
    subject.document_id,
    subject.subject_kind,
    subject.subject_hash,
    canonicalSigners(subject.required_signers),
  ]);
  if (opts.preHash === false) return preimage;
  return new Uint8Array(createHash("sha256").update(preimage).digest());
}

export interface MultisigStatus {
  /** True only when every required signer has exactly one verifying signature and nobody else signed. */
  complete: boolean;
  /** Required signers with no signature present. */
  missing: string[];
  /** Signers present whose signature does not verify against the preimage. */
  invalidSigners: string[];
  /** Signatures from identities OUTSIDE the required set — never counted, always named. */
  unknown: string[];
  /** Signers with more than one signature row — settle once. */
  duplicates: string[];
}

/**
 * Completeness, computed from the collection alone plus an injected verifier.
 *
 * Every defect class is NAMED rather than folded into a boolean, because the operator-facing
 * question differs: "waiting on C" (missing), "B's signature is bad" (invalid), "someone outside
 * the arrangement signed" (unknown — refused because extra names must not make a collection look
 * more agreed than the rule it commits to), and "B signed twice" (duplicate).
 */
export function collectionStatus(
  collection: MultisigCollection,
  verify: (agentId: string, tbs: Uint8Array, signature: Uint8Array) => boolean,
): MultisigStatus {
  const required = new Set(canonicalSigners(collection.required_signers));
  const tbs = buildDocumentMultisigTbs(collection);

  const seen = new Set<string>();
  const invalidSigners: string[] = [];
  const unknown: string[] = [];
  const duplicates: string[] = [];

  for (const { signer_agent_id, signature } of collection.signatures) {
    if (seen.has(signer_agent_id)) {
      duplicates.push(signer_agent_id);
      continue;
    }
    seen.add(signer_agent_id);
    if (!required.has(signer_agent_id)) {
      unknown.push(signer_agent_id);
      continue;
    }
    if (!verify(signer_agent_id, tbs, signature)) {
      invalidSigners.push(signer_agent_id);
    }
  }

  const missing = [...required].filter(
    (id) => !seen.has(id) || invalidSigners.includes(id),
  );
  // A signer whose signature failed is INVALID, not missing — the two send the operator to
  // different fixes — so the missing list excludes them again after the filter above.
  const trulyMissing = missing.filter((id) => !invalidSigners.includes(id));

  return {
    complete:
      trulyMissing.length === 0 &&
      invalidSigners.length === 0 &&
      unknown.length === 0 &&
      duplicates.length === 0,
    missing: trulyMissing,
    invalidSigners,
    unknown,
    duplicates,
  };
}

export function encodeMultisigCollection(collection: MultisigCollection): Uint8Array {
  return encodeCbor({
    document_id: collection.document_id,
    subject_kind: collection.subject_kind,
    subject_hash: collection.subject_hash,
    required_signers: canonicalSigners(collection.required_signers),
    signatures: collection.signatures.map((s) => ({
      signer_agent_id: s.signer_agent_id,
      signature: s.signature,
    })),
  });
}

function present(map: Record<string, unknown>, field: string): unknown {
  if (!(field in map)) {
    throw new Error(`multisig_missing_field: ${field} is mandatory and was not present`);
  }
  return map[field];
}

function str(map: Record<string, unknown>, field: string): string {
  const v = present(map, field);
  if (typeof v !== "string" || v.length === 0) {
    throw new Error(`multisig_field_type: ${field} must be a non-empty text string`);
  }
  return v;
}

function bytes(map: Record<string, unknown>, field: string): Uint8Array {
  const v = present(map, field);
  if (!(v instanceof Uint8Array)) {
    throw new Error(`multisig_field_type: ${field} must be a CBOR byte string`);
  }
  // Copied — cbor-x returns views into the decoded buffer.
  return new Uint8Array(v);
}

export function decodeMultisigCollection(input: Uint8Array): MultisigCollection {
  const decoded = decodeCbor(input);
  if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) {
    throw new Error("multisig_malformed: not a CBOR map");
  }
  const map = decoded as Record<string, unknown>;

  const rawSigners = present(map, "required_signers");
  if (!Array.isArray(rawSigners) || rawSigners.some((s) => typeof s !== "string")) {
    throw new Error("multisig_field_type: required_signers must be an array of strings");
  }

  const rawSignatures = present(map, "signatures");
  if (!Array.isArray(rawSignatures)) {
    throw new Error("multisig_field_type: signatures must be an array");
  }
  const signatures: MultisigSignature[] = rawSignatures.map((entry, i) => {
    if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
      throw new Error(`multisig_field_type: signatures[${i}] must be a CBOR map`);
    }
    const e = entry as Record<string, unknown>;
    return {
      signer_agent_id: str(e, "signer_agent_id"),
      signature: bytes(e, "signature"),
    };
  });

  return {
    document_id: str(map, "document_id"),
    subject_kind: str(map, "subject_kind"),
    subject_hash: bytes(map, "subject_hash"),
    // Canonicalized on decode as well — a wire producer that shipped duplicates or an empty set
    // is refused here, before any completeness question is asked.
    required_signers: canonicalSigners(rawSigners as string[]),
    signatures,
  };
}
