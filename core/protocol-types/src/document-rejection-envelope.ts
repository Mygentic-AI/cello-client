/**
 * DOD-DOC-REJECT-2 — the rejection's signed preimage, and its wire type.
 *
 * A `0x05` rejection leaf has carried a `signature` field since REJECT-1, and nothing defined what
 * that signature was OVER. The field was required — rightly, because an all-zero placeholder in an
 * immutable log is indistinguishable from a real signature that fails to verify — but with no
 * canonical to-be-signed structure it could only ever be filled dishonestly. Writing the
 * composition-root signer is what surfaced it: the only thing available to sign was an empty buffer.
 *
 * ── WHAT A REJECTION HAS TO BIND ──────────────────────────────────────────────────────────────
 *
 * A rejection is a claim with consequences for the other party: they stop retrying, roll back local
 * work, and supersede. So it binds
 *
 *   `document_id`            — a rejection cannot be moved to another document,
 *   `rejected_envelope_hash` — nor to another envelope,
 *   `reason`                 — the sender acts on it, so it must not be substitutable,
 *   `rejecting_agent_id`     — who refused; the counterpart of the ack's `acker_agent_id`,
 *   `round`                  — which retry this is. Unbound, a captured round-1 rejection replayed
 *                              twice more would drive a document to `stalled` without the rejecting
 *                              party ever having refused again.
 *
 * ── WHY IT IS A SEPARATE TYPE FROM THE ACK ────────────────────────────────────────────────────
 *
 * They look similar and are not the same statement. An ACK answers "did you take my envelope" and
 * settles delivery. A REJECTION is a §3.2 protocol act that goes in the log as a leaf, carries a
 * retry round, and is what supersession resolves. One type carrying both would need a mode flag,
 * and a mode flag on a signed structure is how a signature over one meaning gets read as the other.
 */

import { createHash } from "node:crypto";
import { encodeCbor, decodeCbor } from "./cbor.js";

/** Domain tag in slot 0. Distinct from the update, proposal and ack domains. */
export const DOCUMENT_REJECTION_DOMAIN = "CELLO-DOCUMENT-REJECTION-v1";

/** On the wire, so a version skew is DETECTED rather than surfacing as a signature failure. */
export const DOCUMENT_REJECTION_VERSION = 1;

/** Peer-controlled display text; capped for the same reason the ack's reason is. */
export const MAX_REJECTION_DETAIL_LENGTH = 500;

const HEX32 = /^[0-9a-f]{64}$/;

export interface DocumentRejectionEnvelope {
  type: "document_rejection";
  rejection_version: number;
  document_id: string;
  /** The envelope being refused. */
  rejected_envelope_hash: string;
  /** Who refused. The counterpart of the ack's `acker_agent_id`. */
  rejecting_agent_id: string;
  /** The §3.2 machine-readable reason the sender acts on. */
  reason: string;
  detail?: string;
  /**
   * Which retry round this is (1-based). SIGNED, because unbound a captured round-1 rejection
   * replayed twice more drives the document to `stalled` without the rejecting party ever having
   * refused again.
   */
  round: number;
  rejected_at_ms: number;
  /** Ed25519 (RFC 8032) over `buildDocumentRejectionTbs`. */
  signature: Uint8Array;
}

/**
 * The canonical to-be-signed preimage: a fixed-order CBOR ARRAY with the domain in slot 0.
 *
 * An array rather than a map, for the reason `cbor.ts` gives — this encoder is deliberately not
 * deterministic for maps, so a map preimage would make the signature depend on the order the
 * rejecting party happened to build the object in.
 *
 * `detail` is encoded as explicit `null` when absent so the slot is always occupied and no field's
 * meaning depends on whether the one before it was present. The timestamp is coerced to a BigInt
 * past `0xffffffff`, because cbor-x encodes a JS number that large as an IEEE float64 rather than a
 * uint64 — measured on the ack, where it would have made a genuine signature read as a forgery to
 * any implementation encoding canonically.
 */
export function buildDocumentRejectionTbs(
  env: DocumentRejectionEnvelope,
  opts: { preHash?: boolean } = {},
): Uint8Array {
  assertDocumentRejectionConsistent(env);
  const preimage = encodeCbor([
    DOCUMENT_REJECTION_DOMAIN,
    env.rejection_version,
    env.document_id,
    env.rejected_envelope_hash,
    env.rejecting_agent_id,
    env.reason,
    env.detail ?? null,
    env.round,
    typeof env.rejected_at_ms === "number" && env.rejected_at_ms > 0xffffffff
      ? BigInt(env.rejected_at_ms)
      : env.rejected_at_ms,
  ]);
  if (opts.preHash === false) return preimage;
  return new Uint8Array(createHash("sha256").update(preimage).digest());
}

/**
 * The rejection's identity — the `0x05` leaf's envelope hash.
 *
 * Over the same preimage that is signed, so the leaf commits to exactly the bytes whose signature
 * was verified, and excludes the signature so re-signing does not orphan anything pointing at it.
 *
 * This replaces REJECT-1's local `sha256("rejection:" + hash + reason + nonce)` construction, which
 * was a placeholder: it bound no signature, no round, and no rejecting party.
 */
export function documentRejectionHash(env: DocumentRejectionEnvelope): string {
  return createHash("sha256")
    .update(buildDocumentRejectionTbs(env, { preHash: false }))
    .digest("hex");
}

/** The cross-field rules, applied on BOTH encode and decode so the two cannot drift. */
export function assertDocumentRejectionConsistent(env: DocumentRejectionEnvelope): void {
  if (env.reason.length === 0) {
    // The sender is being told to stop and supersede; without the reason it cannot know what to
    // change. The whole rejection protocol exists to avoid exactly that.
    throw new Error("document_rejection_reason: a rejection must carry its reason");
  }
  if (!Number.isInteger(env.round) || env.round < 1) {
    throw new Error(`document_rejection_round: must be a positive integer, got ${env.round}`);
  }
  if (env.detail !== undefined && env.detail.length > MAX_REJECTION_DETAIL_LENGTH) {
    throw new Error(
      `document_rejection_detail: at most ${MAX_REJECTION_DETAIL_LENGTH} characters, got ${env.detail.length}`,
    );
  }
}

export function encodeDocumentRejection(env: DocumentRejectionEnvelope): Uint8Array {
  assertDocumentRejectionConsistent(env);
  return encodeCbor({
    type: env.type,
    rejection_version: env.rejection_version,
    document_id: env.document_id,
    rejected_envelope_hash: env.rejected_envelope_hash,
    rejecting_agent_id: env.rejecting_agent_id,
    reason: env.reason,
    detail: env.detail ?? null,
    round: env.round,
    rejected_at_ms: env.rejected_at_ms,
    signature: env.signature,
  });
}

function present(map: Record<string, unknown>, field: string): unknown {
  // `in`, not a nullish check — the same discipline as every sibling envelope. A defaulted field is
  // a claim the rejecting party never made.
  if (!(field in map)) {
    throw new Error(`document_rejection_missing_field: ${field} is mandatory and was not present`);
  }
  return map[field];
}

export function decodeDocumentRejection(bytes: Uint8Array): DocumentRejectionEnvelope {
  const decoded = decodeCbor(bytes);
  if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) {
    throw new Error("document_rejection_malformed: not a CBOR map");
  }
  const map = decoded as Record<string, unknown>;

  if (present(map, "type") !== "document_rejection") {
    throw new Error("document_rejection_type: expected document_rejection");
  }

  const version = present(map, "rejection_version");
  if (typeof version !== "number" || !Number.isInteger(version)) {
    throw new Error("document_rejection_version: must be an integer");
  }
  if (version !== DOCUMENT_REJECTION_VERSION) {
    throw new Error(
      `document_rejection_version: this build speaks version ${DOCUMENT_REJECTION_VERSION} and the ` +
        `frame declares ${version} — one of the two clients needs upgrading`,
    );
  }

  for (const field of ["document_id", "rejected_envelope_hash"]) {
    const value = present(map, field);
    if (typeof value !== "string" || !HEX32.test(value)) {
      throw new Error(`document_rejection_${field}: must be a 32-byte hex digest`);
    }
  }

  const rejecting = present(map, "rejecting_agent_id");
  if (typeof rejecting !== "string" || rejecting.length === 0) {
    throw new Error("document_rejection_agent: rejecting_agent_id must be a non-empty text string");
  }

  const reason = present(map, "reason");
  if (typeof reason !== "string") {
    throw new Error("document_rejection_reason: must be a text string");
  }

  const rawDetail = present(map, "detail");
  if (rawDetail !== null && typeof rawDetail !== "string") {
    throw new Error("document_rejection_detail: must be a text string or explicit null");
  }
  // Empty string means ABSENT — the same normalisation the ack needed, for the same reason: a peer
  // in a language where a non-nullable string defaults to "" must not be refused for a field it
  // never filled in.
  const detail = rawDetail === "" ? null : (rawDetail as string | null);

  const round = present(map, "round");
  if (typeof round !== "number" || !Number.isInteger(round) || round < 1) {
    throw new Error(`document_rejection_round: must be a positive integer, got ${String(round)}`);
  }

  const rejectedAt = present(map, "rejected_at_ms");
  if (typeof rejectedAt !== "number" || !Number.isSafeInteger(rejectedAt) || rejectedAt <= 0) {
    throw new Error("document_rejection_time: rejected_at_ms must be a positive safe integer");
  }

  const signature = present(map, "signature");
  if (!(signature instanceof Uint8Array)) {
    throw new Error("document_rejection_signature: must be a CBOR byte string");
  }

  const env: DocumentRejectionEnvelope = {
    type: "document_rejection",
    rejection_version: version,
    document_id: map["document_id"] as string,
    rejected_envelope_hash: map["rejected_envelope_hash"] as string,
    rejecting_agent_id: rejecting,
    reason,
    ...(detail === null ? {} : { detail }),
    round,
    rejected_at_ms: rejectedAt,
    // COPIED — cbor-x returns byte strings as views into the buffer it decoded.
    signature: new Uint8Array(signature),
  };
  assertDocumentRejectionConsistent(env);
  return env;
}
