/**
 * DOD-MP-AMEND-1 — the amendment record: an epoch event in its FINAL frame shape, and the replay
 * that derives a document's arrangement from genesis + the chain.
 *
 * The genesis proposal stays the anchor — never edited, still hashing to `document_id`. What may
 * change after it — who holds the document, who administers it, its amendable properties — is
 * derived ONLY from this chain of signed amendments, replayed independently by every holder. An
 * amendment whose signature collection does not meet its kind's requirement is INVALID everywhere,
 * computed rather than detected; that is the invariant that replaced immutability (multiplayer log
 * §6, rulings §13).
 *
 * ── THE FRAME IS FINAL (TIER2-READY constraint 1) ─────────────────────────────────────────────
 *
 * Signed, chained to its predecessor, epoch-incrementing, and carrying `state_hash` — the
 * canonical-hash-at-boundary slot — as DEFINED-ABSENT (`null`) while the tier is `authenticated`.
 * Tier 2 fills the slot; it does not migrate the frame. Dropping the slot "because Tier 1 doesn't
 * use it" is the exact seam violation M14 forbade for `epoch_id`.
 *
 * ── WHO MUST SIGN IS INJECTED ─────────────────────────────────────────────────────────────────
 *
 * The replay owns MECHANICS: chaining, completeness, application order, and the arrangement
 * invariants (admins ⊆ participants, admins never empty, the holder cap). WHICH signatures each
 * kind requires is GOVERN-1's policy, consulted against the state BEFORE the amendment — so a
 * newly-promoted admin is required on the NEXT amendment, not retroactively on their own
 * promotion.
 */

import { createHash } from "node:crypto";
import { encodeCbor, decodeCbor } from "./cbor.js";
import {
  encodeMultisigCollection,
  decodeMultisigCollection,
  type MultisigCollection,
} from "./document-multisig.js";

/**
 * Domain tag in slot 0 of the to-be-signed array. Sibling of the other CELLO-DOCUMENT-* tags.
 * v2 (SYNC-P1): the preimage gained the causal fields — author, sequence, parents. A v1 frame is
 * refused by the mandatory-field discipline below; no compatibility is owed (all holders upgrade
 * together).
 */
export const DOCUMENT_AMENDMENT_DOMAIN = "CELLO-DOCUMENT-AMENDMENT-v2";

/**
 * Ceiling on an entry's parent list. The honest frontier is bounded by the holder cap (D5: 20);
 * the ceiling exists so a hostile daemon cannot make every ancestry walk unbounded.
 */
export const MAX_ENTRY_PARENTS = 64;

/** The `subject_kind` an amendment's multisig collection must carry. */
export const AMENDMENT_SUBJECT_KIND = "document_amendment";

/** D5 (ruled 2026-08-11): documents inherit the group-room cap. Enforced at amendment validation. */
export const MAX_DOCUMENT_HOLDERS = 20;

export const AMENDMENT_KINDS = [
  "add_holder",
  "remove_holder",
  "promote_admin",
  "remove_admin",
  "change_property",
  // SYNC-P2 (R21/R24): the subject's own acts. A `consent` answers an admission and names what
  // it agrees to in the signed property slots ({ key: "consents_to", value: "<tier>/<version>" });
  // a `refuse_join` ends the invitation. Both are authored, subject-ed, and signed by the same
  // party — nobody consents for you.
  "consent",
  "refuse_join",
] as const;
export type AmendmentKind = (typeof AMENDMENT_KINDS)[number];

/**
 * Properties an amendment may change. Deliberately NARROW to start: the seam properties are owned
 * elsewhere (`assurance_tier` changes are the Tier 2 tier-upgrade epoch event; `schema_enforcement`
 * is Tier 2's schema work; `topology` and `content_profile` are identity-shaped — changing them
 * under a live document is a new agreement, not an amendment). Widening this set is a one-line,
 * journaled decision; shrinking it after documents exist is a migration.
 */
export const AMENDABLE_PROPERTIES = new Set(["append_only"]);

export interface DocumentAmendmentBody {
  document_id: string;
  /** The epoch this amendment MINTS: previous epoch + 1. Genesis is epoch 0 and is not an amendment. */
  epoch_id: number;
  /** Hex hash of the predecessor amendment's TBS; null for the first (anchored to genesis via document_id). */
  prev_amendment_hash: string | null;
  kind: AmendmentKind;
  /** The holder the amendment is about (pubkey hex). Null exactly for `change_property`. */
  subject_agent_id: string | null;
  /** Non-null exactly for `change_property`. */
  property_change: { key: string; value: string | number | boolean } | null;
  /**
   * Tier 2's canonical-hash-at-boundary slot. DEFINED-ABSENT (`null`) while the document's tier
   * is `authenticated`; refused non-null at replay until the attested tier exists.
   */
  state_hash: Uint8Array | null;
  authored_at_ms: number;
  /**
   * SYNC-P1 — the causal fields. The accountable initiator (MUST appear in the collection's
   * required set), their own-chain counter, and the frontier heads applied when authoring. For
   * `author_seq > 1` the author's previous entry MUST be among the ancestors the parents reach —
   * a direct parent is the common case, not the requirement. Signed: a forwarder cannot
   * re-attribute, re-sequence, or re-parent without every signature failing (SYNC-R2).
   */
  author_agent_id: string;
  author_seq: number;
  /** Entry hashes (64-hex), CANONICAL: strictly ascending, no duplicates. Empty anchors to genesis. */
  parents: readonly string[];
}

export interface DocumentAmendmentEnvelope {
  body: DocumentAmendmentBody;
  /** SIG-1 collection over `documentAmendmentHash(body)` with `subject_kind: "document_amendment"`. */
  collection: MultisigCollection;
}

/**
 * The canonical to-be-signed preimage: a fixed-order CBOR ARRAY with the domain in slot 0.
 * `property_change` is FLATTENED into two slots — `encodeCbor` maps follow insertion order, and a
 * nested map would make the hash depend on how the builder happened to assemble it.
 */
export function buildDocumentAmendmentTbs(
  body: DocumentAmendmentBody,
  opts: { preHash?: boolean } = {},
): Uint8Array {
  const preimage = encodeCbor([
    DOCUMENT_AMENDMENT_DOMAIN,
    body.document_id,
    body.epoch_id,
    body.prev_amendment_hash,
    body.kind,
    body.subject_agent_id,
    body.property_change?.key ?? null,
    body.property_change?.value ?? null,
    body.state_hash,
    // BIGINT past 0xffffffff — the same float64-vs-uint64 coercion every sibling builder carries.
    typeof body.authored_at_ms === "number" && body.authored_at_ms > 0xffffffff
      ? BigInt(body.authored_at_ms)
      : body.authored_at_ms,
    body.author_agent_id,
    body.author_seq,
    [...body.parents],
  ]);
  if (opts.preHash === false) return preimage;
  return new Uint8Array(createHash("sha256").update(preimage).digest());
}

/** The amendment's identity: SHA-256 over the TBS preimage — signature-independent, like `document_id`. */
export function documentAmendmentHash(body: DocumentAmendmentBody): Uint8Array {
  return new Uint8Array(
    createHash("sha256").update(buildDocumentAmendmentTbs(body, { preHash: false })).digest(),
  );
}

export function encodeDocumentAmendment(env: DocumentAmendmentEnvelope): Uint8Array {
  return encodeCbor({
    // The FRAME discriminator — how the session router tells an amendment from conversation.
    // Not part of the TBS (the hash and every signature are over the body's preimage), so its
    // absence in early builds cost classification, never integrity.
    type: "document_amendment",
    body: {
      document_id: env.body.document_id,
      epoch_id: env.body.epoch_id,
      prev_amendment_hash: env.body.prev_amendment_hash,
      kind: env.body.kind,
      subject_agent_id: env.body.subject_agent_id,
      property_change: env.body.property_change,
      state_hash: env.body.state_hash,
      authored_at_ms: env.body.authored_at_ms,
      author_agent_id: env.body.author_agent_id,
      author_seq: env.body.author_seq,
      parents: [...env.body.parents],
    },
    collection: encodeMultisigCollection(env.collection),
  });
}

function present(map: Record<string, unknown>, field: string): unknown {
  if (!(field in map)) {
    throw new Error(`document_amendment_missing_field: ${field} is mandatory and was not present`);
  }
  return map[field];
}

function str(map: Record<string, unknown>, field: string): string {
  const v = present(map, field);
  if (typeof v !== "string" || v.length === 0) {
    throw new Error(`document_amendment_field_type: ${field} must be a non-empty text string`);
  }
  return v;
}

export function decodeDocumentAmendment(input: Uint8Array): DocumentAmendmentEnvelope {
  const decoded = decodeCbor(input);
  if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) {
    throw new Error("document_amendment_malformed: not a CBOR map");
  }
  const map = decoded as Record<string, unknown>;
  const frameType = present(map, "type");
  if (frameType !== "document_amendment") {
    throw new Error(
      `document_amendment_type: expected document_amendment, got ${String(frameType)}`,
    );
  }

  const rawBody = present(map, "body");
  if (typeof rawBody !== "object" || rawBody === null || Array.isArray(rawBody)) {
    throw new Error("document_amendment_field_type: body must be a CBOR map");
  }
  const b = rawBody as Record<string, unknown>;

  const epochId = present(b, "epoch_id");
  if (typeof epochId !== "number" || !Number.isInteger(epochId) || epochId < 1) {
    throw new Error(
      `document_amendment_epoch: must be a positive integer (genesis is epoch 0 and is not an ` +
        `amendment), got ${String(epochId)}`,
    );
  }

  const kind = str(b, "kind");
  if (!(AMENDMENT_KINDS as readonly string[]).includes(kind)) {
    throw new Error(
      `document_amendment_kind: "${kind}" is not an amendment kind this build knows ` +
        `(${AMENDMENT_KINDS.join(", ")})`,
    );
  }

  const prevHash = present(b, "prev_amendment_hash");
  if (prevHash !== null && (typeof prevHash !== "string" || !/^[0-9a-f]{64}$/.test(prevHash))) {
    throw new Error(
      "document_amendment_field_type: prev_amendment_hash must be 64-hex or explicit null",
    );
  }

  const subject = present(b, "subject_agent_id");
  if (subject !== null && (typeof subject !== "string" || subject.length === 0)) {
    throw new Error(
      "document_amendment_field_type: subject_agent_id must be a non-empty string or explicit null",
    );
  }

  const rawChange = present(b, "property_change");
  let propertyChange: DocumentAmendmentBody["property_change"] = null;
  if (rawChange !== null) {
    if (typeof rawChange !== "object" || Array.isArray(rawChange)) {
      throw new Error("document_amendment_field_type: property_change must be a CBOR map or null");
    }
    const c = rawChange as Record<string, unknown>;
    const key = str(c, "key");
    const value = present(c, "value");
    if (typeof value !== "string" && typeof value !== "number" && typeof value !== "boolean") {
      throw new Error(
        "document_amendment_field_type: property_change.value must be a string, number, or boolean",
      );
    }
    propertyChange = { key, value };
  }

  const stateHash = present(b, "state_hash");
  if (stateHash !== null && !(stateHash instanceof Uint8Array)) {
    throw new Error(
      "document_amendment_field_type: state_hash must be a CBOR byte string or explicit null",
    );
  }

  const authoredAt = present(b, "authored_at_ms");
  if (typeof authoredAt !== "number" || !Number.isInteger(authoredAt)) {
    throw new Error("document_amendment_field_type: authored_at_ms must be an integer");
  }

  const author = present(b, "author_agent_id");
  if (typeof author !== "string" || !/^[0-9a-f]{64}$/.test(author)) {
    throw new Error(
      "document_amendment_field_type: author_agent_id must be a 64-hex agent pubkey",
    );
  }

  const authorSeq = present(b, "author_seq");
  if (typeof authorSeq !== "number" || !Number.isInteger(authorSeq) || authorSeq < 1) {
    throw new Error(
      `document_amendment_author_seq: must be a positive integer (an author's own chain starts ` +
        `at 1), got ${String(authorSeq)}`,
    );
  }

  const rawParents = present(b, "parents");
  if (!Array.isArray(rawParents)) {
    throw new Error("document_amendment_field_type: parents must be an array of entry hashes");
  }
  if (rawParents.length > MAX_ENTRY_PARENTS) {
    throw new Error(
      `document_amendment_parents_cap: ${rawParents.length} parents exceeds the ceiling of ` +
        `${MAX_ENTRY_PARENTS} — an honest frontier is bounded by the holder cap`,
    );
  }
  for (const p of rawParents) {
    if (typeof p !== "string" || !/^[0-9a-f]{64}$/.test(p)) {
      throw new Error("document_amendment_field_type: parents must be 64-hex entry hashes");
    }
  }
  const parents = rawParents as string[];
  for (let i = 1; i < parents.length; i++) {
    if (parents[i]! <= parents[i - 1]!) {
      throw new Error(
        "document_amendment_parents_canonical: parents must be strictly ascending with no " +
          "duplicates — one entry, one identity",
      );
    }
  }

  const rawCollection = present(map, "collection");
  if (!(rawCollection instanceof Uint8Array)) {
    throw new Error("document_amendment_field_type: collection must be a CBOR byte string");
  }

  return {
    body: {
      document_id: str(b, "document_id"),
      epoch_id: epochId,
      prev_amendment_hash: prevHash,
      kind: kind as AmendmentKind,
      subject_agent_id: subject,
      property_change: propertyChange,
      state_hash: stateHash === null ? null : new Uint8Array(stateHash),
      authored_at_ms: authoredAt,
      author_agent_id: author,
      author_seq: authorSeq,
      parents,
    },
    collection: decodeMultisigCollection(new Uint8Array(rawCollection)),
  };
}

/** The genesis facts replay starts from — all of them signed into the proposal (or its admin slot). */
export interface ArrangementGenesis {
  documentId: string;
  proposerAgentId: string;
  peerAgentId: string;
  /** Pubkey-hex identities holding admin power at creation. Must be ⊆ {proposer, peer}, non-empty. */
  adminSet: readonly string[];
  properties: Record<string, string | number | boolean | undefined>;
}

export interface Arrangement {
  epoch: number;
  participants: ReadonlySet<string>;
  /** SYNC-P2: admitted-not-yet-answered (R22). Optional while the interim join surface lives. */
  invited?: ReadonlySet<string>;
  admins: ReadonlySet<string>;
  /** The DERIVED view — genesis properties + applied change_property amendments. */
  properties: Record<string, string | number | boolean | undefined>;
  lastAmendmentHash: string | null;
}

/**
 * GOVERN-1's seam: is the collection's CLAIMED required-signer set acceptable for this amendment,
 * given the arrangement as it stands BEFORE the amendment applies. A verdict rather than a
 * minted set, because "any single admin" has no single answer — {a} and {b} are both acceptable
 * claims — and the multisig layer then demands every claimed signature verify.
 */
export type SignerPolicy = (
  kind: AmendmentKind,
  subjectAgentId: string | null,
  state: { participants: ReadonlySet<string>; admins: ReadonlySet<string> },
  claimedRequiredSet: readonly string[],
) => { ok: true } | { ok: false; reason: string };
