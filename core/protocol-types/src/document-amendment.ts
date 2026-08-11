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
  collectionStatus,
  encodeMultisigCollection,
  decodeMultisigCollection,
  type MultisigCollection,
} from "./document-multisig.js";

/** Domain tag in slot 0 of the to-be-signed array. Sibling of the other CELLO-DOCUMENT-* tags. */
export const DOCUMENT_AMENDMENT_DOMAIN = "CELLO-DOCUMENT-AMENDMENT-v1";

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
    body: {
      document_id: env.body.document_id,
      epoch_id: env.body.epoch_id,
      prev_amendment_hash: env.body.prev_amendment_hash,
      kind: env.body.kind,
      subject_agent_id: env.body.subject_agent_id,
      property_change: env.body.property_change,
      state_hash: env.body.state_hash,
      authored_at_ms: env.body.authored_at_ms,
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

export type DeriveResult =
  | { ok: true; arrangement: Arrangement }
  | { ok: false; reason: string; epoch: number };

function refuse(reason: string, epoch: number): DeriveResult {
  return { ok: false, reason, epoch };
}

/**
 * Replay: genesis + the ordered amendment chain → the current arrangement, or a loud refusal
 * naming the epoch and the cause. NEVER a partial arrangement — a holder that cannot derive the
 * whole chain has no arrangement, which is what makes "invalid everywhere" computable.
 */
export function deriveArrangement(
  genesis: ArrangementGenesis,
  amendments: readonly DocumentAmendmentEnvelope[],
  policy: SignerPolicy,
  verify: (agentId: string, tbs: Uint8Array, signature: Uint8Array) => boolean,
): DeriveResult {
  const participants = new Set([genesis.proposerAgentId, genesis.peerAgentId]);
  const admins = new Set(genesis.adminSet);
  if (admins.size === 0) {
    return refuse(
      "arrangement_admin_set_empty: a document with no admins can never be amended — the " +
        "creation flow must name at least one",
      0,
    );
  }
  for (const admin of admins) {
    if (!participants.has(admin)) {
      return refuse(
        `arrangement_admin_not_participant: ${admin} holds admin power but is not a holder — ` +
          `admins are always holders`,
        0,
      );
    }
  }
  const properties: Arrangement["properties"] = { ...genesis.properties };
  let epoch = 0;
  let lastHash: string | null = null;

  for (const env of amendments) {
    const body = env.body;
    const at = body.epoch_id;

    if (body.document_id !== genesis.documentId) {
      return refuse(
        `amendment_wrong_document: names ${body.document_id}, replaying ${genesis.documentId}`,
        at,
      );
    }
    if (body.epoch_id !== epoch + 1) {
      return refuse(
        `amendment_chain_gap: expected epoch ${epoch + 1} next, got ${body.epoch_id} — a missing ` +
          `amendment is a gap to resolve, never to skip`,
        at,
      );
    }
    if (body.prev_amendment_hash !== lastHash) {
      return refuse(
        `amendment_chain_broken: epoch ${at} chains to ${body.prev_amendment_hash ?? "genesis"} ` +
          `but the replayed predecessor is ${lastHash ?? "genesis"} — a fork, not a gap`,
        at,
      );
    }
    // WHITELIST, not an equality on the benign value: only a tier that DEFINES the slot may fill
    // it. An equality check on "authenticated" silently accepted a Tier 2 field whenever the
    // genesis lacked the tier property — a mis-built genesis running degraded instead of refusing.
    if (body.state_hash !== null && properties["assurance_tier"] !== "attested") {
      return refuse(
        `amendment_state_hash_tier: epoch ${at} carries a canonical state hash but the document's ` +
          `tier is ${JSON.stringify(properties["assurance_tier"] ?? null)} — only "attested" ` +
          `(Tier 2) defines that slot`,
        at,
      );
    }

    // Subject semantics against the CURRENT state — a no-op amendment is refused, not absorbed:
    // silently absorbing "add someone who already holds" would let two amendments with one
    // meaning carry different signatures.
    const subject = body.subject_agent_id;
    switch (body.kind) {
      case "add_holder": {
        if (subject === null) return refuse(`amendment_subject_required: add_holder names nobody`, at);
        if (participants.has(subject)) {
          return refuse(`amendment_subject_already_holder: ${subject} already holds this document`, at);
        }
        if (participants.size + 1 > MAX_DOCUMENT_HOLDERS) {
          return refuse(
            `amendment_holder_cap: admitting ${subject} would make ${participants.size + 1} holders ` +
              `and the cap is ${MAX_DOCUMENT_HOLDERS} (D5)`,
            at,
          );
        }
        break;
      }
      case "remove_holder": {
        if (subject === null) return refuse(`amendment_subject_required: remove_holder names nobody`, at);
        if (!participants.has(subject)) {
          return refuse(`amendment_subject_not_holder: ${subject} does not hold this document`, at);
        }
        if (admins.has(subject) && admins.size === 1) {
          return refuse(
            `amendment_last_admin: removing ${subject} would leave the document with no admins — ` +
              `it could never be amended again`,
            at,
          );
        }
        break;
      }
      case "promote_admin": {
        if (subject === null) return refuse(`amendment_subject_required: promote_admin names nobody`, at);
        if (!participants.has(subject)) {
          return refuse(`amendment_subject_not_holder: ${subject} does not hold this document`, at);
        }
        if (admins.has(subject)) {
          return refuse(`amendment_subject_already_admin: ${subject} is already an admin`, at);
        }
        break;
      }
      case "remove_admin": {
        if (subject === null) return refuse(`amendment_subject_required: remove_admin names nobody`, at);
        if (!admins.has(subject)) {
          return refuse(`amendment_subject_not_admin: ${subject} holds no admin power to remove`, at);
        }
        if (admins.size === 1) {
          return refuse(
            `amendment_last_admin: demoting ${subject} would leave the document with no admins — ` +
              `it could never be amended again`,
            at,
          );
        }
        break;
      }
      case "change_property": {
        if (subject !== null) {
          return refuse(`amendment_subject_forbidden: change_property is about the document, not a holder`, at);
        }
        if (body.property_change === null) {
          return refuse(`amendment_property_missing: change_property carries no change`, at);
        }
        if (!AMENDABLE_PROPERTIES.has(body.property_change.key)) {
          return refuse(
            `amendment_property_not_amendable: "${body.property_change.key}" is not amendable — ` +
              `the amendable set is {${[...AMENDABLE_PROPERTIES].join(", ")}}; tier and schema ` +
              `changes are Tier 2 epoch events, topology and profile are a new agreement`,
            at,
          );
        }
        break;
      }
    }

    // The collection: bound to THIS amendment, its claimed required set ACCEPTABLE TO THE POLICY
    // for the state BEFORE it, and complete. Order matters — a mismatch in what the collection claims is
    // reported before whether it gathered enough names for the wrong claim.
    const expectedHash = documentAmendmentHash(body);
    if (env.collection.document_id !== body.document_id) {
      return refuse(`amendment_collection_document_mismatch: collection names ${env.collection.document_id}`, at);
    }
    if (env.collection.subject_kind !== AMENDMENT_SUBJECT_KIND) {
      return refuse(
        `amendment_collection_kind: collection signs "${env.collection.subject_kind}", not an amendment`,
        at,
      );
    }
    if (Buffer.compare(env.collection.subject_hash, expectedHash) !== 0) {
      return refuse(
        `amendment_collection_subject_mismatch: the collection signs a different amendment than ` +
          `the one it rides with`,
        at,
      );
    }
    const verdict = policy(body.kind, subject, { participants, admins }, env.collection.required_signers);
    if (!verdict.ok) {
      // The policy's reason IS the diagnosis — epoch context prepended, nothing substituted.
      return refuse(`epoch ${at}: ${verdict.reason}`, at);
    }
    const status = collectionStatus(env.collection, verify);
    if (!status.complete) {
      return refuse(
        `amendment_collection_incomplete: epoch ${at} — missing [${status.missing.join(", ")}], ` +
          `invalid [${status.invalidSigners.join(", ")}], unknown [${status.unknown.join(", ")}], ` +
          `duplicate [${status.duplicates.join(", ")}]`,
        at,
      );
    }

    // Apply.
    switch (body.kind) {
      case "add_holder":
        participants.add(subject!);
        break;
      case "remove_holder":
        participants.delete(subject!);
        admins.delete(subject!);
        break;
      case "promote_admin":
        admins.add(subject!);
        break;
      case "remove_admin":
        admins.delete(subject!);
        break;
      case "change_property":
        properties[body.property_change!.key] = body.property_change!.value;
        break;
    }
    epoch = body.epoch_id;
    lastHash = Buffer.from(expectedHash).toString("hex");
  }

  return { ok: true, arrangement: { epoch, participants, admins, properties, lastAmendmentHash: lastHash } };
}
