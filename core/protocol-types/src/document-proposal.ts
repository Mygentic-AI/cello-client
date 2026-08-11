/**
 * DOD-DOC-HANDSHAKE-1 — the document PROPOSAL envelope (§16.3).
 *
 * A distinct wire type from `document-envelope.ts`'s UPDATE envelope. The two share the word
 * "envelope" and nothing else: this one is proposed once, consented to once, and its hash becomes
 * the `document_id` that every subsequent update names.
 *
 * **`document_id` is the hash of this envelope** — globally unique with no minting authority and
 * no coordination round. That is the property that makes the whole scheme federated, and it is why
 * the proposal must be canonically encodable: two parties that hash it differently are on two
 * different documents while believing they are on one.
 *
 * ── THE SEAM (§3.4, §11.1) ────────────────────────────────────────────────────────────────────
 *
 * Three properties are DECLARED in V1 but support exactly one value each, and the pattern is
 * deliberate — §3.3 chose it for `schema_enforcement` and §16.1 generalized it. Declaring a field
 * that only accepts one value looks redundant until you need the second value: the field is
 * already on the wire and already signed, so V2 is a validation change rather than a wire break
 * that strands every document created before it.
 *
 * Refused at BOTH ends — at proposal and again at accept. Not belt-and-braces: the proposer and
 * the accepter run different builds. A V2 peer proposing `topology: "mesh"` to a V1 peer must be
 * refused by the V1 accepter, and a V1 proposer must not be able to emit a value it cannot honour.
 * One-sided validation means whichever side is newer silently decides for both.
 *
 * ── THE FEATURE VERSION (§16.7-8) ─────────────────────────────────────────────────────────────
 *
 * Alpha owes no backward compatibility, so this is not a negotiation — it is the difference
 * between a human answer and a timeout. A peer whose client predates documents does not understand
 * the proposal at all, and without a version the symptom is silence: the proposal is never
 * answered and the operator sees a hang. `documentFeatureIncompatibility` turns that into "your
 * peer's client doesn't support shared documents yet — ask them to upgrade".
 */

import { createHash } from "node:crypto";
import { encodeCbor, decodeCbor } from "./cbor.js";

/** Domain tag in slot 0 of the to-be-signed array. Distinct from the UPDATE envelope's domain. */
export const DOCUMENT_PROPOSAL_DOMAIN = "CELLO-DOCUMENT-PROPOSAL-v1";

/**
 * The document feature version this build speaks. Bumped when the document wire changes in a way
 * a peer must understand; see `documentFeatureIncompatibility` for what a mismatch produces.
 */
export const DOCUMENT_FEATURE_VERSION = 1;

/** §6 — Tier 1. Tier 2 (attested) is V2; the field exists so V2 is a validation change. */
export const ASSURANCE_TIER_V1 = "authenticated";
/** §11 — the pairwise two-document form. Mesh is deferred (§11.1). */
export const TOPOLOGY_V1 = "hub-and-spoke";

export type DocumentConsentState = "pending" | "accepted" | "refused";

/**
 * The properties agreed at handshake (§3.4). **Immutable after accept** — a property change is an
 * epoch event and therefore V2 (§16.3), so no mutate call exists in V1. That is not an omission to
 * fill in later: mutating a property after acceptance would silently change the rules the other
 * party consented to, which is the one thing the handshake exists to prevent.
 */
export interface DocumentProperties {
  /** Only `authenticated` in V1. */
  assurance_tier: string;
  /** Only `false` in V1 — the schema-as-first-update path (§3.3) is V2. */
  schema_enforcement: boolean;
  /** Only `hub-and-spoke` in V1. */
  topology: string;
  /** Receiver-local append-only enforcement (§16.7-1). Freely settable — not a seam field. */
  append_only: boolean;
  /**
   * DOD-DOC-PROFILE-1 — the character space this document is agreed to carry, by NAME.
   *
   * Optional on the wire today and inert: the named codepoint sets are not enforced yet. It is in
   * the SIGNED preimage now because it is bound into `document_id`, and adding it later would
   * change the id of every existing document.
   *
   * Distinct from `schema_enforcement`, which is about structure. This is about which characters
   * may appear at all — decided at consent, where the question "do I want a Devanagari document
   * with this person" is answerable, rather than mid-document where "what is U+200D doing at offset
   * 412" is not.
   */
  content_profile?: string;
}

export interface DocumentProposalEnvelope {
  type: "document_proposal";
  /** Which build proposed this. A peer that cannot read it answers with a human-readable refusal. */
  feature_version: number;
  proposer_agent_id: string;
  peer_agent_id: string;
  /** Free-form label chosen by the proposer, e.g. "markdown". Not a seam field. */
  document_type: string;
  properties: DocumentProperties;
  /**
   * The epoch-zero template (§16.3 step 1), or null. A Yjs update in the pinned encoding, so both
   * sides mint byte-identical starting state rather than each building their own from a template
   * string — two "identical" documents built independently do not converge.
   */
  starting_content: Uint8Array | null;
  /** Distinguishes two otherwise identical proposals, so each gets its own document_id. */
  nonce: Uint8Array;
  proposed_at_ms: number;
  /** Ed25519 (RFC 8032) over `buildDocumentProposalTbs`. */
  signature: Uint8Array;
}

/**
 * The canonical to-be-signed preimage: a fixed-order CBOR ARRAY with the domain in slot 0.
 *
 * The properties are flattened into their own slots rather than nested as a map. `encodeCbor` is
 * not deterministic for maps — keys follow insertion order — so a nested `properties` object would
 * make the signature depend on the order the proposer happened to build it in, and two honest
 * builds of the same proposal would produce different `document_id`s. For this envelope that is
 * worse than a bad signature: the id IS the hash, so the two parties would be on two documents.
 */
export function buildDocumentProposalTbs(
  env: DocumentProposalEnvelope,
  opts: { preHash?: boolean } = {},
): Uint8Array {
  const preimage = encodeCbor([
    DOCUMENT_PROPOSAL_DOMAIN,
    env.feature_version,
    env.proposer_agent_id,
    env.peer_agent_id,
    env.document_type,
    env.properties.assurance_tier,
    env.properties.schema_enforcement,
    env.properties.topology,
    env.properties.append_only,
    // DOD-DOC-PROFILE-1's slot. In the preimage from the start, so the profile is bound into
    // `document_id` and cannot be changed after consent — an upgrade is a NEW document, which is
    // the property that makes "agreed at the handshake" mean anything.
    //
    // Added while M14 has no users: this changes `document_id` for every proposal, and the only
    // time that is free is before anyone holds a document they care about. The enforcement (named
    // codepoint sets) follows on this slot; shipping the slot first is deliberate, because the
    // alternative — enforcing a profile the wire cannot carry — is unimplementable, while a slot
    // with no enforcement is merely inert and clearly marked as such.
    //
    // `null` when the proposer named none, so the slot is always occupied and no field's meaning
    // depends on whether the one before it was present.
    env.properties.content_profile ?? null,
    env.starting_content,
    env.nonce,
    // BIGINT past 0xffffffff — the same coercion three sibling builders carry and which
    // primary-transfer.ts names as a defect it shipped without. cbor-x encodes a JS number that
    // large as an IEEE float64 (`fb`), not a uint64 (`1b`), so any implementation encoding RFC
    // 8949-canonically would compute a DIFFERENT document_id from the same proposal — and for this
    // envelope the id IS the hash, so the two parties would be on two documents.
    //
    // Fixed now rather than left as a known wart: M14 is unreleased, nothing is wired, and no
    // proposal has ever been signed. The frozen vector below is reissued deliberately, which is
    // exactly the case its own comment describes.
    typeof env.proposed_at_ms === "number" && env.proposed_at_ms > 0xffffffff
      ? BigInt(env.proposed_at_ms)
      : env.proposed_at_ms,
  ]);
  if (opts.preHash === false) return preimage;
  return new Uint8Array(createHash("sha256").update(preimage).digest());
}

/**
 * `document_id` = the hash of the proposal envelope (§16.3).
 *
 * Over the same preimage that is signed, and therefore NOT over the signature — so the id a party
 * computes is the id of the thing whose signature it verified, and re-signing cannot change the
 * identity of an already-accepted document.
 */
export function documentIdFromProposal(env: DocumentProposalEnvelope): string {
  return createHash("sha256")
    .update(buildDocumentProposalTbs(env, { preHash: false }))
    .digest("hex");
}

/**
 * Refuse any seam value this build cannot honour, at proposal AND at accept.
 *
 * Returns the reason, or null when the properties are acceptable. A REASON rather than a boolean
 * because the operator on the refusing side has to be able to tell "your peer asked for mesh
 * topology, which this version does not support" from a generic refusal — a handshake that fails
 * without saying which property failed is indistinguishable from the peer being unreachable.
 */
export function seamViolation(props: DocumentProperties): string | null {
  if (props.assurance_tier !== ASSURANCE_TIER_V1) {
    return (
      `document_seam_assurance_tier: this version supports "${ASSURANCE_TIER_V1}" only, and the ` +
      `proposal asks for "${props.assurance_tier}" — attested documents (§6 Tier 2) are not yet built`
    );
  }
  if (props.schema_enforcement !== false) {
    return (
      "document_seam_schema_enforcement: this version supports schema_enforcement: false only — " +
      "schema-as-first-update validation (§3.3) is not yet built"
    );
  }
  // THE PROFILE NAME IS CLOSED (DOD-DOC-PROFILE-1). Refused at the seam like every other property,
  // because the alternative is a document agreed under a name nothing enforces — which reads as
  // protected in the inbox, in `list`, and in every review, and is not. Absent is fine: documents
  // agreed before profiles existed carry none, and the screening floor still applies to them.
  //
  // The names live in the daemon (`document-profile.ts`) because that is where the codepoint sets
  // are; duplicating them here would be two answers to what is admissible, which is the drift
  // `DocumentProperties` was unified to stop. So this checks SHAPE — a non-empty string — and the
  // receiving gate checks membership, refusing an unknown name by enforcing nothing while the
  // denylist still applies.
  if (props.content_profile !== undefined && typeof props.content_profile !== "string") {
    return (
      `content_profile must be a profile NAME (a string) or absent; this build cannot agree a ` +
      `document whose character space is declared as something else`
    );
  }
  if (props.topology !== TOPOLOGY_V1) {
    return (
      `document_seam_topology: this version supports "${TOPOLOGY_V1}" only, and the proposal asks ` +
      `for "${props.topology}" — mesh documents (§11.1) are not yet built`
    );
  }
  return null;
}

/**
 * A human answer for a version mismatch, or null when the peer is compatible.
 *
 * Deliberately phrased for the operator rather than for a log: the alternative to this string is a
 * proposal that is never answered, which surfaces as a hang and gets diagnosed as a network fault.
 */
export function documentFeatureIncompatibility(peerFeatureVersion: number | null): string | null {
  if (peerFeatureVersion === null) {
    return (
      "your peer's client doesn't support shared documents yet — ask them to upgrade to a version " +
      "that speaks the document protocol"
    );
  }
  if (peerFeatureVersion > DOCUMENT_FEATURE_VERSION) {
    return (
      `your peer's client speaks document feature version ${peerFeatureVersion} and this one ` +
      `speaks ${DOCUMENT_FEATURE_VERSION} — upgrade this client to collaborate with them`
    );
  }
  if (peerFeatureVersion < DOCUMENT_FEATURE_VERSION) {
    return (
      `your peer's client speaks document feature version ${peerFeatureVersion} and this one ` +
      `speaks ${DOCUMENT_FEATURE_VERSION} — ask them to upgrade`
    );
  }
  return null;
}

export function encodeDocumentProposal(env: DocumentProposalEnvelope): Uint8Array {
  return encodeCbor({
    type: env.type,
    feature_version: env.feature_version,
    proposer_agent_id: env.proposer_agent_id,
    peer_agent_id: env.peer_agent_id,
    document_type: env.document_type,
    properties: {
      assurance_tier: env.properties.assurance_tier,
      schema_enforcement: env.properties.schema_enforcement,
      topology: env.properties.topology,
      append_only: env.properties.append_only,
      // Present only when declared — the TBS signs this slot (`?? null`), so an encoding that
      // drops it has the receiver rebuild a different preimage and refuse the signature of every
      // profiled proposal. Absent stays absent so profile-less proposals keep their pre-profile
      // byte encoding.
      ...(env.properties.content_profile !== undefined
        ? { content_profile: env.properties.content_profile }
        : {}),
    },
    starting_content: env.starting_content,
    nonce: env.nonce,
    proposed_at_ms: env.proposed_at_ms,
    signature: env.signature,
  });
}

function present(map: Record<string, unknown>, field: string): unknown {
  // `in`, not a nullish check — see document-envelope.ts. A defaulted seam field is a property the
  // peer never actually declared, admitted under this build's own preference.
  if (!(field in map)) {
    throw new Error(`document_proposal_missing_field: ${field} is mandatory and was not present`);
  }
  return map[field];
}

function str(map: Record<string, unknown>, field: string): string {
  const v = present(map, field);
  if (typeof v !== "string" || v.length === 0) {
    throw new Error(`document_proposal_field_type: ${field} must be a non-empty text string`);
  }
  return v;
}

function bytes(map: Record<string, unknown>, field: string): Uint8Array {
  const v = present(map, field);
  if (!(v instanceof Uint8Array)) {
    throw new Error(`document_proposal_field_type: ${field} must be a CBOR byte string`);
  }
  // COPIED — cbor-x returns byte strings as views into the decoded buffer, so a caller reusing a
  // pooled read buffer would mutate the starting content after it was validated and hashed.
  return new Uint8Array(v);
}

/**
 * Decode and validate. Does NOT check the seam — `seamViolation` is called separately at both the
 * proposal and the accept step, because a decoder that refused seam values would make a
 * V2 proposal undecodable and therefore unanswerable, which is exactly the silent hang the feature
 * version exists to replace.
 */
export function decodeDocumentProposal(input: Uint8Array): DocumentProposalEnvelope {
  const decoded = decodeCbor(input);
  if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) {
    throw new Error("document_proposal_malformed: not a CBOR map");
  }
  const map = decoded as Record<string, unknown>;

  const type = str(map, "type");
  if (type !== "document_proposal") {
    throw new Error(`document_proposal_type: expected document_proposal, got ${type}`);
  }

  const featureVersion = present(map, "feature_version");
  if (typeof featureVersion !== "number" || !Number.isInteger(featureVersion) || featureVersion < 1) {
    throw new Error(
      `document_proposal_feature_version: must be a positive integer, got ${String(featureVersion)}`,
    );
  }

  const rawProps = present(map, "properties");
  if (typeof rawProps !== "object" || rawProps === null || Array.isArray(rawProps)) {
    throw new Error("document_proposal_properties: must be a CBOR map");
  }
  const p = rawProps as Record<string, unknown>;
  const schemaEnforcement = present(p, "schema_enforcement");
  if (typeof schemaEnforcement !== "boolean") {
    throw new Error("document_proposal_field_type: properties.schema_enforcement must be a boolean");
  }
  const appendOnly = present(p, "append_only");
  if (typeof appendOnly !== "boolean") {
    throw new Error("document_proposal_field_type: properties.append_only must be a boolean");
  }
  // OPTIONAL, unlike the seam fields above — documents agreed before profiles existed carry none,
  // and `present` would refuse every one of them. When declared it must be a name; membership in
  // the closed set is the gate's question (`seamViolation` checks shape, the daemon checks names).
  const contentProfile = "content_profile" in p ? p["content_profile"] : undefined;
  if (contentProfile !== undefined && (typeof contentProfile !== "string" || contentProfile.length === 0)) {
    throw new Error(
      "document_proposal_field_type: properties.content_profile must be a non-empty text string when present",
    );
  }

  const startingContent = present(map, "starting_content");
  if (startingContent !== null && !(startingContent instanceof Uint8Array)) {
    throw new Error(
      "document_proposal_field_type: starting_content must be a CBOR byte string or explicit null",
    );
  }

  const proposedAt = present(map, "proposed_at_ms");
  if (typeof proposedAt !== "number" || !Number.isInteger(proposedAt)) {
    throw new Error(`document_proposal_field_type: proposed_at_ms must be an integer`);
  }

  return {
    type: "document_proposal",
    feature_version: featureVersion,
    proposer_agent_id: str(map, "proposer_agent_id"),
    peer_agent_id: str(map, "peer_agent_id"),
    document_type: str(map, "document_type"),
    properties: {
      assurance_tier: str(p, "assurance_tier"),
      schema_enforcement: schemaEnforcement,
      topology: str(p, "topology"),
      append_only: appendOnly,
      ...(contentProfile !== undefined ? { content_profile: contentProfile } : {}),
    },
    starting_content: startingContent === null ? null : new Uint8Array(startingContent),
    nonce: bytes(map, "nonce"),
    proposed_at_ms: proposedAt,
    signature: bytes(map, "signature"),
  };
}
