/**
 * DOD-MP-JOIN-1 — the join offer: how a third party enters an existing document.
 *
 * The offer is a courier, not an authority. It carries the RECEIVED BYTES of the genesis
 * proposal, the full amendment chain (the pending `add_holder` last), and the envelope-log
 * snapshot — and the invitee's daemon DERIVES the arrangement from those bytes through the same
 * replay every holder runs. The invitee consents to what they computed, never to what they were
 * told: an offer whose chain does not replay admits nobody, whatever its prose.
 *
 * ── WHY THE SIGNATURE BINDS EVERY CARRIED BYTE ────────────────────────────────────────────────
 *
 * The TBS commits to the hash of the genesis bytes, of each amendment, and of each log envelope.
 * Each carried payload is ALSO independently verifiable (the genesis by its proposer's
 * signature, each amendment by its collection, each envelope by its sender) — the offer-level
 * binding exists so the inviter cannot assemble a misleading BUNDLE out of individually-valid
 * pieces and later disown the assembly. Who showed the invitee what is on the record.
 *
 * ── NEITHER ALONE ADMITS ANYONE ───────────────────────────────────────────────────────────────
 *
 * A valid offer makes a join POSSIBLE; the invitee's signed accept makes it REAL (the daemon
 * unit wires that consent through the settle-once ack pattern). This module rules only on the
 * offer's validity — GOVERN-1's dispositioned consent clause lands in the daemon receive path.
 */

import { createHash } from "node:crypto";
import { encodeCbor, decodeCbor } from "./cbor.js";
import {
  DOCUMENT_FEATURE_VERSION,
  decodeDocumentProposal,
  documentIdFromProposal,
  buildDocumentProposalTbs,
  type DocumentProposalEnvelope,
} from "./document-proposal.js";
import {
  decodeDocumentAmendment,
  deriveArrangement,
  type Arrangement,
  type ArrangementGenesis,
  type DocumentAmendmentEnvelope,
  type SignerPolicy,
} from "./document-amendment.js";

/** Domain tag in slot 0 of the to-be-signed array. Sibling of the other CELLO-DOCUMENT-* tags. */
export const DOCUMENT_JOIN_OFFER_DOMAIN = "CELLO-DOCUMENT-JOIN-OFFER-v1";

export interface DocumentJoinOffer {
  type: "document_join_offer";
  feature_version: number;
  /** The admin authoring this offer — must be a claimed signer of the pending amendment. */
  inviter_agent_id: string;
  invitee_agent_id: string;
  document_id: string;
  /** The genesis proposal AS RECEIVED — the invitee re-derives `document_id` from these bytes. */
  genesis: Uint8Array;
  /** The full amendment chain as received bytes, ordered, the pending `add_holder` LAST. */
  amendments: Uint8Array[];
  /** The update-envelope log snapshot (D1's cheap path) — may be empty for a young document. */
  envelope_log: Uint8Array[];
  offered_at_ms: number;
  /** Ed25519 (RFC 8032) by the inviter over `buildDocumentJoinOfferTbs`. */
  signature: Uint8Array;
}

function sha256(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(bytes).digest());
}

/**
 * The canonical to-be-signed preimage. Payloads enter as HASHES (arrays of 32-byte digests are
 * deterministic CBOR — the multisig precedent), so the signature binds every carried byte
 * without re-encoding megabytes into the preimage.
 */
export function buildDocumentJoinOfferTbs(
  offer: DocumentJoinOffer,
  opts: { preHash?: boolean } = {},
): Uint8Array {
  const preimage = encodeCbor([
    DOCUMENT_JOIN_OFFER_DOMAIN,
    offer.feature_version,
    offer.inviter_agent_id,
    offer.invitee_agent_id,
    offer.document_id,
    sha256(offer.genesis),
    offer.amendments.map(sha256),
    offer.envelope_log.map(sha256),
    typeof offer.offered_at_ms === "number" && offer.offered_at_ms > 0xffffffff
      ? BigInt(offer.offered_at_ms)
      : offer.offered_at_ms,
  ]);
  if (opts.preHash === false) return preimage;
  return sha256(preimage);
}

export function encodeDocumentJoinOffer(offer: DocumentJoinOffer): Uint8Array {
  return encodeCbor({
    type: offer.type,
    feature_version: offer.feature_version,
    inviter_agent_id: offer.inviter_agent_id,
    invitee_agent_id: offer.invitee_agent_id,
    document_id: offer.document_id,
    genesis: offer.genesis,
    amendments: offer.amendments,
    envelope_log: offer.envelope_log,
    offered_at_ms: offer.offered_at_ms,
    signature: offer.signature,
  });
}

function present(map: Record<string, unknown>, field: string): unknown {
  if (!(field in map)) {
    throw new Error(`document_join_missing_field: ${field} is mandatory and was not present`);
  }
  return map[field];
}

function str(map: Record<string, unknown>, field: string): string {
  const v = present(map, field);
  if (typeof v !== "string" || v.length === 0) {
    throw new Error(`document_join_field_type: ${field} must be a non-empty text string`);
  }
  return v;
}

function bytes(map: Record<string, unknown>, field: string): Uint8Array {
  const v = present(map, field);
  if (!(v instanceof Uint8Array)) {
    throw new Error(`document_join_field_type: ${field} must be a CBOR byte string`);
  }
  return new Uint8Array(v);
}

function byteArray(map: Record<string, unknown>, field: string): Uint8Array[] {
  const v = present(map, field);
  if (!Array.isArray(v) || v.some((e) => !(e instanceof Uint8Array))) {
    throw new Error(`document_join_field_type: ${field} must be an array of CBOR byte strings`);
  }
  return v.map((e) => new Uint8Array(e as Uint8Array));
}

export function decodeDocumentJoinOffer(input: Uint8Array): DocumentJoinOffer {
  const decoded = decodeCbor(input);
  if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) {
    throw new Error("document_join_malformed: not a CBOR map");
  }
  const map = decoded as Record<string, unknown>;
  const type = str(map, "type");
  if (type !== "document_join_offer") {
    throw new Error(`document_join_type: expected document_join_offer, got ${type}`);
  }
  const featureVersion = present(map, "feature_version");
  if (typeof featureVersion !== "number" || !Number.isInteger(featureVersion) || featureVersion < 1) {
    throw new Error("document_join_field_type: feature_version must be a positive integer");
  }
  const offeredAt = present(map, "offered_at_ms");
  if (typeof offeredAt !== "number" || !Number.isInteger(offeredAt)) {
    throw new Error("document_join_field_type: offered_at_ms must be an integer");
  }
  return {
    type: "document_join_offer",
    feature_version: featureVersion,
    inviter_agent_id: str(map, "inviter_agent_id"),
    invitee_agent_id: str(map, "invitee_agent_id"),
    document_id: str(map, "document_id"),
    genesis: bytes(map, "genesis"),
    amendments: byteArray(map, "amendments"),
    envelope_log: byteArray(map, "envelope_log"),
    offered_at_ms: offeredAt,
    signature: bytes(map, "signature"),
  };
}

/**
 * The replay's starting facts, computed from a decoded genesis proposal — ONE implementation for
 * every consumer (join validation, the daemon's amendment receive and accept paths), because two
 * copies of the everyone-admin default is how two holders derive different arrangements from one
 * genesis. Absent `admin_set` means both genesis participants govern (the bilateral default);
 * `admin_set` itself lives on the ARRANGEMENT, not in the scalar properties bag the replay
 * derives `change_property` against.
 */
export function arrangementGenesisFromProposal(
  genesis: DocumentProposalEnvelope,
): ArrangementGenesis {
  return {
    documentId: documentIdFromProposal(genesis),
    proposerAgentId: genesis.proposer_agent_id,
    peerAgentId: genesis.peer_agent_id,
    adminSet: genesis.properties.admin_set ?? [genesis.proposer_agent_id, genesis.peer_agent_id],
    properties: {
      assurance_tier: genesis.properties.assurance_tier,
      schema_enforcement: genesis.properties.schema_enforcement,
      topology: genesis.properties.topology,
      append_only: genesis.properties.append_only,
      ...(genesis.properties.content_profile !== undefined
        ? { content_profile: genesis.properties.content_profile }
        : {}),
    },
  };
}

export type JoinOfferValidation =
  | {
      ok: true;
      /** Derived by REPLAY of the carried bytes — the consent surface, computed not trusted. */
      arrangement: Arrangement;
      genesis: DocumentProposalEnvelope;
      amendments: DocumentAmendmentEnvelope[];
      /** Hex hash of the pending `add_holder` — the settle key for the invitee's answer. */
      pendingAmendmentHash: string;
    }
  | { ok: false; reason: string };

function refuse(reason: string): JoinOfferValidation {
  return { ok: false, reason };
}

/**
 * The invitee's ruling on an offer. Order is the disclosure-and-trust boundary: the version
 * answer first (a mismatched build must get a sentence, not a failed signature), then the
 * inviter's signature (nothing else is worth computing on an unauthenticated bundle), then the
 * carried payloads each on their own signatures, then the replay.
 */
export function validateDocumentJoinOffer(
  offer: DocumentJoinOffer,
  policy: SignerPolicy,
  verify: (agentId: string, tbs: Uint8Array, signature: Uint8Array) => boolean,
): JoinOfferValidation {
  if (offer.feature_version !== DOCUMENT_FEATURE_VERSION) {
    const side =
      offer.feature_version > DOCUMENT_FEATURE_VERSION
        ? "upgrade this client to join it"
        : "ask the inviter to upgrade theirs";
    return refuse(
      `join_feature_version: the offer speaks document feature version ${offer.feature_version} ` +
        `and this build speaks ${DOCUMENT_FEATURE_VERSION} — ${side}`,
    );
  }
  if (!verify(offer.inviter_agent_id, buildDocumentJoinOfferTbs(offer), offer.signature)) {
    return refuse(
      `join_signature_invalid: the offer claims to come from ${offer.inviter_agent_id} but its ` +
        `signature does not verify against that agent — nothing about the bundle is trustworthy`,
    );
  }

  let genesis: DocumentProposalEnvelope;
  try {
    genesis = decodeDocumentProposal(offer.genesis);
  } catch (err: unknown) {
    return refuse(
      `join_genesis_undecodable: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (documentIdFromProposal(genesis) !== offer.document_id) {
    return refuse(
      `join_genesis_mismatch: the carried genesis hashes to a different document than the offer ` +
        `names — the anchor cannot be swapped`,
    );
  }
  if (!verify(genesis.proposer_agent_id, buildDocumentProposalTbs(genesis), genesis.signature)) {
    return refuse(
      `join_genesis_signature_invalid: the genesis proposal does not verify against its named ` +
        `proposer ${genesis.proposer_agent_id}`,
    );
  }

  if (offer.amendments.length === 0) {
    return refuse(
      "join_no_pending_amendment: an offer must carry the amendment chain ending in the " +
        "add_holder that admits the invitee — an empty chain admits nobody",
    );
  }
  let amendments: DocumentAmendmentEnvelope[];
  try {
    amendments = offer.amendments.map((a) => decodeDocumentAmendment(a));
  } catch (err: unknown) {
    return refuse(
      `join_amendment_undecodable: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  const derived = deriveArrangement(
    arrangementGenesisFromProposal(genesis),
    amendments,
    policy,
    verify,
  );
  if (!derived.ok) {
    // The replay's reason IS the diagnosis — passed through, never substituted.
    return refuse(derived.reason);
  }

  const pending = amendments[amendments.length - 1]!;
  if (pending.body.kind !== "add_holder" || pending.body.subject_agent_id !== offer.invitee_agent_id) {
    return refuse(
      `join_not_for_invitee: the chain's last amendment does not admit ${offer.invitee_agent_id} — ` +
        `an offer is addressed to the holder its pending amendment names`,
    );
  }
  if (!pending.collection.required_signers.includes(offer.inviter_agent_id)) {
    return refuse(
      `join_inviter_not_signer: ${offer.inviter_agent_id} authored the offer but is not a claimed ` +
        `signer of the admitting amendment — the offer's author must be behind the admission`,
    );
  }

  return {
    ok: true,
    arrangement: derived.arrangement,
    genesis,
    amendments,
    pendingAmendmentHash: pending.collection.subject_hash.length
      ? Buffer.from(pending.collection.subject_hash).toString("hex")
      : "",
  };
}
