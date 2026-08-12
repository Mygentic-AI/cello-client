/**
 * DOD-MP-JOIN-1 — the join offer: how a third party enters an existing document.
 *
 * An admin authors a signed offer carrying the RECEIVED BYTES of the genesis proposal, the full
 * amendment chain (the pending `add_holder` last), and the envelope-log snapshot (D1's cheap
 * path). The invitee derives the arrangement INDEPENDENTLY — replaying genesis + chain through
 * the real policy — and consents to what they computed, never to what they were told. A join is
 * effective only when the amendment is valid AND the invitee consented; neither alone admits
 * anyone.
 *
 * Real Ed25519 throughout — no mocks for crypto.
 */
import { describe, it, expect } from "vitest";
import { generateKeyPairSync, sign as edSign, verify as edVerify } from "node:crypto";
import { decodeCbor, encodeCbor } from "../cbor.js";
import {
  DOCUMENT_JOIN_OFFER_DOMAIN,
  DOCUMENT_FEATURE_VERSION,
  buildDocumentJoinOfferTbs,
  encodeDocumentJoinOffer,
  decodeDocumentJoinOffer,
  validateDocumentJoinOffer,
  documentGovernancePolicy,
  documentAmendmentHash,
  buildDocumentMultisigTbs,
  buildDocumentProposalTbs,
  encodeDocumentProposal,
  documentIdFromProposal,
  encodeDocumentAmendment,
  type DocumentJoinOffer,
  type DocumentProposalEnvelope,
  type DocumentAmendmentBody,
  type DocumentAmendmentEnvelope,
} from "../index.js";

function makeSigner() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = publicKey.export({ type: "spki", format: "der" }).subarray(-32);
  return {
    agentId: Buffer.from(raw).toString("hex"),
    sign: (tbs: Uint8Array): Uint8Array => new Uint8Array(edSign(null, tbs, privateKey)),
    publicKey,
  };
}
type Signer = ReturnType<typeof makeSigner>;

function makeVerify(signers: Signer[]) {
  const byId = new Map(signers.map((s) => [s.agentId, s.publicKey]));
  return (agentId: string, tbs: Uint8Array, signature: Uint8Array): boolean => {
    const key = byId.get(agentId);
    if (!key) return false;
    return edVerify(null, tbs, key, signature);
  };
}

/** A real signed genesis between a and b, admin set as given. */
function makeGenesis(a: Signer, b: Signer, admins: Signer[]): { envelope: DocumentProposalEnvelope; bytes: Uint8Array; documentId: string } {
  const envelope: DocumentProposalEnvelope = {
    type: "document_proposal",
    feature_version: DOCUMENT_FEATURE_VERSION,
    proposer_agent_id: a.agentId,
    peer_agent_id: b.agentId,
    document_type: "markdown",
    properties: {
      assurance_tier: "authenticated",
      schema_enforcement: false,
      topology: "hub-and-spoke",
      append_only: false,
      admin_set: admins.map((s) => s.agentId).sort(),
    },
    starting_content: null,
    nonce: new Uint8Array(16).fill(7),
    proposed_at_ms: 1_700_000_000_000,
    signature: new Uint8Array(0),
  };
  envelope.signature = a.sign(buildDocumentProposalTbs(envelope));
  // Wrapped: encodeCbor hands back Buffers, and the strict decoder returns plain Uint8Arrays —
  // fixtures normalize so deep equality compares bytes, not constructors.
  return { envelope, bytes: new Uint8Array(encodeDocumentProposal(envelope)), documentId: documentIdFromProposal(envelope) };
}

/** A signed add_holder amendment by one admin. */
function makeAddHolder(
  documentId: string,
  invitee: Signer,
  admin: Signer,
  over: Partial<DocumentAmendmentBody> = {},
): DocumentAmendmentEnvelope {
  const body: DocumentAmendmentBody = {
    document_id: documentId,
    epoch_id: 1,
    prev_amendment_hash: null,
    kind: "add_holder",
    subject_agent_id: invitee.agentId,
    property_change: null,
    state_hash: null,
    authored_at_ms: 1_700_000_000_001,
    ...over,
  };
  const hash = documentAmendmentHash(body);
  const required = [admin.agentId];
  const tbs = buildDocumentMultisigTbs({
    document_id: body.document_id,
    subject_kind: "document_amendment",
    subject_hash: hash,
    required_signers: required,
  });
  return {
    body,
    collection: {
      document_id: body.document_id,
      subject_kind: "document_amendment",
      subject_hash: hash,
      required_signers: required,
      signatures: [{ signer_agent_id: admin.agentId, signature: admin.sign(tbs) }],
    },
  };
}

function makeOffer(over: Partial<DocumentJoinOffer> = {}): {
  offer: DocumentJoinOffer;
  a: Signer;
  b: Signer;
  c: Signer;
  documentId: string;
} {
  const a = makeSigner();
  const b = makeSigner();
  const c = makeSigner();
  const g = makeGenesis(a, b, [a, b]);
  const pending = makeAddHolder(g.documentId, c, a);
  const offer: DocumentJoinOffer = {
    type: "document_join_offer",
    feature_version: DOCUMENT_FEATURE_VERSION,
    inviter_agent_id: a.agentId,
    invitee_agent_id: c.agentId,
    document_id: g.documentId,
    genesis: g.bytes,
    amendments: [new Uint8Array(encodeDocumentAmendment(pending))],
    envelope_log: [],
    offered_at_ms: 1_700_000_000_002,
    signature: new Uint8Array(0),
    ...over,
  };
  if (offer.signature.length === 0) {
    offer.signature = a.sign(buildDocumentJoinOfferTbs(offer));
  }
  return { offer, a, b, c, documentId: g.documentId };
}

describe("join offer TBS — the signature binds every carried byte", () => {
  it("is a CBOR array with the domain in slot 0", () => {
    const { offer } = makeOffer();
    const arr = decodeCbor(buildDocumentJoinOfferTbs(offer, { preHash: false })) as unknown[];
    expect(arr[0]).toBe(DOCUMENT_JOIN_OFFER_DOMAIN);
  });

  it("changes when ANY carried payload changes — genesis, an amendment, or a log envelope", () => {
    const { offer } = makeOffer();
    const base = buildDocumentJoinOfferTbs(offer);
    const g2 = { ...offer, genesis: new Uint8Array([...offer.genesis, 1]) };
    expect(buildDocumentJoinOfferTbs(g2)).not.toEqual(base);
    const a2 = { ...offer, amendments: [new Uint8Array([1, 2, 3])] };
    expect(buildDocumentJoinOfferTbs(a2)).not.toEqual(base);
    const l2 = { ...offer, envelope_log: [new Uint8Array([9])] };
    expect(buildDocumentJoinOfferTbs(l2)).not.toEqual(base);
    const v2 = { ...offer, invitee_agent_id: "e".repeat(64) };
    expect(buildDocumentJoinOfferTbs(v2)).not.toEqual(base);
  });
});

describe("join offer wire — strict round-trip", () => {
  it("survives encode → decode with every field intact", () => {
    const { offer } = makeOffer();
    expect(decodeDocumentJoinOffer(encodeDocumentJoinOffer(offer))).toEqual(offer);
  });

  it.each([
    ["genesis", /document_join_missing_field: genesis/],
    ["amendments", /document_join_missing_field: amendments/],
    ["envelope_log", /document_join_missing_field: envelope_log/],
    ["signature", /document_join_missing_field: signature/],
    ["feature_version", /document_join_missing_field: feature_version/],
  ] as const)("decode refuses a missing %s with the NAMED code", (field, expected) => {
    const { offer } = makeOffer();
    const wire = decodeCbor(encodeDocumentJoinOffer(offer)) as Record<string, unknown>;
    delete wire[field];
    expect(() => decodeDocumentJoinOffer(encodeCbor(wire))).toThrow(expected);
  });

  it("copies byte payloads out of the wire rather than aliasing it", () => {
    const { offer } = makeOffer();
    const wire = encodeDocumentJoinOffer(offer);
    const decoded = decodeDocumentJoinOffer(wire);
    wire.fill(0);
    expect(decoded.genesis).toEqual(offer.genesis);
    expect(decoded.amendments[0]).toEqual(offer.amendments[0]);
  });
});

describe("validateDocumentJoinOffer — the invitee derives, never trusts", () => {
  it("a well-formed offer validates: arrangement derived, invitee admitted at the head epoch", () => {
    const { offer, a, b, c } = makeOffer();
    const r = validateDocumentJoinOffer(offer, documentGovernancePolicy, makeVerify([a, b, c]));
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.arrangement.participants.has(c.agentId)).toBe(true);
    expect(r.arrangement.epoch).toBe(1);
    expect([...r.arrangement.admins].sort()).toEqual([a.agentId, b.agentId].sort());
  });

  it("refuses an offer whose signature is not the INVITER's", () => {
    const { offer, a, b, c } = makeOffer();
    const outsider = makeSigner();
    const forged = { ...offer, signature: outsider.sign(buildDocumentJoinOfferTbs(offer)) };
    const r = validateDocumentJoinOffer(forged, documentGovernancePolicy, makeVerify([a, b, c, outsider]));
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toMatch(/join_signature_invalid/);
  });

  it("refuses a genesis whose hash is not the offer's document_id — the anchor cannot be swapped", () => {
    const { offer, a, b, c } = makeOffer();
    const rival = makeGenesis(a, b, [a]);
    const swapped = { ...offer, genesis: rival.bytes };
    const resigned = { ...swapped, signature: a.sign(buildDocumentJoinOfferTbs(swapped)) };
    const r = validateDocumentJoinOffer(resigned, documentGovernancePolicy, makeVerify([a, b, c]));
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toMatch(/join_genesis_mismatch/);
  });

  it("refuses when the chain does not replay — an under-signed pending amendment admits nobody", () => {
    const a = makeSigner();
    const b = makeSigner();
    const c = makeSigner();
    const g = makeGenesis(a, b, [a, b]);
    // b is NOT the claimed signer — the amendment claims a non-admin outsider.
    const outsider = makeSigner();
    const bad = makeAddHolder(g.documentId, c, outsider);
    const offer: DocumentJoinOffer = {
      type: "document_join_offer",
      feature_version: DOCUMENT_FEATURE_VERSION,
      inviter_agent_id: a.agentId,
      invitee_agent_id: c.agentId,
      document_id: g.documentId,
      genesis: g.bytes,
      amendments: [new Uint8Array(encodeDocumentAmendment(bad))],
      envelope_log: [],
      offered_at_ms: 1,
      signature: new Uint8Array(0),
    };
    offer.signature = a.sign(buildDocumentJoinOfferTbs(offer));
    const r = validateDocumentJoinOffer(offer, documentGovernancePolicy, makeVerify([a, b, c, outsider]));
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toMatch(/governance_not_admin/);
  });

  it("refuses when the chain's LAST amendment does not admit THIS invitee", () => {
    const { offer, a, b, c } = makeOffer();
    const stranger = makeSigner();
    const misaddressed = { ...offer, invitee_agent_id: stranger.agentId };
    const resigned = { ...misaddressed, signature: a.sign(buildDocumentJoinOfferTbs(misaddressed)) };
    const r = validateDocumentJoinOffer(resigned, documentGovernancePolicy, makeVerify([a, b, c, stranger]));
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toMatch(/join_not_for_invitee/);
  });

  it("refuses an inviter who did not sign the pending amendment — the offer's author must be behind the admission", () => {
    const { offer, a, b, c } = makeOffer();
    // b re-authors the offer around a's amendment: b is an admin, but the pending amendment's
    // claimed signer is a — an offer must come from someone actually behind the admission.
    const reauthored = { ...offer, inviter_agent_id: b.agentId };
    const resigned = { ...reauthored, signature: b.sign(buildDocumentJoinOfferTbs(reauthored)) };
    const r = validateDocumentJoinOffer(resigned, documentGovernancePolicy, makeVerify([a, b, c]));
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toMatch(/join_inviter_not_signer/);
  });

  it("refuses a feature-version mismatch with a sentence, not a hang", () => {
    const { offer, a, b, c } = makeOffer();
    const newer = { ...offer, feature_version: DOCUMENT_FEATURE_VERSION + 1 };
    const resigned = { ...newer, signature: a.sign(buildDocumentJoinOfferTbs(newer)) };
    const r = validateDocumentJoinOffer(resigned, documentGovernancePolicy, makeVerify([a, b, c]));
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toMatch(/join_feature_version/);
    expect(r.reason).toMatch(/upgrade/);
  });

  it("surfaces what the invitee is consenting TO: the derived rules, not the offer's claims", () => {
    const { offer, a, b, c } = makeOffer();
    const r = validateDocumentJoinOffer(offer, documentGovernancePolicy, makeVerify([a, b, c]));
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    // The genesis properties come back DECODED from the carried bytes — the consent surface.
    expect(r.genesis.properties.assurance_tier).toBe("authenticated");
    expect(r.genesis.properties.admin_set).toEqual([a.agentId, b.agentId].sort());
  });
});

describe("the envelope-log snapshot is hash-bound, not free-riding", () => {
  it("tampering with a carried log envelope breaks the offer's signature", () => {
    const { offer, a, b, c } = makeOffer();
    const withLog = { ...offer, envelope_log: [new Uint8Array([1, 2, 3])] };
    const signed = { ...withLog, signature: a.sign(buildDocumentJoinOfferTbs(withLog)) };
    const tampered = { ...signed, envelope_log: [new Uint8Array([1, 2, 4])] };
    const r = validateDocumentJoinOffer(tampered, documentGovernancePolicy, makeVerify([a, b, c]));
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toMatch(/join_signature_invalid/);
  });
});

