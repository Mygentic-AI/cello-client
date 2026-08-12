/**
 * DOD-DOC-HANDSHAKE-1 — the document proposal envelope and the seam it enforces.
 *
 * The load-bearing property is that `document_id` IS the hash of this envelope. A signature that
 * two honest builds compute differently is an ordinary bug; an ID that two honest builds compute
 * differently puts the two parties on two documents while each believes they share one.
 */

import { describe, it, expect } from "vitest";
import { encodeCbor, decodeCbor } from "../cbor.js";
import {
  DOCUMENT_PROPOSAL_DOMAIN,
  DOCUMENT_FEATURE_VERSION,
  ASSURANCE_TIER_V1,
  TOPOLOGY_DEFAULT,
  SUPPORTED_TOPOLOGIES,
  buildDocumentProposalTbs,
  documentIdFromProposal,
  encodeDocumentProposal,
  decodeDocumentProposal,
  seamViolation,
  documentFeatureIncompatibility,
  type DocumentProposalEnvelope,
  type DocumentProperties,
} from "../document-proposal.js";

function props(over: Partial<DocumentProperties> = {}): DocumentProperties {
  return {
    assurance_tier: ASSURANCE_TIER_V1,
    schema_enforcement: false,
    topology: TOPOLOGY_DEFAULT,
    append_only: false,
    ...over,
  };
}

function proposal(over: Partial<DocumentProposalEnvelope> = {}): DocumentProposalEnvelope {
  return {
    type: "document_proposal",
    feature_version: DOCUMENT_FEATURE_VERSION,
    proposer_agent_id: "agent-a",
    peer_agent_id: "agent-b",
    document_type: "markdown",
    properties: props(),
    starting_content: new Uint8Array([1, 2, 3]),
    nonce: new Uint8Array([9, 9]),
    proposed_at_ms: 1_700_000_000_000,
    signature: new Uint8Array(64).fill(5),
    ...over,
  };
}

describe("document proposal — CBOR round-trip", () => {
  it("survives encode → decode with every field intact", () => {
    const original = proposal();
    expect(decodeDocumentProposal(encodeDocumentProposal(original))).toEqual(original);
  });

  it("round-trips a proposal with NO starting content, as explicit null", () => {
    const decoded = decodeDocumentProposal(
      encodeDocumentProposal(proposal({ starting_content: null })),
    );
    expect(decoded.starting_content).toBeNull();
  });

  it("carries content_profile on the wire — the preimage signs it, so the encoding must too", () => {
    // The profile is in the SIGNED preimage (buildDocumentProposalTbs slot 9). An encoding that
    // drops it makes the receiver rebuild a different preimage (null) and refuse the signature of
    // every profiled proposal — the field would be agreed locally and unsendable.
    const original = proposal({ properties: { ...props(), content_profile: "ascii-markdown" } });
    const decoded = decodeDocumentProposal(encodeDocumentProposal(original));
    expect(decoded.properties.content_profile).toBe("ascii-markdown");
    expect(buildDocumentProposalTbs(decoded)).toEqual(buildDocumentProposalTbs(original));
  });

  it("a proposal with NO profile round-trips with the field absent, not null", () => {
    const decoded = decodeDocumentProposal(encodeDocumentProposal(proposal()));
    expect("content_profile" in decoded.properties).toBe(false);
  });

  it("carries admin_set on the wire, canonicalized sorted — the SET is signed, not the typing order", () => {
    const admins = ["bb".repeat(32), "aa".repeat(32)];
    const original = proposal({ properties: { ...props(), admin_set: admins } });
    const decoded = decodeDocumentProposal(encodeDocumentProposal(original));
    expect(decoded.properties.admin_set).toEqual([...admins].sort());
    expect(buildDocumentProposalTbs(decoded)).toEqual(buildDocumentProposalTbs(original));
    expect(
      documentIdFromProposal(proposal({ properties: { ...props(), admin_set: [...admins].reverse() } })),
    ).toBe(documentIdFromProposal(original));
  });

  it("a DIFFERENT admin set is a DIFFERENT document — the slot is in the id", () => {
    const one = proposal({ properties: { ...props(), admin_set: ["aa".repeat(32)] } });
    const two = proposal({ properties: { ...props(), admin_set: ["bb".repeat(32)] } });
    const none = proposal();
    expect(documentIdFromProposal(one)).not.toBe(documentIdFromProposal(two));
    expect(documentIdFromProposal(one)).not.toBe(documentIdFromProposal(none));
  });

  it("refuses a NON-HEX admin — the joined-scalar TBS is collision-free only because the charset is enforced", () => {
    // AMEND-1 review F1: "aa,bb" as one entry would fold to the same preimage as two entries
    // ["aa","bb"] — one document_id, one signature, two admin sets. The 64-hex rule IS the boundary.
    for (const bad of [["aa,bb"], ["AA".repeat(32)], ["not-a-key"], ["aa".repeat(31)]]) {
      expect(seamViolation({ ...props(), admin_set: bad })).toMatch(/document_proposal_admin_set/);
      expect(() =>
        encodeDocumentProposal(proposal({ properties: { ...props(), admin_set: bad } })),
      ).toThrow(/document_proposal_admin_set/);
    }
  });

  it("refuses a duplicate admin and an empty admin list with NAMED errors", () => {
    const dup = "aa".repeat(32);
    expect(() =>
      encodeDocumentProposal(proposal({ properties: { ...props(), admin_set: [dup, dup] } })),
    ).toThrow(/document_proposal_admin_set/);
    expect(seamViolation({ ...props(), admin_set: [] })).toMatch(/document_proposal_admin_set/);
    expect(seamViolation({ ...props(), admin_set: [dup, dup] })).toMatch(/document_proposal_admin_set/);
    expect(seamViolation({ ...props(), admin_set: [dup] })).toBeNull();
  });

  it("refuses a malformed content_profile with a NAMED error, never a silent default", () => {
    const raw = decodeCbor(encodeDocumentProposal(proposal())) as Record<string, unknown>;
    const props = raw["properties"] as Record<string, unknown>;
    for (const bad of [42, "", null]) {
      props["content_profile"] = bad;
      expect(() => decodeDocumentProposal(encodeCbor(raw))).toThrow(
        /document_proposal_field_type: properties\.content_profile/,
      );
    }
  });

  it("copies byte fields out of the wire rather than aliasing it", () => {
    const wire = encodeDocumentProposal(proposal());
    const decoded = decodeDocumentProposal(wire);
    wire.fill(0);
    expect(Array.from(decoded.starting_content!)).toEqual([1, 2, 3]);
    expect(Array.from(decoded.nonce)).toEqual([9, 9]);
  });
});

describe("document proposal — the decoder refuses rather than defaulting", () => {
  const raw = (o: Record<string, unknown>): Uint8Array => encodeCbor(o);
  const asMap = (e: DocumentProposalEnvelope): Record<string, unknown> =>
    decodeCbor(encodeDocumentProposal(e)) as Record<string, unknown>;

  it("refuses an absent seam property instead of supplying this build's own preference", () => {
    for (const field of ["assurance_tier", "schema_enforcement", "topology"]) {
      const map = asMap(proposal());
      delete (map.properties as Record<string, unknown>)[field];
      // A defaulted seam field is a property the peer never declared, admitted under our own
      // preference — and the peer then believes it agreed to something it never sent.
      expect(() => decodeDocumentProposal(raw(map))).toThrow(
        new RegExp(`document_proposal_(missing_field|field_type).*${field}`),
      );
    }
  });

  it("refuses an absent feature_version — the mismatch answer depends on it", () => {
    const map = asMap(proposal());
    delete map.feature_version;
    expect(() => decodeDocumentProposal(raw(map))).toThrow(/document_proposal_missing_field/);
  });

  it("refuses a non-boolean schema_enforcement rather than coercing it", () => {
    const map = asMap(proposal());
    (map.properties as Record<string, unknown>).schema_enforcement = "false";
    // The string "false" is truthy. Coerced, a proposal asking for enforcement ON would be
    // recorded as OFF and both sides would believe they agreed on something neither asked for.
    expect(() => decodeDocumentProposal(raw(map))).toThrow(/schema_enforcement/);
  });

  it("DECODES a proposal whose seam values this build cannot honour", () => {
    // Deliberate: a V2 proposal must remain decodable so it can be ANSWERED with a reason. A
    // decoder that refused it would leave the proposal unanswered, which is the silent hang the
    // feature version exists to replace.
    const decoded = decodeDocumentProposal(
      encodeDocumentProposal(proposal({ properties: props({ topology: "star" }) })),
    );
    expect(decoded.properties.topology).toBe("star");
    expect(seamViolation(decoded.properties)).toMatch(/document_seam_topology/);
  });
});

describe("document proposal — the seam is refused, and says which property", () => {
  it("accepts the one supported combination", () => {
    expect(seamViolation(props())).toBeNull();
  });

  it("refuses an attested assurance tier, naming it", () => {
    const reason = seamViolation(props({ assurance_tier: "attested" }));
    expect(reason).toMatch(/document_seam_assurance_tier/);
    expect(reason).toContain("attested");
  });

  it("refuses schema_enforcement: true", () => {
    expect(seamViolation(props({ schema_enforcement: true }))).toMatch(
      /document_seam_schema_enforcement/,
    );
  });

  it("accepts BOTH surviving topologies and refuses anything else, naming the mismatch", () => {
    expect(seamViolation(props({ topology: "mesh" }))).toBeNull();
    expect(seamViolation(props({ topology: "hub-and-spoke" }))).toBeNull();
    const r = seamViolation(props({ topology: "star" }));
    expect(r).toMatch(/document_seam_topology/);
    expect(r).toContain('"star"');
    expect(SUPPORTED_TOPOLOGIES.has(TOPOLOGY_DEFAULT)).toBe(true);
    // The VALUE, pinned: reverting the default to hub-and-spoke kept every symbolic assertion
    // green — "mesh becomes the default" had zero revert-surviving coverage.
    expect(TOPOLOGY_DEFAULT).toBe("mesh");
  });

  it("append_only is NOT a seam field — both values are legitimate", () => {
    expect(seamViolation(props({ append_only: true }))).toBeNull();
    expect(seamViolation(props({ append_only: false }))).toBeNull();
  });
});

describe("document proposal — a version mismatch gets a human answer, never a timeout", () => {
  it("says nothing when the peer matches", () => {
    expect(documentFeatureIncompatibility(DOCUMENT_FEATURE_VERSION)).toBeNull();
  });

  it("tells the operator to ask a peer with no document support to upgrade", () => {
    const msg = documentFeatureIncompatibility(null);
    // The alternative to this sentence is a proposal that is never answered — which surfaces as a
    // hang and gets diagnosed as a network fault.
    expect(msg).toContain("doesn't support shared documents");
    expect(msg).toContain("upgrade");
  });

  it("points at the RIGHT side when the peer is newer than this build", () => {
    const msg = documentFeatureIncompatibility(DOCUMENT_FEATURE_VERSION + 1);
    expect(msg).toContain("upgrade this client");
  });

  it("points at the peer when the peer is older", () => {
    const msg = documentFeatureIncompatibility(DOCUMENT_FEATURE_VERSION - 1);
    expect(msg).toContain("ask them to upgrade");
  });
});

describe("document proposal — document_id is the hash, so canonicalization is identity", () => {
  it("is a 32-byte hex digest over the signed preimage, and excludes the signature", () => {
    const id = documentIdFromProposal(proposal());
    expect(id).toMatch(/^[0-9a-f]{64}$/);
    // Re-signing must not change the identity of an already-accepted document.
    expect(documentIdFromProposal(proposal({ signature: new Uint8Array(64).fill(1) }))).toBe(id);
  });

  it("changes when ANY agreed term changes", () => {
    const id = documentIdFromProposal(proposal());
    expect(documentIdFromProposal(proposal({ document_type: "yaml" }))).not.toBe(id);
    expect(documentIdFromProposal(proposal({ peer_agent_id: "agent-c" }))).not.toBe(id);
    expect(documentIdFromProposal(proposal({ nonce: new Uint8Array([9, 8]) }))).not.toBe(id);
    expect(documentIdFromProposal(proposal({ proposed_at_ms: 1 }))).not.toBe(id);
    expect(documentIdFromProposal(proposal({ starting_content: null }))).not.toBe(id);
    expect(documentIdFromProposal(proposal({ feature_version: DOCUMENT_FEATURE_VERSION + 1 }))).not.toBe(id);
    for (const p of [
      props({ assurance_tier: "attested" }),
      props({ schema_enforcement: true }),
      props({ topology: "hub-and-spoke" }),
      props({ append_only: true }),
    ]) {
      expect(documentIdFromProposal(proposal({ properties: p }))).not.toBe(id);
    }
  });

  it("two identical proposals differing ONLY by nonce get different ids", () => {
    // Without this, proposing the same document twice to the same peer in the same millisecond
    // would collide onto one id and the second proposal would silently join the first's document.
    expect(documentIdFromProposal(proposal({ nonce: new Uint8Array([1]) }))).not.toBe(
      documentIdFromProposal(proposal({ nonce: new Uint8Array([2]) })),
    );
  });

  it("is INDEPENDENT of the order the proposal object was built in", () => {
    const a = proposal();
    const b: DocumentProposalEnvelope = {
      signature: a.signature,
      proposed_at_ms: a.proposed_at_ms,
      nonce: a.nonce,
      starting_content: a.starting_content,
      // The properties rebuilt in reverse too — this is the field most likely to be assembled in
      // a different order by a second implementation, and it is nested.
      properties: {
        append_only: a.properties.append_only,
        topology: a.properties.topology,
        schema_enforcement: a.properties.schema_enforcement,
        assurance_tier: a.properties.assurance_tier,
      },
      document_type: a.document_type,
      peer_agent_id: a.peer_agent_id,
      proposer_agent_id: a.proposer_agent_id,
      feature_version: a.feature_version,
      type: a.type,
    };
    // encodeCbor is NOT deterministic for maps — keys follow insertion order. A nested `properties`
    // map inside the preimage would make the document_id depend on build order, which puts two
    // honest parties on two different documents while each believes they share one.
    expect(documentIdFromProposal(b)).toBe(documentIdFromProposal(a));
  });

  it("is an ARRAY with the domain in slot 0, and the properties are FLATTENED", () => {
    const arr = decodeCbor(buildDocumentProposalTbs(proposal(), { preHash: false })) as unknown[];
    expect(Array.isArray(arr)).toBe(true);
    expect(arr[0]).toBe(DOCUMENT_PROPOSAL_DOMAIN);
    // No nested container anywhere in the preimage: every element is a scalar or raw bytes.
    for (const slot of arr) {
      expect(Array.isArray(slot)).toBe(false);
      if (slot !== null && typeof slot === "object") expect(slot).toBeInstanceOf(Uint8Array);
    }
  });

  it("cannot be confused with an UPDATE envelope's preimage", () => {
    // Both are CBOR arrays hashed with SHA-256 and both land in id-shaped columns. The domain tag
    // in slot 0 is the only thing keeping a proposal from ever hashing to an update's digest.
    const arr = decodeCbor(buildDocumentProposalTbs(proposal(), { preHash: false })) as unknown[];
    expect(arr[0]).not.toBe("CELLO-DOCUMENT-UPDATE-v1");
  });
});

describe("document proposal TBS — the FROZEN vector", () => {
  /**
   * The conformance artifact. Every other test here asserts only "these two differ", which leaves
   * field ORDER and arity unpinned — and for THIS envelope the preimage is the document's identity,
   * so a reordering does not merely break signatures, it silently forks every document created
   * across the change. If this fails, the wire changed: decide that deliberately and reissue the
   * vector. Never edit it to match new output.
   */
  const FROZEN: DocumentProposalEnvelope = {
    type: "document_proposal",
    feature_version: 1,
    proposer_agent_id: "vector-proposer",
    peer_agent_id: "vector-peer",
    document_type: "markdown",
    properties: {
      assurance_tier: "authenticated",
      schema_enforcement: false,
      topology: "hub-and-spoke",
      append_only: true,
    },
    starting_content: new Uint8Array([0, 1, 2, 3]),
    nonce: new Uint8Array([4, 5, 6, 7]),
    proposed_at_ms: 1_700_000_000_000,
    signature: new Uint8Array(64).fill(0xcd),
  };

  it("the document_id is byte-for-byte what it was the day it was frozen", () => {
    // REISSUED 2026-08-06, deliberately and for the second time — see the preimage builder's own
    // note about the first. `DOD-DOC-PROFILE-1`'s `content_profile` took a slot in the signed
    // preimage, which changes the id of every proposal.
    //
    // That is the whole point of doing it now: the profile has to be bound into `document_id` for
    // "agreed at the handshake, immutable after accept" to mean anything, and the only moment that
    // rebinding is free is before anyone holds a document they care about. M14 shipped today, to
    // one operator, with no documents in existence.
    //
    // This test firing was the correct outcome, not an obstacle. A frozen vector that could be
    // edited without noticing is not a guard — if this ever fails again after real documents exist,
    // the change is a migration, not a reissue.
    // REISSUED 2026-08-11 (M14B / DOD-MP-AMEND-1): the admin_set slot entered the preimage and
    // feature_version moved to 2 — one batched change, journaled (M14B Entry 5). Documents still
    // do not exist, so rebinding is still free; the NEXT reissue after real documents exist is a
    // MIGRATION, not a reissue.
    expect(documentIdFromProposal(FROZEN)).toBe("92d03c21f3c4827271022376349b32bacd295b1d6a31d025f4f37a88e0180c41");
  });
});
