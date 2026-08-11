/**
 * DOD-MP-AMEND-1 — the amendment record and the replay that derives the arrangement.
 *
 * An amendment is an epoch event in its FINAL frame shape (TIER2-READY 1): signed via SIG-1
 * collections, chained to its predecessor, epoch_id incrementing past 0, the canonical-hash slot
 * defined-absent at Tier 1. Replaying genesis + the chain derives {participants, admins,
 * properties} identically on every holder — or refuses loudly naming the epoch and the cause.
 *
 * WHO must sign is GOVERN-1's question, injected here as a policy seam. These tests use a
 * deliberately simple policy (every current admin signs everything) so that what is proven here
 * is the MECHANICS: chaining, completeness, before-state policy consultation, application order.
 *
 * Signatures are REAL Ed25519 — no mocks for crypto.
 */
import { describe, it, expect } from "vitest";
import { createHash, generateKeyPairSync, sign as edSign, verify as edVerify } from "node:crypto";
import { decodeCbor, encodeCbor } from "../cbor.js";
import {
  DOCUMENT_AMENDMENT_DOMAIN,
  buildDocumentAmendmentTbs,
  documentAmendmentHash,
  encodeDocumentAmendment,
  decodeDocumentAmendment,
  deriveArrangement,
  MAX_DOCUMENT_HOLDERS,
  type DocumentAmendmentBody,
  type DocumentAmendmentEnvelope,
  type ArrangementGenesis,
  type SignerPolicy,
} from "../document-amendment.js";
import { DOCUMENT_MULTISIG_DOMAIN, buildDocumentMultisigTbs } from "../document-multisig.js";
import { DOCUMENT_PROPOSAL_DOMAIN } from "../document-proposal.js";

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

/** GOVERN-1's stand-in: every CURRENT admin must sign every amendment. */
const allAdminsPolicy: SignerPolicy = (_kind, _subject, state) => [...state.admins].sort();

const DOC_ID = "d".repeat(64);

function genesis(a: Signer, b: Signer, admins: Signer[] = [a]): ArrangementGenesis {
  return {
    documentId: DOC_ID,
    proposerAgentId: a.agentId,
    peerAgentId: b.agentId,
    adminSet: admins.map((s) => s.agentId),
    properties: { assurance_tier: "authenticated", schema_enforcement: false, topology: "mesh", append_only: false },
  };
}

function body(over: Partial<DocumentAmendmentBody> = {}): DocumentAmendmentBody {
  return {
    document_id: DOC_ID,
    epoch_id: 1,
    prev_amendment_hash: null,
    kind: "add_holder",
    subject_agent_id: "c".repeat(64),
    property_change: null,
    state_hash: null,
    authored_at_ms: 1_700_000_000_000,
    ...over,
  };
}

/** Build a fully-signed amendment: the required set (per policy at `state`) all sign. */
function signedAmendment(
  amendBody: DocumentAmendmentBody,
  requiredSigners: Signer[],
): DocumentAmendmentEnvelope {
  const hash = documentAmendmentHash(amendBody);
  const required = requiredSigners.map((s) => s.agentId).sort();
  const tbs = buildDocumentMultisigTbs({
    document_id: amendBody.document_id,
    subject_kind: "document_amendment",
    subject_hash: hash,
    required_signers: required,
  });
  return {
    body: amendBody,
    collection: {
      document_id: amendBody.document_id,
      subject_kind: "document_amendment",
      subject_hash: hash,
      required_signers: required,
      signatures: requiredSigners.map((s) => ({
        signer_agent_id: s.agentId,
        signature: s.sign(tbs),
      })),
    },
  };
}

describe("amendment TBS — the epoch event's final frame shape", () => {
  it("is a CBOR array with the domain in slot 0, chained, with the state-hash slot occupied by null", () => {
    const arr = decodeCbor(buildDocumentAmendmentTbs(body(), { preHash: false })) as unknown[];
    expect(arr[0]).toBe(DOCUMENT_AMENDMENT_DOMAIN);
    // The Tier 2 slot is PRESENT and null — defined-absent, never omitted. Tier 2 fills a field;
    // it does not migrate a frame.
    expect(arr).toContain(null);
  });

  it("cannot be confused with a multisig or proposal preimage", () => {
    expect(DOCUMENT_AMENDMENT_DOMAIN).not.toBe(DOCUMENT_MULTISIG_DOMAIN);
    expect(DOCUMENT_AMENDMENT_DOMAIN).not.toBe(DOCUMENT_PROPOSAL_DOMAIN);
  });

  it("the hash excludes nothing that is agreed — every body field moves it", () => {
    const base = documentAmendmentHash(body());
    expect(documentAmendmentHash(body({ epoch_id: 2 }))).not.toEqual(base);
    expect(documentAmendmentHash(body({ kind: "remove_holder" }))).not.toEqual(base);
    expect(documentAmendmentHash(body({ subject_agent_id: "e".repeat(64) }))).not.toEqual(base);
    expect(
      documentAmendmentHash(body({ prev_amendment_hash: "ab".repeat(32) })),
    ).not.toEqual(base);
    expect(
      documentAmendmentHash(body({ kind: "change_property", subject_agent_id: null, property_change: { key: "append_only", value: true } })),
    ).not.toEqual(base);
  });

  it("FROZEN VECTOR — field order is wire law; regenerate only on a journaled preimage change", () => {
    const tbs = buildDocumentAmendmentTbs({
      document_id: "ab".repeat(32),
      epoch_id: 1,
      prev_amendment_hash: null,
      kind: "add_holder",
      subject_agent_id: "cd".repeat(32),
      property_change: null,
      state_hash: null,
      authored_at_ms: 1_700_000_000_000,
    });
    expect(Buffer.from(tbs).toString("hex")).toBe(
      "53cbe466aab49c6c1db5bce80fea33f0c803eefa9af53d2a51db3a9a3a60379c",
    );
  });
});

describe("amendment wire — strict round-trip", () => {
  it("survives encode → decode with every field intact", () => {
    const a = makeSigner();
    const env = signedAmendment(body(), [a]);
    expect(decodeDocumentAmendment(encodeDocumentAmendment(env))).toEqual(env);
  });

  it.each([
    ["document_id", undefined, /document_amendment_missing_field: document_id/],
    ["epoch_id", undefined, /document_amendment_missing_field: epoch_id/],
    ["epoch_id", 0, /document_amendment_epoch: must be a positive integer/],
    ["kind", "make_owner", /document_amendment_kind/],
    ["prev_amendment_hash", undefined, /document_amendment_missing_field: prev_amendment_hash/],
    ["state_hash", undefined, /document_amendment_missing_field: state_hash/],
    ["subject_agent_id", undefined, /document_amendment_missing_field: subject_agent_id/],
  ] as const)(
    "decode refuses body.%s = %j with the NAMED code",
    (field, value, expected) => {
      const env = signedAmendment(body(), [makeSigner()]);
      const wire = decodeCbor(encodeDocumentAmendment(env)) as Record<string, unknown>;
      const bodyMap = wire["body"] as Record<string, unknown>;
      if (value === undefined) delete bodyMap[field];
      else bodyMap[field] = value;
      expect(() => decodeDocumentAmendment(encodeCbor(wire))).toThrow(expected);
    },
  );

  it("decode refuses a missing collection — an unsigned amendment is not an amendment", () => {
    const env = signedAmendment(body(), [makeSigner()]);
    const wire = decodeCbor(encodeDocumentAmendment(env)) as Record<string, unknown>;
    delete wire["collection"];
    expect(() => decodeDocumentAmendment(encodeCbor(wire))).toThrow(
      /document_amendment_missing_field: collection/,
    );
  });
});

describe("deriveArrangement — genesis alone", () => {
  it("derives the bilateral arrangement at epoch 0 with the genesis admin set", () => {
    const a = makeSigner();
    const b = makeSigner();
    const r = deriveArrangement(genesis(a, b), [], allAdminsPolicy, makeVerify([a, b]));
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.arrangement.epoch).toBe(0);
    expect([...r.arrangement.participants].sort()).toEqual([a.agentId, b.agentId].sort());
    expect([...r.arrangement.admins]).toEqual([a.agentId]);
    expect(r.arrangement.properties["topology"]).toBe("mesh");
    expect(r.arrangement.lastAmendmentHash).toBeNull();
  });

  it("refuses a genesis whose admin set contains a non-participant", () => {
    const a = makeSigner();
    const b = makeSigner();
    const outsider = makeSigner();
    const g = { ...genesis(a, b), adminSet: [outsider.agentId] };
    const r = deriveArrangement(g, [], allAdminsPolicy, makeVerify([a, b]));
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toMatch(/arrangement_admin_not_participant/);
  });
});

describe("deriveArrangement — the chain", () => {
  function threeParty() {
    const a = makeSigner();
    const b = makeSigner();
    const c = makeSigner();
    const g = genesis(a, b);
    const first = signedAmendment(body({ subject_agent_id: c.agentId }), [a]);
    return { a, b, c, g, first, verify: makeVerify([a, b, c]) };
  }

  it("a complete add_holder amendment admits the holder and increments the epoch", () => {
    const { a, b, c, g, first, verify } = threeParty();
    const r = deriveArrangement(g, [first], allAdminsPolicy, verify);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.arrangement.epoch).toBe(1);
    expect([...r.arrangement.participants].sort()).toEqual(
      [a.agentId, b.agentId, c.agentId].sort(),
    );
    expect(r.arrangement.lastAmendmentHash).toEqual(
      Buffer.from(documentAmendmentHash(first.body)).toString("hex"),
    );
  });

  it("REFUSES an amendment whose collection is incomplete, naming the missing signer", () => {
    const { a, c, g, verify } = threeParty();
    const amendBody = body({ subject_agent_id: c.agentId });
    // The RIGHT required set ({a}, the sole admin), zero signatures gathered — a partial
    // collection is storable, never valid.
    const partial: DocumentAmendmentEnvelope = {
      body: amendBody,
      collection: {
        document_id: amendBody.document_id,
        subject_kind: "document_amendment",
        subject_hash: documentAmendmentHash(amendBody),
        required_signers: [a.agentId],
        signatures: [],
      },
    };
    const r = deriveArrangement(g, [partial], allAdminsPolicy, verify);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toMatch(/amendment_collection_incomplete/);
    expect(r.reason).toContain(a.agentId);
  });

  it("REFUSES a collection whose required set differs from the policy's answer", () => {
    const { b, c, g, verify } = threeParty();
    // b is not an admin; a collection b signs alone must not admit c even if complete on its own terms.
    const rogue = signedAmendment(body({ subject_agent_id: c.agentId }), [b]);
    const r = deriveArrangement(g, [rogue], allAdminsPolicy, verify);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toMatch(/amendment_required_set_mismatch/);
    expect(r.epoch).toBe(1);
  });

  it("REFUSES a gap — epoch 2 following genesis with no epoch 1", () => {
    const { c, g, verify } = threeParty();
    const skipped = signedAmendment(body({ epoch_id: 2, subject_agent_id: c.agentId }), [
      // policy at genesis: admin a — but the chain check fires first regardless of signatures
      makeSigner(),
    ]);
    const r = deriveArrangement(g, [skipped], allAdminsPolicy, verify);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toMatch(/amendment_chain_gap/);
  });

  it("REFUSES a wrong predecessor hash — a fork is named, not absorbed", () => {
    const { a, c, g, first, verify } = threeParty();
    const second = signedAmendment(
      body({
        epoch_id: 2,
        prev_amendment_hash: "00".repeat(32),
        kind: "promote_admin",
        subject_agent_id: c.agentId,
      }),
      [a],
    );
    const r = deriveArrangement(g, [first, second], allAdminsPolicy, verify);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toMatch(/amendment_chain_broken/);
    expect(r.epoch).toBe(2);
  });

  it("consults the policy against the state BEFORE each amendment — a newly-promoted admin co-signs the NEXT one", () => {
    const { a, b, c, g, first, verify } = threeParty();
    const promote = signedAmendment(
      body({
        epoch_id: 2,
        prev_amendment_hash: Buffer.from(documentAmendmentHash(first.body)).toString("hex"),
        kind: "promote_admin",
        subject_agent_id: b.agentId,
      }),
      [a], // policy BEFORE this amendment: admins = {a}
    );
    const third = signedAmendment(
      body({
        epoch_id: 3,
        prev_amendment_hash: Buffer.from(documentAmendmentHash(promote.body)).toString("hex"),
        kind: "remove_holder",
        subject_agent_id: c.agentId,
      }),
      [a, b], // policy AFTER the promotion: admins = {a, b} — BOTH must sign
    );
    const r = deriveArrangement(g, [first, promote, third], allAdminsPolicy, verify);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.arrangement.epoch).toBe(3);
    expect([...r.arrangement.admins].sort()).toEqual([a.agentId, b.agentId].sort());
    expect(r.arrangement.participants.has(c.agentId)).toBe(false);
  });
});

describe("deriveArrangement — subject rules", () => {
  function setup() {
    const a = makeSigner();
    const b = makeSigner();
    return { a, b, g: genesis(a, b), verify: makeVerify([a, b]) };
  }

  it("refuses adding a holder who already holds — never a silent no-op", () => {
    const { a, b, g, verify } = setup();
    const dup = signedAmendment(body({ subject_agent_id: b.agentId }), [a]);
    const r = deriveArrangement(g, [dup], allAdminsPolicy, verify);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toMatch(/amendment_subject_already_holder/);
  });

  it("refuses removing a non-participant, promoting a non-participant, and demoting a non-admin", () => {
    const { a, b, g, verify } = setup();
    const ghost = "f".repeat(64);
    for (const [kind, subject, code] of [
      ["remove_holder", ghost, /amendment_subject_not_holder/],
      ["promote_admin", ghost, /amendment_subject_not_holder/],
      ["remove_admin", b.agentId, /amendment_subject_not_admin/],
    ] as const) {
      const env = signedAmendment(body({ kind, subject_agent_id: subject }), [a]);
      const r = deriveArrangement(g, [env], allAdminsPolicy, verify);
      expect(r.ok).toBe(false);
      if (r.ok) return;
      expect(r.reason).toMatch(code);
    }
  });

  it("change_property updates the DERIVED view — the genesis record is not touched", () => {
    const { a, g, verify } = setup();
    const change = signedAmendment(
      body({ kind: "change_property", subject_agent_id: null, property_change: { key: "append_only", value: true } }),
      [a],
    );
    const r = deriveArrangement(g, [change], allAdminsPolicy, verify);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.arrangement.properties["append_only"]).toBe(true);
    expect(g.properties["append_only"]).toBe(false);
  });

  it("refuses a change to an IDENTITY property — assurance_tier changes are epoch events Tier 2 owns", () => {
    const { a, b, g, verify } = setup();
    void b;
    const change = signedAmendment(
      body({ kind: "change_property", subject_agent_id: null, property_change: { key: "assurance_tier", value: "attested" } }),
      [a],
    );
    const r = deriveArrangement(g, [change], allAdminsPolicy, verify);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toMatch(/amendment_property_not_amendable/);
  });

  it("refuses a non-null state_hash while the tier is authenticated — the slot is Tier 2's", () => {
    const { a, b, g, verify } = setup();
    void b;
    const withHash = signedAmendment(
      body({ state_hash: new Uint8Array(32).fill(9) }),
      [a],
    );
    const r = deriveArrangement(g, [withHash], allAdminsPolicy, verify);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toMatch(/amendment_state_hash_tier/);
  });

  it("refuses a genesis with NO admins — a document nobody can amend is a dead end, named at creation", () => {
    const a = makeSigner();
    const b = makeSigner();
    const r = deriveArrangement(
      { ...genesis(a, b), adminSet: [] },
      [],
      allAdminsPolicy,
      makeVerify([a, b]),
    );
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toMatch(/arrangement_admin_set_empty/);
  });

  it("refuses removing the LAST admin — by demotion or by removal as holder", () => {
    const { a, b, g, verify } = setup();
    void b;
    for (const kind of ["remove_admin", "remove_holder"] as const) {
      const env = signedAmendment(body({ kind, subject_agent_id: a.agentId }), [a]);
      const r = deriveArrangement(g, [env], allAdminsPolicy, verify);
      expect(r.ok).toBe(false);
      if (r.ok) return;
      expect(r.reason).toMatch(/amendment_last_admin/);
    }
  });

  it("removing a holder who is an admin (with another admin standing) drops BOTH memberships", () => {
    const a = makeSigner();
    const b = makeSigner();
    const g = genesis(a, b, [a, b]); // both admins
    const env = signedAmendment(body({ kind: "remove_holder", subject_agent_id: b.agentId }), [a, b]);
    const r = deriveArrangement(g, [env], allAdminsPolicy, makeVerify([a, b]));
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.arrangement.participants.has(b.agentId)).toBe(false);
    expect(r.arrangement.admins.has(b.agentId)).toBe(false);
  });

  it("enforces the 20-holder cap at amendment validation", () => {
    const a = makeSigner();
    const b = makeSigner();
    const g = genesis(a, b);
    const amendments: DocumentAmendmentEnvelope[] = [];
    let prev: string | null = null;
    // Fill to the cap: 2 genesis holders + 18 additions = 20.
    for (let i = 0; i < MAX_DOCUMENT_HOLDERS - 2 + 1; i++) {
      const subject = createHash("sha256").update(`holder-${i}`).digest("hex");
      const amendBody = body({ epoch_id: i + 1, prev_amendment_hash: prev, subject_agent_id: subject });
      const env = signedAmendment(amendBody, [a]);
      amendments.push(env);
      prev = Buffer.from(documentAmendmentHash(amendBody)).toString("hex");
    }
    const r = deriveArrangement(g, amendments, allAdminsPolicy, makeVerify([a, b]));
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toMatch(/amendment_holder_cap/);
    expect(r.epoch).toBe(MAX_DOCUMENT_HOLDERS - 2 + 1);
  });
});
