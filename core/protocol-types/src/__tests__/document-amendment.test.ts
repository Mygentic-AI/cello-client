/**
 * SYNC-P1 — the entry record (v2): the wire shape, the signed preimage, and its frozen vector.
 *
 * An entry is signed via SIG-1 collections and carries the causal fields — author, own-chain
 * seq, parents — inside the TBS, so a forwarder cannot re-attribute, re-sequence, or re-parent
 * without every signature failing. DERIVATION lives in document-derive.test.ts; this file owns
 * the codec.
 *
 * Signatures are REAL Ed25519 — no mocks for crypto.
 */
import { describe, it, expect } from "vitest";
import { createHash, generateKeyPairSync, sign as edSign } from "node:crypto";
import { decodeCbor, encodeCbor } from "../cbor.js";
import {
  DOCUMENT_AMENDMENT_DOMAIN,
  buildDocumentAmendmentTbs,
  documentAmendmentHash,
  encodeDocumentAmendment,
  decodeDocumentAmendment,
  type DocumentAmendmentBody,
  type DocumentAmendmentEnvelope,
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

const DOC_ID = "d".repeat(64);

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
    author_agent_id: "a".repeat(64),
    author_seq: 1,
    parents: [],
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
    // SYNC-P1: the causal fields are agreed too — a forwarder must not be able to re-attribute,
    // re-sequence, or re-parent an entry without every signature failing.
    expect(documentAmendmentHash(body({ author_agent_id: "b".repeat(64) }))).not.toEqual(base);
    expect(documentAmendmentHash(body({ author_seq: 2 }))).not.toEqual(base);
    expect(documentAmendmentHash(body({ parents: ["ab".repeat(32)] }))).not.toEqual(base);
  });

  it("carries the causal fields in the signed slots after the linear carrier fields", () => {
    const arr = decodeCbor(
      buildDocumentAmendmentTbs(
        body({ author_agent_id: "f".repeat(64), author_seq: 3, parents: ["ab".repeat(32), "cd".repeat(32)] }),
        { preHash: false },
      ),
    ) as unknown[];
    expect(arr[10]).toBe("f".repeat(64));
    expect(arr[11]).toBe(3);
    expect(arr[12]).toEqual(["ab".repeat(32), "cd".repeat(32)]);
  });

  it("FROZEN VECTOR — field order is wire law; regenerate only on a journaled preimage change", () => {
    // SYNC-P1 (journaled: M14B Entry 49) — the preimage gained author_agent_id, author_seq,
    // parents, and the domain moved to v2. The prior v1 vector is retired with the domain.
    const tbs = buildDocumentAmendmentTbs({
      document_id: "ab".repeat(32),
      epoch_id: 1,
      prev_amendment_hash: null,
      kind: "add_holder",
      subject_agent_id: "cd".repeat(32),
      property_change: null,
      state_hash: null,
      authored_at_ms: 1_700_000_000_000,
      author_agent_id: "ef".repeat(32),
      author_seq: 1,
      parents: [],
    });
    expect(Buffer.from(tbs).toString("hex")).toBe(
      "bb3053db48b53847bd5fd12879e6353f9fd7d5f6e0762fb6040f2a2b3d3f0528",
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
    ["author_agent_id", undefined, /document_amendment_missing_field: author_agent_id/],
    ["author_agent_id", "not-hex", /document_amendment_field_type: author_agent_id/],
    ["author_seq", undefined, /document_amendment_missing_field: author_seq/],
    ["author_seq", 0, /document_amendment_author_seq: must be a positive integer/],
    ["parents", undefined, /document_amendment_missing_field: parents/],
    ["parents", ["zz"], /document_amendment_field_type: parents/],
    // Canonical order is wire law: a forwarder shuffling parents must not mint a second identity
    // for the same entry — and since parents are in the TBS, a shuffle also breaks every signature.
    ["parents", ["cd".repeat(32), "ab".repeat(32)], /document_amendment_parents_canonical/],
    ["parents", ["ab".repeat(32), "ab".repeat(32)], /document_amendment_parents_canonical/],
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

  it("decode refuses a parent list wider than the cap — an adversary must not be able to make ancestry walks unbounded", () => {
    const wide = Array.from({ length: 65 }, (_, i) =>
      createHash("sha256").update(`parent-${i}`).digest("hex"),
    ).sort();
    const env = signedAmendment(body(), [makeSigner()]);
    const wire = decodeCbor(encodeDocumentAmendment(env)) as Record<string, unknown>;
    (wire["body"] as Record<string, unknown>)["parents"] = wide;
    expect(() => decodeDocumentAmendment(encodeCbor(wire))).toThrow(
      /document_amendment_parents_cap/,
    );
  });

  it("decode refuses a missing collection — an unsigned amendment is not an amendment", () => {
    const env = signedAmendment(body(), [makeSigner()]);
    const wire = decodeCbor(encodeDocumentAmendment(env)) as Record<string, unknown>;
    delete wire["collection"];
    expect(() => decodeDocumentAmendment(encodeCbor(wire))).toThrow(
      /document_amendment_missing_field: collection/,
    );
  });
});
