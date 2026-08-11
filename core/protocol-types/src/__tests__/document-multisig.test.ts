/**
 * DOD-MP-SIG-1 — the multi-signature primitive.
 *
 * Collect N Ed25519 signatures over ONE domain-separated preimage; a collection missing any
 * required signature is INVALID, verified independently by any holder. Generic by construction
 * (TIER2-READY lens 2): the amendment is its first consumer, Tier 2's N-way quiescence agreement
 * its named second — so nothing in here may know what an amendment is.
 *
 * Signatures are REAL Ed25519 (node:crypto) — no mocks for crypto.
 */
import { describe, it, expect } from "vitest";
import { createHash, generateKeyPairSync, sign as edSign, verify as edVerify } from "node:crypto";
import { decodeCbor, encodeCbor } from "../cbor.js";
import {
  DOCUMENT_MULTISIG_DOMAIN,
  buildDocumentMultisigTbs,
  collectionStatus,
  encodeMultisigCollection,
  decodeMultisigCollection,
  type MultisigCollection,
} from "../document-multisig.js";
import { DOCUMENT_PROPOSAL_DOMAIN } from "../document-proposal.js";

/** A real signer: Ed25519 keypair, identity = 64-hex of the raw public key. */
function makeSigner() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = publicKey.export({ type: "spki", format: "der" }).subarray(-32);
  return {
    agentId: Buffer.from(raw).toString("hex"),
    sign: (tbs: Uint8Array): Uint8Array => new Uint8Array(edSign(null, tbs, privateKey)),
    publicKey,
  };
}

/** The verifier seam, same shape the daemon injects for proposals. */
function makeVerify(signers: ReturnType<typeof makeSigner>[]) {
  const byId = new Map(signers.map((s) => [s.agentId, s.publicKey]));
  return (agentId: string, tbs: Uint8Array, signature: Uint8Array): boolean => {
    const key = byId.get(agentId);
    if (!key) return false;
    return edVerify(null, tbs, key, signature);
  };
}

const SUBJECT_HASH = new Uint8Array(createHash("sha256").update("subject").digest());

function fields(signers: string[], over: Partial<Omit<MultisigCollection, "signatures">> = {}) {
  return {
    document_id: "d".repeat(64),
    subject_kind: "document_amendment",
    subject_hash: SUBJECT_HASH,
    required_signers: signers,
    ...over,
  };
}

function signedCollection(
  signers: ReturnType<typeof makeSigner>[],
  requiredIds: string[] = signers.map((s) => s.agentId),
): MultisigCollection {
  // Sorted here because encode/decode canonicalize the set — a helper handing tests an unsorted
  // required list would make every deep-equality comparison fail on order alone.
  const base = fields([...requiredIds].sort());
  const tbs = buildDocumentMultisigTbs(base);
  return {
    ...base,
    signatures: signers.map((s) => ({ signer_agent_id: s.agentId, signature: s.sign(tbs) })),
  };
}

describe("multisig TBS — one preimage, committed to WHO must sign", () => {
  it("is a CBOR array with the domain in slot 0 and the sorted signer set inside", () => {
    const a = makeSigner();
    const b = makeSigner();
    const sorted = [a.agentId, b.agentId].sort();
    const arr = decodeCbor(
      buildDocumentMultisigTbs(fields([sorted[1]!, sorted[0]!]), { preHash: false }),
    ) as unknown[];
    expect(arr[0]).toBe(DOCUMENT_MULTISIG_DOMAIN);
    expect(arr[arr.length - 1]).toEqual(sorted);
  });

  it("is IDENTICAL regardless of the order the signer set was supplied in", () => {
    const ids = [makeSigner().agentId, makeSigner().agentId, makeSigner().agentId];
    const one = buildDocumentMultisigTbs(fields([...ids]));
    const other = buildDocumentMultisigTbs(fields([...ids].reverse()));
    expect(one).toEqual(other);
  });

  it("refuses an EMPTY required-signer set — a rule nobody must sign is not a rule", () => {
    expect(() => buildDocumentMultisigTbs(fields([]))).toThrow(/multisig_empty_signer_set/);
  });

  it("refuses a DUPLICATE in the required set rather than silently deduping", () => {
    const a = makeSigner().agentId;
    expect(() => buildDocumentMultisigTbs(fields([a, a]))).toThrow(/multisig_duplicate_signer/);
  });

  it("cannot be confused with a proposal preimage — different domain", () => {
    expect(DOCUMENT_MULTISIG_DOMAIN).not.toBe(DOCUMENT_PROPOSAL_DOMAIN);
  });

  it("changes when the subject, the kind, the document, or the signer set changes", () => {
    const a = makeSigner().agentId;
    const b = makeSigner().agentId;
    const base = buildDocumentMultisigTbs(fields([a]));
    expect(buildDocumentMultisigTbs(fields([a], { subject_kind: "quiescence_agreement" }))).not.toEqual(base);
    expect(buildDocumentMultisigTbs(fields([a], { document_id: "e".repeat(64) }))).not.toEqual(base);
    expect(
      buildDocumentMultisigTbs(
        fields([a], { subject_hash: new Uint8Array(32).fill(7) }),
      ),
    ).not.toEqual(base);
    expect(buildDocumentMultisigTbs(fields([a, b]))).not.toEqual(base);
  });
});

describe("collection status — complete means EVERY required signature verifies, nothing else", () => {
  it("all required signers signed → complete", () => {
    const signers = [makeSigner(), makeSigner(), makeSigner()];
    const status = collectionStatus(signedCollection(signers), makeVerify(signers));
    expect(status.complete).toBe(true);
    expect(status.missing).toEqual([]);
    expect(status.unknown).toEqual([]);
    expect(status.invalidSigners).toEqual([]);
    expect(status.duplicates).toEqual([]);
  });

  it("an INVALID signature is not compensated by a second, VALID one — the compensation attack", () => {
    // A wrong "signer satisfied if ANY row verifies" implementation must fail here directly,
    // not only via the duplicates flag as a side effect.
    const signers = [makeSigner()];
    const collection = signedCollection(signers);
    const goodSig = collection.signatures[0]!.signature;
    collection.signatures[0]!.signature = new Uint8Array(64).fill(1);
    collection.signatures.push({ signer_agent_id: signers[0]!.agentId, signature: goodSig });
    const status = collectionStatus(collection, makeVerify(signers));
    expect(status.complete).toBe(false);
    expect(status.invalidSigners).toEqual([signers[0]!.agentId]);
    expect(status.duplicates).toEqual([signers[0]!.agentId]);
  });

  it("one missing signature → NOT complete, and the missing signer is NAMED", () => {
    const all = [makeSigner(), makeSigner(), makeSigner()];
    const absent = all[2]!;
    const partial = signedCollection(all.slice(0, 2), all.map((s) => s.agentId));
    const status = collectionStatus(partial, makeVerify(all));
    expect(status.complete).toBe(false);
    expect(status.missing).toEqual([absent.agentId]);
  });

  it("a signature that does not verify → NOT complete, the signer named as invalid", () => {
    const signers = [makeSigner(), makeSigner()];
    const collection = signedCollection(signers);
    collection.signatures[0]!.signature = new Uint8Array(64).fill(1);
    const status = collectionStatus(collection, makeVerify(signers));
    expect(status.complete).toBe(false);
    expect(status.invalidSigners).toEqual([signers[0]!.agentId]);
  });

  it("a signature from OUTSIDE the required set → NOT complete — extra names must not make a collection look more signed", () => {
    const required = [makeSigner()];
    const outsider = makeSigner();
    const collection = signedCollection(required);
    const tbs = buildDocumentMultisigTbs(fields(required.map((s) => s.agentId)));
    collection.signatures.push({
      signer_agent_id: outsider.agentId,
      signature: outsider.sign(tbs),
    });
    const status = collectionStatus(collection, makeVerify([...required, outsider]));
    expect(status.complete).toBe(false);
    expect(status.unknown).toEqual([outsider.agentId]);
  });

  it("TWO signatures for one signer → NOT complete — settle once", () => {
    const signers = [makeSigner()];
    const collection = signedCollection(signers);
    collection.signatures.push({ ...collection.signatures[0]! });
    const status = collectionStatus(collection, makeVerify(signers));
    expect(status.complete).toBe(false);
    expect(status.duplicates).toEqual([signers[0]!.agentId]);
  });

  it("a signature over a DIFFERENT signer set does not verify here — the preimage commits to the co-signers", () => {
    const a = makeSigner();
    const b = makeSigner();
    // a signs believing they are the SOLE required signer…
    const soloTbs = buildDocumentMultisigTbs(fields([a.agentId]));
    const soloSig = a.sign(soloTbs);
    // …and that signature is presented on a collection whose required set is {a, b}.
    const pair = fields([a.agentId, b.agentId].sort());
    const pairTbs = buildDocumentMultisigTbs(pair);
    const collection: MultisigCollection = {
      ...pair,
      signatures: [
        { signer_agent_id: a.agentId, signature: soloSig },
        { signer_agent_id: b.agentId, signature: b.sign(pairTbs) },
      ],
    };
    const status = collectionStatus(collection, makeVerify([a, b]));
    expect(status.complete).toBe(false);
    expect(status.invalidSigners).toEqual([a.agentId]);
  });
});

describe("collection wire — strict round-trip", () => {
  it("survives encode → decode with every field intact, including a partial collection", () => {
    const all = [makeSigner(), makeSigner()];
    const partial = signedCollection(all.slice(0, 1), all.map((s) => s.agentId));
    expect(decodeMultisigCollection(encodeMultisigCollection(partial))).toEqual(partial);
  });

  it("refuses a missing field rather than defaulting it", () => {
    const collection = signedCollection([makeSigner()]);
    const wire = decodeCbor(encodeMultisigCollection(collection)) as Record<string, unknown>;
    delete wire["required_signers"];
    expect(() => decodeMultisigCollection(encodeCbor(wire))).toThrow(
      /multisig_missing_field: required_signers/,
    );
  });

  it("copies byte fields out of the wire rather than aliasing it", () => {
    const collection = signedCollection([makeSigner()]);
    const wire = encodeMultisigCollection(collection);
    const decoded = decodeMultisigCollection(wire);
    wire.fill(0);
    expect(decoded.subject_hash).toEqual(collection.subject_hash);
    expect(decoded.signatures[0]!.signature).toEqual(collection.signatures[0]!.signature);
  });

  it.each([
    ["document_id", undefined, /multisig_missing_field: document_id/],
    ["document_id", 42, /multisig_field_type: document_id/],
    ["subject_kind", undefined, /multisig_missing_field: subject_kind/],
    ["subject_kind", "", /multisig_field_type: subject_kind/],
    ["subject_hash", undefined, /multisig_missing_field: subject_hash/],
    ["subject_hash", "not-bytes", /multisig_field_type: subject_hash/],
    ["required_signers", [1, 2], /multisig_field_type: required_signers/],
    ["required_signers", [""], /multisig_signer_type/],
    ["signatures", undefined, /multisig_missing_field: signatures/],
    ["signatures", "nope", /multisig_field_type: signatures/],
    ["signatures", ["not-a-map"], /multisig_field_type: signatures\[0\]/],
  ] as const)(
    "decode refuses %s = %j with the NAMED code — never a coerced default",
    (field, value, expected) => {
      const wire = decodeCbor(encodeMultisigCollection(signedCollection([makeSigner()]))) as Record<
        string,
        unknown
      >;
      if (value === undefined) delete wire[field];
      else wire[field] = value;
      expect(() => decodeMultisigCollection(encodeCbor(wire))).toThrow(expected);
    },
  );

  it("decode refuses a non-map root as malformed", () => {
    expect(() => decodeMultisigCollection(encodeCbor([1, 2, 3]))).toThrow(/multisig_malformed/);
  });
});

describe("multisig TBS — the FROZEN vector", () => {
  it("produces the pinned digest for the pinned input — field order is wire law", () => {
    const tbs = buildDocumentMultisigTbs({
      document_id: "ab".repeat(32),
      subject_kind: "document_amendment",
      subject_hash: new Uint8Array(32).fill(3),
      required_signers: ["cd".repeat(32), "ef".repeat(32)],
    });
    // Regenerate ONLY on a deliberate, journaled preimage change. A drive-by failure here means
    // the preimage moved and every signature in every existing collection is void.
    expect(Buffer.from(tbs).toString("hex")).toBe(
      "710723781b0c6fe93e15d908337c939aa42c0e2729acb6bb7b7a575f121e6c11",
    );
  });
});
