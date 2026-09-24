/**
 * CELLO-CONNREQ-001 — ConnectionPackage tests (ported to real ML-DSA-44 in 001-PQPRIM).
 *
 * Every AC and SI from the story spec maps to a named test below.
 *
 * REAL CRYPTO, no mocks. Every key is a real ML-DSA-44 key from `mlDsaProviderFromSeed`, and every
 * signature goes through the Contract 2 frame (`signMlDsa` / `verifyMlDsa`) under the artifact's own
 * context: `cello-mldsa-pseudonym-binding-v1`, `cello-mldsa-endorsement-v1`,
 * `cello-mldsa-attestation-v1`. The HMAC "fake ML-DSA" this suite used to run on is deleted — a
 * double that returns plausible bytes is how a broken verifier stays green.
 *
 * The one exception is AC-009, a pinned CBOR ENCODING vector: its byte fields are fixed opaque values
 * (not a signature, and never verified), because encoding does not look at them and a real ML-DSA
 * signature is randomized (FIPS 204 hedged signing), so it could never be pinned.
 *
 * References:
 *   NIST FIPS 204 — ML-DSA (Module-Lattice-Based Digital Signature Standard)
 *   RFC 8949 §4.2.1 — Canonical CBOR
 */

import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHmac, createHash } from "node:crypto";
import {
  setupV3Tests,
  createTestScope,
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
} from "@claude-flow/testing";
import type { TestScope } from "@claude-flow/testing";
import { Encoder } from "cbor-x";
import { mlDsaGenerateSeed, mlDsaProviderFromSeed, signMlDsa } from "@cello-protocol/crypto";
import type { MlDsaKeyProvider } from "@cello-protocol/crypto";
import {
  buildPseudonymBinding,
  validateConnectionPackage,
  encodeConnectionPackage,
  decodeConnectionPackage,
  verifyEndorsement,
  verifyAttestation,
  verifyPseudonymBinding,
  MAX_PSEUDONYM_LABEL_BYTES,
  ML_DSA_PUBLIC_KEY_BYTES,
  ML_DSA_SIGNATURE_BYTES,
} from "../index.js";
import type {
  PseudonymBinding,
  Endorsement,
  Attestation,
  ConnectionPackage,
} from "../index.js";

setupV3Tests();

const __dirname = dirname(fileURLToPath(import.meta.url));

/** Pad a byte array to the target length by repeating it cyclically. */
function padToLength(src: Uint8Array, targetLen: number): Uint8Array {
  const out = new Uint8Array(targetLen);
  for (let i = 0; i < targetLen; i++) {
    out[i] = src[i % src.length];
  }
  return out;
}

/** Byte-equality helper. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ─── Test data factories ──────────────────────────────────────────────────────

/** Deterministic test bytes of the given length (Ed25519/FROST key slots — not signed with here). */
function makeTestKey(label: string, len: number): Uint8Array {
  const hash = createHash("sha256").update(label).digest();
  return padToLength(hash, len);
}

async function newProvider(): Promise<MlDsaKeyProvider> {
  return mlDsaProviderFromSeed(mlDsaGenerateSeed());
}

const cbor = new Encoder({ tagUint8Array: false });
const ts = (n: number): number | bigint => (n > 0xffffffff ? BigInt(n) : n);

/** The binding TBS, built independently of the private builder (positional canonical CBOR). */
function bindingTbs(b: Omit<PseudonymBinding, "ml_dsa_signature">): Uint8Array {
  return cbor.encode([b.pseudonym_label, b.k_local_pubkey, b.primary_pubkey, b.ml_dsa_pubkey, ts(b.created_at)]);
}
function endorsementTbs(e: Omit<Endorsement, "endorser_ml_dsa_signature">): Uint8Array {
  return cbor.encode([e.endorser_pubkey, e.endorser_ml_dsa_pubkey, e.target_pubkey, e.endorsement_type, ts(e.created_at), ts(e.expires_at)]);
}
function attestationTbs(a: Omit<Attestation, "attester_ml_dsa_signature">): Uint8Array {
  return cbor.encode([a.attester_pubkey, a.attester_ml_dsa_pubkey, a.attestation_type, a.attestation_data, ts(a.created_at), ts(a.expires_at)]);
}

/** Build a PseudonymBinding signed by a real ML-DSA provider. */
async function makePseudonymBinding(
  opts: {
    label?: string;
    kLocalPubkey?: Uint8Array;
    primaryPubkey?: Uint8Array;
    provider?: MlDsaKeyProvider;
    createdAt?: number;
  } = {}
): Promise<{ binding: PseudonymBinding; provider: MlDsaKeyProvider; mlDsaPubkey: Uint8Array }> {
  const provider = opts.provider ?? (await newProvider());
  const mlDsaPubkey = await provider.getPublicKey();
  const result = await buildPseudonymBinding(
    {
      pseudonym_label: opts.label ?? "test-agent",
      k_local_pubkey: opts.kLocalPubkey ?? makeTestKey("klocal", 32),
      primary_pubkey: opts.primaryPubkey ?? makeTestKey("primary", 64),
      ml_dsa_pubkey: mlDsaPubkey,
      created_at: opts.createdAt ?? 1_746_057_600_000,
    },
    provider
  );
  if (!result.ok) throw new Error(`makePseudonymBinding failed: ${result.reason}`);
  return { binding: result.binding, provider, mlDsaPubkey };
}

/** Build an Endorsement signed by a real ML-DSA provider (nothing in the tree produces one yet). */
async function makeEndorsement(
  opts: {
    targetPubkey?: Uint8Array;
    endorsementType?: string;
    createdAt?: number;
    expiresAt?: number;
    endorserProvider?: MlDsaKeyProvider;
  } = {}
): Promise<{ endorsement: Endorsement; endorserProvider: MlDsaKeyProvider }> {
  const endorserProvider = opts.endorserProvider ?? (await newProvider());
  const createdAt = opts.createdAt ?? 1_746_057_600_000;
  const body = {
    endorser_pubkey: makeTestKey("endorser-ed25519", 32),
    endorser_ml_dsa_pubkey: await endorserProvider.getPublicKey(),
    target_pubkey: opts.targetPubkey ?? makeTestKey("klocal", 32),
    endorsement_type: opts.endorsementType ?? "peer_trust",
    created_at: createdAt,
    expires_at: opts.expiresAt ?? createdAt + 86_400_000,
  };
  const sig = await signMlDsa(endorserProvider, "cello-mldsa-endorsement-v1", endorsementTbs(body));
  return { endorsement: { ...body, endorser_ml_dsa_signature: sig }, endorserProvider };
}

/** Build an Attestation signed by a real ML-DSA provider (nothing in the tree produces one yet). */
async function makeAttestation(
  opts: {
    attestationType?: string;
    attestationData?: Uint8Array;
    createdAt?: number;
    expiresAt?: number;
    attesterProvider?: MlDsaKeyProvider;
  } = {}
): Promise<{ attestation: Attestation; attesterProvider: MlDsaKeyProvider }> {
  const attesterProvider = opts.attesterProvider ?? (await newProvider());
  const createdAt = opts.createdAt ?? 1_746_057_600_000;
  const body = {
    attester_pubkey: makeTestKey("attester-ed25519", 32),
    attester_ml_dsa_pubkey: await attesterProvider.getPublicKey(),
    attestation_type: opts.attestationType ?? "capability",
    attestation_data: opts.attestationData ?? new Uint8Array([1, 2, 3]),
    created_at: createdAt,
    expires_at: opts.expiresAt ?? createdAt + 86_400_000,
  };
  const sig = await signMlDsa(attesterProvider, "cello-mldsa-attestation-v1", attestationTbs(body));
  return { attestation: { ...body, attester_ml_dsa_signature: sig }, attesterProvider };
}

// ─── Test scope ───────────────────────────────────────────────────────────────

let scope: TestScope;
beforeEach(() => {
  scope = createTestScope();
});
afterEach(async () => {
  await scope.run(async () => {});
});

// ─── AC-001: Pseudonym-only package — CBOR deterministic, sig verifies ────────

describe("AC-001: package with pseudonym binding only — CBOR deterministic, sig verifies", () => {
  it("AC-001: encodes deterministically; ML-DSA sig verifies; re-encoding produces identical bytes", async () => {
    const { binding } = await makePseudonymBinding();

    const pkg: ConnectionPackage = { pseudonym_binding: binding, endorsements: [], attestations: [] };

    const bytes1 = encodeConnectionPackage(pkg);
    const bytes2 = encodeConnectionPackage(pkg);
    expect(bytesEqual(bytes1, bytes2)).toBe(true);

    expect(await verifyPseudonymBinding(binding)).toBe(true);

    const decoded = decodeConnectionPackage(bytes1);
    const bytes3 = encodeConnectionPackage(decoded);
    expect(bytesEqual(bytes1, bytes3)).toBe(true);
  });
});

// ─── AC-002: Package with 3 endorsements + 1 attestation — all 5 sigs verify ─

describe("AC-002: package with 3 endorsements + 1 attestation — all 5 sigs verify independently", () => {
  it("AC-002: pseudonym sig + 3 endorsement sigs + 1 attestation sig all verify", async () => {
    const kLocalPubkey = makeTestKey("klocal", 32);
    const { binding } = await makePseudonymBinding({ kLocalPubkey });
    const { endorsement: e1 } = await makeEndorsement({ targetPubkey: kLocalPubkey });
    const { endorsement: e2 } = await makeEndorsement({ targetPubkey: kLocalPubkey });
    const { endorsement: e3 } = await makeEndorsement({ targetPubkey: kLocalPubkey });
    const { attestation: a1 } = await makeAttestation();

    expect(await verifyPseudonymBinding(binding)).toBe(true);
    expect(await verifyEndorsement(e1)).toBe(true);
    expect(await verifyEndorsement(e2)).toBe(true);
    expect(await verifyEndorsement(e3)).toBe(true);
    expect(await verifyAttestation(a1)).toBe(true);
  });
});

// ─── AC-003: Tampered pseudonym binding sig → pseudonym_binding_invalid ───────

describe("AC-003: tampered pseudonym binding sig → { valid: false, reason: 'pseudonym_binding_invalid' }", () => {
  it("AC-003: flip one byte in ml_dsa_signature → validateConnectionPackage returns pseudonym_binding_invalid", async () => {
    const kLocalPubkey = makeTestKey("klocal", 32);
    const { binding } = await makePseudonymBinding({ kLocalPubkey });

    const tamperedSig = new Uint8Array(binding.ml_dsa_signature);
    tamperedSig[0] ^= 0xff;
    const pkg: ConnectionPackage = {
      pseudonym_binding: { ...binding, ml_dsa_signature: tamperedSig },
      endorsements: [],
      attestations: [],
    };

    const result = await validateConnectionPackage(pkg, kLocalPubkey, Date.now());
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.reason).toBe("pseudonym_binding_invalid");
    }
  });
});

// ─── AC-004: Tampered endorsement → sig_invalid but package NOT rejected ──────

describe("AC-004: tampered endorsement → signature_invalid; package still valid", () => {
  it("AC-004: pseudonym binding passes; tampered endorsement marked signature_invalid; package valid", async () => {
    const kLocalPubkey = makeTestKey("klocal", 32);
    const { binding } = await makePseudonymBinding({ kLocalPubkey });
    const { endorsement } = await makeEndorsement({ targetPubkey: kLocalPubkey });

    const tamperedSig = new Uint8Array(endorsement.endorser_ml_dsa_signature);
    tamperedSig[10] ^= 0x01;
    const pkg: ConnectionPackage = {
      pseudonym_binding: binding,
      endorsements: [{ ...endorsement, endorser_ml_dsa_signature: tamperedSig }],
      attestations: [],
    };

    const result = await validateConnectionPackage(pkg, kLocalPubkey, 1_746_057_500_000);
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.endorsements).toHaveLength(1);
      expect(result.endorsements[0].validation_status).toBe("signature_invalid");
    }
  });
});

// ─── AC-005: Expired endorsement → marked 'expired', package valid ────────────

describe("AC-005: expired endorsement → marked 'expired'; package valid", () => {
  it("AC-005: endorsement with expires_at 1ms in past → marked expired; package passes", async () => {
    const now = 1_746_057_600_000;
    const kLocalPubkey = makeTestKey("klocal", 32);
    const { binding } = await makePseudonymBinding({ kLocalPubkey });
    const { endorsement } = await makeEndorsement({ targetPubkey: kLocalPubkey, expiresAt: now - 1 });

    const pkg: ConnectionPackage = { pseudonym_binding: binding, endorsements: [endorsement], attestations: [] };

    const result = await validateConnectionPackage(pkg, kLocalPubkey, now);
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.endorsements[0].validation_status).toBe("expired");
    }
  });
});

// ─── AC-006: Endorsement target_pubkey mismatch → marked 'target_mismatch' ───

describe("AC-006: endorsement target_pubkey mismatch → marked 'target_mismatch'", () => {
  it("AC-006: endorsement target ≠ sender k_local_pubkey → target_mismatch status", async () => {
    const kLocalPubkey = makeTestKey("klocal", 32);
    const { binding } = await makePseudonymBinding({ kLocalPubkey });
    const { endorsement } = await makeEndorsement({ targetPubkey: makeTestKey("wrong-klocal", 32) });

    const pkg: ConnectionPackage = { pseudonym_binding: binding, endorsements: [endorsement], attestations: [] };

    const result = await validateConnectionPackage(pkg, kLocalPubkey, 1_746_057_500_000);
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.endorsements[0].validation_status).toBe("target_mismatch");
    }
  });
});

// ─── AC-007: pseudonym_label exactly 64 UTF-8 bytes → construction succeeds ──

describe("AC-007: pseudonym_label exactly 64 UTF-8 bytes → construction succeeds", () => {
  it("AC-007: 64-byte label builds successfully", async () => {
    const label = "a".repeat(MAX_PSEUDONYM_LABEL_BYTES);
    expect(new TextEncoder().encode(label).length).toBe(64);
    const provider = await newProvider();

    const result = await buildPseudonymBinding(
      {
        pseudonym_label: label,
        k_local_pubkey: makeTestKey("klocal", 32),
        primary_pubkey: makeTestKey("primary", 64),
        ml_dsa_pubkey: await provider.getPublicKey(),
        created_at: 1_746_057_600_000,
      },
      provider
    );

    expect(result.ok).toBe(true);
  });
});

// ─── AC-008: pseudonym_label 65 UTF-8 bytes → rejects with pseudonym_label_too_long

describe("AC-008: pseudonym_label 65 UTF-8 bytes → rejects with pseudonym_label_too_long", () => {
  it("AC-008: 65-byte label rejects at build time", async () => {
    const label = "a".repeat(MAX_PSEUDONYM_LABEL_BYTES + 1);
    expect(new TextEncoder().encode(label).length).toBe(65);
    const provider = await newProvider();

    const result = await buildPseudonymBinding(
      {
        pseudonym_label: label,
        k_local_pubkey: makeTestKey("klocal", 32),
        primary_pubkey: makeTestKey("primary", 64),
        ml_dsa_pubkey: await provider.getPublicKey(),
        created_at: 1_746_057_600_000,
      },
      provider
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("pseudonym_label_too_long");
    }
  });
});

// ─── AC-009: Fixture vector — canonical CBOR bytes match fixture hex exactly ──

describe("AC-009: fixture test vector — CBOR bytes match pinned fixture hex", () => {
  it("AC-009: encode from fixture values → bytes match expected_cbor_hex in fixture", () => {
    const fixturePath = join(__dirname, "../../test/vectors/connection-package-canonical.json");
    const fixture = JSON.parse(readFileSync(fixturePath, "utf8")) as {
      seed_hex: string;
      expected_cbor_hex: string;
    };

    // An ENCODING vector: every byte field is a fixed opaque value derived from the fixture seed.
    // `ml_dsa_signature` is not a signature and is never verified — encoding does not read it, and
    // a real ML-DSA signature is randomized, so it could not be pinned.
    const seed = Buffer.from(fixture.seed_hex, "hex");
    const pseudonym_label = "ac009-agent";
    const k_local_pubkey = makeTestKey("ac009-klocal", 32);
    const primary_pubkey = makeTestKey("ac009-primary", 64);
    const ml_dsa_pubkey = padToLength(createHash("sha256").update(seed).digest(), ML_DSA_PUBLIC_KEY_BYTES);
    const created_at = 1_746_057_600_000;
    const tbs = bindingTbs({ pseudonym_label, k_local_pubkey, primary_pubkey, ml_dsa_pubkey, created_at });
    const ml_dsa_signature = padToLength(createHmac("sha256", seed).update(tbs).digest(), ML_DSA_SIGNATURE_BYTES);

    const pkg: ConnectionPackage = {
      pseudonym_binding: { pseudonym_label, k_local_pubkey, primary_pubkey, ml_dsa_pubkey, created_at, ml_dsa_signature },
      endorsements: [],
      attestations: [],
    };

    // Must match the pinned fixture exactly — any encoding change breaks this test
    expect(Buffer.from(encodeConnectionPackage(pkg)).toString("hex")).toBe(fixture.expected_cbor_hex);
  });
});

// ─── AC-010: Two packages from same agent — no indicator of withheld items ───

describe("AC-010: two packages with different endorsement counts — both valid, no leakage", () => {
  it("AC-010: 3-endorsement package and 1-endorsement package both pass; no hint about withheld items", async () => {
    const now = 1_746_057_600_000;
    const kLocalPubkey = makeTestKey("klocal", 32);
    const { binding } = await makePseudonymBinding({ kLocalPubkey });
    const { endorsement: e1 } = await makeEndorsement({ targetPubkey: kLocalPubkey });
    const { endorsement: e2 } = await makeEndorsement({ targetPubkey: kLocalPubkey });
    const { endorsement: e3 } = await makeEndorsement({ targetPubkey: kLocalPubkey });

    const result3 = await validateConnectionPackage({ pseudonym_binding: binding, endorsements: [e1, e2, e3], attestations: [] }, kLocalPubkey, now);
    const result1 = await validateConnectionPackage({ pseudonym_binding: binding, endorsements: [e1], attestations: [] }, kLocalPubkey, now);

    expect(result3.valid).toBe(true);
    expect(result1.valid).toBe(true);
    if (result3.valid) expect(result3.endorsements).toHaveLength(3);
    if (result1.valid) expect(result1.endorsements).toHaveLength(1);
  });
});

// ─── AC-011: Endorsements from two different endorsers — each verifies against its own key

describe("AC-011: endorsements from different endorsers — each verifies against own pubkey", () => {
  it("AC-011: two endorsements from different endorsers each verify; e1's signature under e2's key does not", async () => {
    const kLocalPubkey = makeTestKey("klocal", 32);
    const { endorsement: e1, endorserProvider: ep1 } = await makeEndorsement({ targetPubkey: kLocalPubkey });
    const { endorsement: e2, endorserProvider: ep2 } = await makeEndorsement({ targetPubkey: kLocalPubkey });

    const ep1Pub = await ep1.getPublicKey();
    const ep2Pub = await ep2.getPublicKey();
    expect(bytesEqual(ep1Pub, ep2Pub)).toBe(false);

    expect(await verifyEndorsement(e1)).toBe(true);
    expect(await verifyEndorsement(e2)).toBe(true);

    // e1's genuine signature, presented as if ep2 had made it: refused.
    expect(await verifyEndorsement({ ...e1, endorser_ml_dsa_pubkey: ep2Pub })).toBe(false);
  });
});

// ─── 001-PQPRIM test 18 — the binding's own context, not another artifact's ──

describe("001-PQPRIM test 18: a pseudonym binding re-signed under the endorsement context is refused", () => {
  it("the same TBS, the binding's own genuine key, but the endorsement context → refused", async () => {
    const { binding, provider } = await makePseudonymBinding();
    const tbs = bindingTbs(binding);

    // Positive control: the hand-built TBS signed under the RIGHT context verifies, so the refusal
    // below is the context and nothing else.
    const right = await signMlDsa(provider, "cello-mldsa-pseudonym-binding-v1", tbs);
    expect(await verifyPseudonymBinding({ ...binding, ml_dsa_signature: right })).toBe(true);

    const wrong = await signMlDsa(provider, "cello-mldsa-endorsement-v1", tbs);
    expect(await verifyPseudonymBinding({ ...binding, ml_dsa_signature: wrong })).toBe(false);
  });
});

// ─── 001-PQPRIM test 19 — an endorsement signed by a key other than the one it names ──

describe("001-PQPRIM test 19: an endorsement signed by a genuine third key is refused", () => {
  it("names endorser A's ML-DSA key, carries C's genuine signature over the same TBS and context → refused", async () => {
    const { endorsement } = await makeEndorsement();
    const third = await newProvider();
    const { endorser_ml_dsa_signature: _drop, ...body } = endorsement;
    void _drop;
    const bySomeoneElse = await signMlDsa(third, "cello-mldsa-endorsement-v1", endorsementTbs(body));

    expect(await verifyEndorsement(endorsement)).toBe(true);
    expect(await verifyEndorsement({ ...endorsement, endorser_ml_dsa_signature: bySomeoneElse })).toBe(false);
  });
});

// ─── SI-001: Invalid pseudonym binding always rejects — even with valid items ─

describe("SI-001: invalid pseudonym binding rejects whole package, even with valid endorsements", () => {
  it("SI-001: valid endorsements + invalid pseudonym binding → pseudonym_binding_invalid", async () => {
    const kLocalPubkey = makeTestKey("klocal", 32);
    const { binding } = await makePseudonymBinding({ kLocalPubkey });
    const { endorsement } = await makeEndorsement({ targetPubkey: kLocalPubkey });

    const tamperedSig = new Uint8Array(binding.ml_dsa_signature);
    tamperedSig[0] ^= 0xff;
    tamperedSig[1] ^= 0xff;
    const pkg: ConnectionPackage = {
      pseudonym_binding: { ...binding, ml_dsa_signature: tamperedSig },
      endorsements: [endorsement],
      attestations: [],
    };

    const result = await validateConnectionPackage(pkg, kLocalPubkey, 1_746_057_500_000);
    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.reason).toBe("pseudonym_binding_invalid");
    }
  });
});

// ─── SI-002: Each item independently verifiable outside of a package ─────────

describe("SI-002: endorsement independently verifiable when stripped from package", () => {
  it("SI-002: take endorsement out of package and verify standalone → true", async () => {
    const { endorsement } = await makeEndorsement({ targetPubkey: makeTestKey("klocal", 32) });
    expect(await verifyEndorsement(endorsement)).toBe(true);
  });

  it("SI-002b: attestation independently verifiable when stripped from package", async () => {
    const { attestation } = await makeAttestation();
    expect(await verifyAttestation(attestation)).toBe(true);
  });

  it("SI-002c: an endorsement signature does not verify as an attestation (context separation)", async () => {
    const { attestation, attesterProvider } = await makeAttestation();
    const { attester_ml_dsa_signature: _drop, ...body } = attestation;
    void _drop;
    const underEndorsement = await signMlDsa(attesterProvider, "cello-mldsa-endorsement-v1", attestationTbs(body));
    expect(await verifyAttestation({ ...attestation, attester_ml_dsa_signature: underEndorsement })).toBe(false);
  });
});

// ─── SI-003: buildPseudonymBinding takes provider, not raw sig bytes ──────────

describe("SI-003: buildPseudonymBinding type signature enforces provider injection", () => {
  it("SI-003: function signature only accepts MlDsaKeyProvider — no raw signature parameter exists", () => {
    type BuildParams = Parameters<typeof buildPseudonymBinding>[0];

    const params: BuildParams = {
      pseudonym_label: "test",
      k_local_pubkey: new Uint8Array(32),
      primary_pubkey: new Uint8Array(64),
      ml_dsa_pubkey: new Uint8Array(ML_DSA_PUBLIC_KEY_BYTES),
      created_at: 1_000_000_000,
    };

    // @ts-expect-error — 'ml_dsa_signature' does not exist on BuildParams
    const _shouldFail = params.ml_dsa_signature;
    void _shouldFail;

    expect(buildPseudonymBinding.length).toBe(2);
  });
});

// ─── Additional: encode/decode round-trip with full package ──────────────────

describe("encode/decode round-trip", () => {
  it("round-trip: full package with endorsements and attestations round-trips losslessly and still verifies", async () => {
    const kLocalPubkey = makeTestKey("klocal", 32);
    const { binding } = await makePseudonymBinding({ kLocalPubkey });
    const { endorsement } = await makeEndorsement({ targetPubkey: kLocalPubkey });
    const { attestation } = await makeAttestation();

    const pkg: ConnectionPackage = { pseudonym_binding: binding, endorsements: [endorsement], attestations: [attestation] };
    const decoded = decodeConnectionPackage(encodeConnectionPackage(pkg));

    expect(decoded.pseudonym_binding.pseudonym_label).toBe(pkg.pseudonym_binding.pseudonym_label);
    expect(decoded.pseudonym_binding.created_at).toBe(pkg.pseudonym_binding.created_at);
    expect(bytesEqual(decoded.pseudonym_binding.k_local_pubkey, pkg.pseudonym_binding.k_local_pubkey)).toBe(true);
    expect(bytesEqual(decoded.pseudonym_binding.ml_dsa_signature, pkg.pseudonym_binding.ml_dsa_signature)).toBe(true);
    expect(decoded.endorsements).toHaveLength(1);
    expect(decoded.attestations).toHaveLength(1);
    expect(await verifyPseudonymBinding(decoded.pseudonym_binding)).toBe(true);
    expect(await verifyEndorsement(decoded.endorsements[0])).toBe(true);
    expect(await verifyAttestation(decoded.attestations[0])).toBe(true);
  });

  it("decode throws on non-CBOR input", () => {
    expect(() => decodeConnectionPackage(new Uint8Array([0xff, 0xfe, 0xfd]))).toThrow();
  });
});
