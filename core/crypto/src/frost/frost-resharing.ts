/**
 * FROST proactive share resharing (PSS).
 *
 * Zero-constant-term proactive secret sharing (Herzberg, Jarecki, Krawczyk, Yung — "Proactive Secret
 * Sharing", CRYPTO 1995), applied to the joint FROST/Ed25519 group key (RFC 9591 §C VSS commitments).
 *
 * Each party i adds a degree-(T-1) polynomial δ_i with constant term ZERO to its share. Because every
 * δ_i(0) = 0, the sum Δ = Σ_i δ_i has Δ(0) = 0, so the joint secret f(0) — and therefore the group public
 * key (commitments[0]) — is UNCHANGED, while every individual share s_j = f(j) becomes s'_j = f(j) + Δ(j),
 * a fresh value. A share captured in epoch e is on the OLD polynomial f; it cannot be combined with
 * epoch-(e+1) shares (which lie on f' = f + Δ) to reconstruct or sign for the joint secret.
 *
 * @noble/curves@2.2.0 rejects `utils.generateSecretPolynomial(secret=0)` ("invalid scalar: 1 <= sc < n"),
 * so the zero-constant polynomial is built manually from `utils.Fn` + `utils.randomScalar`. Each
 * contribution publishes Feldman VSS commitments `C_i[k] = a_{i,k}·G`; `C_i[0]` is the curve identity —
 * the public proof that δ_i has a zero constant term (the refresh cannot shift the secret). Recipients
 * verify every sub-share δ_i(j) against the commitments before adding it.
 *
 * Scalars and identifiers use @noble's little-endian encoding: a FROST `identifier` is the 32-byte LE
 * scalar (e.g. "0100…00" === 1). All field arithmetic is mod L via `ed25519_FROST.utils.Fn`.
 */
import { ed25519_FROST, ed25519 } from "@noble/curves/ed25519.js";
import type { FrostSecret, FrostPublic, Key, Signers } from "@noble/curves/abstract/frost.js";

const Fn = ed25519_FROST.utils.Fn;
const Point = ed25519.Point;

/** A party's zero-constant refresh contribution: Feldman commitments + the sub-share for each participant. */
export interface RefreshContribution {
  /** The contributing party's FROST identifier (32-byte LE scalar hex). Binds the contribution to a sender
   *  so the applying party can verify the set is complete (one per participant), deduplicated, and matches
   *  the agreed epoch roster — a partial/empty/divergent set must NOT silently produce a share. */
  readonly fromId: string;
  /** Feldman VSS commitments C[k] = a_k·G, length T. C[0] is the curve identity (zero constant term). */
  readonly commitment: Uint8Array[];
  /** δ(j) for every participant identifier j, as a 32-byte LE scalar. */
  readonly subShares: Record<string, Uint8Array>;
}

function hexToBytes(hex: string): Uint8Array {
  return Uint8Array.from(Buffer.from(hex, "hex"));
}

/** Identifier (32-byte LE scalar hex) → field scalar bigint. `Fn.fromBytes` already rejects a non-canonical
 *  (≥ L) or non-32-byte identifier; FROST identifiers must additionally be non-zero (0 is not a valid
 *  evaluation point), so reject it explicitly — mirrors noble's `validateIdentifier`. */
function identifierScalar(identifier: string): bigint {
  const x = Fn.fromBytes(hexToBytes(identifier));
  if (x === 0n) {
    throw new Error("frost-resharing: identifier 0 is not a valid FROST evaluation point");
  }
  return x;
}

/** Evaluate Σ_k coeffs[k]·x^k (mod L) via Horner, in the scalar field. */
function evalPolynomial(coeffs: bigint[], x: bigint): bigint {
  let acc = Fn.create(0n);
  for (let k = coeffs.length - 1; k >= 0; k--) {
    acc = Fn.add(Fn.mul(acc, x), coeffs[k]);
  }
  return acc;
}

/** scalar·G, identity-safe (Point.BASE.multiply rejects a zero scalar). */
function scalarBaseMul(s: bigint): InstanceType<typeof Point> {
  return s === 0n ? Point.ZERO : Point.BASE.multiply(s);
}

/** point·scalar, identity-safe. */
function pointMul(p: InstanceType<typeof Point>, s: bigint): InstanceType<typeof Point> {
  if (s === 0n) return Point.ZERO;
  if (p.is0()) return Point.ZERO;
  return p.multiply(s);
}

/**
 * Generate one party's refresh contribution: a degree-(T-1) polynomial δ with constant term 0, evaluated
 * at every participant identifier in `allIds`, plus the Feldman commitments to its coefficients.
 *
 * T = signers.min (the reconstruction threshold). δ keeps degree T-1 so the refreshed sharing preserves
 * the same threshold. The non-constant coefficients are uniformly random scalars; the contribution leaks
 * nothing about the holder's existing share.
 */
export function generateRefreshContribution(signers: Signers, myId: string, allIds: string[]): RefreshContribution {
  const threshold = signers.min;
  // coefficients[0] === 0 (zero constant term); coefficients[1..T-1] uniformly random.
  const coefficients: bigint[] = [0n];
  for (let k = 1; k < threshold; k++) {
    coefficients.push(Fn.fromBytes(ed25519_FROST.utils.randomScalar()));
  }
  // Feldman commitments C[k] = coefficients[k]·G; C[0] = 0·G = identity.
  const commitment = coefficients.map((c) => scalarBaseMul(c).toBytes());

  const subShares: Record<string, Uint8Array> = {};
  for (const id of allIds) {
    const share = evalPolynomial(coefficients, identifierScalar(id));
    subShares[id] = Fn.toBytes(share);
  }
  return { fromId: myId, commitment, subShares };
}

/**
 * Verify a contribution's commitment vector is well-formed: exactly T commitments, each a valid curve
 * point, and — the load-bearing check — commitment[0] is the curve IDENTITY, proving the polynomial's
 * constant term is zero (the refresh cannot shift the joint secret). Throws on any violation.
 */
export function verifyRefreshContribution(commitment: Uint8Array[], signers: Signers): void {
  const threshold = signers.min;
  if (commitment.length !== threshold) {
    throw new Error(`frost-resharing: commitment length ${commitment.length} !== threshold ${threshold}`);
  }
  const identityHex = Buffer.from(Point.ZERO.toBytes()).toString("hex");
  if (Buffer.from(commitment[0]).toString("hex") !== identityHex) {
    throw new Error("frost-resharing: commitment[0] is not the identity — refresh would shift the secret");
  }
  // Each commitment must decode to a valid curve point (rejects garbage / off-curve points).
  for (const c of commitment) {
    Point.fromBytes(c);
  }
  // Non-triviality: the polynomial must NOT be identically zero (all coefficients 0 → every commitment is
  // the identity). A zero-polynomial contribution passes the zero-constant check yet adds NO fresh
  // randomness — a free-rider that contributes nothing to Δ. Require at least one non-constant commitment
  // (commitment[1..T-1]) to be non-identity so every contributor actually masks the shares.
  const nonConstantNonIdentity = commitment
    .slice(1)
    .some((c) => Buffer.from(c).toString("hex") !== identityHex);
  if (!nonConstantNonIdentity) {
    throw new Error("frost-resharing: contribution is the zero polynomial (no fresh randomness) — rejected");
  }
}

/**
 * Apply the refresh to one party's Key (secret share + shared public). For this party's identifier j:
 * enforce the full-roster completeness gate, verify every contribution (zero constant term + non-trivial +
 * well-formed) and Feldman-check each sub-share δ_i(j)·G == Σ_k j^k·C_i[k] before trusting it, then return
 * the rotated Key — secret s'_j = s_j + Σ_i δ_i(j) (mod L) AND the homomorphically-updated FrostPublic (see
 * refreshPublic; commitments[1..] and verifyingShares move, commitments[0]=group key is invariant). The
 * returned (secret, public) pair is signing-ready: a post-refresh FROST ceremony verifies against the same
 * group key. Old-epoch shares no longer combine with the result.
 *
 * PRECONDITION — broadcast agreement (NOT enforceable by this local primitive): every honest party MUST
 * receive the IDENTICAL `commitment` (and the matching sub-share) from each contributor i. This primitive
 * verifies each sub-share only against the commitment in ITS OWN list, so a malicious contributor that
 * EQUIVOCATES — handing party A `(C, δ_A)` and party B a different but internally-consistent `(C', δ_B)`,
 * both with commitment[0]=identity — passes every local check, yet A and B then land on DIFFERENT
 * polynomials (Δ_A ≠ Δ_B): no secret shift, but the quorum can no longer reconstruct/sign. Detecting
 * equivocation requires an echo/agreement round (every party broadcasts H(commitment_i) it received and
 * aborts on any mismatch). The daemon orchestration layer (runNetworkRefresh) owns that echo round; this
 * function assumes the contribution set it is handed is already agreement-checked. A corrupt party cannot
 * silently SHIFT THE SECRET here, but the unusable-share (equivocation) attack is out of local scope.
 *
 * Throws if any contribution is malformed or any sub-share is inconsistent with its commitment — a
 * corrupt party cannot silently shift the secret or hand a victim an unusable share.
 */
export function applyRefresh(
  oldKey: Key,
  contributions: RefreshContribution[],
  signers: Signers,
  expectedParticipantIds: string[],
): Key {
  const j = oldKey.secret.identifier;
  const xj = identifierScalar(j);

  // COMPLETENESS GATE: a proactive refresh — like DKG — requires EVERY current shareholder
  // to contribute exactly one δ. The applying party MUST verify the contribution set is the full agreed
  // roster: no missing party (a partial set lands every party on a DIFFERENT polynomial Δ and silently
  // destroys the joint key), no extra/duplicate sender (double-counts a δ), and not empty (a no-op refresh
  // that returns the OLD share while reporting success — leaving a captured epoch-e share alive). This also
  // enforces the joint-randomness requirement: Δ = Σ δ_i is only safe when summed across all independent
  // parties, never a single contributor. Fail LOUD here rather than return a share that looks rotated.
  const expected = new Set(expectedParticipantIds);
  if (expected.size !== expectedParticipantIds.length) {
    throw new Error("frost-resharing: expectedParticipantIds contains duplicates");
  }
  const seen = new Set<string>();
  for (const c of contributions) {
    if (!expected.has(c.fromId)) {
      throw new Error(`frost-resharing: contribution from unexpected party ${c.fromId} (not in the agreed roster)`);
    }
    if (seen.has(c.fromId)) {
      throw new Error(`frost-resharing: duplicate contribution from party ${c.fromId}`);
    }
    seen.add(c.fromId);
  }
  if (seen.size !== expected.size) {
    const missing = expectedParticipantIds.filter((id) => !seen.has(id));
    throw new Error(`frost-resharing: incomplete refresh — missing contributions from ${missing.length} party/parties (a partial refresh would diverge the joint key)`);
  }

  let acc = Fn.fromBytes(oldKey.secret.signingShare);
  for (const contribution of contributions) {
    verifyRefreshContribution(contribution.commitment, signers);

    const subShareBytes = contribution.subShares[j];
    if (!subShareBytes) {
      throw new Error(`frost-resharing: contribution missing sub-share for identifier ${j}`);
    }
    const delta = Fn.fromBytes(subShareBytes);

    // Feldman VSS check: δ_i(j)·G must equal Σ_k j^k · C_i[k] (Horner over the commitment points).
    const lhs = scalarBaseMul(delta);
    let rhs = Point.ZERO;
    for (let k = contribution.commitment.length - 1; k >= 0; k--) {
      rhs = pointMul(rhs, xj).add(Point.fromBytes(contribution.commitment[k]));
    }
    if (!lhs.equals(rhs)) {
      throw new Error(`frost-resharing: sub-share for ${j} fails the VSS check against its commitment`);
    }

    acc = Fn.add(acc, delta);
  }

  // new Uint8Array(...) gives an ArrayBuffer-backed copy (FrostSecret.signingShare is the stricter
  // Uint8Array<ArrayBuffer>, not Fn.toBytes's Uint8Array<ArrayBufferLike>).
  const newSecret: FrostSecret = { identifier: j, signingShare: new Uint8Array(Fn.toBytes(acc)) };

  return { secret: newSecret, public: refreshPublic(oldKey.public, contributions) };
}

/**
 * Homomorphically update the shared FrostPublic for the refreshed sharing. PSS rotates the shares, so the
 * group VSS commitments and every verifying share change — only commitments[0] (the group public key) is
 * invariant. Without this, post-refresh signing fails: `verifyShare` checks a partial signature against the
 * participant's verifyingShare, which moved when the share rotated.
 *
 *   newCommitments[k] = oldCommitments[k] + Σ_i C_i[k]        (the joint polynomial f' = f + Σ δ_i)
 *   newVerifyingShares[id] = Σ_m newCommitments[m]·id^m       (VSS evaluation of f' at each participant)
 *
 * Every honest party computes the IDENTICAL new public from the same agreed contribution set, so the
 * resulting (secret, public) pairs are mutually consistent. commitments[0] is asserted unchanged: Σ_i C_i[0]
 * is the identity (every contribution's zero-constant proof, already checked), so the group key is preserved
 * by construction — the assertion is a belt-and-suspenders guard against a bug upstream.
 */
function refreshPublic(oldPublic: FrostPublic, contributions: RefreshContribution[]): FrostPublic {
  const oldCommitments = oldPublic.commitments as Uint8Array[];
  const degree = oldCommitments.length;

  const newCommitments: Uint8Array[] = [];
  for (let k = 0; k < degree; k++) {
    let acc = Point.fromBytes(oldCommitments[k]);
    for (const c of contributions) {
      acc = acc.add(Point.fromBytes(c.commitment[k]));
    }
    newCommitments.push(new Uint8Array(acc.toBytes()));
  }
  if (Buffer.from(newCommitments[0]).toString("hex") !== Buffer.from(oldCommitments[0]).toString("hex")) {
    throw new Error("frost-resharing: group public key changed — refresh is not secret-preserving");
  }

  const oldVerifying = oldPublic.verifyingShares as Record<string, Uint8Array>;
  const newVerifyingShares: Record<string, Uint8Array> = {};
  for (const id of Object.keys(oldVerifying)) {
    const x = identifierScalar(id);
    let acc = Point.ZERO;
    for (let m = newCommitments.length - 1; m >= 0; m--) {
      acc = pointMul(acc, x).add(Point.fromBytes(newCommitments[m]));
    }
    newVerifyingShares[id] = new Uint8Array(acc.toBytes());
  }

  return {
    signers: oldPublic.signers,
    commitments: newCommitments,
    verifyingShares: newVerifyingShares,
  } as FrostPublic;
}
