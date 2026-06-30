/**
 * FROST proactive share resharing (PSS) — M8B DOD-REFRESH-1.
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
import type { FrostSecret, Signers } from "@noble/curves/abstract/frost.js";

const Fn = ed25519_FROST.utils.Fn;
const Point = ed25519.Point;

/** A party's zero-constant refresh contribution: Feldman commitments + the sub-share for each participant. */
export interface RefreshContribution {
  /** Feldman VSS commitments C[k] = a_k·G, length T. C[0] is the curve identity (zero constant term). */
  readonly commitment: Uint8Array[];
  /** δ(j) for every participant identifier j, as a 32-byte LE scalar. */
  readonly subShares: Record<string, Uint8Array>;
}

function hexToBytes(hex: string): Uint8Array {
  return Uint8Array.from(Buffer.from(hex, "hex"));
}

/** Identifier (32-byte LE scalar hex) → field scalar bigint. */
function identifierScalar(identifier: string): bigint {
  return Fn.fromBytes(hexToBytes(identifier));
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
export function generateRefreshContribution(signers: Signers, allIds: string[]): RefreshContribution {
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
  return { commitment, subShares };
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
}

/**
 * Apply the refresh to one party's share. For this party's identifier j: verify every contribution
 * (zero constant term + well-formed) and Feldman-check each sub-share δ_i(j)·G == Σ_k j^k·C_i[k] before
 * trusting it, then return the rotated share s'_j = s_j + Σ_i δ_i(j) (mod L). The group public key is
 * unchanged; old-epoch shares no longer combine with the result.
 *
 * Throws if any contribution is malformed or any sub-share is inconsistent with its commitment — a
 * corrupt party cannot silently shift the secret or hand a victim an unusable share.
 */
export function applyRefresh(
  oldShare: FrostSecret,
  contributions: RefreshContribution[],
  signers: Signers,
): FrostSecret {
  const j = oldShare.identifier;
  const xj = identifierScalar(j);

  let acc = Fn.fromBytes(oldShare.signingShare);
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
  return { identifier: j, signingShare: new Uint8Array(Fn.toBytes(acc)) };
}
