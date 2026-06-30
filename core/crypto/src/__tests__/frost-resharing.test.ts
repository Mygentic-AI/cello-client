/**
 * FROST proactive share resharing (PSS) — M8B DOD-REFRESH-1.
 *
 * Proves the zero-constant-term proactive secret sharing refresh (Herzberg et al. 1995): every party
 * adds a degree-(T-1) polynomial with constant term ZERO to its share. The sum of those polynomials has
 * constant term 0, so the JOINT SECRET (and therefore the group public key = commitments[0]) is
 * UNCHANGED, while every individual share is rotated — a share captured in epoch e is useless in e+1.
 *
 * @noble/curves@2.2.0 rejects `generateSecretPolynomial(secret=0)` ("invalid scalar: 1 <= sc < n"), so the
 * zero-constant polynomial is built manually from `utils.Fn` + `utils.randomScalar`; `commitment[0]` is the
 * curve identity (Point.ZERO) — the cryptographic proof the refresh does not shift the secret. The test
 * oracle is `combineSecret`: the reconstructed joint secret must be byte-identical before and after.
 */
import { describe, it, expect } from "vitest";
import { ed25519_FROST, ed25519 } from "@noble/curves/ed25519.js";
import {
  generateRefreshContribution,
  verifyRefreshContribution,
  applyRefresh,
  type RefreshContribution,
} from "../frost/frost-resharing.js";

const signers = { min: 3, max: 3 };
const Fn = ed25519_FROST.utils.Fn;
const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

function setup(): {
  ids: string[];
  oldShares: ReturnType<typeof ed25519_FROST.trustedDealer>["secretShares"][string][];
  groupSecretBefore: Uint8Array;
} {
  const dealer = ed25519_FROST.trustedDealer(signers);
  const ids = Object.keys(dealer.secretShares);
  const oldShares = ids.map((id) => dealer.secretShares[id]);
  const groupSecretBefore = ed25519_FROST.combineSecret(oldShares, signers);
  return { ids, oldShares, groupSecretBefore };
}

/** A full agreed roster: one contribution from every participant. */
function fullRoster(ids: string[]): RefreshContribution[] {
  return ids.map((myId) => generateRefreshContribution(signers, myId, ids));
}

/** A contribution with a SPECIFIED constant term whose sub-shares are internally consistent (passes
 *  the Feldman check); used to drive the secret-shift attack through the real entry points. */
function contributionWithConstant(fromId: string, constant: bigint, ids: string[]): RefreshContribution {
  const coeffs = [
    constant,
    Fn.fromBytes(ed25519_FROST.utils.randomScalar()),
    Fn.fromBytes(ed25519_FROST.utils.randomScalar()),
  ];
  const commitment = coeffs.map((c) => (c === 0n ? ed25519.Point.ZERO : ed25519.Point.BASE.multiply(c)).toBytes());
  const subShares: Record<string, Uint8Array> = {};
  for (const id of ids) {
    const x = Fn.fromBytes(Uint8Array.from(Buffer.from(id, "hex")));
    let acc = Fn.create(0n);
    for (let k = coeffs.length - 1; k >= 0; k--) acc = Fn.add(Fn.mul(acc, x), coeffs[k]);
    subShares[id] = Fn.toBytes(acc);
  }
  return { fromId, commitment, subShares };
}

describe("FROST proactive share resharing (PSS) — DOD-REFRESH-1", () => {
  it("preserves the joint secret (group pubkey unchanged) while rotating EVERY share", () => {
    const { ids, oldShares, groupSecretBefore } = setup();
    const contributions = fullRoster(ids);
    const newShares = oldShares.map((s) => applyRefresh(s, contributions, signers, ids));

    // (1) joint secret byte-identical ⇒ group public key unchanged.
    const groupSecretAfter = ed25519_FROST.combineSecret(newShares, signers);
    expect(hex(groupSecretAfter)).toBe(hex(groupSecretBefore));

    // (2) every share rotated; identifier (the evaluation point) preserved.
    for (let i = 0; i < oldShares.length; i++) {
      expect(hex(newShares[i].signingShare)).not.toBe(hex(oldShares[i].signingShare));
      expect(newShares[i].identifier).toBe(oldShares[i].identifier);
    }
  });

  it("old shares are DEAD: a mixed old+new share set does NOT reconstruct the secret", () => {
    const { ids, oldShares, groupSecretBefore } = setup();
    const contributions = fullRoster(ids);
    const newShares = oldShares.map((s) => applyRefresh(s, contributions, signers, ids));

    // A node compromised in epoch e holds an OLD share; with the OTHER parties' NEW shares it is on an
    // inconsistent polynomial and cannot reconstruct (or sign for) the joint secret.
    const mixed = [oldShares[0], newShares[1], newShares[2]];
    expect(hex(ed25519_FROST.combineSecret(mixed, signers))).not.toBe(hex(groupSecretBefore));
    // ...whereas the FULL new set DOES reconstruct (positive companion — proves the rotation is coherent).
    expect(hex(ed25519_FROST.combineSecret(newShares, signers))).toBe(hex(groupSecretBefore));
  });

  it("the contribution proves a ZERO constant term: commitment[0] === curve identity", () => {
    const { ids } = setup();
    const c = generateRefreshContribution(signers, ids[0], ids);
    expect(c.commitment).toHaveLength(signers.min);
    expect(hex(c.commitment[0])).toBe(hex(ed25519.Point.ZERO.toBytes()));
    expect(() => verifyRefreshContribution(c.commitment, signers)).not.toThrow();
  });

  it("VSS REJECTS any NON-identity commitment[0] — not just G (proves the check is === identity)", () => {
    const { ids } = setup();
    const c = generateRefreshContribution(signers, ids[0], ids);
    // Must reject EVERY non-identity constant-term commitment, not special-case 1·G. Tamper with 2·G (a 2×
    // secret shift) AND a random point: a verify that only rejected G would accept these.
    const shiftBy2 = [ed25519.Point.BASE.multiply(2n).toBytes(), ...c.commitment.slice(1)];
    expect(() => verifyRefreshContribution(shiftBy2, signers)).toThrow(/identity|commitment\[0\]|shift/);
    const randomPoint = ed25519.Point.BASE.multiply(Fn.fromBytes(ed25519_FROST.utils.randomScalar())).toBytes();
    expect(() => verifyRefreshContribution([randomPoint, ...c.commitment.slice(1)], signers)).toThrow(
      /identity|commitment\[0\]|shift/,
    );
    expect(() => verifyRefreshContribution([ed25519.Point.BASE.toBytes(), ...c.commitment.slice(1)], signers)).toThrow();
  });

  it("VSS REJECTS the zero polynomial (all-identity commitment) — a free-rider adding no randomness", () => {
    const allIdentity = Array.from({ length: signers.min }, () => ed25519.Point.ZERO.toBytes());
    expect(() => verifyRefreshContribution(allIdentity, signers)).toThrow(/zero polynomial|randomness/);
  });

  it("applyRefresh REJECTS a fully self-consistent SHIFTING contribution end-to-end (secret-shift attack)", () => {
    const { ids, oldShares } = setup();
    // A COMPLETE roster where one contributor (ids[0]) submits a non-zero constant term whose sub-shares
    // are internally consistent (so the Feldman check passes). Only the commitment[0]==identity gate can
    // stop it — drives the secret-shift attack through the real entry point, past the completeness gate.
    const contributions = [
      contributionWithConstant(ids[0], 2n, ids), // the shift
      generateRefreshContribution(signers, ids[1], ids),
      generateRefreshContribution(signers, ids[2], ids),
    ];
    expect(() => applyRefresh(oldShares[0], contributions, signers, ids)).toThrow(/identity|commitment\[0\]|shift/);
  });

  it("applyRefresh VSS-REJECTS a sub-share inconsistent with the sender's commitment", () => {
    const { ids, oldShares } = setup();
    const good = fullRoster(ids);
    // Corrupt the sub-share contribution[1] addressed to party 0 (replace with a different scalar).
    const corrupt: RefreshContribution = {
      fromId: good[1].fromId,
      commitment: good[1].commitment,
      subShares: { ...good[1].subShares, [ids[0]]: ed25519_FROST.utils.randomScalar() },
    };
    expect(() => applyRefresh(oldShares[0], [good[0], corrupt, good[2]], signers, ids)).toThrow(/VSS/);
  });

  describe("completeness gate — a partial/empty/divergent set must FAIL LOUD, never silently no-op", () => {
    it("REJECTS an empty contribution set (would return the old share unchanged = dead-share no-op)", () => {
      const { ids, oldShares } = setup();
      expect(() => applyRefresh(oldShares[0], [], signers, ids)).toThrow(/incomplete|missing/);
    });

    it("REJECTS a partial set missing a participant (would diverge the joint key)", () => {
      const { ids, oldShares } = setup();
      const partial = fullRoster(ids).slice(0, 2); // only 2 of 3 parties contributed
      expect(() => applyRefresh(oldShares[0], partial, signers, ids)).toThrow(/incomplete|missing/);
    });

    it("REJECTS a duplicate contribution from one party (double-counts a δ)", () => {
      const { ids, oldShares } = setup();
      const good = fullRoster(ids);
      expect(() => applyRefresh(oldShares[0], [good[0], good[0], good[2]], signers, ids)).toThrow(/duplicate/);
    });

    it("REJECTS a contribution from a party outside the agreed roster", () => {
      const { ids, oldShares } = setup();
      const good = fullRoster(ids);
      const stranger = { ...good[1], fromId: "ff".repeat(32) };
      expect(() => applyRefresh(oldShares[0], [good[0], stranger, good[2]], signers, ids)).toThrow(/unexpected|roster/);
    });
  });
});
