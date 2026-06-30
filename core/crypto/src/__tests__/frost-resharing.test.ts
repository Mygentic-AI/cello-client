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
} from "../frost/frost-resharing.js";

const signers = { min: 3, max: 3 };
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

describe("FROST proactive share resharing (PSS) — DOD-REFRESH-1", () => {
  it("preserves the joint secret (group pubkey unchanged) while rotating EVERY share", () => {
    const { ids, oldShares, groupSecretBefore } = setup();

    // Each party independently generates a zero-constant refresh contribution evaluated at all participants.
    const contributions = ids.map(() => generateRefreshContribution(signers, ids));

    // Each party applies the refresh to its own share: s'_j = s_j + Σ_i δ_i(j) mod L.
    const newShares = oldShares.map((s) => applyRefresh(s, contributions, signers));

    // (1) joint secret byte-identical ⇒ group public key unchanged.
    const groupSecretAfter = ed25519_FROST.combineSecret(newShares, signers);
    expect(hex(groupSecretAfter)).toBe(hex(groupSecretBefore));

    // (2) every share rotated (no share is unchanged).
    for (let i = 0; i < oldShares.length; i++) {
      expect(hex(newShares[i].signingShare)).not.toBe(hex(oldShares[i].signingShare));
      // identifier (the evaluation point) is preserved — only the share value rotates.
      expect(newShares[i].identifier).toBe(oldShares[i].identifier);
    }
  });

  it("old shares are DEAD: a mixed old+new share set does NOT reconstruct the secret", () => {
    const { ids, oldShares, groupSecretBefore } = setup();
    const contributions = ids.map(() => generateRefreshContribution(signers, ids));
    const newShares = oldShares.map((s) => applyRefresh(s, contributions, signers));

    // A node compromised in epoch e holds an OLD share; combined with the OTHER parties' NEW shares it is
    // on an inconsistent polynomial and cannot reconstruct (or sign for) the joint secret.
    const mixed = [oldShares[0], newShares[1], newShares[2]];
    const reconstructed = ed25519_FROST.combineSecret(mixed, signers);
    expect(hex(reconstructed)).not.toBe(hex(groupSecretBefore));
  });

  it("the contribution proves a ZERO constant term: commitment[0] === curve identity", () => {
    const { ids } = setup();
    const c = generateRefreshContribution(signers, ids);
    expect(c.commitment).toHaveLength(signers.min);
    expect(hex(c.commitment[0])).toBe(hex(ed25519.Point.ZERO.toBytes()));
    expect(() => verifyRefreshContribution(c.commitment, signers)).not.toThrow();
  });

  it("VSS REJECTS a contribution whose constant term is non-zero (secret-shift attack)", () => {
    const { ids } = setup();
    const c = generateRefreshContribution(signers, ids);
    // Tamper: replace the zero-constant commitment[0] with G (non-identity) → a secret shift.
    const tampered = [ed25519.Point.BASE.toBytes(), ...c.commitment.slice(1)];
    expect(() => verifyRefreshContribution(tampered, signers)).toThrow();
  });

  it("applyRefresh VSS-REJECTS a sub-share inconsistent with the sender's commitment", () => {
    const { ids, oldShares } = setup();
    const good = ids.map(() => generateRefreshContribution(signers, ids));
    // Corrupt the sub-share that contribution[1] addressed to party 0 (replace with a different scalar).
    const wrong = ed25519_FROST.utils.randomScalar();
    const corrupt = {
      commitment: good[1].commitment,
      subShares: { ...good[1].subShares, [ids[0]]: wrong },
    };
    expect(() => applyRefresh(oldShares[0], [good[0], corrupt, good[2]], signers)).toThrow();
  });
});
