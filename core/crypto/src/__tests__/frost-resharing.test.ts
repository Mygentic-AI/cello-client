/**
 * FROST proactive share resharing (PSS) — M8B DOD-REFRESH-1.
 *
 * Proves the zero-constant-term proactive secret sharing refresh (Herzberg et al. 1995): every party
 * adds a degree-(T-1) polynomial with constant term ZERO to its share. The sum of those polynomials has
 * constant term 0, so the JOINT SECRET (and therefore the group public key = commitments[0]) is
 * UNCHANGED, while every individual share is rotated — a share captured in epoch e is useless in e+1.
 * applyRefresh returns the full Key (rotated secret + homomorphically-updated public), so post-refresh
 * signing verifies against the SAME group key.
 *
 * @noble/curves@2.2.0 rejects `generateSecretPolynomial(secret=0)`, so the zero-constant polynomial is
 * built manually from `utils.Fn` + `utils.randomScalar`; `commitment[0]` is the curve identity (the proof
 * the refresh does not shift the secret). Oracles: `combineSecret` (joint secret byte-identical) AND a real
 * FROST signing ceremony with the rotated shares (the strongest end-to-end proof).
 */
import { describe, it, expect } from "vitest";
import { ed25519_FROST, ed25519 } from "@noble/curves/ed25519.js";
import type { Key } from "@noble/curves/abstract/frost.js";
import {
  generateRefreshContribution,
  verifyRefreshContribution,
  applyRefresh,
  type RefreshContribution,
} from "../frost/frost-resharing.js";

const signers = { min: 3, max: 3 };
const Fn = ed25519_FROST.utils.Fn;
const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

function setup(): { ids: string[]; oldKeys: Key[]; groupSecretBefore: Uint8Array } {
  const dealer = ed25519_FROST.trustedDealer(signers);
  const ids = Object.keys(dealer.secretShares);
  const oldKeys: Key[] = ids.map((id) => ({ secret: dealer.secretShares[id], public: dealer.public }));
  const groupSecretBefore = ed25519_FROST.combineSecret(oldKeys.map((k) => k.secret), signers);
  return { ids, oldKeys, groupSecretBefore };
}

/** A full agreed roster: one contribution from every participant. */
function fullRoster(ids: string[]): RefreshContribution[] {
  return ids.map((myId) => generateRefreshContribution(signers, myId, ids));
}

/** Run a real FROST T-of-T signing ceremony with the given keys; returns the aggregate signature. */
function frostSign(keys: Key[], msg: Uint8Array): Uint8Array {
  const nonces = keys.map((k) => ed25519_FROST.commit(k.secret));
  const commitmentList = nonces.map((n) => n.commitments);
  const sigShares: Record<string, Uint8Array> = {};
  for (let i = 0; i < keys.length; i++) {
    sigShares[keys[i].secret.identifier] = ed25519_FROST.signShare(
      keys[i].secret,
      keys[i].public,
      nonces[i].nonces,
      commitmentList,
      msg,
    );
  }
  return ed25519_FROST.aggregate(keys[0].public, commitmentList, msg, sigShares);
}

/** A contribution with a SPECIFIED constant term whose sub-shares are internally consistent (passes the
 *  Feldman check); drives the secret-shift attack through the real entry points. */
function contributionWithConstant(fromId: string, constant: bigint, ids: string[]): RefreshContribution {
  const coeffs = [constant, Fn.fromBytes(ed25519_FROST.utils.randomScalar()), Fn.fromBytes(ed25519_FROST.utils.randomScalar())];
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
    const { ids, oldKeys, groupSecretBefore } = setup();
    const contributions = fullRoster(ids);
    const newKeys = oldKeys.map((k) => applyRefresh(k, contributions, signers, ids));

    // (1) joint secret byte-identical ⇒ group public key unchanged.
    expect(hex(ed25519_FROST.combineSecret(newKeys.map((k) => k.secret), signers))).toBe(hex(groupSecretBefore));
    // (2) group public key (commitments[0]) byte-identical.
    expect(hex(newKeys[0].public.commitments[0])).toBe(hex(oldKeys[0].public.commitments[0]));
    // (3) every share rotated; identifier preserved.
    for (let i = 0; i < oldKeys.length; i++) {
      expect(hex(newKeys[i].secret.signingShare)).not.toBe(hex(oldKeys[i].secret.signingShare));
      expect(newKeys[i].secret.identifier).toBe(oldKeys[i].secret.identifier);
    }
  });

  it("a real FROST signature VERIFIES after the refresh — rotated shares + updated public are consistent", () => {
    const { ids, oldKeys } = setup();
    const groupPubkey = oldKeys[0].public.commitments[0] as Uint8Array;
    const msg = new TextEncoder().encode("cello post-refresh signature proof");

    // Signs before the refresh (sanity).
    expect(ed25519_FROST.verify(frostSign(oldKeys, msg), msg, groupPubkey)).toBe(true);

    // ALL parties apply the SAME agreed contribution set (the uniform-relay precondition).
    const contributions = fullRoster(ids);
    const newKeys = oldKeys.map((k) => applyRefresh(k, contributions, signers, ids));

    // The rotated shares jointly produce a signature that verifies against the UNCHANGED group key. This
    // is the end-to-end proof that the updated public (commitments[1..] + verifyingShares) is coherent —
    // a divergent/incorrect pub update would make signShare/aggregate produce an invalid signature.
    expect(hex(newKeys[0].public.commitments[0])).toBe(hex(groupPubkey));
    expect(ed25519_FROST.verify(frostSign(newKeys, msg), msg, groupPubkey)).toBe(true);
  });

  it("old shares are DEAD: a mixed old+new share set does NOT reconstruct the secret", () => {
    const { ids, oldKeys, groupSecretBefore } = setup();
    const contributions = fullRoster(ids);
    const newKeys = oldKeys.map((k) => applyRefresh(k, contributions, signers, ids));

    // A node compromised in epoch e holds an OLD share; with the OTHER parties' NEW shares it is on an
    // inconsistent polynomial and cannot reconstruct (or sign for) the joint secret.
    const mixed = [oldKeys[0].secret, newKeys[1].secret, newKeys[2].secret];
    expect(hex(ed25519_FROST.combineSecret(mixed, signers))).not.toBe(hex(groupSecretBefore));
    // ...whereas the FULL new set DOES reconstruct (positive companion — the rotation is coherent).
    expect(hex(ed25519_FROST.combineSecret(newKeys.map((k) => k.secret), signers))).toBe(hex(groupSecretBefore));
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
    const shiftBy2 = [ed25519.Point.BASE.multiply(2n).toBytes(), ...c.commitment.slice(1)];
    expect(() => verifyRefreshContribution(shiftBy2, signers)).toThrow(/identity|commitment\[0\]|shift/);
    const randomPoint = ed25519.Point.BASE.multiply(Fn.fromBytes(ed25519_FROST.utils.randomScalar())).toBytes();
    expect(() => verifyRefreshContribution([randomPoint, ...c.commitment.slice(1)], signers)).toThrow(/identity|commitment\[0\]|shift/);
    expect(() => verifyRefreshContribution([ed25519.Point.BASE.toBytes(), ...c.commitment.slice(1)], signers)).toThrow();
  });

  it("VSS REJECTS the zero polynomial (all-identity commitment) — a free-rider adding no randomness", () => {
    const allIdentity = Array.from({ length: signers.min }, () => ed25519.Point.ZERO.toBytes());
    expect(() => verifyRefreshContribution(allIdentity, signers)).toThrow(/zero polynomial|randomness/);
  });

  it("applyRefresh REJECTS a fully self-consistent SHIFTING contribution end-to-end (secret-shift attack)", () => {
    const { ids, oldKeys } = setup();
    const contributions = [
      contributionWithConstant(ids[0], 2n, ids), // the shift
      generateRefreshContribution(signers, ids[1], ids),
      generateRefreshContribution(signers, ids[2], ids),
    ];
    expect(() => applyRefresh(oldKeys[0], contributions, signers, ids)).toThrow(/identity|commitment\[0\]|shift/);
  });

  it("applyRefresh VSS-REJECTS a sub-share inconsistent with the sender's commitment", () => {
    const { ids, oldKeys } = setup();
    const good = fullRoster(ids);
    const corrupt: RefreshContribution = {
      fromId: good[1].fromId,
      commitment: good[1].commitment,
      subShares: { ...good[1].subShares, [ids[0]]: ed25519_FROST.utils.randomScalar() },
    };
    expect(() => applyRefresh(oldKeys[0], [good[0], corrupt, good[2]], signers, ids)).toThrow(/VSS/);
  });

  describe("completeness gate — a partial/empty/divergent set must FAIL LOUD, never silently no-op", () => {
    it("REJECTS an empty contribution set (would return the old share unchanged = dead-share no-op)", () => {
      const { ids, oldKeys } = setup();
      expect(() => applyRefresh(oldKeys[0], [], signers, ids)).toThrow(/incomplete|missing/);
    });

    it("REJECTS a partial set missing a participant (would diverge the joint key)", () => {
      const { ids, oldKeys } = setup();
      const partial = fullRoster(ids).slice(0, 2);
      expect(() => applyRefresh(oldKeys[0], partial, signers, ids)).toThrow(/incomplete|missing/);
    });

    it("REJECTS a duplicate contribution from one party (double-counts a δ)", () => {
      const { ids, oldKeys } = setup();
      const good = fullRoster(ids);
      expect(() => applyRefresh(oldKeys[0], [good[0], good[0], good[2]], signers, ids)).toThrow(/duplicate/);
    });

    it("REJECTS a contribution from a party outside the agreed roster", () => {
      const { ids, oldKeys } = setup();
      const good = fullRoster(ids);
      const stranger = { ...good[1], fromId: "ff".repeat(32) };
      expect(() => applyRefresh(oldKeys[0], [good[0], stranger, good[2]], signers, ids)).toThrow(/unexpected|roster/);
    });
  });
});
