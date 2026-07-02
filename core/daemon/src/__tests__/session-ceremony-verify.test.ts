/**
 * F2-a — verifyBilateralSealCertificate must return a REASON on every
 * verified:false (accept-without-independent-verify) branch, so the
 * daemon's session.sealed.signature.checked log can never again read as a
 * silently-tolerated failed check.
 *
 * The two cheapest, share-free branches are covered here (they pin the new
 * `reason` contract deterministically without a real FROST share):
 *   - non_frost_certificate: signatureType !== "frost" → immediate accept.
 *   - no_frost_share:        persistence holds no share → cannot verify.
 *
 * The share-holding branches (own_primary_unavailable / signer_key_not_held)
 * are exercised end-to-end by the live seal path and the DAEMON-004 IPC seal
 * tests; the reason plumbing they share is validated here.
 */
import { describe, it, expect } from "vitest";
import { verifyBilateralSealCertificate } from "../session-ceremony.js";
import type { DaemonRegistrationPersistence } from "../registration-persistence.js";
import type { Logger } from "../types.js";

const noopLogger: Logger = {
  debug() {}, info() {}, warn() {}, error() {},
};

/** Minimal persistence stub — only loadActiveFrostKeyShare is reached by these branches. */
function makePersistence(share: unknown): DaemonRegistrationPersistence {
  return {
    async loadActiveFrostKeyShare() { return share as never; },
  } as unknown as DaemonRegistrationPersistence;
}

const AGENT_PUBKEY_HEX = "aa".repeat(32);

function baseCert(signatureType: "frost" | "single") {
  return {
    sessionId: new Uint8Array(32),
    sealedRoot: new Uint8Array(32),
    leafCount: 4,
    closeTimestamp: 1,
    frostSignature: new Uint8Array(64),
    signerPubkey: new Uint8Array(32), // 32 bytes so the length guard passes
    signatureType,
    legibility: null,
  };
}

describe("F2-a: verifyBilateralSealCertificate returns a reason on verified:false", () => {
  it("non-FROST certificate → { ok:true, verified:false, reason:'non_frost_certificate' }", async () => {
    const verdict = await verifyBilateralSealCertificate(
      { persistence: makePersistence(null), agentPubkeyHex: AGENT_PUBKEY_HEX, logger: noopLogger, counterpartyPrimaryHex: null },
      baseCert("single"),
    );
    expect(verdict.ok).toBe(true);
    expect(verdict).toMatchObject({ ok: true, verified: false, reason: "non_frost_certificate" });
  });

  it("no local FROST share → { ok:true, verified:false, reason:'no_frost_share' }", async () => {
    const verdict = await verifyBilateralSealCertificate(
      { persistence: makePersistence(null), agentPubkeyHex: AGENT_PUBKEY_HEX, logger: noopLogger, counterpartyPrimaryHex: null },
      baseCert("frost"),
    );
    expect(verdict.ok).toBe(true);
    expect(verdict).toMatchObject({ ok: true, verified: false, reason: "no_frost_share" });
  });

  it("still fails closed: a malformed (short) signer pubkey → { ok:false, reason:'no_signer_pubkey' }", async () => {
    const cert = baseCert("frost");
    cert.signerPubkey = new Uint8Array(16); // wrong length
    const verdict = await verifyBilateralSealCertificate(
      { persistence: makePersistence(null), agentPubkeyHex: AGENT_PUBKEY_HEX, logger: noopLogger, counterpartyPrimaryHex: null },
      cert,
    );
    expect(verdict).toMatchObject({ ok: false, reason: "no_signer_pubkey" });
  });
});
