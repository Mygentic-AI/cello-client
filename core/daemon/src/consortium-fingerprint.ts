/**
 * DOD-M15-CONSORTIUM-FINGERPRINT-1 — which consortium is this client actually verifying against?
 *
 * ─── The attack this answers ───────────────────────────────────────────────────────────────────
 *
 * Anyone can fork the open-source client, stand up three nodes, sign their own consortium manifest
 * with their own officer root key and market the result as CELLO. The receipts that network issues
 * mean nothing, and when it is broken into the headline says CELLO was hacked. This is the
 * shadow-frontend attack from crypto, and it worked there for exactly one reason: a user had no
 * cheap way to tell the real deployment from the copy.
 *
 * ─── What already works, and what did not ──────────────────────────────────────────────────────
 *
 * The VERIFICATION is not the gap. `EmbeddedManifestProvider.loadAndVerify` refuses any manifest
 * whose officer signatures do not verify against `BUNDLED_CONSORTIUM_ROOT_KEYS`, compiled into this
 * client, and fails CLOSED with `manifest_signature_invalid`. A fake consortium cannot fool a
 * genuine client; it can only ship its own client.
 *
 * The gap is that the answer was never shown. "Am I on the real network?" was a judgement call
 * instead of a command — this milestone's recurring shape, a check that runs, decides correctly, and
 * tells nobody.
 *
 * ─── One source of truth, and why that is the whole design ─────────────────────────────────────
 *
 * The fingerprint is DERIVED from `BUNDLED_CONSORTIUM_ROOT_KEYS` and `BUNDLED_CONSORTIUM_THRESHOLD`
 * — the same two values the verifier enforces — every time it is read. It is never stored, never
 * copied into a second constant, and never configurable.
 *
 * A second copy would be the defect in miniature: a printed fingerprint that can drift from the
 * enforced one points the WRONG WAY, reassuring an operator who is on a fake network using a value
 * that no longer decides anything. And a fingerprint an operator can override is a fingerprint an
 * attacker can talk them into overriding, so nothing here reads the environment.
 *
 * Crypto reference: RFC 6234 (SHA-256). The digest is an identifier, not a security boundary — the
 * security boundary is the Ed25519 threshold verification in `verifyManifest` (RFC 8032). This makes
 * that boundary's anchor readable by a human in one glance.
 */

import { createHash } from "node:crypto";
import {
  BUNDLED_CONSORTIUM_ROOT_KEYS,
  BUNDLED_CONSORTIUM_THRESHOLD,
} from "./bundled-consortium-manifest.js";
import type { Logger } from "./types.js";

/**
 * Domain separator. Versioned so a future change to what the fingerprint covers produces a visibly
 * different value rather than a silently different one over the same inputs.
 */
export const CONSORTIUM_FINGERPRINT_DOMAIN = "cello-consortium-root-v1";

/** Where the genuine value is published, for an operator comparing what they just read. */
export const CONSORTIUM_FINGERPRINT_PUBLISHED_AT =
  "https://cello.mygentic.ai/fingerprint";

/**
 * The canonical preimage: domain, then the root keys lowercased and SORTED, then the threshold.
 *
 * Sorting is what makes the fingerprint a property of the KEY SET rather than of the order someone
 * happened to write the array in — otherwise a cosmetic reordering during an officer rotation would
 * read as a different consortium and send an operator hunting an attack that is not there.
 *
 * The threshold is inside the preimage because it is enforced alongside the keys: the same two
 * officer keys at threshold 1 and at threshold 2 are different trust arrangements, and a fork that
 * reused our keys at a weaker threshold would otherwise fingerprint identically to us.
 */
export function consortiumFingerprintPreimage(
  rootKeys: readonly string[],
  threshold: number,
): string {
  const keys = [...rootKeys].map((k) => k.trim().toLowerCase()).sort();
  return [CONSORTIUM_FINGERPRINT_DOMAIN, ...keys, String(threshold)].join("\n") + "\n";
}

/** The full SHA-256 digest, hex, of the canonical preimage. */
export function consortiumFingerprintFull(rootKeys: readonly string[], threshold: number): string {
  return createHash("sha256").update(consortiumFingerprintPreimage(rootKeys, threshold), "utf8").digest("hex");
}

/**
 * The SHORT form an operator actually compares by eye: the first 16 hex characters of the digest,
 * in four groups of four.
 *
 * Grouped because an ungrouped hex run is where eye-comparison fails — a reader checks the first
 * few characters and the last few and skips the middle, which is precisely the substitution an
 * attacker would make. The full digest stays in the response beside it for anything automated.
 */
export function consortiumFingerprintShort(rootKeys: readonly string[], threshold: number): string {
  const full = consortiumFingerprintFull(rootKeys, threshold);
  return (full.slice(0, 16).match(/.{4}/g) ?? []).join("-");
}

/**
 * The status block, for `cello status` and `cello_status`.
 *
 * NOTE the same inversion as `describeDirectoryAuth`: the HEALTHY case contributes a field here,
 * against this milestone's general rule that a field on the good path is furniture. The defect being
 * closed is that the real network and a fork are distinguished by nothing an operator can read, so
 * "I checked, and it is ours" has to be an answer they can obtain — an absence proves nothing.
 *
 * It reads the constants directly and takes no arguments, because every argument is a place a
 * different value could enter.
 */
export function describeConsortiumFingerprint(): Record<string, unknown> {
  return {
    consortium_root_fingerprint: consortiumFingerprintShort(
      BUNDLED_CONSORTIUM_ROOT_KEYS,
      BUNDLED_CONSORTIUM_THRESHOLD,
    ),
    consortium_root_fingerprint_full: consortiumFingerprintFull(
      BUNDLED_CONSORTIUM_ROOT_KEYS,
      BUNDLED_CONSORTIUM_THRESHOLD,
    ),
    consortium_root_fingerprint_guidance:
      "This is the consortium root key set this client will accept a manifest from; a manifest " +
      "signed by any other root key is refused. Compare it with the value published at " +
      CONSORTIUM_FINGERPRINT_PUBLISHED_AT +
      " — if they differ, this client is not talking to the CELLO consortium, whatever it calls " +
      "itself. The value cannot be configured, so nothing you were told to set can change it.",
  };
}

/**
 * The startup event — clause 6: "which network is this daemon on" is one grep.
 *
 * Emitted unconditionally, on every startup and under every manifest posture, because the question
 * is asked AFTER the fact. An operator reading a log days later, about a daemon that is no longer
 * running, cannot go and run `cello status` on it; the status surface answers only for a process
 * that still exists. `domain.noun.verb`: the consortium this daemon is anchored to.
 */
export function logConsortiumAnchor(logger: Logger): void {
  logger.info("daemon.consortium.anchored", {
    fingerprint: consortiumFingerprintShort(BUNDLED_CONSORTIUM_ROOT_KEYS, BUNDLED_CONSORTIUM_THRESHOLD),
    fingerprintFull: consortiumFingerprintFull(BUNDLED_CONSORTIUM_ROOT_KEYS, BUNDLED_CONSORTIUM_THRESHOLD),
    rootKeyCount: BUNDLED_CONSORTIUM_ROOT_KEYS.length,
    threshold: BUNDLED_CONSORTIUM_THRESHOLD,
  });
}
