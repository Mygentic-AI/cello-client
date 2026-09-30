/**
 * DOD-M15-CONSORTIUM-FINGERPRINT-1 — which consortium is this daemon actually verifying against?
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
 * whose officer signatures do not verify against the root keys it is handed, and fails CLOSED with
 * `manifest_signature_invalid`. A fake consortium cannot fool a genuine client that is verifying
 * against ours; it can only ship its own client.
 *
 * The gap is that the answer was never shown. "Am I on the real network?" was a judgement call
 * instead of a command — this milestone's recurring shape, a check that runs, decides correctly, and
 * tells nobody.
 *
 * ─── ⚠️ IT REPORTS THE ENFORCED KEYS, NOT THE COMPILED-IN ONES, AND THAT IS THE UNIT ───────────
 *
 * The first cut of this module read `BUNDLED_CONSORTIUM_ROOT_KEYS` unconditionally, and review
 * measured that the daemon does not always verify against them. `buildManifestDeps` has three
 * outcomes, not one:
 *
 *   BUNDLED      no `CELLO_CONSORTIUM_MANIFEST`, and the directory URL matches the bundled roster →
 *                the compiled-in keys are what `loadAndVerify` is handed.
 *   OVERRIDDEN   `CELLO_CONSORTIUM_MANIFEST` is set → `CELLO_CONSORTIUM_ROOT_KEYS` and
 *                `CELLO_CONSORTIUM_THRESHOLD` are what it is handed. A different consortium.
 *   NOT ANCHORED the resolved directory URL is not a bundled endpoint → `{}`: no provider, no root
 *                keys, no manifest verification at all.
 *
 * Printing the bundled fingerprint in the last two postures is the precise failure this order exists
 * to prevent, aimed the worst possible way: an operator talked into pointing at a fork reads the
 * genuine CELLO fingerprint and concludes they are safe. So the block takes the keys the daemon
 * hands the verifier, says which of the three postures it is in, and where nothing is anchored it
 * reports that instead of a fingerprint — a value describing a check that is not running is the one
 * output worse than silence.
 *
 * The value is still not configurable in the sense that matters: nothing here reads the environment,
 * and an override cannot make this block SAY `bundled`. It can only make it say, out loud, that an
 * override is in force.
 *
 * Crypto reference: RFC 6234 (SHA-256). The digest is an identifier, not a security boundary — the
 * security boundary is the Ed25519 AND ML-DSA threshold verification in `verifyManifest` (RFC 8032,
 * FIPS 204). This makes
 * that boundary's anchor readable by a human in one glance.
 */

import { createHash } from "node:crypto";
import {
  BUNDLED_CONSORTIUM_ROOT_KEYS,
  BUNDLED_CONSORTIUM_THRESHOLD,
  BUNDLED_CONSORTIUM_ROOT_KEYS_PQ,
  BUNDLED_CONSORTIUM_PQ_THRESHOLD,
} from "./bundled-consortium-manifest.js";
import { consortiumRootsUsable, type ConsortiumRoots } from "@cello-protocol/transport";
import type { Logger } from "./types.js";

/** The roots compiled into this client — what `bundled` means. */
const BUNDLED_ROOTS: ConsortiumRoots = {
  rootKeys: BUNDLED_CONSORTIUM_ROOT_KEYS,
  threshold: BUNDLED_CONSORTIUM_THRESHOLD,
  rootKeysPq: BUNDLED_CONSORTIUM_ROOT_KEYS_PQ,
  pqThreshold: BUNDLED_CONSORTIUM_PQ_THRESHOLD,
};

/**
 * Domain separator. Versioned so a future change to what the fingerprint covers produces a visibly
 * different value rather than a silently different one over the same inputs.
 */
export const CONSORTIUM_FINGERPRINT_DOMAIN = "cello-consortium-root-v2";

/** Where the genuine value is published, for an operator comparing what they just read. */
export const CONSORTIUM_FINGERPRINT_PUBLISHED_AT = "https://cello.mygentic.ai/fingerprint";

/**
 * The canonical preimage (v2, M9D 004): domain, the Ed25519 root keys lowercased and SORTED, their
 * threshold, then the ML-DSA root keys lowercased and SORTED, and their threshold — one per line.
 * Both sets are enforced, so both are inside the value an operator compares.
 *
 * Sorting is what makes the fingerprint a property of the KEY SET rather than of the order someone
 * happened to write the array in — otherwise a cosmetic reordering during an officer rotation would
 * read as a different consortium and send an operator hunting an attack that is not there.
 *
 * The threshold is inside the preimage because it is enforced alongside the keys: the same two
 * officer keys at threshold 1 and at threshold 2 are different trust arrangements, and a fork that
 * reused our keys at a weaker threshold would otherwise fingerprint identically to us.
 */
export function consortiumFingerprintPreimage(roots: ConsortiumRoots): string {
  const norm = (ks: readonly string[]): string[] => [...ks].map((k) => k.trim().toLowerCase()).sort();
  return [
    CONSORTIUM_FINGERPRINT_DOMAIN,
    ...norm(roots.rootKeys), String(roots.threshold),
    ...norm(roots.rootKeysPq), String(roots.pqThreshold),
  ].join("\n") + "\n";
}

/** The full SHA-256 digest, hex, of the canonical preimage. */
export function consortiumFingerprintFull(roots: ConsortiumRoots): string {
  return createHash("sha256").update(consortiumFingerprintPreimage(roots), "utf8").digest("hex");
}

/**
 * The SHORT form an operator actually compares by eye: the first 16 hex characters of the digest,
 * in four groups of four.
 *
 * Grouped because an ungrouped hex run is where eye-comparison fails — a reader checks the first
 * few characters and the last few and skips the middle, which is precisely the substitution an
 * attacker would make. The full digest stays in the response beside it for anything automated.
 */
export function consortiumFingerprintShort(roots: ConsortiumRoots): string {
  const full = consortiumFingerprintFull(roots);
  return (full.slice(0, 16).match(/.{4}/g) ?? []).join("-");
}

/** What the daemon actually hands `loadAndVerify` — both root sets, or nothing. */
export type EnforcedConsortium = ConsortiumRoots | undefined;

export type ConsortiumPosture = "bundled" | "overridden" | "not_anchored";

/**
 * Which of the three postures a set of enforced values represents.
 *
 * `bundled` is decided by comparing FINGERPRINTS rather than array contents, so a reordered or
 * differently-cased copy of our own key set is still recognised as ours — the same normalisation the
 * published value carries, applied to the decision that quotes it.
 */
export function consortiumPosture(enforced: EnforcedConsortium): ConsortiumPosture {
  if (!enforced || !consortiumRootsUsable(enforced)) return "not_anchored";
  return consortiumFingerprintFull(enforced) === consortiumFingerprintFull(BUNDLED_ROOTS) ? "bundled" : "overridden";
}

/**
 * The status block, for `cello status` and `cello_status`.
 *
 * NOTE the same inversion as `describeDirectoryAuth`: the HEALTHY case contributes a field here,
 * against this milestone's general rule that a field on the good path is furniture. The defect being
 * closed is that the real network and a fork are distinguished by nothing an operator can read, so
 * "I checked, and it is ours" has to be an answer they can obtain — an absence proves nothing.
 */
export function describeConsortiumFingerprint(enforced: EnforcedConsortium): Record<string, unknown> {
  const posture = consortiumPosture(enforced);
  const bundledShort = consortiumFingerprintShort(BUNDLED_ROOTS);

  if (posture === "not_anchored" || !enforced) {
    return {
      consortium_root_fingerprint: null,
      consortium_root_fingerprint_state: "not_anchored",
      consortium_root_fingerprint_guidance:
        "This daemon is verifying NO consortium manifest, so there is no root key set to fingerprint " +
        "and nothing here tells you which network you are on. It happens when the resolved directory " +
        "URL is not one of the endpoints in the bundled roster — local development and the e2e " +
        "harness are the designed cases. A daemon started through the normal CLI with " +
        "CELLO_DIRECTORY_URL unset anchors to the bundled roster automatically; " +
        "directory_authentication in this same output reports the related posture and names the URL " +
        "that failed to match. The CELLO consortium's own fingerprint is " + bundledShort +
        ", published at " + CONSORTIUM_FINGERPRINT_PUBLISHED_AT + ".",
    };
  }

  return {
    consortium_root_fingerprint: consortiumFingerprintShort(enforced),
    consortium_root_fingerprint_full: consortiumFingerprintFull(enforced),
    consortium_root_fingerprint_state: posture,
    // Only when they differ. On the bundled path the two are the same value, and printing it twice
    // invites a reader to compare a number with itself and conclude something from the match.
    ...(posture === "overridden" ? { consortium_root_fingerprint_bundled: bundledShort } : {}),
    consortium_root_fingerprint_guidance:
      posture === "bundled"
        ? "This is the consortium root key set this daemon verifies every manifest against; a " +
          "manifest signed by any other root key is refused. It is the set compiled into this " +
          "client, and no setting is overriding it. Compare it with the value published at " +
          CONSORTIUM_FINGERPRINT_PUBLISHED_AT + " — if they differ, this client is not talking to " +
          "the CELLO consortium, whatever it calls itself."
        : "This daemon is verifying manifests against a root key set supplied by " +
          "CELLO_CONSORTIUM_ROOT_KEYS / CELLO_CONSORTIUM_THRESHOLD / CELLO_CONSORTIUM_ROOT_KEYS_PQ / " +
          "CELLO_CONSORTIUM_PQ_THRESHOLD, NOT the set compiled into this client (" + bundledShort + "). " +
          "That is a different consortium, and receipts from it say nothing about CELLO. If you did " +
          "not choose that deliberately, unset CELLO_CONSORTIUM_MANIFEST and all four root settings and " +
          "restart the daemon, which returns it to the bundled roster. The genuine CELLO value is " +
          "published at " + CONSORTIUM_FINGERPRINT_PUBLISHED_AT + ".",
  };
}

/**
 * The startup event — clause 6: "which network is this daemon on" is one grep.
 *
 * Emitted unconditionally, on every startup and in all three postures, because the question is asked
 * AFTER the fact. An operator reading a log days later, about a daemon that is no longer running,
 * cannot go and run `cello status` on it; the status surface answers only for a process that still
 * exists. It reports the ENFORCED keys for the same reason the status block does — a log line saying
 * a daemon was anchored to CELLO when it was anchored to nothing is worse than no log line.
 */
export function logConsortiumAnchor(logger: Logger, enforced: EnforcedConsortium): void {
  const posture = consortiumPosture(enforced);
  const anchored = posture !== "not_anchored";
  logger.info("daemon.consortium.anchored", {
    posture,
    fingerprint: anchored && enforced ? consortiumFingerprintShort(enforced) : null,
    fingerprintFull: anchored && enforced ? consortiumFingerprintFull(enforced) : null,
    bundledFingerprint: consortiumFingerprintShort(BUNDLED_ROOTS),
    rootKeyCount: enforced?.rootKeys.length ?? 0,
    threshold: enforced?.threshold ?? null,
    pqRootKeyCount: enforced?.rootKeysPq.length ?? 0,
    pqThreshold: enforced?.pqThreshold ?? null,
  });
}
