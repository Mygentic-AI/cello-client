/**
 * M7-MANIFEST-002 — Challenge verifier re-exports.
 *
 * The production verifier (ManifestDirectoryChallengeVerifier) and test stub
 * (TestDirectoryChallengeVerifier) are both defined in @cello-protocol/transport
 * to avoid creating a circular dependency between daemon and transport.
 *
 * This module re-exports them for consumers that import from the daemon package.
 */

export {
  ManifestDirectoryChallengeVerifier,
  TestDirectoryChallengeVerifier,
} from "@cello-protocol/transport";
export type { IDirectoryChallengeVerifier } from "@cello-protocol/transport";
