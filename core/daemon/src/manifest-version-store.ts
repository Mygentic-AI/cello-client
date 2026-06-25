/**
 * M7-MANIFEST-002 — Manifest version store re-exports.
 *
 * IManifestVersionStore persists the last-seen manifest version number to enforce
 * version monotonicity across daemon restarts. A manifest with a lower version
 * number than the last-seen version is rejected as a potential rollback attack.
 *
 * InMemoryManifestVersionStore: stub for tests and initial deployments.
 * DbManifestVersionStore (manifest-version-store-db.ts): the production store — the version lives in
 * the SQLCipher-encrypted manifest_state table (PERSIST-002 AC-008). The old file-backed store was
 * removed.
 */

import type { IManifestVersionStore } from "@cello-protocol/transport";

// Re-export from transport stubs for convenience
export { InMemoryManifestVersionStore } from "@cello-protocol/transport";

export type { IManifestVersionStore };
