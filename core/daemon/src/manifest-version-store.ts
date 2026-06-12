/**
 * M7-MANIFEST-002 — Manifest version store re-exports.
 *
 * IManifestVersionStore persists the last-seen manifest version number to enforce
 * version monotonicity across daemon restarts. A manifest with a lower version
 * number than the last-seen version is rejected as a potential rollback attack.
 *
 * InMemoryManifestVersionStore: stub for tests and initial deployments.
 * FileManifestVersionStore: file-backed bridge for cross-process persistence (AC-005).
 */

import type { IManifestVersionStore } from "@cello-protocol/transport";

// Re-export from transport stubs for convenience
export { InMemoryManifestVersionStore } from "@cello-protocol/transport";

export type { IManifestVersionStore };
