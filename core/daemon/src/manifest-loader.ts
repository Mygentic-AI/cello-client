/**
 * M7-MANIFEST-002 — FileManifestProvider: production IManifestProvider implementation.
 *
 * Reads the bundled consortium-manifest.json from the package root, parses it,
 * verifies the threshold signatures, and caches the result for subsequent calls
 * to getCurrentManifest().
 *
 * Tests use TestManifestProvider (from @cello-protocol/transport) which
 * takes a pre-built ConsortiumManifest and skips file read and signature verification.
 *
 * Crypto reference: RFC 8032 (Ed25519 threshold signature verification via verifyManifest).
 */

import { readFile } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyManifest } from "@cello-protocol/crypto";
import type { ConsortiumManifestInput } from "@cello-protocol/crypto";
import type { ConsortiumManifest } from "@cello-protocol/protocol-types";
import type { IManifestProvider } from "@cello-protocol/transport";

/**
 * FileManifestProvider — reads consortium-manifest.json from the package root.
 *
 * Pseudocode:
 *   loadAndVerify(rootKeys, threshold):
 *     1. Read consortium-manifest.json from the package root (same directory as this file).
 *     2. Parse as JSON — throw on parse failure.
 *     3. Call verifyManifest(parsed, rootKeys, threshold) — RFC 8032 Ed25519 threshold check.
 *     4. If ok: cache the manifest, return it.
 *     5. If not ok: throw Error with reason from verifyManifest diagnostics.
 */
export class FileManifestProvider implements IManifestProvider {
  readonly #manifestPath: string;
  #cachedManifest: ConsortiumManifest | null = null;

  constructor(manifestPath?: string) {
    // Default: consortium-manifest.json in the same directory as this file
    this.#manifestPath = manifestPath ?? join(
      dirname(fileURLToPath(import.meta.url)),
      "consortium-manifest.json",
    );
  }

  async loadAndVerify(rootKeys: readonly string[], threshold: number): Promise<ConsortiumManifest> {
    // Step 1: read the manifest file
    let raw: string;
    try {
      raw = await readFile(this.#manifestPath, "utf-8");
    } catch (err: unknown) {
      throw new Error(
        `manifest_file_unreadable: cannot read ${this.#manifestPath}: ${err instanceof Error ? err.message : String(err)}`,
      );
    }

    // Step 2: parse JSON
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (err: unknown) {
      throw new Error(`manifest_parse_failed: ${err instanceof Error ? err.message : String(err)}`);
    }

    // Cast to ConsortiumManifestInput for verifyManifest (uses indexed record type)
    const manifest = parsed as ConsortiumManifestInput;

    // Step 3: verify threshold signatures (RFC 8032)
    const result = verifyManifest(manifest, rootKeys, threshold);
    if (!result.ok) {
      throw new Error(
        `${result.reason}: ${result.detail} (threshold=${result.diagnostics.threshold}, valid=${result.diagnostics.validOfficers.length})`,
      );
    }

    // Step 4: cache and return (cast back to ConsortiumManifest for consumers)
    this.#cachedManifest = manifest as unknown as ConsortiumManifest;
    return this.#cachedManifest;
  }

  getCurrentManifest(): ConsortiumManifest | null {
    return this.#cachedManifest;
  }

  updateManifest(manifest: ConsortiumManifest): void {
    this.#cachedManifest = manifest;
  }
}
