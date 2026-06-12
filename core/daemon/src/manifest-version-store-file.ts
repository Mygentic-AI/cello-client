/**
 * FileManifestVersionStore — file-backed IManifestVersionStore.
 *
 * Persists the last-seen manifest version to a JSON file on disk, enabling
 * version monotonicity enforcement across daemon restarts.
 *
 * Crypto reference: RFC 8032 (this module stores the manifest version number
 * that backs the monotonicity invariant; the version itself is not cryptographic,
 * but its correct persistence is load-bearing for anti-rollback security).
 */

import { readFile, writeFile, rename, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import type { IManifestVersionStore } from "@cello-protocol/transport";

interface VersionStoreFile {
  lastSeenVersion: number;
}

export class FileManifestVersionStore implements IManifestVersionStore {
  readonly #filePath: string;

  constructor(filePath: string) {
    this.#filePath = filePath;
  }

  async getLastSeenVersion(): Promise<number | null> {
    try {
      const raw = await readFile(this.#filePath, "utf-8");
      const parsed = JSON.parse(raw) as VersionStoreFile;
      return typeof parsed.lastSeenVersion === "number" ? parsed.lastSeenVersion : null;
    } catch {
      return null;
    }
  }

  async persistVersion(version: number): Promise<void> {
    await mkdir(dirname(this.#filePath), { recursive: true });
    const content: VersionStoreFile = { lastSeenVersion: version };
    // ADV-005: Atomic write using write-to-temp-then-rename pattern.
    // rename() is atomic on POSIX (same filesystem). This prevents a crash
    // during write from corrupting the version file and resetting the
    // monotonicity check (which would enable a rollback attack on next start).
    const tmpPath = this.#filePath + ".tmp";
    await writeFile(tmpPath, JSON.stringify(content), "utf-8");
    await rename(tmpPath, this.#filePath);
  }
}
