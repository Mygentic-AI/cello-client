/**
 * FileManifestProvider — the production IManifestProvider (M7-MANIFEST-001/002).
 *
 * Reads a consortium manifest JSON from disk, verifies its threshold officer
 * signatures against the configured root keys (RFC 8032 / Ed25519 via
 * `verifyManifest`), enforces the not_before/expires validity window, and caches
 * the result for getCurrentManifest(). This is the real counterpart to the
 * test-only `TestManifestProvider` (which skips verification): it is what the
 * cello-daemon binary wires when a manifest is configured, so step-6 directory
 * auth (DOD-AUTH-1) reads node pubkeys from a manifest that has actually been
 * verified, and a tampered / expired / rolled-back manifest is refused at load
 * (DOD-AUTH-2 / TUF).
 *
 * The interface contract (manifest-interfaces.ts): loadAndVerify "Throws on
 * signature failure, expiry, or missing nodes." This implementation honours that
 * — every distinct failure cause throws a distinct, named error (DOD-INV-6).
 */
import { readFileSync } from "node:fs";
import type { ConsortiumManifest } from "@cello-protocol/protocol-types";
import { verifyManifest, type ConsortiumManifestInput } from "@cello-protocol/crypto";
import type { IManifestProvider } from "@cello-protocol/transport";

export class ManifestLoadError extends Error {
  readonly reason: string;
  constructor(reason: string, detail?: string) {
    super(detail ? `${reason}: ${detail}` : reason);
    this.name = "ManifestLoadError";
    this.reason = reason;
  }
}

export interface FileManifestProviderOpts {
  /** Absolute path to the consortium manifest JSON. */
  path: string;
  /** Injectable clock (ms epoch) for the validity-window check. Defaults to Date.now. */
  now?: () => number;
}

export class FileManifestProvider implements IManifestProvider {
  readonly #path: string;
  readonly #now: () => number;
  #manifest: ConsortiumManifest | null = null;

  constructor(opts: FileManifestProviderOpts) {
    this.#path = opts.path;
    this.#now = opts.now ?? (() => Date.now());
  }

  async loadAndVerify(rootKeys: readonly string[], threshold: number): Promise<ConsortiumManifest> {
    let raw: string;
    try {
      raw = readFileSync(this.#path, "utf8");
    } catch (err: unknown) {
      throw new ManifestLoadError("manifest_unreadable", err instanceof Error ? err.message : String(err));
    }

    let parsed: ConsortiumManifest;
    try {
      parsed = JSON.parse(raw) as ConsortiumManifest;
    } catch (err: unknown) {
      throw new ManifestLoadError("manifest_malformed", err instanceof Error ? err.message : String(err));
    }

    // Threshold officer-signature verification (RFC 8032). verifyManifest also
    // rejects an empty node set. This is the TUF root-of-trust gate.
    const result = verifyManifest(parsed as unknown as ConsortiumManifestInput, rootKeys, threshold);
    if (!result.ok) {
      throw new ManifestLoadError("manifest_signature_invalid", result.detail);
    }

    // Validity window — a structurally-valid but stale manifest must be refused so
    // a withdrawn/rotated consortium cannot be replayed (DOD-AUTH-2 expiry).
    const nowMs = this.#now();
    const notBeforeMs = Date.parse(parsed.not_before);
    const expiresMs = Date.parse(parsed.expires);
    if (Number.isNaN(notBeforeMs) || Number.isNaN(expiresMs)) {
      throw new ManifestLoadError("manifest_malformed", "not_before/expires not ISO 8601");
    }
    if (nowMs < notBeforeMs) {
      throw new ManifestLoadError("manifest_not_yet_valid", `not_before=${parsed.not_before}`);
    }
    if (nowMs >= expiresMs) {
      throw new ManifestLoadError("manifest_expired", `expires=${parsed.expires}`);
    }

    this.#manifest = parsed;
    return parsed;
  }

  getCurrentManifest(): ConsortiumManifest | null {
    return this.#manifest;
  }

  updateManifest(manifest: ConsortiumManifest): void {
    this.#manifest = manifest;
  }
}
