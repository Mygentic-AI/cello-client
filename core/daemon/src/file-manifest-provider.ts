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
 * Scope — signatures + structure ONLY. loadAndVerify verifies the threshold officer
 * signatures and rejects an empty node set; it deliberately does NOT enforce the
 * not_before/expires validity window or version monotonicity. That policy lives in
 * the daemon (startDaemon), which checks the window after loadAndVerify returns and
 * emits the named events `directory.auth.manifest.expired` /
 * `directory.auth.manifest.version.rollback`. If this provider threw on expiry, it
 * would preempt those named events (the daemon would only see `manifest.load.failed`)
 * and make the daemon's policy layer dead code. Anchoring to the daemon's actual
 * behaviour keeps the observability taxonomy intact (DOD-INV-6/8).
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
}

export class FileManifestProvider implements IManifestProvider {
  readonly #path: string;
  #manifest: ConsortiumManifest | null = null;

  constructor(opts: FileManifestProviderOpts) {
    this.#path = opts.path;
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
    // rejects an empty node set. This is the TUF root-of-trust gate. Expiry / version
    // monotonicity are enforced by the daemon (named events), not here.
    const result = verifyManifest(parsed as unknown as ConsortiumManifestInput, rootKeys, threshold);
    if (!result.ok) {
      throw new ManifestLoadError("manifest_signature_invalid", result.detail);
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

/**
 * EmbeddedManifestProvider — the production provider for the COMPILED-IN consortium roster
 * (FINDING-4). Identical trust gate to FileManifestProvider (threshold officer-signature
 * verification via `verifyManifest`, rejects an empty node set) but the manifest is an in-memory
 * constant compiled into the client rather than a file on disk. This is what the daemon wires by
 * default (no CELLO_CONSORTIUM_MANIFEST override), so the roster and step-6 directory-auth anchor
 * are always present — they cannot be lost by a missing package file or a skipped build-copy step,
 * and a corrupt/mis-signed embedded manifest fails CLOSED at load (ADV-002) rather than silently
 * degrading. Expiry / version monotonicity remain the daemon's policy layer, exactly as for
 * FileManifestProvider (see that class's note) — this provider does structure + signatures only.
 */
export class EmbeddedManifestProvider implements IManifestProvider {
  readonly #input: ConsortiumManifestInput;
  #manifest: ConsortiumManifest | null = null;

  constructor(input: ConsortiumManifestInput) {
    this.#input = input;
  }

  loadAndVerify(rootKeys: readonly string[], threshold: number): Promise<ConsortiumManifest> {
    const result = verifyManifest(this.#input, rootKeys, threshold);
    if (!result.ok) {
      return Promise.reject(new ManifestLoadError("manifest_signature_invalid", result.detail));
    }
    this.#manifest = this.#input as unknown as ConsortiumManifest;
    return Promise.resolve(this.#manifest);
  }

  getCurrentManifest(): ConsortiumManifest | null {
    return this.#manifest;
  }

  updateManifest(manifest: ConsortiumManifest): void {
    this.#manifest = manifest;
  }
}
