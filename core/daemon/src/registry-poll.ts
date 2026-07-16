/**
 * DOD-REGISTRY-1 (client half) — HTTP registry poll.
 *
 * Mirrors http-manifest-poll.ts: fetches the signed registry document from the directory,
 * verifies its Ed25519 signature against a BUILD-TIME-PINNED registry pubkey, enforces
 * anti-rollback (version must be strictly greater than last seen), and updates the
 * in-memory TypeRegistry on success. Never throws — a failure returns a distinct reason
 * and leaves the last-good cache untouched (a bad registry never blanks classification).
 *
 * INV-DIR-DUMB: the directory serves the registry as opaque bytes; the CLIENT is the
 * authoritative verifier.
 * INV-TYPE-CARRY: absent type → unclassified, never an error.
 * INV-ZERO-BUMP: a registry update requires NO release anywhere.
 *
 * Crypto reference: RFC 8032 (Ed25519 single-key verification of the inner document).
 */

import { verify } from "@cello-protocol/crypto";
import type { TypeRegistry, RegistryDocument } from "./type-registry.js";
import type { IRegistryVersionStore } from "./registry-version-store-db.js";
import type { IManifestPollScheduler } from "@cello-protocol/transport";

export interface RegistryPollLogger {
  info(event: string, ctx?: Record<string, unknown>): void;
  warn(event: string, ctx?: Record<string, unknown>): void;
  error(event: string, ctx?: Record<string, unknown>): void;
}

export type RegistryPollFailureReason =
  | "registry_http_unreachable"
  | "registry_not_published"
  | "registry_malformed"
  | "registry_signature_invalid"
  | "registry_version_rollback"
  | "registry_store_error";

export type RegistryPollOutcome =
  | { ok: true; adopted: boolean; oldVersion: number | null; newVersion: number }
  | { ok: false; reason: RegistryPollFailureReason };

export interface RegistryPollDeps {
  typeRegistry: TypeRegistry;
  registryVersionStore: IRegistryVersionStore;
  registryPubkey: string;
  logger: RegistryPollLogger;
}

const FETCH_TIMEOUT_MS = 10_000;

function canonicalRegistryBody(doc: Record<string, unknown>): Uint8Array {
  const body: Record<string, unknown> = {};
  for (const key of Object.keys(doc)) {
    if (key !== "signature") {
      body[key] = doc[key];
    }
  }
  const json = JSON.stringify(body, sortedReplacer);
  return new TextEncoder().encode(json);
}

function sortedReplacer(_key: string, value: unknown): unknown {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    const sorted: Record<string, unknown> = {};
    for (const k of Object.keys(value).sort()) {
      sorted[k] = (value as Record<string, unknown>)[k];
    }
    return sorted;
  }
  return value;
}

export async function pollRegistryOverHttp(
  opts: {
    directoryUrl: string;
    fetchFn?: typeof fetch;
    correlationId?: string;
  } & RegistryPollDeps,
): Promise<RegistryPollOutcome> {
  const {
    directoryUrl,
    fetchFn = fetch,
    correlationId,
    typeRegistry,
    registryVersionStore,
    registryPubkey,
    logger,
  } = opts;
  const registryUrl = `${directoryUrl.replace(/\/$/, "")}/registry`;

  logger.info("registry.poll.dispatched", { directoryUrl, correlationId });

  let rawBytes: ArrayBuffer;
  try {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), FETCH_TIMEOUT_MS);
    let resp: Response;
    try {
      resp = await fetchFn(registryUrl, { signal: ac.signal });
    } finally {
      clearTimeout(timer);
    }
    if (resp.status === 404) {
      logger.info("registry.poll.not_published", { directoryUrl, correlationId });
      return { ok: false, reason: "registry_not_published" };
    }
    if (!resp.ok) {
      logger.warn("registry.poll.failed", { reason: "registry_http_unreachable", status: resp.status, directoryUrl, correlationId });
      return { ok: false, reason: "registry_http_unreachable" };
    }
    rawBytes = await resp.arrayBuffer();
  } catch (err: unknown) {
    logger.warn("registry.poll.failed", { reason: "registry_http_unreachable", directoryUrl, correlationId, error: err instanceof Error ? err.message : String(err) });
    return { ok: false, reason: "registry_http_unreachable" };
  }

  let doc: Record<string, unknown>;
  try {
    const text = new TextDecoder().decode(rawBytes);
    doc = JSON.parse(text) as Record<string, unknown>;
  } catch {
    logger.warn("registry.poll.failed", { reason: "registry_malformed", directoryUrl, correlationId });
    return { ok: false, reason: "registry_malformed" };
  }

  if (typeof doc.version !== "number" || typeof doc.signature !== "string" || typeof doc.types !== "object" || doc.types === null) {
    logger.warn("registry.poll.failed", { reason: "registry_malformed", directoryUrl, correlationId });
    return { ok: false, reason: "registry_malformed" };
  }

  const version = doc.version as number;
  const signature = doc.signature as string;

  // Verify Ed25519 signature against pinned pubkey
  const bodyBytes = canonicalRegistryBody(doc);
  const sigBytes = new Uint8Array(Buffer.from(signature, "hex"));
  const pubBytes = new Uint8Array(Buffer.from(registryPubkey, "hex"));

  if (!verify(pubBytes, bodyBytes, sigBytes)) {
    logger.warn("registry.signature.invalid", { version, directoryUrl, correlationId });
    return { ok: false, reason: "registry_signature_invalid" };
  }

  // Anti-rollback + adopt
  try {
    const lastSeen = registryVersionStore.getLastSeenVersion();
    if (lastSeen !== null && version <= lastSeen) {
      if (version < lastSeen) {
        logger.warn("registry.poll.failed", { reason: "registry_version_rollback", version, lastSeenVersion: lastSeen, correlationId });
        return { ok: false, reason: "registry_version_rollback" };
      }
      // Equal — already current
      return { ok: true, adopted: false, oldVersion: lastSeen, newVersion: version };
    }

    const oldVersion = typeRegistry.currentVersion;
    typeRegistry.update(doc as unknown as RegistryDocument);
    registryVersionStore.persistVersion(version);
    logger.info("registry.poll.success", { oldVersion, newVersion: version, directoryUrl, correlationId });
    return { ok: true, adopted: true, oldVersion, newVersion: version };
  } catch (err: unknown) {
    logger.error("registry.poll.failed", { reason: "registry_store_error", version, directoryUrl, correlationId, error: err instanceof Error ? err.message : String(err) });
    return { ok: false, reason: "registry_store_error" };
  }
}

export function startRegistryPoll(
  opts: {
    scheduler: IManifestPollScheduler;
    directoryUrl: string;
    fetchFn?: typeof fetch;
    mintCorrelationId?: () => string;
  } & RegistryPollDeps,
): () => void {
  const { scheduler, directoryUrl, fetchFn, mintCorrelationId, typeRegistry, registryVersionStore, registryPubkey, logger } = opts;
  let stopped = false;

  const tick = async (): Promise<void> => {
    if (stopped) return;
    await pollRegistryOverHttp({
      directoryUrl,
      fetchFn,
      correlationId: mintCorrelationId?.(),
      typeRegistry,
      registryVersionStore,
      registryPubkey,
      logger,
    }).catch((err: unknown) => {
      logger.error("registry.poll.failed", { reason: "registry_poll_unexpected_error", directoryUrl, error: err instanceof Error ? err.message : String(err) });
    });
    if (!stopped) scheduler.scheduleNext(tick);
  };

  scheduler.scheduleNext(tick);
  return () => {
    stopped = true;
    scheduler.cancel();
  };
}
