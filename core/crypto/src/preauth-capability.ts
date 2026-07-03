/**
 * Pre-authorization capability — M8B-PREAUTH-CAP.
 *
 * A signed permission slip authorizing exactly ONE agent registration. It replaces the opaque
 * single-use pre-auth token: the token had to be looked up in the issuing directory's database, so
 * during a T-of-N DKG the other sovereign nodes — which never hold the token (DOD-INV-2 forbids
 * replicating bearer secrets) — returned NOT_FOUND and the ceremony failed. A capability carries an
 * Ed25519 signature by a pinned issuer key, so EVERY directory verifies it independently, statelessly,
 * with no DB lookup and nothing secret to replicate.
 *
 * Single-use is NOT enforced here — a signature is inherently replayable. It is enforced downstream by
 * the directory binding the capability's `nonce` to the DKG epoch (one nonce ⇒ one agent). This module
 * only mints and verifies the signed authorization and its validity window.
 *
 * Canonical body: all fields except `sig`, object keys sorted lexicographically at every level, JSON
 * with no whitespace, UTF-8 encoded — the SAME scheme as canonicalManifestBody (manifest.ts), kept
 * self-contained here so the two crypto primitives stay decoupled.
 *
 * Crypto reference: RFC 8032 (Ed25519).
 */
import type { KeyProvider } from "./types.js";
import { verify } from "./ed25519.js";

/** The signed fields of a pre-auth capability (everything except the signature). */
export interface PreAuthCapabilityBody {
  /** Random 128-bit replay identity as 32 lowercase hex chars (16 bytes). NOT a secret; one ⇒ one agent. */
  nonce: string;
  /** SHA-256 of the phone stub (hex) — the same binding datum the token row carried (SI-001: never the raw stub). */
  phone_stub_hash: string;
  /** Email domain of the authorized account. */
  email_domain: string;
  /** ISO-8601 issue time (informational). */
  issued_at: string;
  /** ISO-8601 expiry — the capability is invalid at or after this instant. */
  expires_at: string;
}

/** A signed pre-auth capability: the body plus the issuer's Ed25519 signature over its canonical bytes. */
export interface PreAuthCapability extends PreAuthCapabilityBody {
  /** Ed25519 signature (128 hex chars = 64 bytes) over canonicalCapabilityBody, by the issuer key. */
  sig: string;
}

export type CapabilityVerifyReason =
  | "capability_malformed"
  | "capability_signature_invalid"
  | "capability_expired";

export type CapabilityVerifyResult = { ok: true } | { ok: false; reason: CapabilityVerifyReason };

const BODY_FIELDS: readonly (keyof PreAuthCapabilityBody)[] = [
  "nonce",
  "phone_stub_hash",
  "email_domain",
  "issued_at",
  "expires_at",
];

/**
 * Produce the canonical byte representation of a capability body for signing.
 *
 * (RFC 8032 signing input) — copy every field EXCEPT `sig`, sort object keys lexicographically at every
 * nesting level, serialize as whitespace-free JSON, UTF-8 encode. Identical scheme to the manifest.
 */
export function canonicalCapabilityBody(cap: PreAuthCapabilityBody): Uint8Array {
  const body: Record<string, unknown> = {};
  for (const key of Object.keys(cap)) {
    if (key !== "sig") body[key] = (cap as unknown as Record<string, unknown>)[key];
  }
  return new TextEncoder().encode(JSON.stringify(body, sortedReplacer));
}

/** JSON.stringify replacer that sorts object keys lexicographically at every level (arrays keep order). */
function sortedReplacer(_key: string, value: unknown): unknown {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    const sorted: Record<string, unknown> = {};
    for (const k of Object.keys(value).sort()) sorted[k] = (value as Record<string, unknown>)[k];
    return sorted;
  }
  return value;
}

/**
 * Serialize a capability for transport and CLI: base64url of its JSON. Carried in the existing
 * round-1 `preAuthToken` string field (no wire-schema change) and pasted into `cello register`.
 */
export function encodeCapability(cap: PreAuthCapability): string {
  return Buffer.from(JSON.stringify(cap), "utf8").toString("base64url");
}

/** Parse a serialized capability blob; null if it is not valid base64url JSON (verify validates shape). */
export function decodeCapability(blob: string): PreAuthCapability | null {
  try {
    const obj: unknown = JSON.parse(Buffer.from(blob, "base64url").toString("utf8"));
    if (obj === null || typeof obj !== "object") return null;
    return obj as PreAuthCapability;
  } catch {
    return null;
  }
}

/** Sign a capability body with the issuer's Ed25519 key, returning the full capability with `sig` (hex). */
export async function signCapability(
  body: PreAuthCapabilityBody,
  issuer: KeyProvider,
): Promise<PreAuthCapability> {
  const sig = await issuer.sign(canonicalCapabilityBody(body));
  return { ...body, sig: Buffer.from(sig).toString("hex") };
}

/**
 * Verify a capability against the pinned issuer public key and validity window. NEVER throws — every
 * failure is a result value.
 *
 * (RFC 8032 verification)
 *   1. Structural check: all body fields present and string, `sig` is 64-byte hex → else `capability_malformed`.
 *   2. Ed25519.verify(sig, canonicalCapabilityBody, issuerPubkey) → else `capability_signature_invalid`.
 *   3. now >= expires_at → `capability_expired`.
 */
export function verifyCapability(
  cap: PreAuthCapability,
  issuerPubkeyHex: string,
  now: Date = new Date(),
): CapabilityVerifyResult {
  // 1. Structural validation — a malformed capability must fail loudly, never verify by accident.
  if (cap === null || typeof cap !== "object") return { ok: false, reason: "capability_malformed" };
  for (const f of BODY_FIELDS) {
    if (typeof (cap as unknown as Record<string, unknown>)[f] !== "string") {
      return { ok: false, reason: "capability_malformed" };
    }
  }
  const sigBytes = hexToBytes(cap.sig, 64);
  const pubBytes = hexToBytes(issuerPubkeyHex, 32);
  if (sigBytes === null || pubBytes === null) return { ok: false, reason: "capability_malformed" };

  // 2. Signature over the canonical body.
  let valid = false;
  try {
    valid = verify(pubBytes, canonicalCapabilityBody(cap), sigBytes);
  } catch {
    valid = false;
  }
  if (!valid) return { ok: false, reason: "capability_signature_invalid" };

  // 3. Validity window — invalid at or after expiry.
  const expires = new Date(cap.expires_at);
  if (Number.isNaN(expires.getTime()) || now >= expires) {
    return { ok: false, reason: "capability_expired" };
  }
  return { ok: true };
}

/** Decode a hex string to exactly `expectedBytes` bytes, or null if malformed. */
function hexToBytes(hex: string, expectedBytes: number): Uint8Array | null {
  if (typeof hex !== "string" || hex.length !== expectedBytes * 2 || !/^[0-9a-fA-F]+$/.test(hex)) {
    return null;
  }
  const out = new Uint8Array(expectedBytes);
  for (let i = 0; i < expectedBytes; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
