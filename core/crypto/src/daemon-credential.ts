/**
 * Daemon credential and daemon-key proofs.
 *
 * A daemon credential is the issuer's signed statement that one daemon key belongs to one account.
 * The directory issues it after the account's owner approves the device in the portal, and every
 * directory verifies it on its own against the pinned issuer pubkey: no database lookup, nothing
 * secret to replicate.
 *
 * A credential alone would be a bearer token, so every use also carries a signature by the daemon
 * key it names. That key never leaves the daemon's machine, so a copied credential cannot be used
 * anywhere else.
 *
 * Every signed byte string begins with its own domain label, so no signature made here can be
 * replayed as another kind: a credential is not a pre-auth capability, and a registration proof is
 * not a pairing-poll proof. The credential carries no expiry.
 *
 * Canonical body: all fields except `sig`, object keys sorted, whitespace-free JSON, UTF-8, preceded
 * by the domain label — the capability's scheme plus the label.
 *
 * Crypto reference: RFC 8032 (Ed25519).
 */
import type { KeyProvider } from "./types.js";
import { verify } from "./ed25519.js";

/** The signed fields of a daemon credential (everything except the signature). */
export interface DaemonCredentialBody {
  /** Format version. Only 1 exists. */
  v: 1;
  /** Ed25519 public key of the daemon, 64 lowercase hex chars. */
  daemon_pubkey: string;
  /** The account the daemon belongs to: a lowercase UUID, minted once by the directory at approval. */
  account_id: string;
  /** 16 random bytes as 32 lowercase hex chars. Identifies this credential; not a secret. */
  nonce: string;
  /** ISO-8601 issue time (informational). */
  issued_at: string;
}

/** A daemon credential: the body plus the issuer's Ed25519 signature over its canonical bytes. */
export interface DaemonCredential extends DaemonCredentialBody {
  /** Ed25519 signature, 128 hex chars, by the issuer key. */
  sig: string;
}

export type CredentialVerifyReason = "credential_malformed" | "credential_signature_invalid";
export type CredentialVerifyResult = { ok: true } | { ok: false; reason: CredentialVerifyReason };

const CREDENTIAL_DOMAIN = "cello-daemon-credential-v1\n";
const REGISTER_DOMAIN = "cello-daemon-register-v1\n";
const PAIRING_POLL_DOMAIN = "cello-pairing-poll-v1\n";

const SIGNED_FIELDS = new Set(["v", "daemon_pubkey", "account_id", "nonce", "issued_at"]);
const HEX64 = /^[0-9a-f]{64}$/;
const HEX32 = /^[0-9a-f]{32}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** The bytes the issuer signs: the domain label, then the canonical JSON of every field but `sig`. */
export function canonicalCredentialBody(c: DaemonCredentialBody): Uint8Array {
  const body: Record<string, unknown> = {};
  for (const key of Object.keys(c).sort()) {
    if (key !== "sig") body[key] = (c as unknown as Record<string, unknown>)[key];
  }
  return new TextEncoder().encode(CREDENTIAL_DOMAIN + JSON.stringify(body));
}

/** Sign a credential body with the issuer key. */
export async function signDaemonCredential(
  body: DaemonCredentialBody,
  issuer: KeyProvider,
): Promise<DaemonCredential> {
  const sig = await issuer.sign(canonicalCredentialBody(body));
  return { ...body, sig: Buffer.from(sig).toString("hex") };
}

/**
 * Verify a credential against the pinned issuer pubkey. Never throws.
 *
 * (RFC 8032 verification)
 *   1. Shape: v === 1, lowercase-hex pubkey and nonce of the right length, lowercase UUID account,
 *      string issued_at, 128-hex sig → else `credential_malformed`.
 *   2. Ed25519.verify(sig, canonicalCredentialBody, issuerPubkey) → else `credential_signature_invalid`.
 */
export function verifyDaemonCredential(c: DaemonCredential, issuerPubkeyHex: string): CredentialVerifyResult {
  if (c === null || typeof c !== "object") return { ok: false, reason: "credential_malformed" };
  // Only signed fields and the signature: an extra field would ride along unsigned.
  if (Object.keys(c).some((k) => !SIGNED_FIELDS.has(k) && k !== "sig")) {
    return { ok: false, reason: "credential_malformed" };
  }
  if (typeof c.sig !== "string" || !/^[0-9a-f]{128}$/.test(c.sig)) return { ok: false, reason: "credential_malformed" };
  if (
    c.v !== 1 ||
    typeof c.daemon_pubkey !== "string" || !HEX64.test(c.daemon_pubkey) ||
    typeof c.account_id !== "string" || !UUID.test(c.account_id) ||
    typeof c.nonce !== "string" || !HEX32.test(c.nonce) ||
    typeof c.issued_at !== "string"
  ) {
    return { ok: false, reason: "credential_malformed" };
  }
  const sigBytes = hexToBytes(c.sig, 64);
  const pubBytes = hexToBytes(issuerPubkeyHex, 32);
  if (sigBytes === null || pubBytes === null) return { ok: false, reason: "credential_malformed" };
  const body: DaemonCredentialBody = {
    v: c.v, daemon_pubkey: c.daemon_pubkey, account_id: c.account_id, nonce: c.nonce, issued_at: c.issued_at,
  };
  let valid = false;
  try {
    valid = verify(pubBytes, canonicalCredentialBody(body), sigBytes);
  } catch {
    valid = false;
  }
  return valid ? { ok: true } : { ok: false, reason: "credential_signature_invalid" };
}

/** The bytes a daemon signs to register one agent under one credential. */
export function registrationProofBytes(agentPubkeyHex: string, credentialNonce: string): Uint8Array {
  return new TextEncoder().encode(`${REGISTER_DOMAIN}${agentPubkeyHex}\n${credentialNonce}`);
}

/** The bytes a daemon signs to ask whether its pairing has been approved. */
export function pairingPollBytes(pairingCode: string, unixSeconds: number): Uint8Array {
  return new TextEncoder().encode(`${PAIRING_POLL_DOMAIN}${pairingCode}\n${unixSeconds}`);
}

/** Sign bytes with the daemon key; returns 128 hex chars. */
export async function signWithDaemonKey(bytes: Uint8Array, daemonKey: KeyProvider): Promise<string> {
  return Buffer.from(await daemonKey.sign(bytes)).toString("hex");
}

/** Verify a daemon-key signature. Never throws; any malformed input is `false`. */
export function verifyDaemonSignature(bytes: Uint8Array, sigHex: string, daemonPubkeyHex: string): boolean {
  const sigBytes = hexToBytes(sigHex, 64);
  const pubBytes = hexToBytes(daemonPubkeyHex, 32);
  if (sigBytes === null || pubBytes === null) return false;
  try {
    return verify(pubBytes, bytes, sigBytes);
  } catch {
    return false;
  }
}

/** What a daemon presents to register an agent: its credential and its proof for that agent. */
export interface RegistrationGrant {
  credential: DaemonCredential;
  /** 128 hex chars: the daemon key's signature over `registrationProofBytes`. */
  proof: string;
}

/** Marks a grant in the registration token field, distinct from a capability or a claim code. */
export const REGISTRATION_GRANT_PREFIX = "DCRED1.";

/** Serialize a grant for the registration token field: the prefix, then base64url JSON. */
export function encodeRegistrationGrant(g: RegistrationGrant): string {
  return REGISTRATION_GRANT_PREFIX + Buffer.from(JSON.stringify(g), "utf8").toString("base64url");
}

/**
 * Parse a grant, or null if the value is not one. Whitespace is stripped first, because a long value
 * pasted through a terminal arrives wrapped. Only the shape is checked here; the credential and the
 * proof are verified by the caller.
 */
export function decodeRegistrationGrant(s: string): RegistrationGrant | null {
  if (typeof s !== "string") return null;
  const cleaned = s.replace(/\s+/g, "");
  if (!cleaned.startsWith(REGISTRATION_GRANT_PREFIX)) return null;
  const payload = cleaned.slice(REGISTRATION_GRANT_PREFIX.length);
  if (!/^[A-Za-z0-9_-]+$/.test(payload)) return null;
  try {
    const obj: unknown = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (obj === null || typeof obj !== "object") return null;
    const g = obj as Record<string, unknown>;
    if (g["credential"] === null || typeof g["credential"] !== "object" || typeof g["proof"] !== "string") return null;
    return { credential: g["credential"] as DaemonCredential, proof: g["proof"] };
  } catch {
    return null;
  }
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
