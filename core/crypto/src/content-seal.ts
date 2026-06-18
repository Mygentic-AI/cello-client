/**
 * CELLO-M7-MSG-001 — recipient content sealed box.
 *
 * E2E-encrypts a content blob to a recipient's stable Ed25519 identity key so that
 * the relay store-and-forward queue holds only ciphertext it cannot read (SI-001).
 *
 * The relay never has any decryption key. Only the holder of the recipient's
 * Ed25519 identity seed can open the blob.
 *
 * ─── Construction ────────────────────────────────────────────────────────────
 *
 * Pseudocode (SPARC Phase P):
 *
 *   sealToRecipient(recipientEd25519Pub, plaintext):
 *     1. uPub      = edwardsToMontgomery(recipientEd25519Pub)   # RFC 7748 §4.1 map
 *     2. ephSk     = random X25519 secret                        # RFC 7748
 *        ephPk     = X25519 base * ephSk
 *     3. shared    = X25519(ephSk, uPub)                         # ephemeral-static ECDH
 *     4. key       = HKDF-SHA256(ikm=shared, salt=ephPk,
 *                                info="cello-content-park-v1", 32)  # RFC 5869
 *     5. iv        = random 12 bytes
 *        ct||tag   = AES-256-GCM(key, iv, plaintext)             # NIST SP 800-38D
 *     6. blob      = ephPk(32) || iv(12) || ct || tag(16)
 *
 *   openSealed(recipientEd25519Seed, blob):
 *     1. ephPk, iv, ctAndTag = split(blob)
 *     2. montSk  = clamp(SHA-512(seed)[0:32])                    # ed25519 → x25519 scalar
 *     3. shared  = X25519(montSk, ephPk)
 *     4. key     = HKDF-SHA256(ikm=shared, salt=ephPk, info=..., 32)
 *     5. plaintext = AES-256-GCM-decrypt(key, iv, ct, tag)      # null on auth failure
 *
 * Correctness of the Ed25519→X25519 conversion is verified by the round-trip test:
 * the sender converts the recipient's Ed25519 *public* key to a Montgomery
 * u-coordinate; the recipient derives the matching Montgomery *scalar* from its
 * Ed25519 seed; ECDH on both sides yields the same shared secret (RFC 7748 §4.1).
 */

import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

const EPH_PUB_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const KEY_BYTES = 32;

/** Fixed bytes prepended before the AEAD ciphertext: ephemeral pubkey + IV. */
export const CONTENT_SEAL_OVERHEAD_BYTES = EPH_PUB_BYTES + IV_BYTES;

const HKDF_INFO = new TextEncoder().encode("cello-content-park-v1");

const Fp = ed25519.Point.Fp;

/**
 * Convert an Ed25519 public key (Edwards y) to a Montgomery u-coordinate
 * (RFC 7748 §4.1): u = (1 + y) / (1 - y) mod p.
 * Returns null if the point is invalid or maps to the singular point (y == 1).
 */
function edwardsPubToMontgomeryU(edPub: Uint8Array): Uint8Array | null {
  try {
    const pt = ed25519.Point.fromBytes(edPub);
    const y = pt.toAffine().y;
    const denom = Fp.sub(Fp.ONE, y);
    if (Fp.is0(denom)) return null;
    const u = Fp.div(Fp.add(Fp.ONE, y), denom);
    return Fp.toBytes(u);
  } catch {
    return null;
  }
}

/**
 * Derive the X25519 (Montgomery) scalar from an Ed25519 seed, per RFC 8032 §5.1.5
 * key-derivation + RFC 7748 clamping. This is the same scalar Ed25519 uses, which
 * is birationally compatible with the public-key conversion above.
 */
function ed25519SeedToMontgomeryScalar(seed: Uint8Array): Uint8Array {
  const h = sha512(seed.subarray(0, 32));
  const s = h.slice(0, 32);
  s[0] &= 248;
  s[31] &= 127;
  s[31] |= 64;
  return s;
}

/** Encrypt `plaintext` to a recipient identified by their Ed25519 public key. */
export function sealToRecipient(recipientEd25519Pub: Uint8Array, plaintext: Uint8Array): Uint8Array {
  const uPub = edwardsPubToMontgomeryU(recipientEd25519Pub);
  if (!uPub) {
    throw new Error("content-seal: invalid recipient Ed25519 public key");
  }

  const ephSk = x25519.utils.randomSecretKey();
  const ephPk = x25519.getPublicKey(ephSk);
  const shared = x25519.getSharedSecret(ephSk, uPub);
  const key = hkdf(sha256, shared, ephPk, HKDF_INFO, KEY_BYTES);

  const iv = new Uint8Array(randomBytes(IV_BYTES));
  const cipher = createCipheriv("aes-256-gcm", Buffer.from(key), Buffer.from(iv));
  const ct = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
  const tag = cipher.getAuthTag();

  return new Uint8Array(Buffer.concat([Buffer.from(ephPk), Buffer.from(iv), ct, tag]));
}

/**
 * Decrypt a sealed blob using the recipient's Ed25519 identity seed.
 * Returns null on any failure (wrong key, tamper, malformed) — never throws.
 */
export function openSealed(recipientEd25519Seed: Uint8Array, blob: Uint8Array): Uint8Array | null {
  if (blob.length < CONTENT_SEAL_OVERHEAD_BYTES + TAG_BYTES) return null;
  try {
    const ephPk = blob.subarray(0, EPH_PUB_BYTES);
    const iv = blob.subarray(EPH_PUB_BYTES, EPH_PUB_BYTES + IV_BYTES);
    const ctAndTag = blob.subarray(EPH_PUB_BYTES + IV_BYTES);
    const ct = ctAndTag.subarray(0, ctAndTag.length - TAG_BYTES);
    const tag = ctAndTag.subarray(ctAndTag.length - TAG_BYTES);

    const montSk = ed25519SeedToMontgomeryScalar(recipientEd25519Seed);
    const shared = x25519.getSharedSecret(montSk, ephPk);
    const key = hkdf(sha256, shared, ephPk, HKDF_INFO, KEY_BYTES);

    const decipher = createDecipheriv("aes-256-gcm", Buffer.from(key), Buffer.from(iv));
    decipher.setAuthTag(Buffer.from(tag));
    const pt = Buffer.concat([decipher.update(Buffer.from(ct)), decipher.final()]);
    return new Uint8Array(pt);
  } catch {
    return null;
  }
}
