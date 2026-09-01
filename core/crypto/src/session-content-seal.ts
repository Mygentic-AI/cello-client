/**
 * DOD-M15-EPHEMERAL-AUTH-1 — encrypting a message body under the AGREED SESSION KEY.
 *
 * ─── What this is for, and how it differs from `content-seal.ts` ───────────────────────────────
 *
 * Two encryption schemes exist in this codebase and they are NOT interchangeable. Which one applies
 * is decided by the ROUTE a message takes, and getting that wrong is silent:
 *
 *   **This file — LIVE messages.** Encrypted under the per-session key both sides agreed from
 *   throwaway keypairs (`session-key-agreement.ts`). Those keypairs are destroyed when the session
 *   ends, so a recording of the traffic cannot be decrypted later even if both agents' long-term
 *   identity keys are eventually compromised. That is forward secrecy, and it is the whole point.
 *
 *   **`content-seal.ts` — PARKED messages.** Encrypted to the recipient's LONG-TERM identity key,
 *   because the recipient is offline and cannot take part in a handshake. It has no forward secrecy
 *   by construction: whoever holds that identity key can open every message ever sealed to it. That
 *   is an accepted trade for the mailbox and must not be copied here.
 *
 * ⚠️ A message that fails live delivery falls back to the mailbox, so the SAME message can take
 * either scheme. The caller must encrypt the copy that goes on the wire and leave the plaintext it
 * holds for the park backstop alone — sealing an already-encrypted body to the identity key gives
 * the recipient bytes locked under a session key that is about to be destroyed.
 *
 * ─── Construction (SPARC Phase P) ──────────────────────────────────────────────────────────────
 *
 *   sealSessionContent(key, plaintext):
 *     1. iv       = random 12 bytes                              # NIST SP 800-38D §8.2.2
 *     2. ct||tag  = AES-256-GCM(key, iv, plaintext)              # NIST SP 800-38D
 *     3. blob     = VERSION(1) || iv(12) || ct || tag(16)
 *
 *   openSessionContent(key, blob) -> plaintext | null
 *
 * AES-256-GCM matches `content-seal.ts` rather than introducing a second AEAD, so there is one
 * primitive to reason about. RFCs: HKDF — RFC 5869 (upstream, in the key agreement); AES-GCM — NIST
 * SP 800-38D.
 *
 * ─── Why a RANDOM IV rather than a counter ─────────────────────────────────────────────────────
 *
 * A counter is the stronger construction and it needs state that survives a restart. This session
 * key does not: the secret is deliberately never persisted, and a revived session RE-KEYS
 * (Decisions Carried #5), so a counter would restart at zero under a NEW key — which is safe, and
 * would also have to be proven safe at every future change to the revival rule. A 96-bit random IV
 * under a key that lives for one session, with a birthday bound around 2^32 messages, is not the
 * limiting factor here and needs no state at all.
 *
 * ─── The VERSION byte, and why it is here on day one ───────────────────────────────────────────
 *
 * Adding a version to a wire format later is the change this whole line exists to avoid — the same
 * argument that put the PQ hook in the key agreement before there was anything to put in it. A
 * reader that meets a version it does not know REFUSES rather than guessing at the layout, because
 * guessing means feeding attacker-chosen bytes to a decryptor under the wrong framing.
 */

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

/** AES-256. */
const KEY_BYTES = 32;
/** GCM's standard nonce length (NIST SP 800-38D §8.2). */
const IV_BYTES = 12;
/** GCM tag. Full length, never truncated. */
const TAG_BYTES = 16;

/**
 * The only version this build writes, and the only one it reads.
 *
 * `0x01` rather than `0x00`: a zero first byte is what an all-zero buffer and a truncated read both
 * look like, so a version of zero cannot be told from an absent one.
 */
export const SESSION_CONTENT_SEAL_V1 = 0x01;

/** Bytes added to every message: version + IV + tag. */
export const SESSION_CONTENT_SEAL_OVERHEAD_BYTES = 1 + IV_BYTES + TAG_BYTES;

/**
 * Encrypt a message body under the agreed session key.
 *
 * Throws on a wrong-width key rather than deriving from whatever it was given: a short key silently
 * accepted is encryption that appears to work under something that is not the agreed secret.
 */
export function sealSessionContent(key: Uint8Array, plaintext: Uint8Array): Uint8Array {
  if (key.length !== KEY_BYTES) {
    throw new Error(
      `SESSION CONTENT SEAL: the session key must be ${KEY_BYTES} bytes, got ${key.length}. This is a ` +
      "LOCAL defect — the key comes from this side's own agreement, not from the peer. Refusing " +
      "rather than encrypting under something that is not the agreed secret.",
    );
  }
  const iv = new Uint8Array(randomBytes(IV_BYTES));
  const cipher = createCipheriv("aes-256-gcm", Buffer.from(key), Buffer.from(iv));
  const ct = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
  const tag = cipher.getAuthTag();
  return new Uint8Array(
    Buffer.concat([Buffer.from([SESSION_CONTENT_SEAL_V1]), Buffer.from(iv), ct, tag]),
  );
}

/**
 * Decrypt a message body under the agreed session key.
 *
 * **Returns `null` on every failure and never throws** — wrong key, tampered ciphertext, truncated
 * blob, unknown version. The caller cannot tell those apart and must not try: GCM's tag check is the
 * only thing that distinguishes "not for us" from "modified in flight", and a caller that branched
 * on the difference would be branching on attacker-controlled input.
 *
 * The caller's job on `null` is to refuse the message loudly, not to retry or to fall back to
 * reading it as plaintext.
 */
export function openSessionContent(key: Uint8Array, blob: Uint8Array): Uint8Array | null {
  if (key.length !== KEY_BYTES) return null;
  // A blob must have room for version + IV + tag, and one byte cannot be assumed present: an empty
  // frame would otherwise index past the end and read `undefined` as a version.
  if (blob.length < SESSION_CONTENT_SEAL_OVERHEAD_BYTES) return null;
  if (blob[0] !== SESSION_CONTENT_SEAL_V1) return null;

  const iv = blob.subarray(1, 1 + IV_BYTES);
  const ct = blob.subarray(1 + IV_BYTES, blob.length - TAG_BYTES);
  const tag = blob.subarray(blob.length - TAG_BYTES);
  try {
    const decipher = createDecipheriv("aes-256-gcm", Buffer.from(key), Buffer.from(iv));
    decipher.setAuthTag(Buffer.from(tag));
    return new Uint8Array(Buffer.concat([decipher.update(Buffer.from(ct)), decipher.final()]));
  } catch {
    return null;
  }
}
