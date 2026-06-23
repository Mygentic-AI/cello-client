/**
 * DOD-LOG-1 (PERSIST-LOG-001) — at-rest encryption for the durable transcript store.
 *
 * The daemon uses plain node:sqlite (no whole-DB encryption — SQLCipher is a native dep that
 * compiles from source and is intentionally not dragged into the daemon). So the readable
 * transcript plaintext is envelope-encrypted at the column level before it touches disk: each
 * message blob is AES-256-GCM sealed with a dedicated per-DB transcript key.
 *
 * Key separation by design: the agent's Ed25519 identity key SIGNS (the KeyProvider interface is
 * sign-only and never exposes the seed — good hygiene); a SEPARATE 32-byte symmetric key encrypts
 * the transcript at rest. The key lives in a 0600 file beside the daemon DB and is generated once.
 *
 * Blob layout: iv(12) || ciphertext || authTag(16). GCM authenticates, so a tampered or truncated
 * blob fails to decrypt (returns null) rather than yielding garbage plaintext.
 */

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

const KEY_LEN = 32; // AES-256
const IV_LEN = 12; // GCM standard nonce
const TAG_LEN = 16;

export class TranscriptCipher {
  readonly #key: Buffer;

  private constructor(key: Buffer) {
    this.#key = key;
  }

  /**
   * Load the transcript key from `keyPath`, or generate + persist a fresh one (0600) on first use.
   * Atomic-ish create: write then the file is the durable key for this DB for all time.
   */
  static loadOrCreate(keyPath: string): TranscriptCipher {
    if (existsSync(keyPath)) {
      const key = readFileSync(keyPath);
      if (key.length !== KEY_LEN) {
        throw new Error(`transcript key at ${keyPath} is ${key.length} bytes, expected ${KEY_LEN}`);
      }
      return new TranscriptCipher(key);
    }
    const key = randomBytes(KEY_LEN);
    mkdirSync(dirname(keyPath), { recursive: true });
    writeFileSync(keyPath, key, { mode: 0o600 });
    return new TranscriptCipher(key);
  }

  /** For tests: an in-memory cipher with a supplied (or random) key. */
  static fromKey(key?: Buffer): TranscriptCipher {
    return new TranscriptCipher(key ?? randomBytes(KEY_LEN));
  }

  /** Encrypt plaintext → iv || ciphertext || tag. */
  encrypt(plaintext: Uint8Array): Uint8Array {
    const iv = randomBytes(IV_LEN);
    const cipher = createCipheriv("aes-256-gcm", this.#key, iv);
    const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, ct, tag]);
  }

  /** Decrypt an iv||ciphertext||tag blob. Returns null on any tamper / wrong key / malformed input. */
  decrypt(blob: Uint8Array): Uint8Array | null {
    if (blob.length < IV_LEN + TAG_LEN) return null;
    const buf = Buffer.from(blob);
    const iv = buf.subarray(0, IV_LEN);
    const tag = buf.subarray(buf.length - TAG_LEN);
    const ct = buf.subarray(IV_LEN, buf.length - TAG_LEN);
    try {
      const decipher = createDecipheriv("aes-256-gcm", this.#key, iv);
      decipher.setAuthTag(tag);
      return Uint8Array.from(Buffer.concat([decipher.update(ct), decipher.final()]));
    } catch {
      return null;
    }
  }
}
