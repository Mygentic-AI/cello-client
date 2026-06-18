export type PublicKey = Uint8Array; // 32-byte Ed25519 public key
export type Signature = Uint8Array; // 64-byte Ed25519 signature

export interface KeyProvider {
  getPublicKey(): Promise<PublicKey>;
  sign(data: Uint8Array): Promise<Signature>;
  /**
   * CELLO-M7-MSG-001: open a content-park sealed blob addressed to THIS identity key
   * (the receiver-side counterpart of `sealToRecipient`). Returns the plaintext, or
   * null on any failure (wrong key / tamper / malformed). OPTIONAL — only providers
   * that hold the Ed25519 seed (InMemory/File identity keys) implement it; threshold
   * and signing-only providers do not. Callers must feature-detect before use.
   */
  openContentSeal?(blob: Uint8Array): Promise<Uint8Array | null>;
}

export interface KeyFileCorruptError {
  reason: "key_file_corrupt";
  message: string;
}
