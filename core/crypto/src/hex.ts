/**
 * Shared hex decoding for @cello-protocol/crypto. Single source so callers (manifest verification,
 * AE peer-auth) cannot diverge on validation strictness.
 */

/**
 * Decode an exact-length lowercase-or-uppercase hex string to bytes. Returns null on ANY
 * malformation — wrong length, or a non-hex character (e.g. `parseInt("0g", 16)` would yield a
 * partial value, so a strict regex check precedes decoding). Never throws.
 *
 * @param hex the hex string
 * @param expectedBytes required byte length (the string must be exactly 2× this)
 */
export function hexToBytes(hex: string, expectedBytes: number): Uint8Array | null {
  if (hex.length !== expectedBytes * 2 || !/^[0-9a-fA-F]+$/.test(hex)) return null;
  const out = new Uint8Array(expectedBytes);
  for (let i = 0; i < expectedBytes; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
