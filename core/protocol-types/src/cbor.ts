/**
 * The CBOR encoder. Singular, deliberately.
 *
 * `tagUint8Array: false` makes byte fields encode as raw CBOR byte strings (major type 2) rather
 * than cbor-x's default tag-64 typed arrays. That is not a preference — it is the wire format the
 * DIRECTORY decodes, and the relay with it. An encoder configured any other way produces frames a
 * strict CBOR reader sees as a different shape.
 *
 * WHY THIS MODULE EXISTS: this same `new Encoder({ tagUint8Array: false })` had been re-declared in
 * fourteen files, and two files skipped it entirely and used cbor-x's bare `encode`. Those two wrote
 * TAG-64 blobs into the SAME database columns (frost_commitments, frost_verifying_shares) that the
 * others wrote as raw byte strings — so an agent's persisted share blobs silently changed format the
 * first time it ran `cello_refresh_shares`. It "worked" only because cbor-x's own decoder happens to
 * accept both. Any reader that is not cbor-x — a Rust or Go client, an auditor verifying a seal
 * independently — sees one column with two encodings and no way to know which it will get.
 *
 * So: ONE encoder, imported. Do not construct another, and do not import `encode` from cbor-x
 * directly. `no-multiple-cbor-encoders.test.ts` fails the build if you do — deliberately, because a
 * second encoding is not a style question, it is a corrupt column that takes a migration to undo.
 *
 * Decoding stays cbor-x's `decode`, which reads both encodings. That tolerance is what let the
 * divergence hide; it is retained ONLY so already-migrated and in-flight data keeps decoding. It is
 * not a licence to write a second format.
 */
import { Encoder, decode } from "cbor-x";

const ENCODER = new Encoder({ tagUint8Array: false });

/** Encode to canonical CBOR (byte fields as raw byte strings, never tag-64). */
export function encodeCbor(value: unknown): Uint8Array {
  return ENCODER.encode(value) as Uint8Array;
}

/** Decode CBOR. Tolerates tag-64 (pre-migration and in-flight data) as well as raw byte strings. */
export function decodeCbor(bytes: Uint8Array): unknown {
  return decode(bytes);
}
