/**
 * The CBOR encoder. Singular — import it, never construct another.
 *
 * `no-multiple-cbor-encoders.test.ts` fails the build if any production file builds its own Encoder
 * or imports cbor-x's bare `encode`. A second encoder is a second wire format written into the same
 * columns and frames, and it takes a data migration to undo.
 *
 * Two settings, both load-bearing:
 *
 * `tagUint8Array: false` — byte fields encode as CBOR byte strings (major type 2), not cbor-x's
 * tag-64 typed arrays. This is what the directory and the relay decode.
 *
 * `useRecords: false` — objects encode as CBOR maps. cbor-x defaults this ON, which emits its own
 * tag 57343 instead of a map: a private format that no other CBOR reader can parse. Signed TBS
 * payloads are all ARRAYS and encode identically either way, so signatures do not depend on this;
 * what depends on it is whether a non-cbor-x implementation can read our wire and our seals.
 *
 * Decoding uses cbor-x's `decode`, which reads byte strings, tag-64, and records alike. That
 * tolerance is for data that predates this module — it is not a licence to write a second format.
 */
import { Encoder, decode } from "cbor-x";

const ENCODER = new Encoder({ tagUint8Array: false, useRecords: false });

/** Encode to canonical CBOR: byte strings for bytes, maps for objects. Plain RFC 8949. */
export function encodeCbor(value: unknown): Uint8Array {
  return ENCODER.encode(value) as Uint8Array;
}

/** Decode CBOR. Tolerates the older tag-64 and record encodings so pre-migration data still reads. */
export function decodeCbor(bytes: Uint8Array): unknown {
  return decode(bytes);
}
