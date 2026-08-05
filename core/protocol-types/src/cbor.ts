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

/**
 * `setSizeLimits` EXISTS at runtime in cbor-x 1.6.4 and is absent from the shipped `.d.ts`.
 * Verified, not assumed: `Object.keys(require("cbor-x"))` includes it.
 *
 * Declared here rather than cast away, so the call below is type-checked against the shape we
 * actually rely on. If a future cbor-x removes the function, this declaration keeps compiling and
 * the call becomes a no-op — which is why the limits have their own test rather than resting on the
 * import succeeding.
 */
declare module "cbor-x" {
  export function setSizeLimits(limits: {
    maxArraySize?: number;
    maxMapSize?: number;
    maxObjectSize?: number;
  }): void;
}
import { setSizeLimits } from "cbor-x";

/**
 * DECODER SIZE LIMITS — a security boundary, not a tuning knob.
 *
 * Without them, a few bytes of hostile CBOR cost seconds and gigabytes. MEASURED on this decoder:
 * `9f b0` (indefinite-length array header, then a map header, no data) took **5.0 s**; `a1 9f` —
 * THREE bytes, a one-pair map whose first key is an indefinite array — took **9.6 s and 1.1 GB**;
 * `9f 26` was independently measured at 10 s / 1.6 GB. Any code path that hands peer-controlled
 * bytes to `decodeCbor` is therefore a denial of service, and every decoder in this package is on
 * one: the daemon's session content path, the directory's `seal_submission`, the relay.
 *
 * A CALLER-SIDE GUARD CANNOT FIX THIS, and one was tried. Inspecting the header byte is sound about
 * the outermost container and says nothing about what is nested inside it — a valid map header
 * followed by an indefinite array is admitted by any header check, including one requiring the real
 * frames' own `b9 000a` prefix. The bound has to be on the decoder.
 *
 * 65,536 is chosen against BOTH failure directions, measured. Above: worst hostile decode drops to
 * 5 ms from 9,600 ms. Below: it must never refuse a legitimate structure, and the largest one CELLO
 * builds is a seal's `leaves` array on a long-running session — 60,000 leaves decodes in 8 ms and is
 * admitted, which is far beyond any real session. Byte strings are NOT counted against these limits,
 * so a 1 MB Yjs update is unaffected (measured: 0 ms).
 *
 * Process-global to cbor-x, which is the right blast radius: the decode functions are public API of
 * this package, so a limit attached to one caller would leave every other caller unguarded.
 */
setSizeLimits({ maxArraySize: 65536, maxMapSize: 65536, maxObjectSize: 65536 });

const ENCODER = new Encoder({ tagUint8Array: false, useRecords: false });

/**
 * Encode to CBOR: byte strings for bytes, maps for objects. Valid RFC 8949.
 *
 * NOT RFC 8949 §4.2 deterministic FOR MAPS, and anything hashed or signed must account for that.
 * Measured (M10 / DOD-CBOR-1, journal Entry 4):
 *
 *   encode({b:1, a:2})  ->  b9 0002 6162 01 6161 02
 *   encode({a:2, b:1})  ->  b9 0002 6161 02 6162 01     <- different bytes, same object
 *
 * Two departures from Core Deterministic Encoding, both map-only: keys follow INSERTION ORDER
 * rather than bytewise sort, and the map header is not minimal-length (`b9 0002` for a 2-entry map
 * where CDE requires `a2`).
 *
 * ARRAYS, text strings, byte strings, integers and null ARE minimal and order-fixed. That is why
 * every to-be-signed structure in CELLO is an ARRAY with a domain tag in slot 0 —
 * buildAgentRevocationTbs, buildPrimaryTransferTbs, buildSealTbs, buildParkContentTbs,
 * encodeTrustSignalEnvelope. Two parties encoding the same array always produce the same bytes;
 * two parties encoding the same MAP do not, if they built it in a different field order.
 *
 * So: never hash or sign a CBOR map produced by this encoder. Put the fields in a fixed-order array.
 */
export function encodeCbor(value: unknown): Uint8Array {
  return ENCODER.encode(value) as Uint8Array;
}

/** Decode CBOR. Tolerates the older tag-64 and record encodings so pre-migration data still reads. */
export function decodeCbor(bytes: Uint8Array): unknown {
  return decode(bytes);
}
