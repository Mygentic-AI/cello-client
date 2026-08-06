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
 * ── WHY 250,000 AND NOT SOMETHING TIGHTER ─────────────────────────────────────────────────────
 *
 * The bound is set by the LARGEST LEGITIMATE STRUCTURE, not by the attack. `ae-channel.ts` in
 * trustless-cello declares `MAX_WIRE_ITEMS = 250_000` as the anti-hostile-peer bound for
 * directory-to-directory replication, and it decodes BEFORE applying it — so a tighter global cap
 * here silently supersedes it. A first attempt at 65,536 did exactly that: at 65,537 rows in any
 * replicated table (`agent_profiles`, `conversation_seals`, `seal_notarizations`, …, none of which
 * the AE store paginates) replication would have stopped permanently and been reported as a PEER
 * protocol violation. That is the same shape of failure this repo already ate on 2026-08-01.
 *
 * Refusing real data is the worse direction. A slow decode is a nuisance; a directory that cannot
 * replicate, blaming its peer, is an outage nobody can diagnose from the message.
 *
 * The limit is EXCLUSIVE — cbor-x throws "Array length exceeds N" at exactly N, not above it — so a
 * cap of 250,000 would refuse a frame carrying exactly `MAX_WIRE_ITEMS`, which is the boundary the
 * AE channel is most likely to sit on because that is its own declared maximum. 262,144 (2^18) is
 * the next round number clear of it, and the margin is the point rather than the roundness.
 *
 * Measured: a legitimate 250,000-element frame decodes in ~30 ms; the three-byte hostile inputs
 * above are 3–4 ms; byte strings are not counted at all, so a 1 MB Yjs update is unaffected.
 *
 * ── WHAT THIS DOES *NOT* CLOSE ────────────────────────────────────────────────────────────────
 *
 * A size limit is not a completeness argument, and saying otherwise was the previous version of
 * this comment. cbor-x pre-allocates `new Array(declaredCount)` BEFORE reading any element, so
 * NESTED definite-length arrays each sitting just under the cap still allocate: measured, 15 KB of
 * such input costs ~230 ms and ~2.3 GB before V8's stack depth stops it. The missing invariant is
 * "a container cannot declare more elements than there are bytes left to fill it", which cbor-x
 * does not enforce and this cannot express.
 *
 * So every caller that hands PEER-CONTROLLED bytes to `decodeCbor` must also bound the INPUT
 * LENGTH — that is what makes the nesting depth finite. This limit reduces the per-byte
 * amplification by roughly 43,000×; the input cap is what closes the class.
 *
 * Process-global to cbor-x, which is the right blast radius for the part it does cover: the decode
 * functions are public API of this package, so a limit attached to one caller would leave every
 * other caller unguarded. `maxObjectSize` is passed for symmetry and is inert — cbor-x 1.6.4
 * accepts it and never reads it; plain-object key counts are bounded by `maxMapSize`.
 */
setSizeLimits({ maxArraySize: 262_144, maxMapSize: 262_144, maxObjectSize: 262_144 });

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
