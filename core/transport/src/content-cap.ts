/**
 * CELLO-M7-MSG-001 — transport content-size cap.
 *
 * Reads the first length-prefixed frame from a content stream and enforces the
 * application content cap (MAX_CONTENT_BYTES = 1 MB) EXPLICITLY, before the bare
 * it-length-prefixed transport default (4 MB) can fire. Oversize content yields a
 * distinct `content_too_large` outcome — never a silent decode failure that the
 * caller mistakes for a desync (AC-014, SI-003).
 *
 * Pseudocode (SPARC Phase P):
 *   readCappedContentFrame(source, cap):
 *     decode with maxDataLength = transport default (4 MB) so 1–4 MB frames are
 *       observable and we can report their exact size
 *     for first frame:
 *       payload = bytes
 *       if payload.length > cap → { ok:false, content_too_large, size, cap }
 *       else → { ok:true, payload }
 *     no frame → { ok:false, empty }
 *     decode throw (e.g. > 4 MB transport max) → { ok:false, content_too_large }
 */

import * as lp from "it-length-prefixed";
import { MAX_CONTENT_BYTES, IT_LENGTH_PREFIX_DEFAULT_MAX } from "@cello-protocol/protocol-types";

export type CappedFrameResult =
  | { ok: true; payload: Uint8Array }
  | { ok: false; reason: "content_too_large"; size?: number; cap: number; message?: string }
  | { ok: false; reason: "empty" }
  | { ok: false; reason: "decode_error"; message: string };

function toU8(chunk: unknown): Uint8Array {
  if (chunk instanceof Uint8Array) return chunk;
  // Uint8ArrayList from it-length-prefixed exposes subarray()
  const c = chunk as { subarray?: () => Uint8Array };
  if (typeof c?.subarray === "function") return c.subarray();
  return new Uint8Array(chunk as ArrayBufferLike);
}

/**
 * Read and length-cap the first content frame off a length-prefixed source.
 * `cap` defaults to the 1 MB application message cap.
 */
export async function readCappedContentFrame(
  source: AsyncIterable<Uint8Array>,
  cap: number = MAX_CONTENT_BYTES,
): Promise<CappedFrameResult> {
  try {
    for await (const chunk of lp.decode(source, { maxDataLength: IT_LENGTH_PREFIX_DEFAULT_MAX })) {
      const payload = toU8(chunk as unknown);
      if (payload.length > cap) {
        return { ok: false, reason: "content_too_large", size: payload.length, cap };
      }
      return { ok: true, payload };
    }
    return { ok: false, reason: "empty" };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    // A frame larger than the it-length-prefixed transport default trips the
    // decoder's max-length guard. Surface it as content_too_large (never a silent
    // failure, never a desync) rather than an opaque decode error.
    if (/max|length|too long|data length/i.test(message)) {
      return { ok: false, reason: "content_too_large", cap, message };
    }
    return { ok: false, reason: "decode_error", message };
  }
}
