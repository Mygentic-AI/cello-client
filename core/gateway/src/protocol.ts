/**
 * The daemon ↔ gateway wire protocol.
 *
 * Framing: a 4-byte big-endian length prefix followed by a UTF-8 JSON payload. Content bytes
 * ride as base64 inside the JSON (binary-safe over a text protocol). This is the local-sidecar
 * transport (Unix domain socket); Phase 2 swaps the socket for mTLS but keeps these message
 * shapes, so the remote gateway is a transport change, not a protocol change.
 */
import type { ScreenDirection, ScreenDisposition, GovernanceEvent } from "./types.js";

export const SCREEN_OUTBOUND = "screen_outbound";
export const SCREEN_INBOUND = "screen_inbound";
export type ScreenMethod = typeof SCREEN_OUTBOUND | typeof SCREEN_INBOUND;

/** A screen request on the wire. `content` is base64. */
export interface WireScreenRequest {
  id: number;
  method: ScreenMethod;
  content: string;
  ctx: {
    direction: ScreenDirection;
    agentName: string;
    sessionId: string;
    correlationId?: string;
  };
}

/** A screen response on the wire. `content` is base64, present ONLY when the gateway transformed it. */
export interface WireScreenResponse {
  id: number;
  verdict: {
    disposition: ScreenDisposition;
    content?: string;
    reason?: string;
    guidance?: string;
    /** Governance findings — plain JSON, carried verbatim (M9-FEED-001 renders them). */
    events?: GovernanceEvent[];
  };
}

const LENGTH_PREFIX_BYTES = 4;
// A hard ceiling on a single frame so a malformed/hostile length prefix cannot make the reader
// buffer unboundedly. 8 MiB comfortably exceeds the 1 MB content cap plus base64 overhead + JSON.
const MAX_FRAME_BYTES = 8 * 1024 * 1024;

/** Encode an object as a length-prefixed JSON frame. */
export function encodeFrame(obj: unknown): Buffer {
  const json = Buffer.from(JSON.stringify(obj), "utf8");
  const frame = Buffer.allocUnsafe(LENGTH_PREFIX_BYTES + json.length);
  frame.writeUInt32BE(json.length, 0);
  json.copy(frame, LENGTH_PREFIX_BYTES);
  return frame;
}

/**
 * A stateful decoder for length-prefixed JSON frames arriving as arbitrary socket chunks.
 * Feed it each chunk; it invokes `onFrame` for every complete frame. `onError` fires on a
 * frame that exceeds MAX_FRAME_BYTES or fails to parse — the caller should drop the connection.
 */
export class FrameDecoder {
  #buffer: Buffer = Buffer.alloc(0);
  readonly #onFrame: (obj: unknown) => void;
  readonly #onError: (err: Error) => void;

  constructor(onFrame: (obj: unknown) => void, onError: (err: Error) => void) {
    this.#onFrame = onFrame;
    this.#onError = onError;
  }

  push(chunk: Buffer): void {
    this.#buffer = this.#buffer.length === 0 ? chunk : Buffer.concat([this.#buffer, chunk]);
    for (;;) {
      if (this.#buffer.length < LENGTH_PREFIX_BYTES) return;
      const len = this.#buffer.readUInt32BE(0);
      if (len > MAX_FRAME_BYTES) {
        this.#onError(new Error(`frame length ${len} exceeds max ${MAX_FRAME_BYTES}`));
        return;
      }
      if (this.#buffer.length < LENGTH_PREFIX_BYTES + len) return;
      const payload = this.#buffer.subarray(LENGTH_PREFIX_BYTES, LENGTH_PREFIX_BYTES + len);
      this.#buffer = this.#buffer.subarray(LENGTH_PREFIX_BYTES + len);
      try {
        this.#onFrame(JSON.parse(payload.toString("utf8")));
      } catch (err) {
        this.#onError(err instanceof Error ? err : new Error(String(err)));
        return;
      }
    }
  }
}
