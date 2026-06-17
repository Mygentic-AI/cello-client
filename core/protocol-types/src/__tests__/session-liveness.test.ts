/**
 * CELLO-M7-SESSION-003 — session-liveness wire codec tests
 *
 * AC understanding:
 *   - AC-002: the relay liveness frame carries session_id, counterparty_pubkey,
 *     liveness ('alive'|'gone'|'unknown'), observed_at. The client encodes the
 *     query and decodes the response; the relay (trustless-cello) re-implements
 *     the same wire shape in relay-frames.ts. The two MUST agree byte-for-byte,
 *     so the codec here pins the canonical wire shape: snake_case keys, binary
 *     session_id (16 bytes) and counterparty_pubkey (32 bytes), CBOR-encoded.
 *   - The codec is the producer (query) / consumer (response) on the client side.
 *
 * No external state — pure CBOR round-trip; no CELLO_E2E_LIVE guard needed.
 */
import { describe, it, expect } from "vitest";
import {
  encodeSessionLivenessQuery,
  decodeSessionLivenessQuery,
  encodeSessionLivenessResponse,
  decodeSessionLivenessResponse,
} from "../session-liveness.js";

const SID = new Uint8Array(16).fill(7);
const PUB = new Uint8Array(32).fill(9);

describe("session_liveness_query codec", () => {
  it("round-trips a query frame", () => {
    const bytes = encodeSessionLivenessQuery({
      type: "session_liveness_query",
      session_id: SID,
      counterparty_pubkey: PUB,
    });
    const decoded = decodeSessionLivenessQuery(bytes);
    expect(decoded).not.toBeNull();
    expect(decoded!.type).toBe("session_liveness_query");
    expect(Buffer.from(decoded!.session_id)).toEqual(Buffer.from(SID));
    expect(Buffer.from(decoded!.counterparty_pubkey)).toEqual(Buffer.from(PUB));
  });

  it("rejects a wrong-length session_id", () => {
    const bytes = encodeSessionLivenessQuery({
      type: "session_liveness_query",
      session_id: new Uint8Array(8),
      counterparty_pubkey: PUB,
    });
    expect(decodeSessionLivenessQuery(bytes)).toBeNull();
  });

  it("returns null on a frame of the wrong type", () => {
    const bytes = encodeSessionLivenessResponse({
      type: "session_liveness_response",
      session_id: SID,
      counterparty_pubkey: PUB,
      liveness: "alive",
      observed_at: 1,
    });
    expect(decodeSessionLivenessQuery(bytes)).toBeNull();
  });
});

describe("session_liveness_response codec", () => {
  for (const liveness of ["alive", "gone", "unknown"] as const) {
    it(`round-trips a response with liveness '${liveness}'`, () => {
      const bytes = encodeSessionLivenessResponse({
        type: "session_liveness_response",
        session_id: SID,
        counterparty_pubkey: PUB,
        liveness,
        observed_at: 1234,
      });
      const decoded = decodeSessionLivenessResponse(bytes);
      expect(decoded).not.toBeNull();
      expect(decoded!.liveness).toBe(liveness);
      expect(decoded!.observed_at).toBe(1234);
      expect(Buffer.from(decoded!.session_id)).toEqual(Buffer.from(SID));
      expect(Buffer.from(decoded!.counterparty_pubkey)).toEqual(Buffer.from(PUB));
    });
  }

  it("rejects an out-of-range liveness value (never fabricates)", () => {
    // Hand-craft a frame with an illegal liveness string.
    const bytes = encodeSessionLivenessResponse({
      type: "session_liveness_response",
      session_id: SID,
      counterparty_pubkey: PUB,
      // @ts-expect-error deliberately illegal value to prove the decoder validates
      liveness: "busy",
      observed_at: 1,
    });
    expect(decodeSessionLivenessResponse(bytes)).toBeNull();
  });
});
