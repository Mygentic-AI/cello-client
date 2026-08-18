/**
 * CELLO-M7-MSG-001 — transport content-size cap (AC-014, SI-003).
 *
 * The application content cap (MAX_CONTENT_BYTES = 1 MB) is enforced explicitly
 * BEFORE the bare it-length-prefixed 4 MB transport default can fire, so oversize
 * content is rejected with a distinct content_too_large outcome instead of a
 * silent decode failure → desync.
 */

import { describe, it, expect } from "vitest";
import * as lp from "it-length-prefixed";
import { MAX_CONTENT_BYTES } from "@cello-protocol/protocol-types";
import { readCappedContentFrame } from "../content-cap.js";

/** Build an async-iterable source carrying one length-prefixed frame. */
function lpSource(payload: Uint8Array): AsyncIterable<unknown> {
  // Raise the encode-side cap so the test can build oversize frames; the
  // decode-side cap is what readCappedContentFrame is asserting.
  const encoded = lp.encode.single(payload, { maxDataLength: 16 * 1024 * 1024 });
  return (async function* () {
    yield encoded;
  })();
}

describe("readCappedContentFrame (MSG-001 transport cap)", () => {
  it("returns the payload for a frame within the cap", async () => {
    const payload = new Uint8Array([1, 2, 3, 4]);
    const res = await readCappedContentFrame(lpSource(payload) as never);
    expect(res.ok).toBe(true);
    if (res.ok) expect(Buffer.from(res.payload).equals(Buffer.from(payload))).toBe(true);
  });

  it("returns the payload for a frame exactly at the cap", async () => {
    const payload = new Uint8Array(MAX_CONTENT_BYTES).fill(7);
    const res = await readCappedContentFrame(lpSource(payload) as never);
    expect(res.ok).toBe(true);
    if (res.ok) expect(res.payload.length).toBe(MAX_CONTENT_BYTES);
  });

  it("rejects a frame between the 1 MB app cap and the 4 MB transport default as content_too_large (SI-003)", async () => {
    const payload = new Uint8Array(MAX_CONTENT_BYTES + 1).fill(9); // 1 byte over
    const res = await readCappedContentFrame(lpSource(payload) as never);
    expect(res.ok).toBe(false);
    // NARROW on the reason before reading its fields. `size` and `cap` exist only on the
    // `content_too_large` variant, so reading them off the union was asserting on properties the
    // other two refusals do not have — it would have read `undefined` and still passed if the
    // implementation ever returned `empty` or `decode_error` here.
    if (!res.ok && res.reason === "content_too_large") {
      expect(res.size).toBe(MAX_CONTENT_BYTES + 1);
      expect(res.cap).toBe(MAX_CONTENT_BYTES);
    } else {
      expect.unreachable(`expected a content_too_large refusal, got ${JSON.stringify(res)}`);
    }
  });

  it("rejects a frame larger than the 4 MB transport default as content_too_large (no silent failure)", async () => {
    const payload = new Uint8Array(5 * 1024 * 1024).fill(3); // > 4 MB
    const res = await readCappedContentFrame(lpSource(payload) as never);
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("content_too_large");
  });

  it("reports an empty stream distinctly (not content_too_large)", async () => {
    const empty: AsyncIterable<unknown> = (async function* () {})();
    const res = await readCappedContentFrame(empty as never);
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("empty");
  });
});
