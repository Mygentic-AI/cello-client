/**
 * THE CONTENT-HASH ALGORITHM IS NAMED ON THE WIRE — `DOD-M15-SEALWIRE-1` bullet 6, part B1.
 * Decisions Carried #9 (HMAC) and #15 (fall back loudly; refuse only an UNKNOWN algorithm).
 *
 * ─── The defect this closes, which pass-1 of the salt review surfaced and nobody had written down ─
 *
 * A salted content hash and an unsalted one are both **32 bytes in the same wire field**, with
 * nothing telling them apart. So a sender that salts, talking to a peer that does not, fails the
 * receive-path authenticity check on EVERY frame — and that check is the least debuggable shape this
 * system produces: the send succeeds, `parked: false`, the sender's log says the frame left, and the
 * receiver discards before anything about it is logged. `wire-content-hash.ts`'s own header says it
 * took two real daemons to find once, for exactly this reason.
 *
 * The salt-agreement fingerprint check cannot catch it either, because a peer on an older build
 * sends no fingerprint at all.
 *
 * ─── RECEIVER FIRST, and that is the whole shape of B1 ─────────────────────────────────────────
 *
 * This unit teaches the RECEIVER to read the name and verify under it. **No sender salts yet** —
 * part B2 flips that, with the bounded wait that keeps a session from splitting its transcript
 * halfway through. That order is deliberate and it is the only safe one for a wire change: every
 * peer must be able to UNDERSTAND a salted frame before any peer is able to SEND one. Reversed, the
 * first upgraded sender breaks every conversation it has with a peer that has not upgraded yet.
 *
 * So the assertions below are mostly about what the receiver does with a name it is given, and the
 * one that matters most is the refusal for a name it does not know.
 */

import { describe, it, expect } from "vitest";
import {
  CONTENT_HASH_ALGS,
  contentHashFor,
  isKnownContentHashAlg,
  resolveContentHashAlg,
} from "../wire-content-hash.js";
import { deriveSessionSalt, saltedContentHash, SALT_CONTRIBUTION_BYTES } from "@cello-protocol/crypto";

const CONTENT = new TextEncoder().encode("approved");
const SALT = deriveSessionSalt(
  new Uint8Array(SALT_CONTRIBUTION_BYTES).fill(0x11),
  new Uint8Array(SALT_CONTRIBUTION_BYTES).fill(0x22),
);
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

describe("the two algorithms produce different bytes for the same message", () => {
  it("★ salted and unsalted differ — which is the whole reason the name has to travel", () => {
    const plain = contentHashFor(CONTENT, { alg: CONTENT_HASH_ALGS.SHA256, salt: null });
    const salted = contentHashFor(CONTENT, { alg: CONTENT_HASH_ALGS.HMAC_SALT_V1, salt: SALT });
    expect(hex(plain)).not.toBe(hex(salted));
    // Same width, same field, no discriminator in the bytes themselves. A receiver handed one of
    // these and told nothing has no way to tell which it is holding.
    expect(plain.length).toBe(32);
    expect(salted.length).toBe(32);
  });

  it("★ the salted form is HMAC, not SHA-256(salt ‖ content) — Decision #9", () => {
    /**
     * Byte-pinned against the primitive rather than against a re-implementation here. The naive
     * concatenation has a length-extension weakness: an attacker holding `H(salt ‖ m)` and knowing
     * `|salt|` can compute `H(salt ‖ m ‖ pad ‖ m')` without the salt.
     */
    expect(hex(contentHashFor(CONTENT, { alg: CONTENT_HASH_ALGS.HMAC_SALT_V1, salt: SALT })))
      .toBe(hex(saltedContentHash(SALT, CONTENT)));
  });

  it("★ the unsalted form is unchanged, byte for byte — every session in flight depends on it", () => {
    /**
     * The compatibility assertion. `sha256(0x00 ‖ content)` is what every peer on every current
     * build computes; changing it by a byte would break every conversation at once, and the failure
     * would be the silent-discard shape again.
     */
    const expected = Buffer.from(
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      require("node:crypto").createHash("sha256").update(new Uint8Array([0x00])).update(CONTENT).digest(),
    ).toString("hex");
    expect(hex(contentHashFor(CONTENT, { alg: CONTENT_HASH_ALGS.SHA256, salt: null }))).toBe(expected);
  });
});

describe("a name we do not know is REFUSED, never guessed at", () => {
  it("★ an unknown algorithm is not a legacy peer — it is an unreadable one", () => {
    /**
     * Decision #15 draws this line explicitly. ABSENT means legacy: a peer that predates the field,
     * and we know exactly what it computed. NAMED-AND-KNOWN means verify under that name.
     * NAMED-AND-UNKNOWN means a peer built something we cannot reproduce, and there is no correct
     * hash to compare against — falling back to unsalted there would compare two unrelated values
     * and report a tamper.
     */
    expect(isKnownContentHashAlg("hmac-sha512-salt-v9")).toBe(false);
    expect(isKnownContentHashAlg(CONTENT_HASH_ALGS.SHA256)).toBe(true);
    expect(isKnownContentHashAlg(CONTENT_HASH_ALGS.HMAC_SALT_V1)).toBe(true);
  });

  it("★ computing under an unknown algorithm THROWS rather than returning something plausible", () => {
    // A 32-byte value returned here would flow into the cross-check and surface as
    // `content_hash_mismatch` — a tamper report for a version skew.
    expect(() => contentHashFor(CONTENT, { alg: "hmac-sha512-salt-v9", salt: SALT })).toThrow(/unknown/i);
  });

  it("★ asking for the salted algorithm with NO salt throws — it cannot be quietly downgraded", () => {
    /**
     * The silent fallback this refuses: computing an unsalted hash because the salt is missing. The
     * caller would then send a frame LABELLED salted whose bytes are not, and the peer would report
     * a tamper on a message nobody touched.
     */
    expect(() => contentHashFor(CONTENT, { alg: CONTENT_HASH_ALGS.HMAC_SALT_V1, salt: null }))
      .toThrow(/salt/i);
  });
});

describe("resolving what a frame says it used", () => {
  it("★ an ABSENT field means the legacy algorithm — a peer that predates the field", () => {
    expect(resolveContentHashAlg(undefined)).toEqual({ ok: true, alg: CONTENT_HASH_ALGS.SHA256 });
    expect(resolveContentHashAlg(null)).toEqual({ ok: true, alg: CONTENT_HASH_ALGS.SHA256 });
  });

  it("★ a NAMED known algorithm resolves to itself", () => {
    expect(resolveContentHashAlg(CONTENT_HASH_ALGS.HMAC_SALT_V1))
      .toEqual({ ok: true, alg: CONTENT_HASH_ALGS.HMAC_SALT_V1 });
  });

  it("★ a NAMED unknown algorithm is refused, and the refusal names the value", () => {
    const r = resolveContentHashAlg("hmac-sha512-salt-v9");
    expect(r.ok).toBe(false);
    // The operator has to be able to tell a version skew from a tamper, and the only thing that
    // distinguishes them is this string.
    expect(r.ok === false && r.value).toBe("hmac-sha512-salt-v9");
  });

  it("★ a non-string in the field is refused, not coerced", () => {
    // CBOR carries whatever the peer encoded. A number here must not become "42" and then miss the
    // known-name check for a reason that reads like a typo.
    expect(resolveContentHashAlg(42 as unknown as string).ok).toBe(false);
    expect(resolveContentHashAlg({} as unknown as string).ok).toBe(false);
  });

  it("★ the EMPTY STRING is refused rather than treated as absent", () => {
    /**
     * The gap a truthiness check leaves. `if (!alg) return SHA256` would fold `""` into "legacy",
     * so a peer that sends an empty name — a serialisation bug on their side, or a deliberate probe
     * — would be silently verified as unsalted instead of being told its frame is unreadable.
     */
    expect(resolveContentHashAlg("").ok).toBe(false);
  });
});
