/**
 * M9D 003-PQSESSION — the session content key is hybrid (D9), tests 1–3.
 *
 * The content key mixes an ML-KEM-768 shared secret into the X25519 agreement, and binds the KEM's
 * public material (`ct ‖ encapsulatee_mlkem_public`) into the HKDF info (Contract 4). Both inputs are
 * mandatory: an optional PQ input is a downgrade path.
 */
import { describe, it, expect } from "vitest";
import { createHmac } from "node:crypto";
import { x25519 } from "@noble/curves/ed25519.js";
import { deriveSessionSecrets } from "../session-key-agreement.js";
import {
  mlKemGenerateSeed,
  mlKemKeypairFromSeed,
  mlKemEncapsulate,
  mlKemDecapsulate,
  ML_KEM_CIPHERTEXT_BYTES,
  ML_KEM_PUBLIC_KEY_BYTES,
} from "../ml-kem.js";

const SID = new Uint8Array(16).fill(0x42);
const SK_A = new Uint8Array(32).fill(0x11);
const SK_B = new Uint8Array(32).fill(0x22);
const SS_PQ = new Uint8Array(32).fill(0x33);
const TRANSCRIPT = new Uint8Array(ML_KEM_CIPHERTEXT_BYTES + ML_KEM_PUBLIC_KEY_BYTES).map((_, i) => i & 0xff);

/**
 * Pinned once, computed by `independentContentKey` below over ikm = x25519(SK_A, pub(SK_B)) ‖ SS_PQ,
 * salt = SID, info = utf8("cello/session/v1/content-key") ‖ lower public ‖ higher public ‖
 * TRANSCRIPT, 32 bytes.
 *
 * The HKDF is RFC 5869 written out over `node:crypto` HMAC-SHA256 (OpenSSL), not the `@noble/hashes`
 * HKDF the module uses. `node:crypto.hkdfSync` itself cannot be used: it refuses an `info` longer than
 * 1,024 bytes, and this one is 2,364.
 */
const KAT_CONTENT_KEY_HEX = "f0a69613b3006e765361adc96aaccee811135cf39c71ad9903c62204350f6193";

function lexLess(a: Uint8Array, b: Uint8Array): boolean {
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return (a[i] as number) < (b[i] as number);
  return a.length < b.length;
}

/** RFC 5869 extract-then-expand over node:crypto HMAC-SHA256. */
function rfc5869(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Buffer {
  const prk = createHmac("sha256", salt).update(ikm).digest();
  let block = Buffer.alloc(0);
  let out = Buffer.alloc(0);
  for (let i = 1; out.length < length; i++) {
    block = createHmac("sha256", prk).update(Buffer.concat([block, info, Buffer.from([i])])).digest();
    out = Buffer.concat([out, block]);
  }
  return out.subarray(0, length);
}

function independentContentKey(): string {
  const pubA = x25519.getPublicKey(SK_A);
  const pubB = x25519.getPublicKey(SK_B);
  const shared = x25519.getSharedSecret(SK_A, pubB);
  const [first, second] = lexLess(pubA, pubB) ? [pubA, pubB] : [pubB, pubA];
  const ikm = Buffer.concat([shared, SS_PQ]);
  const info = Buffer.concat([Buffer.from("cello/session/v1/content-key", "utf8"), first, second, TRANSCRIPT]);
  return rfc5869(ikm, SID, info, 32).toString("hex");
}

describe("003 test 1 — the combiner KAT, computed independently", () => {
  it("the code's content key equals an independent RFC 5869 HKDF over the Contract 4 inputs", () => {
    const { contentKey } = deriveSessionSecrets({
      ownEphemeralSecret: SK_A,
      peerEphemeralPublic: x25519.getPublicKey(SK_B),
      sessionId: SID,
      extraSharedSecret: SS_PQ,
      pqTranscript: TRANSCRIPT,
    });
    const independent = independentContentKey();
    expect(Buffer.from(contentKey).toString("hex")).toBe(independent);
    expect(independent).toBe(KAT_CONTENT_KEY_HEX);
  });
});

describe("003 test 2 — both PQ inputs are mandatory and fixed-width", () => {
  const base = { ownEphemeralSecret: SK_A, peerEphemeralPublic: x25519.getPublicKey(SK_B), sessionId: SID };
  const cases: Array<[string, Record<string, unknown>]> = [
    ["extraSharedSecret omitted", { pqTranscript: TRANSCRIPT }],
    ["pqTranscript omitted", { extraSharedSecret: SS_PQ }],
    ["extraSharedSecret 31 bytes", { extraSharedSecret: new Uint8Array(31), pqTranscript: TRANSCRIPT }],
    ["pqTranscript 2,271 bytes", { extraSharedSecret: SS_PQ, pqTranscript: new Uint8Array(2271) }],
  ];
  for (const [name, extra] of cases) {
    it(`${name} throws`, () => {
      expect(() => deriveSessionSecrets({ ...base, ...extra } as never)).toThrow(/KEYAGREE/);
    });
  }
});

describe("003 test 3 — a swapped ciphertext breaks agreement", () => {
  it("the decapsulator deriving from ct' (one byte flipped) gets a different key", async () => {
    const seedB = mlKemGenerateSeed();
    const { publicKey: mlkemPubB } = await mlKemKeypairFromSeed(seedB);
    const { ciphertext, sharedSecret } = await mlKemEncapsulate(mlkemPubB);
    const flipped = Uint8Array.from(ciphertext);
    flipped[0] = (flipped[0] as number) ^ 0x01;
    const ssB = await mlKemDecapsulate(seedB, flipped);

    const encapsulator = deriveSessionSecrets({
      ownEphemeralSecret: SK_A, peerEphemeralPublic: x25519.getPublicKey(SK_B), sessionId: SID,
      extraSharedSecret: sharedSecret, pqTranscript: Buffer.concat([ciphertext, mlkemPubB]),
    });
    const decapsulator = deriveSessionSecrets({
      ownEphemeralSecret: SK_B, peerEphemeralPublic: x25519.getPublicKey(SK_A), sessionId: SID,
      extraSharedSecret: ssB, pqTranscript: Buffer.concat([flipped, mlkemPubB]),
    });
    expect(Buffer.from(decapsulator.contentKey).equals(Buffer.from(encapsulator.contentKey))).toBe(false);

    // Control: the genuine ct agrees, so the difference above is the flipped byte.
    const genuine = deriveSessionSecrets({
      ownEphemeralSecret: SK_B, peerEphemeralPublic: x25519.getPublicKey(SK_A), sessionId: SID,
      extraSharedSecret: await mlKemDecapsulate(seedB, ciphertext), pqTranscript: Buffer.concat([ciphertext, mlkemPubB]),
    });
    expect(Buffer.from(genuine.contentKey).equals(Buffer.from(encapsulator.contentKey))).toBe(true);
  });
});
