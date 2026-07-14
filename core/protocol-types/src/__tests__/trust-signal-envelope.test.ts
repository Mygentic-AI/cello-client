/**
 * DOD-CBOR-1 — the canonical trust-signal envelope: serialize, hash, verify.
 *
 * The property under test is CROSS-PARTY HASH AGREEMENT. Four independent implementations re-derive
 * this hash — the portal at mint, the directory at submission (INV-CHOKEPOINT's re-hash), the
 * directory again at presentation (dumb check 1), and the holder/recipient daemons on receipt and at
 * verification. A single byte of divergence at any hop turns a valid signal into a false
 * `hash_mismatch`: unpresentable, and — because it can differ per node or per client version —
 * censorship-shaped. That is why this is a CI invariant (DOD-INV-CANONICAL), not a unit test.
 *
 * WHY AN ARRAY AND NOT A MAP (M10-D15, journal Entry 4). The shared encoder is not RFC 8949 §4.2
 * deterministic for MAPS: keys follow insertion order, and map headers are not minimal-length
 * (a 2-entry map emits `b9 0002`, not `a2`). Arrays, text, byte strings, integers and null are all
 * minimal and order-fixed — measured, see `the shared encoder is deterministic for everything the
 * preimage uses` below, which pins that assumption so it cannot rot silently. Encoding the preimage
 * as a fixed-order array therefore makes determinism STRUCTURAL, at zero encoder change and zero
 * migration of the blobs already on disk.
 *
 * The vectors below are HAND-DERIVED from RFC 8949, not generated from the implementation and
 * asserted back. A vector produced by the code under test proves only that the code agrees with
 * itself; it would happily lock in a non-canonical encoding forever. These bytes are what the
 * standard says, so a second implementation in any language can be checked against them.
 */
import { describe, it, expect } from "vitest";
// The house SHA-256 (crypto/src/hashing.ts). protocol-types already depends on crypto; reaching for
// @noble directly here would add a second path to the same primitive for no reason.
import { hash as sha256 } from "@cello-protocol/crypto";
import {
  TRUST_SIGNAL_DOMAIN,
  encodeTrustSignalEnvelope,
  hashTrustSignalEnvelope,
  verifyTrustSignalHash,
  type TrustSignalEnvelope,
} from "../trust-signal.js";
import { encodeCbor } from "../cbor.js";

/** The reference envelope the hand-derived vector below encodes. */
function referenceEnvelope(): TrustSignalEnvelope {
  return {
    subject_kind: "agent",
    subject: "agent-1",
    issuer_kind: "portal",
    issuer_pubkey: "aabb",
    type: "phone",
    schema_version: 1,
    payload: new Uint8Array([1, 2, 3, 4]),
    issued_at: 1_000_000_000,
    expires_at: null,
    supersedes_hash: null,
  };
}

/**
 * Hand-derived per RFC 8949 §3, element by element. If the implementation disagrees with THIS, the
 * implementation is wrong — not the vector.
 *
 *   8b                          array(11)
 *   6d 43454c4c4f2d545349472d7631    text(13) "CELLO-TSIG-v1"   <- domain tag, slot 0
 *   65 6167656e74                    text(5)  "agent"           <- subject_kind
 *   67 6167656e742d31                text(7)  "agent-1"         <- subject
 *   66 706f7274616c                  text(6)  "portal"          <- issuer_kind
 *   64 61616262                      text(4)  "aabb"            <- issuer_pubkey
 *   65 70686f6e65                    text(5)  "phone"           <- type
 *   01                               uint(1)                    <- schema_version
 *   44 01020304                      bytes(4)                   <- payload (OPAQUE)
 *   1a 3b9aca00                      uint(1000000000)           <- issued_at (epoch SECONDS)
 *   f6                               null                       <- expires_at
 *   f6                               null                       <- supersedes_hash
 */
const REFERENCE_HEX =
  "8b" +
  "6d" + "43454c4c4f2d545349472d7631" +
  "65" + "6167656e74" +
  "67" + "6167656e742d31" +
  "66" + "706f7274616c" +
  "64" + "61616262" +
  "65" + "70686f6e65" +
  "01" +
  "44" + "01020304" +
  "1a" + "3b9aca00" +
  "f6" +
  "f6";

const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

describe("DOD-CBOR-1 — the canonical trust-signal envelope", () => {
  describe("the preimage is exactly what RFC 8949 says", () => {
    it("encodes the reference envelope to the hand-derived bytes", () => {
      expect(hex(encodeTrustSignalEnvelope(referenceEnvelope()))).toBe(REFERENCE_HEX);
    });

    it("hashes to SHA-256 of exactly those bytes — no extra prefix, no double-hash", () => {
      const expected = sha256(Buffer.from(REFERENCE_HEX, "hex"));
      expect(hex(hashTrustSignalEnvelope(referenceEnvelope()))).toBe(hex(expected));
    });

    it("binds the domain tag in slot 0, so a signal hash can never collide with another CELLO structure", () => {
      expect(TRUST_SIGNAL_DOMAIN).toBe("CELLO-TSIG-v1");
      const bytes = encodeTrustSignalEnvelope(referenceEnvelope());
      // array(11) header, then the domain text string.
      expect(bytes[0]).toBe(0x8b);
      expect(hex(bytes.slice(1, 15))).toBe("6d43454c4c4f2d545349472d7631");
    });

    it("the shared encoder is deterministic for EVERY type the preimage uses (the M10-D15 premise)", () => {
      // Maps are the broken case and the preimage deliberately contains none. This pins the premise:
      // if a future encoder change makes arrays non-minimal or order-sensitive, this fails LOUD here
      // rather than silently forking the hash across three repos.
      expect(hex(encodeCbor([1, 2, 3]))).toBe("83010203");           // minimal array header
      expect(hex(encodeCbor("phone"))).toBe("6570686f6e65");         // minimal text header
      expect(hex(encodeCbor(new Uint8Array([1, 2, 3, 4])))).toBe("4401020304"); // byte string, not tag-64
      expect(hex(encodeCbor(1_000_000_000))).toBe("1a3b9aca00");     // minimal uint
      expect(hex(encodeCbor(null))).toBe("f6");
    });

    it("PINS THE TRAP: a plain JS number above 2^32 encodes as a FLOAT64, a BigInt as a uint64", () => {
      // This is the premise the encoder ACTUALLY has, and the one the first version of this unit got
      // wrong. cbor-x emits any `number` > 0xffffffff as major type 7 float64 (`fb`), never a uint64.
      // A conforming CBOR implementation in Rust/Go/Python emits `1b` — so the two disagree on the
      // preimage bytes, and therefore on the hash, permanently.
      //
      // The envelope must therefore NEVER hand a raw number > 2^32 to the encoder. Pinned here so
      // that if cbor-x ever changes this behavior, we find out from a red test rather than from a
      // signal that stops verifying.
      expect(hex(encodeCbor(4_920_000_000))).toBe("fb41f25413e0000000");        // FLOAT64 — the trap
      expect(hex(encodeCbor(BigInt(4_920_000_000)))).toBe("1b0000000125413e00"); // uint64 — the fix
      expect(hex(encodeCbor(0xffff_ffff))).toBe("1affffffff");                   // last safe number
    });
  });

  describe("integers past 2^32 — the float64 trap (a 100-year expiry reaches it TODAY)", () => {
    // An expires_at a century out is 1.768e9 + 3.15e9 = 4.92e9, well past 2^32. This is not a 2106
    // problem; it is the first long-dated signal the portal mints.
    const farFuture = 4_920_000_000;

    it("hashes a far-future expires_at as a CBOR uint64, never a float64", () => {
      const bytes = encodeTrustSignalEnvelope({ ...referenceEnvelope(), expires_at: farFuture });
      expect(hex(bytes)).toContain("1b0000000125413e00"); // uint64
      expect(hex(bytes)).not.toContain("fb");             // no float, anywhere in the preimage
    });

    it("hashes a far-future issued_at as a CBOR uint64, never a float64", () => {
      const bytes = encodeTrustSignalEnvelope({ ...referenceEnvelope(), issued_at: farFuture });
      expect(hex(bytes)).toContain("1b0000000125413e00");
      expect(hex(bytes)).not.toContain("fb");
    });

    it("NO preimage, for any legal envelope, ever contains a float64 marker", () => {
      // The property, stated directly. If a float ever enters the preimage the signal is
      // unreproducible by any other language's CBOR library — so assert its total absence.
      for (const t of [0, 1, 0xffff_ffff, 0xffff_ffff + 1, farFuture, 99_999_999_999]) {
        const bytes = encodeTrustSignalEnvelope({ ...referenceEnvelope(), issued_at: t, expires_at: t });
        expect(hex(bytes).match(/fb[0-9a-f]{16}/), `issued_at=${t} encoded a float64`).toBeNull();
      }
    });

    it("REJECTS a schema_version large enough to float-encode, rather than hashing a float", () => {
      expect(() => encodeTrustSignalEnvelope({ ...referenceEnvelope(), schema_version: 1e300 })).toThrow(/schema_version/i);
      expect(() => encodeTrustSignalEnvelope({ ...referenceEnvelope(), schema_version: 0xffff_ffff + 1 })).toThrow(/schema_version/i);
    });

    it("REJECTS an integer past MAX_SAFE_INTEGER rather than hashing an approximation", () => {
      // Past 2^53 a JS number cannot represent consecutive integers, so the value the caller MEANT
      // and the value we would hash may already differ. There is no honest hash to produce.
      expect(() => encodeTrustSignalEnvelope({ ...referenceEnvelope(), issued_at: 2 ** 53 + 2 })).toThrow(/MAX_SAFE_INTEGER|out of range/i);
    });
  });

  describe("cross-party agreement — the reason this unit exists", () => {
    it("field-construction ORDER does not change the hash (a map preimage would have failed this)", () => {
      // The portal builds envelopes in one order, the daemon in another; both must hash identically.
      // Under a CBOR map this is exactly where the silent, intermittent divergence would come from.
      const a: TrustSignalEnvelope = referenceEnvelope();
      const b: TrustSignalEnvelope = {
        supersedes_hash: null,
        expires_at: null,
        issued_at: 1_000_000_000,
        payload: new Uint8Array([1, 2, 3, 4]),
        schema_version: 1,
        type: "phone",
        issuer_pubkey: "aabb",
        issuer_kind: "portal",
        subject: "agent-1",
        subject_kind: "agent",
      };
      expect(hex(encodeTrustSignalEnvelope(a))).toBe(hex(encodeTrustSignalEnvelope(b)));
      expect(hex(hashTrustSignalEnvelope(a))).toBe(hex(hashTrustSignalEnvelope(b)));
    });

    it("is stable across repeated encodings of the same envelope", () => {
      const env = referenceEnvelope();
      const runs = new Set(Array.from({ length: 50 }, () => hex(encodeTrustSignalEnvelope(env))));
      expect(runs.size).toBe(1);
    });

    it("agrees on randomly generated envelopes (property-based)", () => {
      // Deterministic PRNG — a failure must reproduce, and Math.random would make it a ghost.
      let seed = 0x5eed;
      const rnd = (n: number): number => {
        seed = (seed * 1103515245 + 12345) & 0x7fffffff;
        return seed % n;
      };
      for (let i = 0; i < 200; i++) {
        // Timestamps are drawn ACROSS the 2^32 boundary, deliberately. The original property test
        // drew rnd(2_000_000_000) — strictly below 0xffffffff — so it could never have caught the
        // float64 defect no matter how many iterations it ran. A property test that cannot reach the
        // failing band is not testing the property.
        const ts = (): number => (rnd(2) === 0 ? rnd(2_000_000_000) : 0xffff_ffff + rnd(2_000_000_000));
        const env: TrustSignalEnvelope = {
          subject_kind: rnd(2) === 0 ? "account" : "agent",
          subject: `s-${rnd(1e6)}`,
          issuer_kind: rnd(2) === 0 ? "portal" : "agent",
          issuer_pubkey: rnd(1e9).toString(16).padStart(16, "0"),
          type: `type_${rnd(1e4)}`,
          schema_version: rnd(8) + 1,
          payload: new Uint8Array(Array.from({ length: rnd(64) }, () => rnd(256))),
          issued_at: ts(),
          expires_at: rnd(2) === 0 ? null : ts(),
          supersedes_hash: rnd(2) === 0 ? null : new Uint8Array(Array.from({ length: 32 }, () => rnd(256))),
        };
        // Rebuilding the object with keys in reverse insertion order must not move a single byte.
        const reversed = Object.fromEntries(
          Object.entries(env).reverse(),
        ) as unknown as TrustSignalEnvelope;
        const encoded = hex(encodeTrustSignalEnvelope(env));
        expect(encoded).toBe(hex(encodeTrustSignalEnvelope(reversed)));
        // ...and no envelope, anywhere in the random space, may hash a float.
        expect(encoded.match(/fb[0-9a-f]{16}/), `float64 in preimage for issued_at=${env.issued_at}`).toBeNull();
      }
    });
  });

  describe("string canonicalization — the other cross-language hash-breakers (spec §5)", () => {
    it("REJECTS a non-NFC string rather than silently normalizing it", () => {
      // "é" is c3a9 in NFC and 65cc81 in NFD — same logical string, different preimage, different
      // hash. We refuse rather than normalize: silently normalizing would make two DIFFERENT inputs
      // hash to the SAME signal, a collision we manufactured ourselves.
      const nfd = "café"; // "café" decomposed
      expect(nfd.normalize("NFC")).not.toBe(nfd); // guard the guard: this really is non-NFC
      expect(() => encodeTrustSignalEnvelope({ ...referenceEnvelope(), type: nfd })).toThrow(/NFC/i);
      expect(() => encodeTrustSignalEnvelope({ ...referenceEnvelope(), subject: nfd })).toThrow(/NFC/i);
    });

    it("ACCEPTS the same string in NFC", () => {
      const nfc = "café";
      expect(() => encodeTrustSignalEnvelope({ ...referenceEnvelope(), type: nfc })).not.toThrow();
    });

    it("REJECTS an UPPERCASE hex issuer_pubkey — hex has a case, and case changes the bytes", () => {
      // "AABB" and "aabb" are the same key. A portal storing it uppercase and a directory
      // lowercasing it on read would mint two different hashes for one signal.
      expect(() => encodeTrustSignalEnvelope({ ...referenceEnvelope(), issuer_pubkey: "AABB" })).toThrow(/lowercase hex/i);
      expect(() => encodeTrustSignalEnvelope({ ...referenceEnvelope(), issuer_pubkey: "aaBB" })).toThrow(/lowercase hex/i);
    });

    it("REJECTS a non-hex or odd-length issuer_pubkey", () => {
      expect(() => encodeTrustSignalEnvelope({ ...referenceEnvelope(), issuer_pubkey: "zzzz" })).toThrow(/lowercase hex/i);
      expect(() => encodeTrustSignalEnvelope({ ...referenceEnvelope(), issuer_pubkey: "aab" })).toThrow(/lowercase hex/i);
    });
  });

  describe("the preimage is a CLOSED set (spec §4)", () => {
    it("REJECTS an unknown envelope field loud, rather than silently ignoring it", () => {
      // Silently dropping it would mean two parties who disagree about the field set still agree on
      // the hash — the field would be unauthenticated data riding inside a 'verified' signal.
      const rogue = { ...referenceEnvelope(), evil: "unhashed" } as unknown as TrustSignalEnvelope;
      expect(() => encodeTrustSignalEnvelope(rogue)).toThrow(/unknown envelope field.*evil/i);
    });

    it("REJECTS a missing mandatory field loud", () => {
      const env = referenceEnvelope() as Record<string, unknown>;
      delete env.issued_at;
      expect(() => encodeTrustSignalEnvelope(env as unknown as TrustSignalEnvelope)).toThrow(
        /issued_at/i,
      );
    });

    it("EXCLUDES status/class/verified_at — they are mutable after minting, which is the point", () => {
      // If these entered the preimage, a status change (revoke, supersede) would change the hash and
      // the signal would become unfindable at the directory. DOD-STORE-DIR-1 mutates status in place.
      const withMutables = {
        ...referenceEnvelope(),
        status: "revoked",
        class: 1,
        verified_at: 123,
      } as unknown as TrustSignalEnvelope;
      // They are not merely ignored — they are rejected, because the set is closed. Either way the
      // hash must never depend on them; this asserts the stronger property.
      expect(() => encodeTrustSignalEnvelope(withMutables)).toThrow(/unknown envelope field/i);
    });
  });

  describe("tamper detection", () => {
    it("a single-bit flip anywhere in the preimage changes the hash", () => {
      const base = hex(hashTrustSignalEnvelope(referenceEnvelope()));
      const mutations: Array<Partial<TrustSignalEnvelope>> = [
        { subject_kind: "account" },
        { subject: "agent-2" },
        { issuer_kind: "agent" },
        { issuer_pubkey: "aabc" },
        { type: "email" },
        { schema_version: 2 },
        { payload: new Uint8Array([1, 2, 3, 5]) },
        { issued_at: 1_000_000_001 },
        { expires_at: 1 },
        { supersedes_hash: new Uint8Array(32) },
      ];
      for (const m of mutations) {
        const mutated = { ...referenceEnvelope(), ...m };
        expect(hex(hashTrustSignalEnvelope(mutated)), `mutation ${JSON.stringify(Object.keys(m))} did not change the hash`).not.toBe(base);
      }
    });

    it("verifyTrustSignalHash accepts the true hash and rejects a wrong one", () => {
      const env = referenceEnvelope();
      const good = hashTrustSignalEnvelope(env);
      const bad = new Uint8Array(good);
      bad[0] ^= 0x01;
      expect(verifyTrustSignalHash(env, good)).toBe(true);
      expect(verifyTrustSignalHash(env, bad)).toBe(false);
    });

    it("verifyTrustSignalHash rejects a wrong-length hash rather than comparing a prefix", () => {
      const env = referenceEnvelope();
      expect(verifyTrustSignalHash(env, hashTrustSignalEnvelope(env).slice(0, 16))).toBe(false);
      expect(verifyTrustSignalHash(env, new Uint8Array(0))).toBe(false);
    });
  });

  describe("the nullable slots (M10-D17 — fixed arity, explicit null, never omitted)", () => {
    it("an absent expires_at and an absent supersedes_hash are NOT confusable", () => {
      // The bug this forbids: if absent fields were OMITTED, [.., issued_at, supersedes_hash] and
      // [.., issued_at, expires_at] would both be 10-element arrays whose last slot means different
      // things. Fixed arity + explicit null makes the position unambiguous.
      const noExpiry = { ...referenceEnvelope(), expires_at: null, supersedes_hash: new Uint8Array(32) };
      const noSupersede = { ...referenceEnvelope(), expires_at: 42, supersedes_hash: null };
      const a = encodeTrustSignalEnvelope(noExpiry);
      const b = encodeTrustSignalEnvelope(noSupersede);
      expect(a[0]).toBe(0x8b); // always 11 elements
      expect(b[0]).toBe(0x8b);
      expect(hex(a)).not.toBe(hex(b));
    });

    it("every envelope encodes to exactly 11 elements, whatever is null", () => {
      const variants: TrustSignalEnvelope[] = [
        { ...referenceEnvelope(), expires_at: null, supersedes_hash: null },
        { ...referenceEnvelope(), expires_at: 1, supersedes_hash: null },
        { ...referenceEnvelope(), expires_at: null, supersedes_hash: new Uint8Array(32) },
        { ...referenceEnvelope(), expires_at: 1, supersedes_hash: new Uint8Array(32) },
      ];
      for (const v of variants) expect(encodeTrustSignalEnvelope(v)[0]).toBe(0x8b);
    });
  });

  describe("the payload is OPAQUE — INV-ZERO-BUMP depends on it", () => {
    it("embeds payload bytes verbatim, never decoding or re-encoding them", () => {
      // A payload that was parsed and re-encoded would change bytes under a different encoder
      // version. Treating it as an opaque byte string kills that entire failure class — and it is
      // what lets a type the client has never seen flow through untouched.
      const payload = new Uint8Array([0xd8, 0x40, 0x00, 0xff, 0x9f, 0xff]); // looks like CBOR; is not parsed
      const bytes = encodeTrustSignalEnvelope({ ...referenceEnvelope(), payload });
      expect(hex(bytes)).toContain("46" + hex(payload)); // bytes(6) header + the payload verbatim
    });

    it("hashes an UNKNOWN type string exactly like a known one (INV-TYPE-CARRY)", () => {
      // No enum, no switch, no gate. A type nobody has ever seen must hash and flow.
      const unknown = { ...referenceEnvelope(), type: "some_type_invented_next_year" };
      expect(() => hashTrustSignalEnvelope(unknown)).not.toThrow();
      expect(hashTrustSignalEnvelope(unknown)).toHaveLength(32);
    });

    it("REJECTS a payload that is not raw bytes — an object payload would be map-encoded (non-deterministic)", () => {
      const bad = { ...referenceEnvelope(), payload: { claim: "hi" } } as unknown as TrustSignalEnvelope;
      expect(() => encodeTrustSignalEnvelope(bad)).toThrow(/payload/i);
    });
  });

  describe("no floating point, ever (a float would break byte-agreement across languages)", () => {
    it("REJECTS a non-integer issued_at", () => {
      const bad = { ...referenceEnvelope(), issued_at: 1.5 };
      expect(() => encodeTrustSignalEnvelope(bad)).toThrow(/issued_at.*integer/i);
    });

    it("REJECTS a non-integer expires_at", () => {
      const bad = { ...referenceEnvelope(), expires_at: 1.5 };
      expect(() => encodeTrustSignalEnvelope(bad)).toThrow(/expires_at.*integer/i);
    });

    it("REJECTS NaN and Infinity", () => {
      expect(() => encodeTrustSignalEnvelope({ ...referenceEnvelope(), issued_at: NaN })).toThrow();
      expect(() => encodeTrustSignalEnvelope({ ...referenceEnvelope(), issued_at: Infinity })).toThrow();
    });

    it("REJECTS a timestamp in milliseconds — epoch SECONDS is the contract", () => {
      // 1e12 is ~year 33658 in seconds. A ms timestamp is the classic cross-implementation skew and
      // it would silently produce a signal that never expires.
      const bad = { ...referenceEnvelope(), issued_at: 1_768_000_000_000 };
      expect(() => encodeTrustSignalEnvelope(bad)).toThrow(/seconds/i);
    });
  });
});
