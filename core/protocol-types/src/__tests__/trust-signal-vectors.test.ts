/**
 * DOD-INV-CANONICAL — the CROSS-PARTY vector check.
 *
 * `trust-signal-envelope.test.ts` proves the encoder agrees with RFC 8949 on a hand-derived vector.
 * THIS file proves every party stays agreed with each other over time. The vectors are FROZEN: the
 * portal (at mint), the directory (at submission, and again at presentation), and the holder and
 * recipient daemons all derive `signal_hash` from the same shipped component — so the failure this
 * catches is VERSION SKEW, where one repo pins an older @cello-protocol/protocol-types whose bytes
 * differ. That failure is otherwise invisible: it surfaces in production as an intermittent,
 * per-node `hash_mismatch` on signals that are perfectly valid.
 *
 * Per M10-D16 there is ONE implementation, not three. The vectors are what make that claim
 * checkable from the other two repos (and from any future re-implementation in another language),
 * rather than merely asserted.
 *
 * If a change to the envelope makes this file fail, the change is a PROTOCOL BREAK — it invalidates
 * every signal ever minted (spec §5's retrofit warning). Regenerating the vectors to make the test
 * pass is precisely the wrong move.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { hash as sha256 } from "@cello-protocol/crypto";
import {
  encodeTrustSignalEnvelope,
  hashTrustSignalEnvelope,
  verifyTrustSignalHash,
  type TrustSignalEnvelope,
} from "../trust-signal.js";

const here = dirname(fileURLToPath(import.meta.url));
const VECTORS = join(here, "..", "..", "test", "vectors", "trust-signal-envelope-canonical.json");

interface Vector {
  name: string;
  envelope: {
    subject_kind: "account" | "agent";
    subject: string;
    issuer_kind: "portal" | "agent";
    issuer_pubkey: string;
    type: string;
    schema_version: number;
    /** hex in the file, RAW BYTES in the preimage */
    payload: string;
    issued_at: number;
    expires_at: number | null;
    /** hex in the file, RAW BYTES in the preimage */
    supersedes_hash: string | null;
  };
  preimage_hex: string;
  signal_hash_hex: string;
}

const bytes = (h: string): Uint8Array => new Uint8Array(Buffer.from(h, "hex"));
const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

/** The file's hex-encoded payload/supersedes_hash become the raw bytes the preimage actually uses. */
function toEnvelope(v: Vector): TrustSignalEnvelope {
  return {
    ...v.envelope,
    payload: bytes(v.envelope.payload),
    supersedes_hash: v.envelope.supersedes_hash === null ? null : bytes(v.envelope.supersedes_hash),
  };
}

const loaded = JSON.parse(readFileSync(VECTORS, "utf8")) as { vectors: Vector[] };

describe("DOD-INV-CANONICAL — frozen cross-party envelope vectors", () => {
  it("guards against a vacuous pass — the vector file really was loaded", () => {
    expect(loaded.vectors.length).toBeGreaterThanOrEqual(6);
  });

  it.each(loaded.vectors.map((v) => [v.name, v] as const))(
    "reproduces the frozen preimage and hash: %s",
    (_name, v) => {
      const env = toEnvelope(v);
      expect(hex(encodeTrustSignalEnvelope(env))).toBe(v.preimage_hex);
      expect(hex(hashTrustSignalEnvelope(env))).toBe(v.signal_hash_hex);
      expect(verifyTrustSignalHash(env, bytes(v.signal_hash_hex))).toBe(true);
    },
  );

  it("every frozen hash is SHA-256 of its own frozen preimage (the file is self-consistent)", () => {
    // Catches a hand-edited vector file, which would otherwise let a wrong hash freeze into the repo.
    for (const v of loaded.vectors) {
      expect(hex(sha256(bytes(v.preimage_hex))), v.name).toBe(v.signal_hash_hex);
    }
  });

  it("ANCHOR: the reference vector equals the bytes hand-derived from RFC 8949", () => {
    // This is what stops the frozen file from being circular. Every other vector is frozen from the
    // implementation; THIS one is independently derived from the standard, element by element (see
    // trust-signal-envelope.test.ts). If the implementation ever drifts away from RFC 8949, it
    // cannot quietly take the vector file with it.
    const REFERENCE_HEX =
      "8b" +
      "6d" + "43454c4c4f2d545349472d7631" + // text(13) "CELLO-TSIG-v1"
      "65" + "6167656e74" +                 // text(5)  "agent"
      "67" + "6167656e742d31" +             // text(7)  "agent-1"
      "66" + "706f7274616c" +               // text(6)  "portal"
      "64" + "61616262" +                   // text(4)  "aabb"
      "65" + "70686f6e65" +                 // text(5)  "phone"
      "01" +                                // uint(1)
      "44" + "01020304" +                   // bytes(4)
      "1a" + "3b9aca00" +                   // uint(1000000000)
      "f6" +                                // null
      "f6";                                 // null
    const reference = loaded.vectors.find((v) => v.name.startsWith("reference"));
    expect(reference, "the reference vector must not be removed from the file").toBeDefined();
    expect(reference!.preimage_hex).toBe(REFERENCE_HEX);
  });

  it("every vector's arity is 11 — the fixed-slot rule holds across all of them (M10-D17)", () => {
    for (const v of loaded.vectors) {
      expect(v.preimage_hex.slice(0, 2), v.name).toBe("8b");
    }
  });

  it("all frozen hashes are distinct — no two vectors collapse to the same signal", () => {
    const hashes = new Set(loaded.vectors.map((v) => v.signal_hash_hex));
    expect(hashes.size).toBe(loaded.vectors.length);
  });
});
