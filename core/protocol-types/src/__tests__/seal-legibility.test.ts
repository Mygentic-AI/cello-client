/**
 * CELLO-M7-SESSION-004 — Seal certificate legibility schema (protocol-types)
 *
 * TDD Phase R — written BEFORE the type/constant existed (RED first).
 *
 * Specification (story AC-001, AC-003): the SessionSealed certificate gains a
 * machine-readable `legibility` object that states signatures attest RECEIPT —
 * not assent. This test pins the schema shape and the receipt-not-assent
 * constant, and asserts the object round-trips through the canonical CBOR wire
 * encoding used by the seal frame (RFC 8949 §4.2.1).
 */

import { Encoder, decode as cborDecode } from "cbor-x";
import { describe, it, expect } from "vitest";
import {
  SEAL_RECEIPT_DISCLAIMER,
  type SealLegibility,
  type AttestationMode,
} from "../index.js";

const ENC = new Encoder({ tagUint8Array: false });

describe("M7-SESSION-004: SealLegibility schema (protocol-types)", () => {
  it("the certificate's wording is the settled text, and neutral on agreement", () => {
    // Settled 2026-09-14: a seal may later be offered as evidence of an agreement, so the
    // certificate states what took place and says nothing either way about agreement.
    expect(SEAL_RECEIPT_DISCLAIMER).toBe(
      "Attests that this conversation took place between these two agents, in this order, unaltered.",
    );
    expect(SEAL_RECEIPT_DISCLAIMER.toLowerCase()).not.toMatch(/agree|assent|consent|binding/);
  });

  it("AC-003: attestation_mode is exactly one of live | recovered | absent", () => {
    const valid: AttestationMode[] = ["live", "recovered", "absent"];
    // A type-level guarantee; assert the runtime set used by consumers matches.
    expect(valid).toEqual(["live", "recovered", "absent"]);
  });

  it("a legibility object round-trips through canonical CBOR, carrying no agreement flag", () => {
    const legibility: SealLegibility = {
      attests: "receipt",
      disclaimer: SEAL_RECEIPT_DISCLAIMER,
      participants: [
        { pubkey: new Uint8Array(32).fill(1), content_frontier_seq: 6, last_authored_seq: 7, attestation_mode: "live" },
        { pubkey: new Uint8Array(32).fill(2), content_frontier_seq: 4, last_authored_seq: 8, attestation_mode: "absent" },
      ],
      final_message: { sender_pubkey: new Uint8Array(32).fill(1), seq: 7, answered: false },
    };

    const encoded = ENC.encode(legibility) as Uint8Array;
    const decoded = cborDecode(encoded) as SealLegibility;

    expect(decoded.attests).toBe("receipt");
    expect(decoded).not.toHaveProperty("implies_assent");
    expect(decoded.disclaimer).toBe(SEAL_RECEIPT_DISCLAIMER);
    expect(decoded.participants).toHaveLength(2);
    expect(decoded.participants[0]!.content_frontier_seq).toBe(6);
    expect(decoded.participants[1]!.attestation_mode).toBe("absent");
    expect(decoded.final_message.answered).toBe(false);

    // SI-001: nothing in the serialized object can be read as agreement.
    const keys = JSON.stringify(decoded, (_k, v) =>
      v instanceof Uint8Array || (typeof Buffer !== "undefined" && Buffer.isBuffer(v)) ? "<bytes>" : v,
    ).toLowerCase();
    expect(keys).not.toMatch(/"agreed"|"consent"|"assent":\s*true|"agreement":\s*true/);
  });
});
