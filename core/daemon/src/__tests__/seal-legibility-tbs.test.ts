/**
 * M7 legibility-TBS-binding — unit proof that the canonical hash COVERS every tamperable field.
 *
 * The live spine tests (j-legibility / SPINE-7) prove the positive: a valid bilateral seal verifies
 * with the binding (and that the directory's and daemon's hash implementations AGREE — the FROST
 * seal completes only if they do). This proves the complement: changing ANY field a MITM could
 * tamper (answered / content_frontier_seq / last_authored_seq / attestation_mode / final-message
 * sender or seq / participant pubkey / participant order) changes the hash — so it changes the
 * signed TBS — so the signature would fail. Together they establish tamper-evidence.
 */
import { describe, it, expect } from "vitest";
import { canonicalLegibilityHash, bindLegibilityToTbs, type LegibilityForHash } from "../seal-legibility-tbs.js";

function baseLegibility(): LegibilityForHash {
  return {
    participants: [
      { pubkey: new Uint8Array(32).fill(0xa1), content_frontier_seq: 2, last_authored_seq: 4, attestation_mode: "live" },
      { pubkey: new Uint8Array(32).fill(0xb2), content_frontier_seq: 3, last_authored_seq: 5, attestation_mode: "live" },
    ],
    final_message: { sender_pubkey: new Uint8Array(32).fill(0xa1), seq: 3, answered: false },
  };
}

const hex = (u: Uint8Array): string => Buffer.from(u).toString("hex");

describe("canonicalLegibilityHash — tamper coverage", () => {
  it("is deterministic for identical input", () => {
    expect(hex(canonicalLegibilityHash(baseLegibility()))).toBe(hex(canonicalLegibilityHash(baseLegibility())));
  });

  it("is 32 bytes (SHA-256)", () => {
    expect(canonicalLegibilityHash(baseLegibility()).length).toBe(32);
  });

  it("treats a Buffer pubkey the same as the equal Uint8Array pubkey (wire ↔ source agreement)", () => {
    const a = baseLegibility();
    const b = baseLegibility();
    b.participants[0]!.pubkey = Buffer.from(b.participants[0]!.pubkey as Uint8Array); // CBOR-decoded form
    expect(hex(canonicalLegibilityHash(a))).toBe(hex(canonicalLegibilityHash(b)));
  });

  it("CHANGES when final_message.answered flips (the malicious-tail field)", () => {
    const base = hex(canonicalLegibilityHash(baseLegibility()));
    const t = baseLegibility();
    t.final_message.answered = true;
    expect(hex(canonicalLegibilityHash(t))).not.toBe(base);
  });

  it("CHANGES when a participant content_frontier_seq is inflated", () => {
    const base = hex(canonicalLegibilityHash(baseLegibility()));
    const t = baseLegibility();
    t.participants[1]!.content_frontier_seq = 99;
    expect(hex(canonicalLegibilityHash(t))).not.toBe(base);
  });

  it("CHANGES when an attestation_mode is altered", () => {
    const base = hex(canonicalLegibilityHash(baseLegibility()));
    const t = baseLegibility();
    t.participants[0]!.attestation_mode = "absent";
    expect(hex(canonicalLegibilityHash(t))).not.toBe(base);
  });

  it("CHANGES when last_authored_seq, final_message.seq, or final_message.sender are altered", () => {
    const base = hex(canonicalLegibilityHash(baseLegibility()));
    for (const mutate of [
      (l: LegibilityForHash) => { l.participants[0]!.last_authored_seq = 9; },
      (l: LegibilityForHash) => { l.final_message.seq = 7; },
      (l: LegibilityForHash) => { l.final_message.sender_pubkey = new Uint8Array(32).fill(0xb2); },
    ]) {
      const t = baseLegibility();
      mutate(t);
      expect(hex(canonicalLegibilityHash(t))).not.toBe(base);
    }
  });

  it("CHANGES when the participants are reordered (a MITM swap is detected)", () => {
    const base = hex(canonicalLegibilityHash(baseLegibility()));
    const t = baseLegibility();
    t.participants.reverse();
    expect(hex(canonicalLegibilityHash(t))).not.toBe(base);
  });
});

describe("bindLegibilityToTbs", () => {
  it("is a no-op when legibility is absent (the unilateral seal path)", () => {
    const tbs = new Uint8Array([1, 2, 3, 4]);
    expect(bindLegibilityToTbs(tbs, null)).toBe(tbs);
    expect(bindLegibilityToTbs(tbs, undefined)).toBe(tbs);
  });

  it("appends the 32-byte legibility hash when present", () => {
    const tbs = new Uint8Array([1, 2, 3, 4]);
    const bound = bindLegibilityToTbs(tbs, baseLegibility());
    expect(bound.length).toBe(tbs.length + 32);
    expect(Array.from(bound.slice(0, 4))).toEqual([1, 2, 3, 4]);
    expect(hex(bound.slice(4))).toBe(hex(canonicalLegibilityHash(baseLegibility())));
  });

  it("produces a DIFFERENT bound TBS when the legibility is tampered (the whole point)", () => {
    const tbs = new Uint8Array([1, 2, 3, 4]);
    const honest = bindLegibilityToTbs(tbs, baseLegibility());
    const tampered = baseLegibility();
    tampered.final_message.answered = true;
    expect(hex(bindLegibilityToTbs(tbs, tampered))).not.toBe(hex(honest));
  });
});
