/**
 * M10B / DOD-END-SUBMIT-1 — the sealed submission wire contract.
 *
 * THREE parties rebuild these bytes independently: Bob's daemon signs them, the portal verifies them
 * at drain, and the portal re-derives `submission_id` from them to dedupe a retry. They must agree
 * byte-for-byte across two repos, or a legitimate submission is either unattributable (signature
 * fails) or minted twice (id disagrees). That is why the builder lives here and not in the daemon —
 * a local copy on each side is precisely how two implementations drift (M10B-D28).
 */
import { describe, it, expect } from "vitest";
import {
  SUBMISSION_DOMAIN,
  buildSubmissionTbs,
  encodeSubmission,
  decodeSubmission,
  submissionId,
  type SubmissionBody,
} from "../submission.js";
import { AGENT_REVOCATION_DOMAIN } from "../revocation.js";
import { TRUST_SIGNAL_DOMAIN } from "../trust-signal.js";
import { decodeCbor, encodeCbor } from "../cbor.js";

const BODY = (over: Partial<SubmissionBody> = {}): SubmissionBody => ({
  v: 1,
  op: "submit",
  subject_kind: "agent",
  subject: "aa".repeat(32),
  submitter_pubkey: "bb".repeat(32),
  body: "Alice shipped the payments migration with no incident.",
  issued_at: 1_768_000_000,
  ...over,
});

const SIG = new Uint8Array(64).fill(7);

describe("DOD-END-SUBMIT-1 — the submission TBS", () => {
  it("is an ARRAY, never a map — the encoder is not deterministic for maps", () => {
    // The house rule (cbor.ts): map keys follow INSERTION ORDER and map headers are not
    // minimal-length, so two parties building the same map in a different field order produce
    // different bytes. Every signed structure in CELLO is a fixed-order array for this reason, and a
    // signature over a map here would be a byte-agreement bug that only shows up cross-repo.
    const decoded = decodeCbor(buildSubmissionTbs(BODY()));
    expect(Array.isArray(decoded)).toBe(true);
  });

  it("binds its own domain tag as element 0, distinct from every other CELLO domain", () => {
    const decoded = decodeCbor(buildSubmissionTbs(BODY())) as unknown[];
    expect(decoded[0]).toBe(SUBMISSION_DOMAIN);
    expect(SUBMISSION_DOMAIN).toBe("CELLO-SUBMIT-v1");
    // Collision here would let a signature over one structure be replayed as the other.
    expect(SUBMISSION_DOMAIN).not.toBe(AGENT_REVOCATION_DOMAIN);
    expect(SUBMISSION_DOMAIN).not.toBe(TRUST_SIGNAL_DOMAIN);
    expect(SUBMISSION_DOMAIN).not.toBe("CELLO-TSIG-REQ-v1"); // the directory's request TBS
  });

  it("is deterministic — the same body twice yields identical bytes", () => {
    expect(buildSubmissionTbs(BODY())).toEqual(buildSubmissionTbs(BODY()));
  });

  it("covers EVERY field: changing any one changes the bytes", () => {
    // A field outside the TBS is unauthenticated data riding inside a signed submission — the
    // attacker edits it in flight and the signature still verifies. Each of these must move the
    // bytes, and the revert test for this unit is that dropping a field from the array makes the
    // corresponding case fail.
    const base = buildSubmissionTbs(BODY());
    const mutations: Array<Partial<SubmissionBody>> = [
      { v: 2 },
      { op: "withdraw" },
      { subject_kind: "account" },
      { subject: "cc".repeat(32) },
      { submitter_pubkey: "dd".repeat(32) },
      { body: "Alice shipped the payments migration with no incident!" },
      { issued_at: 1_768_000_001 },
    ];
    for (const m of mutations) {
      expect(buildSubmissionTbs(BODY(m)), `mutation ${JSON.stringify(m)} must change the TBS`)
        .not.toEqual(base);
    }
  });

  it("binds issued_at, so a signature is not a permanent bearer capability", () => {
    // M10B-D28: as first sketched the inner authorization had no timestamp, making it a permanent
    // capability replayable at every node forever. issued_at inside the TBS is what lets the
    // verifier apply the existing clock-skew bound.
    const decoded = decodeCbor(buildSubmissionTbs(BODY())) as unknown[];
    expect(decoded).toContain(1_768_000_000);
  });

  it("binds `op`, so a withdrawal cannot be replayed as a submission", () => {
    // The op discriminates the sealed body (M10B-D28) and rides INSIDE the seal, so the directory
    // still cannot tell a withdrawal from an endorsement. But it must be signed, or an attacker who
    // can flip it turns Bob's endorsement into Bob's retraction of someone else's.
    expect(buildSubmissionTbs(BODY({ op: "submit" })))
      .not.toEqual(buildSubmissionTbs(BODY({ op: "withdraw" })));
  });
});

describe("DOD-END-SUBMIT-1 — encode/decode round-trip", () => {
  it("round-trips a signed submission byte-for-byte", () => {
    const body = BODY();
    const got = decodeSubmission(encodeSubmission(body, SIG));
    expect(got.body).toEqual(body);
    expect(got.signature).toEqual(SIG);
  });

  it("the decoded body rebuilds the IDENTICAL TBS — this is the whole cross-repo contract", () => {
    // The portal never sees the daemon's in-memory object; it sees bytes. If the TBS it rebuilds
    // from the decoded body differs by one byte, every submission is unattributable and the failure
    // looks like a bad key.
    const got = decodeSubmission(encodeSubmission(BODY(), SIG));
    expect(buildSubmissionTbs(got.body)).toEqual(buildSubmissionTbs(BODY()));
  });

  it("REJECTS a truncated or malformed encoding — never a partly-populated body", () => {
    // Poison is unattributable by construction (M10B-D22b): there is nobody to reply to. So the
    // failure must be loud at the decoder, not a body with undefined fields that flows onward and
    // gets attributed to whatever `submitter_pubkey` happened to decode as.
    expect(() => decodeSubmission(new Uint8Array([0x83, 0x01]))).toThrow();
    expect(() => decodeSubmission(new Uint8Array(0))).toThrow();
  });

  it("REJECTS a body whose arity is wrong — the field set is CLOSED", () => {
    // Spec §4's rule, applied here: an unknown/extra field is rejected, never ignored. Silently
    // dropping it would let two parties who disagree about the field set still agree on the
    // signature, making the extra field unauthenticated data inside a "verified" submission.
    expect(() => decodeSubmission(encodeCbor(["CELLO-SUBMIT-v1", 1, "submit"]))).toThrow();
    expect(() => decodeSubmission(encodeCbor([...(decodeCbor(encodeSubmission(BODY(), SIG)) as unknown[]), "extra"])))
      .toThrow();
  });
});

describe("DOD-END-SUBMIT-1 — submission_id (M10B-D20)", () => {
  it("is content-derived: the same signed body yields the same id", () => {
    // This is what makes retry-across-nodes safe rather than a duplication mechanism — the daemon
    // fails over to a second node and the id is identical, so the row is a strict no-op.
    const bytes = encodeSubmission(BODY(), SIG);
    expect(submissionId(bytes)).toBe(submissionId(bytes));
    expect(submissionId(encodeSubmission(BODY(), SIG))).toBe(submissionId(bytes));
  });

  it("DIFFERS for a legitimate re-issue, because issued_at is inside the signed body", () => {
    // M10B-D4 allows re-issuing a corrected endorsement after a refusal. If the id collided, the
    // portal would dedupe the correction away as a retry and Alice would never see it.
    expect(submissionId(encodeSubmission(BODY(), SIG)))
      .not.toBe(submissionId(encodeSubmission(BODY({ issued_at: 1_768_000_001 }), SIG)));
  });

  it("is 64 lowercase hex characters — sha256, as the queue's PK expects", () => {
    expect(submissionId(encodeSubmission(BODY(), SIG))).toMatch(/^[0-9a-f]{64}$/);
  });
});

/**
 * M10B-D4 / DOD-END-SURFACE-1 — refusal is a THIRD OP, not a new structure.
 *
 * Alice refuses an endorsement Bob issued about her and chooses to tell him why. Her message is
 * operator-authored free text scanned at intake exactly like Bob's endorsement body — "the same
 * injection surface pointed the other way" (M10B-D4).
 *
 * It rides `op` because `op` is a protocol verb (what the caller is ASKING FOR), which is the axis
 * INV-ZEROBUMP explicitly permits — as opposed to branching on what a signal MEANS. Crucially this
 * adds no field and reorders nothing: the TBS arity is unchanged, so every signature already made
 * over a `submit` or `withdraw` body still verifies. Widening an enum value is not a wire break.
 */
describe("M10B-D4 — the `refuse` op", () => {
  const refusal: SubmissionBody = {
    v: 1,
    op: "refuse",
    subject_kind: "agent",
    // For a refusal the subject is the TARGET SIGNAL HASH, exactly as it is for a withdrawal: both
    // verbs act on an existing signal rather than asserting a fact about a party.
    subject: "b".repeat(64),
    submitter_pubkey: "a".repeat(64),
    body: "This says I led the migration; I reviewed it. Happy to be endorsed for the review.",
    issued_at: 1_800_000_000,
  };

  it("round-trips through encode → decode with the message intact", () => {
    const sig = new Uint8Array(64).fill(7);
    const got = decodeSubmission(encodeSubmission(refusal, sig));
    expect(got.body).toEqual(refusal);
    expect(got.body.body).toBe(refusal.body);
  });

  it("does NOT change the wire arity — a refusal encodes to the same shape as a submission", () => {
    const sig = new Uint8Array(64).fill(7);
    const asRefusal = encodeSubmission(refusal, sig);
    const asSubmit = encodeSubmission({ ...refusal, op: "submit" }, sig);
    // Same element count: the only difference is one string. If this ever diverges, an existing
    // signature over a `submit` body has stopped being verifiable and that is a migration.
    expect((decodeCbor(asRefusal) as unknown[]).length).toBe((decodeCbor(asSubmit) as unknown[]).length);
  });

  it("is inside the TBS — the message cannot be edited in flight", () => {
    const tampered = { ...refusal, body: "I fully endorse this, please publish it" };
    expect(buildSubmissionTbs(tampered)).not.toEqual(buildSubmissionTbs(refusal));
    // And the op itself is signed, so a refusal cannot be replayed as a submission.
    expect(buildSubmissionTbs({ ...refusal, op: "submit" })).not.toEqual(buildSubmissionTbs(refusal));
  });

  it("still REFUSES an op it does not recognise — widening is not opening", () => {
    const bytes = encodeCbor([
      SUBMISSION_DOMAIN, 1, "publish", "agent", "b".repeat(64), "a".repeat(64), "x", 1,
      new Uint8Array(64),
    ]);
    expect(() => decodeSubmission(bytes)).toThrow(/unknown op 'publish'/);
  });
});
