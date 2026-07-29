/**
 * M10B / DOD-END-SUBMIT-1 — the daemon composes, signs and SEALS a submission.
 *
 * This is the client-supplied source's first hop, and it is where three of the milestone's
 * invariants are either established or lost:
 *
 *   INV-ATTRIBUTION — the submitter pubkey in the body is the SIGNING key's own public half, never
 *                     something a caller passed in. If a caller can name someone else, anyone can
 *                     mint an endorsement attributed to anyone, permanently, inside the hash.
 *   INV-CONSENT     — the directory must not be able to read what it carries. A single fallback to
 *                     sending unsealed hands a node operator every endorsement in the clear.
 *   §5a ABSENT      — no intake key ⇒ REFUSE and name the reason. Never "send it anyway".
 *
 * The tests below use REAL Ed25519 and the REAL seal — no mocks for crypto — so "it is sealed" and
 * "the signature verifies" are demonstrated, not asserted.
 */
import { describe, it, expect } from "vitest";
import { InMemoryKeyProvider, generateKeypair, verify, openSealed } from "@cello-protocol/crypto";
import { buildSubmissionTbs, decodeSubmission, submissionId } from "@cello-protocol/protocol-types";
import type { ConsortiumManifest } from "@cello-protocol/protocol-types";
import { randomBytes } from "node:crypto";
import { composeSealedSubmission } from "../signal-submission.js";
import type { Logger } from "../types.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };

/** A real intake keypair — the portal's side. Submissions are sealed TO this, and opened with the
 *  SEED (`openSealed` takes the seed, not a derived secret key). */
const intakeSeed = new Uint8Array(randomBytes(32));
const intakePubHex = Buffer.from(await new InMemoryKeyProvider(intakeSeed).getPublicKey()).toString("hex");

const manifest = (over: Partial<ConsortiumManifest> = {}): ConsortiumManifest => ({
  version: 7,
  not_before: "2026-01-01T00:00:00Z",
  expires: "2027-01-01T00:00:00Z",
  nodes: [],
  signatures: [],
  intake_key: { key_id: "intake-2026-07", pubkey: intakePubHex },
  ...over,
});

const submitter = new InMemoryKeyProvider(new Uint8Array(randomBytes(32)));

const compose = async (over: Record<string, unknown> = {}) =>
  composeSealedSubmission({
    manifest: manifest(),
    keyProvider: submitter,
    op: "submit",
    subjectKind: "agent",
    subject: "aa".repeat(32),
    body: "Alice shipped the payments migration with no incident.",
    issuedAt: 1_768_000_000,
    logger: silent,
    ...over,
  });

describe("DOD-END-SUBMIT-1 — refusal paths (§5a ABSENT IS NOT FINE)", () => {
  it("REFUSES with a named cause when there is no manifest at all", async () => {
    const res = await compose({ manifest: null });
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("unreachable");
    // A bare `submission_failed` would send the operator hunting. The cause names the subsystem.
    expect(res.reason).toBe("manifest_unavailable");
    expect(res.guidance).toMatch(/manifest/i);
  });

  it("REFUSES when the manifest carries no intake key — and NEVER falls back to unsealed", async () => {
    // The whole claim of the sealed queue is that the directory cannot read what it holds. A daemon
    // that sent plaintext when it could not find a key would satisfy every other test in this file
    // and destroy the property outright.
    const res = await compose({ manifest: manifest({ intake_key: undefined }) });
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("unreachable");
    expect(res.reason).toBe("intake_key_absent");
    expect(res.guidance).toMatch(/intake key/i);
  });

  it("REFUSES a MALFORMED intake key rather than sealing to garbage", async () => {
    // Malformed gets the same answer as absent, for the same reason. Sealing to a non-key produces
    // a blob nobody can open — which arrives at the portal as unattributable POISON with no reply
    // possible (M10B-D22b), so the operator would see their submission vanish silently.
    for (const pubkey of ["", "not-hex", "aabb", intakePubHex.toUpperCase(), intakePubHex + "00"]) {
      const res = await compose({ manifest: manifest({ intake_key: { key_id: "k", pubkey } }) });
      expect(res.ok, `pubkey ${JSON.stringify(pubkey)} must be refused`).toBe(false);
      if (res.ok) throw new Error("unreachable");
      expect(res.reason).toBe("intake_key_malformed");
    }
  });

  it("REFUSES an intake key with an empty key_id — the id is what makes rotation retention work", async () => {
    // Every queue row records the key_id it was sealed to; the portal retains a rotated-out private
    // key until no undrained row references it (M10B-D11). An empty id breaks that bookkeeping
    // silently, stranding submissions at the next rotation.
    const res = await compose({ manifest: manifest({ intake_key: { key_id: "", pubkey: intakePubHex } }) });
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("unreachable");
    expect(res.reason).toBe("intake_key_malformed");
  });
});

describe("DOD-END-SUBMIT-1 — the sealed submission", () => {
  it("SEALS: the ciphertext does not contain the plaintext body", async () => {
    // The revert test for this one is direct — remove the seal and the plaintext is right there in
    // the bytes the directory stores.
    const res = await compose();
    if (!res.ok) throw new Error(`expected ok, got ${res.reason}`);
    const haystack = Buffer.from(res.ciphertext).toString("latin1");
    expect(haystack).not.toContain("Alice shipped the payments migration");
    expect(haystack).not.toContain("aa".repeat(32));
  });

  it("opens with the intake PRIVATE key and round-trips every field", async () => {
    const res = await compose();
    if (!res.ok) throw new Error(`expected ok, got ${res.reason}`);
    const opened = openSealed(intakeSeed, res.ciphertext);
    expect(opened).not.toBeNull();
    const { body } = decodeSubmission(opened!);
    expect(body.op).toBe("submit");
    expect(body.subject_kind).toBe("agent");
    expect(body.subject).toBe("aa".repeat(32));
    expect(body.body).toBe("Alice shipped the payments migration with no incident.");
    expect(body.issued_at).toBe(1_768_000_000);
    expect(body.v).toBe(1);
  });

  it("INV-ATTRIBUTION: submitter_pubkey is the SIGNING key's own public half", async () => {
    // Not a caller-supplied field — there is no parameter for it. The precedent is `accepting_node`
    // in DOD-DIR-WRITE-1: "written by the node itself, never accepted from the request."
    const res = await compose();
    if (!res.ok) throw new Error(`expected ok, got ${res.reason}`);
    const { body } = decodeSubmission(openSealed(intakeSeed, res.ciphertext)!);
    const expected = Buffer.from(await submitter.getPublicKey()).toString("hex");
    expect(body.submitter_pubkey).toBe(expected);
  });

  // NOTE, stated rather than papered over: the two attribution tests below CANNOT see the invariant
  // they are named for. They check that the pubkey equals the signer's — and an implementation of
  // the form `submitter_pubkey: opts.submitterPubkey ?? signerPubkey` passes both, because no test
  // supplies an override. The invariant is the ABSENCE of a parameter, which is a property of the
  // type; it is pinned by the compile-time guard in `signal-submission.ts`, NOT here. A
  // `@ts-expect-error` in this file would assert nothing at all: `core/daemon/tsconfig.json`
  // excludes `src/__tests__`, so nothing typechecks it.

  it("INV-ATTRIBUTION: the signature VERIFIES against that pubkey, over the canonical TBS", async () => {
    // Ed25519 has no key recovery, so the pubkey in the body is worthless until this check passes.
    // This is the check that turns a claimed identity into an authenticated one.
    const res = await compose();
    if (!res.ok) throw new Error(`expected ok, got ${res.reason}`);
    const { body, signature } = decodeSubmission(openSealed(intakeSeed, res.ciphertext)!);
    const ok = verify(Buffer.from(body.submitter_pubkey, "hex"), buildSubmissionTbs(body), signature);
    expect(ok).toBe(true);
  });

  it("a signature from a DIFFERENT key does not verify — the check has teeth", async () => {
    // Without this, "the signature verifies" could be true of an implementation that verifies
    // nothing. Same bytes, wrong key, must fail.
    const res = await compose();
    if (!res.ok) throw new Error(`expected ok, got ${res.reason}`);
    const { body, signature } = decodeSubmission(openSealed(intakeSeed, res.ciphertext)!);
    const impostor = await generateKeypair().getPublicKey();
    expect(verify(impostor, buildSubmissionTbs(body), signature)).toBe(false);
  });

  it("reports the intake key_id it sealed to — rotation retention depends on it", async () => {
    const res = await compose();
    if (!res.ok) throw new Error(`expected ok, got ${res.reason}`);
    expect(res.intakeKeyId).toBe("intake-2026-07");
  });
});

describe("DOD-END-SUBMIT-1 — submission_id (M10B-D20)", () => {
  it("is the sha256 of the bytes actually queued, so the portal can re-derive it", async () => {
    // The directory cannot verify this id — it cannot open the seal. The portal re-derives it from
    // the OPENED body and discards a row whose id disagrees, so the id must be derived from the
    // plaintext submission, NOT from the ciphertext (which differs on every re-seal).
    const res = await compose();
    if (!res.ok) throw new Error(`expected ok, got ${res.reason}`);
    const opened = openSealed(intakeSeed, res.ciphertext)!;
    expect(res.submissionId).toBe(submissionId(opened));
  });

  it("is STABLE across re-seals — which is what makes retry to another node a no-op", async () => {
    // Sealing is randomised, so two seals of one body produce different ciphertext. If the id were
    // derived from the ciphertext, a failover retry would look like a second submission and mint
    // twice, consuming quota twice (M10B-D21's accepted-loss reasoning depends on this).
    const a = await compose();
    const b = await compose();
    if (!a.ok || !b.ok) throw new Error("expected ok");
    expect(a.submissionId).toBe(b.submissionId);
    expect(Buffer.from(a.ciphertext).equals(Buffer.from(b.ciphertext))).toBe(false);
  });

  it("DIFFERS for a legitimate re-issue after a refusal (issued_at is signed)", async () => {
    const a = await compose();
    const b = await compose({ issuedAt: 1_768_000_001 });
    if (!a.ok || !b.ok) throw new Error("expected ok");
    expect(a.submissionId).not.toBe(b.submissionId);
  });
});

describe("DOD-END-SUBMIT-1 — INV-ZEROBUMP", () => {
  it("carries a withdrawal through the identical path — nothing knows a signal TYPE", async () => {
    // `op` is a protocol verb, not a signal type (M10B-D28), and it rides INSIDE the seal so the
    // directory still cannot tell a withdrawal from an endorsement. A second client-sourced type
    // uses this same call with no change here.
    const res = await compose({ op: "withdraw", subject: "bb".repeat(32) });
    if (!res.ok) throw new Error(`expected ok, got ${res.reason}`);
    const { body } = decodeSubmission(openSealed(intakeSeed, res.ciphertext)!);
    expect(body.op).toBe("withdraw");
  });
});

/**
 * M10B-D4 / DOD-END-SURFACE-1 — the refusal message, exercised through the REAL composer.
 *
 * The handler-side test for this is a source audit, and a review showed four wrong implementations
 * that pass it — including one that seals with a DIFFERENT agent's key provider, which is the
 * attribution claim itself. These go through compose → seal → open → decode, so the assertions are
 * about bytes rather than about the shape of the source.
 */
describe("M10B-D4 — a refusal rides the same sealed path", () => {
  const refuse = (over: Record<string, unknown> = {}) =>
    compose({
      op: "refuse",
      subject: "bb".repeat(32), // the TARGET SIGNAL HASH, not a pubkey
      body: "This says I led the migration; I reviewed it. Happy to be endorsed for the review.",
      ...over,
    });

  it("round-trips the operator's message byte-for-byte", async () => {
    const res = await refuse();
    if (!res.ok) throw new Error(`expected ok, got ${res.reason}`);
    const { body } = decodeSubmission(openSealed(intakeSeed, res.ciphertext)!);
    expect(body.op).toBe("refuse");
    expect(body.subject).toBe("bb".repeat(32));
    // What Alice typed is what Bob reads. An implementation that passed `body: ""` — one of the
    // bypasses the source audit could not see — fails here.
    expect(body.body).toBe("This says I led the migration; I reviewed it. Happy to be endorsed for the review.");
  });

  it("attributes the submission to the SIGNING key, and to nothing else", async () => {
    // INV-ATTRIBUTION at the byte level. The compile-time guard proves no OVERRIDE parameter exists;
    // it cannot prove the right provider was passed. Compose with a second identity and assert the
    // two submissions carry different, correct submitter_pubkeys.
    const other = new InMemoryKeyProvider(new Uint8Array(randomBytes(32)));
    const mine = await refuse();
    const theirs = await refuse({ keyProvider: other });
    if (!mine.ok || !theirs.ok) throw new Error("expected both to compose");

    const a = decodeSubmission(openSealed(intakeSeed, mine.ciphertext)!).body;
    const b = decodeSubmission(openSealed(intakeSeed, theirs.ciphertext)!).body;
    expect(a.submitter_pubkey).toBe(Buffer.from(await submitter.getPublicKey()).toString("hex"));
    expect(b.submitter_pubkey).toBe(Buffer.from(await other.getPublicKey()).toString("hex"));
    expect(a.submitter_pubkey).not.toBe(b.submitter_pubkey);
    // And the signature verifies against the claimed key — a body claiming P with any other
    // signature proves nothing (RFC 8032: Ed25519 has no key recovery).
    const signed = decodeSubmission(openSealed(intakeSeed, mine.ciphertext)!);
    expect(verify(Buffer.from(a.submitter_pubkey, "hex"), buildSubmissionTbs(a), signed.signature)).toBe(true);
  });

  it("REFUSES on an EXPIRED manifest — a startup check does not stay true forever", async () => {
    // The manifest is verified once at daemon start and held for the process lifetime. Three weeks
    // later its window may have closed and the portal may have rotated the intake key, while the
    // key itself is still present and well-formed — so the presence checks all pass and the message
    // is sealed to a retired key. The portal cannot open it and cannot attribute it: it vanishes
    // with no error anywhere, after the operator was told it was sent.
    const res = await refuse({
      manifest: manifest({ expires: "2026-01-02T00:00:00Z" }),
      nowMs: () => Date.parse("2026-07-29T00:00:00Z"),
    });
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("unreachable");
    expect(res.reason).toBe("manifest_expired");
    // Names the manifest and the expiry instant — an operator would never guess "consortium
    // manifest" from a message that simply failed to arrive.
    expect(res.guidance).toContain("2026-01-02T00:00:00Z");
    expect(res.guidance).toMatch(/manifest/i);
  });

  it("composes when the manifest is still inside its window — the gate is not just 'always refuse'", async () => {
    const res = await refuse({
      manifest: manifest({ expires: "2027-01-01T00:00:00Z" }),
      nowMs: () => Date.parse("2026-07-29T00:00:00Z"),
    });
    expect(res.ok).toBe(true);
  });

  it("REFUSES an unparseable expiry rather than treating it as valid", async () => {
    // §5a: an unrecognised shape is refused, never read as "no expiry, therefore fine".
    const res = await refuse({ manifest: manifest({ expires: "not-a-date" }) });
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("unreachable");
    expect(res.reason).toBe("manifest_expired");
  });
});
