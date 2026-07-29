/**
 * M10B / DOD-END-SUBMIT-1 — the daemon side of the sealed submission queue (M10B-D2).
 *
 * Bob's daemon composes a submission, signs it with his agent's K_local, and seals it to the
 * portal's intake key. A directory node then carries a blob it cannot read until the portal drains
 * it. **The daemon never talks to the portal** — that is the decision this whole path exists to
 * honour, and it is what keeps a later move to per-node intake a routing change rather than a
 * migration of every installed client.
 *
 * WHAT THIS MODULE IS RESPONSIBLE FOR, and why it is separable from the send: everything here is
 * pure given its inputs, and it is where the invariants live. The transport can retry, fail over, or
 * be replaced; none of that can make an unsealed blob safe or a forged attribution valid.
 *
 *   INV-ATTRIBUTION — `submitter_pubkey` is read from the SIGNING key provider, and there is no
 *                     parameter to override it. A caller cannot name someone else, because the field
 *                     is not an input. Precedent: `accepting_node` in DOD-DIR-WRITE-1, "written by
 *                     the node itself, never accepted from the request".
 *   INV-CONSENT     — the plaintext is sealed to the intake key before it ever reaches the
 *                     directory, so a node operator learns nothing about who endorsed whom.
 *   §5a ABSENT      — a missing OR malformed intake key REFUSES, with the reason named. There is no
 *                     code path here that emits an unsealed submission; that is a structural
 *                     property of this file, not a policy someone remembered to apply.
 *
 * Crypto: Ed25519 → RFC 8032, CBOR → RFC 8949, SHA-256 → FIPS 180-4.
 */

import { sealToRecipient } from "@cello-protocol/crypto";
import type { KeyProvider } from "@cello-protocol/crypto";
import {
  buildSubmissionTbs,
  encodeSubmission,
  submissionId,
  type ConsortiumManifest,
  type SignalSubjectKind,
  type SubmissionBody,
  type SubmissionOp,
} from "@cello-protocol/protocol-types";
import type { Logger } from "./types.js";

/** The wire version this daemon emits. Signed, so it cannot be downgraded in flight. */
const SUBMISSION_VERSION = 1;

/** Ed25519 public keys are 32 bytes — 64 lowercase hex characters. */
const INTAKE_PUBKEY_RE = /^[0-9a-f]{64}$/;

/**
 * Why a submission was refused BEFORE anything was sealed or sent.
 *
 * Each names a cause, never an exit point (§5b). `submission_refused` would tell an operator only
 * that something went wrong; these tell them which subsystem to look at — and for the intake-key
 * cases the answer is "the consortium manifest", which they would never guess.
 */
export type SubmissionRefusalReason =
  | "manifest_unavailable"
  | "intake_key_absent"
  | "intake_key_malformed";

export type ComposeSubmissionResult =
  | {
      ok: true;
      /** sha256 of the signed submission body — content-derived, so a retry to another node dedupes
       *  at the portal instead of minting twice (M10B-D20). */
      submissionId: string;
      /** Which intake key this was sealed to. Recorded on the queue row so the portal can retain a
       *  rotated-out private key until no undrained row references it (M10B-D11). */
      intakeKeyId: string;
      /** The sealed blob. Opaque to the directory. */
      ciphertext: Uint8Array;
    }
  | { ok: false; reason: SubmissionRefusalReason; guidance: string };

export interface ComposeSubmissionOptions {
  /** The VERIFIED consortium manifest, or null if none is loaded. Officer-signed, which is why it is
   *  an acceptable channel for a sealing key — see `intake_key`'s note in protocol-types. */
  manifest: ConsortiumManifest | null;
  /** The submitting agent's K_local. Its public half becomes `submitter_pubkey`; there is
   *  deliberately no way to pass that in separately. */
  keyProvider: KeyProvider;
  op: SubmissionOp;
  subjectKind: SignalSubjectKind;
  /** The subject's K_local pubkey hex for an agent subject; the target signal hash for a withdrawal.
   *  No account identifier ever crosses the wire — the portal resolves agent → account at intake. */
  subject: string;
  /** The operator's own words. Untrusted, and scanned at intake BEFORE hashing — never here: a
   *  client-side scan is advice, not a control, since the client is the thing being defended against. */
  body: string;
  /** Integer epoch SECONDS. Inside the signed body, so the verifier's clock-skew bound applies. */
  issuedAt: number;
  logger: Logger;
}

/**
 * Compose → sign → seal. Returns the exact three values a queue row needs, or a named refusal.
 *
 * Note what this function does NOT do: it does not send, and it does not scan. Sending is the
 * caller's, so a failed node is a retry rather than a re-sign. Scanning is the PORTAL's (spec §7,
 * `DOD-END-SCAN-1`) — scanning here would be theatre, because the operator's own daemon is the
 * party whose content is in question.
 */
export async function composeSealedSubmission(
  opts: ComposeSubmissionOptions,
): Promise<ComposeSubmissionResult> {
  const { manifest, keyProvider, logger } = opts;

  if (!manifest) {
    logger.warn("signal.submission.refused", {
      reason: "manifest_unavailable",
      op: opts.op,
      subjectKind: opts.subjectKind,
    });
    return {
      ok: false,
      reason: "manifest_unavailable",
      guidance:
        "No verified consortium manifest is loaded, so the portal's intake key is unknown. " +
        "A submission is never sent unsealed. Check the daemon's manifest configuration and retry.",
    };
  }

  const intakeKey = manifest.intake_key;
  if (!intakeKey) {
    logger.warn("signal.submission.refused", {
      reason: "intake_key_absent",
      manifestVersion: manifest.version,
      op: opts.op,
    });
    return {
      ok: false,
      reason: "intake_key_absent",
      guidance:
        `Consortium manifest v${manifest.version} publishes no portal intake key, so this submission ` +
        "cannot be sealed. It is NOT sent unsealed — the directory must not be able to read it. " +
        "This needs a manifest that carries `intake_key`.",
    };
  }

  // Malformed is refused for the same reason absent is. Sealing to a non-key produces a blob nobody
  // can open, which reaches the portal as unattributable POISON with no reply possible (M10B-D22b) —
  // so the operator would watch the submission vanish with no error anywhere. Uppercase hex is
  // refused rather than lowercased: the key_id/pubkey pair comes from a SIGNED document, and quietly
  // repairing a signed value hides a manifest-generation bug instead of surfacing it.
  if (!intakeKey.key_id || !INTAKE_PUBKEY_RE.test(intakeKey.pubkey ?? "")) {
    logger.warn("signal.submission.refused", {
      reason: "intake_key_malformed",
      manifestVersion: manifest.version,
      keyId: intakeKey.key_id,
      op: opts.op,
    });
    return {
      ok: false,
      reason: "intake_key_malformed",
      guidance:
        `Consortium manifest v${manifest.version} carries an unusable intake key ` +
        `(key_id: ${JSON.stringify(intakeKey.key_id)}) — the pubkey must be a 32-byte Ed25519 key as ` +
        "64 lowercase hex characters. Refusing rather than sealing to an unopenable value.",
    };
  }

  // INV-ATTRIBUTION: taken from the signer, never from a parameter.
  const submitterPubkey = Buffer.from(await keyProvider.getPublicKey()).toString("hex");

  const body: SubmissionBody = {
    v: SUBMISSION_VERSION,
    op: opts.op,
    subject_kind: opts.subjectKind,
    subject: opts.subject,
    submitter_pubkey: submitterPubkey,
    body: opts.body,
    issued_at: opts.issuedAt,
  };

  const signature = await keyProvider.sign(buildSubmissionTbs(body));
  const encoded = encodeSubmission(body, signature);
  // Derived from the PLAINTEXT submission, not the ciphertext. Sealing is randomised, so a
  // ciphertext-derived id would change on every re-seal and a failover retry would look like a
  // second submission — two mints, double quota consumption.
  const id = submissionId(encoded);
  const ciphertext = sealToRecipient(Buffer.from(intakeKey.pubkey, "hex"), encoded);

  logger.info("signal.submission.sealed", {
    submissionId: id,
    intakeKeyId: intakeKey.key_id,
    op: opts.op,
    subjectKind: opts.subjectKind,
    manifestVersion: manifest.version,
    // The body is NEVER logged — it is the operator's own words about a third party, and this log
    // line would be the one place it existed in the clear on disk.
    bodyBytes: Buffer.byteLength(opts.body, "utf8"),
  });

  return { ok: true, submissionId: id, intakeKeyId: intakeKey.key_id, ciphertext };
}
