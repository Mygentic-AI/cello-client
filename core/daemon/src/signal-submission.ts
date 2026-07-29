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
  | "manifest_expired"
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

/** Epoch millis, injectable so the expiry check is testable without waiting three weeks. */
export type NowMs = () => number;

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
  /** Injectable clock for the manifest-expiry gate. Defaults to `Date.now`. */
  nowMs?: NowMs;
}

/**
 * COMPILE-TIME GUARD for INV-ATTRIBUTION, and it lives HERE rather than in a test on purpose.
 *
 * The invariant is enforced by the ABSENCE of a parameter: `submitter_pubkey` is read from the
 * signing key provider, so a caller cannot name someone else because there is nowhere to put the
 * lie. No runtime test can observe that — an implementation of the form
 * `submitter_pubkey: opts.submitterPubkey ?? signerPubkey` passes every attribution test in the
 * suite, because no test supplies an override. It is a property of the TYPE, so it is pinned at
 * compile time or not at all.
 *
 * And it cannot be pinned from a test file: `core/daemon/tsconfig.json` EXCLUDES `src/__tests__`, so
 * a `@ts-expect-error` there is never evaluated and asserts nothing — a hollow test wearing
 * compile-time clothing. This file is in `include`, so this one really does fail the build.
 *
 * Add a submitter-identity field to `ComposeSubmissionOptions` and the assignment below stops
 * compiling.
 */
type NoSubmitterIdentityOverride =
  Extract<keyof ComposeSubmissionOptions, "submitterPubkey" | "submitter_pubkey" | "submitterKey" | "issuerPubkey"> extends never
    ? true
    : "INV-ATTRIBUTION: ComposeSubmissionOptions must never accept a caller-supplied submitter identity";
const INV_ATTRIBUTION_NO_OVERRIDE: NoSubmitterIdentityOverride = true;
void INV_ATTRIBUTION_NO_OVERRIDE;

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

  // THE MANIFEST IS A STARTUP SNAPSHOT, AND ITS VALIDITY IS TIME-LIMITED.
  //
  // `verifyStartupManifest` checked the signatures, the window and the anti-rollback ONCE, at daemon
  // start, and the daemon then holds that object for its whole lifetime — nothing refreshes it. So
  // the startup gate's guarantee decays: three weeks later the window may have closed and the portal
  // may have rotated the intake key, while this code would still happily seal to the retired one.
  //
  // The operator would be told the message was sent. The portal could not open it. By this module's
  // own definition that arrives as unattributable POISON with no reply possible — the message simply
  // vanishes, with no error anywhere. An EXPIRED input is an UNVERIFIED input (§5a), so it refuses
  // and names the cause rather than trusting a check whose expiry has passed.
  const now = (opts.nowMs ?? Date.now)();
  const expiresAt = Date.parse(manifest.expires);
  if (!Number.isFinite(expiresAt) || expiresAt <= now) {
    logger.warn("signal.submission.refused", {
      reason: "manifest_expired",
      manifestVersion: manifest.version,
      expiresAt: manifest.expires,
      op: opts.op,
    });
    return {
      ok: false,
      reason: "manifest_expired",
      guidance:
        `The consortium manifest verified at daemon start (v${manifest.version}) expired at ` +
        `${manifest.expires}, so its portal intake key can no longer be trusted — sealing to a ` +
        "retired key produces a message the portal cannot open and cannot even attribute. " +
        "Restart the daemon to load and verify a current manifest, then retry.",
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

// ─── The send ────────────────────────────────────────────────────────────────────────────────────

/**
 * Why a submission did not reach a directory node. Distinct from the compose-time refusals: those
 * mean nothing was built, these mean nothing was accepted.
 */
export type SubmissionSendFailure =
  | "directory_unreachable"
  | "submission_write_timeout"
  | "submission_unsupported_by_node"
  | "submission_refused_by_node"
  // The two the TRANSPORT returns. They were missing while the code cast `sent.reason` into this
  // union, which made the declared type a lie a consumer could branch on: an operator surface that
  // switched on this union would have no case for either of the values it most often receives.
  | "signaling_reconnecting"
  | "signaling_lost";

export type SendSubmissionResult =
  | {
      ok: true;
      submissionId: string;
      /**
       * Whether the node actually STORED the row, straight from `enqueueSubmission`'s boolean.
       *
       * `false` means an id was already present. That is USUALLY this submitter's own retry — which
       * is what makes retry-across-nodes safe — but it is also the shape of a single-node censorship
       * attack: `submission_id` is visible in the clear to the receiving node, so a malicious
       * operator can copy it and pre-insert garbage under the same id at the other nodes, and every
       * retry then resolves to "already present". Collapsing the two into plain success destroys the
       * only information that could ever distinguish them.
       */
      stored: boolean;
    }
  | { ok: false; reason: SubmissionSendFailure; guidance: string };

/** The minimum of `SignalingManager` this needs — narrow, so a test drives it without a transport. */
export interface SubmissionSignaling {
  sendRaw(frame: unknown): Promise<{ ok: boolean; reason?: string; guidance?: string }>;
  registerInboundHandler(handler: (frame: Record<string, unknown>) => void): () => void;
}

const DEFAULT_ACK_TIMEOUT_MS = 15_000;

/**
 * Hand a sealed submission to the directory node this agent is connected to, and await its ack.
 *
 * ONE node, deliberately. The daemon holds a single signaling stream, and registration already works
 * this way — it sends `register_request` to the connected node and the DIRECTORY fans out to the
 * quorum. There is no client-side multi-node write path, and inventing one here would duplicate the
 * SignalingManager's reconnect. So "failover" for a submission is that existing reconnect, and a
 * retry afterwards is safe because `submission_id` is content-derived: the same body produces the
 * same id, so a second node stores it once and the portal mints once (M10B-D20, M10B-D21).
 */
export async function sendSealedSubmission(deps: {
  signaling: SubmissionSignaling;
  submissionId: string;
  intakeKeyId: string;
  ciphertext: Uint8Array;
  logger: Logger;
  timeoutMs?: number;
}): Promise<SendSubmissionResult> {
  const { signaling, submissionId: id, intakeKeyId, ciphertext, logger } = deps;
  const timeoutMs = deps.timeoutMs ?? DEFAULT_ACK_TIMEOUT_MS;

  // Advisory only — see the handler. Never resolves the send; it sharpens the TIMEOUT's diagnosis.
  let sawNotAuthenticated = false;
  let resolveFrame!: (f: Record<string, unknown>) => void;
  const pending = new Promise<Record<string, unknown>>((r) => { resolveFrame = r; });
  const unregister = signaling.registerInboundHandler((frame) => {
    const t = frame["type"];
    // A result for a DIFFERENT submission must be ignored: the handler sees every frame on a shared
    // stream, and accepting someone else's ack would report success for a write that never happened.
    // EVERY resolve path is id-gated. The handler sees every frame on a SHARED stream, so an
    // ungated one resolves this submission with someone else's outcome — and two concurrent
    // submissions is not an exotic case, it is the second endorsement.
    if (t === "submission_write_result" && frame["submission_id"] === id) resolveFrame(frame);
    else if (t === "submission_write_error" && frame["submission_id"] === id) resolveFrame(frame);
    // `not_authenticated` is DELIBERATELY NOT a resolve path. An older node replies it when its
    // decoder returns null (M10B-D25r), so it is the version-skew symptom — but it is also what the
    // node sends for a frame that arrives before auth completes, and for ANY other component's
    // undecodable frame on this same stream. Resolving on it would let an unrelated
    // `manifest_poll_request` to an older node report THIS submission as unsupported, while the real
    // result arrives afterwards and is dropped on the floor. It is recorded as advisory context and
    // the timeout decides.
    else if (t === "not_authenticated") sawNotAuthenticated = true;
  });

  try {
    const sent = await signaling.sendRaw({
      type: "submission_write",
      submission_id: id,
      intake_key_id: intakeKeyId,
      ciphertext,
    });
    if (!sent.ok) {
      // The reason CODE carries the transport's own cause when it has one. `directory_unreachable`
      // is an exit-point label — a machine consumer branching on it cannot tell "reconnecting" from
      // "lost", and those want different operator actions.
      const cause = sent.reason ?? "directory_unreachable";
      logger.warn("signal.submission.refused", { submissionId: id, reason: cause });
      return {
        ok: false,
        reason: cause as SubmissionSendFailure,
        // STATED AS IT IS: this submission was NOT delivered and NOTHING here retries it. An earlier
        // draft said "it was not lost", which asserted a retry no code performs — the caller would
        // have to re-invoke, and until DOD-END-SURFACE-1 there is no caller at all. What IS true is
        // that re-submitting is SAFE, which is a different claim.
        guidance:
          `The submission was NOT handed to a directory node (${cause}) and nothing has retried it. ` +
          "Re-submitting is safe: it produces the SAME submission_id, so the retry is stored once, " +
          "not twice.",
      };
    }

    let timer!: ReturnType<typeof setTimeout>;
    const timeout = new Promise<Record<string, unknown>>((r) => {
      timer = setTimeout(() => r({ type: "__timeout__" }), timeoutMs);
    });
    const frame = await Promise.race([pending, timeout]);
    clearTimeout(timer);

    if (frame["type"] === "__timeout__") {
      // F2: NAME THE AMBIGUITY RATHER THAN RESOLVING IT. `not_authenticated` has THREE producers on
      // the directory side — an undecodable frame from a node that has not deployed this frame kind
      // (the version-skew case), an undecodable frame from a node that HAS (i.e. our own bug: a
      // malformed id or an empty ciphertext), and a frame that genuinely arrived before auth
      // completed. An earlier draft asserted the first with certainty and told the operator it was
      // "NOT an authentication problem" — which, in the third case, sends them away from the actual
      // cause and towards a deploy that will never fix it.
      const reason = sawNotAuthenticated ? "submission_unsupported_by_node" : "submission_write_timeout";
      logger.warn("signal.submission.refused", { submissionId: id, reason, timeoutMs, sawNotAuthenticated });
      return {
        ok: false,
        reason,
        guidance: sawNotAuthenticated
          ? "The directory node did not recognise the frame and never acknowledged the submission. " +
            "MOST LIKELY it has not deployed submission support yet — nodes deploy independently per " +
            "region, so check this node's version first. Two other conditions produce the same reply: " +
            "a malformed submission from this client, and a frame rejected because authentication had " +
            "not completed (if the signaling stream also dropped, look there). Re-submitting is safe."
          : `The directory node accepted the frame but did not acknowledge the submission within ${timeoutMs}ms. ` +
            "Whether it was stored is unknown; re-submitting is safe (same submission_id, stored once).",
      };
    }

    if (frame["type"] === "submission_write_error") {
      const reason = typeof frame["reason"] === "string" ? frame["reason"] : "unspecified";
      logger.warn("signal.submission.refused", { submissionId: id, reason: "submission_refused_by_node", nodeReason: reason });
      return {
        ok: false,
        reason: "submission_refused_by_node",
        // The upstream reason SURVIVES into the payload rather than being flattened into this
        // function's own exit label (§5b).
        guidance: `The directory node refused the submission: ${reason}.`,
      };
    }

    const stored = frame["stored"] === true;
    logger.info(stored ? "signal.submission.queued" : "signal.submission.duplicate", {
      submissionId: id,
      intakeKeyId,
      stored,
    });
    return { ok: true, submissionId: id, stored };
  } finally {
    unregister();
  }
}
