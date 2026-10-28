/**
 * M10E 011-CLAIM — the client half of writing and publishing a review.
 *
 * A customer who holds a RIGHT (005 lists them) writes the review. This module turns a right id plus
 * the reviewer's words into a canonical `AttestationPayload`, hands it to the sealed-submission path
 * as an `attest` op, and keeps the author's own encrypted-at-rest copy so `claimed` can show where it
 * got to. One right, one review, and the subject has NO refuse step — the directory mints it from the
 * stored service event (009) and single use is a unique index there.
 *
 * COUNTERBALANCE. The reviewer cannot invent a right: `claimRight` finds it in the directory's own
 * `listRights` answer (whose records this client re-hashes and trusts over the node's flags, 005),
 * and the directory re-derives the right from the stored service event before it will publish. A
 * rewritten client that fabricates a right id simply gets `no_such_right` from the directory. Nothing
 * here is trusted to assert a right into existence.
 *
 * Crypto: the payload is canonical CBOR (RFC 8949); signing + sealing happen in the submission path.
 */
import {
  attestationTemplateHash,
  decodeAttestationPayload,
  encodeAttestationPayload,
  type AttestationPayload,
} from "@cello-protocol/protocol-types";
import { extractErrorMessage } from "./error-message.js";
import { listRights, type ServiceEventDeps } from "./attestation-service-events.js";
import type { SubmissionResult } from "./signal-submission.js";
import type { Logger } from "./types.js";

const hexToBytes = (h: string): Uint8Array => new Uint8Array(Buffer.from(h, "hex"));

type Refusal = { ok: false; reason: string; guidance: string };

/** What the shared submission path returns, narrowed to what the claim needs from it. */
export interface ClaimSubmitResult {
  queued: boolean;
  retrying?: boolean;
  stored?: boolean;
  submissionId?: string;
  reason?: string;
  guidance?: string;
  storedWarning?: string;
}

export interface ClaimDeps {
  /** Lists the rights this agent holds — the ONLY source for the right, so a fabricated id cannot
   *  reach the wire. */
  svc: ServiceEventDeps;
  /** Compose → sign → seal → send an `attest` submission for the selected agent. Signing lives here,
   *  not in this module, and is already covered by the endorsement path's tests. */
  submitAttest: (subject: string, bodyHex: string) => Promise<ClaimSubmitResult>;
  /** Persist the author's own copy of the review. Keyed on the submission id by the caller. */
  storeLocalCopy: (args: { submissionId: string; rightId: string; subject: string; payload: Uint8Array; createdAt: number }) => void;
  now: () => number;
  logger: Logger;
}

export interface ClaimInput {
  rightId: string;
  rating?: number;
  text: string;
  originChannel?: string | null;
}

export type ClaimResult =
  | { ok: true; submissionId: string; namespace: string; subject: string; retrying: boolean; stored: boolean; guidance: string }
  | Refusal;

export async function claimRight(deps: ClaimDeps, input: ClaimInput): Promise<ClaimResult> {
  const wanted = input.rightId.toLowerCase();

  // THE RIGHT COMES FROM THE DIRECTORY, NOT FROM THE CALLER. A missing or expired right is refused
  // here, before anything is sent — but the directory re-checks both, so this is ergonomics, not the
  // guard (the guard is the directory rebuilding the right from the service event).
  const list = await listRights(deps.svc);
  if (!list.ok) return list;
  const right = list.rights.find((r) => r.right_id === wanted);
  if (!right) {
    return { ok: false, reason: "no_such_right", guidance: "No right with that id is listed for this agent. Run `cello attestations rights` to see the ones you hold — an expired right is listed and flagged, never hidden." };
  }
  if (right.expired) {
    return { ok: false, reason: "right_expired", guidance: `The right to review in '${right.namespace}' has expired, so no review can be written. The window is set by the namespace owner.` };
  }
  if (right.template === null) {
    return { ok: false, reason: "unknown_template", guidance: "This right names a template this client does not know. Upgrade @cello-protocol/connect and try again." };
  }
  if (right.template === "scored" && input.rating === undefined) {
    return { ok: false, reason: "rating_required", guidance: `'${right.namespace}' is a scored namespace, so the review needs a 1–5 rating. Pass --rating <1-5>.` };
  }

  // NFC-normalize the text so an honest review is not refused by the record encoder's not-NFC check,
  // and so two copies of the same review hash identically. The encoder is still the authority on
  // length, charset and rating range; this only spares a round trip (005/047 pattern).
  const text = input.text.normalize("NFC");
  const body: unknown[] = right.template === "scored" ? [input.rating, text] : [text];

  const payload: AttestationPayload = {
    right_id: hexToBytes(right.right_id),
    namespace: right.namespace,
    template_hash: attestationTemplateHash(right.template),
    session_id: hexToBytes(right.session_id),
    origin_channel: input.originChannel ?? null,
    body,
  };

  let payloadBytes: Uint8Array;
  try {
    payloadBytes = encodeAttestationPayload(payload);
  } catch (err: unknown) {
    // A bad rating or text (too long, non-printable) is the reviewer's own input — named, not a bare
    // code, so they can fix it.
    return { ok: false, reason: "invalid_review", guidance: `The review could not be encoded: ${extractErrorMessage(err)}` };
  }
  const bodyHex = Buffer.from(payloadBytes).toString("hex");

  const res = await deps.submitAttest(right.subject_pubkey, bodyHex);
  if (!res.queued && !res.retrying) {
    return { ok: false, reason: res.reason ?? "submit_failed", guidance: res.guidance ?? "The review was not submitted." };
  }
  const submissionId = res.submissionId;
  if (!submissionId) {
    return { ok: false, reason: "submit_no_id", guidance: "The submission path returned no handle, so nothing can be tracked. Run `cello attestations rights` and try again." };
  }

  // KEEP THE AUTHOR'S COPY. Stored on both the accepted and the still-retrying outcome, so the review
  // is visible in `claimed` the moment it is written — a retry that lands later is matched by its
  // content-derived submission id.
  deps.storeLocalCopy({
    submissionId,
    rightId: right.right_id,
    subject: right.subject_pubkey,
    payload: payloadBytes,
    createdAt: Math.floor(deps.now() / 1000),
  });

  return {
    ok: true,
    submissionId,
    namespace: right.namespace,
    subject: right.subject_pubkey,
    retrying: res.retrying === true,
    stored: res.stored === true,
    guidance: res.retrying
      ? `The review for '${right.namespace}' is held and will be sent when the directory is reachable; you do not need to run it again. Run \`cello attestations written\` to see where it got to. The subject cannot refuse it.`
      : res.storedWarning
        ? `Submitted the review for '${right.namespace}'. ${res.storedWarning}`
        : `Submitted the review for '${right.namespace}'. The portal scans and publishes it to the public store; the subject cannot refuse or withdraw it. Run \`cello attestations written\` to see the outcome.`,
  };
}

/** One local copy of a review, paired with the directory's outcome for it. */
export interface ClaimedCopy {
  submissionId: string;
  rightId: string;
  subject: string;
  payload: Uint8Array;
  createdAt: number;
}

export interface ClaimedView {
  submission_id: string;
  right_id: string;
  subject_pubkey: string;
  namespace: string;
  rating: number | null;
  text: string;
  created_at: number;
  /** The directory's verdict, or `pending` when no outcome has been returned yet. */
  outcome: string;
  reason: string | null;
}

export interface ClaimedDeps {
  loadLocalCopies: () => ClaimedCopy[];
  fetchResults: () => Promise<{ ok: true; results: SubmissionResult[] } | { ok: false; reason: string; guidance: string }>;
  logger: Logger;
}

export async function listClaimedAttestations(
  deps: ClaimedDeps,
): Promise<{ ok: true; claimed: ClaimedView[]; results_unavailable?: string }> {
  const copies = deps.loadLocalCopies();
  const res = await deps.fetchResults();
  const byId = new Map<string, SubmissionResult>();
  if (res.ok) for (const r of res.results) byId.set(r.submissionId, r);

  const claimed: ClaimedView[] = [];
  for (const c of copies) {
    let namespace = "";
    let rating: number | null = null;
    let text = "";
    try {
      const p = decodeAttestationPayload(c.payload);
      namespace = p.namespace;
      if (p.body.length === 2) {
        rating = typeof p.body[0] === "number" ? p.body[0] : null;
        text = typeof p.body[1] === "string" ? p.body[1] : "";
      } else if (p.body.length === 1) {
        text = typeof p.body[0] === "string" ? p.body[0] : "";
      }
    } catch (err: unknown) {
      // Never silently: the copy still shows, with the decode failure on the record.
      deps.logger.warn("attestation.claimed.undecodable", { submission_id: c.submissionId, reason: extractErrorMessage(err) });
    }
    const r = byId.get(c.submissionId);
    claimed.push({
      submission_id: c.submissionId,
      right_id: c.rightId,
      subject_pubkey: c.subject,
      namespace,
      rating,
      text,
      created_at: c.createdAt,
      // No outcome yet is `pending`, never a fabricated success — the review may still be in flight,
      // or the result may live on a node this read did not reach (see results_unavailable).
      outcome: r ? r.outcome : "pending",
      reason: r ? r.reason : null,
    });
  }

  return { ok: true, claimed, ...(res.ok ? {} : { results_unavailable: res.reason }) };
}
