/**
 * DOD-DOC-TOOLS-1 — the document CONTROL frame: close and kill (§16.5).
 *
 * A unilateral end, told to the other party.
 *
 * ── WHY THE PEER MUST BE TOLD, AND WHY IT IS BEST-EFFORT ──────────────────────────────────────
 *
 * `DocumentLifecycle` already ends a document locally without asking anyone — that is deliberate: a
 * kill is a safety verb, and a safety verb that needs the counterparty's cooperation is not one. But
 * a peer who is never told keeps publishing into a document that will never answer. Their updates
 * are refused at the far end forever, and nothing on their screen explains why. So the notification
 * is REQUIRED to be attempted and ALLOWED to fail, and the operator is told which happened.
 *
 * ── CLOSE AND KILL ARE DIFFERENT FRAMES OF THE SAME SHAPE ─────────────────────────────────────
 *
 * `close` is "I am done with this, and I expect you are too" — the document settles when both sides
 * have said it. `kill` is "this is over now", one-sided and immediate. They travel as one frame with
 * a verb rather than two types because the receiving side's routing, verification and settle-once
 * rules are identical, and two decoders for one shape is how the rules drift apart.
 *
 * The verb is REFUSED BY VALUE on decode. A third verb from a future build must not be admitted as
 * one of these two — a `kill` silently read as a `close` would leave a killed document waiting for
 * a reciprocal close that is never coming.
 *
 * ── WHY IT IS SIGNED ──────────────────────────────────────────────────────────────────────────
 *
 * A kill frame ends a collaboration. Unsigned, anyone reaching the channel could end any document
 * between any two parties, and each operator would believe the other walked away. The signature
 * covers the document id — which commits to both parties, the properties and the nonce — and the
 * verb, because the whole statement is the claim.
 */

import { createHash } from "node:crypto";
import { encodeCbor, decodeCbor } from "./cbor.js";

/** Domain tag in slot 0. Distinct from every other document domain. */
export const DOCUMENT_CONTROL_DOMAIN = "CELLO-DOCUMENT-CONTROL-v1";

/** The frame version, ON THE WIRE, so skew is DETECTED rather than misread as a bad signature. */
export const DOCUMENT_CONTROL_VERSION = 1;

/** Peer-controlled display text bound for an operator's screen. Capped for that reason. */
export const MAX_CONTROL_REASON_LENGTH = 200;

/** The two ways a document ends. Closed set — see the header on refusing a third by value. */
export const DOCUMENT_CONTROL_VERBS = ["close", "kill"] as const;
export type DocumentControlVerb = (typeof DOCUMENT_CONTROL_VERBS)[number];

const HEX32 = /^[0-9a-f]{64}$/;

export interface DocumentControl {
  type: "document_control";
  control_version: number;
  document_id: string;
  /** Who is ending it. */
  sender_agent_id: string;
  verb: DocumentControlVerb;
  /** Optional, and optional for both verbs — an end is a decision, not something one must justify. */
  reason?: string;
  sent_at_ms: number;
  /** Ed25519 (RFC 8032) over `buildDocumentControlTbs`. */
  signature: Uint8Array;
}

function normalizeReason(reason: string | undefined): string | null {
  return reason === undefined || reason === "" ? null : reason;
}

export function assertDocumentControlConsistent(control: DocumentControl): void {
  if (!(DOCUMENT_CONTROL_VERBS as readonly string[]).includes(control.verb)) {
    throw new Error(
      `document_control_verb: expected one of ${DOCUMENT_CONTROL_VERBS.join(", ")}, got "${control.verb}"`,
    );
  }
  if (!HEX32.test(control.document_id)) {
    throw new Error("document_control_document_id: expected 64 lowercase hex characters");
  }
  const reason = normalizeReason(control.reason);
  if (reason !== null && reason.length > MAX_CONTROL_REASON_LENGTH) {
    throw new Error(
      `document_control_reason: a reason may be at most ${MAX_CONTROL_REASON_LENGTH} characters, ` +
        `and this one is ${reason.length}`,
    );
  }
}

/**
 * The canonical to-be-signed preimage: a fixed-order CBOR ARRAY with the domain in slot 0.
 *
 * An array rather than a map for the reason `cbor.ts` gives — this encoder is deliberately not
 * deterministic for maps, so a map preimage would make the signature depend on the order the sender
 * happened to build the object in, and two honest implementations would disagree.
 */
export function buildDocumentControlTbs(
  control: DocumentControl,
  opts: { preHash?: boolean } = {},
): Uint8Array {
  assertDocumentControlConsistent(control);
  const preimage = encodeCbor([
    DOCUMENT_CONTROL_DOMAIN,
    control.control_version,
    control.document_id,
    control.sender_agent_id,
    // THE VERB IS SIGNED. Unsigned, a captured `close` could be replayed as a `kill` — the peer
    // would end a collaboration the sender only meant to wind down, with a valid signature on it.
    control.verb,
    normalizeReason(control.reason),
    // BIGINT past 0xffffffff — cbor-x encodes a large JS number as IEEE float64 (`fb`) rather than
    // uint64 (`1b`), so a canonically-encoding implementation would compute different TBS bytes and
    // reject a GENUINE frame, surfacing as a signature failure that reads as forgery.
    typeof control.sent_at_ms === "number" && control.sent_at_ms > 0xffffffff
      ? BigInt(control.sent_at_ms)
      : control.sent_at_ms,
  ]);
  if (opts.preHash === false) return preimage;
  return new Uint8Array(createHash("sha256").update(preimage).digest());
}

export function encodeDocumentControl(control: DocumentControl): Uint8Array {
  assertDocumentControlConsistent(control);
  return encodeCbor({
    type: control.type,
    control_version: control.control_version,
    document_id: control.document_id,
    sender_agent_id: control.sender_agent_id,
    verb: control.verb,
    reason: normalizeReason(control.reason),
    sent_at_ms: control.sent_at_ms,
    signature: control.signature,
  });
}

function present(map: Record<string, unknown>, field: string): unknown {
  if (!(field in map)) {
    throw new Error(`document_control_missing_field: ${field} is mandatory and was not present`);
  }
  return map[field];
}

/**
 * Decode and validate. Refuses rather than defaulting on every field.
 *
 * The one that matters most is `verb`. Defaulted or coerced, a `kill` read as a `close` leaves a
 * killed document waiting for a reciprocal close that is never coming — the operator sees a
 * collaboration that will not settle and no reason anywhere for why.
 */
export function decodeDocumentControl(bytes: Uint8Array): DocumentControl {
  const decoded = decodeCbor(bytes);
  if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) {
    throw new Error("document_control_malformed: not a CBOR map");
  }
  const map = decoded as Record<string, unknown>;

  if (present(map, "type") !== "document_control") {
    throw new Error("document_control_type: expected document_control");
  }
  const version = present(map, "control_version");
  if (typeof version !== "number" || !Number.isInteger(version)) {
    throw new Error("document_control_version: must be an integer");
  }
  if (version !== DOCUMENT_CONTROL_VERSION) {
    throw new Error(
      `document_control_version_unsupported: this build speaks version ${DOCUMENT_CONTROL_VERSION} ` +
        `and the frame declares ${version} — the peer is running a newer CELLO and one of you needs ` +
        `to upgrade`,
    );
  }
  const documentId = present(map, "document_id");
  if (typeof documentId !== "string" || !HEX32.test(documentId)) {
    throw new Error("document_control_document_id: expected 64 lowercase hex characters");
  }
  const senderAgentId = present(map, "sender_agent_id");
  if (typeof senderAgentId !== "string" || senderAgentId.length === 0) {
    throw new Error("document_control_sender: must be a non-empty string");
  }
  const verb = present(map, "verb");
  if (typeof verb !== "string" || !(DOCUMENT_CONTROL_VERBS as readonly string[]).includes(verb)) {
    // REFUSED BY VALUE. A third verb from a future build must not be admitted as one of these two.
    throw new Error(
      `document_control_verb_unsupported: this build understands ` +
        `${DOCUMENT_CONTROL_VERBS.join(" and ")}, and the frame says "${String(verb)}" — the peer is ` +
        `running a newer CELLO and one of you needs to upgrade`,
    );
  }
  const reason = present(map, "reason");
  if (reason !== null && typeof reason !== "string") {
    throw new Error("document_control_reason: must be a string or null");
  }
  const sentAt = present(map, "sent_at_ms");
  if (typeof sentAt !== "number" || !Number.isFinite(sentAt)) {
    throw new Error("document_control_sent_at: must be a finite number");
  }
  const signature = present(map, "signature");
  if (!(signature instanceof Uint8Array) || signature.length !== 64) {
    throw new Error("document_control_signature: expected 64 bytes");
  }

  const control: DocumentControl = {
    type: "document_control",
    control_version: version,
    document_id: documentId,
    sender_agent_id: senderAgentId,
    verb: verb as DocumentControlVerb,
    ...(reason !== null && reason !== "" ? { reason } : {}),
    sent_at_ms: sentAt,
    // COPIED out of the decode buffer — cbor-x returns byte strings as VIEWS into the input, so
    // retaining one pins the whole frame and lets a later reuse mutate a verified signature.
    signature: Uint8Array.from(signature),
  };
  assertDocumentControlConsistent(control);
  return control;
}
