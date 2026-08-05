/**
 * DOD-DOC-INBOUND-2 — routing an arriving session frame to the document layer.
 *
 * Document traffic and conversation traffic share the session content channel, so something has to
 * decide which is which. That decision has consequences beyond dispatch, and they are the reason
 * this is a unit rather than an `if` at the call site:
 *
 *   - A document frame is NOT a transcript message. Recording one would put CRDT bytes into the
 *     operator's conversation history, where `cello_receive` would hand them to an agent as
 *     something a person said.
 *   - A document frame raises NO DOORBELL (§11.3 — doorbell-on-update is parked). A collaborator
 *     typing produces a stream of updates, and a doorbell per update would interrupt the operator's
 *     agent continuously for something with no deadline.
 *   - A document frame is still a LEAF. The seal covers it as a `0x04` doc-op leaf; that is what
 *     makes the exchange provable. Consuming a frame means "do not treat this as conversation", not
 *     "pretend it did not arrive".
 *
 * ── CLASSIFICATION IS BY DECODE, BEHIND A STRUCTURAL GUARD ────────────────────────────────────
 *
 * A frame is a document frame iff it DECODES as one. No content heuristic, no first-byte guess
 * about what the bytes mean — the same reasoning that made the update envelope carry its encoding
 * explicitly rather than let a decoder infer it. Anything that does not decode is conversation,
 * which is the safe direction: a misrouted document frame lands in a transcript where it is
 * visible, while a misrouted MESSAGE would vanish into the document layer and never reach the
 * operator.
 *
 * A CONVERSATION MESSAGE CANNOT REACH A DECODER AT ALL, and the reason is structural rather than
 * statistical. Both halves verified here, not assumed:
 *
 *   - `couldBeDocumentFrame` requires byte 0 in `0xa0`–`0xb9`, and NONE of those can begin a valid
 *     UTF-8 sequence — they are all continuation bytes (checked against a fatal `TextDecoder`).
 *   - A legitimate message IS UTF-8, by construction rather than by convention: the send path
 *     encodes it with `new TextEncoder().encode(...)` (`session-content-handlers.ts`), and there is
 *     no binary-content path that could produce some other first byte.
 *
 * So no text an operator types, and no text an attacker persuades them to send, is ever classified
 * as a document frame. (A hostile PEER can put raw non-UTF-8 bytes on the channel and have them
 * classified as document traffic — but that only suppresses their own message.)
 *
 * ── THE HEADER GUARD IS A FAST PATH, NOT THE SECURITY BOUNDARY ────────────────────────────────
 *
 * Handing hostile bytes to a CBOR decoder is a denial of service — measured at seconds and
 * gigabytes for a few bytes — and `classify` runs on EVERY inbound frame, so a peer could stall or
 * OOM the daemon's whole content path and stop the operator's ordinary MESSAGES.
 *
 * `couldBeDocumentFrame` was written as the fix and IS NOT ONE. It inspects the header, and the cost
 * lives in structures NESTED inside it: `a1 9f` — a one-pair map whose first key is an
 * indefinite-length array — is three bytes, passes any header check, and cost 9.6 seconds and
 * 1.1 GB. Prefixing the real frames' own `b9 000a` does the same. No header-shaped guard can be
 * sound here.
 *
 * The bound belongs on the DECODER, and it is now in `cbor.ts` — see the note there. This guard
 * stays because it is a correct, cheap fast path that keeps every conversation message out of the
 * decoder entirely, and because the UTF-8 argument above depends on it. It must never again be
 * described as what makes hostile input safe.
 */

import {
  decodeDocumentUpdateEnvelope,
  decodeDocumentAck,
} from "@cello-protocol/protocol-types";
import type { DocumentInbound } from "./document-inbound.js";
import type { DocumentAckInbound } from "./document-ack-inbound.js";
import type { Logger } from "./types.js";

/**
 * What the session layer should do with the frame.
 *
 * `consumed: false` means "this is not document traffic" — the caller records it as a transcript
 * message and fires the doorbell exactly as before. Nothing about the conversation path changes.
 */
export type FrameRouting =
  | { consumed: false }
  | { consumed: true; kind: "update" | "ack"; ok: boolean; reason?: string };

export interface DocumentFrameRouterDeps {
  inbound: DocumentInbound;
  ackInbound: DocumentAckInbound;
  logger: Logger;
}

export class DocumentFrameRouter {
  readonly #d: DocumentFrameRouterDeps;

  constructor(deps: DocumentFrameRouterDeps) {
    this.#d = deps;
  }

  /**
   * Classify and dispatch. Returns whether the document layer consumed the frame.
   *
   * NEVER THROWS. A throw here would escape into the session content path and take down message
   * delivery for the whole session — conversation traffic failing because a document frame was
   * malformed. A document frame that cannot be handled is consumed and reported; the session keeps
   * running.
   */
  route(
    ownerAgentId: string,
    content: Uint8Array,
    nowMs: number,
    correlationId: string,
  ): FrameRouting {
    const kind = classify(content);
    if (kind === null) return { consumed: false };

    try {
      if (kind === "update") {
        const res = this.#d.inbound.receive(ownerAgentId, content, nowMs, correlationId);
        return { consumed: true, kind, ok: res.ok, reason: res.ok ? undefined : res.reason };
      }
      const res = this.#d.ackInbound.receive(ownerAgentId, content, nowMs, correlationId);
      return { consumed: true, kind, ok: res.ok, reason: res.ok ? undefined : res.reason };
    } catch (err: unknown) {
      // Contained deliberately. The document layer refuses by returning a verdict, so reaching here
      // is a programming fault — and the cost of letting it escape is that a peer could stop the
      // operator's MESSAGES from being delivered by sending one bad document frame.
      this.#d.logger.error("document.frame.handler_threw", {
        kind,
        correlationId,
        reason: err instanceof Error ? err.message : String(err),
      });
      return { consumed: true, kind, ok: false, reason: "document_frame_handler_threw" };
    }
  }
}

/**
 * The largest field count a document frame can declare. The update envelope has 10 fields and the
 * ack has 9; the bound is generous so a future field does not silently start routing frames to the
 * transcript, and tight enough that a map header claiming millions of pairs never reaches a decoder.
 */
const MAX_DOCUMENT_FRAME_FIELDS = 32;

/**
 * Could these bytes be a document frame at all — cheaply, and without decoding?
 *
 * The decoders' own first requirement is "a definite-length CBOR map"; this is that requirement,
 * checked on the header instead of after the damage. Note the real frames begin `b9 00 0a` — a
 * NON-MINIMAL two-byte count, which `cbor.ts` documents as this encoder's deliberate behaviour — so
 * the 1- and 2-byte count forms must be admitted. The 4- and 8-byte forms are refused outright: no
 * document frame has four billion fields, and those are precisely the headers that let a few bytes
 * ask for an enormous allocation.
 */
function couldBeDocumentFrame(b: Uint8Array): boolean {
  const header = b[0];
  if (header === undefined) return false;
  // 0xa0..0xb7 — map with the pair count inline (0..23).
  if (header >= 0xa0 && header <= 0xb7) return true;
  // 0xb8 / 0xb9 — map with a 1- or 2-byte pair count, which is what this encoder emits.
  if (header === 0xb8) return b.length >= 2 && b[1]! <= MAX_DOCUMENT_FRAME_FIELDS;
  if (header === 0xb9) {
    return b.length >= 3 && ((b[1]! << 8) | b[2]!) <= MAX_DOCUMENT_FRAME_FIELDS;
  }
  // Everything else — including 0xbf (indefinite-length map) and 0x9f (indefinite-length ARRAY,
  // the header in both measured pathological inputs) — is not a document frame.
  return false;
}

/**
 * `"update"`, `"ack"`, or `null` for "not document traffic".
 *
 * Guarded, then decode-based. The two document types are tried in turn and the first that decodes
 * wins; both decoders check a `type` discriminator before anything else, so neither can claim the
 * other's frame. A conversation message is arbitrary operator text and will not decode as either.
 */
function classify(content: Uint8Array): "update" | "ack" | null {
  if (!couldBeDocumentFrame(content)) return null;
  try {
    decodeDocumentUpdateEnvelope(content);
    return "update";
  } catch {
    // Not an update. Deliberately silent: every conversation message reaches this line, and logging
    // here would put one line per message into the daemon log for the ordinary case.
  }
  try {
    decodeDocumentAck(content);
    return "ack";
  } catch {
    // Not document traffic at all.
  }
  return null;
}
