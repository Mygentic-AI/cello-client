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
 * ── CLASSIFICATION IS BY DECODE, NOT BY SNIFFING ──────────────────────────────────────────────
 *
 * A frame is a document frame iff it decodes as one. No first-byte heuristic, no length check, no
 * "starts with a CBOR map" guess — the same reasoning that made the update envelope carry its
 * encoding explicitly rather than let a decoder infer it. Anything that does not decode is
 * conversation, which is the safe direction: a misrouted document frame lands in a transcript and is
 * visible; a misrouted MESSAGE would vanish into the document layer and never reach the operator.
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
 * `"update"`, `"ack"`, or `null` for "not document traffic".
 *
 * Decode-based. The two document types are tried in turn and the first that decodes wins; both
 * decoders check a `type` discriminator before anything else, so neither can claim the other's
 * frame. A conversation message is arbitrary operator text and will not decode as either.
 */
function classify(content: Uint8Array): "update" | "ack" | null {
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
