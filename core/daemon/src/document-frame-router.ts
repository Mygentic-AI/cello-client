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
 *     no binary-content path. Its first byte is therefore ASCII (`< 0x80`) or a LEAD byte
 *     (`0xc2`–`0xf4`) — never a continuation byte. Note it is NOT always `< 0x80`: a message
 *     beginning in French, Arabic or Chinese starts at `0xc2` or above and is still clear of the
 *     admitted range. Getting that wrong would invite someone to widen the range on a false premise.
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
 * The decoder limit in `cbor.ts` cuts the per-byte amplification by ~43,000×, and it is still not
 * the whole answer: cbor-x pre-allocates `new Array(declaredCount)` before reading any element, so
 * NESTED arrays each under that cap still allocate — measured, 15 KB of them costs ~230 ms and
 * ~2.3 GB. What makes the nesting depth finite is an INPUT LENGTH CAP, which is why one is applied
 * here, at the peer-bytes boundary, before anything else looks at the frame.
 *
 * So the three layers, in the order they run and with what each is actually for:
 *   MAX_DOCUMENT_FRAME_BYTES — bounds the nesting depth. The one that closes the class.
 *   couldBeDocumentFrame     — a cheap fast path; keeps every conversation message out of the
 *                              decoder, and is what the UTF-8 argument above rests on.
 *   cbor.ts size limits      — bounds a single container. Reduces amplification; not a boundary.
 *
 * The guard must never again be described as what makes hostile input safe. It was, and it was not.
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

/**
 * What the session layer needs SYNCHRONOUSLY: is this document traffic, and therefore which leaf
 * kind does the frame get.
 *
 * The handling itself is async — a gate refusal has to SIGN a `0x05` leaf, and signing goes through
 * an async key provider — but `#appendVerifiedContent` decides the leaf kind inline and cannot wait.
 * Splitting the two is what lets both be true without making the whole content path async.
 */
export type FrameClassification =
  | { consumed: false }
  | { consumed: true; kind: "update" | "ack" };

export interface DocumentFrameRouterDeps {
  inbound: DocumentInbound;
  ackInbound: DocumentAckInbound;
  logger: Logger;
}

export class DocumentFrameRouter {
  readonly #d: DocumentFrameRouterDeps;
  /** One promise chain per owning agent — the serialization point. See `#enqueue`. */
  readonly #queues = new Map<string, Promise<void>>();

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
  /**
   * The SYNCHRONOUS half: classify, and start the handling.
   *
   * Returns immediately with what the session layer needs to pick a leaf kind. The handling runs on
   * a per-document queue — see `#handle` — so the caller never waits and frames for one document
   * never overtake each other.
   */
  routeSync(
    ownerAgentId: string,
    content: Uint8Array,
    nowMs: number,
    correlationId: string,
  ): FrameClassification {
    const kind = classify(content);
    if (kind === null) return { consumed: false };
    void this.#enqueue(ownerAgentId, content, nowMs, correlationId, kind);
    return { consumed: true, kind };
  }

  /**
   * SERIALIZED PER DOCUMENT-OWNER, because the chain check is order-dependent even though Yjs is
   * not. An envelope's `doc_prev_hash` must find its predecessor already stored, so two frames
   * handled concurrently can have the second refuse with `document_chain_broken` purely because the
   * first has not finished writing — a self-inflicted fork that looks like a peer fault.
   *
   * Keyed by owner rather than by document: the document id is inside the frame, and reading it
   * requires the decode this queue exists to schedule.
   */
  #enqueue(
    ownerAgentId: string,
    content: Uint8Array,
    nowMs: number,
    correlationId: string,
    kind: "update" | "ack",
  ): Promise<void> {
    const previous = this.#queues.get(ownerAgentId) ?? Promise.resolve();
    const next = previous
      .catch(() => {
        // A previous frame's failure must not cancel this one's turn. It was already reported.
      })
      .then(async () => {
        // `kind` is passed through rather than re-derived: `classify` does up to two full CBOR
        // decodes, and this runs on every inbound frame.
        const outcome = await this.#dispatch(ownerAgentId, content, nowMs, correlationId, kind);
        if (outcome.consumed && !outcome.ok) {
          this.#d.logger.warn("document.frame.refused", {
            kind: outcome.kind,
            reason: outcome.reason,
            correlationId,
          });
        }
      });
    this.#queues.set(ownerAgentId, next);
    // Drop the entry once it is the tail, so the map does not grow one promise per agent forever.
    void next.finally(() => {
      if (this.#queues.get(ownerAgentId) === next) this.#queues.delete(ownerAgentId);
    });
    return next;
  }

  /** Classify and handle, awaiting the outcome. The path a caller takes when it wants the verdict. */
  async route(
    ownerAgentId: string,
    content: Uint8Array,
    nowMs: number,
    correlationId: string,
  ): Promise<FrameRouting> {
    const kind = classify(content);
    if (kind === null) return { consumed: false };
    return this.#dispatch(ownerAgentId, content, nowMs, correlationId, kind);
  }

  async #dispatch(
    ownerAgentId: string,
    content: Uint8Array,
    nowMs: number,
    correlationId: string,
    kind: "update" | "ack",
  ): Promise<FrameRouting> {
    try {
      if (kind === "update") {
        const res = await this.#d.inbound.receive(ownerAgentId, content, nowMs, correlationId);
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
export const MAX_DOCUMENT_FRAME_FIELDS = 32;

/**
 * The largest a document frame can legitimately be, and the bound that makes the decode's nesting
 * depth finite.
 *
 * Sized off the payload it has to carry: the gate caps an update at 1 MiB, and everything else in
 * the envelope — two hashes, an agent id, a state vector, a signature — is small. 2 MiB is
 * comfortably above any real frame and far below the size at which nested-array pre-allocation
 * becomes expensive.
 *
 * This is the layer that actually closes the pathological-input class. The decoder's per-container
 * limit reduces amplification; only a bound on the INPUT can bound the depth.
 */
export const MAX_DOCUMENT_FRAME_BYTES = 2 * 1024 * 1024;

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
  //
  // The upper end of the admitted range must stay at or below 0xbf, or the UTF-8 argument in the
  // header stops holding: 0x80-0xbf are exactly the continuation bytes, and 0xc0 upward CAN begin a
  // valid sequence. A test pins that.
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
  // LENGTH FIRST. See the header: this is what bounds the nesting depth, and it is checked before
  // the frame is looked at in any other way.
  if (content.length > MAX_DOCUMENT_FRAME_BYTES) return null;
  if (!couldBeDocumentFrame(content)) return null;
  try {
    decodeDocumentUpdateEnvelope(content);
    return "update";
  } catch {
    // Not an update. Deliberately silent — a frame reaching here is one that PASSED the header
    // guard, so it is not a conversation message (see the UTF-8 argument in the header); it is a
    // peer's malformed or unrecognised document-shaped frame, and the caller reports the outcome.
  }
  try {
    decodeDocumentAck(content);
    return "ack";
  } catch {
    // Not document traffic at all.
  }
  return null;
}
