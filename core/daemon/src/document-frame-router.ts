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
  decodeCbor,
  decodeDocumentReconcile,
  decodeDocumentUpdateEnvelope,
  decodeDocumentProposal,
  decodeDocumentRejection,
  decodeDocumentProposalAck,
  decodeDocumentAmendment,
} from "@cello-protocol/protocol-types";
import type { DocumentInbound } from "./document-inbound.js";
import type { Logger } from "./types.js";

/**
 * What the session layer should do with the frame.
 *
 * `consumed: false` means "this is not document traffic" — the caller records it as a transcript
 * message and fires the doorbell exactly as before. Nothing about the conversation path changes.
 */
/** Every document frame kind that can arrive on the session channel. */
export type DocumentFrameKind =
  | "update"
  | "proposal"
  | "rejection"
  | "proposal_ack"
  | "amendment"
  | "reconcile";

export type FrameRouting =
  | { consumed: false }
  | { consumed: true; kind: DocumentFrameKind; ok: boolean; reason?: string };

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
  | { consumed: true; kind: DocumentFrameKind };

export interface DocumentFrameRouterDeps {
  inbound: DocumentInbound;
  /**
   * Record an arriving PROPOSAL. Without this a proposal frame is not document traffic as far as
   * the router is concerned, so it falls through to the conversation path and lands in the
   * operator's transcript as unreadable bytes — the exact failure the classification exists to
   * prevent, arriving through the one frame kind nobody had wired.
   */
  recordProposal(ownerAgentId: string, wire: Uint8Array, nowMs: number): void;
  /** Record a rejection the PEER sent us — the receiving half of §3.2. */
  recordRejection(ownerAgentId: string, wire: Uint8Array, nowMs: number): void;
  /**
   * Record the peer's ANSWER to a proposal we authored. Unclassified, this frame falls through to
   * the conversation path and an operator's agent is handed a CBOR ack as something a person said.
   */
  recordProposalAck(ownerAgentId: string, wire: Uint8Array, nowMs: number): void;
  /**
   * The peer has CLOSED or KILLED the document. Unclassified, this frame falls through to the
   * conversation path and the operator keeps publishing into a document that will never answer,
   * with nothing on their screen explaining why.
   */
  /**
   * M14B / DOD-MP-JOIN-1 — an admin's offer to a third party. Validated (the invitee REPLAYS the
   * carried bytes) and recorded — pending or refused-with-reason, never dropped.
   */
  /**
   * An amendment reaching an EXISTING holder — validated against our own chain
   * (validate-before-append) and appended, so our derived participant set does not silently
   * diverge from the amender's (§7-1's hazard). Best-effort delivery at P1; the inbound epoch
   * gate makes a missed one loud.
   */
  recordAmendment(ownerAgentId: string, wire: Uint8Array, nowMs: number): void;
  /**
   * SYNC-P3 — answer (or absorb) a reconcile exchange. Needs the SESSION's authenticated sender:
   * the frame is unsigned by design, and entitlement (R17/R18) is a question about who is
   * ASKING, which only the transport identity can answer. Everything the frame carries is still
   * individually signed and verified on apply.
   */
  handleReconcile(
    ownerAgentId: string,
    wire: Uint8Array,
    senderAgentId: string,
    nowMs: number,
    correlationId: string,
  ): Promise<{ ok: boolean; reason?: string }>;
  /**
   * Tell the sender what happened to their envelope — admitted or refused, both of which SETTLE it.
   *
   * REQUIRED, not optional. Without it the sender has no answer and redelivers until the document
   * stalls; an optional callback would make that outcome a configuration rather than a bug.
   */
  /**
   * Re-project the document onto disk after admitting a peer's update.
   *
   * Required rather than optional: a file surface that only ever writes the local operator's edits
   * out is worse than none, because the stale file reads as the document and gets published back
   * over the peer's work. A daemon with no workspace configured implements this as a no-op.
   */
  rewriteFile(ownerAgentId: string, inResponseTo: Uint8Array): Promise<void>;
  /**
   * Record that the peer changed this document and the agent has not read it yet — §16.5's passive
   * notification.
   *
   * Wired 2026-08-08. The writer and the reader both existed and NEITHER had a production caller,
   * so an admitted update wrote nothing and `cello_check_notifications` had no document section at
   * all; `cello_doc_read` was clearing rows that could never exist. An agent learned a document had
   * moved only by polling. That is the unit-with-no-caller shape this milestone was burned by, and
   * it was carried onto DOC-TOOLS-1 as an explicit clause and left unwired.
   */
  noticeInboundUpdate(ownerAgentId: string, inResponseTo: Uint8Array): void;
  /** Put an already-signed frame on the wire to whoever authored `wire` — the rejection, today. */
  sendFrameToPeer(ownerAgentId: string, inResponseTo: Uint8Array, bytes: Uint8Array): Promise<void>;
  /**
   * Map the daemon's AGENT NAME — the only identifier the session content path carries — to the
   * stable owner key every document row is scoped by (M14-D5: our own K_local pubkey hex).
   *
   * REQUIRED, and required to be here rather than at the call site, because classification must
   * stay synchronous and must not be done twice: `classify` runs up to four CBOR decodes and this
   * is on every inbound frame.
   *
   * The two identifiers are NOT interchangeable and the store says so. Scoping inbound by name
   * while the delivery sweep scopes by pubkey hex writes every received envelope where no query
   * looks: `pendingDeliveries` returns empty, the sweep reports nothing attempted, and a fully
   * synced document is invisible to both halves with no error on any path. Agent NAME is also
   * mutable and reusable after retirement, so it may never be a join key.
   *
   * Returning null is a refusal, not a fallback — the frame is still consumed, because it IS a
   * document frame and letting it fall through would put CRDT bytes in the operator's transcript.
   */
  ownerKeyFor(agentName: string): string | null;
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
    agentName: string,
    content: Uint8Array,
    nowMs: number,
    correlationId: string,
    senderAgentId = "",
  ): FrameClassification {
    const kind = classify(content);
    if (kind === "unshaped") return { consumed: false };
    if (kind === "undecodable") {
      // ANOMALY, worth a line. A frame that passed the header guard and then decoded as NOTHING is
      // not an ordinary conversation message — the guard's whole argument is that operator text
      // cannot begin with a CBOR map header (see the UTF-8 reasoning above). So this is either a
      // peer running a frame type this build does not know, or our own encoder and decoder
      // disagreeing, and both are invisible today: the frame silently becomes a transcript entry.
      //
      // This was the missing diagnostic when a live proposal reached its peer, passed the content
      // hash cross-check byte for byte, and never reached the document layer — every log on the
      // receiving side said "an ordinary message arrived", because that is what the fall-through
      // makes it.
      this.#d.logger.warn("document.frame.undecodable", {
        bytes: content.length,
        header: content[0],
        correlationId,
      });
      return { consumed: false };
    }
    // Resolved AFTER classification and BEFORE handling: a frame that is not document traffic never
    // pays for the lookup, and one that is never reaches the store under the wrong scope.
    const ownerAgentId = this.#d.ownerKeyFor(agentName);
    if (ownerAgentId === null) {
      this.#d.logger.error("document.frame.owner_unresolved", { agentName, kind, correlationId });
      // Consumed anyway. This IS a document frame; the only alternative is the conversation path,
      // which would hand an operator's agent a CBOR envelope as something a person said.
      return { consumed: true, kind };
    }
    void this.#enqueue(ownerAgentId, content, nowMs, correlationId, kind, senderAgentId);
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
    kind: DocumentFrameKind,
    senderAgentId: string,
  ): Promise<void> {
    const previous = this.#queues.get(ownerAgentId) ?? Promise.resolve();
    const next = previous
      .catch(() => {
        // A previous frame's failure must not cancel this one's turn. It was already reported.
      })
      .then(async () => {
        // `kind` is passed through rather than re-derived: `classify` does up to two full CBOR
        // decodes, and this runs on every inbound frame.
        const outcome = await this.#dispatch(
          ownerAgentId, content, nowMs, correlationId, kind, senderAgentId,
        );
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
    senderAgentId = "",
  ): Promise<FrameRouting> {
    const kind = classify(content);
    // Both non-kinds mean "not ours" to this async entry point. `routeSync` is the path that
    // distinguishes them, because it is the one that decides what the session does with the frame.
    if (kind === "unshaped" || kind === "undecodable") return { consumed: false };
    return this.#dispatch(ownerAgentId, content, nowMs, correlationId, kind, senderAgentId);
  }

  async #dispatch(
    ownerAgentId: string,
    content: Uint8Array,
    nowMs: number,
    correlationId: string,
    kind: DocumentFrameKind,
    senderAgentId: string,
  ): Promise<FrameRouting> {
    try {
      if (kind === "update") {
        const res = await this.#d.inbound.receive(ownerAgentId, content, nowMs, correlationId);
        if (res.ok && res.admitted) {
          // REWRITE THE FILE. The document has moved; the operator's editor has not been told.
          // Without this the file surface is write-only — an operator publishes their edits and
          // never sees the peer's, which is worse than no file surface at all, because the stale
          // file then looks like the document and gets published back over their work.
          //
          // Not awaited, and not allowed to fail the admission: the content is already in the
          // document, which is the source of truth. A failed rewrite is a stale projection, and
          // `publish` refuses loudly on a stale baseline rather than diffing against it.
          // NOTICED BEFORE the file rewrite, and synchronously: the notice is a row, not I/O, and
          // an agent that reads the file before the notice lands would clear a count that had not
          // been written. Never allowed to fail the admission — the content is already in the
          // document, which is the source of truth.
          try {
            this.#d.noticeInboundUpdate(ownerAgentId, content);
          } catch (err: unknown) {
            this.#d.logger.warn("document.notice.failed", {
              correlationId,
              reason: err instanceof Error ? err.message : String(err),
            });
          }
          void this.#d.rewriteFile(ownerAgentId, content).catch((err: unknown) => {
            this.#d.logger.warn("document.file.rewrite_threw", {
              correlationId,
              reason: err instanceof Error ? err.message : String(err),
            });
          });
        }
        if (res.ok) {
          // THE SIGNED REFUSAL ITSELF, when there is one. This frame is what
          // advances the SENDER's retry round, and their entire supersede-then-stall protocol is
          // driven by receiving it. Without it their counter never leaves zero and a peer whose
          // every update is refused republishes forever, with its own surface reporting `active`.
          //
          // Absent on a repeat refusal by design — re-sending would advance their round for a retry
          // that never happened and stall the document early.
          if (!res.admitted && res.rejectionWire) {
            void this.#d
              .sendFrameToPeer(ownerAgentId, content, res.rejectionWire)
              .catch((err: unknown) => {
                this.#d.logger.warn("document.rejection.send_threw", {
                  correlationId,
                  reason: err instanceof Error ? err.message : String(err),
                });
              });
          }
        }
        // SYNC-P4 (D4): no ack frame answers content anymore. An admitted envelope shows up in
        // this holder's position at the next exchange — that IS the confirmation. A signed
        // rejection (above) still travels, because it carries a decision, not a receipt.
        return { consumed: true, kind, ok: res.ok, reason: res.ok ? undefined : res.reason };
      }
      if (kind === "proposal") {
        this.#d.recordProposal(ownerAgentId, content, nowMs);
        return { consumed: true, kind, ok: true };
      }
      if (kind === "rejection") {
        this.#d.recordRejection(ownerAgentId, content, nowMs);
        return { consumed: true, kind, ok: true };
      }
      if (kind === "proposal_ack") {
        this.#d.recordProposalAck(ownerAgentId, content, nowMs);
        return { consumed: true, kind, ok: true };
      }
      if (kind === "amendment") {
        this.#d.recordAmendment(ownerAgentId, content, nowMs);
        return { consumed: true, kind, ok: true };
      }
      if (kind === "reconcile") {
        const rec = await this.#d.handleReconcile(
          ownerAgentId, content, senderAgentId, nowMs, correlationId,
        );
        return { consumed: true, kind, ok: rec.ok, reason: rec.reason };
      }
      // Exhaustive over the kind union — reaching here is a programming fault the catch reports.
      throw new Error(`document_frame_unrouted: ${kind as string}`);
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
 * a frame kind, or `null` for "not document traffic".
 *
 * Guarded, then decode-based. The two document types are tried in turn and the first that decodes
 * wins; both decoders check a `type` discriminator before anything else, so neither can claim the
 * other's frame. A conversation message is arbitrary operator text and will not decode as either.
 */
/**
 * `"unshaped"` — not document traffic at all, and cheap to know: too long, or its first byte is not
 * a CBOR map header. `"undecodable"` — it LOOKED like one and decoded as nothing, which is an
 * anomaly worth reporting.
 *
 * Two outcomes rather than one `null` so the caller can tell them apart WITHOUT re-running the
 * guard. It did re-run it, and the cost landed on exactly the wrong path: the hostile-input budget
 * is the one this router's guard exists to protect, and doubling its work took a measured
 * pathological input from comfortably inside the budget to over it.
 */
type Unclassified = "unshaped" | "undecodable";

function classify(content: Uint8Array): DocumentFrameKind | Unclassified {
  // LENGTH FIRST. See the header: this is what bounds the nesting depth, and it is checked before
  // the frame is looked at in any other way.
  if (content.length > MAX_DOCUMENT_FRAME_BYTES) return "unshaped";
  if (!couldBeDocumentFrame(content)) return "unshaped";

  // DECODE ONCE AND READ THE DISCRIMINATOR, rather than trying every decoder in turn.
  //
  // Each decoder validates its own `type` before anything else, so trying them in sequence meant a
  // frame paid for as many full CBOR decodes as there are frame types ahead of it — and hostile
  // bytes that pass the header guard paid for ALL of them. That cost grows every time this protocol
  // gains a frame, which it did three times this milestone: six decoders where there were four, and
  // the measured pathological inputs went from comfortably inside the DoS budget to over it on a
  // slower machine.
  //
  // The decode itself is already bounded — `cbor.ts` sets process-global size limits, which is the
  // actual boundary; the header guard above is only a fast path. So one decode is safe, and one is
  // all this needs: read `type`, then hand the bytes to exactly the decoder that claims them, which
  // re-validates everything including the type. Two decodes worst case instead of six, and one for
  // anything that is not a CBOR map at all.
  let declared: unknown;
  try {
    const decoded = decodeCbor(content);
    if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) return "unshaped";
    declared = (decoded as Record<string, unknown>)["type"];
  } catch {
    // Not decodable as CBOR at all. Shaped like a map header and is not one.
    return "unshaped";
  }
  if (typeof declared !== "string") return "undecodable";

  try {
    switch (declared) {
      case "document_update":
        decodeDocumentUpdateEnvelope(content);
        return "update";
      case "document_proposal":
        decodeDocumentProposal(content);
        return "proposal";
      case "document_rejection":
        decodeDocumentRejection(content);
        return "rejection";
      case "document_proposal_ack":
        decodeDocumentProposalAck(content);
        return "proposal_ack";
      case "document_amendment":
        decodeDocumentAmendment(content);
        return "amendment";
      case "document_reconcile":
        decodeDocumentReconcile(content);
        return "reconcile";
      default:
        // A frame type this build does not know. Reported by the caller rather than silently
        // treated as conversation — see `routeSync`.
        return "undecodable";
    }
  } catch {
    // It NAMED a document frame type and failed that type's own validation. Not conversation:
    // conversation does not carry `type: "document_update"`.
    return "undecodable";
  }
}
