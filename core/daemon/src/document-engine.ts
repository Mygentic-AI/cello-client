/**
 * DOD-DOC-ENGINE-1 — the daemon's Y.Doc lifecycle.
 *
 * The engine owns HOW to apply; the store (DOD-DOC-STORE-1) owns what to replay and in what
 * order. That split is why `replay` here takes whole envelope rows rather than payload bytes:
 * a withdrawal record carries no payload, so an engine handed only payloads could never exclude
 * the update it withdraws.
 *
 * EVERY GUARD BELOW IS A RESPONSE TO A MEASUREMENT, not to a guess. DOD-DOC-FUZZ-1 fuzzed
 * `Y.applyUpdate` and found:
 *
 *   - Malformed input THROWS — so a wrapped apply genuinely contains it, and V1 needs no sandbox.
 *   - But the dangerous class is what Yjs ACCEPTS. An update whose dependencies the receiver
 *     lacks returns success, contributes nothing, and is RETAINED forever in
 *     `doc.store.pendingStructs` — a peer streams those until the daemon dies, and a try/catch
 *     sees only success. Hence the pending-set check after every apply.
 *   - An empty or one-byte update throws a lib0 DECODER error ("Unexpected end of array"), which
 *     names Yjs internals rather than a protocol fault. Hence a floor as well as a cap.
 *   - Yjs does not bound nesting depth at all, and the size cap bounds it poorly (~16 bytes per
 *     level, so roughly 65,000 levels fit in 1 MiB). Structural limits are DOD-DOC-GATE-1's job;
 *     the engine's contract is only that a bad update is a typed error, never a crash.
 *
 * ONE TYPED REASON PER FAILURE CLASS. A lib0 string like "Integer out of Range" describes where
 * the decoder gave up, not what the peer did wrong, so it travels as `detail` and never as the
 * reason an operator or a policy log sees.
 */

import * as Y from "yjs";
import type { DocumentEnvelopeRow } from "./document-store.js";
import type { Logger } from "./types.js";

export type DocumentUpdateFailure =
  | "document_update_too_large"
  | "document_update_too_small"
  | "document_update_malformed"
  | "document_update_unresolved_dependencies";

export interface DocumentUpdateResult {
  ok: boolean;
  reason?: DocumentUpdateFailure;
  /** The underlying cause, when there is one — never the reason itself. */
  detail?: string;
}

/** Thrown by the *OrThrow variants and by `replay`, where returning a verdict would let a caller
 *  persist a state that was never fully applied. */
export class DocumentUpdateError extends Error {
  readonly reason: DocumentUpdateFailure;
  readonly detail?: string;
  constructor(reason: DocumentUpdateFailure, detail?: string) {
    super(detail ? `${reason}: ${detail}` : reason);
    this.name = "DocumentUpdateError";
    this.reason = reason;
    this.detail = detail;
  }
}

/** Pre-parse size cap — bytes are refused on LENGTH before Yjs is invoked at all. */
const MAX_UPDATE_BYTES = 1024 * 1024;

/**
 * The minimum valid update. An empty encoded state is two bytes (`[0,0]`), measured — anything
 * shorter throws a decoder error that says nothing about the protocol.
 */
const MIN_UPDATE_BYTES = 2;

/** The single root text field a V1 text document uses. */
const TEXT_ROOT = "content";

export class DocumentEngine {
  readonly #logger: Logger;

  constructor(logger: Logger) {
    this.#logger = logger;
  }

  /** The pre-parse cap, exposed so callers and tests agree on one number. */
  get maxUpdateBytes(): number {
    return MAX_UPDATE_BYTES;
  }

  /**
   * A fresh live document.
   *
   * Yjs mints its own random clientID and NOTHING here touches it (§14). Deriving it from agent
   * identity, or persisting and restoring one, means two live docs can share it — and
   * DOD-DOC-FUZZ-1 measured that outcome: the colliding writer silently wins, the honest client's
   * update is accepted-and-dropped, and the document becomes a splice of two authors with an
   * empty pending set and no error on any path.
   */
  createDocument(startingContent = ""): Y.Doc {
    const doc = new Y.Doc();
    if (startingContent.length > 0) doc.getText(TEXT_ROOT).insert(0, startingContent);
    return doc;
  }

  readText(doc: Y.Doc): string {
    return doc.getText(TEXT_ROOT).toString();
  }

  insertText(doc: Y.Doc, index: number, text: string): void {
    doc.getText(TEXT_ROOT).insert(index, text);
  }

  /** The full state, or just what a peer holding `sinceStateVector` is missing (§7). */
  encodeState(doc: Y.Doc, sinceStateVector?: Uint8Array): Uint8Array {
    return Y.encodeStateAsUpdate(doc, sinceStateVector);
  }

  encodeStateVector(doc: Y.Doc): Uint8Array {
    return Y.encodeStateVector(doc);
  }

  snapshot(doc: Y.Doc): { binary: Uint8Array; stateVector: Uint8Array } {
    return { binary: Y.encodeStateAsUpdate(doc), stateVector: Y.encodeStateVector(doc) };
  }

  /**
   * Materialize a document from a snapshot binary.
   *
   * The restored document mints a FRESH clientID — the binary carries the operations, never an
   * identity to resume under. See `createDocument` for what sharing one costs.
   */
  restore(binary: Uint8Array): Y.Doc {
    const doc = new Y.Doc();
    Y.applyUpdate(doc, binary);
    return doc;
  }

  /**
   * Apply one update, with every guard the fuzz pass motivated.
   *
   * Never throws and never leaves the document half-integrated: an update that cannot be fully
   * resolved is applied to a THROWAWAY doc first, so the caller's document is untouched when the
   * answer is no.
   */
  applyUpdate(doc: Y.Doc, update: Uint8Array): DocumentUpdateResult {
    if (update.length > MAX_UPDATE_BYTES) {
      return { ok: false, reason: "document_update_too_large" };
    }
    if (update.length < MIN_UPDATE_BYTES) {
      return { ok: false, reason: "document_update_too_small" };
    }

    // Try it on a copy first. Yjs has no "apply atomically" mode, and an update that resolves
    // partially would otherwise leave the real document in a state no one chose.
    const shadow = new Y.Doc();
    try {
      Y.applyUpdate(shadow, Y.encodeStateAsUpdate(doc));
      Y.applyUpdate(shadow, update);
    } catch (err: unknown) {
      return {
        ok: false,
        reason: "document_update_malformed",
        detail: err instanceof Error ? err.message : String(err),
      };
    }

    // THE ACCEPT CLASS. Yjs returned success — that is not evidence the update integrated.
    // A non-empty pending set means it is waiting on structs that never arrived, and admitting
    // it would retain them indefinitely while contributing nothing.
    if (shadow.store.pendingStructs !== null) {
      return {
        ok: false,
        reason: "document_update_unresolved_dependencies",
        detail: `update depends on ${shadow.store.pendingStructs.missing.size} client(s) whose earlier operations are absent`,
      };
    }

    Y.applyUpdate(doc, update);
    return { ok: true };
  }

  /** `applyUpdate` for callers that want the failure to be unmissable. */
  applyUpdateOrThrow(doc: Y.Doc, update: Uint8Array): void {
    const res = this.applyUpdate(doc, update);
    if (!res.ok) throw new DocumentUpdateError(res.reason!, res.detail);
  }

  /**
   * Fold an ordered envelope log into a materialized state — the `ReplayFn` the store injects.
   *
   * Receives the WHOLE log, withdrawal and rejection rows included. Those carry no payload, and
   * excluding the update a withdrawal references is precisely the judgement the store declines to
   * make on the engine's behalf.
   *
   * REFUSES rather than skipping. A payload that will not apply means the log is corrupt, and
   * folding the rest would produce a document that reads as complete while missing operations —
   * the silent divergence the whole two-layer design exists to prevent.
   */
  replay(envelopes: readonly DocumentEnvelopeRow[]): { binary: Uint8Array; stateVector: Uint8Array } {
    const withdrawn = new Set<string>();
    for (const e of envelopes) {
      if ((e.kind === "withdrawal" || e.kind === "rejection") && e.referencesEnvelopeHash) {
        withdrawn.add(e.referencesEnvelopeHash);
      }
    }

    const doc = new Y.Doc();
    let applied = 0;
    for (const e of envelopes) {
      if (e.payload === null) continue; // withdrawal/rejection records, and purged envelopes
      if (withdrawn.has(e.envelopeHash)) continue;
      const res = this.applyUpdate(doc, e.payload);
      if (!res.ok) {
        this.#logger.error("document.replay.failed", {
          documentId: e.documentId,
          envelopeHash: e.envelopeHash,
          reason: res.reason,
          detail: res.detail,
        });
        throw new DocumentUpdateError(res.reason!, `envelope ${e.envelopeHash.slice(0, 16)}…: ${res.detail ?? ""}`);
      }
      applied++;
    }

    this.#logger.info("document.replay.completed", { envelopes: envelopes.length, applied });
    return { binary: Y.encodeStateAsUpdate(doc), stateVector: Y.encodeStateVector(doc) };
  }
}
