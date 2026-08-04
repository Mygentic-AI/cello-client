/**
 * DOD-DOC-ENGINE-1 — the daemon's Y.Doc lifecycle.
 *
 * The engine owns HOW to apply; the store (DOD-DOC-STORE-1) owns what to replay and in what
 * order. `replay` takes whole envelope rows rather than payload bytes so it can tell a
 * payload-free AUDIT record (a withdrawal or rejection, which is expected and skipped) from a
 * payload-free PURGED update (an operation whose bytes are gone, which must refuse). That is the
 * only thing `kind` is read for — `referencesEnvelopeHash` is pure audit at replay time, never
 * read, because a withdrawal excludes nothing (§16.4; see `replay`).
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
  | "document_update_unresolved_dependencies"
  | "document_snapshot_malformed"
  | "document_snapshot_incomplete"
  | "document_envelope_purged";

export type DocumentUpdateResult =
  | { ok: true }
  /** `detail` is the underlying cause — never the reason itself. */
  | { ok: false; reason: DocumentUpdateFailure; detail?: string };

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

  /**
   * Read the single text root a text-typed document uses.
   *
   * Named for the root it reads, not for "the document's content". `DocumentRow.documentType`
   * admits markdown, json and xml; on the latter two the data does not live in this root, and an
   * unnamed `readText` would return "" — indistinguishable from an empty document. Structured
   * types get their own accessors when a unit needs them.
   */
  readTextRoot(doc: Y.Doc): string {
    return doc.getText(TEXT_ROOT).toString();
  }

  insertIntoTextRoot(doc: Y.Doc, index: number, text: string): void {
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
    try {
      Y.applyUpdate(doc, binary);
    } catch (err: unknown) {
      // This is the one method that reads bytes off disk, and it used to be a bare applyUpdate —
      // so a corrupt `document_snapshots` row surfaced as "Unexpected end of array", the exact
      // lib0 string this module says must never be a reason. It named Yjs internals and pointed
      // an operator at the wrong subsystem.
      const detail = err instanceof Error ? err.message : String(err);
      this.#logger.error("document.snapshot.malformed", { detail });
      throw new DocumentUpdateError("document_snapshot_malformed", detail);
    }
    if (doc.store.pendingStructs !== null) {
      // A snapshot that decodes but is incomplete would otherwise restore SHORT and silent.
      this.#logger.error("document.snapshot.incomplete", {
        missing: doc.store.pendingStructs.missing.size,
      });
      // Its OWN class. An incomplete snapshot is not "an incoming update depends on absent
      // structs" — same symptom, different fault, and one reason per class is this module's rule.
      throw new DocumentUpdateError(
        "document_snapshot_incomplete",
        `snapshot is missing operations from ${doc.store.pendingStructs.missing.size} client(s)`,
      );
    }
    return doc;
  }

  /**
   * Apply one update, with every guard the fuzz pass motivated.
   *
   * Never throws and never leaves the document half-integrated: an update that cannot be fully
   * resolved is applied to a THROWAWAY doc first, so the caller's document is untouched when the
   * answer is no.
   */
  /**
   * Apply one update to a caller's live document, leaving it untouched if the answer is no.
   *
   * The trial runs on a FRESH scratch document every time. Reusing one across calls is unsound:
   * `Y.applyUpdate` MERGES, it does not reset, so a scratch doc seeded from an empty document
   * still holds the previous trial's operations — and with that residue present, an update whose
   * dependencies the target lacks reports an EMPTY pending set. The one guard that catches the
   * accept class would go green on exactly the input it exists to refuse. (Measured, not
   * reasoned: a shadow holding "AAA" re-seeded from an empty doc still reads "AAA".)
   */
  applyUpdate(doc: Y.Doc, update: Uint8Array): DocumentUpdateResult {
    return this.#applyChecked(doc, new Y.Doc(), update);
  }

  #applyChecked(doc: Y.Doc, shadow: Y.Doc, update: Uint8Array): DocumentUpdateResult {
    if (update.length > MAX_UPDATE_BYTES) {
      return this.#refuse("document_update_too_large", `${update.length} bytes exceeds the ${MAX_UPDATE_BYTES}-byte cap`, update);
    }
    if (update.length < MIN_UPDATE_BYTES) {
      return this.#refuse("document_update_too_small", `${update.length} bytes is below the ${MIN_UPDATE_BYTES}-byte minimum for a Yjs update`, update);
    }

    // Trial it on scratch state first. Yjs has no atomic-apply mode, and an update that resolves
    // only partially would otherwise leave the caller's document in a state nobody chose.
    try {
      Y.applyUpdate(shadow, Y.encodeStateAsUpdate(doc));
      Y.applyUpdate(shadow, update);
    } catch (err: unknown) {
      return this.#refuse("document_update_malformed", err instanceof Error ? err.message : String(err), update);
    }

    // THE ACCEPT CLASS. Yjs returned success — that is not evidence the update integrated. A
    // non-empty pending set means it is waiting on structs that never arrived; admitting it would
    // retain them indefinitely while contributing nothing (measured, DOD-DOC-FUZZ-1).
    //
    // PRECONDITION THIS IMPLIES: a sender's envelopes must be delivered in chain order. Yjs would
    // otherwise BUFFER an out-of-order update and resolve it on the next state-vector exchange;
    // this refuses instead. That is right for replay, where a gap means a corrupt log — a live
    // receive path wanting buffer-and-re-request semantics needs its own entry point, not this one.
    if (shadow.store.pendingStructs !== null) {
      return this.#refuse(
        "document_update_unresolved_dependencies",
        `depends on ${shadow.store.pendingStructs.missing.size} client(s) whose earlier operations are absent`,
        update,
      );
    }

    Y.applyUpdate(doc, update);
    return { ok: true };
  }

  /**
   * Apply straight to `doc`, checking the pending set afterwards.
   *
   * No trial copy, because atomicity buys nothing here: `replay` throws on the first failure and
   * the half-built document is discarded whole. Trialling each envelope would cost a full
   * encode/decode of a growing document per envelope — the fold is O(n·|doc|) either way, but
   * this halves the constant and removes the aliasing hazard entirely.
   */
  #applyDirect(doc: Y.Doc, update: Uint8Array): DocumentUpdateResult {
    if (update.length > MAX_UPDATE_BYTES) {
      return this.#refuse("document_update_too_large", `${update.length} bytes exceeds the ${MAX_UPDATE_BYTES}-byte cap`, update);
    }
    if (update.length < MIN_UPDATE_BYTES) {
      return this.#refuse("document_update_too_small", `${update.length} bytes is below the ${MIN_UPDATE_BYTES}-byte minimum for a Yjs update`, update);
    }
    try {
      Y.applyUpdate(doc, update);
    } catch (err: unknown) {
      return this.#refuse("document_update_malformed", err instanceof Error ? err.message : String(err), update);
    }
    if (doc.store.pendingStructs !== null) {
      return this.#refuse(
        "document_update_unresolved_dependencies",
        `depends on ${doc.store.pendingStructs.missing.size} client(s) whose earlier operations are absent`,
        update,
      );
    }
    return { ok: true };
  }

  /** Every refusal is logged, not merely returned — a return value nobody reads is not observable. */
  #refuse(reason: DocumentUpdateFailure, detail: string, update: Uint8Array): DocumentUpdateResult {
    this.#logger.warn("document.update.refused", { reason, detail, bytes: update.length });
    return { ok: false, reason, detail };
  }

  /** `applyUpdate` for callers that want the failure to be unmissable. */
  applyUpdateOrThrow(doc: Y.Doc, update: Uint8Array): void {
    const res = this.applyUpdate(doc, update);
    if (!res.ok) throw new DocumentUpdateError(res.reason, res.detail);
  }

  /**
   * Fold an ordered envelope log into a materialized state — the `ReplayFn` the store injects.
   *
   * **A WITHDRAWAL EXCLUDES NOTHING.** §16.4 is explicit: withdrawing rolls the change back with
   * a *Yjs undo* and writes a record "beside the original envelope — marked withdrawn, never
   * deleted, so the log stays intact". Rejection resolves the same way, by supersession —
   * "inverses, not erasure" (§3.2). So the undo is itself an ordinary update in the log, and
   * replay simply applies every payload in order.
   *
   * An earlier version of this method excluded the referenced envelope instead, which is
   * unsound in a CRDT log and was measured to be so: Yjs operations are causally chained, so
   * dropping any but the LAST envelope leaves every later one depending on structs that never
   * arrive — the document rebuilds until the next daemon restart and is permanently unopenable
   * after it. It also let ANY sender suppress ANY other sender's content by appending a
   * payload-free row, since nothing upstream checks authorship of a reference. Both problems
   * dissolve when the log is simply replayed, which is what the spec said to do.
   *
   * REFUSES rather than skipping. A payload that will not apply means the log is corrupt, and
   * folding the rest would produce a document that reads as complete while missing operations —
   * the silent divergence the whole two-layer design exists to prevent.
   */
  replay(envelopes: readonly DocumentEnvelopeRow[]): { binary: Uint8Array; stateVector: Uint8Array } {
    const doc = new Y.Doc();
    let applied = 0;

    for (const e of envelopes) {
      if (e.payload === null) {
        // A withdrawal or rejection RECORD legitimately carries no payload — it is audit, not
        // content. An `update` row with no payload is different: it is a PURGED operation whose
        // bytes are gone (§16.7-12), and folding around it would produce a document that reads
        // as complete while missing an operation. Purge is V2, so this cannot happen yet — which
        // is exactly why it must refuse now rather than become a silent skip later.
        if (e.kind === "update") {
          this.#logger.error("document.replay.failed", {
            documentId: e.documentId,
            envelopeHash: e.envelopeHash,
            reason: "document_envelope_purged",
          });
          throw new DocumentUpdateError(
            "document_envelope_purged",
            `envelope ${e.envelopeHash.slice(0, 16)}… is an update whose payload has been purged — ` +
              `the document cannot be rebuilt without it`,
          );
        }
        continue;
      }

      const res = this.#applyDirect(doc, e.payload);
      if (!res.ok) {
        this.#logger.error("document.replay.failed", {
          documentId: e.documentId,
          envelopeHash: e.envelopeHash,
          reason: res.reason,
          detail: res.detail,
        });
        throw new DocumentUpdateError(
          res.reason,
          `envelope ${e.envelopeHash.slice(0, 16)}…: ${res.detail ?? ""}`,
        );
      }
      applied++;
    }

    this.#logger.info("document.replay.completed", { envelopes: envelopes.length, applied });
    return { binary: Y.encodeStateAsUpdate(doc), stateVector: Y.encodeStateVector(doc) };
  }
}
