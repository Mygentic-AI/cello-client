/**
 * DOD-DOC-INBOUND-2 — the live `Y.Doc` cache.
 *
 * The inbound path needs a document to apply an update to, and it must be THE document — the same
 * object every subsequent update sees. Materializing a fresh one per frame would make each update
 * land on an empty doc and converge with nothing.
 *
 * ── WHY THIS IS A UNIT AND NOT A `Map` IN THE COMPOSITION ROOT ────────────────────────────────
 *
 * Three properties, and each is a defect if it goes the other way:
 *
 *   RESTORED FROM THE LOG, not created empty. A daemon restart must not lose the document — the
 *   log is what makes it survivable, and a cache that starts blank silently discards everything
 *   the operator and their peer have written. `rebuildSnapshot` verifies the chain before replaying,
 *   so a document that cannot be rebuilt REFUSES rather than coming back partial.
 *
 *   BOUNDED. A daemon attends many agents over a long life and a `Y.Doc` holds the whole document
 *   plus its history. An unbounded map is a leak whose symptom is the daemon dying days later with
 *   no obvious cause — the shape `session-node-manager.ts` already had to fix once for received
 *   content. Eviction is safe here in a way it usually is not: the log is the truth, so an evicted
 *   document is rebuilt on next use rather than lost.
 *
 *   EVICTION IS NEVER SILENT DATA LOSS, which is only true because the two above hold together. If
 *   eviction existed without log-backed restore it would be exactly the silent loss it looks like.
 */

import * as Y from "yjs";
import type { DocumentStore } from "./document-store.js";
import type { DocumentEngine } from "./document-engine.js";
import type { Logger } from "./types.js";

/**
 * How many documents stay resident. Small on purpose: an operator collaborates on a handful at a
 * time, and the cost of a miss is a rebuild from the log, not a failure.
 */
export const LIVE_DOC_CACHE_SIZE = 32;

export class LiveDocuments {
  readonly #store: DocumentStore;
  readonly #engine: DocumentEngine;
  readonly #logger: Logger;
  /** Insertion-ordered, so the oldest key is the eviction candidate. */
  readonly #live = new Map<string, Y.Doc>();

  /** Epoch zero for a document, from its stored proposal. See `get`. */
  readonly #startingContentFor: (ownerAgentId: string, documentId: string) => Uint8Array | null;

  constructor(
    store: DocumentStore,
    engine: DocumentEngine,
    logger: Logger,
    startingContentFor: (ownerAgentId: string, documentId: string) => Uint8Array | null = () => null,
  ) {
    this.#store = store;
    this.#engine = engine;
    this.#logger = logger;
    this.#startingContentFor = startingContentFor;
  }

  /**
   * The live document, restored from the log on a miss.
   *
   * THROWS rather than returning an empty document when the log cannot be rebuilt. An empty doc
   * here would be applied to, published from, and would converge the peer's real content away — a
   * silent whole-document loss originating in a cache miss.
   *
   * PRECISION, measured 2026-08-05: that covers a log that EXISTS and does not verify. An id this
   * daemon has never heard of has no log to fail on, so it comes back as a legitimately empty
   * document. Harmless only because every caller checks `documents` first — the operator surface
   * refuses with `document_unknown`, and the inbound path refuses before materializing anything.
   * A future caller that skips that check gets an empty document and no signal, so the check is
   * part of the contract rather than an incidental habit of the current callers.
   */
  get(ownerAgentId: string, documentId: string): Y.Doc {
    // `\0` as the ESCAPE, not a literal NUL byte. Written raw, git classifies the whole file as
    // binary — `git diff` reports `Bin 4508 -> 5084` and shows nothing — so every change to this
    // file is invisible to code review. Caught by a reviewer who had to strip the bytes to read it.
    const key = `${ownerAgentId}\0${documentId}`;
    const hit = this.#live.get(key);
    if (hit) {
      // Refresh recency: delete and re-insert so the Map's insertion order is a true LRU rather
      // than a first-in-first-out queue that evicts the document being actively edited.
      this.#live.delete(key);
      this.#live.set(key, hit);
      return hit;
    }

    const snapshot = this.#store.rebuildSnapshot(ownerAgentId, documentId, (rows) =>
      this.#engine.replay(rows),
    );
    const doc = this.#engine.restore(snapshot.binary);
    // EPOCH ZERO FIRST, and it is not in the envelope log.
    //
    // A document's starting content is agreed in the PROPOSAL — both sides apply the same bytes, so
    // neither has to author it and there is no first envelope carrying it. That is correct on the
    // wire and it left the content living only in the `Y.Doc` the propose/accept handler happened to
    // be holding: restart the daemon and the document came back EMPTY, on both sides, with the row
    // still present and the log still valid. An operator would open a document they had been
    // working in and find nothing there — and then write into it, publishing the deletion of
    // everything the peer still had.
    //
    // Re-applied here rather than logged at accept time because the proposal is already stored and
    // `document_id` is the hash of it: taking epoch zero from the proposal is deterministic on both
    // sides forever, while an envelope written at accept would be one side's authored operation and
    // the two would not match.
    //
    // Applying to a rebuilt doc is safe and idempotent — a Yjs update already present is a no-op,
    // which is the property the whole replay depends on.
    const starting = this.#startingContentFor(ownerAgentId, documentId);
    if (starting) this.#engine.applyUpdate(doc, starting);
    this.#live.set(key, doc);
    this.#evictIfNeeded();
    return doc;
  }

  /** Drop one document — after a kill or close, where keeping it resident buys nothing. */
  release(ownerAgentId: string, documentId: string): void {
    const key = `${ownerAgentId}\0${documentId}`;
    const doc = this.#live.get(key);
    if (!doc) return;
    this.#live.delete(key);
    doc.destroy();
  }

  /** Resident count, for tests and for an operator-facing surface that wants to show it. */
  size(): number {
    return this.#live.size;
  }

  #evictIfNeeded(): void {
    while (this.#live.size > LIVE_DOC_CACHE_SIZE) {
      const oldest = this.#live.keys().next();
      if (oldest.done === true) return;
      const doc = this.#live.get(oldest.value);
      this.#live.delete(oldest.value);
      // DESTROYED, not just dropped. A Y.Doc holds observers; releasing the reference without
      // destroying it leaves them attached and the memory reachable, which is the leak this cache
      // exists to prevent wearing a different shape.
      doc?.destroy();
      this.#logger.debug("document.live.evicted", { resident: this.#live.size });
    }
  }
}
