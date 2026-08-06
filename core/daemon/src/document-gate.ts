/**
 * DOD-DOC-GATE-1 — the validation gate (§3.2).
 *
 *   arrive → shadow-apply → validate the PROJECTED DIFF → admit or quarantine
 *
 * The shadow document is rebuilt from ACCEPTED state and discarded. Validation asks a question;
 * admitting is a separate, explicit act, so a refused update never touches the live document.
 *
 * ── WHY THE RULES ARE WHAT THEY ARE ───────────────────────────────────────────────────────────
 *
 * Every rule here answers something DOD-DOC-FUZZ-1 MEASURED against real Yjs, and six of the nine
 * are the ACCEPT class — input `Y.applyUpdate` returns SUCCESS for. That matters because the V1
 * posture is "cap, catch, contain" (§16.7-7), and none of its three legs catches an accept: the
 * size cap sees a small update, the try/catch sees success, and "structural limits on the shadow"
 * has nothing to measure because the shadow looks fine. Measured, in order:
 *
 *   (a) an update whose dependencies never arrive is ACCEPTED and RETAINED forever — a peer
 *       streams those until the daemon dies, and a try/catch sees only success;
 *   (b) an update carries NO document identity, so one built on a different document merges
 *       silently — binding is out-of-band work the gate must do;
 *   (c) V2-format bytes are accepted by the v1 decoder and silently drop all content;
 *   (d) trailing bytes past the decoder's cursor are ignored, so unlimited byte strings decode to
 *       identical state — which makes an update's hash a poor identifier for what it says, and
 *       that hash becomes a `0x04` leaf;
 *   (h) authorship IS the clientID, so a colliding one silently wins and the honest client's
 *       update is then accepted-and-dropped, leaving a splice of two authors with an EMPTY
 *       pending set — the (a) rule cannot see this, which is why (h) is separate;
 *   (i) a ten-byte well-formed update deletes a document's entire content. Structural limits are
 *       UPPER bounds, so a shrinking update passes every one of them.
 *
 * The remaining three are the throw class: a size floor (e) because an empty update throws a lib0
 * decoder string rather than a protocol fault, one typed reason per throw (g), and a nesting-depth
 * limit (f) because Yjs bounds depth not at all and the size cap bounds it poorly — ~16 bytes per
 * level, so roughly 65,000 levels fit inside 1 MiB.
 *
 * ── QUARANTINE, NEVER DISCARD ─────────────────────────────────────────────────────────────────
 *
 * A refused update is HELD. Every path out of this gate — including an unexpected failure inside
 * a rule — produces a verdict and an event. A gate that admitted on internal error would be
 * strictly worse than one with no rules at all, and one that dropped silently would diverge the
 * two copies permanently and invisibly (§3.2).
 */

import * as Y from "yjs";
import type { DocumentEngine } from "./document-engine.js";
import type { Logger } from "./types.js";

/** The one accepted update encoding (§16.7-8 pins it in the protocol types). */
export const UPDATE_ENCODING_V1 = "yjs-v1";

export interface GateLimits {
  /** Pre-parse cap: bytes are refused on LENGTH before Yjs is invoked. */
  maxUpdateBytes: number;
  /** The document's size AFTER the update would apply. */
  maxDocumentBytes: number;
  /** Yjs bounds nesting not at all, and the size cap bounds it poorly. */
  maxNestingDepth: number;
  /** Per sender, per rolling minute. */
  maxUpdatesPerMinute: number;
}

/** Published so a peer can discover them — a receiver-local limit nobody can learn is not a protocol. */
export const DEFAULT_GATE_LIMITS: GateLimits = {
  // Deliberately the same number the engine enforces, taken from the engine at construction so
  // the two cannot drift into two sources of truth.
  maxUpdateBytes: 1024 * 1024,
  maxDocumentBytes: 8 * 1024 * 1024,
  maxNestingDepth: 64,
  maxUpdatesPerMinute: 120,
};

/** What the update WOULD do to the document — the only form in which a policy can judge it. */
export interface ProjectedDiff {
  inserted: string;
  deletedChars: number;
  /** Keys a JSON-shaped update would touch. */
  changedKeys: string[];
  /** The document's size if this were admitted. */
  resultingBytes: number;
  maxDepth: number;
}

export interface GateContext {
  documentId: string;
  senderAgentId: string;
  /** clientIDs this peer is KNOWN to write under — the out-of-band binding (h) requires. */
  senderClientIds: number[];
  /**
   * The document the ENVELOPE says this update belongs to (§14). Declared, never inferred: an
   * update carries no document identity, so a well-formed one built on an unrelated document
   * merges silently and no property of the bytes can reveal it. Absent is a refusal.
   *
   * REQUIRED rather than optional so a caller cannot forget it — and the runtime refusal stays
   * for the untyped boundary. **These fields carry no security on their own: they are only as
   * trustworthy as the envelope signature that covers them.** DOD-DOC-ENVELOPE-1 owes a blocking
   * AC that `documentId`, the encoding, and the sender's clientID are inside the signed TBS.
   */
  declaredDocumentId: string | undefined;
  /**
   * The update encoding the ENVELOPE declares (§16.7-8 pins it). Declared rather than sniffed
   * because the byte-level signatures overlap: a v2 update begins `[0, 0, …]` and a legitimate
   * pure-delete v1 delta begins `[0, 1, …]`, so a first-byte heuristic refuses real deletions.
   * Absent is a refusal.
   */
  declaredEncoding: string | undefined;
  appendOnly?: boolean;
  /**
   * DOD-DOC-PROFILE-1 — the character space this document was AGREED to carry, from the signed
   * proposal via the stored row.
   *
   * Taken from the persisted document like `appendOnly`, and for the identical reason: it is agreed
   * at the handshake and bound into `document_id`, so reading it from a caller option would leave a
   * document configured with a profile unprotected unless every future call site remembered to pass
   * it.
   */
  contentProfile?: string;
}

/** A pluggable rule. Returns null to allow. DOD-DOC-SCREEN-1 registers here. */
export type GateRule = (
  diff: ProjectedDiff,
  context: GateContext,
) => { reason: string; detail?: string } | null;

/** Machine-readable, so a peer's daemon can act without parsing prose (§16.7-6). */
export interface GateLimitBreach {
  name: string;
  limit: number;
  actual: number;
}

export interface GateQuarantine {
  admit: false;
  reason: string;
  detail?: string;
  limit?: GateLimitBreach;
  /** The pluggable rule that refused, when one did. */
  rule?: string;
  /**
   * THE UPDATE ITSELF. §3.2: a quarantined update is HELD — never admitted, never discarded — so
   * the caller can persist it, reference it from a `0x05` leaf, and resolve it by supersession
   * (DOD-DOC-REJECT-1). Returning only a reason would have made "never discarded" a comment
   * rather than a property: the bytes would die with this stack frame.
   */
  quarantined: Uint8Array;
}

export type GateVerdict = { admit: true; projectedDiff: ProjectedDiff } | GateQuarantine;

export class DocumentGate {
  readonly #engine: DocumentEngine;
  readonly #limits: GateLimits;
  readonly #logger: Logger;
  readonly #rules = new Map<string, GateRule>();
  /** senderAgentId → recent admission timestamps, for the rate limit. */
  readonly #recent = new Map<string, number[]>();

  constructor(engine: DocumentEngine, limits: Partial<GateLimits>, logger: Logger) {
    this.#engine = engine;
    // The engine already enforces a pre-parse cap; take it rather than repeat the constant, so a
    // change in one place cannot leave the gate admitting what the engine will refuse.
    this.#limits = { ...DEFAULT_GATE_LIMITS, maxUpdateBytes: engine.maxUpdateBytes, ...limits };
    this.#logger = logger;
  }

  limits(): GateLimits {
    return { ...this.#limits };
  }

  /** Register a pluggable rule. The screening rule (DOD-DOC-SCREEN-1) plugs in here. */
  addRule(name: string, rule: GateRule): void {
    this.#rules.set(name, rule);
  }

  /**
   * Validate an incoming update against the accepted state.
   *
   * Never mutates `accepted`. Never throws — every failure, including an unexpected one inside a
   * rule, becomes a quarantine verdict.
   */
  validate(accepted: Y.Doc, update: Uint8Array, context: GateContext, now = Date.now()): GateVerdict {
    try {
      return this.#validate(accepted, update, context, now);
    } catch (err: unknown) {
      // The catch-all is the no-silent-drop invariant made structural: a rule with a bug in it
      // must not become an admission.
      return this.#quarantine(context, update, {
        admit: false,
        reason: "document_gate_rule_failed",
        detail: err instanceof Error ? err.message : String(err),
      });
    }
  }

  #validate(accepted: Y.Doc, update: Uint8Array, context: GateContext, now: number): GateVerdict {
    // ── Pre-parse, before Yjs sees the bytes ────────────────────────────────
    if (update.length > this.#limits.maxUpdateBytes) {
      return this.#quarantine(context, update, {
        admit: false,
        reason: "document_update_too_large",
        limit: { name: "maxUpdateBytes", limit: this.#limits.maxUpdateBytes, actual: update.length },
      });
    }
    if (update.length < 2) {
      // (e) The floor. Below it Yjs throws "Unexpected end of array" — a decoder string naming
      // lib0 internals rather than a protocol fault the peer could act on.
      return this.#quarantine(context, update, {
        admit: false,
        reason: "document_update_too_small",
        detail: `${update.length} bytes is below the 2-byte minimum for a Yjs update`,
      });
    }

    // (c) V2 bytes are ACCEPTED by the v1 decoder and silently drop all content, so the encoding
    // is pinned. Declared, not sniffed — see GateContext.
    if (context.declaredEncoding !== UPDATE_ENCODING_V1) {
      return this.#quarantine(context, update, {
        admit: false,
        reason: "document_update_encoding_unsupported",
        detail: `envelope declares encoding ${JSON.stringify(context.declaredEncoding ?? null)}; ` +
          `only ${UPDATE_ENCODING_V1} is accepted, and v2 bytes decode to an empty document without error`,
      });
    }

    // (b) An update carries NO document identity, so the binding is the envelope's and the check
    // is the receiver's. ABSENT IS NOT FINE: an unbound update is refused, not trusted.
    if (context.declaredDocumentId !== context.documentId) {
      return this.#quarantine(context, update, {
        admit: false,
        reason: "document_update_foreign_origin",
        detail: `envelope declares document ${String(context.declaredDocumentId ?? "(none)").slice(0, 16)}… ` +
          `but this is ${context.documentId.slice(0, 16)}… — updates carry no document identity, so ` +
          `a well-formed update built on another document would otherwise merge silently`,
      });
    }

    // ── Rate, per sender ────────────────────────────────────────────────────
    // Counted on ARRIVAL, after the cheap pre-parse checks and BEFORE the shadow rebuild.
    // Counting admissions instead left a peer who sends only invalid updates un-rate-limited,
    // and everything past this point costs a full encode+apply of the whole document per attempt.
    const window = (this.#recent.get(context.senderAgentId) ?? []).filter((t) => now - t < 60_000);
    if (window.length >= this.#limits.maxUpdatesPerMinute) {
      this.#recent.set(context.senderAgentId, window);
      return this.#quarantine(context, update, {
        admit: false,
        reason: "document_update_rate_exceeded",
        limit: {
          name: "maxUpdatesPerMinute",
          limit: this.#limits.maxUpdatesPerMinute,
          actual: window.length + 1,
        },
      });
    }

    window.push(now);
    this.#recent.set(context.senderAgentId, window);
    // Prune senders whose window has emptied, so the map does not accumulate one entry per peer
    // for the life of the process.
    for (const [sender, times] of this.#recent) {
      if (times.length > 0 && now - times[times.length - 1]! > 60_000) this.#recent.delete(sender);
    }

    // ── Shadow apply, on state rebuilt from ACCEPTED — never long-lived ─────
    const shadow = new Y.Doc();
    try {
      Y.applyUpdate(shadow, Y.encodeStateAsUpdate(accepted));
    } catch (err: unknown) {
      return this.#quarantine(context, update, {
        admit: false,
        reason: "document_accepted_state_unreadable",
        detail: err instanceof Error ? err.message : String(err),
      });
    }

    const beforeText = shadow.getText("content").toString();
    const beforeKeys = new Map(Object.entries(shadow.getMap("data").toJSON() as Record<string, unknown>));

    try {
      Y.applyUpdate(shadow, update);
    } catch (err: unknown) {
      // (g) ONE typed reason per throw. The decoder string is useful and travels as detail —
      // it is simply not a reason an operator or a policy log can key on.
      return this.#quarantine(context, update, {
        admit: false,
        reason: "document_update_malformed",
        detail: err instanceof Error ? err.message : String(err),
      });
    }

    // (a) Yjs returned success — that is not evidence the update integrated. BOTH pending sets
    // count: an update carrying a DELETE SET for structs the receiver has never seen leaves
    // pendingStructs null and pendingDs populated, and that retains forever exactly as the
    // struct case does. Reading one field was coding the mechanism; the rule is about whether
    // the update actually integrated.
    const pendingStructs = shadow.store.pendingStructs;
    const pendingDs = shadow.store.pendingDs;
    if (pendingStructs !== null || pendingDs !== null) {
      return this.#quarantine(context, update, {
        admit: false,
        reason: "document_update_unresolved_dependencies",
        detail: pendingStructs
          ? `depends on ${pendingStructs.missing.size} client(s) whose earlier operations are absent`
          : `carries a delete set referring to operations this document has never seen`,
      });
    }

    // (d) Re-encode THE UPDATE ITSELF and compare. Comparing against the canonical DELTA looked
    // equivalent and is not: a peer that batches several transactions (the normal shape for an
    // append-only log) or sends full state (what y-protocols sync step 2 does with no state
    // vector) produces an update legitimately LARGER than the delta, and both were measured
    // being refused as "trailing bytes" — an attack label on a benign encoding, which sends an
    // operator hunting a malicious peer while the document stops converging.
    //
    // `Y.diffUpdate` against an empty state vector re-encodes the update's own content and drops
    // slack. `Y.mergeUpdates([padded])` does NOT — it preserves the padding — so it is not a
    // usable detector here.
    let canonicalUpdate: Uint8Array;
    try {
      canonicalUpdate = Y.diffUpdate(update, Y.encodeStateVector(new Y.Doc()));
    } catch (err: unknown) {
      // A throw here is a malformed update, not an internal rule failure — labelling it
      // document_gate_rule_failed would name this gate's exit point rather than the peer's fault.
      return this.#quarantine(context, update, {
        admit: false,
        reason: "document_update_malformed",
        detail: err instanceof Error ? err.message : String(err),
      });
    }
    const reEncoded = Y.encodeStateAsUpdate(shadow);
    if (update.length > canonicalUpdate.length) {
      return this.#quarantine(context, update, {
        admit: false,
        reason: "document_update_trailing_bytes",
        detail: `${update.length - canonicalUpdate.length} bytes past the decoder's cursor — the encoding ` +
          `would otherwise be malleable, and this update's hash becomes a 0x04 leaf`,
      });
    }

    // (b) and (h): who wrote this, and on what.
    const authorship = this.#checkAuthorship(accepted, shadow, context);
    if (authorship) return this.#quarantine(context, update, authorship);

    // ── The PROJECTED DIFF — what the update would do ───────────────────────
    const afterText = shadow.getText("content").toString();
    const afterKeys = new Map(Object.entries(shadow.getMap("data").toJSON() as Record<string, unknown>));
    const diff: ProjectedDiff = {
      inserted: insertedText(beforeText, afterText),
      deletedChars: deletedCount(beforeText, afterText),
      changedKeys: [...new Set([...beforeKeys.keys(), ...afterKeys.keys()])].filter(
        (k) => JSON.stringify(beforeKeys.get(k)) !== JSON.stringify(afterKeys.get(k)),
      ),
      resultingBytes: reEncoded.length,
      maxDepth: deepestRoot(shadow, this.#limits.maxNestingDepth),
    };

    // ── Structural limits, on the projected result ──────────────────────────
    if (diff.resultingBytes > this.#limits.maxDocumentBytes) {
      return this.#quarantine(context, update, {
        admit: false,
        reason: "document_too_large",
        limit: { name: "maxDocumentBytes", limit: this.#limits.maxDocumentBytes, actual: diff.resultingBytes },
      });
    }
    if (diff.maxDepth > this.#limits.maxNestingDepth) {
      return this.#quarantine(context, update, {
        admit: false,
        reason: "document_nesting_too_deep",
        limit: { name: "maxNestingDepth", limit: this.#limits.maxNestingDepth, actual: diff.maxDepth },
      });
    }

    // (i) append_only, judged on the PROJECTED DIFF rather than the update's size — a ten-byte
    // update deletes everything and every structural limit passes it.
    //
    // Measured in BOTH coordinate spaces the write path projects from. Diffing only the text root
    // made append_only a COMPLETE NO-OP for json documents, whose content lives in the map: an
    // 8-byte update emptied `data` with deletedChars = 0 and was admitted.
    if (context.appendOnly === true) {
      // The UPDATE'S OWN DELETE SET, not a projection diff. Measured, it is exactly the right
      // question and the projection was not:
      //   - it is root- and type-agnostic, so an append-only document is protected whatever roots
      //     a peer chooses — the previous version protected `content` and `data` and nothing else,
      //     which is no protection at all when the peer names the roots;
      //   - a map key REWRITE deletes the old item, so §16.7-1's "deletes OR EDITS" falls out;
      //   - and growing a NESTED entry deletes nothing, so it is admitted. The projection diff
      //     compared top-level keys with JSON.stringify and called that a removal, refusing the
      //     very append the feature is named for and telling the operator content was removed
      //     when nothing was.
      const deletions = countDeletions(update);
      if (deletions > 0) {
        return this.#quarantine(context, update, {
          admit: false,
          reason: "document_append_only_violation",
          detail: `the update deletes or rewrites ${deletions} existing range(s); this document ` +
            `accepts appends only`,
        });
      }
    }

    // ── Pluggable rules (DOD-DOC-SCREEN-1 registers here) ───────────────────
    for (const [name, rule] of this.#rules) {
      const refusal = rule(diff, context);
      if (refusal) {
        return this.#quarantine(context, update, { admit: false, ...refusal, rule: name });
      }
    }

    this.#logger.info("document.update.admitted", {
      documentId: context.documentId,
      senderAgentId: context.senderAgentId,
      insertedChars: diff.inserted.length,
      deletedChars: diff.deletedChars,
    });
    return { admit: true, projectedDiff: diff };
  }

  /**
   * (h) Every client whose CLOCK ADVANCED must be one this peer is bound to.
   *
   * The first version asked whether a clientID was NEW — exempting any already present in the
   * accepted state, including the document owner's own. That is exactly the attack AC (h) was
   * written from, and it was measured working: integrate the accepted state, THEN set clientID to
   * the owner's, and the forged update is admitted and attributed to the owner ("FORGED honest
   * content"), with an empty pending set so rule (a) cannot see it either. Setting the clientID
   * after integration sidesteps Yjs's own "Changed the client-id" guard; a hand-rolled encoder
   * needs no trick at all.
   *
   * Advancement is the right question for INSERTIONS: a peer never legitimately advances another
   * client's clock. Reusing a clock position below the owner's is deduped by Yjs, and one above
   * leaves a gap that rule (a) catches.
   *
   * IT DOES NOT COVER DELETIONS. A Yjs delete set carries no clientID and advances no clock, so a
   * BOUND peer can delete the owner's content and this rule sees nothing — which is legitimate
   * CRDT behaviour for an authorized writer, not a forgery, but it means `append_only` is the only
   * thing standing between a bound peer and erasure, and it defaults off. Recorded rather than
   * left for a reader to infer, and carried as an AC on DOD-DOC-REJECT-1.
   */
  #checkAuthorship(
    accepted: Y.Doc,
    shadow: Y.Doc,
    context: GateContext,
  ): { admit: false; reason: string; detail?: string } | null {
    const before = Y.decodeStateVector(Y.encodeStateVector(accepted));
    const after = Y.decodeStateVector(Y.encodeStateVector(shadow));
    const bound = new Set(context.senderClientIds);

    const advanced: number[] = [];
    for (const [client, clock] of after) {
      if (clock > (before.get(client) ?? 0)) advanced.push(client);
    }
    const unbound = advanced.filter((c) => !bound.has(c));
    if (unbound.length > 0) {
      return {
        admit: false,
        reason: "document_update_unbound_client",
        detail: `clientID(s) ${unbound.join(", ")} advanced but are not bound to sender ` +
          `${context.senderAgentId.slice(0, 16)}… — either an update authored under another ` +
          `party's identity, or relayed third-party operations, which V1 does not support ` +
          `(hub-and-spoke is deferred, §11.1)`,
      };
    }
    return null;
  }

  #quarantine(context: GateContext, update: Uint8Array, verdict: Omit<GateQuarantine, "quarantined">): GateVerdict {
    // A quarantined update is HELD — never admitted, never discarded — so the record carries what
    // is needed to act on it: which document, which peer, and why (§3.2).
    this.#logger.warn("document.update.quarantined", {
      documentId: context.documentId,
      senderAgentId: context.senderAgentId,
      reason: verdict.reason,
      detail: verdict.detail,
      limit: verdict.limit,
      rule: verdict.rule,
    });
    // COPY. Storing the caller's reference would let a pooled network read buffer be reused
    // underneath us, so DOD-DOC-REJECT-1 would hash bytes that are no longer the ones refused —
    // into a 0x05 leaf, silently.
    return { ...verdict, quarantined: new Uint8Array(update) };
  }
}

function insertedText(before: string, after: string): string {
  if (after.length <= before.length) return "";
  let from = 0;
  while (from < before.length && before[from] === after[from]) from++;
  const tail = before.length - from;
  return after.slice(from, after.length - tail);
}

function deletedCount(before: string, after: string): number {
  let from = 0;
  const max = Math.min(before.length, after.length);
  while (from < max && before[from] === after[from]) from++;
  let suffix = 0;
  while (
    suffix < before.length - from &&
    suffix < after.length - from &&
    before[before.length - 1 - suffix] === after[after.length - 1 - suffix]
  ) {
    suffix++;
  }
  return Math.max(0, before.length - from - suffix);
}

/**
 * The deepest nesting across EVERY root, whatever shape that root is.
 *
 * Two things this must not do, both measured going wrong:
 *
 * 1. **It must not recurse.** `YMap.toJSON()` and a recursive depth walk are mutually recursive,
 *    and past roughly a thousand levels they throw `RangeError: Maximum call stack size exceeded`.
 *    A `catch` around that returned 0, which INVERTED the rule — 30 levels were caught and 5,000
 *    sailed through, so the deeper the attack the more certain it passed. Worse, it converted the
 *    gate's own fail-safe catch-all into an admission. This walk is iterative and bails the moment
 *    it passes the limit it is enforcing, so it never goes deeper than it has to.
 * 2. **It must not instantiate roots by a guessed type.** `doc.getMap(name)` MIGRATES an
 *    uninstantiated root to a map in place, so an Array- or Text-shaped root became an empty map
 *    and reported depth 0 — the same bypass, reached with a different type. Walking Yjs's own item
 *    graph is shape-agnostic: a nested type is a nested type whether it hangs off `_map` or the
 *    `_start` list.
 */
function deepestRoot(doc: Y.Doc, bailAt: number): number {
  let deepest = 0;
  const stack: Array<{ type: Y.AbstractType<unknown>; depth: number }> = [];
  for (const root of doc.share.values()) {
    stack.push({ type: root as Y.AbstractType<unknown>, depth: 0 });
  }

  while (stack.length > 0) {
    const { type, depth } = stack.pop()!;
    if (depth > deepest) deepest = depth;
    // Never walk deeper than the limit under enforcement — the answer cannot change.
    if (deepest > bailAt) return deepest;

    const internals = type as unknown as {
      _map?: Map<string, { content?: unknown }>;
      _start?: { content?: unknown; right?: unknown } | null;
    };
    if (internals._map) {
      for (const item of internals._map.values()) {
        const nested = nestedType(item);
        if (nested) stack.push({ type: nested, depth: depth + 1 });
      }
    }
    let item = internals._start;
    while (item) {
      const nested = nestedType(item);
      if (nested) stack.push({ type: nested, depth: depth + 1 });
      item = item.right as typeof item;
    }
  }
  return deepest;
}

/** The type nested inside an item, or null when the item holds a plain value. */
function nestedType(item: { content?: unknown } | null | undefined): Y.AbstractType<unknown> | null {
  const content = item?.content;
  if (content instanceof Y.ContentType) {
    return content.type as Y.AbstractType<unknown>;
  }
  return null;
}

/**
 * How many ranges this update deletes — the basis for `append_only`.
 *
 * The update's own delete set, rather than a diff of the projected document. Measured, that is
 * the right question and a projection diff was not: this is root- and type-agnostic (so a peer
 * cannot escape by naming its own roots), a map-key rewrite deletes the old item so §16.7-1's
 * "deletes OR EDITS" falls out, and growing a nested entry deletes nothing so it is admitted.
 */
function countDeletions(update: Uint8Array): number {
  try {
    const { ds } = Y.decodeUpdate(update);
    let total = 0;
    for (const ranges of ds.clients.values()) total += ranges.length;
    return total;
  } catch {
    // Undecodable here means the malformed check upstream already refused it. Inventing an
    // append_only violation from a decode failure would name the wrong cause.
    return 0;
  }
}
