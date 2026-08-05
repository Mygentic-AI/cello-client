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
  agentId: string;
  documentId: string;
  senderAgentId: string;
  /** clientIDs this peer is KNOWN to write under — the out-of-band binding (h) requires. */
  senderClientIds: number[];
  /**
   * The document the ENVELOPE says this update belongs to (§14). Declared, never inferred: an
   * update carries no document identity, so a well-formed one built on an unrelated document
   * merges silently and no property of the bytes can reveal it. Absent is a refusal.
   */
  declaredDocumentId?: string;
  /**
   * The update encoding the ENVELOPE declares (§16.7-8 pins it). Declared rather than sniffed
   * because the byte-level signatures overlap: a v2 update begins `[0, 0, …]` and a legitimate
   * pure-delete v1 delta begins `[0, 1, …]`, so a first-byte heuristic refuses real deletions.
   * Absent is a refusal.
   */
  declaredEncoding?: string;
  appendOnly?: boolean;
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
    this.#limits = { ...DEFAULT_GATE_LIMITS, ...limits };
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
      return this.#quarantine(context, {
        admit: false,
        reason: "document_gate_rule_failed",
        detail: err instanceof Error ? err.message : String(err),
      });
    }
  }

  #validate(accepted: Y.Doc, update: Uint8Array, context: GateContext, now: number): GateVerdict {
    // ── Pre-parse, before Yjs sees the bytes ────────────────────────────────
    if (update.length > this.#limits.maxUpdateBytes) {
      return this.#quarantine(context, {
        admit: false,
        reason: "document_update_too_large",
        limit: { name: "maxUpdateBytes", limit: this.#limits.maxUpdateBytes, actual: update.length },
      });
    }
    if (update.length < 2) {
      // (e) The floor. Below it Yjs throws "Unexpected end of array" — a decoder string naming
      // lib0 internals rather than a protocol fault the peer could act on.
      return this.#quarantine(context, {
        admit: false,
        reason: "document_update_too_small",
        detail: `${update.length} bytes is below the 2-byte minimum for a Yjs update`,
      });
    }

    // (c) V2 bytes are ACCEPTED by the v1 decoder and silently drop all content, so the encoding
    // is pinned. Declared, not sniffed — see GateContext.
    if (context.declaredEncoding !== UPDATE_ENCODING_V1) {
      return this.#quarantine(context, {
        admit: false,
        reason: "document_update_encoding_unsupported",
        detail: `envelope declares encoding ${JSON.stringify(context.declaredEncoding ?? null)}; ` +
          `only ${UPDATE_ENCODING_V1} is accepted, and v2 bytes decode to an empty document without error`,
      });
    }

    // (b) An update carries NO document identity, so the binding is the envelope's and the check
    // is the receiver's. ABSENT IS NOT FINE: an unbound update is refused, not trusted.
    if (context.declaredDocumentId !== context.documentId) {
      return this.#quarantine(context, {
        admit: false,
        reason: "document_update_foreign_origin",
        detail: `envelope declares document ${String(context.declaredDocumentId ?? "(none)").slice(0, 16)}… ` +
          `but this is ${context.documentId.slice(0, 16)}… — updates carry no document identity, so ` +
          `a well-formed update built on another document would otherwise merge silently`,
      });
    }

    // ── Rate, per sender ────────────────────────────────────────────────────
    const window = (this.#recent.get(context.senderAgentId) ?? []).filter((t) => now - t < 60_000);
    if (window.length >= this.#limits.maxUpdatesPerMinute) {
      this.#recent.set(context.senderAgentId, window);
      return this.#quarantine(context, {
        admit: false,
        reason: "document_update_rate_exceeded",
        limit: {
          name: "maxUpdatesPerMinute",
          limit: this.#limits.maxUpdatesPerMinute,
          actual: window.length + 1,
        },
      });
    }

    // ── Shadow apply, on state rebuilt from ACCEPTED — never long-lived ─────
    const shadow = new Y.Doc();
    try {
      Y.applyUpdate(shadow, Y.encodeStateAsUpdate(accepted));
    } catch (err: unknown) {
      return this.#quarantine(context, {
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
      return this.#quarantine(context, {
        admit: false,
        reason: "document_update_malformed",
        detail: err instanceof Error ? err.message : String(err),
      });
    }

    // (a) Yjs returned success — that is not evidence the update integrated.
    if (shadow.store.pendingStructs !== null) {
      return this.#quarantine(context, {
        admit: false,
        reason: "document_update_unresolved_dependencies",
        detail: `depends on ${shadow.store.pendingStructs.missing.size} client(s) whose earlier operations are absent`,
      });
    }

    // (d) Trailing bytes past the decoder's cursor are ignored, so the detector is re-encoding
    // the SAME delta canonically — the shadow's state since the accepted state vector — and
    // comparing byte counts. Comparing against the full state would compare a delta to a
    // snapshot, which are different things and different lengths for legitimate reasons.
    const canonicalDelta = Y.encodeStateAsUpdate(shadow, Y.encodeStateVector(accepted));
    const reEncoded = Y.encodeStateAsUpdate(shadow);
    if (update.length > canonicalDelta.length) {
      return this.#quarantine(context, {
        admit: false,
        reason: "document_update_trailing_bytes",
        detail: `${update.length - canonicalDelta.length} bytes past the decoder's cursor — the encoding ` +
          `would otherwise be malleable, and this update's hash becomes a 0x04 leaf`,
      });
    }

    // (b) and (h): who wrote this, and on what.
    const authorship = this.#checkAuthorship(accepted, shadow, context);
    if (authorship) return this.#quarantine(context, authorship);

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
      maxDepth: maxDepth(shadow.getMap("data").toJSON()),
    };

    // ── Structural limits, on the projected result ──────────────────────────
    if (diff.resultingBytes > this.#limits.maxDocumentBytes) {
      return this.#quarantine(context, {
        admit: false,
        reason: "document_too_large",
        limit: { name: "maxDocumentBytes", limit: this.#limits.maxDocumentBytes, actual: diff.resultingBytes },
      });
    }
    if (diff.maxDepth > this.#limits.maxNestingDepth) {
      return this.#quarantine(context, {
        admit: false,
        reason: "document_nesting_too_deep",
        limit: { name: "maxNestingDepth", limit: this.#limits.maxNestingDepth, actual: diff.maxDepth },
      });
    }

    // (i) append_only, judged on the PROJECTED DIFF rather than on the update's size — a
    // ten-byte update can delete everything, and every structural limit passes it.
    if (context.appendOnly === true && diff.deletedChars > 0) {
      return this.#quarantine(context, {
        admit: false,
        reason: "document_append_only_violation",
        detail: `the projected diff removes ${diff.deletedChars} character(s) of existing content`,
      });
    }

    // ── Pluggable rules (DOD-DOC-SCREEN-1 registers here) ───────────────────
    for (const [name, rule] of this.#rules) {
      const refusal = rule(diff, context);
      if (refusal) {
        return this.#quarantine(context, { admit: false, ...refusal, rule: name });
      }
    }

    window.push(now);
    this.#recent.set(context.senderAgentId, window);
    this.#logger.info("document.update.admitted", {
      documentId: context.documentId,
      senderAgentId: context.senderAgentId,
      insertedChars: diff.inserted.length,
      deletedChars: diff.deletedChars,
    });
    return { admit: true, projectedDiff: diff };
  }

  /**
   * (h) Every newly-seen clientID must be one this peer is bound to.
   *
   * Not detectable from the update — authorship in Yjs IS the clientID, which is exactly why a
   * colliding one silently outranks the honest client and leaves an EMPTY pending set, so rule
   * (a) cannot see it. The binding is an out-of-band fact the gate is given.
   */
  #checkAuthorship(
    accepted: Y.Doc,
    shadow: Y.Doc,
    context: GateContext,
  ): { admit: false; reason: string; detail?: string } | null {
    const acceptedClients = new Set(Y.decodeStateVector(Y.encodeStateVector(accepted)).keys());
    const shadowClients = [...Y.decodeStateVector(Y.encodeStateVector(shadow)).keys()];
    const bound = new Set(context.senderClientIds);
    const unbound = shadowClients.filter((c) => !acceptedClients.has(c) && !bound.has(c));
    if (unbound.length > 0) {
      return {
        admit: false,
        reason: "document_update_unbound_client",
        detail: `clientID(s) ${unbound.join(", ")} are not bound to sender ${context.senderAgentId.slice(0, 16)}… — ` +
          `authorship in Yjs IS the clientID, so an unbound one can silently outrank the honest client`,
      };
    }
    return null;
  }

  #quarantine(context: GateContext, verdict: GateQuarantine): GateVerdict {
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
    return verdict;
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

function maxDepth(value: unknown, depth = 0): number {
  if (value === null || typeof value !== "object") return depth;
  let deepest = depth;
  for (const child of Object.values(value as Record<string, unknown>)) {
    deepest = Math.max(deepest, maxDepth(child, depth + 1));
  }
  return deepest;
}
