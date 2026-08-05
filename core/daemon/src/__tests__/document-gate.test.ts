/**
 * DOD-DOC-GATE-1 — the validation gate (§3.2).
 *
 * arrive → shadow-apply → validate the PROJECTED DIFF → admit or quarantine.
 *
 * The nine acceptance criteria (a)–(i) on this unit are not design intuitions: DOD-DOC-FUZZ-1
 * MEASURED them against real Yjs, and six of them are the ACCEPT class — input Yjs returns
 * success for. "Cap, catch, contain" does not catch any of those, because the try/catch sees
 * success and the shadow document shows no violation to measure. Each test below names the
 * criterion it pins.
 *
 * Determinism: every concurrent case pins clientIDs (see yjs-determinism.test.ts for why).
 */

import { describe, it, expect } from "vitest";
import * as Y from "yjs";
import { DocumentEngine } from "../document-engine.js";
import { DocumentGate, UPDATE_ENCODING_V1, type GateVerdict } from "../document-gate.js";

const AGENT = "aa".repeat(32);
const PEER = "bb".repeat(32);
const DOC = "cc".repeat(32);

function recordingLogger(): { logger: never; events: Array<{ event: string; fields: Record<string, unknown> }> } {
  const events: Array<{ event: string; fields: Record<string, unknown> }> = [];
  const capture = (event: string, fields: Record<string, unknown> = {}) => void events.push({ event, fields });
  return {
    logger: { debug: capture, info: capture, warn: capture, error: capture } as never,
    events,
  };
}

function newGate(overrides: Partial<ConstructorParameters<typeof DocumentGate>[1]> = {}) {
  const { logger, events } = recordingLogger();
  const gate = new DocumentGate(new DocumentEngine(logger), { ...overrides }, logger);
  return { gate, events };
}

/** An accepted-state document with a pinned clientID. */
function acceptedDoc(text = "the accepted document body"): Y.Doc {
  const doc = new Y.Doc();
  doc.clientID = 1_000_000;
  if (text) doc.getText("content").insert(0, text);
  return doc;
}

/** A well-formed update from a peer, built on the accepted state. */
function peerUpdate(accepted: Y.Doc, clientId: number, mutate: (doc: Y.Doc) => void): Uint8Array {
  const peer = new Y.Doc();
  peer.clientID = clientId;
  Y.applyUpdate(peer, Y.encodeStateAsUpdate(accepted));
  mutate(peer);
  return Y.encodeStateAsUpdate(peer, Y.encodeStateVector(accepted));
}

/**
 * The envelope's declared bindings travel WITH the update (§14). They are parameters rather than
 * anything inferred from the bytes, because the measured finding is that the bytes cannot say:
 * an update carries no document identity, and a v2 update's first bytes overlap a legitimate
 * pure-delete v1 delta's.
 */
const context = {
  agentId: AGENT,
  documentId: DOC,
  senderAgentId: PEER,
  senderClientIds: [500],
  declaredDocumentId: DOC,
  declaredEncoding: UPDATE_ENCODING_V1,
};

describe("DocumentGate — the happy path", () => {
  it("ADMITS a well-formed update and reports the projected diff", () => {
    const { gate } = newGate();
    const accepted = acceptedDoc();
    const update = peerUpdate(accepted, 500, (d) => d.getText("content").insert(26, " plus more"));

    const verdict = gate.validate(accepted, update, context);
    expect(verdict.admit).toBe(true);
    if (verdict.admit) {
      // The gate validates the PROJECTED DIFF, so it must be able to say what the diff was.
      expect(verdict.projectedDiff.inserted).toContain("plus more");
      expect(verdict.projectedDiff.deletedChars).toBe(0);
    }
  });

  it("the shadow document is NEVER long-lived — the accepted doc is untouched by validation", () => {
    const { gate } = newGate();
    const accepted = acceptedDoc();
    const before = accepted.getText("content").toString();
    gate.validate(accepted, peerUpdate(accepted, 500, (d) => d.getText("content").insert(0, "X")), context);
    // §3.2: the shadow is rebuilt from accepted state and discarded. Validation is a question,
    // not a mutation — admitting is a separate, explicit act.
    expect(accepted.getText("content").toString()).toBe(before);
  });
});

describe("DocumentGate — the ACCEPT class (a)–(d), (h): what Yjs returns success for", () => {
  it("(a) QUARANTINES an update whose dependencies never arrive", () => {
    const { gate } = newGate();
    const accepted = acceptedDoc("");
    const source = new Y.Doc();
    source.clientID = 500;
    const updates: Uint8Array[] = [];
    source.on("update", (u: Uint8Array) => updates.push(u));
    for (let i = 0; i < 4; i++) source.getText("content").insert(0, `chunk${i} `);

    // Skip the first, so the rest depend on structs the receiver never sees. Yjs ACCEPTS these
    // and retains them forever — a peer streams them until the daemon dies.
    const verdict = gate.validate(accepted, updates[2]!, context);
    expect(verdict.admit).toBe(false);
    if (!verdict.admit) expect(verdict.reason).toBe("document_update_unresolved_dependencies");
  });

  it("(b) QUARANTINES an update whose envelope names a DIFFERENT document", () => {
    const { gate } = newGate();
    const accepted = acceptedDoc("my document");
    // A perfectly well-formed update, correctly signed, from a bound peer — for another document.
    // Nothing in the bytes can reveal that, which is why the binding is declared and checked.
    const update = peerUpdate(accepted, 500, (d) => d.getText("content").insert(0, "X"));

    const verdict = gate.validate(accepted, update, {
      ...context,
      declaredDocumentId: "dd".repeat(32),
    });
    expect(verdict.admit).toBe(false);
    if (!verdict.admit) expect(verdict.reason).toBe("document_update_foreign_origin");
  });

  it("(b) QUARANTINES an update with NO declared document — absent is not fine", () => {
    const { gate } = newGate();
    const accepted = acceptedDoc("my document");
    const update = peerUpdate(accepted, 500, (d) => d.getText("content").insert(0, "X"));
    const withoutBinding = { ...context, declaredDocumentId: undefined };

    const verdict = gate.validate(accepted, update, withoutBinding);
    expect(verdict.admit).toBe(false);
    if (!verdict.admit) expect(verdict.reason).toBe("document_update_foreign_origin");
  });

  it("(c) QUARANTINES an update whose envelope declares a non-v1 encoding", () => {
    const { gate } = newGate();
    const accepted = acceptedDoc("");
    const source = new Y.Doc();
    source.clientID = 500;
    source.getText("content").insert(0, "content that would vanish");

    // V2 bytes are ACCEPTED by the v1 decoder and silently drop everything, so the version is
    // pinned on the wire rather than sniffed: a v2 update begins [0,0,…] and a legitimate
    // pure-delete v1 delta begins [0,1,…], so a first-byte heuristic would refuse real deletions.
    const verdict = gate.validate(accepted, Y.encodeStateAsUpdateV2(source), {
      ...context,
      declaredEncoding: "yjs-v2",
    });
    expect(verdict.admit).toBe(false);
    if (!verdict.admit) expect(verdict.reason).toBe("document_update_encoding_unsupported");
  });

  it("(c) QUARANTINES an update with NO declared encoding", () => {
    const { gate } = newGate();
    const accepted = acceptedDoc("");
    const update = peerUpdate(accepted, 500, (d) => d.getText("content").insert(0, "x"));
    const withoutEncoding = { ...context, declaredEncoding: undefined };

    const verdict = gate.validate(accepted, update, withoutEncoding);
    expect(verdict.admit).toBe(false);
    if (!verdict.admit) expect(verdict.reason).toBe("document_update_encoding_unsupported");
  });

  it("(d) QUARANTINES an update with TRAILING BYTES — the encoding is otherwise malleable", () => {
    const { gate } = newGate();
    const accepted = acceptedDoc("hello");
    const clean = peerUpdate(accepted, 500, (d) => d.getText("content").insert(5, " world"));
    const padded = new Uint8Array(clean.length + 3);
    padded.set(clean);
    padded.set([0, 0, 0], clean.length);

    // Unlimited byte strings decode to identical state, so an unbounded update is not a stable
    // identifier for what it says — which matters because its hash becomes a 0x04 leaf.
    expect(gate.validate(accepted, clean, context).admit).toBe(true);
    const verdict = gate.validate(accepted, padded, context);
    expect(verdict.admit).toBe(false);
    if (!verdict.admit) expect(verdict.reason).toBe("document_update_trailing_bytes");
  });

  it("(h) QUARANTINES an update whose clientID is not one the peer is known to use", () => {
    const { gate } = newGate();
    const accepted = acceptedDoc("honest content");
    // The peer writes under a clientID the receiver has not bound to their identity. Yjs cannot
    // detect this — authorship IS the clientID — so the binding is the gate's job.
    const update = peerUpdate(accepted, 999_999, (d) => d.getText("content").insert(0, "FORGED "));

    const verdict = gate.validate(accepted, update, context);
    expect(verdict.admit).toBe(false);
    if (!verdict.admit) expect(verdict.reason).toBe("document_update_unbound_client");
  });

  it("(h) ADMITS an update under a clientID the peer IS known to use", () => {
    const { gate } = newGate();
    const accepted = acceptedDoc("honest content");
    const update = peerUpdate(accepted, 500, (d) => d.getText("content").insert(0, "theirs "));
    expect(gate.validate(accepted, update, context).admit).toBe(true);
  });
});

describe("DocumentGate — the throw class (e), (g)", () => {
  it("(e) QUARANTINES an update below the two-byte floor with a PROTOCOL reason", () => {
    const { gate } = newGate();
    const accepted = acceptedDoc();
    for (const tooSmall of [new Uint8Array(0), new Uint8Array(1)]) {
      const verdict = gate.validate(accepted, tooSmall, context);
      expect(verdict.admit).toBe(false);
      if (!verdict.admit) {
        expect(verdict.reason).toBe("document_update_too_small");
        // Never "Unexpected end of array" — that names lib0's decoder, not the peer's fault.
        expect(verdict.reason).not.toContain("array");
      }
    }
  });

  it("(g) maps EVERY Yjs throw to one typed reason, carrying the decoder string as detail", () => {
    const { gate } = newGate();
    const accepted = acceptedDoc();
    const verdict = gate.validate(accepted, new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff]), context);
    expect(verdict.admit).toBe(false);
    if (!verdict.admit) {
      expect(verdict.reason).toBe("document_update_malformed");
      expect(verdict.detail).toBeTruthy();
    }
  });
});

describe("DocumentGate — receiver-local limits (§16.7-6), reasons naming the limit AND the value", () => {
  it("refuses an oversized update, naming both the limit and what arrived", () => {
    const { gate } = newGate({ maxUpdateBytes: 64 });
    const accepted = acceptedDoc();
    const big = peerUpdate(accepted, 500, (d) => d.getText("content").insert(0, "x".repeat(500)));

    const verdict = gate.validate(accepted, big, context);
    expect(verdict.admit).toBe(false);
    if (!verdict.admit) {
      expect(verdict.reason).toBe("document_update_too_large");
      // Machine-readable: the peer's daemon has to be able to act on this without parsing prose.
      expect(verdict.limit).toEqual({ name: "maxUpdateBytes", limit: 64, actual: big.length });
    }
  });

  it("refuses an update that would push the DOCUMENT past its size limit", () => {
    const { gate } = newGate({ maxDocumentBytes: 40 });
    const accepted = acceptedDoc("small");
    const update = peerUpdate(accepted, 500, (d) => d.getText("content").insert(5, "y".repeat(200)));

    const verdict = gate.validate(accepted, update, context);
    expect(verdict.admit).toBe(false);
    if (!verdict.admit) {
      expect(verdict.reason).toBe("document_too_large");
      expect(verdict.limit?.name).toBe("maxDocumentBytes");
    }
  });

  it("(f) refuses an update exceeding the NESTING DEPTH limit — Yjs bounds depth not at all", () => {
    const { gate } = newGate({ maxNestingDepth: 5 });
    const accepted = acceptedDoc("");
    const deep = new Y.Doc();
    deep.clientID = 500;
    Y.applyUpdate(deep, Y.encodeStateAsUpdate(accepted));
    let map = deep.getMap("data");
    for (let i = 0; i < 20; i++) {
      const child = new Y.Map();
      map.set("child", child);
      map = child;
    }
    const update = Y.encodeStateAsUpdate(deep, Y.encodeStateVector(accepted));

    const verdict = gate.validate(accepted, update, context);
    expect(verdict.admit).toBe(false);
    if (!verdict.admit) {
      expect(verdict.reason).toBe("document_nesting_too_deep");
      expect(verdict.limit?.name).toBe("maxNestingDepth");
      // The size cap bounds depth poorly — ~16 bytes/level, so ~65,000 levels fit in 1 MiB.
      // The depth limit is therefore load-bearing, not a nicety.
      expect(update.length).toBeLessThan(4096);
    }
  });

  it("refuses when the update RATE limit is exceeded, naming the window", () => {
    const { gate } = newGate({ maxUpdatesPerMinute: 3 });
    const accepted = acceptedDoc();
    const update = peerUpdate(accepted, 500, (d) => d.getText("content").insert(0, "a"));

    let lastVerdict: GateVerdict | null = null;
    for (let i = 0; i < 5; i++) lastVerdict = gate.validate(accepted, update, context);

    expect(lastVerdict!.admit).toBe(false);
    if (!lastVerdict!.admit) {
      expect(lastVerdict!.reason).toBe("document_update_rate_exceeded");
      expect(lastVerdict!.limit?.name).toBe("maxUpdatesPerMinute");
    }
  });

  it("publishes its defaults — a receiver-local limit a peer cannot discover is not a protocol", () => {
    const { gate } = newGate();
    const defaults = gate.limits();
    expect(defaults.maxUpdateBytes).toBeGreaterThan(0);
    expect(defaults.maxDocumentBytes).toBeGreaterThan(0);
    expect(defaults.maxNestingDepth).toBeGreaterThan(0);
    expect(defaults.maxUpdatesPerMinute).toBeGreaterThan(0);
  });
});

describe("DocumentGate — (i) append_only, which needed a measurement behind it", () => {
  it("QUARANTINES an update whose projected diff DELETES existing content", () => {
    const { gate } = newGate();
    const accepted = acceptedDoc("content that must not be destroyed");
    // A ten-byte well-formed update wipes a document. Structural limits are UPPER bounds, so a
    // shrinking update passes every one of them and the shadow is merely smaller.
    const deletion = peerUpdate(accepted, 500, (d) => d.getText("content").delete(0, 33));
    expect(deletion.length).toBeLessThan(32);

    const verdict = gate.validate(accepted, deletion, { ...context, appendOnly: true });
    expect(verdict.admit).toBe(false);
    if (!verdict.admit) expect(verdict.reason).toBe("document_append_only_violation");
  });

  it("QUARANTINES an update that EDITS existing content, not just one that deletes", () => {
    const { gate } = newGate();
    const accepted = acceptedDoc("original text");
    const edit = peerUpdate(accepted, 500, (d) => {
      d.getText("content").delete(0, 8);
      d.getText("content").insert(0, "modified");
    });

    const verdict = gate.validate(accepted, edit, { ...context, appendOnly: true });
    expect(verdict.admit).toBe(false);
    if (!verdict.admit) expect(verdict.reason).toBe("document_append_only_violation");
  });

  it("ADMITS a pure append on an append_only document", () => {
    const { gate } = newGate();
    const accepted = acceptedDoc("existing entry");
    const append = peerUpdate(accepted, 500, (d) =>
      d.getText("content").insert(14, "\nappended entry"),
    );
    expect(gate.validate(accepted, append, { ...context, appendOnly: true }).admit).toBe(true);
  });

  it("the same deletion is ADMITTED when the document is not append_only", () => {
    const { gate } = newGate();
    const accepted = acceptedDoc("deletable content");
    const deletion = peerUpdate(accepted, 500, (d) => d.getText("content").delete(0, 9));
    expect(gate.validate(accepted, deletion, context).admit).toBe(true);
  });
});

describe("DocumentGate — no silent drop: EVERY refusal is observable", () => {
  it("every refusal emits document.update.quarantined with a machine-readable reason", () => {
    const { gate, events } = newGate({ maxUpdateBytes: 32 });
    const accepted = acceptedDoc();

    gate.validate(accepted, new Uint8Array(0), context);
    gate.validate(accepted, new Uint8Array([0xff, 0xff, 0xff]), context);
    gate.validate(accepted, peerUpdate(accepted, 500, (d) => d.getText("content").insert(0, "x".repeat(200))), context);

    const quarantined = events.filter((e) => e.event === "document.update.quarantined");
    expect(quarantined).toHaveLength(3);
    // A quarantined update is HELD — never admitted, never discarded — so the record has to
    // carry enough to act on: which document, which peer, and why.
    for (const q of quarantined) {
      expect(typeof q.fields.reason).toBe("string");
      expect(q.fields.documentId).toBe(DOC);
      expect(q.fields.senderAgentId).toBe(PEER);
    }
  });

  it("an admission emits document.update.admitted", () => {
    const { gate, events } = newGate();
    const accepted = acceptedDoc();
    gate.validate(accepted, peerUpdate(accepted, 500, (d) => d.getText("content").insert(0, "ok")), context);
    expect(events.some((e) => e.event === "document.update.admitted")).toBe(true);
  });

  it("an UNEXPECTED failure inside the gate still quarantines — it never falls through to admit", () => {
    const { gate, events } = newGate();
    const accepted = acceptedDoc();
    // A rule that throws stands in for any future rule with a bug in it. The no-silent-drop
    // invariant says every error path quarantines and emits; a gate that admitted on an internal
    // error would be strictly worse than one with no rules at all.
    gate.addRule("exploding-rule", () => {
      throw new Error("rule blew up");
    });

    const verdict = gate.validate(accepted, peerUpdate(accepted, 500, (d) => d.getText("content").insert(0, "x")), context);
    expect(verdict.admit).toBe(false);
    if (!verdict.admit) expect(verdict.reason).toBe("document_gate_rule_failed");
    expect(events.some((e) => e.event === "document.update.quarantined")).toBe(true);
  });
});

describe("DocumentGate — the screening hook (DOD-DOC-SCREEN-1 plugs in here)", () => {
  it("a pluggable rule sees the PROJECTED DIFF, not the raw bytes", () => {
    const { gate } = newGate();
    const accepted = acceptedDoc("base");
    let seen: string | null = null;
    gate.addRule("observe-diff", (diff) => {
      seen = diff.inserted;
      return null;
    });

    gate.validate(accepted, peerUpdate(accepted, 500, (d) => d.getText("content").insert(4, " INSERTED TEXT")), context);
    // Screening operates on what the update WOULD DO to the document, which is the only form in
    // which a policy can judge it — raw CRDT bytes say nothing a rule could read.
    expect(seen).toContain("INSERTED TEXT");
  });

  it("a rule's refusal becomes the verdict, with the rule named", () => {
    const { gate } = newGate();
    const accepted = acceptedDoc("base");
    gate.addRule("refusing-rule", () => ({ reason: "document_screening_refused", detail: "policy says no" }));

    const verdict = gate.validate(accepted, peerUpdate(accepted, 500, (d) => d.getText("content").insert(0, "x")), context);
    expect(verdict.admit).toBe(false);
    if (!verdict.admit) {
      expect(verdict.reason).toBe("document_screening_refused");
      expect(verdict.rule).toBe("refusing-rule");
    }
  });
});
