/**
 * DOD-DOC-ENVELOPE-1 — the document UPDATE envelope (§14), and the three bindings it must sign.
 *
 * The gate (DOD-DOC-GATE-1) enforces three bindings that NO property of an update's bytes can
 * establish. Each is only as trustworthy as the signature covering it, and GATE-1's reviews made
 * all three blocking ACs on this unit:
 *
 *   1. `document_id`      — a Yjs update carries no document identity, so a well-formed update
 *                           built against another document merges silently into this one.
 *   2. `update_encoding`  — v2 bytes are ACCEPTED by the v1 decoder and silently drop all content,
 *                           and it cannot be sniffed: a v2 update begins [0,0,…] while a legitimate
 *                           pure-delete v1 delta begins [0,1,…], so a first-byte heuristic refuses
 *                           real deletions.
 *   3. `sender_client_id` — authorship in Yjs IS the clientID, and the gate refuses any client
 *                           whose clock advances without being bound to the sender. §14 forbids
 *                           persisting a clientID, so a restarted honest peer mints a fresh one:
 *                           the gate's rule is correct ONLY if the binding is LEARNABLE, and this
 *                           envelope is where it is learned.
 */

import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { encodeCbor, decodeCbor } from "../cbor.js";
import {
  DOCUMENT_UPDATE_DOMAIN,
  DOCUMENT_UPDATE_ENCODING_V1,
  buildDocumentUpdateTbs,
  encodeDocumentUpdateEnvelope,
  decodeDocumentUpdateEnvelope,
  documentEnvelopeHash,
  verifyDocumentChainLink,
  type DocumentUpdateEnvelope,
} from "../document-envelope.js";

const DOC = "aa".repeat(32);
const OTHER_DOC = "bb".repeat(32);
const PREV = "cc".repeat(32);

function envelope(over: Partial<DocumentUpdateEnvelope> = {}): DocumentUpdateEnvelope {
  return {
    type: "document_update",
    document_id: DOC,
    doc_prev_hash: PREV,
    sender_agent_id: "agent-a",
    sender_client_id: 3_141_592,
    update_encoding: DOCUMENT_UPDATE_ENCODING_V1,
    governance_parents: [],
    state_vector: new Uint8Array([1, 2, 3]),
    update: new Uint8Array([9, 8, 7, 6]),
    signature: new Uint8Array(64).fill(7),
    ...over,
  };
}

describe("document update envelope — CBOR round-trip", () => {
  it("survives encode → decode with every field intact and bytes as bytes", () => {
    const original = envelope();
    const decoded = decodeDocumentUpdateEnvelope(encodeDocumentUpdateEnvelope(original));

    expect(decoded).toEqual(original);
    // Byte fields must come back as byte strings, not tag-64 typed arrays or arrays of numbers —
    // the directory and the relay decode this wire too.
    expect(decoded.update).toBeInstanceOf(Uint8Array);
    expect(decoded.state_vector).toBeInstanceOf(Uint8Array);
  });

  it("byte fields are COPIED out of the wire, not left as views into it", () => {
    const wire = encodeDocumentUpdateEnvelope(envelope());
    const decoded = decodeDocumentUpdateEnvelope(wire);

    // cbor-x hands back subarrays of the buffer it decoded. A caller that reads frames into a
    // pooled buffer would then have the update change UNDER the gate: validated as one thing,
    // applied as another. Clobbering the wire must not touch what we decoded.
    wire.fill(0);
    expect(Array.from(decoded.update)).toEqual([9, 8, 7, 6]);
    expect(decoded.update.buffer).not.toBe(wire.buffer);
  });

  it("a genesis envelope round-trips with doc_prev_hash EXPLICITLY null", () => {
    const decoded = decodeDocumentUpdateEnvelope(
      encodeDocumentUpdateEnvelope(envelope({ doc_prev_hash: null })),
    );
    expect(decoded.doc_prev_hash).toBeNull();
  });
});

describe("document update envelope — the decoder refuses loudly, naming the gap", () => {
  /** Encode a raw map so the test can omit or corrupt a field the typed builder cannot. */
  const raw = (obj: Record<string, unknown>): Uint8Array => encodeCbor(obj);
  const asMap = (env: DocumentUpdateEnvelope): Record<string, unknown> =>
    decodeCbor(encodeDocumentUpdateEnvelope(env)) as Record<string, unknown>;

  it("an ABSENT doc_prev_hash is refused — absence is not genesis", () => {
    const map = asMap(envelope());
    delete map.doc_prev_hash;
    // The whole point of the chain link is that the log can be extracted and verified across
    // sealed sessions. A decoder that reads a missing link as `null` turns every gap in the chain
    // into a new, valid-looking genesis — which is exactly the forgery the chain exists to stop.
    expect(() => decodeDocumentUpdateEnvelope(raw(map))).toThrow(
      /document_envelope_missing_field.*doc_prev_hash/,
    );
  });

  it("an ABSENT governance_parents is refused — the causal link is not optional (SYNC-G1)", () => {
    // This field is the envelope's ONLY link to the governance world that makes it admissible
    // (R20/R30 rule on it). A decoder that defaulted it to [] would hand every legacy or forged
    // envelope the genesis world for free.
    const map = asMap(envelope());
    delete map.governance_parents;
    expect(() => decodeDocumentUpdateEnvelope(raw(map))).toThrow(
      /document_envelope_missing_field.*governance_parents/,
    );
  });

  it("a NON-CANONICAL governance_parents list is refused — one envelope, one identity", () => {
    // Descending order and duplicates each yield a second byte-identity for the same logical
    // envelope; the strictly-ascending rule is what makes the hash a canonical name.
    const a = "aa".repeat(32);
    const b = "bb".repeat(32);
    for (const bad of [[b, a], [a, a]]) {
      const map = asMap(envelope());
      map.governance_parents = bad;
      expect(() => decodeDocumentUpdateEnvelope(raw(map))).toThrow(
        /document_envelope_governance_parents_canonical/,
      );
    }
  });

  it("a governance_parents list past the cap of 64 is refused by name", () => {
    const map = asMap(envelope());
    map.governance_parents = Array.from({ length: 65 }, (_v, i) =>
      i.toString(16).padStart(2, "0").repeat(32).slice(0, 64),
    ).sort();
    expect(() => decodeDocumentUpdateEnvelope(raw(map))).toThrow(
      /document_envelope_governance_parents_cap/,
    );
  });

  it("an unrecognized update encoding is refused rather than guessed at", () => {
    const map = asMap(envelope());
    map.update_encoding = "yjs-v2";
    // Refusing is the entire mitigation: v2 bytes decode cleanly under v1 and yield an EMPTY
    // document, with no error on any path.
    expect(() => decodeDocumentUpdateEnvelope(raw(map))).toThrow(/document_envelope_encoding/);
  });

  it("a missing update encoding is refused — it cannot be inferred from the bytes", () => {
    const map = asMap(envelope());
    delete map.update_encoding;
    expect(() => decodeDocumentUpdateEnvelope(raw(map))).toThrow(
      /document_envelope_missing_field.*update_encoding/,
    );
  });

  it("a missing sender_client_id is refused — authorship would be unlearnable", () => {
    const map = asMap(envelope());
    delete map.sender_client_id;
    expect(() => decodeDocumentUpdateEnvelope(raw(map))).toThrow(
      /document_envelope_missing_field.*sender_client_id/,
    );
  });

  it("a non-integer or negative sender_client_id is refused", () => {
    for (const bad of [-1, 1.5, "7"]) {
      const map = asMap(envelope());
      map.sender_client_id = bad;
      expect(() => decodeDocumentUpdateEnvelope(raw(map))).toThrow(/document_envelope_client_id/);
    }
  });

  it("a document_id that is not a 32-byte hex digest is refused", () => {
    for (const bad of ["", "zz".repeat(32), "aa".repeat(16)]) {
      const map = asMap(envelope());
      map.document_id = bad;
      expect(() => decodeDocumentUpdateEnvelope(raw(map))).toThrow(/document_envelope_document_id/);
    }
  });

  it("a doc_prev_hash present but malformed is refused — distinct from absent, distinct from null", () => {
    const map = asMap(envelope());
    map.doc_prev_hash = "nope";
    expect(() => decodeDocumentUpdateEnvelope(raw(map))).toThrow(/document_envelope_prev_hash/);
  });
});

describe("document update TBS — the three bindings are INSIDE the signature", () => {
  const tbsOf = (over: Partial<DocumentUpdateEnvelope> = {}): string =>
    Buffer.from(buildDocumentUpdateTbs(envelope(over))).toString("hex");

  it("is an ARRAY with the domain tag in slot 0", () => {
    // cbor.ts: this encoder is NOT deterministic for MAPS (insertion order, non-minimal headers),
    // so every to-be-signed structure in CELLO is a fixed-order array with a domain in slot 0.
    // Signing a map here would make two honest implementations produce different signatures over
    // the same envelope.
    const tbsArray = decodeCbor(buildDocumentUpdateTbs(envelope(), { preHash: false }));
    expect(Array.isArray(tbsArray)).toBe(true);
    expect((tbsArray as unknown[])[0]).toBe(DOCUMENT_UPDATE_DOMAIN);
  });

  it("BINDING 1 — changing document_id changes the TBS", () => {
    // Without this, a well-formed update authored against another document merges silently.
    expect(tbsOf({ document_id: OTHER_DOC })).not.toBe(tbsOf());
  });

  it("BINDING 2 — changing update_encoding changes the TBS", () => {
    expect(tbsOf({ update_encoding: "yjs-v9" })).not.toBe(tbsOf());
  });

  it("BINDING 3 — changing sender_client_id changes the TBS", () => {
    // Authorship in Yjs IS the clientID. If it is outside the signature, an attacker relabels the
    // author of an update the gate then accepts as the bound peer's.
    expect(tbsOf({ sender_client_id: 999 })).not.toBe(tbsOf());
  });

  it("the chain link, the sender and the update bytes are all covered too", () => {
    expect(tbsOf({ doc_prev_hash: "dd".repeat(32) })).not.toBe(tbsOf());
    expect(tbsOf({ doc_prev_hash: null })).not.toBe(tbsOf());
    expect(tbsOf({ sender_agent_id: "agent-b" })).not.toBe(tbsOf());
    expect(tbsOf({ update: new Uint8Array([9, 8, 7, 5]) })).not.toBe(tbsOf());
    expect(tbsOf({ state_vector: new Uint8Array([1, 2, 4]) })).not.toBe(tbsOf());
  });

  it("the SIGNATURE itself is not covered — a TBS cannot include its own signature", () => {
    expect(tbsOf({ signature: new Uint8Array(64).fill(1) })).toBe(tbsOf());
  });

  it("is stable across field insertion order — two honest senders agree byte-for-byte", () => {
    const a = envelope();
    // Rebuild with the keys in a deliberately different order. A map-based TBS would diverge here;
    // the array form must not.
    const b: DocumentUpdateEnvelope = {
      governance_parents: a.governance_parents,
      signature: a.signature,
      update: a.update,
      state_vector: a.state_vector,
      update_encoding: a.update_encoding,
      sender_client_id: a.sender_client_id,
      sender_agent_id: a.sender_agent_id,
      doc_prev_hash: a.doc_prev_hash,
      document_id: a.document_id,
      type: a.type,
    };
    expect(buildDocumentUpdateTbs(b)).toEqual(buildDocumentUpdateTbs(a));
  });

  it("distinct envelopes cannot collide by shifting a byte across an ADJACENT field boundary", () => {
    // The classic concatenation forgery: joined without length framing, moving a byte from the end
    // of one field to the start of the next yields an identical preimage. state_vector and update
    // are adjacent and both raw bytes, which is the only pair where this is even expressible — an
    // earlier version compared two values of ONE non-adjacent field and a naive concatenation
    // would have passed it unchanged.
    const one = tbsOf({ state_vector: new Uint8Array([1, 2, 3]), update: new Uint8Array([4]) });
    const two = tbsOf({ state_vector: new Uint8Array([1, 2]), update: new Uint8Array([3, 4]) });
    expect(one).not.toBe(two);
  });
});

describe("documentEnvelopeHash", () => {
  it("is the SHA-256 of the canonical envelope encoding, and is signature-independent", () => {
    const a = envelope();
    const hash = documentEnvelopeHash(a);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);

    // The hash is what the NEXT envelope chains to and what a 0x05 rejection leaf references. If
    // it covered the signature, a re-signed but otherwise identical envelope would break the chain
    // of anything already pointing at it.
    expect(documentEnvelopeHash(envelope({ signature: new Uint8Array(64).fill(2) }))).toBe(hash);
    expect(documentEnvelopeHash(envelope({ update: new Uint8Array([0]) }))).not.toBe(hash);
  });

  it("matches an independent SHA-256 over the TBS preimage", () => {
    const a = envelope();
    const expected = createHash("sha256")
      .update(buildDocumentUpdateTbs(a, { preHash: false }))
      .digest("hex");
    expect(documentEnvelopeHash(a)).toBe(expected);
  });
});

describe("document update TBS — the FROZEN vector", () => {
  /**
   * The conformance artifact. Every other TBS test asserts only "these two differ", which leaves
   * the field ORDER completely unpinned: swap two slots or insert one mid-array and the whole
   * suite stays green while every signature this module will ever produce changes. §14 names
   * canonicalization drift as the worst failure mode for trust in the mechanism, because it
   * surfaces as a false divergence alarm at quiescence rather than as an error.
   *
   * This one assertion pins the order, the arity, the domain string and the encoding at once, and
   * it is what a second implementation conforms against. If it fails, the wire changed — decide
   * that deliberately and reissue the vector; never edit it to match new output.
   */
  const FROZEN: DocumentUpdateEnvelope = {
    type: "document_update",
    document_id: "00".repeat(31) + "01",
    doc_prev_hash: "00".repeat(31) + "02",
    sender_agent_id: "vector-agent",
    sender_client_id: 4_294_967_290,
    update_encoding: "yjs-v1",
    state_vector: new Uint8Array([0, 1, 2, 3]),
    update: new Uint8Array([4, 5, 6, 7]),
    // v3 (SYNC-P4 D7, journaled: M14B RESUME STATE): epoch_id left the preimage and the domain
    // moved to v3 — the wire changed DELIBERATELY, and the vector was reissued below. (v2 added
    // governance_parents, Entry 58.)
    governance_parents: ["ab".repeat(32)],
    signature: new Uint8Array(64).fill(0xab),
  };

  it("the preimage and the hash are byte-for-byte what they were the day they were frozen", () => {
    expect(Buffer.from(buildDocumentUpdateTbs(FROZEN, { preHash: false })).toString("hex")).toBe(
      "89781843454c4c4f2d444f43554d454e542d5550444154452d76337840303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030317840303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030326c766563746f722d6167656e741afffffffa66796a732d76314400010203440405060781784061626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162",
    );
    expect(documentEnvelopeHash(FROZEN)).toBe("4d61ad4debf773f054a7c3eca50b65fb7a5a189e231f85fa2d14edb349ffa37b");
  });
});

describe("verifyDocumentChainLink — the receive-time check names the gap", () => {
  const sender = (head: string | null, ...known: string[]) => ({
    head,
    known: new Set(head === null ? known : [head, ...known]),
  });

  it("accepts an envelope whose doc_prev_hash is the sender's head", () => {
    expect(verifyDocumentChainLink(envelope({ doc_prev_hash: PREV }), sender(PREV))).toEqual({
      duplicate: false,
    });
  });

  it("accepts a genesis envelope when the sender has no prior envelope", () => {
    expect(verifyDocumentChainLink(envelope({ doc_prev_hash: null }), sender(null))).toEqual({
      duplicate: false,
    });
  });

  it("refuses a genesis envelope from a sender that ALREADY has a chain", () => {
    expect(() => verifyDocumentChainLink(envelope({ doc_prev_hash: null }), sender(PREV))).toThrow(
      /document_chain_forked/,
    );
  });

  it("a REDELIVERED head is benign, not a chain failure", () => {
    const env = envelope({ doc_prev_hash: PREV });
    expect(verifyDocumentChainLink(env, sender(documentEnvelopeHash(env), PREV))).toEqual({
      duplicate: true,
    });
  });

  it("an OLDER redelivery is benign too — not only the newest one", () => {
    // Delivery derives pending from the log and retries across restarts, so if envelope N-1's ack
    // is lost while N lands, the very next retry is an older duplicate. Compared against the head
    // alone, that reported a broken chain for the protocol's own designed retry.
    const older = envelope({ doc_prev_hash: PREV });
    const head = "9a".repeat(32);
    expect(
      verifyDocumentChainLink(older, sender(head, PREV, documentEnvelopeHash(older))),
    ).toEqual({ duplicate: true });
  });

  it("distinguishes a BRANCH from a GAP — they are different facts", () => {
    const head = "9a".repeat(32);
    // Chains to something we hold, but which is not the head: a branch.
    expect(() =>
      verifyDocumentChainLink(envelope({ doc_prev_hash: PREV }), sender(head, PREV)),
    ).toThrow(/document_chain_forked/);
    // Chains to something we have never seen: a gap. One string for both would hide a fork inside
    // a delivery-shaped error.
    expect(() =>
      verifyDocumentChainLink(envelope({ doc_prev_hash: "ee".repeat(32) }), sender(head, PREV)),
    ).toThrow(/document_chain_broken/);
  });

  it("names both links and the sender when the predecessor is unknown", () => {
    const wrong = "ee".repeat(32);
    let caught = "";
    try {
      verifyDocumentChainLink(envelope({ doc_prev_hash: wrong }), sender(PREV));
    } catch (e) {
      caught = (e as Error).message;
    }
    expect(caught).toMatch(/document_chain_broken/);
    expect(caught).toContain(wrong);
    expect(caught).toContain(PREV);
    expect(caught).toContain("agent-a");
  });

  it("refuses a non-genesis envelope when the sender has no chain yet", () => {
    let caught = "";
    try {
      verifyDocumentChainLink(envelope({ doc_prev_hash: PREV }), sender(null));
    } catch (e) {
      caught = (e as Error).message;
    }
    expect(caught).toMatch(/document_chain_broken/);
    expect(caught).toContain(PREV);
  });
});
