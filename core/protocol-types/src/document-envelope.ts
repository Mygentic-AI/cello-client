/**
 * DOD-DOC-ENVELOPE-1 — the document UPDATE envelope (§14).
 *
 * A distinct wire type from the handshake PROPOSAL envelope (whose hash mints the `document_id`).
 * The two share the word, not the shape.
 *
 * ── WHY THREE OF THESE FIELDS ARE SECURITY FIELDS, NOT METADATA ───────────────────────────────
 *
 * DOD-DOC-GATE-1 enforces three bindings that no property of a Yjs update's BYTES can establish.
 * The gate is only as trustworthy as the signature covering them, which is why all three sit
 * inside the TBS rather than beside it:
 *
 *   `document_id`      A Yjs update carries no document identity. A well-formed update authored
 *                      against a DIFFERENT document merges into this one silently and converges —
 *                      there is no error, and the result is a splice of two documents.
 *
 *   `update_encoding`  v2-encoded bytes are ACCEPTED by the v1 decoder and silently drop all
 *                      content. It cannot be sniffed either: a v2 update begins [0,0,…] and a
 *                      legitimate pure-delete v1 delta begins [0,1,…], so a first-byte heuristic
 *                      would refuse real deletions. The sender must SAY, under signature.
 *
 *   `sender_client_id` Authorship in Yjs IS the clientID, and the gate refuses any client whose
 *                      clock advances without being bound to the sender. §14 forbids persisting or
 *                      deriving a clientID (a shared one splices two authors together with an
 *                      empty pending set — measured in DOD-DOC-FUZZ-1), so an honest peer mints a
 *                      fresh one on every restart. The gate's rule is therefore correct ONLY if
 *                      the binding is LEARNABLE, and this envelope is where it is learned. Outside
 *                      the signature, "learnable" would mean "assertable by anyone on the wire".
 *
 * `epoch_id` and `doc_prev_hash` are not optional and are not defaulted (§14). An update that does
 * not state its epoch cannot be verified unambiguously after a compaction, and the chain link is
 * what lets the document log be extracted and verified across sealed sessions.
 */

import { createHash } from "node:crypto";
import { encodeCbor, decodeCbor } from "./cbor.js";

/** Domain tag in slot 0 of the to-be-signed array. */
export const DOCUMENT_UPDATE_DOMAIN = "CELLO-DOCUMENT-UPDATE-v1";

/**
 * The pinned Yjs update encoding (§16.7-8). Pinned in the protocol types precisely so that two
 * supporting clients can never disagree silently — the failure mode of disagreement is an empty
 * document, not an error.
 */
export const DOCUMENT_UPDATE_ENCODING_V1 = "yjs-v1";

/** V1 has exactly one epoch. Compaction (which mints new epochs) is V2. */
export const DOCUMENT_EPOCH_V1 = 0;

/** A 32-byte hex digest — the shape of `document_id` and of every chain link. */
const HEX32 = /^[0-9a-f]{64}$/;

export interface DocumentUpdateEnvelope {
  type: "document_update";
  /** Hash of the handshake proposal envelope that minted this document. */
  document_id: string;
  /** Constant `DOCUMENT_EPOCH_V1` in V1 — carried explicitly, never omitted. */
  epoch_id: number;
  /**
   * The per-sender chain link: the `documentEnvelopeHash` of this sender's previous envelope for
   * this document, or `null` for this sender's FIRST envelope. `null` and absent are different
   * facts and are treated differently — see `decodeDocumentUpdateEnvelope`.
   */
  doc_prev_hash: string | null;
  sender_agent_id: string;
  /** The Yjs clientID this update was authored under. See the header. */
  sender_client_id: number;
  /** Always `DOCUMENT_UPDATE_ENCODING_V1` in V1. See the header. */
  update_encoding: string;
  /** The sender's Yjs state vector at publish (§7) — what it had seen when it authored. */
  state_vector: Uint8Array;
  /** The Yjs update payload. */
  update: Uint8Array;
  /** Ed25519 (RFC 8032) over `buildDocumentUpdateTbs`. */
  signature: Uint8Array;
}

/**
 * The canonical to-be-signed preimage: a fixed-order CBOR ARRAY with the domain in slot 0.
 *
 * An array, not a map, because `encodeCbor` is deliberately NOT deterministic for maps — keys
 * follow insertion order and the header is not minimal-length (see `cbor.ts`). Two honest senders
 * that built the same envelope in a different field order would produce different signatures over
 * it. Arrays are order-fixed and self-delimiting, which also removes the concatenation ambiguity
 * that length-framing exists to prevent.
 *
 * The `signature` is excluded, as it must be — a statement cannot cover its own signature.
 *
 * `preHash: false` returns the preimage itself rather than its digest; it exists for the hash
 * construction below and for tests that need to inspect the structure.
 */
export function buildDocumentUpdateTbs(
  env: DocumentUpdateEnvelope,
  opts: { preHash?: boolean } = {},
): Uint8Array {
  const preimage = encodeCbor([
    DOCUMENT_UPDATE_DOMAIN,
    env.document_id,
    env.epoch_id,
    env.doc_prev_hash, // null encodes distinctly from any string — genesis is unambiguous
    env.sender_agent_id,
    env.sender_client_id,
    env.update_encoding,
    env.state_vector,
    env.update,
  ]);
  if (opts.preHash === false) return preimage;
  return new Uint8Array(createHash("sha256").update(preimage).digest());
}

/**
 * The envelope's identity: SHA-256 over the same preimage that is signed.
 *
 * Deliberately the SAME preimage, so a chain link commits to exactly the bytes whose signature was
 * verified — a link can never point at an envelope other than the one that was authenticated.
 *
 * It therefore excludes the signature, which is the property the chain needs: a re-signed but
 * otherwise identical envelope keeps its hash, so anything already pointing at it (the next
 * envelope in the chain, a `0x05` rejection leaf) is not orphaned.
 */
export function documentEnvelopeHash(env: DocumentUpdateEnvelope): string {
  return createHash("sha256")
    .update(buildDocumentUpdateTbs(env, { preHash: false }))
    .digest("hex");
}

export function encodeDocumentUpdateEnvelope(env: DocumentUpdateEnvelope): Uint8Array {
  return encodeCbor({
    type: env.type,
    document_id: env.document_id,
    epoch_id: env.epoch_id,
    doc_prev_hash: env.doc_prev_hash,
    sender_agent_id: env.sender_agent_id,
    sender_client_id: env.sender_client_id,
    update_encoding: env.update_encoding,
    state_vector: env.state_vector,
    update: env.update,
    signature: env.signature,
  });
}

function requirePresent(map: Record<string, unknown>, field: string): unknown {
  // `in`, not a truthiness or nullish check. ABSENT and `null` are different facts: absent
  // doc_prev_hash read as null would turn every gap in a chain into a fresh valid-looking genesis,
  // and absent epoch_id read as 0 would make a post-compaction ambiguity silent. A decoder that
  // supplies a default for a field the spec calls mandatory is manufacturing the sender's claim.
  if (!(field in map)) {
    throw new Error(`document_envelope_missing_field: ${field} is mandatory and was not present`);
  }
  return map[field];
}

function requireBytes(map: Record<string, unknown>, field: string): Uint8Array {
  const value = requirePresent(map, field);
  if (!(value instanceof Uint8Array)) {
    throw new Error(`document_envelope_field_type: ${field} must be a CBOR byte string`);
  }
  // COPIED, not returned as-is. Measured: cbor-x returns byte strings as VIEWS into the buffer it
  // was handed (`decoded.buffer === input.buffer`), so an aliased update mutates when the caller
  // reuses or zeroes its read buffer — and a pooled network read buffer is exactly that. Every
  // check in this decoder, and every check the gate makes afterwards, would then have been made
  // against bytes that are no longer the bytes applied. The copy is also what makes the return
  // type honest: a Buffer view and a Uint8Array are not interchangeable to a structural comparison.
  return new Uint8Array(value);
}

function requireString(map: Record<string, unknown>, field: string): string {
  const value = requirePresent(map, field);
  if (typeof value !== "string") {
    throw new Error(`document_envelope_field_type: ${field} must be a text string`);
  }
  return value;
}

/**
 * Decode and VALIDATE. Every refusal names the field, because the caller's next move is to tell an
 * operator which peer sent what — an unnamed refusal is a label on the exit point, not a diagnosis.
 */
export function decodeDocumentUpdateEnvelope(bytes: Uint8Array): DocumentUpdateEnvelope {
  const decoded = decodeCbor(bytes);
  if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) {
    throw new Error("document_envelope_malformed: not a CBOR map");
  }
  const map = decoded as Record<string, unknown>;

  const type = requireString(map, "type");
  if (type !== "document_update") {
    throw new Error(`document_envelope_type: expected document_update, got ${type}`);
  }

  const documentId = requireString(map, "document_id");
  if (!HEX32.test(documentId)) {
    throw new Error(
      `document_envelope_document_id: must be a 32-byte lowercase hex digest, got "${documentId}"`,
    );
  }

  const epochId = requirePresent(map, "epoch_id");
  if (typeof epochId !== "number" || !Number.isInteger(epochId)) {
    throw new Error(`document_envelope_epoch: must be an integer, got ${String(epochId)}`);
  }
  if (epochId !== DOCUMENT_EPOCH_V1) {
    // V2 introduces compaction and non-zero epochs. Accepting one now would mean applying an
    // update whose base state this build cannot reconstruct.
    throw new Error(
      `document_envelope_epoch: this build speaks epoch ${DOCUMENT_EPOCH_V1} only, got ${epochId}`,
    );
  }

  const prev = requirePresent(map, "doc_prev_hash");
  if (prev !== null && (typeof prev !== "string" || !HEX32.test(prev))) {
    throw new Error(
      `document_envelope_prev_hash: must be a 32-byte hex digest or explicit null, got "${String(prev)}"`,
    );
  }

  const senderAgentId = requireString(map, "sender_agent_id");
  if (senderAgentId.length === 0) {
    throw new Error("document_envelope_sender: sender_agent_id must not be empty");
  }

  const clientId = requirePresent(map, "sender_client_id");
  if (typeof clientId !== "number" || !Number.isInteger(clientId) || clientId < 0) {
    throw new Error(
      `document_envelope_client_id: must be a non-negative integer, got ${String(clientId)}`,
    );
  }

  const encoding = requireString(map, "update_encoding");
  if (encoding !== DOCUMENT_UPDATE_ENCODING_V1) {
    // The one refusal that cannot be replaced by a heuristic. See the header.
    throw new Error(
      `document_envelope_encoding: this build speaks ${DOCUMENT_UPDATE_ENCODING_V1} only, got "${encoding}"`,
    );
  }

  return {
    type: "document_update",
    document_id: documentId,
    epoch_id: epochId,
    doc_prev_hash: prev,
    sender_agent_id: senderAgentId,
    sender_client_id: clientId,
    update_encoding: encoding,
    state_vector: requireBytes(map, "state_vector"),
    update: requireBytes(map, "update"),
    signature: requireBytes(map, "signature"),
  };
}

/**
 * The receive-time chain check: does this envelope link to what we already hold from this sender?
 *
 * `known` is every envelope hash we hold from this sender for this document, and `head` is their
 * most recent. Both, not just the head: replay is SET-based per §16.7-5, and delivery derives
 * pending from the log and retries across restarts — so an older envelope arriving again, because
 * its ack was lost while a later one landed, is designed behaviour. Comparing against the head
 * alone recognised only the newest redelivery and reported every other one as a broken chain.
 *
 * The set is also what separates the two failures. A predecessor we have never seen is a GAP; a
 * predecessor we hold that is not the head is a BRANCH. One reason string for both would hide a
 * fork inside a delivery-shaped error.
 *
 * The refusal reasons are deliberately the SAME STRINGS the daemon's whole-log verifier uses
 * (`DocumentStore.verifyChainLinkage`): `document_chain_forked` and `document_chain_broken`. Two
 * vocabularies for one fact means a policy-log query or an operator keyed on one silently misses
 * the other. The division of labour is real — this checks a single link on arrival, that one walks
 * the whole log for reachability — but they are the same two failures.
 *
 * **LINKAGE ONLY — this is not authenticity.** `documentEnvelopeHash` excludes the signature, so
 * `duplicate: true` means the TBS is byte-identical to one we hold, NOT that whoever sent it holds
 * the key. A caller must verify the signature before consulting the chain; `duplicate` is the
 * value most likely to be read as "already known, ack it and move on".
 */
export function verifyDocumentChainLink(
  env: DocumentUpdateEnvelope,
  sender: { head: string | null; known: ReadonlySet<string> },
): { duplicate: boolean } {
  if (sender.known.has(documentEnvelopeHash(env))) return { duplicate: true };

  if (env.doc_prev_hash === null) {
    if (sender.head !== null) {
      // Two roots for one sender. DOD-DOC-REJECT-1 measured what this costs: the chain no longer
      // verifies, so the document rebuilds until the next daemon restart and is permanently
      // unopenable after it. The log is append-only; there is no repair.
      throw new Error(
        `document_chain_forked: ${env.sender_agent_id} sent a genesis envelope for document ` +
          `${env.document_id}, but we already hold their chain at ${sender.head}`,
      );
    }
    return { duplicate: false };
  }

  if (!sender.known.has(env.doc_prev_hash)) {
    throw new Error(
      `document_chain_broken: ${env.sender_agent_id} chained to ${env.doc_prev_hash} for document ` +
        `${env.document_id}, which we have never seen — their last envelope we hold is ` +
        `${sender.head ?? "none (no envelope from this sender yet)"}`,
    );
  }

  if (env.doc_prev_hash !== sender.head) {
    throw new Error(
      `document_chain_forked: ${env.sender_agent_id} chained to ${env.doc_prev_hash} for document ` +
        `${env.document_id}, which we hold but which is not their head ${sender.head} — a chain ` +
        `branches nowhere`,
    );
  }

  return { duplicate: false };
}
