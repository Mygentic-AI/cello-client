/**
 * DOD-MP-AMEND-1 (daemon half) — the append-only amendment store.
 *
 * Amendments are stored as RECEIVED BYTES (TRACE-1 Entry 1(d): any frame whose hash or signature
 * matters is never persisted re-encoded), keyed (owner, document, epoch), append-only. The store
 * owns PERSISTENCE and chain SHAPE (contiguity, fork refusal, idempotent redelivery); signature
 * and policy validity are the replay's question at consumption, and the inbound path's before
 * anything is appended.
 */
import { describe, it, expect, beforeEach } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import {
  documentAmendmentHash,
  encodeDocumentAmendment,
  buildDocumentMultisigTbs,
  type DocumentAmendmentBody,
  type DocumentAmendmentEnvelope,
} from "@cello-protocol/protocol-types";
import { DocumentAmendmentStore } from "../document-amendment-store.js";
import type { Logger } from "../types.js";

const silent: Logger = { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} };

function makeSigner() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = publicKey.export({ type: "spki", format: "der" }).subarray(-32);
  return {
    agentId: Buffer.from(raw).toString("hex"),
    sign: (tbs: Uint8Array): Uint8Array => new Uint8Array(edSign(null, tbs, privateKey)),
  };
}

const OWNER = "owner-agent";
const DOC = "d".repeat(64);
const admin = makeSigner();

function amendment(over: Partial<DocumentAmendmentBody> = {}): DocumentAmendmentEnvelope {
  const body: DocumentAmendmentBody = {
    document_id: DOC,
    epoch_id: 1,
    prev_amendment_hash: null,
    kind: "add_holder",
    subject_agent_id: "c".repeat(64),
    property_change: null,
    state_hash: null,
    authored_at_ms: 1_700_000_000_000,
    ...over,
  };
  const hash = documentAmendmentHash(body);
  const required = [admin.agentId];
  const tbs = buildDocumentMultisigTbs({
    document_id: body.document_id,
    subject_kind: "document_amendment",
    subject_hash: hash,
    required_signers: required,
  });
  return {
    body,
    collection: {
      document_id: body.document_id,
      subject_kind: "document_amendment",
      subject_hash: hash,
      required_signers: required,
      signatures: [{ signer_agent_id: admin.agentId, signature: admin.sign(tbs) }],
    },
  };
}

function chainOf(...envs: DocumentAmendmentEnvelope[]): DocumentAmendmentEnvelope[] {
  // Rewrite prev hashes so the given kinds/subjects form a real chain.
  let prev: string | null = null;
  return envs.map((e, i) => {
    const body = { ...e.body, epoch_id: i + 1, prev_amendment_hash: prev };
    const fixed = amendment(body);
    prev = Buffer.from(documentAmendmentHash(fixed.body)).toString("hex");
    return fixed;
  });
}

describe("DocumentAmendmentStore", () => {
  let store: DocumentAmendmentStore;
  let db: DatabaseSync;

  beforeEach(() => {
    db = new DatabaseSync(":memory:");
    store = new DocumentAmendmentStore(db as never, silent);
  });

  it("DDL is idempotent — constructing twice over one database is fine", () => {
    expect(() => new DocumentAmendmentStore(db as never, silent)).not.toThrow();
  });

  it("append → chain round-trips the RECEIVED bytes in epoch order", () => {
    const [one, two] = chainOf(amendment(), amendment({ kind: "promote_admin", subject_agent_id: "e".repeat(64) }));
    // Deliberately appended out of construction order? No — contiguity forbids it; append in order.
    const r1 = store.append(OWNER, DOC, encodeDocumentAmendment(one!), 1000);
    const r2 = store.append(OWNER, DOC, encodeDocumentAmendment(two!), 2000);
    expect(r1.recorded).toBe(true);
    expect(r2.epochId).toBe(2);
    const chain = store.chain(OWNER, DOC);
    expect(chain.map((e) => e.body.epoch_id)).toEqual([1, 2]);
    expect(chain[0]).toEqual(one);
    expect(chain[1]).toEqual(two);
  });

  it("copies the input bytes — mutating the caller's buffer after append changes nothing", () => {
    const [one] = chainOf(amendment());
    const bytes = encodeDocumentAmendment(one!);
    store.append(OWNER, DOC, bytes, 1000);
    bytes.fill(0);
    expect(store.chain(OWNER, DOC)[0]).toEqual(one);
  });

  it("a REDELIVERED amendment (same epoch, same hash) is idempotent — recorded: false, one row", () => {
    const [one] = chainOf(amendment());
    const bytes = encodeDocumentAmendment(one!);
    expect(store.append(OWNER, DOC, bytes, 1000).recorded).toBe(true);
    expect(store.append(OWNER, DOC, bytes, 2000).recorded).toBe(false);
    expect(store.chain(OWNER, DOC)).toHaveLength(1);
  });

  it("a DIFFERENT amendment at an occupied epoch is a FORK — refused loudly, first record kept", () => {
    const [one] = chainOf(amendment());
    store.append(OWNER, DOC, encodeDocumentAmendment(one!), 1000);
    const rival = amendment({ subject_agent_id: "f".repeat(64) }); // also epoch 1, different hash
    expect(() => store.append(OWNER, DOC, encodeDocumentAmendment(rival), 2000)).toThrow(
      /document_amendment_conflict/,
    );
    expect(store.chain(OWNER, DOC)).toHaveLength(1);
    expect(store.chain(OWNER, DOC)[0]).toEqual(one);
  });

  it("a GAP is refused at append — epoch 2 cannot land before epoch 1 exists", () => {
    const [one, two] = chainOf(amendment(), amendment({ kind: "promote_admin", subject_agent_id: "e".repeat(64) }));
    void one;
    expect(() => store.append(OWNER, DOC, encodeDocumentAmendment(two!), 1000)).toThrow(
      /document_amendment_chain_gap/,
    );
  });

  it("malformed bytes are refused with the decoder's NAMED reason, and nothing is stored", () => {
    expect(() => store.append(OWNER, DOC, new Uint8Array([1, 2, 3]), 1000)).toThrow();
    expect(store.chain(OWNER, DOC)).toHaveLength(0);
  });

  it("keys on (owner, document) — two owners and two documents never see each other's chains", () => {
    const [one] = chainOf(amendment());
    store.append(OWNER, DOC, encodeDocumentAmendment(one!), 1000);
    expect(store.chain("other-owner", DOC)).toHaveLength(0);
    expect(store.chain(OWNER, "e".repeat(64))).toHaveLength(0);
    expect(store.currentEpoch("other-owner", DOC)).toBe(0);
  });

  it("currentEpoch is 0 with no amendments and the max epoch afterwards", () => {
    expect(store.currentEpoch(OWNER, DOC)).toBe(0);
    const [one, two] = chainOf(amendment(), amendment({ kind: "promote_admin", subject_agent_id: "e".repeat(64) }));
    store.append(OWNER, DOC, encodeDocumentAmendment(one!), 1000);
    store.append(OWNER, DOC, encodeDocumentAmendment(two!), 2000);
    expect(store.currentEpoch(OWNER, DOC)).toBe(2);
  });
});
