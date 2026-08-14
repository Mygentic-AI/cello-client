/**
 * DOD-MP-JOIN-1 (daemon half) — the join store: pending consent, both roles, settle-once.
 */
import { describe, it, expect, beforeEach } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { generateKeyPairSync, sign as edSign, verify as edVerify } from "node:crypto";
import {
  DOCUMENT_FEATURE_VERSION,
  buildDocumentProposalTbs,
  encodeDocumentProposal,
  documentIdFromProposal,
  documentAmendmentHash,
  buildDocumentMultisigTbs,
  encodeDocumentAmendment,
  buildDocumentJoinOfferTbs,
  encodeDocumentJoinOffer,
  buildDocumentJoinAnswerTbs,
  encodeDocumentJoinAnswer,
  type DocumentProposalEnvelope,
  type DocumentAmendmentBody,
  type DocumentJoinOffer,
  type DocumentJoinAnswer,
} from "@cello-protocol/protocol-types";
import { DocumentJoinStore } from "../document-join-store.js";
import type { Logger } from "../types.js";

const silent: Logger = { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} };

function makeSigner() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = publicKey.export({ type: "spki", format: "der" }).subarray(-32);
  return {
    agentId: Buffer.from(raw).toString("hex"),
    sign: (tbs: Uint8Array): Uint8Array => new Uint8Array(edSign(null, tbs, privateKey)),
    publicKey,
  };
}
type Signer = ReturnType<typeof makeSigner>;

function makeVerify(signers: Signer[]) {
  const byId = new Map(signers.map((s) => [s.agentId, s.publicKey]));
  return (agentId: string, tbs: Uint8Array, signature: Uint8Array): boolean => {
    const key = byId.get(agentId);
    if (!key) return false;
    return edVerify(null, tbs, key, signature);
  };
}

/** A real signed offer bundle: a invites c into a document a shares with b. */
function bundle() {
  const a = makeSigner();
  const b = makeSigner();
  const c = makeSigner();
  const genesis: DocumentProposalEnvelope = {
    type: "document_proposal",
    feature_version: DOCUMENT_FEATURE_VERSION,
    proposer_agent_id: a.agentId,
    peer_agent_id: b.agentId,
    document_type: "markdown",
    properties: {
      assurance_tier: "authenticated", schema_enforcement: false,
      topology: "hub-and-spoke", append_only: false,
      admin_set: [a.agentId, b.agentId].sort(),
    },
    starting_content: null,
    nonce: new Uint8Array(16).fill(3),
    proposed_at_ms: 1_700_000_000_000,
    signature: new Uint8Array(0),
  };
  genesis.signature = a.sign(buildDocumentProposalTbs(genesis));
  const documentId = documentIdFromProposal(genesis);
  const body: DocumentAmendmentBody = {
    document_id: documentId, epoch_id: 1, prev_amendment_hash: null,
    kind: "add_holder", subject_agent_id: c.agentId,
    property_change: null, state_hash: null, authored_at_ms: 1,
    author_agent_id: a.agentId, author_seq: 1, parents: [],
  };
  const hash = documentAmendmentHash(body);
  const tbs = buildDocumentMultisigTbs({
    document_id: documentId, subject_kind: "document_amendment",
    subject_hash: hash, required_signers: [a.agentId],
  });
  const amendment = {
    body,
    collection: {
      document_id: documentId, subject_kind: "document_amendment", subject_hash: hash,
      required_signers: [a.agentId],
      signatures: [{ signer_agent_id: a.agentId, signature: a.sign(tbs) }],
    },
  };
  const offer: DocumentJoinOffer = {
    type: "document_join_offer",
    feature_version: DOCUMENT_FEATURE_VERSION,
    inviter_agent_id: a.agentId,
    invitee_agent_id: c.agentId,
    document_id: documentId,
    genesis: new Uint8Array(encodeDocumentProposal(genesis)),
    amendments: [new Uint8Array(encodeDocumentAmendment(amendment))],
    envelope_log: [],
    offered_at_ms: 2,
    signature: new Uint8Array(0),
  };
  offer.signature = a.sign(buildDocumentJoinOfferTbs(offer));
  return {
    a, b, c, documentId,
    amendmentHash: Buffer.from(hash).toString("hex"),
    wire: new Uint8Array(encodeDocumentJoinOffer(offer)),
  };
}

function answerFor(
  bd: ReturnType<typeof bundle>,
  accepted: boolean,
  reason: string | null = null,
): Uint8Array {
  const answer: DocumentJoinAnswer = {
    type: "document_join_answer",
    document_id: bd.documentId,
    amendment_hash: bd.amendmentHash,
    invitee_agent_id: bd.c.agentId,
    accepted,
    refusal_reason: reason,
    answered_at_ms: 3,
    signature: new Uint8Array(0),
  };
  answer.signature = bd.c.sign(buildDocumentJoinAnswerTbs(answer));
  return new Uint8Array(encodeDocumentJoinAnswer(answer));
}

describe("DocumentJoinStore", () => {
  let store: DocumentJoinStore;
  beforeEach(() => {
    store = new DocumentJoinStore(new DatabaseSync(":memory:") as never, silent);
  });

  it("records an arriving offer pending, and a redelivery cannot reopen a decision", () => {
    const bd = bundle();
    expect(store.recordIncoming(bd.c.agentId, bd.wire, bd.amendmentHash, { state: "pending" }, 1))
      .toMatchObject({ state: "pending" });
    expect(store.pendingFor(bd.c.agentId)).toHaveLength(1);
    store.decide(bd.c.agentId, bd.amendmentHash, false, "no thanks", 2);
    const redelivered = store.recordIncoming(
      bd.c.agentId, bd.wire, bd.amendmentHash, { state: "pending" }, 3,
    );
    expect(redelivered.state).toBe("refused");
    expect(store.pendingFor(bd.c.agentId)).toHaveLength(0);
  });

  it("records a validation refusal WITH its reason — never dropped", () => {
    const bd = bundle();
    const r = store.recordIncoming(
      bd.c.agentId, bd.wire, bd.amendmentHash,
      { state: "refused", reason: "join_feature_version: …" }, 1,
    );
    expect(r).toMatchObject({ state: "refused" });
    expect(store.get(bd.c.agentId, bd.amendmentHash)?.reason).toContain("join_feature_version");
  });

  it("decide settles ONCE — the second decision reports the standing state and decides nothing", () => {
    const bd = bundle();
    store.recordIncoming(bd.c.agentId, bd.wire, bd.amendmentHash, { state: "pending" }, 1);
    expect(store.decide(bd.c.agentId, bd.amendmentHash, true, null, 2)).toEqual({
      decided: true, state: "accepted",
    });
    expect(store.decide(bd.c.agentId, bd.amendmentHash, false, "changed my mind", 3)).toEqual({
      decided: false, state: "accepted",
    });
  });

  it("the inviter records the invitee's signed answer — and a CONTRADICTING second answer is refused", () => {
    const bd = bundle();
    const verify = makeVerify([bd.a, bd.b, bd.c]);
    store.recordOutgoing(bd.a.agentId, bd.wire, bd.amendmentHash, 1);
    const first = store.recordAnswer(bd.a.agentId, answerFor(bd, true), verify, 2);
    expect(first).toMatchObject({ ok: true, settled: true });
    // Same answer again: settled fact, not an error.
    expect(store.recordAnswer(bd.a.agentId, answerFor(bd, true), verify, 3)).toMatchObject({
      ok: true, settled: false,
    });
    // The opposite answer: refused, stored state stands.
    const contradiction = store.recordAnswer(bd.a.agentId, answerFor(bd, false, "actually no"), verify, 4);
    expect(contradiction.ok).toBe(false);
    if (contradiction.ok) return;
    expect(contradiction.reason).toMatch(/join_answer_contradiction/);
    expect(store.get(bd.a.agentId, bd.amendmentHash)?.state).toBe("accepted");
  });

  it("refuses an answer whose signature is not the INVITED party's", () => {
    const bd = bundle();
    store.recordOutgoing(bd.a.agentId, bd.wire, bd.amendmentHash, 1);
    const rogue = makeSigner();
    const forged: DocumentJoinAnswer = {
      type: "document_join_answer",
      document_id: bd.documentId,
      amendment_hash: bd.amendmentHash,
      invitee_agent_id: bd.c.agentId,
      accepted: true,
      refusal_reason: null,
      answered_at_ms: 3,
      signature: new Uint8Array(0),
    };
    forged.signature = rogue.sign(buildDocumentJoinAnswerTbs(forged));
    const r = store.recordAnswer(
      bd.a.agentId,
      new Uint8Array(encodeDocumentJoinAnswer(forged)),
      makeVerify([bd.a, bd.b, bd.c, rogue]),
      4,
    );
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toMatch(/join_answer_signature_invalid/);
  });

  it("refuses an answer for an offer we never made", () => {
    const bd = bundle();
    const r = store.recordAnswer(bd.a.agentId, answerFor(bd, true), makeVerify([bd.c]), 1);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toMatch(/join_answer_unknown_offer/);
  });

  it("keys on the owner — the inviter's and invitee's rows never collide", () => {
    const bd = bundle();
    store.recordOutgoing(bd.a.agentId, bd.wire, bd.amendmentHash, 1);
    store.recordIncoming(bd.c.agentId, bd.wire, bd.amendmentHash, { state: "pending" }, 1);
    expect(store.get(bd.a.agentId, bd.amendmentHash)?.role).toBe("inviter");
    expect(store.get(bd.c.agentId, bd.amendmentHash)?.role).toBe("invitee");
    expect(store.pendingFor(bd.a.agentId)).toHaveLength(0);
  });
});
