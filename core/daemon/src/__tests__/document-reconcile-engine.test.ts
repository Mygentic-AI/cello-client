/**
 * SYNC-P3 — the responder engine: entitlement first, then exactly the difference.
 *
 * The reads are faked; the ENTRIES are real signed wires (the refusal-set exclusion hashes
 * them, and a fake hash would test nothing). What is pinned here is the DECISIONS: who gets
 * refused and how finally, what a behind peer is sent, what a forked author triggers, and that
 * nothing in a refusal set is ever re-offered.
 */
import { describe, it, expect } from "vitest";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import {
  documentAmendmentHash,
  encodeDocumentAmendment,
  buildDocumentMultisigTbs,
  type DocumentAmendmentBody,
  type DocumentAmendmentEnvelope,
  type DocumentStateView,
} from "@cello-protocol/protocol-types";
import {
  buildReconcileBlock,
  respondToReconcile,
  type ReconcileReads,
} from "../document-reconcile-engine.js";
import type { DocumentEnvelopeRow } from "../document-store.js";
import type { AuthorWatermark } from "../document-amendment-store.js";

const DOC = "d".repeat(64);

function makeSigner() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = publicKey.export({ type: "spki", format: "der" }).subarray(-32);
  return {
    agentId: Buffer.from(raw).toString("hex"),
    sign: (tbs: Uint8Array): Uint8Array => new Uint8Array(edSign(null, tbs, privateKey)),
  };
}
const admin = makeSigner();
const peer = "b".repeat(64);

function entryOf(over: Partial<DocumentAmendmentBody> = {}): DocumentAmendmentEnvelope {
  const body: DocumentAmendmentBody = {
    document_id: DOC,
    epoch_id: 1,
    prev_amendment_hash: null,
    kind: "add_holder",
    subject_agent_id: "c".repeat(64),
    property_change: null,
    state_hash: null,
    authored_at_ms: 1_700_000_000_000,
    author_agent_id: admin.agentId,
    author_seq: 1,
    parents: [],
    ...over,
  };
  const hash = documentAmendmentHash(body);
  const tbs = buildDocumentMultisigTbs({
    document_id: body.document_id,
    subject_kind: "document_amendment",
    subject_hash: hash,
    required_signers: [admin.agentId],
  });
  return {
    body,
    collection: {
      document_id: body.document_id,
      subject_kind: "document_amendment",
      subject_hash: hash,
      required_signers: [admin.agentId],
      signatures: [{ signer_agent_id: admin.agentId, signature: admin.sign(tbs) }],
    },
  };
}

function hashHex(env: DocumentAmendmentEnvelope): string {
  return Buffer.from(documentAmendmentHash(env.body)).toString("hex");
}

function stateView(over: Partial<{
  participants: string[];
  invited: string[];
}> = {}): DocumentStateView {
  return {
    participants: new Set(over.participants ?? [admin.agentId, peer]),
    invited: new Set(over.invited ?? []),
    admins: new Set([admin.agentId]),
    properties: { assurance_tier: "authenticated" },
    order: [],
    frontier: [],
    voids: [],
    excluded: [],
    authorSeqs: new Map(),
    interimMaxEpoch: 0,
    interimLastHash: null,
  };
}

let envSeq = 0;
function contentRow(sender: string, payload: Uint8Array | null = new Uint8Array([1])): DocumentEnvelopeRow {
  envSeq += 1;
  return {
    envelopeHash: `${envSeq}`.padStart(2, "0").repeat(32),
    documentId: DOC,
    senderAgentId: sender,
    docPrevHash: null,
    epochId: 0,
    signature: new Uint8Array(64),
    stateVector: new Uint8Array([0]),
    payload,
    governanceParents: [],
    kind: payload === null ? "reject" : "update",
    createdAtMs: 1,
  } as DocumentEnvelopeRow;
}

function reads(over: Partial<ReconcileReads> = {}): ReconcileReads {
  return {
    deriveState: () => ({ ok: true, state: stateView() }),
    watermarks: () => new Map<string, AuthorWatermark>(),
    entriesByAuthorAfter: () => [],
    envelopeLog: () => [],
    refusedHashes: () => [],
    membershipState: () => "untouched",
    genesisBytes: () => null,
    removalClosure: () => null,
    ...over,
  };
}

function block(over: Partial<Parameters<typeof respondToReconcile>[2]> = {}) {
  return {
    document_id: DOC,
    governance: [],
    content: [],
    refused: [],
    entries: [],
    envelopes: [],
    ...over,
  };
}

describe("respondToReconcile — entitlement first (R17/R18/R19)", () => {
  it("a STRANGER is refused by name, NON-terminal, the sentence says why it is not final — and the refusal block leaks NO positions", () => {
    const r = respondToReconcile(reads(), "9".repeat(64), block());
    expect(r.block.refusal).toBeDefined();
    expect(r.block.refusal!.terminal).toBe(false);
    expect(r.block.refusal!.reason).toMatch(/document_reconcile_stranger/);
    expect(r.block.refusal!.reason).toMatch(/non-terminal/);
    expect(r.block.refusal!.reason).toMatch(/admission may/);
    expect(r.block.governance).toEqual([]);
    expect(r.block.content).toEqual([]);
  });

  it("a REMOVED holder gets a terminal ruling that DELIVERS — their own removal and its ancestors ride the refusal block (R32)", () => {
    // The review's F1: the old shape refused bare, so a holder offline at removal time could
    // never learn why the document went quiet — their own state said participant forever.
    const closureWires = [new Uint8Array([1, 1]), new Uint8Array([2, 2])];
    const r = respondToReconcile(
      reads({
        membershipState: () => "removed",
        removalClosure: () => closureWires,
      }),
      "9".repeat(64),
      block(),
    );
    expect(r.block.refusal).toMatchObject({ terminal: true });
    expect(r.block.refusal!.reason).toMatch(/document_reconcile_removed/);
    expect(r.block.refusal!.reason).toMatch(/forward-only/);
    expect(r.block.entries).toEqual(closureWires);
  });

  it("an INVITED seat is answered — invited may receive (R17)", () => {
    const invitee = "9".repeat(64);
    const r = respondToReconcile(
      reads({ deriveState: () => ({ ok: true, state: stateView({ invited: [invitee] }) }) }),
      invitee,
      block(),
    );
    expect(r.block.refusal).toBeUndefined();
  });

  it("an underivable document refuses NON-terminally with the derivation's own reason", () => {
    const r = respondToReconcile(
      reads({ deriveState: () => ({ ok: false, reason: "arrangement_admin_set_empty: x" }) }),
      peer,
      block(),
    );
    expect(r.block.refusal).toMatchObject({ terminal: false });
    expect(r.block.refusal!.reason).toContain("arrangement_admin_set_empty");
  });
});

describe("respondToReconcile — the governance difference", () => {
  const e1 = entryOf({ author_seq: 1 });
  const e2 = entryOf({ author_seq: 2, epoch_id: 2, parents: [hashHex(e1)], subject_agent_id: "e".repeat(64) });
  const wires = [new Uint8Array(encodeDocumentAmendment(e1)), new Uint8Array(encodeDocumentAmendment(e2))];

  function govReads() {
    return reads({
      watermarks: () =>
        new Map([[admin.agentId, { seq: 2, headHashes: [hashHex(e2)] }]]),
      entriesByAuthorAfter: (_d, author, afterSeq) =>
        author === admin.agentId ? wires.filter((_, i) => i + 1 > afterSeq) : [],
    });
  }

  it("a peer with no watermark for an author gets that author's whole chain, in seq order", () => {
    const r = respondToReconcile(govReads(), peer, block());
    expect(r.block.entries).toHaveLength(2);
  });

  it("a peer behind by one gets exactly the suffix", () => {
    const r = respondToReconcile(
      govReads(),
      peer,
      block({ governance: [{ author: admin.agentId, seq: 1, head_hashes: [hashHex(e1)] }] }),
    );
    expect(r.block.entries).toHaveLength(1);
    expect(r.block.entries[0]).toEqual(wires[1]);
  });

  it("a FORK at the same seq re-offers from before the fork point — detection, not silence", () => {
    const r = respondToReconcile(
      govReads(),
      peer,
      block({ governance: [{ author: admin.agentId, seq: 2, head_hashes: ["ff".repeat(32)] }] }),
    );
    expect(r.block.entries).toHaveLength(1); // from seq 1: our seq-2 branch ships
  });

  it("NOTHING in the peer's refusal set is re-offered (R36)", () => {
    const r = respondToReconcile(
      govReads(),
      peer,
      block({ refused: [hashHex(e2)] }),
    );
    expect(r.block.entries).toHaveLength(1);
    expect(r.block.entries[0]).toEqual(wires[0]);
  });

  it("a peer at our exact position gets NO entries — idempotence is the absence of a difference", () => {
    const r = respondToReconcile(
      govReads(),
      peer,
      block({ governance: [{ author: admin.agentId, seq: 2, head_hashes: [hashHex(e2)] }] }),
    );
    expect(r.block.entries).toHaveLength(0);
    expect(r.peerAhead).toBe(false);
  });
});

describe("respondToReconcile — the content difference", () => {
  it("sends the sender-chain suffix past the peer's count; refused stubs are skipped, the hole named by our refusal set", () => {
    const rows = [contentRow(admin.agentId), contentRow(admin.agentId, null), contentRow(admin.agentId)];
    const r = respondToReconcile(
      reads({
        envelopeLog: () => rows,
        refusedHashes: () => [rows[1]!.envelopeHash],
      }),
      peer,
      block({ content: [{ author: admin.agentId, count: 1, head_hash: rows[0]!.envelopeHash }] }),
    );
    // Rows 2 and 3 are past the count; row 2 is a payload-less stub → only row 3 ships.
    expect(r.block.envelopes).toHaveLength(1);
    expect(r.block.refused).toContain(rows[1]!.envelopeHash);
  });

  it("flags peerAhead when the peer's content count exceeds ours — step 3 is owed", () => {
    const r = respondToReconcile(
      reads(),
      peer,
      block({ content: [{ author: peer, count: 4, head_hash: "aa".repeat(32) }] }),
    );
    expect(r.peerAhead).toBe(true);
  });
});

describe("respondToReconcile — the reply byte budget (review F3)", () => {
  it("stops adding payload when the budget runs out, keeps the positions, and SAYS it truncated", () => {
    const e1 = entryOf({ author_seq: 1 });
    const e2 = entryOf({ author_seq: 2, epoch_id: 2, parents: [hashHex(e1)], subject_agent_id: "e".repeat(64) });
    const wires = [new Uint8Array(encodeDocumentAmendment(e1)), new Uint8Array(encodeDocumentAmendment(e2))];
    const r = respondToReconcile(
      reads({
        watermarks: () => new Map([[admin.agentId, { seq: 2, headHashes: [hashHex(e2)] }]]),
        entriesByAuthorAfter: () => wires,
      }),
      peer,
      block(),
      { remainingBytes: wires[0]!.length + 10 }, // room for one wire, not two
    );
    expect(r.truncated).toBe(true);
    expect(r.block.entries).toHaveLength(1);
    // The POSITION is intact — the peer learns exactly how far behind it still is.
    expect(r.block.governance).toHaveLength(1);
  });
});

describe("respondToReconcile — the joiner bootstrap", () => {
  it("a peer with an EMPTY position is handed the genesis alongside everything else", () => {
    const g = new Uint8Array([9, 9, 9]);
    const r = respondToReconcile(
      reads({
        deriveState: () => ({ ok: true, state: stateView({ invited: ["9".repeat(64)] }) }),
        genesisBytes: () => g,
      }),
      "9".repeat(64),
      block(),
    );
    expect(r.block.genesis).toEqual(g);
  });

  it("a peer with ANY position gets no genesis — they already hold the anchor", () => {
    const r = respondToReconcile(
      reads({ genesisBytes: () => new Uint8Array([9]) }),
      peer,
      block({ content: [{ author: peer, count: 1, head_hash: "aa".repeat(32) }] }),
    );
    expect(r.block.genesis).toBeUndefined();
  });
});

describe("buildReconcileBlock — a deterministic position", () => {
  it("orders authors and heads canonically so two builds of one state are byte-identical", () => {
    const r = reads({
      watermarks: () =>
        new Map([
          ["ff".repeat(32), { seq: 1, headHashes: ["bb".repeat(32), "aa".repeat(32)] }],
          ["aa".repeat(32), { seq: 2, headHashes: ["cc".repeat(32)] }],
        ]),
    });
    const b = buildReconcileBlock(r, DOC);
    expect(b.governance.map((g) => g.author)).toEqual(["aa".repeat(32), "ff".repeat(32)]);
    expect(b.governance[1]!.head_hashes).toEqual(["aa".repeat(32), "bb".repeat(32)]);
    expect(b.entries).toEqual([]);
    expect(b.envelopes).toEqual([]);
  });
});
