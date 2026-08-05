/**
 * DOD-DOC-HANDSHAKE-1 — the consent state machine, daemon side (§16.3).
 *
 * `node:sqlite` here is the test-file allowance; production is SQLCipher.
 */

import { describe, it, expect } from "vitest";
import { DatabaseSync } from "node:sqlite";
import {
  encodeDocumentProposal,
  documentIdFromProposal,
  DOCUMENT_FEATURE_VERSION,
  ASSURANCE_TIER_V1,
  TOPOLOGY_V1,
  type DocumentProposalEnvelope,
  type DocumentProperties,
} from "@cello-protocol/protocol-types";
import { DocumentHandshake } from "../document-handshake.js";
import type { Logger } from "../types.js";

const OWNER = "owner-agent";
const NOW = 1_700_000_000_000;

function recordingLogger(): { logger: Logger; events: Array<{ event: string; fields: Record<string, unknown> }> } {
  const events: Array<{ event: string; fields: Record<string, unknown> }> = [];
  const push = (event: string, fields?: Record<string, unknown>) => {
    events.push({ event, fields: fields ?? {} });
  };
  const logger = {
    debug: push, info: push, warn: push, error: push,
    child: () => logger,
  } as unknown as Logger;
  return { logger, events };
}

function props(over: Partial<DocumentProperties> = {}): DocumentProperties {
  return {
    assurance_tier: ASSURANCE_TIER_V1,
    schema_enforcement: false,
    topology: TOPOLOGY_V1,
    append_only: false,
    ...over,
  };
}

let nonce = 0;
function proposal(over: Partial<DocumentProposalEnvelope> = {}): DocumentProposalEnvelope {
  nonce += 1;
  return {
    type: "document_proposal",
    feature_version: DOCUMENT_FEATURE_VERSION,
    proposer_agent_id: "agent-a",
    peer_agent_id: OWNER,
    document_type: "markdown",
    properties: props(),
    starting_content: new Uint8Array([1, 2, 3]),
    nonce: new Uint8Array([nonce]),
    proposed_at_ms: NOW,
    signature: new Uint8Array(64).fill(5),
    ...over,
  };
}

function newFixture() {
  const { logger, events } = recordingLogger();
  const db = new DatabaseSync(":memory:");
  return { handshake: new DocumentHandshake(db, logger), events, db, logger };
}

describe("DocumentHandshake — a proposal becomes a pending item", () => {
  it("records an acceptable proposal as pending, keyed by the proposal hash", () => {
    const { handshake } = newFixture();
    const env = proposal();
    const res = handshake.recordProposal(OWNER, encodeDocumentProposal(env), NOW);

    expect(res.state).toBe("pending");
    // document_id IS the hash of the proposal envelope (§16.3) — no minting authority, no
    // coordination round.
    expect(res.documentId).toBe(documentIdFromProposal(env));
    expect(handshake.pending(OWNER).map((p) => p.documentId)).toEqual([res.documentId]);
  });

  it("round-trips the envelope through storage without changing the document_id", () => {
    const { handshake } = newFixture();
    const env = proposal();
    const { documentId } = handshake.recordProposal(OWNER, encodeDocumentProposal(env), NOW);
    // The stored bytes are re-decoded on read. If that round trip were lossy the id would drift
    // from the one both parties agreed on, and the two sides would be on different documents.
    expect(documentIdFromProposal(handshake.get(OWNER, documentId)!.envelope)).toBe(documentId);
  });

  it("a redelivered proposal does not reset a decision already made", () => {
    const { handshake } = newFixture();
    const env = proposal();
    const wire = encodeDocumentProposal(env);
    const { documentId } = handshake.recordProposal(OWNER, wire, NOW);
    handshake.refuse(OWNER, documentId, "not now", NOW);

    handshake.recordProposal(OWNER, wire, NOW + 1);
    // Re-arrival is normal — delivery retries. Resetting to pending would let a peer un-refuse a
    // proposal the operator declined, simply by sending it again.
    expect(handshake.get(OWNER, documentId)!.consentState).toBe("refused");
  });
});

describe("DocumentHandshake — the seam is refused at PROPOSAL and again at ACCEPT", () => {
  for (const [label, p] of [
    ["an attested assurance tier", props({ assurance_tier: "attested" })],
    ["schema enforcement", props({ schema_enforcement: true })],
    ["mesh topology", props({ topology: "mesh" })],
  ] as const) {
    it(`auto-refuses ${label} at proposal, with the reason recorded`, () => {
      const { handshake } = newFixture();
      const res = handshake.recordProposal(
        OWNER,
        encodeDocumentProposal(proposal({ properties: p })),
        NOW,
      );
      expect(res.state).toBe("refused");
      expect(res.reason).toMatch(/document_seam_/);
      // Recorded rather than dropped: a dropped proposal is indistinguishable from a peer that
      // never sent one, and the operator has no way to learn their peer tried.
      expect(handshake.get(OWNER, res.documentId)!.refusalReason).toBe(res.reason);
      expect(handshake.pending(OWNER)).toHaveLength(0);
    });
  }

  it("refuses at ACCEPT too, even if the row somehow reached pending", () => {
    const { handshake, db } = newFixture();
    const env = proposal({ properties: props({ topology: "mesh" }) });
    const { documentId } = handshake.recordProposal(OWNER, encodeDocumentProposal(env), NOW);
    // Force the row to pending — this models the real case the second check exists for: the row
    // was recorded by an OLDER build whose seam rules were looser, and this build must not accept
    // terms it predates. The proposer and the accepter never run the same binary.
    db.prepare("UPDATE document_proposals SET consent_state = 'pending' WHERE document_id = ?").run(
      documentId,
    );

    const res = handshake.accept(OWNER, documentId, NOW);
    expect(res.ok).toBe(false);
    expect((res as { detail: string }).detail).toMatch(/document_seam_topology/);
    expect(handshake.get(OWNER, documentId)!.consentState).toBe("pending");
  });

  it("auto-refuses a feature-version mismatch, naming both versions", () => {
    const { handshake } = newFixture();
    const res = handshake.recordProposal(
      OWNER,
      encodeDocumentProposal(proposal({ feature_version: DOCUMENT_FEATURE_VERSION + 1 })),
      NOW,
    );
    expect(res.state).toBe("refused");
    expect(res.reason).toMatch(/document_feature_version_mismatch/);
    expect(res.reason).toContain(String(DOCUMENT_FEATURE_VERSION + 1));
  });
});

describe("DocumentHandshake — acceptance is COMPARE-AND-SET, so a decision is made once", () => {
  it("accepts a pending proposal exactly once", () => {
    const { handshake } = newFixture();
    const { documentId } = handshake.recordProposal(OWNER, encodeDocumentProposal(proposal()), NOW);

    expect(handshake.accept(OWNER, documentId, NOW).ok).toBe(true);
    const second = handshake.accept(OWNER, documentId, NOW);
    // Two concurrent accepts — an agent and a CLI, or two windows on one machine — are real on a
    // multi-attended daemon. Read-then-write would let both see `pending`, both mint the document,
    // and both report success.
    expect(second.ok).toBe(false);
    expect((second as { reason: string }).reason).toBe("document_proposal_not_pending");
    expect((second as { detail: string }).detail).toContain("accepted");
  });

  it("REFUSES to accept a proposal the operator already refused", () => {
    const { handshake } = newFixture();
    const { documentId } = handshake.recordProposal(OWNER, encodeDocumentProposal(proposal()), NOW);
    handshake.refuse(OWNER, documentId, "the properties are wrong for this work", NOW);

    const res = handshake.accept(OWNER, documentId, NOW);
    // The one outcome consent exists to make impossible: accepting after a decline.
    expect(res.ok).toBe(false);
    expect((res as { detail: string }).detail).toContain("refused");
    expect((res as { detail: string }).detail).toContain("the properties are wrong");
  });

  it("cannot refuse a proposal already accepted", () => {
    const { handshake } = newFixture();
    const { documentId } = handshake.recordProposal(OWNER, encodeDocumentProposal(proposal()), NOW);
    handshake.accept(OWNER, documentId, NOW);
    expect(handshake.refuse(OWNER, documentId, "changed my mind", NOW).ok).toBe(false);
    expect(handshake.get(OWNER, documentId)!.consentState).toBe("accepted");
  });

  it("refuses an unknown proposal by name rather than throwing", () => {
    const { handshake } = newFixture();
    const res = handshake.accept(OWNER, "ff".repeat(32), NOW);
    expect(res.ok).toBe(false);
    expect((res as { reason: string }).reason).toBe("document_proposal_unknown");
  });

  it("a refusal must say why", () => {
    const { handshake } = newFixture();
    const { documentId } = handshake.recordProposal(OWNER, encodeDocumentProposal(proposal()), NOW);
    // An operator meeting a refused proposal months later has no other record of which refusal it
    // was — theirs, or the daemon's on a seam violation.
    expect(() => handshake.refuse(OWNER, documentId, "   ", NOW)).toThrow(
      /document_refusal_reason_required/,
    );
  });

  it("hands the accepted envelope back, so both sides mint from the AGREED content", () => {
    const { handshake } = newFixture();
    const env = proposal({ starting_content: new Uint8Array([7, 7, 7]) });
    const { documentId } = handshake.recordProposal(OWNER, encodeDocumentProposal(env), NOW);

    const res = handshake.accept(OWNER, documentId, NOW);
    expect(res.ok).toBe(true);
    // Not a template string each side renders itself: two "identical" documents built
    // independently do not converge in a CRDT.
    expect(Array.from((res as { envelope: DocumentProposalEnvelope }).envelope.starting_content!)).toEqual([7, 7, 7]);
  });
});

describe("DocumentHandshake — properties are IMMUTABLE after accept (§16.3)", () => {
  it("exposes no mutate call, and the stored properties are the ones consented to", () => {
    const { handshake } = newFixture();
    const env = proposal({ properties: props({ append_only: true }) });
    const { documentId } = handshake.recordProposal(OWNER, encodeDocumentProposal(env), NOW);
    handshake.accept(OWNER, documentId, NOW);

    // A property change is an epoch event and therefore V2. The absence of a setter is the
    // enforcement — mutating after acceptance would silently change the rules the other party
    // agreed to, which is the one thing the handshake exists to prevent.
    expect("setProperties" in handshake).toBe(false);
    expect("updateProperties" in handshake).toBe(false);
    expect(handshake.get(OWNER, documentId)!.envelope.properties.append_only).toBe(true);
  });

  it("a re-proposal with DIFFERENT properties is a DIFFERENT document, not an edit", () => {
    const { handshake } = newFixture();
    const base = proposal();
    const { documentId: first } = handshake.recordProposal(
      OWNER,
      encodeDocumentProposal(base),
      NOW,
    );
    const { documentId: second } = handshake.recordProposal(
      OWNER,
      encodeDocumentProposal({ ...base, properties: props({ append_only: true }) }),
      NOW,
    );
    // Because document_id is the hash of the terms, changing a term cannot masquerade as the same
    // document — the id moves. That is the property doing the enforcement.
    expect(second).not.toBe(first);
    expect(handshake.pending(OWNER)).toHaveLength(2);
  });
});
