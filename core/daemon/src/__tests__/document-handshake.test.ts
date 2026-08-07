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

/** Verifies everything — the signature seam is exercised on its own in its own block. */
const ALWAYS_VALID = () => true;

function newFixture(verify = ALWAYS_VALID) {
  const { logger, events } = recordingLogger();
  const db = new DatabaseSync(":memory:");
  return { handshake: new DocumentHandshake(db, logger, verify), events, db, logger };
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
    // Compared against the ORIGINAL in-memory envelope, not against another decode of the same
    // bytes: a decode that dropped a field CONSISTENTLY would make both sides equally lossy and
    // the assertion would hold while the id drifted from what the peer computed.
    expect(documentIdFromProposal(handshake.get(OWNER, documentId)!.envelope)).toBe(
      documentIdFromProposal(env),
    );
  });

  it("a redelivered proposal does not reset a decision already made", () => {
    const { handshake } = newFixture();
    const env = proposal();
    const wire = encodeDocumentProposal(env);
    const { documentId } = handshake.recordProposal(OWNER, wire, NOW);
    handshake.refuse(OWNER, documentId, "not now", NOW);

    const redelivered = handshake.recordProposal(OWNER, wire, NOW + 1);
    // Re-arrival is normal — delivery retries. Resetting to pending would let a peer un-refuse a
    // proposal the operator declined, simply by sending it again.
    expect(handshake.get(OWNER, documentId)!.consentState).toBe("refused");
    // And the RETURN must match the row. Reporting "pending" for a decision already made surfaces
    // it to the operator as still awaiting them, and logs an arrival that did not happen.
    expect(redelivered.state).toBe("refused");
    expect(redelivered.reason).toBe("not now");
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
    // And the row is DECIDED, not left pending — see the dedicated block below for why.
    expect(handshake.get(OWNER, documentId)!.consentState).toBe("refused");
  });

  it("auto-refuses a feature-version mismatch, naming both versions", () => {
    const { handshake } = newFixture();
    const res = handshake.recordProposal(
      OWNER,
      encodeDocumentProposal(proposal({ feature_version: DOCUMENT_FEATURE_VERSION + 1 })),
      NOW,
    );
    expect(res.state).toBe("refused");
    // The clause asks for a HUMAN answer, and the useful part is which side must upgrade. A
    // machine label like "version_mismatch: 2 vs 1" is accurate and tells the operator nothing
    // they can act on.
    expect(res.reason).toContain("upgrade this client");
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

    // An ALLOWLIST over the prototype, not a denylist of two guessed names — the method nobody
    // thought of is exactly the one a denylist misses. A new public method fails this test until
    // someone justifies it, which is the point: a property change is an epoch event and therefore
    // V2, and mutating after acceptance would silently change the rules the other party agreed to.
    // `recordOutgoing` is on the list deliberately: it WRITES a proposal (one we authored, so it can
    // be re-sent to an offline peer without minting a second document) and never touches an existing
    // row's properties — its INSERT is ON CONFLICT DO NOTHING, so a stored proposal is unreachable
    // from it. That is the justification this allowlist exists to demand.
    expect(Object.getOwnPropertyNames(DocumentHandshake.prototype).sort()).toEqual(
      // `recordPeerDecision`/`peerDecision` are the mirror direction — THEIR answer to OUR proposal.
      // They write `peer_accepted`, never `consent_state` or `envelope`, so the properties this
      // test guards remain unreachable from them. Justified for the same reason `recordOutgoing`
      // is: this allowlist demands a reason, and "it writes a different column" is one.
      // `peerAnswer` joins its siblings for the same reason: it READS `peer_accepted`/`peer_reason`
      // and touches neither `consent_state` nor `envelope`, so the properties this test guards stay
      // unreachable from it.
      //
      // `markProposalSent`/`proposalSent` are the newest pair, and the justification this allowlist
      // demands is: they record and read a TRANSPORT fact — did our offer actually leave — in
      // `proposal_sent_at`. Neither can reach `consent_state` or `envelope`; `markProposalSent`'s
      // UPDATE names one column and is further guarded by `proposal_sent_at IS NULL`, so it cannot
      // even rewrite its own. They exist because nothing durable recorded the send outcome, which
      // made `peerAccepted: null` mean both "they are thinking" and "they were never asked" — and
      // the shipped guidance told the operator to wait, which is wrong for the second.
      ["accept", "constructor", "get", "pending", "recordProposal", "recordOutgoing", "refuse",
       "recordPeerDecision", "peerDecision", "peerAnswer", "markProposalSent", "proposalSent"].sort(),
    );
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


describe("DocumentHandshake — acceptance is CONCURRENCY-safe, not merely sequential", () => {
  it("a decision landing BETWEEN the read and the write does not get overwritten", () => {
    const { handshake, db } = newFixture();
    const { documentId } = handshake.recordProposal(OWNER, encodeDocumentProposal(proposal()), NOW);

    // The real interleaving. A sequential "call accept twice" test cannot tell compare-and-set
    // from read-then-write — both return an error on the second call. This one can: it refuses the
    // proposal from OUTSIDE, after accept() has read the row and before it writes. Read-then-write
    // accepts a proposal the operator declined, which is the one outcome consent exists to prevent.
    let fired = false;
    const realPrepare = db.prepare.bind(db);
    (db as unknown as { prepare: typeof db.prepare }).prepare = ((sql: string) => {
      const stmt = realPrepare(sql);
      if (!fired && sql.includes("SELECT * FROM document_proposals")) {
        const all = stmt.all.bind(stmt);
        return new Proxy(stmt, {
          get: (t, k) =>
            k === "all"
              ? (...args: unknown[]) => {
                  const rows = all(...(args as never[]));
                  if (!fired) {
                    fired = true;
                    handshake.refuse(OWNER, documentId, "declined while you were reading", NOW);
                  }
                  return rows;
                }
              : Reflect.get(t, k, t),
        });
      }
      return stmt;
    }) as typeof db.prepare;

    const res = handshake.accept(OWNER, documentId, NOW);
    expect(res.ok).toBe(false);
    expect(handshake.get(OWNER, documentId)!.consentState).toBe("refused");
  });
});

describe("DocumentHandshake — an unverified proposal never reaches the inbox", () => {
  it("REFUSES a proposal whose signature does not verify, and stores nothing", () => {
    const { handshake } = newFixture(() => false);
    expect(() =>
      handshake.recordProposal(OWNER, encodeDocumentProposal(proposal()), NOW),
    ).toThrow(/document_proposal_signature_invalid/);
    // Nothing stored: ON CONFLICT DO NOTHING makes the FIRST arrival's bytes permanent for a
    // document_id, so admitting an unverified one lets anyone who observed the honest proposal
    // race a junk variant, win the key, and poison the id while the real proposal is discarded.
    expect(handshake.pending(OWNER)).toHaveLength(0);
  });

  it("verifies against the PROPOSER and over the proposal's own preimage", () => {
    const seen: Array<{ agent: string; sigByte: number }> = [];
    const { handshake } = newFixture((agent, _tbs, sig) => {
      seen.push({ agent, sigByte: sig[0]! });
      return true;
    });
    handshake.recordProposal(OWNER, encodeDocumentProposal(proposal()), NOW);
    expect(seen[0]!.agent).toBe("agent-a");
    expect(seen[0]!.sigByte).toBe(5);
  });
});

describe("DocumentHandshake — a proposal must be ADDRESSED to the accepting agent", () => {
  it("refuses to record a proposal naming a different peer", () => {
    const { handshake } = newFixture();
    expect(() =>
      handshake.recordProposal(
        OWNER,
        encodeDocumentProposal(proposal({ peer_agent_id: "someone-else" })),
        NOW,
      ),
    ).toThrow(/document_proposal_wrong_peer/);
    // On a multi-agent daemon an unchecked pair lets consent be taken from a party the proposal
    // never named, while document_id — which does commit to peer_agent_id — says otherwise.
    expect(handshake.pending(OWNER)).toHaveLength(0);
  });
});

describe("DocumentHandshake — a seam violation at ACCEPT is recorded, not just returned", () => {
  it("transitions the row to refused so the operator can clear it", () => {
    const { handshake, db } = newFixture();
    const env = proposal({ properties: props({ topology: "mesh" }) });
    const { documentId } = handshake.recordProposal(OWNER, encodeDocumentProposal(env), NOW);
    db.prepare("UPDATE document_proposals SET consent_state = 'pending' WHERE document_id = ?").run(
      documentId,
    );

    handshake.accept(OWNER, documentId, NOW);
    const row = handshake.get(OWNER, documentId)!;
    // Left pending, this is an inbox entry the operator can never clear, carrying no reason —
    // while the arrival path records one for the identical condition.
    expect(row.consentState).toBe("refused");
    expect(row.refusalReason).toMatch(/document_seam_topology/);
    expect(handshake.pending(OWNER)).toHaveLength(0);
  });
});
