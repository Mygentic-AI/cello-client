/**
 * DOD-MP-GOVERN-1 — the signature-requirement policy, per rulings D2/D3 (2026-08-11).
 *
 * A SINGLE admin's signature suffices for add_holder, promote_admin, remove_holder (of a
 * non-admin), and change_property. remove_admin takes ALL OTHER admins — and with exactly two
 * admins neither can remove the other (BY DESIGN; the refusal names the recourse). A self-signed
 * voluntary leave is always acceptable, admin or not. The policy VALIDATES the collection's
 * claimed required set — it does not mint one, because "any one admin" has no single answer.
 *
 * Proven entirely bilateral where possible, and against deriveArrangement end-to-end with real
 * Ed25519 — no mocks for crypto.
 */
import { describe, it, expect } from "vitest";
import { generateKeyPairSync, sign as edSign, verify as edVerify } from "node:crypto";
import {
  documentGovernancePolicy,
  deriveArrangement,
  documentAmendmentHash,
  buildDocumentMultisigTbs,
  type DocumentAmendmentBody,
  type DocumentAmendmentEnvelope,
  type ArrangementGenesis,
} from "../index.js";

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

const DOC = "d".repeat(64);

function state(participants: Signer[], admins: Signer[]) {
  return {
    participants: new Set(participants.map((s) => s.agentId)),
    admins: new Set(admins.map((s) => s.agentId)),
  };
}

const ok = { ok: true };

describe("governance policy — single-admin kinds", () => {
  const [a, b, c] = [makeSigner(), makeSigner(), makeSigner()];
  const st = state([a, b, c], [a, b]);

  it.each(["add_holder", "promote_admin", "change_property"] as const)(
    "%s: any ONE current admin's claimed set is acceptable",
    (kind) => {
      expect(documentGovernancePolicy(kind, "f".repeat(64), st, [a.agentId])).toMatchObject(ok);
      expect(documentGovernancePolicy(kind, "f".repeat(64), st, [b.agentId])).toMatchObject(ok);
    },
  );

  it("a NON-admin's claimed set is refused, naming the rule", () => {
    const r = documentGovernancePolicy("add_holder", "f".repeat(64), st, [c.agentId]);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toMatch(/governance_not_admin/);
  });

  it("TWO admins claimed for a single-admin kind is refused — the claimed set must match the rule exactly", () => {
    // A wider claim is not "extra safe": every claimed signer must sign for the collection to
    // complete, so an inflated claim lets one absent co-signer veto an action the rule gives to
    // any single admin — a quiet governance change smuggled through the claim.
    const r = documentGovernancePolicy("add_holder", "f".repeat(64), st, [a.agentId, b.agentId]);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toMatch(/governance_claim_shape/);
  });

  it("remove_holder of a NON-admin: any one admin", () => {
    expect(documentGovernancePolicy("remove_holder", c.agentId, st, [a.agentId])).toMatchObject(ok);
  });
});

describe("governance policy — the voluntary leave", () => {
  const [a, b, c] = [makeSigner(), makeSigner(), makeSigner()];
  const st = state([a, b, c], [a]);

  it("a holder may sign their OWN removal, admin or not — leaving is always theirs", () => {
    expect(documentGovernancePolicy("remove_holder", c.agentId, st, [c.agentId])).toMatchObject(ok);
  });

  it("a non-admin cannot sign someone ELSE's removal", () => {
    const r = documentGovernancePolicy("remove_holder", b.agentId, st, [c.agentId]);
    expect(r.ok).toBe(false);
  });
});

describe("governance policy — remove_admin, all the OTHERS", () => {
  it("with three admins, removing one takes exactly the other two", () => {
    const [a, b, c] = [makeSigner(), makeSigner(), makeSigner()];
    const st = state([a, b, c], [a, b, c]);
    const others = [a.agentId, b.agentId].sort();
    expect(documentGovernancePolicy("remove_admin", c.agentId, st, others)).toMatchObject(ok);
    // Missing one other, or including the subject, is refused.
    expect(documentGovernancePolicy("remove_admin", c.agentId, st, [a.agentId]).ok).toBe(false);
    expect(
      documentGovernancePolicy("remove_admin", c.agentId, st, [a.agentId, b.agentId, c.agentId]).ok,
    ).toBe(false);
  });

  it("with exactly TWO admins neither can remove the other — BY DESIGN, and the refusal names the recourse", () => {
    const [a, b] = [makeSigner(), makeSigner()];
    const st = state([a, b], [a, b]);
    const r = documentGovernancePolicy("remove_admin", b.agentId, st, [a.agentId]);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toMatch(/governance_two_admin_deadlock/);
    expect(r.reason).toMatch(/duplicate/); // the recourse: stop, duplicate, start fresh
  });

  it("an admin may still LEAVE as a holder in the two-admin case — deadlock blocks removal, not exit", () => {
    const [a, b] = [makeSigner(), makeSigner()];
    const st = state([a, b], [a, b]);
    expect(documentGovernancePolicy("remove_holder", b.agentId, st, [b.agentId])).toMatchObject(ok);
  });

  it("remove_holder CANNOT expel a fellow admin — the all-others rule is not bypassable through the holder door", () => {
    // Without this, one admin's signature removes another admin entirely (holder removal drops
    // admin status too), evading remove_admin's rule and the two-admin deadlock in one move.
    const [a, b, c] = [makeSigner(), makeSigner(), makeSigner()];
    const st = state([a, b, c], [a, b, c]);
    const r = documentGovernancePolicy("remove_holder", b.agentId, st, [a.agentId]);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toMatch(/governance_remove_admin_first/);
  });
});

describe("governance policy — end to end through deriveArrangement", () => {
  const DOCID = DOC;

  function genesis(a: Signer, b: Signer, admins: Signer[]): ArrangementGenesis {
    return {
      documentId: DOCID,
      proposerAgentId: a.agentId,
      peerAgentId: b.agentId,
      adminSet: admins.map((s) => s.agentId),
      properties: { assurance_tier: "authenticated", schema_enforcement: false, topology: "mesh", append_only: false },
    };
  }

  function signed(bodyIn: Partial<DocumentAmendmentBody>, signers: Signer[]): DocumentAmendmentEnvelope {
    const body: DocumentAmendmentBody = {
      document_id: DOCID,
      epoch_id: 1,
      prev_amendment_hash: null,
      kind: "add_holder",
      subject_agent_id: "c".repeat(64),
      property_change: null,
      state_hash: null,
      authored_at_ms: 1_700_000_000_000,
      ...bodyIn,
    };
    const hash = documentAmendmentHash(body);
    const required = signers.map((s) => s.agentId).sort();
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
        signatures: signers.map((s) => ({ signer_agent_id: s.agentId, signature: s.sign(tbs) })),
      },
    };
  }

  it("one admin invites; the other admin's signature is NOT needed (D2: single-admin power)", () => {
    const [a, b, c] = [makeSigner(), makeSigner(), makeSigner()];
    const r = deriveArrangement(
      genesis(a, b, [a, b]),
      [signed({ subject_agent_id: c.agentId }, [b])],
      documentGovernancePolicy,
      makeVerify([a, b, c]),
    );
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.arrangement.participants.has(c.agentId)).toBe(true);
  });

  it("a non-admin's invite is refused end to end", () => {
    const [a, b, c] = [makeSigner(), makeSigner(), makeSigner()];
    const r = deriveArrangement(
      genesis(a, b, [a]),
      [signed({ subject_agent_id: c.agentId }, [b])],
      documentGovernancePolicy,
      makeVerify([a, b, c]),
    );
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toMatch(/governance_not_admin/);
  });

  it("the two-admin deadlock holds end to end, with the recourse in the refusal", () => {
    const [a, b] = [makeSigner(), makeSigner()];
    const r = deriveArrangement(
      genesis(a, b, [a, b]),
      [signed({ kind: "remove_admin", subject_agent_id: b.agentId }, [a])],
      documentGovernancePolicy,
      makeVerify([a, b]),
    );
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toMatch(/governance_two_admin_deadlock/);
  });
});
