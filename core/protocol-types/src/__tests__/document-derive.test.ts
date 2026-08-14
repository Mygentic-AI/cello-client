/**
 * SYNC-P1 — the causal derivation: Kahn + ascending-entry-hash linearization, fold rules F1–F4
 * (M14B Build Journal Entries 48–49). One derivation for every holder: the same entry set MUST
 * produce the identical {participants, admins, properties} everywhere, and every genuinely
 * conflicting governance act has a stated, order-independent outcome.
 *
 * The order-sensitive cases GRIND authored_at_ms until the two entries' hashes sort each way, so
 * dominance is proven in BOTH fold orders — not just the one this run's keys happened to give.
 *
 * Policy is the REAL documentGovernancePolicy — the conflict rules lean on its exact requirements
 * (single-admin kinds, the holder door, all-other-admins removal). Signatures are REAL Ed25519.
 */
import { describe, it, expect } from "vitest";
import { generateKeyPairSync, sign as edSign, verify as edVerify } from "node:crypto";
import {
  documentAmendmentHash,
  type DocumentAmendmentBody,
  type DocumentAmendmentEnvelope,
  type ArrangementGenesis,
} from "../document-amendment.js";
import { documentGovernancePolicy } from "../document-governance.js";
import { buildDocumentMultisigTbs } from "../document-multisig.js";
import { deriveDocumentState, checkEntryAdmissible } from "../document-derive.js";

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

const DOC_ID = "d".repeat(64);
const T0 = 1_700_000_000_000;

function genesis(a: Signer, b: Signer, admins: Signer[] = [a]): ArrangementGenesis {
  return {
    documentId: DOC_ID,
    proposerAgentId: a.agentId,
    peerAgentId: b.agentId,
    adminSet: admins.map((s) => s.agentId),
    properties: { assurance_tier: "authenticated", schema_enforcement: false, topology: "mesh", append_only: false },
  };
}

/** A fully-signed causal entry. Author defaults to the first signer; the claimed set is exact. */
function entry(
  over: Partial<DocumentAmendmentBody>,
  signers: Signer[],
): DocumentAmendmentEnvelope {
  const body: DocumentAmendmentBody = {
    document_id: DOC_ID,
    epoch_id: 1,
    prev_amendment_hash: null,
    kind: "add_holder",
    subject_agent_id: "c".repeat(64),
    property_change: null,
    state_hash: null,
    authored_at_ms: T0,
    author_agent_id: signers[0]!.agentId,
    author_seq: 1,
    parents: [],
    ...over,
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

function hashHex(env: DocumentAmendmentEnvelope): string {
  return Buffer.from(documentAmendmentHash(env.body)).toString("hex");
}

/**
 * Grind authored_at_ms on entry B until its hash sorts the requested way against entry A's.
 * Bodies only — signatures are applied by the builders after the order is fixed.
 */
function grindOrder(
  makeA: () => DocumentAmendmentEnvelope,
  makeB: (ts: number) => DocumentAmendmentEnvelope,
  bLower: boolean,
): { a: DocumentAmendmentEnvelope; b: DocumentAmendmentEnvelope } {
  const a = makeA();
  const ha = hashHex(a);
  for (let ts = T0 + 1; ts < T0 + 10_000; ts++) {
    const b = makeB(ts);
    if ((hashHex(b) < ha) === bLower) return { a, b };
  }
  throw new Error("grind failed to find the requested hash order in 10k attempts");
}

function deriveOk(
  g: ArrangementGenesis,
  entries: DocumentAmendmentEnvelope[],
  signers: Signer[],
) {
  const r = deriveDocumentState(g, entries, documentGovernancePolicy, makeVerify(signers));
  expect(r.ok).toBe(true);
  if (!r.ok) throw new Error(r.reason);
  return r.state;
}

describe("deriveDocumentState — determinism", () => {
  it("is a pure function of the entry SET — any array order gives the identical state", () => {
    const [a, b, c, d] = [makeSigner(), makeSigner(), makeSigner(), makeSigner()];
    const g = genesis(a, b, [a]);
    const e1 = entry({ subject_agent_id: c.agentId, author_seq: 1 }, [a]);
    const e2 = entry(
      { subject_agent_id: d.agentId, author_seq: 2, epoch_id: 2, parents: [hashHex(e1)] },
      [a],
    );
    const e3 = entry(
      {
        kind: "promote_admin",
        subject_agent_id: c.agentId,
        author_seq: 3,
        epoch_id: 3,
        parents: [hashHex(e2)],
      },
      [a],
    );
    const signers = [a, b, c, d];
    const forward = deriveOk(g, [e1, e2, e3], signers);
    const shuffled = deriveOk(g, [e3, e1, e2], signers);
    expect([...shuffled.participants].sort()).toEqual([...forward.participants].sort());
    expect([...shuffled.admins].sort()).toEqual([...forward.admins].sort());
    expect(shuffled.order).toEqual(forward.order);
    expect(shuffled.frontier).toEqual(forward.frontier);
    expect([...forward.participants].sort()).toEqual(
      [a.agentId, b.agentId, c.agentId, d.agentId].sort(),
    );
    expect([...forward.admins].sort()).toEqual([a.agentId, c.agentId].sort());
  });

  it("derives a sequential chain exactly as the linear replay did", () => {
    const [a, b, c] = [makeSigner(), makeSigner(), makeSigner()];
    const g = genesis(a, b, [a]);
    const add = entry({ subject_agent_id: c.agentId }, [a]);
    const flip = entry(
      {
        kind: "change_property",
        subject_agent_id: null,
        property_change: { key: "append_only", value: true },
        author_seq: 2,
        epoch_id: 2,
        parents: [hashHex(add)],
      },
      [a],
    );
    const remove = entry(
      {
        kind: "remove_holder",
        subject_agent_id: c.agentId,
        author_seq: 3,
        epoch_id: 3,
        parents: [hashHex(flip)],
      },
      [a],
    );
    const s = deriveOk(g, [add, flip, remove], [a, b, c]);
    expect([...s.participants].sort()).toEqual([a.agentId, b.agentId].sort());
    expect(s.properties["append_only"]).toBe(true);
    expect(s.voids).toEqual([]);
    expect(s.interimMaxEpoch).toBe(3);
    expect(s.interimLastHash).toBe(hashHex(remove));
  });

  it("refuses a genesis with no admins — that is a document-level refusal, not a void", () => {
    const [a, b] = [makeSigner(), makeSigner()];
    const g = { ...genesis(a, b), adminSet: [] };
    const r = deriveDocumentState(g, [], documentGovernancePolicy, makeVerify([a, b]));
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toMatch(/arrangement_admin_set_empty/);
  });
});

describe("deriveDocumentState — concurrent property changes (LWW by the total order)", () => {
  function propertyRace(bLower: boolean) {
    const [a, b] = [makeSigner(), makeSigner()];
    const g = genesis(a, b, [a, b]);
    const { a: ea, b: eb } = grindOrder(
      () =>
        entry(
          {
            kind: "change_property",
            subject_agent_id: null,
            property_change: { key: "append_only", value: true },
          },
          [a],
        ),
      (ts) =>
        entry(
          {
            kind: "change_property",
            subject_agent_id: null,
            property_change: { key: "append_only", value: false },
            authored_at_ms: ts,
          },
          [b],
        ),
      bLower,
    );
    const s = deriveOk(g, [ea, eb], [a, b]);
    return { s, ea, eb };
  }

  it("the entry later in the total order wins; both stand on the record", () => {
    const { s, ea, eb } = propertyRace(true); // b's hash lower → a folds later → a's value wins
    expect(s.properties["append_only"]).toBe(true);
    expect(s.order).toEqual([hashHex(eb), hashHex(ea)]);
    expect(s.voids).toEqual([]);
  });

  it("…and symmetrically in the other hash order", () => {
    const { s, ea, eb } = propertyRace(false); // b's hash higher → b folds later → b's value wins
    expect(s.properties["append_only"]).toBe(false);
    expect(s.order).toEqual([hashHex(ea), hashHex(eb)]);
    expect(s.voids).toEqual([]);
  });
});

describe("deriveDocumentState — removal dominates a concurrent promotion (both hash orders)", () => {
  function race(bLower: boolean) {
    const [a, b, c] = [makeSigner(), makeSigner(), makeSigner()];
    const g = genesis(a, b, [a, b]);
    const admit = entry({ subject_agent_id: c.agentId }, [a]);
    const admitHash = hashHex(admit);
    // A removes C (single-admin: C is a plain participant at the removal's ancestors)…
    const { a: removal, b: promotion } = grindOrder(
      () =>
        entry(
          {
            kind: "remove_holder",
            subject_agent_id: c.agentId,
            author_seq: 2,
            epoch_id: 2,
            parents: [admitHash],
          },
          [a],
        ),
      // …while B, concurrently and unaware, promotes C to admin.
      (ts) =>
        entry(
          {
            kind: "promote_admin",
            subject_agent_id: c.agentId,
            epoch_id: 2,
            parents: [admitHash],
            authored_at_ms: ts,
          },
          [b],
        ),
      bLower,
    );
    return { g, entries: [admit, removal, promotion], signers: [a, b, c], c };
  }

  it("C is removed when the removal folds first", () => {
    const { g, entries, signers, c } = race(false);
    const s = deriveOk(g, entries, signers);
    expect(s.participants.has(c.agentId)).toBe(false);
    expect(s.admins.has(c.agentId)).toBe(false);
  });

  it("C is removed even when the PROMOTION folds first — never a hash coin toss", () => {
    const { g, entries, signers, c } = race(true);
    const s = deriveOk(g, entries, signers);
    expect(s.participants.has(c.agentId)).toBe(false);
    expect(s.admins.has(c.agentId)).toBe(false);
  });
});

describe("deriveDocumentState — a removed admin's concurrent authority is void", () => {
  function setup() {
    const [a, b, c, d] = [makeSigner(), makeSigner(), makeSigner(), makeSigner()];
    const g = genesis(a, b, [a, b]);
    const admitC = entry({ subject_agent_id: c.agentId }, [a]);
    const promoteC = entry(
      {
        kind: "promote_admin",
        subject_agent_id: c.agentId,
        author_seq: 2,
        epoch_id: 2,
        parents: [hashHex(admitC)],
      },
      [a],
    );
    return { a, b, c, d, g, admitC, promoteC };
  }

  function concurrentGrantRace(grantLower: boolean) {
    const { a, b, c, d, g, admitC, promoteC } = setup();
    // C (admin) invites D concurrently with C's removal by {A, B} — GROUND both hash orders,
    // because with the removal folding first the policy alone would void the grant and a broken
    // concurrency rule would hide behind it on the hash coin (review F1's hollow-test finding).
    const removeC = entry(
      {
        kind: "remove_admin",
        subject_agent_id: c.agentId,
        author_seq: 3,
        epoch_id: 3,
        parents: [hashHex(promoteC)],
      },
      [a, b],
    );
    const { b: grant } = grindOrder(
      () => removeC,
      (ts) =>
        entry(
          { subject_agent_id: d.agentId, epoch_id: 3, parents: [hashHex(promoteC)], authored_at_ms: ts },
          [c],
        ),
      grantLower,
    );
    const s = deriveOk(g, [admitC, promoteC, grant, removeC], [a, b, c, d]);
    return { s, grant, c, d };
  }

  it("a grant NOT ancestral to the removal is void — even when the GRANT folds first", () => {
    const { s, grant, c, d } = concurrentGrantRace(true);
    expect(s.participants.has(d.agentId)).toBe(false);
    expect(s.admins.has(c.agentId)).toBe(false);
    // remove_admin DEMOTES — C stays a holder (the holder door is a separate, guarded act).
    expect(s.participants.has(c.agentId)).toBe(true);
    expect(s.voids.find((v) => v.hash === hashHex(grant))!.reason).toMatch(
      /concurrent.*removal|removal.*concurrent/i,
    );
  });

  it("…and in the other hash order too", () => {
    const { s, grant, d } = concurrentGrantRace(false);
    expect(s.participants.has(d.agentId)).toBe(false);
    expect(s.voids.map((v) => v.hash)).toContain(hashHex(grant));
  });

  it("RE-ADMISSION works — a removal among an entry's ANCESTORS is not concurrent with it (review F1)", () => {
    // The Entry 48 promise, pinned: remove C, re-admit C, re-promote C — C's next act TAKES
    // EFFECT. The broken rule ("non-ancestral" instead of "concurrent") voided a re-admitted
    // admin forever, with a reason naming a race that never happened.
    const [a, b, c] = [makeSigner(), makeSigner(), makeSigner()];
    const g = genesis(a, b, [a]);
    const admitC = entry({ subject_agent_id: c.agentId }, [a]);
    const removeC = entry(
      { kind: "remove_holder", subject_agent_id: c.agentId, author_seq: 2, epoch_id: 2, parents: [hashHex(admitC)] },
      [a],
    );
    const readmitC = entry(
      { subject_agent_id: c.agentId, author_seq: 3, epoch_id: 3, parents: [hashHex(removeC)] },
      [a],
    );
    const repromoteC = entry(
      { kind: "promote_admin", subject_agent_id: c.agentId, author_seq: 4, epoch_id: 4, parents: [hashHex(readmitC)] },
      [a],
    );
    const act = entry(
      {
        kind: "change_property",
        subject_agent_id: null,
        property_change: { key: "append_only", value: true },
        epoch_id: 5,
        parents: [hashHex(repromoteC)],
      },
      [c],
    );
    const s = deriveOk(g, [admitC, removeC, readmitC, repromoteC, act], [a, b, c]);
    expect(s.participants.has(c.agentId)).toBe(true);
    expect(s.admins.has(c.agentId)).toBe(true);
    expect(s.properties["append_only"]).toBe(true);
    expect(s.voids).toEqual([]);
  });

  it("WITHOUT re-admission, a removed party's post-removal act still voids — on its own merits, not on concurrency", () => {
    const [a, b, c] = [makeSigner(), makeSigner(), makeSigner()];
    const g = genesis(a, b, [a]);
    const admitC = entry({ subject_agent_id: c.agentId }, [a]);
    const removeC = entry(
      { kind: "remove_holder", subject_agent_id: c.agentId, author_seq: 2, epoch_id: 2, parents: [hashHex(admitC)] },
      [a],
    );
    const lateAct = entry(
      {
        kind: "change_property",
        subject_agent_id: null,
        property_change: { key: "append_only", value: true },
        epoch_id: 3,
        parents: [hashHex(removeC)],
      },
      [c],
    );
    const s = deriveOk(g, [admitC, removeC, lateAct], [a, b, c]);
    expect(s.properties["append_only"]).toBe(false);
    const reason = s.voids.find((v) => v.hash === hashHex(lateAct))!.reason;
    expect(reason).toMatch(/governance_not_admin/);
    expect(reason).not.toMatch(/concurrent/);
  });

  it("a grant the removers had SEEN (ancestral to the removal) stands", () => {
    const { a, b, c, d, g, admitC, promoteC } = setup();
    const grant = entry(
      { subject_agent_id: d.agentId, epoch_id: 3, parents: [hashHex(promoteC)] },
      [c],
    );
    // The removal names the grant among its parents — the removers acted knowing of it.
    const removeC = entry(
      {
        kind: "remove_admin",
        subject_agent_id: c.agentId,
        author_seq: 3,
        epoch_id: 4,
        parents: [hashHex(grant)],
      },
      [a, b],
    );
    const s = deriveOk(g, [admitC, promoteC, grant, removeC], [a, b, c, d]);
    expect(s.participants.has(d.agentId)).toBe(true);
    expect(s.admins.has(c.agentId)).toBe(false);
  });
});

describe("deriveDocumentState — the admin floor (Entry 49 addendum)", () => {
  function threeAdmins() {
    const [a, b, c] = [makeSigner(), makeSigner(), makeSigner()];
    const g = genesis(a, b, [a, b]);
    const admitC = entry({ subject_agent_id: c.agentId }, [a]);
    const promoteC = entry(
      {
        kind: "promote_admin",
        subject_agent_id: c.agentId,
        author_seq: 2,
        epoch_id: 2,
        parents: [hashHex(admitC)],
      },
      [a],
    );
    const base = [hashHex(promoteC)];
    return { a, b, c, g, prelude: [admitC, promoteC], base };
  }

  it("two mutual removals among three admins leave the co-signer standing", () => {
    const { a, b, c, g, prelude, base } = threeAdmins();
    // remove(A) by {B,C} ∥ remove(B) by {A,C} — C co-signs both.
    const removeA = entry(
      { kind: "remove_admin", subject_agent_id: a.agentId, epoch_id: 3, parents: base, author_agent_id: b.agentId },
      [b, c],
    );
    const removeB = entry(
      { kind: "remove_admin", subject_agent_id: b.agentId, epoch_id: 3, parents: base },
      [a, c],
    );
    const s = deriveOk(g, [...prelude, removeA, removeB], [a, b, c]);
    expect([...s.admins]).toEqual([c.agentId]);
    // Forward-only: the removed are gone as participants too? No — remove_admin demotes only.
    expect(s.participants.has(a.agentId)).toBe(true);
    expect(s.participants.has(b.agentId)).toBe(true);
  });

  it("a three-way removal race leaves exactly ONE admin — never zero", () => {
    const { a, b, c, g, prelude, base } = threeAdmins();
    const removeA = entry(
      { kind: "remove_admin", subject_agent_id: a.agentId, epoch_id: 3, parents: base, author_agent_id: b.agentId },
      [b, c],
    );
    const removeB = entry(
      { kind: "remove_admin", subject_agent_id: b.agentId, epoch_id: 3, parents: base },
      [a, c],
    );
    const removeC = entry(
      { kind: "remove_admin", subject_agent_id: c.agentId, epoch_id: 3, parents: base },
      [a, b],
    );
    const s = deriveOk(g, [...prelude, removeA, removeB, removeC], [a, b, c]);
    expect(s.admins.size).toBe(1);
    const floored = s.voids.filter((v) => /admin_floor/.test(v.reason));
    expect(floored.length).toBe(1);
  });
});

describe("deriveDocumentState — equivocation folds as concurrency", () => {
  it("two entries by one author at the same seq both fold; the derivation stays deterministic", () => {
    const [a, b, c, d] = [makeSigner(), makeSigner(), makeSigner(), makeSigner()];
    const g = genesis(a, b, [a]);
    const forkOne = entry({ subject_agent_id: c.agentId }, [a]);
    const forkTwo = entry({ subject_agent_id: d.agentId, authored_at_ms: T0 + 5 }, [a]);
    expect(forkOne.body.author_seq).toBe(forkTwo.body.author_seq);
    const signers = [a, b, c, d];
    const one = deriveOk(g, [forkOne, forkTwo], signers);
    const two = deriveOk(g, [forkTwo, forkOne], signers);
    expect(one.order).toEqual(two.order);
    expect([...one.participants].sort()).toEqual(
      [a.agentId, b.agentId, c.agentId, d.agentId].sort(),
    );
    // The fork is visible: two applied entries by A at seq 1.
    expect(one.authorSeqs.get(a.agentId)).toBe(1);
  });
});

describe("deriveDocumentState — incomplete ancestry excludes, never guesses", () => {
  it("an entry whose parent is absent is EXCLUDED with its descendants, and says so", () => {
    const [a, b, c, d] = [makeSigner(), makeSigner(), makeSigner(), makeSigner()];
    const g = genesis(a, b, [a]);
    const missing = entry({ subject_agent_id: c.agentId }, [a]); // never passed in
    const orphan = entry(
      {
        subject_agent_id: d.agentId,
        author_seq: 2,
        epoch_id: 2,
        parents: [hashHex(missing)],
      },
      [a],
    );
    const s = deriveOk(g, [orphan], [a, b, c, d]);
    expect(s.participants.has(d.agentId)).toBe(false);
    expect(s.excluded.map((e) => e.hash)).toContain(hashHex(orphan));
    expect(s.excluded[0]!.reason).toMatch(/ancest|parent/i);
    expect(s.order).toEqual([]);
  });

  it("an author's own chain must be contiguous — seq 2 whose parents omit their seq 1 is void", () => {
    const [a, b, c, d] = [makeSigner(), makeSigner(), makeSigner(), makeSigner()];
    const g = genesis(a, b, [a]);
    const first = entry({ subject_agent_id: c.agentId }, [a]);
    // Seq 2 by A, but its parents do NOT include A's seq-1 entry.
    const broken = entry(
      { subject_agent_id: d.agentId, author_seq: 2, epoch_id: 2, parents: [] },
      [a],
    );
    const s = deriveOk(g, [first, broken], [a, b, c, d]);
    expect(s.participants.has(c.agentId)).toBe(true);
    expect(s.participants.has(d.agentId)).toBe(false);
    expect(s.voids.find((v) => v.hash === hashHex(broken))!.reason).toMatch(/own.chain|own_chain/i);
  });
});

describe("deriveDocumentState — fold-voids stay on the record (F4)", () => {
  it("adding an existing holder is void with the named reason; the state is untouched", () => {
    const [a, b] = [makeSigner(), makeSigner()];
    const g = genesis(a, b, [a]);
    const dup = entry({ subject_agent_id: b.agentId }, [a]);
    const s = deriveOk(g, [dup], [a, b]);
    expect([...s.participants].sort()).toEqual([a.agentId, b.agentId].sort());
    expect(s.voids.length).toBe(1);
    expect(s.voids[0]!.reason).toMatch(/already_holder/);
    // Void entries are still IN the linearization — history, not refusal.
    expect(s.order).toEqual([hashHex(dup)]);
  });

  it("an author outside the collection's required set is void — accountability is signed", () => {
    const [a, b, c] = [makeSigner(), makeSigner(), makeSigner()];
    const g = genesis(a, b, [a, b]);
    // Signed by admin B, but CLAIMS author A — the initiator must be in the required set.
    const impostor = entry(
      { subject_agent_id: c.agentId, author_agent_id: a.agentId },
      [b],
    );
    const s = deriveOk(g, [impostor], [a, b, c]);
    expect(s.participants.has(c.agentId)).toBe(false);
    expect(s.voids[0]!.reason).toMatch(/author.*required|accountab/i);
  });

  it("an incomplete signature collection is void, not document-fatal", () => {
    const [a, b, c, d] = [makeSigner(), makeSigner(), makeSigner(), makeSigner()];
    const g = genesis(a, b, [a]);
    // Distinct subjects — were both to admit the same holder, whichever folds first would flip
    // the OTHER's void reason to already_holder and the assertion would ride the hash coin.
    const unsigned = entry({ subject_agent_id: c.agentId }, [a]);
    unsigned.collection.signatures = [];
    const good = entry({ subject_agent_id: d.agentId, authored_at_ms: T0 + 9 }, [a]);
    const s = deriveOk(g, [unsigned, good], [a, b, c, d]);
    expect(s.participants.has(d.agentId)).toBe(true);
    expect(s.participants.has(c.agentId)).toBe(false);
    expect(s.voids.find((v) => v.hash === hashHex(unsigned))!.reason).toMatch(/incomplete/);
  });
});

describe("deriveDocumentState — the holder cap under concurrency", () => {
  it("two concurrent admissions at cap-1 admit exactly one, deterministically", () => {
    const [a, b] = [makeSigner(), makeSigner()];
    const g = genesis(a, b, [a]);
    // Fill to cap-1 sequentially (17 admissions on top of the 2 genesis holders → 19).
    const fillers: DocumentAmendmentEnvelope[] = [];
    let prev: string[] = [];
    for (let i = 0; i < 17; i++) {
      const e = entry(
        {
          subject_agent_id: makeSigner().agentId,
          author_seq: i + 1,
          epoch_id: i + 1,
          parents: prev,
          authored_at_ms: T0 + i,
        },
        [a],
      );
      fillers.push(e);
      prev = [hashHex(e)];
    }
    // Two concurrent admissions by admin A — a same-seq fork, both signed, both admissible.
    const race1 = entry(
      { subject_agent_id: makeSigner().agentId, author_seq: 18, epoch_id: 18, parents: prev, authored_at_ms: T0 + 100 },
      [a],
    );
    const race2 = entry(
      { subject_agent_id: makeSigner().agentId, author_seq: 18, epoch_id: 18, parents: prev, authored_at_ms: T0 + 102 },
      [a],
    );
    const s = deriveOk(g, [...fillers, race1, race2], [a, b]);
    expect(s.participants.size).toBe(20);
    const capVoids = s.voids.filter((v) => /holder_cap/.test(v.reason));
    expect(capVoids.length).toBe(1);
  });
});

describe("deriveDocumentState — replay-parity cases (coverage carried from the deleted linear replay)", () => {
  it("genesis alone derives the bilateral arrangement with the genesis admin set", () => {
    const [a, b] = [makeSigner(), makeSigner()];
    const s = deriveOk(genesis(a, b), [], [a, b]);
    expect([...s.participants].sort()).toEqual([a.agentId, b.agentId].sort());
    expect([...s.admins]).toEqual([a.agentId]);
    expect(s.properties["topology"]).toBe("mesh");
    expect(s.interimMaxEpoch).toBe(0);
    expect(s.interimLastHash).toBeNull();
  });

  it("refuses a genesis whose admin set contains a non-participant", () => {
    const [a, b, outsider] = [makeSigner(), makeSigner(), makeSigner()];
    const g = { ...genesis(a, b), adminSet: [outsider.agentId] };
    const r = deriveDocumentState(g, [], documentGovernancePolicy, makeVerify([a, b]));
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toMatch(/arrangement_admin_not_participant/);
  });

  it("a claim the policy refuses is void with the policy's own sentence — a rogue signer set admits nobody", () => {
    const [a, b, c, rogue] = [makeSigner(), makeSigner(), makeSigner(), makeSigner()];
    const g = genesis(a, b, [a]);
    // Signed and complete — but the claimed required set is the rogue, not a current admin.
    const env = entry({ subject_agent_id: c.agentId, author_agent_id: rogue.agentId }, [rogue]);
    const s = deriveOk(g, [env], [a, b, c, rogue]);
    expect(s.participants.has(c.agentId)).toBe(false);
    expect(s.voids[0]!.reason).toMatch(/governance_not_admin/);
  });

  it("removing a non-holder is void by name", () => {
    const [a, b] = [makeSigner(), makeSigner()];
    const env = entry({ kind: "remove_holder", subject_agent_id: "9".repeat(64) }, [a]);
    const s = deriveOk(genesis(a, b), [env], [a, b]);
    expect(s.voids[0]!.reason).toMatch(/amendment_subject_not_holder/);
  });

  it("a property outside the amendable set is void by name", () => {
    const [a, b] = [makeSigner(), makeSigner()];
    const env = entry(
      {
        kind: "change_property",
        subject_agent_id: null,
        property_change: { key: "assurance_tier", value: "attested" },
      },
      [a],
    );
    const s = deriveOk(genesis(a, b), [env], [a, b]);
    expect(s.voids[0]!.reason).toMatch(/amendment_property_not_amendable/);
    expect(s.properties["assurance_tier"]).toBe("authenticated");
  });

  it("a canonical state hash on an authenticated-tier document is void — only Tier 2 defines the slot", () => {
    const [a, b, c] = [makeSigner(), makeSigner(), makeSigner()];
    const env = entry(
      { subject_agent_id: c.agentId, state_hash: new Uint8Array(32) },
      [a],
    );
    const s = deriveOk(genesis(a, b), [env], [a, b, c]);
    expect(s.participants.has(c.agentId)).toBe(false);
    expect(s.voids[0]!.reason).toMatch(/amendment_state_hash_tier/);
  });
});

describe("checkEntryAdmissible — the state-independent door", () => {
  it("admits a properly-bound, fully-signed entry", () => {
    const [a, b] = [makeSigner(), makeSigner()];
    void b;
    const env = entry({ subject_agent_id: "c".repeat(64) }, [a]);
    expect(checkEntryAdmissible(env, makeVerify([a]))).toEqual({ ok: true });
  });

  it("refuses an author outside the required set, an unbound collection, and a failed signature — each by name", () => {
    const [a, b] = [makeSigner(), makeSigner()];
    const impostor = entry({ subject_agent_id: "c".repeat(64), author_agent_id: b.agentId }, [a]);
    const r1 = checkEntryAdmissible(impostor, makeVerify([a, b]));
    expect(r1.ok).toBe(false);
    if (!r1.ok) expect(r1.reason).toMatch(/entry_author_not_required/);

    const unsigned = entry({ subject_agent_id: "c".repeat(64) }, [a]);
    unsigned.collection.signatures = [];
    const r2 = checkEntryAdmissible(unsigned, makeVerify([a]));
    expect(r2.ok).toBe(false);
    if (!r2.ok) expect(r2.reason).toMatch(/amendment_collection_incomplete/);

    const rebound = entry({ subject_agent_id: "c".repeat(64) }, [a]);
    rebound.collection.subject_hash = new Uint8Array(32);
    const r3 = checkEntryAdmissible(rebound, makeVerify([a]));
    expect(r3.ok).toBe(false);
    if (!r3.ok) expect(r3.reason).toMatch(/amendment_collection_subject_mismatch/);
  });

  it("does NOT rule on semantics — an add of an existing holder passes the door (the fold voids it)", () => {
    const [a, b] = [makeSigner(), makeSigner()];
    const dup = entry({ subject_agent_id: b.agentId }, [a]);
    expect(checkEntryAdmissible(dup, makeVerify([a]))).toEqual({ ok: true });
  });
});

describe("deriveDocumentState — authoring seeds", () => {
  it("exposes frontier, per-author seqs, and the interim carrier fields", () => {
    const [a, b, c] = [makeSigner(), makeSigner(), makeSigner()];
    const g = genesis(a, b, [a, b]);
    const e1 = entry({ subject_agent_id: c.agentId }, [a]);
    const e2 = entry(
      {
        kind: "change_property",
        subject_agent_id: null,
        property_change: { key: "append_only", value: true },
        epoch_id: 2,
        parents: [hashHex(e1)],
      },
      [b],
    );
    const s = deriveOk(g, [e1, e2], [a, b, c]);
    expect(s.frontier).toEqual([hashHex(e2)]);
    expect(s.authorSeqs.get(a.agentId)).toBe(1);
    expect(s.authorSeqs.get(b.agentId)).toBe(1);
    expect(s.interimMaxEpoch).toBe(2);
  });
});
