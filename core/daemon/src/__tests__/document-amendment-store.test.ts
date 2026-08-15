/**
 * SYNC-P1 (daemon half) — the fork-tolerant entry store.
 *
 * Entries are stored as RECEIVED BYTES (TRACE-1 Entry 1(d): any frame whose hash or signature
 * matters is never persisted re-encoded), keyed by ENTRY HASH — never by an epoch slot. Two
 * concurrent entries claiming the same epoch or the same author seq are BOTH stored; ruling on
 * conflicts is the causal fold's job (deriveDocumentState), not the store's. The store owns:
 *
 * - **Ancestry closure** — an entry lands in `entries` only when every parent has landed. An
 *   entry with a missing parent is HELD (R14): recorded in the pending table, never applied,
 *   never counted in a watermark, promoted the moment its ancestry completes — cascade included.
 * - **Idempotent redelivery** — same bytes again is `recorded: false`, one row.
 * - **Watermarks** — per author: the highest CONTIGUOUS seq held, with the head hash(es) at that
 *   seq. Two heads at one seq is an equivocation made VISIBLE, not an error here.
 *
 * What the store does NOT judge: signatures, policy, subject semantics. The fold rules on those
 * at every consumption, and the inbound path rules BEFORE appending.
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

function entryOf(over: Partial<DocumentAmendmentBody> = {}): DocumentAmendmentEnvelope {
  const body: DocumentAmendmentBody = {
    document_id: DOC,
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

function hashHex(env: DocumentAmendmentEnvelope): string {
  return Buffer.from(documentAmendmentHash(env.body)).toString("hex");
}

/** A linear causal chain by the fixture admin: each entry parents the previous one. */
function causalChain(...overs: Partial<DocumentAmendmentBody>[]): DocumentAmendmentEnvelope[] {
  let prev: string[] = [];
  return overs.map((over, i) => {
    const env = entryOf({ author_seq: i + 1, parents: prev, ...over });
    prev = [hashHex(env)];
    return env;
  });
}

describe("DocumentAmendmentStore — the fork-tolerant entry store", () => {
  let store: DocumentAmendmentStore;
  let db: DatabaseSync;

  beforeEach(() => {
    db = new DatabaseSync(":memory:");
    store = new DocumentAmendmentStore(db as never, silent);
  });

  it("DDL is idempotent — constructing twice over one database is fine", () => {
    expect(() => new DocumentAmendmentStore(db as never, silent)).not.toThrow();
  });

  it("opens a database populated BEFORE the pivot without touching its rows", () => {
    // The pre-P1 table (epoch-keyed) may hold old-shape bytes. Constructing the new store over
    // it must neither crash nor mistake those rows for entries.
    const legacy = new DatabaseSync(":memory:");
    legacy.exec(`
      CREATE TABLE IF NOT EXISTS document_amendments (
        owner_agent_id TEXT NOT NULL, document_id TEXT NOT NULL, epoch_id INTEGER NOT NULL,
        amendment_hash TEXT NOT NULL, received_bytes BLOB NOT NULL, recorded_at INTEGER NOT NULL,
        PRIMARY KEY (owner_agent_id, document_id, epoch_id)
      );
    `);
    legacy
      .prepare(
        `INSERT INTO document_amendments VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .run(OWNER, DOC, 1, "ab".repeat(32), Buffer.from([1, 2, 3]), 500);
    const s2 = new DocumentAmendmentStore(legacy as never, silent);
    expect(s2.chain(OWNER, DOC)).toHaveLength(0);
    const still = legacy
      .prepare(`SELECT COUNT(*) AS n FROM document_amendments`)
      .get() as { n: number };
    expect(still.n).toBe(1);
  });

  it("append → chain round-trips the RECEIVED bytes", () => {
    const [one, two] = causalChain({}, { kind: "promote_admin", subject_agent_id: "c".repeat(64) });
    const r1 = store.append(OWNER, DOC, encodeDocumentAmendment(one!), 1000);
    const r2 = store.append(OWNER, DOC, encodeDocumentAmendment(two!), 2000);
    expect(r1.recorded).toBe(true);
    expect(r1.held).toBe(false);
    expect(r2.entryHash).toBe(hashHex(two!));
    const chain = store.chain(OWNER, DOC);
    expect(chain).toHaveLength(2);
    expect(chain).toContainEqual(one);
    expect(chain).toContainEqual(two);
  });

  it("copies the input bytes — mutating the caller's buffer after append changes nothing", () => {
    const [one] = causalChain({});
    const bytes = encodeDocumentAmendment(one!);
    store.append(OWNER, DOC, bytes, 1000);
    bytes.fill(0);
    expect(store.chain(OWNER, DOC)[0]).toEqual(one);
  });

  it("a REDELIVERED entry (same hash) is idempotent — recorded: false, one row", () => {
    const [one] = causalChain({});
    const bytes = encodeDocumentAmendment(one!);
    expect(store.append(OWNER, DOC, bytes, 1000).recorded).toBe(true);
    expect(store.append(OWNER, DOC, bytes, 2000).recorded).toBe(false);
    expect(store.chain(OWNER, DOC)).toHaveLength(1);
  });

  it("CONCURRENT entries claiming the same epoch and seq are BOTH stored — conflict is the fold's ruling, not the store's", () => {
    const one = entryOf({ subject_agent_id: "c".repeat(64) });
    const rival = entryOf({ subject_agent_id: "f".repeat(64) }); // also epoch 1, seq 1, parents []
    expect(store.append(OWNER, DOC, encodeDocumentAmendment(one), 1000).recorded).toBe(true);
    expect(store.append(OWNER, DOC, encodeDocumentAmendment(rival), 2000).recorded).toBe(true);
    expect(store.chain(OWNER, DOC)).toHaveLength(2);
  });

  it("an entry with a MISSING parent is HELD — recorded in pending, absent from the chain (R14)", () => {
    const [one, two] = causalChain({}, { kind: "promote_admin", subject_agent_id: "c".repeat(64) });
    const r = store.append(OWNER, DOC, encodeDocumentAmendment(two!), 1000);
    expect(r.held).toBe(true);
    expect(r.recorded).toBe(true);
    expect(store.chain(OWNER, DOC)).toHaveLength(0);
    const pending = store.pending(OWNER, DOC);
    expect(pending).toHaveLength(1);
    expect(pending[0]!.entryHash).toBe(hashHex(two!));
    expect(pending[0]!.missingParents).toEqual([hashHex(one!)]);
  });

  it("a held entry PROMOTES the moment its ancestry completes — cascade included", () => {
    const [one, two, three] = causalChain(
      {},
      { kind: "promote_admin", subject_agent_id: "c".repeat(64) },
      { kind: "change_property", subject_agent_id: null, property_change: { key: "append_only", value: true } },
    );
    // Arrive backwards: three, two, then one. Nothing applies until one lands, then all three do.
    expect(store.append(OWNER, DOC, encodeDocumentAmendment(three!), 1).held).toBe(true);
    expect(store.append(OWNER, DOC, encodeDocumentAmendment(two!), 2).held).toBe(true);
    expect(store.chain(OWNER, DOC)).toHaveLength(0);
    const r = store.append(OWNER, DOC, encodeDocumentAmendment(one!), 3);
    expect(r.held).toBe(false);
    expect(r.promoted.map((e) => e.entryHash).sort()).toEqual(
      [hashHex(two!), hashHex(three!)].sort(),
    );
    // The envelopes ride along, so the layer can surface what a promotion applied.
    expect(r.promoted.map((e) => e.envelope.body.kind).sort()).toEqual(
      ["change_property", "promote_admin"].sort(),
    );
    expect(store.chain(OWNER, DOC)).toHaveLength(3);
    expect(store.pending(OWNER, DOC)).toHaveLength(0);
  });

  it("a redelivered HELD entry is idempotent too", () => {
    const [, two] = causalChain({}, { kind: "promote_admin", subject_agent_id: "c".repeat(64) });
    const bytes = encodeDocumentAmendment(two!);
    expect(store.append(OWNER, DOC, bytes, 1).recorded).toBe(true);
    expect(store.append(OWNER, DOC, bytes, 2).recorded).toBe(false);
    expect(store.pending(OWNER, DOC)).toHaveLength(1);
  });

  it("malformed bytes are refused with the decoder's NAMED reason, and nothing is stored", () => {
    expect(() => store.append(OWNER, DOC, new Uint8Array([1, 2, 3]), 1000)).toThrow();
    expect(store.chain(OWNER, DOC)).toHaveLength(0);
    expect(store.pending(OWNER, DOC)).toHaveLength(0);
  });

  it("bytes naming a different document are refused by name", () => {
    const stray = entryOf({ document_id: "e".repeat(64) });
    expect(() => store.append(OWNER, DOC, encodeDocumentAmendment(stray), 1000)).toThrow(
      /document_amendment_wrong_document/,
    );
  });

  it("keys on (owner, document) — two owners and two documents never see each other's entries", () => {
    const [one] = causalChain({});
    store.append(OWNER, DOC, encodeDocumentAmendment(one!), 1000);
    expect(store.chain("other-owner", DOC)).toHaveLength(0);
    expect(store.chain(OWNER, "e".repeat(64))).toHaveLength(0);
    expect(store.chain("other-owner", DOC)).toHaveLength(0);
  });

  it("watermarks: highest CONTIGUOUS seq per author with head hashes; a held gap is not counted", () => {
    const [one, two, three] = causalChain(
      {},
      { kind: "promote_admin", subject_agent_id: "c".repeat(64) },
      { kind: "change_property", subject_agent_id: null, property_change: { key: "append_only", value: true } },
    );
    store.append(OWNER, DOC, encodeDocumentAmendment(one!), 1);
    store.append(OWNER, DOC, encodeDocumentAmendment(three!), 2); // held: two is missing
    let marks = store.watermarks(OWNER, DOC);
    expect(marks.get(admin.agentId)).toEqual({ seq: 1, headHashes: [hashHex(one!)] });
    store.append(OWNER, DOC, encodeDocumentAmendment(two!), 3);
    marks = store.watermarks(OWNER, DOC);
    expect(marks.get(admin.agentId)).toEqual({ seq: 3, headHashes: [hashHex(three!)] });
  });

  it("watermarks make an EQUIVOCATION visible — two heads at one seq, never a silent pick", () => {
    const forkA = entryOf({ subject_agent_id: "c".repeat(64) });
    const forkB = entryOf({ subject_agent_id: "f".repeat(64) });
    store.append(OWNER, DOC, encodeDocumentAmendment(forkA), 1);
    store.append(OWNER, DOC, encodeDocumentAmendment(forkB), 2);
    const marks = store.watermarks(OWNER, DOC);
    expect(marks.get(admin.agentId)!.seq).toBe(1);
    expect(marks.get(admin.agentId)!.headHashes.sort()).toEqual(
      [hashHex(forkA), hashHex(forkB)].sort(),
    );
  });


  it("the chain length tracks appended entries — the epoch spine is gone (D7)", () => {
    expect(store.chain(OWNER, DOC)).toHaveLength(0);
    const [one, two] = causalChain({}, { kind: "promote_admin", subject_agent_id: "c".repeat(64) });
    store.append(OWNER, DOC, encodeDocumentAmendment(one!), 1000);
    store.append(OWNER, DOC, encodeDocumentAmendment(two!), 2000);
    expect(store.chain(OWNER, DOC)).toHaveLength(2);
  });
});
