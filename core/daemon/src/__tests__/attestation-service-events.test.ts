/**
 * M10E 005-SVCCLIENT — the client marks a service event during an open session, and lists the
 * rights it holds. Real keys, a fake signaling object (as in 003's tests), and a REAL SQLCipher
 * database for the store/upgrade paths (never node:sqlite).
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";
import { generateKeypair, verify, type InMemoryKeyProvider } from "@cello-protocol/crypto";
import {
  attestationTemplateHash,
  decodeServiceEvent,
  encodeAttestationRight,
  hashAttestationRight,
  hashServiceEvent,
  type AttestationRight,
  type SessionAssignmentFrost,
} from "@cello-protocol/protocol-types";
import { openEncryptedDatabase, type DaemonDatabase } from "../sqlcipher-db.js";
import { ensureSessionSchema } from "../session-schema.js";
import { createNamespace, type NamespaceDeps } from "../attestation-namespaces.js";
import { markServiceEvent, listRights, type ServiceEventDeps } from "../attestation-service-events.js";
import {
  encodeSessionProof, persistSessionProof, sessionProofFromAssignment, type SessionProof, type ProofStoreDb,
} from "../attestation-session-proof.js";
import type { Logger } from "../types.js";

const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

const GOLDEN_PROOF_HEX =
  "8f7043454c4c4f2d415350524f4f462d763150010101010101010101010101010101015820020202020202020202020202020202020202020202020202020202020202020258200303030303030303030303030303030303030303030303030303030303030303fb427a3185c5000000616181622f78616281622f796572656c6179f560617258200404040404040404040404040404040404040404040404040404040404040404584005050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505";

interface FakeSignaling {
  sent: Array<Record<string, unknown>>;
  push: (reply: Record<string, unknown>) => void;
  sendRaw: (frame: unknown) => Promise<{ ok: boolean; reason?: string }>;
  registerInboundHandler: (h: (f: Record<string, unknown>) => void) => () => void;
}
function makeSignaling(): FakeSignaling {
  const sent: Array<Record<string, unknown>> = [];
  const handlers = new Set<(f: Record<string, unknown>) => void>();
  return {
    sent,
    push: (reply) => { for (const h of [...handlers]) h(reply); },
    sendRaw: async (frame) => { sent.push(frame as Record<string, unknown>); return { ok: true }; },
    registerInboundHandler: (h) => { handlers.add(h); return () => handlers.delete(h); },
  };
}
async function waitForSent(sig: FakeSignaling, n: number): Promise<void> {
  for (let i = 0; i < 500 && sig.sent.length < n; i++) await new Promise((r) => setTimeout(r, 2));
}

interface SpyLogger extends Logger { events: Array<{ level: string; event: string; ctx: Record<string, unknown> }>; }
function makeLogger(): SpyLogger {
  const events: SpyLogger["events"] = [];
  return {
    events,
    debug: (event, ctx) => events.push({ level: "debug", event, ctx: ctx ?? {} }),
    info: (event, ctx) => events.push({ level: "info", event, ctx: ctx ?? {} }),
    warn: (event, ctx) => events.push({ level: "warn", event, ctx: ctx ?? {} }),
    error: (event, ctx) => events.push({ level: "error", event, ctx: ctx ?? {} }),
  };
}

const NOW_MS = 1_800_000_000_000;

let sig: FakeSignaling;
let logger: SpyLogger;
let me: InMemoryKeyProvider;
let them: InMemoryKeyProvider;
let mePub: string;
let themPub: string;

beforeEach(async () => {
  sig = makeSignaling();
  logger = makeLogger();
  me = generateKeypair();
  them = generateKeypair();
  mePub = hex(await me.getPublicKey());
  themPub = hex(await them.getPublicKey());
});

const SID = "cd".repeat(16);

/** A stored proof naming `a` and `b` as the two participants (client does not verify the sig). */
function storedProof(aPub: string, bPub: string, sessionIdHex = SID): Uint8Array {
  const p: SessionProof = {
    session_id: new Uint8Array(Buffer.from(sessionIdHex, "hex")),
    pub_a: new Uint8Array(Buffer.from(aPub, "hex")),
    pub_b: new Uint8Array(Buffer.from(bPub, "hex")),
    session_timestamp: NOW_MS,
    initiator_session_peer_id: "12D3KooWinit", initiator_session_addrs: ["/ip4/1.2.3.4/tcp/1"],
    counterparty_session_peer_id: "12D3KooWcp", counterparty_session_addrs: ["/ip4/5.6.7.8/tcp/2"],
    transport_mode: "direct", high_stakes: false, prior_relay_id: "", relay_id: "",
    signer_pubkey: new Uint8Array(32).fill(9), directory_signature: new Uint8Array(64).fill(8),
  };
  return encodeSessionProof(p);
}

function svcDeps(over: Partial<ServiceEventDeps> = {}): ServiceEventDeps {
  return {
    signaling: sig, keyProvider: me, ownerPubkeyHex: mePub, now: () => NOW_MS, logger,
    loadSessionProof: () => storedProof(mePub, themPub),
    chainHeadHash: () => new Uint8Array(32),
    timeoutMs: 120,
    ...over,
  };
}

// The `expired` flag the client surfaces comes from the directory's reply, not from the record, so
// both rights carry a valid in-range TTL (604800..15552000s); only the reply's flag differs.
function rightRecord(ttlSeconds: number, createdAt = 1_800_000_000): AttestationRight {
  return {
    service_event_hash: new Uint8Array(32).fill(1), holder_pubkey: mePub, subject_pubkey: themPub,
    namespace: "reviews.alpha", template_hash: attestationTemplateHash("scored"),
    session_id: new Uint8Array(Buffer.from(SID, "hex")), created_at: createdAt,
    expires_at: createdAt + ttlSeconds, kind: "service_event",
  };
}

describe("005-SVCCLIENT — proof encoder", () => {
  it("K1. the fixed proof encodes to the directory's golden hex, byte for byte", () => {
    const fixed: SessionProof = {
      session_id: new Uint8Array(16).fill(1), pub_a: new Uint8Array(32).fill(2), pub_b: new Uint8Array(32).fill(3),
      session_timestamp: 1_800_000_000_000, initiator_session_peer_id: "a", initiator_session_addrs: ["/x"],
      counterparty_session_peer_id: "b", counterparty_session_addrs: ["/y"], transport_mode: "relay",
      high_stakes: true, prior_relay_id: "", relay_id: "r", signer_pubkey: new Uint8Array(32).fill(4),
      directory_signature: new Uint8Array(64).fill(5),
    };
    expect(hex(encodeSessionProof(fixed))).toBe(GOLDEN_PROOF_HEX);
  });
});

function assignment(): SessionAssignmentFrost {
  return {
    signature_type: "frost",
    session_id: new Uint8Array(Buffer.from(SID, "hex")),
    participant_a: { pubkey: new Uint8Array(Buffer.from(mePub, "hex")), peer_id: "12D3KooWinit", multiaddrs: ["/ip4/1.2.3.4/tcp/1"] },
    participant_b: { pubkey: new Uint8Array(Buffer.from(themPub, "hex")), peer_id: "12D3KooWcp", multiaddrs: ["/ip4/5.6.7.8/tcp/2"] },
    relay_endpoint: { peer_id: "r", multiaddrs: [] },
    directory_endpoint: { peer_id: "d", multiaddrs: [] },
    session_timestamp: NOW_MS,
    directory_pubkey: new Uint8Array(32).fill(7),
    directory_signature: new Uint8Array(64).fill(8),
    initiator_session_peer_id: "12D3KooWinit", initiator_session_addrs: ["/ip4/1.2.3.4/tcp/1"],
    counterparty_session_peer_id: "12D3KooWcp", counterparty_session_addrs: ["/ip4/5.6.7.8/tcp/2"],
    transport_mode: "direct", high_stakes: false, prior_relay_id: "", relay_id: "",
    signer_pubkey: new Uint8Array(32).fill(9),
  };
}

describe("005-SVCCLIENT — keeping the proof", () => {
  let dir: string;
  let db: DaemonDatabase;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "svc-proof-"));
    db = openEncryptedDatabase(join(dir, "s.db"), randomBytes(32));
    ensureSessionSchema(db, logger, () => {});
  });
  afterEach(async () => { db.close(); await rm(dir, { recursive: true, force: true }); });

  it("K2. a verified assignment stores its proof; a failed verification stores nothing", () => {
    persistSessionProof(db, "agent-1", SID, assignment(), { ok: true }, () => NOW_MS, logger, "corr-ok");
    const row = db.prepare("SELECT proof FROM session_proofs WHERE agent_id = ? AND session_id = ?").get("agent-1", SID) as { proof: Buffer } | undefined;
    expect(row).toBeDefined();
    expect(hex(new Uint8Array(row!.proof))).toBe(hex(encodeSessionProof(sessionProofFromAssignment(assignment()))));

    const other = "ab".repeat(16);
    persistSessionProof(db, "agent-1", other, assignment(), { ok: false }, () => NOW_MS, logger, "corr-bad");
    const none = db.prepare("SELECT proof FROM session_proofs WHERE agent_id = ? AND session_id = ?").get("agent-1", other) as unknown;
    expect(none).toBeUndefined();
  });

  it("K9. a database with the main schema (no session_proofs), with a sessions row, gains session_proofs and keeps its row", () => {
    // Simulate a database from before this change: drop the table this order adds, then write a
    // sessions row the way the live daemon would.
    db.exec("DROP TABLE session_proofs");
    db.prepare("INSERT INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)")
      .run(SID, "agent-1", themPub, "open", NOW_MS, NOW_MS);
    // Re-run the schema (what the next daemon start does).
    ensureSessionSchema(db, logger, () => {});
    const kept = db.prepare("SELECT counterparty_pubkey FROM sessions WHERE agent_id = ? AND session_id = ?").get("agent-1", SID) as { counterparty_pubkey: string } | undefined;
    expect(kept?.counterparty_pubkey).toBe(themPub);
    // The new table exists and is writable.
    persistSessionProof(db, "agent-1", SID, assignment(), { ok: true }, () => NOW_MS, logger, "corr");
    const row = db.prepare("SELECT 1 AS one FROM session_proofs WHERE agent_id = ? AND session_id = ?").get("agent-1", SID) as { one: number } | undefined;
    expect(row?.one).toBe(1);
  });

  it("K10. a proof-store write that throws is logged at error and does not throw", () => {
    const throwingDb: ProofStoreDb = { prepare: () => { throw new Error("disk full"); } };
    expect(() => persistSessionProof(throwingDb, "agent-1", SID, assignment(), { ok: true }, () => NOW_MS, logger, "corr")).not.toThrow();
    const err = logger.events.find((e) => e.event === "attestation.session_proof.store_failed");
    expect(err?.level).toBe("error");
    expect(String(err?.ctx.reason)).toContain("disk full");
  });
});

describe("005-SVCCLIENT — marking a service event", () => {
  it("K3. a mark sends a frame whose event decodes, is signed by us, names the counterparty, and carries the proof unchanged", async () => {
    const proof = storedProof(mePub, themPub);
    const p = markServiceEvent(svcDeps({ loadSessionProof: () => proof }), { session_id: SID, namespace: "reviews.alpha" });
    await waitForSent(sig, 1);
    const frame = sig.sent[0]!;
    expect(frame["type"]).toBe("attestation_service_event_mark");
    const ev = decodeServiceEvent(frame["event"] as Uint8Array);
    expect(ev.subject_pubkey).toBe(mePub);
    expect(ev.counterparty_pubkey).toBe(themPub);
    expect(ev.namespace).toBe("reviews.alpha");
    expect(verify(Buffer.from(mePub, "hex"), hashServiceEvent(ev), frame["signature"] as Uint8Array)).toBe(true);
    expect(hex(frame["session_proof"] as Uint8Array)).toBe(hex(proof));
    sig.push({ type: "attestation_service_event_result", session_id: SID, namespace: "reviews.alpha", status: "stored" });
    expect(await p).toEqual({ ok: true, status: "stored" });
  });

  it("K4. an attestation_service_event_result reply resolves stored", async () => {
    const p = markServiceEvent(svcDeps(), { session_id: SID, namespace: "reviews.alpha" });
    await waitForSent(sig, 1);
    sig.push({ type: "attestation_service_event_result", session_id: SID, namespace: "reviews.alpha", status: "stored" });
    expect(await p).toEqual({ ok: true, status: "stored" });
  });

  it("K5. a session with no stored proof → no_session_proof, nothing sent", async () => {
    const res = await markServiceEvent(svcDeps({ loadSessionProof: () => null }), { session_id: SID, namespace: "reviews.alpha" });
    expect(res).toMatchObject({ ok: false, reason: "no_session_proof" });
    expect(sig.sent).toHaveLength(0);
  });

  it("K6. a session_sealed reply → refusal with that reason and guidance saying 'before it is sealed'", async () => {
    const p = markServiceEvent(svcDeps(), { session_id: SID, namespace: "reviews.alpha" });
    await waitForSent(sig, 1);
    sig.push({ type: "attestation_namespace_error", reason: "session_sealed" });
    const res = await p;
    expect(res).toMatchObject({ ok: false, reason: "session_sealed" });
    expect((res as { guidance: string }).guidance).toContain("before it is sealed");
  });

  it("K7. a mark and a namespace create started together are sent one after the other, never overlapping", async () => {
    const nsDeps: NamespaceDeps = { signaling: sig, keyProvider: me, ownerPubkeyHex: mePub, now: () => NOW_MS, logger, timeoutMs: 120 };
    const createP = createNamespace(nsDeps, { namespace: "reviews.beta", mode: "public", scored: true, right_ttl_days: 30, condition: "granted when a booking is confirmed" });
    const markP = markServiceEvent(svcDeps(), { session_id: SID, namespace: "reviews.alpha" });
    // The create holds the shared chain: only its frame is on the wire until it resolves.
    await waitForSent(sig, 1);
    expect(sig.sent).toHaveLength(1);
    expect(sig.sent[0]!["type"]).toBe("attestation_namespace_put");
    sig.push({ type: "attestation_namespace_result", owner_pubkey: mePub, namespace: "reviews.beta", status: "stored" });
    await createP;
    await waitForSent(sig, 2);
    expect(sig.sent[1]!["type"]).toBe("attestation_service_event_mark");
    sig.push({ type: "attestation_service_event_result", session_id: SID, namespace: "reviews.alpha", status: "stored" });
    await markP;
  });
});

describe("005-SVCCLIENT — listing rights", () => {
  it("K8. a rights reply with one live and one expired right → both listed, expired false then true", async () => {
    const live = rightRecord(2_592_000);
    const dead = rightRecord(604_800, 1_800_000_000 - 8 * 86_400);
    const p = listRights(svcDeps());
    await waitForSent(sig, 1);
    expect(sig.sent[0]!["type"]).toBe("attestation_rights_list");
    sig.push({
      type: "attestation_rights",
      entries: [
        { right: encodeAttestationRight(live), right_id: hex(hashAttestationRight(live)), expired: false },
        { right: encodeAttestationRight(dead), right_id: hex(hashAttestationRight(dead)), expired: true },
      ],
      next: null,
    });
    const res = await p;
    if (!res.ok) throw new Error(JSON.stringify(res));
    expect(res.rights).toHaveLength(2);
    expect(res.rights[0]!.expired).toBe(false);
    expect(res.rights[1]!.expired).toBe(true);
    expect(res.rights[0]!.subject_pubkey).toBe(themPub);
    expect(res.rights[0]!.template).toBe("scored");
  });

  it("an entry whose right_id does not match the recomputed hash is kept, re-id'd, and logged", async () => {
    const r = rightRecord(2_592_000);
    const p = listRights(svcDeps());
    await waitForSent(sig, 1);
    sig.push({ type: "attestation_rights", entries: [{ right: encodeAttestationRight(r), right_id: "deadbeef", expired: false }], next: null });
    const res = await p;
    if (!res.ok) throw new Error(JSON.stringify(res));
    expect(res.rights).toHaveLength(1);
    expect(res.rights[0]!.right_id).toBe(hex(hashAttestationRight(r)));
    expect(logger.events.find((e) => e.event === "attestation.rights.id_mismatch")?.level).toBe("warn");
  });

  it("K8b. expiry is judged by our clock, never the directory's flag", async () => {
    // A dishonest node flags the live right expired, and the expired one live. Neither sticks.
    const live = rightRecord(2_592_000);
    const dead = rightRecord(604_800, 1_800_000_000 - 8 * 86_400);
    const p = listRights(svcDeps());
    await waitForSent(sig, 1);
    sig.push({
      type: "attestation_rights",
      entries: [
        { right: encodeAttestationRight(live), right_id: hex(hashAttestationRight(live)), expired: true },
        { right: encodeAttestationRight(dead), right_id: hex(hashAttestationRight(dead)), expired: false },
      ],
      next: null,
    });
    const res = await p;
    if (!res.ok) throw new Error(JSON.stringify(res));
    expect(res.rights.map((r) => r.expired)).toEqual([false, true]);
  });

  it("an undecodable entry is logged, never dropped silently", async () => {
    const p = listRights(svcDeps());
    await waitForSent(sig, 1);
    sig.push({ type: "attestation_rights", entries: [{ right: new Uint8Array([1, 2, 3]), right_id: "ab", expired: false }], next: null });
    const res = await p;
    if (!res.ok) throw new Error(JSON.stringify(res));
    expect(res.rights).toHaveLength(0);
    expect(logger.events.find((e) => e.event === "attestation.rights.undecodable")?.level).toBe("warn");
  });
});
