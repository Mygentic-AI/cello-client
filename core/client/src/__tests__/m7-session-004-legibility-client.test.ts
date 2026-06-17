/**
 * CELLO-M7-SESSION-004 — Client-side seal certificate legibility (parse, verify, persist)
 *
 * TDD Phase R. Covers the cello-client half of the story:
 *   AC-005  the legibility object is persisted in client SQLite (idempotent inline
 *           ALTER TABLE — NOT Flyway), survives a store close/reopen ("restart"), is
 *           returned intact on read, and the client re-derives each party's
 *           content_frontier_seq from its own local state and confirms it equals the
 *           published value.
 *   AC-009  the client rejection code `certificate_frontier_unverifiable` is a distinct
 *           string that never collides with the directory seal-rejection codes; a
 *           malformed certificate is rejected (null), never silently accepted.
 *   SI-002  the client guard rejects a certificate whose published frontier EXCEEDS the
 *           maximum the client can independently re-derive for an included party.
 *
 * ─── S (Specification) ──────────────────────────────────────────────────────
 * The directory builds the legibility certificate and pushes it on the SessionSealed
 * frame. The client persists it alongside the sealed record, exposes it intact on read,
 * and independently re-derives the content frontiers — rejecting (rather than rendering)
 * any certificate whose published frontier exceeds what the client signed/observed.
 *
 * Crypto/encoding refs: Ed25519 RFC 8032, CBOR canonical RFC 8949 §4.2.1.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { rmSync, mkdirSync } from "node:fs";
import { Encoder, decode as cborDecode } from "cbor-x";
import { SEAL_RECEIPT_DISCLAIMER, type SealLegibility } from "@cello-protocol/protocol-types";
import {
  parseLegibility,
  findUnverifiableFrontier,
  CERTIFICATE_FRONTIER_UNVERIFIABLE,
} from "../seal-legibility-client.js";
import { deriveDbKey } from "../db-key-derivation.js";
import { loadClientStartupState, type StartupContext } from "../client-startup.js";
import type { SessionRecord } from "../types.js";

const ENC = new Encoder({ tagUint8Array: false });

// ─── Dynamic import for SQLCipher (skips cleanly where the native module is absent) ──

let sqlCipherAvailable = false;
let SQLCipherClientStore: typeof import("../sqlcipher-client-store.js").SQLCipherClientStore;
let ClientStatePersistence: typeof import("../client-state-persistence.js").ClientStatePersistence;

try {
  const storeMod = await import("../sqlcipher-client-store.js");
  SQLCipherClientStore = storeMod.SQLCipherClientStore;
  const persistMod = await import("../client-state-persistence.js");
  ClientStatePersistence = persistMod.ClientStatePersistence;
  sqlCipherAvailable = true;
} catch {
  sqlCipherAvailable = false;
}

const describeWithSQLCipher = sqlCipherAvailable ? describe : describe.skip;

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeSpyLogger() {
  const events: Array<{ level: string; event: string; context: Record<string, unknown> }> = [];
  const mk = (level: string) => (event: string, context: Record<string, unknown> = {}) =>
    events.push({ level, event, context });
  return { debug: mk("debug"), info: mk("info"), warn: mk("warn"), error: mk("error"), events };
}

function makeTmpDbPath(): string {
  const dir = join(tmpdir(), `cello-session-004-${randomBytes(8).toString("hex")}`);
  mkdirSync(dir, { recursive: true });
  return join(dir, "test.db");
}

function cleanupPath(dbPath: string): void {
  try { rmSync(join(dbPath, ".."), { recursive: true, force: true }); } catch { /* ignore */ }
}

/** A well-formed legibility certificate for two parties A (frontier 6) and B (frontier 4). */
function makeLegibility(aPubkey: Uint8Array, bPubkey: Uint8Array): SealLegibility {
  return {
    attests: "receipt",
    implies_assent: false,
    disclaimer: SEAL_RECEIPT_DISCLAIMER,
    participants: [
      { pubkey: aPubkey, content_frontier_seq: 6, last_authored_seq: 7, attestation_mode: "live" },
      { pubkey: bPubkey, content_frontier_seq: 4, last_authored_seq: 8, attestation_mode: "live" },
    ],
    final_message: { sender_pubkey: aPubkey, seq: 7, answered: false },
  };
}

/**
 * Build a minimal StartupContext that drives the REAL `loadClientStartupState`
 * reconstruction path and captures the SessionRecords it rebuilds via `setSession`.
 * Every method the session-loading section (§6) does not touch is a no-op; this test
 * persists only a session + agent row, so the FROST/ML-DSA/registration branches are skipped.
 */
function makeCapturingStartupContext(opts: {
  persistence: InstanceType<typeof ClientStatePersistence>;
  logger: ReturnType<typeof makeSpyLogger>;
}): { ctx: StartupContext; sessions: Map<string, SessionRecord> } {
  const sessions = new Map<string, SessionRecord>();
  const noop = () => {};
  const ctx: StartupContext = {
    node: {} as StartupContext["node"],
    logger: opts.logger,
    persistence: opts.persistence,
    getDirectoryEndpoint: () => null,
    getThresholdSigner: () => undefined,
    setThresholdSigner: noop,
    getMyPubkeyHex: () => null,
    setMyPubkeyHex: noop,
    setRegistrationState: noop,
    setMlDsaProvider: noop,
    addConnection: noop,
    addConnectionByPeer: noop,
    addProfileUncheckedPeer: noop,
    setConnectionPolicy: noop,
    addPeer: noop,
    hasPeer: () => false,
    setEndorsements: noop,
    setAttestations: noop,
    setLoadedPendingHashes: noop,
    getSessionById: (id) => sessions.get(id),
    setSession: (id, record) => { sessions.set(id, record); },
    initSessionMessageQueue: noop,
    getMyPrimaryPubkey: () => null,
    setMyPrimaryPubkey: noop,
    restoreDecidedRequest: noop,
    restorePendingInboundRequest: noop,
    restoreReviewQueueItem: noop,
  };
  return { ctx, sessions };
}

// ─── parseLegibility (pure) ────────────────────────────────────────────────────

describe("M7-SESSION-004 (client): parseLegibility", () => {
  const a = new Uint8Array(32).fill(1);
  const b = new Uint8Array(32).fill(2);

  it("parses a well-formed object and round-trips through canonical CBOR", () => {
    const leg = makeLegibility(a, b);
    const decoded = cborDecode(ENC.encode(leg) as Uint8Array);
    const parsed = parseLegibility(decoded);
    expect(parsed).not.toBeNull();
    expect(parsed!.attests).toBe("receipt");
    expect(parsed!.implies_assent).toBe(false);
    expect(parsed!.disclaimer).toBe(SEAL_RECEIPT_DISCLAIMER);
    expect(parsed!.participants).toHaveLength(2);
    expect(parsed!.participants[0]!.content_frontier_seq).toBe(6);
    expect(parsed!.participants[1]!.content_frontier_seq).toBe(4);
    expect(parsed!.final_message.answered).toBe(false);
  });

  it("rejects a malformed certificate rather than silently accepting it", () => {
    const base = makeLegibility(a, b);
    // attests is not the literal 'receipt'
    expect(parseLegibility({ ...base, attests: "agreement" })).toBeNull();
    // implies_assent is not the literal false (an attempt to read as agreement)
    expect(parseLegibility({ ...base, implies_assent: true })).toBeNull();
    // empty disclaimer
    expect(parseLegibility({ ...base, disclaimer: "" })).toBeNull();
    // participants not an array
    expect(parseLegibility({ ...base, participants: "nope" })).toBeNull();
    // invalid attestation_mode
    expect(parseLegibility({
      ...base,
      participants: [{ pubkey: a, content_frontier_seq: 1, last_authored_seq: 1, attestation_mode: "agreed" }],
    })).toBeNull();
    // missing final_message
    expect(parseLegibility({ ...base, final_message: null })).toBeNull();
    // non-boolean answered
    expect(parseLegibility({
      ...base,
      final_message: { sender_pubkey: a, seq: 1, answered: "false" },
    })).toBeNull();
    // not an object
    expect(parseLegibility(null)).toBeNull();
    expect(parseLegibility(42)).toBeNull();
  });
});

// ─── findUnverifiableFrontier — SI-002 client guard (pure) ──────────────────────

describe("M7-SESSION-004 (client): findUnverifiableFrontier (SI-002 guard)", () => {
  const a = new Uint8Array(32).fill(1);
  const b = new Uint8Array(32).fill(2);
  const aHex = Buffer.from(a).toString("hex");
  const bHex = Buffer.from(b).toString("hex");

  it("returns null when every re-derivable party's published frontier matches the derived maximum", () => {
    const leg = makeLegibility(a, b); // A=6, B=4
    const derived = new Map([[aHex, 6], [bHex, 4]]);
    expect(findUnverifiableFrontier(leg, derived)).toBeNull();
  });

  it("returns null when a published frontier is BELOW the derived maximum (legitimately behind is fine)", () => {
    const leg = makeLegibility(a, b);
    const derived = new Map([[aHex, 10], [bHex, 9]]);
    expect(findUnverifiableFrontier(leg, derived)).toBeNull();
  });

  it("flags the offending party when a published frontier EXCEEDS the derived maximum (inflated claim)", () => {
    const leg = makeLegibility(a, b); // B published 4
    const derived = new Map([[aHex, 6], [bHex, 3]]); // client only re-derives B up to 3
    const bad = findUnverifiableFrontier(leg, derived);
    expect(bad).not.toBeNull();
    expect(bad!.party).toBe(bHex);
    expect(bad!.publishedFrontier).toBe(4);
    expect(bad!.derivedFrontier).toBe(3);
  });

  it("skips parties the client cannot independently re-derive (not in the map)", () => {
    const leg = makeLegibility(a, b);
    // Only A is re-derivable; B (counterparty, client behind) is excluded — must NOT false-positive.
    const derived = new Map([[aHex, 6]]);
    expect(findUnverifiableFrontier(leg, derived)).toBeNull();
  });
});

// ─── AC-009: error-code distinctness ───────────────────────────────────────────

describe("M7-SESSION-004 (client): AC-009 error-code distinctness", () => {
  it("certificate_frontier_unverifiable is distinct from all directory seal-rejection codes", () => {
    const directorySealCodes = [
      "merkle_root_mismatch",
      "leaf_signature_invalid",
      "prev_root_chain_broken",
      "causal_chain_violated",
      "seal_leaves_invalid",
    ];
    expect(CERTIFICATE_FRONTIER_UNVERIFIABLE).toBe("certificate_frontier_unverifiable");
    expect(directorySealCodes).not.toContain(CERTIFICATE_FRONTIER_UNVERIFIABLE);
  });
});

// ─── AC-005: persistence round-trip across a store close/reopen ─────────────────

describeWithSQLCipher("M7-SESSION-004 (client): AC-005 legibility persists and round-trips on restart", () => {
  let dbPath: string;
  let logger: ReturnType<typeof makeSpyLogger>;

  beforeEach(() => {
    dbPath = makeTmpDbPath();
    logger = makeSpyLogger();
  });
  afterEach(() => cleanupPath(dbPath));

  it("legibility blob + counterparty_ack_frontier survive close/reopen; re-derived frontier matches published", async () => {
    const agentPubkey = randomBytes(32).toString("hex");
    const dbKey = deriveDbKey(randomBytes(32), agentPubkey);

    const store = new SQLCipherClientStore(dbKey, { dbPath, agentId: agentPubkey, logger });
    await store.open();
    const persistence = new ClientStatePersistence({
      store, agentPubkey, keyFilePath: "/tmp/test-key", logger,
    });
    await persistence.upsertAgent();

    // This client is party A (own signed frontier = last_seen_seq = 6).
    // The counterparty is party B; the client has observed B's ack frontier up to 4.
    const aPubkey = Buffer.from(agentPubkey, "hex");
    const bPubkey = randomBytes(32);
    const legibility = makeLegibility(aPubkey, bPubkey);

    const sessionIdHex = randomBytes(32).toString("hex");
    const session: import("../types.js").SessionRecord = {
      session_id: Buffer.from(sessionIdHex, "hex"),
      counterparty_pubkey: bPubkey,
      counterparty_peer_id: "peer-b",
      counterparty_multiaddrs: [],
      relay_endpoint: { peer_id: "r1", multiaddrs: [] },
      directory_endpoint: { peer_id: "d1", multiaddrs: [] },
      directory_pubkey: randomBytes(32),
      genesis_prev_root: randomBytes(32),
      last_seen_seq: 6,
      last_sent_seq: 7,
      next_expected_seq: 8,
      status: "sealed",
      desynchronized: false,
      local_tree_leaves: [],
      sealed_root: randomBytes(32),
      seal_type: "frost",
      close_timestamp: Date.now(),
      frost_signature: randomBytes(64),
      signer_pubkey: randomBytes(32),
      counterparty_ack_frontier: 4,
      legibility,
    };

    await persistence.persistSession(sessionIdHex, session);
    await store.close();

    // "Restart" — fresh open re-applies the idempotent inline columns and reloads.
    const store2 = new SQLCipherClientStore(dbKey, { dbPath, agentId: agentPubkey, logger });
    await store2.open();
    const persistence2 = new ClientStatePersistence({
      store: store2, agentPubkey, keyFilePath: "/tmp/test-key", logger,
    });

    const rows = await persistence2.loadSessions();
    expect(rows).toHaveLength(1);
    const row = rows[0]!;

    // counterparty_ack_frontier round-trips.
    expect(row.counterparty_ack_frontier).toBe(4);

    // legibility_cbor round-trips and re-parses intact (the exact reconstruction path
    // loadClientStartupState uses: CBOR decode → parseLegibility).
    expect(row.legibility_cbor).not.toBeNull();
    const blob = row.legibility_cbor instanceof Buffer
      ? new Uint8Array(row.legibility_cbor)
      : new Uint8Array(row.legibility_cbor as Uint8Array);
    const reloaded = parseLegibility(cborDecode(blob));
    expect(reloaded).not.toBeNull();
    expect(reloaded!.attests).toBe("receipt");
    expect(reloaded!.implies_assent).toBe(false);
    expect(reloaded!.disclaimer).toBe(SEAL_RECEIPT_DISCLAIMER);
    expect(reloaded!.participants).toHaveLength(2);
    expect(reloaded!.final_message.answered).toBe(false);

    // The client independently re-derives each party's content_frontier_seq from its own
    // local state (own = last_seen_seq = 6; counterparty = observed ack frontier = 4) and
    // confirms it equals the published value (no SI-002 violation).
    const derived = new Map<string, number>([
      [agentPubkey, row.last_seen_seq],                                    // own frontier
      [Buffer.from(bPubkey).toString("hex"), row.counterparty_ack_frontier], // counterparty
    ]);
    expect(findUnverifiableFrontier(reloaded!, derived)).toBeNull();

    const aEntry = reloaded!.participants.find(
      (p) => Buffer.from(p.pubkey).toString("hex") === agentPubkey,
    )!;
    expect(aEntry.content_frontier_seq).toBe(6);
    expect(aEntry.content_frontier_seq).toBe(row.last_seen_seq);

    // Drive the REAL production reconstruction path (loadClientStartupState §6) rather than
    // re-deriving CBOR decode → parseLegibility by hand: the in-memory SessionRecord the
    // facade actually uses after restart must carry the legibility object intact.
    const { ctx, sessions } = makeCapturingStartupContext({ persistence: persistence2, logger });
    await loadClientStartupState(ctx);
    const restored = sessions.get(sessionIdHex);
    expect(restored).toBeDefined();
    expect(restored!.counterparty_ack_frontier).toBe(4);
    expect(restored!.legibility).toBeDefined();
    expect(restored!.legibility!.attests).toBe("receipt");
    expect(restored!.legibility!.implies_assent).toBe(false);
    expect(restored!.legibility!.disclaimer).toBe(SEAL_RECEIPT_DISCLAIMER);
    expect(restored!.legibility!.final_message.answered).toBe(false);
    // The reconstructed in-use record passes the SI-002 self-verification too.
    expect(findUnverifiableFrontier(restored!.legibility!, new Map<string, number>([
      [agentPubkey, restored!.last_seen_seq],
      [Buffer.from(bPubkey).toString("hex"), restored!.counterparty_ack_frontier],
    ]))).toBeNull();

    await store2.close();
  });

  it("the inline ALTER TABLE columns are idempotent across repeated opens (no Flyway migration)", async () => {
    const agentPubkey = randomBytes(32).toString("hex");
    const dbKey = deriveDbKey(randomBytes(32), agentPubkey);

    // Open/close three times — the guarded ALTER TABLE must not throw on the duplicate column.
    for (let i = 0; i < 3; i++) {
      const store = new SQLCipherClientStore(dbKey, { dbPath, agentId: agentPubkey, logger });
      await store.open();
      const cols = await store.allRows<{ name: string }>(`PRAGMA table_info(sessions)`);
      const names = cols.map((c) => c.name);
      expect(names).toContain("legibility_cbor");
      expect(names).toContain("counterparty_ack_frontier");
      await store.close();
    }

    // No inline-migration failure was ever logged.
    const failures = logger.events.filter((e) => e.event === "client.store.inline.migration.failed");
    expect(failures).toHaveLength(0);
  });
});
