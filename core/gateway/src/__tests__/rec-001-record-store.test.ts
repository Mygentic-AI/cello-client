/**
 * M9-REC-001 — local security-pass records (the cheap half of tamper-proof records; directory
 * attestation is Phase-2 M9-ATTEST-001).
 *
 * The gateway records what it did to EVERY message — clean / redacted / blocked / warned — in its own
 * SQLCipher store (DOD-M9B-STORE-1), each record hash-chained to the prior one so tampering is
 * detectable. A clean pass is recorded too (an absent record for a delivered message is itself evidence
 * of suppression). Each record carries a fingerprint, ready to attest to the directory in Phase 2.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { openEncryptedStoreDb } from "../store/encrypted-db.js";
import { GatewayRecordStore } from "../records/record-store.js";

const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);

describe("M9-REC-001 GatewayRecordStore — every message recorded, hash-chained", () => {
  let dir: string;
  let dbPath: string;
  let keyPath: string;
  let store: GatewayRecordStore;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "cello-rec-"));
    dbPath = join(dir, "records.db");
    keyPath = join(dir, "store.key");
    await writeFile(keyPath, randomBytes(32), { mode: 0o600 });
    store = new GatewayRecordStore(dbPath, keyPath);
  });
  afterEach(async () => {
    store.close();
    await rm(dir, { recursive: true, force: true });
  });

  it("records a CLEAN pass too (not just blocks) — with a fingerprint", () => {
    const r = store.record({ direction: "outbound", disposition: "clean", contentHash: HASH_A });
    expect(r.seq).toBe(1);
    expect(typeof r.fingerprint).toBe("string");
    expect(r.fingerprint.length).toBe(64);
    expect(store.count()).toBe(1);
  });

  it("records each of clean / redact / block / warn", () => {
    store.record({ direction: "outbound", disposition: "clean", contentHash: HASH_A });
    store.record({ direction: "outbound", disposition: "redact", contentHash: HASH_A, reason: "secret:aws" });
    store.record({ direction: "outbound", disposition: "warn", contentHash: HASH_A, reason: "pii:email" });
    store.record({ direction: "inbound", disposition: "block", contentHash: HASH_B, reason: "inbound_language_blocked" });
    const all = store.all();
    expect(all.map((r) => r.disposition)).toEqual(["clean", "redact", "warn", "block"]);
    expect(all[3].direction).toBe("inbound");
    expect(all[3].reason).toBe("inbound_language_blocked");
  });

  it("sequence numbers increment monotonically; records are append-only", () => {
    store.record({ direction: "outbound", disposition: "clean", contentHash: HASH_A });
    store.record({ direction: "inbound", disposition: "clean", contentHash: HASH_B });
    store.record({ direction: "outbound", disposition: "block", contentHash: HASH_A });
    expect(store.all().map((r) => r.seq)).toEqual([1, 2, 3]);
  });

  it("each record is hash-chained to its predecessor; verifyChain holds on an intact log", () => {
    const r1 = store.record({ direction: "outbound", disposition: "clean", contentHash: HASH_A });
    const r2 = store.record({ direction: "outbound", disposition: "redact", contentHash: HASH_B, reason: "secret" });
    expect(r1.fingerprint).not.toBe(r2.fingerprint);
    expect(store.verifyChain()).toBe(true);
  });

  it("verifyChain CATCHES tampering — an edited record is detected", () => {
    store.record({ direction: "outbound", disposition: "block", contentHash: HASH_A, reason: "injection" });
    store.record({ direction: "outbound", disposition: "clean", contentHash: HASH_B });
    expect(store.verifyChain()).toBe(true);
    store.close();
    // Tamper directly in the DB file (a raw connection): rewrite record 1's disposition block→clean,
    // leaving its stored fingerprint untouched. On reopen the recomputed fingerprint no longer matches.
    const raw = openEncryptedStoreDb(dbPath, keyPath);
    raw.prepare("UPDATE security_records SET disposition = 'clean' WHERE seq = 1").run();
    raw.close();
    const reopened = new GatewayRecordStore(dbPath, keyPath);
    expect(reopened.verifyChain()).toBe(false);
    reopened.close();
  });

  it("verifyChain CATCHES deletion — a removed middle record breaks the chain", () => {
    store.record({ direction: "outbound", disposition: "clean", contentHash: HASH_A });
    store.record({ direction: "outbound", disposition: "block", contentHash: HASH_B, reason: "x" });
    store.record({ direction: "outbound", disposition: "clean", contentHash: HASH_A });
    expect(store.verifyChain()).toBe(true);
    store.close();
    const raw = openEncryptedStoreDb(dbPath, keyPath);
    raw.prepare("DELETE FROM security_records WHERE seq = 2").run(); // suppress the block record
    raw.close();
    const reopened = new GatewayRecordStore(dbPath, keyPath);
    expect(reopened.verifyChain()).toBe(false);
    reopened.close();
  });

  it("verifyChain CATCHES a swapped content hash — the record binds WHICH content was screened", () => {
    store.record({ direction: "outbound", disposition: "block", contentHash: HASH_A, reason: "injection" });
    store.record({ direction: "outbound", disposition: "clean", contentHash: HASH_B });
    expect(store.verifyChain()).toBe(true);
    store.close();
    // Swap record 1's content_hash (rewrite history to claim a DIFFERENT message was blocked), leaving
    // its stored fingerprint untouched. The recomputed fingerprint no longer matches → caught.
    const raw = openEncryptedStoreDb(dbPath, keyPath);
    raw.prepare(`UPDATE security_records SET content_hash = '${"c".repeat(64)}' WHERE seq = 1`).run();
    raw.close();
    const reopened = new GatewayRecordStore(dbPath, keyPath);
    expect(reopened.verifyChain()).toBe(false);
    reopened.close();
  });

  it("verifyChain CATCHES a flipped disposition AND direction (both are in the fingerprint)", () => {
    store.record({ direction: "inbound", disposition: "block", contentHash: HASH_A, reason: "lang" });
    store.close();
    const raw = openEncryptedStoreDb(dbPath, keyPath);
    raw.prepare(`UPDATE security_records SET direction = 'outbound' WHERE seq = 1`).run(); // forge the direction
    raw.close();
    const reopened = new GatewayRecordStore(dbPath, keyPath);
    expect(reopened.verifyChain()).toBe(false);
    reopened.close();
  });

  it("verifyChain CATCHES a rewritten reason (the WHY is bound too)", () => {
    store.record({ direction: "outbound", disposition: "block", contentHash: HASH_A, reason: "injection" });
    store.close();
    const raw = openEncryptedStoreDb(dbPath, keyPath);
    raw.prepare(`UPDATE security_records SET reason = 'benign' WHERE seq = 1`).run(); // rewrite why it blocked
    raw.close();
    const reopened = new GatewayRecordStore(dbPath, keyPath);
    expect(reopened.verifyChain()).toBe(false);
    reopened.close();
  });

  it("the record log SURVIVES reopen (persisted to the gateway's own DB file)", () => {
    store.record({ direction: "outbound", disposition: "clean", contentHash: HASH_A });
    store.record({ direction: "inbound", disposition: "block", contentHash: HASH_B, reason: "lang" });
    store.close();
    const reopened = new GatewayRecordStore(dbPath, keyPath);
    expect(reopened.count()).toBe(2);
    expect(reopened.verifyChain()).toBe(true);
    expect(reopened.all()[1].reason).toBe("lang");
    reopened.close();
  });

  it("the fingerprint binds the content hash — two records of different content differ even at the same disposition", () => {
    const r1 = store.record({ direction: "outbound", disposition: "clean", contentHash: HASH_A });
    const fresh = new GatewayRecordStore(join(dir, "records2.db"), keyPath);
    const r2 = fresh.record({ direction: "outbound", disposition: "clean", contentHash: HASH_B });
    expect(r1.fingerprint).not.toBe(r2.fingerprint); // same seq/disposition, different content → different fp
    fresh.close();
  });
});
