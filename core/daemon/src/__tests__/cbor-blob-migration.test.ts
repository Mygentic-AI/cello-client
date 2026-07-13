/**
 * §1.1 — the persisted FROST blobs migrate to ONE encoding, and nobody loses a key doing it.
 *
 * The defect: `frost_commitments` / `frost_verifying_shares` were written by registration in the
 * canonical encoding (raw CBOR byte strings) and REWRITTEN by `cello_refresh_shares` in cbor-x's
 * default TAG-64 encoding. Both are on disk in the field. cbor-x reads both, which is the only
 * reason anything worked.
 *
 * These tests use `encode` from cbor-x DIRECTLY to forge the old tag-64 blobs. That is deliberate:
 * it is the exact byte sequence the old refresh path produced, so the fixture is the real
 * pre-migration artifact and not an approximation of one.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { encode as tag64Encode } from "cbor-x";
import { encodeCbor, decodeCbor } from "@cello-protocol/protocol-types";
import { openEncryptedDatabase, type DaemonDatabase } from "../sqlcipher-db.js";
import { ensureIdentitySchema } from "../db-identity-store.js";
import { migrateCborBlobsToCanonical } from "../cbor-blob-migration.js";
import type { Logger } from "../types.js";

const TAG64 = Buffer.from([0xd8, 0x40]); // CBOR tag 64 = uint8 typed array

describe("§1.1: migrate persisted FROST blobs to one canonical CBOR encoding", () => {
  let dir: string;
  let db: DaemonDatabase;
  let events: Array<{ event: string; ctx: Record<string, unknown> }>;
  let logger: Logger;

  // A realistic share payload: a map of participant id → bytes. The BYTES are what tag-64 changes.
  const commitments = { "1": new Uint8Array([1, 2, 3, 4]), "2": new Uint8Array([5, 6, 7, 8]) };
  const verifying = { "1": new Uint8Array([9, 9, 9]), "2": new Uint8Array([8, 8, 8]) };

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "cello-cbor-mig-"));
    events = [];
    logger = {
      debug() {}, info(e, c) { events.push({ event: e, ctx: c ?? {} }); },
      warn(e, c) { events.push({ event: e, ctx: c ?? {} }); },
      error(e, c) { events.push({ event: e, ctx: c ?? {} }); },
    };
    db = openEncryptedDatabase(join(dir, "cello.db"), "0".repeat(64), logger);
    ensureIdentitySchema(db);
  });

  afterEach(async () => {
    try { db.close(); } catch { /* already closed */ }
    await rm(dir, { recursive: true, force: true });
  });

  function seedAgent(agentId: string, commitmentsBlob: Uint8Array, verifyingBlob: Uint8Array): void {
    db.prepare(
      `INSERT INTO agents (agent_id, agent_name, k_local_seed, k_local_pubkey,
                           frost_commitments, frost_verifying_shares, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      agentId,
      `agent-${agentId}`,
      Buffer.alloc(32, 7),          // k_local_seed  — NOT NULL
      "aa".repeat(32),              // k_local_pubkey — NOT NULL
      Buffer.from(commitmentsBlob),
      Buffer.from(verifyingBlob),
      1_752_000_000_000,            // created_at — NOT NULL
      1_752_000_000_000,            // updated_at — NOT NULL
    );
  }

  function readBlob(agentId: string, column: string): Uint8Array {
    const row = db.prepare(`SELECT ${column} AS b FROM agents WHERE agent_id = ?`).get(agentId) as { b: Buffer };
    return new Uint8Array(row.b);
  }

  it("rewrites a TAG-64 blob (what the old refresh path wrote) to canonical, preserving the VALUE", () => {
    const oldCommitments = new Uint8Array(tag64Encode(commitments) as Uint8Array);
    const oldVerifying = new Uint8Array(tag64Encode(verifying) as Uint8Array);
    // Precondition: the fixture really IS the broken format, or this test proves nothing.
    expect(Buffer.from(oldCommitments).includes(TAG64)).toBe(true);
    seedAgent("a1", oldCommitments, oldVerifying);

    migrateCborBlobsToCanonical(db, logger);

    const got = readBlob("a1", "frost_commitments");
    expect(Buffer.from(got).includes(TAG64)).toBe(false);            // the tag is gone
    expect(Buffer.from(got).equals(Buffer.from(encodeCbor(commitments)))).toBe(true); // byte-exact canonical

    // The KEY MATERIAL survived. This is the assertion that matters — a migration that produced
    // clean bytes but a different value would destroy the agent's ability to sign.
    const after = decodeCbor(got) as Record<string, Uint8Array>;
    expect(new Uint8Array(after["1"])).toEqual(commitments["1"]);
    expect(new Uint8Array(after["2"])).toEqual(commitments["2"]);

    const v = decodeCbor(readBlob("a1", "frost_verifying_shares")) as Record<string, Uint8Array>;
    expect(new Uint8Array(v["1"])).toEqual(verifying["1"]);
  });

  it("leaves an ALREADY-canonical blob byte-for-byte untouched (idempotent, no needless rewrite)", () => {
    const canonical = encodeCbor(commitments);
    seedAgent("a2", canonical, encodeCbor(verifying));

    migrateCborBlobsToCanonical(db, logger);
    expect(Buffer.from(readBlob("a2", "frost_commitments")).equals(Buffer.from(canonical))).toBe(true);
    expect(events.some((e) => e.event === "daemon.cbor.migration.rewritten")).toBe(false);
  });

  it("running it twice changes nothing the second time — no flag to get wrong", () => {
    seedAgent("a3", new Uint8Array(tag64Encode(commitments) as Uint8Array), new Uint8Array(tag64Encode(verifying) as Uint8Array));

    migrateCborBlobsToCanonical(db, logger);
    const afterFirst = readBlob("a3", "frost_commitments");
    events = [];

    migrateCborBlobsToCanonical(db, logger);
    expect(Buffer.from(readBlob("a3", "frost_commitments")).equals(Buffer.from(afterFirst))).toBe(true);
    expect(events.some((e) => e.event === "daemon.cbor.migration.rewritten")).toBe(false);
  });

  it("FAILS SAFE: an UNDECODABLE blob is left exactly as it was, and reported — never dropped", () => {
    // A share we cannot read is a share we must not touch. Destroying it makes the agent
    // permanently unable to sign or seal — strictly worse than leaving an old encoding in place.
    const garbage = new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff]);
    seedAgent("a4", garbage, encodeCbor(verifying));

    expect(() => migrateCborBlobsToCanonical(db, logger)).not.toThrow();

    expect(Buffer.from(readBlob("a4", "frost_commitments")).equals(Buffer.from(garbage))).toBe(true);
    expect(events.some((e) => e.event === "daemon.cbor.migration.undecodable")).toBe(true);

    // ...and the OTHER column on the same row still migrates. One bad blob must not abandon the row.
    expect(Buffer.from(readBlob("a4", "frost_verifying_shares")).includes(TAG64)).toBe(false);
  });

  it("an agent with NO share (never registered) is skipped without incident", () => {
    db.prepare(
      `INSERT INTO agents (agent_id, agent_name, k_local_seed, k_local_pubkey, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).run("a5", "agent-a5", Buffer.alloc(32, 7), "aa".repeat(32), 1_752_000_000_000, 1_752_000_000_000);
    expect(() => migrateCborBlobsToCanonical(db, logger)).not.toThrow();
    expect(events.some((e) => e.event === "daemon.cbor.migration.rewritten")).toBe(false);
  });

  it("migrates a MIXED fleet in one pass — the real field state after some agents refreshed", () => {
    // This is the actual on-disk situation: whoever ran `cello_refresh_shares` has tag-64, whoever
    // did not still has canonical, and they sit in the same table.
    seedAgent("mixed-old", new Uint8Array(tag64Encode(commitments) as Uint8Array), new Uint8Array(tag64Encode(verifying) as Uint8Array));
    seedAgent("mixed-new", encodeCbor(commitments), encodeCbor(verifying));

    migrateCborBlobsToCanonical(db, logger);

    for (const id of ["mixed-old", "mixed-new"]) {
      const blob = readBlob(id, "frost_commitments");
      expect(Buffer.from(blob).includes(TAG64), `${id} still tagged`).toBe(false);
      expect(Buffer.from(blob).equals(Buffer.from(encodeCbor(commitments))), `${id} not canonical`).toBe(true);
    }
  });
});
