/**
 * M8B quorum — additive migration for the persisted quorum Q.
 *
 * Finding #1 (Critical) fix: the DKG's quorum Q (directory nodeIds) is persisted so a restored
 * FrostThresholdSigner targets the actual share-holders, not the full live roster. This exercises the
 * riskiest path — the `ALTER TABLE agents ADD COLUMN frost_directory_node_ids` migration on a
 * pre-quorum DB (a fresh table already has the column via CREATE_AGENTS_SQL, so that path is covered
 * by the existing 521 daemon tests; this one is NOT).
 */
import { describe, it, expect } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { ensureIdentitySchema } from "../db-identity-store.js";

const colNames = (db: DatabaseSync): string[] =>
  (db.prepare("PRAGMA table_info(agents)").all() as Array<{ name: string }>).map((c) => c.name);

describe("M8B quorum — frost_directory_node_ids additive migration", () => {
  it("adds the column to a pre-quorum agents table (has agent_id, lacks the column)", () => {
    const db = new DatabaseSync(":memory:");
    // A pre-quorum agents table: stable-agent_id shape (so no re-key rebuild fires) WITHOUT the M8B column.
    db.exec(`CREATE TABLE agents (
      agent_id TEXT PRIMARY KEY, agent_name TEXT NOT NULL, k_local_seed BLOB NOT NULL,
      k_local_pubkey TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'created',
      frost_epoch_id TEXT, frost_primary_pubkey TEXT, frost_identifier TEXT, frost_signing_share BLOB,
      frost_threshold INTEGER, frost_participants INTEGER, frost_commitments BLOB,
      frost_verifying_shares BLOB, frost_dkg_method TEXT,
      created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)`);
    expect(colNames(db)).not.toContain("frost_directory_node_ids");

    ensureIdentitySchema(db);

    expect(colNames(db)).toContain("frost_directory_node_ids");
    // Idempotent — a second call must not throw (column already present).
    expect(() => ensureIdentitySchema(db)).not.toThrow();
  });

  it("a fresh DB gets the column via CREATE (no ALTER needed)", () => {
    const db = new DatabaseSync(":memory:");
    ensureIdentitySchema(db);
    expect(colNames(db)).toContain("frost_directory_node_ids");
  });
});
