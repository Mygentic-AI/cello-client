/**
 * CELLO-M7-PERSIST-002 (AC-008): DB-backed manifest version store.
 *
 * The last-seen manifest version is stored in the encrypted `manifest_state` table and reloaded from
 * it; no `manifest-version.json` file is written. Monotonicity is enforced by the consumer
 * (SignalingManager) — this store just durably persists + reloads the number across a process boundary.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { DbManifestVersionStore } from "../manifest-version-store-db.js";
import { openTestDb } from "./helpers/encrypted-db.js";
import type { Logger } from "../types.js";

function makeLogger(): Logger {
  return { debug() {}, info() {}, warn() {}, error() {} };
}

let tempDir = "";
let dbPath = "";
beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "persist002-manifest-"));
  dbPath = join(tempDir, "sessions.db");
});
afterEach(async () => {
  await rm(tempDir, { recursive: true, force: true });
});

describe("PERSIST-002 AC-008 — DbManifestVersionStore", () => {
  it("returns null before any version is persisted", async () => {
    const store = new DbManifestVersionStore(openTestDb(dbPath), makeLogger());
    expect(await store.getLastSeenVersion()).toBeNull();
  });

  it("persists + reloads the version across a fresh DB handle (durable, encrypted, no JSON file)", async () => {
    const store = new DbManifestVersionStore(openTestDb(dbPath), makeLogger());
    await store.persistVersion(7);
    expect(await store.getLastSeenVersion()).toBe(7);

    // A new store on a fresh handle to the same encrypted DB sees the committed value.
    const reopened = new DbManifestVersionStore(openTestDb(dbPath), makeLogger());
    expect(await reopened.getLastSeenVersion()).toBe(7);

    // Upsert (singleton row): a later version replaces, not appends.
    await reopened.persistVersion(9);
    expect(await reopened.getLastSeenVersion()).toBe(9);
    const rows = openTestDb(dbPath).prepare("SELECT COUNT(*) AS c FROM manifest_state").get() as { c: number };
    expect(rows.c).toBe(1);

    // No plaintext manifest-version.json file is written.
    expect(existsSync(join(tempDir, "manifest-version.json"))).toBe(false);
  });
});
