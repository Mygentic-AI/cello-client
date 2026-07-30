/**
 * DOD-M9B-STORE-1 — custody: the gateway stores are SQLCipher-encrypted, keyed by the daemon's
 * key file, fail-closed on a missing or wrong key, and share ONE encrypted file (M9B-D9).
 *
 * The revert test lives in the assertions themselves: a node:sqlite implementation of the stores
 * passes none of these — its file carries the plaintext magic, and it opens fine without any key.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, writeFile, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";
import { GatewayConfigStore } from "../config/config-store.js";
import { GatewayRecordStore } from "../records/record-store.js";
import { GatewayStoreError } from "../store/encrypted-db.js";

const PLAINTEXT_MAGIC = Buffer.concat([Buffer.from("SQLite format 3", "latin1"), Buffer.from([0x00])]);

describe("DOD-M9B-STORE-1 — encrypted gateway stores (fail-closed custody)", () => {
  let dir: string;
  let dbPath: string;
  let keyPath: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "cello-m9b-store-"));
    dbPath = join(dir, "gateway.db");
    keyPath = join(dir, "sessions.db.key");
    await writeFile(keyPath, randomBytes(32), { mode: 0o600 });
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("REFUSES to open when the key file is absent (store_key_unavailable) — never a plaintext fallback", async () => {
    let thrown: unknown;
    try {
      new GatewayConfigStore(dbPath, join(dir, "no-such.key"));
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(GatewayStoreError);
    expect((thrown as GatewayStoreError).code).toBe("store_key_unavailable");
    // Nothing plaintext was created as a side effect of the refusal.
    expect(await readFile(dbPath).catch(() => null)).toBeNull();
  });

  it("REFUSES a malformed key (wrong length) — store_key_unavailable, with guidance", async () => {
    await writeFile(keyPath, randomBytes(16), { mode: 0o600 });
    let thrown: unknown;
    try {
      new GatewayConfigStore(dbPath, keyPath);
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(GatewayStoreError);
    expect((thrown as GatewayStoreError).code).toBe("store_key_unavailable");
    expect((thrown as GatewayStoreError).guidance.length).toBeGreaterThan(0);
  });

  it("both stores share ONE encrypted file and round-trip across reopen WITH the key (M9B-D9)", () => {
    const config = new GatewayConfigStore(dbPath, keyPath);
    const records = new GatewayRecordStore(dbPath, keyPath);
    expect(config.set("autonomous_override", false).ok).toBe(true);
    const rec = records.record({ direction: "outbound", disposition: "clean", contentHash: "ab".repeat(32) });
    expect(rec.seq).toBe(1);
    config.close();
    records.close();

    const config2 = new GatewayConfigStore(dbPath, keyPath);
    const records2 = new GatewayRecordStore(dbPath, keyPath);
    expect(config2.get("autonomous_override")).toBe(false);
    expect(records2.count()).toBe(1);
    expect(config2.verifyChain("autonomous_override")).toBe(true);
    expect(records2.verifyChain()).toBe(true);
    config2.close();
    records2.close();
  });

  it("the file on disk is CIPHERTEXT — the plaintext SQLite magic is absent", async () => {
    const config = new GatewayConfigStore(dbPath, keyPath);
    config.set("pii_whitelist", [], { confirmed: false });
    config.close();
    const head = (await readFile(dbPath)).subarray(0, PLAINTEXT_MAGIC.length);
    expect(head.equals(PLAINTEXT_MAGIC)).toBe(false);
  });

  it("REFUSES to open with the WRONG key (store_key_mismatch) — never returns a handle", async () => {
    const config = new GatewayConfigStore(dbPath, keyPath);
    config.set("autonomous_override", false);
    config.close();

    const wrongKeyPath = join(dir, "wrong.key");
    await writeFile(wrongKeyPath, randomBytes(32), { mode: 0o600 });
    let thrown: unknown;
    try {
      new GatewayConfigStore(dbPath, wrongKeyPath);
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(GatewayStoreError);
    expect((thrown as GatewayStoreError).code).toBe("store_key_mismatch");
  });
});
