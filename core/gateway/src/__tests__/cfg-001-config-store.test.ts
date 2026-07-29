/**
 * M9-CFG-001 — the gateway's own versioned config store (INV-4).
 *
 * The store lives in the gateway's SQLCipher file, opened with the daemon's key (DOD-M9C-STORE-1),
 * is append-only/versioned, and enforces the §7 governance rule:
 * **TIGHTENING a guard is free; LOOSENING one requires explicit confirmation.** Each version is
 * hash-chained (a per-row fingerprint over key+version+value+prev) so the change history is
 * tamper-evident and attested-ready (the cheap half of Phase-2 attestation).
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { openEncryptedStoreDb } from "../store/encrypted-db.js";
import { GatewayConfigStore } from "../config/config-store.js";

describe("M9-CFG-001 GatewayConfigStore — versioned, tighten-free / loosen-confirmed", () => {
  let dir: string;
  let dbPath: string;
  let keyPath: string;
  let store: GatewayConfigStore;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "cello-cfg-"));
    dbPath = join(dir, "config.db");
    keyPath = join(dir, "store.key");
    await writeFile(keyPath, randomBytes(32), { mode: 0o600 });
    store = new GatewayConfigStore(dbPath, keyPath);
  });
  afterEach(async () => {
    store.close();
    await rm(dir, { recursive: true, force: true });
  });

  it("the FIRST value for a key is set freely (version 1) and read back", () => {
    const r = store.set("autonomous_override", false);
    expect(r.ok).toBe(true);
    expect(r.ok && r.version).toBe(1);
    expect(store.get("autonomous_override")).toBe(false);
  });

  it("TIGHTENING is free — autonomous_override true→false needs no confirmation", () => {
    store.set("autonomous_override", true, { confirmed: true }); // first set to the looser value (confirmed)
    const r = store.set("autonomous_override", false); // true→false = tighten
    expect(r.ok).toBe(true);
    expect(r.ok && r.direction).toBe("tighten");
    expect(store.get("autonomous_override")).toBe(false);
  });

  it("LOOSENING without confirmation is REJECTED and NOT versioned", () => {
    store.set("autonomous_override", false); // v1, tightest
    const r = store.set("autonomous_override", true); // false→true = loosen, no confirm
    expect(r.ok).toBe(false);
    expect(!r.ok && r.reason).toBe("needs_confirmation");
    expect(!r.ok && r.direction).toBe("loosen");
    expect(store.get("autonomous_override")).toBe(false); // unchanged — the loosening did not apply
    expect(store.history("autonomous_override").length).toBe(1); // no new version row
  });

  it("LOOSENING WITH confirmation applies and is versioned", () => {
    store.set("autonomous_override", false); // v1
    const r = store.set("autonomous_override", true, { confirmed: true });
    expect(r.ok).toBe(true);
    expect(r.ok && r.direction).toBe("loosen");
    expect(r.ok && r.version).toBe(2);
    expect(store.get("autonomous_override")).toBe(true);
  });

  it("PII whitelist: ADD a value is loosen (needs confirm); REMOVE is tighten (free)", () => {
    // First set of a non-empty whitelist is itself a loosen from the [] baseline → needs confirmation (B1).
    store.set("pii_whitelist", ["a@x.example"], { confirmed: true }); // v1 (loosen, confirmed)
    const add = store.set("pii_whitelist", ["a@x.example", "b@y.example"]); // loosen
    expect(add.ok).toBe(false);
    expect(!add.ok && add.direction).toBe("loosen");
    const addOk = store.set("pii_whitelist", ["a@x.example", "b@y.example"], { confirmed: true });
    expect(addOk.ok).toBe(true);
    const remove = store.set("pii_whitelist", ["a@x.example"]); // tighten — free
    expect(remove.ok).toBe(true);
    expect(remove.ok && remove.direction).toBe("tighten");
  });

  it("rate cap: LOWER is tighten (free); RAISE is loosen; REMOVING the cap (→0) is loosen", () => {
    store.set("rate_max_per_window", 5); // v1
    expect(store.set("rate_max_per_window", 2).ok).toBe(true); // lower = tighten, free
    const raise = store.set("rate_max_per_window", 10); // raise = loosen
    expect(raise.ok).toBe(false);
    expect(!raise.ok && raise.direction).toBe("loosen");
    const removeCap = store.set("rate_max_per_window", 0); // 0 = no cap = loosest
    expect(removeCap.ok).toBe(false);
    expect(!removeCap.ok && removeCap.direction).toBe("loosen");
  });

  it("language allowlist: ADD a script is loosen; REMOVE is tighten", () => {
    store.set("language_allow", ["latin"]); // v1
    expect(store.set("language_allow", ["latin", "cyrillic"]).ok).toBe(false); // add = loosen
    expect(store.set("language_allow", [] as string[]).ok).toBe(true); // remove all = tighten, free
  });

  it("history is APPEND-ONLY and versions increment monotonically", () => {
    store.set("autonomous_override", false); // v1
    store.set("autonomous_override", true, { confirmed: true }); // v2
    store.set("autonomous_override", false); // v3 (tighten)
    const h = store.history("autonomous_override");
    expect(h.map((v) => v.version)).toEqual([1, 2, 3]);
    expect(h.map((v) => v.value)).toEqual([false, true, false]);
  });

  it("each version is hash-chained: the fingerprint depends on the prior version (tamper-evident)", () => {
    const v1 = store.set("autonomous_override", false);
    const v2 = store.set("autonomous_override", true, { confirmed: true });
    expect(v1.ok && v2.ok && typeof v1.fingerprint).toBe("string");
    expect(v1.ok && v2.ok && v1.fingerprint).not.toBe(v2.ok && v2.fingerprint);
    // verifyChain walks the rows recomputing each fingerprint from its predecessor.
    expect(store.verifyChain("autonomous_override")).toBe(true);
  });

  it("verifyChain CATCHES tampering: editing a stored value directly in the DB breaks the chain", () => {
    store.set("pii_whitelist", ["a@x.example"], { confirmed: true }); // v1 (loosen from [] baseline)
    store.set("pii_whitelist", [] as string[]); // v2 (tighten — free)
    expect(store.verifyChain("pii_whitelist")).toBe(true);
    store.close();
    // Tamper: silently widen v1's whitelist in the DB, leaving its stored fingerprint untouched. On
    // reopen the recomputed fingerprint no longer matches the stored one → the chain must reject it.
    const raw = openEncryptedStoreDb(dbPath, keyPath);
    raw.prepare(`UPDATE config_versions SET value_json = '["a@x.example","evil@attacker.example"]' WHERE key = 'pii_whitelist' AND version = 1`).run();
    raw.close();
    const reopened = new GatewayConfigStore(dbPath, keyPath);
    expect(reopened.verifyChain("pii_whitelist")).toBe(false); // tamper detected
    reopened.close();
  });

  it("verifyChain CATCHES deletion: removing a version row breaks the prev-link chain", () => {
    store.set("autonomous_override", false); // v1
    store.set("autonomous_override", true, { confirmed: true }); // v2
    store.set("autonomous_override", false); // v3 (tighten)
    expect(store.verifyChain("autonomous_override")).toBe(true);
    store.close();
    const raw = openEncryptedStoreDb(dbPath, keyPath);
    raw.prepare(`DELETE FROM config_versions WHERE key = 'autonomous_override' AND version = 2`).run();
    raw.close();
    const reopened = new GatewayConfigStore(dbPath, keyPath);
    expect(reopened.verifyChain("autonomous_override")).toBe(false); // v3's prev_fingerprint no longer matches
    reopened.close();
  });

  it("B1: first-set of the LOOSEST value is GATED — classified against the tightest baseline, needs confirm", () => {
    // The store ships empty; without the baseline, first-enabling autonomous_override would be free. It is
    // a loosen from the tightest default (false) and must require confirmation.
    const r = store.set("autonomous_override", true); // first set, loosest value, NO confirmation
    expect(r.ok).toBe(false);
    expect(!r.ok && r.direction).toBe("loosen");
    expect(store.get("autonomous_override")).toBeUndefined(); // nothing was written
    // With confirmation it applies.
    expect(store.set("autonomous_override", true, { confirmed: true }).ok).toBe(true);
  });

  it("B1: first-set of the TIGHTEST value is free (matches the baseline → neutral)", () => {
    const r = store.set("autonomous_override", false); // baseline value, no confirm
    expect(r.ok).toBe(true);
    expect(r.ok && r.direction).toBe("neutral");
  });

  it("B1: first-set of a rate CAP is a tighten (free) — a cap is stricter than the no-cap baseline", () => {
    const r = store.set("rate_max_per_window", 5); // 0(no cap) → 5 = tighten
    expect(r.ok).toBe(true);
    expect(r.ok && r.direction).toBe("tighten");
  });

  it("H1: flipping `confirmed` directly in the DB breaks the chain (the governance bit is hashed)", () => {
    store.set("autonomous_override", false); // v1
    store.set("autonomous_override", true, { confirmed: true }); // v2 loosen, confirmed=1
    expect(store.verifyChain("autonomous_override")).toBe(true);
    store.close();
    const raw = openEncryptedStoreDb(dbPath, keyPath);
    raw.prepare(`UPDATE config_versions SET confirmed = 0 WHERE key = 'autonomous_override' AND version = 2`).run();
    raw.close();
    const reopened = new GatewayConfigStore(dbPath, keyPath);
    expect(reopened.verifyChain("autonomous_override")).toBe(false); // a forged "unconfirmed" loosen is caught
    reopened.close();
  });

  it("H2: SHRINKING the rate window is a loosen (faster refill = more throughput) — needs confirm", () => {
    store.set("rate_window_ms", 60_000); // v1 (baseline → neutral, free)
    const shrink = store.set("rate_window_ms", 30_000); // shorter = loosen
    expect(shrink.ok).toBe(false);
    expect(!shrink.ok && shrink.direction).toBe("loosen");
    const grow = store.set("rate_window_ms", 120_000); // longer = tighten, free
    expect(grow.ok).toBe(true);
    expect(grow.ok && grow.direction).toBe("tighten");
  });

  it("M2: a type-confused value is rejected (cannot silently disable a guard)", () => {
    expect(() => store.set("rate_max_per_window", "off" as unknown as number)).toThrow(/invalid value/i);
    expect(() => store.set("autonomous_override", "false" as unknown as boolean)).toThrow(/invalid value/i);
    expect(() => store.set("pii_whitelist", "a@x.example" as unknown as string[])).toThrow(/invalid value/i);
  });

  it("the store SURVIVES reopen (persisted to the gateway's own DB file)", () => {
    store.set("autonomous_override", false);
    store.set("rate_max_per_window", 3);
    store.close();
    const reopened = new GatewayConfigStore(dbPath, keyPath);
    expect(reopened.get("autonomous_override")).toBe(false);
    expect(reopened.get("rate_max_per_window")).toBe(3);
    reopened.close();
  });

  it("an unknown config key is rejected (a typo cannot silently create an unguarded setting)", () => {
    expect(() => store.set("totally_made_up", true)).toThrow(/unknown config key/i);
  });
});
