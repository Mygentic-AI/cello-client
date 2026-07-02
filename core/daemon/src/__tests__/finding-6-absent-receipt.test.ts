/**
 * M8B FINDING-6 (cascade-2) — the ABSENT party (B) must persist a retrievable receipt.
 *
 * Two units the wiring builds on:
 *  1. recordSealCertificateEnsuringRow (SessionNodeManager): recordSealCertificate is an
 *     `UPDATE ... WHERE` — a SILENT no-op when B has no local `sessions` row (a reconnecting absent
 *     party may not have one). This ensures a stub row first so B's receipt is actually durable +
 *     retrievable. (The trap the cascade-2 reviewer flagged as Critical 2.)
 *  2. upgradeAbsentToRecovered (pure): on a verified seal_upgrade_confirmed, each party upgrades its
 *     OWN stored unilateral receipt — the counterparty that was recorded 'absent' becomes 'recovered'
 *     (B ratified + proved content possession via the KERNEL gate). No directory change: the leaves
 *     aren't persisted at upgrade time, so the bilateral receipt is built client-side from the cert
 *     each party already holds. Never overstates (frontiers unchanged; only the attestation flips).
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SessionNodeManager, type ISessionNodeFactory } from "../session-node-manager.js";
import { upgradeAbsentToRecovered, hasAbsentParticipant } from "../seal-receipt-upgrade.js";
import type { Logger } from "../types.js";

const silentLogger: Logger = { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} };
// A factory that never makes a node — these tests only exercise the DB.
const stubFactory: ISessionNodeFactory = { createNode: async () => { throw new Error("no node in this test"); } };

describe("FINDING-6: recordSealCertificateEnsuringRow (durable absent-party receipt)", () => {
  let tempDir: string;
  beforeEach(async () => { tempDir = await mkdtemp(join(tmpdir(), "cello-f6-")); });
  afterEach(async () => { await rm(tempDir, { recursive: true, force: true }); });

  async function newManager(): Promise<SessionNodeManager> {
    const mgr = new SessionNodeManager({ factory: stubFactory, logger: silentLogger, dbPath: join(tempDir, `f6-${Math.random().toString(36).slice(2)}.db`) });
    await mgr.initialize();
    return mgr;
  }

  const SID = "6f".padEnd(32, "0"); // 16-byte session id hex
  const CP = "aa".repeat(32); // counterparty (present party A) pubkey hex
  const ROOT = "cc".repeat(32);
  const LEG = JSON.stringify({ attests: "receipt", participants: [{ pubkey: CP, content_frontier_seq: 2, attestation_mode: "live" }] });

  it("plain recordSealCertificate SILENTLY no-ops when B has no local row (the bug)", async () => {
    const mgr = await newManager();
    mgr.recordSealCertificate("bob", SID, ROOT, LEG);
    expect(mgr.getSealCertificate("bob", SID)).toBeNull();
  });

  it("recordSealCertificateEnsuringRow persists a RETRIEVABLE cert when there is no prior row", async () => {
    const mgr = await newManager();
    mgr.recordSealCertificateEnsuringRow("bob", SID, CP, ROOT, LEG);
    const cert = mgr.getSealCertificate("bob", SID);
    expect(cert).not.toBeNull();
    expect(cert!.sealed_root).toBe(ROOT);
    expect((cert!.legibility as { participants: unknown[] }).participants).toHaveLength(1);
  });

  it("updates an EXISTING row (interrupted post-restart) without duplicating it", async () => {
    const mgr = await newManager();
    const now = Date.now();
    mgr.getDb()
      .prepare("INSERT INTO sessions (session_id, agent_name, counterparty_pubkey, status, created_at, updated_at) VALUES (?,?,?,?,?,?)")
      .run(SID, "bob", CP, "interrupted", now, now);
    mgr.recordSealCertificateEnsuringRow("bob", SID, CP, "dd".repeat(32), LEG);
    expect(mgr.getSealCertificate("bob", SID)!.sealed_root).toBe("dd".repeat(32));
    const { c } = mgr.getDb().prepare("SELECT COUNT(*) c FROM sessions WHERE agent_name=? AND session_id=?").get("bob", SID) as { c: number };
    expect(c).toBe(1);
  });
});

describe("FINDING-6: upgradeAbsentToRecovered (client-side bilateral upgrade of a stored receipt)", () => {
  it("flips the 'absent' participant to 'recovered', leaves others untouched", () => {
    const leg = {
      attests: "receipt",
      implies_assent: false,
      participants: [
        { pubkey: "aa", content_frontier_seq: 3, attestation_mode: "live" },
        { pubkey: "bb", content_frontier_seq: 0, attestation_mode: "absent" },
      ],
    };
    const upgraded = upgradeAbsentToRecovered(leg) as typeof leg;
    expect(upgraded.participants[0].attestation_mode).toBe("live");
    expect(upgraded.participants[1].attestation_mode).toBe("recovered");
    // frontiers are NEVER inflated by the flip — only the attestation changes.
    expect(upgraded.participants[1].content_frontier_seq).toBe(0);
  });

  it("is a no-op when there is no 'absent' participant (already bilateral)", () => {
    const leg = { participants: [{ pubkey: "aa", attestation_mode: "live" }, { pubkey: "bb", attestation_mode: "recovered" }] };
    const upgraded = upgradeAbsentToRecovered(leg) as typeof leg;
    expect(upgraded.participants.map((p) => p.attestation_mode)).toEqual(["live", "recovered"]);
  });

  it("tolerates a malformed legibility (returns it unchanged rather than throwing)", () => {
    expect(upgradeAbsentToRecovered(undefined)).toBeUndefined();
    expect(upgradeAbsentToRecovered({ nope: 1 })).toEqual({ nope: 1 });
  });
});

describe("FINDING-6: hasAbsentParticipant (one-way-ratchet guard for 3b re-delivery)", () => {
  it("true for a fresh unilateral cert (has an 'absent' party), false once upgraded to 'recovered'", () => {
    const fresh = { participants: [{ pubkey: "aa", attestation_mode: "live" }, { pubkey: "bb", attestation_mode: "absent" }] };
    expect(hasAbsentParticipant(fresh)).toBe(true);
    const upgraded = upgradeAbsentToRecovered({ participants: [{ pubkey: "aa", attestation_mode: "live" }, { pubkey: "bb", attestation_mode: "absent" }] });
    expect(hasAbsentParticipant(upgraded)).toBe(false); // ratchet: a re-delivered notification must NOT re-persist over this
  });

  it("false for malformed/empty legibility (nothing to protect)", () => {
    expect(hasAbsentParticipant(undefined)).toBe(false);
    expect(hasAbsentParticipant({ nope: 1 })).toBe(false);
    expect(hasAbsentParticipant({ participants: [] })).toBe(false);
  });
});
