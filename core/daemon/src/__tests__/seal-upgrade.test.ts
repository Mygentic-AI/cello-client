/**
 * CELLO-M7-UPGRADE-001 (DOD-UP-1) — adversarial unit tests for the extracted seal-upgrade module.
 *
 * These run the REAL bodies of the two security-critical paths (not just the happy path the live
 * J-UPGRADE-001 covers), closing the hollow-test gaps the test-attacker found and pinning the
 * code-reviewer's H1/M1 hardening:
 *
 *  - attemptSealUpgrade (THE KERNEL): a gutted impl that signs unconditionally must FAIL here. We
 *    assert the gate is genuinely consulted — content_tamper / content_unrecoverable / content_incomplete
 *    all REFUSE (no seal_upgrade_request sent), and only clean+complete content signs + sends.
 *  - verifyUpgradeConfirmedCert (AC-008 + H1): a gutted verifier that accepts any confirmed frame must
 *    FAIL here. We assert a forged returning signature, an attacker-chosen returning_pubkey
 *    (participant_mismatch / unknown_session — H1), and a failed present attestation all REJECT.
 */
import { describe, it, expect, beforeAll } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { generateKeypair } from "@cello-protocol/crypto";
import type { Logger } from "../types.js";
import {
  attemptSealUpgrade,
  verifyUpgradeConfirmedCert,
  buildSealUpgradeAckTbs,
  evaluateSealUpgrade,
  type AttemptSealUpgradeDeps,
  type VerifyUpgradeConfirmedDeps,
} from "../seal-upgrade.js";

interface LogEvent { level: string; event: string; context?: Record<string, unknown> }
function makeLogger(): { logger: Logger; events: LogEvent[] } {
  const events: LogEvent[] = [];
  const logger: Logger = {
    debug(event, context) { events.push({ level: "debug", event, context }); },
    info(event, context) { events.push({ level: "info", event, context }); },
    warn(event, context) { events.push({ level: "warn", event, context }); },
    error(event, context) { events.push({ level: "error", event, context }); },
  };
  return { logger, events };
}

type Kp = ReturnType<typeof generateKeypair>;
let keyB: Kp, keyA: Kp;
let bHex: string, aHex: string;
const SID = new Uint8Array(randomBytes(16));
const SID_HEX = Buffer.from(SID).toString("hex");
const ROOT = new Uint8Array(randomBytes(32));

beforeAll(async () => {
  keyB = generateKeypair();
  keyA = generateKeypair();
  bHex = Buffer.from(await keyB.getPublicKey()).toString("hex");
  aHex = Buffer.from(await keyA.getPublicKey()).toString("hex");
});

function attemptDeps(over: Partial<AttemptSealUpgradeDeps>): { deps: AttemptSealUpgradeDeps; sent: Record<string, unknown>[]; events: LogEvent[] } {
  const { logger, events } = makeLogger();
  const sent: Record<string, unknown>[] = [];
  const deps: AttemptSealUpgradeDeps = {
    logger, agentName: "agentB", agentPubkeyHex: bHex,
    getReadiness: () => ({ known: true, tampered: false }),
    getContentLeafCount: () => 10,
    recoverContent: async () => { /* no-op */ },
    getKeyProvider: () => keyB,
    sendRaw: async (f) => { sent.push(f); return { ok: true }; },
    ...over,
  };
  return { deps, sent, events };
}

const UNI_FRAME = (): Record<string, unknown> => ({ session_id: SID, sealed_root: ROOT, leaf_count: 3 });

describe("DOD-UP-1: evaluateSealUpgrade (pure gate)", () => {
  it("refuses unknown (content_unrecoverable) and tampered (content_tamper); proceeds when verified", () => {
    expect(evaluateSealUpgrade({ known: false, tampered: false })).toEqual({ proceed: false, refuseReason: "content_unrecoverable" });
    expect(evaluateSealUpgrade({ known: true, tampered: true })).toEqual({ proceed: false, refuseReason: "content_tamper" });
    expect(evaluateSealUpgrade({ known: true, tampered: false })).toEqual({ proceed: true });
  });
});

describe("DOD-UP-1 KERNEL: attemptSealUpgrade refuses unless B genuinely possesses + verified content", () => {
  it("content_tamper → NO seal_upgrade_request sent (the kernel refusal)", async () => {
    const { deps, sent } = attemptDeps({ getReadiness: () => ({ known: true, tampered: true }) });
    const r = await attemptSealUpgrade(deps, SID_HEX, UNI_FRAME());
    expect(r).toEqual({ sent: false, reason: "content_tamper" });
    expect(sent).toHaveLength(0);
  });

  it("content_unrecoverable (session unknown) → NO request sent", async () => {
    const { deps, sent } = attemptDeps({ getReadiness: () => ({ known: false, tampered: false }) });
    const r = await attemptSealUpgrade(deps, SID_HEX, UNI_FRAME());
    expect(r).toEqual({ sent: false, reason: "content_unrecoverable" });
    expect(sent).toHaveLength(0);
  });

  it("content_incomplete (B holds fewer than leaf_count-1 content leaves) → NO request sent (M1)", async () => {
    // leaf_count 3 ⇒ need 2 content leaves; B has only 1.
    const { deps, sent } = attemptDeps({ getContentLeafCount: () => 1 });
    const r = await attemptSealUpgrade(deps, SID_HEX, UNI_FRAME());
    expect(r).toEqual({ sent: false, reason: "content_incomplete" });
    expect(sent).toHaveLength(0);
  });

  it("clean + complete content → signs the ack with B's K_local and SENDS seal_upgrade_request", async () => {
    const { deps, sent } = attemptDeps({});
    const r = await attemptSealUpgrade(deps, SID_HEX, UNI_FRAME());
    expect(r).toEqual({ sent: true });
    expect(sent).toHaveLength(1);
    expect(sent[0]!["type"]).toBe("seal_upgrade_request");
    expect(sent[0]!["leaf_count"]).toBe(3);
    // The ack is a genuine B signature over the upgrade-ack TBS for R1.
    const ackTbs = buildSealUpgradeAckTbs(SID, ROOT);
    const { verify } = await import("@cello-protocol/crypto");
    expect(verify(await keyB.getPublicKey(), ackTbs, sent[0]!["ack_signature"] as Uint8Array)).toBe(true);
  });

  it("malformed notification (no leaf_count) → NO request sent", async () => {
    const { deps, sent } = attemptDeps({});
    const r = await attemptSealUpgrade(deps, SID_HEX, { session_id: SID, sealed_root: ROOT });
    expect(r.sent).toBe(false);
    expect(sent).toHaveLength(0);
  });
});

describe("DOD-UP-1 AC-008 + H1: verifyUpgradeConfirmedCert never trusts the directory's bilateral claim", () => {
  let celloDir: string;
  beforeAll(() => { celloDir = mkdtempSync(join(tmpdir(), "cello-upcert-")); });

  // A confirmed frame as the directory would build it: present=A, returning=B, B's ack over (SID,ROOT).
  async function confirmedFrame(over: Partial<Record<string, unknown>> = {}): Promise<Record<string, unknown>> {
    const ackTbs = buildSealUpgradeAckTbs(SID, ROOT);
    const bAck = new Uint8Array(await keyB.sign(ackTbs));
    return {
      type: "seal_upgrade_confirmed",
      session_id: SID, sealed_root: ROOT, leaf_count: 3, close_timestamp: 1234,
      present_pubkey: await keyA.getPublicKey(), present_signature: new Uint8Array(randomBytes(64)),
      present_signature_type: "frost",
      returning_pubkey: await keyB.getPublicKey(), returning_signature: bAck,
      seal_type: "BILATERAL",
      ...over,
    };
  }

  function verifyDeps(agentPubkeyHex: string, counterpartyHex: string | null): VerifyUpgradeConfirmedDeps & { events: LogEvent[] } {
    const { logger, events } = makeLogger();
    return { logger, agentName: "agent", agentPubkeyHex, celloDir, getCounterpartyHex: () => counterpartyHex, events };
  }

  it("valid cert (B verifying its own ack over R1, A is counterparty) → ok, party=returning", async () => {
    const d = verifyDeps(bHex, aHex);
    const r = await verifyUpgradeConfirmedCert(d, SID_HEX, await confirmedFrame());
    expect(r).toEqual({ ok: true, party: "returning" });
  });

  it("H1: unknown session (no local record) → reject unknown_session", async () => {
    const d = verifyDeps(bHex, null);
    const r = await verifyUpgradeConfirmedCert(d, SID_HEX, await confirmedFrame());
    expect(r).toEqual({ ok: false, reason: "unknown_session" });
  });

  it("H1: attacker-chosen returning_pubkey (a throwaway key, even validly signed) → reject participant_mismatch", async () => {
    // The malicious-directory attack: returning_pubkey is the attacker's key, signed by the attacker.
    const attackerAck = new Uint8Array(await attacker.sign(buildSealUpgradeAckTbs(SID, ROOT)));
    const d = verifyDeps(bHex, aHex);
    const r = await verifyUpgradeConfirmedCert(d, SID_HEX, await confirmedFrame({
      returning_pubkey: await attacker.getPublicKey(), returning_signature: attackerAck,
    }));
    expect(r).toEqual({ ok: false, reason: "participant_mismatch" });
  });

  it("AC-008: returning signature over the WRONG root → reject returning_signature_invalid", async () => {
    const wrongAck = new Uint8Array(await keyB.sign(buildSealUpgradeAckTbs(SID, new Uint8Array(randomBytes(32)))));
    const d = verifyDeps(bHex, aHex);
    const r = await verifyUpgradeConfirmedCert(d, SID_HEX, await confirmedFrame({ returning_signature: wrongAck }));
    expect(r).toEqual({ ok: false, reason: "returning_signature_invalid" });
  });

  it("present party (A) with no FROST share on disk → reject present_signature_invalid (present branch refuses on failure)", async () => {
    // self = A (present). Binding passes (present=A=self, returning=B=counterparty), returning sig valid,
    // then the present-attestation verify runs verifyUnilateralCertificate against a celloDir with no
    // share → it must REFUSE, not silently accept.
    const d = verifyDeps(aHex, bHex);
    const r = await verifyUpgradeConfirmedCert(d, SID_HEX, await confirmedFrame());
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/^present_signature_invalid:/);
  });
});
