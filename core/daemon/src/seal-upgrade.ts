/**
 * The returning-absent-party seal upgrade. It lives outside daemon.ts so the KERNEL (content-
 * possession gate) and the dual-attestation verify run under adversarial unit tests with the REAL
 * bodies, not just the happy path.
 *
 * When the previously-ABSENT party B returns, it RATIFIES the existing unilateral sealed root R1 (it
 * does NOT re-seal a new root). B signs an ack over CBOR([SEAL_UPGRADE_ACK_DOMAIN, session_id,
 * sealed_root]) with its K_local. The directory verifies it and writes a SUPERSEDING bilateral
 * notarization. Both parties verify the dual-attestation cert before accepting bilateral.
 */
import { Encoder } from "cbor-x";
import { verify as ed25519Verify } from "@cello-protocol/crypto";
import type { KeyProvider } from "@cello-protocol/crypto";
import type { Logger } from "./types.js";
import { verifyUnilateralCertificate } from "./session-ceremony.js";
import type { DaemonRegistrationPersistence } from "./registration-persistence.js";

/**
 * Domain separator for the upgrade-ack TBS. B's daemon and the directory MUST build byte-identical
 * bytes — same domain string, same cbor-x encoder options (tagUint8Array:false); the directory side
 * must be kept byte-identical. Domain separation prevents replay as any other CELLO signature.
 */
export const SEAL_UPGRADE_ACK_DOMAIN = "cello-seal-upgrade-ack-v1";
const UPGRADE_CBOR_ENC = new Encoder({ tagUint8Array: false });

/** The exact upgrade-ack TBS B signs / the directory + present party verify. */
export function buildSealUpgradeAckTbs(sessionId: Uint8Array, sealedRoot: Uint8Array): Uint8Array {
  return UPGRADE_CBOR_ENC.encode([SEAL_UPGRADE_ACK_DOMAIN, sessionId, sealedRoot]);
}

function toU8(v: unknown): Uint8Array | null {
  return v instanceof Uint8Array ? v : Buffer.isBuffer(v) ? new Uint8Array(v as Buffer) : null;
}

/** Verifiability of a session for B to ratify a unilateral seal — the SAME bar as the auto-ack. */
export interface SealUpgradeReadiness { known: boolean; tampered: boolean }

/**
 * THE KERNEL DECISION. B may sign its ratification ONLY when it genuinely possesses + integrity-
 * verified the content behind R1. A session B has no record of (content_unrecoverable) or whose
 * content cross-check flagged tamper (content_tamper) is REFUSED. Verified-but-disliked content is
 * NOT a refusal — disagreement ≠ unverifiable.
 */
export function evaluateSealUpgrade(
  readiness: SealUpgradeReadiness,
): { proceed: true } | { proceed: false; refuseReason: "content_unrecoverable" | "content_tamper" } {
  if (!readiness.known) return { proceed: false, refuseReason: "content_unrecoverable" };
  if (readiness.tampered) return { proceed: false, refuseReason: "content_tamper" };
  return { proceed: true };
}

export interface AttemptSealUpgradeDeps {
  logger: Logger;
  agentName: string;
  agentPubkeyHex: string;
  /** B's session verifiability for this session (SessionNodeManager.getSealUpgradeReadiness). */
  getReadiness: (agentName: string, sessionIdHex: string) => SealUpgradeReadiness;
  /**
   * The number of content leaves B holds for this session (SessionNodeManager.getSessionTree
   * (...).size()). R1 has leaf_count leaves = content leaves + A's single SEAL ctrl leaf, so B's
   * content tree must hold at least leaf_count-1 leaves or B is missing content it would over-attest.
   */
  getContentLeafCount: (agentName: string, sessionIdHex: string) => number;
  /** Recover parked content so B holds everything behind R1 before the gate (autoRecoverForAgent). */
  recoverContent: (agentName: string) => Promise<void>;
  /** B's K_local signer for this agent (keyProviders.get). */
  getKeyProvider: (agentName: string) => KeyProvider | undefined;
  /** Send a signaling frame to the directory (signaling.sendRaw). */
  sendRaw: (frame: Record<string, unknown>) => Promise<{ ok: boolean }>;
}

/**
 * THE KERNEL, wired. Recover content → consult the gate → REFUSE (no signature, no request) on
 * content_unrecoverable / content_tamper → else sign the ack over R1 with B's OWN K_local and send
 * seal_upgrade_request. Returns whether a request was sent (and the refuse reason if not) so a unit
 * test asserts the gate is genuinely consulted, not bypassed. Never throws.
 */
export async function attemptSealUpgrade(
  deps: AttemptSealUpgradeDeps,
  sessionIdHex: string,
  frame: Record<string, unknown>,
): Promise<{ sent: boolean; reason?: string }> {
  try {
    const sessionId = toU8(frame["session_id"]);
    const sealedRoot = toU8(frame["sealed_root"]);
    const leafCount = typeof frame["leaf_count"] === "number" ? frame["leaf_count"] : null;
    if (!sessionId || !sealedRoot || leafCount === null) {
      deps.logger.warn("session.seal.upgrade.refused", { sessionId: sessionIdHex, reason: "malformed_notification" });
      return { sent: false, reason: "malformed_notification" };
    }

    // B (responder) CANNOT channel-independently verify the unilateral cert's signature — that is the
    // INITIATOR's group key, which B does not hold. B accepts R1 on the AUTHENTICATED daemon↔directory
    // Noise channel (as the responder accepts session_sealed). Its real protection is the gate below;
    // a wrong R1 yields a B-ack that doesn't match A's real seal → no coherent bilateral forms.

    // Recover any parked content so B holds everything behind R1, THEN gate.
    await deps.recoverContent(deps.agentName).catch(() => { /* per-relay errors logged inside */ });
    const decision = evaluateSealUpgrade(deps.getReadiness(deps.agentName, sessionIdHex));
    if (!decision.proceed) {
      // KERNEL refusal. content_tamper is a SECURITY event (ERROR); content_unrecoverable is WARN.
      const level = decision.refuseReason === "content_tamper" ? "error" : "warn";
      deps.logger[level]("session.seal.upgrade.refused", { sessionId: sessionIdHex, reason: decision.refuseReason });
      return { sent: false, reason: decision.refuseReason };
    }

    // KERNEL completeness: B must hold the FULL content behind R1, not merely a tamper-free subset.
    // R1 = root over [content leaves..., A's SEAL ctrl leaf], so leaf_count counts the content leaves
    // + 1; B's content tree must hold >= leaf_count-1. Refuse if B recovered an INCOMPLETE transcript —
    // never over-attest to content B did not fully receive. This count gate is the bar until exact
    // root-reproduction (canonical-sequence reconciliation) lands.
    const contentLeaves = deps.getContentLeafCount(deps.agentName, sessionIdHex);
    if (contentLeaves < leafCount - 1) {
      deps.logger.warn("session.seal.upgrade.refused", {
        sessionId: sessionIdHex, reason: "content_incomplete", have: contentLeaves, need: leafCount - 1,
      });
      return { sent: false, reason: "content_incomplete" };
    }

    // KERNEL passed — sign the ack over R1 with B's OWN K_local and request the upgrade.
    const keyProvider = deps.getKeyProvider(deps.agentName);
    if (!keyProvider) {
      deps.logger.warn("session.seal.upgrade.refused", { sessionId: sessionIdHex, reason: "no_key_provider" });
      return { sent: false, reason: "no_key_provider" };
    }
    const ackTbs = buildSealUpgradeAckTbs(sessionId, sealedRoot);
    const ackSig = new Uint8Array(await keyProvider.sign(ackTbs));
    const returningPubkey = new Uint8Array(Buffer.from(deps.agentPubkeyHex, "hex"));
    const sent = await deps.sendRaw({
      type: "seal_upgrade_request",
      session_id: sessionId,
      returning_pubkey: returningPubkey,
      ack_signature: ackSig,
      // forwarded (from the notification cert) so the directory relays it → the present party rebuilds
      // the seal TBS and verifies its own attestation.
      leaf_count: leafCount,
    });
    if (!sent.ok) {
      deps.logger.warn("session.seal.upgrade.refused", { sessionId: sessionIdHex, reason: "request_send_failed" });
      return { sent: false, reason: "request_send_failed" };
    }
    deps.logger.info("session.seal.upgrade.requested", { sessionId: sessionIdHex, agentName: deps.agentName });
    return { sent: true };
  } catch (err: unknown) {
    deps.logger.warn("session.seal.upgrade.refused", {
      sessionId: sessionIdHex,
      reason: err instanceof Error ? err.message : String(err),
    });
    return { sent: false, reason: "exception" };
  }
}

export interface VerifyUpgradeConfirmedDeps {
  logger: Logger;
  agentName: string;
  agentPubkeyHex: string;
  /** DB-backed identity persistence (the FROST share for cert verification). */
  persistence: DaemonRegistrationPersistence;
  /**
   * The counterparty pubkey (hex) of the LOCAL session record for sessionIdHex, or null if this
   * agent has no such session. Binds the cert's present/returning pubkeys to the REAL participants so
   * a malicious directory cannot sign the ack with a throwaway key and force a state transition on a
   * session we are in (or push a confirmed frame for a session we never had).
   */
  getCounterpartyHex: (agentName: string, sessionIdHex: string) => string | null;
}

/**
 * Dual-attestation verify. NEVER trust the directory's "bilateral" claim.
 *
 *  - ALWAYS verify the RETURNING attestation (B's ack) over R1 — proves B genuinely ratified, catches
 *    a directory that fabricated or swapped B's signature. The load-bearing check (anyone can do it).
 *  - If THIS agent is the PRESENT party (A, holds its primary key), ALSO verify the present attestation
 *    over the rebuilt seal TBS (leaf_count-bound). The responder (B) cannot (no initiator key).
 *
 * Returns { ok:false, reason } on any malformed/forged cert — the caller must NOT mark the session
 * bilateral in that case. Returns the party so the caller can log accurately.
 */
export async function verifyUpgradeConfirmedCert(
  deps: VerifyUpgradeConfirmedDeps,
  sessionIdHex: string,
  frame: Record<string, unknown>,
): Promise<{ ok: true; party: "present" | "returning" } | { ok: false; reason: string }> {
  const sessionId = toU8(frame["session_id"]);
  const sealedRoot = toU8(frame["sealed_root"]);
  const leafCount = typeof frame["leaf_count"] === "number" ? frame["leaf_count"] : null;
  const tsRaw = frame["close_timestamp"];
  const closeTs = typeof tsRaw === "number" ? tsRaw : typeof tsRaw === "bigint" ? Number(tsRaw) : null;
  const presentPubkey = toU8(frame["present_pubkey"]);
  const presentSig = toU8(frame["present_signature"]);
  const presentSigType = frame["present_signature_type"];
  const returningPubkey = toU8(frame["returning_pubkey"]);
  const returningSig = toU8(frame["returning_signature"]);
  if (!sessionId || !sealedRoot || leafCount === null || closeTs === null || !presentPubkey ||
      !presentSig || !returningPubkey || !returningSig ||
      (presentSigType !== "frost" && presentSigType !== "single")) {
    deps.logger.warn("session.seal.upgrade.cert.invalid", { sessionId: sessionIdHex, reason: "malformed_confirmed" });
    return { ok: false, reason: "malformed_confirmed" };
  }

  // Bind the cert's present/returning pubkeys to the REAL participants of OUR session record.
  // The pair {present, returning} must equal {self, our counterparty}; otherwise a single untrusted
  // directory could sign the ack with an attacker-chosen key and drive a B-side state transition, or
  // push a confirmed frame for a session we never had. We must hold the session locally to accept.
  const presentHex = Buffer.from(presentPubkey).toString("hex");
  const returningHex = Buffer.from(returningPubkey).toString("hex");
  const selfHex = deps.agentPubkeyHex;
  const counterpartyHex = deps.getCounterpartyHex(deps.agentName, sessionIdHex);
  if (!counterpartyHex) {
    deps.logger.warn("session.seal.upgrade.cert.invalid", { sessionId: sessionIdHex, reason: "unknown_session" });
    return { ok: false, reason: "unknown_session" };
  }
  const expected = new Set([selfHex, counterpartyHex]);
  if (presentHex === returningHex || !expected.has(presentHex) || !expected.has(returningHex)) {
    deps.logger.warn("session.seal.upgrade.cert.invalid", { sessionId: sessionIdHex, reason: "participant_mismatch" });
    return { ok: false, reason: "participant_mismatch" };
  }

  // 1. Returning attestation (the returning party's ack) over R1 — the kernel check. returningPubkey
  //    is now proven to be a real participant of this session (self or counterparty), not attacker-chosen.
  const ackTbs = buildSealUpgradeAckTbs(sessionId, sealedRoot);
  if (!ed25519Verify(returningPubkey, ackTbs, returningSig)) {
    deps.logger.warn("session.seal.upgrade.cert.invalid", { sessionId: sessionIdHex, reason: "returning_signature_invalid" });
    return { ok: false, reason: "returning_signature_invalid" };
  }

  // 2. Present attestation (A's seal sig) — only the present party holds the key to verify it.
  const isPresent = selfHex === presentHex;
  if (isPresent) {
    const presentResult = await verifyUnilateralCertificate(
      { persistence: deps.persistence, agentPubkeyHex: deps.agentPubkeyHex, logger: deps.logger },
      { sessionId, sealedRoot, leafCount, closeTimestamp: closeTs, frostSignature: presentSig, signatureType: presentSigType },
    );
    if (!presentResult.ok) {
      deps.logger.warn("session.seal.upgrade.cert.invalid", { sessionId: sessionIdHex, reason: `present_signature_invalid:${presentResult.reason}` });
      return { ok: false, reason: `present_signature_invalid:${presentResult.reason}` };
    }
  }

  return { ok: true, party: isPresent ? "present" : "returning" };
}
