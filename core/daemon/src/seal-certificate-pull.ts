/**
 * DOD-TERMINAL-STATE-DIVERGENCE-1 — ask the directory for a seal certificate we were never pushed.
 *
 * `session_sealed` is pushed ONCE, over this agent's authenticated directory signaling stream. If
 * that stream is down at the instant the directory pushes, the frame is gone: the directory's
 * re-delivery queue is per-node while clients roam across nodes, so reconnecting elsewhere drains an
 * empty queue. The session IS notarized and the counterparty holds a receipt; this side holds an
 * `interrupted` row and — before this module — could never produce one.
 *
 * The result was a deadlock of two individually-true answers. `cello_close_session` reported
 * `session_already_sealed`; `cello_sealed_receipt` reported `not_sealed_yet`; each pointed at the
 * other, and the only exit an operator found was a force-abandon that PERMANENTLY forfeited this
 * side's half of a receipt that existed on the counterparty's.
 *
 * THE DIRECTORY IS NOT TRUSTED HERE. A pulled certificate is recorded only if
 * `verifyBilateralSealCertificate` accepts it — the same verifier, over the same TBS, that the push
 * path runs. A directory that altered `legibility` or `leaf_count` changes the hash and the FROST
 * signature fails. That is what makes serving this from ANY node safe, and it is why the pull adds
 * no new trust in the directory even though it adds a new thing to ask it.
 */
import { SignalingManager } from "@cello-protocol/transport";
import { verifyBilateralSealCertificate } from "./session-ceremony.js";
import type { DaemonRegistrationPersistence } from "./registration-persistence.js";
import type { SessionNodeManager } from "./session-node-manager.js";
import type { Logger } from "./types.js";

/** Bounded so a close or a receipt read cannot hang on a directory that never answers. */
const SEAL_CERTIFICATE_PULL_TIMEOUT_MS = 10_000;

export interface SealCertificatePullDeps {
  logger: Logger;
  sessionNodeManager: SessionNodeManager;
  signalingFor: (agentName: string) => SignalingManager | undefined;
  sendOver: (agentName: string, frame: Record<string, unknown>) => Promise<{ ok: boolean; reason?: string }>;
  getPersistence: (agentName: string) => DaemonRegistrationPersistence;
  getAgentPubkeyHex: (agentName: string) => string | undefined;
}

export type SealCertificatePullResult =
  /**
   * `verified` is REQUIRED, not optional, and that is the point.
   *
   * `verifyBilateralSealCertificate` returns `{ok:true, verified:false}` when this daemon holds no
   * key for the certificate's signer — a legitimate state, and no longer a rare one: clearing a
   * counterparty's pin (the remedy for the identity-refusal lockout) moves every past session with
   * them from *verified* to *taken on their word*.
   *
   * Until now the pull returned `{ok:true, rootHex}` either way, so `cello_sealed_receipt` handed
   * the agent a response byte-for-byte identical to a verified one. An operator could clear a
   * contact, pull an old receipt, and pass it to a third party as proof. It is not proof, and
   * nothing in the response said so. Making the field non-optional means a new caller cannot
   * construct this result without deciding what to tell them.
   */
  | { ok: true; rootHex: string; verified: boolean }
  /**
   * `reason` is never collapsed. Each of these sends the caller somewhere different, and the whole
   * defect class this unit belongs to is exit-point labels standing in for causes:
   *   no_signaling        — this daemon has no stream to ask over (not a statement about the seal)
   *   send_failed         — the request never left
   *   timeout             — no answer within the bound
   *   not_found           — the directory has no VERIFIABLE certificate for us on this session
   *   verification_failed — a certificate arrived and did NOT verify. Never recorded. This is the
   *                         one that means something is wrong rather than merely absent.
   */
  | { ok: false; reason: "no_signaling" | "send_failed" | "timeout" | "not_found" | "verification_failed"; detail?: string };

type PullFrame =
  | { type: "seal_certificate"; frame: Record<string, unknown> }
  | { type: "seal_certificate_error"; reason: string }
  | { type: "timeout" };

function toU8(v: unknown): Uint8Array | null {
  if (v instanceof Uint8Array) return v;
  if (Buffer.isBuffer(v)) return new Uint8Array(v as Buffer);
  return null;
}

/**
 * Pull, verify and record the certificate for one session. Returns the sealed root on success.
 *
 * Idempotent by construction: recording a certificate we already hold is a no-op at the store, and
 * the caller is expected to check for a local certificate first — this is the path for when there
 * is none.
 */
export async function pullSealCertificate(
  deps: SealCertificatePullDeps,
  agentName: string,
  sessionIdHex: string,
): Promise<SealCertificatePullResult> {
  const { logger, sessionNodeManager, signalingFor, sendOver, getPersistence, getAgentPubkeyHex } = deps;

  const mgr = signalingFor(agentName);
  if (!mgr) {
    // NOT a statement about the seal. Saying "not found" here would tell an operator their
    // conversation was never sealed because their own daemon had no stream — a false claim of the
    // exact kind this line exists to remove.
    return { ok: false, reason: "no_signaling" };
  }

  const sessionIdBytes = Uint8Array.from(Buffer.from(sessionIdHex, "hex"));

  const answer = await new Promise<PullFrame>((resolve) => {
    const timeoutHandle = setTimeout(() => {
      unregister();
      resolve({ type: "timeout" });
    }, SEAL_CERTIFICATE_PULL_TIMEOUT_MS);

    const unregister = mgr.registerInboundHandler((frame) => {
      if (frame.type !== "seal_certificate" && frame.type !== "seal_certificate_error") return;
      // Scope to THIS session — a concurrent pull for another session must not resolve this one.
      const sid = toU8(frame["session_id"]);
      if (!sid || Buffer.from(sid).toString("hex") !== sessionIdHex) return;

      clearTimeout(timeoutHandle);
      unregister();
      if (frame.type === "seal_certificate") {
        resolve({ type: "seal_certificate", frame: frame as Record<string, unknown> });
      } else {
        resolve({ type: "seal_certificate_error", reason: typeof frame["reason"] === "string" ? frame["reason"] : "unknown" });
      }
    });

    void sendOver(agentName, { type: "seal_certificate_request", session_id: sessionIdBytes }).then((r) => {
      if (r.ok) return;
      clearTimeout(timeoutHandle);
      unregister();
      resolve({ type: "seal_certificate_error", reason: `send_failed:${r.reason ?? "unknown"}` });
    });
  });

  if (answer.type === "timeout") {
    logger.warn("seal.certificate.pull.timeout", { agentName, sessionId: sessionIdHex });
    return { ok: false, reason: "timeout" };
  }
  if (answer.type === "seal_certificate_error") {
    if (answer.reason.startsWith("send_failed")) {
      logger.warn("seal.certificate.pull.send_failed", { agentName, sessionId: sessionIdHex, reason: answer.reason });
      return { ok: false, reason: "send_failed", detail: answer.reason };
    }
    logger.info("seal.certificate.pull.not_found", { agentName, sessionId: sessionIdHex, reason: answer.reason });
    return { ok: false, reason: "not_found", detail: answer.reason };
  }

  const f = answer.frame;
  const sealedRoot = toU8(f["sealed_root"]);
  const frostSignature = toU8(f["frost_signature"]);
  const signerPubkey = toU8(f["signer_pubkey"]);
  const leafCount = typeof f["leaf_count"] === "number" ? f["leaf_count"] : null;
  const closeTsRaw = f["close_timestamp"];
  const closeTimestamp = typeof closeTsRaw === "number" ? closeTsRaw : typeof closeTsRaw === "bigint" ? Number(closeTsRaw) : null;

  if (!sealedRoot || !frostSignature || !signerPubkey || leafCount === null || closeTimestamp === null) {
    // A certificate missing a TBS field cannot be verified, so it cannot be recorded. Refusing is
    // the only safe answer — recording it unverified is precisely the trust the pull must not add.
    logger.error("seal.certificate.pull.malformed", {
      agentName, sessionId: sessionIdHex,
      reason: "missing_certificate_fields",
    });
    return { ok: false, reason: "verification_failed", detail: "missing_certificate_fields" };
  }

  const agentPubkeyHex = getAgentPubkeyHex(agentName);
  if (!agentPubkeyHex) return { ok: false, reason: "verification_failed", detail: "agent_pubkey_unavailable" };

  const record = sessionNodeManager.getSessionRecord(agentName, sessionIdHex);
  const verdict = await verifyBilateralSealCertificate(
    {
      persistence: getPersistence(agentName),
      agentPubkeyHex,
      logger,
      counterpartyPrimaryHex: record?.counterparty_primary_pubkey ?? null,
    },
    {
      sessionId: sessionIdBytes,
      sealedRoot,
      leafCount,
      closeTimestamp,
      frostSignature,
      signerPubkey,
      signatureType: "frost",
      legibility: (f["legibility"] ?? null) as never,
    },
  );

  if (!verdict.ok) {
    // Tamper-evidence: do NOT record, do NOT mark the session sealed. Same posture as the push path
    // on a bad signature — a certificate that fails verification is worse than none, because
    // recording it would put a forged root behind the operator's receipt.
    logger.error("seal.certificate.pull.invalid", { agentName, sessionId: sessionIdHex, reason: verdict.reason });
    return { ok: false, reason: "verification_failed", detail: verdict.reason };
  }
  if (!verdict.verified) {
    /**
     * ACCEPTED WITHOUT VERIFICATION — and until now that was SILENT, on a path whose own header
     * claims it *"distinguishes them by VERIFYING a certificate, not by trusting an answer"*
     * (review N3).
     *
     * `verifyBilateralSealCertificate` returns `{ok:true, verified:false}` when it does not hold the
     * signer's key. That is a legitimate state — but it stopped being rare the moment
     * `cello_contact_remove` began NULLing the pin (the fix for the identity-refusal lockout). One
     * operator action silently moved every past session with that counterparty from *verified* to
     * *taken on trust*, and nothing said so.
     *
     * Forgetting a counterparty's identity genuinely DOES cost the ability to verify their old
     * certificates — the key was thrown away on purpose. The defect was never the cost; it was that
     * the cost was invisible while a comment two files away promised the opposite. The certificate
     * is still recorded (it arrived over an authenticated channel), and the operator is now told
     * what they are holding.
     */
    logger.warn("seal.certificate.pull.unverified", {
      agentName,
      sessionId: sessionIdHex,
      reason: verdict.reason,
      impact:
        "this certificate was accepted without checking its signature, because this daemon holds no key for its signer — most often because the counterparty's pinned identity was cleared by cello_contact_remove. The sealed root is recorded on the counterparty's word, not on a verified signature",
      guidance:
        "if you need this receipt to be independently verifiable, ask the counterparty to re-seal, or re-establish a session with them first so their identity is pinned again",
    });
  }

  const rootHex = Buffer.from(sealedRoot).toString("hex");
  const legibility = f["legibility"];
  if (legibility !== undefined && legibility !== null) {
    try {
      sessionNodeManager.recordSealCertificate(agentName, sessionIdHex, rootHex, JSON.stringify(legibility));
    } catch (error) {
      logger.warn("seal.certificate.persist.failed", {
        sessionId: sessionIdHex,
        reason: error instanceof Error ? error.message : String(error),
      });
    }
  }

  logger.info("seal.certificate.pull.recovered", {
    agentName,
    sessionId: sessionIdHex,
    sealedRoot: rootHex,
    verified: verdict.verified,
    // The impact line said "provable" unconditionally, which is FALSE in exactly the branch above:
    // an unverified certificate is recorded on the counterparty's word and proves nothing to a
    // third party. A claim that is true on the common path and false on the dangerous one is worse
    // than no claim, because it reads as reassurance precisely when reassurance is unwarranted.
    impact: verdict.verified
      ? "a seal this side never received the push for is now local, and its signature was checked"
      : "a seal this side never received the push for is now local, but its signature was NOT checked — it is recorded on the counterparty's word",
  });

  // STATUS FIRST AND SYNCHRONOUS, teardown second — the same terminal transition the push path
  // makes, so a pulled seal and a pushed one leave the daemon in identical states.
  //
  // The comment here used to credit `destroySessionNode` with marking the row. It does not when the
  // session has no live node — it returns early at `if (!entry) return` and writes the status below
  // that guard — and THIS path is precisely the no-node case: a daemon pulls a certificate exactly
  // when it was down or disconnected while the seal happened.
  try { sessionNodeManager.markSealed(agentName, sessionIdHex); }
  catch (err: unknown) {
    logger.error("session.seal.status.write.threw", {
      sessionId: sessionIdHex, agentName,
      error: err instanceof Error ? err.message : String(err),
      impact: verdict.verified
        ? "the certificate was pulled and verified, but this row still reads interrupted"
        : "the certificate was pulled (signature NOT checked), but this row still reads interrupted",
    });
  }
  void sessionNodeManager.destroySessionNode(agentName, sessionIdHex, "sealed");

  return { ok: true, rootHex, verified: verdict.verified };
}
