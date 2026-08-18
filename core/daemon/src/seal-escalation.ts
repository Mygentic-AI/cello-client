/**
 * DOD-M12B-SEAL-ESCALATE-DUP-1 — the ONE unilateral escalation.
 *
 * There used to be two, and `daemon.ts`'s away/one-shot copy missed every fix this milestone made to
 * the other: the empty-carry refusal, the gappy-chain refusal, the duplicate-own-ctrl-leaf refusal,
 * and the bilateral-in-progress refusal. It spent the full timeout on each of those cases and then
 * reported `seal_unilateral_timeout` — the label that names our own wait, which is the founding
 * error-fidelity defect of this milestone. Pinned by `msg-019-one-escalation.test.ts`, which fails
 * if a second implementation appears.
 */
import type { KeyProvider } from "@cello-protocol/crypto";
import type { SessionNodeManager } from "./session-node-manager.js";
import type { UnilateralResult } from "./seal-coordinator.js";
import type { Logger } from "./types.js";

/**
 * How long to wait for the directory's answer to a `seal_unilateral` request.
 *
 * ONE number, because the two callers had their own copies of it and that is the same drift this
 * module exists to end — the away path's was a hardcoded literal that no test could shorten.
 */
export const UNILATERAL_SEAL_TIMEOUT_MS = 30_000;

export interface SealEscalationDeps {
  logger: Logger;
  sessionNodeManager: SessionNodeManager;
  sendOver: (agentName: string, frame: Record<string, unknown>) => Promise<{ ok: boolean; reason?: string }>;
  pendingUnilateralWaiters: Map<string, (r: UnilateralResult) => void>;
  sealKey: (agentName: string, sessionId: string) => string;
  getKeyProvider: (agentName: string) => KeyProvider | undefined;
  /** How long to wait for the directory's answer. */
  timeoutMs: number;
  /** Called on a completed seal, for callers holding per-session state to evict. */
  onSealed?: (agentName: string, sessionId: string) => void;
}

/**
 * DOD-M12B-INTERRUPTED-ESCALATE-1 — ask the directory to notarize with the counterparty absent.
 *
 * Extracted from the ACTIVE branch so the INTERRUPTED branch can reach it too. It could not
 * before: every exit from the interrupted branch is a `return`, so the active block below it —
 * the only place this code lived — was structurally unreachable for an interrupted session. The
 * result was that an interrupted session could never obtain a receipt, **even when a human closed
 * it by hand**: it reached `seal_interrupted_pending`, a mutually signed record nobody was ever
 * asked to notarize, and stopped there. 26 sessions sat in that state for up to 10.5 days.
 *
 * The directory enforces the delivery-grace gate and answers `seal_unilateral_too_early` with the
 * time remaining, which is returned as `retry_after_seconds` so a caller that can wait does not
 * have to be a human reading a sentence.
 */
export async function escalateToUnilateralSeal(
  deps: SealEscalationDeps,
  /** AGENT NAME, not a SessionRecord. The away path holds no record and was passing a two-field
   *  cast; only `agent_name` was ever read, so the cast bought nothing except a latent crash the
   *  first time someone here reaches for a third field. */
  agentName: string,
  sessionId: string,
  escalation: { reportedRootHex: string; sequenceNumber: number },
  correlationId: string,
  /**
   * Refuse locally when the carry cannot possibly verify, instead of spending 30 s to be told
   * nothing. ON for the two paths `submitAndEscalate` drives — the interrupted close and the
   * `seal_interrupted_pending` close — and deliberately OFF for the ACTIVE one. Those two are new
   * and are what the restart-seal resolver drives automatically for every orphan. The ACTIVE path's
   * behaviour is left exactly as it was — it has shipped and been exercised for milestones, and
   * a pre-flight refusal there could turn a seal that works today into one that does not.
   */
  opts: { refuseOnUnusableCarry: boolean } = { refuseOnUnusableCarry: false },
): Promise<
  | { ok: true; sealed_root: string; seal_type: "unilateral"; legibility?: unknown }
  | { ok: false; reason: string; retry_after_seconds?: number; guidance: string }
> {
  const { logger, sessionNodeManager, sendOver, pendingUnilateralWaiters, sealKey, getKeyProvider, onSealed } = deps;
  const UNILATERAL_TIMEOUT_MS = deps.timeoutMs;
  let resolveUni!: (r: UnilateralResult) => void;
  const uniP = new Promise<UnilateralResult>((r) => { resolveUni = r; });
  pendingUnilateralWaiters.set(sealKey(agentName, sessionId), resolveUni);
  // FED-OPTIONB-SEAL-001 (Option B): carry the full leaf chain (both parties) + the relay receipts so
  // the directory rebuilds + verifies the tree OFFLINE — no directory→relay getSealLeaves dial. The
  // store is keyed by the agent's K_local pubkey (the same key the relay client recorded under).
  const sealAgentKp = getKeyProvider(agentName);
  const sealAgentPubkeyHex = sealAgentKp ? Buffer.from(await sealAgentKp.getPublicKey()).toString("hex") : "";
  // NAMED SEPARATELY, because without it this falls through to an empty carry and answers
  // `seal_carry_empty` — "the relay released the session, the receipt is no longer obtainable",
  // which is TERMINAL in the restart-seal resolver. A local agent that is not loaded would have
  // been written off as permanent relay-side loss, with a durable give-up row to match.
  if (!sealAgentPubkeyHex) {
    pendingUnilateralWaiters.delete(sealKey(agentName, sessionId));
    return {
      ok: false,
      reason: "seal_agent_key_unavailable",
      guidance:
        "This agent's identity key is not loaded in this daemon, so the leaf chain a notarization is verified from cannot be read. Start the agent (cello_start_agent) and retry cello_close_session. Nothing about the session is lost.",
    };
  }
  const sealCarry = sessionNodeManager.getSealCarry(sealAgentPubkeyHex, sessionId);
  const seal_leaves = sealCarry.map((l) => ({
    sequence_number: l.sequenceNumber,
    leaf_kind: l.leafKind,
    structure2_cbor: l.structure2Cbor,
    structure1_cbor: l.structure1Cbor,
    // Relay receipt (present only for the present party's OWN leaves — the seq-pinning teeth).
    relay_id: l.relayId,
    relay_timestamp: l.relayTimestamp,
    relay_signature: l.relaySignatureHex ? new Uint8Array(Buffer.from(l.relaySignatureHex, "hex")) : undefined,
  }));
  // REFUSE LOCALLY FOR A LOCALLY-KNOWABLE FAILURE, rather than spending 30 s to be told nothing.
  //
  // Every directory-side refusal — `unilateral_leaves_unavailable`, `unilateral_chain_noncontiguous`,
  // `unilateral_own_leaf_unwitnessed`, `unilateral_receipt_invalid`, `unilateral_root_unverifiable`,
  // `unilateral_seal_leaf_invalid`, and the already-sealed dedup — is a bare `return` that sends
  // no frame. All seven reach the caller as `seal_unilateral_timeout`, which names our own wait:
  // the one thing that was working. That is this milestone's founding error-fidelity defect,
  // reproduced, and the restart-seal resolver now hits it automatically for every orphan.
  //
  // Two of the causes are checkable here, from the carry we are about to send, and they are the
  // dominant ones. The directory still re-checks everything — this refuses earlier and by name,
  // it does not become the authority.
  if (opts.refuseOnUnusableCarry && seal_leaves.length === 0) {
    pendingUnilateralWaiters.delete(sealKey(agentName, sessionId));
    return {
      ok: false,
      reason: "seal_carry_empty",
      guidance:
        "This side holds no relay-witnessed leaves for the session, so there is nothing the directory could rebuild the record from. That usually means the relay dropped the session (it releases one 24 hours after the last message) before it was closed. cello_transcript still shows what was said; a notarized receipt is no longer obtainable.",
    };
  }
  const sequences = seal_leaves.map((l) => l.sequence_number).sort((a, b) => a - b);
  const contiguousFromOne = sequences.every((n, i) => n === i + 1);
  if (opts.refuseOnUnusableCarry && !contiguousFromOne) {
    pendingUnilateralWaiters.delete(sealKey(agentName, sessionId));
    return {
      ok: false,
      reason: "seal_carry_noncontiguous",
      guidance:
        `The record this side holds has a gap: the relay assigned sequences ${sequences.join(", ")}, and a unilateral seal requires an unbroken chain from 1. A message the relay witnessed never reached this daemon. Try again once it arrives (cello_receive drains what the relay still holds); if it never does, only a force-abandon can end the session, and that produces no receipt.`,
    };
  }

  // A THIRD locally-knowable cause: a carry that already holds TWO of our SEAL ctrl leaves. Those
  // sessions exist right now — the one-shot submit mark has always been in memory, so any close
  // in flight across a restart could post a second before the durable recovery shipped. The
  // directory refuses them with `unilateral_seal_leaf_invalid`, silently, so each one currently
  // burns five resolver attempts and 30 s apiece before being reported as a directory timeout.
  // JUDGED FIRST, because it is the PERMANENT one. Two of our own ctrl leaves can never be
  // notarized by any directory, and a carry holding those plus the counterparty's would otherwise
  // match the bilateral check below and be answered "wait, a better receipt is coming" — for a
  // session where nothing is coming, and where the resolver would then spend five attempts
  // instead of giving up once with the truthful reason.
  const ownCtrl = sealCarry.filter((l) => l.leafKind === 0x02 && l.senderPubkeyHex === sealAgentPubkeyHex);
  if (opts.refuseOnUnusableCarry && ownCtrl.length > 1) {
    pendingUnilateralWaiters.delete(sealKey(agentName, sessionId));
    return {
      ok: false,
      reason: "seal_carry_duplicate_own_ctrl_leaf",
      guidance:
        `This session's record holds ${ownCtrl.length} SEAL control leaves from this side where it may hold exactly one, so no directory can notarize it. That happens when a close was interrupted mid-flight and a later close posted a second leaf. The conversation itself is intact — cello_transcript shows it — but a notarized receipt is no longer obtainable, and only a force-abandon can end the session.`,
    };
  }

  // WHAT THIS ACTUALLY CHECKS, and why it is deliberately NARROWER than the directory's rule.
  // The directory refuses unless there is exactly ONE ctrl leaf (`ctrlLeaves.length !== 1`). This
  // refuses only the case it can name usefully: more than one, from more than one SENDER — ours
  // plus the counterparty's. Two cases the directory still refuses and this does NOT pre-empt:
  //   zero ctrl leaves            — our own relay receipt may simply not have landed yet, so
  //                                 refusing here would be a FALSE refusal on a healthy session.
  //   >1, all authored by THEM    — not ours to explain, and not actionable by this operator.
  // The case it does catch is the responder-side normal: the relay reads two senders' leaves as
  // both parties having posted and starts a full BILATERAL seal — a better receipt than a
  // unilateral one — while this side would fire a unilateral request the directory refuses
  // silently, costing a 30-second wait to be told nothing.
  //
  // ORDER MATTERS: the duplicate-own-leaf check above runs FIRST. A carry holding two of OUR
  // leaves plus the counterparty's matches both predicates, and that session is permanently
  // unsealable — telling the operator to wait for a bilateral seal that can never land would be
  // worse than the silence this replaces.
  const allCtrl = sealCarry.filter((l) => l.leafKind === 0x02);
  if (opts.refuseOnUnusableCarry && allCtrl.length > 1 && new Set(allCtrl.map((l) => l.senderPubkeyHex)).size > 1) {
    pendingUnilateralWaiters.delete(sealKey(agentName, sessionId));
    return {
      ok: false,
      reason: "seal_carry_bilateral_in_progress",
      guidance:
        "Both parties have posted their SEAL leaf, so the relay has what it needs to notarize this BILATERALLY — a better receipt than a unilateral one, and asking for a unilateral seal now would be refused. Wait for the seal to land (cello_sessions shows the status) and read the receipt with cello_sealed_receipt.",
    };
  }

  const sent = await sendOver(agentName, {
    type: "seal_unilateral",
    session_id: new Uint8Array(Buffer.from(sessionId, "hex")),
    reported_root: new Uint8Array(Buffer.from(escalation.reportedRootHex, "hex")),
    reported_seq: escalation.sequenceNumber,
    seal_leaves,
  });
  if (!sent.ok) {
    pendingUnilateralWaiters.delete(sealKey(agentName, sessionId));
    return {
      ok: false,
      reason: "seal_unilateral_send_failed",
      guidance: "The unilateral seal request could not be sent to the directory. Check the directory connection (cello status) and retry cello_close_session.",
    };
  }
  let uniTimer!: ReturnType<typeof setTimeout>;
  const uniTimeoutP = new Promise<UnilateralResult>((r) => {
    uniTimer = setTimeout(() => r({ ok: false, reason: "seal_unilateral_timeout" }), UNILATERAL_TIMEOUT_MS);
  });
  const uniResult = await Promise.race([uniP, uniTimeoutP]);
  clearTimeout(uniTimer);
  pendingUnilateralWaiters.delete(sealKey(agentName, sessionId));
  if (uniResult.ok) {
    logger.info("session.seal.completed", { sessionId, sealedRoot: uniResult.sealedRootHex, role: "unilateral", correlationId });
    onSealed?.(agentName, sessionId); // Fix #1 review: evict the broker entry on terminal seal success (a FAILED close keeps it so a retry can still reconnect).
    // M8B FINDING-3 (cascade-2): return the legibility certificate inline — same shape as the
    // bilateral close (AC-006) — so the operator gets the receipt on the surface that proves
    // the seal, not just a bare root. It is also persisted for cello_get_sealed_receipt.
    return {
      ok: true,
      sealed_root: uniResult.sealedRootHex,
      seal_type: "unilateral",
      ...(uniResult.legibility !== undefined ? { legibility: uniResult.legibility } : {}),
    };
  }
  if (uniResult.reason === "seal_unilateral_too_early") {
    // F20: tell the operator WHEN the unilateral seal becomes available, not just "later".
    const when =
      typeof uniResult.remainingSeconds === "number"
        ? `A unilateral seal becomes available in ~${uniResult.remainingSeconds}s. `
        : "";
    return {
      ok: false,
      reason: "seal_counterparty_pending",
      // DOD-M12B-RESTART-SEAL-1: the deadline as a NUMBER, not only inside the sentence. The
      // directory tells us exactly when this becomes allowed and, until now, the only consumer of
      // that fact was English prose asking a human to come back in eleven minutes.
      ...(typeof uniResult.remainingSeconds === "number"
        ? { retry_after_seconds: uniResult.remainingSeconds }
        : {}),
      guidance: `Your SEAL leaf is recorded, but the counterparty has not closed and the directory's delivery-grace window has not yet elapsed, so a unilateral seal is not yet allowed. ${when}Retry cello_close_session after the grace period, or once the counterparty closes.`,
    };
  }
  return {
    ok: false,
    reason: uniResult.reason,
    guidance: "The unilateral seal did not complete (the directory could not verify the reported root, or the certificate failed verification). Confirm your messages reached the relay (cello_sessions) before retrying cello_close_session.",
  };
}
