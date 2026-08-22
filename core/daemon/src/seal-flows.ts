/**
 * The two seal-initiation flows that cello_close_session dispatches into.
 *
 *   handleSealInterruptedFlow — the counterparty is GONE. Exchange seal-interrupted leaves over the
 *     directory pass-through, then freeze the session at seal_interrupted_pending.
 *   handleActiveSealFlow — the counterparty is LIVE. Run the bilateral close.
 *
 * The daemon holds no FrostThresholdSigner and no directory FROST ceremony client, so it CANNOT
 * produce a threshold signature by itself. That is the sovereign-node invariant, and it is why these
 * functions only ever assemble and exchange leaves — the notarization happens at the directory.
 */
import { randomUUID } from "node:crypto";
import { buildSignedSealInterruptedLeaf, verifyCounterpartySealLeaf } from "./seal-leaf.js";
import { SignalingManager } from "@cello-protocol/transport";
import type { SealInterruptedLeaf } from "@cello-protocol/protocol-types";
import type { KeyProvider } from "@cello-protocol/crypto";
import type { SessionNodeManager } from "./session-node-manager.js";
import type { AgentInfo, Logger } from "./types.js";

/**
 * DOD-FRONTIER-STRAND-1 AC2: a failure may carry the numbers that caused it. `reason` stays the
 * machine-readable discriminator every caller already switches on; these are additive detail so an
 * operator is told WHAT disagreed rather than being sent to a counterparty that may be this same
 * daemon. All optional — a rejection from an older counterparty carries none of them.
 */
export interface SealFailureDetail {
  /** The counterparty's own refusal reason, distinct from OUR terminal `reason`. */
  rejection_reason?: string;
  your_leaf_count?: number;
  their_leaf_count?: number;
  diverging_leaf_index?: number;
}

export type SealFlowResult =
  | {
      ok: true;
      sessionId: string;
      status: "seal_interrupted_pending";
      /**
       * DOD-M12B-SEAL-BILATERAL-FIRST-1: which ceremony this commitment belongs to, when we KNOW.
       *
       * `relay_bilateral` means the counterparty told us it is on the relay's bilateral ceremony and
       * was waiting for our half — so a bilateral receipt is already coming, and asking the
       * directory to notarize with that counterparty marked ABSENT would take the worse artifact.
       * Absent means "an ordinary interrupted commitment", which escalates as usual.
       */
      ceremony?: "relay_bilateral";
    }
  | ({ ok: false; reason: string; guidance: string } & SealFailureDetail);

export type ActiveSealResult =
  | { ok: true; sessionId: string; status: "seal_interrupted_pending"; rootHex: string }
  | { ok: false; reason: string; guidance: string };

export interface SealFlowDeps {
  logger: Logger;
  sessionNodeManager: SessionNodeManager;
  agents: AgentInfo[];
  getKeyProvider: (agentName: string) => KeyProvider | undefined;
  /** This agent's directory signaling stream, or undefined if it has none. */
  signalingFor: (agentName: string) => SignalingManager | undefined;
  sendOver: (agentName: string, frame: Record<string, unknown>) => Promise<{ ok: boolean; reason?: string }>;
  /**
   * DOD-FRONTIER-STRAND-1 AC3: retain an observed mismatch so the session list can show it.
   * REQUIRED, not optional (review M4) — there is exactly one composition root, so optionality
   * buys nothing and costs the compiler's ability to catch a wiring that was never done. That is
   * precisely how the responder's missing `clearFrontierMismatch` stayed invisible.
   */
  recordFrontierMismatch: (agentName: string, sessionId: string, m: { ours: number; theirs: number; divergingLeafIndex: number }) => void;
  /** AC3: a seal that SUCCEEDS proves the frontiers agree — a stale flag would be the same defect inverted. */
  clearFrontierMismatch: (agentName: string, sessionId: string) => void;
}


/**
 * The operator-visible text for a counterparty's seal-interrupted rejection.
 *
 * Extracted from the flow so it can be TESTED. AC2 is worded about the message the INITIATOR shows
 * — "reports the ACTUAL mismatch … instead of directing the operator to ask the counterparty" — and
 * that message was previously built inline inside `handleSealInterruptedFlow`, reachable only by
 * standing up two daemons and driving a real seal exchange. So the clause the AC is actually about
 * had no test at all (review). A pure function is the honest seam.
 */
export function renderSealRejection(
  reason: string,
  sessionId: string,
  frontier?: { responder: number; initiator: number; diverging: number },
): { guidance: string } & SealFailureDetail {
  // Gated on the REASON as well as the presence of numbers (review L3). Only a
  // leaf_count_mismatch means what this narrative says; if any other reason ever arrives carrying a
  // frontier, rendering it here would explain the wrong thing confidently.
  if (frontier && reason === "leaf_count_mismatch") {
    const { responder, initiator, diverging } = frontier;
    return {
      rejection_reason: reason,
      your_leaf_count: initiator,
      their_leaf_count: responder,
      diverging_leaf_index: diverging,
      guidance:
        `The two sides disagree on how many messages this session contains: you hold ${initiator}, ` +
        `they hold ${responder}. They diverge at leaf ${diverging} — compare that message on both ` +
        `transcripts with cello_transcript ${sessionId}. A leaf that only one side recorded cannot ` +
        `be co-signed, so the session cannot seal until the records agree. If BOTH agents run on ` +
        `this machine, read both sides here; there is no other end to check.`,
    };
  }
  // M12-P14: the terminal-status refusals are the counterparty telling us the session is already
  // FINISHED on its side. Verbatim relay is right for a condition we cannot interpret; these three
  // we can, and the generic wording ("check the counterparty's daemon for that condition") sends an
  // operator hunting a fault where there is none. A sealed session in particular is a SUCCESS —
  // the receipt exists — and reporting it as a rejection to go investigate is actively wrong.
  const terminal: Record<string, string> = {
    session_abandoned:
      `The counterparty has already ABANDONED this session, so there is nothing left to co-sign — an abandon is terminal and yields no notarized receipt on either side. This is the state someone put it in deliberately (a force-close), not a fault to chase. Close it on this side too: cello_close_session ${sessionId} { force: true }. ` +
      `One check before you do: this reason is chosen by the COUNTERPARTY and is not verified here, so a bug or a version skew on their side could send it for a session that actually sealed. If you have any independent reason to think it did seal — you saw a seal complete, or an earlier close reported session_already_sealed — do not force; run cello_sealed_receipt ${sessionId} first. Force is only safe when nothing was notarized.`,
    session_already_sealed:
      `The counterparty REPORTS this session as already SEALED — it says a receipt exists on its side. That is its claim, relayed over the wire; this side has not seen or verified any such receipt, so do not repeat it to the operator as established fact. Try cello_sealed_receipt ${sessionId} rather than re-requesting a seal. ` +
      `IF THAT RETURNS not_sealed_yet, stop and read this: the seal completion never reached this side, so no local certificate was ever written and none can be produced here. Both answers are true and they point at each other — closing again will just report session_already_sealed a second time. ` +
      `Do NOT reach for cello_close_session { force: true } to escape the loop. Force PERMANENTLY forfeits this side's half, and the asymmetry is the whole point: a receipt you cannot yet verify is still recoverable, a forfeited one never is. Ask the counterparty for their sealed_root — this side holds none to compare against, which IS the divergence. Leave the session as it is and tell the operator the session id and the counterparty's pubkey: this is a known daemon defect (the seal completion is pushed with no pull twin), not an error they caused.`,
    session_seal_already_pending:
      `The counterparty has already recorded its half of this seal and is waiting on ours, so a second request cannot be answered. Do not re-send it; check cello_sessions ${sessionId} for the seal's completion.`,
  };
  // Review MEDIUM-5: `reason` comes off the wire — the counterparty's rejection, relayed verbatim
  // by the directory without validation. A plain object-literal lookup is prototype-reachable, so
  // `reason: "toString"` passes an `!== undefined` guard and returns a FUNCTION as `guidance`,
  // which serialises away and leaves the operator a rejection with no guidance at all. Own-property
  // check: a hostile or merely buggy counterparty must not be able to choose that.
  if (Object.hasOwn(terminal, reason)) {
    return { rejection_reason: reason, guidance: terminal[reason] };
  }
  // Only a leaf_count_mismatch is EXPECTED to carry the numbers, so only there is their absence
  // evidence of an older daemon. The responder rejects for five other reasons, and rendering those
  // as a version problem asserts a cause the code never observed.
  return {
    rejection_reason: reason,
    guidance: reason === "leaf_count_mismatch"
      ? `The counterparty rejected the seal-interrupted request because the two sides disagree on how many messages this session holds, but it did not report its own count — it is running an older daemon. Compare the two transcripts with cello_transcript ${sessionId}; a session strands when one side holds a leaf the other never recorded.`
      : `The counterparty rejected the seal-interrupted request: ${reason}. That is its own reason, reported verbatim — nothing here diagnoses it further. Check the counterparty's daemon for that condition; cello_transcript ${sessionId} shows this side's record if you need it.`,
  };
}

export function createSealFlows(deps: SealFlowDeps) {
  const { logger, sessionNodeManager, agents, getKeyProvider, signalingFor, sendOver, recordFrontierMismatch, clearFrontierMismatch } = deps;
  const keyProviders = { get: getKeyProvider } as { get: (a: string) => KeyProvider | undefined };

  // Seal-interrupted bilateral INITIATOR flow.
  //
  // ⚠️ SCOPE — this flow does NOT complete a FROST-notarized seal, and must not pretend to.
  //
  //   What it DOES: both parties produce and exchange real K_local Ed25519-signed SEAL-INTERRUPTED
  //   leaves over an agreed {leafCount, merkleRoot}; the initiator verifies the signature, the
  //   echoed nonce, and the cross-checks; the verified bilateral commitment is persisted; the
  //   session advances to the NON-TERMINAL 'seal_interrupted_pending' state.
  //
  //   What it does NOT do: the FROST threshold notarization. The daemon holds no
  //   FrostThresholdSigner and no directory FROST ceremony client, so it CANNOT produce a threshold
  //   seal here. The session therefore STOPS at the persisted bilateral commitment rather than
  //   claim a completed seal. Wiring the real seal means injecting a SealManager adapter.
  //
  //   Merkle-ROOT agreement is deliberately NOT compared at this layer, and the reason is still
  //   sound: under concurrent bidirectional traffic the two sides' local append orders — and
  //   therefore their roots — can legitimately diverge until the relay-assigned canonical sequence
  //   exists, so comparing roots here would reject honest sessions. leafCount agreement (each side
  //   against its own tree size, or message_count when no tree exists) is the bilateral check
  //   available at this layer.
  //
  //   ⚠️ DOD-M15-CLAIM-COMMENTS-1 — WHAT THIS COMMENT USED TO IMPLY IS NOT TRUE. It ended "true root
  //   agreement belongs to the FROST seal against the directory-held tree", which reads as *someone
  //   else checks it*. NOBODY DOES. The directory's own SEAL-leaf handler defers the same check back
  //   to the client ("deferred to a follow-on story since clients perform this verification
  //   locally"), and the client check it names does not exist — so the certified root is never
  //   compared against either party's transcript, on any path except the unilateral one.
  //
  //   Two comments deferring to each other is how the gap survived review: each half reads as a
  //   considered decision to check elsewhere, and there is no elsewhere. `DOD-M15-SEALWIRE-1` moves
  //   the bilateral root into the content-hash domain and makes the comparison a one-line check the
  //   client can actually perform; until it lands, this layer's leafCount check is the ONLY
  //   bilateral agreement there is, and it agrees on counts rather than on contents.
  //
  //   Both sides bind over their OWN tree root + size (SI-001) whenever a non-empty tree exists —
  //   e.g. reloaded from session_tree_leaves after a restart. Only sessions with no persisted tree
  //   fall back to message_count plus the caller-supplied root.

  // M7-SESSION-001 / DAEMON-004: shared bilateral ack-await machinery. The
  // interrupted-seal flow AND the active-session seal flow both send a
  // `seal_interrupted_request` and wait on the directory signaling stream for the
  // counterparty's `seal_interrupted_ack` / `seal_interrupted_rejection` (or time
  // out). Extracted so the two flows wait identically — the directory pass-through
  // routing (directory-node.ts) is the only wired transport for this exchange.
  const SEAL_INTERRUPTED_TIMEOUT_MS = 30_000;
  type SealAckResult =
    | { type: "seal_interrupted_ack"; sealInterruptedLeaf: Record<string, unknown>; nonce: string | null }
    // DOD-FRONTIER-STRAND-1 AC2: the responder's frontier numbers ride the rejection so the
    // initiator can name the mismatch instead of guessing at it. Optional — an older counterparty
    // sends the bare reason, and the renderer must degrade to the old wording rather than print
    // "undefined vs undefined".
    | { type: "seal_interrupted_rejection"; reason: string; pendingCeremony?: string; frontier?: { responder: number; initiator: number; diverging: number } }
    | { type: "timeout" };

  function awaitSealAck(sessionId: string, mgr: SignalingManager | undefined): Promise<SealAckResult> {
    return new Promise<SealAckResult>((resolve) => {
      // CONN-001: await the ack on the OWNING agent's own stream (per-agent in prod, shared in test).
      if (!mgr) { resolve({ type: "timeout" }); return; }
      const timeoutHandle = setTimeout(() => {
        unregister();
        resolve({ type: "timeout" });
      }, SEAL_INTERRUPTED_TIMEOUT_MS);

      const unregister = mgr.registerInboundHandler((frame) => {
        if (frame.type !== "seal_interrupted_ack" && frame.type !== "seal_interrupted_rejection") {
          return;
        }
        if (typeof frame.sessionId !== "string" || frame.sessionId !== sessionId) return;

        clearTimeout(timeoutHandle);
        unregister();

        if (frame.type === "seal_interrupted_ack") {
          resolve({
            type: "seal_interrupted_ack",
            sealInterruptedLeaf: (frame.sealInterruptedLeaf as Record<string, unknown>) ?? {},
            nonce: typeof frame.nonce === "string" ? frame.nonce : null,
          });
        } else {
          // Only treat the frontier detail as present when BOTH numbers are real. A half-populated
          // frame must render as "no detail", never as a mismatch with one side invented.
          // M12-P15: which ceremony the peer is actually on. ONE status covers two that need
          // opposite actions, so the initiator must never infer it — absent means do not act.
          const ceremony = typeof frame["pending_ceremony"] === "string" ? frame["pending_ceremony"] : undefined;
          const responder = frame["responder_leaf_count"];
          const initiator = frame["initiator_leaf_count"];
          const diverging = frame["diverging_leaf_index"];
          const hasFrontier = typeof responder === "number" && typeof initiator === "number";
          resolve({
            type: "seal_interrupted_rejection",
            reason: typeof frame.reason === "string" ? frame.reason : "unknown",
            ...(ceremony !== undefined ? { pendingCeremony: ceremony } : {}),
            ...(hasFrontier
              ? { frontier: { responder, initiator, diverging: typeof diverging === "number" ? diverging : Math.min(responder, initiator) } }
              : {}),
          });
        }
      });
    });
  }

  async function handleSealInterruptedFlow(
    sessionId: string,
    record: import("./types.js").SessionRecord,
    correlationId: string,
    merkleRootAtInterruption: string,
    /**
     * Send and await on THIS stream instead of the agent's home one.
     *
     * A directory routes by looking up a stream IT holds, and each daemon holds its stream to its
     * OWN home node — so a request for a counterparty homed elsewhere must be sent to THEIR node,
     * not ours. Ours logs "target offline" and answers nothing, and the 30s wait below expires.
     *
     * The close handler supplies the visiting connection it opened to the counterparty's node. A
     * visiting connection makes us REACHABLE FROM that node, which is what the active seal needs
     * (the broker pushes to us); this flow needs the other direction, and both use the same
     * connection.
     */
    via?: SignalingManager,
  ): Promise<SealFlowResult> {
    const nonce = randomUUID();

    // Retrieve the agent's own pubkey from the agent list
    // (the agent_name stored in the session record identifies which agent was in session)
    const agent = agents.find((a) => a.name === record.agent_name);
    const myPubkeyHex = agent?.pubkey ?? "";
    const counterpartyPubkey = record.counterparty_pubkey;

    // DAEMON-004 (AC-007 / SI-001 / finding #2): prefer the daemon-owned tree.
    // After a SIGKILL+restart the active session is forced to 'interrupted' and
    // its Merkle tree is reloaded from session_tree_leaves. When that reloaded
    // tree is non-empty it is the authoritative transcript: the seal binds over
    // the daemon's OWN reloaded root + size, and any caller-supplied
    // merkleRootAtInterruption is IGNORED (SI-001). Only when no tree was ever
    // persisted (legacy / pre-DAEMON-004 sessions) do we fall back to the
    // caller-supplied root and the message_count column (SESSION-001 behavior).
    const reloadedTree = sessionNodeManager.getSessionTree(record.agent_name, sessionId);
    const hasOwnTree = reloadedTree.size() > 0;
    const ownLeafCount = hasOwnTree ? reloadedTree.size() : (record.message_count ?? 0);
    const effectiveRoot = hasOwnTree
      ? sessionNodeManager.getSessionTreeRootHex(record.agent_name, sessionId)
      : merkleRootAtInterruption;

    // DB-001: check signaling status before attempting to send
    if (signalingFor(record.agent_name)?.status === "reconnecting") {
      logger.error("session.interrupted.seal.failed", {
        sessionId,
        agentName: record.agent_name,
        reason: "signaling_reconnecting",
        error: "directory_signaling_reconnecting",
        correlationId,
      });
      return {
        ok: false,
        reason: "signaling_reconnecting",
        guidance: "The directory signaling stream is reconnecting. Wait for directory_signaling to show connected in cello status before initiating seal-interrupted. The daemon reconnects automatically — no manual intervention required.",
      };
    }

    // H-1: construct and K_local-sign our OWN SEAL-INTERRUPTED leaf before sending.
    const myKeyProvider = keyProviders.get(record.agent_name);
    if (!myKeyProvider) {
      logger.error("session.interrupted.seal.failed", {
        sessionId,
        agentName: record.agent_name,
        reason: "signing_key_unavailable",
        error: "no_key_provider_for_agent",
        correlationId,
      });
      return {
        ok: false,
        reason: "signing_key_unavailable",
        guidance: "The signing key for the agent that owned this session could not be loaded. Confirm the agent's key file exists under ~/.cello/agents and restart the daemon.",
      };
    }
    const ownLeaf = await buildSignedSealInterruptedLeaf(myKeyProvider, {
      sessionId,
      leafCount: ownLeafCount,
      merkleRootAtInterruption: effectiveRoot,
      signerPubkeyHex: myPubkeyHex,
    });

    // Send SealInterruptedRequest via directory signaling
    const request = {
      type: "seal_interrupted_request",
      sessionId,
      initiatorPubkey: myPubkeyHex,
      counterpartyPubkey,
      leafCountAtInterruption: ownLeafCount,
      merkleRootAtInterruption: effectiveRoot,
      nonce,
    };

    const sendResult = via ? await via.sendRaw(request) : await sendOver(record.agent_name, request);
    if (!sendResult.ok) {
      logger.error("session.interrupted.seal.failed", {
        sessionId,
        agentName: record.agent_name,
        reason: "seal_interrupted_counterparty_unavailable",
        error: sendResult.reason,
        correlationId,
      });
      return {
        ok: false,
        reason: "seal_interrupted_counterparty_unavailable",
        guidance: "The counterparty is not currently reachable to complete the seal-interrupted flow. Retry when the counterparty is online — check their connection status via cello_status.",
      };
    }

    // Wait for counterparty ack/rejection via the shared signaling await machinery.
    const ackResult = await awaitSealAck(sessionId, via ?? signalingFor(record.agent_name));

    if (ackResult.type === "timeout") {
      logger.error("session.interrupted.seal.failed", {
        sessionId,
        agentName: record.agent_name,
        reason: "seal_interrupted_counterparty_unavailable",
        error: "seal_interrupted_response_timeout",
        correlationId,
      });
      return {
        ok: false,
        reason: "seal_interrupted_counterparty_unavailable",
        guidance: "The counterparty is not currently reachable to complete the seal-interrupted flow. Retry when the counterparty is online — check their connection status via cello_status.",
      };
    }

    if (ackResult.type === "seal_interrupted_rejection") {
      logger.error("session.interrupted.seal.failed", {
        sessionId,
        agentName: record.agent_name,
        reason: "seal_interrupted_rejected_by_counterparty",
        error: ackResult.reason,
        ...(ackResult.frontier
          ? {
            responderLeafCount: ackResult.frontier.responder,
            initiatorLeafCount: ackResult.frontier.initiator,
            divergingLeafIndex: ackResult.frontier.diverging,
          }
          : {}),
        correlationId,
      });
      // DOD-FRONTIER-STRAND-1 AC2: name the mismatch. The old text said "ask the counterparty to
      // check their interrupted sessions on their end" — which, when both agents run on ONE daemon
      // (the case that stranded session dbb93dfc… for a week), points at a machine that does not
      // exist while withholding the two numbers that identify the problem.
      if (ackResult.frontier) {
        const { responder, initiator, diverging } = ackResult.frontier;
        // AC3: the INITIATOR learns the two numbers here and must keep them too — otherwise only the
        // responder's session list shows the strand and the side that attempted the close sees
        // nothing afterwards.
        recordFrontierMismatch(record.agent_name, sessionId, {
          ours: initiator, theirs: responder, divergingLeafIndex: diverging,
        });
        // AC3 asks for a LOG EVENT, and only the responder emitted one (review M6). On a
        // two-machine strand an operator grepping the INITIATING daemon — the side that ran the
        // close and saw the failure — found nothing at all.
        logger.warn("session.frontier.mismatch", {
          sessionId,
          agentName: record.agent_name,
          role: "initiator",
          ourLeafCount: initiator,
          theirLeafCount: responder,
          divergingLeafIndex: diverging,
          correlationId,
        });
      }
      // M12-P15: the counterparty just told us which ceremony IT is on. Act on that rather than
      // dead-ending — the dead end is what left force:true (no receipt) as the only exit.
      //
      // ONLY `relay_bilateral`. A peer on the seal-interrupted ceremony has no relay SEAL ctrl leaf
      // and never will, so our leaf would be one leaf into a log that can never hold a second
      // distinct sender: the seal never completes and we would have reported ok. An ABSENT field
      // (older peer) is not a hint — it is unknown, and unknown means do not sign.
      if (ackResult.reason === "session_seal_already_pending" && ackResult.pendingCeremony === "relay_bilateral") {
        logger.info("session.seal.ceremony.realigned", {
          sessionId, agentName: record.agent_name,
          from: "seal_interrupted", to: "bilateral_cosign", because: ackResult.reason, correlationId,
        });
        const submitted = await sessionNodeManager.submitSealLeaf(record.agent_name, sessionId, correlationId);
        // `responder_seal_already_submitted` means our half is ALREADY in the relay log. The active
        // seal path treats it as success for exactly that reason; treating it as failure here told
        // the operator to retry forever (every retry re-hits the synchronous idempotency mark) while
        // forbidding the only real exit.
        if (submitted.ok || submitted.reason === "responder_seal_already_submitted") {
          // CARRY THE CEREMONY. Without it the caller cannot tell this apart from an ordinary
          // interrupted commitment and escalates milliseconds later — asking for an ABSENT-party
          // seal against a counterparty that is demonstrably present and co-operating.
          return { ok: true, sessionId, status: "seal_interrupted_pending", ceremony: "relay_bilateral" };
        }
        return {
          ok: false,
          reason: "seal_cosign_failed",
          rejection_reason: ackResult.reason,
          guidance: `The counterparty is running the relay bilateral seal and was waiting for our half, so we submitted it instead of re-requesting an interrupted seal — but the submit failed (${submitted.reason}). The session is NOT terminal: retry cello_close_session ${sessionId} once that cause is cleared.`,
        };
      }
      return {
        ok: false,
        reason: "seal_interrupted_rejected_by_counterparty",
        ...renderSealRejection(ackResult.reason, sessionId, ackResult.frontier),
      };
    }

    // ackResult.type === "seal_interrupted_ack"
    {
      const leaf = ackResult.sealInterruptedLeaf;

      // C-1 / SI-002 / SI-003: nonce (L-2), leafCount agreement, and the
      // counterparty's own Ed25519 signature are verified by the shared helper.
      // We compare against our OWN ownLeafCount (an independent value) so a real
      // divergence in transcript length is caught. Merkle-root agreement is NOT
      // verified at this leaf-exchange layer (it is the FROST-seal step's job
      // against the directory-held tree); see the H-1 SCOPE note above.
      const verified = verifyCounterpartySealLeaf({
        leaf,
        sentNonce: nonce,
        ackNonce: ackResult.nonce,
        ownLeafCount,
        expectedCounterpartyPubkey: record.counterparty_pubkey,
      });
      if (!verified.ok) {
        const reasonMap = {
          nonce_mismatch: "seal_interrupted_nonce_mismatch",
          leaf_count_mismatch: "seal_interrupted_leaf_count_mismatch",
          leaf_signature_invalid: "seal_interrupted_leaf_signature_invalid",
        } as const;
        const guidanceMap = {
          nonce_mismatch: "The counterparty's acknowledgement did not echo the expected nonce. This indicates a stale or replayed response. The session remains interrupted — retry cello_close_session.",
          leaf_count_mismatch: "The counterparty's recorded message count at interruption does not match ours. The two sides have divergent session histories and cannot form a bilateral commitment. Compare cello status on both ends before retrying.",
          leaf_signature_invalid: "The counterparty's SEAL-INTERRUPTED leaf signature did not verify. The seal flow has been aborted. The session remains interrupted — retry cello_close_session after confirming the counterparty is using a compatible version.",
        } as const;
        logger.error("session.interrupted.seal.failed", {
          sessionId,
          agentName: record.agent_name,
          reason: reasonMap[verified.reason],
          error: verified.error,
          correlationId,
        });
        return { ok: false, reason: reasonMap[verified.reason], guidance: guidanceMap[verified.reason] };
      }

      // H-1: signature + nonce + cross-checks all passed. We have a VERIFIED
      // bilateral commitment (both K_local-signed leaves over the same
      // {leafCount, merkleRoot}). Persist BOTH leaves and advance the session to
      // the NON-TERMINAL 'seal_interrupted_pending' state. We do NOT write
      // 'sealed' — the FROST threshold notarization has not run (see the H-1
      // SCOPE note above for exactly what blocks it).
      const advanced = sessionNodeManager.persistSealInterruptedCommitment({
        agentName: record.agent_name,
        sessionId,
        role: "initiator",
        ownLeaf,
        counterpartyLeaf: leaf,
        merkleRoot: effectiveRoot,
        nonce,
      });
      if (!advanced) {
        logger.error("session.interrupted.seal.failed", {
          sessionId,
          agentName: record.agent_name,
          reason: "seal_interrupted_persist_failed",
          error: "session row was not in 'interrupted' state at commit time",
          correlationId,
        });
        return {
          ok: false,
          reason: "seal_interrupted_persist_failed",
          guidance: "The bilateral commitment could not be persisted because the session was no longer in the interrupted state. Re-check cello status — it may already be pending or sealed.",
        };
      }
      logger.info("session.interrupted.pending", {
        sessionId,
        agentName: record.agent_name,
        leafCount: ownLeafCount,
        correlationId,
      });
      // AC3: the frontiers evidently agree now — drop any recorded mismatch. A flag that outlives
      // the condition is the same defect inverted: an operator told a healthy session is stranded
      // stops believing the flag, and the next real strand reads as noise.
      clearFrontierMismatch(record.agent_name, sessionId);
      return { ok: true, sessionId, status: "seal_interrupted_pending" };
    }
  }

  // ─── CELLO-M7-DAEMON-004: active-session seal initiation ─────────────────────
  //
  // Pseudocode (SPARC Phase P):
  //   1. DB-002: if signaling reconnecting → return signaling_reconnecting and do
  //      NOT initiate a partial seal that cannot be notarized.
  //   2. SI-001: read the merkle root from the daemon's OWN tree (never a caller param).
  //   3. K_local-sign a SEAL ctrl leaf over that root (SI-003: signed by our own node).
  //   4. Fire session.seal.initiated with rootHex == our own tree root, role:'initiator'.
  //   5. Submit the SEAL to the relay/counterparty + coordinate FROST via signaling,
  //      reusing the same signaling stream the interrupted-seal flow (SESSION-001) uses.
  //      The bilateral counterparty ack + FROST threshold notarization complete the
  //      seal end-to-end (AC-004, exercised under CELLO_E2E_LIVE) — the daemon never
  //      synthesizes the counterparty's signature.
  // round-2 [medium]: the IPC return status MUST match the persisted row. The
  // active-seal flow advances the session to 'seal_interrupted_pending' (the same
  // non-terminal bilateral-commitment state the interrupted flow uses); returning
  // a distinct 'seal_initiated' here meant the close response and a subsequent
  // cello_status / cello_list_sessions showed two names for one state. One name.

  async function handleActiveSealFlow(
    sessionId: string,
    record: import("./types.js").SessionRecord,
    correlationId: string,
  ): Promise<ActiveSealResult> {
    const agent = agents.find((a) => a.name === record.agent_name);
    const myPubkeyHex = agent?.pubkey ?? "";
    const kp = keyProviders.get(record.agent_name);

    // DB-002: never initiate a partial seal while signaling is reconnecting.
    if (signalingFor(record.agent_name)?.status === "reconnecting") {
      return {
        ok: false,
        reason: "signaling_reconnecting",
        guidance: "The directory signaling stream is reconnecting. Wait for directory_signaling to show connected in cello status before retrying the close. The daemon reconnects automatically.",
      };
    }

    if (!kp || !myPubkeyHex) {
      logger.error("session.seal.initiate.failed", {
        sessionId,
        reason: "signing_key_unavailable",
        errorMessage: "no key provider or pubkey for the agent that owns this session",
        correlationId,
      });
      return {
        ok: false,
        reason: "signing_key_unavailable",
        guidance: "The signing key for the agent that owns this session could not be loaded. Confirm the agent's key file exists under ~/.cello/agents and restart the daemon.",
      };
    }

    // SI-001: the root is the daemon's OWN tree root — computed from the leaves it
    // appended itself. Any caller-supplied merkleRoot is never read here.
    const ownRootHex = sessionNodeManager.getSessionTreeRootHex(record.agent_name, sessionId);
    const leafCount = sessionNodeManager.getSessionTree(record.agent_name, sessionId).size();
    const nonce = randomUUID();

    // SI-003: K_local-sign our OWN SEAL leaf over our own root. We reuse the
    // wired SEAL-INTERRUPTED leaf shape so the counterparty co-signs an identical
    // canonical form (the active and interrupted bilateral exchanges share the
    // directory pass-through routing — there is no separate `seal_request`
    // transport, and inventing one silently drops the frame at the directory).
    let ownLeaf: SealInterruptedLeaf;
    try {
      ownLeaf = await buildSignedSealInterruptedLeaf(kp, {
        sessionId,
        leafCount,
        merkleRootAtInterruption: ownRootHex,
        signerPubkeyHex: myPubkeyHex,
      });
    } catch (err: unknown) {
      logger.error("session.seal.initiate.failed", {
        sessionId,
        reason: "seal_leaf_signing_failed",
        errorMessage: err instanceof Error ? err.message : String(err),
        correlationId,
      });
      return {
        ok: false,
        reason: "seal_leaf_signing_failed",
        guidance: "The SEAL leaf could not be signed. Check the daemon logs for the signing error and confirm the agent key is intact.",
      };
    }

    // AC-003: session.seal.initiated — rootHex MUST equal the daemon's own root.
    logger.info("session.seal.initiated", {
      sessionId,
      rootHex: ownRootHex,
      role: "initiator",
      correlationId,
    });

    // Submit the SEAL request over the directory signaling stream (the SAME wired
    // pass-through the interrupted-seal flow uses) and AWAIT the counterparty's
    // bilateral ack. We never report success on a fire-and-forget send.
    const sendResult = await sendOver(record.agent_name, {
      type: "seal_interrupted_request",
      sessionId,
      initiatorPubkey: myPubkeyHex,
      counterpartyPubkey: record.counterparty_pubkey,
      leafCountAtInterruption: leafCount,
      merkleRootAtInterruption: ownRootHex,
      nonce,
    });
    if (!sendResult.ok) {
      logger.error("session.seal.initiate.failed", {
        sessionId,
        reason: sendResult.reason,
        errorMessage: sendResult.reason,
        correlationId,
      });
      return {
        ok: false,
        reason: sendResult.reason ?? "directory_unreachable",
        guidance: "guidance" in sendResult && typeof sendResult.guidance === "string"
          ? sendResult.guidance
          : "The seal could not be submitted to the directory. Retry once cello status shows directory_signaling connected.",
      };
    }

    // Wait for the counterparty's bilateral ack (or rejection / timeout).
    const ackResult = await awaitSealAck(sessionId, signalingFor(record.agent_name));
    if (ackResult.type === "timeout" || ackResult.type === "seal_interrupted_rejection") {
      const reason = ackResult.type === "timeout" ? "seal_counterparty_unavailable" : "seal_rejected_by_counterparty";
      logger.error("session.seal.initiate.failed", {
        sessionId,
        reason,
        errorMessage: ackResult.type === "timeout" ? "seal_response_timeout" : ackResult.reason,
        correlationId,
      });
      return {
        ok: false,
        reason,
        guidance: ackResult.type === "timeout"
          ? "The counterparty did not acknowledge the seal in time. Retry when they are online — check cello_status. The session remains active and usable."
          : "The counterparty rejected the seal request. Their session state may be inconsistent. Ask them to check cello status before retrying.",
      };
    }

    // SI-002 / SI-003: verify the counterparty's own-signed ack leaf over our root.
    const verified = verifyCounterpartySealLeaf({
      leaf: ackResult.sealInterruptedLeaf,
      sentNonce: nonce,
      ackNonce: ackResult.nonce,
      ownLeafCount: leafCount,
      expectedCounterpartyPubkey: record.counterparty_pubkey,
    });
    if (!verified.ok) {
      logger.error("session.seal.initiate.failed", {
        sessionId,
        reason: `seal_${verified.reason}`,
        errorMessage: verified.error,
        correlationId,
      });
      return {
        ok: false,
        reason: `seal_${verified.reason}`,
        guidance: "The counterparty's seal acknowledgement failed verification (nonce, leaf count, or signature). The session remains active — retry cello_close_session once both sides agree on the transcript.",
      };
    }

    // Verified bilateral commitment over the daemon's OWN root. Persist both
    // signed leaves and advance the session out of 'active'. As in the
    // interrupted flow, we stop at the bilateral commitment ('seal_interrupted_pending');
    // the FROST threshold notarization that finalizes 'sealed' is the deferred
    // directory step (AC-004, exercised under CELLO_E2E_LIVE).
    const advanced = sessionNodeManager.persistSealInterruptedCommitment({
      agentName: record.agent_name,
      sessionId,
      role: "initiator",
      ownLeaf,
      counterpartyLeaf: ackResult.sealInterruptedLeaf,
      merkleRoot: ownRootHex,
      nonce,
    });
    if (!advanced) {
      logger.error("session.seal.initiate.failed", {
        sessionId,
        reason: "seal_persist_failed",
        errorMessage: "session row was not in an active/interrupted state at commit time",
        correlationId,
      });
      return {
        ok: false,
        reason: "seal_persist_failed",
        guidance: "The bilateral seal commitment could not be persisted because the session changed state. Re-check cello status — it may already be pending or sealed.",
      };
    }

    // round-2 finding #5: the session is now frozen at 'seal_interrupted_pending'.
    // Retire its live libp2p node so no further inbound content can arrive (which
    // ingestReceivedContent now also rejects) and so the node is not leaked per
    // active close. retireSessionNode stops the node WITHOUT changing the DB status.
    await sessionNodeManager.retireSessionNode(record.agent_name, sessionId);

    // AC3: the frontiers evidently agree now — drop any recorded mismatch. A flag that outlives
    // the condition is the same defect inverted: an operator told a healthy session is stranded
    // stops believing the flag, and the next real strand reads as noise.
    clearFrontierMismatch(record.agent_name, sessionId);
    return { ok: true, sessionId, status: "seal_interrupted_pending", rootHex: ownRootHex };
  }
  return { awaitSealAck, handleSealInterruptedFlow, handleActiveSealFlow };
}
