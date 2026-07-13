import { buildSignedSealInterruptedLeaf, verifyCounterpartySealLeaf } from "./seal-leaf.js";
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
import { SignalingManager } from "@cello-protocol/transport";
import type { SealInterruptedLeaf } from "@cello-protocol/protocol-types";
import type { KeyProvider } from "@cello-protocol/crypto";
import type { SessionNodeManager } from "./session-node-manager.js";
import type { AgentInfo, Logger } from "./types.js";

export type SealFlowResult =
  | { ok: true; sessionId: string; status: "seal_interrupted_pending" }
  | { ok: false; reason: string; guidance: string };

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
}

export function createSealFlows(deps: SealFlowDeps) {
  const { logger, sessionNodeManager, agents, getKeyProvider, signalingFor, sendOver } = deps;
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
  //   Merkle-ROOT agreement is deliberately NOT compared at this layer. Under concurrent
  //   bidirectional traffic the two sides' local append orders — and therefore their roots — can
  //   legitimately diverge until the relay-assigned canonical sequence exists. Comparing roots here
  //   would reject honest sessions. leafCount agreement (each side against its own tree size, or
  //   message_count when no tree exists) is the bilateral check available at this layer; true root
  //   agreement belongs to the FROST seal against the directory-held tree.
  //
  //   Both sides bind over their OWN tree root + size (SI-001) whenever a non-empty tree exists —
  //   e.g. reloaded from session_tree_leaves after a restart. Only sessions with no persisted tree
  //   fall back to message_count plus the caller-supplied root.
  // Result type for handleSealInterruptedFlow — maps to the MCP tool response shape.

  // M7-SESSION-001 / DAEMON-004: shared bilateral ack-await machinery. The
  // interrupted-seal flow AND the active-session seal flow both send a
  // `seal_interrupted_request` and wait on the directory signaling stream for the
  // counterparty's `seal_interrupted_ack` / `seal_interrupted_rejection` (or time
  // out). Extracted so the two flows wait identically — the directory pass-through
  // routing (directory-node.ts) is the only wired transport for this exchange.
  const SEAL_INTERRUPTED_TIMEOUT_MS = 30_000;
  type SealAckResult =
    | { type: "seal_interrupted_ack"; sealInterruptedLeaf: Record<string, unknown>; nonce: string | null }
    | { type: "seal_interrupted_rejection"; reason: string }
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
          resolve({
            type: "seal_interrupted_rejection",
            reason: typeof frame.reason === "string" ? frame.reason : "unknown",
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

    const sendResult = await sendOver(record.agent_name, request);
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
    const ackResult = await awaitSealAck(sessionId, signalingFor(record.agent_name));

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
        correlationId,
      });
      return {
        ok: false,
        reason: "seal_interrupted_rejected_by_counterparty",
        guidance: "The counterparty rejected the seal-interrupted request. This may indicate their session state is inconsistent. Ask the counterparty to check their interrupted sessions via cello status on their end.",
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

    return { ok: true, sessionId, status: "seal_interrupted_pending", rootHex: ownRootHex };
  }
  return { awaitSealAck, handleSealInterruptedFlow, handleActiveSealFlow };
}
