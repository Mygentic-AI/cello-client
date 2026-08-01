/**
 * The inbound seal-interrupted REQUEST: the counterparty went away, and the other side is asking us
 * to co-sign the seal of a session neither of us can finish normally.
 *
 * We answer with our OWN signed leaf, or with a rejection naming the exact mismatch (nonce,
 * leaf count, signature). We never sign a leaf whose content we cannot corroborate — a
 * seal-interrupted ack is a cryptographic statement about what was said, not a courtesy.
 */
import { randomUUID } from "node:crypto";
import type { KeyProvider } from "@cello-protocol/crypto";
import type { SessionNodeManager } from "./session-node-manager.js";
import type { AgentInfo, Logger } from "./types.js";
import { buildSignedSealInterruptedLeaf } from "./seal-leaf.js";

export interface InboundSealRequestDeps {
  logger: Logger;
  sessionNodeManager: SessionNodeManager;
  agents: AgentInfo[];
  getKeyProvider: (agentName: string) => KeyProvider | undefined;
  sendOver: (agentName: string, frame: Record<string, unknown>) => Promise<{ ok: boolean; reason?: string }>;
  /** DOD-FRONTIER-STRAND-1 AC3: retain an observed mismatch so the session list can show it. */
  recordFrontierMismatch?: (agentName: string, sessionId: string, m: { ours: number; theirs: number; divergingLeafIndex: number }) => void;
}

export function createInboundSealRequestHandler(deps: InboundSealRequestDeps) {
  const { logger, sessionNodeManager, agents, getKeyProvider, sendOver, recordFrontierMismatch } = deps;

  // ─── M7-SESSION-001 (H-1): seal-interrupted bilateral RESPONDER ────────────
  //
  // A PERSISTENT inbound handler (registered once, below) that reacts to inbound
  // `seal_interrupted_request` frames from a counterparty. It validates local
  // state, K_local-signs this node's SEAL-INTERRUPTED leaf (co-signing the same
  // Merkle root the initiator sent), echoes the nonce, includes initiatorPubkey
  // for directory routing, persists the responder side of the commitment, moves
  // the session to 'seal_interrupted_pending', and returns a seal_interrupted_ack.
  // On any inconsistent local state it returns a seal_interrupted_rejection.
  async function handleInboundSealInterruptedRequest(frame: Record<string, unknown>): Promise<void> {
    const correlationId = randomUUID();
    const sessionId = typeof frame["sessionId"] === "string" ? frame["sessionId"] : null;
    const initiatorPubkey = typeof frame["initiatorPubkey"] === "string" ? frame["initiatorPubkey"] : null;
    const counterpartyPubkey = typeof frame["counterpartyPubkey"] === "string" ? frame["counterpartyPubkey"] : null;
    const leafCountReq = typeof frame["leafCountAtInterruption"] === "number" ? frame["leafCountAtInterruption"] : null;
    const merkleRootReq = typeof frame["merkleRootAtInterruption"] === "string" ? frame["merkleRootAtInterruption"] : "";
    const nonce = typeof frame["nonce"] === "string" ? frame["nonce"] : null;

    // Cannot even route a rejection without sessionId + initiatorPubkey.
    if (!sessionId || !initiatorPubkey || !counterpartyPubkey || nonce === null || leafCountReq === null) {
      logger.warn("session.interrupted.request.malformed", {
        correlationId,
        hasSessionId: sessionId !== null,
        hasInitiatorPubkey: initiatorPubkey !== null,
      });
      return;
    }

    // DOD-FRONTIER-STRAND-1 AC2: a rejection may carry the numbers that caused it.
    //
    // The RESPONDER is the only party that ever sees both frontiers — it holds its own tree and
    // receives the initiator's claimed count in the request. It used to compare them and then throw
    // the comparison away, sending the bare word "leaf_count_mismatch". The initiator, which knows
    // only its own side, then told the operator to go ask the counterparty. When both agents live on
    // ONE daemon (the loopback case that produced session dbb93dfc…, stranded for a week) there is
    // no counterparty to ask and no second machine to check: the advice was unfollowable and the one
    // fact that would have solved it in a minute was discarded here.
    const reject = async (reason: string, detail?: Record<string, number>): Promise<void> => {
      // CONN-001: send the rejection over the LOCAL responder agent's own stream (the agent whose
      // pubkey is counterpartyPubkey — the stream this request arrived on). If unresolved, sendOver
      // reports a send failure rather than throwing.
      // review F5: detail is spread FIRST so the fixed fields always win. Spread last, a future
      // caller passing `{ reason: 1 }` would silently overwrite the machine-readable discriminator
      // every consumer switches on — a footgun with no error, only a wrong answer.
      const sent = await sendOver(agents.find((a) => a.pubkey === counterpartyPubkey)?.name ?? "", {
        ...(detail ?? {}),
        type: "seal_interrupted_rejection",
        sessionId,
        initiatorPubkey,
        reason,
      });
      // fallback-finder LOW: don't log the rejection as delivered when the send failed (e.g. no local
      // agent for counterpartyPubkey, or a transient send error) — the counterparty would otherwise
      // appear rejected but only ever see a timeout.
      if (sent.ok) {
        logger.warn("session.interrupted.request.rejected", { sessionId, reason, correlationId });
      } else {
        logger.warn("session.interrupted.request.rejection.send.failed", { sessionId, reason, sendReason: sent.reason, correlationId });
      }
    };

    // DOD-LOOP-1: resolve the addressed local agent FIRST — the composite (agent, session_id) key
    // needs it. The request must be addressed to one of our agents (counterpartyPubkey is OUR
    // pubkey from the initiator's perspective).
    const localAgent = agents.find((a) => a.pubkey === counterpartyPubkey);
    if (!localAgent) { await reject("unknown_counterparty"); return; }

    const localRecord = sessionNodeManager.getSessionRecord(localAgent.name, sessionId);
    if (!localRecord) { await reject("session_not_found"); return; }
    // DAEMON-004: an 'active' session is eligible too (the active-session seal
    // reuses this exchange). We still never re-process a terminal 'sealed' row or
    // an already-pending one.
    if (localRecord.status !== "interrupted" && localRecord.status !== "active") {
      await reject("session_not_interrupted");
      return;
    }
    // From our perspective the initiator is our counterparty.
    if (localRecord.counterparty_pubkey !== initiatorPubkey) { await reject("initiator_mismatch"); return; }

    // DAEMON-004 (SI-001): we sign over OUR OWN daemon-owned tree, never the
    // initiator-supplied root.
    //
    // round-2 finding #6: for an ACTIVE session the daemon ALWAYS binds its own tree
    // root — even the canonical EMPTY-tree root when no content has flowed — never the
    // initiator-supplied `merkleRootReq`. Echoing the caller's root would let an
    // initiator dictate the root a responder signs (the SI-001 trust hole). Only a
    // LEGACY 'interrupted' session that predates DAEMON-004 (no tree ever persisted)
    // falls back to message_count + the supplied root (SESSION-001 behavior).
    const ownTree = sessionNodeManager.getSessionTree(localAgent.name, sessionId);
    const isActive = localRecord.status === "active";
    const useOwnTree = isActive || ownTree.size() > 0;
    const ownLeafCount = useOwnTree ? ownTree.size() : (localRecord.message_count ?? 0);
    const ownRoot = useOwnTree ? sessionNodeManager.getSessionTreeRootHex(localAgent.name, sessionId) : merkleRootReq;

    // SI-002/AC-008: leaf-count agreement against our own state.
    if (ownLeafCount !== leafCountReq) {
      // AC2: carry BOTH frontiers and the first index where they can differ. The diverging index is
      // the lower count — leaf indices are contiguous from 0, so the shorter side simply stops
      // there, and that leaf is the one an operator should read on both transcripts. (Which side is
      // longer is not assumed: either can be, depending on which one failed to record.)
      const diverging = Math.min(ownLeafCount, leafCountReq);
      logger.warn("session.frontier.mismatch", {
        sessionId,
        agentName: localAgent.name,
        responderLeafCount: ownLeafCount,
        initiatorLeafCount: leafCountReq,
        divergingLeafIndex: diverging,
        correlationId,
      });
      // AC3: keep it. Without this the refusal is a transient string in one command's output, and
      // the session goes back to looking exactly like a healthy paused one.
      recordFrontierMismatch?.(localAgent.name, sessionId, {
        ours: ownLeafCount, theirs: leafCountReq, divergingLeafIndex: diverging,
      });
      await reject("leaf_count_mismatch", {
        responder_leaf_count: ownLeafCount,
        initiator_leaf_count: leafCountReq,
        diverging_leaf_index: diverging,
      });
      return;
    }

    const kp = getKeyProvider(localAgent.name);
    if (!kp) { await reject("signing_key_unavailable"); return; }

    // Co-sign our SEAL-INTERRUPTED leaf. When we hold our own tree the root is
    // ours (SI-001); otherwise we echo the initiator-supplied root unchanged.
    const ownLeaf = await buildSignedSealInterruptedLeaf(kp, {
      sessionId,
      leafCount: ownLeafCount,
      merkleRootAtInterruption: ownRoot,
      signerPubkeyHex: counterpartyPubkey,
    });

    // Persist the responder side of the bilateral commitment. The responder never
    // receives the initiator's leaf in this request→ack protocol, so it records
    // only its own signed leaf plus the agreed root; the full both-leaves artifact
    // lives on the initiator side. Advances status interrupted → seal_interrupted_pending.
    sessionNodeManager.persistSealInterruptedCommitment({
      agentName: localAgent.name,
      sessionId,
      role: "responder",
      ownLeaf,
      counterpartyLeaf: null,
      merkleRoot: ownRoot,
      nonce,
    });

    const ack = {
      type: "seal_interrupted_ack",
      sessionId,
      initiatorPubkey,
      nonce,
      sealInterruptedLeaf: ownLeaf,
    };
    const sendResult = await sendOver(localAgent.name, ack);
    if (!sendResult.ok) {
      logger.error("session.interrupted.ack.send.failed", {
        sessionId,
        agentName: localAgent.name,
        reason: sendResult.reason,
        correlationId,
      });
      return;
    }
    logger.info("session.interrupted.responder.acked", {
      sessionId,
      agentName: localAgent.name,
      leafCount: ownLeafCount,
      correlationId,
    });
  }

  return { handleInboundSealInterruptedRequest };
}
