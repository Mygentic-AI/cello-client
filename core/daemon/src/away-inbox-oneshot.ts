/**
 * `DOD-INBOX-ONESHOT-1` — an away agent's inbox accepts ONE message, then closes itself.
 *
 * ─── What this restores, and why it was missing ────────────────────────────────────────────────
 *
 * The away reply tells the caller, in its own words, that this inbox "accepts one message per
 * visit — please close the session now". Nothing enforced that. A caller who kept talking was
 * talking into an empty room, and the session stayed open indefinitely with no operator anywhere
 * near it.
 *
 * It was enforced once. `DOD-M15-AWAYSCOPE-1` (2026-09-12) deleted the branch that answered
 * mid-conversation messages with the away GREETING — correctly: that greeting took a hash-chain
 * leaf in a live exchange and made the receipt unobtainable. But the one-shot rejection and the
 * seal it initiated lived in the same branch and went with it, and that half was not the defect.
 * Its own commit said so: "deleting the wrong one of the two mechanisms is the whole risk here".
 *
 * So the termination is back, on its own, in its own file, where it cannot be confused with the
 * greeting. It NEVER sends the away text. It sends one closing line and seals.
 *
 * ─── Why the close is a real message and a real seal ───────────────────────────────────────────
 *
 * Because an inbound message is an attack surface, and an away agent's record of it must obey the
 * same rules as everything else: the rejection is signed, ordered by the relay, and takes its leaf.
 * A "quiet" close that left no record would be the one conversation in the system with no evidence.
 *
 * ⚠️ IT PLACES ITS OWN LEAVES, so this file belongs in the seal call-site enforcer's CALLERS list.
 *
 * ─── The rule that stops two machines sealing a conversation nobody had ────────────────────────
 *
 * When both agents are away, each side's auto-reply lands on the other as an inbound message. Left
 * alone, the one-shot fires on BOTH sides, each posts a SEAL ctrl leaf, and two distinct-sender
 * ctrl leaves is exactly what notarizes a session. Measured from the relay's own log 2026-08-09: a
 * session sealed THREE SECONDS after opening, its entire content two machines telling each other
 * nobody was home, while both operators went on believing it was live.
 *
 * So a message carrying the auto-reply marker is never answered and never counted. The narrow rule
 * — suppress a machine answering a machine — is the correct one. The broad rule ("never notarize a
 * session where we only sent away traffic") was tried and reverted: it also disabled closing the
 * inbox on a real caller who ignores the instruction, which is the behaviour this file exists for.
 *
 * ⚠️ THE MARKER IS TEXT, SO IT IS ADVISORY — say it rather than imply a rule. It is a token at the
 * front of the message body, not a signed frame field, so any caller who types it is never counted
 * and never closed on. What that buys them is the PRE-FIX behaviour: the session stays open until
 * the operator returns. It buys them no leaf, no seal, no reply and nothing this side would not
 * otherwise have given them. Closing that off means carrying the flag in the frame beside the text,
 * which is a wire change on both sides and is not worth it for an opt-out into waiting longer.
 */
import { randomUUID } from "node:crypto";
import type { KeyProvider } from "@cello-protocol/crypto";
import type { Logger, SessionRecord } from "./types.js";
import type { SessionNodeManager } from "./session-node-manager.js";
import type { ActiveSealResult } from "./seal-flows.js";
import type { SealCompletion, UnilateralResult } from "./seal-coordinator.js";
import { markAsAutoReply, isAutoReplyMarked } from "./away-detection.js";
import { isLocalCredentialRefusal, LEAF_KIND_MSG } from "./session-relay-client.js";
import { sentAuthorship } from "./session-content-handlers.js";
import { escalateToUnilateralSeal as runUnilateralEscalation, UNILATERAL_SEAL_TIMEOUT_MS } from "./seal-escalation.js";
import type { SendClaims } from "./send-claims.js";

/** The one line this file ever sends. Marked as machine-generated; [[WRAP]] stays at the END. */
const ONESHOT_REJECT_TEXT = "This inbox only accepts one message per visit. Closing. [[WRAP]]";

export interface AwayInboxOneshotDeps {
  logger: Logger;
  sessionNodeManager: SessionNodeManager;
  /**
   * Sends on the wire right now — the half `weSpoke` cannot see.
   *
   * An outbound transcript row is written AFTER the send resolves, so for the whole round trip of
   * an operator's reply there is a human speaking and no record of it. Reading `weSpoke` in that
   * window answers "nobody spoke here" about a live conversation, and this path is terminal.
   */
  sendClaims: SendClaims;
  /**
   * The away wiring's own guard set, shared rather than copied: this file must fire only for a
   * session that was ACTUALLY told "one message per visit", and that set is what records it. It
   * also carries our own once-only key, so re-attending an agent re-arms both together (the
   * `${name}:` sweep in agent-handlers.ts clears them as one).
   */
  awayAckSent: Set<string>;
  keyProviders: Map<string, KeyProvider>;
  /** The seal machinery this hands off to once the conversation is closed. */
  sealKey: (agentName: string, sessionId: string) => string;
  sealInterruptedInProgress: Set<string>;
  pendingSealWaiters: Map<string, (completion: SealCompletion) => void>;
  pendingUnilateralWaiters: Map<string, (r: UnilateralResult) => void>;
  sendOver: (agentName: string, frame: Record<string, unknown>) => Promise<{ ok: boolean; reason?: string }>;
  handleActiveSealFlow: (sessionId: string, record: SessionRecord, correlationId: string) => Promise<ActiveSealResult>;
}

export function createAwayInboxOneshot(deps: AwayInboxOneshotDeps): {
  closeInboxIfIgnored: (agentName: string, sessionId: string) => Promise<void>;
} {
  const {
    logger, sessionNodeManager, sendClaims, awayAckSent, keyProviders,
    sealKey, sealInterruptedInProgress, pendingSealWaiters, pendingUnilateralWaiters,
    sendOver, handleActiveSealFlow,
  } = deps;

  /**
   * Their messages, counted from the DURABLE transcript rather than an arrival buffer.
   *
   * The in-memory buffer this used to peek at is deliberately gone (see the note in
   * session-node-manager.ts): it held the plaintext of every live conversation in daemon memory for
   * nobody. The transcript is what production serves and what the operator reads, so counting there
   * also means a restart mid-visit does not reset the caller's allowance.
   *
   * Auto-replies are excluded from the count AND cannot be the trigger — see the header.
   */
  function readSession(agentName: string, sessionId: string): { theirCount: number; latest: string | null; weSpoke: boolean } {
    const { messages } = sessionNodeManager.readTranscript(agentName, sessionId);
    let theirCount = 0;
    let latest: string | null = null;
    let weSpoke = false;
    for (const m of messages) {
      if (m.direction === "sent") {
        // ANYTHING of ours that is not the greeting means a human spoke here. See `weSpoke` at the
        // call site: it is the line between an answering machine and a conversation.
        if (!isAutoReplyMarked(m.text)) weSpoke = true;
        continue;
      }
      if (m.direction !== "received") continue;
      // `latest` is the last thing they sent WHATEVER it was, because the auto-reply case is a
      // decision this makes (never answer a machine), not one it can make by never seeing it.
      latest = m.text;
      if (isAutoReplyMarked(m.text)) continue;
      theirCount += 1;
    }
    return { theirCount, latest, weSpoke };
  }

  async function closeInboxIfIgnored(agentName: string, sessionId: string): Promise<void> {
    /**
     * THIS IS THE AWAY CASE AND ONLY THE AWAY CASE — the session was answered by the machine at the
     * door, because nobody was at the desk OR because this caller's tier says do not engage (a
     * private agent, which IS attended and still away). The greeting having REACHED the caller is
     * what says so, and it is why attendance is not consulted here: the tier case would fail an
     * attendance test while being exactly the case this exists for.
     *
     * ⚠️ `:greeted`, NEVER `:request`. The latter is set before the send and stays set when the
     * outbound screen blocks the greeting — so keying on it would close a visit on a caller who was
     * never told the rule they are being held to.
     *
     * A conversation that was under way when someone dropped is a DIFFERENT case with its own
     * machinery (recovery and the relay mailbox). Nothing here may reach it — see `weSpoke`.
     */
    if (!awayAckSent.has(`${agentName}:${sessionId}:greeted`)) return;

    const rejectedKey = `${agentName}:${sessionId}:rejected`;
    if (awayAckSent.has(rejectedKey)) return;

    const { theirCount, latest, weSpoke } = readSession(agentName, sessionId);
    if (latest === null) return;
    /**
     * ⚠️ THE LINE PRINCIPLE 4 DRAWS, AND THE WHOLE REASON THIS IS SAFE TO SHIP.
     *
     * "A session with nobody live must not be terminal" was ruled on 2026-09-11 after a machine
     * greeting took a leaf MID-CONVERSATION and cost a completed exchange its receipt. That ruling
     * is about a conversation. If this side has said anything of its own, a human was here, and the
     * machine does not get to end it — the party who comes back closes, per principle 8.
     *
     * A session whose only outbound line is the greeting is not a conversation. Nobody had it, and
     * closing it destroys nothing.
     */
    if (weSpoke) return;
    // A send whose transcript row failed is a message this side made that the transcript cannot
    // show. "Cannot tell" is not "nobody spoke", and only one of those may end a session.
    if (sendClaims.rowMissing(agentName, sessionId)) {
      logger.warn("session.away.inbox.oneshot.skipped_unreadable_record", {
        agentName, sessionId,
        impact: "this side sent something the transcript does not hold, so whether a human spoke here cannot be decided — the visit is left open",
      });
      return;
    }
    // AND the same question for a reply that is on the wire but not yet on disk. Without this, the
    // window between `sendContent` resolving and its transcript row being written reads as silence.
    if (sendClaims.held(agentName, sessionId)) {
      logger.info("session.away.inbox.oneshot.skipped_send_in_flight", {
        agentName, sessionId,
        impact: "a reply from this side is on the wire, so this is a conversation — the visit is not closed",
      });
      return;
    }
    // THE ARRIVAL ITSELF IS A MACHINE'S: never answered, never counted, and checked before the
    // count so two away agents cannot reach the seal below by trading greetings.
    if (isAutoReplyMarked(latest)) {
      logger.info("session.away.mutual.skipped", {
        agentName, sessionId,
        impact: "no one-shot close — two away agents must not notarize a conversation nobody had",
      });
      return;
    }
    // Their one message has arrived, so the visit is over. Waiting for a SECOND would be a shop that
    // locks up only when someone tries the handle after closing time.
    if (theirCount < 1) return;
    // They are closing of their own accord — let the ordinary seal proceed, and do not spend the
    // one-shot on it. Matched at the END, because DOD-SIGNAL-TOKEN-1 appends the real token there
    // and a substring match would read a mere mention of the token as a close.
    if (latest.trimEnd().endsWith("[[WRAP]]")) {
      logger.info("session.away.inbox.oneshot.skipped_wrap", { agentName, sessionId });
      return;
    }

    awayAckSent.add(rejectedKey); // guard BEFORE async work — concurrent arrivals must not re-enter
    const record = sessionNodeManager.getSessionRecord(agentName, sessionId);
    if (!record || record.status !== "active") return;

    const rejectText = markAsAutoReply(ONESHOT_REJECT_TEXT);
    const rejectBytes = new TextEncoder().encode(rejectText);
    // One decision point for the hash AND its algorithm — see `contentHashForSession`.
    const reject = await sessionNodeManager.contentHashForSession(agentName, sessionId, rejectBytes);
    // Best-effort: a send failure still triggers the seal — we are closing regardless.
    const sendResult = await sessionNodeManager.sendContent(
      agentName, sessionId, rejectBytes, new Uint8Array(reject.hash), randomUUID(), LEAF_KIND_MSG, reject.alg,
    );
    if (sendResult.ok || sendResult.durable) {
      // At the RELAY's position, not the tail, and committed when the send went out OR was durably
      // queued — either way the relay already witnessed its sequence. This is the sharpest case of
      // that rule in the codebase: the seal is initiated a few lines below, so a leaf at the wrong
      // index seals a tree the counterparty can never agree with.
      const placed = sessionNodeManager.placeOwnLeaf(
        agentName, sessionId, Buffer.from(reject.hash).toString("hex"), rejectBytes,
        sendResult.sequenceNumber, randomUUID(), "msg", sentAuthorship(sendResult),
      );
      if (placed.placed) {
        sessionNodeManager.recordTranscriptMessage(agentName, sessionId, placed.leafIndex, "sent", rejectBytes, randomUUID(), sentAuthorship(sendResult));
      }
      logger.info("session.away.inbox.oneshot.rejected", {
        agentName, sessionId, sequenceNumber: placed.placed ? placed.leafIndex : placed.heldAt,
        committed: placed.placed, queued: !sendResult.ok,
      });
    } else {
      // Not queued anywhere — the rejection is gone. We still seal (we are closing regardless), and
      // the counterparty simply never learns why, so say that plainly.
      logger.error("session.away.inbox.oneshot.reject_send_failed", {
        agentName, sessionId, reason: sendResult.reason, cause: sendResult.cause,
        impact: "the rejection is lost and was NOT queued — the session seals with no explanation to the counterparty",
      });
    }

    /**
     * The divergence gate has to hold on the path with no operator. `cello_close_session` refuses a
     * diverged record; this autonomous path must too, and the LOG is its whole surface because
     * there is no caller awaiting an answer.
     */
    /**
     * ASKED AGAIN, BECAUSE THE SEND ABOVE TOOK A ROUND TRIP. The checks at entry were true when the
     * caller's message arrived; an operator who started replying during our own send would not have
     * been visible then. Sealing is the irreversible half, so the last thing before it is the same
     * question, freshly asked.
     */
    if (sendClaims.held(agentName, sessionId) || readSession(agentName, sessionId).weSpoke) {
      logger.info("session.away.inbox.oneshot.seal_skipped_operator_returned", {
        agentName, sessionId,
        impact: "the operator spoke while this was closing, so the session is NOT sealed — it is theirs to close",
      });
      return;
    }
    const readiness = sessionNodeManager.sealReadiness(agentName, sessionId);
    if (readiness.diverged) {
      logger.warn("session.away.inbox.oneshot.seal_skipped_diverged", {
        agentName, sessionId, treeSize: readiness.treeSize, highWaterSeq: readiness.highWaterSeq,
        impact: "this side's tree parted from the relay's ordering, so the seal was NOT initiated — the session stays closeable by hand, where the operator can compare counts with the counterparty first",
      });
      return;
    }
    await initiateSeal(agentName, sessionId, record);
  }

  /**
   * Seal via the RELAY-mediated path, not the signaling one.
   *
   * The signaling path compares leaf counts, and this party's tree includes the rejection sent
   * milliseconds ago while the counterparty's may not have ingested it yet — a race that fails the
   * seal for a reason that is not real. The relay path posts a SEAL ctrl leaf and waits for the
   * counterparty to co-seal independently, so no count comparison happens at all.
   */
  async function initiateSeal(agentName: string, sessionId: string, record: SessionRecord): Promise<void> {
    const correlationId = randomUUID();
    const sk = sealKey(agentName, sessionId);
    if (sealInterruptedInProgress.has(sk)) return;
    sealInterruptedInProgress.add(sk);
    try {
      let resolveSeal!: (c: SealCompletion) => void;
      const sealedP = new Promise<SealCompletion>((r) => { resolveSeal = r; });
      pendingSealWaiters.set(sk, resolveSeal);

      const submit = await sessionNodeManager.submitSealLeaf(agentName, sessionId, correlationId);
      if (!submit.ok && submit.reason !== "responder_seal_already_submitted") {
        pendingSealWaiters.delete(sk);
        if (submit.reason === "relay_unavailable" || isLocalCredentialRefusal(submit.reason)) {
          const fallback = await handleActiveSealFlow(sessionId, record, correlationId);
          if (fallback.ok) logger.info("session.away.inbox.oneshot.seal_initiated", { agentName, sessionId, path: "signaling_fallback" });
          else logger.warn("session.away.inbox.oneshot.seal_initiate_failed", { agentName, sessionId, reason: fallback.reason, path: "signaling_fallback" });
        } else {
          logger.warn("session.away.inbox.oneshot.seal_initiate_failed", { agentName, sessionId, reason: submit.reason });
        }
        return;
      }
      logger.info("session.away.inbox.oneshot.seal_initiated", { agentName, sessionId, path: "relay" });

      const bilateralTimeoutMs = Number(process.env["CELLO_SEAL_BILATERAL_TIMEOUT_MS"]) || 660_000;
      let timer!: ReturnType<typeof setTimeout>;
      const timeoutP = new Promise<null>((r) => { timer = setTimeout(() => r(null), bilateralTimeoutMs); });
      const completion = await Promise.race([sealedP, timeoutP]);
      clearTimeout(timer);
      pendingSealWaiters.delete(sk);

      if (completion !== null) {
        // A REFUSED certificate resolves the waiter rather than being dropped, so the two must be
        // told apart — logging a refusal as "sealed" is the silent acceptance to avoid.
        if ("refused" in completion) {
          logger.error("session.away.inbox.oneshot.seal_refused", {
            agentName, sessionId, reason: completion.reason, detail: completion.detail,
            impact: "the away auto-seal was REFUSED: the directory returned a validly signed root that does not describe this conversation. The session is NOT sealed and nothing was signed with this agent's key.",
          });
          return;
        }
        logger.info("session.away.inbox.oneshot.sealed", { agentName, sessionId, sealedRoot: completion.rootHex });
        return;
      }

      const escalation = submit.ok
        ? { reportedRootHex: submit.reportedRootHex, sequenceNumber: submit.sequenceNumber }
        : submit.reason === "responder_seal_already_submitted" && typeof submit.reportedRootHex === "string" && typeof submit.sequenceNumber === "number"
          ? { reportedRootHex: submit.reportedRootHex, sequenceNumber: submit.sequenceNumber }
          : null;
      if (!escalation) {
        logger.warn("session.away.inbox.oneshot.seal_pending", { agentName, sessionId });
        return;
      }
      // THE SHARED ESCALATION, not a second copy — a duplicate drifted once and missed every
      // refusal the shared one gained (empty carry, gappy chain, two of our own ctrl leaves).
      const uni = await runUnilateralEscalation(
        { logger, sessionNodeManager, sendOver, pendingUnilateralWaiters, sealKey, getKeyProvider: (a) => keyProviders.get(a), timeoutMs: UNILATERAL_SEAL_TIMEOUT_MS },
        agentName, sessionId, escalation, correlationId, { refuseOnUnusableCarry: true },
      );
      if (uni.ok) {
        logger.info("session.away.inbox.oneshot.sealed", { agentName, sessionId, sealedRoot: uni.sealed_root, sealType: "unilateral" });
      } else {
        // CARRY THE GUIDANCE: it is the sentence telling an operator whether to retry or
        // force-abandon, and this log is the path's only surface.
        logger.warn("session.away.inbox.oneshot.seal_unilateral_failed", { agentName, sessionId, reason: uni.reason, guidance: uni.guidance });
      }
    } finally {
      sealInterruptedInProgress.delete(sealKey(agentName, sessionId));
    }
  }

  return { closeInboxIfIgnored };
}
