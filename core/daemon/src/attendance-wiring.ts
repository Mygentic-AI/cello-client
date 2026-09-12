/**
 * What an UNATTENDED agent does when someone CALLS it: answer the call once, say so plainly, and
 * leave the rest to the operator who comes back.
 *
 * ⚠️ IT ANSWERS CALLS, NEVER CONVERSATIONS (DOD-M15-AWAYSCOPE-1). An answering machine is for a
 * call nobody picked up. Once two agents are in an accepted session, a daemon that types into it is
 * putting a status announcement in a record that attests what the two PARTIES said — and on
 * session `e7dd3f43…` that one greeting cost a completed, witnessed conversation its receipt on
 * both machines, permanently. A daemon's assertion about itself is a fact ABOUT the session and
 * rides the out-of-band liveness frame; it never takes a chain leaf. The only trigger left here is
 * an inbound session REQUEST.
 *
 * "Attended" means a live client has claimed the agent with `cello_use_agent`. Several sessions
 * attending one agent at once is legitimate and permanent — co-attendance, not exclusivity — which
 * is why the COUNT is kept separate from the boolean and both read the same `currentAgent` map the
 * doorbell routes on. They cannot disagree about who is present.
 *
 * ⚠️ IT PLACES ITS OWN LEAVES. The greeting is content: it is sent, it takes a leaf and it records
 * a transcript row, exactly as a voicemail outgoing message belongs on the tape. So this file stays
 * in the seal call-site enforcer's CALLERS list — that guard stops SCANNING a file that leaves the
 * list rather than going red.
 */
import { randomUUID } from "node:crypto";
import type { SessionNodeManager } from "./session-node-manager.js";
import type { Logger } from "./types.js";
import type { SecurityGatewayClient } from "@cello-protocol/gateway";
import { countAttendance, ContentTakeLedger } from "./co-attendance.js";
import { markAsAutoReply, systemAwayText } from "./away-detection.js";
import { LEAF_KIND_MSG } from "./session-relay-client.js";
import { sentAuthorship } from "./session-content-handlers.js";
import { extractErrorMessage } from "./error-message.js";

export interface AttendanceWiringDeps {
  logger: Logger;
  sessionNodeManager: SessionNodeManager;
  /**
   * The per-connection agent selection, read whole: "is anyone attending X" is a scan of the live
   * selections, and the count is the same scan. Read-only — this surface never changes a selection.
   */
  perConnectionState: ReadonlyMap<string, { currentAgent: string | null }>;
  /** The away reply is outbound content and takes the same screen every other send takes. */
  securityGateway: SecurityGatewayClient;
}

export function createAttendanceWiring(deps: AttendanceWiringDeps) {
  const { logger, sessionNodeManager, perConnectionState, securityGateway } = deps;

  // M8C-AWAY-1: away response — an unattended Primary auto-answers session requests
  // with the default transparent away text and queues them (the DoD's own mandated default).
  // CORE ships now; the operator-configurable custom-text / opaque-privacy-mode SWITCH is PARKED
  // on M9-CFG-001, journaled as D15 (M8C-DECISIONS.md, mirrors D14) — a genuine per-agent operator
  // preference that needs the deferred config store, whereas transparent is already the correct,
  // non-fake default this unit must ship regardless.
  // "Attended" per the design doc (2026-07-01 command-surface discussion, Agent State Model):
  // Primary + a live client session has claimed the agent via use_agent. Scanning
  // perConnectionState is cheap (a handful of connections) and needs no separate tracked state.
  function isAttended(agentName: string): boolean {
    for (const s of perConnectionState.values()) if (s.currentAgent === agentName) return true;
    return false;
  }
  // DOD-COATTEND-VISIBLE-1: the COUNT, deliberately kept separate from the boolean above. Several
  // sessions attending one agent is legitimate and permanent (co-attendance, not exclusivity — spec
  // §3); what was missing is that nobody was ever TOLD. `isAttended` is left byte-identical because
  // M8C-AWAY-1's auto-ack suppression hangs off its early return, and both read the same
  // `currentAgent` map the doorbell routes on, so the count can never disagree with who gets woken.
  function attendanceCount(agentName: string): number {
    return countAttendance(perConnectionState, agentName);
  }
  // Which connection consumed which leaf, so the session that finds an empty buffer can be told
  // whether its counterparty is quiet or its sibling was faster. Written at the destructive drain in
  // session-content-handlers; read at that handler's timeout. Delivery itself is unchanged.
  const contentTakes = new ContentTakeLedger();
  /**
   * In-flight background seal ceremonies — `DOD-M15-CLOSEWAIT-1` review MEDIUM-6.
   *
   * The close now answers at commitment and finishes the ceremony detached. Without this the tail
   * was the ONE background task `stop()` could cut at an arbitrary point, while it cancels or awaits
   * every other one.
   */
  const backgroundSeals = new Set<Promise<unknown>>();
  // Coalescing: one away ack per (agent, session, kind) per away period — cleared when the agent
  // becomes attended again (cello_use_agent) so the NEXT away period gets a fresh ack rather than
  // staying silent forever. Known imprecision (journaled, not silent): clearing fires on ANY
  // use_agent selecting this name, even if another connection kept it attended throughout — an
  // edge case, not a correctness gap in the core "queue + one calm ack while genuinely away" promise.
  const awayAckSent = new Set<string>();
  /**
   * DOD-M15-AWAYSCOPE-1 — THIS ANSWERS A CALL. It does not answer a conversation.
   *
   * There is one caller left, the inbound session-REQUEST path, and the `kind` parameter is gone
   * rather than defaulted: a second value is what let this function be reached from an existing
   * session, and a default would leave that call compiling.
   */
  async function sendAwayResponse(agentName: string, sessionId: string): Promise<void> {
    if (isAttended(agentName)) return;
    /**
     * The log keeps saying which kind it was, and that is deliberate now that there is only one.
     * The live failure this order closes is READ OFF a daemon log line — `kind: "message"` at
     * 16:13:28.804 is the whole tell — so a log that still names the kind is what makes the absence
     * of the deleted one provable from a production log rather than only from the source.
     */
    const kind = "request" as const;
    const dedupKey = `${agentName}:${sessionId}:${kind}`;
    if (awayAckSent.has(dedupKey)) return;
    const record = sessionNodeManager.getSessionRecord(agentName, sessionId);
    if (!record || record.status !== "active") return;
    // The inbound accept path does NOT auto-add the sender: an unattended stranger STAYS unknown
    // across every inbound interaction. Promotion requires operator engagement — an outbound
    // initiate, a cello_send reply, or an explicit contact add. Nothing depends on its ordering.
    const isKnown = sessionNodeManager.isKnown(agentName, record.counterparty_pubkey);
    awayAckSent.add(dedupKey); // guard BEFORE the async send — concurrent arrivals must not double-ack
    try {
      // DOD-AWAY-TIER-1: resolve most-specific-first — per-contact away_message → per-tier away
      // (settings) → agent default (settings) → the system default (code, per kind). Total.
      // DOD-M12B-AWAY-MARK-1: THE choke point. Every away reply this daemon sends passes through
      // this one expression — the per-contact message, the per-tier message, the agent default, the
      // system default and the stranger ack — so marking here is what makes "an operator's
      // CONFIGURED away message is indistinguishable from a person" go away, which is the half
      // exact-text matching could not reach by construction. markAsAutoReply is idempotent, so the
      // system defaults (already marked at their source) do not pick up a second token.
      const awayText = sessionNodeManager.resolveAwayMessage(agentName, record.counterparty_pubkey)
        ?? systemAwayText(agentName, isKnown);
      // AWAYSALT-1 review MEDIUM-3: the salt wait widens the window in which BOTH acks are computed
      // before either is a leaf, so the tree check below would pass both through. Claim the TEXT first.
      const txtKey = `${agentName}:${sessionId}:txt:${awayText}`;
      if (awayAckSent.has(txtKey)) { logger.info("session.away.response.suppressed_duplicate", { agentName, sessionId, kind, reason: "identical_ack_already_in_flight" }); return; }
      awayAckSent.add(txtKey);
      const draftBytes = new TextEncoder().encode(awayText);
      // SI (AWAY-TIER-1): an away message is now operator-configurable, i.e. an outbound DISCLOSURE.
      // Screen it on the outbound path like any content — it does NOT bypass the gateway. A block/warn
      // verdict means it is not sent (the dedup guard stays set — one screen per away period, no spam);
      // a redact verdict sends the ALTERED bytes.
      const awayVerdict = await securityGateway.screenOutbound(draftBytes, {
        direction: "outbound", agentName, sessionId, correlationId: randomUUID(),
      });
      if (awayVerdict.disposition === "block" || awayVerdict.disposition === "warn") {
        logger.info("session.away.response.screened_out", { agentName, sessionId, kind, disposition: awayVerdict.disposition });
        return;
      }
      if (awayVerdict.disposition === "redact" && awayVerdict.content === undefined) {
        logger.error("session.away.response.redact_without_content", { agentName, sessionId, kind });
        return;
      }
      // DOD-M12B-AWAY-MARK-1: mark AFTER screening, never before. A redact verdict REPLACES the
      // bytes, and marking the draft would let that replacement silently strip the marker — an away
      // reply back on the wire indistinguishable from a person, with no log line saying so. Marking
      // here also means the gateway screens the OPERATOR-CONFIGURED message — the only unmarked
      // input — rather than a daemon token bolted to its front. Every system default, the stranger
      // ack included since AWAYLEAF-1, is marked at source; markAsAutoReply is idempotent.
      const screenedBytes = awayVerdict.disposition === "redact" && awayVerdict.content !== undefined
        ? new Uint8Array(awayVerdict.content)
        : draftBytes;
      const contentBytes = new TextEncoder().encode(
        markAsAutoReply(new TextDecoder().decode(screenedBytes)),
      );
      // AWAYSALT-1 — BEFORE hashing: unsalted here closes salt adoption for the whole session, and every later message from the peer is refused. See `markSaltPending`.
      sessionNodeManager.expectSaltAgreement(agentName, sessionId);
      // B2b: one decision point for the hash AND its algorithm — see `contentHashForSession`.
      const away = await sessionNodeManager.contentHashForSession(agentName, sessionId, contentBytes);
      // DOD-M15-AWAYLEAF-1 — the DURABLE half of the no-duplicate-leaf rule; `txtKey` is the in-flight
      // half. Both acks carry the same bytes whenever the away text does not vary by kind, and a leaf
      // only one side holds is never co-signed: measured on 9b4d89f9, 4 against 3, `leaf_count_mismatch`.
      const awayHashHex = Buffer.from(away.hash).toString("hex");
      if (sessionNodeManager.getSessionTree(agentName, sessionId).indexOfHash(awayHashHex) >= 0) {
        logger.info("session.away.response.suppressed_duplicate", {
          agentName, sessionId, kind, contentHashHex: awayHashHex, reason: "identical_leaf_already_in_this_session",
          impact: "no second ack is sent; two leaves with one content hash leave this session unable to seal",
        });
        return;
      }
      const sendResult = await sessionNodeManager.sendContent(agentName, sessionId, contentBytes, new Uint8Array(away.hash), randomUUID(), LEAF_KIND_MSG, away.alg);
      if (!sendResult.ok && !sendResult.durable) {
        // Reviewer MEDIUM fix: a transient failure must NOT permanently silence the rest of this
        // away period — clear the guard so the next inbound arrival retries the ack. Both guards:
        // AWAYLEAF-1's in-flight claim would otherwise suppress the retry as its own duplicate.
        awayAckSent.delete(dedupKey); awayAckSent.delete(txtKey);
        // M12-P13: this branch now means the reply is GONE, not merely late (the queued case is
        // handled below), so it is an error and it says what the consequence is. It was a bare warn
        // when it fired live on 2026-08-05 and read as routine churn.
        logger.error("session.away.response.failed", {
          agentName, sessionId, kind, reason: sendResult.reason, cause: sendResult.cause,
          impact: "the away reply is lost and was NOT queued — the counterparty gets no acknowledgement",
        });
        return;
      }
      const contentHashHex = Buffer.from(away.hash).toString("hex");
      if (!sendResult.ok) {
        // M12-P13 (found live 2026-08-05, M12 Entry 89): the reply is durably queued and already
        // owns the sequence the relay witnessed for it, so its leaf MUST be committed here. Without
        // it this side's tree stays one short of that sequence, and since `nextExpected` is the tree
        // size, every message the counterparty sends afterwards is held behind a gap nothing can
        // fill. That is exactly how the receiver stranded its own session at sequence 0.
        //
        // The dedup guard deliberately STAYS SET: a queued reply is coming, and re-sending on the
        // next arrival would mint a second greeting at a second sequence.
        // DOD-M12B-INDEX-1: the queued reply owns the position the relay witnessed for it, and
        // that is where its leaf goes.
        // Witnessed and SIGNED — only the direct hand-off failed — so the proof exists and must
        // reach the leaf. This is the site `sentAuthorship`'s own comment calls dead-by-construction
        // under an `ok`-gated read; the same reasoning applies to the leaf, not just the row.
        const placedQueued = sessionNodeManager.placeOwnLeaf(agentName, sessionId, contentHashHex, contentBytes, sendResult.sequenceNumber, randomUUID(), "msg", sentAuthorship(sendResult));
        if (placedQueued.placed) {
          sessionNodeManager.recordTranscriptMessage(agentName, sessionId, placedQueued.leafIndex, "sent", contentBytes, randomUUID(), sentAuthorship(sendResult));
        }
        logger.info("session.away.response.deferred", {
          agentName, sessionId, kind, isKnown,
          sequenceNumber: placedQueued.placed ? placedQueued.leafIndex : placedQueued.heldAt,
          committed: placedQueued.placed,
          reason: sendResult.reason, cause: sendResult.cause,
        });
        return;
      }
      // DOD-M12B-INDEX-1: the away responder fires while inbound is still arriving, so it is the
      // path most likely to have a gap open under it — exactly where a tail append does damage.
      const placedReply = sessionNodeManager.placeOwnLeaf(agentName, sessionId, contentHashHex, contentBytes, sendResult.sequenceNumber, randomUUID(), "msg", sentAuthorship(sendResult));
      if (placedReply.placed) {
        sessionNodeManager.recordTranscriptMessage(agentName, sessionId, placedReply.leafIndex, "sent", contentBytes, randomUUID(), sentAuthorship(sendResult));
      }
      logger.info("session.away.response.sent", {
        agentName, sessionId, kind, isKnown,
        sequenceNumber: placedReply.placed ? placedReply.leafIndex : placedReply.heldAt,
        committed: placedReply.placed,
      });
    } catch (err: unknown) {
      // Reviewer MEDIUM fix: same as above — an unexpected throw must not permanently lock out
      // future retries for the rest of this away period.
      awayAckSent.delete(dedupKey);
      logger.warn("session.away.response.failed", { agentName, sessionId, kind, error: extractErrorMessage(err) });
    }
  }

  // `isAttended` is NOT returned: its only caller in the repo is `sendAwayResponse`, which moved
  // with it. Returning it would make a private local reachable through an exported factory for no
  // consumer — new surface, which Rule D forbids.
  return { attendanceCount, sendAwayResponse, contentTakes, backgroundSeals, awayAckSent };
}
