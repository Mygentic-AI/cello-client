/**
 * What an UNATTENDED agent does when someone reaches it: answer once, say so plainly, and — if the
 * caller keeps talking to an empty room — close the conversation rather than leave it open forever.
 *
 * "Attended" means a live client has claimed the agent with `cello_use_agent`. Several sessions
 * attending one agent at once is legitimate and permanent — co-attendance, not exclusivity — which
 * is why the COUNT is kept separate from the boolean and both read the same `currentAgent` map the
 * doorbell routes on. They cannot disagree about who is present.
 *
 * Eleven dependencies, under the order's bound of ~12 — counted, because the first version of
 * this line said seven. This block was never entangled with the boot
 * sequence; it just happened to be written in the middle of it.
 *
 * ⚠️ IT PLACES ITS OWN LEAVES. The one-shot rejection sends content, appends the leaf and records
 * the transcript row, so this file belongs in the seal call-site enforcer's CALLERS list — it is
 * added there in the same commit, because that guard stops SCANNING a file that leaves the list
 * rather than going red.
 */
import { randomUUID } from "node:crypto";
import type { SessionNodeManager } from "./session-node-manager.js";
import type { Logger, SessionRecord } from "./types.js";
import type { ActiveSealResult } from "./seal-flows.js";
import type { KeyProvider } from "@cello-protocol/crypto";
import type { SecurityGatewayClient } from "@cello-protocol/gateway";
import { countAttendance, ContentTakeLedger } from "./co-attendance.js";
import { isOwnAwayAutoReply, markAsAutoReply, isAutoReplyMarked, systemAwayText } from "./away-detection.js";
import { LEAF_KIND_MSG } from "./session-relay-client.js";
import { sentAuthorship } from "./session-content-handlers.js";
import { escalateToUnilateralSeal as runUnilateralEscalation, UNILATERAL_SEAL_TIMEOUT_MS } from "./seal-escalation.js";
import type { UnilateralResult } from "./seal-coordinator.js";
import type { SealCompletion } from "./seal-coordinator.js";

export interface AttendanceWiringDeps {
  logger: Logger;
  sessionNodeManager: SessionNodeManager;
  /**
   * The per-connection agent selection, read whole: "is anyone attending X" is a scan of the live
   * selections, and the count is the same scan. Read-only — this surface never changes a selection.
   */
  perConnectionState: ReadonlyMap<string, { currentAgent: string | null }>;
  keyProviders: Map<string, KeyProvider>;
  /** The away reply is outbound content and takes the same screen every other send takes. */
  securityGateway: SecurityGatewayClient;
  /**
   * The seal machinery a one-shot rejection hands off to once it has closed the conversation. All
   * four come from the seal coordinator, which is built ABOVE this wiring, so they are values.
   */
  sealKey: (agentName: string, sessionId: string) => string;
  sealInterruptedInProgress: Set<string>;
  pendingSealWaiters: Map<string, (completion: SealCompletion) => void>;
  pendingUnilateralWaiters: Map<string, (r: UnilateralResult) => void>;
  /** Sends a frame over the OWNING agent's directory manager. */
  sendOver: (agentName: string, frame: Record<string, unknown>) => Promise<{ ok: boolean; reason?: string }>;
  handleActiveSealFlow: (
    sessionId: string,
    record: SessionRecord,
    correlationId: string,
  ) => Promise<ActiveSealResult>;
}

export function createAttendanceWiring(deps: AttendanceWiringDeps) {
  const {
    logger, sessionNodeManager, perConnectionState, keyProviders, securityGateway,
    handleActiveSealFlow, sealKey, sealInterruptedInProgress, pendingSealWaiters,
    pendingUnilateralWaiters, sendOver,
  } = deps;

  // M8C-AWAY-1: away response — an unattended Primary auto-answers session requests + messages
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
  async function sendAwayResponse(agentName: string, sessionId: string, kind: "request" | "message"): Promise<void> {
    if (isAttended(agentName)) return;
    // DOD-AWAY-WRAP-1 AC2: if the triggering message carries [[WRAP]], the caller is done — skip the
    // away reply entirely and let the seal ceremony proceed. The dedupKey is intentionally NOT added
    // here: the WRAP path is a silent close, not an away period that should be deduped.
    if (kind === "message") {
      const latestHex = sessionNodeManager.peekLatestReceivedContentHex(agentName, sessionId);
      if (latestHex !== null) {
        const text = Buffer.from(latestHex, "hex").toString("utf8");
        // DOD-WRAP-SUBSTRING-1: match the APPENDED token, not any substring —
        // DOD-SIGNAL-TOKEN-1 always appends the real token at the END of the body. A substring
        // match would classify a mere mention of [[WRAP]] (sent signal:"over") as a close
        // signal, silently skipping both the away reply and the oneshot rejection.
        if (text.trimEnd().endsWith("[[WRAP]]")) {
          logger.info("session.away.response.skipped_wrap", { agentName, sessionId });
          return;
        }
        // DOD-AWAY-MUTUAL-SEAL-1: an away responder must not answer ANOTHER away responder, and
        // must not count one toward the one-shot rule.
        //
        // When both agents are unattended, each side's auto-reply arrives at the other as an inbound
        // message. The second such arrival looks exactly like "a caller who ignored the
        // leave-a-message instruction" — so the one-shot fires on BOTH sides, each sends a [[WRAP]]
        // rejection and initiates a seal, and two distinct-sender SEAL ctrl leaves is precisely what
        // notarizes a session.
        //
        // Measured from the relay's own log 2026-08-09: sealed THREE SECONDS after opening, its
        // entire content two machines telling each other nobody was home. Neither daemon learned —
        // the seal completion is pushed with no pull twin — so both showed `active`, and the
        // operators returned and talked into a closed room for 68 minutes before finding out.
        //
        // Returned silently rather than answered: a reply would continue the ping-pong, and there is
        // nobody on the far side to read one.
        if (isOwnAwayAutoReply(text)) {
          logger.info("session.away.mutual.skipped", {
            agentName,
            sessionId,
            // DOD-M12B-AWAY-MARK-1: WHICH branch matched. The marker is in-band and therefore
            // typeable, so prefixing every message with it skips the one-shot auto-close for free —
            // the cost of that attack fell from "reproduce the exact away wording" to "type 15
            // characters". This field is what makes a peer doing it on every message visible;
            // without it the line reads as routine machine-to-machine traffic.
            matched: isAutoReplyMarked(text) ? "marker" : "legacy_exact",
            impact:
              "no away reply and no one-shot seal — two away agents must not notarize a conversation nobody had",
          });
          return;
        }
      }
    }
    const dedupKey = `${agentName}:${sessionId}:${kind}`;
    // F3 fix: a dedicated guard prevents re-entry after the rejection fires — without it a
    // rapid-fire sender could trigger multiple rejection sends and concurrent seal submits while
    // the session remains active (seal failed). ⚠️ It said "never cleared, no re-attend resets it":
    // FALSE — it matches the `${name}:` sweep in agent-handlers.ts, so re-attending re-arms it.
    const rejectedKey = `${agentName}:${sessionId}:rejected`;
    if (awayAckSent.has(dedupKey)) {
      // DOD-INBOX-ONESHOT-1: a second inbound message while the first away ack is still live means
      // the caller ignored the leave-a-message instruction. Send one [[WRAP]]-bearing rejection and
      // immediately initiate the seal so the session closes without operator intervention.
      if (kind === "message" && !awayAckSent.has(rejectedKey)) {
        awayAckSent.add(rejectedKey); // guard BEFORE async work — concurrent arrivals must not re-enter
        const record2 = sessionNodeManager.getSessionRecord(agentName, sessionId);
        if (record2 && record2.status === "active") {
          // Reviewer F2: token at the END — the daemon's own output must honor the
          // DOD-SIGNAL-TOKEN-1 append-at-end contract that DOD-WRAP-SUBSTRING-1 detection
          // is anchored on (a counterparty daemon's end-anchored detector must see this close).
          // DOD-M12B-AWAY-MARK-1: machine-generated, so it is marked — and the marker goes at the
          // FRONT precisely so [[WRAP]] keeps the end position the counterparty's detector anchors on.
          const rejectText = markAsAutoReply("This inbox only accepts one message per visit. Closing. [[WRAP]]");
          const rejectBytes = new TextEncoder().encode(rejectText);
          // B2b: one decision point for the hash AND its algorithm — see `contentHashForSession`.
          const reject = await sessionNodeManager.contentHashForSession(agentName, sessionId, rejectBytes);
          // Best-effort: a send failure still triggers the seal — we are closing regardless.
          const sendResult = await sessionNodeManager.sendContent(agentName, sessionId, rejectBytes, new Uint8Array(reject.hash), randomUUID(), LEAF_KIND_MSG, reject.alg);
          // M12-P13: commit the leaf when the rejection went out OR when it is durably queued —
          // either way the relay already witnessed its sequence. This caller is the sharpest case
          // of the three: the seal is initiated immediately below, so a hole here does not merely
          // stall the far side, it seals a tree that is one leaf short of a sequence the
          // counterparty will still receive content at. The roots then cannot agree, and the
          // session is unsealable for good.
          if (sendResult.ok || sendResult.durable) {
            const rejectHashHex = Buffer.from(reject.hash).toString("hex");
            // DOD-M12B-INDEX-1: at the relay's position, not the tail. This is the riskiest append
            // in the codebase for that — the seal is initiated a few lines below, so a leaf at the
            // wrong index does not merely stall the far side, it seals a tree the counterparty can
            // never agree with.
            // The proof travels with the leaf, not only with the transcript row below: when this
            // append is HELD behind a gap, the `recordTranscriptMessage` call is skipped entirely
            // and the held entry is the only thing that reaches the row on release.
            const placed = sessionNodeManager.placeOwnLeaf(agentName, sessionId, rejectHashHex, rejectBytes, sendResult.sequenceNumber, randomUUID(), "msg", sentAuthorship(sendResult));
            if (placed.placed) {
              sessionNodeManager.recordTranscriptMessage(agentName, sessionId, placed.leafIndex, "sent", rejectBytes, randomUUID(), sentAuthorship(sendResult));
            }
            logger.info("session.away.inbox.oneshot.rejected", { agentName, sessionId, sequenceNumber: placed.placed ? placed.leafIndex : placed.heldAt, committed: placed.placed, queued: !sendResult.ok });
          } else {
            // Not queued anywhere — the rejection is gone. We still seal (we are closing regardless),
            // and the counterparty simply never learns why, so say that plainly rather than at warn.
            logger.error("session.away.inbox.oneshot.reject_send_failed", {
              agentName, sessionId, reason: sendResult.reason, cause: sendResult.cause,
              impact: "the rejection is lost and was NOT queued — the session seals with no explanation to the counterparty",
            });
          }
          // DOD-INBOX-ONESHOT-1 / DOD-SEAL-BILATERAL-TIMEOUT-1: initiate the seal via the
          // relay-mediated path (submitSealLeaf → bilateral wait → unilateral escalation).
          // The signaling-only path (handleActiveSealFlow) suffers a leaf_count_mismatch race:
          // this party's tree includes the just-sent rejection, but the counterparty's tree may
          // not have ingested it yet when the seal request arrives over the signaling channel.
          // The relay path avoids this entirely — it posts a SEAL ctrl leaf and waits for the
          // counterparty to independently co-seal; no bilateral leaf-count comparison needed.
          /**
           * DOD-M15-DIVERGE-1 (review HIGH-3) — the gate has to hold on the path with no operator.
           *
           * `cello_close_session` refuses a diverged record, but this autonomous path never
           * consulted `sealReadiness` at all: it read `placed.placed` and discarded
           * `placed.diverged`, then initiated the seal directly. So "a diverged session is blocked
           * from sealing" held for the close a human drives and not for the one that runs itself —
           * which is the worse of the two, because the append two lines above is, by its own
           * comment, "the riskiest append in the codebase" for exactly this reason.
           *
           * THE LOG IS THE SURFACE HERE, and that is not a weakening of Invariant 2. There is no
           * caller to answer — nothing is awaiting a response on this path — so the log carries the
           * whole warning rather than half of it.
           */
          const oneshotReadiness = sessionNodeManager.sealReadiness(agentName, sessionId);
          if (oneshotReadiness.diverged) {
            logger.warn("session.away.inbox.oneshot.seal_skipped_diverged", {
              agentName, sessionId,
              treeSize: oneshotReadiness.treeSize, highWaterSeq: oneshotReadiness.highWaterSeq,
              impact: "this side's tree parted from the relay's ordering, so the seal was NOT initiated — the session stays closeable by hand, where the operator is told what parted and can compare counts with the counterparty before deciding",
            });
          } else {
          void (async () => {
            const correlationId = randomUUID();
            const sk = sealKey(agentName, sessionId);
            if (sealInterruptedInProgress.has(sk)) return;
            sealInterruptedInProgress.add(sk);
            try {
              // DOD-M15-SEALWIRE-1 bullet 2 (review F4): SealCompletion is now a union — a refused
              // certificate resolves the waiter rather than dropping it, so this path must handle it
              // too rather than treating a refusal as a seal.
              let resolveSeal!: (c: SealCompletion) => void;
              const sealedP = new Promise<SealCompletion>((r) => { resolveSeal = r; });
              pendingSealWaiters.set(sk, resolveSeal);

              const submit = await sessionNodeManager.submitSealLeaf(agentName, sessionId, correlationId);
              if (!submit.ok && submit.reason !== "responder_seal_already_submitted") {
                pendingSealWaiters.delete(sk);
                if (submit.reason === "relay_unavailable") {
                  const fallback = await handleActiveSealFlow(sessionId, record2, correlationId);
                  if (fallback.ok) {
                    logger.info("session.away.inbox.oneshot.seal_initiated", { agentName, sessionId, path: "signaling_fallback" });
                  } else {
                    logger.warn("session.away.inbox.oneshot.seal_initiate_failed", { agentName, sessionId, reason: fallback.reason, path: "signaling_fallback" });
                  }
                } else {
                  logger.warn("session.away.inbox.oneshot.seal_initiate_failed", { agentName, sessionId, reason: submit.reason });
                }
                return;
              }

              logger.info("session.away.inbox.oneshot.seal_initiated", { agentName, sessionId, path: "relay" });

              const bilateralTimeoutMs = Number(process.env["CELLO_SEAL_BILATERAL_TIMEOUT_MS"]) || 660_000;
              let timer!: ReturnType<typeof setTimeout>;
              const timeoutP = new Promise<null>((r) => { timer = setTimeout(() => r(null), bilateralTimeoutMs); });
              const sealedCompletion = await Promise.race([sealedP, timeoutP]);
              clearTimeout(timer);
              pendingSealWaiters.delete(sk);

              if (sealedCompletion !== null) {
                // DOD-M15-SEALWIRE-1 bullet 2 (review F4): a REFUSED certificate resolves the waiter
                // now rather than being dropped, so this path must tell the two apart — logging a
                // refusal as "sealed" would be the silent acceptance the whole bullet exists to stop.
                if ("refused" in sealedCompletion) {
                  logger.error("session.away.inbox.oneshot.seal_refused", {
                    agentName, sessionId, reason: sealedCompletion.reason, detail: sealedCompletion.detail,
                    impact:
                      "the away auto-seal was REFUSED: the directory returned a validly signed root " +
                      "that does not describe this conversation. The session is NOT sealed and nothing " +
                      "was signed with this agent's key.",
                  });
                  return;
                }
                logger.info("session.away.inbox.oneshot.sealed", { agentName, sessionId, sealedRoot: sealedCompletion.rootHex });
                return;
              }

              // Bilateral timeout — escalate to unilateral seal.
              const escalation = submit.ok
                ? { reportedRootHex: submit.reportedRootHex, sequenceNumber: submit.sequenceNumber }
                : submit.reason === "responder_seal_already_submitted" &&
                    typeof submit.reportedRootHex === "string" &&
                    typeof submit.sequenceNumber === "number"
                  ? { reportedRootHex: submit.reportedRootHex, sequenceNumber: submit.sequenceNumber }
                  : null;
              if (!escalation) {
                logger.warn("session.away.inbox.oneshot.seal_pending", { agentName, sessionId });
                return;
              }

              // DOD-M12B-SEAL-ESCALATE-DUP-1: THE SHARED ESCALATION, not a second copy.
              //
              // This used to be a line-for-line duplicate with its own hardcoded 30 s timeout, and
              // it missed every refusal the other one gained: an empty carry, a gappy chain, two of
              // our own ctrl leaves (permanently unsealable), and a bilateral seal already running.
              // It spent the full timeout on each and then reported `seal_unilateral_timeout` — the
              // label that names our own wait. Sharing the body is what stops that drifting again.
              const uni = await runUnilateralEscalation(
                {
                  logger, sessionNodeManager, sendOver, pendingUnilateralWaiters, sealKey,
                  getKeyProvider: (a) => keyProviders.get(a),
                  timeoutMs: UNILATERAL_SEAL_TIMEOUT_MS,
                },
                agentName,
                sessionId,
                escalation,
                correlationId,
                { refuseOnUnusableCarry: true },
              );
              if (uni.ok) {
                logger.info("session.away.inbox.oneshot.sealed", { agentName, sessionId, sealedRoot: uni.sealed_root, sealType: "unilateral" });
              } else {
                // CARRY THE GUIDANCE. The four refusals this path just gained come with the
                // sentence that tells an operator whether to retry or force-abandon — and the log
                // is this path's ONLY surface, so dropping it leaves a nameable cause with no
                // action attached. The old reasons had no guidance to lose; these do.
                logger.warn("session.away.inbox.oneshot.seal_unilateral_failed", {
                  agentName, sessionId, reason: uni.reason, guidance: uni.guidance,
                });
              }
            } finally {
              sealInterruptedInProgress.delete(sealKey(agentName, sessionId));
            }
          })();
          }
        }
      }
      return;
    }
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
        ?? systemAwayText(kind, agentName, isKnown);
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
      // B2b: one decision point for the hash AND its algorithm — see `contentHashForSession`.
      const away = await sessionNodeManager.contentHashForSession(agentName, sessionId, contentBytes);
      /**
       * DOD-M15-AWAYLEAF-1 — NEVER EMIT A LEAF THIS SESSION ALREADY HOLDS. An unattended agent acks
       * twice (knock, then message), and the two are the SAME BYTES whenever the text does not vary
       * by kind: the stranger default, and EVERY configured away message, since `resolveAwayMessage`
       * above is kind-independent and overrides the per-kind default — so a known contact collides.
       * The receiver separates duplicates by relay POSITION (DOD-FRONTIER-STRAND-1), but a parked
       * predecessor routinely makes that record `unusable` and strips the position; it then dedups on
       * content hash and records ONE where the sender counted two. Measured 2026-09-07, session
       * 9b4d89f9: 4 against 3, refused `leaf_count_mismatch`; a leaf one side lacks is never co-signed.
       * The TREE is the check: the same durable, per-session record the receiver itself dedups against.
       */
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
        // away period — clear the guard so the next inbound arrival retries the ack.
        awayAckSent.delete(dedupKey);
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
      logger.warn("session.away.response.failed", { agentName, sessionId, kind, error: err instanceof Error ? err.message : String(err) });
    }
  }

  // `isAttended` is NOT returned: its only caller in the repo is `sendAwayResponse`, which moved
  // with it. Returning it would make a private local reachable through an exported factory for no
  // consumer — new surface, which Rule D forbids.
  return { attendanceCount, sendAwayResponse, contentTakes, backgroundSeals, awayAckSent };
}
