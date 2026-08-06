/**
 * cello_send and cello_receive — the content path.
 *
 * The two biggest handlers in the daemon, and the two I had put on a DO-NOT-CUT list. That list was
 * written before anything had been measured, and it was wrong: these close over eleven things, not
 * the whole daemon. They are listed below, which is the point of the move.
 *
 * They stay TOGETHER because they are two halves of one state machine — the read cursor. cello_send
 * appends to the daemon-owned tree; cello_receive advances the per-connection cursor and the durable
 * watermark. Splitting them would put the cursor's writer and its reader in different modules.
 */
import { wireContentHash } from "./wire-content-hash.js";
import { randomUUID } from "node:crypto";
import { MAX_CONTENT_BYTES } from "@cello-protocol/protocol-types";
import { TIER } from "./contacts-tier-migration.js";
import { GATEWAY_UNAVAILABLE, GOVERNANCE_TIMEOUT, type SecurityGatewayClient } from "@cello-protocol/gateway";
import type { IpcHandler } from "./ipc-server.js";
import type { SessionNodeManager } from "./session-node-manager.js";
import type { RetryQueue } from "./retry-queue.js";
import type { Logger } from "./types.js";
import type { ConnState } from "./contact-handlers.js";
import type { ContentTakeLedger } from "./co-attendance.js";

export interface SessionContentDeps {
  handlers: Map<string, IpcHandler>;
  logger: Logger;
  sessionNodeManager: SessionNodeManager;
  securityGateway: SecurityGatewayClient;
  retryQueue: RetryQueue;
  getConnState: (connectionId: string) => ConnState | undefined;
  resolveCurrentAgent: (connState: ConnState | undefined, explicitAgent?: string) => string | null;
  NO_CURRENT_AGENT_RESPONSE: unknown;
  /** M8C-CURSOR-1: the per-connection read cursor (read-before-write gating). */
  getConnectionCursor: (connectionId: string, sessionId: string) => number;
  advanceConnectionCursor: (connectionId: string, sessionId: string, seq: number) => void;
  /** Never vaults the cursor past a hole in the delivered sequence. */
  safeCursorAdvance: (connectionId: string, sessionId: string, deliveredSeqs: ReadonlySet<number>) => void;
  /**
   * DOD-COATTEND-1 (review F1) — the DELIVERY bookmark, deliberately NOT the gate's cursor. The
   * gate asks "has this connection seen every leaf?" and must stop at a gap; delivery asks "what
   * have I already handed this connection?" and is destroyed by stopping. See daemon.ts for why
   * reusing one for the other produced an unbounded redelivery loop.
   */
  getDeliveryBookmark: (connectionId: string, sessionId: string) => number;
  advanceDeliveryBookmark: (connectionId: string, sessionId: string, seq: number) => void;
  /** M8C-TGDOOR-1: a read clears the doorbell's ring-once-until-read. */
  clearTelegramRung: (agentName: string, sessionId: string) => void;
  /** DOD-COATTEND-VISIBLE-1: how many connections attend this agent right now (reporting only). */
  attendanceCount: (agentName: string) => number;
  /**
   * DOD-COATTEND-VISIBLE-1: which connection consumed which leaf. Written here, at the one place
   * the destructive drain happens, and read at the timeout to tell a robbed caller apart from a
   * quiet counterparty. It does not change delivery — the drain stays `buf.shift()`.
   */
  contentTakes: ContentTakeLedger;
}

export function registerSessionContentHandlers(deps: SessionContentDeps): void {
  const {
    handlers, logger, sessionNodeManager, securityGateway, retryQueue,
    getConnState, resolveCurrentAgent, NO_CURRENT_AGENT_RESPONSE,
    getConnectionCursor, advanceConnectionCursor, safeCursorAdvance,
    getDeliveryBookmark, advanceDeliveryBookmark, clearTelegramRung,
    attendanceCount, contentTakes,
  } = deps;

  /**
   * DOD-COATTEND-SENDWINDOW-1 (review F1) — sessions with a send ON THE WIRE right now.
   *
   * The frontier comparison alone was not enough, and the reasoning that produced it had a hole:
   * it is TRUE that a send cannot be refused after `sendContent` (the counterparty already holds
   * the message, and refusing would strand the session with disagreeing frontiers — the
   * DOD-FRONTIER-STRAND-1 shape). It does NOT follow that checking only before it is sufficient.
   * `sendContent` IS the last await, and the wider one: it awaits the relay hash submit, the
   * stream open and the stream close — a network round trip in production, against the gateway
   * round trip the frontier check covers. Reproduced by review on a real daemon with two real IPC
   * connections: two `ok: true`, two frames on the wire, two leaves.
   *
   * So the window is closed by a CLAIM rather than a later check. A sibling that finds the claim
   * held is refused BEFORE its own wire call — nothing is on the wire, nothing is stranded, and the
   * strand argument that ruled out a post-wire refusal never applies.
   *
   * Keyed (agent, session): the race is two connections replying into ONE conversation. Held in the
   * factory closure, which runs once per daemon, so it is exactly as long-lived as the handler set.
   */
  /**
   * DOD-COATTEND-VISIBLE-1 AC6 (review F2) — attendance as reported ON A RESPONSE.
   *
   * `attendanceCount` walks the connections that explicitly called `cello_use_agent`. A connection
   * can reach these handlers WITHOUT having done so, through `resolveCurrentAgent`'s sole-online
   * fallback — which is not exotic: it is every `cello` CLI invocation with no persisted selection,
   * and any MCP client that skipped the call. Such a reader was not counted, INCLUDING ITSELF, and
   * was handed `attendance: 0` — told that zero sessions attend the agent it is reading.
   *
   * That is worse than the missing field this AC set out to fix: not absent, but a definite
   * negative that is false. The caller is holding the response, so at least one session is on this
   * agent by construction. A response can never honestly say 0.
   */
  const attendingNow = (agentName: string): number => Math.max(1, attendanceCount(agentName));

  const sendInFlight = new Map<string, number>();
  /**
   * How long a claim is honored before a sibling may proceed anyway (review H3).
   *
   * `finally` covers throw and reject. It does NOT cover a promise that NEVER SETTLES, and
   * `sendContent` awaits `node.newStream` and `stream.close` with no timeout or abort signal —
   * only the relay submit is bounded. Before the claim existed, a hung libp2p stream hung ONE
   * call; with an unbounded claim it would refuse every sibling send on that conversation until
   * the daemon restarted, behind guidance that says "wait a moment" forever. Trading a permanent
   * outage for a small chance of the duplicate this line prevents is the wrong way round: the
   * defect is a bad conversation, the wedge is a dead one.
   *
   * Generous relative to the honest worst case (~30 s of bounded relay retries plus an unbounded
   * stream tail), so it expires hangs rather than races.
   */
  const SEND_CLAIM_TTL_MS = 60_000;

  // ─── CELLO-M7-DAEMON-004: cello_send (live send + daemon-owned tree append) ──
  handlers.set("cello_send", async (params, connectionId) => {
    const connState = getConnState(connectionId);
    // CC-3 / M8C-AUTOSTART-1 F18: explicit { agent } > current > sole online agent.
    const agentName = resolveCurrentAgent(connState, params?.agent as string | undefined);
    if (!agentName) return NO_CURRENT_AGENT_RESPONSE;

    // round-2 BLOCKING: read the snake_case public field cello-mcp.ts actually sends.
    const sessionId = params?.session_id as string | undefined;
    const contentStr = typeof params?.content === "string" ? params.content : undefined;
    if (!sessionId || contentStr === undefined) {
      return { ok: false, reason: "missing_params", guidance: "Provide 'session_id' (hex) and 'content' (string) parameters." };
    }

    // DOD-LOOP-1: the (agent, session_id) lookup is itself the ownership scope.
    const record = sessionNodeManager.getSessionRecord(agentName, sessionId);
    if (!record) {
      return { ok: false, reason: "session_not_found", guidance: "No session found with this ID. Check cello_sessions for active sessions." };
    }
    if (record.agent_name !== agentName) {
      return { ok: false, reason: "session_not_owned", guidance: "This session belongs to a different agent. Call cello_use_agent to switch to the agent that owns it, then retry." };
    }
    if (record.status !== "active") {
      return { ok: false, reason: "session_not_active", guidance: `Session is '${record.status}', not active. Content can only be sent on an active session. If it is interrupted, call cello_close_session to seal it.` };
    }

    // M8C-CURSOR-1: read-before-write gate. current_seq is the tree's highest leaf index
    // (message_count is kept in sync with leafCount on every append, both directions — DAEMON-004
    // finding #2), so it reflects EVERY message in the session regardless of which connection sent
    // or received it. If this connection hasn't read up to current_seq (e.g. a second attended
    // session on the same agent that hasn't polled since the other connection's last send), refuse
    // rather than let it send blind — the WhatsApp-group-chat model. Runs BEFORE the
    // governance-decisions parsing below: an access-control gate must short-circuit before any
    // unrelated prep work for a send that may not be allowed to proceed at all.
    //
    // The gate consults TWO authorities and passes if EITHER says the caller is caught up:
    //
    //   1. the connection cursor (in-memory, per-connection) — satisfied by a long-lived client
    //      like the MCP shim, which holds one socket for the whole session.
    //
    //   2. the persisted per-(agent, session) read watermark. A STATELESS client CANNOT satisfy
    //      authority 1: the `cello` CLI runs a fresh process, and therefore a fresh connection, per
    //      command, so it always presents cursor -1. Without the watermark, every CLI send is
    //      refused forever once the counterparty has spoken — as is every send from a RECONNECTING
    //      MCP client, whose new connectionId also resets the cursor to -1. Do not remove it.
    //
    // What the gate protects, precisely: an agent must never reply to COUNTERPARTY content nobody
    // on its side has seen. That guarantee is durable — it survives the socket.
    //
    // What it deliberately does NOT protect: a message this agent SENT from a different local
    // connection does not block. Two attended windows on one agent do not gate each other, because
    // locally-authored content is not "unread counterparty content" — the AGENT wrote it. The
    // principal is the agent, not the socket, and the daemon cannot referee which of an operator's
    // own windows a human is looking at. This is deliberate; do not "fix" it.
    const currentSeq = record.message_count - 1;
    // DOD-COATTEND-SENDWINDOW-1: the frontier AS THIS SEND SAW IT. Re-read immediately before the
    // wire, below — anything that moved it in between is a leaf this send was never checked
    // against.
    const frontierAtGate = sessionNodeManager.getSessionTree(agentName, sessionId).size();
    const connectionCursor = getConnectionCursor(connectionId, sessionId);
    const unreadReceived = sessionNodeManager.getUnreadReceivedCount(agentName, sessionId);
    const caughtUp = connectionCursor >= currentSeq || unreadReceived === 0;
    if (!caughtUp) {
      // M8C-CURSOR-1 (reviewer MEDIUM fix): every sibling rejection in this handler logs; this
      // gate must too — a security-relevant control-flow path with no observability is a gap.
      // Both authorities are logged, so the next reader can tell WHICH one refused.
      logger.warn("session.send.blocked", {
        sessionId,
        currentSeq,
        lastReadSeq: connectionCursor,
        unreadReceived,
        connectionId,
        agentName,
        // AC2 asks the event to NAME the authority that refused (review F7). Reaching this branch
        // means BOTH authorities said no — the gate passes if EITHER is satisfied — so there is no
        // "binding one" to report and the ternary I first wrote here was dead: `connectionCursor <
        // currentSeq` is always true at this point, so it could only ever print `unread_watermark`,
        // and an operator filtering for `connection_cursor` would get zero hits forever and
        // conclude cursor refusals do not exist. That is the defect F7 was raised to fix, rebuilt
        // (review H2). The true statement is that both are false; `lastReadSeq` and
        // `unreadReceived` above already carry which is how far off.
        authority: "cursor_and_watermark",
      });
      return {
        ok: false,
        reason: "session_not_current",
        current_seq: currentSeq,
        last_read_seq: connectionCursor,
        unread_received: unreadReceived,
        // DOD-ONBOARD-HELP-1 §5: say what is wrong and what to do, in that order, in plain words.
        // The old text opened with the internal noun ("this agent hasn't read…"); a refused send is
        // the most common wall a new operator hits, so it leads with the COUNT and the FIX. The
        // session id is interpolated so the remedy is copy-pasteable, not a template to fill in.
        // Rendered per surface at the IPC boundary — a CLI caller sees `cello receive <id>`.
        guidance: `${unreadReceived} unread message(s) — run cello_receive ${sessionId} first to read them, then send again. (Or cello_transcript ${sessionId} for the whole conversation.) You are blocked from replying to something you haven't read.`,
      };
    }

    // M9-FEED-001 §6: the agent's governance re-send decisions, keyed by the flagId a prior `warn`
    // returned. Optional; validated shape only (the gateway re-scans + applies them, INV-4). A
    // malformed map is ignored rather than failing the send (the gateway will just re-warn).
    const rawDecisions = params?.governance_decisions;
    let governanceDecisions: Record<string, "redact" | "allow_once" | "allow_always"> | undefined;
    if (rawDecisions && typeof rawDecisions === "object" && !Array.isArray(rawDecisions)) {
      const valid: Record<string, "redact" | "allow_once" | "allow_always"> = {};
      for (const [k, v] of Object.entries(rawDecisions as Record<string, unknown>)) {
        if (v === "redact" || v === "allow_once" || v === "allow_always") valid[k] = v;
      }
      if (Object.keys(valid).length > 0) governanceDecisions = valid;
    }

    const correlationId = randomUUID();
    const contentBytes = new TextEncoder().encode(contentStr);

    // CELLO-M7-MSG-001 (AC-013/AC-018/AC-021): enforce the 1 MB application content cap
    // BEFORE any transmission or hash/leaf production. This replaces the silent oversize
    // decode-failure → desync: the send is rejected with a distinct, diagnosable reason
    // and actionable guidance; no content frame is transmitted, no leaf is appended, and
    // the session stays usable.
    if (contentBytes.length > MAX_CONTENT_BYTES) {
      logger.warn("content.rejected.too_large", {
        sessionId,
        contentSize: contentBytes.length,
        cap: MAX_CONTENT_BYTES,
        correlationId,
      });
      return {
        ok: false,
        reason: "content_too_large",
        guidance: `This message is ${contentBytes.length} bytes, over the ${MAX_CONTENT_BYTES}-byte (1 MB) per-message content cap. Split it into multiple messages each under the cap, or use the large-object/file transfer path for large payloads (not cello_send). Nothing was sent and the session is still active — retry with smaller content.`,
      };
    }

    const recipientPubkey = record.counterparty_pubkey;

    // M9 outbound screening seam (INV-5/SI-001). Screen BEFORE anything reaches the wire. The
    // gateway verdict drives the four cello_send outcomes (M9-FEED-001): block / warn → NOT sent;
    // allow → sent as-is; redact → sent in ALTERED form. A configured-but-unreachable gateway fails
    // closed (block, gateway_unavailable), so a screening outage can never let content out ungated.
    const outboundVerdict = await securityGateway.screenOutbound(contentBytes, {
      direction: "outbound",
      agentName: record.agent_name,
      sessionId,
      correlationId,
      ...(governanceDecisions !== undefined ? { governanceDecisions } : {}),
    });
    if (outboundVerdict.disposition === "block") {
      if (outboundVerdict.reason === GOVERNANCE_TIMEOUT) {
        logger.error("security.gateway.timeout", { sessionId, reason: outboundVerdict.reason, correlationId });
      } else if (outboundVerdict.reason === GATEWAY_UNAVAILABLE) {
        logger.error("security.gateway.unavailable", { direction: "outbound", reason: outboundVerdict.reason, correlationId });
      } else {
        logger.info("security.verdict.returned", { disposition: "block", sessionId, reason: outboundVerdict.reason, correlationId });
      }
      return {
        ok: false,
        reason: outboundVerdict.reason ?? "blocked_by_governance",
        guidance: outboundVerdict.guidance ??
          "This message was blocked by the security gateway and was NOT sent. The session is still active.",
        blocks: (outboundVerdict.events ?? []).filter((e) => e.disposition === "block"),
      };
    }
    if (outboundVerdict.disposition === "warn") {
      logger.info("security.verdict.returned", { disposition: "warn", sessionId, correlationId });
      return {
        ok: false,
        reason: "governance_warn",
        guidance: outboundVerdict.guidance ??
          "This message was held for a governance decision and was NOT sent. Re-send the same content with a " +
          "governance_decisions map ({flagId: redact | allow_once | allow_always}) to resolve each flagged item.",
        flags: (outboundVerdict.events ?? []).filter((e) => e.disposition === "warn"),
      };
    }

    // FAIL-CLOSED (code-review MED): a `redact` verdict MUST carry the redacted content. If it ever
    // arrives without it, sending the original `contentBytes` would leak the pre-redaction draft — the
    // one place M9 could fail OPEN. Treat it as a block, never an allow-original. (Unreachable today:
    // the gateway always includes content on redact; this is the defensive floor.)
    if (outboundVerdict.disposition === "redact" && outboundVerdict.content === undefined) {
      logger.error("security.verdict.redact_without_content", { sessionId, correlationId });
      return {
        ok: false,
        reason: "redact_without_content",
        guidance: "The security gateway returned a redact verdict without the redacted content. To avoid " +
          "leaking the original, nothing was sent. This is a gateway fault — check the gateway logs and retry.",
      };
    }

    // allow or redact → send. On redact the ALTERED bytes are what go on the wire AND what the leaf
    // hash binds — the transcript records what was actually sent, not the pre-redaction draft.
    const modified = outboundVerdict.disposition === "redact" && outboundVerdict.content !== undefined;
    const sendBytes = modified ? new Uint8Array(outboundVerdict.content as Uint8Array) : contentBytes;
    const contentHash = wireContentHash(sendBytes);
    const contentHashHex = Buffer.from(contentHash).toString("hex");

    // ─── DOD-COATTEND-SENDWINDOW-1 (§4): re-check the gate, in the same synchronous window as the
    //     act that makes this message irreversible ───────────────────────────────────────────────
    //
    // NO AWAIT MAY BE INTRODUCED BETWEEN THIS CHECK AND `sendContent` BELOW. The check is only
    // worth anything because nothing can interleave between it and the wire; adding an await here
    // reopens exactly the window it closes, silently, while leaving code that still looks correct.
    //
    // WHY HERE AND NOT AT `appendSessionLeaf`, WHICH IS WHAT AC1 ASKS FOR. AC1 copies the inbound
    // pattern (`session-node-manager.ts:3682-3695`), where the append IS the commit point.
    // Outbound it is not: `sendContent` puts the message ON THE WIRE and runs BEFORE the append, so
    // by the append the counterparty already holds it. Refusing there would leave them holding
    // content this side never leafed — the two frontiers disagree, neither will co-sign, and the
    // session is unsealable except by forfeiting the receipt. That is DOD-FRONTIER-STRAND-1, the
    // defect that left `dbb93dfc…` stranded for a week, manufactured on purpose to satisfy the
    // letter of an AC. The purpose of AC1 is "re-check where it still matters"; outbound, that is
    // the wire.
    //
    // WHY A FRONTIER COMPARISON RATHER THAN RE-RUNNING `caughtUp`. AC3: the gate's second authority
    // is the PERSISTED read watermark, which is AGENT-scoped — so the moment ANY connection reads,
    // `unreadReceived === 0` for every one of them, and re-running the gate would pass a racing
    // sibling exactly as it passed the first time. That agent-scoping is DOD-CURSOR-DURABLE-1
    // behaving as its own §6 predicted: right for stateless clients, wrong for this. So the tighten
    // is stated AGAINST it rather than around it — this asks a question the watermark cannot
    // answer: "did the session move under me while I was gone?"
    const frontierNow = sessionNodeManager.getSessionTree(agentName, sessionId).size();
    const inFlightKey = `${agentName}\u0000${sessionId}`;
    const claimedAt = sendInFlight.get(inFlightKey);
    if (claimedAt !== undefined && Date.now() - claimedAt < SEND_CLAIM_TTL_MS) {
      // A sibling is between its own frontier check and its append RIGHT NOW. Its leaf does not
      // exist yet, so the comparison below cannot see it — this is the half of the window a
      // frontier check structurally cannot cover, whatever it is compared against.
      logger.warn("session.send.blocked", {
        sessionId, agentName, connectionId, correlationId,
        authority: "sibling_send_in_flight",
        claimHeldMs: Date.now() - claimedAt,
      });
      return {
        ok: false,
        reason: "session_moved_under_send",
        in_flight: true,
        // Says "may have sent" (review L4): the in-flight send can still fail and be queued for
        // retry, in which case nothing was said and there is nothing to read. Promising the operator
        // a reply that does not exist sends them to an unchanged transcript to look for it.
        guidance: `Another session on this agent is sending into this conversation right now, so nothing was sent. Wait a moment, then check cello_transcript ${sessionId} — they may have already answered — before deciding whether your reply still applies. Do not simply resend.`,
      };
    }
    if (frontierNow !== frontierAtGate) {
      logger.warn("session.send.blocked", {
        sessionId, agentName, connectionId, correlationId,
        authority: "frontier_moved_during_send",
        frontierAtGate, frontierNow,
      });
      return {
        ok: false,
        reason: "session_moved_under_send",
        frontier_at_gate: frontierAtGate,
        frontier_now: frontierNow,
        // Says LEAF, not "message" (review F6). The frontier counts leaves, and a leaf can exist
        // with no transcript row — a security-gateway terminal block commits one and never records
        // the text. Promising N messages in the transcript and delivering fewer sends the operator
        // hunting for content that was screened out and is not there.
        guidance: `The conversation moved while this message was being prepared — the session's record gained ${frontierNow - frontierAtGate} leaf/leaves from another session on this agent or from the counterparty, so nothing was sent. Read what arrived with cello_transcript ${sessionId} (a leaf that was screened out has no readable text and will not appear there), then decide whether your reply still applies. Do not simply resend: another session may have already answered.`,
      };
    }
    // THE CLAIM — taken in the same synchronous window as the check above (no await between them),
    // and released the instant the wire call settles.
    //
    // Releasing there is safe and is not an oversight: after `await sendContent` resolves, the
    // continuation runs the `finally`, the ok-check and `appendSessionLeaf` WITHOUT YIELDING, so no
    // other connection can observe the gap. By the time one runs again the frontier has either
    // moved (append happened → its own frontier comparison catches it) or the send failed and
    // nothing was committed (→ it is free to try). `finally` rather than a plain call so a throw
    // cannot wedge the session into permanent refusal.
    sendInFlight.set(inFlightKey, Date.now());
    let sendResult: Awaited<ReturnType<typeof sessionNodeManager.sendContent>>;
    try {
      sendResult = await sessionNodeManager.sendContent(record.agent_name, sessionId, sendBytes, new Uint8Array(contentHash), correlationId);
    } finally {
      sendInFlight.delete(inFlightKey);
    }
    if (!sendResult.ok) {
      // DB-001 / dead-channel contract: never silently drop, never desync. Preserve
      // the content in the durable retry_queue so it is retried on reconnect, and
      // surface a named, diagnosable failure.
      //
      // M12-P13 (review MEDIUM-4): NOT on the durable path. `drainSession` — this nonce queue's
      // only consumer — has no production caller, so every row it writes is permanent: unbounded
      // growth plus a second copy of the message plaintext at rest. On a durable failure the
      // awaiting-ACK queue already holds the content and actually drains, so writing here too
      // stored the same plaintext twice and drained neither copy from this table.
      if (!sendResult.durable) {
        const nonce = randomUUID();
        try {
          retryQueue.enqueue(sessionId, new TextEncoder().encode(nonce), sendBytes);
        } catch (err: unknown) {
          logger.error("session.content.queue.failed", {
            sessionId,
            error: err instanceof Error ? err.message : String(err),
            correlationId,
          });
        }
      }
      logger.warn("session.content.send.failed", {
        sessionId,
        recipientPubkey,
        reason: sendResult.reason,
        errorMessage: sendResult.error,
        durable: sendResult.durable,
        cause: sendResult.cause,
        correlationId,
      });
      // M12-P13: a DURABLY QUEUED message still owns the sequence the relay witnessed for it before
      // direct delivery was ever attempted — the same reasoning that makes a parked message occupy
      // its leaf position below. Leaving the hole here is what stalls the far side: `nextExpected`
      // is this tree's size, so the counterparty's next message arrives at a sequence this tree can
      // never reach and is held behind the gap forever (found live 2026-08-05, M12 Entry 89).
      // A LOST message gets no leaf — that would commit a sequence no content will ever fill, and
      // the two roots could then never seal.
      if (sendResult.durable) {
        const { leafIndex: queuedLeaf } = sessionNodeManager.appendSessionLeaf(record.agent_name, sessionId, "msg", contentHashHex, correlationId);
        sessionNodeManager.recordTranscriptMessage(record.agent_name, sessionId, queuedLeaf, "sent", sendBytes, correlationId);
        advanceConnectionCursor(connectionId, sessionId, queuedLeaf);
        logger.info("session.content.queued.committed", {
          sessionId, sequenceNumber: queuedLeaf, contentHash: contentHashHex, correlationId,
        });
        return {
          ok: false,
          reason: sendResult.reason,
          queued: true,
          sequence_number: queuedLeaf,
          guidance: sendResult.guidance ?? "The message is queued and will be re-sent automatically when the relay link is back. No action needed.",
        };
      }
      return {
        ok: false,
        reason: sendResult.reason,
        // M12-P12 (review pass 2): sendContent knows whether the content is actually recoverable;
        // this boundary used to overwrite that with one sentence promising a retry for EVERY
        // failure — including a persist that threw, where the message is simply gone, and a session
        // with no relay, where the direct nonce queue it names has no production drain. Telling an
        // operator "it will be retried" about a lost message is the same lie that let the original
        // defect sit unnoticed; the caller's own guidance wins whenever it has one.
        guidance: sendResult.guidance ?? "The content could not be delivered over the session stream right now, and no relay is configured for this session — it is NOT queued for automatic retry. Send it again once the counterparty is reachable; check cello_status for their status.",
      };
    }

    // Delivered directly OR dispatched to relay (DOD-LEAVEMSG-1) — either way the content is now
    // part of the daemon-owned tree: the relay witness (R1) already assigned it a sequence before
    // direct delivery was even attempted, so a parked message occupies the SAME leaf position it
    // would have taken if delivered live. Append once, for both outcomes.
    const { leafIndex, newRootHex } = sessionNodeManager.appendSessionLeaf(record.agent_name, sessionId, "msg", contentHashHex, correlationId);
    // DOD-LOG-1: persist the readable SENT plaintext to the durable transcript, keyed by the
    // canonical leaf sequence so it joins the committed hash chain (survives restart).
    // M9 merge fix: use sendBytes (the ALTERED bytes on a redact verdict), never the pre-redaction
    // contentBytes — the leaf hash above already binds sendBytes; the transcript must match what
    // actually went on the wire, not the pre-redaction draft (M9's own stated seam invariant).
    sessionNodeManager.recordTranscriptMessage(record.agent_name, sessionId, leafIndex, "sent", sendBytes, correlationId);
    // M8C-CURSOR-1: the sender authored this leaf — advance ITS OWN cursor so it doesn't get
    // blocked by session_not_current on its own just-sent message.
    advanceConnectionCursor(connectionId, sessionId, leafIndex);
    void newRootHex;
    // CC-1 (2026-07-07): operator engagement promotes the counterparty to a known contact. A
    // committed reply — past the read-before-write gate, content now on the wire AND in the tree —
    // IS the operator choosing to trust this sender; the inbound-accept path deliberately no longer
    // auto-adds (that defeated screening + anti-spam). For an OUTBOUND session the counterparty is
    // already a contact (cello_initiate_session added it), so this is an idempotent no-op there; it
    // matters for inbound-originated sessions, where the reply is the trust signal. addContact is
    // INSERT OR IGNORE — it never refreshes added_at. DOD-TIER-4 AC3: engaging (a committed reply into
    // an inbound session I accepted) makes the counterparty KNOWN, provenance 'accepted'. For an
    // OUTBOUND session the row already exists ('initiated', KNOWN) and INSERT OR IGNORE leaves it
    // untouched — 'initiated' correctly wins there.
    sessionNodeManager.addContact(record.agent_name, recipientPubkey, undefined, "accepted", TIER.KNOWN);
    if (modified) {
      logger.info("security.verdict.returned", { disposition: "redact", sessionId, sequenceNumber: leafIndex, correlationId });
    }
    if (!sendResult.delivered) {
      // DOD-LEAVEMSG-1 (sender half): direct delivery failed but the sealed, hashed content was
      // successfully deposited at the relay (pickup_queue) — this is a SUCCESS outcome, not a
      // failure. The recipient's daemon pulls it via RELAYWAKE on next reconnect. Reporting this
      // as ok:false (the pre-LEAVEMSG-1 behavior) misrepresented an in-flight message as lost.
      logger.info("session.content.dispatched_to_relay", {
        sessionId,
        recipientPubkey,
        contentHashHex,
        sequenceNumber: leafIndex,
        correlationId,
      });
      return {
        ok: true,
        sequence_number: leafIndex,
        delivered: false,
        reason: "dispatched_to_relay",
        modified,
        guidance: "The counterparty is not directly reachable right now, so this message was sealed and dispatched to relay store-and-forward. It will be delivered the next time the counterparty's daemon reconnects — no further action is needed.",
        ...(modified ? { transformations: (outboundVerdict.events ?? []).filter((e) => e.disposition === "redact") } : {}),
      };
    }
    logger.info("session.content.sent", {
      sessionId,
      recipientPubkey,
      contentHashHex,
      sequenceNumber: leafIndex,
      correlationId,
    });
    return {
      ok: true,
      sequence_number: leafIndex,
      delivered: true,
      modified,
      // On a redact, tell the agent exactly what was transformed (the §6 sender-side surface).
      ...(modified ? { transformations: (outboundVerdict.events ?? []).filter((e) => e.disposition === "redact") } : {}),
    };
  });

  // ─── CELLO-M7-DAEMON-004 / F1-a: cello_receive (BLOCKING, session-scoped) ────────
  // F1-a fix: the daemon port had dropped the blocking receive (the handler was a
  // non-blocking buf.shift). It now BLOCKS up to timeout_ms, polling the received-content
  // buffer — resolved by the next arrival, a terminal seal answer (F1-b), or timeout. This is
  // the "blocking receive variant" the guidance names.
  //
  // ONE name (DOD-ONBOARD-HELP-1, Andre 2026-07-11). This was briefly registered under
  // `cello_receive_session` as well — one implementation behind two names. That alias is DELETED:
  // it accepted or joined nothing (inbound sessions are auto-accepted by the standing receiver),
  // so it was a second name for a step that does not exist, and its help said otherwise.
  const RECEIVE_DEFAULT_TIMEOUT_MS = 30000; // matches the cello-mcp shim's documented default
  const handleReceive: IpcHandler = async (params, connectionId) => {
    const connState = getConnState(connectionId);
    // CC-3 / M8C-AUTOSTART-1 F18: explicit { agent } > current > sole online agent.
    const agentName = resolveCurrentAgent(connState, params?.agent as string | undefined);
    if (!agentName) return NO_CURRENT_AGENT_RESPONSE;

    // Read the snake_case public field cello-mcp.ts actually sends.
    const sessionId = params?.session_id as string | undefined;
    if (!sessionId) {
      return { ok: false, reason: "missing_params", guidance: "Provide 'session_id' (hex) to receive content for a specific session." };
    }
    const record = sessionNodeManager.getSessionRecord(agentName, sessionId);
    // DOD-UNREAD-1 D4b: a TRANSCRIPT-ONLY session — received rows exist but no sessions row (the
    // pre-D3/D4a phantom residue: the counterparty's reply landed while this side refused the
    // session). Those rows are counted unread by getUnreadSummary, so cello_receive MUST be able
    // to read them or the badge can never clear. Reading is a transcript operation: the since_seq
    // catch-up below works from the durable transcript alone. Only a session with NEITHER a row
    // NOR transcript rows is truly not found.
    let transcriptOnly = false;
    if (!record) {
      if (sessionNodeManager.readTranscript(agentName, sessionId).messages.length === 0) {
        return { ok: false, reason: "session_not_found", guidance: "No session found with this ID. Check cello_sessions." };
      }
      transcriptOnly = true;
    }
    // (D4 review F3: the old `record.agent_name !== agentName` → session_not_owned branch was dead
    // code — getSessionRecord is keyed by (agent_name, session_id), so a record can never belong to
    // a different agent. A cross-agent session id simply has no record under this agent.)

    // M8C-SINCESEQ-1: stateless catch-up. When since_seq is provided, return a BATCH of received
    // transcript messages with sequence > since_seq (durable transcript, not the ephemeral buffer —
    // so concurrent arrivals don't shift what a given since_seq returns; no replay race). Replaces
    // the cello_get_transcript workaround for away-then-return. Received-direction only (the messages
    // you'd have gotten live). Advances the read watermark (delivery marks read — clears INBOX
    // unread). A distinct early branch: the plain (no since_seq) receive is entirely unchanged.
    const rawSince = params?.since_seq;
    if (typeof rawSince === "number" && Number.isFinite(rawSince)) {
      const sinceSeq = rawSince;
      // D4b AC2: a transcript-only session has no record to attribute from — `from` is null,
      // NEVER the string "unknown" (the transcript stores no counterparty; don't invent one).
      const from = record ? record.counterparty_pubkey : null;
      const { messages } = sessionNodeManager.readTranscript(agentName, sessionId);
      const received = messages.filter((m) => m.direction === "received" && m.sequence > sinceSeq);
      if (received.length > 0) {
        // ─── review F8 (pre-existing, fixed here): this was a RAW VAULT to the highest received
        //     sequence in the batch — `advanceLastDeliveredSeq(…, maxSeq)` — which jumps any leaf
        //     in between. The leaf it jumps can be a transcript row that failed to decrypt:
        //     `readTranscript` drops such a row from `messages`, but `getUnreadReceivedCount`
        //     still counts it. So an undecryptable message was silently marked read, stopped
        //     counting as unread, and cleared the send gate's second authority — a message nobody
        //     could read, reported as read. That is precisely what CATCHUP AC3 forbids of a
        //     catch-up path, on the door that was NOT chosen, which is why it survived this long.
        //
        //     TWO THINGS THE WALK MUST GET RIGHT, and I got the second one wrong first (review H1).
        //
        //     (a) SEEDED AT `sinceSeq`, not at the stored watermark. `since_seq: N` is the CALLER
        //         ASSERTING it already holds through N, so rows at or below N are its claim and must
        //         not block the advance. Seeding at the watermark makes ordinary catch-up stop dead
        //         at the first row the caller skipped — M8C-SINCESEQ-1 S1/S2/S3 caught that.
        //
        //     (b) CONTIGUOUS OVER **BOTH DIRECTIONS**, not over the received-only batch. Leaf
        //         indices are contiguous across both directions, so a SENT leaf — this agent's own
        //         reply, or a sibling connection's — is a hole in any received-only set. Walking
        //         `received` therefore stopped on the most ordinary event in the protocol, and
        //         reading everything no longer cleared unread: the badge could not be cleared, and
        //         a stateless CLI caller was refused forever through the very door the guidance
        //         points at. That is CATCHUP §3b's own defect — a rule satisfiable only through a
        //         door the caller is not pointed at — reintroduced on the watermark.
        //
        //     The same received-only-view mistake as DOD-COATTEND-1 review F1, made a second time
        //     one file over: `daemon.ts` already says "every sibling send is a hole" in as many
        //     words. `cello_get_transcript` gets this right by walking both directions; so does this
        //     now. What still stops the walk is a genuinely absent index — an undecryptable row or a
        //     screened-out leaf, which have no transcript row at all and ARE unread.
        let frontier = sinceSeq;
        const presentSeqs = new Set(messages.map((m) => m.sequence));
        while (presentSeqs.has(frontier + 1)) frontier += 1;
        sessionNodeManager.advanceLastDeliveredSeq(agentName, sessionId, frontier); // MONOTONIC — takes MAX
        clearTelegramRung(agentName, sessionId); // M8C-TGDOOR-1: read clears the ring
      }
      // M8C-CURSOR-1 (reviewer HIGH fix): only advance through the CONTIGUOUS run this batch
      // actually delivered — if a sent leaf from another local connection sits in a gap, this
      // correctly refuses to advance past it (cello_get_transcript is still required to catch up).
      safeCursorAdvance(connectionId, sessionId, new Set(received.map((m) => m.sequence)));
      logger.info("session.receive.since_seq", { sessionId, agentName, since_seq: sinceSeq, count: received.length });
      return {
        ok: true,
        since_seq: sinceSeq,
        count: received.length,
        // AC6 (review F1): the catch-up batch is THE stateless-client door — `cello receive <id>
        // --since-seq -1` is a fresh connection every time, so it never saw a doorbell, and the
        // `session_not_live` refusal below points callers here BY NAME. Shipping attendance on the
        // live exits and not this one left the defect alive in the exact shape the AC exists for.
        attendance: attendingNow(agentName),
        messages: received.map((m) => ({ sequence: m.sequence, content: m.text, from })),
      };
    }

    // D4b AC3: the plain (blocking) receive waits on a LIVE session's buffer — a transcript-only
    // session has no live node and nothing will ever arrive. Waiting to a null timeout would be
    // misleading and session_not_found would be a lie (the transcript exists). A distinct reason
    // points the caller at the read that works.
    if (transcriptOnly) {
      return {
        ok: false,
        reason: "session_not_live",
        attendance: attendingNow(agentName),
        guidance: "This session exists only as a durable transcript (no live session — it was never established or predates this daemon). Read it with cello_receive { since_seq } (e.g. since_seq: -1 for everything) or cello_transcript.",
      };
    }

    const rawTimeout = params?.timeout_ms;
    const timeoutMs = typeof rawTimeout === "number" && Number.isFinite(rawTimeout) && rawTimeout >= 0
      ? rawTimeout
      : RECEIVE_DEFAULT_TIMEOUT_MS;
    const deadline = Date.now() + timeoutMs;
    // DOD-COATTEND-VISIBLE-1 AC3: before this line the plain blocking receive wrote NOTHING to the
    // log on ANY outcome — the only event in the path was `session.receive.since_seq`, which is the
    // OTHER branch — so a session having its message taken by a sibling left no trace anywhere, for
    // the operator in the moment or for anyone reading the log afterwards. One correlationId threads
    // every exit below.
    const receiveCorrelationId = randomUUID();
    // Recomputed at EVERY exit, never snapshotted here (review MEDIUM): the loop below blocks for
    // up to timeout_ms — 30 s by default — and sessions attach and detach inside that window. A
    // count captured before the wait is stale exactly when it matters, and it is the number the
    // operator reads and the number interpolated into the guidance. It is an O(connections) walk
    // over a handful of entries; there is nothing to save by caching it.

    for (;;) {
      // TERMINAL FIRST (DOD-COATTEND-1). Reading the DURABLE RECORD means a sealed session's rows
      // are still present, so a content read would keep delivering on a session that has already
      // terminated — and F1-b's `session_sealed` answer would never be reached. Under the old
      // destructive queue this ordering did not matter, because the seal EVICTED the buffer and the
      // read found nothing. It matters now, so the terminal answer is checked before the record.
      //
      // F1-b: the session sealed while we were (or before we started) waiting — return the
      //    terminal answer instead of hanging to timeout. unread_count reports messages that
      //    were evicted unread (still durable — recoverable via cello_get_transcript).
      const terminal = sessionNodeManager.peekTerminalMarker(agentName, sessionId);
      if (terminal) {
        const sealedRoot = sessionNodeManager.getSealedRootHex(agentName, sessionId);
        // AC3 covers "both outcomes" — got something / got nothing. This is the third exit from the
        // same silent handler, and leaving it silent would reproduce the defect one branch over.
        logger.info("session.receive.sealed", {
          sessionId, agentName, connectionId, attendance: attendanceCount(agentName),
          unreadCount: terminal.unreadCount, correlationId: receiveCorrelationId,
        });
        return {
          ok: true,
          type: "session_sealed",
          session_id: sessionId,
          ...(sealedRoot ? { sealed_root: sealedRoot } : {}),
          unread_count: terminal.unreadCount,
          attendance: attendingNow(agentName),
          guidance: terminal.unreadCount > 0
            ? `The session has been sealed by both parties. ${terminal.unreadCount} message(s) arrived that were not read live — call cello_transcript to retrieve the full sealed history. No further actions are required on this session.`
            : "The session has been sealed by both parties. The full history is available via cello_transcript. No further actions are required on this session.",
        };
      }
      // ─── DOD-COATTEND-1: read the DURABLE RECORD against THIS connection's bookmark ───
      //
      // This used to be `takeReceivedContent`, a `buf.shift()` on a buffer keyed
      // (agentName, sessionId) and NOT by connection. The doorbell is multicast, so two attached
      // sessions were both woken, both entered this loop, and whichever hit the next 20 ms tick
      // first REMOVED the message from the other's view — which was then told, word for word, what
      // a quiet counterparty produces.
      //
      // Now: the transcript is the source of truth and each connection has its own cursor, so
      // reading is non-destructive by construction. Nothing one consumer does mutates state another
      // consumer reads — which is exactly what `shift()` violated. The doorbell STAYS multicast
      // (AC 2); the queue was the defect, not the wake-up.
      //
      // Ordering is safe: `#appendVerifiedContent` writes the transcript row (`:3996`) BEFORE it
      // pushes to the buffer (`:4003`), so the record can never lag the queue this replaces.
      //
      // The bar is the DELIVERY BOOKMARK, not the gate's read cursor (review F1, BLOCKING). Using
      // the cursor here pinned this connection below the first gap in its received-only view — and
      // a sibling connection's SENT leaf is such a gap, as is a security-gateway block that leaves
      // a permanent hole. The same message was then re-served on every call, forever. The gate's
      // cursor stays exactly as it was; it simply is not the thing that answers this question.
      const deliveredThrough = getDeliveryBookmark(connectionId, sessionId);
      // Asked ~47x/second per blocked connection, so the predicate is in SQL and exactly one blob is
      // decoded (review F5). The obvious `readTranscript().messages.find(...)` decoded the entire
      // session on every tick and threw all of it away.
      //
      // Guarded on `record` (review F7 claimed this guard was dead — it is NOT, and the typecheck
      // proved it): a TRANSCRIPT-ONLY session has received rows and no `sessions` row, and it does
      // not return above, it falls through with `record === null`. Live delivery needs the
      // counterparty pubkey, which only the record carries, so those sessions are read through the
      // since_seq catch-up from the transcript alone — exactly as before this change. Dropping the
      // guard is a null dereference on the one session shape that reaches here without a record.
      const nextRow = record
        ? sessionNodeManager.findNextReceivedAfter(agentName, sessionId, deliveredThrough)
        : null;
      const entry = nextRow
        ? {
          contentHex: Buffer.from(nextRow.text, "utf8").toString("hex"),
          senderPubkey: record!.counterparty_pubkey,
          sequenceNumber: nextRow.sequence,
        }
        : null;
      if (entry) {
        // M8C-INBOX-1 (N3): delivery marks read — advance the persisted read watermark so this
        // message no longer counts as unread in cello_check_notifications. Monotonic (never lowers).
        sessionNodeManager.advanceLastDeliveredSeq(agentName, sessionId, entry.sequenceNumber);
        clearTelegramRung(agentName, sessionId); // M8C-TGDOOR-1: read clears the ring
        // M8C-CURSOR-1 (reviewer HIGH fix): a single delivered message only proves THIS sequence
        // was read — safeCursorAdvance refuses to vault past a gap (e.g. an unread sent leaf from
        // another local connection) even though this specific sequence number is now known.
        safeCursorAdvance(connectionId, sessionId, new Set([entry.sequenceNumber]));
        // ...and separately, this connection has now BEEN HANDED this leaf. Monotonic, no gap walk:
        // that is the whole distinction (review F1). Without this the read above re-finds the same
        // row on the next call.
        advanceDeliveryBookmark(connectionId, sessionId, entry.sequenceNumber);
        // DOD-COATTEND-VISIBLE-1: the ledger of which connection was handed which leaf.
        //
        // It was written when this WAS a destructive drain, and the comment here used to say so —
        // "the message has just been REMOVED from every co-attending session's view". That is no
        // longer true and had become the most misleading sentence in the file (review F6): it
        // asserted the very property this unit removed, at the one site a reader would come to
        // check it. Delivery is non-destructive now; the ledger survives because the `taken_by_
        // sibling_session` discriminator still reads it, and its deletion is its own unit.
        contentTakes.record(agentName, sessionId, connectionId, entry.sequenceNumber);
        logger.info("session.receive.delivered", {
          sessionId, agentName, connectionId, sequenceNumber: entry.sequenceNumber,
          attendance: attendanceCount(agentName), correlationId: receiveCorrelationId,
        });
        const contentText = Buffer.from(entry.contentHex, "hex").toString("utf8");
        const trimmed = contentText.trimEnd();
        const signalGuidance =
          trimmed.endsWith("[[WRAP]]")
            ? "Counterparty wrapped. Call cello_close_session now — do not reply."
            : trimmed.endsWith("[[OVER]]")
              ? "Counterparty's turn is done. Counterparty has indicated they are expecting a reply — use cello_send to reply."
              : /\[\[STANDBY EST:\d+m\]\]$/.test(trimmed)
                ? "Counterparty is working and will follow up when done — no response expected. To block: call cello_receive with a longer timeout_ms. To check back later: schedule a cron and call cello_receive then."
                : undefined;
        return {
          ok: true,
          content: contentText,
          // AC6: every READ answer says whether this session is alone. The push already carried
          // this; the read surfaces did not, so a session that never saw a doorbell — a fresh MCP
          // connection, EVERY `cello` CLI invocation, anything that attached after the last
          // arrival — had no way to learn it was co-attended. Live finding, journal Entry 33.
          attendance: attendingNow(agentName),
          sessionId,
          sequence_number: entry.sequenceNumber,
          senderPubkey: entry.senderPubkey,
          ...(signalGuidance !== undefined ? { guidance: signalGuidance } : {}),
        };
      }
      // 3) Out of time — non-blocking-equivalent empty answer.
      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        // ─── DOD-COATTEND-1 (review F2): a LOCAL failure must not wear the counterparty's label ───
        //
        // Content arrived, was verified and leafed, and its plaintext failed to reach the
        // transcript. Since Tier 1 the transcript IS the delivery path, so that message can never
        // be handed to any session. Every word of the empty answer below is wrong for this case:
        // waiting cannot help, the transcript does not hold it, and "do not resend your last
        // message" is aimed at the one party who could still fix it. Answer with the actual fault,
        // above the branch that would otherwise substitute for it.
        const undeliverable = sessionNodeManager.getUndeliverableSeqs(agentName, sessionId);
        if (undeliverable.length > 0) {
          logger.error("session.receive.undeliverable", {
            sessionId, agentName, connectionId, sequences: undeliverable,
            attendance: attendanceCount(agentName), correlationId: receiveCorrelationId,
          });
          return {
            ok: true,
            content: null,
            reason: "content_undeliverable",
            attendance: attendingNow(agentName),
            undeliverable_sequences: [...undeliverable],
            guidance: `${undeliverable.length} message(s) arrived but could not be written to the local transcript, so they cannot be delivered — this is a fault on THIS machine (check disk space and ~/.cello permissions; see transcript.message.record.failed in the daemon log), not a quiet counterparty. Do not wait: waiting cannot recover them. Ask the counterparty to resend once the local fault is fixed.`,
          };
        }
        const liveness = sessionNodeManager.getSessionLiveness(agentName, sessionId);
        const attendance = attendanceCount(agentName);
        // ─── DOD-COATTEND-VISIBLE-1 AC1: the loser of the race gets a DIFFERENT answer ───
        //
        // The buffer is keyed (agentName, sessionId) and drained with `buf.shift()`, so when the
        // multicast doorbell wakes two attending sessions the faster one REMOVES the message. Until
        // this branch existed the slower one was told, word for word, what a quiet counterparty
        // produces — and nothing was logged either, so the theft left no trace anywhere.
        //
        // The bar is this connection's own read cursor, not a time window: it reports content this
        // connection genuinely has not seen, and it CLEARS itself once the caller catches up. The
        // discriminator is `reason` — the field this very return already uses for its other branch —
        // so a caller switching on it needs no new shape. `taken_by_sibling` carries the machine-
        // readable detail; the prose below is the presentation of that, never a substitute for it.
        const missed = contentTakes.missedBy(
          agentName, sessionId, connectionId, getConnectionCursor(connectionId, sessionId),
        );
        if (missed) {
          // The message a sibling took is described WITHOUT claiming that sibling still attends
          // this agent (review MEDIUM). A connection may operate on the sole online agent through
          // `resolveCurrentAgent` WITHOUT attending it, and it drains the same buffer — so a real
          // thief need not be counted in `attendance`. The old wording produced sentences that
          // contradicted themselves ("another session attending alice — 1 sessions are attending").
          // `attendance` stays as its own field, meaning what it says: how many sessions SELECTED
          // this agent.
          const takenDetail = {
            count: missed.count,
            last_sequence: missed.lastSequence,
            connections: missed.connections,
            // `count` is a floor once the per-session cap has discarded older takes.
            ...(missed.truncated ? { truncated: true } : {}),
          };
          logger.warn("session.receive.taken_by_sibling", {
            sessionId, agentName, connectionId, timeoutMs, attendance, liveness,
            takenCount: missed.count, lastTakenSeq: missed.lastSequence, takenBy: missed.connections,
            truncated: missed.truncated, correlationId: receiveCorrelationId,
          });
          const missedText = `Another session on this daemon already received ${missed.count} message(s) on this session that you have not read (up to sequence ${missed.lastSequence}). Nothing was lost: read what you missed with cello_transcript ${sessionId}.`;
          // BOTH conditions can be true, and `counterparty_gone` WINS the `reason` field when they
          // are (review MEDIUM). `reason` is the machine-readable discriminator, and a caller
          // switching on it must still see the TERMINAL, actionable condition: telling an operator
          // to "read what you missed, then reply" to a counterparty whose connection is dead sends
          // them to the wrong subsystem and the reply goes nowhere. The theft is additive
          // information, so it rides as a field and as the first half of the guidance — nothing is
          // hidden, but the answer names the condition that changes what the operator should DO.
          if (liveness === "gone") {
            return {
              ok: true,
              content: null,
              reason: "counterparty_gone",
              liveness: "gone",
              taken_by_sibling: takenDetail,
              attendance,
              guidance: `${missedText} Note the counterparty's session connection has ALSO dropped (liveness: gone), so no more content will arrive and a reply cannot reach them — call cello_close_session to seal the session once you have read the history. If the counterparty never co-closes, a unilateral seal becomes available after the directory's delivery-grace window.`,
            };
          }
          return {
            ok: true,
            content: null,
            reason: "taken_by_sibling_session",
            taken_by_sibling: takenDetail,
            attendance,
            guidance: `${missedText} Then reply — do not resend your last message.`,
          };
        }
        // M8B F16: a dead session must not return the SAME null timeout as a
        // quiet-but-healthy one. The liveness signal (session.liveness.changed → gone,
        // tracked per session by the node manager) finally reaches the MCP surface here.
        if (liveness === "gone") {
          logger.info("session.receive.empty", {
            sessionId, agentName, connectionId, timeoutMs, attendance,
            liveness, correlationId: receiveCorrelationId,
          });
          return {
            ok: true,
            content: null,
            attendance: attendingNow(agentName),
            reason: "counterparty_gone",
            liveness: "gone",
            guidance: "The counterparty's session connection has dropped (liveness: gone) — it may have crashed or gone offline. No more content will arrive on the direct path. Call cello_close_session to seal the session; if the counterparty never co-closes, a unilateral seal becomes available after the directory's delivery-grace window.",
          };
        }
        logger.info("session.receive.empty", {
          sessionId, agentName, connectionId, timeoutMs, attendance,
          liveness, correlationId: receiveCorrelationId,
        });
        // AC6: the QUIET answer carries it too. This is the exit a session with no doorbell to
        // learn from is most likely to reach — it attached, found nothing waiting, and would
        // otherwise have no way to know another window holds the same agent.
        return {
          ok: true,
          content: null,
          attendance: attendingNow(agentName),
          guidance: "No content arrived within timeout_ms. Call cello_receive again to keep waiting — do not resend your last message. Or read cello_transcript for the full session history.",
        };
      }
      await new Promise((r) => setTimeout(r, Math.min(20, remaining)));
    }
  };
  handlers.set("cello_receive", handleReceive);
}
