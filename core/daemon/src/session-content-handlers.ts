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
import { randomUUID, createHash } from "node:crypto";
import { MAX_CONTENT_BYTES } from "@cello-protocol/protocol-types";
import { TIER } from "./contacts-tier-migration.js";
import { GATEWAY_UNAVAILABLE, GOVERNANCE_TIMEOUT, type SecurityGatewayClient } from "@cello-protocol/gateway";
import type { IpcHandler } from "./ipc-server.js";
import type { SessionNodeManager } from "./session-node-manager.js";
import type { RetryQueue } from "./retry-queue.js";
import type { Logger } from "./types.js";
import type { ConnState } from "./contact-handlers.js";

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
  /** M8C-TGDOOR-1: a read clears the doorbell's ring-once-until-read. */
  clearTelegramRung: (agentName: string, sessionId: string) => void;
}

export function registerSessionContentHandlers(deps: SessionContentDeps): void {
  const {
    handlers, logger, sessionNodeManager, securityGateway, retryQueue,
    getConnState, resolveCurrentAgent, NO_CURRENT_AGENT_RESPONSE,
    getConnectionCursor, advanceConnectionCursor, safeCursorAdvance, clearTelegramRung,
  } = deps;

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
    const contentHash = createHash("sha256").update(new Uint8Array([0x00])).update(sendBytes).digest();
    const contentHashHex = Buffer.from(contentHash).toString("hex");

    const sendResult = await sessionNodeManager.sendContent(record.agent_name, sessionId, sendBytes, new Uint8Array(contentHash), correlationId);
    if (!sendResult.ok) {
      // DB-001 / dead-channel contract: never silently drop, never desync. Preserve
      // the content in the durable retry_queue so it is retried on reconnect, and
      // surface a named, diagnosable failure.
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
      logger.warn("session.content.send.failed", {
        sessionId,
        recipientPubkey,
        reason: sendResult.reason,
        errorMessage: sendResult.error,
        correlationId,
      });
      return {
        ok: false,
        reason: sendResult.reason,
        guidance: "The content could not be delivered over the session stream right now. It has been queued in the durable retry queue and will be retried when the counterparty reconnects. The session remains usable — check cello_status for the counterparty's status.",
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
        // readTranscript is ordered by sequence ASC → the last is the max.
        const maxSeq = received[received.length - 1].sequence;
        sessionNodeManager.advanceLastDeliveredSeq(agentName, sessionId, maxSeq);
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
        guidance: "This session exists only as a durable transcript (no live session — it was never established or predates this daemon). Read it with cello_receive { since_seq } (e.g. since_seq: -1 for everything) or cello_transcript.",
      };
    }

    const rawTimeout = params?.timeout_ms;
    const timeoutMs = typeof rawTimeout === "number" && Number.isFinite(rawTimeout) && rawTimeout >= 0
      ? rawTimeout
      : RECEIVE_DEFAULT_TIMEOUT_MS;
    const deadline = Date.now() + timeoutMs;

    for (;;) {
      // 1) Deliverable content wins — drain one buffered message per call (FIFO).
      const entry = sessionNodeManager.takeReceivedContent(agentName, sessionId);
      if (entry) {
        // M8C-INBOX-1 (N3): delivery marks read — advance the persisted read watermark so this
        // message no longer counts as unread in cello_check_notifications. Monotonic (never lowers).
        sessionNodeManager.advanceLastDeliveredSeq(agentName, sessionId, entry.sequenceNumber);
        clearTelegramRung(agentName, sessionId); // M8C-TGDOOR-1: read clears the ring
        // M8C-CURSOR-1 (reviewer HIGH fix): a single delivered message only proves THIS sequence
        // was read — safeCursorAdvance refuses to vault past a gap (e.g. an unread sent leaf from
        // another local connection) even though this specific sequence number is now known.
        safeCursorAdvance(connectionId, sessionId, new Set([entry.sequenceNumber]));
        return {
          ok: true,
          content: Buffer.from(entry.contentHex, "hex").toString("utf8"),
          sessionId,
          sequence_number: entry.sequenceNumber,
          senderPubkey: entry.senderPubkey,
        };
      }
      // 2) F1-b: the session sealed while we were (or before we started) waiting — return the
      //    terminal answer instead of hanging to timeout. unread_count reports messages that
      //    were evicted unread (still durable — recoverable via cello_get_transcript).
      const terminal = sessionNodeManager.peekTerminalMarker(agentName, sessionId);
      if (terminal) {
        const sealedRoot = sessionNodeManager.getSealedRootHex(agentName, sessionId);
        return {
          ok: true,
          type: "session_sealed",
          session_id: sessionId,
          ...(sealedRoot ? { sealed_root: sealedRoot } : {}),
          unread_count: terminal.unreadCount,
          guidance: terminal.unreadCount > 0
            ? `The session has been sealed by both parties. ${terminal.unreadCount} message(s) arrived that were not read live — call cello_transcript to retrieve the full sealed history. No further actions are required on this session.`
            : "The session has been sealed by both parties. The full history is available via cello_transcript. No further actions are required on this session.",
        };
      }
      // 3) Out of time — non-blocking-equivalent empty answer.
      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        // M8B F16: a dead session must not return the SAME null timeout as a
        // quiet-but-healthy one. The liveness signal (session.liveness.changed → gone,
        // tracked per session by the node manager) finally reaches the MCP surface here.
        if (sessionNodeManager.getSessionLiveness(agentName, sessionId) === "gone") {
          return {
            ok: true,
            content: null,
            reason: "counterparty_gone",
            liveness: "gone",
            guidance: "The counterparty's session connection has dropped (liveness: gone) — it may have crashed or gone offline. No more content will arrive on the direct path. Call cello_close_session to seal the session; if the counterparty never co-closes, a unilateral seal becomes available after the directory's delivery-grace window.",
          };
        }
        return { ok: true, content: null, guidance: "No content arrived within timeout_ms. Call cello_receive again to keep waiting, or read cello_transcript for the full session history." };
      }
      await new Promise((r) => setTimeout(r, Math.min(20, remaining)));
    }
  };
  handlers.set("cello_receive", handleReceive);
}
