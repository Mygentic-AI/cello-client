/**
 * The verbs that exist for TESTS, and nothing else.
 *
 * Two groups with different guards, and the difference is why this file has a header. The seven
 * `__test_*` verbs sit inside `CELLO_ENV === "test"` and cannot be reached in production. The six
 * above them — `queue_failed_send`, `debug_inject_park_fault`, `enqueue_awaiting_content`,
 * `mark_content_acked`, `check_nonce`, `drain_session` — are NOT gated, and FOUR of them write state.
 * `check_nonce` is the one to notice: it does not merely read, it `checkAndAdd`s, which INSERTs into
 * `session_seen_nonces` and survives a restart — so pre-registering a nonce makes the real message
 * carrying it arrive and be discarded as a duplicate, logged at debug and nowhere else. Their only
 * callers are tests (measured: nothing in the CLI, nothing in the MCP shim), so a production daemon
 * answers six verbs nobody outside a test has a use for.
 *
 * ⚠️ THE ASYMMETRY IS RECORDED, NOT FIXED HERE. Gating them changes behaviour and this is a movement
 * order; the guard structure moved exactly as it was. It is written into the order's *Newly
 * discovered* so it can be ranked — rather than inherited by the next reader, who would see the file
 * name and assume the whole thing is unreachable in production.
 *
 * ⚠️ TWO PRODUCTION REGISTRATIONS DID NOT COME WITH IT. `contentPark.registerHandlers(handlers)` and
 * `registerInboundSessionHandlers(handlers)` sit between the two groups in the original file and are
 * real surfaces. They stay in the composition root; only the test verbs on either side moved. That
 * DOES change registration order — those two now run after all thirteen instead of between them —
 * and it is inert: dispatch resolves against the live map on each request rather than snapshotting
 * it, the IPC server is not created until every registration has run, and none of these verb names
 * collides. Written down because "do not reorder registration" is a rule of this order, and the
 * next reader deserves the measurement rather than the worry.
 */
import type { IpcHandler } from "./ipc-server.js";
import type { SessionNodeManager } from "./session-node-manager.js";
import type { Logger } from "./types.js";
import type { RetryQueue } from "./retry-queue.js";
import type { NonceDedupStore } from "./nonce-dedup.js";
import { REFUSAL_REASONS, CAPACITY_REASONS, type AnyRefusalReason } from "./refusal-reasons.js";
import type { InboundSessionEvent } from "./inbound-sessions.js";

/** The per-connection agent selection, as these verbs need to read it. */
export interface TestConnState { currentAgent: string | null; }

export interface TestHandlerDeps {
  handlers: Map<string, IpcHandler>;
  logger: Logger;
  sessionNodeManager: SessionNodeManager;
  retryQueue: RetryQueue;
  nonceDedupStore: NonceDedupStore;
  /** Opens a delivery window and hands back the release. */
  deliveryOpens: { begin: (openerPubkey: string, targetPubkey: string) => () => void };
  /** Name → pubkey, empty string when this daemon holds no such agent. */
  pubkeyOfAgent: (name: string) => string;
  /** The one dispatch path that also reaches Telegram — tests drive it to assert both halves. */
  dispatchSessionStateChangedWithTelegram: (
    agentName: string,
    sessionId: string,
    state: string,
    counterpartyPubkey: string | null,
  ) => void;
  /** The inbound-session queue machinery these verbs seed, injected rather than reached for. */
  enqueueInboundSession: (agentName: string, event: InboundSessionEvent) => void;
  recordRefusal: (
    agentName: string,
    sessionIdHex: string,
    counterpartyPubkeyHex: string,
    reason: AnyRefusalReason,
  ) => void;
  /** The queue itself — one verb backdates the entry it just enqueued, which needs the container. */
  inboundSessionQueues: Map<string, InboundSessionEvent[]>;
  /** Read this connection's agent selection. The READ, not the container. */
  getConnState: (connectionId: string) => TestConnState | undefined;
}

export function registerTestHandlers(deps: TestHandlerDeps): void {
  const {
    handlers,
    logger,
    sessionNodeManager,
    retryQueue,
    nonceDedupStore,
    deliveryOpens,
    pubkeyOfAgent,
    dispatchSessionStateChangedWithTelegram,
    enqueueInboundSession,
    recordRefusal,
    inboundSessionQueues,
    getConnState,
  } = deps;

  handlers.set("queue_failed_send", async (params, _connectionId) => {
    const sessionId = params?.sessionId as string | undefined;
    const nonceHex = params?.nonce as string | undefined;
    const contentHex = params?.content as string | undefined;
    if (!sessionId || !nonceHex || !contentHex) {
      return { error: "missing_params", guidance: "Provide sessionId, nonce (hex), and content (hex)." };
    }
    const nonce = Buffer.from(nonceHex, "hex");
    const content = Buffer.from(contentHex, "hex");
    retryQueue.enqueue(sessionId, nonce, content);
    return { queued: true, queueDepth: retryQueue.getSessionDepth(sessionId) };
  });

  // CELLO-M7-MSG-001 (AC-004/AC-005): the send path records un-acked content here when
  // its TTF timer fires, so a crash before the relay park confirms is recoverable at the
  // next startup flush. Stored in the SAME retry_queue table (awaiting_ack = 1).
  // M12-P12 verification surface. REFUSES unless the daemon was started with
  // CELLO_FAULT_INJECTION=1 — the gate is here rather than at the call site so a normal daemon
  // cannot be talked into dropping messages by anything that can reach the socket, and the refusal
  // names why rather than silently no-opping.
  handlers.set("debug_inject_park_fault", async (params) => {
    if (process.env.CELLO_FAULT_INJECTION !== "1") {
      return {
        error: "fault_injection_disabled",
        guidance: "Start the daemon with CELLO_FAULT_INJECTION=1 to enable. This is a verification surface for M12-P12 and is inert in a normal daemon.",
      };
    }
    const count = typeof params?.count === "number" ? params.count : 1;
    const cause = typeof params?.cause === "string" ? params.cause : undefined;
    const armed = sessionNodeManager.injectParkFault(count, cause);
    // The park fault alone reproduces nothing — the counterparty's session node accepts the frame
    // and the park path is never entered. Arm the dial failure with it unless told otherwise.
    const sendArmed = params?.withSendFault === false ? 0 : sessionNodeManager.injectSendFault(count);
    logger.warn("content.park.fault.armed", { count: armed, sendArmed, cause: cause ?? "standing_receiver_creating" });
    return { armed, sendArmed };
  });

  handlers.set("enqueue_awaiting_content", async (params, connectionId) => {
    const sessionId = params?.sessionId as string | undefined;
    const contentHashHex = params?.contentHash as string | undefined;
    const contentHex = params?.content as string | undefined;
    if (!sessionId || !contentHashHex || !contentHex) {
      return { error: "missing_params", guidance: "Provide sessionId, contentHash (hex), and content (hex)." };
    }
    // DOD-LOOP-1: awaiting content is keyed by the OWNING agent. Prefer an explicit agentName param;
    // fall back to the connection's current agent.
    // DOD-AGENT-ID-JOINKEY-1: the old `?? ""` fell back to an EMPTY-STRING agent, silently merging
    // every unaddressed caller's awaiting content into one nameless queue. There is no such agent.
    const agentName = (params?.agentName as string | undefined)
      ?? getConnState(connectionId)?.currentAgent;
    if (!agentName) {
      return { error: "no_current_agent", guidance: "Select an agent with cello_use_agent, or pass agentName." };
    }
    const agentId = sessionNodeManager.resolveAgentId(agentName);
    // The fault-injection IPC seam. It states all three trailing values explicitly rather than
    // relying on defaults (B2b-1 pass-2 F1): `undefined` for the ordering record and the algorithm
    // is what this path genuinely has — it injects a bare queued entry — and saying so keeps the
    // seam honest about what it is producing rather than inheriting whatever the signature assumed.
    retryQueue.enqueueAwaitingContent(agentId, sessionId, Buffer.from(contentHashHex, "hex"), Buffer.from(contentHex, "hex"), undefined, undefined, undefined);
    return { queued: true, awaitingDepth: retryQueue.getAwaitingDepth(agentId, sessionId) };
  });

  // CELLO-M7-MSG-001: a `persisted` delivery ACK (or a confirmed park) clears the durable
  // awaiting-ACK entry so the startup flush does not re-park already-delivered content.
  handlers.set("mark_content_acked", async (params, connectionId) => {
    const sessionId = params?.sessionId as string | undefined;
    const contentHashHex = params?.contentHash as string | undefined;
    if (!sessionId || !contentHashHex) {
      return { error: "missing_params", guidance: "Provide sessionId and contentHash (hex)." };
    }
    const agentName = (params?.agentName as string | undefined)
      ?? getConnState(connectionId)?.currentAgent;
    if (!agentName) {
      return { error: "no_current_agent", guidance: "Select an agent with cello_use_agent, or pass agentName." };
    }
    const agentId = sessionNodeManager.resolveAgentId(agentName);
    retryQueue.markContentAcked(agentId, sessionId, Buffer.from(contentHashHex, "hex"));
    return { acked: true, awaitingDepth: retryQueue.getAwaitingDepth(agentId, sessionId) };
  });

  handlers.set("check_nonce", async (params, _connectionId) => {
    const sessionId = params?.sessionId as string | undefined;
    const nonceHex = params?.nonce as string | undefined;
    const senderPubkeyHex = params?.senderPubkey as string | undefined;
    if (!sessionId || !nonceHex || !senderPubkeyHex) {
      return { error: "missing_params", guidance: "Provide sessionId, nonce (hex), and senderPubkey (hex)." };
    }
    const nonce = Buffer.from(nonceHex, "hex");
    const senderPubkey = Buffer.from(senderPubkeyHex, "hex");
    const duplicate = nonceDedupStore.checkAndAdd(sessionId, nonce, senderPubkey);
    return { duplicate };
  });

  // DAEMON-003: drain_session IPC handler — triggered on peer reconnect.
  // Returns pending entry metadata (nonces only — SI-002 forbids content in IPC frames).
  // The actual drain+delivery is triggered separately when a real sendFn is available.
  handlers.set("drain_session", async (params, _connectionId) => {
    const sessionId = params?.sessionId as string | undefined;
    if (!sessionId) {
      return { error: "missing_params", guidance: "Provide sessionId." };
    }
    const depth = retryQueue.getSessionDepth(sessionId);
    const entries = retryQueue.getSessionEntries(sessionId);
    return { pendingCount: depth, nonces: entries.map(e => e.nonceHex) };
  });

  // MCP-002: Test-only handler to emit session lifecycle events.
  // Guarded by CELLO_ENV=test — never available in production.
  if (process.env["CELLO_ENV"] === "test") {
  handlers.set("__test_emit_session_event", async (params, _connectionId) => {
    const type = params?.type as string | undefined;
    const sessionId = params?.sessionId as string | undefined;
    const agentName = params?.agentName as string | undefined;
    const counterpartyPubkey = (params?.counterpartyPubkey as string) ?? null;

    if (!type || !sessionId || !agentName) {
      return { error: "missing_params", guidance: "Provide type, sessionId, and agentName." };
    }

    if (type === "created") {
      const sessionPeerId = (params?.sessionPeerId as string) ?? "";
      const correlationId = (params?.correlationId as string) ?? "";
      logger.info("session.node.created", { sessionId, agentName, sessionPeerId, correlationId });
      dispatchSessionStateChangedWithTelegram(agentName, sessionId, "created", counterpartyPubkey);
    } else if (type === "destroyed") {
      const state = (params?.state as string) ?? "interrupted";
      const reason = (params?.reason as string) ?? state;
      logger.info("session.node.destroyed", { sessionId, agentName, reason });
      dispatchSessionStateChangedWithTelegram(agentName, sessionId, state, counterpartyPubkey);
    }

    return { ok: true };
  });

  // DOD-M12B-DELIVERY-QUIET-1: drive the delivery-open intent directly, so the doorbell exemption
  // is testable without standing up a document, a peer daemon and a real directory negotiation.
  // The registry's begin() hands back a closure, so the releases are held here by key.
  // The hook takes AGENT NAMES and resolves both to pubkeys through `pubkeyOfAgent`, exactly as the
  // real delivery adapter does. That is deliberate: the first version of this hook let a test
  // register a tuple production never produces — an agent registered as the dialler and then
  // emitted as the receiver of its own dial — so the suite proved the guard's boolean logic and
  // nothing about the wiring, and stayed green against a guard that could never fire.
  const testDeliveryReleases = new Map<string, () => void>();
  // DOD-M12B-INBOX-TRUTH-1: seed a refusal, so the ended-unread return branch's lost
  // `refused_session_requests` has a regression test. The field had none before or after the fix.
  handlers.set("__test_record_refusal", async (params, _connectionId) => {
    const agentName = params?.agentName as string | undefined;
    const sessionId = params?.sessionId as string | undefined;
    if (!agentName || !sessionId) return { error: "missing_params", guidance: "Provide agentName and sessionId." };
    // The reason is VALIDATED against the closed union rather than cast through it. A test seam
    // that can inject a reason production cannot produce would let a test prove the inbox handles a
    // code no refusal path emits — which is the shape DOD-M15-GUARD-HEARD-1 exists to remove, and a
    // seam is not exempt from it.
    const asked = (params?.reason as string) ?? CAPACITY_REASONS.ABUSE_BOUND_SESSIONS_PER_SENDER;
    const known: readonly string[] = [
      ...Object.values(REFUSAL_REASONS),
      ...Object.values(CAPACITY_REASONS),
    ];
    if (!known.includes(asked)) {
      return {
        error: "unknown_refusal_reason",
        guidance:
          `"${asked}" is not a reason any refusal path can emit. Use one of: ${known.join(", ")}. ` +
          `Seeding an invented reason would test the inbox against a code production never produces.`,
      };
    }
    recordRefusal(agentName, sessionId, (params?.counterpartyPubkey as string) ?? "", asked as AnyRefusalReason);
    return { ok: true };
  });

  handlers.set("__test_delivery_open_begin", async (params, _connectionId) => {
    const openerAgent = params?.openerAgent as string | undefined;
    const targetAgent = params?.targetAgent as string | undefined;
    if (!openerAgent || !targetAgent) return { error: "missing_params", guidance: "Provide openerAgent and targetAgent (both agent NAMES)." };
    const openerPubkey = pubkeyOfAgent(openerAgent);
    const targetPubkey = pubkeyOfAgent(targetAgent);
    testDeliveryReleases.set(`${openerAgent}>${targetAgent}`, deliveryOpens.begin(openerPubkey, targetPubkey));
    return { ok: true, openerPubkey, targetPubkey };
  });
  handlers.set("__test_delivery_open_end", async (params, _connectionId) => {
    const openerAgent = params?.openerAgent as string | undefined;
    const targetAgent = params?.targetAgent as string | undefined;
    if (!openerAgent || !targetAgent) return { error: "missing_params", guidance: "Provide openerAgent and targetAgent (both agent NAMES)." };
    const key = `${openerAgent}>${targetAgent}`;
    testDeliveryReleases.get(key)?.();
    testDeliveryReleases.delete(key);
    return { ok: true };
  });

  // M8C-INBOX-1: test hook to enqueue a pending inbound session request (mirrors the real inbound
  // flow's enqueueInboundSession) so cello_check_notifications' pending_session_requests is testable
  // without standing up the full libp2p inbound path.
  handlers.set("__test_enqueue_inbound_session", async (params, _connectionId) => {
    const agentName = params?.agentName as string | undefined;
    const sessionIdHex = params?.sessionId as string | undefined;
    const counterpartyPubkeyHex = (params?.counterpartyPubkey as string) ?? "";
    if (!agentName || !sessionIdHex) {
      return { error: "missing_params", guidance: "Provide agentName and sessionId." };
    }
    enqueueInboundSession(agentName, { sessionIdHex, counterpartyPubkeyHex, genesisPrevRootHex: "" });
    // M8C-TTL-1: let a test backdate the just-enqueued entry's timestamp (simulating age) without
    // waiting real hours or faking global timers — enqueueInboundSession always stamps Date.now().
    const enqueuedAtOverride = params?.enqueuedAtOverride as number | undefined;
    if (enqueuedAtOverride !== undefined) {
      const q = inboundSessionQueues.get(agentName);
      const entry = q?.[q.length - 1];
      if (entry) entry.enqueuedAt = enqueuedAtOverride;
    }
    return { ok: true };
  });

  // TTL-terminal-reap: seed a session row at a given terminal status so tests can assert that
  // reapExpiredInboundSessions drops the matching inbound queue entry without waiting 24h.
  handlers.set("__test_insert_session_row", async (params, _connectionId) => {
    const agentName = params?.agentName as string | undefined;
    const sessionId = params?.sessionId as string | undefined;
    const status = params?.status as string | undefined;
    const counterpartyPubkey = (params?.counterpartyPubkey as string) ?? "testpubkey";
    if (!agentName || !sessionId || !status) {
      return { error: "missing_params", guidance: "Provide agentName, sessionId, status." };
    }
    const db = sessionNodeManager.getDb();
    const now = Date.now();
    const agentRow = db.prepare("SELECT agent_id FROM agents WHERE agent_name = ?").get(agentName) as { agent_id: string } | undefined;
    if (!agentRow) return { error: "agent_not_found" };
    db.prepare(
      "INSERT OR REPLACE INTO sessions (session_id, agent_id, counterparty_pubkey, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)"
    ).run(sessionId, agentRow.agent_id, counterpartyPubkey, status, now, now);
    return { ok: true };
  });

  // M8C-INBOX-1 (reviewer F1): buffer a received message so a test can drive a live cello_receive
  // and assert the watermark advances (the N3 delivery-marks-read coupling), without a session tree.
  handlers.set("__test_buffer_received", async (params, _connectionId) => {
    const agentName = params?.agentName as string | undefined;
    const sessionId = params?.sessionId as string | undefined;
    const seq = params?.seq as number | undefined;
    const content = (params?.content as string) ?? "hello";
    if (!agentName || !sessionId || typeof seq !== "number") {
      return { error: "missing_params", guidance: "Provide agentName, sessionId, seq." };
    }
    sessionNodeManager.pushReceivedContentForTest(agentName, sessionId, seq, content, (params?.senderPubkey as string) ?? "cp");
    return { ok: true };
  });
  } // end CELLO_ENV=test guard
}
