/**
 * Phase 4 of boot: parked content, and every path that gets it moving again.
 *
 * The retry queue and its durable rows, the park retry timers, the startup park sweep, and the flush
 * that drains what was waiting once an agent's link comes back. One topic: content that could not be
 * delivered when it was written, and the several distinct ways it stops being stuck.
 *
 * ⚠️ TWO VALUES ARRIVE AS GETTERS, and both for the same measured reason: the outbound-session
 * module is constructed BELOW this phase, so a park retry that has to reach a counterparty on
 * another node can only resolve through it at the moment it retries. By value they would be
 * `undefined` for the life of the process and every cross-node retry would fail silently.
 *
 * Nine dependencies, under the order's bound — counted after the extraction, not before: an earlier
 * draft of this list carried `sealFailures` and a `stop` getter that the moved code never calls.
 */
import { randomUUID } from "node:crypto";
import { RetryQueue } from "./retry-queue.js";
import { ContentParkClient } from "./content-park-client.js";
import { AgentRelayClient } from "./session-relay-client.js";
import { sealParkEnvelope } from "./park-envelope.js";
import type { Logger, DaemonConfig, AgentInfo } from "./types.js";
import type { SignalingManager } from "@cello-protocol/transport";
import type { KeyProvider } from "@cello-protocol/crypto";
import type { SessionNodeManager } from "./session-node-manager.js";

export interface BootParkedContentDeps {
  config: DaemonConfig;
  logger: Logger;
  sessionNodeManager: SessionNodeManager;
  agents: ReadonlyArray<AgentInfo>;
  keyProviders: Map<string, KeyProvider>;
  resolveConsortiumRoster: () => Promise<Array<{ peerId: string; multiaddr: string; nodeId: string }> | null>;
  waitForSignalingConnected: (mgr: SignalingManager, timeoutMs: number) => Promise<boolean>;
  /**
   * ⚠️ BOTH GETTERS. The outbound-session module is built BELOW this phase, and a park retry that has
   * to reach a counterparty on another node resolves through it at the moment it retries.
   */
  getOpenVisitingConnection: () => (
    agentName: string, kp: KeyProvider, pubkeyHex: string,
    endpoint: { peerId: string; multiaddr: string }, correlationId: string, nodeId: string,
  ) => { mgr: SignalingManager; stop: (reason: string) => Promise<void> };
  /** session key → the node id that brokered it. */
  getCrossNodeBrokerBySession: () => Map<string, string>;
}

export function startBootParkedContent(deps: BootParkedContentDeps) {
  const {
    config, logger, sessionNodeManager, agents, keyProviders,
    resolveConsortiumRoster, waitForSignalingConnected,
    getOpenVisitingConnection, getCrossNodeBrokerBySession,
  } = deps;

  // Both use the same SQLite DB as the SessionNodeManager (daemon.db equivalent).
  // loadFromDb() must complete BEFORE IPC socket opens (AC-007).
  const retryQueue = new RetryQueue(sessionNodeManager.getDb(), logger);
  retryQueue.loadFromDb();
  // DOD-RETRYQ-STRAND-1: the terminal-transition hook below only fires for sessions that go
  // terminal while this daemon runs. A session already sealed/abandoned before boot never
  // transitions again — close-session returns `already_abandoned` without reaching abandonSession —
  // so without this its rows are unreachable by every removal path and retryQueueDepth stays pinned
  // forever. That is exactly the row found on the live daemon, 25.6h old. Runs after loadFromDb so
  // the in-memory queues are dropped in step with the rows, and before the IPC socket opens so no
  // client ever observes the stale depth.
  retryQueue.reapAlreadyTerminalSessions();

  // CELLO-M7-MSG-001 (AC-001/AC-003/AC-019): wire the awaiting-ACK lifecycle's durable
  // side effects to the retry_queue. A `persisted` delivery ACK clears the durable
  // entry; a TTF expiry records the un-acked content for the crash backstop (the relay
  // park deposit itself is added in 3b). Both side effects are best-effort and never
  // throw into the content stream handler.
  // DOD-AGENT-ID-JOINKEY-1: RetryQueue owns an agent-scoped table, so it is handed the STABLE
  // agent_id. The daemon resolves the operator-facing name ONCE, here at its own boundary.
  // M12-P15: let a session with NO in-memory node still reach its relay to seal. The manager
  // deliberately holds no K_local, so the client is built here where the keys live. This is what
  // makes the detached path work after a RESTART — the exact situation that marked the session
  // interrupted and then left it unsealable, with force-abandon (no receipt) as the only exit.
  sessionNodeManager.setDetachedRelayClientBuilder((agentName, relayPeerId, relayAddrs, stores) => {
    const kp = keyProviders.get(agentName);
    const agent = agents.find((a) => a.name === agentName);
    if (!kp || !agent?.pubkey) return undefined;
    return new AgentRelayClient({
      relayPeerId,
      relayAddrs,
      keyProvider: kp,
      senderPubkey: Buffer.from(agent.pubkey, "hex"),
      logger,
      // Review HIGH-1: a client that can submit but cannot RECORD drops the durable evidence the
      // seal depends on — silently, while reporting success.
      receiptStore: stores.receiptStore,
      sealLeafStore: stores.sealLeafStore,
      // `DOD-M15-SELFCHAIN-1` — without this the client cannot chain a message to this agent's own
      // previous one, and says so rather than signing an unlinked claim.
      ownChainStore: stores.ownChainStore,
      // DOD-M15-RELAYSLOTS-1: the manager owns the current token and hands the accessor down, so
      // this client reads a fresh one at every auth instead of a snapshot taken here at build time.
      onlineToken: stores.onlineToken,
      // DOD-M15-CORROBORATE-1: the DETACHED client needs this as much as the live one — a session
      // being sealed after a restart is exactly when its operator is not watching.
      onWitnessAlert: (alert) => { sessionNodeManager.recordRelayWitnessAlert(agentName, alert); },
      onWitnessUnreadable: (peerId, why) => { sessionNodeManager.recordRelayWitnessUnreadable(agentName, peerId, why); },
    });
  });

  // DOD-RETRYQ-STRAND-1: a direct-resend row is reachable only by drainSession, which has no
  // production caller — so once its session can never drain again the row is unreachable by every
  // removal path that exists, and pins retryQueueDepth forever. Found live: one row stranded 25.6h,
  // after which the metric could no longer tell a real delivery backlog from a corpse.
  sessionNodeManager.setSessionTerminalHook((sessionId, terminalStatus) => {
    retryQueue.reapTerminalSession(sessionId, terminalStatus);
  });

  /**
   * DOD-M12B-SESSION-SEED-1 — the retry drain is DELIBERATELY NOT WIRED. Review HIGH-1.
   *
   * It was wired, and it was worse than the problem it solved. `retryQueue.enqueue` runs only on the
   * `!sendResult.durable` branch — content that got NO local leaf and NO transcript row, because as
   * that branch's own comment says, *"A LOST message gets no leaf — that would commit a sequence no
   * content will ever fill."*
   *
   * The hook re-sent those rows with `sendContent`, which is wire-and-witness only: it consumes a
   * canonical relay sequence and returns one, and the hook discarded it without calling
   * `placeOwnLeaf` or writing the transcript. So the counterparty would silently receive the message
   * while OUR tree kept a permanent hole at that sequence. Every later message would be held behind
   * the gap with guidance blaming the counterparty for a message they already sent, the two roots
   * would have parted, and the session could never seal.
   *
   * A stranded queue row is recoverable. A parted hash chain is not. So this stays unwired until the
   * drain routes through the same commit path `cello_send` uses (place the leaf at the returned
   * sequence, write the transcript, keep the row on failure) rather than calling `sendContent` raw.
   *
   * The operator-facing consequence of leaving it unwired is unchanged from before this milestone:
   * a message that fails this way is reported lost and must be re-sent by hand. That is honest, and
   * it is what the guidance already says.
   */

  sessionNodeManager.setAwaitingAckHooks({
    onPersisted: (agentName, sessionId, contentHashHex) => {
      retryQueue.markContentAcked(sessionNodeManager.resolveAgentId(agentName), sessionId, Buffer.from(contentHashHex, "hex"));
    },
    // `DOD-M15-SEALWIRE-1` B2b-1 review F1 — `contentHashAlg` is the DURABLE WRITER for the column
    // this unit added. Without it every queued row carries NULL, the crash backstop re-parks a salted
    // message as sha256, and the recipient refuses it and re-pulls it forever. The commit that added
    // the column said the producer "passes it"; the producer was passing a value nothing supplied,
    // because these two hooks were never widened.
    onTtf: (agentName, sessionId, contentHashHex, content, structure1Cbor, structure2Cbor, contentHashAlg, structure1Signature, leafKind) => {
      retryQueue.enqueueAwaitingContent(sessionNodeManager.resolveAgentId(agentName), sessionId, Buffer.from(contentHashHex, "hex"), content, structure1Cbor, structure2Cbor, contentHashAlg, structure1Signature, leafKind);
    },
    // M12-P12: same durable destination, different cause — a park deposit the relay refused. The
    // TTF timer is already cancelled on this path, so this is the only thing holding the content.
    // M12-P13 (review HIGH-1): the enqueue's own answer is returned, never a bare `true`. A dropped
    // copy that reports success now buys a committed hash-chain leaf for content that is gone.
    onParkFailed: (agentName, sessionId, contentHashHex, content, structure1Cbor, structure2Cbor, contentHashAlg, structure1Signature, leafKind) => {
      return retryQueue.enqueueAwaitingContent(sessionNodeManager.resolveAgentId(agentName), sessionId, Buffer.from(contentHashHex, "hex"), content, structure1Cbor, structure2Cbor, contentHashAlg, structure1Signature, leafKind);
    },
  });

  // MSG-001-3b (2b): the LIVE content-park deposit. On a not-confirmed send (direct delivery
  // failed, or TTF with no `persisted` ACK) the session manager calls this with the recipient +
  // the session's relay endpoint; we seal the content to the recipient (E2E — the relay never sees
  // plaintext, INV-3) and deposit it to that relay's store-and-forward mailbox via the standing
  // receiver node. The recipient pulls + recovers it at the witnessed sequence (R1) on next online.
  // Fix #1 EXTENSION (cross-node seal-liveness) — the AUTO-ACKNOWLEDGE half.
  //
  // close-session-handler already re-opens a transient visiting connection to the broker for its
  // own path. The auto-ack path had no such guard, and it is the one that fires FIRST whenever the
  // counterparty closes first: it submits a seal leaf, the directory answers within ~60ms by pushing
  // `seal_verified` to the INITIATOR, finds no stream (the initiator released its visiting
  // connection after setup), ENQUEUES the frame, and then blocks waiting for a co-signature it never
  // asked for. Proven on GCP — leaf 18:41:56.555, directory `seal.certificate.deferred`
  // (initiator_stream_absent) 18:41:56.615, broker reconnect 18:42:01.529: five seconds too late.
  //
  // Returns null for same-node sessions (no broker entry) — those reach the initiator on its home
  // stream and need no visiting connection.
  sessionNodeManager.setEnsureSealBroker(async (agentName, sessionId) => {
    const brokerNode = getCrossNodeBrokerBySession().get(`${agentName}:${sessionId}`);
    if (!brokerNode) return null;
    const kp = keyProviders.get(agentName);
    if (!kp) {
      logger.warn("session.seal.autoack.broker.no_keyprovider", { agentName, brokerNode });
      return null;
    }
    const pubHex = Buffer.from(await kp.getPublicKey()).toString("hex");
    const roster = await resolveConsortiumRoster();
    const target = roster?.find((e) => e.nodeId === brokerNode) ?? null;
    if (!target) {
      logger.warn("session.seal.autoack.broker.unresolved", { agentName, brokerNode });
      return null;
    }
    const correlationId = randomUUID();
    const conn = getOpenVisitingConnection()(agentName, kp, pubHex, { peerId: target.peerId, multiaddr: target.multiaddr }, correlationId, brokerNode);
    if (await waitForSignalingConnected(conn.mgr, 10_000)) {
      logger.info("session.seal.autoack.broker.reconnected", { agentName, brokerNode, correlationId });
      return conn;
    }
    await conn.stop("autoack-seal-broker-unreachable");
    logger.warn("session.seal.autoack.broker.unreachable", { agentName, brokerNode, correlationId });
    return null;
  });

  /**
   * DOD-M15-RELAYABUSE-1: scheduled park-retry timers, tracked so shutdown can clear them.
   *
   * ⚠️ Every other daemon timer is cleared in `stop()`; an untracked one lets an in-process restart
   * leave a stale timer that drains into a torn-down manager. Unref'd already, so it cannot hold the
   * process open — this is about a clean teardown, not about exiting.
   */
  const parkRetryTimers = new Set<ReturnType<typeof setTimeout>>();

  /**
   * DOD-M15-RELAYABUSE-1: schedule ONE drain at the delay the relay asked for.
   *
   * ⚠️ ONE implementation, used by both park paths. The live-send path and the drain path both need
   * this and a second copy is how the clamp ends up on only one of them — which is exactly the shape
   * review found here (the number had a consumer on one path and was dropped on the other).
   *
   * CLAMPED, because the value comes from another party's software and an unclamped one inverts the
   * fix: Node's `setTimeout` holds an int32, so a relay reporting `3_000_000_000` overflows it and
   * fires in about ONE MILLISECOND — re-parking instantly into the limit that just refused, and
   * printing a `TimeoutOverflowWarning` from a daemon whose convention forbids console output.
   */
  function scheduleParkRetry(retryAfterMs: number, filterAgentName: string | undefined, source: "send" | "drain"): void {
    const MIN_RETRY_MS = 1_000;
    const MAX_RETRY_MS = 5 * 60_000;
    const delay = Math.min(Math.max(retryAfterMs, MIN_RETRY_MS), MAX_RETRY_MS);
    if (delay !== retryAfterMs) {
      logger.warn("content.park.retry.clamped", {
        source,
        requestedMs: retryAfterMs,
        usedMs: delay,
        impact:
          "the relay asked for a retry delay outside the range this daemon will schedule, so it was " +
          "clamped — an unclamped value can overflow the timer and fire immediately, which would " +
          "re-park straight into the limit that just refused",
      });
    }
    logger.info("content.park.retry.scheduled", { source, delayMs: delay, ...(filterAgentName !== undefined ? { agentName: filterAgentName } : {}) });
    const timer = setTimeout(() => {
      parkRetryTimers.delete(timer);
      void flushAwaitingContent(filterAgentName).catch((err: unknown) => {
        logger.warn("content.park.retry.timer.failed", {
          source,
          reason: err instanceof Error ? err.message : String(err),
          impact: "the scheduled drain threw; the ordinary event triggers (boot, agent start, reconnect) still apply",
        });
      });
    }, delay);
    timer.unref?.();
    parkRetryTimers.add(timer);
  }

  sessionNodeManager.setContentParkHook(async ({ agentName, sessionId, recipientPubkeyHex, relayPeerId, relayAddrs, contentHashHex, content, structure1Cbor, structure2Cbor, structure1Signature, leafKind, contentHashAlg }) => {
    const node = sessionNodeManager.getStandingReceiverNode();
    if (!node) {
      const reason = "standing_receiver_unavailable";
      // M12-P12 (review F4): `standing_receiver_unavailable` is the exit-point label that already
      // misnamed this incident 102 times; standingReceiverAbsenceReason() names WHICH of the four
      // causes it is. That distinction is what separates "mid-rebuild, a retry in seconds works"
      // from "agent offline, this will never work" — the difference between a backstop that helps
      // and one that spins. The wire reason stays put; the cause rides alongside.
      const cause = sessionNodeManager.standingReceiverAbsenceReason(agentName);
      logger.warn("content.park.deposit.failed", { sessionId, contentHash: contentHashHex, reason, cause });
      // DOD-LEAVEMSG-1 (reviewer HIGH fix): return the typed failure, never resolve as if this
      // were a success — #parkContent's caller (sendContent) shapes a live "dispatched to relay"
      // response from this, and a silently-resolved void here would report a message as safely
      // parked when nothing was ever deposited.
      return { ok: false, reason, cause };
    }
    // SEC-1: sign the entry as the SENDING agent. Without a key we cannot produce an envelope the
    // recipient will accept, so fail LOUD rather than depositing something that will be refused on
    // recovery (a deposit the recipient must reject is worse than no deposit — it looks delivered).
    const senderKp = keyProviders.get(agentName);
    if (!senderKp) {
      const reason = "signing_key_unavailable";
      logger.warn("content.park.deposit.failed", { agentName, sessionId, contentHash: contentHashHex, reason });
      return { ok: false, reason };
    }
    const recipientPubkey = Buffer.from(recipientPubkeyHex, "hex");
    const contentHashBytes = Buffer.from(contentHashHex, "hex");
    logger.info("content.park.signed", { agentName, sessionId, contentHash: contentHashHex });
    // DOD-MSG-4 (2b): seal the ORDERING ENVELOPE (content + the relay's signed Structure2), not bare
    // content, so the parked entry is self-ordering on recover. The relay still holds only ciphertext.
    // SEC-1: sealParkEnvelope is the SOLE producer — it signs (sender's K_local, over the
    // session/recipient/content binding) and seals in one place, so the two park sites cannot drift
    // apart on what gets signed.
    //
    // `DOD-M15-SEALWIRE-1` PART B2b — the algorithm is threaded through, and it is the value THIS
    // MESSAGE was hashed under, never one re-derived from the session's current row. Whether a hash
    // is salted is a fact about the message that was sent; what this side holds now says nothing
    // about it.
    //
    // ⛔ THIS COMMENT USED TO SAY "Still `sha256` everywhere, because no send path salts yet — the
    // plumbing is proven carrying the value that cannot break anything, and only then does the value
    // change." That described B2b, and B2b-2 then CHANGED THE VALUE: a session holding an agreed
    // salt hashes under `hmac-sha256-salt-v1`, so this path really does carry a salted algorithm
    // now. Rewritten rather than deleted — a stale reassurance is what `CLAIM-COMMENTS-1` is for,
    // and on 2026-08-24 a test declared `sha256` on the strength of this sentence and got a tamper
    // verdict on an honest message.
    const ciphertext = await sealParkEnvelope({
      signer: senderKp,
      sessionIdHex: sessionId,
      recipientPubkey,
      contentHash: contentHashBytes,
      content,
      // The algorithm the DIRECT frame named for this same message. The park copy must claim what
      // the message actually is, not what this side would choose for it now.
      contentHashAlg,
      structure1Cbor,
      structure2Cbor,
      // 034-CARRYLEAF: promotes the envelope to v4 when present, which is what lets the recipient
      // witness this leaf if its author never does.
      structure1Signature,
      leafKind,
    });
    const client = new ContentParkClient({ relayPeerId, relayAddrs: [...relayAddrs], logger });
    const res = await client.deposit(node, {
      recipientPubkey,
      contentHash: Buffer.from(contentHashHex, "hex"),
      sessionId: Buffer.from(sessionId, "hex"),
      ciphertext,
    });
    if (res.ok) {
      logger.info("content.park.deposited", { sessionId, contentHash: contentHashHex, recipientPubkey: recipientPubkeyHex.slice(0, 16) });
      return { ok: true };
    }
    logger.warn("content.park.deposit.failed", {
      sessionId,
      contentHash: contentHashHex,
      reason: res.reason,
      ...(res.retryAfterMs !== undefined ? { retryAfterMs: res.retryAfterMs } : {}),
    });
    /**
     * DOD-M15-RELAYABUSE-1 — **GIVE THE RELAY'S "WHEN" A CONSUMER.**
     *
     * A deferred park is otherwise retried only on EVENTS — boot, agent start, the drain hook, a
     * signaling reconnect. None of those is coming for a throttle: the relay is healthy, the link
     * never dropped, and the condition clears on a timer nobody is watching. So the one refusal that
     * self-heals in about a minute was the one that waited longest, purely because the number the
     * relay had already computed had no reader.
     *
     * Scheduled ONCE per refusal, unref'd so it can never hold the process open, and best-effort:
     * the existing event triggers remain the guarantee, and this is a shortcut on top of them. It
     * deliberately does not retry-on-retry — a timer that reschedules itself on failure is a
     * self-inflicted flood, which is what the limiter exists to stop.
     */
    if (res.retryAfterMs !== undefined && res.retryAfterMs > 0) {
      /**
       * ⚠️ CLAMPED, because the number comes from ANOTHER PARTY'S SOFTWARE and an unclamped one is
       * not merely wrong — it inverts the fix. Node's `setTimeout` holds an int32: a relay reporting
       * `3_000_000_000` overflows it and the timer fires in about **one millisecond**, re-parking
       * instantly into the limit that just refused, and printing a `TimeoutOverflowWarning` on
       * stderr from a daemon whose convention forbids console output. A reported `1` does the same
       * thing 250 ms later.
       *
       * The floor is a second and the ceiling five minutes: long enough that a shortcut is a
       * shortcut, short enough that it stays one. A clamp is announced rather than silent — a relay
       * asking us to wait 35 days is a fact an operator wants.
       */
      scheduleParkRetry(res.retryAfterMs, agentName, "send");
    }
    return {
      ok: false,
      reason: res.reason ?? "relay_deposit_failed",
      // DOD-M15-RELAYABUSE-1 review MEDIUM-6: the guidance quotes the relay's OWN window instead of
      // guessing "about a minute", which is a hardcoded assumption about a configurable value.
      ...(res.retryAfterMs !== undefined ? { retryAfterMs: res.retryAfterMs } : {}),
    };
  });

  // CELLO-M7-MSG-001 (AC-004/AC-005, D-d): startup flush of locally-persisted un-acked
  // content (the crash backstop). Runs HERE — before the IPC socket opens, consistent
  // with DAEMON-003 startup loading (AC-007) — so a sender that crashed before its TTF
  // park confirmed re-parks its un-acked content to the relay store-and-forward queue on
  // restart. Best-effort: a failed park stays queued (drainAwaitingToPark does not evict
  // on failure), to be retried at the next startup flush or reconnect.
  //
  // Re-home note (Option A): the park target (config.contentParkFn) is supplied natively
  // by the daemon's own send path — NOT by a hosted CelloClient. When it is absent (e.g.
  // a daemon started without the content send path wired, or unit tests), the flush is a
  // documented no-op (content.park.flush.deferred at WARN) and the durable awaiting
  // entries simply remain queued for the next startup that has a park target.
  // MSG-2 startup-flush park target: seal + deposit an un-acked awaiting entry sourced from
  // PERSISTED session state (the in-memory entry is gone after a restart). Same seal + deposit
  // as the live hook above; the endpoint + recipient come from the sessions row.
  const startupParkFn: import("./retry-queue.js").ParkFn = async (entry) => {
    // The durable row carries the OWNING agent's stable id. Resolve it back to a name for the
    // name-addressed session/standing-receiver lookups. A retired owner resolves fine and then has no
    // standing receiver, so the park fails loudly below rather than silently re-parking as someone else.
    const ownerName = sessionNodeManager.agentNameForId(entry.agentId);
    if (ownerName === null) return { parked: false, error: "owning_agent_not_found" };
    const ep = sessionNodeManager.getPersistedRelayEndpoint(ownerName, entry.sessionId);
    const record = sessionNodeManager.getSessionRecord(ownerName, entry.sessionId);
    if (!ep) return { parked: false, error: "no_persisted_relay_endpoint" };
    if (!record?.counterparty_pubkey) return { parked: false, error: "no_counterparty" };
    // DOD-LOOP-1: the re-park must originate from the session's OWNING agent (the original
    // sender), so use THAT agent's standing-receiver node — not "any" agent's. Post-DOD-LOOP-1 the
    // owning agent's SR exists only once it is online, which is why the native flush is
    // (re-)triggered per-agent on agent-online (see flushAwaitingContent / cello_start_agent), not
    // only at pre-IPC startup when no agent is online yet.
    const node = sessionNodeManager.getStandingReceiverNode(record.agent_name);
    if (!node) return { parked: false, error: "standing_receiver_unavailable" };
    // SEC-1: the crash backstop must sign too — an unsigned re-park would be REFUSED on recovery,
    // which would turn the message-loss backstop into a message-loss cause. The SEC-1 signature
    // binds to the sender's own K_local, which the owning agent still holds after a crash.
    // M12-P12 (review F2): the ordering record IS now persisted (retry_queue.structure{1,2}_cbor),
    // so a re-park is self-ordering whenever the row carries one. Rows written before that column
    // existed carry none and still recover in arrival order — the pre-existing behaviour, now the
    // exception rather than the rule.
    const senderKp = keyProviders.get(ownerName);
    if (!senderKp) return { parked: false, error: "signing_key_unavailable" };
    const recipientPubkey = Buffer.from(record.counterparty_pubkey, "hex");
    const contentHashBytes = Buffer.from(entry.contentHashHex, "hex");
    logger.info("content.park.signed", { agentName: ownerName, sessionId: entry.sessionId, contentHash: entry.contentHashHex, source: "startup_flush" });
    // DOD-MSG-4 (2b): ONE envelope format on the recover side. M12-P12 (F2): carry the persisted
    // ordering record when the row has one, so the recipient places the content at its WITNESSED
    // sequence rather than its arrival index — the receiver's #witnessedSeq map is in-memory and
    // empty after a restart, so arrival order there means a wrong leaf index and a divergent tree.
    // SEC-1: same sole producer as the live hook — the backstop signs from the persisted
    // (sessionId, recipient, contentHash).
    //
    // `DOD-M15-SEALWIRE-1` PART B2b — the algorithm is threaded through, and it is the value THIS
    // MESSAGE was hashed under, never one re-derived from the session's current row. Whether a hash
    // is salted is a fact about the message that was sent; what this side holds now says nothing
    // about it.
    //
    // ⛔ THIS COMMENT USED TO SAY "Still `sha256` everywhere, because no send path salts yet — the
    // plumbing is proven carrying the value that cannot break anything, and only then does the value
    // change." That described B2b, and B2b-2 then CHANGED THE VALUE: a session holding an agreed
    // salt hashes under `hmac-sha256-salt-v1`, so this path really does carry a salted algorithm
    // now. Rewritten rather than deleted — a stale reassurance is what `CLAIM-COMMENTS-1` is for,
    // and on 2026-08-24 a test declared `sha256` on the strength of this sentence and got a tamper
    // verdict on an honest message.
    const ciphertext = await sealParkEnvelope({
      signer: senderKp,
      sessionIdHex: entry.sessionId,
      recipientPubkey,
      contentHash: contentHashBytes,
      content: entry.contentBlob,
      // The queued row's own record of how it was hashed. `undefined` for a row written before the
      // column existed, which resolves to `sha256` — exactly what such a row actually used.
      contentHashAlg: entry.contentHashAlg,
      structure1Cbor: entry.structure1Cbor,
      structure2Cbor: entry.structure2Cbor,
      // 034-CARRYLEAF: a re-parked message must reach its recipient in a shape they can WITNESS on
      // the sender's behalf, or a crash re-opens the withholding hole on the mailbox route.
      structure1Signature: entry.structure1Signature,
      leafKind: entry.leafKind,
    });
    const client = new ContentParkClient({ relayPeerId: ep.relayPeerId, relayAddrs: [...ep.relayAddrs], logger });
    const res = await client.deposit(node, {
      recipientPubkey,
      contentHash: Buffer.from(entry.contentHashHex, "hex"),
      sessionId: Buffer.from(entry.sessionId, "hex"),
      ciphertext,
    });
    if (res.ok) {
      logger.info("content.park.deposited", { sessionId: entry.sessionId, contentHash: entry.contentHashHex, source: "startup_flush" });
      return { parked: true };
    }
    return {
      parked: false,
      error: res.reason ?? "deposit_failed",
      // DOD-M15-RELAYABUSE-1 review HIGH-2: carry the relay's own "when" out of the DRAIN path too.
      ...(res.retryAfterMs !== undefined ? { retryAfterMs: res.retryAfterMs } : {}),
    };
  };

  // Re-park un-acked awaiting content to the relay store-and-forward queue. Runs once pre-IPC
  // (the crash backstop) and again per-agent when an agent comes online — because post-DOD-LOOP-1
  // the native `startupParkFn` needs the OWNING agent's standing receiver, which exists only once
  // that agent is online. `filterAgentName` scopes the drain to one agent's sessions on the agent-
  // online re-run; with no filter it attempts all (the pre-IPC pass / injected-target test path).
  // M12-P12 (review pass 2): the sender flush now has FOUR triggers (boot, agent start, the parked-
  // drain hook, signaling reconnect), and two of them fire deterministically together on agent start
  // — the drain hook runs inside ensureStandingReceiver, whose own .then() then calls this again
  // while the first pass is still dialling the relay. The receiver twin (contentPark) already
  // coalesces for exactly this reason; adding triggers to the sender half without the same guard was
  // an asymmetry, not a decision. Re-run once at the end if a trigger arrived mid-flight, so a
  // coalesced call never DROPS work — it defers it.
  const flushInFlight = new Set<string>();
  const flushRerunRequested = new Set<string>();
  async function flushAwaitingContent(filterAgentName?: string): Promise<void> {
    const flushKey = filterAgentName ?? "*";
    if (flushInFlight.has(flushKey)) {
      flushRerunRequested.add(flushKey);
      return;
    }
    flushInFlight.add(flushKey);
    try {
      await flushAwaitingContentInner(filterAgentName);
    } finally {
      flushInFlight.delete(flushKey);
    }
    if (flushRerunRequested.delete(flushKey)) {
      await flushAwaitingContent(filterAgentName);
    }
  }

  async function flushAwaitingContentInner(filterAgentName?: string): Promise<void> {
    // DOD-AGENT-ID-JOINKEY-1: the queue is keyed by the STABLE agent_id, but the caller (and the
    // human-readable log) speak the NAME. Resolve once here; log the name, filter by the id.
    const filterAgentId = filterAgentName !== undefined
      ? sessionNodeManager.resolveAgentId(filterAgentName)
      : undefined;
    const all = retryQueue.getAwaitingSessions();
    const sessions = filterAgentId === undefined
      ? all
      : all.filter((s) => s.agentId === filterAgentId);
    if (sessions.length === 0) return;
    const parkFn = config.contentParkFn ?? startupParkFn;
    if (!parkFn) {
      const pendingCount = sessions.reduce((n, s) => n + retryQueue.getAwaitingDepth(s.agentId, s.sessionId), 0);
      logger.warn("content.park.flush.deferred", {
        sessionCount: sessions.length,
        pendingCount,
        reason: "no_content_park_target",
      });
      return;
    }
    let parkedTotal = 0;
    for (const s of sessions) {
      try {
        parkedTotal += await retryQueue.drainAwaitingToPark(s.agentId, s.sessionId, parkFn, (retryAfterMs) => {
          /**
           * DOD-M15-RELAYABUSE-1 review HIGH-2 — **the drain path can now schedule its own
           * follow-up, which is what makes the retry work for a BACKLOG rather than one message.**
           *
           * Before this, only the live send path heard the relay's delay. With a backlog larger than
           * one rate-limit window, the drain deposited what the window allowed, every remaining item
           * was refused, and all of them fell back to waiting for an unrelated reconnect — the exact
           * condition the retry timer was added to remove.
           *
           * ONE timer per pass (the drain reports the largest delay it saw, not one per item), and
           * it deliberately does not chain beyond that: the next pass schedules the next one only if
           * it is refused again, so a permanently-full relay costs one timer per window rather than
           * an accelerating stream of them.
           */
          scheduleParkRetry(retryAfterMs, filterAgentName, "drain");
        });
      } catch (err: unknown) {
        logger.error("content.park.flush.failed", {
          sessionId: s.sessionId,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }
    logger.info("content.park.flush.completed", {
      sessionCount: sessions.length,
      parkedCount: parkedTotal,
      ...(filterAgentName !== undefined ? { agentName: filterAgentName } : {}),
    });
  }
  return { retryQueue, parkRetryTimers, scheduleParkRetry, startupParkFn, flushAwaitingContent };
}
