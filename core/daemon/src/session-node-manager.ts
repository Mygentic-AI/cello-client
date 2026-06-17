/**
 * CELLO Daemon — SessionNodeManager
 *
 * Manages the lifecycle of all ephemeral session nodes:
 *   1. Per-session nodes: fresh transport key + Peer ID, connectionGater allows
 *      only the designated counterparty. Created during cello_initiate_session
 *      (outbound) or cello_await_session (inbound, via standing receiver handoff).
 *   2. Standing receiver node: pre-created, open gater, kept alive at all times.
 *      Handed to the first inbound session; immediately replaced.
 *   3. 32-node cap: enforced before any new node is created.
 *   4. Session status in SQLite: active → sealed (on close) or interrupted
 *      (on graceful shutdown or SIGKILL-restart detection).
 *
 * Pseudocode (SPARC Phase P):
 *
 * initialize():
 *   1. Open SQLite (node:sqlite), create sessions table if not exists
 *   2. Detect interrupted sessions: SELECT * FROM sessions WHERE status='active'
 *      → batch-update to 'interrupted', log session.interrupted.detected for each
 *      (source: 'daemon_restart') — runs before IPC socket opens so no race
 *   3. Create standing receiver node (fresh libp2p, open gater, sentinel agentName)
 *   4. Start standing receiver, set standingReceiverReady=true
 *   5. Log session.node.created for the standing receiver
 *
 * createSessionNode(sessionId, agentName, counterpartyPubkey, counterpartyPeerId, correlationId):
 *   Pseudocode:
 *   1. Check activeNodes.size >= MAX_SESSION_NODES → log cap.reached, return error
 *   2. Create SessionConnectionGater(counterpartyPeerId) — restricted from birth
 *   3. nodeFactory.createNode({gater}) → fresh libp2p node
 *   4. node.start() — bind TCP ephemeral port
 *   5. Insert SQLite row status='active'
 *   6. Log session.node.created
 *   7. Add to activeNodes map
 *   8. Return {ok:true, peerId, addrs}
 *   On libp2p error: extract error.message (never ${error}), log create.failed, return error
 *
 * acceptSession(sessionId, agentName, counterpartyPubkey, initiatorPeerId, correlationId):
 *   Pseudocode:
 *   1. If !standingReceiverReady → return standing_receiver_unavailable
 *   2. Take standing receiver from slot (clear slot atomically)
 *   3. gater.setAllowedPeer(initiatorPeerId) ← BEFORE returning multiaddr (AC-015)
 *   4. Insert SQLite row status='active'
 *   5. Log session.node.created
 *   6. Add to activeNodes map
 *   7. Trigger async replacement of standing receiver (do NOT await)
 *   8. Return {ok:true, peerId, addrs}
 *
 * destroySessionNode(sessionId, reason):
 *   Pseudocode:
 *   1. Find node in activeNodes
 *   2. stop node
 *   3. Update SQLite status to sealed/interrupted/error
 *   4. Remove from activeNodes
 *   5. Log session.node.destroyed
 *
 * gracefulShutdown():
 *   Pseudocode:
 *   1. Get all activeNodes
 *   2. For each: update SQLite 'interrupted', log destroyed(reason:'interrupted')
 *   3. Stop all nodes
 *   4. Stop standing receiver
 *
 * getStatus(): { standingReceiverReady: boolean }
 */

// node:sqlite (DatabaseSync) requires Node.js >= 24 (stable in 24 LTS).
// The engines field in package.json is set to ">=24" specifically because of this
// dependency — do not lower the engine floor without replacing this import.
import { DatabaseSync } from "node:sqlite";
import { randomUUID, createHash } from "node:crypto";
import * as lp from "it-length-prefixed";
import { decode, Encoder } from "cbor-x";
import type { Stream } from "@libp2p/interface";
import type { Logger, SessionRecord } from "./types.js";
import { MAX_SESSION_NODES, STANDING_RECEIVER_AGENT_NAME } from "./types.js";
import { SessionConnectionGater } from "./session-connection-gater.js";
import { SessionTree, type SessionTreeLeafKind } from "./session-tree.js";
import { CELLO_CONTENT_PROTOCOL_ID, type CelloNode } from "@cello-protocol/transport";

const CBOR_ENC = new Encoder({ tagUint8Array: false });

// ─── Interfaces ───────────────────────────────────────────────────────────────

/**
 * Adapter interface for session node creation. Allows test injection of a
 * failing factory (AC-007) without touching the real libp2p stack.
 * The adapter pattern is mandatory per outline.md constraints.
 */
export interface ISessionNodeFactory {
  createNode(config: SessionNodeConfig): Promise<CelloNode>;
}

export interface SessionNodeConfig {
  sessionId: string;
  connectionGater?: SessionConnectionGater;
}

// ─── Active session entry ─────────────────────────────────────────────────────

interface ActiveSessionEntry {
  node: CelloNode;
  agentName: string;
  counterpartyPubkey: string;
  gater: SessionConnectionGater;
  correlationId: string;
  /**
   * DAEMON-004: the counterparty's SESSION-layer Peer ID — the dial target for
   * the direct content stream (/cello/content/1.0.0). Set when the node is
   * created (outbound: the gater-allowed peer) or accepted (inbound: initiator).
   */
  counterpartySessionPeerId: string;
}

/** DAEMON-004: a piece of content received and verified, awaiting cello_receive. */
interface ReceivedContentEntry {
  contentHex: string;
  senderPubkey: string;
  sequenceNumber: number;
}

// ─── Result types ─────────────────────────────────────────────────────────────

type CreateSessionResult =
  | { ok: true; peerId: string; addrs: string[] }
  | { ok: false; reason: string; guidance: string };

// ─── SessionNodeManager ───────────────────────────────────────────────────────

export class SessionNodeManager {
  readonly #factory: ISessionNodeFactory;
  readonly #logger: Logger;
  readonly #dbPath: string;
  #db: DatabaseSync | null = null;
  #activeNodes = new Map<string, ActiveSessionEntry>();
  #standingReceiver: { node: CelloNode; gater: SessionConnectionGater } | null = null;
  #standingReceiverReady = false;
  // DAEMON-004: lazily-loaded in-memory cache of each session's daemon-owned
  // Merkle tree. The authoritative store is the session_tree_leaves table —
  // the cache is rebuilt from it on first access (so it survives a restart).
  #trees = new Map<string, SessionTree>();
  // DAEMON-004: per-session FIFO buffer of verified received content awaiting
  // cello_receive. Populated by ingestReceivedContent / the content stream handler.
  #receivedContent = new Map<string, ReceivedContentEntry[]>();
  // M7-SESSION-001 (M-1 PUSH): optional callback fired when a session changes
  // state, so the composition root can dispatch a session_state_changed
  // notification to live MCP clients. Injected via a setter AFTER construction
  // because the NotificationDispatcher is built later than this manager in
  // daemon.ts (it depends on the IPC server). Never required — when unset,
  // state changes are persisted and logged but no push notification is emitted.
  #onSessionStateChanged:
    | ((
        agentName: string,
        sessionId: string,
        state: string,
        counterpartyPubkey: string | null,
      ) => void)
    | null = null;

  constructor(opts: {
    factory: ISessionNodeFactory;
    logger: Logger;
    dbPath: string;
  }) {
    this.#factory = opts.factory;
    this.#logger = opts.logger;
    this.#dbPath = opts.dbPath;
  }

  // ─── Initialization ──────────────────────────────────────────────────────

  async initialize(): Promise<void> {
    // Step 1: Open SQLite and create sessions table
    this.#db = new DatabaseSync(this.#dbPath);
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        agent_name TEXT NOT NULL,
        counterparty_pubkey TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      )
    `);

    // M7-SESSION-001: idempotent schema extension — add message_count and interrupted_at
    // columns if they do not exist. ALTER TABLE IF NOT EXISTS COLUMN is not supported by
    // older SQLite; we use a try/catch per column as the idempotent approach.
    for (const ddl of [
      "ALTER TABLE sessions ADD COLUMN message_count INTEGER NOT NULL DEFAULT 0",
      "ALTER TABLE sessions ADD COLUMN interrupted_at TEXT",
    ]) {
      try {
        this.#db.exec(ddl);
      } catch (err: unknown) {
        // Only swallow the idempotent "duplicate column name" case (the column
        // already exists from a prior init). Any other failure — disk full,
        // SQLITE_LOCKED, corruption — must propagate, otherwise the daemon would
        // run without these columns and later silently read undefined.
        const msg = err instanceof Error ? err.message : String(err);
        if (!msg.includes("duplicate column name")) throw err;
      }
    }

    // M7-SESSION-001 (H-1): side table holding the verified bilateral
    // SEAL-INTERRUPTED commitment artifacts. A side table (CREATE TABLE IF NOT
    // EXISTS) is inherently idempotent — no ALTER TABLE / duplicate-column
    // handling required. We keep BOTH parties' signed leaves and the agreed
    // Merkle root so the achieved commitment is never discarded.
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS seal_interrupted_artifacts (
        session_id TEXT PRIMARY KEY,
        role TEXT NOT NULL,
        own_leaf TEXT NOT NULL,
        counterparty_leaf TEXT NOT NULL,
        merkle_root TEXT NOT NULL,
        nonce TEXT NOT NULL,
        created_at INTEGER NOT NULL
      )
    `);

    // DAEMON-004 (AC-007 / SI-001): the daemon-owned per-session Merkle tree,
    // persisted as an ordered list of leaf hashes. The (session_id, leaf_index)
    // primary key enforces append-order uniqueness; a fresh daemon reconstructs
    // each tree from these rows so the transcript survives a restart. Querying
    // by session_id ORDER BY leaf_index is the only read pattern.
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS session_tree_leaves (
        session_id TEXT NOT NULL,
        leaf_index INTEGER NOT NULL,
        leaf_kind TEXT NOT NULL,
        leaf_hash_hex TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (session_id, leaf_index)
      )
    `);

    // Step 2: Detect interrupted sessions (SIGKILL detection — AC-010).
    // Any 'active' row in a freshly-started daemon is a remnant of a prior
    // killed process. Batch-update to 'interrupted' before IPC opens.
    const activeRows = this.#db
      .prepare("SELECT * FROM sessions WHERE status = 'active'")
      .all() as unknown as SessionRecord[];

    if (activeRows.length > 0) {
      const now = Date.now();
      const interruptedAt = new Date(now).toISOString();
      for (const row of activeRows) {
        try {
          this.#db
            .prepare(
              "UPDATE sessions SET status = 'interrupted', updated_at = ?, interrupted_at = COALESCE(interrupted_at, ?) WHERE session_id = ?",
            )
            .run(now, interruptedAt, row.session_id);
          this.#logger.warn("session.interrupted.detected", {
            sessionId: row.session_id,
            agentName: row.agent_name,
            source: "daemon_restart",
          });
        } catch (err: unknown) {
          this.#logger.error("session.interrupt.db.write.failed", {
            sessionId: row.session_id,
            error: err instanceof Error ? err.message : String(err),
          });
        }
      }
    }

    // Step 3: Create the standing receiver node (eager — AC-002 requires it
    // to be ready before the IPC socket opens).
    await this.#createStandingReceiver();
  }

  // ─── Public API ──────────────────────────────────────────────────────────

  /**
   * Get the underlying DatabaseSync handle.
   * Used by the composition root (daemon.ts) to pass to RetryQueue and
   * NonceDedupStore — they share the same SQLCipher DB file (DAEMON-003 AC-008).
   */
  getDb(): DatabaseSync {
    if (!this.#db) {
      throw new Error("SessionNodeManager not initialized — call initialize() first");
    }
    return this.#db;
  }

  /** Whether the standing receiver node is ready for the next inbound session. */
  getStandingReceiverReady(): boolean {
    return this.#standingReceiverReady;
  }

  /**
   * M7-SESSION-001 (M-1 PUSH): register the session-state-change callback.
   * Called by the composition root (daemon.ts) after the NotificationDispatcher
   * exists. Setter injection avoids a construction-order/circular dependency.
   */
  setOnSessionStateChanged(
    cb: (
      agentName: string,
      sessionId: string,
      state: string,
      counterpartyPubkey: string | null,
    ) => void,
  ): void {
    this.#onSessionStateChanged = cb;
  }

  /**
   * Create a new outbound session node.
   * Called during cello_initiate_session.
   *
   * @param sessionId      Unique session ID (hex string)
   * @param agentName      Name of the initiating agent
   * @param counterpartyPubkey  Counterparty's K_local public key (hex)
   * @param counterpartyPeerId  Counterparty's session-layer Peer ID (for gater)
   * @param correlationId  Correlation ID minted at session initiation
   */
  async createSessionNode(
    sessionId: string,
    agentName: string,
    counterpartyPubkey: string,
    counterpartyPeerId: string,
    correlationId: string,
  ): Promise<CreateSessionResult> {
    // Cap enforcement (AC-006)
    if (this.#activeNodes.size >= MAX_SESSION_NODES) {
      this.#logger.warn("session.node.cap.reached", {
        agentName,
        currentCount: this.#activeNodes.size,
        maxCount: MAX_SESSION_NODES,
      });
      return {
        ok: false,
        reason: "max_sessions_reached",
        guidance:
          "The daemon has reached its maximum of 32 concurrent session nodes. " +
          "Close an existing session before starting a new one.",
      };
    }

    // Create restricted gater — allows only counterpartyPeerId
    const gater = new SessionConnectionGater({
      sessionId,
      allowedPeerId: counterpartyPeerId,
      logger: this.#logger,
    });

    let node: CelloNode;
    try {
      node = await this.#factory.createNode({ sessionId, connectionGater: gater });
      await node.start();
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      this.#logger.error("session.node.create.failed", {
        sessionId,
        agentName,
        error: errorMessage,
        correlationId,
      });
      return {
        ok: false,
        reason: "session_node_creation_failed",
        guidance:
          "Failed to create session transport node. The daemon logged the cause in " +
          "session.node.create.failed. Check that the system has available ports and sufficient memory.",
      };
    }

    const peerId = node.getPeerId();
    const addrs = node.listenAddresses();

    // Persist to SQLite
    this.#insertSessionRow(sessionId, agentName, counterpartyPubkey, "active");

    // Log observability event (session.node.created)
    this.#logger.info("session.node.created", {
      sessionId,
      agentName,
      sessionPeerId: peerId,
      correlationId,
    });

    // Add to active map
    this.#activeNodes.set(sessionId, {
      node,
      agentName,
      counterpartyPubkey,
      gater,
      correlationId,
      counterpartySessionPeerId: counterpartyPeerId,
    });

    // DAEMON-004: register the content stream handler so inbound content_frames
    // are cross-checked, appended to the daemon-owned tree, and buffered.
    this.#registerContentHandler(sessionId, node, counterpartyPubkey);

    return { ok: true, peerId, addrs };
  }

  /**
   * Hand the standing receiver to an inbound session.
   * Called during cello_await_session.
   *
   * CRITICAL (AC-015): gater.setAllowedPeer() is called BEFORE returning
   * the node's multiaddr to the caller. This closes the window where an
   * unexpected peer could connect during the hand-off.
   */
  acceptSession(
    sessionId: string,
    agentName: string,
    counterpartyPubkey: string,
    initiatorPeerId: string,
    correlationId: string,
  ): CreateSessionResult {
    if (!this.#standingReceiverReady || this.#standingReceiver === null) {
      return {
        ok: false,
        reason: "standing_receiver_unavailable",
        guidance:
          "The standing receiver node is initializing (completes within 200ms). " +
          "Retry cello_await_session in a moment.",
      };
    }

    // Cap enforcement — inbound sessions count against the same limit (AC-006)
    if (this.#activeNodes.size >= MAX_SESSION_NODES) {
      this.#logger.warn("session.node.cap.reached", {
        agentName,
        currentCount: this.#activeNodes.size,
        maxCount: MAX_SESSION_NODES,
      });
      return {
        ok: false,
        reason: "max_sessions_reached",
        guidance:
          "The daemon has reached its maximum of 32 concurrent session nodes. " +
          "Close an existing session before starting a new one.",
      };
    }

    const { node, gater } = this.#standingReceiver;

    // AC-015: update gater BEFORE retrieving multiaddr / returning to caller
    gater.setAllowedPeer(initiatorPeerId);

    const peerId = node.getPeerId();
    const addrs = node.listenAddresses();

    // Persist to SQLite
    this.#insertSessionRow(sessionId, agentName, counterpartyPubkey, "active");

    // Log observability event
    this.#logger.info("session.node.created", {
      sessionId,
      agentName,
      sessionPeerId: peerId,
      correlationId,
    });

    // Remove from standing receiver slot and add to active map
    this.#standingReceiver = null;
    this.#standingReceiverReady = false;
    this.#activeNodes.set(sessionId, {
      node,
      agentName,
      counterpartyPubkey,
      gater,
      correlationId,
      counterpartySessionPeerId: initiatorPeerId,
    });

    // DAEMON-004: register the content stream handler for the inbound session.
    this.#registerContentHandler(sessionId, node, counterpartyPubkey);

    // Immediately spin up a replacement (async — do NOT await, AC-003)
    this.#createStandingReceiverWithRetry(correlationId);

    return { ok: true, peerId, addrs };
  }

  /**
   * Destroy a session node after seal or on error teardown.
   * Status written to SQLite.
   */
  async destroySessionNode(
    sessionId: string,
    reason: "sealed" | "interrupted" | "error",
  ): Promise<void> {
    const entry = this.#activeNodes.get(sessionId);
    if (!entry) return;

    try {
      await entry.node.stop();
    } catch (err: unknown) {
      this.#logger.error("session.node.stop.failed", {
        sessionId,
        agentName: entry.agentName,
        error: err instanceof Error ? err.message : String(err),
        correlationId: entry.correlationId,
      });
      // Fall through — still remove from active map and update DB
    }

    // Update SQLite — 'sealed' → 'sealed', 'interrupted'/'error' → 'interrupted'.
    // 'error' is not a valid SessionStatus in SQLite; error-torn-down sessions
    // surface as interrupted so AC-010 recovery handles them at next login.
    // The session.node.destroyed log preserves the original reason for observability.
    const dbStatus = reason === "sealed" ? "sealed" : "interrupted";
    this.#updateSessionStatus(sessionId, dbStatus);

    this.#activeNodes.delete(sessionId);

    this.#logger.info("session.node.destroyed", {
      sessionId,
      agentName: entry.agentName,
      reason,
    });
  }

  /**
   * Graceful shutdown: mark all active sessions as interrupted, stop all nodes.
   * Called from the SIGTERM / cello logout path (AC-009).
   * SQLite writes complete before this method returns.
   */
  async gracefulShutdown(): Promise<void> {
    // Mark ALL 'active' rows interrupted in SQLite — single batch UPDATE covers
    // both in-memory managed nodes AND any rows that were inserted directly
    // (e.g. by the binary AC-009 SIGTERM test inserting synthetic rows).
    // This is the authoritative persistence step; in-memory map is secondary.
    const now = Date.now();
    if (!this.#db) {
      this.#logger.error("session.interrupt.db.write.failed", {
        sessionId: "__all__",
        error: "db not initialized",
      });
    } else {
      const interruptedAt = new Date(now).toISOString();
      try {
        this.#db.prepare(
          "UPDATE sessions SET status = 'interrupted', updated_at = ?, interrupted_at = COALESCE(interrupted_at, ?) WHERE status = 'active'",
        ).run(now, interruptedAt);
      } catch (err: unknown) {
        this.#logger.error("session.interrupt.db.write.failed", {
          sessionId: "__all__",
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }

    // Stop all session nodes, then emit session.node.destroyed only on success
    // (mirrors destroySessionNode ordering: stop first, log destroyed after)
    const stopPromises: Promise<void>[] = [];
    for (const [sessionId, entry] of this.#activeNodes) {
      stopPromises.push(
        entry.node.stop().then(() => {
          this.#logger.info("session.node.destroyed", {
            sessionId,
            agentName: entry.agentName,
            reason: "interrupted",
          });
        }).catch((err: unknown) => {
          this.#logger.error("session.node.stop.failed", {
            sessionId,
            agentName: entry.agentName,
            error: err instanceof Error ? err.message : String(err),
            correlationId: entry.correlationId,
          });
        }),
      );
    }
    await Promise.all(stopPromises);
    this.#activeNodes.clear();

    // Stop standing receiver
    if (this.#standingReceiver) {
      try {
        await this.#standingReceiver.node.stop();
      } catch (err: unknown) {
        this.#logger.error("session.node.stop.failed", {
          sessionId: "standing_receiver_shutdown",
          agentName: STANDING_RECEIVER_AGENT_NAME,
          error: err instanceof Error ? err.message : String(err),
          correlationId: "n/a",
        });
      }
      this.#standingReceiver = null;
      this.#standingReceiverReady = false;
    }
  }

  /**
   * Return all sessions with a given status from SQLite.
   * Used by cello status to surface interrupted sessions.
   */
  getSessionsByStatus(status: "active" | "sealed" | "interrupted"): SessionRecord[] {
    if (!this.#db) return [];
    return this.#db
      .prepare("SELECT * FROM sessions WHERE status = ?")
      .all(status) as unknown as SessionRecord[];
  }

  /**
   * M7-SESSION-001: Mark a session as interrupted with message count and timestamp.
   * Called when a relay session_interrupted frame arrives or a relay stream closes.
   * Also tears down the in-memory session node if one exists for this sessionId.
   *
   * @param sessionId The hex session ID from the relay frame
   * @param messageCount Number of message leaves at interruption
   * @param source 'relay_frame' | 'stream_close'
   */
  async markInterruptedWithDetails(
    sessionId: string,
    messageCount: number,
    source: "relay_frame" | "stream_close",
  ): Promise<void> {
    if (!this.#db) return;

    // H-3 SECURITY: only an 'active' session may transition to 'interrupted'.
    // A late or forged relay frame must NOT revert a 'sealed', 'seal_interrupted_pending',
    // or already-'interrupted' session back to 'interrupted'. This mirrors the
    // stream-close guard in #watchRelayStream below — the two paths must agree.
    const existing = this.getSessionRecord(sessionId);
    if (!existing || existing.status !== "active") {
      this.#logger.warn("session.interrupt.ignored", {
        sessionId,
        source,
        currentStatus: existing?.status ?? "absent",
        reason: "session_not_active",
      });
      return;
    }

    const now = Date.now();
    const interruptedAt = new Date(now).toISOString();

    try {
      // The `AND status = 'active'` predicate is the authoritative guard: even if
      // the pre-check above raced (it cannot — DatabaseSync is synchronous), the
      // UPDATE only mutates a row that is still active.
      this.#db
        .prepare(
          "UPDATE sessions SET status = 'interrupted', updated_at = ?, message_count = ?, interrupted_at = ? WHERE session_id = ? AND status = 'active'",
        )
        .run(now, messageCount, interruptedAt, sessionId);
    } catch (err: unknown) {
      this.#logger.error("session.interrupt.db.write.failed", {
        sessionId,
        error: err instanceof Error ? err.message : String(err),
      });
    }

    // Look up the entry to get agentName for the log event.
    // Fall back to the DB row when the session isn't in the in-memory map
    // (e.g. the session was already torn down before the stream watcher fired).
    const entry = this.#activeNodes.get(sessionId);
    const agentName: string = entry?.agentName
      ?? existing.agent_name
      ?? "unknown";

    // Tear down the in-memory session node if it exists
    if (entry) {
      try {
        await entry.node.stop();
      } catch (err: unknown) {
        this.#logger.error("session.node.stop.failed", {
          sessionId,
          agentName,
          error: err instanceof Error ? err.message : String(err),
          correlationId: entry.correlationId,
        });
        // Fall through — still remove from active map
      }
      this.#activeNodes.delete(sessionId);
      this.#logger.info("session.node.destroyed", {
        sessionId,
        agentName,
        reason: "interrupted",
      });
    }

    this.#logger.warn("session.interrupted.detected", {
      sessionId,
      agentName,
      source,
    });

    // M7-SESSION-001 (M-1 PUSH): notify live MCP clients that this session is now
    // interrupted. Only fires on a real active→interrupted transition (the guard
    // above already returned for any non-active session).
    try {
      this.#onSessionStateChanged?.(
        agentName,
        sessionId,
        "interrupted",
        existing.counterparty_pubkey,
      );
    } catch (err: unknown) {
      this.#logger.debug("session.state.notify.failed", {
        sessionId,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  /**
   * M7-SESSION-001 (H-1): persist a verified bilateral SEAL-INTERRUPTED
   * commitment and transition the session to 'seal_interrupted_pending'.
   *
   * This is NOT a seal. It records that both parties produced and exchanged
   * K_local-signed SEAL-INTERRUPTED leaves over the same {leafCount, merkleRoot}.
   * The FROST threshold notarization is a separate, currently-unwired step (see
   * daemon.ts handleSealInterruptedFlow H-1 note), which is precisely why the
   * status is 'seal_interrupted_pending' and never 'sealed'.
   *
   * The status update is guarded so it only advances a session out of the
   * 'interrupted' state — it will not overwrite a 'sealed' row.
   *
   * @returns true if the session row was advanced to seal_interrupted_pending.
   */
  persistSealInterruptedCommitment(opts: {
    sessionId: string;
    role: "initiator" | "responder";
    ownLeaf: unknown;
    counterpartyLeaf: unknown;
    merkleRoot: string;
    nonce: string;
  }): boolean {
    if (!this.#db) return false;
    const now = Date.now();
    try {
      this.#db
        .prepare(
          `INSERT OR REPLACE INTO seal_interrupted_artifacts
           (session_id, role, own_leaf, counterparty_leaf, merkle_root, nonce, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          opts.sessionId,
          opts.role,
          JSON.stringify(opts.ownLeaf),
          JSON.stringify(opts.counterpartyLeaf),
          opts.merkleRoot,
          opts.nonce,
          now,
        );
    } catch (err: unknown) {
      this.#logger.error("session.interrupted.db.write.failed", {
        sessionId: opts.sessionId,
        error: err instanceof Error ? err.message : String(err),
      });
      return false;
    }

    const result = this.#db
      .prepare(
        "UPDATE sessions SET status = 'seal_interrupted_pending', updated_at = ? WHERE session_id = ? AND status = 'interrupted'",
      )
      .run(now, opts.sessionId);
    return Number(result.changes) > 0;
  }

  /**
   * M7-SESSION-001 (H-1): read back the persisted bilateral commitment artifacts
   * for a session. Returns null when none exist.
   */
  getSealInterruptedArtifacts(sessionId: string): {
    role: string;
    ownLeaf: unknown;
    counterpartyLeaf: unknown;
    merkleRoot: string;
    nonce: string;
  } | null {
    if (!this.#db) return null;
    const row = this.#db
      .prepare("SELECT * FROM seal_interrupted_artifacts WHERE session_id = ?")
      .get(sessionId) as
      | {
          role: string;
          own_leaf: string;
          counterparty_leaf: string;
          merkle_root: string;
          nonce: string;
        }
      | undefined;
    if (!row) return null;
    return {
      role: row.role,
      ownLeaf: JSON.parse(row.own_leaf),
      counterpartyLeaf: JSON.parse(row.counterparty_leaf),
      merkleRoot: row.merkle_root,
      nonce: row.nonce,
    };
  }

  /**
   * Return the session record for a specific sessionId, regardless of status.
   * Used by cello_close_session to inspect session state.
   */
  getSessionRecord(sessionId: string): SessionRecord | null {
    if (!this.#db) return null;
    const row = this.#db
      .prepare("SELECT * FROM sessions WHERE session_id = ?")
      .get(sessionId) as unknown as SessionRecord | undefined;
    return row ?? null;
  }

  // ─── DAEMON-004: daemon-owned Merkle tree ──────────────────────────────────

  /**
   * Return the daemon-owned Merkle tree for a session, loading it from SQLite
   * on first access (so it survives a restart — AC-007). Never returns null;
   * an unknown session yields an empty tree.
   */
  getSessionTree(sessionId: string): SessionTree {
    const cached = this.#trees.get(sessionId);
    if (cached) return cached;
    const tree = this.#loadTreeFromDb(sessionId);
    this.#trees.set(sessionId, tree);
    return tree;
  }

  /** Current daemon-owned tree root for a session, as hex. */
  getSessionTreeRootHex(sessionId: string): string {
    return this.getSessionTree(sessionId).rootHex();
  }

  /**
   * Append a leaf (by its 32-byte leaf-hash hex) to the daemon-owned tree,
   * persist it, advance the root, and fire session.tree.appended.
   *
   * @returns the new leaf index and the recomputed root hex.
   */
  appendSessionLeaf(
    sessionId: string,
    kind: SessionTreeLeafKind,
    leafHashHex: string,
    correlationId?: string,
  ): { leafIndex: number; newRootHex: string } {
    const tree = this.getSessionTree(sessionId);
    const { leafIndex, newRootHex } = tree.appendLeafHash(kind, leafHashHex);

    if (this.#db) {
      try {
        this.#db
          .prepare(
            `INSERT INTO session_tree_leaves
             (session_id, leaf_index, leaf_kind, leaf_hash_hex, created_at)
             VALUES (?, ?, ?, ?, ?)`,
          )
          .run(sessionId, leafIndex, kind, leafHashHex, Date.now());
      } catch (err: unknown) {
        // A persist failure must be visible, not swallowed: the in-memory tree
        // has advanced but the durable transcript has not, which would diverge
        // on restart. Surface it loudly.
        this.#logger.error("session.tree.persist.failed", {
          sessionId,
          leafIndex,
          error: err instanceof Error ? err.message : String(err),
          correlationId,
        });
      }
    }

    this.#logger.info("session.tree.appended", {
      sessionId,
      leafIndex,
      newRootHex,
      correlationId,
    });
    return { leafIndex, newRootHex };
  }

  /**
   * DAEMON-004: send content over the session node's direct P2P content stream.
   * On a dead/missing stream this returns a NAMED, diagnosable failure — never a
   * silent success and never a desync (closing the old silent
   * `void sendContentFrame(...)` catch at session-manager.ts:621-623).
   *
   * The relay hash-submit round-trip that assigns the global sequence number is
   * the live-session path (AC-001 under CELLO_E2E_LIVE) and is layered by MSG-001.
   */
  async sendContent(
    sessionId: string,
    content: Uint8Array,
    contentHash: Uint8Array,
  ): Promise<{ ok: true } | { ok: false; reason: string; error: string }> {
    const entry = this.#activeNodes.get(sessionId);
    if (!entry) {
      return { ok: false, reason: "session_node_unavailable", error: "no active session node for this session" };
    }
    try {
      const stream = await entry.node.newStream(entry.counterpartySessionPeerId, CELLO_CONTENT_PROTOCOL_ID);
      const frame = CBOR_ENC.encode({
        type: "content_frame",
        session_id: sessionId,
        content_hash: contentHash,
        content_bytes: content,
      }) as Uint8Array;
      stream.send(lp.encode.single(frame));
      try { await stream.close(); } catch { /* best-effort close */ }
      return { ok: true };
    } catch (err: unknown) {
      // error.message extracted — never [object Object].
      return {
        ok: false,
        reason: "session_stream_unavailable",
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }

  /**
   * DAEMON-004: cross-check received content against its hash, append the
   * verified leaf to the daemon-owned tree, and buffer it for cello_receive.
   * A hash MISMATCH is genuine tamper — rejected without append or buffer.
   *
   * @returns the appended leaf index (as sequenceNumber) on success.
   */
  ingestReceivedContent(
    sessionId: string,
    content: Uint8Array,
    contentHash: Uint8Array,
    correlationId?: string,
  ): { ok: true; leafIndex: number; sequenceNumber: number } | { ok: false; reason: string } {
    const computed = createHash("sha256").update(new Uint8Array([0x00])).update(content).digest();
    const contentHashHex = Buffer.from(contentHash).toString("hex");
    if (Buffer.from(computed).toString("hex") !== contentHashHex) {
      this.#logger.warn("session.content.cross_check.failed", {
        sessionId,
        reason: "content_hash_mismatch",
        correlationId,
      });
      return { ok: false, reason: "content_hash_mismatch" };
    }

    const entry = this.#activeNodes.get(sessionId);
    const senderPubkey = entry?.counterpartyPubkey
      ?? this.getSessionRecord(sessionId)?.counterparty_pubkey
      ?? "unknown";

    const { leafIndex, newRootHex } = this.appendSessionLeaf(sessionId, "msg", contentHashHex, correlationId);

    let buf = this.#receivedContent.get(sessionId);
    if (!buf) { buf = []; this.#receivedContent.set(sessionId, buf); }
    buf.push({ contentHex: Buffer.from(content).toString("hex"), senderPubkey, sequenceNumber: leafIndex });

    this.#logger.info("session.content.received", {
      sessionId,
      senderPubkey,
      contentHashHex,
      sequenceNumber: leafIndex,
      correlationId,
    });
    void newRootHex;
    return { ok: true, leafIndex, sequenceNumber: leafIndex };
  }

  /** DAEMON-004: pop the oldest verified received content for cello_receive. */
  takeReceivedContent(sessionId: string): ReceivedContentEntry | null {
    const buf = this.#receivedContent.get(sessionId);
    if (!buf || buf.length === 0) return null;
    return buf.shift() ?? null;
  }

  #loadTreeFromDb(sessionId: string): SessionTree {
    if (!this.#db) return SessionTree.empty();
    const rows = this.#db
      .prepare(
        "SELECT leaf_kind, leaf_hash_hex FROM session_tree_leaves WHERE session_id = ? ORDER BY leaf_index ASC",
      )
      .all(sessionId) as Array<{ leaf_kind: string; leaf_hash_hex: string }>;
    return SessionTree.fromLeaves(
      rows.map((r) => ({ kind: r.leaf_kind === "ctrl" ? "ctrl" : "msg", hashHex: r.leaf_hash_hex })),
    );
  }

  /**
   * DAEMON-004: register the /cello/content/1.0.0 handler on a session node so
   * inbound content_frames are decoded, cross-checked, and ingested.
   */
  #registerContentHandler(sessionId: string, node: CelloNode, _counterpartyPubkey: string): void {
    void node.handle(CELLO_CONTENT_PROTOCOL_ID, (stream) => {
      void this.#handleContentStream(sessionId, stream);
    }).catch((err: unknown) => {
      this.#logger.error("session.content.handler.register.failed", {
        sessionId,
        error: err instanceof Error ? err.message : String(err),
      });
    });
  }

  async #handleContentStream(sessionId: string, stream: Stream): Promise<void> {
    const iter = (lp.decode(stream) as AsyncIterable<unknown>)[Symbol.asyncIterator]() as AsyncIterator<Uint8Array>;
    try {
      const result = await iter.next();
      if (result.done || result.value === undefined) return;
      const bytes = result.value instanceof Uint8Array ? result.value
        : Buffer.isBuffer(result.value) ? new Uint8Array(result.value as Buffer)
        : (result.value as { slice(): Uint8Array }).slice();
      const frame = decode(bytes) as Record<string, unknown>;
      if (frame["type"] !== "content_frame") return;
      const contentBytes = frame["content_bytes"];
      const contentHash = frame["content_hash"];
      if (!(contentBytes instanceof Uint8Array) || !(contentHash instanceof Uint8Array)) return;
      this.ingestReceivedContent(sessionId, contentBytes, contentHash);
    } catch (err: unknown) {
      this.#logger.warn("session.content.stream.read.failed", {
        sessionId,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  /**
   * M7-SESSION-001 AC-004/AC-005: Register a relay stream for an active session.
   * Starts a background reader that watches for session_interrupted frames and
   * stream close events. Both detection paths call markInterruptedWithDetails().
   *
   * The reader runs for the lifetime of the relay stream. If the stream closes
   * without delivering a session_interrupted frame (AC-005 / 'stream_close' path),
   * the session is still marked interrupted.
   *
   * @param sessionId The hex session ID
   * @param stream The relay stream to monitor
   * @param messageCount Number of message leaves at the time of registration
   *   (used as the count at interruption — best effort since exact count at frame
   *   receipt may differ, but this is the value available at stream setup time)
   */
  registerRelayStream(sessionId: string, stream: Stream, messageCount: number = 0): void {
    void this.#watchRelayStream(sessionId, stream, messageCount);
  }

  /**
   * Background relay stream watcher.
   * Pseudocode:
   *   1. Create LP-framed iterator over the stream
   *   2. For each frame:
   *      a. If type === 'session_interrupted':
   *         - Record receivedInterruptFrame = true
   *         - Call markInterruptedWithDetails(sessionId, messageCount, 'relay_frame')
   *         - Break (no more frames expected)
   *   3. On stream close (loop ends normally or with error):
   *      a. If !receivedInterruptFrame:
   *         - Call markInterruptedWithDetails(sessionId, messageCount, 'stream_close')
   */
  async #watchRelayStream(sessionId: string, stream: Stream, messageCount: number): Promise<void> {
    let receivedInterruptFrame = false;
    const source = (lp.decode(stream) as AsyncIterable<unknown>)[Symbol.asyncIterator]() as AsyncIterator<Uint8Array>;
    try {
      while (true) {
        let result: IteratorResult<Uint8Array>;
        try {
          result = await source.next();
        } catch {
          // Stream error (e.g. stream aborted) — treat as stream close
          break;
        }
        if (result.done || result.value === undefined) break;

        let frame: Record<string, unknown>;
        try {
          const bytes = result.value instanceof Uint8Array ? result.value
            : Buffer.isBuffer(result.value) ? new Uint8Array(result.value as Buffer)
            : (result.value as { slice(): Uint8Array }).slice();
          frame = decode(bytes) as Record<string, unknown>;
        } catch {
          continue;
        }

        if (frame["type"] === "session_interrupted") {
          // H-3 SECURITY: this stream is registered (bound) to a specific
          // sessionId. A malicious or buggy relay could put a DIFFERENT session_id
          // in the frame body to target a session this stream is not authorized
          // for (cross-session targeting). Never trust the frame's id: if the frame
          // names a different session, reject it and keep watching the bound one.
          const frameSessionId = typeof frame["session_id"] === "string"
            ? frame["session_id"]
            : (frame["session_id"] instanceof Uint8Array
              ? Buffer.from(frame["session_id"]).toString("hex")
              : null);
          if (frameSessionId !== null && frameSessionId !== sessionId) {
            this.#logger.warn("session.interrupt.frame.session_mismatch", {
              boundSessionId: sessionId,
              frameSessionId,
              reason: "cross_session_frame_rejected",
            });
            continue; // ignore the hostile/mismatched frame; keep reading
          }
          receivedInterruptFrame = true;
          // Always mark the BOUND sessionId — never the id carried in the frame.
          await this.markInterruptedWithDetails(sessionId, messageCount, "relay_frame");
          break; // No more relay frames expected after session_interrupted
        }
      }
    } catch {
      // Stream read loop ended — fall through to stream_close check
    }

    // AC-005: stream closed without a session_interrupted frame
    if (!receivedInterruptFrame) {
      // Only mark interrupted if this session is still active in SQLite
      const record = this.getSessionRecord(sessionId);
      if (record && record.status === "active") {
        await this.markInterruptedWithDetails(sessionId, messageCount, "stream_close");
      }
    }
  }

  // ─── Private helpers ──────────────────────────────────────────────────────

  async #createStandingReceiver(): Promise<void> {
    const sessionId = `standing_receiver_${randomUUID()}`;
    // Mint a correlationId per creation attempt so log events are trackable
    const correlationId = randomUUID();
    const gater = new SessionConnectionGater({
      sessionId,
      allowedPeerId: null, // open — counterparty unknown at creation time
      logger: this.#logger,
    });

    let node: CelloNode;
    try {
      node = await this.#factory.createNode({ sessionId, connectionGater: gater });
      await node.start();
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      this.#logger.error("session.node.create.failed", {
        sessionId,
        agentName: STANDING_RECEIVER_AGENT_NAME,
        error: errorMessage,
        correlationId,
      });
      return; // standing receiver not ready — callers check #standingReceiverReady
    }

    this.#standingReceiver = { node, gater };
    this.#standingReceiverReady = true;

    this.#logger.info("session.node.created", {
      sessionId,
      agentName: STANDING_RECEIVER_AGENT_NAME,
      sessionPeerId: node.getPeerId(),
      correlationId,
    });
  }

  #insertSessionRow(
    sessionId: string,
    agentName: string,
    counterpartyPubkey: string,
    status: "active" | "sealed" | "interrupted",
  ): boolean {
    if (!this.#db) return false;
    const now = Date.now();
    try {
      this.#db
        .prepare(
          `INSERT INTO sessions
           (session_id, agent_name, counterparty_pubkey, status, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?)`,
        )
        .run(sessionId, agentName, counterpartyPubkey, status, now, now);
      return true;
    } catch (err: unknown) {
      this.#logger.error("session.interrupt.db.write.failed", {
        sessionId,
        error: err instanceof Error ? err.message : String(err),
      });
      return false;
    }
  }

  async #createStandingReceiverWithRetry(correlationId: string): Promise<void> {
    const MAX_RETRIES = 3;
    const BACKOFF_MS = [100, 500, 2000];
    for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
      try {
        await this.#createStandingReceiver();
        return;
      } catch (err: unknown) {
        this.#logger.error("session.node.create.failed", {
          sessionId: "standing_receiver_replacement",
          agentName: STANDING_RECEIVER_AGENT_NAME,
          error: err instanceof Error ? err.message : String(err),
          correlationId,
        });
        if (attempt < MAX_RETRIES - 1) {
          await new Promise((r) => setTimeout(r, BACKOFF_MS[attempt]));
        }
      }
    }
    this.#logger.error("session.standing_receiver.permanently_unavailable", {
      correlationId,
    });
  }

  #updateSessionStatus(
    sessionId: string,
    status: "active" | "sealed" | "interrupted",
  ): void {
    if (!this.#db) return;
    const now = Date.now();
    try {
      this.#db
        .prepare(
          "UPDATE sessions SET status = ?, updated_at = ? WHERE session_id = ?",
        )
        .run(status, now, sessionId);
    } catch (err: unknown) {
      this.#logger.error("session.interrupt.db.write.failed", {
        sessionId,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }
}
