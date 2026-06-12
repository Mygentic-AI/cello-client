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
import { randomUUID } from "node:crypto";
import type { Logger, SessionRecord } from "./types.js";
import { MAX_SESSION_NODES, STANDING_RECEIVER_AGENT_NAME } from "./types.js";
import { SessionConnectionGater } from "./session-connection-gater.js";
import type { CelloNode } from "@cello-protocol/transport";

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

    // Step 2: Detect interrupted sessions (SIGKILL detection — AC-010).
    // Any 'active' row in a freshly-started daemon is a remnant of a prior
    // killed process. Batch-update to 'interrupted' before IPC opens.
    const activeRows = this.#db
      .prepare("SELECT * FROM sessions WHERE status = 'active'")
      .all() as unknown as SessionRecord[];

    if (activeRows.length > 0) {
      const now = Date.now();
      for (const row of activeRows) {
        try {
          this.#db
            .prepare(
              "UPDATE sessions SET status = 'interrupted', updated_at = ? WHERE session_id = ?",
            )
            .run(now, row.session_id);
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

  /** Whether the standing receiver node is ready for the next inbound session. */
  getStandingReceiverReady(): boolean {
    return this.#standingReceiverReady;
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
    });

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
    });

    // Immediately spin up a replacement (async — do NOT await, AC-003)
    this.#createStandingReceiver().catch((err: unknown) => {
      this.#logger.error("session.node.create.failed", {
        sessionId: "standing_receiver_replacement",
        agentName: STANDING_RECEIVER_AGENT_NAME,
        error: err instanceof Error ? err.message : String(err),
        correlationId,
      });
    });

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
    // Mark all active sessions interrupted in SQLite first
    const now = Date.now();
    for (const [sessionId] of this.#activeNodes) {
      try {
        if (!this.#db) {
          this.#logger.error("session.interrupt.db.write.failed", {
            sessionId,
            error: "db not initialized",
          });
        } else {
          this.#db.prepare(
            "UPDATE sessions SET status = 'interrupted', updated_at = ? WHERE session_id = ?",
          ).run(now, sessionId);
        }
      } catch (err: unknown) {
        this.#logger.error("session.interrupt.db.write.failed", {
          sessionId,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }

    // Stop all session nodes, then emit session.node.destroyed after each stop
    // (mirrors destroySessionNode ordering: stop first, log destroyed after)
    const stopPromises: Promise<void>[] = [];
    for (const [sessionId, entry] of this.#activeNodes) {
      stopPromises.push(
        entry.node.stop().catch((err: unknown) => {
          this.#logger.error("session.node.stop.failed", {
            sessionId,
            agentName: entry.agentName,
            error: err instanceof Error ? err.message : String(err),
            correlationId: entry.correlationId,
          });
        }).then(() => {
          this.#logger.info("session.node.destroyed", {
            sessionId,
            agentName: entry.agentName,
            reason: "interrupted",
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
          `INSERT OR REPLACE INTO sessions
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
