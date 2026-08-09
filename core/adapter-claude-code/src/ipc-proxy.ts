/**
 * IPC Proxy — thin client for connecting cello-mcp to the daemon.
 *
 * RECONNECT-001: the proxy SURVIVES a daemon restart. A dropped socket reconnects with backoff; it
 * must never latch a permanent dead flag, which would make every subsequent tool call return
 * `ipc_connection_lost` forever and orphan every connected agent at once.
 *
 * Two invariants the reconnect must not break:
 *
 *  1. **Replay the session, not just the socket.** The daemon rebuilds per-connection state on
 *     restart, so a reconnected socket has no registered clientType and no current agent. Both are
 *     replayed (`ipc.connect`, then `cello_use_agent`) BEFORE any queued caller is released —
 *     otherwise tools fail `no_current_agent` and the NotificationDispatcher (which routes on
 *     currentAgent) silently stops delivering doorbells.
 *
 *  2. **Never replay an in-flight request.** `cello_send` is not idempotent; a silent retry would
 *     double-send a message. In-flight calls resolve as `ipc_connection_lost` and the caller retries
 *     explicitly. Only the handshake — which IS idempotent — is replayed.
 */

import { createConnection, type Socket } from "node:net";

export interface IpcProxyResult {
  [key: string]: unknown;
}

export interface IpcProxyOptions {
  /** Replayed as `ipc.connect { clientType }` after a reconnect. */
  clientType?: string;
}

const IPC_CONNECTION_LOST = {
  ok: false,
  reason: "ipc_connection_lost",
  guidance:
    "The connection to the CELLO daemon was lost and could not be re-established. The daemon may be down — run `cello status` in a terminal to check, and `cello login` to start it. If the daemon is running, reconnect this MCP server with `/mcp reconnect cello`.",
};

/** Returned while a reconnect is in progress or just failed — the caller should simply retry. */
const IPC_RECONNECTING = {
  ok: false,
  reason: "ipc_connection_lost",
  guidance:
    "The CELLO daemon connection dropped (the daemon likely restarted) and is being re-established automatically. Retry this call in a moment. If it keeps failing, run `cello status`, then `/mcp reconnect cello`.",
};

const IPC_DESERIALIZATION_ERROR = {
  ok: false,
  reason: "ipc_deserialization_error",
  guidance:
    "The daemon sent a malformed response — this may be transient. Retry your operation. If the error persists, run `cello-mcp --version` and `cello status` to check for a version mismatch between cello-mcp and the running daemon.",
};

// CELLO-M7-MSG-001: must stay in sync with ipc-server.ts MAX_BUFFER_SIZE. It is 4 MB so that a
// max-size (1 MB) cello_send content message + JSON envelope traverses IPC and reaches the daemon's
// content_too_large check, instead of tripping a fatal buffer overflow at the 1 MB content cap
// boundary.
const MAX_BUFFER_SIZE = 4 * 1024 * 1024; // 4MB — matches IPC server limit

const RECONNECT_BASE_DELAY_MS = 200;
const RECONNECT_MAX_DELAY_MS = 5_000;
/** How long a caller waits for an in-progress reconnect before giving up on this call. */
const RECONNECT_WAIT_MS = 15_000;
/** A handshake replay that never answers must not wedge the reconnect loop. */
const HANDSHAKE_TIMEOUT_MS = 5_000;

export class IpcProxy {
  readonly #socketPath: string;
  readonly #clientType: string | undefined;
  #socket: Socket | null = null;
  /** True only after close() — an operator-initiated shutdown never reconnects. */
  #closedByUs = false;
  #connected = false;
  #nextId = 1;
  #pending = new Map<string, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
  #buffer = "";
  #notificationHandler: ((frame: Record<string, unknown>) => void) | null = null;
  #reconnectHandler: (() => void) | null = null;

  #reconnectTimer: NodeJS.Timeout | null = null;
  #reconnectAttempt = 0;
  /** Single-flight guard: a reconnect in progress must never spawn a second loop. */
  #reconnecting = false;
  /**
   * A FAILED INITIAL connect must not start a background reconnect loop behind connect()'s
   * rejection — the caller (cello-mcp) exits with an actionable message instead. Only a
   * connection that once worked is worth restoring.
   */
  #everConnected = false;
  #connectWaiters: Array<() => void> = [];
  /** Last successfully-selected agent, replayed after reconnect so routing survives. */
  #currentAgent: string | null = null;

  constructor(socketPath: string, opts: IpcProxyOptions = {}) {
    this.#socketPath = socketPath;
    this.#clientType = opts.clientType;
  }

  /**
   * Register a handler for server-initiated notification frames (frames with a `notification`
   * key and no `id`). The daemon's NotificationDispatcher pushes these; the Claude Code shim
   * translates each into an MCP `notifications/claude/channel` event (CELLO-M8C-WAKE-001,
   * channel stage 1). Only one handler is supported — the last registration wins. The handler
   * survives reconnects.
   */
  onNotification(handler: (frame: Record<string, unknown>) => void): void {
    this.#notificationHandler = handler;
  }

  /**
   * Register a handler fired when the proxy RE-connects to a daemon, after the handshake replay has
   * restored the session — never on the first connect, which the caller already knows about because
   * `connect()` returned.
   *
   * It exists because the daemon coming back was invisible to the agent: `shutdown` is pushed by the
   * dying daemon, but nothing announces the new one, since a fresh daemon has no idea a client is
   * waiting. Only the shim knows, and it was writing "reconnected to the CELLO daemon" to stderr,
   * which no agent reads. Fired AFTER the replay so the announcement is true when it arrives — the
   * agent selection is already restored, not still in flight.
   */
  onReconnect(handler: () => void): void {
    this.#reconnectHandler = handler;
  }

  /** The agent this connection is routing to, as restored by the handshake replay. */
  get currentAgent(): string | null {
    return this.#currentAgent;
  }

  /**
   * Connect to the daemon IPC socket.
   * Throws if the socket doesn't exist (ENOENT) or daemon isn't listening (ECONNREFUSED), so
   * startup still fails fast with an actionable message rather than retrying invisibly.
   */
  connect(): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const socket = createConnection(this.#socketPath);
      this.#socket = socket;
      let settled = false;

      socket.on("connect", () => {
        settled = true;
        this.#connected = true;
        this.#everConnected = true;
        this.#reconnectAttempt = 0;
        resolve();
      });

      socket.on("error", (err: Error) => {
        if (!settled) {
          settled = true;
          this.#connected = false;
          this.#failPending();
          reject(err);
          return;
        }
        // Post-connect errors surface as 'close'; nothing to do here.
      });

      this.#attach(socket);
    });
  }

  /** Wire the data/close handlers shared by the initial connect and every reconnect. */
  #attach(socket: Socket): void {
    socket.on("data", (chunk: Buffer) => {
      this.#buffer += chunk.toString("utf-8");
      if (this.#buffer.length > MAX_BUFFER_SIZE) {
        this.#buffer = "";
        socket.destroy();
        return;
      }
      this.#processBuffer();
    });

    socket.on("close", () => {
      const wasConnected = this.#connected;
      this.#connected = false;
      // Invariant 2: pending requests are FAILED, never replayed. cello_send is not idempotent.
      this.#failPending();
      if (!this.#closedByUs && wasConnected) {
        process.stderr.write("cello-mcp: daemon connection lost — reconnecting…\n");
      }
      // Guard on #everConnected: a failed initial connect rejects to the caller; it must not
      // silently retry in the background behind that rejection.
      if (!this.#closedByUs && this.#everConnected) this.#scheduleReconnect();
    });
  }

  #failPending(): void {
    for (const [, p] of this.#pending) p.resolve(IPC_RECONNECTING);
    this.#pending.clear();
  }

  #scheduleReconnect(): void {
    // Single-flight: a timer already armed, or an attempt in progress, must not stack another.
    if (this.#closedByUs || this.#reconnectTimer || this.#reconnecting) return;
    const delay = Math.min(
      RECONNECT_BASE_DELAY_MS * 2 ** this.#reconnectAttempt,
      RECONNECT_MAX_DELAY_MS,
    );
    this.#reconnectAttempt++;
    this.#reconnectTimer = setTimeout(() => {
      this.#reconnectTimer = null;
      void this.#attemptReconnect();
    }, delay);
    this.#reconnectTimer.unref?.();
  }

  async #attemptReconnect(): Promise<void> {
    if (this.#closedByUs || this.#reconnecting) return;
    this.#reconnecting = true;
    try {
      const socket = await this.#openSocket();
      this.#socket = socket;
      this.#buffer = "";
      this.#attach(socket);
      this.#connected = true;
      this.#everConnected = true;

      // Invariant 1: restore the SESSION before releasing any caller. Both replayed frames are
      // idempotent, so replaying them is safe in a way replaying cello_send would not be.
      await this.#replayHandshake();

      this.#reconnectAttempt = 0;
      process.stderr.write("cello-mcp: reconnected to the CELLO daemon\n");
      // Announce BEFORE releasing waiters so the operator's agent learns the daemon is back before
      // the first unblocked call returns. A throwing handler must not abort the reconnect — the
      // connection is already good, and losing it over a failed announcement would be a strictly
      // worse outcome than a missing doorbell.
      try {
        this.#reconnectHandler?.();
      } catch { /* announcement is best-effort; the reconnect itself has already succeeded */ }
      this.#releaseWaiters();
    } catch {
      this.#connected = false;
      this.#reconnecting = false;
      this.#scheduleReconnect();
      return;
    }
    this.#reconnecting = false;
  }

  #openSocket(): Promise<Socket> {
    return new Promise<Socket>((resolve, reject) => {
      const socket = createConnection(this.#socketPath);
      const onError = (err: Error) => {
        socket.destroy();
        reject(err);
      };
      socket.once("error", onError);
      socket.once("connect", () => {
        socket.removeListener("error", onError);
        resolve(socket);
      });
    });
  }

  async #replayHandshake(): Promise<void> {
    // Bounded: a daemon that accepts the socket but never answers must not wedge the reconnect
    // loop forever. Only these two frames get a timeout — see #rawCall.
    if (this.#clientType) {
      await this.#rawCall("ipc.connect", { clientType: this.#clientType }, HANDSHAKE_TIMEOUT_MS);
    }
    if (this.#currentAgent) {
      // THE REPLAY'S ANSWER IS LOAD-BEARING — it used to be discarded.
      //
      // Observed live 2026-08-01: a session was told "the daemon is back and you are acting as
      // Miss_Chelly" while the daemon held no current agent for that connection at all
      // (`cello_stop_using_agent` → released: null; `cello_agents` → selected:false, attendance:0).
      // The replay had been REFUSED and nobody looked. `#currentAgent` is otherwise only cleared on
      // an explicit de-selection, so the cache went on asserting an agent the daemon never
      // attached — and `onReconnect` builds its announcement from that cache, so the claim was
      // manufactured by the very component whose call had just failed.
      //
      // It fires precisely when it hurts: a daemon that has just restarted may not have the agent
      // online yet, and cello_use_agent does NOT auto-start on this path (deliberately — a reconnect
      // must never silently re-arm an agent the operator stopped).
      //
      // `agent_already_current` is SUCCESS: it means this connection already holds it. Anything
      // else means the daemon did not give it back, so the cache must stop claiming it — a stale
      // mirror is worse than an empty one, because the operator reads the mirror.
      // `trigger` is diagnostic, not behavioural — the daemon logs it and changes nothing on it.
      // DOD-AGENT-SELECTION-UNWARRANTED-1: a connection changed identity twice and neither switch
      // could be attributed, because an operator's explicit cello_use_agent and this replay reach
      // the same handler byte-identical. The daemon could log the name but never who asked.
      const wanted = this.#currentAgent;
      const replayed = (await this.#rawCall(
        "cello_use_agent",
        { name: wanted, trigger: "replay" },
        HANDSHAKE_TIMEOUT_MS,
      )) as { ok?: boolean; reason?: string } | null;
      const restored = replayed !== null
        && (replayed.ok === true || replayed.reason === "agent_already_current");
      if (!restored) {
        this.#currentAgent = null;
        // Dropping the cache here is CORRECT (R1) — a stale mirror is worse than an empty one. But
        // it used to happen without a word anywhere, and that silence IS the "my selection just
        // vanished" report: tools start answering no_current_agent and nothing says why. Name the
        // agent and the daemon's own reason, so the operator can re-select instead of debugging.
        const why = replayed === null ? "no response" : (replayed.reason ?? "refused");
        process.stderr.write(
          `cello-mcp: the daemon did not restore agent '${wanted}' after reconnect (${why}) — ` +
          `this connection is now attending nothing. Call cello_use_agent to select again.\n`,
        );
      }
    }
  }

  #releaseWaiters(): void {
    const waiters = this.#connectWaiters;
    this.#connectWaiters = [];
    for (const w of waiters) w();
  }

  /** Wait (bounded) for a reconnect to complete. Resolves true if connected. */
  #waitForConnection(): Promise<boolean> {
    if (this.#connected) return Promise.resolve(true);
    return new Promise<boolean>((resolve) => {
      const timer = setTimeout(() => {
        this.#connectWaiters = this.#connectWaiters.filter((w) => w !== waiter);
        resolve(false);
      }, RECONNECT_WAIT_MS);
      timer.unref?.();
      const waiter = () => {
        clearTimeout(timer);
        resolve(true);
      };
      this.#connectWaiters.push(waiter);
    });
  }

  /**
   * Send an IPC request and await the response.
   * Returns the result directly if successful, or an error object with reason/guidance.
   */
  async call(method: string, params?: Record<string, unknown>): Promise<unknown> {
    if (!method || typeof method !== "string") {
      return { ok: false, reason: "invalid_method", guidance: "IPC method name must be a non-empty string." };
    }
    if (this.#closedByUs) return IPC_CONNECTION_LOST;

    if (!this.#connected) {
      const ok = await this.#waitForConnection();
      if (!ok) return IPC_RECONNECTING;
    }

    const result = await this.#rawCall(method, params);

    // Remember the selected agent so a reconnect can restore routing. Both `ok:true` and
    // `agent_already_current` mean the daemon considers this agent current for the connection.
    if (method === "cello_use_agent" && params && typeof params["name"] === "string") {
      const r = result as { ok?: boolean; reason?: string } | null;
      if (r && (r.ok === true || r.reason === "agent_already_current")) {
        this.#currentAgent = params["name"] as string;
      }
    }

    // EVERY DE-SELECTION MUST CLEAR THE CACHE, or #replayHandshake silently undoes it.
    //
    // The cache had a set path and no clear path, and #replayHandshake replays `cello_use_agent`
    // after every reconnect — a handler that AUTO-STARTS the agent. So:
    //
    //   • release to go away → socket drops (daemon restart, `cello logout/login`, /mcp reconnect)
    //     → the shim re-attends → isAttended() is true again → the away message stops firing, with
    //     nothing in any log saying the release was reverted. The bug this tool exists to fix, back
    //     on a timer.
    //   • take an agent offline → reconnect → replay AUTO-STARTS it. An agent the operator
    //     deliberately took offline comes back online and reachable, silently. That is
    //     kill-switch-adjacent, and it contradicted parity-commands.ts's own claim that "the MCP
    //     surface never does this". Pre-existing; found by the same review, fixed here with it.
    const cleared = result as { ok?: boolean } | null;
    if (cleared?.ok === true) {
      if (method === "cello_stop_using_agent") {
        this.#currentAgent = null;
      } else if (method === "cello_set_agent_offline" && params?.["name"] === this.#currentAgent) {
        // Wire name — the TOOL is cello_set_agent_offline (see agent-handlers.ts on why they differ).
        this.#currentAgent = null;
      }
    }
    return result;
  }

  /**
   * Write a frame on the current socket without the connected-gate (used by the handshake replay).
   *
   * `timeoutMs` is OPTIONAL and only the handshake supplies it. Ordinary calls must NEVER be
   * capped client-side: `cello_receive` legitimately blocks server-side for `timeout_ms` (30s by
   * default, and callers may pass more). A blanket timeout here would silently break blocking
   * receive — the doorbell's own pull path.
   */
  #rawCall(method: string, params?: Record<string, unknown>, timeoutMs?: number): Promise<unknown> {
    const id = String(this.#nextId++);
    return new Promise<unknown>((resolve) => {
      const timer =
        timeoutMs === undefined
          ? null
          : setTimeout(() => {
              this.#pending.delete(id);
              resolve(IPC_RECONNECTING);
            }, timeoutMs);
      timer?.unref?.();
      const done = (v: unknown) => {
        if (timer) clearTimeout(timer);
        resolve(v);
      };

      this.#pending.set(id, { resolve: done, reject: () => done(IPC_RECONNECTING) });

      const frame = JSON.stringify({ id, method, params }) + "\n";
      try {
        this.#socket!.write(frame);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        process.stderr.write(`cello-mcp: IPC write failed: ${msg}\n`);
        this.#pending.delete(id);
        done(IPC_RECONNECTING);
      }
    });
  }

  close(): void {
    this.#closedByUs = true;
    this.#connected = false;
    if (this.#reconnectTimer) {
      clearTimeout(this.#reconnectTimer);
      this.#reconnectTimer = null;
    }
    this.#releaseWaiters();
    if (this.#socket) {
      this.#socket.end();
      this.#socket = null;
    }
  }

  /** True only after an explicit close(). A dropped daemon is recoverable, not dead. */
  get isDead(): boolean {
    return this.#closedByUs;
  }

  #processBuffer(): void {
    let newlineIdx: number;
    while ((newlineIdx = this.#buffer.indexOf("\n")) !== -1) {
      const line = this.#buffer.slice(0, newlineIdx);
      this.#buffer = this.#buffer.slice(newlineIdx + 1);
      if (line.trim().length === 0) continue;

      let frame: Record<string, unknown>;
      try {
        frame = JSON.parse(line) as Record<string, unknown>;
      } catch {
        // Malformed JSON — resolve the oldest pending request with deserialization error.
        // In production the daemon never sends malformed frames; this handles transient
        // corruption or version mismatch. We resolve the oldest pending because responses
        // arrive in order for the single-socket serial protocol.
        process.stderr.write(`cello-mcp: received malformed IPC frame (${line.length} bytes)\n`);
        const oldestEntry = this.#pending.entries().next();
        if (!oldestEntry.done) {
          const [oldestId, resolver] = oldestEntry.value;
          this.#pending.delete(oldestId);
          resolver.resolve(IPC_DESERIALIZATION_ERROR);
        }
        continue;
      }

      // Check for notification frames (server-initiated, no id). This branch runs BEFORE response
      // correlation and never touches #pending — a notification must never be mistaken for a
      // response nor consume a pending request (CELLO-M8C-WAKE-001, falsify-first).
      if ("notification" in frame) {
        try {
          this.#notificationHandler?.(frame);
        } catch (err: unknown) {
          // A throwing handler must not kill the read loop — subsequent responses/notifications
          // must still be processed. The shim's bridge does its own C5 error-fidelity logging;
          // this is the last-resort guard for the proxy's own read loop.
          const msg = err instanceof Error ? err.message : String(err);
          process.stderr.write(`cello-mcp: notification handler threw: ${msg}\n`);
        }
        continue;
      }

      // Regular response — correlate by id
      const responseId = frame.id as string;
      const pending = this.#pending.get(responseId);
      if (pending) {
        this.#pending.delete(responseId);
        if ("error" in frame) {
          const err = frame.error as { code: string; message: string; guidance: string };
          pending.resolve({
            ok: false,
            reason: err.code,
            message: err.message,
            guidance: err.guidance,
          });
        } else {
          pending.resolve(frame.result);
        }
      } else if (responseId) {
        process.stderr.write(`cello-mcp: orphaned IPC response for id=${responseId} (no pending request)\n`);
      }
    }
  }
}
