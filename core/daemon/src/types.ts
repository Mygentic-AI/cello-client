/**
 * CELLO Daemon IPC Types
 *
 * IPC framing: JSON-newline-delimited over Unix domain socket.
 * Requests: {id, method, params}
 * Responses: {id, result} or {id, error: {code, message, guidance}}
 */

import type {
  IManifestProvider,
  IManifestVersionStore,
  IManifestPollScheduler,
  IDirectoryChallengeVerifier,
  ConnectResult,
  IAutoNatService,
} from "@cello-protocol/transport";
import type { TransportDialer, SessionNegotiator } from "./transport-selector.js";
import type { SecurityGatewayClient } from "@cello-protocol/gateway";

// Re-export the TYPE for daemon consumers (the composition root supplies the impl). The always-allow
// implementation is NOT re-exported here — it lives at `@cello-protocol/daemon/testing`, so a
// production file cannot reach it by ordinary import (DOD-M9B-WIRE-1, INV-9).
export type { SecurityGatewayClient };

// Re-export manifest interfaces for consumers of the daemon package
export type {
  IManifestProvider,
  IManifestVersionStore,
  IManifestPollScheduler,
  IDirectoryChallengeVerifier,
};

// Type-only import (erased at runtime — no circular dependency at load time).
import type { DirectoryEndpoint } from "./signaling-connect.js";
import type { TelegramBotClient } from "./telegram-bot-client.js";

// --- Logger interface (injected, never imported directly) ---

export interface Logger {
  debug(event: string, context: Record<string, unknown>): void;
  info(event: string, context: Record<string, unknown>): void;
  warn(event: string, context: Record<string, unknown>): void;
  error(event: string, context: Record<string, unknown>): void;
}

// --- Lock file ---

export interface LockFileContent {
  pid: number;
  socketPath: string;
  version: string;
}

// --- IPC protocol ---

export interface IpcRequest {
  id: string;
  method: string;
  params?: Record<string, unknown>;
}

export interface IpcResponseOk {
  id: string;
  result: unknown;
}

export interface IpcResponseError {
  id: string;
  error: {
    code: string;
    message: string;
    guidance: string;
  };
}

export type IpcResponse = IpcResponseOk | IpcResponseError;

// Notifications are server-initiated frames that don't correlate to a request.
// They use a distinct shape so clients never confuse them with responses.
export interface IpcNotification {
  notification: string;
  data?: Record<string, unknown>;
}

export type IpcFrame = IpcResponse | IpcNotification;

// --- Session node sentinel ---

/**
 * Sentinel agentName used for the standing receiver node before any agent
 * transitions to Online. The IPC socket opens after initialize() completes,
 * so no agent can call cello_start_agent before the standing receiver exists.
 */
export const STANDING_RECEIVER_AGENT_NAME = "__standing_receiver__" as const;

// --- Agent state ---

/**
 * What an agent can actually do right now — a strict ladder, worst fact first.
 *
 * Every value is a fact about THIS AGENT. Nothing system-wide is smuggled in: a consortium that is
 * short of threshold affects every agent equally, so it was never a property of an agent and lives
 * on the daemon-level `directory` block instead. (Andre, 2026-08-09 — `isolated` was proposed for
 * this enum and rejected on exactly that ground.)
 *
 *   load_failed  — the identity would not load. Bad key file or database; nothing else will work.
 *   unregistered — created on this machine, never registered with the directory. Nobody can reach
 *                  it. Determined by whether the DKG left a FROST share, which is registration's
 *                  durable product — not by a flag anyone could forget to set.
 *   stopped      — registered, not running in this daemon.
 *   paused       — deliberately taken offline by the operator. This is the kill switch WORKING;
 *                  it is not a failure and must never read as one.
 *   connecting   — started, directory signaling not up yet. Normal for a minute after registering.
 *   unattended   — fully ready to receive, and NOBODY IS HOME to answer. Callers get the away
 *                  message. Its own rung because this state was invisible and load-bearing: the
 *                  witness stall happened precisely because BOTH sides were unattended, both away
 *                  responders fired, and the away flow ends a session — so two agents sealed a
 *                  conversation nobody had.
 *   online       — ready AND at least one connection attending. The final good state.
 *
 * REPLACES `"registered" | "online" | "current" | "load_failed"`, which collapsed five distinct
 * conditions into "online" and carried `current` as a state — selection is a per-connection concept
 * and already has its own `selected` boolean, so a state value for it was two sources of truth.
 */
export type AgentState =
  | "load_failed"
  | "unregistered"
  | "stopped"
  | "paused"
  | "connecting"
  | "unattended"
  | "online";

export interface AgentInfo {
  name: string;
  state: AgentState;
  pubkey?: string;
  error?: string;
  /**
   * Whether THIS agent currently has an armed standing receiver. Populated on the
   * cello_status surface (getStatus) so a deaf agent — online but unable to accept inbound
   * sessions — is visible per-agent, not hidden behind the daemon-level ANY-agent aggregate.
   */
  standing_receiver_ready?: boolean;
  /**
   * DOD-M12B-RESERVATION-RETRY-1: whether a NAT'd peer can actually DIAL this agent.
   * `standing_receiver_ready` only says a receiver EXISTS — it is true for a plain TCP node no relay
   * would give a circuit reservation to, which behind NAT is reachable by nobody. That difference
   * was visible only in the log, where it appeared 481 times and nobody acted.
   */
  standing_receiver_reachability?: "reserved" | "retrying" | "unreachable" | "absent";
  /**
   * Whether THIS agent is the current (selected) agent for the requesting connection. Kept SEPARATE
   * from `state` — `state` must not overload the value "current", or two equally healthy agents read
   * as different readiness levels. A selected agent reads `state: "online"` + `selected: true`.
   */
  selected?: boolean;
  /**
   * DOD-COATTEND-VISIBLE-1: how many live connections attend this agent right now, including the
   * requesting one. Several sessions on one agent is legitimate (co-attendance, spec §3) but was
   * completely invisible, so an operator whose messages were being taken by another window had no
   * way to see why. Live, not cumulative — it falls when a session disconnects.
   */
  attendance?: number;
}

// --- Connection state ---

export type ConnectionStatus = "verified" | "stale" | "gone" | "unverified";

export interface ConnectionInfo {
  counterpartyPubkey: string;
  status: ConnectionStatus;
}

// --- Status response ---

export type DirectorySignalingState = "connected" | "reconnecting" | "lost";

export interface DaemonStatusResponse {
  daemon: "running";
  directory_signaling: DirectorySignalingState;
  agents: AgentInfo[];
  // No `connections` field: an always-empty placeholder conveys nothing and reads as a mock. The
  // ConnectionInfo type stays exported as the shape connected-client visibility will populate;
  // per-connection state lives in perConnectionState.
  /**
   * True when the standing receiver node is listening and ready to accept the
   * next inbound session. Set to true by SessionNodeManager.initialize() during
   * daemon startup, before the IPC socket opens.
   */
  standing_receiver_ready: boolean;
  /**
   * Total count of retry_queue entries across all sessions.
   * Always present as integer >= 0.
   */
  retryQueueDepth: number;
  /**
   * Interrupted sessions from SQLite.
   * Always present (empty array if none). Never undefined or omitted.
   */
  interrupted_sessions: InterruptedSessionInfo[];
  /**
   * ACTIVE sessions with their direct-path counterparty liveness, so a
   * counterparty-gone session is visible to the operator instead of looking identical
   * to a quiet-but-healthy one. Always present (empty array if none).
   */
  active_sessions: ActiveSessionInfo[];
}


/**
 * DOD-M12B-SEAL-STUCK-1 — whether a session can be sealed, as an operator surface.
 *
 * THREE STATES, because there are three answers and collapsing them is how this milestone's
 * defects keep happening.
 *
 * `blocked` carries the two numbers separately, and they are NOT interchangeable:
 *   - `heldBehindGap` — messages this side RECEIVED and verified, waiting for an earlier position.
 *     Durable since DOD-M12B-STRAND-1, so this half survives a restart.
 *   - `awaitingArrival` — positions the relay witnessed for which nothing has arrived at all.
 *     Memory-only, so this half does NOT survive a restart, which is why `unknown` exists.
 *   - `oldestHeldMs` separates "stuck since this morning" from "in flight 40 ms ago". Without it a
 *     healthy mid-conversation window — the relay witnesses a counterparty leaf a moment before the
 *     content arrives — reads exactly like a permanently stranded session, and a warning on
 *     everything is a warning on nothing.
 *
 * `unknown` is NOT a soft `ready`. It is returned when this process cannot answer: the witness
 * state that would show a never-arrived position is memory-only, so for a session that carries
 * leaves from before this daemon started, "no gap recorded" means "not recorded", not "no gap".
 * Reporting `ready` there would invite a close, and a short chain gets `leaf_count_mismatch` back —
 * which is terminal, and the notarized receipt is gone for good.
 *
 * A `blocked` answer can still clear on its own: the close path drains parked relay content and
 * re-checks before it refuses, which this read does not do. So this surface answers "right now",
 * and a close may succeed against a session shown here as blocked.
 */
export type SealReadinessView =
  | { state: "ready" }
  | { state: "blocked"; awaitingArrival: number; heldBehindGap: number; oldestHeldMs: number | null }
  | { state: "unknown"; reason: string };

/** One active session's status row (see DaemonStatusResponse.active_sessions). */
export interface ActiveSessionInfo {
  sessionId: string;
  agentName: string;
  counterpartyPubkey: string;
  /** Direct-path counterparty liveness; 'unknown' before any session-node observation.
   *  DOD-M12B-ACK-1: 'impaired' means the connection is up and our writes on it are failing —
   *  distinct from 'gone' (the connection dropped), which is what cello_receive turns into "call
   *  cello_close_session". It is daemon-local and is NOT the relay's SessionLiveness wire type. */
  liveness: "alive" | "impaired" | "gone" | "unknown";
  /** DOD-SESSION-NAME-1: this agent's own label for the session; null when unnamed. */
  sessionName: string | null;
  /**
   * DOD-M12B-SEAL-STUCK-1 — whether this session can be sealed. See SealReadinessView.
   *
   * A chain with a gap cannot be co-signed, so the close refuses — correctly. But until this field
   * existed the condition was only discoverable by ATTEMPTING a close on each session and reading
   * the refusal, so 25 unsealable sessions accumulated on one daemon with every surface calling
   * them ordinary active sessions, while each held a slot against the per-sender cap.
   */
  sealReadiness: SealReadinessView;
  /** DOD-FRONTIER-STRAND-1 AC3 — see SessionListEntry.frontierMismatch. Declared here because
   *  buildInterruptedSessions returns THIS type; it typechecked only because TS exempts spread
   *  properties from excess-property checking, so a renderer typed as this could not read it. */
  frontierMismatch?: SessionListEntry["frontierMismatch"];
}

// --- Daemon configuration ---

export interface DaemonConfig {
  celloDir: string;
  socketPath: string;
  lockFilePath: string;
  maxConnections: number;
  version: string;
  logger: Logger;
  /**
   * Manifest loading and verification.
   * When provided, startDaemon() calls manifestProvider.loadAndVerify() at startup.
   * When absent, manifest loading is skipped.
   *
   * Production: requires manifestRootKeys (non-empty array) and manifestThreshold (>= 1).
   * The bundled consortium-manifest.json is NOT shipped in the npm package — operators
   * must supply their own manifest path via FileManifestProvider(path).
   */
  manifestProvider?: IManifestProvider;
  /**
   * Officer root keys for manifest signature verification.
   * Required when manifestProvider is provided.
   */
  manifestRootKeys?: readonly string[];
  /**
   * Officer threshold for manifest signature verification.
   * Required when manifestProvider is provided.
   */
  manifestThreshold?: number;
  /**
   * Version store for monotonicity enforcement.
   * When absent, monotonicity check is skipped.
   */
  manifestVersionStore?: IManifestVersionStore;
  /**
   * Poll scheduler for background manifest refresh.
   * When absent, polling is disabled.
   */
  manifestPollScheduler?: IManifestPollScheduler;
  /**
   * Base URL for the daemon-level HTTP manifest poll (`${directoryHttpUrl}/manifest`). The poll runs
   * over unauthenticated HTTP, NOT the keystone signaling stream, so it keeps running with zero
   * agents. Defaults to resolveDirectoryUrl(process.env). Tests inject an in-process server URL.
   */
  directoryHttpUrl?: string;
  /**
   * Challenge verifier for directory step-5 identity proof.
   * When absent, directory challenge verification is skipped.
   */
  challengeVerifier?: IDirectoryChallengeVerifier;
  /**
   * Injectable connect function for the directory signaling stream.
   * When absent, a stub that always rejects (directory_signaling_not_configured) is used.
   * Production: performs the full 7-step directory handshake.
   *
   * Tests inject a fake signalingConnect directly. Production leaves this undefined
   * and supplies directoryEndpointResolver instead (see below), so startDaemon can
   * build the real connect wired to its own loaded-agent identity.
   */
  signalingConnect?: () => Promise<ConnectResult>;
  /**
   * Resolves the directory endpoint to dial (GET /bootstrap).
   * When signalingConnect is absent and this is present, startDaemon builds the
   * production signalingConnect from this resolver + the daemon's primary agent
   * identity. Ignored when signalingConnect is provided directly.
   */
  directoryEndpointResolver?: () => Promise<DirectoryEndpoint | null>;
  /**
   * Injectable session-node factory for the composition root.
   * When absent, the production factory (real libp2p via createNode) is used.
   * Tests inject a controllable factory to exercise the send/receive/tree path
   * without the real transport stack.
   */
  sessionNodeFactory?: import("./session-node-manager.js").ISessionNodeFactory;
  /**
   * Park target for the startup flush of un-acked content. On startup — BEFORE the IPC
   * socket opens — the daemon drains retry_queue entries still awaiting a `persisted`
   * delivery ACK and re-parks each to the relay store-and-forward queue via this function
   * (the crash backstop). The function performs the encrypted relay deposit and is the
   * natural emitter of content.park.deposited (it holds the recipient context).
   *
   * It is supplied by the daemon's OWN send path — the daemon owns the session core, so it
   * constructs the relay-deposit function natively (never a hosted CelloClient /
   * RelayStreamManager). When absent (a daemon started without the content send path, or
   * unit tests), the startup flush is a no-op (content.park.flush.deferred at WARN) and the
   * durable awaiting entries remain queued for the next startup that has a park target.
   */
  contentParkFn?: import("./retry-queue.js").ParkFn;
  /**
   * The TTF (time-to-flush) window, in ms, the sender waits for a `persisted` delivery ACK
   * before handing un-acked content to the park backstop. Default 20_000. Tests inject a
   * small value to drive TTF expiry deterministically.
   */
  contentTtfMs?: number;
  /**
   * DOD-M12B-RESTART-SEAL-1: how long after boot the restart-seal resolver waits before its first
   * attempt, in ms. Default 30_000 — a seal is a directory ceremony and signaling is still being
   * established when boot finishes, so attempting immediately spends an attempt on a connection
   * that does not exist yet. Tests set it small to drive the resolver deterministically.
   */
  restartSealInitialDelayMs?: number;
  /**
   * DOD-M12B-RESTART-SEAL-1: gap between two restart-seal attempts, in ms. Default 5_000 — a seal
   * is a directory ceremony and a machine holding hundreds of orphans must not answer a restart
   * with hundreds of simultaneous ones. Tests set it small so every queued row lands inside the
   * assertion window; without that a scope test passes because of the stagger, not the guard.
   */
  restartSealStaggerMs?: number;
  /**
   * Low-level dialer backing the transport selector in
   * production environments (dev/staging/production). Wraps a CelloNode (direct +
   * relay circuit dial) and the daemon relay registry. Required for production
   * CELLO_ENV; for 'local'/'test' the composition root uses an in-process stub.
   */
  transportDialer?: TransportDialer;
  /**
   * AutoNAT service adapter backing dialability detection
   * in production environments. Wraps the standing-receiver node's libp2p AutoNAT
   * observable. For 'local'/'test' the composition root uses a stub (dialable=false).
   */
  autoNatService?: IAutoNatService;
  /**
   * Directory session negotiation adapter. cello_initiate_session calls negotiate() to
   * obtain the FROST-signed SessionAssignment, then drives the transport selector to dial
   * the counterparty. When absent, cello_initiate_session reports
   * directory_signaling_not_configured — it does NOT crash.
   */
  sessionNegotiator?: SessionNegotiator;
  /**
   * Returns this daemon's relay circuit address (from the relay registry populated at
   * directory connection) for the SessionAssignment advertised address when the standing
   * receiver is NOT dialable. When absent, an empty advertised relay address is used (the
   * negotiator supplies the real one in production).
   */
  getRelayCircuitAddress?: () => string;
  /**
   * Injectable Telegram Bot API client (test override — production uses HttpTelegramBotClient,
   * constructed from telegram_settings once configured via setTelegramSettings). Absent = the
   * Telegram doorbell is inert (no poller starts) until settings exist.
   */
  telegramBotClient?: TelegramBotClient;
  /**
   * The security gateway client. Every outbound message is screened in cello_send before
   * sessionNodeManager.sendContent; every inbound message is screened in the inbound funnel
   * before it enters the receive buffer. The daemon holds ONLY this narrow interface — all
   * detection lives in the separate gateway program.
   *
   * REQUIRED (INV-9, M9B-D10). It was optional, defaulting to `PassthroughGatewayClient`, and
   * because no production caller ever set it, every shipped daemon screened NOTHING while
   * announcing that the gateway was connected. An optional field with a permissive default made
   * the invariant hold by CONVENTION while the comment claimed it held by construction. Now the
   * compiler asks. A caller that genuinely wants no screening — a test — passes
   * `new PassthroughGatewayClient()` and thereby says so out loud.
   */
  securityGateway: SecurityGatewayClient;
  /**
   * Restart the screening sidecar so a stored config change actually applies (M9B-D17). The
   * gateway reads its config only at boot, so without this a confirmed loosening would be recorded
   * and have no effect — the operator told `ok`, the running gateway unchanged. Supplied by the
   * composition root, which owns the sidecar's lifecycle; absent in tests that assert storage only.
   */
  restartSecurityGateway?: (correlationId?: string) => Promise<void>;
  /**
   * Tear down whatever the composition root started alongside the daemon — today the screening
   * sidecar. Called at the END of the daemon's own stop(), so it runs on EVERY exit path, not just
   * the signal handler: `cello logout` goes through the IPC `shutdown` verb, which never reaches
   * the bin's SIGTERM handler.
   */
  onShutdown?: () => Promise<void>;
  /**
   * DOD-LOGOUT-EXIT-1: the daemon has finished stopping and is ready for the process to end.
   * Fired as the LAST act of stop(), after the singleton lock is released, on every path — the
   * bin's SIGTERM handler AND the IPC `shutdown` verb that `cello logout` uses.
   *
   * Why this exists. The two shutdown paths were not symmetric: the signal handler ran
   * `await handle.stop(); process.exit(0)`, while the IPC path started stop(), acknowledged, and
   * never exited — it relied on the event loop draining by itself. But stop() releases the socket,
   * the lock file and the singleton lock, which are exactly the two facts `logout`'s `daemonGone()`
   * consults, so the daemon went HANDLE-FREE WHILE STILL ALIVE: every local check agreed it was
   * gone while it still held an ESTABLISHED connection to a directory node. A kill switch may not
   * lie, and the handles being correctly released is precisely why this one hid.
   *
   * Why a hook and not a `process.exit()` in stop(). daemon.ts is called IN-PROCESS by vitest and by
   * embedders; exiting there would kill the test runner. Only the binary owns the process, so only
   * the binary may end it.
   *
   * Why chasing the stragglers instead was rejected: the set of things that can hold the loop
   * (unawaited libp2p teardown, an in-flight dial with no timeout, the Telegram long-poll whose
   * stop only bumps a generation counter, in-flight registry/manifest fetches) is open-ended, and
   * the next addition would reintroduce the lie silently. Fix them on their own merits; do not make
   * the kill switch depend on having found all of them.
   *
   * Fired at most ONCE per daemon, even if stop() is called again.
   *
   * CARRIES THE OUTCOME, and the caller must act on it. `ok: false` means the teardown threw
   * partway — sessions possibly not marked interrupted, the database possibly not checkpointed.
   * The process must still end (a half-stopped daemon may not keep talking to a directory), but it
   * must not claim it stopped cleanly: the binary exits NON-ZERO on `ok: false`. Exiting 0 for both
   * would reintroduce, one level up, exactly the lie this hook was added to kill.
   *
   * A throw from this hook is NOT swallowed — it propagates out of stop(). This is the only call
   * that ends the process, so a failure here means the kill switch did not fire, and that must be
   * loud enough for `cello logout` to time out and report failure rather than print "Daemon
   * stopped." over a daemon that is still running.
   */
  onStopped?: (outcome: { ok: boolean; error?: Error }) => void | Promise<void>;
  /**
   * DOD-REGISTRY-1: Ed25519 pubkey (hex) for verifying the type registry inner signature.
   * Build-time pinned. When absent, the registry poll is disabled (all types unclassified).
   */
  registryPubkey?: string;
  /**
   * DOD-REGISTRY-1: poll scheduler for background registry refresh.
   * When absent (or registryPubkey absent), registry polling is disabled.
   */
  registryPollScheduler?: import("@cello-protocol/transport").IManifestPollScheduler;
  /**
   * DOD-M15-STALEROSTER-1: scheduler for the background directory-reachability sweep.
   *
   * Injectable for the same reason the two above are — without it, "does the daemon actually START
   * the sweep" is unobservable, and the revert test proved that gap was real: disabling the wiring
   * entirely left the whole suite green while the reading went back to freezing on recovery.
   *
   * When absent the daemon builds its own slow randomized scheduler; the sweep is never off while a
   * manifest provider exists.
   */
  rosterSweepScheduler?: import("@cello-protocol/transport").IManifestPollScheduler;
  /**
   * DOD-M15-STALEROSTER-1: injectable fetch for the directory `/bootstrap` probes.
   *
   * Already threaded through `verifyStartupManifest` and `createConsortiumRouting`; it simply had
   * no way in from the daemon's own config. Without it, "does the background sweep use the PATIENT
   * probe budget" is unobservable at the wiring level — and a wiring-level blind spot is exactly
   * what let the whole sweep be deleted with the suite still green. Defaults to global fetch.
   */
  fetchFn?: typeof fetch;
}

// --- Session node types ---

/**
 * Maximum number of concurrent session nodes per daemon.
 */
export const MAX_SESSION_NODES = 32;

/**
 * Status of a session persisted in SQLite.
 *
 * - active: live session with a transport node.
 * - interrupted: relay/daemon detected the session was cut short; eligible for
 *   the operator-initiated seal-interrupted bilateral flow.
 * - seal_interrupted_pending: both parties have produced and exchanged signed
 *   SEAL-INTERRUPTED leaves (a verified bilateral commitment), but the FROST
 *   threshold notarization has NOT been performed. This is a non-terminal state
 *   — it is explicitly NOT 'sealed'. See daemon.ts handleSealInterruptedFlow for what
 *   blocks the threshold seal.
 * - sealed: a real FROST threshold notarization completed. Only the normal
 *   (non-interrupted) close path produces this today.
 */
export type SessionStatus =
  | "active"
  | "sealed"
  | "interrupted"
  | "seal_interrupted_pending"
  // A locally-terminal state for a half-open session that can never be bilaterally sealed — set by a
  // force-abandon (cello_close_session { force }) or the dead-half-open reaper. No FROST notarization
  // (there is nothing to notarize on a dead handshake); it just leaves the open list.
  | "abandoned";

export interface SessionRecord {
  /**
   * DOD-M15-REFUSED-INBOUND-SILENT-1 — whether this session's content hashes are salted.
   *
   * Deliberately a status field and not an alert: an unsalted session is exactly as verifiable as
   * every session shipped before salting existed, so nothing is wrong and there is nothing to
   * interrupt anyone with. It exists so an operator can tell *unsalted because this build predates
   * the feature* from *unsalted because adoption was refused* — only the second says anything about
   * their setup. Absent on records that did not come from a listing surface.
   */
  content_hashes_salted?: boolean;
  session_id: string;
  /**
   * The STABLE key this row is scoped by. Every `sessions` query joins on this, never on
   * `agent_name`.
   */
  agent_id: string;
  /**
   * DISPLAY ONLY. Joined in from the `agents` table (its single source of truth) — it is NOT a column
   * of `sessions`, precisely so a rename cannot leave a stale copy behind. Never put it in a
   * PRIMARY KEY, a JOIN predicate, or a WHERE-match: a retire FREES the name for reuse, so it does
   * not identify an agent across the retired boundary.
   */
  agent_name: string;
  counterparty_pubkey: string;
  status: SessionStatus;
  created_at: number;
  updated_at: number;
  /** Leaf count at interruption. 0 if not yet set. */
  message_count: number;
  /** ISO 8601 timestamp of interruption. Null if not yet set. */
  interrupted_at: string | null;
  /**
   * The counterparty's FROST primary (group) pubkey hex, from the
   * SessionAssignment's signer_pubkey. The responder verifies the bilateral seal signature against
   * it. Null when this party initiated (it verifies against its own primary).
   */
  counterparty_primary_pubkey?: string | null;
  /**
   * DOD-SESSION-NAME-1: this agent's own human-readable label for the session. Null when unnamed,
   * and unnamed MEANS something (see the column comment in session-node-manager). Local and
   * cosmetic — it reaches no wire structure.
   */
  session_name?: string | null;
}

/** An interrupted session entry in the cello status response. */
export interface InterruptedSessionInfo {
  sessionId: string;
  agentName: string;
  counterpartyPubkey: string;
  messageCount: number;
  interruptedAt: string;
  /** DOD-SESSION-NAME-1: this agent's own label for the session; null when unnamed. */
  sessionName: string | null;
  /**
   * DOD-M12B-SEAL-STUCK-1 — whether this session can be sealed. See SealReadinessView.
   *
   * An interrupted session can seal (that is what seal-interrupted is for), so it can also be
   * BLOCKED from sealing by a gap. `frontierMismatch` beside this reports a different, later
   * condition: the two sides have already exchanged and disagreed. This one is the gap on OUR side,
   * knowable before any exchange, and it is the more common of the two.
   *
   * A PLAIN PROPERTY, not optional — matching the active list. The optional form was built with a
   * spread, which bypasses excess-property checking, and that is exactly how `frontierMismatch`
   * four lines down came to typecheck while no renderer could read it.
   */
  sealReadiness: SealReadinessView;
}

/**
 * cello_sessions: one session in the discovery list for the current agent.
 * Covers every status (active, sealed, interrupted, seal_interrupted_pending) so
 * the by-id reads (cello_transcript / cello_sealed_receipt) have a source for their
 * session ids. Timestamps are ISO 8601; interruptedAt is null unless the session
 * is/was interrupted.
 */
export interface SessionListEntry {
  /**
   * DOD-M15-REFUSED-INBOUND-SILENT-1 — present ONLY when this session's content hashes are NOT
   * salted, so it stays readable rather than becoming a field on every row that everyone skips.
   *
   * Its absence is the healthy, ordinary case. Its presence does not mean anything is wrong — an
   * unsalted session is exactly as verifiable as every session shipped before salting existed — it
   * means the operator can tell *unsalted because this build predates the feature* from *unsalted
   * because adoption was refused*, and only the second says anything about their setup.
   */
  contentHashesSalted?: false;
  sessionId: string;
  agentName: string;
  counterpartyPubkey: string;
  status: SessionStatus;
  /** Operator-facing bucket derived from status + messageCount: open | closed | failed. */
  category: "open" | "closed" | "failed";
  /**
   * DOD-FRONTIER-STRAND-1 AC3: present ONLY when a seal exchange has proved the two sides disagree
   * on how many messages this session holds. Its presence means the session is STRANDED — it cannot
   * co-sign and will never seal — as distinct from an ordinary interrupted session that is merely
   * waiting for both parties to be online. Absent is the healthy case; there is no "false" to read.
   */
  frontierMismatch?: {
    ours: number;
    theirs: number;
    divergingLeafIndex: number;
    observedAt: string;
    guidance: string;
  };

  messageCount: number;
  createdAt: string;
  updatedAt: string;
  interruptedAt: string | null;
  /** The resolved display label (pet name ?? offered ?? fingerprint). */
  who: string;
  whoKnown: boolean;
  /**
   * DOD-SESSION-NAME-1: this agent's own label for the session, or null when unnamed.
   *
   * Returned ALONGSIDE sessionId, never instead of it — the id is what you paste into the next
   * command. Null is a value with meaning: a session that closed cleanly through an agent usually
   * has a name, so an unnamed closed one is a hint it did not.
   */
  sessionName: string | null;
  /**
   * Whether this session's message hashes are salted — `DOD-M15-SEALWIRE-1` bullet 6.
   *
   * `false` is not a fault. It means this conversation hashes the way every build before the salt
   * existed, which is exactly as verifiable; what it loses is that a relay holding the hashes could
   * confirm a guess at a short message in this conversation. The common cause is a counterparty who
   * was offline or on an older build when the session opened, and it is permanent for the session
   * either way — the agreement runs at open, before anything is hashed.
   *
   * ⚠️ REQUIRED, NOT OPTIONAL. An absent field would be indistinguishable from `false`, so an older
   * daemon and an unprotected session would read the same — the exact collapse Decision #15 spends a
   * whole wire discriminator preventing. A security property must never be inferable from a gap.
   */
  contentSalted: boolean;
}

/**
 * Result of a session listing (cello_sessions / the daemon-wide `list_sessions`). `sessions`
 * is already filtered + capped at `limit`; `totalMatched` is how many matched the filter before the
 * cap, so the caller can tell the operator "showing 50 of 312".
 */
export interface SessionListResponse {
  ok: true;
  filter: "open" | "closed" | "failed" | "all";
  limit: number;
  totalMatched: number;
  sessions: SessionListEntry[];
}

// --- Error codes ---

export const ErrorCodes = {
  DAEMON_LOCK_STALE_REMOVED: "daemon_lock_stale_removed",
  DAEMON_SOCKET_BIND_FAILED: "daemon_socket_bind_failed",
  AGENT_LOAD_FAILED: "agent_load_failed",
  IPC_CONNECTION_LIMIT: "ipc_connection_limit",
  CONNECTION_VALIDATION_TIMEOUT: "connection_validation_timeout",
  DIRECTORY_UNREACHABLE_AT_LOGIN: "directory_unreachable_at_login",
  MAX_SESSIONS_REACHED: "max_sessions_reached",
  SESSION_NODE_CREATION_FAILED: "session_node_creation_failed",
  STANDING_RECEIVER_UNAVAILABLE: "standing_receiver_unavailable",
} as const;
