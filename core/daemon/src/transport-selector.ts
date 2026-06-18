/**
 * CELLO Daemon — transport-selector.ts (CELLO-M7-TRANSPORT-001)
 *
 * Direct-P2P-by-default transport selection with relay fallback and a best-effort
 * dcutr hole-punch upgrade.
 *
 * ─── Specification (Phase S) ──────────────────────────────────────────────────
 * Given a FROST-signed SessionAssignment (produced by WIRE-001), choose how to
 * dial the counterparty's session node:
 *   1. Read transport_mode from the assignment. This is the ONLY authority for
 *      the dial strategy (SI-001 / AC-015) — NEVER infer mode from address format.
 *   2. transport_mode === 'direct' → dial counterparty_session_addrs directly.
 *   3. direct dial fails OR transport_mode === 'relay' → dial the relay circuit
 *      address (from the daemon's relay registry, independent of transport_mode —
 *      AC-006).
 *   4. After a relay connection is established → attempt a dcutr hole-punch upgrade
 *      (non-blocking, best-effort). Failure is non-fatal (SI-003).
 *   5. If BOTH direct and relay fail → terminal 'relay_fallback_also_failed' (AC-008).
 *
 * Error code registry (fixed strings — also in CONTEXT.md):
 *   'autonat_unavailable'                       — internal; no probers reachable.
 *   'direct_dial_failed_falling_back_to_relay'  — WARN; intermediate, non-fatal.
 *   'relay_fallback_also_failed'                — terminal session failure.
 *   'dcutr_upgrade_failed'                      — DEBUG; non-fatal.
 *
 * ─── Pseudocode (Phase P) ─────────────────────────────────────────────────────
 * dial(assignment, { correlationId }):
 *   mode = assignment.transport_mode            // authoritative
 *   sessionId = hex(assignment.session_id)
 *   peerId = assignment.counterparty_session_peer_id
 *   directAddrs = assignment.counterparty_session_addrs ?? []
 *   if mode === 'direct':
 *     try { dialer.dialDirect(peerId, directAddrs); log mode.selected('direct'); return {ok, 'direct'} }
 *     catch e { log direct_dial.failed(WARN, e.message) }   // fall through
 *   try { dialer.dialRelay(dialer.relayCircuitAddr(assignment), peerId) }
 *   catch { return {ok:false, 'relay_fallback_also_failed', guidance} }   // NO mode.selected
 *   log mode.selected('relay')
 *   dcutrSettled = (async () => {
 *     try { dialer.attemptDcutr(peerId); log dcutr.upgraded(INFO); return true }
 *     catch e { log dcutr.failed(DEBUG, e.message); return false } })()
 *   return {ok:true, 'relay', dcutrSettled}             // dial does NOT await dcutr
 */

import type { SessionAssignment } from "@cello-protocol/protocol-types";
import type { Logger } from "./types.js";
import type { Dialability } from "@cello-protocol/transport";

// ─── Error codes (fixed) ──────────────────────────────────────────────────────

export const TRANSPORT_ERROR = {
  /** Internal: AutoNAT could not run because no directory-node probers are reachable. */
  AUTONAT_UNAVAILABLE: "autonat_unavailable",
  /** WARN-level intermediate, non-fatal: direct dial failed, relay fallback initiated. */
  DIRECT_DIAL_FAILED_FALLING_BACK: "direct_dial_failed_falling_back_to_relay",
  /** Terminal: both direct dial and relay fallback failed. */
  RELAY_FALLBACK_ALSO_FAILED: "relay_fallback_also_failed",
  /** DEBUG-level non-fatal: dcutr hole-punch upgrade attempt failed. */
  DCUTR_UPGRADE_FAILED: "dcutr_upgrade_failed",
} as const;

const RELAY_FALLBACK_GUIDANCE =
  "Both direct P2P connection and relay fallback failed. The counterparty may be " +
  "offline or unreachable from any path. Try again later, or check network connectivity.";

/** Default direct-dial timeout (ms). Not a user-facing option (implementation_notes). */
export const DEFAULT_DIRECT_DIAL_TIMEOUT_MS = 5000;

// ─── TransportResult ──────────────────────────────────────────────────────────

/**
 * The outcome of a transport selection. Discriminated by `ok` so the failure
 * branch is exactly the `{ ok:false, reason, guidance }` shape the MCP layer
 * surfaces to the caller (AC-008).
 *
 * For the relay branch, `dcutrSettled` resolves when the background dcutr attempt
 * settles — `true` if the connection was hole-punch upgraded to direct, `false`
 * otherwise. dial() does NOT await it: the session is usable immediately upon the
 * relay connection (AC-007). Production callers may ignore `dcutrSettled`.
 */
export type TransportResult =
  | { ok: true; mode: "direct" }
  | { ok: true; mode: "relay"; dcutrSettled: Promise<boolean> }
  | {
      ok: false;
      reason: typeof TRANSPORT_ERROR.RELAY_FALLBACK_ALSO_FAILED;
      guidance: string;
    };

export interface TransportDialOptions {
  /** Correlation ID threaded through every event for this session flow. */
  correlationId: string;
}

// ─── ITransportSelector ───────────────────────────────────────────────────────

/**
 * Adapter interface for choosing and performing the transport dial.
 * Real implementation: TransportSelector (drives a TransportDialer + Logger).
 * Stub: LocalTransportSelectorStub (returns configurable canned results — used by
 * the composition root when CELLO_ENV is 'local'|'test').
 */
export interface ITransportSelector {
  dial(assignment: SessionAssignment, opts: TransportDialOptions): Promise<TransportResult>;
}

// ─── SessionNegotiator (the WIRE-001/SIGNAL-001 seam) ─────────────────────────

/**
 * The advertised address this daemon offers to the directory for a new session,
 * derived from the standing receiver's AutoNAT dialability (AC-004 / AC-019):
 * a direct multiaddr when dialable, the relay circuit address otherwise.
 */
export interface SessionNegotiationContext {
  agentName: string;
  correlationId: string;
  advertisedAddress: AdvertisedAddress;
  params: Record<string, unknown>;
}

/**
 * Outcome of directory session negotiation. On success it carries the
 * FROST-signed SessionAssignment (transport_mode + counterparty_session_addrs)
 * that the TransportSelector then consumes.
 */
export type SessionNegotiationResult =
  | { ok: true; assignment: SessionAssignment }
  | { ok: false; reason: string; guidance: string };

/**
 * Adapter that performs directory session negotiation and returns the
 * FROST-signed SessionAssignment. The real implementation is owned by
 * WIRE-001/SIGNAL-001 (directory signaling); it is injected into the daemon
 * composition root. When absent, cello_initiate_session reports
 * directory_signaling_not_configured (it does NOT crash — the transport adapters
 * are still wired). This is the seam that lets cello_initiate_session drive the
 * transport selector once an assignment exists (AC-010(c)).
 */
export interface SessionNegotiator {
  negotiate(ctx: SessionNegotiationContext): Promise<SessionNegotiationResult>;
}

// ─── TransportDialer ──────────────────────────────────────────────────────────

/**
 * The low-level dial operations the selector composes. The real implementation
 * wraps a CelloNode (direct dial + relay circuit dial) plus the daemon's relay
 * registry. Each operation throws on failure; the selector catches and routes.
 */
export interface TransportDialer {
  /** Dial the counterparty directly. Throws on timeout/refused/unreachable. */
  dialDirect(peerId: string | undefined, addrs: string[], timeoutMs: number): Promise<void>;
  /** Dial the counterparty via the relay circuit address. Throws on failure. */
  dialRelay(relayCircuitAddr: string, peerId: string | undefined): Promise<void>;
  /**
   * The relay circuit address for this assignment. Sourced from the daemon's relay
   * registry (populated during directory connection) — NOT parsed from the
   * assignment's address fields, and available regardless of transport_mode (AC-006).
   */
  relayCircuitAddr(assignment: SessionAssignment): string;
  /** Attempt a dcutr hole-punch upgrade. Throws on failure (non-fatal — SI-003). */
  attemptDcutr(peerId: string | undefined): Promise<void>;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function sessionIdHex(assignment: SessionAssignment): string {
  return Buffer.from(assignment.session_id).toString("hex");
}

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

// ─── TransportSelector (real) ─────────────────────────────────────────────────

export class TransportSelector implements ITransportSelector {
  readonly #dialer: TransportDialer;
  readonly #logger: Logger;
  readonly #directDialTimeoutMs: number;

  constructor(opts: {
    dialer: TransportDialer;
    logger: Logger;
    directDialTimeoutMs?: number;
  }) {
    this.#dialer = opts.dialer;
    this.#logger = opts.logger;
    this.#directDialTimeoutMs = opts.directDialTimeoutMs ?? DEFAULT_DIRECT_DIAL_TIMEOUT_MS;
  }

  async dial(
    assignment: SessionAssignment,
    opts: TransportDialOptions,
  ): Promise<TransportResult> {
    const sessionId = sessionIdHex(assignment);
    const { correlationId } = opts;
    const peerId = assignment.counterparty_session_peer_id;
    const directAddrs = assignment.counterparty_session_addrs ?? [];
    // transport_mode is the ONLY authority (SI-001 / AC-015). Never inferred.
    const mode = assignment.transport_mode;

    // Step 1: direct dial when transport_mode === 'direct'.
    if (mode === "direct") {
      try {
        await this.#dialer.dialDirect(peerId, directAddrs, this.#directDialTimeoutMs);
        this.#logger.info("session.transport.mode.selected", {
          sessionId,
          mode: "direct",
          correlationId,
        });
        return { ok: true, mode: "direct" };
      } catch (err) {
        // Recoverable: log WARN and fall through to relay fallback (AC-006).
        // failureReason is the actual error message — never ${error}.
        this.#logger.warn("session.transport.direct_dial.failed", {
          sessionId,
          counterpartyPeerId: peerId,
          failureReason: errMessage(err),
          reason: TRANSPORT_ERROR.DIRECT_DIAL_FAILED_FALLING_BACK,
          correlationId,
        });
      }
    }

    // Step 2: relay fallback (transport_mode === 'relay', or direct dial failed).
    try {
      const relayAddr = this.#dialer.relayCircuitAddr(assignment);
      await this.#dialer.dialRelay(relayAddr, peerId);
    } catch (err) {
      // Terminal: both direct and relay failed. session.transport.mode.selected is
      // NOT logged (no mode was selected — AC-008). We DO log the underlying relay
      // failure reason at WARN so the on-call engineer can diagnose why the
      // fallback failed (never swallow the exception silently).
      this.#logger.warn("session.transport.relay_fallback.failed", {
        sessionId,
        counterpartyPeerId: peerId,
        failureReason: errMessage(err),
        reason: TRANSPORT_ERROR.RELAY_FALLBACK_ALSO_FAILED,
        correlationId,
      });
      return {
        ok: false,
        reason: TRANSPORT_ERROR.RELAY_FALLBACK_ALSO_FAILED,
        guidance: RELAY_FALLBACK_GUIDANCE,
      };
    }

    this.#logger.info("session.transport.mode.selected", {
      sessionId,
      mode: "relay",
      correlationId,
    });

    // Step 3: best-effort dcutr upgrade — non-blocking. The session is usable
    // immediately upon relay connection (AC-007); dcutr runs in the background.
    const dcutrSettled = this.#attemptDcutr(peerId, sessionId, correlationId);

    return { ok: true, mode: "relay", dcutrSettled };
  }

  async #attemptDcutr(
    peerId: string | undefined,
    sessionId: string,
    correlationId: string,
  ): Promise<boolean> {
    try {
      await this.#dialer.attemptDcutr(peerId);
      this.#logger.info("session.transport.dcutr.upgraded", { sessionId, correlationId });
      return true;
    } catch (err) {
      // Non-fatal (SI-003). DEBUG because dcutr failure is expected in many
      // network topologies. failureReason is error.message — never ${error}.
      this.#logger.debug("session.transport.dcutr.failed", {
        sessionId,
        failureReason: errMessage(err),
        reason: TRANSPORT_ERROR.DCUTR_UPGRADE_FAILED,
        correlationId,
      });
      return false;
    }
  }
}

// ─── LocalTransportSelectorStub ───────────────────────────────────────────────

/**
 * In-process transport selector stub. Returns a configurable canned result with
 * no network access. Selected by the composition root when CELLO_ENV is
 * 'local' | 'test', so the daemon's session establishment path is wired and does
 * not crash with "adapter not wired" (AC-010). Defaults to a successful relay
 * selection (the conservative, always-available transport).
 */
export class LocalTransportSelectorStub implements ITransportSelector {
  #result: TransportResult;

  constructor(result?: TransportResult) {
    this.#result =
      result ?? { ok: true, mode: "relay", dcutrSettled: Promise.resolve(false) };
  }

  async dial(_assignment: SessionAssignment, _opts: TransportDialOptions): Promise<TransportResult> {
    return this.#result;
  }

  /** Test/composition driver: set the canned result. */
  setResult(result: TransportResult): void {
    this.#result = result;
  }
}

// ─── Advertised-address selection (AC-004 / AC-019 / DB-001) ──────────────────

export type AdvertisedAddress =
  | { kind: "direct"; addr: string }
  | { kind: "relay"; addr: string };

/**
 * Decide what address a node advertises in its SessionAssignment negotiation,
 * given its AutoNAT dialability and its relay circuit address.
 *
 * dialable with a publicAddr → advertise the direct address (transport_mode will
 * be 'direct'). Otherwise (behind NAT, or AutoNAT unavailable because the
 * directory is reconnecting) → advertise the relay circuit address (conservative
 * fallback; transport_mode will be 'relay'). This decision is made once at
 * session establishment and is immutable for that session (AC-019).
 */
export function selectAdvertisedAddress(
  dialability: Dialability,
  relayCircuitAddr: string,
): AdvertisedAddress {
  if (dialability.dialable && dialability.publicAddr) {
    return { kind: "direct", addr: dialability.publicAddr };
  }
  return { kind: "relay", addr: relayCircuitAddr };
}
