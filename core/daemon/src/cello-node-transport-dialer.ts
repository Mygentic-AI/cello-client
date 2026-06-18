/**
 * CELLO Daemon — cello-node-transport-dialer.ts (CELLO-M7-TRANSPORT-001)
 *
 * CelloNodeTransportDialer — the REAL TransportDialer (CELLO_ENV dev/staging/
 * production). It performs the low-level dial operations the TransportSelector
 * composes, over a live session CelloNode plus the daemon's relay registry.
 *
 * Review finding C1(b): no real TransportDialer existed — only the
 * LocalTransportSelectorStub returned canned results. This is the production
 * implementation the composition root wires when CELLO_ENV is a production
 * variant.
 *
 * ─── Operations ──────────────────────────────────────────────────────────────
 *   dialDirect(peerId, addrs, timeoutMs) — dial the counterparty's direct
 *     multiaddrs (TCP/QUIC). Each addr is raced against timeoutMs. Throws if every
 *     address fails (the selector catches and falls back to relay — AC-006).
 *   dialRelay(relayCircuitAddr, peerId)  — dial via the relay circuit address.
 *   relayCircuitAddr(assignment)         — build the circuit address from the
 *     daemon's relay registry (NOT the assignment's address fields — AC-006), so
 *     the fallback works regardless of transport_mode.
 *   attemptDcutr(peerId)                 — observe whether libp2p's automatic
 *     dcutr hole-punch upgraded the relayed connection to direct within a window.
 *     Throws if no direct connection appears (non-fatal — selector logs DEBUG).
 *
 * SI-001: this dialer NEVER inspects transport_mode or infers strategy from
 * address format — it only performs the operation the selector asks for. The
 * authoritative transport_mode decision lives entirely in the TransportSelector.
 */

import type { SessionAssignment } from "@cello-protocol/protocol-types";
import type { CelloNode } from "@cello-protocol/transport";
import type { TransportDialer } from "./transport-selector.js";

/** A relay endpoint from the daemon's relay registry (populated at directory connect). */
export interface RelayEndpoint {
  peerId: string;
  multiaddrs: string[];
}

export interface CelloNodeTransportDialerOptions {
  /** The session node used to dial the counterparty. */
  node: CelloNode;
  /**
   * The daemon's relay registry — returns the known relay endpoint, or null when
   * no relay is registered. AC-006: the relay address is sourced here, never
   * parsed from the assignment's address fields.
   */
  relayRegistry: () => RelayEndpoint | null;
  /** How long to wait for the dcutr upgrade to surface a direct connection (ms). */
  dcutrObserveTimeoutMs?: number;
  /** Poll interval while observing for the dcutr upgrade (ms). */
  dcutrPollIntervalMs?: number;
}

const DEFAULT_DCUTR_OBSERVE_TIMEOUT_MS = 10_000;
const DEFAULT_DCUTR_POLL_INTERVAL_MS = 250;

export class CelloNodeTransportDialer implements TransportDialer {
  readonly #node: CelloNode;
  readonly #relayRegistry: () => RelayEndpoint | null;
  readonly #dcutrTimeoutMs: number;
  readonly #dcutrPollMs: number;

  constructor(opts: CelloNodeTransportDialerOptions) {
    this.#node = opts.node;
    this.#relayRegistry = opts.relayRegistry;
    this.#dcutrTimeoutMs = opts.dcutrObserveTimeoutMs ?? DEFAULT_DCUTR_OBSERVE_TIMEOUT_MS;
    this.#dcutrPollMs = opts.dcutrPollIntervalMs ?? DEFAULT_DCUTR_POLL_INTERVAL_MS;
  }

  async dialDirect(peerId: string | undefined, addrs: string[], timeoutMs: number): Promise<void> {
    if (addrs.length === 0) {
      throw new Error("no direct addresses to dial");
    }
    let lastError: unknown;
    for (const addr of addrs) {
      try {
        await this.#withTimeout(this.#node.dial(addr), timeoutMs, `direct dial to ${addr}`);
        return; // first successful dial wins
      } catch (err) {
        lastError = err;
      }
    }
    throw lastError instanceof Error
      ? lastError
      : new Error(`direct dial failed for all ${addrs.length} address(es): ${String(lastError)}`);
  }

  async dialRelay(relayCircuitAddr: string, _peerId: string | undefined): Promise<void> {
    await this.#node.dial(relayCircuitAddr);
  }

  relayCircuitAddr(assignment: SessionAssignment): string {
    const relay = this.#relayRegistry();
    if (!relay || relay.multiaddrs.length === 0) {
      throw new Error("no relay endpoint registered — cannot build relay circuit address");
    }
    const counterparty = assignment.counterparty_session_peer_id;
    if (!counterparty) {
      throw new Error("assignment has no counterparty_session_peer_id for the relay circuit");
    }
    // /<relay-multiaddr>/p2p/<relay-peer-id>/p2p-circuit/p2p/<counterparty-session-peer-id>
    return `${relay.multiaddrs[0]}/p2p/${relay.peerId}/p2p-circuit/p2p/${counterparty}`;
  }

  async attemptDcutr(peerId: string | undefined): Promise<void> {
    if (!peerId) {
      throw new Error("no counterparty peer id to observe dcutr upgrade for");
    }
    // libp2p's dcutr service runs automatically once a relayed connection exists.
    // We observe whether it produced a direct (non-circuit) connection within the
    // window. This is best-effort — failure is non-fatal (SI-003).
    const deadline = Date.now() + this.#dcutrTimeoutMs;
    for (;;) {
      if (this.#node.hasDirectConnectionTo(peerId)) return;
      if (Date.now() >= deadline) {
        throw new Error(`dcutr did not establish a direct connection to ${peerId} within ${this.#dcutrTimeoutMs}ms`);
      }
      await new Promise((r) => setTimeout(r, this.#dcutrPollMs));
    }
  }

  async #withTimeout<T>(p: Promise<T>, timeoutMs: number, label: string): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        p,
        new Promise<never>((_resolve, reject) => {
          timer = setTimeout(() => reject(new Error(`${label} timed out after ${timeoutMs}ms`)), timeoutMs);
        }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }
}
