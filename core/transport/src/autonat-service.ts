/**
 * CELLO Transport — autonat-service.ts (CELLO-M7-TRANSPORT-001)
 *
 * NodeAutoNatService — the REAL IAutoNatService adapter (CELLO_ENV dev/staging/
 * production). It wraps a started CelloNode and surfaces the node's
 * libp2p-AutoNAT-driven dialability observable, gated by the directory-node prober
 * set, and emits the story's AutoNAT observability events through an injected
 * Logger.
 *
 * ─── Why this exists (review finding C2 + C1) ────────────────────────────────
 * The transport node owns a dialability observable but emits NO log events. The
 * story REQUIRES:
 *   - transport.autonat.result      (INFO, every probe cycle) — { dialable,
 *                                     publicAddr, nodeType }
 *   - transport.autonat.unavailable (WARN, when no directory probers are
 *                                     reachable) — { nodeType,
 *                                     directorySignalingStatus }
 * NodeAutoNatService is where those events are produced. It is the production
 * counterpart of LocalAutoNatStub (which returns canned values with no node).
 *
 * ─── SI-002: probers are exclusively manifest directory nodes ────────────────
 * AutoNAT can only run when at least one manifest-verified directory node is
 * connected to act as a dial-back prober. When the prober set is empty (directory
 * in 'reconnecting' state — SIGNAL-001), AutoNAT cannot run: getDialability()
 * returns the conservative DEFAULT_DIALABILITY ({ dialable:false, publicAddr:null })
 * regardless of what the node's raw observable says, and the dual unavailable
 * WARN event fires. A rogue non-manifest responder is never in the prober set, so
 * it can never push the node to dialable:true.
 */

import type { CelloNode } from "./types.js";
import type { Dialability, IAutoNatService, Unsubscribe } from "./autonat.js";
import { DEFAULT_DIALABILITY } from "./autonat.js";

/** Minimal logger surface used by NodeAutoNatService (injected, never imported). */
export interface AutoNatLogger {
  info(event: string, context: Record<string, unknown>): void;
  warn(event: string, context: Record<string, unknown>): void;
}

export type AutoNatNodeType = "session" | "standing_receiver";

export interface NodeAutoNatServiceOptions {
  /** The started CelloNode whose AutoNAT dialability this service surfaces. */
  node: CelloNode;
  /** Injected logger for the AutoNAT observability events. */
  logger: AutoNatLogger;
  /** 'standing_receiver' or 'session' — recorded on every event. */
  nodeType: AutoNatNodeType;
  /**
   * Directory-node multiaddrs serving as AutoNAT probers (SI-002). Empty when the
   * directory connection is in 'reconnecting' state — AutoNAT cannot run then.
   */
  probers?: string[];
  /**
   * Source of the directory signaling status string for the unavailable event.
   * Defaults to 'reconnecting' (the only state in which probers are empty).
   */
  directorySignalingStatus?: () => string;
}

/**
 * Real IAutoNatService over a live CelloNode. Subscribes to the node's dialability
 * observable; every change emits transport.autonat.result (and, when no probers
 * are reachable, transport.autonat.unavailable).
 */
export class NodeAutoNatService implements IAutoNatService {
  readonly #node: CelloNode;
  readonly #logger: AutoNatLogger;
  readonly #nodeType: AutoNatNodeType;
  #probers: string[];
  readonly #getStatus: () => string;
  readonly #listeners = new Set<(d: Dialability) => void>();
  readonly #unsubNode: Unsubscribe;

  constructor(opts: NodeAutoNatServiceOptions) {
    this.#node = opts.node;
    this.#logger = opts.logger;
    this.#nodeType = opts.nodeType;
    this.#probers = opts.probers ? [...opts.probers] : [];
    this.#getStatus = opts.directorySignalingStatus ?? (() => "reconnecting");
    // Each AutoNAT probe cycle that changes the node's dialability re-emits the
    // result event and notifies daemon-side observers.
    this.#unsubNode = this.#node.onDialabilityChange((d) => this.#emitResult(d));
  }

  /**
   * Current dialability. AutoNAT requires at least one directory-node prober; when
   * the prober set is empty (reconnecting), return the conservative default — the
   * node's raw observable is not trusted because no manifest prober confirmed it
   * (SI-002 / AC-004 / DB-001).
   */
  getDialability(): Dialability {
    if (this.#probers.length === 0) return { ...DEFAULT_DIALABILITY };
    return this.#node.getDialability();
  }

  /** The manifest directory-node prober set (SI-002). */
  getProbers(): string[] {
    return [...this.#probers];
  }

  onChange(listener: (d: Dialability) => void): Unsubscribe {
    this.#listeners.add(listener);
    return () => {
      this.#listeners.delete(listener);
    };
  }

  /** Update the prober set (e.g. on directory connect/disconnect). */
  setProbers(probers: string[]): void {
    this.#probers = [...probers];
  }

  /**
   * Emit the current probe result. Call once after the node has started so the
   * standing-receiver/session node's initial dialability (and any unavailable
   * condition) is logged even before libp2p fires its first self:peer:update.
   */
  emitInitialResult(): void {
    this.#emitResult(this.#node.getDialability());
  }

  /** Release the node subscription. */
  stop(): void {
    this.#unsubNode();
  }

  #emitResult(raw: Dialability): void {
    const noProbers = this.#probers.length === 0;
    // When AutoNAT cannot run, force the conservative default — the node's raw
    // observable was never confirmed by a manifest prober (SI-002).
    const d: Dialability = noProbers ? { ...DEFAULT_DIALABILITY } : raw;

    this.#logger.info("transport.autonat.result", {
      dialable: d.dialable,
      publicAddr: d.publicAddr,
      nodeType: this.#nodeType,
      ...(noProbers
        ? { note: "autonat_unavailable — directory in reconnecting state" }
        : {}),
    });

    // Dual-event (story Observability §notes): the unavailable WARN fires
    // alongside the INFO result whenever AutoNAT could not run. The INFO event is
    // the standard per-probe report; the WARN drives operational alarms.
    if (noProbers) {
      this.#logger.warn("transport.autonat.unavailable", {
        nodeType: this.#nodeType,
        directorySignalingStatus: this.#getStatus(),
      });
    }

    for (const l of this.#listeners) l({ ...d });
  }
}
