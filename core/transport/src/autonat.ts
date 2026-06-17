/**
 * CELLO Transport — autonat.ts (CELLO-M7-TRANSPORT-001)
 *
 * AutoNAT dialability detection for session and standing-receiver nodes.
 *
 * ─── Specification (Phase S) ──────────────────────────────────────────────────
 * AutoNAT (libp2p) asks already-connected peers to dial back the node's
 * advertised address. If a dial-back succeeds, the node is publicly dialable; if
 * it fails, the node is behind NAT and must use a relay circuit address. CELLO
 * uses directory nodes (manifest-verified, three independent regions) as the
 * dial-back probers — they are already connected and trusted, so no dedicated
 * AutoNAT bootstrap infrastructure is required.
 *
 * Adapter pattern (mandatory per CLAUDE.md):
 *   IAutoNatService is the daemon-facing adapter for querying dialability. The
 *   real implementation (NodeAutoNatService) wraps a CelloNode and surfaces the
 *   node's libp2p-driven dialability observable, plus the directory prober set
 *   obtained from the daemon context. LocalAutoNatStub returns configurable
 *   values without any network access (CELLO_ENV='local'|'test').
 *
 * SI-002: probers are exclusively directory nodes whose identity is verified via
 * the consortium manifest. libp2p AutoNAT v1 probes connected peers; CELLO only
 * connects to manifest-verified directory nodes (enforced by the connection
 * policy / connection gater), so the effective prober set is the directory node
 * set. getProbers() surfaces that set so callers can assert it (AC-001(c)) and so
 * a rogue non-manifest responder cannot be counted (SI-002).
 *
 * ─── Pseudocode (Phase P) ─────────────────────────────────────────────────────
 * Dialability is { dialable, publicAddr }:
 *   - dialable: true iff AutoNAT confirmed at least one externally-reachable
 *     (public, non-circuit) multiaddr.
 *   - publicAddr: that confirmed multiaddr, or null when behind NAT / undetermined.
 *
 * LocalAutoNatStub:
 *   constructor(initial = { dialable: false, publicAddr: null }, probers = [])
 *   getDialability(): return current
 *   getProbers(): return probers
 *   onChange(cb): register; return unsubscribe
 *   setDialability(next): set current; notify all listeners  (test driver)
 *   setProbers(p): set probers  (test driver — e.g. simulate reconnecting => [])
 */

// ─── Dialability ──────────────────────────────────────────────────────────────

/**
 * The result of an AutoNAT probe cycle. Node-level (not session-scoped).
 *   dialable  — true if at least one directory node confirmed dial-back success.
 *   publicAddr — the externally-reachable multiaddr if dialable; null otherwise.
 */
export interface Dialability {
  dialable: boolean;
  publicAddr: string | null;
}

/** Conservative default used before any probe completes / when AutoNAT cannot run. */
export const DEFAULT_DIALABILITY: Dialability = Object.freeze({
  dialable: false,
  publicAddr: null,
});

/** Unsubscribe handle returned by observe registrations. */
export type Unsubscribe = () => void;

// ─── IAutoNatService ────────────────────────────────────────────────────────

/**
 * Daemon-facing adapter for dialability. The session establishment logic reads
 * getDialability() to decide what address to advertise in the SessionAssignment
 * negotiation (direct multiaddr when dialable, relay circuit address otherwise).
 */
export interface IAutoNatService {
  /** Current dialability. Returns DEFAULT_DIALABILITY before the first probe. */
  getDialability(): Dialability;
  /**
   * The directory-node multiaddrs serving as AutoNAT probers (SI-002). Empty when
   * no directory nodes are connected (reconnecting state — AutoNAT cannot run).
   */
  getProbers(): string[];
  /** Observe dialability changes. Returns an unsubscribe handle. */
  onChange(listener: (d: Dialability) => void): Unsubscribe;
}

// ─── LocalAutoNatStub ─────────────────────────────────────────────────────────

/**
 * In-process AutoNAT stub. Returns configurable dialability with no network
 * access. Selected when CELLO_ENV is 'local' or 'test'. Defaults to NOT dialable
 * (the conservative relay fallback) per the story's edge-case requirements.
 */
export class LocalAutoNatStub implements IAutoNatService {
  #dialability: Dialability;
  #probers: string[];
  readonly #listeners = new Set<(d: Dialability) => void>();

  constructor(opts?: { dialability?: Dialability; probers?: string[] }) {
    this.#dialability = opts?.dialability ?? { ...DEFAULT_DIALABILITY };
    this.#probers = opts?.probers ? [...opts.probers] : [];
  }

  getDialability(): Dialability {
    return { ...this.#dialability };
  }

  getProbers(): string[] {
    return [...this.#probers];
  }

  onChange(listener: (d: Dialability) => void): Unsubscribe {
    this.#listeners.add(listener);
    return () => {
      this.#listeners.delete(listener);
    };
  }

  /** Test driver: update dialability and notify observers. */
  setDialability(next: Dialability): void {
    this.#dialability = { ...next };
    for (const l of this.#listeners) l(this.getDialability());
  }

  /** Test driver: set the prober set (e.g. [] to simulate the reconnecting state). */
  setProbers(probers: string[]): void {
    this.#probers = [...probers];
  }
}
