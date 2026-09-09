/**
 * Collecting trust signals parked at nodes this daemon is not connected to.
 *
 * ─── WHY A SWEEP IS NEEDED AT ALL ──────────────────────────────────────────────────────────────
 *
 * `pickup_queue` is node-local by design and does NOT replicate, so a signal delivered to one
 * directory is collectable only from that directory. The one thing that collects it is a stream
 * AUTHENTICATING there, because the drain runs on auth. An agent connects to a single directory —
 * chosen at random on every start — so a signal parked anywhere else simply waited.
 *
 * C1 made a visiting connection able to receive pickups at all. This makes it deterministic rather
 * than incidental: without it, collection happens only if you happen to start a session with
 * someone who lives on that node.
 *
 * ─── WHAT THIS DELIBERATELY IS NOT ─────────────────────────────────────────────────────────────
 *
 * Not on the login path. The home stream drains inline on its own auth, as it always has; this runs
 * in the background afterwards. The signaling wait is already the reason bootstrap needed a fast
 * probe, and n round trips added to it would be felt on every start for a benefit that is never
 * urgent — a signal that has waited for a directory to be visited can wait another few seconds.
 *
 * Not a node list. The roster comes from the signed manifest the daemon already polls, so a fleet
 * of five sweeps five with no code change.
 */
import type { KeyProvider } from "@cello-protocol/crypto";
import type { Logger } from "./types.js";
import type { ConsortiumEndpoint } from "./directory-bootstrap.js";
import { extractErrorMessage } from "./error-message.js";

/** What a sweep found, per node. Never collapsed into a single boolean — see `unreachable`. */
export interface SweepResult {
  /** Nodes that answered and said their drain was finished. */
  visited: string[];
  /** Nodes that could not be dialled at all. */
  unreachable: string[];
  /** Nodes that answered but never said they were finished — we hit the ceiling instead. */
  incomplete: string[];
  /** True when the manifest could not be resolved, so we do not know who to ask. */
  rosterUnavailable: boolean;
}

export interface TrustSignalSweepDeps {
  logger: Logger;
  resolveConsortiumRoster: () => Promise<ConsortiumEndpoint[] | null>;
  openVisitingConnection: (
    agentName: string,
    agentKeyProvider: KeyProvider,
    agentPubkeyHex: string,
    endpoint: { peerId: string; multiaddr: string },
    correlationId: string,
    nodeId: string,
  ) => { mgr: { registerInboundHandler: (h: (f: Record<string, unknown>) => void) => void }; stop: (reason: string) => Promise<void> };
  /** How long to wait for a node's end-of-drain frame before closing anyway. */
  ceilingMs?: number;
}

export type TrustSignalSweep = (
  agentName: string,
  agentKeyProvider: KeyProvider,
  agentPubkeyHex: string,
  /**
   * The node this daemon is already connected to, skipped because its drain ran on its own auth.
   *
   * Optional because the caller does not always know it. When it is unknown every node is visited,
   * including home — which costs one extra connection whose drain immediately reports nothing left,
   * not a wrong answer. A wasted round trip in the background beats guessing which node to skip.
   */
  homeNodeId?: string,
) => Promise<SweepResult>;

export function createTrustSignalSweep(deps: TrustSignalSweepDeps): TrustSignalSweep {
  const { logger, resolveConsortiumRoster, openVisitingConnection } = deps;
  const ceilingMs = deps.ceilingMs ?? 10_000;

  return async (agentName, agentKeyProvider, agentPubkeyHex, homeNodeId) => {
    const result: SweepResult = { visited: [], unreachable: [], incomplete: [], rosterUnavailable: false };

    const roster = await resolveConsortiumRoster();
    if (!roster) {
      // NOT the same as "nobody had anything". We do not know who to ask, and saying nothing was
      // waiting would be a claim we cannot support.
      result.rosterUnavailable = true;
      logger.warn("trust_signal.sweep.roster_unavailable", { agentName });
      return result;
    }

    // Skip home when we know it: its drain already ran on this stream's own auth, so visiting it
    // would open a second authenticated connection to a node we are already on, for nothing.
    const targets = homeNodeId ? roster.filter((n) => n.nodeId !== homeNodeId) : roster;
    if (targets.length === 0) return result;

    for (const node of targets) {
      const correlationId = `sweep-${agentName}-${node.nodeId}-${Date.now()}`;
      let conn: ReturnType<TrustSignalSweepDeps["openVisitingConnection"]> | undefined;
      try {
        conn = openVisitingConnection(
          agentName, agentKeyProvider, agentPubkeyHex,
          { peerId: node.peerId, multiaddr: node.multiaddr }, correlationId, node.nodeId,
        );
      } catch (err: unknown) {
        // ONE NODE DOWN MUST NOT END THE SWEEP, and must never read as "nothing waiting" — that
        // would let a single unreachable node manufacture a false negative, telling the operator
        // there is nothing to collect when nobody looked.
        result.unreachable.push(node.nodeId);
        logger.warn("trust_signal.sweep.node_unreachable", {
          agentName, node: node.nodeId,
          reason: extractErrorMessage(err),
        });
        continue;
      }

      // Wait for the node to say the drain is finished — or give up at the ceiling.
      //
      // The terminal frame is what makes this correct: a timer alone truncates a slow drain and
      // re-drops the remainder on the next sweep, forever, because the directory deletes on ACK and
      // an un-acked row simply comes back. The ceiling is the backstop for a node that never sends
      // one, including any directory older than that change.
      const completed = await new Promise<boolean>((resolve) => {
        const timer = setTimeout(() => resolve(false), ceilingMs);
        conn!.mgr.registerInboundHandler((frame) => {
          if (frame["type"] !== "trust_signal_drain_complete") return;
          clearTimeout(timer);
          resolve(true);
        });
      });

      if (completed) result.visited.push(node.nodeId);
      else {
        // Answered, but never said it was done. We may have collected everything or only part of
        // it, and we cannot tell — which is a different answer from a clean sweep and is recorded
        // as one.
        result.incomplete.push(node.nodeId);
        logger.warn("trust_signal.sweep.no_terminal_frame", { agentName, node: node.nodeId, ceilingMs });
      }

      // `stop` awaits any in-flight pickup handler before tearing the stream down (C1 review), so a
      // signal still being opened and stored is not cut off by this close.
      await conn.stop(completed ? "sweep_complete" : "sweep_ceiling");
    }

    logger.info("trust_signal.sweep.finished", {
      agentName,
      visited: result.visited.length,
      unreachable: result.unreachable.length,
      incomplete: result.incomplete.length,
    });
    return result;
  };
}
