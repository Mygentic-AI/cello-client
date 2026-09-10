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
  /**
   * Nodes the manifest declares that could NOT be resolved this sweep.
   *
   * Without this the `unreachable` bucket can never fill, because the roster is already the
   * REACHABLE SUBSET — `manifestNodesToEndpoints` drops a node whose /bootstrap probe failed. A
   * dead node therefore appeared in no bucket at all and the sweep reported "visited 2,
   * unreachable 0" for a three-node fleet, which is exactly the false negative the order forbids:
   * the operator is told nothing is waiting when nobody looked.
   */
  getUnresolvedNodes?: () => ReadonlyArray<{ nodeId: string; reason: string }>;
  openVisitingConnection: (
    agentName: string,
    agentKeyProvider: KeyProvider,
    agentPubkeyHex: string,
    endpoint: { peerId: string; multiaddr: string },
    correlationId: string,
    nodeId: string,
  ) => {
    mgr: {
      registerInboundHandler: (h: (f: Record<string, unknown>) => void) => void;
      /** "connected" once the stream is authenticated; the manager connects asynchronously. */
      readonly status?: string;
    };
    stop: (reason: string) => Promise<void>;
  };
  /** How long to wait for a node's end-of-drain frame before closing anyway. */
  ceilingMs?: number;
}

/**
 * WHY THE TRIGGER IS A PARAMETER (048-SWEEPTICK, added after the unit could not be verified).
 *
 * The tick and `onConnected` produced byte-identical log lines, so on a live daemon there was no way
 * to tell which one had swept — and signaling turns its stream over often enough that a tick's sweep
 * lands inside a burst of reconnect-driven ones. The unit's own live check was therefore impossible:
 * every candidate observation was equally explained by the trigger it was meant to replace.
 *
 * That is the failure this unit exists to prevent, one level up. 043-C2's sweep was correct and
 * unobservable, so nobody noticed it ran once per connection; 048's tick was correct and
 * unobservable, so nobody could show it ran at all.
 */
export type SweepTrigger = "connect" | "tick";

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
  /** What caused this sweep. Defaults to `connect`, which is the only caller that passes nothing. */
  trigger?: SweepTrigger,
) => Promise<SweepResult>;

export function createTrustSignalSweep(deps: TrustSignalSweepDeps): TrustSignalSweep {
  const { logger, resolveConsortiumRoster, openVisitingConnection, getUnresolvedNodes } = deps;
  const ceilingMs = deps.ceilingMs ?? 10_000;
  // One sweep per agent at a time. `onConnected` fires on every reconnect, so a flapping stream
  // would otherwise stack sweeps, each holding up to N authenticated visiting streams and
  // re-triggering every node's drain. Duplicate delivery is safe — the wallet write is
  // content-addressed and the drain deletes only on ACK — so this is load, not corruption, but it
  // is load that arrives exactly when the network is already struggling.
  const inFlight = new Set<string>();
  /**
   * 048-SWEEPTICK — the problem set this agent reported LAST time, so a steady state is stated once.
   *
   * This module was written for a once-per-connection cadence and logs like it: a warn per
   * unreachable-or-unresolved node per run, plus a `finished` line per run. Since 048 it runs every
   * five minutes for the life of the daemon, so a node that is delisted but still in the manifest
   * turned two warns a day into roughly 1,150 — and the next incident is found by grepping
   * `daemon.log`, which would then return a wall of a condition nobody is going to act on. A warning
   * that fires on a steady state has stopped being a signal.
   *
   * So the CHANGE is warned, the repeat is debugged. Nothing is hidden: the full result is still
   * returned to the caller and `finished` still carries every count.
   */
  const lastProblems = new Map<string, string>();

  return async (agentName, agentKeyProvider, agentPubkeyHex, homeNodeId, trigger = "connect") => {
    if (inFlight.has(agentName)) {
      logger.info("trust_signal.sweep.already_running", { agentName, trigger });
      return { visited: [], unreachable: [], incomplete: [], rosterUnavailable: false };
    }
    inFlight.add(agentName);
    try {
      return await run(agentName, agentKeyProvider, agentPubkeyHex, homeNodeId, trigger);
    } finally {
      inFlight.delete(agentName);
    }
  };

  async function run(
    agentName: string,
    agentKeyProvider: KeyProvider,
    agentPubkeyHex: string,
    homeNodeId: string | undefined,
    trigger: SweepTrigger,
  ): Promise<SweepResult> {
    const result: SweepResult = { visited: [], unreachable: [], incomplete: [], rosterUnavailable: false };

    // Which nodes were already a problem last time. A node's FIRST bad sweep warns; the same node
    // still bad five minutes later is debug. See `lastProblems` — this is the per-node half of it.
    const previously = new Set((lastProblems.get(agentName) ?? "").split(/[,|]/).filter(Boolean));
    const problem = (nodeId: string) => (previously.has(nodeId) ? (logger.debug ?? logger.warn) : logger.warn);

    // Declared-but-unresolvable nodes, named BEFORE any dialling. These never reach the loop below
    // because the roster excludes them, and saying nothing about them is how one dead node makes
    // "nothing waiting" look true.
    for (const n of getUnresolvedNodes?.() ?? []) {
      if (n.nodeId === homeNodeId) continue;
      result.unreachable.push(n.nodeId);
      problem(n.nodeId)("trust_signal.sweep.node_unreachable", { agentName, node: n.nodeId, reason: n.reason, trigger });
    }

    const roster = await resolveConsortiumRoster();
    if (!roster) {
      // NOT the same as "nobody had anything". We do not know who to ask, and saying nothing was
      // waiting would be a claim we cannot support.
      result.rosterUnavailable = true;
      logger.warn("trust_signal.sweep.roster_unavailable", { agentName, trigger });
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
        // openVisitingConnection connects ASYNCHRONOUSLY, so in practice it does not throw on a
        // dial failure — that case is caught after the ceiling instead. This catches a synchronous
        // fault while it wires the connection up, where `conn` is undefined and there is nothing to
        // stop. One node failing must never end the sweep.
        result.unreachable.push(node.nodeId);
        problem(node.nodeId)("trust_signal.sweep.node_unreachable", { agentName, node: node.nodeId, reason: extractErrorMessage(err), trigger });
        continue;
      }

      // try/finally, because the teardown is not optional. A throw between here and `stop()` would
      // leave an AUTHENTICATED visiting connection open — and the order names the consequence
      // directly: the directory drains its durable notification queue down any such stream, which
      // is a bug this connection type has already caused once.
      try {
        // Register BEFORE the promise, so a throw here cannot reject it and skip the teardown.
        let onComplete: (() => void) | undefined;
        conn.mgr.registerInboundHandler((frame) => {
          if (frame["type"] !== "trust_signal_drain_complete") return;
          onComplete?.();
        });

        // Wait for the node to say the drain is finished — or give up at the ceiling.
        //
        // The terminal frame is what makes this correct: a timer alone truncates a slow drain and
        // re-drops the remainder on the next sweep, forever, because the directory deletes on ACK
        // and an un-acked row simply comes back. The ceiling is the backstop for a node that never
        // sends one, including any directory older than that change.
        const completed = await new Promise<boolean>((resolve) => {
          const timer = setTimeout(() => resolve(false), ceilingMs);
          // Do not hold the process open waiting on a node that has gone quiet.
          timer.unref?.();
          onComplete = () => { clearTimeout(timer); resolve(true); };
        });

        if (completed) result.visited.push(node.nodeId);
        else if (conn.mgr.status !== undefined && conn.mgr.status !== "connected") {
          // NEVER CONNECTED, so this is a transport failure and not a slow drain. Filing it as
          // `incomplete` would name the directory's drain for something that is the network —
          // an exit-point label standing in for the real cause, which is the reading an operator
          // would then act on.
          result.unreachable.push(node.nodeId);
          problem(node.nodeId)("trust_signal.sweep.node_unreachable", {
            agentName, node: node.nodeId, reason: "never_connected", ceilingMs, trigger,
          });
        } else {
          // Connected and answering, but never said it was done. We may have collected everything
          // or only part of it and cannot tell — a different answer from a clean sweep, recorded
          // as one.
          result.incomplete.push(node.nodeId);
          problem(node.nodeId)("trust_signal.sweep.no_terminal_frame", { agentName, node: node.nodeId, ceilingMs, trigger });
        }
      } finally {
        // `stop` awaits any in-flight pickup handler before tearing the stream down (C1 review), so
        // a signal still being opened and stored is not cut off by this close.
        await conn.stop("sweep_finished");
      }
    }

    // The signature of anything an operator might act on. `visited` is deliberately absent: a node
    // moving from unreachable back to visited changes this string via the other two buckets.
    const problems = [...result.unreachable].sort().join(",") + "|" + [...result.incomplete].sort().join(",");
    const changed = lastProblems.get(agentName) !== problems;
    lastProblems.set(agentName, problems);

    // `trigger` FIRST after the agent, because it is the field that makes this line answer the
    // question the unit is judged on: did the tick run, or was that a reconnect?
    const line = { agentName, trigger, visited: result.visited.length, unreachable: result.unreachable.length, incomplete: result.incomplete.length };
    if (changed) logger.info("trust_signal.sweep.finished", line);
    else logger.debug?.("trust_signal.sweep.finished", { ...line, repeat: true });
    return result;
  };
}
