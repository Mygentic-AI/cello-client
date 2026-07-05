/**
 * Cross-node session establishment — the pure per-attempt decision (Story B, item 2).
 *
 * Given a discovery outcome and which node we're already connected to (home), decide what the
 * negotiator does next. Kept out of the daemon's async retry loop so the branch/error-code mapping is
 * unit-testable in isolation (mirrors the directory-side resolveDiscoveryState).
 *
 * Design: docs/planning/discussion_logs/2026-07-04_1730_cross-node-session-topology.md §"Item 2".
 */

export type DiscoveryOutcome =
  | { kind: "result"; state: "online" | "offline" | "unknown_agent"; owningNodeIds: string[] }
  | { kind: "error" } // directory DB error during lookup — retryable, never authoritative
  | { kind: "unsupported" }; // old directory (unknown frame / no reply) — fall back to today's behavior

export type NegotiationAction =
  | { kind: "fallback" } // old directory → run the session_request on the home stream (today's path)
  | { kind: "same_node" } // target is on the node we're already connected to → home path, ZERO visiting
  | { kind: "cross_node"; owningNodeId: string } // reach into the target's home over a visiting connection
  | { kind: "unknown_agent" } // state 3 — a bad address, distinct code, NO retry
  | { kind: "offline" } // state 2 — known but offline, NO retry storm
  | { kind: "retry" }; // transient (DB error, or online-with-no-owner) → re-discover and retry

/**
 * Classify one discovery result into the next negotiator action. Pure. The retry counting, backoff,
 * and the actual I/O (open visiting connection, send session_request) live in the daemon loop.
 */
export function classifyDiscoveryOutcome(disc: DiscoveryOutcome, homeNodeId: string | null): NegotiationAction {
  // Old directory that doesn't understand discovery_lookup → today's local-only behavior on home.
  if (disc.kind === "unsupported") return { kind: "fallback" };
  // A directory DB error is retryable — NEVER collapsed into an authoritative offline/unknown.
  if (disc.kind === "error") return { kind: "retry" };

  if (disc.state === "unknown_agent") return { kind: "unknown_agent" };
  if (disc.state === "offline") return { kind: "offline" };

  // state === "online": pick the owning node (list-valued; length 1 until the k>1 homing knob).
  const owningNodeId = disc.owningNodeIds[0];
  // Online but no owner named is malformed — treat as transiently unresolved, retry (never dial a
  // fabricated node).
  if (!owningNodeId) return { kind: "retry" };
  // Same-node shortcut requires KNOWING our own node id (step-6 identity). Without it (homeNodeId
  // null), we cannot prove co-location, so we take the cross-node path (which validates the owning
  // node through the signed manifest before dialing).
  if (homeNodeId !== null && owningNodeId === homeNodeId) return { kind: "same_node" };
  return { kind: "cross_node", owningNodeId };
}
