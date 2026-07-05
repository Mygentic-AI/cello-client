/**
 * Cross-node session establishment — discovery outcome types + the pure online-result classifier
 * (Story B, item 2).
 *
 * The daemon's discovery step produces a DiscoveryOutcome; the retry loop handles the transport /
 * directory-fault / no-reply variants attempt-aware (each with its own log + terminal reason), and
 * defers the actual 3-state routing decision to classifyOnlineResult — kept pure so the branch and
 * error-code mapping are unit-testable in isolation (mirrors the directory-side resolveDiscoveryState).
 *
 * Design: docs/planning/discussion_logs/2026-07-04_1730_cross-node-session-topology.md §"Item 2".
 */

export type DiscoveryOutcome =
  // The directory answered with a 3-state result.
  | { kind: "result"; state: "online" | "offline" | "unknown_agent"; owningNodeIds: string[] }
  // The directory answered with discovery_lookup_error (a DB fault during the lookup) — retryable, and
  // a DIRECTORY-side fault (must NOT be reported to the caller as the counterparty being offline).
  | { kind: "error"; reason: string }
  // A reply arrived but did not parse (protocol/version anomaly) — retryable, surfaced distinctly.
  | { kind: "malformed" }
  // No reply within the window. Could be an old directory (predates discovery) OR a slow/dropped reply
  // on a new one — so it is RETRIED, and only falls back to today's local-only behavior as a last resort.
  | { kind: "timeout" }
  // Could not even send the lookup — the home signaling stream is down (reconnecting/lost). A TRANSPORT
  // failure, never an "old directory" — and the local-only fallback would fail the same way.
  | { kind: "send_failed"; reason: string };

export type ResultAction =
  | { kind: "same_node" } // target is on the node we're already connected to → home path, ZERO visiting
  | { kind: "cross_node"; owningNodeId: string } // reach into the target's home over a visiting connection
  | { kind: "unknown_agent" } // state 3 — a bad address, distinct code, NO retry
  | { kind: "offline" } // state 2 — known but offline, NO retry storm
  | { kind: "retry" }; // online but no owner named — transient, re-discover

/**
 * Route a 3-state discovery RESULT into the next action. Pure. Retry counting, backoff, transport /
 * directory-fault / timeout handling, and the actual I/O live in the daemon loop.
 */
export function classifyOnlineResult(
  state: "online" | "offline" | "unknown_agent",
  owningNodeIds: string[],
  homeNodeId: string | null,
): ResultAction {
  if (state === "unknown_agent") return { kind: "unknown_agent" };
  if (state === "offline") return { kind: "offline" };

  // state === "online": pick the owning node (list-valued; length 1 until the k>1 homing knob).
  const owningNodeId = owningNodeIds[0];
  // Online but no owner named is malformed — treat as transiently unresolved, retry (never dial a
  // fabricated node).
  if (!owningNodeId) return { kind: "retry" };
  // Same-node shortcut requires KNOWING our own node id (step-6 identity). Without it (homeNodeId
  // null), we cannot prove co-location, so we take the cross-node path (which validates the owning
  // node through the signed manifest before dialing).
  if (homeNodeId !== null && owningNodeId === homeNodeId) return { kind: "same_node" };
  return { kind: "cross_node", owningNodeId };
}
