import type { SessionStatus } from "./types.js";

/**
 * The operator-facing CATEGORY of a session, derived from its raw status + message count.
 * The raw statuses (active / interrupted / sealed / seal_interrupted_pending) are an internal
 * lifecycle detail; operators reason in three buckets:
 *
 *   - open    — live or resumable: an active session, OR an interrupted one that actually
 *               exchanged messages (you can pick it back up).
 *   - closed  — done: sealed (or sealing — seal_interrupted_pending).
 *   - failed  — a session-initiation that never exchanged a message and got cut. A dead
 *               handshake. These must NOT clutter `cello status`, and are only returned by
 *               `get-sessions --failed` (or --all).
 *
 * This is the single source of truth for the status filter and the get-sessions flags, so the
 * two never drift.
 */
export type SessionCategory = "open" | "closed" | "failed";

export function classifySession(status: SessionStatus, messageCount: number): SessionCategory {
  if (status === "sealed" || status === "seal_interrupted_pending") return "closed";
  // CC-5/F21: a force-abandoned / reaped half-open session is a dead handshake — it belongs in the
  // "failed" bucket (out of `cello status`, visible only via --failed/--all), regardless of whether its
  // own auto-"Dispatched." ack bumped message_count.
  if (status === "abandoned") return "failed";
  if (status === "interrupted") return messageCount > 0 ? "open" : "failed";
  // "active"
  return "open";
}
