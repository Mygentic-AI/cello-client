/**
 * DOD-DOC-DELIVERY-2 — binding the delivery worker's reachability check to `discovery_lookup`.
 *
 * The worker asks one question — "is this peer reachable right now?" — and its whole retry
 * behaviour turns on the answer being about the PEER. `runDiscoveryLookup` deliberately returns
 * five outcomes, only one of which is an answer about the peer at all, and this maps them:
 *
 *   result / offline | unknown_agent  ->  false   the peer is not reachable. A fact about them.
 *   result / online                   ->  true
 *   error | malformed | timeout | send_failed
 *                                     ->  THROW   the lookup did not happen. A fact about US.
 *
 * The throw is the point. `isPeerReachable` returning false for a directory fault would record a
 * directory outage — or our own signaling stream being down — as the operator's collaborator being
 * absent, and send them to ask the wrong person why nothing is syncing. The worker already treats
 * a throw as `lookup_failed` and keeps that distinction in the log; this is what feeds it.
 *
 * `unknown_agent` maps to false rather than throwing on purpose. It IS an answer from the
 * directory about the peer — the address does not resolve — and the honest consequence is the same
 * as offline: do not dial, retry later. It is a bad address rather than a transient absence, so it
 * is surfaced distinctly by the caller rather than being collapsed into the same log line.
 */

import type { DiscoveryOutcome } from "./cross-node-negotiation.js";

/** Why a lookup could not be performed. Carries the upstream reason verbatim. */
export class DiscoveryUnavailableError extends Error {
  readonly kind: string;
  constructor(kind: string, reason: string) {
    super(`document_discovery_unavailable: ${kind}${reason ? ` (${reason})` : ""}`);
    this.name = "DiscoveryUnavailableError";
    this.kind = kind;
  }
}

export interface Reachability {
  reachable: boolean;
  /** Present when the directory answered but the address does not resolve to a known agent. */
  unknownAgent: boolean;
}

/**
 * Map a discovery outcome onto the worker's reachability question.
 *
 * Pure, so the mapping is testable without a directory — which matters, because the expensive way
 * to discover this mapping is wrong is in production, where the symptom is an operator chasing a
 * collaborator who was never offline.
 */
export function reachabilityFromDiscovery(outcome: DiscoveryOutcome): Reachability {
  switch (outcome.kind) {
    case "result":
      if (outcome.state === "online") {
        if (outcome.owningNodeIds.length === 0) {
          // `classifyOnlineResult` calls exactly this shape malformed — "online but no owner named
          // … never dial a fabricated node" — and treats it as retry, not as availability. This
          // module's whole thesis is that only a RESULT is an answer about the peer; a result that
          // names no home answers nothing.
          throw new DiscoveryUnavailableError("online_without_owner", "no owning node named");
        }
        return { reachable: true, unknownAgent: false };
      }
      if (outcome.state === "unknown_agent") return { reachable: false, unknownAgent: true };
      return { reachable: false, unknownAgent: false };

    case "error":
      // A directory DB fault. Retryable, and emphatically not the counterparty being offline —
      // the outcome type's own comment says so, and collapsing it here would undo that care.
      throw new DiscoveryUnavailableError("directory_error", outcome.reason);

    case "malformed":
      // A reply that did not parse: a protocol or version anomaly on a directory that DID respond.
      // Distinct from a clean directory error, and never availability.
      throw new DiscoveryUnavailableError("malformed_reply", "");

    case "timeout":
      // No reply in the window — an old directory, or a slow or dropped reply on a new one. Either
      // way we learned nothing about the peer.
      throw new DiscoveryUnavailableError("timeout", "");

    case "send_failed":
      // Our OWN signaling stream is down. The most important one to keep separate: reporting our
      // transport fault as the peer's absence points the operator at the wrong machine entirely.
      throw new DiscoveryUnavailableError("signaling_unavailable", outcome.reason);

    default: {
      // Exhaustiveness, enforced by the compiler. A new outcome kind must be classified
      // deliberately rather than defaulting into "reachable" or "offline", which are the two
      // answers a silent default would have to invent.
      const never: never = outcome;
      throw new DiscoveryUnavailableError(
        "unrecognized_outcome",
        `unhandled discovery outcome ${JSON.stringify(never)}`,
      );
    }
  }
}
