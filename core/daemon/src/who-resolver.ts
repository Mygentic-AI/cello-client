/**
 * What to CALL a counterparty in a message an operator reads.
 *
 * Three tiers, and the order matters: the local pet name an operator chose, then the display name
 * the counterparty offered for this session, then the key fingerprint. A label can never block a
 * message and can never stand in for identity — the pubkey is the identity, and this only decides
 * what a human sees beside it.
 */
import { whoLabel } from "./who-label.js";
import type { SessionNodeManager } from "./session-node-manager.js";
import type { Logger } from "./types.js";

export interface WhoLabelDeps {
  logger: Logger;
  sessionNodeManager: SessionNodeManager;
  /** The display name the counterparty offered for this session, if any. */
  getOfferedMoniker: (agentName: string, sessionIdHex: string) => string | null;
}

export function createWhoResolver(deps: WhoLabelDeps) {
  const { logger, sessionNodeManager, getOfferedMoniker } = deps;

  // MONIKER-4 AC2: resolve the counterparty's display label — local pet name (MONIKER-3) ??
  // offered name for this session (MONIKER-2) ?? fingerprint. Total: any failure inside
  // resolution degrades to fingerprint via whoLabel's own tiers; a label can never block a
  // doorbell (spec §8).
  function resolveWho(agentName: string, pubkeyHex: string, sessionIdHex: string): { who: string; whoKnown: boolean } {
    let localMoniker: string | null = null;
    try {
      localMoniker = sessionNodeManager.getContactMoniker(agentName, pubkeyHex);
    } catch (err: unknown) {
      logger.warn("moniker.local.read_failed", { agentName, pubkey: pubkeyHex, reason: err instanceof Error ? err.message : String(err) });
    }
    // DOD-MONIKER-6: read only the box written FOR this agent — never a co-resident agent's.
    const resolved = whoLabel({ localMoniker, offeredMoniker: getOfferedMoniker(agentName, sessionIdHex), pubkeyHex });
    // `sessionId` is load-bearing for diagnosis, not decoration. `source:"offered"` is CORRECT for a
    // RECEIVER and wrong only for an INITIATOR (an initiator must never find a box — see DOD-MONIKER-6),
    // so a line cannot be judged without knowing who opened the session. Join on sessionId against
    // `session.inbound.accepted`, which names the receiver; any other agent on that session is the
    // initiator. Without this field the M8C live run produced a wrong verdict twice (journal Entry 76).
    //
    // The resolved LABEL is never logged: for an unverified offer it is an attacker-chosen string, and
    // MONIKER-2 AC2 already forbids echoing the raw value (`moniker.rejected` logs the reason, not the
    // name). `whoKnown` carries the trust bit without the payload.
    logger.debug("moniker.resolved", {
      agentName,
      sessionId: sessionIdHex,
      pubkey: pubkeyHex,
      source: resolved.source,
      whoKnown: resolved.whoKnown,
    });
    return { who: resolved.who, whoKnown: resolved.whoKnown };
  }

  return { resolveWho };
}
