/**
 * "Somebody is sending on this session RIGHT NOW" — the half a frontier check cannot cover.
 *
 * A send claims its session before it goes to the wire and releases it after. Between those two
 * points the message exists nowhere a reader can see it: no leaf, no transcript row, nothing in the
 * tree. Any check that asks "has anyone spoken here?" by reading state answers NO for the whole
 * round trip, which on a slow link is seconds.
 *
 * It lived inside `session-content-handlers.ts` as a private map, where `cello_send` used it to stop
 * two connections appending at the same frontier. It is out here because a SECOND reader now needs
 * the same fact for a sharper reason: `away-inbox-oneshot.ts` decides whether to END a session, and
 * "nobody has spoken" read at the wrong moment closes and seals a conversation the operator is in
 * the middle of replying to.
 *
 * ⚠️ CREATED PER DAEMON AND PASSED IN — never a module-level singleton. Tests start several daemons
 * in one process, and a shared map would let one daemon's in-flight send answer another's question.
 */

/**
 * How long a claim is honored before a sibling may proceed anyway.
 *
 * `finally` covers throw and reject. It does NOT cover a promise that NEVER SETTLES, and
 * `sendContent` awaits `node.newStream` and `stream.close` with no timeout or abort signal — only
 * the relay submit is bounded. With an unbounded claim, one hung libp2p stream would refuse every
 * sibling send on that conversation until the daemon restarted, behind guidance that says "wait a
 * moment" forever. Trading a permanent outage for a small chance of a duplicate is the wrong way
 * round: the defect is a bad conversation, the wedge is a dead one.
 *
 * Generous relative to the honest worst case (~30 s of bounded relay retries plus an unbounded
 * stream tail), so it expires hangs rather than races.
 */
export const SEND_CLAIM_TTL_MS = 60_000;

export interface SendClaims {
  /**
   * A SENT message reached the wire and its transcript row did NOT land. The leaf is committed, so
   * the conversation is intact; this side's readable copy is what is missing. Lives here because it
   * is the same kind of fact as a claim — something true about this process's sends that no reader
   * of the durable record can see — and both readers of this object need it.
   */
  noteRowMissing(agentName: string, sessionId: string): void;
  /**
   * True when this side is known to have said something the transcript cannot show. A reader asking
   * "did a human speak here" must then answer "cannot tell", never "nobody spoke" — only one of
   * those ends a session.
   */
  rowMissing(agentName: string, sessionId: string): boolean;
  /** Claim the session for a send that is about to go to the wire. */
  claim(agentName: string, sessionId: string): void;
  /** Release it. Call from a `finally` so a throw cannot wedge the session into permanent refusal. */
  release(agentName: string, sessionId: string): void;
  /** When the live claim was made, or `undefined` if there is none within the TTL. */
  claimedAt(agentName: string, sessionId: string): number | undefined;
  /** Is a send on the wire for this session right now? */
  held(agentName: string, sessionId: string): boolean;
}

export function createSendClaims(now: () => number = Date.now): SendClaims {
  const claims = new Map<string, number>();
  const rowHoles = new Set<string>();
  // NUL-joined: neither an agent name nor a session id can contain it, so no pair of distinct
  // (agent, session) can collide on one key.
  const key = (agentName: string, sessionId: string): string => `${agentName}\u0000${sessionId}`;
  return {
    claim(agentName, sessionId) { claims.set(key(agentName, sessionId), now()); },
    release(agentName, sessionId) { claims.delete(key(agentName, sessionId)); },
    claimedAt(agentName, sessionId) {
      const at = claims.get(key(agentName, sessionId));
      return at !== undefined && now() - at < SEND_CLAIM_TTL_MS ? at : undefined;
    },
    held(agentName, sessionId) { return this.claimedAt(agentName, sessionId) !== undefined; },
    noteRowMissing(agentName, sessionId) { rowHoles.add(key(agentName, sessionId)); },
    rowMissing(agentName, sessionId) { return rowHoles.has(key(agentName, sessionId)); },
  };
}
