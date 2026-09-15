/**
 * Keep re-dialling a lost relay stream while something still depends on it.
 *
 * The relay client made ONE reconnect attempt when its reader ended. Live 2026-09-15: a laptop woke,
 * the reader ended, and that attempt ran before the network was back. Nothing dialled again — only
 * a send re-dials, and a receiving agent has nothing to send — so three messages sent during the
 * sleep never arrived as `leaf_deliver`. The delay doubles to a one-minute ceiling: one dial a minute
 * per relay costs nothing, and a stream that never returns is a conversation that silently stops.
 *
 * A REFUSAL is not a network drop, and must not read like one. When the relay answered and said no,
 * it is logged at error (once per distinct reason) and the loop drops straight to the ceiling. It
 * does not stop: the commonest refusal is an expired online token, which the next signaling
 * reconnect replaces, and the client reads the token fresh at every auth.
 */
import type { Logger } from "./types.js";

export const RELAY_RECONNECT_BASE_MS = 2_000;
export const RELAY_RECONNECT_MAX_MS = 60_000;

export async function reconnectWithBackoff(opts: {
  relayPeerId: string;
  logger: Logger;
  /** One pass over every node that could dial. True when the stream is back. */
  connectOnce: () => Promise<boolean>;
  /** The refusal the last attempt ended on, if the relay answered at all. */
  refusal: () => { reason: string; advice: string } | null;
  /** Closed, already connected, or no session left to deliver to. */
  shouldStop: () => boolean;
  baseMs: number;
}): Promise<void> {
  const { relayPeerId, logger } = opts;
  // Floored at 1ms: a zero base doubles to zero and the loop would spin flat out.
  let delay = Math.max(opts.baseMs, 1);
  let lastRefusal: string | undefined;
  for (let attempt = 1; !opts.shouldStop(); attempt++) {
    if (await opts.connectOnce()) return;
    const refused = opts.refusal();
    if (refused) {
      if (refused.reason !== lastRefusal) {
        logger.error("session.relay.reconnect.refused", {
          relayPeerId, reason: refused.reason, advice: refused.advice,
          impact: "the relay answered and refused, so this is not a network drop; retrying once a minute in case it clears",
        });
      }
      lastRefusal = refused.reason;
      delay = RELAY_RECONNECT_MAX_MS;
    }
    if (opts.shouldStop()) return;
    logger.info("session.relay.reconnect.scheduled", { relayPeerId, attempt, retryInMs: delay });
    await new Promise<void>((r) => { setTimeout(r, delay).unref?.(); });
    delay = Math.min(delay * 2, RELAY_RECONNECT_MAX_MS);
  }
}
