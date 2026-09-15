/**
 * Keep re-dialling a lost relay stream while something still depends on it.
 *
 * The relay client made ONE reconnect attempt when its reader ended. Live 2026-09-15: a laptop woke,
 * the reader ended, and that attempt ran before the network was back. Nothing dialled again — only
 * a send re-dials, and a receiving agent has nothing to send — so three messages sent during the
 * sleep never arrived as `leaf_deliver`. The delay doubles to a one-minute ceiling: one dial a minute
 * per relay costs nothing, and a stream that never returns is a conversation that silently stops.
 */
export const RELAY_RECONNECT_BASE_MS = 2_000;
export const RELAY_RECONNECT_MAX_MS = 60_000;

export async function reconnectWithBackoff(opts: {
  /** One pass over every node that could dial. True when the stream is back. */
  tryOnce: () => Promise<boolean>;
  /** Closed, already connected, or no session left to deliver to. */
  shouldStop: () => boolean;
  baseMs: number;
  onScheduled: (attempt: number, retryInMs: number) => void;
}): Promise<void> {
  let delay = opts.baseMs;
  for (let attempt = 1; !opts.shouldStop(); attempt++) {
    if (await opts.tryOnce()) return;
    if (opts.shouldStop()) return;
    opts.onScheduled(attempt, delay);
    await new Promise<void>((r) => { setTimeout(r, delay).unref?.(); });
    delay = Math.min(delay * 2, RELAY_RECONNECT_MAX_MS);
  }
}
