/**
 * Registering the trust-signal pickup handler on a signaling stream — the ONE place it happens.
 *
 * ─── WHY THIS IS A SHARED REGISTRAR AND NOT AN INLINE `registerInboundHandler` ─────────────────
 *
 * A directory drains its pickup queue down ANY stream that authenticates, and the daemon opens two
 * kinds: the agent's own per-agent manager, and a transient VISITING connection to another node
 * when a counterparty lives there. The handler was registered only on the first, so a visited node
 * pushed its pickups and the daemon dropped every frame — re-sent and re-dropped on every visit,
 * silently, while the operator's wallet read "No trust signals in wallet".
 *
 * `outbound-sessions.ts` already states the rule in its own header — "Anything a home stream must
 * handle, a visiting stream must handle too" — and `registerSealListeners` exists precisely because
 * the seal frames hit this failure first, and the fix there was to make them "a single bundle and
 * not three separate registrations". This is the same shape for the same reason: an inline
 * registration is a thing the next connection type will forget.
 */
import type { SignalingManager } from "@cello-protocol/transport";
import type { KeyProvider } from "@cello-protocol/crypto";

/** What `createInboundSessions` supplies: open the seal, verify, store, then ACK. */
export type TrustSignalPickupHandler = (
  frame: Record<string, unknown>,
  agentKeyProvider: KeyProvider,
  signaling: SignalingManager,
  agentName: string,
  /** "home", or the node id of the visited directory whose drain sent this. */
  origin?: string,
) => Promise<void>;

/**
 * Registers the listener and hands back a way to wait for whatever it is still doing.
 *
 * `origin` names the stream so the pickup logs can tell a home arrival from a visited node's drain.
 * Until there was more than one stream type that was unambiguous; now the same five log events fire
 * from two places and nothing said which, which is also the data the fan-out's "collected from node
 * X" reporting will need.
 */
export type PickupListenerRegistrar = (
  signaling: SignalingManager,
  agentName: string,
  agentKeyProvider: KeyProvider,
  origin: string,
) => { settle: (timeoutMs: number) => Promise<void> };

/**
 * Build the registrar.
 *
 * `getHandler` is resolved at FRAME time, not at registration time: the daemon builds its signaling
 * wiring before the inbound-session handlers exist, so capturing the handler when the listener is
 * registered would bind whatever was there at boot — which for this frame type is nothing.
 */
export function createPickupListenerRegistrar(
  getHandler: () => TrustSignalPickupHandler,
): PickupListenerRegistrar {
  return (signaling, agentName, agentKeyProvider, origin) => {
    // WHY IN-FLIGHT WORK IS TRACKED RATHER THAN FLOATED AND FORGOTTEN.
    //
    // A visiting connection is transient: `openVisitingConnection`'s caller stops it the moment the
    // session handoff finishes. The handler is asynchronous — it opens the seal, decodes, writes to
    // the wallet, and only THEN acks — so a teardown can win the race and the ACK never lands. The
    // signal itself is safe (the wallet write already happened and is content-addressed), but the
    // directory keeps the row and re-sends the same pickup on every future visit, and the log names
    // the failed send rather than the teardown that caused it.
    //
    // It also matters for what comes next: the fan-out closes each visiting connection on a terminal
    // end-of-drain frame or a bounded ceiling, and a ceiling that fires mid-handler would truncate
    // the drain the terminal frame exists to complete. Tracked here so that comes for free.
    const inFlight = new Set<Promise<void>>();
    signaling.registerInboundHandler((frame) => {
      if (frame["type"] !== "trust_signal_pickup") return;
      // `signaling` is the stream the frame ARRIVED on, and that is what the handler ACKs down.
      // Acking a visiting node's pickup down the home stream would leave the visited node's row
      // unacked forever — re-sent on every visit, which is this bug wearing a different hat.
      const p = getHandler()(frame as Record<string, unknown>, agentKeyProvider, signaling, agentName, origin)
        .catch(() => {})
        .finally(() => { inFlight.delete(p); });
      inFlight.add(p);
    });
    return {
      settle: async (timeoutMs: number) => {
        if (inFlight.size === 0) return;
        // BOUNDED. A handler wedged on a slow database must delay a teardown, never prevent one —
        // an unbounded wait here would turn a stuck pickup into a stuck session close.
        await Promise.race([
          Promise.allSettled([...inFlight]),
          new Promise((r) => setTimeout(r, timeoutMs)),
        ]);
      },
    };
  };
}
