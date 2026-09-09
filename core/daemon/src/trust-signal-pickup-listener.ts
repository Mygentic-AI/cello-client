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
) => Promise<void>;

export type PickupListenerRegistrar = (
  signaling: SignalingManager,
  agentName: string,
  agentKeyProvider: KeyProvider,
) => void;

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
  return (signaling, agentName, agentKeyProvider) => {
    signaling.registerInboundHandler((frame) => {
      if (frame["type"] !== "trust_signal_pickup") return;
      // `signaling` is the stream the frame ARRIVED on, and that is what the handler ACKs down.
      // Acking a visiting node's pickup down the home stream would leave the visited node's row
      // unacked forever — re-sent on every visit, which is this bug wearing a different hat.
      void getHandler()(frame as Record<string, unknown>, agentKeyProvider, signaling, agentName);
    });
  };
}
