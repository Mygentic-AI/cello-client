/**
 * DOD-M12B-DELIVERY-QUIET-1 — which sessions this daemon's DOCUMENT DELIVERY worker is opening.
 *
 * ── THE LOOP THIS EXISTS TO BREAK ────────────────────────────────────────────────────────────────
 *
 * Two reachability triggers fire when a session comes up, and both are correct when a PEER caused
 * the session:
 *
 *   1. The initiator half — `onSessionOpened` in `initiate-session-handler.ts`, fired by the side
 *      that dialled.
 *   2. The inbound half — `dispatchSessionStateChangedWithTelegram` on `state === "created"`,
 *      fired by the side that accepted, which ALSO rings the conversation doorbell and pushes a
 *      Telegram notification.
 *
 * Either one calls `ReconcileScheduler.onReachable`, and that is not a nudge: it sets
 * `failures = 0` and `nextAttemptMs = 0` and sweeps every shared document immediately. The stated
 * rationale is sound — "the backoff modeled 'they do not answer', and here they demonstrably just
 * did" (SYNC-P5 R39 trigger 2) — but it is only sound when the peer caused the session.
 *
 * When the DELIVERY WORKER opened it, the "signal" is our own outbound act reflected back at us. We
 * learn nothing about the peer, and we wipe a backoff that a refusal — possibly that same peer's
 * refusal, seconds earlier — had just set. Then:
 *
 *   the sweep needs a session → it opens one → creation fires the trigger → the trigger zeroes the
 *   backoff and sweeps every document → the sweep needs sessions → …
 *
 * Measured 2026-08-17: 321 reconcile attempts in 85 minutes driving 53 sessions and 63 standing-
 * receiver rebuilds. After `DOD-SYNC-REFUSAL-BACKOFF-1` removed the refusal storm, still 55
 * attempts in 20 minutes with 0 refusals — the volume that fix did not reach is this trigger.
 *
 * ── WHY AN INTENT, KEYED ON THE PEER, AND NOT A SESSION ID ───────────────────────────────────────
 *
 * The obvious design is to record the session id the delivery worker opened. It does not work: the
 * id is minted by the DIRECTORY and only reaches the opener at the end of negotiation, whereas the
 * directory has already pushed the assignment to the counterparty — which, when both agents live on
 * one daemon (the measured configuration), is this same process. The inbound doorbell therefore
 * fires BEFORE the opener ever learns the id, so a session-id registry is always too late.
 *
 * So what is registered is the INTENT — "this local agent's delivery worker is opening a session
 * with this peer right now" — before negotiation starts, and released when the open returns.
 *
 * ── THE KNOWN IMPRECISION, STATED RATHER THAN HIDDEN ─────────────────────────────────────────────
 *
 * If a delivery open to peer P is in flight for agent A at the same instant A's OPERATOR opens a
 * session to the same P, the inbound half cannot tell the two assignments apart and will suppress
 * the operator's doorbell too. It is narrow (same local agent, same peer, overlapping windows) and
 * it costs one missed notification for a session the operator started themselves and is therefore
 * already watching. The alternative — suppressing nothing — is the storm. This is the same class of
 * accepted, journaled imprecision as the away-ack coalescing guard in `attendance-wiring.ts`.
 *
 * Counting, not a boolean: two documents can be delivering to the same peer concurrently, and a
 * boolean cleared by whichever finishes first would re-open the loop for the other.
 */

/** Who caused a session to exist. Decides whether its creation is a signal about the peer. */
export type SessionOpenedBy = "operator" | "document_delivery";

export interface DeliveryOpenRegistry {
  /**
   * Register that `openerPubkey`'s delivery worker is opening a session with `targetPubkey`.
   * Returns the release function.
   */
  begin(openerPubkey: string, targetPubkey: string): () => void;
  /**
   * True while a delivery open from `openerPubkey` toward `targetPubkey` is in flight.
   *
   * ORDER IS THE WHOLE THING. The two halves that ask this question stand at opposite ends of the
   * same dial, so one of them must reverse its own arguments:
   *
   *   initiator half — WE opened it:  isDeliveryOpening(us, them)
   *   inbound half   — THEY opened it: isDeliveryOpening(them, us)
   *
   * The first version of this registry keyed on (agent NAME, peer PUBKEY) and both halves passed
   * their own local agent first. The initiator half matched; the inbound half asked
   * `(receiver-name, initiator-pubkey)` against a registry holding `(initiator-name, target-pubkey)`
   * — two tuples that can never be equal — so the doorbell guard read as protection and was
   * unreachable in production, and the log line meant to prove it worked never fired either.
   * Pubkeys on BOTH ends is what lets the two halves name the same pair at all.
   */
  isDeliveryOpening(openerPubkey: string, targetPubkey: string): boolean;
  /** In-flight count. Exposed for assertions and for the leak check a test can make. */
  inFlight(): number;
}

/**
 * How long an entry may claim to be "in flight" before it is ignored.
 *
 * `openSessionAs` carries no deadline of its own, so a dial that never settles would leave the
 * intent registered and silence that peer's doorbell for the life of the process — a worse outage
 * than the storm this exists to stop. A dial that has been in flight for two minutes is not in
 * flight; it is stuck, and a stuck dial must not be able to mute anything.
 */
export const DELIVERY_OPEN_STALE_MS = 120_000;

export function createDeliveryOpenRegistry(now: () => number = Date.now): DeliveryOpenRegistry {
  // Pubkeys reach this code from a wire assignment on one side and from a caller's parameter on the
  // other, and those two do not agree on case. Lowercased at the boundary so a comparison here can
  // never be the reason the suppression silently stops working.
  //
  // NUL separator, written as an escape rather than a raw byte: a literal U+0000 in the source made
  // this file binary to git, so `git show` printed no diff for it at all and the one new module in
  // the unit could not be reviewed through the normal path.
  const key = (openerPubkey: string, targetPubkey: string): string =>
    `${openerPubkey.toLowerCase()}\u0000${targetPubkey.toLowerCase()}`;
  // Start times, newest last. An array rather than a count so a stale entry can be dropped
  // individually — a bare counter cannot tell which of two in-flight opens is the wedged one.
  const opens = new Map<string, number[]>();

  const live = (k: string): number[] => {
    const all = opens.get(k);
    if (all === undefined) return [];
    const cutoff = now() - DELIVERY_OPEN_STALE_MS;
    const fresh = all.filter((startedAt) => startedAt > cutoff);
    if (fresh.length === 0) opens.delete(k);
    else if (fresh.length !== all.length) opens.set(k, fresh);
    return fresh;
  };

  return {
    begin(openerPubkey, targetPubkey) {
      const k = key(openerPubkey, targetPubkey);
      const startedAt = now();
      opens.set(k, [...live(k), startedAt]);
      let released = false;
      return () => {
        // Idempotent: a caller that releases twice must not drop someone else's entry and leave the
        // doorbell suppressed for a peer whose open has not finished.
        if (released) return;
        released = true;
        const remaining = opens.get(k);
        if (remaining === undefined) return;
        const at = remaining.indexOf(startedAt);
        const next = at === -1 ? remaining : [...remaining.slice(0, at), ...remaining.slice(at + 1)];
        if (next.length === 0) opens.delete(k);
        else opens.set(k, next);
      };
    },
    isDeliveryOpening(openerPubkey, targetPubkey) {
      return live(key(openerPubkey, targetPubkey)).length > 0;
    },
    inFlight() {
      let total = 0;
      for (const k of [...opens.keys()]) total += live(k).length;
      return total;
    },
  };
}
