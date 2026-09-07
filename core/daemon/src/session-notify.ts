/**
 * Telling the operator something happened to a session — and staying quiet when the daemon itself
 * caused it.
 *
 * A session that comes up because a DELIVERY WORKER dialled is not news: the operator did not ask
 * for it and nothing is waiting on them. A session that comes up because a person opened one is.
 * The delivery-open registry is what tells the two apart, and it lives here rather than beside the
 * dispatch because that distinction IS the dispatch's only interesting decision.
 */
import type { Logger } from "./types.js";
import type { LoadedAgent } from "./agent-loader.js";
import type { NotificationDispatcher } from "./notification-dispatcher.js";
import type { ReconcileScheduler } from "./document-reconcile-scheduler.js";
import { createDeliveryOpenRegistry } from "./delivery-open-registry.js";

export interface SessionNotifyDeps {
  logger: Logger;
  /** The live registry — a new agent must resolve without a restart. */
  loadedAgents: ReadonlyArray<LoadedAgent>;
  resolveWho: (agentName: string, pubkeyHex: string, sessionIdHex: string) => { who: string; whoKnown: boolean };
  sendTelegramDoorbell: (
    agentName: string,
    sessionId: string,
    kind: "state_change" | "session_request" | "message_waiting",
    detail: string,
  ) => Promise<void>;
  clearTelegramRung: (agentName: string, sessionId: string) => void;
  /**
   * ⚠️ FIVE GETTERS, AND TWO OF THEM ARE THE SHAPE THAT FAILS SILENTLY.
   *
   * `getReconcileScheduler` and `getDocumentOwnerKeyFor` read `let` bindings that are declared above
   * this call and ASSIGNED far below it. That is the only shape that goes quiet: still `undefined`,
   * no error, no type complaint — which is exactly how unit 4 shipped a permanently dead refusal
   * backoff. The other three read `const`s declared below, which would crash loudly at boot; they
   * are getters because they must be, not because getters are safer.
   */
  getNotificationDispatcher: () => NotificationDispatcher;
  getReconcileScheduler: () => ReconcileScheduler | undefined;
  getDocumentOwnerKeyFor: () => ((agentName: string) => string | null) | undefined;
  getOfferedMonikers: () => Map<string, string>;
  getOfferKey: () => (agentName: string, sessionIdHex: string) => string;
}

export function createSessionNotify(deps: SessionNotifyDeps) {
  const {
    logger, loadedAgents, resolveWho, sendTelegramDoorbell, clearTelegramRung,
    getNotificationDispatcher, getReconcileScheduler, getDocumentOwnerKeyFor,
    getOfferedMonikers, getOfferKey,
  } = deps;

  // DOD-M12B-DELIVERY-QUIET-1: which peers this daemon's document delivery worker is mid-dial to.
  // Read by BOTH reachability triggers and by the doorbell below. See delivery-open-registry.ts for
  // why this records an intent keyed on the peer rather than the session id — the short version is
  // that the directory mints the id and pushes the assignment to the counterparty before the opener
  // ever sees it, so on a one-daemon pair the inbound doorbell fires first and a session-id
  // registry is always too late.
  const deliveryOpens = createDeliveryOpenRegistry();
  /**
   * An agent's own pubkey, synchronously. The registry keys on PUBKEYS at both ends because that is
   * the only pair the dialling side and the accepting side can both name — the accepting side never
   * learns the dialler's local agent name, and the dialling side never learns ours.
   */
  const pubkeyOfAgent = (name: string): string => loadedAgents.find((a) => a.name === name)?.pubkey ?? "";
  /**
   * Is a delivery worker mid-dial from `openerPubkey` to `targetPubkey`?
   *
   * One predicate, passed to every consumer, so the doorbell, the phone and both reachability
   * triggers cannot drift apart on the answer. An unresolvable agent yields "" and never matches,
   * which fails OPEN — an unknown agent rings rather than being silently muted.
   */
  const isDeliveryOpenInFlight = (openerPubkey: string, targetPubkey: string): boolean =>
    openerPubkey !== "" && targetPubkey !== "" && deliveryOpens.isDeliveryOpening(openerPubkey, targetPubkey);
  /**
   * The ACCEPTING side's question: "did a delivery worker on `openerPubkey`'s daemon dial the local
   * agent `targetAgentName`?"
   *
   * A named predicate rather than a reversed call, because getting the order wrong here is exactly
   * the defect this line was re-opened to fix: the accepting side naturally reaches for its own
   * agent first, which compares the receiver's tuple against a registry holding the dialler's and
   * silently never matches.
   */
  const isDeliveryOpenToAgent = (openerPubkey: string, targetAgentName: string): boolean =>
    isDeliveryOpenInFlight(openerPubkey, pubkeyOfAgent(targetAgentName));

  function dispatchSessionStateChangedWithTelegram(
    agentName: string,
    sessionId: string,
    state: string,
    counterpartyPubkey: string | null,
  ): void {
    // DOD-M12B-DELIVERY-QUIET-1: this session came up because a DELIVERY WORKER dialled, so its
    // creation is machine traffic — not news about the peer, not a conversation, and not something
    // to buzz a phone about. Scoped to `created` on purpose: a session going DOWN is news whoever
    // opened it, and it is the operator's only signal that a conversation was cut off.
    //
    // ARGUMENTS ARE REVERSED HERE, AND THAT IS THE POINT. This function runs on the side that
    // ACCEPTED, so the opener is the COUNTERPARTY and the target is US. Asking
    // `(agentName, counterpartyPubkey)` — our own agent first, like the initiator half does — is
    // what made the first version of this guard unreachable in production: it compared the
    // receiver's tuple against a registry holding the dialler's.
    if (state === "created" && counterpartyPubkey !== null && isDeliveryOpenToAgent(counterpartyPubkey, agentName)) {
      // Suppression is LOGGED. A doorbell that silently stops ringing is the next defect, and the
      // measured storm was so hard to read precisely because nothing named its cause.
      logger.info("session.doorbell.suppressed_delivery", {
        agentName, sessionId, state, opener: counterpartyPubkey.slice(0, 16),
        impact: "document delivery opened this session — no doorbell, no phone push, no backoff reset",
      });
      return;
    }
    // MONIKER-4 AC2: stamp who/whoKnown on the counterparty-bearing frame. Resolved BEFORE the
    // offered-name drop below so a terminal state's own doorbell still shows the name. Below the
    // guard: on a suppressed event it was computed and thrown away.
    const who = counterpartyPubkey ? resolveWho(agentName, counterpartyPubkey, sessionId) : undefined;
    // SYNC-P5 (R39): a session coming up IS the party-became-reachable signal — every shared
    // document gets a reconcile attempt, and the scheduler's backoff resets (they just answered).
    // Sound ONLY when the peer caused it, which is what the guard above establishes.
    // Resolved ONCE per call, not per use: these are `let`s assigned elsewhere, and re-reading them
    // between the guard and the use is how a narrowed value stops being narrowed.
    const scheduler = getReconcileScheduler();
    const ownerKeyFor = getDocumentOwnerKeyFor();
    if (scheduler && ownerKeyFor && counterpartyPubkey && state === "created") {
      const ownerAgentId = ownerKeyFor(agentName);
      if (ownerAgentId !== null) {
        // DOD-M12B-DELIVERY-QUIET-1: the trigger FIRING is logged, not only its failure. This is
        // the storm driver — it zeroes the backoff and sweeps every shared document — and it was
        // invisible in the log unless it threw, so 321 attempts in 85 minutes named no cause. It is
        // also the only way either direction of the delivery exemption is observable.
        logger.info("document.reconcile.reachable_trigger_fired", {
          agentName, trigger: "inbound_session_created", peer: counterpartyPubkey.slice(0, 16),
        });
        void scheduler
          .onReachable(ownerAgentId, counterpartyPubkey.toLowerCase())
          .catch((err: unknown) => {
            logger.warn("document.reconcile.reachable_trigger_failed", {
              agentName, reason: err instanceof Error ? err.message : String(err),
            });
          });
      }
    }
    getNotificationDispatcher().dispatchSessionStateChanged(agentName, sessionId, state, counterpartyPubkey, who);
    void sendTelegramDoorbell(agentName, sessionId, "state_change", `Session ${state}`);
    // Reviewer HIGH fix (a60d68ed): telegramRungUnread had NO cleanup at all — a session that
    // rings once and is never read via cello_receive/since_seq (e.g. the operator only ever uses
    // cello_get_transcript, which does not advance the read watermark) left a permanent entry for
    // the life of the daemon process. Every state change is a natural point to drop it — the
    // worst case if the session is still genuinely active is one possible extra ring later, far
    // preferable to an unbounded leak (the exact class of bug fixed for TTL-1's expired-log at
    // af8a701 in this same milestone).
    clearTelegramRung(agentName, sessionId);
    // MONIKER-2 AC2b (review F1): the offered name is display material for the session's
    // lifetime only. Production emits "created", "interrupted", "counterparty_closing" through
    // this wrapper — a terminal-only check was dead code and left the map growing for the
    // daemon's lifetime (remote-fed). Drop on ANY state past "created": a prematurely dropped
    // label degrades to fingerprint, which the spec sanctions; an unbounded map does not.
    // DOD-MONIKER-6 AC3: drop only THIS agent's box — a co-resident agent's session moving on
    // must never cost this agent the caller's name.
    if (state !== "created" && getOfferedMonikers().delete(getOfferKey()(agentName, sessionId))) {
      logger.debug("moniker.offer.dropped", { agentName, sessionId, state });
    }
  }

  return { deliveryOpens, pubkeyOfAgent, isDeliveryOpenInFlight, isDeliveryOpenToAgent, dispatchSessionStateChangedWithTelegram };
}
