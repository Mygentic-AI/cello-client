/**
 * Bringing an agent online, and reporting honestly whether it can actually be REACHED.
 *
 * "Online" and "reachable" are two different facts and the whole value of this path is refusing to
 * collapse them. An agent marked online whose standing receiver never came up looks identical to a
 * healthy one at every surface — so a second `cello_start_agent`, which is what an operator runs
 * when the first seemed not to work, reports the receiver's REAL state rather than a bare ok.
 */
import type { AgentInfo, Logger } from "./types.js";
import type { SessionNodeManager } from "./session-node-manager.js";
import type { SignalingManager } from "@cello-protocol/transport";
import type { KeyProvider } from "@cello-protocol/crypto";
import type { NotificationDispatcher } from "./notification-dispatcher.js";
import { extractErrorMessage } from "./error-message.js";

/** What starting an agent can answer. The readiness half is why this is a union and not a boolean. */
export type StartAgentResult =
  | { ok: true; standing_receiver: "ready" }
  | { ok: true; standing_receiver: "starting"; standing_receiver_cause: string | undefined; guidance: string }
  | { ok: false; reason: string; guidance: string };

export interface StartAgentDeps {
  logger: Logger;
  sessionNodeManager: SessionNodeManager;
  /** Live containers — a copy would report a stale online set forever. */
  agents: ReadonlyArray<AgentInfo>;
  onlineAgents: Set<string>;
  explicitlyOfflineAgents: Set<string>;
  keyProviders: Map<string, KeyProvider>;
  /**
   * ⚠️ A GETTER. The dispatcher is constructed ~575 lines BELOW this call and is only ever used when
   * an agent is actually started, which is always later. It is a `const`, so by value this would be
   * a temporal-dead-zone crash at boot rather than a silent absence — loud, but still wrong.
   */
  getNotificationDispatcher: () => NotificationDispatcher;
  /** ⚠️ NOT a getter — for an agent with no manager this CONSTRUCTS one and dials. */
  getAgentSignaling: (
    agentName: string, kp: KeyProvider, pubkeyHex: string,
  ) => { signaling: SignalingManager };
  autoRecoverForAgent: (agentName: string, trigger?: string) => Promise<void>;
  flushAwaitingContent: (filterAgentName?: string) => Promise<void>;
}

export function createStartAgent(deps: StartAgentDeps) {
  const {
    logger, sessionNodeManager, agents, onlineAgents, explicitlyOfflineAgents, keyProviders,
    getNotificationDispatcher, getAgentSignaling, autoRecoverForAgent, flushAwaitingContent,
  } = deps;

  // ─── MCP-001: cello_start_agent handler ───
  // M8C-AUTOSTART-1 (A2): the shared start path. Extracted from cello_start_agent so cello_use_agent
  // can AUTO-START an offline agent through the exact same code (idempotent, same signaling +
  // standing-receiver setup, same agent_state_changed event) — never a divergent shim-side retry.
  // Permissive by design (D12): an agent that exists goes online regardless of directory
  // registration state (online-without-registration is an established contract). Returns a
  // structured failure so callers can surface agent_start_failed with a real reason + guidance.
  /**
   * `standing_receiver` is part of the SUCCESS shape, not an optional extra — `DOD-M15-START-AGENT-
   * UNAWAITED-1`. A bare `{ ok: true }` claimed the agent was started and reachable when only the
   * first half was known, and the union makes the two states impossible to conflate at a call site.
   */
  function startAgentInternal(name: string):
    | { ok: true; standing_receiver: "ready" }
    | { ok: true; standing_receiver: "starting"; standing_receiver_cause: string | undefined; guidance: string }
    | { ok: false; reason: string; guidance: string } {
    const agent = agents.find((a) => a.name === name);
    if (!agent || agent.state === "load_failed") {
      return { ok: false, reason: "agent_not_found", guidance: `Agent '${name}' does not exist. Run 'cello login' to register agents, or check agent names with cello_agents.` };
    }
    if (onlineAgents.has(name)) {
      // Idempotent — already online, no event.
      //
      // It still reports REAL readiness rather than a bare ok. "Already online" says this daemon
      // marked the agent online at some earlier moment; it says nothing about whether the receiver
      // that ensure was firing ever came up. An operator who calls start twice — which is exactly
      // what someone does when the first one seemed not to work — would otherwise get the most
      // reassuring answer in the run on the attempt where something is actually wrong.
      const readyNow = sessionNodeManager.getStandingReceiverInfo(name) !== null;
      if (readyNow) return { ok: true, standing_receiver: "ready" };
      const cause = sessionNodeManager.standingReceiverAbsenceReason(name);
      return {
        ok: true,
        standing_receiver: "starting",
        standing_receiver_cause: cause,
        guidance:
          `'${name}' was already online, and its standing receiver is not up (${cause}). Outbound ` +
          `sends and cello_initiate_session ensure it on demand. An inbound session arriving before ` +
          `it is ready is refused with 'standing_receiver_unavailable' — this daemon, not the ` +
          `counterparty. If it stays this way, stop the agent and start it again.`,
      };
    }
    onlineAgents.add(name);
    // Pressing start clears the deliberate-offline mark — that is what makes the switch reversible.
    explicitlyOfflineAgents.delete(name);
    // CELLO-M7-CONN-001 (DOD-CONN-2, code-review HIGH): the "online" transition establishes THIS
    // agent's OWN directory signaling connection (the documented getAgentSignaling "online" trigger),
    // so the directory has a stream to push inbound session_assignment / seal_interrupted_request to.
    // Without this, a started receiver agent sitting in cello_await_session (notably after a daemon
    // restart, where login does NOT auto-start agents) would have no stream and never receive inbound —
    // a regression of the pre-CONN-001 keystone, which connected the primary at startup. Lazy +
    // idempotent (getAgentSignaling reuses an existing manager); the test path returns the shared one.
    const startKp = keyProviders.get(name);
    if (startKp && agent.pubkey) {
      getAgentSignaling(name, startKp, agent.pubkey);
      logger.info("agent.directory.connection.initiated", { agentName: name, agentPubkey: agent.pubkey });
    }
    // DOD-LOOP-1: each online agent gets its OWN standing receiver, so two agents on one daemon
    // (loopback) never contend for a single one. Fire-and-forget (initiate/accept also ensure on
    // demand); never let it throw out of the handler. Once the SR is up, re-park any of THIS
    // agent's un-acked awaiting content (the crash backstop — its node was unavailable at the
    // pre-IPC startup flush because no agent was online yet).
    // The standing-receiver ensure + sender re-park; a rejection here is a standing-receiver failure.
    void sessionNodeManager.ensureStandingReceiverForAgent(name)
      .then(() => flushAwaitingContent(name))
      .catch((err: unknown) => {
        logger.warn("session.standing_receiver.ensure.failed", {
          agentName: name,
          reason: extractErrorMessage(err),
          // `DOD-M15-START-AGENT-UNAWAITED-1`. The operator has ALREADY been told `ok: true` — this
          // handler answered before this promise settled — so nothing corrects that answer if this
          // is permanent. Say what it costs them here, because this line is the only account.
          impact:
            "cello_start_agent already answered ok for this agent, and its standing receiver did not " +
            "come up. The agent is online to the directory and CANNOT accept an inbound session: a " +
            "counterparty dialling it is refused standing_receiver_unavailable. Initiate and accept " +
            "each re-ensure on demand, so this may still recover on the next attempt; if it does not, " +
            "stop and restart the agent.",
        });
      })
      // DOD-MSG-4 (auto-recover-on-reconnect): RECEIVER drains its parked mailbox from every relay it
      // has sessions on (symmetric to the sender re-park). Its own stage so a failure is labelled
      // correctly (review #4), not as a standing-receiver error. autoRecoverForAgent catches per-relay
      // errors internally, so this .catch is a backstop only.
      .then(() => autoRecoverForAgent(name, "agent_start"))
      .catch((err: unknown) => {
        logger.warn("content.recover.auto.failed", { agentName: name, stage: "agent_start", error: extractErrorMessage(err) });
      });
    /**
     * `DOD-M15-START-AGENT-UNAWAITED-1` — SAY WHETHER THE AGENT CAN ACTUALLY HEAR YET.
     *
     * The ensure above is fire-and-forget and that is deliberate: initiate and accept both ensure on
     * demand, and awaiting it here would turn a transient network failure into a failed start. **The
     * defect was never the timing — it was the CLAIM.** `{ ok: true }` with nothing else reads as
     * "your agent is running and reachable", and a session landing in the window before the receiver
     * exists is refused `standing_receiver_unavailable` — a precondition on OUR side, surfacing to
     * the operator as though the counterparty or the directory were at fault.
     *
     * ⚠️ **This field is only worth having because it can genuinely say `ready`.** Computed one line
     * after firing an async ensure, a naive readiness flag would be `starting` on every call — a
     * field that can never take its other value, which is the same defect as a log line reporting a
     * verdict its producer cannot have. It escapes that because `ensureStandingReceiverForAgent` is
     * IDEMPOTENT: an agent that already holds a receiver (a repeat start, or one whose receiver
     * survived) has one at this instant and reports `ready` truthfully.
     *
     * `cause` is read from the same four-way answer the refusal path uses, so the response and the
     * eventual error agree instead of describing the same state in two vocabularies.
     */
    const receiverReady = sessionNodeManager.getStandingReceiverInfo(name) !== null;
    const startingCause = receiverReady ? undefined : sessionNodeManager.standingReceiverAbsenceReason(name);
    logger.info("agent.online", {
      agentName: name,
      agentPubkey: agent.pubkey ?? "",
      standingReceiver: receiverReady ? "ready" : "starting",
      ...(startingCause !== undefined ? { standingReceiverCause: startingCause } : {}),
    });
    // MCP-002: Broadcast agent_state_changed to ALL connections
    getNotificationDispatcher().dispatchAgentStateChanged(name, "online", "started");
    if (receiverReady) return { ok: true, standing_receiver: "ready" as const };
    return {
      ok: true,
      standing_receiver: "starting" as const,
      standing_receiver_cause: startingCause,
      // Invariant: an agent-facing response carries an affordance. Naming the refusal text is the
      // load-bearing half — an operator who hits it in the next second can otherwise only conclude
      // the other side is broken.
      guidance:
        `'${name}' is online and its standing receiver is still being built. Outbound sends and ` +
        `cello_initiate_session ensure it on demand, so ordinary use is fine. A session arriving in ` +
        `the next moment can be refused with 'standing_receiver_unavailable' — that is this daemon ` +
        `not being ready yet, NOT the counterparty being unreachable. It clears on its own; ` +
        `cello_status reports the receiver once it is up.`,
    };
  }

  return { startAgentInternal };
}
