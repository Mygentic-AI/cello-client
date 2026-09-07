/**
 * Which agent a call is FOR, and how a caller learns it fell back.
 *
 * One rule, in one place, because the alternative has already happened: several handlers each
 * deciding what "the current agent" means is how a call lands on an agent the operator did not
 * choose. The fallback notice rides an AsyncLocalStorage so an answer can carry WHY it fell back
 * without every caller having to thread it through.
 *
 * The registration guidance stayed in the root: it is written between this block and the agent
 * lifecycle handlers, and moving it would have meant moving the handler registration with it.
 */
import { AsyncLocalStorage } from "node:async_hooks";
import { resolveCurrentAgentFor } from "./agent-selection.js";
import type { Logger } from "./types.js";

export interface AgentSelectionDeps {
  logger: Logger;
  /** The live set — a copy would freeze at boot and the single-online-agent fallback would never fire. */
  onlineAgents: ReadonlySet<string>;
}

export function createAgentSelection(deps: AgentSelectionDeps) {
  const { logger, onlineAgents } = deps;

  // M8C-AUTOSTART-1 (F18): resolve which agent an agent-defaulting tool should act on for this
  // connection: an explicit { agent } wins; else the connection's current agent; else — when EXACTLY one
  // agent is online daemon-wide — that sole agent (removes the "why did it forget my agent" moment
  // after a /mcp reconnect). Two-or-more online with none selected stays ambiguous → null (the
  // caller returns no_current_agent), because guessing between peers would misroute.
  /**
   * Which agent does this call act as?
   *
   * An explicit { agent } wins, then this connection's selection. Only with NEITHER does the daemon fall back
   * to the sole online agent — a convenience for a caller that never chose, where "the online one"
   * cannot mean anyone else.
   *
   * The fallback is REFUSED for a connection whose selection was taken away (`clearedAgent`): it
   * chose an agent, that agent was stopped or retired, and the choice is gone. Falling back there
   * silently re-targets the next call at whoever else happens to be online — the caller asked for
   * alice, alice was stopped, and the work lands on bob reporting success. A lost intent is not the
   * same as no intent, and it must fail loud (no_current_agent) rather than be guessed at.
   */
  /**
   * Which agent this call acts as — `DOD-M15-SELECTION-1`, logic in `agent-selection.ts`.
   *
   * It used to end with `if (onlineAgents.size === 1) return [...onlineAgents][0]`, so a connection
   * that had selected nothing acted as whichever agent happened to be the only one online. On a
   * shared daemon that can be a DIFFERENT operator's agent, and a live MCP session was being bound
   * to an identity it never asked for.
   *
   * The resolution is now attributable: every path reports how it was reached, and `fallback` — the
   * one that was invisible — is logged at INFO. `DOD-M15-IPCVISIBLE-1`.
   */
  /**
   * The fallback notice owed to THIS REQUEST's response — `DOD-M15-SELECTION-1` clause 2.
   *
   * ─── Why an AsyncLocalStorage and not a per-connection map ─────────────────────────────────────
   *
   * The first cut keyed a `WeakMap` on the per-connection state object, so the notice belonged to
   * the CONNECTION and was read back at the response boundary. Review found that hands the notice to
   * whichever response finishes first, and Claude Code issues tool calls in parallel:
   *
   *   1. the agent calls `cello_receive` — nothing selected, so the fallback resolves and records
   *      the notice, then the handler BLOCKS for up to 30 s waiting for content;
   *   2. in the same turn it calls `cello_sessions {agent: "bob"}`, which names an agent explicitly
   *      and never falls back;
   *   3. `cello_sessions` returns first and takes the notice on its way out.
   *
   * Bob's response now says *"no agent was selected, so 'solo' was used"* — false, on the one call
   * that did name an agent — and `cello_receive`, the call that actually fell back, says nothing.
   * Exactly inverted.
   *
   * A notice is a fact about ONE CALL, so it is stored in that call's async context. The store is
   * created per request in `renderedHandlers` and dies with it, which also means a handler that
   * THROWS cannot leave a notice behind to attach itself to some later, unrelated response — the
   * other half of the same review finding.
   */
  const fallbackNoticeStore = new AsyncLocalStorage<{ notice?: Record<string, unknown> }>();

  function resolveCurrentAgent(
    connState: { currentAgent: string | null; clearedAgent?: string; clientType?: string } | undefined,
    explicitAgent?: string,
  ): string | null {
    return resolveCurrentAgentFor({
      connState,
      onlineAgents,
      ...(explicitAgent !== undefined ? { explicitAgent } : {}),
      onResolved: (agent, trigger) => {
        // Only the FALLBACK is announced. `explicit` and `selected` are the ordinary cases and
        // logging them would bury the one that matters — a signal that fires on the normal case is
        // not a signal.
        if (trigger !== "fallback") return;
        /**
         * RECORDED FOR THE RESPONSE, not just the log — `DOD-M15-SELECTION-1` clause 2.
         *
         * The log tells whoever reads the daemon log. The RESPONSE tells the agent that just acted
         * as an identity it never selected, which is the one that stops the half-attended state
         * being read as the protocol dropping messages.
         */
        /**
         * No `connState` guard. The first cut wrote the notice only `if (agent && connState)`, and
         * `perConnectionState` is populated at `ipc.connect` — which `withIpc` in the CLI
         * (`core/cli/src/commands.ts`) does not send. So every plain `cello` invocation fell back
         * and got a response that said nothing, while the log line below fired regardless: the
         * clause asks for explicit IN THE RESPONSE, and those callers had it explicit in the log
         * only. The store is per-REQUEST, so it exists whether or not the connection ever
         * handshook.
         */
        const store = fallbackNoticeStore.getStore();
        if (agent && store) {
          store.notice = {
            acting_as: agent,
            agent_selection: "fallback",
            agent_selection_guidance:
              `No agent was selected on this connection, so '${agent}' was used because it is the ` +
              `only one online. This is a per-call subject, NOT an attendance: doorbells route by ` +
              `the connection's registered agent and this does not set it. Two things follow — ` +
              `this session will not WAKE on an incoming message even though sending and reading ` +
              `work, and anyone who opens a session with you is sent an AWAY auto-reply while you ` +
              `sit here able to answer. Run cello_use_agent to fix both. Naming the agent on each ` +
              `call is NOT a remedy for either: it settles which agent a call is about and leaves ` +
              `the connection just as unattended.`,
          };
        }
        logger.info("agent.current.fallback", {
          agentName: agent,
          clientType: connState?.clientType ?? "cli",
          impact:
            "this call had no selected agent and exactly one was online, so that one was used. It " +
            "is a per-call subject, NOT an attendance: doorbells route by the connection's " +
            "registered agent, which this does not set.",
          guidance:
            "If this was not the intended agent, name it explicitly, or run cello_use_agent to " +
            "select one for the connection.",
        });
      },
    });
  }

  return { fallbackNoticeStore, resolveCurrentAgent };
}
