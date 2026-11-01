/**
 * The exclusivity check every request passes through — M15D 001-DAEMON.
 *
 * Runs in the daemon's handler wrapper, BEFORE the handler, so no handler can forget it:
 * 1. the caller is resolved from the socket (C1/C2) — a refused caller never reaches a handler;
 * 2. for the five calls that act AS an agent (send, receive, close, initiate, await), the agent is
 *    resolved the same way the handler will resolve it, then:
 *    - an agent that is not online is refused `agent_offline` (start it first; nothing auto-starts);
 *    - an agent another caller holds is refused `agent_held`, or `agent_displaced` the first time
 *      for a caller that was forced out. The way back is `cello_use_agent` with `force: true`;
 *    - a receive or await that proceeds counts as the caller waiting — the agent is reachable for
 *      exactly as long as it runs.
 * Reads (transcript, sessions, inbox, agents, status) are never refused here.
 *
 * The Hermes cello bridge is a listener: it is never refused and never holds.
 */
import { resolveCurrentAgentFor } from "./agent-selection.js";
import { resolveCaller } from "./caller-identity.js";
import type { Caller, HolderRegistry } from "./holder-registry.js";
import type { Logger } from "./types.js";

export const GUARDED_METHODS: ReadonlySet<string> = new Set([
  "cello_send", "cello_receive", "cello_close_session", "cello_initiate_session", "cello_await_session",
]);
const WAITING_METHODS: ReadonlySet<string> = new Set(["cello_receive", "cello_await_session"]);

export type Admission =
  | { ok: true; caller: Caller; finish: () => void }
  | { ok: false; response: Record<string, unknown> };

export interface AttendanceGuardDeps {
  logger: Logger;
  registry: HolderRegistry;
  onlineAgents: ReadonlySet<string>;
  getConnState: (connectionId: string) => { currentAgent: string | null; clearedAgent?: string; clientType?: string } | undefined;
  /** Agents this daemon knows (loaded). An unknown name is left to the handler's own refusal. */
  isKnownAgent: (agentName: string) => boolean;
}

export function createAttendanceGuard(deps: AttendanceGuardDeps) {
  const { logger, registry, onlineAgents, getConnState, isKnownAgent } = deps;

  function admit(method: string, params: Record<string, unknown> | undefined, connectionId: string, rawCaller: unknown): Admission {
    const connState = getConnState(connectionId);
    // The hello itself declares what the socket is; it cannot be judged by what it is declaring.
    const resolved = method === "ipc.connect"
      ? resolveCaller(connState, connectionId, undefined)
      : resolveCaller(connState, connectionId, rawCaller);
    if (!resolved.ok) {
      logger.warn("daemon.ipc.caller.refused", {
        connectionId, method, reason: resolved.reason, clientType: connState?.clientType ?? "unknown",
      });
      return { ok: false, response: { ok: false, reason: resolved.reason, guidance: resolved.guidance } };
    }
    const caller = resolved.caller;

    // An endpoint socket keeps no selection of its own: the caller's hold is its selection.
    if (connState && connState.clientType === "endpoint") {
      connState.currentAgent = registry.heldBy(caller.key) ?? null;
    }

    if (!GUARDED_METHODS.has(method) || connState?.clientType === "hermes") {
      return { ok: true, caller, finish: () => {} };
    }

    const explicit = typeof params?.["agent"] === "string" ? (params["agent"] as string) : undefined;
    const agent = resolveCurrentAgentFor({ connState, onlineAgents, ...(explicit ? { explicitAgent: explicit } : {}) });
    if (!agent || !isKnownAgent(agent)) return { ok: true, caller, finish: () => {} };

    if (!onlineAgents.has(agent)) {
      logger.warn("agent.attend.refused", { connectionId, method, agentName: agent, reason: "agent_offline", callerLabel: caller.label });
      return {
        ok: false,
        response: {
          ok: false,
          reason: "agent_offline",
          agent,
          guidance: `'${agent}' is offline, so nothing was done. Start it with cello_start_agent, then retry.`,
        },
      };
    }

    const check = registry.check(agent, caller);
    if (!check.ok) {
      logger.warn("agent.attend.refused", {
        connectionId, method, agentName: agent, reason: check.reason,
        holderLabel: check.holder.label, callerLabel: caller.label,
      });
      const what = check.reason === "agent_displaced"
        ? `'${agent}' was taken over by ${check.by_label}. This session no longer holds it, so nothing was done.`
        : `'${agent}' is being used by ${check.holder.label} (since ${check.holder.since}, last active ${check.holder.last_active}), so nothing was sent, read or closed.`;
      return {
        ok: false,
        response: {
          ok: false,
          reason: check.reason,
          agent,
          holder: check.holder,
          ...(check.reason === "agent_displaced" ? { by_label: check.by_label } : {}),
          guidance: `${what} To take it over, call cello_use_agent with name '${agent}' and force: true (cello use-agent --force) — ${check.holder.label} will be told. Or act as a different agent.`,
        },
      };
    }

    registry.touch(agent, caller);
    const finish = WAITING_METHODS.has(method) ? registry.beginWait(agent, caller, connectionId) : () => {};
    return { ok: true, caller, finish };
  }

  return { admit };
}
