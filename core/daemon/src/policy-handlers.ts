/**
 * 008-POLICY — the IPC surface for the operator's policies (amended 2026-09-28: the agent proposes,
 * the operator approves).
 *
 * `cello_policy_list`, `cello_policy_pending` and `cello_policy_propose` answer any surface; a
 * proposal is stored pending and changes nothing. `cello_policy_approve` / `cello_policy_decline`
 * answer only a connection that handshook as `cli`, and the CLI asks only at an interactive
 * terminal — so a hijacked agent can draft a change but never put one in force. There is no MCP
 * approve tool; this refusal is the daemon's half of that.
 */
import type { IpcHandler } from "./ipc-server.js";
import type { SessionNodeManager } from "./session-node-manager.js";
import type { ConnState } from "./contact-handlers.js";
import type { Logger } from "./types.js";
import { PolicyValidationError, POLICY_TYPES, type PolicyScope, type PolicyType, type PolicyValue } from "./policy-store.js";
import { PolicyProposals } from "./policy-proposals.js";
import { SETTABLE_TIER_NAMES } from "./agent-settings-keys.js";
import { ChannelSubscriptionStore } from "./channel-subscription-store.js";
import { extractErrorMessage } from "./error-message.js";

export interface PolicyHandlerDeps {
  handlers: Map<string, IpcHandler>;
  logger: Logger;
  sessionNodeManager: SessionNodeManager;
  getConnState: (connectionId: string) => ConnState | undefined;
  resolveCurrentAgent: (connState: ConnState | undefined, explicitAgent?: string) => string | null;
  NO_CURRENT_AGENT_RESPONSE: unknown;
  getClientType: (connectionId: string) => string | undefined;
}

const approveCommand = (id?: string): string => `cello policy approve${id ? ` ${id}` : ""}`;

const TERMINAL_ONLY = {
  ok: false,
  reason: "policy_approve_terminal_only",
  guidance:
    "Only your operator can approve or decline a policy change, at a terminal, after reading the " +
    `exact text. Ask them to run \`${approveCommand()}\`.`,
};

export function registerPolicyHandlers(deps: PolicyHandlerDeps): void {
  const { handlers, logger, sessionNodeManager: snm, getConnState, resolveCurrentAgent, NO_CURRENT_AGENT_RESPONSE, getClientType } = deps;

  let proposals: PolicyProposals | null = null;
  const props = (): PolicyProposals => (proposals ??= new PolicyProposals(snm.getDb(), logger, snm.getPolicyStore()));

  const agentFor = (params: Record<string, unknown> | undefined, connectionId: string): string | null =>
    resolveCurrentAgent(getConnState(connectionId), params?.["agent"] as string | undefined);

  const refusal = (err: unknown) => err instanceof PolicyValidationError
    ? { ok: false, reason: err.reason, guidance: err.message }
    : { ok: false, reason: "policy_store_failed", guidance: `The policy store could not be read or written: ${extractErrorMessage(err)}` };

  /** Wraps a handler that needs the current agent and turns a store throw into a named refusal. */
  const withAgent = (fn: (agentName: string, agentId: string, params: Record<string, unknown> | undefined, connectionId: string) => unknown): IpcHandler =>
    (params, connectionId) => {
      const agentName = agentFor(params, connectionId);
      if (!agentName) return Promise.resolve(NO_CURRENT_AGENT_RESPONSE);
      try {
        return Promise.resolve(fn(agentName, snm.resolveAgentId(agentName), params, connectionId));
      } catch (err: unknown) {
        return Promise.resolve(refusal(err));
      }
    };

  const terminalOnly = (fn: IpcHandler): IpcHandler => (params, connectionId) => {
    if (getClientType(connectionId) !== "cli") {
      logger.warn("policy.approve.refused", { connectionId, surface: getClientType(connectionId) ?? "unknown" });
      return Promise.resolve(TERMINAL_ONLY);
    }
    return fn(params, connectionId);
  };

  handlers.set("cello_policy_propose", withAgent((agentName, agentId, params, connectionId) => {
    const action = params?.["action"] === "clear" ? "clear" : "set";
    const value: PolicyValue = params?.["none"] === true
      ? { mode: "none" }
      : { mode: "text", text: typeof params?.["text"] === "string" ? params["text"] : "" };
    const everyN = params?.["every_n"] === undefined ? undefined : Number(params["every_n"]);
    const p = props().propose(agentId, {
      scope: String(params?.["scope"] ?? "") as PolicyScope,
      target: typeof params?.["target"] === "string" ? params["target"] : "",
      type: String(params?.["type"] ?? "") as PolicyType,
      action, ...(action === "set" ? { value } : {}), ...(everyN !== undefined ? { everyN } : {}),
    }, getClientType(connectionId) === "cli" ? "operator" : "agent");
    return {
      ok: true, agent: agentName, ...p, in_force: false,
      approve_command: approveCommand(p.proposal_id),
      guidance:
        "This only drafts. Nothing changes until your operator runs " +
        `\`${approveCommand(p.proposal_id)}\` at a terminal and reads the text. Tell them the command.`,
    };
  }));

  handlers.set("cello_policy_pending", withAgent((agentName, agentId) => {
    const now = Date.now();
    return {
      ok: true, agent: agentName,
      pending: props().pending(agentId).map((p) => ({ ...p, age_ms: now - p.created_at })),
      guidance: `Pending changes are not in force. Your operator approves each at a terminal: ${approveCommand()}`,
    };
  }));

  handlers.set("cello_policy_approve", terminalOnly(withAgent((agentName, agentId, params) => {
    const r = props().approve(agentId, String(params?.["proposal_id"] ?? ""));
    return r.ok ? { ok: true, agent: agentName, applied: r.proposal } : { ...r, guidance: "No pending proposal has that id (it may have expired after 24 hours). See: cello policy pending" };
  })));

  handlers.set("cello_policy_decline", terminalOnly(withAgent((agentName, agentId, params) => {
    const id = String(params?.["proposal_id"] ?? "");
    return props().decline(agentId, id)
      ? { ok: true, agent: agentName, declined: id }
      : { ok: false, reason: "proposal_not_found", guidance: "No pending proposal has that id. See: cello policy pending" };
  })));

  handlers.set("cello_policy_list", withAgent((agentName, agentId) => {
    const store = snm.getPolicyStore();
    const brief = (r: { level: string; text: string } | null) => (r ? { level: r.level, text: r.text } : null);
    // Which level wins for a peer with no contact row, per tier; and per followed channel.
    const tiers = Object.fromEntries(SETTABLE_TIER_NAMES.map((t) => [
      t, Object.fromEntries(POLICY_TYPES.map((ty) => [ty, brief(store.resolveSession(agentId, ty, "", t))])),
    ]));
    const channels = Object.fromEntries(new ChannelSubscriptionStore(snm.getDb(), logger).listedFor(agentId)
      .map((s) => [s.channel_pubkey, brief(store.resolveChannel(agentId, s.channel_pubkey))]));
    return {
      ok: true, agent: agentName, policies: store.list(agentId), winning: { tiers, channels },
      guidance: "What is in force. To change it, propose (cello policy propose) and have the operator approve at a terminal (cello policy approve).",
    };
  }));
}
