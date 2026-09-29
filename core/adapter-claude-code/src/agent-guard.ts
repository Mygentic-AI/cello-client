/**
 * Which agents an HTTP endpoint may serve.
 *
 * The unit of identity is the agent's pubkey (from `cello_list_agents`), never its display name: a
 * name in a tool argument is resolved to a pubkey against a FRESH roster before it is compared, so a
 * renamed agent, or a name reused after retirement, cannot pass as a permitted one.
 */

import type { ToolProxy } from "./cello-tools.js";
import { logEvent, type LogFn } from "./shim-log.js";

export type AgentGuardReason = "agents_empty" | "agent_unknown" | "daemon_unreachable";

export class AgentGuardError extends Error {
  constructor(readonly reason: AgentGuardReason, message: string) {
    super(message);
    this.name = "AgentGuardError";
  }
}

interface RosterEntry { name: string; pubkey: string }

/** The daemon did not answer with a roster (it is down, or refused); `raw` is what it said instead. */
class RosterUnavailable extends Error {
  constructor(readonly raw: unknown) {
    super("agent roster unavailable");
  }
}

async function roster(proxy: ToolProxy): Promise<RosterEntry[]> {
  const out = (await proxy.call("cello_list_agents")) as { agents?: unknown } | undefined;
  if (!Array.isArray(out?.agents)) throw new RosterUnavailable(out);
  const list = out.agents as Array<Record<string, unknown>>;
  return list
    .filter((a) => typeof a["name"] === "string" && typeof a["pubkey"] === "string")
    .map((a) => ({ name: a["name"] as string, pubkey: (a["pubkey"] as string).toLowerCase() }));
}

/** Startup: turn the operator's names-or-pubkeys into a set of identities, or fail naming what is wrong. */
export async function resolvePermittedAgents(
  proxy: ToolProxy,
  entries: readonly string[],
): Promise<{ permitted: Set<string>; names: string[] }> {
  if (entries.length === 0) {
    throw new AgentGuardError("agents_empty", "an agent list was given but it is empty; name at least one agent, or omit it to serve all");
  }
  let existing: RosterEntry[];
  try {
    existing = await roster(proxy);
  } catch (e) {
    if (e instanceof RosterUnavailable) {
      throw new AgentGuardError("daemon_unreachable", `cannot check the agent list against the daemon: ${JSON.stringify(e.raw)}`);
    }
    throw e;
  }
  const permitted = new Set<string>();
  const unknown: string[] = [];
  for (const raw of entries) {
    const e = raw.trim();
    const hit = existing.find((a) => a.name === e || a.pubkey === e.toLowerCase());
    if (hit) permitted.add(hit.pubkey);
    else unknown.push(e);
  }
  if (unknown.length > 0) {
    throw new AgentGuardError(
      "agent_unknown",
      `unknown agent(s): ${unknown.join(", ")}. Agents this daemon has: ${existing.map((a) => a.name).join(", ") || "(none)"}`,
    );
  }
  return { permitted, names: existing.filter((a) => permitted.has(a.pubkey)).map((a) => a.name) };
}

/** The daemon methods whose `name` param names an AGENT; every other tool carries an optional `agent`. */
const NAME_KEYED_AGENT_METHODS = new Set(["cello_start_agent", "cello_set_agent_offline", "cello_use_agent"]);

export function guardProxy(inner: ToolProxy, permitted: ReadonlySet<string> | "all", log: LogFn = logEvent): ToolProxy {
  if (permitted === "all") return inner as ToolProxy;

  const refuse = async (asked: string, method: string): Promise<Record<string, unknown>> => {
    const names = (await roster(inner).catch(() => [] as RosterEntry[])).filter((a) => permitted.has(a.pubkey)).map((a) => a.name);
    log("mcp.http.agent.refused", { method, agent: asked });
    return {
      ok: false,
      reason: "agent_not_permitted",
      guidance: `This endpoint serves only: ${names.join(", ") || "(none currently)"}. "${asked}" is not one of them; the endpoint's operator chose that list at startup and it cannot be widened from here. Use one of the listed agents.`,
    };
  };

  return {
    async call(method, params) {
      const key = NAME_KEYED_AGENT_METHODS.has(method) ? "name" : "agent";
      const asked = params?.[key];
      if (typeof asked === "string") {
        try {
          const hit = (await roster(inner)).find((a) => a.name === asked || a.pubkey === asked.toLowerCase());
          if (!hit || !permitted.has(hit.pubkey)) return await refuse(asked, method);
        } catch (e) {
          // No roster means no identity to compare: refuse, and hand back the daemon's own answer
          // (daemon_not_running + its recovery) rather than masking it as a permission failure.
          if (e instanceof RosterUnavailable) return e.raw;
          throw e;
        }
      }
      const result = await inner.call(method, params);
      // Any answer carrying an agent roster is filtered, whichever tool produced it.
      if (result && typeof result === "object") {
        const r = result as { agents?: Array<Record<string, unknown>> };
        if (Array.isArray(r.agents)) {
          return { ...r, agents: r.agents.filter((a) => typeof a["pubkey"] === "string" && permitted.has((a["pubkey"] as string).toLowerCase())) };
        }
      }
      return result;
    },
  };
}

/**
 * A synchronous predicate for daemon doorbell frames, backed by a name→identity map taken from the
 * roster. A frame about an agent not in the map — or with no agent — is dropped (fail closed); the
 * recovery for a dropped doorbell is the inbox, which is how a missed push is recovered everywhere.
 */
export async function makeNotificationPermit(
  proxy: ToolProxy,
  permitted: ReadonlySet<string>,
  log: LogFn = logEvent,
): Promise<(frame: Record<string, unknown>) => boolean> {
  const entries = await roster(proxy).catch((e: unknown) => {
    if (e instanceof RosterUnavailable) return [] as RosterEntry[];
    throw e;
  });
  const allowedNames = new Set(entries.filter((a) => permitted.has(a.pubkey)).map((a) => a.name));
  return (frame) => {
    const data = (frame as { data?: Record<string, unknown> }).data ?? {};
    const agent = data["agent"];
    const ok = typeof agent === "string" && allowedNames.has(agent);
    if (!ok) log("mcp.http.notification.dropped", { agent: typeof agent === "string" ? agent : null });
    return ok;
  };
}
