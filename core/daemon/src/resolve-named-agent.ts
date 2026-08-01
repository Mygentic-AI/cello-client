/**
 * One guard for "the caller named an agent" — shared, so the third copy never gets written.
 *
 * DOD-INBOX-AGENT-1 closed a defect where `cello_check_notifications` accepted an `agent` parameter
 * and silently dropped it, answering as whatever agent the CONNECTION held. Reviewing that fix found
 * the same shape in three more places, including the one next door in `contact-handlers.ts`, where
 * it is worse because that path WRITES: `cello_contact_add({ agent: "", pubkey })` fell through to
 * the connection's selection and filed the contact under the wrong desk, and `{ agent: "carol" }`
 * with no carol wrote a row keyed to an agent that does not exist. Both `ok: true`.
 *
 * The three ways a named agent goes wrong, and why each must REFUSE rather than fall back:
 *
 *  1. **A non-string** (`{ agent: 123 }`). MCP callers are shielded by zod; direct-IPC callers are
 *     not. §5a is explicit that unreachability is a property of today's call graph, not of the code.
 *  2. **An empty string.** `""` is falsy but not nullish, so a bare truthiness test reads it as "no
 *     name given" and runs as the connection's selection — the exact misroute, reintroduced through
 *     the guard meant to prevent it. `{ agent: someUnsetVar }` produces it, and so does an
 *     unsubstituted `<exact name>` placeholder in a prompt.
 *  3. **A name that is not here.** Falling back answers a question about carol with alice's data.
 *
 * And one that is NOT "not found": an agent whose identity FAILED TO LOAD exists. Saying "does not
 * exist" sends the operator to `cello_agents`, which filters `load_failed` out — so they see nothing,
 * confirm the wrong diagnosis, and never reach `cello_status`, which would have shown the real error.
 * That is an exit-point label standing in for the cause.
 */

/** Agent-name length cap, matching the moniker convention — the name is echoed back into guidance. */
const MAX_NAME_ECHO = 64;

export interface NamedAgentRefusal {
  ok: false;
  reason: "invalid_agent_value" | "missing_agent_value" | "agent_not_found" | "agent_load_failed";
  guidance: string;
}

/** What the resolver needs to know about the agents on this machine. */
export interface KnownAgent {
  name: string;
  state?: string;
  error?: string;
}

/** Truncate a caller-supplied name before echoing it into an operator-facing string. */
function echoName(name: string): string {
  return name.length <= MAX_NAME_ECHO ? name : `${name.slice(0, MAX_NAME_ECHO)}…`;
}

/**
 * Validate an explicitly-named agent.
 *
 * Returns `{ ok: true, agent }` when the caller named a real agent, `{ ok: true, agent: null }` when
 * the caller named NOTHING (so the caller should fall back to its own connection-scoped resolution),
 * and a refusal otherwise. The three-way return is the point: "named nothing" and "named something
 * unusable" are different, and collapsing them is the whole defect class.
 */
export function resolveNamedAgent(
  rawAgent: unknown,
  known: ReadonlyArray<KnownAgent>,
): { ok: true; agent: string | null } | NamedAgentRefusal {
  if (rawAgent === undefined || rawAgent === null) return { ok: true, agent: null };

  if (typeof rawAgent !== "string") {
    return {
      ok: false,
      reason: "invalid_agent_value",
      guidance: `The 'agent' parameter must be an agent name (a string), but got ${Array.isArray(rawAgent) ? "an array" : typeof rawAgent}. Nothing was read or written. Pass the name, or omit 'agent' to use this connection's current agent.`,
    };
  }

  if (rawAgent.trim() === "") {
    return {
      ok: false,
      reason: "missing_agent_value",
      guidance: "The 'agent' parameter was empty (an unset variable, or an unsubstituted placeholder?). Nothing was read or written — an empty name is NOT treated as 'no agent given', because that would silently run as whichever agent this connection happens to hold. Name an agent, or omit 'agent' entirely.",
    };
  }

  const match = known.find((a) => a.name === rawAgent);
  if (!match) {
    return {
      ok: false,
      reason: "agent_not_found",
      guidance: `Agent '${echoName(rawAgent)}' does not exist on this machine, so nothing was read or written. Check the name with cello_agents, or omit 'agent' to use this connection's current agent.`,
    };
  }

  // It EXISTS but its identity could not be loaded. Reported as itself: cello_agents hides
  // load_failed agents, so "does not exist" would send the operator to the one surface that
  // confirms the wrong answer. cello_status shows the state and the underlying error.
  if (match.state === "load_failed") {
    return {
      ok: false,
      reason: "agent_load_failed",
      guidance: `Agent '${echoName(rawAgent)}' exists but its identity failed to load, so nothing was read or written${match.error ? ` (${match.error})` : ""}. Run cello_status to see the error — note cello_agents omits agents in this state, so it will look like the agent is missing.`,
    };
  }

  return { ok: true, agent: rawAgent };
}
