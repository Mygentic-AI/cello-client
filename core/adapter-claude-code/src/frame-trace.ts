/**
 * Inbound JSON-RPC frame trace — what the MCP CLIENT actually sent us.
 *
 * Written for a failure this repo could not otherwise see: a Claude Cowork session reaching
 * cello-mcp through Anthropic's `mcp__remote-devices__*` bridge had every `session_id`-carrying
 * tool call rejected by the SDK's own schema validation ("expected string, received undefined")
 * while the operator passed a correct id every time. Calls with no `session_id` — including ones
 * with other required string args — went through untouched.
 *
 * The SDK validates `arguments` against the tool's zod shape BEFORE any handler of ours runs, so by
 * the time cello-mcp has control the evidence is already gone: we see a validation error, never the
 * frame that caused it. This module summarizes the raw frame at the transport seam, which is the
 * only place the distinction survives:
 *
 *   - `arguments` absent entirely  → the client dropped the whole argument object
 *   - `arguments` present, key gone → the client dropped or renamed that ONE key
 *   - key present, value empty/null → the client forwarded a hollowed-out value
 *
 * Those three have the same downstream symptom and completely different causes, which is why the
 * bridge failure above stalled on inference. Off unless CELLO_MCP_TRACE=1: a trace of every frame
 * is a diagnostic tool, not a default.
 *
 * MESSAGE CONTENT NEVER RIDES. `content` — the only field that carries an operator's actual message
 * bytes — is recorded as a type-and-length stub, never verbatim. The trace answers "did the
 * parameter arrive", which needs the SHAPE of the call, not what was said in it. Every other value
 * is recorded as-is: a session id or pubkey is routing metadata, and a redacted one would defeat
 * the whole point of the trace.
 */

/** The one argument key that may hold message bytes. Recorded as a stub, never verbatim. */
const CONTENT_KEY = "content";

function stub(value: unknown): string {
  if (typeof value === "string") return `<string:${value.length} chars>`;
  return `<${value === null ? "null" : typeof value}>`;
}

export interface FrameTrace {
  event: "mcp.frame.received";
  /** JSON-RPC method, or null if the frame had none (malformed / notification shapes). */
  method: string | null;
  /** JSON-RPC id, when present — lets a trace line be paired with the response the client saw. */
  id?: string | number;
  /** tools/call only: the tool name. */
  tool?: string;
  /**
   * tools/call only: false when the client sent `params` with NO `arguments` member at all. This is
   * the single most load-bearing field here — it separates "dropped everything" from "dropped one
   * key", and no error the SDK produces distinguishes them.
   */
  hasArguments?: boolean;
  /** tools/call only: the argument keys as they actually arrived, in arrival order. */
  argKeys?: string[];
  /** tools/call only: the arguments, with `content` stubbed. */
  args?: Record<string, unknown>;
}

/**
 * Summarize one inbound frame for the trace log.
 *
 * Total — never throws and never returns null. A frame we cannot parse is itself evidence (a
 * malformed client is exactly the kind of thing this trace exists to catch), so an unrecognized
 * shape is reported as such rather than swallowed.
 */
export function summarizeInboundFrame(msg: unknown): FrameTrace {
  if (typeof msg !== "object" || msg === null) {
    return { event: "mcp.frame.received", method: null };
  }
  const frame = msg as Record<string, unknown>;
  const method = typeof frame["method"] === "string" ? (frame["method"] as string) : null;
  const trace: FrameTrace = { event: "mcp.frame.received", method };

  const id = frame["id"];
  if (typeof id === "string" || typeof id === "number") trace.id = id;

  if (method !== "tools/call") return trace;

  const params = typeof frame["params"] === "object" && frame["params"] !== null
    ? (frame["params"] as Record<string, unknown>)
    : {};
  if (typeof params["name"] === "string") trace.tool = params["name"] as string;

  const rawArgs = params["arguments"];
  const hasArguments = typeof rawArgs === "object" && rawArgs !== null && !Array.isArray(rawArgs);
  trace.hasArguments = hasArguments;
  if (!hasArguments) return trace;

  const args = rawArgs as Record<string, unknown>;
  trace.argKeys = Object.keys(args);
  trace.args = Object.fromEntries(
    Object.entries(args).map(([k, v]) => [k, k === CONTENT_KEY ? stub(v) : v]),
  );
  return trace;
}
