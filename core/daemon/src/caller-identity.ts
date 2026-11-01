/**
 * Who is making this request — M15D 001-DAEMON, contract C1/C2.
 *
 * The caller is decided by the DAEMON from the socket, never by anything a client types:
 * - a socket that declared `clientType: "endpoint"` (the web endpoint) must carry an envelope
 *   `caller: { id, label }` on every request, set by the endpoint from the verified OAuth token →
 *   `endpoint:<id>`;
 * - the CLI (`clientType: "cli"`, or a plain `cello` command that sends no hello) → `cli:<host>`, one
 *   caller per machine, so `cello use-agent` in one command still holds in the next;
 * - every other socket (the plugin, Hermes) → `socket:<connectionId>`: the socket IS the caller.
 *
 * A `caller` on any socket that is not an endpoint is refused `caller_not_permitted`: otherwise any
 * local process could name itself someone else and walk past exclusivity. Missing, malformed and
 * empty share one refusal, `caller_missing`.
 */
import { AsyncLocalStorage } from "node:async_hooks";
import { hostname } from "node:os";
import type { Caller } from "./holder-registry.js";

export type CallerResolution =
  | { ok: true; caller: Caller }
  | { ok: false; reason: "caller_not_permitted" | "caller_missing"; guidance: string };

const LABELS: Record<string, string> = { mcp: "an MCP session", hermes: "the Hermes cello bridge" };

export function resolveCaller(
  connState: { clientType?: string } | undefined,
  connectionId: string,
  rawCaller: unknown,
  host: string = hostname(),
): CallerResolution {
  const clientType = connState?.clientType;
  if (clientType === "endpoint") {
    const c = rawCaller as { id?: unknown; label?: unknown } | null | undefined;
    if (!c || typeof c !== "object" || typeof c.id !== "string" || c.id === "" || typeof c.label !== "string") {
      return {
        ok: false,
        reason: "caller_missing",
        guidance: "This socket declared itself a web endpoint, so every request must carry caller: { id, label } from the verified token. The request was not run.",
      };
    }
    return { ok: true, caller: { key: `endpoint:${c.id}`, label: c.label || c.id } };
  }
  if (rawCaller !== undefined) {
    return {
      ok: false,
      reason: "caller_not_permitted",
      guidance: "Only a web endpoint (ipc.connect with clientType \"endpoint\") may name a caller. The request was not run.",
    };
  }
  if (clientType === undefined || clientType === "cli") return { ok: true, caller: { key: `cli:${host}`, label: "the cello CLI" } };
  return { ok: true, caller: { key: `socket:${connectionId}`, label: LABELS[clientType] ?? clientType } };
}

/** The caller of the request now running. Set per request by the daemon's handler wrapper. */
export const callerContext = new AsyncLocalStorage<Caller>();

/** Throws outside a request: a handler that cannot say who called it must not guess. */
export function currentCaller(): Caller {
  const caller = callerContext.getStore();
  if (!caller) throw new Error("currentCaller: no request context — this handler was invoked outside the IPC wrapper");
  return caller;
}
