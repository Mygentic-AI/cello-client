/**
 * DOD-ONBOARD-HELP-1 §2b — the ONE vocabulary.
 *
 * A capability has exactly one name, and that name renders differently on each surface:
 *
 *     capability "agents"  →  MCP tool `cello_agents`  ·  CLI command `cello agents`
 *
 * The rule (Andre, 2026-07-11): **an MCP tool's name is `cello_` + the CLI command name**,
 * snake_cased, keeping any sub-verb. Humans and agents learn a capability ONCE.
 *
 * Why this table exists rather than three lists of string literals:
 *
 *  - the CLI registry names its commands,
 *  - the connect shim names its MCP tools,
 *  - and the DAEMON names them BACK to you in ~50 error-guidance strings.
 *
 * That third one is the trap. The daemon is where a new user actually MEETS these names — a
 * refused send says "call cello_receive first". Rename the tools without touching the daemon and
 * every one of those strings points at a tool that no longer exists: an error message that hands
 * you a wrong instruction is worse than no error message. So the names live HERE, once, and the
 * daemon RENDERS them for whichever surface is asking (it knows: `clientType` is recorded at
 * `ipc.connect`). A CLI caller is told `cello use-agent`; an MCP caller is told `cello_use_agent`.
 *
 * Enforced by dod-onboard-help-1-vocabulary.test.ts:
 *  - every entry obeys the `cello_` + command rule (no hand-typed exceptions),
 *  - every `cello_*` token in a daemon guidance string resolves here (a stale/typo'd name FAILS
 *    the build rather than shipping a dead instruction),
 *  - the CLI registry's command names == the CLI names here,
 *  - the connect shim's tool names == the MCP names here.
 */

/** A capability reachable from BOTH surfaces. `mcp` is the tool name; `cli` is the command line. */
export interface DualSurfaceVerb {
  mcp: string;
  cli: string;
}

/**
 * Every capability with BOTH an MCP tool and a CLI command. Guidance naming one of these is
 * rendered per caller.
 *
 * The `cli` string is what an operator would TYPE, so per-contact ops carry the `<pubkey>`
 * placeholder — the CLI shape is `cello contact <pubkey> set-tier`, not `cello contact-set-tier`.
 */
export const DUAL_SURFACE_VERBS: readonly DualSurfaceVerb[] = [
  // Agents
  { mcp: "cello_agents", cli: "cello agents" },
  { mcp: "cello_start_agent", cli: "cello start-agent" },
  { mcp: "cello_stop_agent", cli: "cello stop-agent" },
  { mcp: "cello_use_agent", cli: "cello use-agent" },
  { mcp: "cello_status", cli: "cello status" },
  // Messaging
  { mcp: "cello_initiate_session", cli: "cello initiate-session" },
  { mcp: "cello_await_session", cli: "cello await-session" },
  { mcp: "cello_close_session", cli: "cello close-session" },
  { mcp: "cello_send", cli: "cello send" },
  { mcp: "cello_receive", cli: "cello receive" },
  // `receive_session` is a literal ALIAS of `receive` — the daemon registers the SAME handler
  // object for both (`handlers.set("cello_receive_session", handleReceive)`). It does not accept
  // or join anything; inbound sessions are auto-accepted by the standing receiver. Its help said
  // "Accept / join an inbound session request", which was simply false. Pending Andre's ruling to
  // DELETE it (no-aliases doctrine); until then it is described for what it actually is.
  { mcp: "cello_receive_session", cli: "cello receive-session" },
  { mcp: "cello_inbox", cli: "cello inbox" },
  // Sessions & receipts
  { mcp: "cello_sessions", cli: "cello sessions" },
  { mcp: "cello_transcript", cli: "cello transcript" },
  { mcp: "cello_sealed_receipt", cli: "cello sealed-receipt" },
  // Contacts
  { mcp: "cello_contacts", cli: "cello contacts" },
  { mcp: "cello_contact_add", cli: "cello contact <pubkey> add" },
  { mcp: "cello_contact_remove", cli: "cello contact <pubkey> remove" },
  { mcp: "cello_contact_set_tier", cli: "cello contact <pubkey> set-tier" },
  { mcp: "cello_contact_set_away", cli: "cello contact <pubkey> set-away" },
  { mcp: "cello_contact_set_moniker", cli: "cello contact <pubkey> set-moniker" },
  // Other
  { mcp: "cello_moniker", cli: "cello moniker" },
  { mcp: "cello_settings_get", cli: "cello settings get" },
  { mcp: "cello_settings_set", cli: "cello settings set" },
];

/**
 * Tools that exist ONLY on the MCP surface. They are the DOD-CUSTODY-DAEMON-1 stubs — the daemon
 * handlers return `not_implemented`, so there is deliberately no CLI command to build a second
 * broken path to. Listed so the audit test can tell "known MCP-only" from "stale name".
 */
export const MCP_ONLY_TOOLS: readonly string[] = [
  "cello_backup",
  "cello_restore",
  "cello_get_inclusion_proof",
];

/** Every `cello_*` token the daemon is ALLOWED to name in guidance. Anything else is a bug. */
export function knownToolNames(): ReadonlySet<string> {
  return new Set([...DUAL_SURFACE_VERBS.map((v) => v.mcp), ...MCP_ONLY_TOOLS]);
}

/** Longest-first, so `cello_contact_set_moniker` is matched before a hypothetical `cello_contact`. */
const CLI_BY_MCP: ReadonlyArray<DualSurfaceVerb> = [...DUAL_SURFACE_VERBS].sort(
  (a, b) => b.mcp.length - a.mcp.length,
);

/**
 * Rewrite MCP tool names in a guidance string into the CLI verbs an operator would type.
 *
 * Only `cello_*` tokens in DUAL_SURFACE_VERBS are rewritten. An MCP-only tool has no CLI verb to
 * offer, so it is left alone — inventing one would send the operator to a command that does not
 * exist, which is the exact failure this whole mechanism prevents.
 */
export function toCliGuidance(text: string): string {
  let out = text;
  for (const { mcp, cli } of CLI_BY_MCP) {
    // Word-boundary on the tail: `cello_agents` must not match inside `cello_agents_foo`.
    out = out.replace(new RegExp(`${mcp}(?![a-z_])`, "g"), cli);
  }
  return out;
}

/** The client surfaces the daemon renders guidance for. Recorded per connection at `ipc.connect`. */
export type ClientSurface = "cli" | "mcp";

/**
 * Render a handler's response for the surface that asked.
 *
 * Applied ONCE, at the IPC response boundary (daemon.ts wraps every handler), so a new handler
 * cannot forget it and a new guidance string cannot drift. MCP callers get the response verbatim —
 * the source strings already hold the canonical MCP names.
 *
 * Only the `guidance` field is touched. Never `reason` — that is a machine-readable code a script
 * branches on, and rewriting it would silently break every caller that switches on it.
 */
export function renderForSurface(result: unknown, surface: ClientSurface): unknown {
  if (surface === "mcp") return result;
  if (result === null || typeof result !== "object" || Array.isArray(result)) return result;
  const record = result as Record<string, unknown>;
  if (typeof record.guidance !== "string") return result;
  const rendered = toCliGuidance(record.guidance);
  if (rendered === record.guidance) return result;
  return { ...record, guidance: rendered };
}
