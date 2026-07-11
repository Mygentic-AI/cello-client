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

/**
 * `cello_*` identifiers that are NOT tools and must never be mistaken for one.
 *
 * `cello_message` is the doorbell NOTIFICATION frame type (and the stem of the
 * `notification.cello_message.dispatch.failed` log event). It is wire vocabulary and log taxonomy,
 * never a command an operator could run — so the audit must recognise it rather than demand it be
 * renamed to a tool that would not exist.
 */
export const NON_TOOL_IDENTIFIERS: readonly string[] = ["cello_message"];

/** Every `cello_*` token the daemon is ALLOWED to name in guidance. Anything else is a bug. */
export function knownToolNames(): ReadonlySet<string> {
  return new Set([
    ...DUAL_SURFACE_VERBS.map((v) => v.mcp),
    ...MCP_ONLY_TOOLS,
    ...NON_TOOL_IDENTIFIERS,
  ]);
}

/**
 * CLI verbs that NO LONGER EXIST (DOD-ONBOARD-HELP-1 §2, clean renames — no aliases).
 *
 * Why this list exists as well as the tool audit: the tool audit matches `cello_*` tokens, so it is
 * structurally BLIND to a dead *CLI* verb — `cello register` is just prose to it. That blindness is
 * exactly how three dead-command instructions survived a green build in the first cut of this story
 * (the missing-token onboarding error, an unregistered-agent warning, and relay-receipts' own usage
 * line all still said `cello register` / `cello receipts`). A user handed a command that does not
 * dispatch is worse off than one handed nothing.
 *
 * Anchoring is by NEGATIVE LOOKAHEAD, not a trailing space — see deadCliVerbPattern() for why the
 * space failed.
 */
export const DEAD_CLI_VERBS: readonly string[] = [
  "cello register",
  "cello install",
  "cello receipts",
  "cello close",
  "cello initiate",
  // DELETED outright (Andre, 2026-07-11), not renamed — there is no replacement to point at. It was
  // a literal alias of `cello receive` (the daemon ran the SAME handler) whose help claimed an
  // accept/join step CELLO does not have. Listed here so no string can quietly offer it again.
  "cello receive-session",
];

/**
 * The pre-§3 flat contact shape: `cello contact <op> <pubkey>`. The arguments are REVERSED now
 * (`cello contact <pubkey> <op>`), so these are not merely renamed — following one silently targets
 * a contact named "add". In the live shape an OP can never follow `contact` directly; a pubkey does.
 */
const DEAD_CONTACT_OPS = ["list", "add", "remove", "tier", "away", "set-tier", "set-away", "set-moniker"];

/**
 * Match any dead CLI verb, wherever it is SPOKEN — the one regex both audits share.
 *
 * The negative lookahead `(?![-\w])` is what makes this work, and the first cut got it wrong: it
 * anchored on a trailing SPACE (`"cello register "`), which review broke immediately — a verb
 * followed by a quote, period, backtick, paren or comma slipped straight through, and a live string
 * (`'cello register'`, in the Hermes plugin scaffolded onto the operator's disk) was sailing past a
 * green audit. An audit defeated by a full stop is not an audit.
 *
 * The lookahead still lets the LIVE commands through, because each dead verb is a strict prefix of
 * its replacement: `cello register-agent`, `cello close-session`, `cello initiate-session` all have
 * a `-` right where the lookahead refuses one.
 */
export function deadCliVerbPattern(): RegExp {
  const verbs = DEAD_CLI_VERBS.map((v) => v.replace(/^cello /, "")).join("|");
  const ops = DEAD_CONTACT_OPS.join("|");
  return new RegExp(`cello\\s+(?:${verbs})(?![-\\w])|cello\\s+contact\\s+(?:${ops})(?![-\\w])`, "g");
}

/**
 * MCP tool names this story RENAMED AWAY. Nothing may hand one of these to an agent again.
 *
 * Distinct from `knownToolNames()` (an allowlist: "every cello_* token must be in the table"). That
 * allowlist works inside the daemon, where every `cello_*` token IS a tool name — but it cannot be
 * used across the CLI package, where `cello_*` tokens are also IPC WIRE method names
 * (`client.send("cello_list_agents")`, which deliberately do not move) and, in the scaffolded Hermes
 * assets, plain config identifiers (`cello_socket_path`, `cello_dir`). An allowlist there would
 * either drown in false positives or be so riddled with exceptions it stopped meaning anything.
 *
 * So outside the daemon we assert the DENYLIST instead: whatever else a string says, it must not
 * name a tool we deleted. That is precisely the regression that shipped — the Hermes `platform_hint`
 * told the operator's agent to call `cello_check_notifications` and `cello_list_sessions` after both
 * had ceased to exist.
 */
export const RENAMED_AWAY_TOOLS: readonly string[] = [
  // DELETED outright (Andre, 2026-07-11), not renamed: cello_receive_session was a literal alias of
  // cello_receive — the same daemon handler — whose help claimed an accept/join step that does not
  // exist. There is no replacement to point at; the capability was never real.
  "cello_receive_session",
  "cello_list_agents",
  "cello_list_sessions",
  "cello_check_notifications",
  "cello_get_transcript",
  "cello_get_sealed_receipt",
  "cello_set_moniker",
  "cello_contact_list",
];

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
/**
 * Instructions that carry ARGUMENTS, not just a name — rewritten whole, before the token pass.
 *
 * Renaming the tool is not enough when the instruction is a CALL. `cello inbox`'s rename notice ends
 * with a literal, copy-pasteable invocation:
 *
 *     Adopt it: cello_contact_set_moniker { pubkey: "abcd…", moniker: "Zoe" }, or ignore.
 *
 * Rewriting only the token gave a CLI operator `cello contact <pubkey> set-moniker { pubkey: "abcd…",
 * moniker: "Zoe" }` — the tool's name with the tool's JSON still bolted on, and a literal `<pubkey>`
 * placeholder next to the real key. It looks like a command and is not one; pasting it now trips the
 * invalid_pubkey gate. Half a translation is its own kind of wrong answer.
 *
 * So the call form is translated as a unit, arguments and all, and the result is a line the operator
 * can actually paste. Run BEFORE the token pass, which would otherwise have already eaten the name.
 */
const CALL_FORMS: ReadonlyArray<{ re: RegExp; cli: (m: RegExpExecArray) => string }> = [
  {
    re: /cello_contact_set_moniker\s*\{\s*pubkey:\s*"([^"]*)",\s*moniker:\s*"([^"]*)"\s*\}/g,
    cli: (m) => `cello contact ${m[1]} set-moniker "${m[2]}"`,
  },
];

export function toCliGuidance(text: string): string {
  let out = text;
  for (const { re, cli } of CALL_FORMS) {
    out = out.replace(new RegExp(re.source, re.flags), (...args) => cli(args as unknown as RegExpExecArray));
  }
  for (const { mcp, cli } of CLI_BY_MCP) {
    // Word-boundary on the tail: `cello_agents` must not match inside `cello_agents_foo`.
    out = out.replace(new RegExp(`${mcp}(?![a-z_])`, "g"), cli);
  }
  return out;
}

/** The client surfaces the daemon renders guidance for. Recorded per connection at `ipc.connect`. */
export type ClientSurface = "cli" | "mcp";

/**
 * The response keys that carry an INSTRUCTION TO A HUMAN — the ones that name a command to run.
 *
 * `reason` is deliberately absent and must stay absent: it is a machine-readable code that scripts
 * branch on (`reason === "session_not_current"`). Rewriting it would silently break every caller.
 */
const INSTRUCTION_KEYS = new Set(["guidance", "warning_guidance", "notice"]);

/**
 * Render a handler's response for the surface that asked.
 *
 * Applied ONCE, at the IPC response boundary (daemon.ts wraps every handler), so a new handler
 * cannot forget it and a new guidance string cannot drift. MCP callers get the response verbatim —
 * the source strings already hold the canonical MCP names.
 *
 * RECURSES into nested objects and arrays. The first cut only rewrote a TOP-LEVEL `guidance`, which
 * left real instructions per-surface-wrong: `cello inbox`'s rename notices live at
 * `agents[i].rename_notices[j].notice` and told a CLI operator to call `cello_contact_set_moniker`
 * with JSON arguments — a thing they cannot type. A choke point that only covers the easy shape is
 * not a choke point; it just moves the leak somewhere less visible.
 */
export function renderForSurface(result: unknown, surface: ClientSurface): unknown {
  if (surface === "mcp") return result;
  return renderCli(result);
}

function renderCli(value: unknown): unknown {
  if (Array.isArray(value)) {
    let changed = false;
    const out = value.map((v) => {
      const r = renderCli(v);
      if (r !== v) changed = true;
      return r;
    });
    return changed ? out : value;
  }
  if (value === null || typeof value !== "object") return value;

  const record = value as Record<string, unknown>;
  let changed = false;
  const out: Record<string, unknown> = {};
  for (const [key, v] of Object.entries(record)) {
    let next: unknown = v;
    if (INSTRUCTION_KEYS.has(key) && typeof v === "string") {
      next = toCliGuidance(v);
    } else if (v !== null && typeof v === "object") {
      next = renderCli(v);
    }
    if (next !== v) changed = true;
    out[key] = next;
  }
  // Identity-preserving when nothing changed — the MCP path and untouched CLI payloads keep the
  // exact object the handler returned, so nothing downstream can depend on an incidental copy.
  return changed ? out : value;
}
