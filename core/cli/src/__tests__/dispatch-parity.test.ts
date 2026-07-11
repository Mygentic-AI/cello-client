/**
 * DOD-CLI-PARITY-1 — two locks the earlier tests were missing (unit-review T1/T2):
 *
 * T2. The Phase 0 prove-point is "every existing command still behaves identically". Nothing tested
 *     that. The registry refactor MOVED each command's argument parsing out of a switch in
 *     bin/cello.ts (which read process.argv[3..5] directly) into a run() that reads args[0..2] — an
 *     index-translation refactor, the exact class of change that silently drops an argument. Without
 *     these tests every run() body could be `async () => ({stdout:"",stderr:"",exitCode:0})` and the
 *     suite would stay green. Here we drive spec.run() and assert the EXACT arguments forwarded to
 *     the command layer.
 *
 * T1. The `--pretty` grant (registry.flagsFor) is what lets a bash user format any parity command's
 *     output. It was only tested by a loop over jsonOut commands, which was vacuous while none
 *     existed. It is exercised directly here.
 *
 * Plus: the MCP↔CLI parity claim (DoD §9) is asserted from the registry's own ipcMethod field, so
 * "every cello_* tool has a CLI command calling the SAME handler" is checkable, not just asserted
 * in prose.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { CommandContext } from "../registry.js";

// Spy on the layer the registry delegates to. Both modules are mocked so no daemon is touched:
// this file tests WIRING (which function, which arguments), not behavior.
vi.mock("../commands.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../commands.js")>();
  return {
    ...actual,
    login: vi.fn(async () => ({ exitCode: 0, output: "ok" })),
    register: vi.fn(async () => ({ exitCode: 0, output: "ok" })),
    createAgent: vi.fn(async () => ({ exitCode: 0, output: "ok" })),
    removeAgent: vi.fn(async () => ({ exitCode: 0, output: "ok" })),
    refreshShares: vi.fn(async () => ({ exitCode: 0, output: "ok" })),
    relayReceipts: vi.fn(async () => ({ exitCode: 0, output: "ok" })),
    sessions: vi.fn(async () => ({ exitCode: 0, output: "ok" })),
    contactAdd: vi.fn(async () => ({ exitCode: 0, output: "ok" })),
    contactRemove: vi.fn(async () => ({ exitCode: 0, output: "ok" })),
    contactList: vi.fn(async () => ({ exitCode: 0, output: "ok" })),
    contactSetTier: vi.fn(async () => ({ exitCode: 0, output: "ok" })),
    contactSetAway: vi.fn(async () => ({ exitCode: 0, output: "ok" })),
    settingsGet: vi.fn(async () => ({ exitCode: 0, output: "ok" })),
    settingsSet: vi.fn(async () => ({ exitCode: 0, output: "ok" })),
    monikerSet: vi.fn(async () => ({ exitCode: 0, output: "ok" })),
    telegramSetToken: vi.fn(async () => ({ exitCode: 0, output: "ok" })),
  };
});

vi.mock("../parity-commands.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../parity-commands.js")>();
  const stub = () => vi.fn(async () => ({ stdout: "{}", stderr: "", exitCode: 0 }));
  return {
    ...actual,
    listAgents: stub(),
    startAgent: stub(),
    stopAgent: stub(),
    useAgent: stub(),
    inbox: stub(),
    transcript: stub(),
    contactSetMoniker: stub(),
    contactAdd: stub(),
    contactRemove: stub(),
    contactList: stub(),
    contactSetTier: stub(),
    contactSetAway: stub(),
    sealedReceipt: stub(),
    initiate: stub(),
    send: stub(),
    receive: stub(),
    receiveSession: stub(),
    closeSession: stub(),
    awaitSession: stub(),
  };
});

const commands = await import("../commands.js");
const parity = await import("../parity-commands.js");
const { findCommand, COMMANDS, flagsFor } = await import("../registry.js");
const { checkArgs } = await import("../cli-args.js");

const CELLO_DIR = "/tmp/cello-dispatch-test";
const ctx: CommandContext = {
  celloDir: CELLO_DIR,
  daemonBin: "/nonexistent/daemon.js",
  logger: { debug() {}, info() {}, warn() {}, error() {} },
};

/** Drive a command exactly as bin/cello.ts does: spec.run(ctx, argv.slice(3)). */
async function run(name: string, args: string[]): Promise<void> {
  const spec = findCommand(name);
  if (!spec) throw new Error(`no such command: ${name}`);
  await spec.run(ctx, args);
}

/** As run(), but hands back the CliOutput — for asserting a command REFUSED (exit 1, no dispatch). */
async function runOut(name: string, args: string[]) {
  const spec = findCommand(name);
  if (!spec) throw new Error(`no such command: ${name}`);
  return spec.run(ctx, args);
}

beforeEach(() => {
  vi.clearAllMocks();
  delete process.env.CELLO_PREAUTH_TOKEN;
});

describe("T2: the registry forwards EXACTLY what the old switch forwarded", () => {
  it("register-agent: positional agent + token + phone stub, in order", async () => {
    await run("register-agent", ["alice", "CELLO-tok", "+15551234"]);
    expect(commands.register).toHaveBeenCalledWith(CELLO_DIR, "alice", "CELLO-tok", "+15551234");
  });

  it("register-agent: falls back to CELLO_PREAUTH_TOKEN when the token argument is absent", async () => {
    // The env-var form is documented in help and keeps the token out of shell history. The
    // argv[3..5] → args[0..2] translation is precisely where this fallback could be lost.
    process.env.CELLO_PREAUTH_TOKEN = "CELLO-from-env";
    await run("register-agent", ["alice"]);
    expect(commands.register).toHaveBeenCalledWith(CELLO_DIR, "alice", "CELLO-from-env", "");
  });

  it("create-agent / remove-agent / refresh / receipts: the name positional", async () => {
    await run("create-agent", ["alice"]);
    expect(commands.createAgent).toHaveBeenCalledWith(CELLO_DIR, "alice");
    await run("remove-agent", ["bob"]);
    expect(commands.removeAgent).toHaveBeenCalledWith(CELLO_DIR, "bob");
    await run("refresh", ["carol"]);
    expect(commands.refreshShares).toHaveBeenCalledWith(CELLO_DIR, "carol");
    await run("relay-receipts", ["dave"]);
    expect(commands.relayReceipts).toHaveBeenCalledWith(CELLO_DIR, "dave");
  });

  it("sessions: filter precedence (all > closed > failed > open) and --limit parsing", async () => {
    await run("sessions", []);
    expect(commands.sessions).toHaveBeenCalledWith(CELLO_DIR, { filter: undefined, limit: undefined });

    await run("sessions", ["--all", "--closed"]); // --all wins
    expect(commands.sessions).toHaveBeenLastCalledWith(CELLO_DIR, { filter: "all", limit: undefined });

    await run("sessions", ["--closed", "--failed"]); // --closed wins over --failed
    expect(commands.sessions).toHaveBeenLastCalledWith(CELLO_DIR, { filter: "closed", limit: undefined });

    await run("sessions", ["--open", "--limit", "5"]);
    expect(commands.sessions).toHaveBeenLastCalledWith(CELLO_DIR, { filter: "open", limit: 5 });

    await run("sessions", ["--limit", "notanumber"]); // non-numeric → ignored, not NaN
    expect(commands.sessions).toHaveBeenLastCalledWith(CELLO_DIR, { filter: undefined, limit: undefined });
  });

  it("contact: every sub-verb routes to its OWN function (not a neighbour)", async () => {
    // Review F3: the whole address book now goes through the §3 parity path (one command, one
    // contract) — errors on stderr, --pretty available — instead of half legacy / half parity.
    const o = { agent: undefined, pretty: false };
    await run("contact", ["pk1", "add", "--agent", "alice"]);
    expect(parity.contactAdd).toHaveBeenCalledWith(CELLO_DIR, "pk1", { agent: "alice", pretty: false });

    await run("contact", ["pk1", "remove"]);
    expect(parity.contactRemove).toHaveBeenCalledWith(CELLO_DIR, "pk1", o);

    // §3: listing the book is its OWN command now — `cello contacts`, not `cello contact list`.
    await run("contacts", ["--agent", "alice"]);
    expect(parity.contactList).toHaveBeenCalledWith(CELLO_DIR, { agent: "alice", pretty: false });

    await run("contact", ["pk1", "set-tier", "3"]);
    expect(parity.contactSetTier).toHaveBeenCalledWith(CELLO_DIR, "pk1", 3, o);

    await run("contact", ["pk1", "set-away", "back", "on", "Monday"]);
    expect(parity.contactSetAway).toHaveBeenCalledWith(CELLO_DIR, "pk1", "back on Monday", o);

    await run("contact", ["pk1", "set-away"]); // empty message → CLEAR (null), not ""
    expect(parity.contactSetAway).toHaveBeenLastCalledWith(CELLO_DIR, "pk1", null, o);
  });

  it("settings / moniker: sub-verbs and the clear path", async () => {
    await run("settings", ["get", "away.default", "--agent", "alice"]);
    expect(commands.settingsGet).toHaveBeenCalledWith(CELLO_DIR, "away.default", "alice");
    await run("settings", ["get"]); // key omitted → list all
    expect(commands.settingsGet).toHaveBeenLastCalledWith(CELLO_DIR, undefined, undefined);
    await run("settings", ["set", "bounds.known.max_sessions", "8"]);
    expect(commands.settingsSet).toHaveBeenCalledWith(CELLO_DIR, "bounds.known.max_sessions", "8", undefined);

    await run("moniker", ["set", "Bob", "--agent", "alice"]);
    expect(commands.monikerSet).toHaveBeenCalledWith(CELLO_DIR, "Bob", "alice");
    await run("moniker", ["clear"]); // clear = null, and must not be confused with set
    expect(commands.monikerSet).toHaveBeenLastCalledWith(CELLO_DIR, null, undefined);
  });

  it("telegram: set-token forwards both credentials", async () => {
    await run("telegram", ["set-token", "123:abc", "999"]);
    expect(commands.telegramSetToken).toHaveBeenCalledWith(CELLO_DIR, "123:abc", "999");
  });

  it("bad input still prints usage and exits 1 (never a silent success)", async () => {
    for (const [name, args] of [
      ["contact", ["bogus"]],
      ["settings", ["bogus"]],
      ["moniker", ["bogus"]],
      ["telegram", ["bogus"]],
    ] as Array<[string, string[]]>) {
      const out = await findCommand(name)!.run(ctx, args);
      expect(out.exitCode, `${name} bad input must exit 1`).toBe(1);
      expect(out.stdout.length, `${name} must still explain itself`).toBeGreaterThan(0);
    }
  });
});

describe("Phases 1-2: parity commands forward the MCP params exactly", () => {
  it("agent lifecycle", async () => {
    await run("agents", []);
    expect(parity.listAgents).toHaveBeenCalledWith(CELLO_DIR, { pretty: false });
    await run("start-agent", ["alice"]);
    expect(parity.startAgent).toHaveBeenCalledWith(CELLO_DIR, "alice", { pretty: false });
    await run("stop-agent", ["alice"]);
    expect(parity.stopAgent).toHaveBeenCalledWith(CELLO_DIR, "alice", { pretty: false });
    await run("use-agent", ["alice"]);
    expect(parity.useAgent).toHaveBeenCalledWith(CELLO_DIR, "alice", { pretty: false });
  });

  it("inbox: --scope is passed through; an unrecognized scope is not invented", async () => {
    await run("inbox", ["--scope", "all"]);
    expect(parity.inbox).toHaveBeenCalledWith(CELLO_DIR, { agent: undefined, pretty: false, scope: "all" });
    await run("inbox", []);
    expect(parity.inbox).toHaveBeenLastCalledWith(CELLO_DIR, { agent: undefined, pretty: false, scope: undefined });
    // Review F6: an unrecognized scope FAILS LOUD — it is not silently downgraded to `current`,
    // which would answer a question the operator never asked (and hide another agent's inbox).
    const bad = await findCommand("inbox")!.run(ctx, ["--scope", "sideways"]);
    expect(bad.exitCode).toBe(1);
    expect(bad.stdout).toBe("");
    expect(JSON.parse(bad.stderr)).toMatchObject({ ok: false, reason: "invalid_flag_value", flag: "--scope" });
  });

  it("F5: a NON-NUMERIC numeric flag fails loud — it never silently changes what the command does", async () => {
    // --since-seq abc used to be dropped, turning a catch-up BATCH into a 30s blocking live wait
    // that answers "nothing new" to a question that was never asked.
    const bad = await findCommand("receive")!.run(ctx, ["sid1", "--since-seq", "abc"]);
    expect(bad.exitCode).toBe(1);
    expect(bad.stdout).toBe("");
    expect(JSON.parse(bad.stderr)).toMatchObject({ ok: false, reason: "invalid_flag_value", flag: "--since-seq" });
    expect(parity.receive).not.toHaveBeenCalled(); // the command was NOT run

    const badTimeout = await findCommand("await-session")!.run(ctx, ["--timeout-ms", "soon"]);
    expect(badTimeout.exitCode).toBe(1);
    expect(parity.awaitSession).not.toHaveBeenCalled();
  });

  it("send: message is the remaining args joined; --agent and --pretty are not part of it", async () => {
    await run("send", ["sid1", "hello", "there", "--agent", "alice", "--pretty"]);
    expect(parity.send).toHaveBeenCalledWith(CELLO_DIR, "sid1", "hello there", { agent: "alice", pretty: true });
  });

  it("receive: --since-seq and --timeout-ms reach the daemon as numbers, and neither eats the session id", async () => {
    await run("receive", ["sid1", "--since-seq", "7", "--timeout-ms", "500"]);
    expect(parity.receive).toHaveBeenCalledWith(CELLO_DIR, "sid1", {
      agent: undefined, pretty: false, sinceSeq: 7, timeoutMs: 500,
    });
    // Flags BEFORE the positional must not shift it — the value-flag consumption has to be exact.
    await run("receive", ["--timeout-ms", "500", "sid2"]);
    expect(parity.receive).toHaveBeenLastCalledWith(CELLO_DIR, "sid2", {
      agent: undefined, pretty: false, sinceSeq: undefined, timeoutMs: 500,
    });
  });

  it("close: --force is passed ONLY when asked for (it forfeits the seal)", async () => {
    await run("close-session", ["sid1"]);
    expect(parity.closeSession).toHaveBeenCalledWith(CELLO_DIR, "sid1", { agent: undefined, pretty: false, force: false });
    await run("close-session", ["sid1", "--force"]);
    expect(parity.closeSession).toHaveBeenLastCalledWith(CELLO_DIR, "sid1", { agent: undefined, pretty: false, force: true });
  });

  it("initiate / await-session / receive-session / transcript", async () => {
    await run("initiate-session", ["ab12"]);
    expect(parity.initiate).toHaveBeenCalledWith(CELLO_DIR, "ab12", { agent: undefined, pretty: false });
    await run("await-session", ["--timeout-ms", "900"]);
    expect(parity.awaitSession).toHaveBeenCalledWith(CELLO_DIR, { agent: undefined, pretty: false, timeoutMs: 900 });
    await run("receive-session", ["sid1", "--timeout-ms", "900"]);
    expect(parity.receiveSession).toHaveBeenCalledWith(CELLO_DIR, "sid1", { agent: undefined, pretty: false, timeoutMs: 900 });
    await run("transcript", ["sid1", "--agent", "alice"]);
    expect(parity.transcript).toHaveBeenCalledWith(CELLO_DIR, "sid1", { agent: "alice", pretty: false });
  });

  it("contact set-moniker routes to the per-CONTACT moniker handler (NOT the agent's own moniker)", async () => {
    // These two are easy to conflate — conflating them would rename YOUR agent instead of tagging a
    // contact, and both "succeed". The registry must keep them apart.
    await run("contact", ["pk1", "set-moniker", "Sup"]);
    expect(parity.contactSetMoniker).toHaveBeenCalledWith(CELLO_DIR, "pk1", "Sup", { agent: undefined, pretty: false });
    expect(commands.monikerSet).not.toHaveBeenCalled();

    await run("contact", ["pk1", "set-moniker"]); // empty → clear
    expect(parity.contactSetMoniker).toHaveBeenLastCalledWith(CELLO_DIR, "pk1", null, { agent: undefined, pretty: false });
  });

  it("set-tier / set-away are accepted under the `<pubkey> <op>` shape", async () => {
    const o = { agent: undefined, pretty: false };
    await run("contact", ["pk1", "set-tier", "4"]);
    expect(parity.contactSetTier).toHaveBeenCalledWith(CELLO_DIR, "pk1", 4, o);
    await run("contact", ["pk1", "set-away", "on", "leave"]);
    expect(parity.contactSetAway).toHaveBeenCalledWith(CELLO_DIR, "pk1", "on leave", o);
  });

  // DOD-ONBOARD-HELP-1 §2/§3: the legacy `tier` / `away` aliases and the old `contact <op> <pubkey>`
  // arg ORDER are DELETED. This matters more than it looks: under the new shape the first positional
  // is a PUBKEY, so the old `contact tier pk1 3` does not error — it would parse as pubkey="tier",
  // op="pk1". It must fall through to usage + exit 1, never act on a contact named "tier".
  it("the OLD contact shape is refused, not silently misread as a pubkey", async () => {
    for (const argv of [["tier", "pk1", "3"], ["away", "pk1", "later"], ["list"], ["add", "pk1"]]) {
      vi.clearAllMocks();
      const out = await runOut("contact", argv);
      expect(out.exitCode, `'contact ${argv.join(" ")}' must not succeed`).toBe(1);
      expect(parity.contactSetTier).not.toHaveBeenCalled();
      expect(parity.contactSetAway).not.toHaveBeenCalled();
      expect(parity.contactAdd).not.toHaveBeenCalled();
      expect(parity.contactList).not.toHaveBeenCalled();
    }
  });

  it("sealed-receipt dispatches (review T1: it had NO behavioral coverage at all)", async () => {
    await run("sealed-receipt", ["sid9", "--agent", "alice"]);
    expect(parity.sealedReceipt).toHaveBeenCalledWith(CELLO_DIR, "sid9", { agent: "alice", pretty: false });
  });
});

describe("T1: the --pretty grant and the auditable MCP↔CLI parity table", () => {
  it("every jsonOut command accepts --pretty (the grant is real, not decorative)", () => {
    const jsonCommands = COMMANDS.filter((c) => c.jsonOut);
    expect(jsonCommands.length).toBeGreaterThan(10); // the loop must not be vacuous
    for (const spec of jsonCommands) {
      expect(flagsFor(spec.name).has("--pretty"), `${spec.name} must grant --pretty`).toBe(true);
      expect(checkArgs(spec.name, ["--pretty"]), `${spec.name} must accept --pretty`).toEqual({ kind: "ok" });
    }
  });

  it("a command WITHOUT the JSON contract does not silently accept --pretty", () => {
    expect(checkArgs("login", ["--pretty"])).toEqual({ kind: "unknown_flag", flag: "--pretty" });
  });

  it("DoD §9: every in-scope cello_* MCP tool has a CLI command calling the SAME IPC handler", () => {
    // The parity claim, checkable from the registry itself. The three descoped tools
    // (cello_backup / cello_restore / cello_get_inclusion_proof) are deliberately ABSENT: their
    // daemon handlers are not_implemented stubs, so a CLI pass-through would ship a fake command.
    // They are tracked as known-open under DOD-CUSTODY-DAEMON-1 — NOT silently dropped.
    const expected: Record<string, string> = {
      cello_list_agents: "agents",
      cello_start_agent: "start-agent",
      cello_stop_agent: "stop-agent",
      cello_use_agent: "use-agent",
      cello_check_notifications: "inbox",
      cello_get_transcript: "transcript",
      cello_initiate_session: "initiate-session",
      cello_send: "send",
      cello_receive: "receive",
      cello_receive_session: "receive-session",
      cello_close_session: "close-session",
      cello_await_session: "await-session",
      // NOT in the brief's table — it claimed cello_get_sealed_receipt was "already covered" by
      // `cello receipts`. It is not: `receipts` calls cello_get_relay_receipts, a DIFFERENT handler.
      // The notarized bilateral seal receipt had no CLI surface; this is it.
      cello_get_sealed_receipt: "sealed-receipt",
    };
    for (const [tool, cliName] of Object.entries(expected)) {
      const spec = findCommand(cliName);
      expect(spec, `MCP tool ${tool} must have the CLI command '${cliName}'`).toBeDefined();
      expect(spec!.ipcMethod, `'${cliName}' must call ${tool}, the same handler the MCP tool calls`).toBe(tool);
      expect(spec!.jsonOut, `'${cliName}' must honor the bash contract`).toBe(true);
    }
  });

  it("the three DESCOPED custody tools have no CLI command (a fake pass-through is worse than none)", () => {
    for (const name of ["backup", "restore", "inclusion-proof"]) {
      expect(findCommand(name), `'${name}' must NOT exist until the daemon handler is real`).toBeUndefined();
    }
  });
});
