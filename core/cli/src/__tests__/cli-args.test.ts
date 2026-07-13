/**
 * M8B riders F1/F2 — CLI usability:
 *  - F1: the usage string must list EVERY command (refresh and receipts were missing).
 *  - F2: subcommands must handle --help/-h, and unknown flags must be REJECTED instead
 *    of being coerced into positional arguments (e.g. `cello register --help` used to
 *    try to register an agent literally named "--help").
 *
 * The argument handling is extracted into cli-args.ts so it is testable without
 * spawning the binary; src/bin/cello.ts consumes it.
 */
import { describe, it, expect } from "vitest";
import { MONIKER_RE } from "@cello-protocol/protocol-types";
import { USAGE, helpForCommand, checkArgs, splitAgentFlag, KNOWN_COMMANDS } from "../cli-args.js";

describe("F1: usage string lists every command", () => {
  it("mentions refresh and receipts (previously missing) alongside the rest", () => {
    for (const cmd of ["login", "logout", "status", "register-agent", "create-agent", "remove-agent", "refresh", "relay-receipts", "sessions"]) {
      expect(USAGE, `usage must list '${cmd}'`).toContain(cmd);
    }
  });

  it("F1: `--` end-of-flags terminator lets a dash-prefixed positional VALUE through (settings set away.default '- back Monday')", () => {
    // checkArgs must not reject the dash value after `--`, and splitAgentFlag must keep it positional.
    expect(checkArgs("settings", ["set", "away.default", "--", "- back Monday"])).toEqual({ kind: "ok" });
    const { agent, positional } = splitAgentFlag(["set", "away.default", "--", "- back Monday"]);
    expect(agent).toBeUndefined();
    expect(positional).toEqual(["set", "away.default", "- back Monday"]);
    // --agent BEFORE the terminator still resolves; a dash value AFTER it is verbatim.
    const withAgent = splitAgentFlag(["set", "bounds.known.max_sessions", "--agent", "alice", "--", "-5"]);
    expect(withAgent.agent).toBe("alice");
    expect(withAgent.positional).toEqual(["set", "bounds.known.max_sessions", "-5"]);
    // Without the terminator, a bare dash value is still a fail-loud unknown flag (unchanged).
    expect(checkArgs("settings", ["set", "away.default", "-5"])).toEqual({ kind: "unknown_flag", flag: "-5" });
  });

  // This hand-written list is deliberately INDEPENDENT of the registry — it is the outside anchor
  // that the registry's own derive-lock tests cannot be (they would agree with any table, including
  // a wrong one). Adding OR RENAMING a command means updating this list on purpose. It is what
  // caught every half-rename in DOD-ONBOARD-HELP-1: the old names had to be struck out by hand.
  it("KNOWN_COMMANDS matches the dispatchable set", () => {
    expect([...KNOWN_COMMANDS].sort()).toEqual(
      [
        // Setup
        "login", "logout", "status", "create-agent", "register-agent", "remove-agent",
        // Agents
        "agents", "start-agent", "use-agent", "stop-agent", "refresh",
        // Messaging
        "initiate-session", "await-session", "close-session", "name-session", "send", "receive", "inbox",
        // Sessions & receipts
        "sessions", "transcript", "sealed-receipt", "relay-receipts",
        // Contacts
        "contacts", "contact",
        // Other
        "settings", "moniker", "telegram", "bridge",
      ].sort(),
    );
  });

  // DOD-ONBOARD-HELP-1 §2: the renames are CLEAN. No aliases — one user, no install base, so an
  // alias would be permanent debt bought for nobody.
  it("the OLD command names are gone from the dispatchable set", () => {
    for (const old of ["install", "register", "close", "initiate", "receipts", "receive-session"]) {
      expect(KNOWN_COMMANDS.has(old), `'${old}' must be deleted, not aliased`).toBe(false);
    }
  });

  // MONIKER-1 AC2: `cello moniker set <name>` / `cello moniker clear` — the outbound-name override.
  it("moniker help states the set/clear surface and derives the name rule from the constant", () => {
    const help = helpForCommand("moniker");
    expect(help).toContain("moniker set");
    expect(help).toContain("moniker clear");
    expect(help).toContain(MONIKER_RE.source); // derived, never hand-typed (MONIKER-0 AC2)
  });

  it("moniker accepts --agent and rejects unknown flags", () => {
    expect(checkArgs("moniker", ["set", "Bob", "--agent", "alice"])).toEqual({ kind: "ok" });
    expect(checkArgs("moniker", ["set", "Bob", "--bogus"])).toEqual({ kind: "unknown_flag", flag: "--bogus" });
    expect(checkArgs("moniker", ["--help"])).toEqual({ kind: "help" });
  });

  // MONIKER-1 review Finding 1 (+ pre-existing Finding 2 in `contact`): with --agent ABSENT,
  // the old inline filter dropped positional index 0 (`i === agentIdx + 1` with agentIdx = -1),
  // so `cello moniker set Bob` and `cello contact list` printed usage instead of dispatching.
  // The parse is extracted here so the dispatch-layer logic is testable.
  describe("splitAgentFlag — the shared --agent + positionals parse", () => {
    it("keeps ALL positionals when --agent is absent (the Finding-1 regression)", () => {
      expect(splitAgentFlag(["set", "Bob"])).toEqual({ agent: undefined, positional: ["set", "Bob"] });
      expect(splitAgentFlag(["clear"])).toEqual({ agent: undefined, positional: ["clear"] });
      expect(splitAgentFlag(["list"])).toEqual({ agent: undefined, positional: ["list"] });
    });

    it("extracts --agent and its value wherever they sit", () => {
      expect(splitAgentFlag(["set", "Bob", "--agent", "alice"])).toEqual({ agent: "alice", positional: ["set", "Bob"] });
      expect(splitAgentFlag(["--agent", "alice", "set", "Bob"])).toEqual({ agent: "alice", positional: ["set", "Bob"] });
      expect(splitAgentFlag(["set", "--agent", "alice", "Bob"])).toEqual({ agent: "alice", positional: ["set", "Bob"] });
    });

    it("a trailing --agent with no value yields agent undefined and drops nothing else", () => {
      expect(splitAgentFlag(["set", "Bob", "--agent"])).toEqual({ agent: undefined, positional: ["set", "Bob"] });
    });
  });

  // CC-7 (P2-5 / DOD-ONBOARD-HELP-1): the top-level usage must be real orientation, not a bare list.
  it("opens with what CELLO is and the first-time onboarding path (not just a command list)", () => {
    expect(USAGE).toContain("CELLO"); // says what it is
    // the onboarding path a first-time user needs, in order.
    const loginAt = USAGE.indexOf("cello login");
    const createAt = USAGE.indexOf("cello create-agent");
    const registerAt = USAGE.indexOf("cello register");
    const statusAt = USAGE.indexOf("cello status");
    expect(loginAt).toBeGreaterThanOrEqual(0);
    expect(createAt).toBeGreaterThan(loginAt);
    expect(registerAt).toBeGreaterThan(createAt);
    expect(statusAt).toBeGreaterThan(registerAt);
  });
});

describe("F2: --help/-h on subcommands", () => {
  it("checkArgs reports help for --help and -h on any command", () => {
    expect(checkArgs("register-agent", ["--help"])).toEqual({ kind: "help" });
    expect(checkArgs("create-agent", ["-h"])).toEqual({ kind: "help" });
    expect(checkArgs("sessions", ["--help"])).toEqual({ kind: "help" });
  });

  it("--help anywhere wins, even after an unknown flag (the doc-comment contract)", () => {
    expect(checkArgs("register-agent", ["--bogus", "--help"])).toEqual({ kind: "help" });
    expect(checkArgs("sessions", ["--bogus", "-h"])).toEqual({ kind: "help" });
  });

  it("--help/-h is never swallowed as --limit's value", () => {
    expect(checkArgs("sessions", ["--limit", "-h"])).toEqual({ kind: "help" });
    expect(checkArgs("sessions", ["--limit", "--help"])).toEqual({ kind: "help" });
  });

  it("helpForCommand returns a usage line for every command", () => {
    for (const cmd of KNOWN_COMMANDS) {
      const help = helpForCommand(cmd);
      expect(help.length, `help for '${cmd}' must not be empty`).toBeGreaterThan(0);
      expect(help).toContain(cmd);
    }
  });

  // M8C-ONBOARD-HELP-1 (F24/R1/R2/R5): real help, not a bare command list.
  it("create-agent help states the exact name rule", () => {
    const help = helpForCommand("create-agent");
    // MONIKER-0 AC2: assert against the shared constant's own source text, not a
    // hand-typed twin — the prose copy is DERIVED from the constant, not parallel to it.
    expect(help).toContain(MONIKER_RE.source);
    expect(help).toContain("no spaces");
  });

  it("register help shows the two-step, a worked example, the token format, and the env-var form", () => {
    const help = helpForCommand("register-agent");
    expect(help).toContain("create-agent"); // the create → register two-step is explained
    expect(help).toContain("CELLO-");        // token format
    expect(help.toLowerCase()).toContain("example");
    expect(help).toContain("CELLO_PREAUTH_TOKEN"); // env-var form documented
  });
});

describe("F2: unknown flags are rejected, not coerced to positionals", () => {
  it("rejects an unknown flag on a command that takes no flags", () => {
    const res = checkArgs("register-agent", ["--bogus"]);
    expect(res).toEqual({ kind: "unknown_flag", flag: "--bogus" });
  });

  it("rejects an unknown flag mixed with valid positionals", () => {
    const res = checkArgs("create-agent", ["myagent", "--force"]);
    expect(res).toEqual({ kind: "unknown_flag", flag: "--force" });
  });

  it("accepts the sessions filter flags and --limit with its value", () => {
    expect(checkArgs("sessions", ["--open"])).toEqual({ kind: "ok" });
    expect(checkArgs("sessions", ["--all", "--limit", "5"])).toEqual({ kind: "ok" });
  });

  it("rejects an unknown flag on sessions", () => {
    expect(checkArgs("sessions", ["--bogus"])).toEqual({ kind: "unknown_flag", flag: "--bogus" });
  });

  it("plain positionals pass through untouched", () => {
    expect(checkArgs("register-agent", ["alice", "token-123"])).toEqual({ kind: "ok" });
    expect(checkArgs("refresh", ["alice"])).toEqual({ kind: "ok" });
  });
});
