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
import { USAGE, helpForCommand, checkArgs, KNOWN_COMMANDS } from "../cli-args.js";

describe("F1: usage string lists every command", () => {
  it("mentions refresh and receipts (previously missing) alongside the rest", () => {
    for (const cmd of ["login", "logout", "status", "register", "create-agent", "remove-agent", "refresh", "receipts", "sessions"]) {
      expect(USAGE, `usage must list '${cmd}'`).toContain(cmd);
    }
  });

  it("KNOWN_COMMANDS matches the dispatchable set", () => {
    expect([...KNOWN_COMMANDS].sort()).toEqual(
      ["contact", "create-agent", "login", "logout", "receipts", "refresh", "register", "remove-agent", "sessions", "status"].sort(),
    );
  });
});

describe("F2: --help/-h on subcommands", () => {
  it("checkArgs reports help for --help and -h on any command", () => {
    expect(checkArgs("register", ["--help"])).toEqual({ kind: "help" });
    expect(checkArgs("create-agent", ["-h"])).toEqual({ kind: "help" });
    expect(checkArgs("sessions", ["--help"])).toEqual({ kind: "help" });
  });

  it("--help anywhere wins, even after an unknown flag (the doc-comment contract)", () => {
    expect(checkArgs("register", ["--bogus", "--help"])).toEqual({ kind: "help" });
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
    expect(help).toContain("^[a-zA-Z0-9_-]{1,64}$");
    expect(help).toContain("no spaces");
  });

  it("register help shows the two-step, a worked example, the token format, and the env-var form", () => {
    const help = helpForCommand("register");
    expect(help).toContain("create-agent"); // the create → register two-step is explained
    expect(help).toContain("CELLO-");        // token format
    expect(help.toLowerCase()).toContain("example");
    expect(help).toContain("CELLO_PREAUTH_TOKEN"); // env-var form documented
  });
});

describe("F2: unknown flags are rejected, not coerced to positionals", () => {
  it("rejects an unknown flag on a command that takes no flags", () => {
    const res = checkArgs("register", ["--bogus"]);
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
    expect(checkArgs("register", ["alice", "token-123"])).toEqual({ kind: "ok" });
    expect(checkArgs("refresh", ["alice"])).toEqual({ kind: "ok" });
  });
});
