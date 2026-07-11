/**
 * DOD-CLI-PARITY-1 Phase 0 — the command REGISTRY is the single source of truth.
 *
 * The registry maps each command to { name, summary, help, flags, run }. Everything derives
 * from it: dispatch (bin/cello.ts), the `cello --help` Commands: table (DOD-ONBOARD-HELP-1's
 * remaining gap), per-command `cello <cmd> --help`, and the recognized-flag set.
 *
 * The point of the refactor is that these CANNOT DRIFT: adding a command forces adding its
 * one-line summary, and the help table is rendered from the same entries dispatch reads.
 * These tests are the drift lock.
 *
 * Also covers the §3 bash-adapter contract (json-out.ts): JSON on stdout, structured errors
 * VERBATIM on stderr, exit code branching on ok — a command must never dress a failed IPC
 * call as success (the DOD-SENDRAW-1 / DOD-LOGOUT-WAIT-1 lesson at the CLI surface).
 */
import { describe, it, expect } from "vitest";
import { COMMANDS, findCommand, renderCommandsTable, commandNames } from "../registry.js";
import { emitIpcResult } from "../json-out.js";
import { USAGE, KNOWN_COMMANDS, helpForCommand, checkArgs } from "../cli-args.js";

describe("Phase 0: the registry is the single source of truth", () => {
  it("every command has a non-empty one-line summary (adding a command FORCES a summary)", () => {
    for (const spec of COMMANDS) {
      expect(spec.summary.length, `'${spec.name}' must have a summary`).toBeGreaterThan(0);
      // A summary is ONE line — it renders as a single table row.
      expect(spec.summary, `'${spec.name}' summary must be one line`).not.toContain("\n");
    }
  });

  it("every command has help text and a runnable handler", () => {
    for (const spec of COMMANDS) {
      expect(spec.help.length, `'${spec.name}' must have help`).toBeGreaterThan(0);
      expect(typeof spec.run, `'${spec.name}' must have a run()`).toBe("function");
    }
  });

  it("command names are unique", () => {
    const names = commandNames();
    expect(new Set(names).size).toBe(names.length);
  });

  it("findCommand resolves a known command and rejects an unknown one", () => {
    expect(findCommand("status")?.name).toBe("status");
    expect(findCommand("definitely-not-a-command")).toBeUndefined();
  });
});

describe("Phase 0: KNOWN_COMMANDS / helpForCommand / checkArgs all DERIVE from the registry", () => {
  it("KNOWN_COMMANDS is exactly the registry's command set (cannot drift)", () => {
    expect([...KNOWN_COMMANDS].sort()).toEqual([...commandNames()].sort());
  });

  it("helpForCommand returns the registry entry's help verbatim", () => {
    for (const spec of COMMANDS) {
      expect(helpForCommand(spec.name)).toBe(spec.help);
    }
  });

  it("checkArgs derives its recognized flags from the registry entry", () => {
    // sessions declares --limit as a value-consuming flag in the registry.
    expect(checkArgs("sessions", ["--all", "--limit", "5"])).toEqual({ kind: "ok" });
    expect(checkArgs("sessions", ["--bogus"])).toEqual({ kind: "unknown_flag", flag: "--bogus" });
    // a command that declares no flags rejects any flag
    expect(checkArgs("register", ["--bogus"])).toEqual({ kind: "unknown_flag", flag: "--bogus" });
  });
});

describe("DOD-ONBOARD-HELP-1: `cello --help` renders a DESCRIBED Commands: table", () => {
  it("renders one line per command, each with its summary (git / `claude --help` style)", () => {
    const table = renderCommandsTable();
    for (const spec of COMMANDS) {
      const line = table.split("\n").find((l) => l.trim().startsWith(spec.name + " "));
      expect(line, `table must have a row for '${spec.name}'`).toBeDefined();
      expect(line, `'${spec.name}' row must carry its summary`).toContain(spec.summary);
    }
  });

  it("USAGE embeds the table — every command is listed WITH a description", () => {
    expect(USAGE).toContain("Commands:");
    for (const spec of COMMANDS) {
      expect(USAGE, `usage must list '${spec.name}'`).toContain(spec.name);
      expect(USAGE, `usage must describe '${spec.name}'`).toContain(spec.summary);
    }
  });

  it("the old pipe-delimited command blob is GONE (that was the HELP-1 gap)", () => {
    expect(USAGE).not.toContain("<login|logout|status|register|");
  });

  it("still opens with orientation + the first-time onboarding path, in order (CC-7 regression)", () => {
    expect(USAGE).toContain("CELLO");
    const loginAt = USAGE.indexOf("cello login");
    const createAt = USAGE.indexOf("cello create-agent");
    const registerAt = USAGE.indexOf("cello register");
    const statusAt = USAGE.indexOf("cello status");
    expect(loginAt).toBeGreaterThanOrEqual(0);
    expect(createAt).toBeGreaterThan(loginAt);
    expect(registerAt).toBeGreaterThan(createAt);
    expect(statusAt).toBeGreaterThan(registerAt);
  });

  it("still points at per-command help", () => {
    expect(USAGE).toContain("--help");
  });
});

describe("§3 bash-adapter contract: JSON out, verbatim structured errors, exit codes", () => {
  it("ok:true → compact JSON on stdout, exit 0, nothing on stderr", () => {
    const e = emitIpcResult({ ok: true, session_id: "abc" });
    expect(e.exitCode).toBe(0);
    expect(e.stderr).toBe("");
    expect(JSON.parse(e.stdout)).toEqual({ ok: true, session_id: "abc" });
    // compact by default — scripts are the first-class consumer
    expect(e.stdout).not.toContain("\n  ");
  });

  it("ok:false → the daemon's structured error VERBATIM on stderr, exit 1, NOTHING on stdout", () => {
    // The whole point: a failed IPC call must never be dressed as success, and every field the
    // daemon sent (reason, guidance, and any extras like the cursor) survives untouched.
    const daemonError = {
      ok: false,
      reason: "session_not_current",
      current_seq: 7,
      last_read_seq: 3,
      guidance: "call cello transcript first",
    };
    const e = emitIpcResult(daemonError);
    expect(e.exitCode).toBe(1);
    expect(e.stdout).toBe("");
    expect(JSON.parse(e.stderr)).toEqual(daemonError); // verbatim — no field dropped, none added
  });

  it("a not_implemented daemon stub is surfaced as a FAILURE, never as success", () => {
    // Guards the exact trap in the brief: backup/restore/inclusion-proof are daemon stubs today.
    const e = emitIpcResult({ ok: false, reason: "not_implemented", guidance: "future milestone" });
    expect(e.exitCode).toBe(1);
    expect(e.stdout).toBe("");
    expect(JSON.parse(e.stderr).reason).toBe("not_implemented");
  });

  it("a PAYLOAD-ONLY response (the daemon's second convention) is a result, not a failure", () => {
    // Verified against daemon.ts, not assumed: cello_list_agents returns a bare { agents: [] } and
    // cello_await_session returns { type: "timeout" } — NO `ok` field at all. `ok:false` is the
    // daemon's one and only failure convention (a real transport failure THROWS). So keying the
    // exit code on `ok === true` would report working commands as broken: `cello agents` would exit
    // 1 on success. We key on `ok === false` instead.
    const agents = emitIpcResult({ agents: [{ name: "alice" }] });
    expect(agents.exitCode).toBe(0);
    expect(agents.stderr).toBe("");
    expect(JSON.parse(agents.stdout).agents).toHaveLength(1);

    const timeout = emitIpcResult({ type: "timeout" });
    expect(timeout.exitCode).toBe(0);
    expect(JSON.parse(timeout.stdout).type).toBe("timeout");
  });

  it("ok:false is ALWAYS a failure, whatever else the body carries", () => {
    // The no-fabricated-success rule: we never synthesize ok:true, never rewrite a body, and never
    // let an ok:false through to stdout — however result-shaped the rest of it looks.
    const e = emitIpcResult({ ok: false, reason: "nope", messages: [], sessions: [] });
    expect(e.exitCode).toBe(1);
    expect(e.stdout).toBe("");
    expect(JSON.parse(e.stderr).reason).toBe("nope");
  });

  it("--pretty renders human-readable JSON on the SAME stream with the SAME exit code", () => {
    const ok = emitIpcResult({ ok: true, a: 1 }, { pretty: true });
    expect(ok.exitCode).toBe(0);
    expect(ok.stdout).toContain("\n  "); // indented
    expect(JSON.parse(ok.stdout)).toEqual({ ok: true, a: 1 });

    const bad = emitIpcResult({ ok: false, reason: "nope" }, { pretty: true });
    expect(bad.exitCode).toBe(1);
    expect(bad.stderr).toContain("\n  ");
    expect(JSON.parse(bad.stderr)).toEqual({ ok: false, reason: "nope" });
  });

  it("every command declaring the JSON contract accepts --pretty", () => {
    for (const spec of COMMANDS) {
      if (!spec.jsonOut) continue;
      expect(checkArgs(spec.name, ["--pretty"]), `'${spec.name}' must accept --pretty`).toEqual({ kind: "ok" });
    }
  });
});
