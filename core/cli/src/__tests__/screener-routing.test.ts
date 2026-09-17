/**
 * DOD-M9C-SCREENINSTALL-1 — `cello screener` routes each sub-verb to its own function.
 *
 * The same guard the `doc` group has, and for the same reason: the sub-verbs dispatch from one `run`
 * body as a chain of `if`s, and deleting a branch leaves every other test green while the command
 * silently prints usage and exits 2. Reading the dispatch source is what actually fails when a
 * branch is removed.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { COMMANDS, helpForSpec } from "../registry.js";

const REGISTRY_SRC = readFileSync(new URL("../registry.ts", import.meta.url), "utf8");

function screenerRunBody(): string {
  const start = REGISTRY_SRC.indexOf('\n    name: "screener",');
  expect(start, "the screener command spec was renamed — this guard now points at nothing").toBeGreaterThan(0);
  const end = REGISTRY_SRC.indexOf('\n    name: "', start + 10);
  return REGISTRY_SRC.slice(start, end === -1 ? undefined : end);
}

describe("SCREENINSTALL: cello screener routing", () => {
  it("is a registered command with a summary the help table renders", () => {
    const spec = COMMANDS.find((c) => c.name === "screener");
    expect(spec, "screener is not registered — the install has no entry point").toBeDefined();
    expect(spec!.summary.length).toBeGreaterThan(10);
  });

  it("routes status, install, --manual and --repair to their own paths", () => {
    const body = screenerRunBody();
    expect(body).toContain('sub === "status"');
    expect(body).toContain("screenerStatusCommand(");
    expect(body).toContain('sub === "install"');
    expect(body).toContain("screenerInstallCommand(");
    expect(body).toContain('args.includes("--manual")');
    expect(body).toContain("screenerManualInstructions(");
    expect(body).toContain('repair: args.includes("--repair")');
    expect(body).toContain('assumeYes: args.includes("--yes")');
  });

  it("declares every flag it reads, so an unknown-flag guard cannot reject its own flags", () => {
    const spec = COMMANDS.find((c) => c.name === "screener")!;
    const declared = (spec.flags ?? []).map((f) => f.name).sort();
    expect(declared).toEqual(["--manual", "--repair", "--yes"]);
  });

  it("help names all four surfaces an operator can run", () => {
    const help = helpForSpec("screener");
    for (const needle of ["screener status", "screener install", "--yes", "--manual", "--repair"]) {
      expect(help, needle).toContain(needle);
    }
  });

  it("never prompts unless stdin is a TTY — the dispatch decides that, not the command", () => {
    expect(screenerRunBody()).toContain("process.stdin.isTTY === true");
  });
});
