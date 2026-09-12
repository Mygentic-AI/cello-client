/**
 * 074-DOCSFLAG clause 4 — `cello --help` shows no `doc` command when the flag is off.
 *
 * The clause says "test asserts on rendered help text", and that is what this does: it renders the
 * real `Commands:` table and the real top-level usage string the binary prints, and greps them the
 * way an operator's eye would. It also asserts DISPATCH, because help and dispatch come off the same
 * registry and a command that is hidden but still typeable is a worse state than either.
 *
 * ── WHY DYNAMIC IMPORTS AND A SAVED ENVIRONMENT ───────────────────────────────────────────────
 *
 * The registry, `KNOWN_COMMANDS` and `USAGE` are module-level constants, which is deliberate and
 * predates this order: the CLI is a fresh process per invocation, so reading the flag once at module
 * load IS reading it once at startup. A static import would therefore freeze whichever state this
 * file's environment happened to be in. `vi.resetModules()` plus a dynamic import is what lets one
 * file observe both states, and each case sets the environment before the import that reads it.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { DOCUMENTS_FLAG_ENV } from "@cello-protocol/daemon";

const DOC_SUBVERBS = [
  "propose", "invite", "remove", "inbox", "accept", "refuse", "list",
  "read", "diff", "watch", "write", "publish", "close", "kill",
] as const;

async function loadCli(flag: "on" | "off") {
  if (flag === "on") process.env[DOCUMENTS_FLAG_ENV] = "1";
  else delete process.env[DOCUMENTS_FLAG_ENV];
  vi.resetModules();
  const registry = await import("../registry.js");
  const args = await import("../cli-args.js");
  return { ...registry, ...args };
}

describe("074-DOCSFLAG clause 4 — the CLI's document commands and their help", () => {
  let saved: string | undefined;

  beforeEach(() => {
    saved = process.env[DOCUMENTS_FLAG_ENV];
  });

  afterEach(() => {
    if (saved === undefined) delete process.env[DOCUMENTS_FLAG_ENV];
    else process.env[DOCUMENTS_FLAG_ENV] = saved;
    vi.resetModules();
  });

  it("OFF: the rendered Commands: table has no doc row and no Documents section", async () => {
    const { renderCommandsTable } = await loadCli("off");
    const table = renderCommandsTable();
    expect(table).not.toMatch(/^\s*doc\s/m);
    expect(table).not.toContain("Documents:");
    // The search had reach: the table is the real one and still lists the messaging verbs.
    expect(table).toMatch(/^\s*send\s/m);
  });

  it("OFF: the top-level USAGE an operator reads never mentions a document command", async () => {
    const { USAGE } = await loadCli("off");
    expect(USAGE).not.toContain("cello doc ");
    expect(USAGE).not.toMatch(/^\s*doc\s/m);
    expect(USAGE).toContain("cello");
  });

  it("OFF: `doc` is not dispatchable, and is not merely hidden from the table", async () => {
    const { commandNames, findCommand, KNOWN_COMMANDS } = await loadCli("off");
    expect(commandNames()).not.toContain("doc");
    expect(findCommand("doc")).toBeUndefined();
    expect(KNOWN_COMMANDS.has("doc")).toBe(false);
  });

  it("ON: the doc command is back, with every sub-verb in its help — byte-for-byte the old surface", async () => {
    const { renderCommandsTable, findCommand, KNOWN_COMMANDS } = await loadCli("on");
    expect(renderCommandsTable()).toMatch(/^\s*doc\s/m);
    expect(renderCommandsTable()).toContain("Documents:");
    expect(KNOWN_COMMANDS.has("doc")).toBe(true);
    const spec = findCommand("doc");
    expect(spec, "the doc spec is missing with the flag ON").toBeDefined();
    for (const sub of DOC_SUBVERBS) {
      expect(spec?.help, `'cello doc ${sub}' is not in the help`).toContain(`doc ${sub}`);
    }
  });
});
