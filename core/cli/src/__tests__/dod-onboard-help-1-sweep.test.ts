/**
 * DOD-ONBOARD-HELP-1 §2 — "grep and update EVERY reference." The sweep that makes that a property
 * of the build rather than a promise in a doc.
 *
 * This test exists because the first cut of this story shipped THREE dead-command instructions
 * through a fully green suite:
 *   - commands.ts   the missing-token onboarding error said "cello register" (twice),
 *   - commands.ts   relay-receipts' OWN usage line said "Usage: cello receipts <name>",
 *   - hermes/assets.ts  the scaffolded Hermes plugin — written to the OPERATOR'S DISK and injected
 *                       into their agent's system prompt — named cello_check_notifications and
 *                       cello_list_sessions, tools this very story deleted.
 * Every §2 test passed, because they all asserted against USAGE and the registry — the two places
 * the rename was obviously done. The strings that actually reach a stuck user were never read.
 *
 * A rename is not "done" when the command table is right. It is done when nothing anywhere still
 * tells a human to run the old thing. So: scan the SOURCE, not the abstraction.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, relative } from "node:path";
import { deadCliVerbPattern, RENAMED_AWAY_TOOLS } from "@cello-protocol/daemon";

const here = dirname(fileURLToPath(import.meta.url));
const SRC = join(here, "..");

/** Every non-test .ts under core/cli/src — including hermes/, whose assets ship to operator disk. */
function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    if (entry === "__tests__") continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...sourceFiles(full));
    else if (entry.endsWith(".ts") && !entry.endsWith(".d.ts")) out.push(full);
  }
  return out;
}

const FILES = sourceFiles(SRC);

/**
 * Scan for names shown to a HUMAN (or written into an agent's prompt) — never IPC plumbing.
 *
 * Two exclusions, both load-bearing:
 *
 *  1. Comments. They narrate history ("renamed from `cello install`"), which is legitimate; forcing
 *     them to lie would be absurd.
 *
 *  2. Bare string literals — `"cello_list_agents"` standing alone as its own literal. Those are IPC
 *     WIRE method names (`client.send("cello_list_agents")`, the `IPC_METHODS` map, the method union
 *     type), and the wire deliberately does NOT move: a renamed method would break a new daemon
 *     talking to an OLD connect shim. The tool name moved; the method it proxies to did not.
 *
 * What survives both is a tool name embedded in PROSE — a sentence a person or an agent reads and
 * acts on. That is exactly the Hermes `platform_hint` ("their names are cello_use_agent,
 * cello_receive, …"), which is the string that shipped two deleted tools into an operator's agent.
 * The distinction is precise: an identifier IS its literal; an instruction merely contains one.
 */
function scan(re: RegExp): Array<{ file: string; line: number; token: string }> {
  const hits: Array<{ file: string; line: number; token: string }> = [];
  for (const file of FILES) {
    readFileSync(file, "utf8")
      .split("\n")
      .forEach((raw, i) => {
        const t = raw.trim();
        if (t.startsWith("//") || t.startsWith("*") || t.startsWith("/*")) return;
        const code = raw
          .replace(/\s\/\/[^"'`]*$/, "") // trailing inline comment
          // Strip a quoted tool name ONLY in a WIRE POSITION — directly after `(`, `,`, `:` or `|`,
          // which is where an IPC method name is passed as an argument, mapped in IPC_METHODS, or
          // listed in a method union type.
          //
          // The first cut stripped ANY exactly-quoted token, anywhere. Review showed the hole: house
          // style quotes commands inside prose ("Fetch it with 'cello_check_notifications' first"),
          // and that inner literal was stripped too — so a stale name hid inside the very sentence
          // that hands it to a user. Position is what separates an identifier from an instruction.
          .replace(/([(,:|]\s*)(["'`])cello_[a-z_]+\2/g, '$1""')
        for (const m of code.matchAll(re)) {
          hits.push({ file: relative(SRC, file), line: i + 1, token: m[0] });
        }
      });
  }
  return hits;
}

const show = (h: Array<{ file: string; line: number; token: string }>) =>
  h.map((x) => `  ${x.file}:${x.line}  ${x.token}`).join("\n");

describe("DOD-ONBOARD-HELP-1 §2 — no shipped string names a DEAD command", () => {
  it("is not vacuous — it really is reading the CLI sources, hermes assets included", () => {
    expect(FILES.length).toBeGreaterThan(5);
    expect(FILES.some((f) => f.includes("hermes"))).toBe(true);
    expect(FILES.some((f) => f.endsWith("commands.ts"))).toBe(true);
  });

  it("never tells a user to run a renamed-away CLI command", () => {
    const dead = scan(deadCliVerbPattern());
    expect(
      dead,
      `A shipped string tells the operator to run a command that no longer dispatches. §2 renamed ` +
        `it and DELETED the old name — there are no aliases, so this instruction dead-ends.\n` +
        show(dead),
    ).toEqual([]);
  });

  it("NEGATIVE CONTROL — the dead-verb scan really fires, and on punctuation too", () => {
    // The bug review caught: a trailing-space anchor let `'cello register'` (quoted, in the Hermes
    // plugin) sail past. These assert the pattern catches every punctuation form AND still lets the
    // live commands through — the two ways this check can be silently useless.
    const re = () => deadCliVerbPattern();
    for (const dead of [
      "run 'cello register' first",
      "run `cello register`.",
      "see cello install, then",
      "cello receipts\n",
      "use cello close(id)",
      "cello contact add <pk>",
      "cello contact set-tier <pk> 3",
    ]) {
      expect(re().test(dead), `must FLAG: ${dead}`).toBe(true);
    }
    for (const live of [
      "run 'cello register-agent alice'",
      "cello close-session <id>",
      "cello initiate-session <pk>",
      "cello relay-receipts <name>",
      "cello contact <pubkey> add",
      "cello contacts --agent alice",
    ]) {
      expect(re().test(live), `must ALLOW: ${live}`).toBe(false);
    }
  });

  it("NEGATIVE CONTROL — a stale tool name quoted INSIDE prose is not hidden by the literal-strip", () => {
    // Review's F3. A wire literal (`client.send("cello_list_agents")`) must be stripped; the SAME
    // token quoted inside a sentence must NOT be — that sentence is an instruction to a human.
    const strip = (line: string) => line.replace(/([(,:|]\s*)(["'`])cello_[a-z_]+\2/g, '$1""');
    expect(strip('const r = await client.send("cello_list_agents");')).not.toContain("cello_list_agents");
    expect(strip('output: "Fetch it with \'cello_check_notifications\' first."')).toContain("cello_check_notifications");
  });

  it("never names an MCP tool that was renamed away", () => {
    // This is what catches the Hermes platform_hint — it hands the operator's agent a literal list
    // of tool names to call, and two of them had been deleted by this very story. That file is
    // written to the operator's DISK and injected into their agent's system prompt, so a stale name
    // there is not a doc nit: it is an agent calling a tool that is not there.
    //
    // A denylist, not an allowlist — see RENAMED_AWAY_TOOLS. Inside this package a `cello_*` token
    // is just as likely to be an IPC WIRE name (which deliberately does not move) or a config key
    // (`cello_socket_path`) as a tool, so "every token must be a known tool" would be noise.
    const stale = scan(new RegExp(RENAMED_AWAY_TOOLS.join("|"), "g"));
    expect(
      stale,
      `A shipped string names an MCP tool that no longer exists. If it is scaffolded into an agent's ` +
        `prompt (hermes/assets.ts), that agent will call a tool that isn't there.\n` + show(stale),
    ).toEqual([]);
  });
});
