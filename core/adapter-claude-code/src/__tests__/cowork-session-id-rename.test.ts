/**
 * The MCP-surface parameter is `cello_session_id`, and the IPC field is still `session_id`.
 *
 * Anthropic's `remote-devices` bridge drops the tool argument named literally `session_id` and only
 * that token (anthropics/claude-code#77248, open). A Cowork client could therefore open a CELLO
 * session and do nothing with it: all eight session-scoped tools rejected every call as "expected
 * string, received undefined" while a correct id was passed each time.
 *
 * Nothing failed when the rename was applied — no test named the parameter at all — so this file
 * exists to make the rename load-bearing. Two halves, both asserted per tool, because either one
 * alone is a broken shim:
 *
 *   1. the DECLARED schema key is `cello_session_id` (else Cowork's calls are stripped again), and
 *   2. the payload sent to the daemon is still `session_id` (else every call 'missing_params' —
 *      the daemon, CLI and database were deliberately left untouched by this change).
 *
 * Source-read rather than server-stood-up, matching DOD-AGENT-PARAM-1: both halves are literals in
 * the shim, and the failure being pinned is exactly one of them changing without the other.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(here, "..", "bin", "cello-mcp.ts"), "utf8");

/** Every tool that takes a session id. All eight were dead through the bridge. */
const SESSION_ID_TOOLS = [
  "cello_send",
  "cello_receive",
  "cello_close_session",
  "cello_name_session",
  "cello_dismiss",
  "cello_sealed_receipt",
  "cello_transcript",
  "cello_get_inclusion_proof",
] as const;

/**
 * ⚠️ THE ANCHOR WAS `server.tool("${tool}"` — EXACT, AND THAT WAS A HOLE, not a style preference.
 *
 * A tool registered across several lines (`server.tool(\n  "name",`) was INVISIBLE to this guard.
 * For a tool in the list below that surfaces as "is not registered as a tool", which at least fails;
 * for any OTHER tool it fails silently, and the whole-surface sweep at the foot of this file had the
 * same blindness in its `^\s{2}` indent anchor — so a multi-line registration could declare the very
 * `session_id` parameter the Cowork bridge strips and no test here would see it.
 *
 * Found when `DOD-M15-INCLUSION-1` reformatted `cello_get_inclusion_proof` onto several lines. The
 * matcher is now whitespace-tolerant, which WIDENS what the guard can see rather than relaxing what
 * it demands: every assertion below is unchanged.
 */
function blockFor(tool: string): string {
  const start = source.search(new RegExp(`server\\.tool\\(\\s*"${tool}"`));
  expect(start, `${tool} is not registered as a tool`).toBeGreaterThan(-1);
  const next = source.indexOf("server.tool(", start + 1);
  return source.slice(start, next === -1 ? source.length : next);
}

describe("Cowork bridge (claude-code#77248): the session id parameter", () => {
  it.each(SESSION_ID_TOOLS)("%s declares `cello_session_id`, never the stripped token", (tool) => {
    const block = blockFor(tool);
    expect(block, `${tool} must declare cello_session_id`).toContain("cello_session_id: z.string()");
    // The bare token as a SCHEMA KEY is what the bridge eats. Anchored to the declaration form so a
    // `session_id` inside the proxy payload or a description string does not trip it.
    expect(block, `${tool} must not re-declare the stripped \`session_id\` param`)
      .not.toMatch(/^\s+session_id: z\./m);
  });

  it.each(SESSION_ID_TOOLS)("%s still sends `session_id` to the daemon — IPC is unchanged", (tool) => {
    const block = blockFor(tool);
    // Renamed on destructure, so the payload literal keeps the daemon's field name.
    expect(block).toContain("cello_session_id: session_id");
    expect(block).toMatch(/session_id[,\s}]/);
  });

  it("leaves the whole surface free of the stripped token as a declared argument", () => {
    // Belt and braces across all 42 tools, including any added later: no tool may declare a
    // parameter literally named `session_id` again, whatever it is for.
    // `\s+`, not `\s{2}`: a multi-line `server.tool(` indents its parameter object by four, so the
    // two-space anchor could not see one at all — the same blindness as `blockFor` above.
    const declarations = source.match(/^\s+session_id: z\./gm) ?? [];
    expect(declarations, "a tool re-declared the parameter the Cowork bridge strips").toEqual([]);
  });
});
