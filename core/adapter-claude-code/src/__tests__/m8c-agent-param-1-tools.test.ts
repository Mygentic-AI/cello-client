/**
 * CELLO-M8C — DOD-AGENT-PARAM-1 / AC-B2: the 8 session tools EXPOSE the agent selector.
 *
 * The daemon has honoured a per-call agent selector on these handlers all along; the shim never
 * declared it and never forwarded it. So a multi-agent operator could only switch with the sticky,
 * connection-scoped cello_use_agent — they could not say "do THIS one call as Alice", which they
 * already can on every contact and settings tool.
 *
 * This reads the shim SOURCE rather than standing an MCP server up: the tool schema and the
 * proxy.call payload are both literals in it, and the defect being pinned is precisely that one of
 * them can exist without the other (a declared param the shim then drops on the floor is worse than
 * no param — the operator's agent is told it works). Both halves are asserted per tool.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(here, "..", "bin", "cello-mcp.ts"), "utf8");

/** MCP tool name → the daemon method it proxies to (they differ on four of them). */
const SESSION_TOOLS: Array<[tool: string, method: string]> = [
  ["cello_initiate_session", "cello_initiate_session"],
  ["cello_close_session", "cello_close_session"],
  ["cello_await_session", "cello_await_session"],
  ["cello_send", "cello_send"],
  ["cello_receive", "cello_receive"],
  ["cello_sessions", "cello_list_sessions"],
  ["cello_sealed_receipt", "cello_get_sealed_receipt"],
  ["cello_transcript", "cello_get_transcript"],
];

/** The text from `server.tool("<name>"` up to the start of the next tool registration. */
function blockFor(tool: string): string {
  const start = source.indexOf(`server.tool("${tool}"`);
  expect(start, `${tool} is not registered as a tool`).toBeGreaterThan(-1);
  const next = source.indexOf("server.tool(", start + 1);
  return source.slice(start, next === -1 ? source.length : next);
}

describe("DOD-AGENT-PARAM-1 AC-B2: `agent` on the session tools", () => {
  it.each(SESSION_TOOLS)("%s declares an optional `agent` param", (tool) => {
    const block = blockFor(tool);
    expect(block).toMatch(/agent:\s*z\.string\(\)\.optional\(\)/);
    // The wording the already-shipped contact/settings tools use — one vocabulary, not two.
    expect(block).toContain("defaults to the current agent");
  });

  it.each(SESSION_TOOLS)("%s FORWARDS the agent under the KEY the daemon reads", (tool, method) => {
    const block = blockFor(tool);
    const call = block.slice(block.indexOf(`proxy.call("${method}"`));
    // The key, in shorthand position — NOT merely the token `agent` somewhere in the payload. A bare
    // /\bagent\b/ matches the VALUE, so `{ agentName: agent }` would sail through it: the shim would
    // declare the param, the operator's agent would be told it works, the daemon would read
    // params?.agent → undefined, and the call would silently act as the sole online agent instead.
    // That is the exact defect this file exists to catch, so the assertion has to see the key.
    expect(call, `${tool} declares \`agent\` but never sends it under that key`).toMatch(/[{,]\s*agent\s*[,}]/);
  });

  it("no tool sends the dead `name` spelling as a selector", () => {
    for (const [tool] of SESSION_TOOLS) {
      expect(blockFor(tool)).not.toMatch(/name:\s*agent\b|\bname:\s*z\.string\(\)\.optional\(\)/);
    }
  });
});
