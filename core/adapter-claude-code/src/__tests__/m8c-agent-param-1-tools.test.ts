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
  // DOD-INBOX-AGENT-1: cello_inbox was never in this list, which is exactly WHY the defect it fixes
  // survived DOD-AGENT-PARAM-1 and had to be found by a human a milestone later. Omitting an entry
  // from a hand-maintained enumerator makes the loop shorter, never red.
  ["cello_inbox", "cello_check_notifications"],
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

  // ─── The blind-enumerator guard (DOD-INBOX-AGENT-1, review HIGH) ─────────────────────────────
  //
  // Everything above iterates a list a human maintains, so it can only ever check what somebody
  // remembered to add — the failure mode that produced this very unit. This one is DERIVED from the
  // source: whatever declares the parameter must also forward it, whether or not anyone listed it.
  // A new tool that declares `agent` and drops it goes red the day it is written.
  it("EVERY tool that declares `agent` also forwards it — no hand-maintained list involved", () => {
    const declaring = [...source.matchAll(/server\.tool\("([a-z_]+)"/g)]
      .map((m) => m[1])
      .filter((tool) => /agent:\s*z\.string\(\)\.optional\(\)/.test(blockFor(tool)));

    // Sanity: if this ever finds nothing, the regex has drifted and the guard is vacuous.
    expect(declaring.length, "no tool declares an `agent` param — the scan has drifted").toBeGreaterThan(5);

    for (const tool of declaring) {
      const block = blockFor(tool);
      const callAt = block.indexOf("proxy.call(");
      expect(callAt, `${tool} declares \`agent\` but makes no proxy.call`).toBeGreaterThan(-1);
      // Two shapes forward it: a spread/shorthand `{ agent }`, and the builder form
      // `params.agent = agent`. Both are legitimate; matching only the first would have called the
      // contact tools broken. What is NOT legitimate is declaring it and never sending it.
      const call = block.slice(callAt);
      const forwards = /[{,]\s*agent\s*[,}]/.test(call) || /\.agent\s*=\s*agent\b/.test(block);
      expect(forwards, `${tool} declares \`agent\` but never sends it under that key — the operator's agent is told it works`).toBe(true);
      // ...and it must not DROP an empty name on the way. `z.string().optional()` accepts "", so a
      // truthiness test sends the daemon "no agent given" and the call runs as whatever desk the
      // connection holds, ok:true — the misroute the parameter exists to prevent, reintroduced by
      // the code that forwards it. This fired on four tools, two of which WRITE.
      expect(block, `${tool} drops an empty \`agent\` instead of letting the daemon refuse it`)
        .not.toMatch(/if \(agent\) |\(agent \? \{ agent \}/);
      expect(block, `${tool}'s \`agent\` description must use the shared vocabulary`).toContain("defaults to the current agent");
    }
  });

  it("no tool sends the dead `name` spelling as a selector", () => {
    for (const [tool] of SESSION_TOOLS) {
      expect(blockFor(tool)).not.toMatch(/name:\s*agent\b|\bname:\s*z\.string\(\)\.optional\(\)/);
    }
  });
});
