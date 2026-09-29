/**
 * Which of the registered MCP tools an HTTP endpoint exposes.
 *
 * File format, one entry per line: `#` comments and blank lines ignored; `*` adds every registered
 * tool; a bare name adds that tool; `-name` removes it. Processed in order. A given file is
 * AUTHORITATIVE — DEFAULT_DENIED_TOOLS applies only when there is no file.
 */

import { registerCelloTools, type ToolSink } from "./cello-tools.js";

/** Tools that change an agent's reachability or trust posture; an operator does these at a terminal. */
export const DEFAULT_DENIED_TOOLS: readonly string[] = [
  "cello_config_set",
  "cello_settings_set",
  "cello_set_agent_offline",
  "cello_contact_set_tier",
];

export type ToolsFileReason = "unknown_tool" | "empty_set";

export class ToolsFileError extends Error {
  constructor(readonly reason: ToolsFileReason, message: string) {
    super(message);
    this.name = "ToolsFileError";
  }
}

/** The names `registerCelloTools` declares, learned by running it against a recording sink. */
export function collectToolNames(): string[] {
  const names: string[] = [];
  const sink = { tool: (name: string) => { names.push(name); } } as unknown as ToolSink;
  registerCelloTools(sink, { call: async () => undefined });
  return names;
}

export function resolveAllowedTools(all: readonly string[], fileText: string | undefined): Set<string> {
  if (fileText === undefined) return new Set(all.filter((t) => !DEFAULT_DENIED_TOOLS.includes(t)));

  const known = new Set(all);
  const allowed = new Set<string>();
  for (const raw of fileText.split("\n")) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) continue;
    if (line === "*") {
      for (const t of all) allowed.add(t);
      continue;
    }
    const remove = line.startsWith("-");
    const name = remove ? line.slice(1).trim() : line;
    if (!known.has(name)) {
      throw new ToolsFileError(
        "unknown_tool",
        `tools file names "${name}", which is not a registered CELLO tool. Registered tools: ${all.join(", ")}`,
      );
    }
    if (remove) allowed.delete(name);
    else allowed.add(name);
  }
  if (allowed.size === 0) {
    throw new ToolsFileError("empty_set", "tools file leaves no tool allowed; an endpoint that exposes nothing is a misconfiguration");
  }
  return allowed;
}

/** A sink that forwards only allowed tools to the real server; the rest are never declared on it. */
export function filteringSink(server: ToolSink, allowed: ReadonlySet<string>): ToolSink {
  const forward = server.tool.bind(server) as (...args: unknown[]) => unknown;
  return {
    tool: ((name: string, ...rest: unknown[]) => (allowed.has(name) ? forward(name, ...rest) : undefined)) as unknown as ToolSink["tool"],
  };
}
