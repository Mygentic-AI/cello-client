/**
 * 023-MCPCHAN — every channel capability the daemon serves is reachable from MCP.
 *
 * WHY THIS EXISTS, and it is the order's whole thesis. The MCP surface is audited against ONE table,
 * `vocabulary.ts`, in both directions: every tool the shim registers must be in the table, and every
 * row in the table must be registered by the shim. **Neither direction asks whether a capability
 * reached the table at all.** Sixteen orders added fourteen channel verbs to the daemon and the CLI,
 * skipped the table, and every guard stayed green while an agent could not touch a channel.
 *
 * So this audit starts from the DAEMON'S OWN HANDLER REGISTRATIONS — the thing that cannot be
 * forgotten, because it is what makes the verb work — and asks whether the shim can reach each one.
 *
 * ⚠️ IT DERIVES THE LIST, IT DOES NOT RESTATE IT. A hand-written list of fourteen names is exactly
 * the artifact that goes stale: verb fifteen gets added and nobody updates the test.
 *
 * ⚠️ IT CHECKS `proxy.call`, NOT `server.tool`. The tool name follows the CLI command; the daemon
 * WIRE name is never renamed, because `connect` has no daemon dependency and a new daemon must keep
 * serving an old shim. So `cello channel setup` is the tool `cello_channel_setup` calling the method
 * `cello_channel_config` — two legitimately different strings. Reachability is a property of the
 * wire call, and that is what is asserted here.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const SHIM_SRC = readFileSync(join(here, "..", "bin", "cello-mcp.ts"), "utf8");
const DAEMON_SRC = join(here, "..", "..", "..", "daemon", "src");

/** Every `cello_channel*` IPC method the daemon registers a handler for. */
function daemonChannelMethods(): string[] {
  const files = readdirSync(DAEMON_SRC, { withFileTypes: true })
    .filter((e) => e.isFile() && e.name.endsWith(".ts"))
    .map((e) => join(DAEMON_SRC, e.name));
  const found = new Set<string>();
  for (const f of files) {
    for (const m of readFileSync(f, "utf8").matchAll(/handlers\.set\(\s*"(cello_channels?[a-z_]*)"/g)) {
      found.add(m[1]!);
    }
  }
  return [...found].sort();
}

/** Every daemon method the shim proxies to, whatever the tool it sits behind is called. */
function shimProxiedMethods(): Set<string> {
  return new Set([...SHIM_SRC.matchAll(/proxy\.call\(\s*"(cello_[a-z_]+)"/g)].map((m) => m[1]!));
}

describe("023-MCPCHAN — the channel verbs are on the MCP surface", () => {
  it("finds the daemon's channel handlers at all (guards against a vacuous pass)", () => {
    // If the scan finds nothing — a moved file, a changed registration idiom — every assertion
    // below passes trivially, which is the failure mode this audit was written to end.
    expect(daemonChannelMethods().length).toBeGreaterThanOrEqual(14);
  });

  it("every channel verb the daemon serves is reachable through the shim", () => {
    const proxied = shimProxiedMethods();
    const unreachable = daemonChannelMethods().filter((m) => !proxied.has(m));
    expect(
      unreachable,
      `The daemon serves these channel verbs and the MCP shim cannot call them, so an agent ` +
        `cannot use them at all — only a person at a terminal can. Register a tool for each and ` +
        `add its row to ALWAYS_ON_VERBS in vocabulary.ts.\n  ${unreachable.join("\n  ")}`,
    ).toEqual([]);
  });
});
