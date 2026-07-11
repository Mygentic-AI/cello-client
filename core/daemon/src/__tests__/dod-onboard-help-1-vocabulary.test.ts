/**
 * DOD-ONBOARD-HELP-1 §2b — the ONE vocabulary, and the audit that keeps it true.
 *
 * The teeth here are the SOURCE AUDIT (§"daemon guidance"). Renaming the MCP tools is only safe if
 * nothing still hands out the old names — and the daemon hands out names in ~50 error strings. A
 * unit test of the renderer alone would pass happily while the daemon told operators to run
 * `cello_list_agents`, a tool that no longer exists. So the audit reads daemon.ts itself.
 */

import { describe, it, expect, afterEach } from "vitest";
import { readFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { startDaemon, type DaemonHandle } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import type { Logger, DaemonConfig } from "../types.js";
import {
  DUAL_SURFACE_VERBS,
  MCP_ONLY_TOOLS,
  knownToolNames,
  toCliGuidance,
  renderForSurface,
} from "../vocabulary.js";

const here = dirname(fileURLToPath(import.meta.url));
const DAEMON_SRC = join(here, "..", "daemon.ts");

describe("DOD-ONBOARD-HELP-1 §2b — the vocabulary obeys its own rule", () => {
  it("every MCP tool name is `cello_` + the CLI command name, snake_cased", () => {
    for (const { mcp, cli } of DUAL_SURFACE_VERBS) {
      // `cello contact <pubkey> set-tier` → the command words, minus the placeholder.
      const words = cli
        .split(/\s+/)
        .slice(1) // drop the leading "cello"
        .filter((w) => !w.startsWith("<"))
        .join("_")
        .replace(/-/g, "_");
      expect(mcp, `${cli} must map to cello_${words}`).toBe(`cello_${words}`);
    }
  });

  it("no name is claimed twice (a duplicate would make the rename ambiguous)", () => {
    const mcpNames = DUAL_SURFACE_VERBS.map((v) => v.mcp);
    const cliNames = DUAL_SURFACE_VERBS.map((v) => v.cli);
    expect(new Set(mcpNames).size).toBe(mcpNames.length);
    expect(new Set(cliNames).size).toBe(cliNames.length);
  });

  it("the old, pre-rename tool names are GONE from the vocabulary", () => {
    const stale = [
      "cello_list_agents",
      "cello_list_sessions",
      "cello_check_notifications",
      "cello_get_transcript",
      "cello_get_sealed_receipt",
      "cello_set_moniker",
      "cello_contact_list",
    ];
    const known = knownToolNames();
    for (const old of stale) {
      expect(known.has(old), `${old} was renamed — it must not survive here`).toBe(false);
    }
  });
});

describe("DOD-ONBOARD-HELP-1 §5 — guidance renders for the surface that asked", () => {
  it("a CLI caller is told the CLI verb, never the MCP tool name", () => {
    expect(toCliGuidance("Select an agent with cello_use_agent, or pass { name }.")).toBe(
      "Select an agent with cello use-agent, or pass { name }.",
    );
    expect(toCliGuidance("Check cello_sessions for active sessions.")).toBe(
      "Check cello sessions for active sessions.",
    );
  });

  it("renders the LONGEST match first — cello_contact_set_moniker is not mangled into cello_contact + suffix", () => {
    expect(toCliGuidance("Add it first with cello_contact_set_moniker.")).toBe(
      "Add it first with cello contact <pubkey> set-moniker.",
    );
  });

  it("an MCP caller gets the guidance verbatim", () => {
    const r = { ok: false, reason: "no_current_agent", guidance: "Call cello_use_agent." };
    expect(renderForSurface(r, "mcp")).toBe(r); // same object — no needless copy
  });

  it("rewrites ONLY `guidance` — never `reason`, which scripts branch on", () => {
    const out = renderForSurface(
      { ok: false, reason: "session_not_current", guidance: "Call cello_receive to read them." },
      "cli",
    ) as Record<string, unknown>;
    expect(out.reason).toBe("session_not_current");
    expect(out.guidance).toBe("Call cello receive to read them.");
  });

  it("leaves MCP-only tools alone — there is no CLI verb to send an operator to", () => {
    // Inventing `cello backup` here would point the operator at a command that does not exist —
    // the exact failure this mechanism prevents. (DOD-CUSTODY-DAEMON-1 will add the real one.)
    expect(toCliGuidance("Run cello_backup first.")).toBe("Run cello_backup first.");
  });

  it("passes non-objects and guidance-free payloads straight through", () => {
    expect(renderForSurface({ agents: [] }, "cli")).toEqual({ agents: [] });
    expect(renderForSurface(null, "cli")).toBeNull();
    expect(renderForSurface("plain", "cli")).toBe("plain");
  });
});

describe("DOD-ONBOARD-HELP-1 §2b — SOURCE AUDIT: the daemon never names a tool that doesn't exist", () => {
  const source = readFileSync(DAEMON_SRC, "utf8");

  /**
   * Every `cello_*` token the daemon can HAND TO A USER.
   *
   * Deliberately NOT scoped to lines containing `guidance:` — that was the first cut, and it had a
   * hole: the seal-timeout message, the sealed-session notice, and the moniker-adopt hint are
   * operator-facing strings that sit on a ternary/continuation line with no `guidance:` on it. The
   * audit would have passed while three live strings still named a dead tool. So: scan CODE.
   *
   * Excluded, correctly:
   *  - comments — they document the IPC METHOD, whose name is accurate and does not move,
   *  - `handlers.set("cello_x")` — the IPC wire name. Renaming it would break a new daemon talking
   *    to an OLD connect shim (connect has no daemon dep, so they are not pinned together),
   *  - the custody stub-tool array (cello_backup / cello_restore / cello_get_inclusion_proof).
   */
  function operatorFacingToolTokens(): Array<{ line: number; token: string }> {
    const found: Array<{ line: number; token: string }> = [];
    source.split("\n").forEach((raw, i) => {
      const t = raw.trim();
      if (t.startsWith("//") || t.startsWith("*") || t.startsWith("/*")) return; // comment
      if (/handlers\.set\(/.test(raw)) return; // IPC method registration
      if (/for \(const tool of \[/.test(raw)) return; // custody stub list
      const code = raw.replace(/\s\/\/[^"'`]*$/, ""); // drop a trailing inline comment
      for (const m of code.matchAll(/cello_[a-z_]+/g)) {
        found.push({ line: i + 1, token: m[0] });
      }
    });
    return found;
  }
  const guidanceToolTokens = operatorFacingToolTokens;

  it("every cello_* token the daemon shows a user resolves to a real tool", () => {
    const known = knownToolNames();
    const unknown = guidanceToolTokens().filter((t) => !known.has(t.token));
    expect(
      unknown,
      `daemon.ts guidance names tool(s) that do not exist. An error message handing the operator a ` +
        `dead command is worse than no message. Either rename to the vocabulary name, or — if it is ` +
        `CLI-only (register-agent, bridge, refresh, relay-receipts) — write the CLI verb ` +
        `('cello create-agent'), not a cello_* token.\n` +
        unknown.map((u) => `  daemon.ts:${u.line}  ${u.token}`).join("\n"),
    ).toEqual([]);
  });

  it("the guidance strings actually USE the vocabulary (the audit is not vacuous)", () => {
    // Guard against the audit passing simply because someone stripped every tool name out.
    expect(guidanceToolTokens().length).toBeGreaterThan(20);
  });

  it("MCP_ONLY_TOOLS are the custody stubs, and are the only allowed non-dual names", () => {
    expect([...MCP_ONLY_TOOLS].sort()).toEqual([
      "cello_backup",
      "cello_get_inclusion_proof",
      "cello_restore",
    ]);
  });
});

/**
 * The END-TO-END lock. Everything above tests the renderer in isolation — which would stay green
 * even if daemon.ts never CALLED it. This drives a real daemon over a real socket, as each surface,
 * and asserts they are told different things. It is the only test here that can fail if the wrapper
 * at the IPC boundary is removed.
 */
describe("DOD-ONBOARD-HELP-1 §5 — a live daemon renders guidance per connection surface", () => {
  let handle: DaemonHandle | undefined;
  let tempDir: string | undefined;
  const clients: IpcClient[] = [];
  const logger: Logger = { debug() {}, info() {}, warn() {}, error() {} };

  afterEach(async () => {
    for (const c of clients) c.close();
    clients.length = 0;
    if (handle) await handle.stop();
    handle = undefined;
    if (tempDir) await rm(tempDir, { recursive: true, force: true });
    tempDir = undefined;
  });

  async function connectAs(clientType: "cli" | "mcp"): Promise<IpcClient> {
    const client = await connectToDaemon(join(tempDir!, "daemon.sock"));
    clients.push(client);
    await client.send("ipc.connect", { clientType });
    return client;
  }

  it("tells a CLI caller `cello use-agent` and an MCP caller `cello_use_agent` — same handler, same session", async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-vocab-"));
    const config: DaemonConfig = {
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger,
    };
    handle = await startDaemon(config);

    // No agent selected on either connection → both hit the same no_current_agent guard. The only
    // difference between them is which surface asked.
    const cli = await connectAs("cli");
    const mcp = await connectAs("mcp");

    const cliRes = (await cli.send("cello_refresh_shares", {})) as Record<string, unknown>;
    const mcpRes = (await mcp.send("cello_refresh_shares", {})) as Record<string, unknown>;

    // Same machine-readable verdict — the reason code is NEVER rewritten (scripts branch on it).
    expect(cliRes.reason).toBe("no_current_agent");
    expect(mcpRes.reason).toBe("no_current_agent");

    // Different human-readable remedy: each caller is told the thing it can actually invoke.
    expect(String(cliRes.guidance)).toContain("cello use-agent");
    expect(String(cliRes.guidance)).not.toContain("cello_use_agent");

    expect(String(mcpRes.guidance)).toContain("cello_use_agent");
    expect(String(mcpRes.guidance)).not.toContain("cello use-agent");
  });
});
