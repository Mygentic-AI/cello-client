/**
 * DOD-ONBOARD-HELP-1 §2b — the ONE vocabulary, and the audit that keeps it true.
 *
 * The teeth here are the SOURCE AUDIT (§"daemon guidance"). Renaming the MCP tools is only safe if
 * nothing still hands out the old names — and the daemon hands out names in ~50 error strings. A
 * unit test of the renderer alone would pass happily while the daemon told operators to run
 * `cello_list_agents`, a tool that no longer exists. So the audit reads daemon.ts itself.
 */

import { describe, it, expect, afterEach } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, join, relative } from "node:path";
import { startDaemon, type DaemonHandle } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import type { Logger, DaemonConfig } from "../types.js";
import {
  DUAL_SURFACE_VERBS,
  MCP_ONLY_TOOLS,
  deadCliVerbPattern,
  knownToolNames,
  toCliGuidance,
  renderForSurface,
} from "../vocabulary.js";

const here = dirname(fileURLToPath(import.meta.url));
const SRC_DIR = join(here, "..");

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

  it("renders NESTED instructions too — `cello inbox`'s rename notices are not top-level", () => {
    // Review finding 4. The adopt hint lives at agents[i].rename_notices[j].notice. The first cut
    // rewrote only a TOP-LEVEL `guidance`, so a CLI operator running `cello inbox` was handed an MCP
    // tool name plus JSON arguments they cannot type. A choke point that only covers the easy shape
    // isn't a choke point — it just moves the leak somewhere less visible.
    const out = renderForSurface(
      {
        agents: [
          {
            agent: "alice",
            rename_notices: [
              {
                pubkey: "ab",
                notice: 'Adopt it: cello_contact_set_moniker { pubkey: "ab", moniker: "Zoe" }, or ignore.',
              },
            ],
          },
        ],
      },
      "cli",
    ) as { agents: Array<{ rename_notices: Array<{ notice: string }> }> };
    const notice = out.agents[0].rename_notices[0].notice;
    expect(notice).not.toContain("cello_contact_set_moniker");

    // TYPEABLE, not merely renamed. The earlier version of this test asserted only that the tool
    // NAME had changed — and passed on `cello contact <pubkey> set-moniker { pubkey: "ab", … }`:
    // the tool's JSON still bolted on, next to a literal placeholder. It looked translated and was
    // not runnable. So assert the property that actually matters — an operator can PASTE this.
    expect(notice).toContain('cello contact ab set-moniker "Zoe"');
    expect(notice, "no MCP JSON arguments may survive").not.toMatch(/[{}]/);
    expect(notice, "no unfilled <pubkey> placeholder").not.toContain("<pubkey>");
  });

  it("renders `warning_guidance` — an instruction key that is not called `guidance`", () => {
    const out = renderForSurface(
      { ok: true, warning_guidance: "Not registered — run cello_status to check." },
      "cli",
    ) as Record<string, unknown>;
    expect(out.warning_guidance).toBe("Not registered — run cello status to check.");
  });

  it("an MCP caller gets a NESTED payload back untouched, object identity and all", () => {
    const r = { agents: [{ rename_notices: [{ notice: "Adopt it: cello_contact_set_moniker." }] }] };
    expect(renderForSurface(r, "mcp")).toBe(r);
  });

  it("passes non-objects and guidance-free payloads straight through", () => {
    expect(renderForSurface({ agents: [] }, "cli")).toEqual({ agents: [] });
    expect(renderForSurface(null, "cli")).toBeNull();
    expect(renderForSurface("plain", "cli")).toBe("plain");
  });
});

describe("DOD-ONBOARD-HELP-1 §2b — SOURCE AUDIT: the daemon never names a command that doesn't exist", () => {
  /**
   * Scan EVERY non-test source file in the daemon, not just daemon.ts.
   *
   * The first cut scanned daemon.ts alone, and review found the hole immediately:
   * session-node-manager.ts, session-ceremony.ts and transport-selector.ts all produce
   * operator-facing guidance too. A stale name in any of them passed a green audit. An audit whose
   * blind spot is "the other files" is an audit that certifies what it happens to look at.
   */
  // RECURSIVE (review F5): a flat readdir skipped core/daemon/src/bin/ entirely, while the comment
  // above promised "EVERY non-test source file". No leak there today, but the next file added under
  // a subdirectory would have been invisible — an audit that quietly stops at the first directory.
  function sourceFiles(dir: string): string[] {
    const out: string[] = [];
    for (const entry of readdirSync(dir)) {
      if (entry === "__tests__") continue;
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) out.push(...sourceFiles(full));
      // vocabulary.ts DEFINES the dead names (that is its job) — scanning it would flag the list
      // against itself. It ships no operator-facing strings of its own.
      else if (entry.endsWith(".ts") && !entry.endsWith(".d.ts") && entry !== "vocabulary.ts") out.push(full);
    }
    return out;
  }
  const files = sourceFiles(SRC_DIR).map((f) => relative(SRC_DIR, f)).sort();

  /**
   * Every token in a source file that the daemon can HAND TO A USER as an instruction.
   *
   * Deliberately NOT scoped to lines containing `guidance:` — several operator-facing strings sit on
   * a ternary/continuation line with no `guidance:` on it (the seal-timeout message, the
   * sealed-session notice, the moniker-adopt hint). So: scan CODE.
   *
   * Excluded, correctly:
   *  - comments — they document the IPC METHOD, whose name is accurate and does not move,
   *  - `handlers.set("cello_x")` — the IPC wire name. Renaming it would break a new daemon talking
   *    to an OLD connect shim (connect has no daemon dep, so they are not pinned together),
   *  - the custody stub-tool array (cello_backup / cello_restore / cello_get_inclusion_proof).
   */
  function scan(re: RegExp): Array<{ file: string; line: number; token: string }> {
    const found: Array<{ file: string; line: number; token: string }> = [];
    for (const file of files) {
      readFileSync(join(SRC_DIR, file), "utf8")
        .split("\n")
        .forEach((raw, i) => {
          const t = raw.trim();
          if (t.startsWith("//") || t.startsWith("*") || t.startsWith("/*")) return; // comment
          if (/handlers\.set\(/.test(raw)) return; // IPC method registration
          if (/for \(const tool of \[/.test(raw)) return; // custody stub list
          const code = raw.replace(/\s\/\/[^"'`]*$/, ""); // drop a trailing inline comment
          for (const m of code.matchAll(re)) {
            found.push({ file, line: i + 1, token: m[0] });
          }
        });
    }
    return found;
  }

  const show = (hits: Array<{ file: string; line: number; token: string }>) =>
    hits.map((u) => `  ${u.file}:${u.line}  ${u.token}`).join("\n");

  it("every cello_* token the daemon shows a user resolves to a real tool", () => {
    const known = knownToolNames();
    const unknown = scan(/cello_[a-z_]+/g).filter((t) => !known.has(t.token));
    expect(
      unknown,
      `The daemon names MCP tool(s) that do not exist. An error message handing the operator a dead ` +
        `command is worse than no message. Either rename to the vocabulary name, or — if the ` +
        `capability is CLI-only (register-agent, bridge, refresh, relay-receipts) — write the CLI ` +
        `verb ('cello create-agent'), not a cello_* token.\n` + show(unknown),
    ).toEqual([]);
  });

  it("the daemon never hands out a DEAD CLI verb (the tool audit is structurally blind to these)", () => {
    // Review finding: `cello register` survived in daemon.ts's unregistered-agent warning, because a
    // bare CLI verb carries no `cello_` token for the audit above to catch. Two audits, two shapes.
    const dead = scan(deadCliVerbPattern());
    expect(
      dead,
      `The daemon tells an operator to run a command that no longer dispatches (DOD-ONBOARD-HELP-1 ` +
        `§2 renamed it and deleted the old name — there are no aliases).\n` + show(dead),
    ).toEqual([]);
  });

  it("the audit is not vacuous — it really is reading tool names out of the source", () => {
    expect(scan(/cello_[a-z_]+/g).length).toBeGreaterThan(20);
    expect(files.length).toBeGreaterThan(10); // and really is reading the whole package
    expect(files).toContain("daemon.ts");
    expect(files).toContain("session-node-manager.ts");
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

/**
 * Review finding 7 — the address book must not accept an address that can never match anyone.
 *
 * Under §3's new `contact <pubkey> <op>` shape the FIRST positional is the pubkey, so the muscle
 * memory of the old shape (`contact tier <pk> 3`) can put a VERB where a key belongs. Most of those
 * slips die in the CLI (unknown op → usage, exit 1), but `cello contact tier add` has a valid op —
 * it reached the daemon, which stored a contact whose pubkey is the literal string "tier" and
 * replied ok:true. The operator is told they added someone. They added a typo.
 */
describe("DOD-ONBOARD-HELP-1 (review F7) — a contact pubkey must be a pubkey", () => {
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

  it("refuses a non-hex pubkey on every contact handler, and changes nothing", async () => {
    tempDir = await mkdtemp(join(tmpdir(), "cello-pubkey-"));
    handle = await startDaemon({
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger,
    });
    const client = await connectToDaemon(join(tempDir, "daemon.sock"));
    clients.push(client);
    await client.send("ipc.connect", { clientType: "cli" });

    // "tier" is what `cello contact tier add` would send as the pubkey.
    for (const [method, extra] of [
      ["cello_contact_add", {}],
      ["cello_contact_set_tier", { tier: 3 }],
      ["cello_contact_set_away", { message: "later" }],
      ["cello_contact_set_moniker", { moniker: "Bob" }],
    ] as Array<[string, Record<string, unknown>]>) {
      const res = (await client.send(method, { pubkey: "tier", ...extra })) as Record<string, unknown>;
      expect(res.ok, `${method} accepted a non-hex pubkey`).toBe(false);
      expect(res.reason, `${method} must say WHY`).toBe("invalid_pubkey");
      expect(String(res.guidance)).toContain("64 hex characters");
      expect(String(res.guidance)).toContain("Nothing was changed");
    }

    // A well-formed key gets PAST the shape gate (it fails later, on no_current_agent — which proves
    // the validator is not simply refusing everything). The regex is the SAME one
    // cello_initiate_session already enforces on target_pubkey, so this is the codebase's existing
    // rule, not a new and stricter one.
    const good = (await client.send("cello_contact_add", { pubkey: "a".repeat(64) })) as Record<string, unknown>;
    expect(good.reason).not.toBe("invalid_pubkey");

    // REMOVE is deliberately NOT shape-gated — it is the escape hatch. Gating it would make a junk
    // row written by the older unvalidated code permanently undeletable, because deleting it means
    // naming it. A validator that traps the mess it was built to prevent is worse than no validator.
    const rm = (await client.send("cello_contact_remove", { pubkey: "tier" })) as Record<string, unknown>;
    expect(rm.reason, "remove must not refuse a malformed key — that is the only way out").not.toBe("invalid_pubkey");
  });
});
