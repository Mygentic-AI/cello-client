/**
 * DOD-ONBOARD-HELP-1 §2b — the connect shim's MCP tool names ARE the vocabulary.
 *
 * The rule: an MCP tool's name is `cello_` + the CLI command name. Humans and agents learn a
 * capability ONCE. This test is what makes that structural rather than aspirational — the shim
 * cannot register a tool the vocabulary does not know, and cannot silently drop one it does.
 *
 * The vocabulary lives in @cello-protocol/daemon and is imported here as a DEV dependency only:
 * the shim is a thin proxy (no libp2p, no DB, no crypto) and must stay that way, so the daemon
 * never enters its runtime dependency tree — only its test's.
 *
 * The shim's tool names must be string literals (the MCP SDK registers them alongside zod schemas),
 * so they cannot be derived from the table at runtime. That is exactly why this audit exists: a
 * literal that can drift, plus a test that will not let it.
 *
 * SCOPE — read this before widening it. This audits `bin/cello-mcp.ts`, the PUBLISHED entrypoint.
 * `src/server.ts` (and `core/client/src/mcp-server.ts`) are the legacy M1 in-process servers. An
 * earlier version of this comment claimed they were "not published" — that was WRONG, and review
 * caught it: both are exported from their package roots and ship in `dist/`. Nothing drives them at
 * runtime (the shim proxies to the daemon), but they still register the pre-rename tool names, so
 * they are a SECOND vocabulary sitting on the public export surface — the exact thing §2b abolishes.
 * Tracked as DOD-LEGACY-MCP-1: delete the dead `createMcpServer` / `createMcpSessionServer` exports.
 * Not fixed here because deleting public exports is a separate, riskier change than a help pass.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { DUAL_SURFACE_VERBS, MCP_ONLY_TOOLS, knownToolNames } from "@cello-protocol/daemon";

const here = dirname(fileURLToPath(import.meta.url));
const SHIM_SRC = join(here, "..", "bin", "cello-mcp.ts");
const source = readFileSync(SHIM_SRC, "utf8");

/**
 * The package's PUBLISHED non-code files — from `files:` in package.json, so this follows what
 * actually ships rather than what I remember shipping.
 *
 * SKILL.md is the reason this exists. It ships INSIDE the connect tarball (`files: ["dist/",
 * "package.json", "SKILL.md"]`) and it tells an agent which tools to call — and it was naming
 * `cello_list_sessions`, `cello_get_sealed_receipt` and `cello_receive_session` after all three had
 * been renamed or deleted. Every audit written for this story scanned `.ts` files, so not one of
 * them ever looked at it, and it went out in connect@0.0.66.
 *
 * That is the same class as the Hermes scaffolded assets, caught for the third time. The lesson the
 * audits kept missing: follow what SHIPS, not what compiles.
 */
const PKG = JSON.parse(readFileSync(join(here, "..", "..", "package.json"), "utf8")) as {
  files?: string[];
};
const SHIPPED_DOCS = (PKG.files ?? [])
  .filter((f) => f.endsWith(".md"))
  .map((f) => ({ name: f, text: readFileSync(join(here, "..", "..", f), "utf8") }));

/** Every tool the shim entrypoint registers — the surface an operator's MCP client actually sees. */
function registeredTools(): string[] {
  return [...source.matchAll(/server\.tool\("(cello_[a-z_]+)"/g)].map((m) => m[1]).sort();
}

describe("DOD-ONBOARD-HELP-1 §2b — CLI ↔ MCP name parity", () => {
  it("registers at least the full known surface (guards against a vacuous pass)", () => {
    expect(registeredTools().length).toBeGreaterThanOrEqual(25);
  });

  it("every registered tool name exists in the vocabulary", () => {
    const known = knownToolNames();
    const strangers = registeredTools().filter((t) => !known.has(t));
    expect(
      strangers,
      `The shim registers tool(s) the vocabulary does not know. Either add them to ` +
        `DUAL_SURFACE_VERBS (with their CLI command) or MCP_ONLY_TOOLS, or fix the name. A tool ` +
        `outside the vocabulary is a capability with two names — the exact thing §2b abolishes.`,
    ).toEqual([]);
  });

  it("every DUAL-surface capability is actually registered as a tool", () => {
    const registered = new Set(registeredTools());
    const missing = DUAL_SURFACE_VERBS.map((v) => v.mcp).filter((m) => !registered.has(m));
    expect(
      missing,
      `The vocabulary promises these are reachable from MCP, but the shim never registers them. ` +
        `A promise the binary does not keep is worse than an absent one.`,
    ).toEqual([]);
  });

  it("the MCP-only custody stubs are registered (they are the ONLY non-dual tools)", () => {
    const registered = new Set(registeredTools());
    for (const t of MCP_ONLY_TOOLS) expect(registered.has(t), `${t} missing`).toBe(true);
  });

  it("the OLD, pre-rename tool names are gone from the shim", () => {
    // A leftover here is not cosmetic: the daemon's error guidance now names the NEW tools, so a
    // stale registration means the operator is told to call `cello_transcript` while the shim only
    // offers `cello_get_transcript`. Half a rename is worse than none.
    for (const stale of [
      "cello_list_agents",
      "cello_list_sessions",
      "cello_check_notifications",
      "cello_get_transcript",
      "cello_get_sealed_receipt",
      "cello_set_moniker",
      "cello_contact_list",
    ]) {
      expect(source, `${stale} is still registered as a tool`).not.toContain(`server.tool("${stale}"`);
    }
  });

  it("cello_receive_session is DELETED — no registration, no proxy call, nowhere in the shim", () => {
    // Andre, 2026-07-11: delete it fully. It was a literal alias of cello_receive (the daemon ran the
    // SAME handler) whose description claimed an accept/join step CELLO does not have. The daemon
    // handler is gone too, so a lingering registration here would proxy to a method that no longer
    // exists — a tool that is guaranteed to fail. Assert the whole file, not just the registration.
    expect(source).not.toContain("cello_receive_session");
  });

  it("every cello_* token in a PUBLISHED doc is a REAL tool", () => {
    // ALLOWLIST, not a denylist — and the distinction is the whole finding.
    //
    // The first cut checked SKILL.md against RENAMED_AWAY_TOOLS (the 8 names this story killed). It
    // went green while SKILL.md handed an agent ELEVEN other tools that do not exist —
    // cello_request_connection, cello_accept_connection, cello_get_policy, cello_setup_guidance,
    // cello_list_connections … all M1 leftovers that survive only in the legacy in-process server.
    // A denylist can only catch the deaths you remember. This doc had drifted into fiction: it also
    // never mentioned 15 tools that DO exist.
    //
    // An allowlist is safe HERE (and was not, in core/cli/src) because a shipped .md is pure
    // agent-facing prose — it carries no IPC wire names, which is the one thing that legitimately
    // names a tool that is not on the tool surface.
    expect(SHIPPED_DOCS.length, "no shipped .md found — this audit would be vacuous").toBeGreaterThan(0);
    const known = knownToolNames();
    const stale = SHIPPED_DOCS.flatMap((d) =>
      [...new Set(d.text.match(/cello_[a-z_]+/g) ?? [])]
        .filter((t) => !known.has(t))
        .map((t) => `${d.name}: ${t}`),
    );
    expect(
      stale,
      `A PUBLISHED doc names a tool that does not exist. SKILL.md ships inside the tarball and is ` +
        `the doc that hands an agent its tool list — a dead name here is an agent calling a tool ` +
        `that is not there.\n  ${stale.join("\n  ")}`,
    ).toEqual([]);
  });

  it("the shipped docs actually document the LIVE surface (not a stale subset)", () => {
    // The mirror of the above: absence of dead names is not presence of real ones. SKILL.md had
    // drifted so far it omitted 15 live tools while advertising 11 dead ones.
    const doc = SHIPPED_DOCS.map((d) => d.text).join("\n");
    for (const t of ["cello_agents", "cello_use_agent", "cello_inbox", "cello_transcript", "cello_contacts", "cello_sealed_receipt"]) {
      expect(doc, `SKILL.md never mentions ${t}, a live tool`).toContain(t);
    }
  });

  it("the IPC wire names are NOT renamed — the shim still calls the daemon's existing methods", () => {
    // The tool renamed; the method it proxies to did not. This is deliberate: connect has no daemon
    // dependency, so a new daemon must keep serving an OLD shim. Renaming the wire would break that
    // pairing silently. Assert the mapping really is tool≠method for the renamed ones.
    expect(source).toContain('proxy.call("cello_list_agents")');
    expect(source).toContain('proxy.call("cello_get_transcript"');
    expect(source).toContain('proxy.call("cello_check_notifications"');
  });
});
