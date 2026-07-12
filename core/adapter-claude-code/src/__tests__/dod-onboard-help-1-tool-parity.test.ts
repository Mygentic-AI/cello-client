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
 *
 * HISTORY, because the invariant below got STRONGER and the reason matters. `src/server.ts` and
 * `core/client/src/mcp-server.ts` were the legacy M1 in-process MCP servers. An earlier version of
 * this comment claimed they were "not published" — that was WRONG, and review caught it: both were
 * exported from their package roots and shipped in `dist/`. Nothing drove them at runtime (the shim
 * proxies to the daemon), but they still registered the pre-rename tool names, so the tarball
 * carried a SECOND vocabulary — the exact thing §2b abolishes. This test could then only BOUND the
 * damage: it asserted `server.ts` was the ONE file allowed to name a renamed-away tool, so the
 * quarantine could not silently grow.
 *
 * DOD-LEGACY-MCP-1 (2026-07-12) DELETED both servers. The quarantine is now EMPTY, so the assertion
 * is no longer "only server.ts may" — it is "NOBODY may." Do not weaken it back to an allowlist. If
 * this test fails because some file names a renamed-away tool, the answer is to fix that file; there
 * is no longer any such thing as a legitimately-quarantined second vocabulary.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, relative } from "node:path";
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

  it("NOBODY may name a renamed-away tool — the legacy quarantine is empty (DOD-LEGACY-MCP-1)", () => {
    // This assertion used to be an ALLOWLIST: `toEqual(["server.ts"])`. `dist/server.js` — the legacy
    // in-process MCP server — really did ship in the tarball and really did still register
    // cello_receive_session, cello_list_sessions and cello_get_sealed_receipt. It was unreachable at
    // runtime, but exported from the package root, so the tarball carried a SECOND vocabulary. All
    // this test could do was BOUND that: name the one quarantined file so it could not quietly grow.
    //
    // DOD-LEGACY-MCP-1 deleted the file. The quarantine is empty, so the bound becomes an absolute:
    // no source file may name a renamed-away tool. An allowlist that is empty is just a denylist —
    // and this one has no exceptions left to grant.
    //
    // If this fails: do NOT add the offending file to an exception list. There is no exception list.
    // A live source file naming a dead tool is a surface handing an agent a tool that does not exist.
    // Fix the file.
    //
    // The scan is RECURSIVE (it was top-level-only, which would have missed `bin/` and any subdir)
    // and skips `__tests__`, since a test legitimately names dead tools in order to assert they are
    // gone — including the test directly above this one.
    const walk = (dir: string): string[] =>
      readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
        if (e.name === "__tests__" || e.name === "node_modules") return [];
        const full = join(dir, e.name);
        return e.isDirectory() ? walk(full) : e.name.endsWith(".ts") ? [full] : [];
      });

    const SRC = join(here, "..");
    const scanned = walk(SRC);
    // Guard against a vacuous pass: an empty scan would make the assertion below trivially true.
    expect(scanned.length, "the recursive scan found no source files — this audit would be vacuous")
      .toBeGreaterThan(3);

    // WHAT THIS AUDITS: agent-facing surface. A renamed-away name is a defect when an AGENT can see
    // it — a tool registration, a tool description, a guidance string ("Use `cello_list_sessions`
    // to…"). That is what hands an agent a tool that does not exist. Two things are therefore
    // stripped first, and each is a MECHANISM, not a file — a real `server.tool("cello_list_sessions"`
    // in any file, including the shim, is still caught. Do not turn this back into a file allowlist.
    //
    //  1. IPC WIRE CALLS. `bin/cello-mcp.ts` really does contain `proxy.call("cello_list_agents")`.
    //     The TOOL was renamed; the daemon METHOD it proxies to deliberately was NOT — connect has no
    //     daemon dependency, so a new daemon must keep serving an OLD shim. Renaming the wire would
    //     silently break that pairing. The last test in this file asserts those wire names are still
    //     present, so this exemption is not a loophole: it is the other half of a stated contract.
    //  2. COMMENTS. Developer prose never reaches an agent, and the comments in question exist
    //     precisely to explain the tool↔wire divergence above.
    // The comment strips are ANCHORED to line-leading comments. An unanchored `//` strip would kill
    // everything after any `//` — including one inside a STRING, e.g. a URL in a tool description:
    //   server.tool("cello_sessions", "See https://docs.cello.dev — replaces cello_list_sessions")
    // …which would erase `cello_list_sessions` and turn the audit whose whole job is to catch that
    // name GREEN. The stripper must never be able to destroy the evidence it is filtering around.
    // Anchoring covers every real comment in these files and cannot eat a string literal.
    const agentFacing = (text: string): string =>
      text
        .replace(/^\s*\/\*[\s\S]*?\*\//gm, "")            // block comments (line-leading)
        .replace(/^\s*\*.*$/gm, "")                       // jsdoc continuation lines
        .replace(/^\s*\/\/.*$/gm, "")                     // line comments (line-leading)
        .replace(/proxy\.call\(\s*"cello_[a-z_]+"/g, ""); // IPC wire method names

    const STALE = /cello_(receive_session|list_sessions|get_sealed_receipt|list_agents|check_notifications|get_transcript|set_moniker|contact_list)/;

    // NEGATIVE CONTROL. `agentFacing()` is a stripper, and a stripper that strips too much turns this
    // audit green by erasing the evidence. Prove it still bites: a registration and a guidance string
    // must survive stripping and be caught, while a wire call and a comment must not.
    expect(STALE.test(agentFacing('server.tool("cello_list_sessions", {...})')),
      "a tool registration must still be caught").toBe(true);
    expect(STALE.test(agentFacing('desc: "Use cello_get_sealed_receipt to fetch the receipt"')),
      "an agent-facing guidance string must still be caught").toBe(true);
    // THE ONE THAT MATTERS: a `//` inside a string must not let the stripper eat the evidence after
    // it. This is the exact hole an unanchored comment-strip would open.
    expect(STALE.test(agentFacing('server.tool("cello_sessions", "See https://x.dev — replaces cello_list_sessions")')),
      "a stale name after a URL's // must STILL be caught — the stripper may not erase evidence").toBe(true);
    expect(STALE.test(agentFacing('const r = await proxy.call("cello_list_agents");')),
      "an IPC wire call is not a tool name").toBe(false);
    expect(STALE.test(agentFacing('  // the daemon still exposes cello_set_moniker on the wire')),
      "a developer comment is not agent-facing").toBe(false);

    const offenders = scanned
      .filter((f) => STALE.test(agentFacing(readFileSync(f, "utf8"))))
      .map((f) => relative(SRC, f));

    expect(
      offenders.sort(),
      "A source file names a renamed-away tool. The legacy in-process servers are DELETED, so there " +
        "is no legitimate quarantine left — this is a live surface advertising a tool that does not exist.",
    ).toEqual([]);
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
