/**
 * THE VOCABULARY MUST BE AN EXEMPTION LIST, NOT AN INCLUSION LIST.
 *
 * The existing parity test asks "is every capability in `DUAL_SURFACE_VERBS` registered on both
 * surfaces?" — which is sound, and blind in one direction. Add a capability WITHOUT adding its
 * vocabulary row and the test checks a shorter list against a shorter list, finds them consistent,
 * and passes. It cannot fail, because the thing you broke is not in what it looks at.
 *
 * That is exactly how `cello trust-signals results` shipped CLI-only (2026-07-30): daemon handler
 * written, CLI verb written, vocabulary row forgotten, gate green.
 *
 * It is also the shape of three other failures in the same 48 hours — a table declared in a
 * replication list that was never applied; a column added to a schema that no writer filled in; a
 * spec listing a table the store's registry did not carry. Every one is a hand-maintained list
 * trusted as complete by something downstream, where FORGETTING IS SILENT.
 *
 * So this test walks the other way: the daemon's own `handlers.set("cello_…")` registrations are the
 * ground truth of what capabilities exist, and every one must be accounted for — either as a
 * dual-surface verb or as a DELIBERATE exemption written down here. Forgetting now FAILS, and an
 * exemption you must type is one you have to think about.
 *
 * Static source scan rather than constructing a daemon: handlers are registered from six modules
 * into a map local to `createDaemon`, and standing one up needs a database, transport and keys. The
 * sibling parity test already reads source for exactly this reason.
 */
import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
// Deliberately NOT importing the vocabulary. This test asks whether a capability is REACHABLE from
// each surface, which is the property that matters — the daemon's internal handler name and its tool
// name differ (`wallet_list_signals` is `cello_trust_signals_list`), so comparing names would only
// re-test the naming convention, not whether an operator can actually call the thing.

const here = dirname(fileURLToPath(import.meta.url));
const SRC = join(here, "..");

/**
 * Capabilities that are deliberately NOT on both surfaces. Each needs a reason, because the reason
 * is the whole value of the list — an unexplained entry is indistinguishable from an oversight, and
 * the next reader cannot tell whether removing it is a fix or a regression.
 */
const EXEMPT = new Map<string, string>([
  ["cello_refresh_shares", "recovery plumbing invoked by the restore flow, never an operator verb"],
  ["cello_get_relay_receipts", "diagnostic read used by support tooling, not surfaced to operators"],
  ["cello_telegram_set_token", "credential entry — deliberately terminal-only, never over MCP"],
  ["cello_create_agent", "onboarding runs in the terminal; the MCP shim has no agent to act as yet"],
  ["cello_register", "onboarding runs in the terminal; needs a token pasted from another channel"],
  ["cello_remove_agent", "destructive and irreversible — deliberately requires the terminal"],
  ["cello_status", "`cello status` serves this from `cello_list_agents`; both surfaces have the verb"],
  ["wallet_list_issued", "not its own verb — joined into the results verb on BOTH surfaces so a submission awaiting the subject shows as pending"],
  /**
   * DOD-M15-BACKUP-1. Both verbs EXIST on both surfaces — `cello backup` / `cello restore` and
   * `cello_backup` / `cello_restore` — so this is not the usual single-surface exemption. They are
   * listed because the CLI does not PROXY the daemon handler, which is what the scan looks for, and
   * in both cases not proxying is the point.
   */
  ["cello_backup", "the CLI runs the capability directly (backup-restore.ts) instead of proxying the handler, so an operator can still export their identity when the daemon will not start — which is exactly when a backup matters"],
  ["cello_restore", "restore must run with the daemon STOPPED: a running daemon holds the database open and could flush its own pages over the restored ones, leaving a database that is half one identity and half another. The MCP handler therefore refuses and prints the sequence; only the CLI performs it"],
  /**
   * DOD-M15-INCLUSION-1, and this guard is the reason they are listed AT ALL.
   *
   * `cello_get_inclusion_proof` existed before this unit and was invisible here: its handler was
   * registered inside a `for (const tool of [...])` loop, and the scan below looks for a literal
   * `handlers.set("cello_…")`. So a capability shipped MCP-only for a whole milestone without ever
   * reaching this list. Giving it a real handler is what surfaced it — which is the inversion
   * working, one release later than it should have.
   */
  ["cello_get_inclusion_proof", "MCP-only, as it was before it was implemented — the caller is an agent holding a session it is already acting in, and the proof is an object to hand on rather than a line to read in a terminal"],
  ["cello_verify_inclusion_proof", "MCP-only for now, matching the tool it checks. ⚠️ THE WEAKER HALF OF THE PAIR, and stated plainly: the verifier reads no session and no database precisely so a SCEPTIC can run it, and a sceptic is likelier to have a terminal than an MCP client. A CLI twin is recorded under 'Newly discovered' on the 009-PROOF work order rather than built here"],
]);

/** Handlers that are not capabilities at all. */
const isInternal = (name: string): boolean => !name.startsWith("cello_") && !name.startsWith("wallet_");

const SHIM = readFileSync(join(here, "..", "..", "..", "adapter-claude-code", "src", "bin", "cello-mcp.ts"), "utf8");
const CLI = readdirSync(join(here, "..", "..", "..", "cli", "src"))
  .filter((f) => f.endsWith(".ts"))
  .map((f) => readFileSync(join(here, "..", "..", "..", "cli", "src", f), "utf8"))
  .join("\n");

function registeredCapabilities(): string[] {
  const found = new Set<string>();
  for (const file of readdirSync(SRC).filter((f) => f.endsWith(".ts"))) {
    const src = readFileSync(join(SRC, file), "utf8");
    for (const m of src.matchAll(/handlers\.set\("([a-z_.]+)"/g)) {
      if (!isInternal(m[1]) && !m[1].startsWith("__test")) found.add(m[1]);
    }
  }
  return [...found].sort();
}

/** Does some surface actually call this daemon method? */
const reachableFrom = (source: string, handler: string): boolean => source.includes(`"${handler}"`);

describe("capability registration — surfaces are checked against the DAEMON, not against a list", () => {
  it("finds the daemon's capabilities at all (guards against a vacuous pass)", () => {
    // Without this, a regex that matched nothing would make every assertion below trivially true —
    // the same blindness this file exists to remove, reintroduced one level up.
    const caps = registeredCapabilities();
    expect(caps.length, "the scan found no handlers — the regex or the layout changed").toBeGreaterThan(15);
    expect(caps, "a known capability must be among them").toContain("cello_await_session");
  });

  it("EVERY capability is reachable from BOTH surfaces, or exempted in writing", () => {
    // THE INVERSION. The old parity test asked "is every listed verb registered?" — so a capability
    // with no list entry made the check shorter rather than failing it. `cello trust-signals results`
    // and `wallet_list_issued` both shipped CLI-only that way, gate green both times.
    //
    // Asking the daemon instead means a new handler must be dealt with on the day it is written.
    const missing = registeredCapabilities()
      .filter((c) => !EXEMPT.has(c))
      .map((c) => ({ c, mcp: reachableFrom(SHIM, c), cli: reachableFrom(CLI, c) }))
      .filter((x) => !x.mcp || !x.cli)
      .map((x) => `${x.c} (missing from ${!x.mcp ? "MCP" : ""}${!x.mcp && !x.cli ? " and " : ""}${!x.cli ? "CLI" : ""})`);

    expect(
      missing,
      `these daemon capabilities are not reachable from both surfaces. Either wire the missing one, ` +
        `or add the capability to EXEMPT above with the reason it is deliberately single-surface`,
    ).toEqual([]);
  });

  it("every exemption names a reason", () => {
    // An unexplained exemption is indistinguishable from an oversight, and the next reader cannot
    // tell whether removing it is a fix or a regression.
    for (const [name, reason] of EXEMPT) {
      expect(reason.length, `${name} is exempt with no reason`).toBeGreaterThan(20);
    }
  });
});
