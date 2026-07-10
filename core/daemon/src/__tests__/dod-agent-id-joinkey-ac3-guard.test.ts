/**
 * DOD-AGENT-ID-JOINKEY-1 — AC3 guard: `agent_name` never scopes a query again.
 *
 * The migration demoted `agent_name` to a display attribute of the `agents` table. The standing rule
 * (repo .claude/CLAUDE.md, "Database — join on the STABLE key, never the mutable one") makes any
 * `agent_name` in a PRIMARY KEY, JOIN, or WHERE-match a review-blocker anywhere.
 *
 * A rule a human has to remember is a rule that decays. This test is the enforcement: it scans the
 * daemon's data-access source for SQL that scopes on `agent_name` and fails if any reappears. It is
 * the AC3 sibling of the AC1 wire scan — same "prove the absence, mechanically" shape.
 *
 * It cannot live as an ESLint AST rule: the offending text is inside SQL STRING LITERALS, invisible
 * to the linter's syntax tree. A source scan is the right tool.
 *
 * What is ALLOWED and must NOT trip it:
 *   - `SELECT agent_name …` for display, and `AS agent_name` from a JOIN to `agents`.
 *   - the ONE resolver `SELECT agent_id FROM agents WHERE agent_name = ?` — the sanctioned boundary
 *     where a name becomes a key, against the `agents` table itself (never a session table).
 *   - prose in comments.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

/** The files that own the seven re-keyed tables' SQL. */
const DATA_ACCESS_FILES = [
  join(HERE, "..", "session-node-manager.ts"),
  join(HERE, "..", "retry-queue.ts"),
];

/** Strip block and line comments — prose about agent_name is fine; only executable SQL matters. */
function stripComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
}

/**
 * SQL fragments that use `agent_name` as a KEY rather than for display. Word-boundary anchored so
 * `counterparty_agent_name` (were it ever added) would not false-negative, and vice versa.
 */
const SCOPING_PATTERNS: Array<{ re: RegExp; what: string }> = [
  { re: /\bWHERE\b[^;)]*\bagent_name\b\s*=/i, what: "WHERE agent_name =" },
  { re: /\bagent_name\b[^;)]*\bWHERE\b/i, what: "agent_name used before WHERE (reversed predicate)" },
  { re: /\bPRIMARY\s+KEY\s*\([^)]*\bagent_name\b/i, what: "PRIMARY KEY (… agent_name …)" },
  { re: /\bON\s+CONFLICT\s*\([^)]*\bagent_name\b/i, what: "ON CONFLICT (… agent_name …)" },
  { re: /\bJOIN\b[^;]*\bON\b[^;]*\bagent_name\b/i, what: "JOIN … ON … agent_name" },
  { re: /\b(INSERT\s+(?:OR\s+\w+\s+)?INTO|REPLACE\s+INTO)\s+(?!agents\b)\w+[^;]*\(\s*[^)]*\bagent_name\b/i, what: "INSERT INTO <session table> (… agent_name …)" },
];

/**
 * The ONE sanctioned use: the resolver reads agent_id FROM the agents table, keyed by name. Matching
 * it against `agents` (not a session table) is exactly the demotion working — the name is a lookup
 * key on its OWN table, and a foreign key nowhere.
 */
const RESOLVER_RE = /SELECT\s+agent_name\s+FROM\s+agents|SELECT\s+agent_id\s+FROM\s+agents\s+WHERE\s+agent_name/i;

describe("DOD-AGENT-ID-JOINKEY-1 AC3 — agent_name never scopes a session-table query", () => {
  it("the scan covers the data-access files (it has teeth)", () => {
    for (const f of DATA_ACCESS_FILES) {
      expect(readFileSync(f, "utf8").length, `${f} must be readable and non-empty`).toBeGreaterThan(0);
    }
  });

  it("no PRIMARY KEY / WHERE / JOIN / ON CONFLICT / INSERT scopes on agent_name", () => {
    const offenders: string[] = [];
    for (const file of DATA_ACCESS_FILES) {
      const code = stripComments(readFileSync(file, "utf8"));
      // Look at each SQL-ish line; skip the sanctioned agents-table resolver.
      for (const [i, rawLine] of code.split("\n").entries()) {
        if (!/agent_name/.test(rawLine)) continue;
        if (RESOLVER_RE.test(rawLine)) continue;
        for (const { re, what } of SCOPING_PATTERNS) {
          if (re.test(rawLine)) {
            offenders.push(`${file.slice(HERE.length + 1)}:${i + 1}  [${what}]  ${rawLine.trim().slice(0, 100)}`);
          }
        }
      }
    }
    expect(
      offenders,
      "agent_name is back in a session-table key/join/where. It is a mutable, reuse-freed display " +
        "label — scoping on it hands one identity's rows to another keypair (DOD-AGENT-ID-JOINKEY-1). " +
        "Scope by agent_id; resolve the name once via #requireAgentId.",
    ).toEqual([]);
  });

  it("multi-line PRIMARY KEY declarations are caught too (schema spans lines)", () => {
    // The CREATE TABLE blocks put `PRIMARY KEY (agent_id, …)` on its own line, several lines below
    // the column list. Scan the whole (comment-stripped) file so a `PRIMARY KEY (agent_name` that
    // wraps is not missed by the per-line pass above.
    const offenders: string[] = [];
    for (const file of DATA_ACCESS_FILES) {
      const code = stripComments(readFileSync(file, "utf8"));
      const m = code.match(/PRIMARY\s+KEY\s*\([^)]*\bagent_name\b[^)]*\)/gi);
      if (m) offenders.push(`${file.slice(HERE.length + 1)}: ${m.join(" ; ")}`);
    }
    expect(offenders, "a PRIMARY KEY still names agent_name — the exact schema artifact this unit removed").toEqual([]);
  });
});
