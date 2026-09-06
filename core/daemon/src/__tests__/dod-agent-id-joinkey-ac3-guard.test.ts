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
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

/**
 * EVERY daemon source file, not a list of the ones that owned the SQL when this was written.
 *
 * ⚠️ It WAS a list — `session-node-manager.ts` and `retry-queue.ts`, described as "the files that
 * own the seven re-keyed tables' SQL". That stopped being true the moment the god-file split began:
 * the schema, the queries, the records, the held content, the leaf records and the relay path all
 * hold SQL now and none of them was scanned. Nothing was actually missed — no session table is
 * scoped on `agent_name` anywhere — but the failure mode of a list is that forgetting an entry
 * makes the loop SHORTER, never red, so nobody would have learned otherwise.
 *
 * The rule this guard enforces is universal: no query anywhere may scope a session table on a
 * mutable display label. A universal rule deserves a universal scan, and a glob cannot shrink.
 */
const DATA_ACCESS_FILES = readdirSync(join(HERE, ".."))
  .filter((f) => f.endsWith(".ts"))
  .map((f) => join(HERE, "..", f));

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
 * THE SANCTIONED USE, stated as the rule rather than as two query shapes.
 *
 * The rule is *"`agent_name` never scopes a SESSION table"*. It has always been legal against the
 * `agents` table itself: that is the one place the name is a lookup key on its own row, and a
 * foreign key nowhere. It is how a name is resolved to an id in the first place.
 *
 * ⚠️ This used to be two hard-coded SELECT shapes, and it only looked adequate because the scan
 * was pointed at two files. Widening the scan to the whole directory surfaced SIXTEEN legitimate
 * `agents`-table lookups it did not recognise — none of them a violation, all of them reported as
 * one. **An exemption written as a list of shapes is the same defect as a scan written as a list of
 * files:** it goes stale silently, and the failure is a false accusation rather than a miss.
 *
 * So: a line is exempt when every table it names IS `agents`. A line that touches any other table
 * while scoping on `agent_name` is the thing this guard exists to catch, and it is still caught.
 */
const TABLE_RE = /\b(?:FROM|JOIN|INTO|UPDATE)\s+([A-Za-z_][\w]*)/gi;
/**
 * ⚠️ IT TAKES A WINDOW, NOT A LINE, because SQL wraps. A statement like
 *
 *     `UPDATE agents SET frost_epoch_id=?, …
 *        WHERE agent_name=?`
 *
 * puts the table on one line and the predicate on another, so a per-line exemption sees a bare
 * `WHERE agent_name=?` naming no table at all and reports a legitimate `agents` update as a
 * violation. Looking back to the nearest table token is what makes the exemption match the way
 * people actually write the query.
 */
function onlyTouchesAgentsTable(window: string): boolean {
  const tables = [...window.matchAll(TABLE_RE)].map((m) => m[1]!.toLowerCase());
  return tables.length > 0 && tables.every((t) => t === "agents");
}

/**
 * The ONE file-level exemption, and it is the migration that created the column this rule protects.
 *
 * `agent-id-migration.ts` backfills `agent_id` onto the session tables by joining them to `agents`
 * ON `agent_name`. That join is the entire point of it: before it ran, the name was the only key
 * there was. It can only be written the way the rule forbids, and it runs once.
 */
const EXEMPT_FILES = new Set(["agent-id-migration.ts"]);

describe("DOD-AGENT-ID-JOINKEY-1 AC3 — agent_name never scopes a session-table query", () => {
  it("the scan covers the data-access files (it has teeth)", () => {
    for (const f of DATA_ACCESS_FILES) {
      expect(readFileSync(f, "utf8").length, `${f} must be readable and non-empty`).toBeGreaterThan(0);
    }
    // And it is looking at real SQL, not an empty directory: a scan that reads nothing containing
    // `agent_name` at all would report no offenders forever.
    const mentions = DATA_ACCESS_FILES.filter((f) => /agent_name/.test(readFileSync(f, "utf8")));
    expect(mentions.length, "no daemon source mentions agent_name — this scan is matching nothing")
      .toBeGreaterThan(0);
  });

  it("no PRIMARY KEY / WHERE / JOIN / ON CONFLICT / INSERT scopes on agent_name", () => {
    const offenders: string[] = [];
    for (const file of DATA_ACCESS_FILES) {
      if (EXEMPT_FILES.has(file.split("/").pop()!)) continue;
      const code = stripComments(readFileSync(file, "utf8"));
      // Look at each SQL-ish line; skip the sanctioned agents-table lookups.
      const codeLines = code.split("\n");
      for (const [i, rawLine] of codeLines.entries()) {
        if (!/agent_name/.test(rawLine)) continue;
        // Six lines is comfortably more than the longest wrapped statement in the tree and far less
        // than the distance to an unrelated one.
        if (onlyTouchesAgentsTable(codeLines.slice(Math.max(0, i - 6), i + 1).join(" "))) continue;
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
      if (EXEMPT_FILES.has(file.split("/").pop()!)) continue;
      const code = stripComments(readFileSync(file, "utf8"));
      const m = code.match(/PRIMARY\s+KEY\s*\([^)]*\bagent_name\b[^)]*\)/gi);
      if (m) offenders.push(`${file.slice(HERE.length + 1)}: ${m.join(" ; ")}`);
    }
    expect(offenders, "a PRIMARY KEY still names agent_name — the exact schema artifact this unit removed").toEqual([]);
  });
});
