/**
 * DOD-DOC-SKILL-1 — the PLUGIN skills are shipped content, and nothing was auditing them.
 *
 * `core/adapter-claude-code/SKILL.md` is audited (adapter-002) because it rides in the connect
 * tarball. The plugin's own skills — `plugins/cello/skills/*` — ship a different way: the
 * marketplace install clones the repo, so committing them IS publishing them. They were unaudited,
 * and they are the files an agent actually reads before driving CELLO.
 *
 * A skill is not documentation. It is an instruction sheet handed to a model that will act on it, so
 * a tool name that no longer exists does not read as a stale doc — it reads as a capability, and the
 * agent calls it, gets `method_not_found`, and reports a broken system. The daemon has carried this
 * exact guard for its guidance strings since DOD-ONBOARD-HELP-1; the skills needed the same one.
 */

import { describe, it, expect } from "vitest";
import { readFile, readdir } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { knownToolNames, RENAMED_AWAY_TOOLS, deadCliVerbPattern } from "@cello-protocol/daemon";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SKILLS_DIR = join(__dirname, "../../../../plugins/cello/skills");

async function skillFiles(): Promise<Array<{ name: string; content: string }>> {
  const dirs = await readdir(SKILLS_DIR, { withFileTypes: true });
  return Promise.all(
    dirs
      .filter((d) => d.isDirectory())
      .map(async (d) => ({
        name: d.name,
        content: await readFile(join(SKILLS_DIR, d.name, "SKILL.md"), "utf-8"),
      })),
  );
}

describe("plugin skills — shipped content, audited like shipped content", () => {
  it("finds the skills at all", async () => {
    // Guards the guard. A moved directory would otherwise make every assertion below pass over an
    // empty list — the shape that let five trust-signal tools ship undocumented.
    const skills = await skillFiles();
    expect(skills.length).toBeGreaterThan(0);
    expect(skills.map((s) => s.name).sort()).toContain("documents");
  });

  it("names no tool that was RENAMED AWAY or deleted", async () => {
    // DENYLIST, not the allowlist the daemon uses on itself, and `vocabulary.ts` says why: inside
    // the daemon every `cello_*` token is a tool name, so "must be in the table" holds. In a skill
    // it does not — `cello_session_id` is a tool PARAMETER, and prose legitimately writes
    // `cello_doc_*`. An allowlist here either drowns in false positives or accumulates so many
    // exceptions it stops meaning anything. I wrote the allowlist version first and it reported
    // three of those as defects, which is the failure mode the comment predicts.
    const offenders: string[] = [];
    for (const skill of await skillFiles()) {
      for (const dead of RENAMED_AWAY_TOOLS) {
        // Anchored so `cello_receive_session` does not match inside a longer identifier.
        if (new RegExp(`\\b${dead}\\b`).test(skill.content)) offenders.push(`${skill.name}: ${dead}`);
      }
    }
    expect(
      offenders,
      "A skill is an instruction sheet a model ACTS on. A tool name that does not exist is not a " +
        "stale doc — the agent calls it, gets method_not_found, and reports a broken system.",
    ).toEqual([]);
  });

  it("names no CLI verb that does not dispatch", async () => {
    // Needed IN ADDITION to the token audit, which is structurally blind to prose: `cello register`
    // is just words to a `cello_*` matcher. A user handed a command that does nothing is worse off
    // than one handed nothing.
    //
    // ONE pattern over all verbs — `deadCliVerbPattern()` takes no argument. Calling it per-verb
    // (my first version) silently ignored the argument, so a single match was reported against
    // every verb in the list: seven findings for one line, none of them named correctly.
    const offenders: string[] = [];
    for (const skill of await skillFiles()) {
      const matches = skill.content.match(deadCliVerbPattern()) ?? [];
      for (const m of matches) offenders.push(`${skill.name}: ${m}`);
    }
    expect(offenders).toEqual([]);
  });

  it("every skill declares a name and a description an agent can route on", async () => {
    for (const skill of await skillFiles()) {
      // The description is what decides whether the skill is loaded at all. Without it the file is
      // shipped, correct, and never read.
      expect(skill.content.startsWith("---\n"), `${skill.name} has no frontmatter`).toBe(true);
      const frontmatter = skill.content.slice(4, skill.content.indexOf("\n---", 4));
      expect(frontmatter, `${skill.name}`).toMatch(/^name: /m);
      expect(frontmatter, `${skill.name}`).toMatch(/^description: /m);
    }
  });

  it("the documents skill covers every document verb", async () => {
    const skills = await skillFiles();
    const documents = skills.find((s) => s.name === "documents")!;
    const docVerbs = [...knownToolNames()].filter((t) => t.startsWith("cello_doc_"));
    expect(docVerbs.length).toBeGreaterThan(0);
    // Driven off the vocabulary, not a sample: a verb added later fails this until it is documented,
    // which is the only version of this check that stays true.
    const missing = docVerbs.filter((v) => !documents.content.includes(v));
    expect(missing, `plugins/cello/skills/documents/SKILL.md omits: ${missing.join(", ")}`).toEqual([]);
  });
});
