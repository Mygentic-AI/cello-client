/**
 * DOD-AGENT-ID-JOINKEY-1 — AC1: the WIRE PROOF. This test GATES the whole unit.
 *
 * The migration re-keys seven local tables from `agent_name` to `agent_id`. That is safe to do
 * unilaterally, on one machine, with no directory change and no deploy, ONLY IF no wire frame
 * identifies a party by name. This file proves that, and it is the reason the rest of the unit is
 * allowed to exist. If it goes red, STOP — the client-only premise is wrong and the story re-scopes.
 *
 * AC1 IS TWO CLAIMS, AND THEY HAVE DIFFERENT TRUTH VALUES. The story originally said "`agent_name`
 * must appear in ZERO wire structures". That is FALSE, and believing it is dangerous. Split it:
 *
 *   (a) No wire frame declares a field NAMED `agent_name`/`agentName`. Parties are identified by
 *       pubkey and session_id, always.  ← TRUE, and asserted negatively below.
 *
 *   (b) The agent's NAME VALUE does reach the wire — exactly once, as `offered_moniker`, whose
 *       MONIKER-1 default is `moniker ?? agent_name` (db-identity-store `getOutboundName`). It is a
 *       SELF-DECLARED DISPLAY LABEL: charset-bounded by MONIKER_RE, never a key, never persisted by
 *       the directory, pinned-to-pubkey by the receiver.  ← TRUE, and asserted POSITIVELY below.
 *
 * (b) is asserted positively ON PURPOSE. A diligent implementer who reads only claim (a), greps, and
 * finds `offered_moniker: "Ms_Chelly"` on a live frame would conclude the wire proof FAILED and "fix"
 * it by severing the `?? agent_name` fallback — deleting MONIKER-1/MONIKER-2, a shipped feature, to
 * satisfy a mis-worded criterion. A wrong invariant is more dangerous than a missing one: it recruits
 * a careful person into breaking something. These tests make severing the fallback go RED.
 *
 * What (a) and (b) together license: the local JOIN KEY changes; the wire LABEL does not. Nothing in
 * this migration alters a byte on the wire, so it cannot desync the directory or confuse a peer.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { MONIKER_RE, validateMoniker } from "@cello-protocol/protocol-types";
import { DbIdentityStore, ensureIdentitySchema } from "../db-identity-store.js";
import type { Logger } from "../types.js";

function makeLogger(): Logger {
  return { debug() {}, info() {}, warn() {}, error() {} };
}

// core/daemon/src/__tests__ → up four → repo root.
const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");

/**
 * The NETWORK wire surface: frame encoders/decoders whose output crosses a socket to a peer or to a
 * directory node. Deliberately EXCLUDES the local IPC surface (core/gateway, core/adapter-claude-code,
 * core/daemon), where `agent_name` is not merely tolerable but CORRECT — the operator addresses their
 * own agent by name (`cello_use_agent { name }`), on one machine, and no peer ever sees it.
 *
 * The retire-reuse ambiguity that poisons a DB join cannot arise on the IPC path either: IPC-by-name
 * resolves only ACTIVE agents, and the `agents_active_name` partial unique index makes active names
 * unique. The same index that FAILS to protect the session tables (they keep retired rows) DOES
 * protect IPC addressing (it never crosses the retired boundary). That asymmetry is the whole defect.
 */
const WIRE_SOURCE_DIRS = [
  join(REPO_ROOT, "core", "transport", "src"),
  join(REPO_ROOT, "core", "protocol-types", "src"),
];

/** Frame parsers that live outside the two wire packages but decode directory frames. */
const WIRE_SOURCE_FILES = [
  join(REPO_ROOT, "core", "client", "src", "session-assignment-parser.ts"),
  join(REPO_ROOT, "core", "daemon", "src", "session-assignment-parser.ts"),
];

/** Strip block and line comments so PROSE about agent_name never trips the scan — only code does. */
function stripComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
}

function wireSourceFiles(): string[] {
  const files: string[] = [...WIRE_SOURCE_FILES];
  for (const dir of WIRE_SOURCE_DIRS) {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.isFile() && entry.name.endsWith(".ts")) files.push(join(dir, entry.name));
    }
  }
  return files;
}

describe("DOD-AGENT-ID-JOINKEY-1 AC1(a) — no wire frame identifies a party by NAME", () => {
  it("the wire source set is non-empty and includes the signaling + frame modules (the scan has teeth)", () => {
    const files = wireSourceFiles();
    // A scan over an empty/mis-pathed file set would vacuously "pass". Pin that it actually reads
    // the modules that matter, or this whole gate is theatre.
    expect(files.length).toBeGreaterThan(5);
    expect(files.some((f) => f.endsWith("signaling-manager.ts"))).toBe(true);
    expect(files.some((f) => f.endsWith("node.ts"))).toBe(true);
    expect(files.some((f) => f.endsWith("session.ts"))).toBe(true);
    expect(files.some((f) => f.endsWith("session-assignment-parser.ts"))).toBe(true);
    for (const f of files) expect(readFileSync(f, "utf8").length).toBeGreaterThan(0);
  });

  it("declares no field named agent_name / agentName anywhere on the network wire", () => {
    const offenders: string[] = [];
    for (const file of wireSourceFiles()) {
      const code = stripComments(readFileSync(file, "utf8"));
      // Word-boundary match on both the snake_case wire spelling and the camelCase TS spelling.
      const hits = code.match(/\bagent_name\b|\bagentName\b/g);
      if (hits) offenders.push(`${file.slice(REPO_ROOT.length + 1)} (${hits.length} occurrence(s))`);
    }
    expect(
      offenders,
      "An agent NAME became part of a network frame. The DOD-AGENT-ID-JOINKEY-1 migration assumes " +
        "the wire identifies parties by pubkey + session_id ONLY, so a local re-key cannot desync " +
        "the directory or confuse a peer. That assumption just broke — STOP and re-scope the story.",
    ).toEqual([]);
  });
});

describe("DOD-AGENT-ID-JOINKEY-1 AC1(b) — the name reaches the wire ONLY as a display moniker", () => {
  /** A minimal agents table + one agent, via the real identity store. */
  function storeWithAgent(name: string): { store: DbIdentityStore; db: DatabaseSync } {
    const db = new DatabaseSync(":memory:");
    ensureIdentitySchema(db);
    const store = new DbIdentityStore(db, makeLogger());
    store.createAgent(name, new Uint8Array(32).fill(7), "aa".repeat(32));
    return { store, db };
  }

  it("POSITIVE: with no moniker override, the outbound name IS the agent_name — do not sever this", () => {
    const { store } = storeWithAgent("CELLO_Support");
    // This is the `moniker ?? agent_name` fallback (MONIKER-1 AC1). It is the ONE path by which an
    // agent's name reaches a peer. It is CORRECT. A test that demands "agent_name never crosses the
    // wire" would delete it — hence this positive assertion, which goes red if anyone tries.
    expect(store.getOutboundName("CELLO_Support")).toBe("CELLO_Support");
  });

  it("POSITIVE: an explicit moniker override replaces the name on the wire (the name is not special)", () => {
    const { store } = storeWithAgent("CELLO_Support");
    store.setMoniker("CELLO_Support", "Helpdesk");
    // The wire label is a LABEL. It is whatever the operator declares. The name is only its default —
    // which is exactly why the name is display, not identity.
    expect(store.getOutboundName("CELLO_Support")).toBe("Helpdesk");
  });

  it("the outbound label is charset-bounded by MONIKER_RE (it cannot forge a channel tag)", () => {
    const { store } = storeWithAgent("CELLO_Support");
    const outbound = store.getOutboundName("CELLO_Support")!;
    expect(validateMoniker(outbound)).toBe(outbound);
    expect(MONIKER_RE.test(outbound)).toBe(true);
  });

  it("the STABLE key never reaches the wire either — the outbound label is never the agent_id", () => {
    // Guards the opposite over-correction: "the name is unsafe on the wire, send the stable id".
    // agent_id is an internal surrogate. Leaking it would hand peers a correlatable identifier that
    // survives rename, for no protocol benefit. The wire gets a pubkey and a self-declared label.
    const { store, db } = storeWithAgent("CELLO_Support");
    const agentId = (db.prepare("SELECT agent_id FROM agents WHERE agent_name = ?").get("CELLO_Support") as { agent_id: string }).agent_id;
    const outbound = store.getOutboundName("CELLO_Support");
    expect(agentId).toMatch(/^[0-9a-f-]{8,}$/);
    expect(outbound).not.toBe(agentId);
  });
});
