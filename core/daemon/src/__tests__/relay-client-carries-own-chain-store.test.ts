/**
 * Every production relay client carries the durable record of what this agent has said.
 *
 * Live 2026-09-15, lid-close test: `session.relay.own_chain.store_absent` fired at ERROR on the Mac
 * at wake. The LIVE session's client (`connectSessionRelay`) was built without `ownChainStore`,
 * while the detached builder in `boot-parked-content.ts` passed it. Its own log line says what that costs: after a daemon
 * restart mid-conversation this side starts a new chain, and the counterparty refuses every later
 * message as though the record had been altered.
 *
 * A source check, because the construction sites drifted apart once already and a behavioural
 * test would pin only one of them.
 */
import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const SRC = join(dirname(fileURLToPath(import.meta.url)), "..");

describe("relay client construction", () => {
  it("★★★ every `new AgentRelayClient({` in production source passes ownChainStore", () => {
    const sites: Array<{ file: string; carries: boolean }> = [];
    const files = (readdirSync(SRC, { recursive: true }) as string[])
      .filter((f) => f.endsWith(".ts") && !f.split(/[\\/]/).includes("__tests__"));
    for (const file of files) {
      const text = readFileSync(join(SRC, file), "utf8");
      for (let i = text.indexOf("new AgentRelayClient({"); i !== -1; i = text.indexOf("new AgentRelayClient({", i + 1)) {
        // The options object ends at the first line closing at the construction's own indentation.
        const lineStart = text.lastIndexOf("\n", i) + 1;
        const indent = /^\s*/.exec(text.slice(lineStart, i))![0];
        const end = text.indexOf(`\n${indent}});`, i);
        const block = text.slice(i, end === -1 ? undefined : end);
        sites.push({ file, carries: block.includes("ownChainStore") });
      }
    }
    expect(sites.length, "PRECONDITION: the scan found the construction sites").toBeGreaterThanOrEqual(2);
    expect(
      sites.filter((s) => !s.carries).map((s) => s.file),
      "a client without the store cannot chain to its own last message after a restart",
    ).toEqual([]);
  });
});
