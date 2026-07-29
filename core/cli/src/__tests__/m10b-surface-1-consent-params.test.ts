import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "../../../..");

/**
 * DOD-END-SURFACE-1 — the two surfaces must send the parameter the DAEMON READS.
 *
 * This exists because the first cut of the consent verbs shipped `signal_hash` from both the MCP tool
 * and the CLI while `cello_consent_accept`/`_refuse` read `hash_prefix`. Every call would have come
 * back `invalid_prefix` — a dead verb on both surfaces, with green name-parity tests either side of
 * it, because name parity checks that the TOOL exists, never that its arguments arrive.
 *
 * A source audit rather than a live call: the alternative is standing up a daemon per verb, and the
 * defect is textual — a name on one side that no longer matches the name on the other.
 */
describe("DOD-END-SURFACE-1 — consent verb parameters reach the handler", () => {
  const daemon = readFileSync(resolve(repo, "core/daemon/src/daemon.ts"), "utf8");
  const mcp = readFileSync(resolve(repo, "core/adapter-claude-code/src/bin/cello-mcp.ts"), "utf8");
  const cli = readFileSync(resolve(repo, "core/cli/src/parity-commands.ts"), "utf8");

  /** The params a handler actually reads: every `params?.<name>` inside its handler body. */
  function paramsReadBy(method: string): Set<string> {
    const start = daemon.indexOf(`handlers.set("${method}"`);
    expect(start, `${method} is registered in the daemon`).toBeGreaterThan(-1);
    const next = daemon.indexOf("handlers.set(", start + 1);
    const body = daemon.slice(start, next === -1 ? daemon.length : next);
    return new Set([...body.matchAll(/params\?\.(\w+)/g)].map((m) => m[1]));
  }

  for (const verb of ["accept", "refuse"] as const) {
    const method = `cello_consent_${verb}`;

    it(`${method}: the MCP tool sends a parameter the handler reads`, () => {
      const call = mcp.match(new RegExp(`proxy\\.call\\("${method}", \\{([^}]*)\\}`));
      expect(call, `${method} is proxied by the MCP shim`).not.toBeNull();
      const sent = [...call![1].matchAll(/(\w+)/g)].map((m) => m[1]);
      const read = paramsReadBy(method);
      expect(sent.length).toBeGreaterThan(0);
      for (const name of sent) {
        expect(read.has(name), `MCP sends '${name}' but ${method} never reads it — the verb is dead`).toBe(true);
      }
    });

    it(`${method}: the CLI sends a parameter the handler reads`, () => {
      const call = cli.match(new RegExp(`IPC_METHODS\\["consent-${verb}"\\], \\{([^}]*)\\}`));
      expect(call, `consent-${verb} is dispatched by the CLI`).not.toBeNull();
      const sent = [...call![1].matchAll(/(\w+):/g)].map((m) => m[1]);
      const read = paramsReadBy(method);
      expect(sent.length).toBeGreaterThan(0);
      for (const name of sent) {
        expect(read.has(name), `CLI sends '${name}' but ${method} never reads it — the verb is dead`).toBe(true);
      }
    });
  }

  it("is not vacuous — it really is reading the handler's parameter names", () => {
    // If paramsReadBy silently returned an empty set, every assertion above would pass by vacuity on
    // the `for` loop never running... except it wouldn't, because `sent` is non-empty and each name is
    // checked against `read`. Pin the extractor directly anyway.
    expect(paramsReadBy("cello_consent_accept")).toContain("hash_prefix");
  });
});
