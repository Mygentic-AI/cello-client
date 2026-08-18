/**
 * DOD-M9B-ENV-1 (policy D-5) — the environment cannot loosen a guard. Proven, not asserted.
 *
 * Four variables used to sit UNDER the config store as defaults, so anyone who could set an
 * environment variable could enable autonomous override, seed the PII whitelist, or raise the
 * outbound rate cap — with no confirmation, no versioned row, and no hash-chained fingerprint.
 * That is the entire tighten-free / loosen-confirmed mechanism bypassed. A gate with a published
 * bypass is not a gate.
 *
 * These tests spawn the REAL BUILT bin with the old variables set to their most permissive values
 * and prove they do nothing. The revert test: restore any one fallback and the matching case here
 * goes red, because the gateway would start honoring it again.
 */
import { describe, it, expect, beforeAll } from "vitest";
import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";
import { spawnGatewaySidecar } from "../spawn.js";
import { LocalSidecarGatewayClient } from "../client.js";

const PKG_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

/** The four policy variables D-5 removed, at their most permissive settings. */
const REMOVED_POLICY_ENV = {
  CELLO_GATEWAY_AUTONOMOUS_OVERRIDE: "1",
  CELLO_GATEWAY_PII_WHITELIST: "secret@leak.example",
  CELLO_GATEWAY_RATE_MAX_PER_WINDOW: "9999",
  CELLO_GATEWAY_RATE_WINDOW_MS: "1",
};

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else out.push(full);
  }
  return out;
}

describe("DOD-M9B-ENV-1 — the environment is not a config surface", () => {
  beforeAll(() => {
    execFileSync("npx", ["tsc", "--build"], { cwd: PKG_ROOT, stdio: "pipe", timeout: 180_000 });
  }, 200_000);

  it("nothing in the built artifact READS the four policy variables — asserted on what ships", () => {
    // Match the ACCESS, not the name. `tsc` preserves comments, and the bin carries one explaining
    // why these were removed — which is documentation worth keeping, not a bypass. What must not
    // exist is code that reads them: `process.env["NAME"]` or `process.env.NAME`.
    const offenders: string[] = [];
    for (const file of walk(join(PKG_ROOT, "dist")).filter((f) => f.endsWith(".js"))) {
      const text = readFileSync(file, "utf8");
      for (const name of Object.keys(REMOVED_POLICY_ENV)) {
        const reads = new RegExp(`process\\.env\\s*(\\[\\s*["'\`]${name}["'\`]\\s*\\]|\\.${name}\\b)`);
        if (reads.test(text)) offenders.push(`${file.replace(PKG_ROOT, "")}: reads ${name}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it("the assertion above is not vacuous — it DOES catch a process.env read of a gateway variable", () => {
    // The store paths are still read from the environment (plumbing, not policy), so this proves
    // the regex finds a real read in the real artifact rather than passing because it matches
    // nothing at all.
    const bin = readFileSync(join(PKG_ROOT, "dist", "bin", "cello-gateway.js"), "utf8");
    const reads = /process\.env\s*(\[\s*["'`]CELLO_GATEWAY_STORE_DB["'`]\s*\]|\.CELLO_GATEWAY_STORE_DB\b)/;
    expect(reads.test(bin)).toBe(true);
  });

  it("a PII value 'whitelisted' only by the environment is STILL redacted or warned — the bypass is inert", async () => {
    const dir = await mkdtemp(join(tmpdir(), "cello-m9b-env-"));
    try {
      const keyPath = join(dir, "store.key");
      await writeFile(keyPath, randomBytes(32), { mode: 0o600 });
      const sidecar = await spawnGatewaySidecar({
        socketPath: join(dir, "gw.sock"),
        // The BUILT bin: this test runs from source, where the spawner's default entry
        // (./bin/cello-gateway.js beside itself) does not exist.
        entryPath: join(PKG_ROOT, "dist", "bin", "cello-gateway.js"),
        env: {
          ...REMOVED_POLICY_ENV,
          CELLO_GATEWAY_STORE_DB: join(dir, "gateway.db"),
          CELLO_GATEWAY_STORE_KEY_FILE: keyPath,
        },
      });
      try {
        const client = new LocalSidecarGatewayClient({ socketPath: join(dir, "gw.sock") });
        const verdict = await client.screenOutbound(
          new TextEncoder().encode("reach me at secret@leak.example"),
          { direction: "outbound", agentName: "a", sessionId: "s" },
        );
        await client.close();
        // If the env whitelist still worked, this would pass silently as `allow`. It must not.
        expect(verdict.disposition).not.toBe("allow");
      } finally {
        await sidecar.stop();
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }, 60_000);
});
