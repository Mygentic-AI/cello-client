/**
 * CELLO-M7-DAEMON-004 — SI-002 / AC-006: dead-stack retirement.
 *
 * SI-002 (unit): no production code path constructs CelloClient or routes an
 * active session's send / receive / seal through core/client/session-manager.ts
 * or seal-manager.ts. The dead stack is RETIRED, not merely bypassed — verified
 * by a grep over the daemon and adapter production source (outside __tests__)
 * for `new CelloClient`, `session-manager`, and `seal-manager`. Zero matches.
 *
 * AC-006 (finding #7): the check also greps the BUILT production bundles (dist)
 * when present, matching the AC's "built daemon and adapter production bundles"
 * wording — source-clean is the proxy, bundle-clean is the literal artifact.
 */

import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
// core/daemon/src/__tests__ → core
const CORE_ROOT = join(__dirname, "..", "..", "..");

const FORBIDDEN = ["new CelloClient", "session-manager", "seal-manager"];

function collectTsFiles(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) {
      if (entry === "__tests__" || entry === "node_modules" || entry === "dist") continue;
      out.push(...collectTsFiles(full));
    } else if (entry.endsWith(".ts")) {
      out.push(full);
    }
  }
  return out;
}

/** Collect built .js bundle files under a dist directory (excludes test bundles). */
function collectJsFiles(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) {
      if (entry === "__tests__" || entry === "node_modules") continue;
      out.push(...collectJsFiles(full));
    } else if (entry.endsWith(".js")) {
      out.push(full);
    }
  }
  return out;
}

describe("DAEMON-004: SI-002 dead-stack retirement", () => {
  it("daemon + adapter production source contains no CelloClient / session-manager / seal-manager references", () => {
    const dirs = [
      join(CORE_ROOT, "daemon", "src"),
      join(CORE_ROOT, "adapter-claude-code", "src"),
    ];
    const offenders: string[] = [];
    for (const dir of dirs) {
      for (const file of collectTsFiles(dir)) {
        const text = readFileSync(file, "utf8");
        for (const token of FORBIDDEN) {
          if (text.includes(token)) {
            offenders.push(`${file}: contains "${token}"`);
          }
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  it("AC-006: the BUILT daemon + adapter dist bundles contain no CelloClient / session-manager / seal-manager references", () => {
    const distDirs = [
      join(CORE_ROOT, "daemon", "dist"),
      join(CORE_ROOT, "adapter-claude-code", "dist"),
    ];
    const offenders: string[] = [];
    for (const dir of distDirs) {
      // dist may be absent if the build gate has not yet run in this checkout;
      // collectJsFiles returns [] in that case and the source-level check above
      // remains the active guard. When dist IS present it must also be clean.
      for (const file of collectJsFiles(dir)) {
        const text = readFileSync(file, "utf8");
        for (const token of FORBIDDEN) {
          if (text.includes(token)) {
            offenders.push(`${file}: contains "${token}"`);
          }
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  it("the daemon package.json does not depend on @cello-protocol/client", () => {
    const pkg = JSON.parse(readFileSync(join(CORE_ROOT, "daemon", "package.json"), "utf8")) as {
      dependencies?: Record<string, string>;
    };
    expect(Object.keys(pkg.dependencies ?? {})).not.toContain("@cello-protocol/client");
  });
});
