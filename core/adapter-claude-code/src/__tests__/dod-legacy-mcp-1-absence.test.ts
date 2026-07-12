/**
 * DOD-LEGACY-MCP-1 — the legacy in-process MCP servers are GONE.
 *
 * What this guards, and why it is asserted on SOURCE rather than on `dist/`:
 *
 * The defect was never "an unused function exists". It was that `@cello-protocol/connect` SHIPPED a
 * SECOND tool vocabulary: `dist/server.js` really was in the v0.0.97 tarball, really did register
 * `cello_receive_session` / `cello_list_sessions` / `cello_get_sealed_receipt` — names that are
 * renamed away or deleted — and really was exported from the package root. Unreachable at runtime
 * (the live shim `bin/cello-mcp.ts` proxies to the daemon and never imports it), but an agent that
 * introspects the package sees two vocabularies for one capability.
 *
 * Dropping the export ALONE does not fix that: `tsc` compiles every file under `src/`, so
 * `dist/server.js` would still be emitted and still ship. The files must actually be DELETED. That
 * is why the assertions below are on the source tree — `dist/` is a pure function of it. `tsc`
 * cannot emit `dist/server.js` from a `src/server.ts` that does not exist.
 *
 * The tarball itself is verified at the completion gate (`npm pack` + grep), which is the only place
 * a built artifact actually exists. Asserting on `dist/` here would pass vacuously on a clean
 * checkout, where nothing has been built yet — a green test that proves nothing is worse than none.
 */

import { describe, it, expect } from "vitest";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const ADAPTER_SRC = join(here, "..");
const CLIENT_SRC = join(here, "..", "..", "..", "client", "src");

/** Every `.ts` file under a package's `src/`, excluding its tests. */
function sourceFiles(root: string): string[] {
  const out: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir)) {
      if (entry === "__tests__" || entry === "node_modules") continue;
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) walk(full);
      else if (entry.endsWith(".ts")) out.push(full);
    }
  };
  walk(root);
  return out;
}

describe("DOD-LEGACY-MCP-1 — the legacy in-process MCP servers are deleted", () => {
  it("the dead source files do not exist", () => {
    expect(existsSync(join(ADAPTER_SRC, "server.ts")), "adapter server.ts still exists").toBe(false);
    expect(existsSync(join(ADAPTER_SRC, "notifications.ts")), "adapter notifications.ts still exists").toBe(false);
    expect(existsSync(join(CLIENT_SRC, "mcp-server.ts")), "client mcp-server.ts still exists").toBe(false);
  });

  it("connect's package root exports none of the legacy symbols", () => {
    const index = readFileSync(join(ADAPTER_SRC, "index.ts"), "utf8");
    for (const sym of ["createMcpServer", "pushChannelNotification", "pushSessionRequestNotification"]) {
      expect(index, `${sym} is still exported from @cello-protocol/connect`).not.toContain(sym);
    }
  });

  it("client's package root no longer exports createMcpSessionServer", () => {
    const index = readFileSync(join(CLIENT_SRC, "index.ts"), "utf8");
    expect(index, "createMcpSessionServer is still exported from @cello-protocol/client").not.toContain(
      "createMcpSessionServer",
    );
  });

  it("no surviving source file imports a legacy symbol (nothing can resurrect them)", () => {
    // A dangling import would fail the build — but it would fail it in `tsc`, which is a compile
    // error, not a statement of intent. This says the intent out loud.
    const offenders: string[] = [];
    for (const file of [...sourceFiles(ADAPTER_SRC), ...sourceFiles(CLIENT_SRC)]) {
      const text = readFileSync(file, "utf8");
      for (const sym of [
        "createMcpServer",
        "createMcpSessionServer",
        "pushSessionRequestNotification",
        "pushChannelNotification",
        "DEFAULT_DEMO_AGENT_ID",
      ]) {
        if (text.includes(sym)) offenders.push(`${file}: ${sym}`);
      }
    }
    expect(offenders, `A surviving source file still references a deleted legacy symbol.`).toEqual([]);
  });

  it("the built dist/ carries no legacy artifact — this is the defect, asserted directly", () => {
    // Source deletion is necessary but not sufficient FOREVER: a build-config change could put a
    // `server.js` back in the tarball. So assert the artifact itself.
    //
    // The hazard is a vacuous pass on an unbuilt checkout — `existsSync(dist/server.js) === false`
    // is trivially true when there is no dist/ at all. The fix is not to skip: it is to PIN a marker
    // that must exist, so an unbuilt tree fails LOUDLY instead of passing silently.
    const DIST = join(ADAPTER_SRC, "..", "dist");
    expect(existsSync(join(DIST, "index.js")), "dist/ is not built — run `pnpm run build` first").toBe(true);

    expect(existsSync(join(DIST, "server.js")), "dist/server.js is BACK in the tarball").toBe(false);
    expect(existsSync(join(DIST, "notifications.js")), "dist/notifications.js is BACK in the tarball").toBe(false);
    expect(
      existsSync(join(ADAPTER_SRC, "..", "..", "client", "dist", "mcp-server.js")),
      "client dist/mcp-server.js is BACK in the tarball",
    ).toBe(false);
  });

  it("guards against a vacuous pass — the files it scans really are there", () => {
    // If `sourceFiles()` silently returned [] (wrong path, renamed dir), every assertion above would
    // pass while proving nothing. Pin the thing that must exist.
    expect(sourceFiles(ADAPTER_SRC).length).toBeGreaterThan(3);
    expect(sourceFiles(CLIENT_SRC).length).toBeGreaterThan(10);
    expect(existsSync(join(ADAPTER_SRC, "bin", "cello-mcp.ts")), "the LIVE shim must still exist").toBe(true);
  });
});
