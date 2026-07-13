/**
 * DEAD-CODE PURGE — the M6-era in-process stack is GONE, and it may not come back.
 *
 * What was removed, and why the assertions below are shaped the way they are:
 *
 * `@cello-protocol/client` was the M6-era in-process client — key material, libp2p node, SQLCipher
 * store, session/seal state machines. The M6→M7 migration moved every one of those into the daemon,
 * which reimplements them natively (`daemon.ts`: "we reimplement natively here — the daemon never
 * imports @cello-protocol/client"). Nothing on the shipped path constructed it: Claude Code talks to
 * `bin/cello-mcp.ts`, a stdio→IPC proxy, which talks to the daemon. The package survived only because
 * two legacy in-process MCP servers re-exported it — and those were deleted by DOD-LEGACY-MCP-1.
 * With the tether cut, all 25 files were unreachable from every production entrypoint. They are gone.
 *
 * Also gone: `adapter/lock-file.ts` (the M6 PID lock — the daemon has its own),
 * `daemon/cello-node-transport-dialer.ts` (scaffolding never wired in), and the library-export
 * surfaces of connect and cli (`index.ts` + `config.ts`) — both packages are consumed as BINARIES,
 * never imported as libraries.
 *
 * The assertions are on SOURCE and on BUILT dist/. Source alone is not enough: `tsc --build` is
 * incremental and never deletes orphaned outputs, and `tsc --build --clean` does NOT remove them
 * either (it only cleans what it still tracks, and an orphan's source is gone). So a warm checkout
 * keeps compiling and PACKING files whose source was deleted — the tarball ships code that no longer
 * exists in the repo. That is not hypothetical: it happened on 2026-07-13, when `dist/server.js`
 * reappeared in a merged tree with every unit test green. Only an explicit recursive delete of every
 * package's `dist` directory clears it — `tsc` cannot.
 */

import { describe, it, expect } from "vitest";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const ADAPTER = join(here, "..", "..");          // core/adapter-claude-code
const CORE = join(ADAPTER, "..");                // core/

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

describe("DEAD-CODE PURGE — the M6 in-process stack is deleted", () => {
  it("the @cello-protocol/client package does not exist", () => {
    // Assert the PACKAGE is gone, not merely the directory. `git rm` removes tracked files; it cannot
    // remove untracked detritus, so a warm checkout can keep an empty `core/client/` holding a stale
    // node_modules and an old .tgz long after every source file is deleted. That husk ships nothing
    // and compiles nothing — failing on it would be a false alarm that trains people to ignore this
    // test. What must never come back is a real package: a manifest, sources, or a build output.
    for (const marker of ["package.json", "src", "dist"]) {
      expect(
        existsSync(join(CORE, "client", marker)),
        `core/client/${marker} is BACK — the M6 in-process client has been resurrected`,
      ).toBe(false);
    }
  });

  it("the orphaned M6 modules do not exist", () => {
    const gone = [
      ["adapter-claude-code", "src", "lock-file.ts"],       // M6 PID lock; the daemon has its own
      ["adapter-claude-code", "src", "index.ts"],           // connect is a BIN, not a library
      ["adapter-claude-code", "src", "config.ts"],          // only ever reachable via that index
      ["cli", "src", "index.ts"],                           // cli is a BIN, not a library
      ["daemon", "src", "cello-node-transport-dialer.ts"],  // never wired into the daemon
    ];
    for (const parts of gone) {
      const p = join(CORE, ...parts);
      expect(existsSync(p), `${parts.join("/")} is back`).toBe(false);
    }
  });

  it("no surviving source file imports the dead client package", () => {
    // A dangling import fails the build — but that is a compile error, not a statement of intent.
    // This says it out loud, and it is what stops someone re-adding the dependency.
    //
    // Match an actual IMPORT, not any mention: a live file may legitimately NAME the package in
    // prose to state that it must never be imported. A bare substring check would flag that comment
    // and push someone to delete the very rule it records.
    const IMPORTS_CLIENT = /(?:from|import)\s*\(?\s*["']@cello-protocol\/client["']/;
    const offenders: string[] = [];
    for (const pkg of ["adapter-claude-code", "cli", "daemon", "crypto", "transport", "protocol-types", "gateway"]) {
      const src = join(CORE, pkg, "src");
      if (!existsSync(src)) continue;
      for (const file of sourceFiles(src)) {
        if (IMPORTS_CLIENT.test(readFileSync(file, "utf8"))) offenders.push(file);
      }
    }
    expect(offenders, "a source file still imports the deleted @cello-protocol/client").toEqual([]);
  });

  it("no package still declares a dependency on the dead client", () => {
    const offenders: string[] = [];
    for (const pkg of readdirSync(CORE)) {
      const pj = join(CORE, pkg, "package.json");
      if (!existsSync(pj)) continue;
      const json = JSON.parse(readFileSync(pj, "utf8")) as Record<string, Record<string, string>>;
      for (const field of ["dependencies", "devDependencies", "peerDependencies"]) {
        if (json[field]?.["@cello-protocol/client"]) offenders.push(`${pkg}:${field}`);
      }
    }
    expect(offenders, "a package.json still depends on @cello-protocol/client").toEqual([]);
  });

  it("the built dist/ carries no artifact of the deleted code", () => {
    // THE ONE THAT ACTUALLY GUARDS THE TARBALL. Pin a must-exist marker first, so an unbuilt tree
    // fails LOUDLY rather than passing vacuously on `existsSync(...) === false`.
    const dist = join(ADAPTER, "dist");
    expect(existsSync(join(dist, "bin", "cello-mcp.js")), "dist/ is not built — run `pnpm run build`").toBe(true);

    for (const orphan of ["server.js", "notifications.js", "index.js", "config.js", "lock-file.js"]) {
      expect(existsSync(join(dist, orphan)), `dist/${orphan} is back in the tarball`).toBe(false);
    }
    expect(existsSync(join(CORE, "client", "dist")), "core/client/dist is back").toBe(false);
  });

  it("guards against a vacuous pass — the tree it scans really is there", () => {
    expect(sourceFiles(join(CORE, "daemon", "src")).length).toBeGreaterThan(10);
    expect(existsSync(join(ADAPTER, "src", "bin", "cello-mcp.ts")), "the LIVE shim must still exist").toBe(true);
    expect(existsSync(join(CORE, "daemon", "src", "daemon.ts")), "the LIVE daemon must still exist").toBe(true);
  });
});
