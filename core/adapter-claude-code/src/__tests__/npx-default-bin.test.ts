/**
 * The plugin starts the shim as `npx --yes @cello-protocol/connect@latest`, naming no command.
 * npx can pick a command only when the package has exactly one bin (or one named `connect`).
 * connect 0.0.240 shipped a second bin, `cello-mcp-http`, and npx answered "could not determine
 * executable to run" — every plugin install lost its CELLO tools on reconnect.
 */
import { describe, it, expect } from "vitest";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const pkgDir = join(import.meta.dirname, "..", "..");
const pkg = JSON.parse(readFileSync(join(pkgDir, "package.json"), "utf8")) as {
  bin: Record<string, string>;
  exports: Record<string, { types: string; import: string } | string>;
};

describe("npx can pick connect's command with none named", () => {
  it("has exactly one bin, and it is the stdio shim", () => {
    expect(pkg.bin).toEqual({ "cello-mcp": "./dist/bin/cello-mcp.js" });
  });

  it("the ./lib export points at lib, which is a compiled source file", () => {
    expect(pkg.exports["./lib"]).toEqual({ types: "./dist/lib.d.ts", import: "./dist/lib.js" });
    expect(existsSync(join(pkgDir, "src", "lib.ts"))).toBe(true);
  });
});
