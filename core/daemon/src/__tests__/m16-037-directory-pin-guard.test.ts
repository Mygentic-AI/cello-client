/**
 * M16 037-TESTTRUTH decision 4 — the live-consortium audit, as a standing guard.
 *
 * A daemon booted from the bundled manifest with no directory override dials the LIVE GCP
 * consortium. On 2026-09-25 the 024 create test did exactly that on every full-suite run and crashed
 * a production directory (fe8c5341). The rule the order sets is: no test reaches the live consortium.
 * `spawnRealDaemon` now pins a closed local port by default (see its header); this test proves a
 * daemon started through that helper — with NOTHING pinned by the caller — never names a live node.
 *
 * ⚠️ **TEETH.** The bundled manifest genuinely names `*.cello.mygentic.ai`, asserted below, so the
 * regex is not vacuous: the same `/mygentic\.ai/` matcher was RED against an unpinned 024 daemon's
 * log before fe8c5341. Reproducing that red here would require booting a daemon that dials
 * production, which the order forbids, so the pin is verified in the safe direction and its teeth
 * rest on that recorded evidence plus the manifest assertion.
 */
import { describe, it, expect, afterEach } from "vitest";
import { readdirSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { spawnRealDaemon, makeCelloDir, cleanupCelloDir, type SpawnedDaemon } from "./helpers/spawn-real-daemon.js";
import { BUNDLED_CONSORTIUM_MANIFEST } from "../bundled-consortium-manifest.js";

/** Every `.ts` file under a package's `__tests__` (including `helpers/`). */
function testFilesUnder(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...testFilesUnder(full));
    else if (entry.name.endsWith(".ts")) out.push(full);
  }
  return out;
}

describe("M16 037-TESTTRUTH: a helper-started daemon never reaches the live consortium", () => {
  let celloDir: string | undefined;
  let daemon: SpawnedDaemon | undefined;

  afterEach(async () => {
    if (daemon) {
      await daemon.stopGracefully().catch(() => daemon?.kill("SIGKILL"));
      daemon = undefined;
    }
    await cleanupCelloDir(celloDir);
    celloDir = undefined;
  });

  it("spawnRealDaemon with no directory override pins a local port, and its log names no live node", async () => {
    // The live directories the pin exists to keep out — if the manifest ever stopped naming them this
    // guard would pass for the wrong reason, so the presence is asserted first.
    expect(JSON.stringify(BUNDLED_CONSORTIUM_MANIFEST), "the bundled manifest must name the live nodes the pin overrides")
      .toMatch(/mygentic\.ai/);

    celloDir = await makeCelloDir("cello-m16-037-");
    // No CELLO_DIRECTORY_URL and no CELLO_E2E_LIVE: the helper's default pin is the only thing between
    // this daemon and the live consortium.
    daemon = spawnRealDaemon(celloDir);
    await daemon.waitForEvent("daemon.started");
    // Let the directory bootstrap attempt its dial before the log is read — a live host would already
    // be named in directory.bootstrap.* by now.
    await new Promise((r) => setTimeout(r, 2000));

    expect(daemon.output(), "a helper-started daemon reached a live CELLO directory").not.toMatch(/mygentic\.ai/);
  }, 40_000);

  /**
   * The static half of the audit (037 review M-2): no test may spawn the daemon binary — directly,
   * or through the CLI `login` — without pinning the directory. A file is compliant if it routes
   * through `spawnRealDaemon` (whose default pins the port) OR names `CELLO_DIRECTORY_URL` itself.
   * This is what makes the audit standing rather than a one-time sweep: a NEW daemon-spawning test
   * that forgets the pin fails here.
   */
  it("no test spawns the daemon binary or CLI login without pinning CELLO_DIRECTORY_URL", () => {
    const repoRoot = join(import.meta.dirname, "..", "..", "..", "..");
    const coreDir = join(repoRoot, "core");
    const files: string[] = [];
    for (const pkg of readdirSync(coreDir, { withFileTypes: true })) {
      if (pkg.isDirectory()) files.push(...testFilesUnder(join(coreDir, pkg.name, "src", "__tests__")));
    }
    // Sanity: the scan must actually find test files, or a broken path would pass vacuously.
    expect(files.length, "the test-tree scan found no files").toBeGreaterThan(50);

    const violators: string[] = [];
    for (const file of files) {
      const content = readFileSync(file, "utf8");
      // Matches both `../bin/cello-daemon.ts` and a path built from join("dist","bin","cello-daemon.js")
      // segments — the filename is the stable signal, the path separators are not.
      const referencesBinary = /cello-daemon\.(ts|js)/.test(content);
      const spawnsOrLogins = /\bspawn\s*\(/.test(content) || /\blogin\s*\(/.test(content);
      if (!(referencesBinary && spawnsOrLogins)) continue; // not a daemon-binary spawner
      const pinned = content.includes("spawnRealDaemon") || content.includes("CELLO_DIRECTORY_URL");
      if (!pinned) violators.push(file.slice(repoRoot.length + 1));
    }
    expect(violators, `these tests spawn the daemon without pinning the directory:\n${violators.join("\n")}`).toEqual([]);
  });
});
