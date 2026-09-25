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
import { spawnRealDaemon, makeCelloDir, cleanupCelloDir, type SpawnedDaemon } from "./helpers/spawn-real-daemon.js";
import { BUNDLED_CONSORTIUM_MANIFEST } from "../bundled-consortium-manifest.js";

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
});
