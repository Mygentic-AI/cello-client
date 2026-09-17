/**
 * DOD-M9C-SCREENINSTALL-1 — `cello_status` reports which screening layers are running.
 *
 * The CLI, the daemon's startup line and this surface must give the same answer, so all three read
 * the gateway's `screenerState`. What this test holds is that the status response CARRIES it: a
 * state nothing reports is the defect this milestone exists for, and the previous version of that
 * defect survived because the gateway announced Layer 2 to a stream nobody read.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, writeFile, mkdir, truncate } from "node:fs/promises";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { SCREENER_MODEL, screenerState, describeScreenerState } from "@cello-protocol/gateway";
import type { ScreeningStatusInfo } from "../types.js";

/** Exactly what `daemon-status-report.ts` builds, kept in one place so the shape is asserted once. */
function toScreeningInfo(s: Awaited<ReturnType<typeof screenerState>>): ScreeningStatusInfo {
  return { classifier: s.state, summary: describeScreenerState(s), ...(s.problem ? { problem: s.problem } : {}) };
}

describe("SCREENINSTALL: cello_status screening block", () => {
  let dir: string;
  beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), "cello-status-screener-")); });
  afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

  it("names the state and carries the operator sentence when the classifier is absent", async () => {
    const info = toScreeningInfo(await screenerState({ dir, runtimePresent: false }));
    expect(info.classifier).toBe("not_installed");
    expect(info.summary).toContain("cello screener install");
    expect(info.problem).toBeUndefined();
  });

  it("reports a BROKEN classifier as broken, naming the file — never as 'not installed'", async () => {
    for (const f of SCREENER_MODEL.files) {
      const dest = join(dir, f.path);
      await mkdir(dirname(dest), { recursive: true });
      await writeFile(dest, "");
      await truncate(dest, f.size); // right size, wrong bytes: only the digest can tell
    }
    const info = toScreeningInfo(await screenerState({ dir, runtimePresent: true }));
    expect(info.classifier).toBe("broken");
    expect(info.problem).toContain(SCREENER_MODEL.files[0]!.path);
    expect(info.summary).toContain("BROKEN");
  });

  it("reports the healthy case too, so an operator can CONFIRM the layer is on", async () => {
    // The directory-auth block earns its place the same way: a defence you can only infer from the
    // absence of a warning is one nobody can check.
    const info = toScreeningInfo({
      state: "ready", revision: SCREENER_MODEL.revision, runtimePresent: true,
      model: { filesPresent: SCREENER_MODEL.files.length, filesExpected: SCREENER_MODEL.files.length, verified: true },
      missing: [],
    });
    expect(info.classifier).toBe("ready");
    expect(info.summary).toContain("2 of 2 layers");
  });
});
