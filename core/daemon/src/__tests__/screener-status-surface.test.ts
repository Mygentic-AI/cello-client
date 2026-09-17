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
import { SCREENER_MODEL, localPathOf, screenerState, describeScreenerState } from "@cello-protocol/gateway";
import type { ScreeningStatusInfo } from "../types.js";
import { screeningSessionNoticeFrom, screeningStatus } from "../screening-status.js";

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
      const dest = join(dir, localPathOf(f));
      await mkdir(dirname(dest), { recursive: true });
      await writeFile(dest, "");
      await truncate(dest, f.size); // right size, wrong bytes: only the digest can tell
    }
    const info = toScreeningInfo(await screenerState({ dir, runtimePresent: true }));
    expect(info.classifier).toBe("broken");
    expect(info.problem).toContain(localPathOf(SCREENER_MODEL.files[0]!));
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

describe("SCREENINSTALL: screeningStatus is the real function every surface calls", () => {
  it("answers with a state and a sentence, and never throws", async () => {
    // The mapping above is asserted against a reimplementation; this calls the SHIPPED function, so
    // a status block that stopped being built fails here rather than passing a private copy.
    const prev = process.env["CELLO_GATEWAY_MODEL_DIR"];
    process.env["CELLO_GATEWAY_MODEL_DIR"] = "/tmp/cello-screener-definitely-absent";
    const info = await screeningStatus();
    expect(info).toBeDefined();
    expect(["not_installed", "half_installed", "broken", "ready", "unknown"]).toContain(info.classifier);
    expect(info.summary).toMatch(/Screening:/);
    if (prev === undefined) delete process.env["CELLO_GATEWAY_MODEL_DIR"]; else process.env["CELLO_GATEWAY_MODEL_DIR"] = prev;
  });
});

describe("SCREENINSTALL: the per-session notice", () => {
  it("is silent when both layers are running", async () => {
    // A notice on a healthy inbox is furniture, and furniture is what teaches readers to skip.
    const notice = await screeningSessionNoticeFrom(async () => ({ classifier: "ready", summary: "2 of 2" }));
    expect(notice).toBeUndefined();
  });

  it("names the state and the command while the classifier is absent", async () => {
    const notice = await screeningSessionNoticeFrom(async () => ({ classifier: "not_installed", summary: "x" }));
    expect(notice).toContain("1 of 2 layers");
    expect(notice).toContain("cello screener install");
  });

  it("fires for a BROKEN classifier too — broken is not running", async () => {
    const notice = await screeningSessionNoticeFrom(async () => ({ classifier: "broken", summary: "x", problem: "y" }));
    expect(notice).toBeDefined();
  });

  it("says UNKNOWN when the check itself failed, rather than implying the content was judged", async () => {
    const notice = await screeningSessionNoticeFrom(async () => ({ classifier: "unknown", summary: "x", problem: "permission denied" }));
    expect(notice).toContain("UNKNOWN");
    expect(notice).toContain("permission denied");
  });

  it("points a BROKEN classifier at --repair and says it did NOT judge the content", async () => {
    const notice = await screeningSessionNoticeFrom(async () => ({ classifier: "broken", summary: "x", problem: "tokenizer.json does not match" }));
    expect(notice).toContain("did NOT judge");
    expect(notice).toContain("--repair");
  });
});
